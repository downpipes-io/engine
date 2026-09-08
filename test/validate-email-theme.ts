// Prove src/email-theme.ts, the HTML card every transactional email this engine sends is rendered into.
//
// WHY THIS FILE EXISTS. `git grep -ln 'email-theme'` returns five files, all of them under src/, and no
// test file among them. The send primitive beneath the card is covered by
// test/validate-email.ts (src/email.ts: address validation, recipient bounds, the fail-open reason
// vocabulary, and that nothing but from/to/subject/text/html crosses to the binding). The CARD ITSELF was
// covered by nothing at all, in a repo where this mail goes to a customer's own on-call team.
//
// WHAT THE SIBLING ALREADY SOLVED. control-plane/test/validate-emails.ts grades the licensing pack against
// a set of rules this file extends rather than reinvents: renders a full document, no em or en dash
// anywhere in any part, no external URL outside an allowed set, NO REMOTE RESOURCE OF ANY KIND, hostile
// values escaped, and WCAG contrast computed from the colours the renderer actually emitted rather than
// checked against a magic hex string. Those transfer, and the remote-resource rule matters more here than
// there: a tracking pixel or a remote webfont in an on-call alert is a privacy leak and a rendering
// failure on a locked-down mail client at the same time.
//
// WHAT DID NOT TRANSFER, with the reason.
//   - The claim-code and raw-token rules. There is no claim code and no licence token in engine mail. The
//     engine's own redaction boundary stands in their place: section (8) drives the REAL notify caller and
//     proves the emission's unsafe fields never reach the card.
// - The human-date rule. control-plane renders " (UTC)" because a customer reading a licence
//     term should not have to parse an ISO string. An on-call alert is the opposite case: the operator
//     wants the precise instant, and src/notify/channels/email.ts renders emission.at verbatim on purpose.
//     Section (8) pins that it survives verbatim instead.
//   - The honesty-law eligibility matrix. It grades commercial entitlement copy. Engine mail makes no
//     entitlement claim.
//   - The text-part hygiene rules. This module renders the HTML part only; the plain-text bodies are built
//     by the callers, and the send primitive that carries both is already covered next door.
//   - The allowed-HOST list. control-plane mail links to Downpipes-owned hosts, so a host allowlist is the
//     right shape there. This engine is SELF-HOSTED and its only links are the customer's own console
//     origin, which no list here can know. Section (4) takes the rule in its inverted form, which is the
//     part that actually protects the reader: the card may carry the caller's URL and NOTHING ELSE, so a
//     vendor link or a tracking domain added to the chrome fails.
//   - The vendor sign-off rule, INVERTED. control-plane asserts the licensing pack carries a named
//     personal and company sign-off. This mail is sent BY a customer's engine TO their own team, so the
//     module's header forbids exactly that sign-off. Section (5) asserts its ABSENCE.
//
// In memory only. NOTHING IS SENT: no binding, no network, no clock. Run:
//   node test/validate-email-theme.ts

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { blankComments } from "./lib/blank-comments.mjs";
import { DEFAULT_FOOTER_NOTE, renderEngineEmailHtml, type EngineEmailInput } from "../src/email-theme.ts";
import { format } from "../src/notify/channels/email.ts";
import type { NotifyEmission } from "../src/notify/types.ts";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const THEME_MODULE = "src/email-theme.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- WCAG relative luminance and contrast ratio ------------------------------------------------------
// Ported from control-plane/test/validate-emails.ts, for the same reason it was ported there: the check
// has to run on the colour the renderer EMITTED. A test that looks for a known-good hex string passes on
// the day the palette is edited and the string is edited with it.
function relativeLuminance(hex: string): number {
  const n = hex.replace("#", "");
  const channel = (v: number): number => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4);
  const r = channel(Number.parseInt(n.slice(0, 2), 16) / 255);
  const g = channel(Number.parseInt(n.slice(2, 4), 16) / 255);
  const b = channel(Number.parseInt(n.slice(4, 6), 16) / 255);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function contrastRatio(hexA: string, hexB: string): number {
  const lumA = relativeLuminance(hexA);
  const lumB = relativeLuminance(hexB);
  const [hi, lo] = lumA > lumB ? [lumA, lumB] : [lumB, lumA];
  return (hi + 0.05) / (lo + 0.05);
}

// ---- the message kinds that actually use the card ----------------------------------------------------
// One fixture per call site on origin/main, each carrying the SHAPE its caller passes rather than a
// convenient shape. Section (1) re-derives the call sites from source and fails if this list stops being
// the whole population, so a fifth kind added without a fixture cannot slip through as "all kinds pass".
const CONSOLE_ORIGIN = "https://console.acme-internal.example.com";
const BOOTSTRAP_LINK = `${CONSOLE_ORIGIN}/bootstrap?t=opaque-one-time-handle`;

const kinds: Record<string, EngineEmailInput> = {
  // src/notify/channels/email.ts format(): the alert, and the digest flush that reuses it. No CTA.
  alert: {
    subject: "[downpipe] critical: backup-failure",
    heading: "critical: backup-failure",
    paragraphs: ["nightly-r2 has not completed a run since its last success.", "Event: backup-failure\nSeverity: critical\nDownpipe: nightly-r2\nTime: 2026-08-10T02:15:00.000Z"],
  },
  // src/admin/router-auth-flow.ts: the first-Owner set-up link. Subject override plus a CTA.
  bootstrap: {
    subject: "Set up the first Owner of this Downpipes engine",
    heading: "Set up the first Owner",
    paragraphs: ["This Downpipes engine has no Owner yet.", "Opening the link asks this device for a passkey. It works once and expires in 24 hours."],
    cta: { label: "Set up the first Owner", url: BOOTSTRAP_LINK },
  },
  // src/admin/router-sources.ts: the role invite, in its CTA-bearing form.
  invite: {
    subject: "You have a new role in Downpipes",
    heading: "You have a new role",
    paragraphs: ["You have been granted the Operator role.", "Set up your passkey to sign in."],
    cta: { label: "Set up your passkey", url: `${CONSOLE_ORIGIN}/register` },
  },
  // src/admin/router-sources.ts: the same invite where no origin is known, so no CTA is emitted at all.
  inviteNoCta: {
    subject: "You have a new role in Downpipes",
    heading: "You have a new role",
    paragraphs: ["You have been granted the Operator role."],
  },
  // src/admin/router-custody.ts: the recovery-share email, the one kind that carries a code block and a
  // numbered list, and the only kind whose body is a customer's own key material. NO CTA: a share email
  // must never carry a link.
  custodyShare: {
    subject: "Keep this downpipes recovery share safe",
    heading: "Keep this recovery share safe",
    paragraphs: ["You have been given one share for Jo Bloggs (Finance) of a downpipes recovery key.", "On its own this share reveals nothing. Any 3 of the 5 shares together reconstruct the key if recovery is ever needed."],
    code: { value: "SYNTHETIC-SHARE-VALUE-NEVER-A-REAL-ONE", label: "Your share" },
    steps: { heading: "What to do now", items: ["Save this share offline, or in a password manager such as Bitwarden.", "Then delete this email.", "Keep it to yourself and do not forward it."] },
  },
  // src/admin/router-destinations.ts: the console's outbound delivery test. No CTA.
  deliveryTest: {
    subject: "Downpipes email delivery test",
    heading: "Email delivery test",
    paragraphs: ["This is the delivery test you requested from the Downpipes console.", "If you are reading it, outbound email from this engine works.", "Sender: alerts@acme-internal.example.com."],
  },
};

const rendered: Record<string, string> = {};
for (const [id, input] of Object.entries(kinds)) rendered[id] = renderEngineEmailHtml(input);

// The URL each kind's caller supplied, and the complete set of URLs the rendered card is therefore
// allowed to carry. A kind absent from this map is allowed no URL at all.
const suppliedUrls: Record<string, string[]> = {
  bootstrap: [BOOTSTRAP_LINK],
  invite: [`${CONSOLE_ORIGIN}/register`],
};

// ---- (1) the population: every caller of the card has a fixture above --------------------------------
// A suite that grades "every kind" is worth exactly as much as its claim to know every kind. The call
// sites are re-derived from src/ with comments blanked first, because src/util/html.ts and
// src/notify/channels/email.ts each NAME email-theme.ts in prose while only one of them calls it, and a
// scanner that reads a comment as code is a defect this workspace has shipped before.
function derivedCallers(): string[] {
  const files: string[] = [];
  const walk = (rel: string): void => {
    for (const entry of readdirSync(join(REPO, rel), { withFileTypes: true })) {
      const child = `${rel}/${entry.name}`;
      if (entry.isDirectory()) walk(child);
      else if (entry.name.endsWith(".ts")) files.push(child);
    }
  };
  walk("src");
  const callers: string[] = [];
  for (const rel of files) {
    // The module that DECLARES the function is not one of its callers. Skipping it by name rather than by
    // pattern keeps the next assertion able to notice if the declaration ever moves elsewhere.
    if (rel === THEME_MODULE) continue;
    const code = blankComments(readFileSync(join(REPO, rel), "utf8"));
    if (code.includes("renderEngineEmailHtml(")) callers.push(rel);
  }
  return callers.sort();
}

// ---- (8) fixture: the REAL notify caller, so the redaction boundary is proven where it is enforced ----
const ID_SENTINEL = "dp_01SENTINELID_MUST_NEVER_RENDER";
const HOSTILE_NAME = `nightly<script>alert(1)</script>&"pipe"`;
const emission: NotifyEmission = {
  event: "backup-failure",
  severity: "critical",
  downpipeId: ID_SENTINEL,
  downpipeName: HOSTILE_NAME,
  detail: `${HOSTILE_NAME} has not completed a run since 2026-08-09.`,
  at: "2026-08-10T02:15:00.000Z",
  recovered: false,
  catchingUp: true,
};

function main(): void {
  // --- (1) ------------------------------------------------------------------------------------------
  console.log("(1) the population of message kinds is the population of call sites");
  {
    const callers = derivedCallers();
    const expected = ["src/admin/router-auth-flow.ts", "src/admin/router-custody.ts", "src/admin/router-destinations.ts", "src/admin/router-sources.ts", "src/notify/channels/email.ts"];
    ok(`the card has ${expected.length} callers in src/, and they are the ones fixtured here`, callers.join(",") === expected.join(","));
    ok("the derivation found callers at all (the scan itself is exercised)", callers.length > 0);
    ok("src/util/html.ts is not counted: it names the module in prose and never calls it", !callers.includes("src/util/html.ts"));
    ok(`${THEME_MODULE} is still where the card is declared`, blankComments(readFileSync(join(REPO, THEME_MODULE), "utf8")).includes("export function renderEngineEmailHtml("));
    // The zero-render refusal the whole exercise is about. A run that rendered nothing has not passed.
    ok(`a non-zero number of kinds was rendered (${Object.keys(rendered).length})`, Object.keys(rendered).length > 0);
    ok("every declared kind produced a document", Object.values(rendered).every((h) => h.length > 0) && Object.keys(rendered).length === Object.keys(kinds).length);
  }

  // --- (2) structure, per kind ------------------------------------------------------------------------
  console.log("(2) each kind renders the card's load-bearing structure");
  for (const [id, html] of Object.entries(rendered)) {
    const input = kinds[id] as EngineEmailInput;
    ok(`${id}: is a complete document`, html.startsWith("<!doctype html>") && html.trimEnd().endsWith("</body></html>"));
    ok(`${id}: the title is the subject the caller set`, html.includes(`<title>${input.subject}</title>`));
    ok(`${id}: the heading is rendered as the only h1`, html.split("<h1").length === 2 && html.includes(`>${input.heading}</h1>`));
    ok(`${id}: every paragraph reached the card`, input.paragraphs.every((p) => html.includes(p.split("\n")[0] as string)));
    ok(`${id}: the card is capped at 560px`, html.includes("max-width:560px"));
    ok(`${id}: an MSO ghost table caps it for the Word renderer too`, html.includes("<!--[if mso]>") && html.includes('width="560"') && html.includes("<![endif]-->"));
    ok(`${id}: the layout tables are marked role="presentation"`, html.includes('role="presentation"'));
    ok(`${id}: a hidden preheader is present`, html.includes('style="display:none;'));
    ok(`${id}: both colour schemes are declared`, html.includes('name="color-scheme" content="light dark"') && html.includes("prefers-color-scheme: dark"));
    ok(`${id}: the footer carries the neutral automated-message note`, html.includes(DEFAULT_FOOTER_NOTE));
    ok(`${id}: the wordmark is text, never an image`, html.split(">downpipes</div>").length === 3);
    const wantsCta = input.cta !== undefined;
    // The button's MARKUP, not the string "dp-btn": the enhancement block restates .dp-btn for the dark
    // scheme in every kind, so a bare substring check would read as a button on a card that has none.
    ok(`${id}: a CTA button is present exactly when the caller passed one`, /<td class="dp-btn" bgcolor=/.test(html) === wantsCta);
    if (wantsCta) {
      const cta = input.cta as { label: string; url: string };
      ok(`${id}: the CTA pads the coloured cell, not the anchor, so Outlook keeps the pill`, /class="dp-btn" bgcolor="#[0-9a-f]{6}" style="background-color:#[0-9a-f]{6};border-radius:6px;padding:11px 22px;"/.test(html) && html.includes("display:block"));
      ok(`${id}: the CTA links exactly where the caller asked`, html.includes(`href="${cta.url}"`));
    }
  }

  // --- (3) no remote resource of any kind -------------------------------------------------------------
  // The rule that matters most for mail. Taken whole from the sibling and widened by three shapes it does
  // not carry (an iframe, a table/td background attribute, and a protocol-relative src), because those are
  // the remaining ways a remote fetch reaches a mail client.
  console.log("(3) no remote resource of any kind");
  for (const [id, html] of Object.entries(rendered)) {
    ok(`${id}: no <img>, so no tracking pixel and no remote logo`, !html.includes("<img"));
    ok(`${id}: no <script>`, !html.includes("<script"));
    ok(`${id}: no <link> and no @import`, !html.includes("<link") && !html.includes("@import"));
    ok(`${id}: no webfont and no CSS url() load`, !html.includes("@font-face") && !html.includes("url("));
    ok(`${id}: no <iframe>, <video>, <audio> or <object>`, !/<(?:iframe|video|audio|object|embed)\b/i.test(html));
    ok(`${id}: no background= attribute (the old Outlook remote-image route)`, !/\sbackground\s*=/i.test(html));
    ok(`${id}: no protocol-relative resource reference`, !/(?:src|href)\s*=\s*"\/\//i.test(html));
  }

  // --- (4) the card carries the caller's URL and nothing else -----------------------------------------
  console.log("(4) no URL the caller did not supply");
  {
    let sawAnyUrl = false;
    for (const [id, html] of Object.entries(rendered)) {
      const allowed = suppliedUrls[id] ?? [];
      const found = [...html.matchAll(/https?:\/\/[^\s"'<>]+/g)].map((m) => m[0]);
      if (found.length > 0) sawAnyUrl = true;
      ok(`${id}: found ${found.length} URL(s), all of them the caller's`, found.every((u) => allowed.includes(u)));
      ok(`${id}: the caller's URL(s) all survived into the card`, allowed.every((u) => found.includes(u)));
    }
    ok("at least one kind carried a URL, so the scan is exercised rather than vacuous", sawAnyUrl);
  }

  // --- (5) no vendor identity -------------------------------------------------------------------------
  // The module's loudest documented invariant, and the one nothing enforced. This mail is sent by the
  // customer's own engine to the customer's own team.
  console.log("(5) no vendor identity in mail a customer's engine sends to its own team");
  for (const [id, html] of Object.entries(rendered)) {
    // Graded on the CARD'S OWN CHROME, with the caller's URL removed first. Whether a caller may pass a
    // given link is section (4)'s question, and answering it twice with two different rules would make
    // one of them wrong the first time a caller has an honest reason to link somewhere.
    const chrome = (suppliedUrls[id] ?? []).reduce((acc, u) => acc.split(u).join(""), html);
    ok(`${id}: no Maelstrom sign-off`, !/maelstrom/i.test(chrome));
    ok(`${id}: no personal sign-off from the vendor`, !/O&#39;Connor|O'Connor/.test(chrome));
    ok(`${id}: no vendor contact, marketing address or unsubscribe rail in the chrome`, !/downpipes\.io|support@|sales@|unsubscribe/i.test(chrome));
    ok(`${id}: the footer note is the neutral engine line`, html.includes("This is an automated message from your Downpipes engine."));
  }

  // --- (6) no em dash, no en dash -----------------------------------------------------------------------
  // Written as code points, never the literal characters, so this file does not itself trip the repo-wide
  // prose gate that already bans them across the source tree.
  console.log("(6) no em dash or en dash in any rendered kind");
  {
    const EM_DASH = String.fromCodePoint(0x2014);
    const EN_DASH = String.fromCodePoint(0x2013);
    for (const [id, html] of Object.entries(rendered)) {
      ok(`${id}: no em dash`, !html.includes(EM_DASH));
      ok(`${id}: no en dash`, !html.includes(EN_DASH));
    }
  }

  // --- (7) escaping ------------------------------------------------------------------------------------
  console.log("(7) a hostile value renders as text, never as markup");
  {
    const hostile = renderEngineEmailHtml({
      heading: `<script>alert("h")</script>`,
      // The PARAGRAPH path is its own escape route: paragraphs go through linkifyHtml, not through the
      // plain escapeHtml the heading takes, and it is the path a customer-controlled downpipe name
      // actually travels. Splitting the two was not academic. A mutant that dropped escaping from
      // linkifyHtml alone left every assertion in this section green, because nothing here put markup in
      // a paragraph, and it was caught two sections later by luck rather than by design.
      paragraphs: [`Acme "&" Co <b>bold</b> <script>alert(2)</script>`, `see https://console.example.com/a"onmouseover="x for detail`],
      subject: `<img src=x onerror=alert(1)>`,
      cta: { label: `<b>go</b>`, url: `https://console.example.com/go"onmouseover="x` },
      footerNote: `</td></tr></table><script>1</script>`,
    });
    ok("the injected script tag never reaches the document as markup", !hostile.includes("<script>") && hostile.includes("&lt;script&gt;"));
    // SCOPED TO THE PROSE BLOCK, and that is the whole assertion. Checked against the document as a
    // whole, both of the next two lines pass on a renderer that has stopped escaping paragraphs
    // altogether, because the hidden preheader carries an escaped copy of the first paragraph by a
    // different route and the substring is found there. A positive substring search that does not say
    // WHERE is a control of the wrong kind.
    const prose = [...hostile.matchAll(/<div class="dp-text" style="[^"]*">([\s\S]*?)<\/div>/g)].map((m) => m[1] as string);
    ok(`the prose blocks were located (${prose.length} of them)`, prose.length === 2);
    ok("markup in a PARAGRAPH is escaped on the linkify path, not only on the heading path", prose.join("").includes("&lt;b&gt;bold&lt;/b&gt;") && prose.join("").includes("&lt;script&gt;alert(2)&lt;/script&gt;"));
    ok("no prose block carries raw markup", prose.every((p) => !/<(?!br>|a href=|\/a>)/.test(p)));
    ok("the injected img tag in the subject is escaped in the title", !hostile.includes("<img") && hostile.includes("&lt;img src=x onerror=alert(1)&gt;"));
    ok("quotes and ampersands are entity-escaped in the prose block itself", (prose[0] as string).includes("Acme &quot;&amp;&quot; Co"));
    ok("a quote in a linkified URL cannot break out of the href attribute", !/href="[^"]*"[a-z]/i.test(hostile));
    ok("a quote in the CTA URL cannot break out of the href attribute either", hostile.includes("&quot;onmouseover=&quot;x"));
    ok("a hostile footer note cannot close the card's table", !hostile.includes("</td></tr></table><script>"));
    ok("the escaped hostile document is still a complete document", hostile.startsWith("<!doctype html>") && hostile.trimEnd().endsWith("</body></html>"));
  }

  // --- (8) the redaction boundary, driven through the real caller --------------------------------------
  // src/notify/channels/email.ts builds the card from the emission's SAFE SURFACE only. That claim lives in
  // a comment there and in nothing else. Driving format() rather than re-typing its input is the point: a
  // future edit that starts passing the whole emission into the card fails here.
  console.log("(8) the notify redaction boundary survives into the rendered card");
  {
    const msg = format(["oncall@acme-internal.example.com"], emission);
    const html = msg.html as string;
    ok("format() produced an HTML part at all", typeof msg.html === "string" && html.startsWith("<!doctype html>"));
    ok("the downpipe id never reaches the card", !html.includes(ID_SENTINEL));
    ok("the downpipe id never reaches the text part either (the control for the line above)", !msg.text.includes(ID_SENTINEL));
    ok("the routing-only recovered / catchingUp hints never reach the card", !/recovered|catchingUp|catching up/i.test(html));
    ok("the event, severity and downpipe name reach the card", html.includes("backup-failure") && html.includes("critical") && html.includes("nightly"));
    ok("the emit instant survives VERBATIM, not reformatted (an operator triages on the exact time)", html.includes("2026-08-10T02:15:00.000Z"));
    ok("the customer-controlled downpipe name is escaped in the card", !html.includes("<script>alert(1)</script>") && html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
    ok("the same name is carried unescaped in the text part, so the escaping is the CARD's doing", msg.text.includes("<script>alert(1)</script>"));
    ok("the card emits no link for an alert, so nothing sensitive can ride one", !/https?:\/\//.test(html));
    // A null downpipe name is the account-level event, and the fact line must then be absent from BOTH
    // parts rather than rendering as "Downpipe: null".
    const accountLevel = format(["oncall@acme-internal.example.com"], { ...emission, downpipeId: null, downpipeName: null, detail: "A role was changed." });
    ok("an account-level emission omits the downpipe fact line from the card", !(accountLevel.html as string).includes("Downpipe:"));
    ok("and omits it from the text part too", !accountLevel.text.includes("Downpipe:"));
    ok("an account-level emission never renders the word null as a fact value", !/>\s*Downpipe:\s*null/.test(accountLevel.html as string));
  }

  // --- (9) contrast, computed on the colours the renderer emitted --------------------------------------
  // Both schemes the card supports: the inline light palette most clients show, and the dark palette the
  // enhancement block restates for clients that honour prefers-color-scheme. Every colour is EXTRACTED
  // from the rendered document, and a colour that cannot be extracted is a failure rather than a skip: a
  // regex that stops matching would otherwise turn this whole section green by measuring nothing.
  console.log("(9) WCAG contrast in both schemes, on the emitted colours");
  {
    const AA_TEXT = 4.5;
    const AA_NON_TEXT = 3;
    let buttonsChecked = 0;
    for (const [id, html] of Object.entries(rendered)) {
      const footerAt = html.indexOf('<tr><td class="dp-footer dp-inner-pad"');
      ok(`${id}: the footer row was located, so header and footer colours are told apart`, footerAt > 0);
      const head = html.slice(0, footerAt);
      const foot = html.slice(footerAt);
      const grab = (re: RegExp, where: string): string | undefined => re.exec(where)?.[1];

      const light = {
        card: grab(/class="dp-card" style="[^"]*background-color:(#[0-9a-f]{6})/i, html),
        text: grab(/class="dp-text" style="[^"]*color:(#[0-9a-f]{6})/i, html),
        heading: grab(/class="dp-heading" style="[^"]*color:(#[0-9a-f]{6})/i, html),
        headAccent: grab(/class="dp-accent" style="[^"]*color:(#[0-9a-f]{6})/i, head),
        footAccent: grab(/class="dp-accent" style="[^"]*color:(#[0-9a-f]{6})/i, foot),
        muted: grab(/class="dp-muted" style="[^"]*color:(#[0-9a-f]{6})/i, foot),
        footerBg: grab(/class="dp-footer dp-inner-pad" style="[^"]*background-color:(#[0-9a-f]{6})/i, html),
        rule: grab(/class="dp-rule" bgcolor="(#[0-9a-f]{6})"/i, html),
      };
      const dark = {
        card: grab(/\.dp-card \{ background-color: (#[0-9a-f]{6})/i, html),
        text: grab(/\.dp-text, \.dp-heading \{ color: (#[0-9a-f]{6})/i, html),
        muted: grab(/\.dp-muted \{ color: (#[0-9a-f]{6})/i, html),
        accent: grab(/\.dp-accent \{ color: (#[0-9a-f]{6})/i, html),
        link: grab(/\.dp-link \{ color: (#[0-9a-f]{6})/i, html),
        footerBg: grab(/\.dp-footer \{ background-color: (#[0-9a-f]{6})/i, html),
      };
      const missing = [...Object.entries(light), ...Object.entries(dark)].filter(([, v]) => v === undefined).map(([k]) => k);
      ok(`${id}: every light and dark colour was extracted from the document (missing: ${missing.length === 0 ? "none" : missing.join(", ")})`, missing.length === 0);
      if (missing.length > 0) continue;

      const pairs: [string, string, string, number][] = [
        ["body prose on the card, light", light.text as string, light.card as string, AA_TEXT],
        ["the heading on the card, light", light.heading as string, light.card as string, AA_TEXT],
        ["the header wordmark on the card, light", light.headAccent as string, light.card as string, AA_TEXT],
        ["the footer wordmark on the footer, light", light.footAccent as string, light.footerBg as string, AA_TEXT],
        ["the footer note on the footer, light", light.muted as string, light.footerBg as string, AA_TEXT],
        ["the accent rule against the card, light", light.rule as string, light.card as string, AA_NON_TEXT],
        ["body prose on the card, dark", dark.text as string, dark.card as string, AA_TEXT],
        ["the wordmark on the card, dark", dark.accent as string, dark.card as string, AA_TEXT],
        ["the wordmark on the footer, dark", dark.accent as string, dark.footerBg as string, AA_TEXT],
        ["the footer note on the footer, dark", dark.muted as string, dark.footerBg as string, AA_TEXT],
        ["an inline link on the card, dark", dark.link as string, dark.card as string, AA_TEXT],
      ];
      for (const [what, fg, bg, floor] of pairs) {
        const ratio = contrastRatio(fg, bg);
        ok(`${id}: ${what} clears ${floor}:1 (actual ${ratio.toFixed(2)}:1)`, ratio >= floor);
      }

      // The CTA label is white inline and is NOT restated by the dark block, so the same pair has to clear
      // the floor against the button fill in both schemes. Only the kinds that emit a button have one.
      const btnBg = grab(/class="dp-btn" bgcolor="(#[0-9a-f]{6})"/i, html);
      const btnFg = grab(/font-weight:600;color:(#[0-9a-f]{6});text-decoration:none;/i, html);
      const btnDark = grab(/\.dp-btn \{ background-color: (#[0-9a-f]{6})/i, html);
      if (kinds[id]?.cta !== undefined) {
        ok(`${id}: the button's own colours were extracted`, btnBg !== undefined && btnFg !== undefined && btnDark !== undefined);
        if (btnBg !== undefined && btnFg !== undefined && btnDark !== undefined) {
          buttonsChecked++;
          const lightRatio = contrastRatio(btnFg, btnBg);
          const darkRatio = contrastRatio(btnFg, btnDark);
          ok(`${id}: the CTA label clears ${AA_TEXT}:1 on the button, light (actual ${lightRatio.toFixed(2)}:1)`, lightRatio >= AA_TEXT);
          ok(`${id}: the CTA label clears ${AA_TEXT}:1 on the button, dark (actual ${darkRatio.toFixed(2)}:1)`, darkRatio >= AA_TEXT);
        }
      } else {
        ok(`${id}: no button colours to extract, because this kind emits no button`, btnBg === undefined && btnFg === undefined);
      }
    }
    ok(`at least one kind's button was graded (${buttonsChecked} of them), so the button pairs are exercised`, buttonsChecked > 0);
  }

  // --- (10) progressive enhancement -------------------------------------------------------------------
  // The module claims the <style> block is enhancement only. A client that strips it (many do) must still
  // get the whole palette from the inline attributes. Proven by stripping it and re-checking the colours,
  // not by reading the sentence in the header.
  console.log("(10) the card survives a client that strips the enhancement <style> block");
  for (const [id, html] of Object.entries(rendered)) {
    const stripped = html.replace(/<style>[\s\S]*?<\/style>/, "");
    ok(`${id}: the style block was actually removed (the strip itself is exercised)`, stripped.length < html.length && !stripped.includes("prefers-color-scheme"));
    ok(`${id}: the page and card backgrounds are still inline`, /style="margin:0;padding:0;background-color:#[0-9a-f]{6};"/i.test(stripped) && /class="dp-card" style="[^"]*background-color:#[0-9a-f]{6}/i.test(stripped));
    ok(`${id}: the prose colour and font are still inline`, /class="dp-text" style="font-family:[^"]*color:#[0-9a-f]{6};/i.test(stripped));
    ok(`${id}: the heading, wordmark and footer note are still inline`, /class="dp-heading" style="[^"]*color:#[0-9a-f]{6};/i.test(stripped) && /class="dp-accent" style="[^"]*color:#[0-9a-f]{6};/i.test(stripped) && /class="dp-muted" style="[^"]*color:#[0-9a-f]{6};/i.test(stripped));
    ok(`${id}: the card is still capped at 560px without the style block`, stripped.includes("max-width:560px"));
    ok(`${id}: the heading survives the strip`, stripped.includes(`>${(kinds[id] as EngineEmailInput).heading}</h1>`));
  }

  // --- (11) the hidden preheader ----------------------------------------------------------------------
  console.log("(11) preheader discipline");
  {
    const long = "x".repeat(400);
    const doc = renderEngineEmailHtml({ heading: "H", paragraphs: [`  ${long}  `] });
    const preheader = /mso-hide:all;font-size:1px;line-height:1px;color:#[0-9a-f]{6};">([^<]*)</i.exec(doc)?.[1];
    ok("the preheader div was found", typeof preheader === "string");
    const visible = (preheader ?? "").split("&#160;&#8204;")[0] as string;
    ok(`the preheader is capped at 140 characters (actual ${visible.length})`, visible.length === 140);
    ok("the preheader is padded so the client snippet does not run into the body copy", (preheader ?? "").includes("&#160;&#8204;"));
    const collapsed = renderEngineEmailHtml({ heading: "H", paragraphs: ["  a \n\n b  "] });
    ok("the preheader collapses whitespace and trims", /line-height:1px;color:#[0-9a-f]{6};">a b&#160;/i.test(collapsed));
    ok("the preheader defaults to the first paragraph", renderEngineEmailHtml({ heading: "H", paragraphs: ["first para"] }).includes(">first para&#160;"));
    ok("an explicit preheader overrides the first paragraph", renderEngineEmailHtml({ heading: "H", paragraphs: ["first para"], preheader: "own line" }).includes(">own line&#160;"));
    ok("a card with no paragraphs falls back to the heading", renderEngineEmailHtml({ heading: "Only the heading", paragraphs: [] }).includes(">Only the heading&#160;"));
    ok("the preheader is escaped like everything else", renderEngineEmailHtml({ heading: "H", paragraphs: ["<b>x</b>"] }).includes("&lt;b&gt;x&lt;/b&gt;"));
  }

  console.log(failures === 0 ? "\nEMAIL THEME PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
