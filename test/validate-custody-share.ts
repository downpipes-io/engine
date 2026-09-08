// Validate the custody-share email route's render + sanitise layer (src/admin/router-custody.ts).
//
// This route is the ONE sanctioned exception to the email primitive's "never a key" boundary: it emails a
// single Shamir share of the customer's split break-glass key. A share below the reconstruction threshold
// is information-theoretically null, and the ciphertext (the envelope over identity.key) never reaches the
// engine (S1), so the send is safe. That safety rests on a few load-bearing properties this test pins:
//
//   1. Body-only. buildShareEmail returns EXACTLY { subject, text, html } -- no attachment surface (B1).
//   2. Static subject. The subject is a fixed string that never carries the share, the label, or the counts,
//      so no operator-controlled or secret value can land in a header (M3a: header-injection surface closed).
//   3. HTML escaping. The one operator-controlled string in the HTML body (the custodian label) is escaped,
//      so a crafted label cannot inject markup into the email (M3b).
//   4. The share is actually delivered in the body (text AND html), with the custodian save-then-delete
//      instructions and the "reveals nothing on its own" framing (the honest-copy requirement, B3).
//   5. Label sanitisation. cleanLabel strips control characters (CR/LF/DEL and friends) and bounds length,
//      so a label cannot smuggle a newline toward a header or blow up the body.
//   6. SHARE_BYTES is 33 (1 index byte + 32 payload), the console Shamir share size the route re-validates.
//   7. An over-length custodian name is REFUSED rather than shortened, because the label NAMES A PERSON on
//      an email that person reads, and every legal name including one at exactly the bound is still accepted.
//   8. The label is cleaned BEFORE it is capped, so what the route accepts is what the custodian is emailed.
//
// Run with `node test/validate-custody-share.ts`.

import { handleAdmin } from "../src/admin/router.ts";
import { buildShareEmail, cleanLabel, custodianLabelRejection, SHARE_BYTES } from "../src/admin/router-custody.ts";
import { DEFAULT_FOOTER_NOTE } from "../src/email-theme.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
// This suite is SILENT ON PASS and writes its FAIL lines to stderr, so a run that asserted 40 things
// and a run that asserted none look identical on stdout. That makes it invisible to both halves of a
// verification: the exit code still works, but nothing in the log says how much was checked. Counting
// the checks and handing the count to the guard puts it on the canonical VERDICT line.
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  if (!cond) {
    failures++;
    console.error(`FAIL: ${label}`);
  }
}

// A representative share for the RENDER layer. Value and length are irrelevant there (buildShareEmail never
// measures it); only its presence in the body is asserted. It decodes to 32 bytes, NOT 33, so it is not a
// share the ROUTE would accept, and section 9 uses its own correctly-sized one below. Getting that wrong is
// what made every route assertion fail on the share rather than on its subject, while the status-only
// assertion still read 400 and passed for the wrong reason.
const SHARE = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
// SHARE_33 decodes to exactly SHARE_BYTES, so the route's length rule passes and the label is actually
// reached. It is 33 arbitrary bytes, not a Shamir share of any real key.
const SHARE_33 = "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj";

function main(): void {
  ok(`SHARE_BYTES is 33 (1 index + 32 payload)`, SHARE_BYTES === 33);

  // --- 1. Body-only: exactly subject/text/html, no attachment or any extra field (B1). ---
  const mail = buildShareEmail(SHARE, 5, 3, "Alice (CFO)");
  const keys = Object.keys(mail).sort();
  ok(`buildShareEmail returns exactly {subject,text,html} (no attachment surface)`, keys.length === 3 && keys[0] === "html" && keys[1] === "subject" && keys[2] === "text");

  // --- 2. Static subject: fixed, and free of the share, the label, and the counts (M3a). ---
  const a = buildShareEmail(SHARE, 5, 3, "Alice (CFO)");
  const b = buildShareEmail("ZZZdifferentShareZZZ", 7, 4, "Bob <ops@corp>");
  ok(`subject is a fixed constant across different inputs`, a.subject === b.subject);
  ok(`subject carries no share value`, !a.subject.includes(SHARE) && !b.subject.includes("ZZZdifferentShareZZZ"));
  ok(`subject carries no custodian label`, !a.subject.includes("Alice") && !b.subject.includes("Bob"));
  ok(`subject carries no counts (n/m stay in the body)`, !/\d/.test(a.subject));
  // A subject with no CR/LF cannot terminate a header line.
  ok(`subject has no CR/LF`, !/[\r\n]/.test(a.subject));

  // --- 3. HTML escaping of the operator-controlled label (M3b). ---
  const hostile = buildShareEmail(SHARE, 3, 2, `<script>alert(1)</script>"'&`);
  ok(`hostile label does not appear raw in the HTML body`, !hostile.html.includes("<script>alert(1)</script>"));
  ok(`hostile label's angle brackets are escaped in HTML`, hostile.html.includes("&lt;script&gt;"));
  ok(`hostile label's quote and ampersand are escaped in HTML`, hostile.html.includes("&quot;") && hostile.html.includes("&#39;") && hostile.html.includes("&amp;"));
  // The share is base64url (closed alphabet), so it needs no escaping, but it must be present verbatim.
  ok(`the share appears verbatim in the HTML body`, hostile.html.includes(SHARE));

  // --- 4. The share is delivered, with the custodian instructions and honest framing (B3). ---
  ok(`share appears in the plain-text body`, mail.text.includes(SHARE));
  ok(`text tells the custodian to use a password manager (Bitwarden named)`, /password manager/i.test(mail.text) && /Bitwarden/.test(mail.text));
  ok(`text tells the custodian to delete the email`, /delete this email/i.test(mail.text));
  ok(`text states a single share reveals nothing on its own`, /reveals nothing/i.test(mail.text));
  ok(`text states the m-of-n threshold (any 3 of the 5)`, mail.text.includes("3") && mail.text.includes("5") && /reconstruct/i.test(mail.text));
  ok(`html carries the same save-then-delete instructions`, /password manager/i.test(mail.html) && /delete this email/i.test(mail.html) && /Bitwarden/.test(mail.html));

  // --- 4b. It is the ENGINE'S card, not a second renderer, and it carries NO VENDOR IDENTITY. ---
  //
  // This message leaves the CUSTOMER'S engine over the CUSTOMER'S sending domain to a custodian the
  // customer chose, and a prior version carried a personal sign-off naming the vendor.
  // email-theme.ts states the rule for this whole class of mail in its own header, and it binds hardest
  // here: the custody design turns on Maelstrom receiving nothing, so a recovery-share email signed by
  // the vendor invites a custodian to read vendor involvement into a ceremony the vendor has no part in.
  // Asserted on BOTH parts, because the sign-off was in both.
  ok(`no vendor sign-off in either part (engine mail carries no vendor identity)`, !/Maelstrom/.test(mail.text) && !/Maelstrom/.test(mail.html));
  ok(`both parts close with the theme's neutral automated-message line`, mail.text.includes(DEFAULT_FOOTER_NOTE) && mail.html.includes(DEFAULT_FOOTER_NOTE));
  // The card itself, not a copy of it. Each of these was ABSENT from the hand-rolled renderer this
  // replaced, and each is why it rendered differently from every other downpipes email.
  ok(`the html part is the engine card: capped at 560px, not a fixed 480px table`, mail.html.includes("max-width:560px") && !mail.html.includes('width="480"'));
  ok(`the html part declares a charset, a language and both colour schemes`, mail.html.includes('<meta charset="utf-8">') && mail.html.includes('<html lang="en">') && mail.html.includes('name="color-scheme" content="light dark"'));
  ok(`the html part carries dark-scheme rules, so it does not stay a light card in a dark client`, mail.html.includes("prefers-color-scheme: dark"));
  ok(`the html part relaxes its padding on a narrow screen (it must fit a phone)`, mail.html.includes("max-width: 600px") && mail.html.includes("dp-inner-pad"));
  ok(`the accent is the brand indigo the licensing pack uses, not the superseded slate`, mail.html.includes("#3b66f0") && !mail.html.includes("#34506c"));
  ok(`the instructions are a REAL ordered list, so they survive a client that strips every style`, mail.html.includes("<ol") && mail.html.split("<li").length === 4);
  ok(`the share sits in the monospace well and can wrap inside the card`, mail.html.includes("ui-monospace") && mail.html.includes("overflow-wrap:anywhere"));
  // A share email must carry NO link at all: there is nothing for a custodian to click, and a link is
  // the one thing a phishing copy of this message would need.
  // The button is matched on the ELEMENT it renders, not on the class name: .dp-btn also appears as a
  // rule inside the progressive-enhancement <style> block of every card, button or not, so asserting on
  // the class alone would have failed here for a reason that has nothing to do with this message.
  ok(`the html part carries no link and no button`, !mail.html.includes("<a href=") && !mail.html.includes('<td class="dp-btn"'));
  // The plain-text part is WRAPPED. It used to be emitted as unwrapped logical lines, one of them 175
  // characters, so a client that does not soft-wrap made a custodian scroll sideways. The share is the
  // one line allowed to run long: it is a single token and a break in it would look like part of the value.
  {
    // Measured over the PROSE lines only, with the share line removed by identity rather than by length:
    // this file's fixture share is 43 characters, so a check that required exactly one overlong line
    // would have been asserting about the fixture's width and not about the wrapper. A long share is
    // covered beside it, where the wrapper must leave the token whole.
    const proseOver = mail.text.split("\n").filter((l) => l !== SHARE && l.length > 72);
    ok(`every prose line in the text part wraps at 72 columns`, proseOver.length === 0);
    const longShare = "Z".repeat(200);
    const wide = buildShareEmail(longShare, 5, 3, "Alice (CFO)");
    ok(`a share longer than the wrap column is left whole, never broken across lines`, wide.text.split("\n").includes(longShare));
    ok(`and that is the ONLY line allowed past the column (the check is exercised)`, wide.text.split("\n").filter((l) => l.length > 72).length === 1);
  }

  // --- 5. cleanLabel strips control characters and bounds length. ---
  ok(`cleanLabel strips CR/LF (no header-injection via the label)`, cleanLabel("Alice\r\nBcc: evil@x.com") === "AliceBcc: evil@x.com");
  ok(`cleanLabel strips tab and DEL`, cleanLabel("a\tb\x7fc") === "abc");
  ok(`cleanLabel strips a NUL and other C0 controls`, cleanLabel("a\x00b\x1bc") === "abc");
  ok(`cleanLabel trims surrounding whitespace`, cleanLabel("   Alice   ") === "Alice");
  ok(`cleanLabel bounds length to 120`, cleanLabel("x".repeat(500)).length === 120);
  ok(`cleanLabel returns "" for a non-string`, cleanLabel(undefined) === "" && cleanLabel(42) === "" && cleanLabel(null) === "");
  ok(`cleanLabel keeps a normal unicode label intact`, cleanLabel("Zoë O'Brien") === "Zoë O'Brien");

  // --- 6. An empty label degrades gracefully (no "for undefined"). ---
  const noLabel = buildShareEmail(SHARE, 4, 2, "");
  ok(`empty label produces no dangling "for" phrase in text`, !/ for \s*$/m.test(noLabel.text) && !noLabel.text.includes("for  "));
  ok(`empty label still renders a valid body with the share`, noLabel.text.includes(SHARE) && noLabel.html.includes(SHARE));

  // --- 7. An over-length custodian name is REFUSED, not shortened. ---
  //
  // The label is IDENTITY: it is printed on the share email as the name of the person holding the share, and
  // the custodian reads it. Before this, a 121-character name was silently cut to 120 and emailed, and the
  // route answered exactly as it did when no label was sent at all, so nothing anywhere said the name had
  // been changed. A truncated name is not a rejected one: it looks valid, it sends without complaint, and it
  // fails the only job it has.
  //
  // The bound is the console field's own bound, enforced inline and again at Send, so no console caller is
  // newly refused; what this closes is every OTHER caller, for whom the shortening was silent.
  const L = (n: number): string => "x".repeat(n);
  ok(`custodianLabelRejection refuses 121 characters`, custodianLabelRejection(L(121)) !== null);
  ok(`the refusal names the custodian name and the bound`, /custodian name must be 120 characters or fewer/.test(custodianLabelRejection(L(121)) ?? ""));
  ok(`the refusal says it is refused rather than shortened`, /refused rather than shortened/.test(custodianLabelRejection(L(121)) ?? ""));
  // NO OVER-REFUSAL, including exactly at the boundary.
  ok(`custodianLabelRejection accepts exactly 120 characters (the boundary itself)`, custodianLabelRejection(L(120)) === null);
  ok(`custodianLabelRejection accepts 119 characters`, custodianLabelRejection(L(119)) === null);
  ok(`custodianLabelRejection accepts an ordinary name`, custodianLabelRejection("Alex Chen, Security") === null);
  ok(`custodianLabelRejection accepts a blank, an absent and a non-string label`, custodianLabelRejection("") === null && custodianLabelRejection(undefined) === null && custodianLabelRejection(42) === null);
  // The length is measured on the CLEANED value, so surrounding whitespace cannot push a legal name over.
  ok(`custodianLabelRejection measures the CLEANED label, so 120 characters padded with spaces is accepted`, custodianLabelRejection(`   ${L(120)}   `) === null);

  // --- 8. Clean BEFORE cap, so an accepted label is emailed equal to its cleaned form. ---
  //
  // cleanLabel used to slice to 120 and strip control characters afterwards, so a legal 120-character name
  // carrying any control character was quietly emailed as 119 or fewer. That is the same cap-before-clean
  // shape found on the change-number normaliser, and it was found here by the control that proves a legal
  // value at exactly the boundary is still accepted rather than by looking for it.
  ok(`a control character does not eat a character of a legal 120-character label`, cleanLabel(`\x00${L(120)}`) === L(120));
  ok(`a legal 120-character label behind a control character is NOT refused`, custodianLabelRejection(`\x00${L(120)}`) === null);
  ok(`what is accepted is emailed equal to its cleaned form (the slice is a no-op on an accepted label)`, cleanLabel(`  Zoë O'Brien\x1b  `) === "Zoë O'Brien" && custodianLabelRejection(`  Zoë O'Brien\x1b  `) === null);
  // And a genuinely over-length label is still bounded by cleanLabel for any caller that skipped the twin.
  ok(`cleanLabel still bounds a 500-character label to 120 (defence in depth)`, cleanLabel(L(500)).length === 120);
  ok(`a label that is 121 printable characters only after cleaning is refused`, custodianLabelRejection(`\x00${L(121)}`) !== null);

  console.log(failures === 0 ? "\nCUSTODY-SHARE (ENGINE) VECTORS PASS" : `\n${failures} FAILURE(S)`);
}

// --- 9. The ROUTE, driven. -----------------------------------------------------------------------------
//
// Sections 7 and 8 pin the rule. This one pins that POST /custody/send-share actually APPLIES it, which is
// the half a unit test cannot see: the defect was never that the bound did not exist, it was that the route
// shortened instead of refusing and answered exactly as it did when no label was sent at all.
//
// It drives the PRODUCTION handleAdmin over an in-memory SchedulerDO on the break-glass token path (no Access
// harness needed). The EMAIL binding is an in-process capture, so nothing leaves this process and the
// assertions can read the body the custodian would actually be sent.
async function route(): Promise<void> {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = {
    fetch: async (i: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(typeof i === "string" ? i : i instanceof URL ? i.toString() : i.url, init)),
  } as unknown as DurableObjectStub;
  const ns = { idFromName: (_n: string) => ({}) as unknown as DurableObjectId, get: (_id: DurableObjectId) => stub } as unknown as DurableObjectNamespace;
  let captured: { text?: string } | null = null;
  const env = {
    SCHEDULER: ns,
    ADMIN_TOKEN: "custody-share-test-token",
    EMAIL: { send: async (p: { text?: string }) => { captured = p; } },
    EMAIL_FROM: "ops@acme.example",
  } as unknown as Env;

  const send = async (label: unknown, shareB64: string = SHARE_33): Promise<{ status: number; error: string; text: string }> => {
    captured = null;
    const body: Record<string, unknown> = { toEmail: "custodian@acme.example", shareB64, n: 3, m: 2 };
    if (label !== undefined) body.custodianLabel = label;
    const r = await handleAdmin(
      new Request("https://engine.example/admin/custody/send-share", {
        method: "POST",
        headers: { authorization: "Bearer custody-share-test-token", "content-type": "application/json" },
        body: JSON.stringify(body),
      }),
      env,
    );
    const raw = await r.text();
    let error = "";
    try {
      error = ((JSON.parse(raw) as Record<string, unknown>).error as string) ?? "";
    } catch {
      error = raw;
    }
    return { status: r.status, error, text: (captured as { text?: string } | null)?.text ?? "" };
  };

  const NAME_121 = "N".repeat(121);
  const NAME_120 = "M".repeat(120);

  const over = await send(NAME_121);
  ok(`route: a 121-character custodian name is refused 400`, over.status === 400);
  ok(`route: the refusal names the custodian name`, /custodian name must be 120 characters or fewer/.test(over.error));
  ok(`route: a refused name emails NOTHING, so no custodian is named by a shortened string`, over.text === "");

  // PINNING CONTROL. The identical request with the label ABSENT must answer DIFFERENTLY. Before the fix
  // these two were byte-identical 200s, and that identity is precisely what proved the label was never
  // judged; it is now what proves the refusal belongs to the label rather than to the request.
  const absent = await send(undefined);
  ok(`route: PINNING CONTROL: the identical request with the label ABSENT is accepted 200`, absent.status === 200);
  ok(`route: PINNING CONTROL: the over-length case answers differently from the label being absent`, over.error !== "" && over.status !== absent.status);

  // PINNING CONTROL, the other way: a LEGAL name carrying a different fault must answer about that fault,
  // so the refusal cannot be an artefact of "this request was bad".
  const badShare = await send("Alex Chen", "AAAA");
  ok(`route: PINNING CONTROL: a legal name with a bad share answers about the share, not the name`, badShare.status === 400 && /share must be/.test(badShare.error) && badShare.error !== over.error);

  // NO OVER-REFUSAL, at the boundary and inside it, read off the body the custodian would receive.
  const atBound = await send(NAME_120);
  ok(`route: NO OVER-REFUSAL: a name of exactly 120 characters is accepted and emailed in full`, atBound.status === 200 && atBound.text.includes(NAME_120));
  const ordinary = await send("Alex Chen, Security");
  ok(`route: NO OVER-REFUSAL: an ordinary name is accepted and emailed verbatim`, ordinary.status === 200 && ordinary.text.includes("Alex Chen, Security"));
  ok(`route: NO OVER-REFUSAL: a blank name is accepted`, (await send("")).status === 200);
  // The cap-before-clean defect, at the route: 120 printable characters behind a control character clean to
  // exactly 120, so they are legal, and all 120 must reach the email.
  const padded = await send(`\x00${NAME_120}`);
  ok(`route: a control character does not shorten a legal 120-character name`, padded.status === 200 && padded.text.includes(NAME_120));
  // And the header-injection strip still runs on the value that is accepted.
  const crlf = await send("Alice\r\nBcc: evil@x.example");
  ok(`route: the control-character strip still holds on an accepted name`, crlf.status === 200 && !/Alice\r\n/.test(crlf.text) && crlf.text.includes("AliceBcc: evil@x.example"));

  console.log(failures === 0 ? "CUSTODY-SHARE ROUTE VECTORS PASS" : `${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
await route();
