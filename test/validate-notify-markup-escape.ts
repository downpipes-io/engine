// validate-notify-markup-escape: a downpipe NAME cannot become active markup in a Slack or Teams alert.
//
// WHY THIS FILE EXISTS. ASVS V1.3.3 asks that data passed to a potentially dangerous context is sanitised
// for that context. The Slack and Teams sinks render the emission detail, and the detail is built from the
// downpipe name (`${name} backup succeeded`, and its siblings), which config-validate bounds by LENGTH only.
// Measured against the real adapters before this fix: the name
//   <!channel> <https://evil.example|Open the restore console>
// produced a Slack payload carrying it verbatim in both the text and the mrkdwn block (a channel-wide ping
// and a labelled phishing link), and a Teams card whose markdown text carried `[click](https://evil.example)`
// as a live link. An operator with downpipe.write could put that into every alert the channel carries.
//
// EVERY ABSENCE HERE HAS A CONTROL: the raw detail is asserted to CONTAIN the payload first, so the escaped
// output's lack of it is a measurement rather than a probe that never saw the characters.

import { format as slackFormat } from "../src/notify/channels/slack.ts";
import { formatCard } from "../src/notify/channels/teams.ts";
import type { NotifyEmission } from "../src/notify/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

const NAME = "<!channel> <https://evil.example|Open the restore console> [click](https://evil.example) & co";
const emission = { event: "backup-failure", severity: "critical", downpipeId: "dp-1", detail: `${NAME} last run failed`, ts: "2026-09-11T00:00:00.000Z" } as unknown as NotifyEmission;

console.log("\nSlack: the three entity escapes the API requires, on text and on the mrkdwn block");
{
  ok("CONTROL: the raw detail carries the channel ping and the labelled link", emission.detail.includes("<!channel>") && emission.detail.includes("<https://evil.example|"));
  const p = slackFormat(emission);
  const bodies = [p.text, ...(p.blocks ?? []).map((b) => b.text.text)];
  ok("both bodies were rendered", bodies.length === 2);
  for (const [i, b] of bodies.entries()) {
    ok(`body ${i}: no raw '<' survives`, !b.includes("<"));
    ok(`body ${i}: no raw '>' survives`, !b.includes(">"));
    ok(`body ${i}: the ping is entity-escaped, so Slack shows the characters rather than acting on them`, b.includes("&lt;!channel&gt;"));
    ok(`body ${i}: the labelled link is entity-escaped`, b.includes("&lt;https://evil.example|Open the restore console&gt;"));
    ok(`body ${i}: a bare ampersand is escaped exactly once (no double escaping)`, b.includes("&amp; co") && !b.includes("&amp;amp;"));
  }
  ok("the closed-vocabulary event label still renders as mrkdwn bold", (p.blocks ?? [])[0]!.text.text.startsWith("*backup-failure*"));
}

console.log("\nTeams: the MessageCard renders the detail literally, not as markdown");
{
  ok("CONTROL: the raw detail carries a markdown link", emission.detail.includes("[click](https://evil.example)"));
  const c = formatCard(emission) as unknown as { markdown?: boolean; text: string; title: string };
  ok("markdown rendering is switched off on the card", c.markdown === false);
  ok("the text is carried as typed (the card, not the sender, is what neutralises it)", c.text === emission.detail);
  ok("the title is built from closed vocabularies only, never the detail", !c.title.includes("evil.example"));
}

console.log(failures === 0 ? "\nNOTIFY MARKUP ESCAPE VECTORS PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
