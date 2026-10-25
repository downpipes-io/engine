// The SHIPPED wrangler.toml names the vendor update channel on its canonical host.
//
// A customer may move UPDATE_CHANNEL_URL into a Worker secret and comment the line out; the customer
// preflight (test/validate-updates.ts) accepts that form. This validator grades the repository's own
// shipped config, so it runs in engine CI and on the release path, not in the customer's tree.
//
// Run: node test/validate-shipped-update-channel.ts

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CANONICAL_UPDATE_HOST, gradeChannelLine } from "./lib/update-channel-toml.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A shipped tree is read through `read`, so the negative controls below run the same check over synthetic trees.
function shippedChannelOk(read: (relPath: string) => string | null): boolean {
  const text = read("wrangler.toml");
  return text !== null && gradeChannelLine(text).state === "canonical";
}

const ENGINE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const readReal = (relPath: string): string | null => {
  try {
    return readFileSync(join(ENGINE_DIR, relPath), "utf8");
  } catch {
    return null;
  }
};

const real = readReal("wrangler.toml");
ok("shipped wrangler.toml is present", real !== null);
const graded = real === null ? null : gradeChannelLine(real);
ok("shipped wrangler.toml sets UPDATE_CHANNEL_URL (an active line)", graded !== null && graded.state !== "secret");
ok(`shipped UPDATE_CHANNEL_URL names the canonical host "${CANONICAL_UPDATE_HOST}"`, graded !== null && graded.state === "canonical");

// NEGATIVE CONTROLS: the check must fail over a shipped tree that is wrong.
ok("control: a shipped tree whose wrangler.toml lacks the line FAILS", !shippedChannelOk(() => 'name = "x"\n# UPDATE_CHANNEL_URL = "https://update.downpipes.io/stable.json"\n'));
ok("control: a shipped tree with a non-canonical host FAILS", !shippedChannelOk(() => 'UPDATE_CHANNEL_URL = "https://updates.downpipes.io/stable.json"\n'));
ok("control: a shipped tree with no wrangler.toml FAILS", !shippedChannelOk(() => null));
for (const [label, line] of [
  ["single-quoted value", "UPDATE_CHANNEL_URL = 'https://update.downpipes.io/stable.json'\n"],
  ["triple-quoted value", 'UPDATE_CHANNEL_URL = """https://update.downpipes.io/stable.json"""\n'],
  ["quoted key", '"UPDATE_CHANNEL_URL" = "https://update.downpipes.io/stable.json"\n'],
  ["second active line", 'UPDATE_CHANNEL_URL = "https://update.downpipes.io/stable.json"\nUPDATE_CHANNEL_URL = "https://evil.example/x"\n'],
  ["userinfo", 'UPDATE_CHANNEL_URL = "https://update.downpipes.io@evil.example/stable.json"\n'],
  ["http scheme", 'UPDATE_CHANNEL_URL = "http://update.downpipes.io/stable.json"\n'],
  ["uppercase host", 'UPDATE_CHANNEL_URL = "https://UPDATE.DOWNPIPES.IO/stable.json"\n'],
  ["hex-escaped quoted key", '"UPDATE_CHANNEL\\x5fURL" = "https://evil.example/x"\nUPDATE_CHANNEL_URL = "https://update.downpipes.io/stable.json"\n'],
  ["unicode-escaped quoted key", '"UPDATE_CHANNEL\\u005fURL" = "https://evil.example/x"\nUPDATE_CHANNEL_URL = "https://update.downpipes.io/stable.json"\n'],
  ["escape-decoded quoted key of another name", '"\\x55PDATE_CHANNEL_URL" = "https://evil.example/x"\nUPDATE_CHANNEL_URL = "https://update.downpipes.io/stable.json"\n'],
  ["port", 'UPDATE_CHANNEL_URL = "https://update.downpipes.io:8443/stable.json"\n'],
] as const) ok(`control: a shipped tree with a ${label} FAILS`, !shippedChannelOk(() => line));
ok("control: a canonical shipped tree with a multi-line array of bare quoted elements still passes", shippedChannelOk(() => 'compatibility_flags = [\n  "nodejs_compat",\n]\nUPDATE_CHANNEL_URL = "https://update.downpipes.io/stable.json"\n'));
ok("control: a canonical shipped tree passes", shippedChannelOk(() => 'UPDATE_CHANNEL_URL = "https://update.downpipes.io/stable.json"\n'));

console.log(failures === 0 ? "\nSHIPPED UPDATE CHANNEL PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
