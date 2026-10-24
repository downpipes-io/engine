// Grades the UPDATE_CHANNEL_URL line of a wrangler config. Shared by the customer preflight member
// (test/validate-updates.ts) and the shipped-config validator (test/validate-shipped-update-channel.ts) so
// both parse the line one way.
//
// A customer may keep the channel URL as a Worker secret (`wrangler secret put UPDATE_CHANNEL_URL`) with the
// line commented out or removed; the runtime then pins the host to update.downpipes.io (checkUpdates).
//
// FAIL CLOSED. The only recognised active form is `UPDATE_CHANNEL_URL = "<url>"` (an optional trailing
// comment is allowed). Any other non-comment line that names the key (single or triple quotes, a quoted key,
// an unquoted value, an inline table, a quoted key assignment, an escape in a line naming UPDATE_) is drift, and so is a second line naming it. The secret form is "no
// non-comment line names the key".

export const CANONICAL_UPDATE_HOST = "update.downpipes.io";

export type ChannelLineState =
  | { state: "secret"; reason: string }
  | { state: "canonical"; host: string }
  | { state: "drift"; reason: string };

const QUOTED_KEY_ASSIGNMENT = /^[ \t]*(?:"(?:[^"\\]|\\.)*"|'[^']*')[ \t]*=/;
const RECOGNISED = /^[ \t]*UPDATE_CHANNEL_URL[ \t]*=[ \t]*"([^"]*)"[ \t]*(#.*)?$/;
// https, no userinfo, no port, the host exactly as written in lowercase, then an optional path.
const CANONICAL_URL = /^https:\/\/update\.downpipes\.io(\/[^\s\\@]*)?$/;

/** Grades one wrangler config text. */
export function gradeChannelLine(tomlText: string): ChannelLineState {
  const lines = tomlText.split(/\r?\n/).filter((line) => !/^[ \t]*#/.test(line));
  // A quoted key can spell the name with escapes (\x5f, \u005f) that no text match on the name sees. A quoted
  // KEY ASSIGNMENT (a quoted string, optional spaces, then "=") is drift whatever it names, and so is any
  // line naming UPDATE_ that carries a backslash. A bare quoted array element on its own line is not a key.
  if (lines.some((line) => QUOTED_KEY_ASSIGNMENT.test(line) || (line.includes("UPDATE_") && line.includes("\\")))) {
    return { state: "drift", reason: "a quoted key assignment, or an escape in a line naming UPDATE_ (a quoted key can spell UPDATE_CHANNEL_URL with escapes)" };
  }
  const naming = lines.filter((line) => line.includes("UPDATE_CHANNEL_URL"));
  if (naming.length === 0) {
    return { state: "secret", reason: `UPDATE_CHANNEL_URL is a Worker secret here; the runtime pins its host to ${CANONICAL_UPDATE_HOST}` };
  }
  if (naming.length > 1) return { state: "drift", reason: "more than one line names UPDATE_CHANNEL_URL" };
  const m = naming[0]!.match(RECOGNISED);
  if (m === null || m[1] === undefined) return { state: "drift", reason: 'the UPDATE_CHANNEL_URL line is not the form UPDATE_CHANNEL_URL = "<url>"' };
  if (!CANONICAL_URL.test(m[1])) return { state: "drift", reason: `UPDATE_CHANNEL_URL is not https://${CANONICAL_UPDATE_HOST}/...` };
  return { state: "canonical", host: CANONICAL_UPDATE_HOST };
}
