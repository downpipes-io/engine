// The frozen acceptance statements for the key-posture choice (onboarding fork + the Keys-screen
// posture actions). This module is the SINGLE SOURCE of the exact words a customer confirms when
// they choose or change their recovery posture, so the acknowledgement recorded in the tamper-
// evident audit log binds a known, versioned text: the audit target carries the statement VERSION
// and the SHA-384 of the text, never the free-form text itself, and this constant is what that
// hash is computed over. The console ships the SAME strings (mirrored, with a parity gate on both
// sides asserting the shared hash), so what the customer READ is provably what the engine RECORDED.
//
// Editing a statement's words is a NEW VERSION: bump the version id and regenerate the vector,
// never edit v1's text in place (an edited-in-place text would make every historical v1 ack refer
// to words that were never shown).

import { sha384 } from "../crypto/primitives.ts";
import { hexEncode, utf8 } from "../crypto/bytes.ts";

// PostureChoice is the two recovery postures a customer can acknowledge. "operational" installs the
// in-account operational key (automated proof, a decryption-capable key in the engine); "break-glass-
// only" installs no operational key (manual proof only, nothing in the engine can decrypt at rest).
export type PostureChoice = "operational" | "break-glass-only";

// PostureAckChannel is where the acknowledgement was captured: the first-run onboarding fork, or a
// later posture change on the Keys screen. Recorded so an onboarding acknowledgement (often taken
// under the bootstrap token, low evidentiary weight) is distinguishable from a named-owner Keys-
// screen acknowledgement.
export type PostureAckChannel = "onboarding" | "keys-rekey";

// PostureAckPrincipalType is the resolved evidentiary weight of the actor: an owner who authenticated
// with a passkey (strongest), a named operator (an Access/IdP identity), or the bare bootstrap admin
// token (weakest, unattributable to a person). The router derives it from the caller's auth method;
// it rides the audit target so a bootstrap-token acknowledgement never reads as a named one.
export type PostureAckPrincipalType = "owner-passkey" | "named-operator" | "bootstrap-admin-token";

// PostureAckStatement is a versioned acceptance text. The version is bumped on any wording change so
// a recorded hash always refers to the exact words that were shown.
export interface PostureAckStatement {
  version: string;
  text: string;
}

// POSTURE_ACK_STATEMENTS holds the current acceptance statement for each posture. Each statement
// RESTATES the specific residual inline (never a generic "I have read the implications"), so the
// recorded artefact proves the exact risk was put in front of the customer at the moment they
// confirmed. The offline statement names what genuinely still stops (reopening a run the engine sealed
// EARLIER without the customer present, so scheduled restore tests and pruning do not run in the engine),
// so the safer-sounding posture is not chosen for a security halo.
//
// v2 corrects a clause that had gone stale under the code. v1 listed "in-console restore"
// among the things that do not run, and that stopped being true when the in-console break-glass restore
// landed: restore now opens a run from a browser-supplied per-run master and refuses only when there is
// NEITHER an operational key NOR a supplied master (admin/restore.ts, the `!env.OPERATIONAL_PRIVATE &&
// master === undefined` gate). So an offline-key-only estate keeps in-console restore, attended.
//
// The direction of the error is the reason it is worth a version rather than a note. v1 overstated the
// cost of the strict posture, telling customers they gave up something they keep, on the one screen where
// they decide between the two. A statement that talks people out of the stronger custody posture by being
// wrong about it is not a safe kind of wrong.
export const POSTURE_ACK_STATEMENTS: Record<PostureChoice, PostureAckStatement> = {
  operational: {
    version: "key-posture-ack/v1",
    text: "I am enabling an operational key. It is stored as a secret in my own engine, in my own Cloudflare account, and it can decrypt my stored archives. I understand that if my Cloudflare account is compromised, or a malicious platform update runs in my engine, my stored archives could be read. I understand that removing this key later does not protect archives already sealed while it was present, because each archive is wrapped to the keys in force when it was written. I am accepting this so my engine can reopen and restore-test runs it sealed earlier without me present.",
  },
  "break-glass-only": {
    version: "key-posture-ack/v2",
    text: "I am choosing an offline key only. My engine will hold no key that can decrypt my stored archives. It will still verify each run as it seals it, and prove its own test data recoverable every hour, but it cannot reopen a run it sealed earlier without me. Scheduled restore tests and retention pruning therefore do not run in my engine, and I am responsible for pruning my own archives with the offline reader, supplying my break-glass key at the time. Restoring from the console still works with me present, supplying my break-glass key in my browser, and I am also responsible for proving past runs restorable at an attended verification. If I lose that key my backups cannot be recovered.",
  },
};

// postureAckStatementHash returns the "sha384:"-prefixed hex SHA-384 of a statement's text, the value
// the audit target carries so the tamper-evident chain binds WHICH words were acknowledged without
// storing the words. The console computes the same value over its mirrored copy; the shared vector
// gate asserts the two agree.
export async function postureAckStatementHash(text: string): Promise<string> {
  return `sha384:${hexEncode(await sha384(utf8(text)))}`;
}

// resolvePostureAckStatement returns the current statement for a posture, or null when the requested
// version does not match the current one (a stale console posting an old version is refused rather
// than silently recorded against today's words).
export function resolvePostureAckStatement(posture: PostureChoice, version: string): PostureAckStatement | null {
  const s = POSTURE_ACK_STATEMENTS[posture];
  if (!s || s.version !== version) return null;
  return s;
}
