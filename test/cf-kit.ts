// Which credential kit the live harnesses read, and the safety rule that goes with it.
//
// Every live harness used to hardcode the throwaway proving account's kit directory. That was fine while
// there was one account. It stops being fine the moment a second, REAL account is available for testing,
// because the choice of account then decides what a mutating harness is allowed to do, and a hardcoded
// path makes that choice invisible.
//
//   DOWNPIPE_CF_KIT=<dirname>   selects a kit under ~/Desktop/downpipes-live-keys/
//   unset                       the throwaway proving account, which is the safe default
//
// THE RULE THAT MATTERS
// ---------------------
// The harnesses are NOT equally safe to point at a real account:
//
//   capture-completeness  READ-ONLY (without --seed). Safe anywhere.
//   idempotence           every write is dryRun. Safe anywhere.
//   autoprove             CREATES objects and DELETES ONLY WHAT IT CREATED, matched on its own
//                         `dp-roundtrip` marker. Safe on a real account under an owner's "delete anything
//                         you create" permission.
//   hand-writer-update    creates and updates its own objects. Same posture as autoprove.
//   singleton-prove       DAMAGES EXISTING CONFIGURATION. It flips a live setting and restores it. That is
//                         NOT "anything you create": it changes settings the owner already had, and a
//                         failed restore leaves a real account altered. It refuses to run against a
//                         non-default kit unless DOWNPIPE_CF_ALLOW_DAMAGE=1 is also set, so pointing the
//                         suite at a production account cannot quietly include it.
//
// requireDamagePermission below is what enforces that last one, rather than leaving it to whoever reads
// this comment.

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const DEFAULT_KIT = "throwaway-cf-2026-07-26";

export function kitName(): string {
  const k = process.env.DOWNPIPE_CF_KIT;
  return k !== undefined && k !== "" ? k : DEFAULT_KIT;
}

export function kitDir(): string {
  return join(homedir(), "Desktop", "downpipes-live-keys", kitName());
}

export function kitReady(): boolean {
  return process.env.DOWNPIPE_LIVE_CF === "1" && existsSync(join(kitDir(), "cf-api-token.txt"));
}

// isDefaultKit is the throwaway proving account, the one whose configuration nobody minds losing.
export function isDefaultKit(): boolean {
  return kitName() === DEFAULT_KIT;
}

// requireDamagePermission gates a harness that modifies EXISTING configuration. On the throwaway account it
// is always allowed. Anywhere else it needs an explicit second flag, because "you may test against my
// account, delete anything you create" does not grant permission to change settings that were already
// there. Returns a reason to skip, or "" when it may proceed.
export function requireDamagePermission(): string {
  if (isDefaultKit()) return "";
  if (process.env.DOWNPIPE_CF_ALLOW_DAMAGE === "1") return "";
  return `refusing to modify existing configuration on kit "${kitName()}": this harness damages settings that are already there and restores them, which is not covered by permission to delete what it creates. Set DOWNPIPE_CF_ALLOW_DAMAGE=1 to override.`;
}

// announceKit prints WHICH ACCOUNT a run used, once, at the top of every harness.
//
// Routing the kit correctly is only half of it. A run that reads the right credentials and never says so
// still leaves "did this pass against the account I asked for" unanswerable from the output, and that
// question had a wrong answer for four harnesses until the spelling of one path was fixed. A green that
// cannot be attributed to an account is worth less than it looks.
//
// The kit NAME is a directory name, never a credential, so printing it discloses nothing.
export function announceKit(harness: string): void {
  console.log(`[${harness}] kit "${kitName()}"${isDefaultKit() ? " (the throwaway proving account)" : " (NOT the throwaway account)"}`);
}
