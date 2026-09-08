// W4, STANDALONE ROLLBACK (a first-class, always-available revert, independent of an in-flight apply).
// This is the safe recovery direction (the same direction the settle auto-rollback takes), so by design it
// needs NO second-owner approval (W5 keeps dual control on the consequential KEEP/apply direction only).
//
// Moved out of update-apply.ts (file-size remediation, finding engine-struct-miss-updateapply). Behaviour is
// unchanged: this module is re-exported by update-apply.ts so existing importers are untouched. It is PURE
// ORCHESTRATION over the injected DeployDriver + HealthGate, proven by validators with fakes.

import type { CanaryLiveness } from "../canary/types.ts";
import type { DeployDriver, HealthGate, StepLog } from "./update-types.ts";
import { liveSingleVersion, msg } from "./update-types.ts";
import { isEngineCompatible } from "./updates.ts";

// PAIRED_ROLLBACK_COPY is the exact, normative one-line copy the console shows BEFORE a token is spent,
// BEFORE a token is spent, whenever the floor check below decides an engine rollback must bundle the
// console with it.
export const PAIRED_ROLLBACK_COPY = "Rolling the engine back past what this console requires; the console will be rolled back with it.";

// engineRollbackSatisfiesConsoleFloor (conditional-bundling rollback) answers whether an ENGINE
// rollback to `targetVersion` may proceed ENGINE-ONLY given the LIVE console's persisted minEngineVersion
// floor (read off lastConsole; see router-updates-components.ts executeConsoleApply, which persists it at
// console-apply time). Absent/blank floor -- no console record ever applied here, or the applied console
// declared no floor -- means "no requirement", always satisfied, proceed engine-only exactly as before
// consoles existed. This reuses isEngineCompatible (itself compareSemver-based) treating the ROLLBACK
// TARGET as if it were the running engine version against that floor: exactly the question "would this
// engine version satisfy what the console requires". isEngineCompatible's own fail-closed rule (an
// UNPARSEABLE target or floor reads INCOMPATIBLE) is what makes this fail closed into PAIRED on an
// unparseable comparison -- the caller must never strand a console on an engine it cannot prove compatible
// with. Pure.
export function engineRollbackSatisfiesConsoleFloor(targetVersion: string, consoleMinEngineVersion: string | undefined): boolean {
  return isEngineCompatible(targetVersion, consoleMinEngineVersion);
}

// RollbackResult is the closed outcome of a standalone rollback.
//   reverted    the recorded known-good version was deployed AND the canary confirmed it healthy
//   no-target   there is no recorded prior version to roll back to (nothing was changed)
//   already     the engine is ALREADY on the target version (idempotent no-op)
//   failed      the deploy of the prior version failed (the engine is unchanged, deploys are atomic)
//   reverted-unverified  the prior version was deployed but the canary could not confirm it (data/recovery
//                        still safe; flagged so the operator investigates), deliberately NOT auto-re-rolled
//                        (rolling a rollback forward again is not obviously safer; surface it instead)
export type RollbackOutcome = "reverted" | "no-target" | "already" | "failed" | "reverted-unverified";

export interface StandaloneRollbackArgs {
  // toVersion is the recorded KNOWN-GOOD version to revert to (the prior live version from the last apply).
  // The caller (the router) reads it from the persisted update lifecycle record; the orchestration does not
  // invent it. An empty/absent value yields a clean "no-target" (never a blind deploy).
  toVersion: string;
}

export interface StandaloneRollbackResult {
  outcome: RollbackOutcome;
  fromVersion?: string; // the version that was live before the rollback (what we reverted away from)
  toVersion: string; // the known-good version we reverted to (or attempted to)
  canaryVerdict?: CanaryLiveness;
  steps: StepLog[];
  reason?: string;
}

// runStandaloneRollback reverts the engine to a RECORDED known-good version, independent of any in-flight
// apply. It is the SAFE recovery direction (the same direction the settle auto-rollback takes), so by design
// it needs NO second-owner approval (W5 keeps dual control on the consequential KEEP/apply direction only).
// Ordering is the safety: read the current live version (so we know what we are reverting away from, and can
// short-circuit if already there) -> deploy the known-good version -> canary-verify it landed healthy. It is
// PURE ORCHESTRATION over the injected driver + gate (proven by validators with fakes) and NEVER throws out
// (fail-safe): every path resolves to a structured result with a plain-words reason. Even a failed rollback
// leaves DATA + RECOVERY untouched (archives immutable; restore out-of-band), which the reason states.
// Step 1 of the rollback: read the current live version (what we are reverting away from; also lets us
// short-circuit). When the driver can report the FULL slice set, use it to learn the deployment SHAPE: a
// single-version deployment is safe to short-circuit against; a multi-version SPLIT (an opt-in ramp left
// mid-flight) must NEVER short-circuit even if the target happens to be one of the slices, a split could
// leave the suspect version still serving traffic, so we deploy the known-good at 100% to collapse the split
// (idempotent). Returns the read result or a structured failure; logs the read step via the passed logger.
async function readLiveForRollback(
  driver: DeployDriver,
  log: (step: string, ok: boolean, detail?: string) => void,
): Promise<{ fromVersion: string; liveSingle: string | null } | { error: string }> {
  try {
    if (typeof driver.currentLiveVersions === "function") {
      const slices = await driver.currentLiveVersions();
      const liveSingle = liveSingleVersion(slices);
      // fromVersion (what we reverted away from) is the dominant slice; reuse currentLiveVersionId for it so
      // the recorded value is identical to the apply path's rollback target.
      const fromVersion = await driver.currentLiveVersionId();
      log("read-live-version", true, liveSingle === null ? `${fromVersion} (split: ${slices.map((s) => `${s.versionId}@${s.percentage}%`).join(", ")})` : fromVersion);
      return { fromVersion, liveSingle };
    }
    const fromVersion = await driver.currentLiveVersionId();
    log("read-live-version", true, fromVersion); // no slice detail: treat the reported version as the single live version
    return { fromVersion, liveSingle: fromVersion };
  } catch (e) {
    log("read-live-version", false, msg(e));
    return { error: msg(e) };
  }
}

export async function runStandaloneRollback(driver: DeployDriver, gate: HealthGate, args: StandaloneRollbackArgs): Promise<StandaloneRollbackResult> {
  const steps: StepLog[] = [];
  const log = (step: string, ok: boolean, detail?: string): void => {
    steps.push({ step, ok, ...(detail !== undefined ? { detail } : {}) });
  };
  const toVersion = (args.toVersion ?? "").trim();
  const base = (extra: Partial<StandaloneRollbackResult>): StandaloneRollbackResult => ({ toVersion, steps, outcome: "failed", ...extra });

  // 0. No recorded target -> clean no-op (never a blind deploy).
  if (toVersion === "") {
    log("rollback-target", false, "no recorded known-good version");
    return base({ outcome: "no-target", reason: "there is no recorded prior engine version to roll back to; nothing was changed. (A rollback target is recorded the first time you apply an update.)" });
  }

  // 1. Read the current live version and the deployment shape.
  const live = await readLiveForRollback(driver, log);
  if ("error" in live) {
    return base({ outcome: "failed", reason: `could not read the engine's current deployed version, so a rollback cannot be performed safely; nothing was changed: ${live.error}` });
  }
  const { fromVersion, liveSingle } = live;

  // 2. Already on the target -> idempotent no-op. ONLY when the live deployment is a SINGLE version equal to
  //    the target (never on a split, a split must be collapsed by deploying the known-good at 100%).
  if (liveSingle !== null && liveSingle === toVersion) {
    log("already-on-target", true, toVersion);
    return base({ outcome: "already", fromVersion, reason: `the engine is already running version ${toVersion}; nothing was changed.` });
  }

  // 3. Deploy the known-good version (atomic). A failure leaves the prior version live (clean no-op).
  try {
    await driver.deployVersion(toVersion);
    log("deploy-known-good", true, toVersion);
  } catch (e) {
    log("deploy-known-good", false, msg(e));
    return base({ outcome: "failed", fromVersion, reason: `could not roll back to version ${toVersion} (the previously-live version is still serving; Cloudflare deploys are atomic, so nothing was half-applied): ${msg(e)}` });
  }

  // 4. Canary-verify the rollback landed healthy on the NOW-LIVE known-good code. This must run on the
  //    now-live version (the router calls it over its service binding after the deploy, exactly like settle).
  let canaryVerdict: CanaryLiveness;
  try {
    canaryVerdict = await gate.flyNow();
    log("canary-verify", canaryVerdict === "alive", canaryVerdict);
  } catch (e) {
    canaryVerdict = "ailing";
    log("canary-verify", false, `the canary flight errored after the rollback: ${msg(e)}`);
  }
  if (canaryVerdict === "alive") {
    return base({ outcome: "reverted", fromVersion, canaryVerdict, reason: `rolled back to the known-good version ${toVersion}; the canary sings on it. Your data and backups were never affected.` });
  }
  // The rollback deployed but the canary could not confirm it. We do NOT auto-re-roll (rolling a known-good
  // rollback forward again is not obviously safer); surface it honestly for the operator. Data/recovery safe.
  return base({ outcome: "reverted-unverified", fromVersion, canaryVerdict, reason: `rolled back to version ${toVersion}, but the canary could not confirm it healthy (${canaryVerdict}); investigate from the console. Your DATA and RECOVERY are unaffected (archives are immutable and restore is out-of-band).` });
}
