// The safe-apply update module: apply a newer, vendor-signed engine version FROM THE CONSOLE (no CLI),
// such that a bad release can NEVER brick the customer's platform. The model is verify -> record the
// rollback target -> upload the new version -> promote it -> prove health with a real canary flight ->
// AUTO-ROLLBACK to the recorded version if it does not sing.
//
// WHY THIS IS SAFE TO ATTEMPT AT ALL: an update only replaces the engine WORKER (the moving part). The
// two things that matter are independent of the running engine and cannot be harmed by a bad deploy:
// the DATA (archives are immutable, append-only, in the customer's own bucket) and RECOVERY (the archive
// is self-describing and signed; the standalone reader + recovery kit restore without the engine). So a
// bad release is at worst a brief availability blip on the live engine version, which Cloudflare lets us
// roll back. This module's whole job is "don't leave them on a broken live version".
//
// This module is PURE ORCHESTRATION over two injected interfaces (a DeployDriver and a HealthGate), so
// every brick-safety invariant is proven by the validator with fakes, with no Cloudflare account and no
// real deploy. The real DeployDriver (Cloudflare versions/deployments) lives in cf-deploy.ts.

import type { CanaryLiveness } from "../canary/types.ts";
import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import type { ArtefactMeta, DeployDriver, GuardMessages, HealthGate, StepLog } from "./update-types.ts";
// The shared driver/gate interfaces, the step-log/artefact shapes and the two pure helpers live in a base
// module so the apply/rollback/ramp orchestration files all share them without importing each other. They are
// re-exported below so this module's public surface is unchanged. See update-types.ts.
import { decideKeep, msg, optional, verifyAndGuard } from "./update-types.ts";
import { compareSemver, isEngineCompatible } from "./updates.ts";

export { decideKeep };

// UpdateOutcome is the closed result of an apply attempt. Every path resolves to one of these; the
// module never throws out (fail-safe), it records the outcome + a human reason.
//   no-update   already on the recommended version (nothing to do)
//   dry-run     verified + planned; nothing was uploaded or promoted (the default, opt-in to go live)
//   refused     aborted BEFORE going live (bad artefact, migration required, upload/promote failed),
//               the engine is unchanged
//   applied     promoted AND the canary proved it healthy, the new version is live and trusted
//   rolled-back promoted but the canary did not sing, automatically reverted to the prior version
//
// G219: the two outcomes below exist because the closed enum used to ASSERT THE OPPOSITE OF REALITY for the
// two worst states this machine can reach. Every consumer keys off this enum -- the pack (updates.last.outcome),
// the console badge, the notification rules, and the diagnostics bot's update-failed-or-rollback-needed
// signal -- so a wrong value is not a cosmetic problem, it is every downstream reader being told the opposite
// of the truth, with the truth surviving only in a prose `reason` field none of them read.
//
//   rollback-failed      the canary said NO, the automatic rollback was attempted, AND THE ROLLBACK DEPLOY
//                        ITSELF FAILED. The engine is STILL SERVING THE BAD BUILD. This was recorded as
//                        "rolled-back" -- so the pack, the badge and the bot all said the customer had been
//                        safely reverted while they were, in fact, live on the dead version. It is the single
//                        most dangerous lie in the update path, and it needed its own member, not a footnote
//                        in a sentence.
//   applied-unconfirmed  the promote was ACCEPTED and the confirmation read-back could not be performed, so
//                        the engine cannot prove the intended version is the live one. "applied" claims proof
//                        that was never obtained; this claims exactly what happened and no more.
export type UpdateOutcome = "no-update" | "dry-run" | "refused" | "applied" | "rolled-back" | "rollback-failed" | "applied-unconfirmed";

// StepLog, ArtefactMeta, LiveVersionShare, DeployDriver and HealthGate are defined in update-types.ts and
// re-exported at the foot of this module so this module's public surface is unchanged.
export type { ArtefactMeta, DeployDriver, HealthGate, LiveVersionShare, ReadbackResult, StepLog } from "./update-types.ts";
export { liveSingleVersion, msg } from "./update-types.ts";

import type { ReadbackResult } from "./update-types.ts";

export interface UpdateApplyResult {
  outcome: UpdateOutcome;
  recommendedVersion: string;
  fromVersion?: string; // the version that was live before (the rollback target)
  toVersion?: string; // the version that was uploaded/promoted
  canaryBaseline?: CanaryLiveness; // the canary liveness BEFORE the apply (from the DO; no extra flight)
  canaryVerdict?: CanaryLiveness; // the canary liveness AFTER promoting the new version
  steps: StepLog[];
  reason?: string; // a plain-words explanation, present for every non-"applied" outcome
  // confirmationPending (design UPDATE-UX-015 §3, additive): true only on an "applied" outcome that was
  // KEPT via the self-check (the canary itself never sang alive), so the keep is honest-but-provisional
  // until the hourly canary confirms it in the background (see notify-passes.ts confirmUpdateIfSettled).
  // Absent on every other outcome, and absent on a keep the canary itself confirmed (verdict alive).
  confirmationPending?: boolean;
}

export interface SafeApplyInput {
  artefact: Uint8Array; // the downloaded new Worker bundle bytes
  expectedSha384: string; // the hash the SIGNATURE-VERIFIED channel declared for this artefact (hex)
  meta: ArtefactMeta;
  runningVersion: string; // the engine's own ENGINE_VERSION
  recommendedVersion: string; // the channel's recommended version
  dryRun: boolean; // when true: verify + plan only, never upload or promote (the route default)
  // allowDowngrade is the EXPLICIT owner opt-in to apply a version that is NOT strictly newer than the
  // running engine (an emergency downgrade-to-recover). DEFAULT false: the normal apply REFUSES a channel
  // that recommends an older (or unparseable) version, backward motion is meant to be system-controlled via
  // the rollback path, never silently driven by a (correctly-signed) channel pinning an older build. When the
  // owner deliberately sets this flag, a downgrade to a strictly-older version is permitted (still verified,
  // canary-gated and reversible); an EQUAL version still short-circuits as no-update either way.
  allowDowngrade?: boolean;
  // settledHighWaterMark (R8) is the monotonic anti-rollback floor (the highest version ever successfully
  // settled), read from the DO and threaded in by the route. verifyAndGuard refuses a target below it EVEN
  // with allowDowngrade. Absent = no version settled yet = no floor. See update-types.ts GuardInput.
  settledHighWaterMark?: string;
  // knownRollbackTarget/knownToVersion (asvs-HI-14-r2), threaded straight through to verifyAndGuard: the
  // route's own persisted-lifecycle known-good, read the same way resolveRollbackTarget already does for
  // the standalone rollback route. See update-types.ts GuardInput for the full rationale.
  knownRollbackTarget?: string;
  knownToVersion?: string;
  // readbackMode (DP-D) selects the post-upload read-back gate's behaviour: "warn" (the default when
  // absent) reads the uploaded version back from Cloudflare's API, hashes it against the signed digest
  // and RECORDS the verdict but proceeds either way; "enforce" refuses promotion unless the read-back
  // VERIFIED (fail-closed, gated on a sandbox experiment before it is ever the default); "off"
  // skips the read-back. Threaded from env.UPDATE_READBACK_MODE by the route.
  readbackMode?: "off" | "warn" | "enforce";
}

// decideKeep now lives in update-types.ts (asvs-HI-13 refactor: shared so settleAfterPromote AND
// settleAfterRamp, update-ramp.ts, can both call the SAME rule without the sibling orchestration files
// importing each other), imported + re-exported at the top of this module. Its behaviour there is the
// OPTIMISTIC rule (..07 rework, after three live drills rolled back healthy updates): a verified
// atomic promote is KEPT unless a completed flight is DEAD (a data-integrity failure); an ailing/pending
// flight (the post-swap DO-reset window) always keeps, confirmation pending, and the self-check no longer
// gates it -- see update-types.ts for the full rationale. settleAfterRamp applies its OWN additional
// baseline-regression guard on top of this (update-ramp.ts), which this rework does not weaken.


// PromoteResult is phase 1's outcome. "promoted" means the new version is LIVE but not yet verified,
// phase 2 (settleAfterPromote, run on the new version) must follow to canary-gate it.
export interface PromoteResult {
  phase: "promote";
  outcome: "no-update" | "dry-run" | "refused" | "promoted";
  recommendedVersion: string;
  fromVersion?: string;
  toVersion?: string;
  canaryBaseline?: CanaryLiveness;
  steps: StepLog[];
  reason?: string;
  // readback (DP-D, ADDITIVE) is the post-upload read-back verdict (see update-types.ts
  // ReadbackResult): whether Cloudflare's own API returned byte-exactly the signed bundle BEFORE
  // promotion. Present whenever the gate ran (warn or enforce); absent on off mode, dry-runs and
  // refusals that never reached the upload.
  readback?: ReadbackResult;
}

// PROMOTE_GUARD_MESSAGES is the atomic-apply operator wording for the shared guard steps. The strings are
// byte-identical to the inline messages planAndPromote used before the verifyAndGuard extraction, so the
// console copy is unchanged.
// EXPORTED so a validator can drive the guard with the PRODUCT'S OWN refusal sentences rather than a
// hand-typed copy of them: classifyUpdateFailStep selects the closed {step, cause} by reading these strings, so
// a test that re-types them would keep passing while a reworded message silently un-wired the classifier and
// sent every digest mismatch back to the residual {version-post, other} it used to land in.
export const PROMOTE_GUARD_MESSAGES: GuardMessages = {
  antiRollbackBelow: (rec, highWater) => `the recommended version ${rec} is BELOW ${highWater}, the highest version this engine has already successfully run; it will not be applied even with downgrade allowed (going below a version you have run could re-introduce an already-patched issue). Use the Roll back control to return to a recorded known-good version. Nothing was changed.`,
  antiRollbackIncomparable: (rec, highWater) => `the recommended version ${rec} cannot be compared to ${highWater} (the highest version this engine has already run), so it will not be applied (it cannot be proven to be at or above that floor). Nothing was changed.`,
  forwardOnlyIncomparable: (rec, running) => `the recommended version ${rec} cannot be compared to the running engine ${running}, so it will not be applied automatically (backward or unknown moves are not channel-driven). Nothing was changed.`,
  forwardOnlyNotNewer: (rec, running) => `the recommended version ${rec} is not newer than the running engine ${running}; the engine is only moved forward by the normal apply (going back to an earlier version is done with the Roll back control). Nothing was changed.`,
  migration: () => "this release requires a Durable Object migration and must be applied manually (the safe-apply module deliberately does not auto-apply migrations; nothing was changed)",
  compat: (_rec, minEngine, running) => `this release requires engine version ${minEngine} or newer, but this engine is ${running}; update to an intervening version first (the safe-apply module will not apply onto too-old an engine). Nothing was changed.`,
  verifyNoHash: () => "the signed update channel did not declare a hash for this version, so the download cannot be verified; nothing was deployed",
  verifyHashError: (detail) => `the update could not be hashed for verification; nothing was deployed: ${detail}`,
  verifyMismatch: () => "the downloaded update did not match the signed channel's hash (possible corruption or tampering); nothing was deployed",
  recordRollbackError: (detail) => `could not read the engine's current deployed version, so there would be nothing to roll back to; nothing was changed: ${detail}`,
  liveSplit: (detail) => `the engine's live deployment is currently split across more than one version (${detail}), most likely a gradual ramp still in progress or awaiting a decision; the true rollback target cannot be determined automatically while more than one version is live. Settle or roll back that ramp (or resolve it from the Cloudflare dashboard) before applying again. Nothing was changed.`,
};

// planAndPromote is PHASE 1, it runs on the CURRENT (old) version (the request that triggers the
// update executes the live code, which is the old one until the promote lands). It verifies, records the
// rollback target, reads the baseline, and (unless dryRun) uploads + promotes the new version. It does
// NOT run the canary: the canary must exercise the NEW code, which only a later request to the now-live
// version can do (phase 2). Never throws (fail-safe). Ordering IS the safety:
//   1. already-current short-circuit  2. migration guard  3. verify artefact (no deploy without verify)
//   4. record rollback target  5. baseline  6. dry-run stop  7. upload (not live)  8. promote (now live)
export async function planAndPromote(driver: DeployDriver, gate: Pick<HealthGate, "baseline">, input: SafeApplyInput): Promise<PromoteResult> {
  const steps: StepLog[] = [];
  const log = (step: string, ok: boolean, detail?: string): void => {
    steps.push({ step, ok, ...(detail !== undefined ? { detail } : {}) });
  };
  const rec = input.recommendedVersion;
  const base = (extra: Partial<PromoteResult>): PromoteResult => ({ phase: "promote", recommendedVersion: rec, steps, outcome: "refused", ...extra });

  // 1. Already current: nothing to do (idempotent). (The remaining guards differ in outcome between the
  // atomic apply and the ramp, so this short-circuit stays in each caller.)
  if (input.runningVersion === rec) {
    log("up-to-date", true, `already running ${rec}`);
    return base({ outcome: "no-update" });
  }

  // 1b..4. The SHARED guard sequence (forward-only, migration, compat, verify-artefact, record-rollback-
  // target) runs in verifyAndGuard so a guard change lands in one place (findings 023-02/023-11). The
  // apply-specific operator wording is supplied here; a refusal is mapped straight into a PromoteResult.
  const guard = await verifyAndGuard(driver, input, PROMOTE_GUARD_MESSAGES, log, { sha384, hexEncode, isEngineCompatible, compareSemver });
  if (!guard.ok) return base({ outcome: "refused", reason: guard.reason });
  const fromVersion = guard.fromVersion;

  // 5. Canary baseline from the DO (no flight).
  let canaryBaseline: CanaryLiveness;
  try {
    canaryBaseline = await gate.baseline();
  } catch {
    canaryBaseline = "pending";
  }
  log("canary-baseline", true, canaryBaseline);

  // 6. DRY-RUN: verified + planned, nothing deployed. The route default; going live is opt-in. fromVersion
  // is absent only here (a tokenless Preview cannot read the live version; the guard reported it honestly).
  if (input.dryRun) {
    log("dry-run", true, fromVersion !== undefined ? `would upload ${rec} and promote, gated by the canary; rollback target is ${fromVersion}` : `would upload ${rec} and promote, gated by the canary; the rollback target is read, with your deploy token, at apply time`);
    return base({ outcome: "dry-run", ...(fromVersion !== undefined ? { fromVersion } : {}), canaryBaseline });
  }

  // Type narrowing only: on a LIVE run a failed rollback-target read already refused inside verifyAndGuard,
  // so fromVersion is always present here. Refuse (fail-safe) rather than assert if that ever breaks.
  if (fromVersion === undefined) {
    return base({ outcome: "refused", reason: PROMOTE_GUARD_MESSAGES.recordRollbackError("the rollback target was not recorded") });
  }

  // 7..8. Deployment phase: upload (not live) then atomic promote. Extracted per finding 023-01 so the
  // verification phase and the deployment phase are separately readable.
  return uploadAndPromote(driver, input, base, log, { fromVersion, canaryBaseline });
}

// uploadAndPromote is planAndPromote's deployment phase (the steps after the dry-run boundary): upload the
// new version (not live), then atomically promote it. A failure at either step is a clean refusal that
// leaves the engine on the prior version. Split from planAndPromote per finding engine-src-023-01 so the
// verification phase (verifyAndGuard) and the deployment phase are independently testable.
async function uploadAndPromote(
  driver: DeployDriver,
  input: SafeApplyInput,
  base: (extra: Partial<PromoteResult>) => PromoteResult,
  log: (step: string, ok: boolean, detail?: string) => void,
  carry: { fromVersion: string; canaryBaseline: CanaryLiveness },
): Promise<PromoteResult> {
  const { fromVersion, canaryBaseline } = carry;
  // Upload the new version (NOT live yet). A failure here leaves the engine entirely unchanged.
  let toVersion: string;
  try {
    toVersion = await driver.uploadVersion(input.artefact, input.meta);
    log("upload-version", true, toVersion);
  } catch (e) {
    log("upload-version", false, msg(e));
    return base({ outcome: "refused", fromVersion, canaryBaseline, reason: `the new version could not be uploaded; your engine is unchanged: ${msg(e)}` });
  }
  // DP-D READ-BACK GATE, deliberately BETWEEN upload and promote: the one place a mismatch is free to
  // refuse, because nothing is live yet and nothing needs rolling back (strictly safer than a
  // post-traffic gate). Warn mode (the default) records the verdict and proceeds; enforce mode
  // promotes ONLY a verified read-back and is enabled only after a sandbox experiment proves
  // the platform returns module bytes unchanged. The verdict rides the result into the pending and
  // settled records either way, so every apply leaves durable evidence of what Cloudflare held.
  const readbackMode = input.readbackMode ?? "warn";
  let readback: ReadbackResult | undefined;
  if (readbackMode !== "off") {
    readback = await readBackUploaded(driver, input, toVersion, readbackMode);
    log("read-back", readback.verdict === "verified", `${readback.verdict}${readback.deployedSha384 !== undefined ? ` ${readback.deployedSha384}` : ""}${readback.detail !== undefined ? ` (${readback.detail})` : ""}`);
    if (readbackMode === "enforce" && readback.verdict !== "verified") {
      return base({
        outcome: "refused",
        fromVersion,
        toVersion,
        canaryBaseline,
        readback,
        reason: `the uploaded version could not be confirmed byte-exact against the signed channel (read-back ${readback.verdict}${readback.detail !== undefined ? `: ${readback.detail}` : ""}); nothing was promoted and the previously live version keeps serving.`,
      });
    }
  }
  // Promote (make it the live deployment). Cloudflare deploys are atomic: a failed promote leaves the
  // PRIOR version live, so a promote failure is a clean refusal with no rollback needed.
  try {
    await driver.deployVersion(toVersion);
    log("promote", true, toVersion);
  } catch (e) {
    log("promote", false, msg(e));
    return base({ outcome: "refused", fromVersion, toVersion, canaryBaseline, ...(readback !== undefined ? { readback } : {}), reason: `the new version was uploaded but promotion failed; your engine is unchanged (still on the prior version): ${msg(e)}` });
  }
  // Promoted but NOT yet verified, phase 2 (on the new version) must canary-gate it.
  return base({ outcome: "promoted", fromVersion, toVersion, canaryBaseline, ...(readback !== undefined ? { readback } : {}) });
}

// readBackUploaded fetches the just-uploaded version's module bytes back from the platform and hashes
// them against the SIGNED channel digest (the same expectedSha384 verifyAndGuard already enforced on the
// downloaded bytes, so verified here means: what Cloudflare holds is what the channel signed). Every
// failure path degrades to an honest verdict, never a throw: the caller decides what a non-verified
// verdict means under the active mode.
// EXPORTED so the redaction validator can drive the REAL throw path (a driver whose fetchVersionModule
// rejects, which is what a read-back against a dead script or a refused Cloudflare API call does) instead of
// hand-writing the record it produces. The leak this guards is on the catch arm below.
export async function readBackUploaded(driver: DeployDriver, input: SafeApplyInput, versionId: string, mode: "warn" | "enforce"): Promise<ReadbackResult> {
  if (typeof driver.fetchVersionModule !== "function") {
    return { verdict: "unavailable", mode, detail: "the deploy driver does not support version read-back" };
  }
  try {
    const bytes = await driver.fetchVersionModule(versionId, input.meta.mainModule || "index.js");
    const deployedSha384 = hexEncode(await sha384(bytes));
    if (deployedSha384 === input.expectedSha384) return { verdict: "verified", mode, deployedSha384 };
    return { verdict: "mismatch", mode, deployedSha384, detail: "the platform returned bytes whose digest differs from the signed channel's" };
  } catch (e) {
    return { verdict: "unavailable", mode, detail: msg(e) };
  }
}

// SettleArgs carries the phase-1 facts (from the DO "pending verification" record) into phase 2.
export interface SettleArgs {
  fromVersion: string;
  toVersion: string;
  recommendedVersion: string;
  canaryBaseline?: CanaryLiveness;
}

export interface SettleResult {
  phase: "settle";
  // G219: rollback-failed is a REAL settle outcome and the type must be able to hold it. Widened to the full
  // UpdateOutcome subset this phase can produce, so the "the rollback deploy itself failed" branch cannot be
  // silently coerced back into a "rolled-back" that means the opposite.
  outcome: "applied" | "rolled-back" | "rollback-failed";
  recommendedVersion: string;
  fromVersion: string;
  toVersion: string;
  canaryBaseline?: CanaryLiveness;
  canaryVerdict?: CanaryLiveness;
  steps: StepLog[];
  reason?: string;
  // confirmationPending: see UpdateApplyResult above; set true only on "applied" when the keep was decided
  // by the self-check (verdict not alive), never when the canary itself sang.
  confirmationPending?: boolean;
}

// settleAfterPromote is PHASE 2, it MUST run on the NEW (now-live) version, so the canary it flies
// exercises the NEW code. (The console calls this over its service binding right after phase 1, so it
// hits the current live deployment, which is the just-promoted new version.) It reads the baseline (when
// not carried in), flies the canary on the new code, decides keep-vs-rollback, and on a non-singing
// verdict rolls back to fromVersion. Never throws (fail-safe). The deploy token is supplied to this call
// too (so the rollback can act) and is never stored.
export async function settleAfterPromote(driver: DeployDriver, gate: HealthGate, args: SettleArgs): Promise<SettleResult> {
  const steps: StepLog[] = [];
  const log = (step: string, ok: boolean, detail?: string): void => {
    steps.push({ step, ok, ...(detail !== undefined ? { detail } : {}) });
  };
  const { fromVersion, toVersion, recommendedVersion: rec } = args;

  let canaryBaseline = args.canaryBaseline;
  if (canaryBaseline === undefined) {
    try {
      canaryBaseline = await gate.baseline();
    } catch {
      canaryBaseline = "pending";
    }
  }

  // Canary gate on the now-live NEW code. A gate error is treated as "could not prove healthy".
  let canaryVerdict: CanaryLiveness;
  try {
    canaryVerdict = await gate.flyNow();
    log("canary-verdict", canaryVerdict === "alive", canaryVerdict);
  } catch (e) {
    canaryVerdict = "ailing";
    log("canary-verdict", false, `the canary flight errored on the new version: ${msg(e)}`);
  }

  // The self-check is consulted whenever the canary cannot gate (a pending/ailing flight -- which the
  // post-swap window can produce transiently regardless of the baseline; see decideKeep). Only a clean
  // ALIVE or a hard DEAD verdict decides without it.
  let selfCheckOk = false;
  if (canaryVerdict !== "alive" && canaryVerdict !== "dead") {
    try {
      selfCheckOk = await gate.selfCheck();
    } catch {
      selfCheckOk = false;
    }
    log("self-check", selfCheckOk, selfCheckOk ? "the new version boots, answers and reports the expected version" : "the new version did not pass its self-check");
  }

  const decision = decideKeep(canaryBaseline, canaryVerdict, selfCheckOk);
  const base = (extra: Partial<SettleResult>): SettleResult => ({ phase: "settle", recommendedVersion: rec, fromVersion, toVersion, canaryBaseline, canaryVerdict, steps, outcome: "applied", ...extra });
  if (decision.keep) {
    log("decision", true, decision.reason);
    // confirmationPending (design §3): the canary itself only decides on an ALIVE verdict; anything else
    // that still kept (ailing/pending, the self-check passed) is a KEEP the canary never confirmed, so the
    // record is honest-but-provisional until the hourly canary sings on this version in the background.
    const confirmationPending = canaryVerdict !== "alive";
    return base({ outcome: "applied", ...(confirmationPending ? { confirmationPending: true } : {}) });
  }
  log("decision", false, decision.reason);

  // ROLLBACK to the recorded prior version. If even the rollback fails, that is the loudest signal, but
  // DATA and RECOVERY are still safe (archives immutable; restore out-of-band), so say so.
  try {
    await driver.deployVersion(fromVersion);
    log("rollback", true, `rolled back to ${fromVersion}`);
    return base({ outcome: "rolled-back", reason: `the update to ${rec} did not pass the canary (${decision.reason}); your engine was automatically rolled back to the prior version. Nothing was lost and no backup or restore was affected.` });
  } catch (e) {
    log("rollback", false, msg(e));
    // G219: this branch used to return outcome "rolled-back" -- the engine is on the BAD version and the enum
    // said it had been reverted. The prose told the truth and nothing that reads this record reads prose.
    return base({ outcome: "rollback-failed", reason: `the update to ${rec} did not pass the canary AND the automatic rollback FAILED (${msg(e)}). The engine is on the new version; re-deploy version ${fromVersion} from the Cloudflare dashboard. Your DATA and RECOVERY are unaffected: archives are immutable and restore is out-of-band (the standalone reader + your recovery kit), so backups remain safe and restorable regardless.` });
  }
}

// runSafeApply is the COMBINED single-context flow: phase 1 then (if promoted) phase 2. It is the
// executable specification the validator drives end-to-end with fakes, and is used wherever both phases
// genuinely run in one runtime (the validator, and any future split-topology where the engine can call
// its own new version inline). In the default topology the two phases are driven across two requests by
// the console (phase 1 on the old version, phase 2 on the promoted new version); see the router. Never
// throws.
export async function runSafeApply(driver: DeployDriver, gate: HealthGate, input: SafeApplyInput): Promise<UpdateApplyResult> {
  const p = await planAndPromote(driver, gate, input);
  if (p.outcome !== "promoted") {
    // no-update | dry-run | refused all map straight through.
    return {
      outcome: p.outcome,
      recommendedVersion: p.recommendedVersion,
      steps: p.steps,
      ...optional("fromVersion", p.fromVersion),
      ...optional("toVersion", p.toVersion),
      ...optional("canaryBaseline", p.canaryBaseline),
      ...optional("reason", p.reason),
    };
  }
  const s = await settleAfterPromote(driver, gate, {
    fromVersion: p.fromVersion!,
    toVersion: p.toVersion!,
    recommendedVersion: p.recommendedVersion,
    ...optional("canaryBaseline", p.canaryBaseline),
  });
  return {
    outcome: s.outcome,
    recommendedVersion: s.recommendedVersion,
    fromVersion: s.fromVersion,
    toVersion: s.toVersion,
    steps: [...p.steps, ...s.steps],
    ...optional("canaryBaseline", s.canaryBaseline),
    ...optional("canaryVerdict", s.canaryVerdict),
    ...optional("reason", s.reason),
    ...optional("confirmationPending", s.confirmationPending),
  };
}

export {
  type RampInput,
  type RampOutcome,
  type RampResult,
  type RampSettleArgs,
  type RampSettleOutcome,
  type RampSettleResult,
  rampPercentageValid,
  settleAfterRamp,
  startGradualRamp,
} from "./update-ramp.ts";
// The standalone rollback (W4) and the opt-in gradual ramp (W4) were split into sibling modules to keep this
// file under the size budget. They are re-exported here so this module's public surface is unchanged and every
// existing importer of update-apply.ts keeps working. See update-rollback.ts and update-ramp.ts.
export {
  type RollbackOutcome,
  runStandaloneRollback,
  type StandaloneRollbackArgs,
  type StandaloneRollbackResult,
} from "./update-rollback.ts";

