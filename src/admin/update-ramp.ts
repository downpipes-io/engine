// W4, OPT-IN GRADUAL RAMP (default OFF). A normal apply stays the atomic dry-run -> promote -> canary-gate
// -> auto-rollback path in update-apply.ts; the owner explicitly opts into a percentage ramp PER RELEASE. A
// ramp serves the new version to a FRACTION OF REAL TRAFFIC (it is NOT an isolated sandbox, isolated preview
// URLs need *.workers.dev, which downpipes bans; this is the honest, feasible substitute, O-2/O-6). The flow:
// verify + upload + RAMP to `percentage`% -> KEEP-at-percentage (await an explicit "promote to 100%") or
// AUTO-ROLLBACK to 100% prior on a non-singing verdict. The full-100% promote and the rollback both reuse
// deployVersion (atomic). Like the rest of this module it is pure orchestration, proven with fakes, and
// never throws out.
//
// TWO-PHASE (asvs-HI-13): exactly like update-apply.ts's promote/settle split, the canary/self-check gate
// MUST run in a genuinely SEPARATE request from the one that shifts traffic. startGradualRamp (phase 1,
// below) uploads + ramps `percentage`% and returns immediately as 'ramp-pending' -- it NEVER flies the
// canary. The request that calls driver.rampVersion() is still executing the bundle that was ALREADY loaded
// before that traffic-shift took effect (a Worker invocation cannot hot-swap the code it is mid-way through
// running), so an inline flight here would necessarily re-test the OLD version and falsely report the just-
// ramped one healthy (update-gate.ts's own header explains this is exactly what the promote/settle split
// exists to avoid). A genuinely later, separate call to settleAfterRamp (phase 2, mirroring
// settleAfterPromote) is required before a ramp can be trusted; because that later call is still only
// PROBABILISTICALLY routed onto the ramped slice (weighted by `percentage`, unlike the atomic settle's
// guaranteed 100% cutover), settleAfterRamp also verifies its own self-identity before trusting a keep
// decision, see its own header.
//
// Moved out of update-apply.ts (file-size remediation, finding engine-struct-miss-updateapply). Behaviour is
// unchanged: this module is re-exported by update-apply.ts so existing importers are untouched.

import type { CanaryLiveness } from "../canary/types.ts";
import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import type { ArtefactMeta, DeployDriver, GuardMessages, HealthGate, StepLog } from "./update-types.ts";
import { decideKeep, msg, verifyAndGuard } from "./update-types.ts";
import { compareSemver, isEngineCompatible } from "./updates.ts";

export interface RampInput {
  artefact: Uint8Array;
  expectedSha384: string;
  meta: ArtefactMeta;
  runningVersion: string;
  recommendedVersion: string;
  percentage: number; // the fraction of live traffic to serve the new version (1..99; clamped/validated)
  allowDowngrade?: boolean; // EXPLICIT owner opt-in to ramp a non-newer version (default false; see SafeApplyInput)
  settledHighWaterMark?: string; // R8 anti-rollback floor (highest version ever settled); see GuardInput
  // knownRollbackTarget/knownToVersion (asvs-HI-14-r2), threaded straight through to verifyAndGuard: the
  // route's own persisted-lifecycle known-good. See update-types.ts GuardInput for the full rationale.
  knownRollbackTarget?: string;
  knownToVersion?: string;
}

// RampOutcome (phase 1, startGradualRamp -- see settleAfterRamp below for phase 2's outcomes):
//   refused        aborted before any traffic shift (bad artefact, migration/compat guard, upload failed,
//                  invalid percentage, or the driver cannot ramp), engine unchanged
//   ramp-pending   the new version is now serving `percentage`% of live traffic; NOT YET VERIFIED. This
//                  call runs on the PRE-ramp code (see the module header), so it structurally cannot
//                  canary-gate the just-ramped version -- a genuinely separate settleAfterRamp call is
//                  required before the ramp can be trusted.
//   no-update      already on the recommended version
export type RampOutcome = "refused" | "ramp-pending" | "no-update";

export interface RampResult {
  outcome: RampOutcome;
  recommendedVersion: string;
  fromVersion?: string; // the prior (rollback) version
  toVersion?: string; // the new version
  percentage?: number; // the live percentage the new version is serving (on "ramp-pending")
  steps: StepLog[];
  reason?: string;
}

// rampPercentageValid bounds the opt-in ramp percentage to a real partial split (1..99 integer). 100 is not
// a ramp (use the atomic promote); 0 is a no-op; a non-integer/out-of-range value is refused. Pure.
export function rampPercentageValid(p: number): boolean {
  return Number.isInteger(p) && p >= 1 && p <= 99;
}

// RAMP_GUARD_MESSAGES is the gradual-ramp operator wording for the shared guard steps. The strings are
// byte-identical to the inline messages startGradualRamp used before the verifyAndGuard extraction, so the
// console copy is unchanged.
const RAMP_GUARD_MESSAGES: GuardMessages = {
  antiRollbackBelow: (rec, highWater) => `the recommended version ${rec} is BELOW ${highWater}, the highest version this engine has already successfully run; it will not be ramped even with downgrade allowed (going below a version you have run could re-introduce an already-patched issue). Use the Roll back control instead. Nothing was changed.`,
  antiRollbackIncomparable: (rec, highWater) => `the recommended version ${rec} cannot be compared to ${highWater} (the highest version this engine has already run), so it will not be ramped (it cannot be proven to be at or above that floor). Nothing was changed.`,
  forwardOnlyIncomparable: (rec, running) => `the recommended version ${rec} cannot be compared to the running engine ${running}, so it will not be ramped automatically. Nothing was changed.`,
  forwardOnlyNotNewer: (rec, running) => `the recommended version ${rec} is not newer than the running engine ${running}; a ramp only moves the engine forward (use the Roll back control to go back). Nothing was changed.`,
  migration: () => "this release requires a Durable Object migration and cannot be ramped (apply it manually); nothing was changed.",
  compat: (_rec, minEngine, running) => `this release requires engine version ${minEngine} or newer, but this engine is ${running}; nothing was changed.`,
  verifyNoHash: () => "the signed update channel did not declare a hash for this version, so the download cannot be verified; nothing was deployed.",
  verifyHashError: (detail) => `the update could not be hashed for verification; nothing was deployed: ${detail}`,
  verifyMismatch: () => "the downloaded update did not match the signed channel's hash (possible corruption or tampering); nothing was deployed.",
  recordRollbackError: (detail) => `could not read the engine's current deployed version, so there would be nothing to roll back to; nothing was changed: ${detail}`,
  liveSplit: (detail) => `the engine's live deployment is currently split across more than one version (${detail}), most likely another gradual ramp still in progress or awaiting a decision; the true rollback target cannot be determined automatically while more than one version is live. Settle or roll back that ramp (or resolve it from the Cloudflare dashboard) before ramping again. Nothing was changed.`,
};

// startGradualRamp is phase 1: it verifies + uploads the new version and ramps a fraction of traffic to it.
// It does NOT canary-gate (see the module header: this call runs on the PRE-ramp code, so it structurally
// cannot test the version it just shifted traffic to) -- settleAfterRamp, called separately, does that. It
// REUSES the same verify-before-deploy, migration guard, compat guard and record-the-rollback-target
// ordering as planAndPromote, so the ramp can never skip a safety check the atomic path enforces. It
// requires driver.rampVersion (the partial-split op); a driver without it is a clean refusal (never a
// silent 100% promote). Never throws.
export async function startGradualRamp(driver: DeployDriver, input: RampInput): Promise<RampResult> {
  const steps: StepLog[] = [];
  const log = (step: string, ok: boolean, detail?: string): void => {
    steps.push({ step, ok, ...(detail !== undefined ? { detail } : {}) });
  };
  const rec = input.recommendedVersion;
  const base = (extra: Partial<RampResult>): RampResult => ({ recommendedVersion: rec, steps, outcome: "refused", ...extra });

  if (input.runningVersion === rec) {
    log("up-to-date", true, `already running ${rec}`);
    return base({ outcome: "no-update" });
  }
  // Ramp-only guards (percentage in 1..99, the driver supports a split) run before the shared sequence so a
  // ramp that cannot proceed is refused without touching the deploy machinery.
  if (!rampPercentageValid(input.percentage)) {
    log("ramp-percentage", false, String(input.percentage));
    return base({ outcome: "refused", reason: "a gradual ramp needs a percentage between 1 and 99 (100% is the normal atomic promote); nothing was changed." });
  }
  if (typeof driver.rampVersion !== "function") {
    log("ramp-support", false, "driver cannot ramp");
    return base({ outcome: "refused", reason: "this deploy path does not support a gradual ramp; use the normal apply (atomic, canary-gated). Nothing was changed." });
  }
  // The SHARED guard sequence (forward-only, migration, compat, verify-artefact, record-rollback-target)
  // runs in verifyAndGuard so a guard change lands in one place (findings 023-02/023-11). The ramp-specific
  // operator wording is supplied here; a refusal is mapped straight into a RampResult.
  const guard = await verifyAndGuard(driver, input, RAMP_GUARD_MESSAGES, log, { sha384, hexEncode, isEngineCompatible, compareSemver });
  if (!guard.ok) return base({ outcome: "refused", reason: guard.reason });

  // Type narrowing only: a ramp is always live (never a dry run), so a failed rollback-target read already
  // refused inside verifyAndGuard and fromVersion is always present here. Refuse (fail-safe) if that breaks.
  if (guard.fromVersion === undefined) {
    return base({ outcome: "refused", reason: RAMP_GUARD_MESSAGES.recordRollbackError("the rollback target was not recorded") });
  }

  // Deployment phase: upload + ramp a fraction of traffic (NOT canary-gated here, see the module header).
  // Extracted per findings 023-01/023-02 so the shared guard phase and the ramp-specific deploy phase read
  // separately.
  return rampUploadAndGate(driver, input, base, log, guard.fromVersion);
}

// rampUploadAndGate is startGradualRamp's deployment phase (after the shared guard sequence): upload the
// new version and ramp `percentage`% of traffic to it. It does NOT fly the canary (asvs-HI-13): this
// function is still running inside the SAME request that called driver.rampVersion(), i.e. the bundle that
// was already loaded before the traffic-shift took effect, so a canary flown here would necessarily re-test
// the OLD code and could never observe the just-ramped version. It returns 'ramp-pending' immediately;
// settleAfterRamp (below), invoked by a genuinely separate later request, is what actually gates it.
// driver.rampVersion is guaranteed present (the caller refused a driver without it). Never throws. Split per
// finding engine-src-023-01.
async function rampUploadAndGate(
  driver: DeployDriver,
  input: RampInput,
  base: (extra: Partial<RampResult>) => RampResult,
  log: (step: string, ok: boolean, detail?: string) => void,
  fromVersion: string,
): Promise<RampResult> {
  const rec = input.recommendedVersion;
  // Upload the new version (NOT live yet).
  let toVersion: string;
  try {
    toVersion = await driver.uploadVersion(input.artefact, input.meta);
    log("upload-version", true, toVersion);
  } catch (e) {
    log("upload-version", false, msg(e));
    return base({ outcome: "refused", fromVersion, reason: `the new version could not be uploaded; your engine is unchanged: ${msg(e)}` });
  }

  // RAMP: serve `percentage`% to the new version, the rest to the prior. A failure leaves the prior at 100%.
  try {
    await driver.rampVersion!(toVersion, fromVersion, input.percentage);
    log("ramp", true, `${input.percentage}% -> ${toVersion}, ${100 - input.percentage}% -> ${fromVersion}`);
  } catch (e) {
    log("ramp", false, msg(e));
    return base({ outcome: "refused", fromVersion, toVersion, reason: `the gradual ramp could not be started; your engine is unchanged (still 100% on the prior version): ${msg(e)}` });
  }

  return base({ outcome: "ramp-pending", fromVersion, toVersion, percentage: input.percentage, reason: `version ${rec} is now serving ${input.percentage}% of live traffic; verification is PENDING (a separate check must confirm the ramped slice is healthy before it can be trusted). Promote it to 100% or roll it back once verified. Note: a ramp serves real traffic, not an isolated preview.` });
}

// RampSettleArgs carries phase-1's facts (the DO's pending-ramp record) into phase 2.
export interface RampSettleArgs {
  fromVersion: string; // the rollback target (100% prior)
  toVersion: string; // the uploaded + ramped version being verified
  recommendedVersion: string; // the semver this pending record is about (NOT a Cloudflare version id)
}

// RampSettleOutcome (phase 2, settleAfterRamp):
//   applied       a genuinely fresh request confirmed self-identity against toVersion's own recommended
//                 version AND the canary/self-check rule kept it; the ramp is now TRUSTED (still serving
//                 its configured percentage -- promote to 100% is a separate, explicit apply)
//   rolled-back   the ramped version did not pass verification (or the rollback deploy itself failed); the
//                 whole split was reverted to 100% on the prior version (or needs a manual re-deploy)
//   inconclusive  this settle request did NOT land on toVersion's own code (ENGINE_VERSION did not match
//                 the recommended version this pending record is about), so a healthy-looking result proves
//                 nothing about the ramped version specifically -- it may just as easily have re-tested the
//                 untouched majority slice. NOTHING was changed (no deploy; the pending stays armed): retry,
//                 each attempt is a fresh dispatch with its own `percentage`% chance of landing on the
//                 ramped slice.
//   rollback-failed-still-split  (G219) the ramped version did not pass AND the rollback to 100% prior FAILED.
//                 The deployment is STILL SPLIT: a live percentage of real customer traffic is still being
//                 routed to the suspect version, right now. This was recorded as "rolled-back", so the pack,
//                 the console badge and the bot all reported a reverted deployment while the split was still
//                 serving. The ramp's whole purpose is to bound blast radius, and the one outcome that says
//                 the blast radius is UNBOUNDED was the one it could not express.
export type RampSettleOutcome = "applied" | "rolled-back" | "inconclusive" | "rollback-failed-still-split";

export interface RampSettleResult {
  phase: "ramp-settle";
  outcome: RampSettleOutcome;
  recommendedVersion: string;
  fromVersion: string;
  toVersion: string;
  canaryBaseline?: CanaryLiveness;
  canaryVerdict?: CanaryLiveness;
  steps: StepLog[];
  reason?: string;
}

// settleAfterRamp is the ramp's phase 2. It MUST be invoked by a genuinely separate request from the one
// that ramped (mirroring settleAfterPromote), so Cloudflare has a chance to route THIS dispatch onto the
// ramped slice. UNLIKE settleAfterPromote (a guaranteed 100% cutover, so any request is certain to land on
// the new version), a ramp settle is only PROBABILISTICALLY routed (still `percentage`% / `100-percentage`%
// live): an "alive" canary verdict alone does NOT prove this request ran toVersion's code, it could just as
// easily be a fresh flight against the untouched majority slice. So self-identity (gate.selfCheck(), which
// update-gate.ts implements as ENGINE_VERSION === the recommended version this gate was built for) is
// consulted UNCONDITIONALLY here, not only as decideKeep's ailing/pending fallback, and gates whether a
// KEEP decision may be trusted at all -- a keep whose self-check fails is INCONCLUSIVE, not a rollback:
// there is no evidence the ramped code is unhealthy, only that this call could not observe it. Rollback
// remains the safe direction regardless of which slice was measured, so it is never gated on self-identity.
// Never throws (fail-safe).
export async function settleAfterRamp(driver: Pick<DeployDriver, "deployVersion">, gate: HealthGate, args: RampSettleArgs): Promise<RampSettleResult> {
  const steps: StepLog[] = [];
  const log = (step: string, ok: boolean, detail?: string): void => {
    steps.push({ step, ok, ...(detail !== undefined ? { detail } : {}) });
  };
  const { fromVersion, toVersion, recommendedVersion: rec } = args;

  let canaryBaseline: CanaryLiveness;
  try {
    canaryBaseline = await gate.baseline();
  } catch {
    canaryBaseline = "pending";
  }

  let canaryVerdict: CanaryLiveness;
  try {
    canaryVerdict = await gate.flyNow();
    log("canary-verdict", canaryVerdict === "alive", canaryVerdict);
  } catch (e) {
    canaryVerdict = "ailing";
    log("canary-verdict", false, `the canary flight errored on the ramped version: ${msg(e)}`);
  }

  // selfCheck is needed for EVERY non-dead verdict here (unlike settleAfterPromote, which trusts a bare
  // "alive" unconditionally because its 100% cutover already guarantees identity): it is this settle's ONLY
  // proof that THIS invocation actually ran toVersion's own code. A "dead" verdict never becomes a keep
  // (decideKeep below), so self-check is skipped there (nothing it could prove would change the outcome).
  let selfCheckOk = false;
  if (canaryVerdict !== "dead") {
    try {
      selfCheckOk = await gate.selfCheck();
    } catch {
      selfCheckOk = false;
    }
    log("self-check", selfCheckOk, selfCheckOk ? "this request ran the ramped version's own code and passed preflight" : "this request did not confirm it ran the ramped version's own code");
  }

  const decision = decideKeep(canaryBaseline, canaryVerdict, selfCheckOk);
  // RAMP-PATH STRICTNESS (HI-13), preserved across the incident-fix to decideKeep. That fix
  // relaxed decideKeep so an INCOMPLETE flight (ailing/pending) no longer auto-rolls-back on an alive
  // baseline -- because settleAfterPromote runs on the JUST-PROMOTED isolate, where the code-swap DO reset
  // can make a flight fail to complete for reasons that say nothing about the new build. That rationale does
  // NOT hold here: a ramp serves REAL production traffic and this settle is a genuinely SEPARATE dispatch,
  // not the just-promoted isolate. So on the ramp path a previously-ALIVE canary that degrades to a
  // non-alive verdict on the ramped code IS a regression we act on -- roll back even when the self-check
  // passes, exactly as this path shipped before the atomic-path fix relaxed decideKeep. (A dead verdict
  // already rolls back inside decideKeep; a non-alive baseline has no healthy reference to regress from, so
  // it falls through to decideKeep's self-check fallback unchanged, keeping when self-identity is proven.)
  const baselineRegression = canaryBaseline === "alive" && canaryVerdict !== "alive";
  const base = (extra: Partial<RampSettleResult>): RampSettleResult => ({ phase: "ramp-settle", recommendedVersion: rec, fromVersion, toVersion, canaryBaseline, canaryVerdict, steps, outcome: "rolled-back", ...extra });

  if (decision.keep && !baselineRegression) {
    // decideKeep's "alive" branch trusts the verdict unconditionally (it does not itself consult
    // selfCheckOk), which is exactly the false-assurance gap this finding closes: a keep is asserted here
    // ONLY once self-identity also confirms it (the ailing/pending+selfCheckOk branch already implies this).
    if (!selfCheckOk) {
      return base({ outcome: "inconclusive", reason: `this verification request did not land on the ramped version's own code, so its healthy-looking result does not prove version ${rec} is safe; the ramp is UNCHANGED, still serving its configured percentage. Verify again -- each attempt has a fresh chance of landing on the ramped slice.` });
    }
    log("decision", true, decision.reason);
    return base({ outcome: "applied", reason: `${decision.reason}, confirmed on the ramped version's own code. Version ${rec} is now trusted at its configured percentage of live traffic; promote it to 100% when you are comfortable, or roll back at any time.` });
  }
  // decision.reason is a KEEP reason when a baseline regression forced the rollback (decision.keep was
  // true), so name the regression explicitly for the log and operator message in that case.
  const rollbackReason = baselineRegression && decision.keep ? `the canary regressed from alive to ${canaryVerdict} on the ramped version` : decision.reason;
  log("decision", false, rollbackReason);
  try {
    await driver.deployVersion(fromVersion);
    log("rollback", true, `rolled back to 100% ${fromVersion}`);
    return base({ outcome: "rolled-back", reason: `the ramped version ${rec} did not pass verification (${rollbackReason}); the whole deployment was rolled back to 100% on the prior version. Nothing was lost and no backup or restore was affected.` });
  } catch (e) {
    log("rollback", false, msg(e));
    // G219: "a live traffic split still routes to the suspect version" -- and the enum said "rolled-back".
    return base({ outcome: "rollback-failed-still-split", reason: `the ramped version ${rec} did not pass verification AND the rollback to 100% prior FAILED (${msg(e)}); the deployment is STILL SPLIT and a share of live traffic is still reaching ${rec}. Re-deploy version ${fromVersion} from the Cloudflare dashboard. Your DATA and RECOVERY are unaffected (archives immutable; restore out-of-band).` });
  }
}
