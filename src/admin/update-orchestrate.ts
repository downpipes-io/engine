// Multi-component update orchestration: the CONSOLE-component state machines and the request parsing the
// component-aware routes share. The engine component keeps its existing machinery untouched (planAndPromote
// / settleAfterPromote / runStandaloneRollback in update-apply.ts); this module adds the console's, built
// from the SAME parts: the shared verifyAndGuard sequence, a per-component anti-rollback floor, and an
// injected driver (cf-assets-deploy.ts) so every invariant is proven by validators with fakes.
//
// SEQUENCING CONTRACT: when a release ships BOTH components, the engine applies FIRST and must SETTLE
// engine applies FIRST and must SETTLE (canary keep) before the console applies -- a new console may call
// new engine API, and engine API changes are additive, so engine-new + console-old is the compatibility
// direction that is always safe. The router enforces the ordering (the console intent is QUEUED on the
// engine's pending record and run by the settle route after an applied outcome); this module supplies the
// console-side verbs it runs.
//
// CONSOLE HEALTH GATE: the engine cannot honestly probe CONSOLE_ORIGIN over HTTP (customer consoles sit
// behind Cloudflare Access; the engine would see the Access challenge, not the console), so there is NO
// engine-side HTTP probe here. The engine-side gate is API-level promote confirmation (the promote lands
// at 100% and the deployments read confirms the new version is the live one); the REAL canary is the
// operator's browser (the console SPA checks its own build stamp after the swap -- the console's half,
// not this module's).

import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { type AssetsDeployDriver, type ConsoleBundle, parseConsoleBundle } from "./cf-assets-deploy.ts";
import type { RollbackOutcome } from "./update-rollback.ts";
import { type GuardMessages, liveSingleVersion, msg, type StepLog, verifyAndGuard } from "./update-types.ts";
import { type ComponentArtefact, compareSemver, isEngineCompatible, UPDATE_COMPONENTS, type UpdateComponent } from "./updates.ts";

export type { UpdateComponent };

// parseComponentsRequest validates the OPTIONAL `components` field of an update-family request (apply,
// settle, rollback, ramp: the console sends the SAME split on all of them, so they all read it through
// this one parser). ABSENT means the engine-only action, byte-for-byte -- returned as components:null so
// the router falls into the unchanged path. Present, it must be a non-empty array of component ids this
// build can plan (UPDATE_COMPONENTS); duplicates fold; anything else is a loud, honest refusal (400), and
// carries no pack counter: the console's own component ids are exactly the set this build plans, so no
// request a real client can send reaches that arm. Pure.
export function parseComponentsRequest(raw: unknown): { ok: true; components: UpdateComponent[] | null } | { ok: false; error: string } {
  if (raw === undefined) return { ok: true, components: null };
  if (!Array.isArray(raw) || raw.length === 0) {
    return { ok: false, error: 'components must be a non-empty array naming "engine" and/or "console" (omit the field entirely for the engine-only apply); nothing was changed' };
  }
  const out: UpdateComponent[] = [];
  for (const c of raw) {
    if (!(UPDATE_COMPONENTS as readonly unknown[]).includes(c)) {
      return { ok: false, error: `unknown update component ${JSON.stringify(c)}: this engine can update "engine" and "console"; nothing was changed` };
    }
    const id = c as UpdateComponent;
    if (!out.includes(id)) out.push(id);
  }
  return { ok: true, components: out };
}

// CONSOLE_GUARD_MESSAGES is the console-component operator wording for the shared guard steps, the
// console sibling of PROMOTE_GUARD_MESSAGES / RAMP_GUARD_MESSAGES. The forward-only pair is present for
// the GuardMessages contract but UNREACHABLE on this path (see applyConsoleComponent: the engine cannot
// know the console's running version, so the forward-only compare has no honest operand and is not run).
const CONSOLE_GUARD_MESSAGES: GuardMessages = {
  antiRollbackBelow: (rec, highWater) => `the console component ${rec} is BELOW ${highWater}, the highest console version this engine has already successfully applied; it will not be applied even with downgrade allowed (going below a version you have run could re-introduce an already-patched issue). Use the console Roll back control to return to a recorded known-good version. Nothing was changed.`,
  antiRollbackIncomparable: (rec, highWater) => `the console component ${rec} cannot be compared to ${highWater} (the highest console version this engine has already applied), so it will not be applied (it cannot be proven to be at or above that floor). Nothing was changed.`,
  forwardOnlyIncomparable: (rec) => `the console component ${rec} cannot be version-compared, so it will not be applied automatically. Nothing was changed.`,
  forwardOnlyNotNewer: (rec) => `the console component ${rec} is not applied automatically in the backward direction (use the console Roll back control). Nothing was changed.`,
  migration: () => "a console component never requires a Durable Object migration; refusing a release that claims one (nothing was changed).",
  compat: (_rec, minEngine, running) => `this console component requires engine version ${minEngine} or newer, but this engine is ${running}; update the engine first (the console is only deployed against a compatible engine). Nothing was changed.`,
  verifyNoHash: () => "the signed update channel did not declare a hash for this console component, so the download cannot be verified; nothing was deployed.",
  verifyHashError: (detail) => `the console component could not be hashed for verification; nothing was deployed: ${detail}`,
  verifyMismatch: () => "the downloaded console component did not match the signed channel's hash (possible corruption or tampering); nothing was deployed.",
  recordRollbackError: (detail) => `could not read the console's current deployed version, so there would be nothing to roll back to; nothing was changed: ${detail}`,
  // liveSplit (asvs-HI-14): a console deploy is always atomic (100% cutover; the console never ramps, see
  // router-updates.ts's "ramp is engine-only, forever"), so a live console split cannot come from this
  // engine's own operation -- it can only mean an out-of-band change (a manual Cloudflare dashboard action,
  // or a deploy outside this engine's bookkeeping). Reachable in principle (the console driver does expose
  // currentLiveVersions), so this is real defence in depth, not decoration.
  liveSplit: (detail) => `the console's live deployment is currently split across more than one version (${detail}), which this engine never does itself (a console release is always an atomic 100% cutover); resolve the split from the Cloudflare dashboard first. Nothing was changed.`,
};

export interface ConsoleApplyInput {
  bundleBytes: Uint8Array; // the downloaded console artefact file (hash-verified against the channel below)
  component: ComponentArtefact; // the verified channel's console entry (version + url + sha384 present)
  runningEngineVersion: string; // ENGINE_VERSION: the console's minEngineVersion is checked against the RUNNING ENGINE
  consoleFloor?: string; // floors.console, the console's own R8 anti-rollback floor
  dryRun: boolean; // verify + plan only (the same default posture as the engine apply)
}

// ConsoleApplyOutcome is the closed result of a console-component apply:
//   dry-run     verified + parsed + planned; nothing was uploaded or promoted
//   refused     aborted with the console UNCHANGED (guard refusal, bundle refusal, upload/promote failure
//               -- Cloudflare deploys are atomic, so a failed promote leaves the prior version serving)
//   applied     promoted at 100% AND the deployments read confirms the new version is the live one (the
//               engine-side gate; the operator's browser check is the real canary)
//   rolled-back the promote was accepted but the confirmation read showed a DIFFERENT live version, so the
//               recorded prior version was re-deployed (honest recovery, never a pretend success)
// G219: applied-unconfirmed and rollback-failed are the console arm's two honest outcomes for the states the
// enum previously mis-stated -- a promote whose live-version confirmation could not be read (so "applied" was
// claiming a proof it never obtained), and a rollback whose own deploy failed (so "rolled-back" was claiming a
// revert that did not happen, while the customer kept being served the bad console build).
export type ConsoleApplyOutcome = "dry-run" | "refused" | "applied" | "rolled-back" | "applied-unconfirmed" | "rollback-failed";

export interface ConsoleApplyResult {
  component: "console";
  outcome: ConsoleApplyOutcome;
  recommendedVersion: string; // the console component's own version
  fromVersion?: string; // the console version that was live before (the rollback target)
  toVersion?: string; // the console version that was uploaded/promoted
  steps: StepLog[];
  reason?: string;
}

// applyConsoleComponent is the console component's safe-apply state machine, the static-assets sibling of
// planAndPromote. Ordering IS the safety:
//   1. shared guard sequence (verifyAndGuard): per-component anti-rollback floor -> compat vs the RUNNING
//      ENGINE -> verify the bundle's sha384 against the signed channel -> record the console rollback
//      target. The FORWARD-ONLY guard deliberately does not run here: the engine cannot know the console's
//      running version (the design's one honest asymmetry), so its compare has no truthful operand; the
//      monotonic floors.console (which even allowDowngrade never crosses) plus the document-level R9
//      freshness guard carry the anti-backslide protection. requiresMigration is never set (there is no
//      console DO to migrate).
//   2. STRICT bundle parse (per-asset sha256 re-verified) + the bundle/channel version must agree.
//   3. dry-run stops here with the plan.  4. upload (inert until deployed).  5. atomic promote.
//   6. API-level confirmation read; a promote that did not land rolls back to the recorded target.
// Never throws (fail-safe); every path resolves to a structured result with a plain-words reason.
export async function applyConsoleComponent(driver: AssetsDeployDriver, input: ConsoleApplyInput): Promise<ConsoleApplyResult> {
  const steps: StepLog[] = [];
  const log = (step: string, ok: boolean, detail?: string): void => {
    steps.push({ step, ok, ...(detail !== undefined ? { detail } : {}) });
  };
  const rec = input.component.version;
  const base = (extra: Partial<ConsoleApplyResult>): ConsoleApplyResult => ({ component: "console", recommendedVersion: rec, steps, outcome: "refused", ...extra });

  // 1. The shared guard sequence. allowDowngrade:true here is NOT an owner downgrade opt-in: it is how
  // this path expresses "the forward-only compare has no honest operand for the console" (see the module
  // comment); the anti-rollback floor above it runs FIRST and UNCONDITIONALLY either way.
  const guard = await verifyAndGuard(
    driver,
    {
      artefact: input.bundleBytes,
      expectedSha384: input.component.sha384 ?? "",
      meta: { version: rec, ...(input.component.minEngineVersion !== undefined ? { minEngineVersion: input.component.minEngineVersion } : {}) },
      runningVersion: input.runningEngineVersion,
      recommendedVersion: rec,
      allowDowngrade: true,
      ...(input.consoleFloor !== undefined ? { settledHighWaterMark: input.consoleFloor } : {}),
      dryRun: input.dryRun,
    },
    CONSOLE_GUARD_MESSAGES,
    log,
    { sha384, hexEncode, isEngineCompatible, compareSemver },
  );
  if (!guard.ok) return base({ outcome: "refused", reason: guard.reason });
  const fromVersion = guard.fromVersion;

  // 2. STRICT parse + per-asset verification of the (channel-hash-verified) bundle bytes.
  let bundle: ConsoleBundle;
  try {
    bundle = await parseConsoleBundle(input.bundleBytes);
    log("parse-console-bundle", true, `${bundle.assets.length} asset(s) + the shell worker (${bundle.worker.mainModule})`);
  } catch (e) {
    log("parse-console-bundle", false, msg(e));
    return base({ outcome: "refused", ...(fromVersion !== undefined ? { fromVersion } : {}), reason: `the console bundle did not verify: ${msg(e)}` });
  }
  if (bundle.version !== rec) {
    log("bundle-version", false, `bundle says ${bundle.version}, the signed channel says ${rec}`);
    return base({ outcome: "refused", ...(fromVersion !== undefined ? { fromVersion } : {}), reason: `the console bundle self-describes as ${bundle.version} but the signed channel offered ${rec}; refusing the mismatch (nothing was changed)` });
  }

  // 3. DRY-RUN: verified + parsed + planned, nothing deployed.
  if (input.dryRun) {
    log("dry-run", true, fromVersion !== undefined ? `would upload ${bundle.assets.length} asset(s) + the shell worker and promote atomically; the console rollback target is ${fromVersion}` : `would upload ${bundle.assets.length} asset(s) + the shell worker and promote atomically; the rollback target is read, with your deploy token, at apply time`);
    return base({ outcome: "dry-run", ...(fromVersion !== undefined ? { fromVersion } : {}) });
  }
  // Type narrowing only: on a LIVE run a failed rollback-target read already refused inside verifyAndGuard.
  if (fromVersion === undefined) {
    return base({ outcome: "refused", reason: CONSOLE_GUARD_MESSAGES.recordRollbackError("the rollback target was not recorded") });
  }

  // 4. Upload the new console version (inert until deployed). A failure leaves the console unchanged.
  let toVersion: string;
  try {
    toVersion = await driver.uploadVersion(bundle);
    log("upload-version", true, toVersion);
  } catch (e) {
    log("upload-version", false, msg(e));
    return base({ outcome: "refused", fromVersion, reason: `the new console version could not be uploaded; your console is unchanged: ${msg(e)}` });
  }

  // 5. Atomic promote. A failure leaves the PRIOR console version serving (a clean refusal, no rollback needed).
  try {
    await driver.deployVersion(toVersion);
    log("promote", true, toVersion);
  } catch (e) {
    log("promote", false, msg(e));
    return base({ outcome: "refused", fromVersion, toVersion, reason: `the new console version was uploaded but promotion failed; your console is unchanged (the previously-live version is still serving): ${msg(e)}` });
  }

  // 6. API-LEVEL CONFIRMATION (the engine-side console gate; contract: no HTTP probe of CONSOLE_ORIGIN --
  // Access would answer, not the console). Re-read the live deployment: the just-promoted version must be
  // the live one. A DIFFERENT live version means the promote did not land as expected -> roll back to the
  // recorded target (honest recovery). An UNREADABLE confirmation is reported as a step but keeps the
  // applied outcome (the promote API accepted the deploy, which is the primary confirmation; the operator's
  // browser check is the real canary either way).
  try {
    const liveNow = await driver.currentLiveVersionId();
    if (liveNow === toVersion) {
      log("confirm-live", true, toVersion);
      return base({ outcome: "applied", fromVersion, toVersion, reason: `console ${rec} is live (promote confirmed at 100%). Reload the console to finish; if the page misbehaves, use the console Roll back control.` });
    }
    log("confirm-live", false, `expected ${toVersion} live, found ${liveNow}`);
  } catch (e) {
    log("confirm-live", false, `the confirmation read failed (${msg(e)}); the promote API accepted the deploy`);
    // G219: "applied" is a claim of PROOF -- the promote landed AND the live version was read back and matched.
    // Here the read-back never happened, so the engine cannot say which version is live. It reported "applied"
    // anyway, which is the enum asserting a confirmation it does not have.
    return base({ outcome: "applied-unconfirmed", fromVersion, toVersion, reason: `console ${rec} was promoted, but the confirmation read failed, so the live version could not be verified; verify from your browser (reload the console) and use the console Roll back control if it misbehaves.` });
  }
  try {
    await driver.deployVersion(fromVersion);
    log("rollback", true, `rolled back to ${fromVersion}`);
    return base({ outcome: "rolled-back", fromVersion, toVersion, reason: `the console promote did not land as the live version, so the console was rolled back to the recorded prior version. The engine is unaffected; retry the console component alone.` });
  } catch (e) {
    log("rollback", false, msg(e));
    // G219: the console rollback FAILED and the enum said "rolled-back". The customer is still being served
    // the unexpected console build.
    return base({ outcome: "rollback-failed", fromVersion, toVersion, reason: `the console promote did not land as the live version AND the rollback to the prior version failed (${msg(e)}); the console may be serving an unexpected version -- re-deploy version ${fromVersion} from the Cloudflare dashboard. The engine, your DATA and RECOVERY are unaffected.` });
  }
}

export interface ConsoleRollbackResult {
  component: "console";
  outcome: RollbackOutcome;
  fromVersion?: string; // the console version that was live before the rollback
  toVersion: string; // the known-good console version reverted to (or attempted)
  steps: StepLog[];
  reason?: string;
}

// rollbackConsoleComponent is the STANDALONE console rollback, mirroring runStandaloneRollback for the
// console script minus the engine canary (a static-assets swap has no canary; the gate is the same
// API-level confirmation the apply uses, and the operator's browser is the real check). Same closed
// outcomes; same split-awareness (never short-circuit on a multi-version split -- deploy the known-good at
// 100% to collapse it). Never throws (fail-safe).
export async function rollbackConsoleComponent(driver: AssetsDeployDriver, args: { toVersion: string }): Promise<ConsoleRollbackResult> {
  const steps: StepLog[] = [];
  const log = (step: string, ok: boolean, detail?: string): void => {
    steps.push({ step, ok, ...(detail !== undefined ? { detail } : {}) });
  };
  const toVersion = (args.toVersion ?? "").trim();
  const base = (extra: Partial<ConsoleRollbackResult>): ConsoleRollbackResult => ({ component: "console", toVersion, steps, outcome: "failed", ...extra });

  if (toVersion === "") {
    log("rollback-target", false, "no recorded known-good console version");
    return base({ outcome: "no-target", reason: "there is no recorded prior console version to roll back to; nothing was changed. (A console rollback target is recorded the first time a console component is applied from here.)" });
  }

  // 1. Read the live console deployment (what we revert away from + the single-vs-split shape).
  let fromVersion: string;
  let liveSingle: string | null;
  try {
    const slices = await driver.currentLiveVersions();
    liveSingle = liveSingleVersion(slices);
    fromVersion = await driver.currentLiveVersionId();
    log("read-live-version", true, liveSingle === null ? `${fromVersion} (split: ${slices.map((s) => `${s.versionId}@${s.percentage}%`).join(", ")})` : fromVersion);
  } catch (e) {
    log("read-live-version", false, msg(e));
    return base({ outcome: "failed", reason: `could not read the console's current deployed version, so a rollback cannot be performed safely; nothing was changed: ${msg(e)}` });
  }

  // 2. Already on the target (single-version deployments only; a split is collapsed by deploying at 100%).
  if (liveSingle !== null && liveSingle === toVersion) {
    log("already-on-target", true, toVersion);
    return base({ outcome: "already", fromVersion, reason: `the console is already serving version ${toVersion}; nothing was changed.` });
  }

  // 3. Deploy the known-good console version (atomic; a failure leaves the prior version serving).
  try {
    await driver.deployVersion(toVersion);
    log("deploy-known-good", true, toVersion);
  } catch (e) {
    log("deploy-known-good", false, msg(e));
    return base({ outcome: "failed", fromVersion, reason: `could not roll the console back to version ${toVersion} (the previously-live console version is still serving; Cloudflare deploys are atomic, so nothing was half-applied): ${msg(e)}` });
  }

  // 4. API-level confirmation (the console's gate; no canary exists for a static-assets swap).
  try {
    const liveNow = await driver.currentLiveVersionId();
    if (liveNow === toVersion) {
      log("confirm-live", true, toVersion);
      return base({ outcome: "reverted", fromVersion, reason: `rolled the console back to the known-good version ${toVersion} (promote confirmed at 100%). Reload the console in your browser.` });
    }
    log("confirm-live", false, `expected ${toVersion} live, found ${liveNow}`);
    return base({ outcome: "reverted-unverified", fromVersion, reason: `the console rollback was accepted but the live deployment reads as a different version; investigate from the Cloudflare dashboard. Your engine, DATA and RECOVERY are unaffected.` });
  } catch (e) {
    log("confirm-live", false, msg(e));
    return base({ outcome: "reverted-unverified", fromVersion, reason: `rolled the console back to version ${toVersion}, but the confirmation read failed (${msg(e)}); reload the console in your browser to verify. Your engine, DATA and RECOVERY are unaffected.` });
  }
}
