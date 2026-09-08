// Shared base for the safe-apply update harness: the injected driver/gate interfaces, the step-log shape, the
// artefact metadata, and the two pure helpers (msg, liveSingleVersion) that the orchestration modules all use.
//
// This module holds ONLY the symbols that update-apply.ts, update-ramp.ts and update-rollback.ts all depend on,
// so the three orchestration files share them without importing each other (no circular dependency). The split
// is purely structural (file-size remediation, finding engine-struct-miss-updateapply); update-apply.ts
// re-exports every symbol here so the harness's public surface is unchanged and importers are untouched.

// StepLog is one ordered step of an apply/rollback/ramp attempt, surfaced to the console so the operator
// watches the harness reason in real terms (verify -> upload -> promote -> canary -> decision). Redaction-safe.
export interface StepLog {
  step: string;
  ok: boolean;
  detail?: string;
}

// ArtefactMeta is the channel-declared description of the new build. requiresMigration is the safety
// hatch: a release that needs a Durable Object migration (new DO classes / a destructive schema change)
// is REFUSED for auto-apply and must be applied manually, because the canary cannot prove a migration
// safe after the fact.
export interface ArtefactMeta {
  version: string;
  requiresMigration?: boolean;
  mainModule?: string; // the ESM entry module name in the bundle (driver default applies when absent)
  // minEngineVersion is the W2 compat floor: the OLDEST engine this release may be applied ONTO. When set
  // and the running engine is older (or the floor is unparseable), planAndPromote REFUSES before any deploy
  //, a clean refusal, nothing uploaded/promoted. Pairs with the existing requiresMigration refusal.
  minEngineVersion?: string;
}

// LiveVersionShare is one (versionId, percentage) slice of the live deployment. A normal deployment is a
// SINGLE slice at 100; an opt-in ramp is a real TWO-slice split. currentLiveVersions exposes the whole set so
// the orchestration can tell a single-version deployment from a split and NEVER short-circuit on a split.
export interface LiveVersionShare {
  versionId: string;
  percentage: number;
}

// DeployDriver abstracts the Cloudflare versions/deployments surface so the state machine is testable.
// uploadVersion creates a NOT-YET-LIVE version (preserving the engine's bindings/secrets/DOs) and
// returns its id; deployVersion makes a version the live deployment (used to promote AND to roll back).
// rampVersion (W4, OPT-IN) splits LIVE traffic between a new version and the prior one by percentage (the
// gradual-rollout path the owner opts into per release); it is OPTIONAL on the interface so existing fakes
// that don't ramp still satisfy it, the orchestration only calls it on the explicit ramp path.
export interface DeployDriver {
  // currentLiveVersionId returns the DOMINANT live version (the slice serving the most traffic). For a single
  // deployment that is the only version; for a split it is the larger slice. It is kept for the record-the-
  // rollback-target step; callers that must reason about a SPLIT use currentLiveVersions (below) instead of
  // assuming a single version.
  currentLiveVersionId(): Promise<string>;
  // currentLiveVersions returns EVERY live slice (versionId + percentage). OPTIONAL on the interface so
  // existing fakes that only model a single version still satisfy it; when absent, callers conservatively
  // treat the deployment as "shape unknown" and DO NOT short-circuit (they deploy the known-good at 100%,
  // which is idempotent and safe). The real cf-deploy driver implements it from the deployments endpoint.
  currentLiveVersions?(): Promise<LiveVersionShare[]>;
  uploadVersion(artefact: Uint8Array, meta: ArtefactMeta): Promise<string>;
  deployVersion(versionId: string): Promise<void>;
  // rampVersion serves `percentage`% of live traffic to newVersionId and the remainder to priorVersionId
  // (a real two-version traffic split, NOT an isolated preview). Optional: the default atomic-promote path
  // never calls it; only the opt-in gradual ramp does. Promoting to 100% afterwards uses deployVersion.
  rampVersion?(newVersionId: string, priorVersionId: string, percentage: number): Promise<void>;
  // fetchVersionModule (DP-D read-back, OPTIONAL) fetches the just-UPLOADED version's main module bytes
  // back from Cloudflare's own API so the apply can confirm the platform holds EXACTLY the signed bytes
  // BEFORE promotion (upload -> read back -> compare -> only then promote; a mismatch can never brick,
  // the previous version keeps serving). Optional so existing fakes and older drivers stay valid: when
  // absent the read-back gate reports "unavailable" honestly (warn mode proceeds; enforce mode refuses).
  // Throws with a redaction-safe reason when the platform response cannot be read as module bytes; the
  // A sandbox experiment is what graduates the gate from warn to enforce.
  fetchVersionModule?(versionId: string, mainModule: string): Promise<Uint8Array>;
}

// normaliseReadbackMode maps the UNTRUSTED env value (UPDATE_READBACK_MODE) to a gate mode. Absent or
// unknown reads as "warn", the safe default: evidence is recorded on every apply and nothing new can
// refuse. "off" and "enforce" must be explicit, exact spellings; enforce is enabled only after the
// A sandbox experiment proves the platform returns module bytes unchanged.
export function normaliseReadbackMode(v: unknown): "off" | "warn" | "enforce" {
  return v === "off" || v === "enforce" ? v : "warn";
}

// ReadbackResult is the DP-D read-back outcome recorded on the promote result and the lifecycle records:
// verified (the platform's bytes hash-equal the signed digest), mismatch (they do not; enforce mode
// refuses promotion), unavailable (no driver support, unrecognised endpoint shape, or a fetch failure --
// an honest non-answer that warn mode logs and enforce mode refuses). mode echoes the gate mode the
// verdict was produced under, so a record reads unambiguously later.
export interface ReadbackResult {
  verdict: "verified" | "mismatch" | "unavailable";
  mode: "off" | "warn" | "enforce";
  deployedSha384?: string; // present when bytes were read back and hashed (verified or mismatch)
  detail?: string; // redaction-safe reason for an unavailable/mismatch verdict
}

// HealthGate proves whether the live engine is healthy. baseline() is the canary liveness BEFORE the
// apply (read from the DO, kept current by the hourly cron, no extra flight). flyNow() runs a REAL
// canary flight against the configured destinations on the now-live code and folds it to one liveness.
// selfCheck() is the lighter fallback used only when the canary cannot gate (no destination configured):
// it confirms the new code boots, answers, and reports the expected version + a passing preflight.
export interface HealthGate {
  baseline(): Promise<import("../canary/types.ts").CanaryLiveness>;
  flyNow(): Promise<import("../canary/types.ts").CanaryLiveness>;
  selfCheck(): Promise<boolean>;
  // G275: the SAME flight as flyNow(), plus the one fact its CanaryLiveness cannot carry -- whether the cycle
  // MEASURED anything at all. A canary that resolved no destination attempts no probe and reports "pending",
  // which is byte-identical to a legitimately slow post-swap flight (a flight that ran and had not resolved).
  // Those are opposite tickets: "your engine could not reach its own config plane / destination" versus "wait
  // and settle again". Optional and ADDITIVE so the pure orchestrators (settleAfterPromote, settleAfterRamp,
  // runStandaloneRollback) and their fakes are untouched; probeSettleVerdict prefers it when the gate offers it.
  flyNowMeasured?(): Promise<{ status: import("../canary/types.ts").CanaryLiveness; measured: boolean }>;
}

// decideKeep is the gate rule (pure, so the validator drives every branch). It is OPTIMISTIC: a verified
// atomic promote is trusted and KEPT unless there is POSITIVE evidence the new build is bad.
//   alive -> KEEP (confirmed: the canary sings on the new version, every byte exact).
//   dead  -> ROLLBACK, always and immediately (a strayed byte is a DATA-INTEGRITY death -- the one and
//            only positive evidence of a bad build; never retried, never excused).
// ailing | pending -> KEEP (confirmation pending). This is the crux of the optimistic-keep rework: the
//            settle runs on the JUST-PROMOTED isolate, where the code swap has reset every Durable
//            Object, and BOTH the canary flight AND the self-check round-trip that DO -- so in the
//            post-swap window they routinely fail to COMPLETE. That is NOT evidence the build is bad; it
//            is the health check sitting inside its own blast radius. Three live drills rolled back
//            perfectly healthy updates on exactly this. So a non-dead verdict NO LONGER rolls back: we
//            keep the verified new version and let the HOURLY canary -- which runs from well clear of the
//            swap window -- be the real health gate (it auto-rolls-back and alerts if the build ever
//            proves genuinely unhealthy; the operator's one-click rollback covers the meantime). The
//            self-check result is RECORDED for diagnosis (it shapes the reason and the confidence) but
//            NEVER gates: a check that cannot run in this window must not decide a rollback.
// Data safety is independent of this choice: archives are immutable and recovery does not depend on the
// engine version, so a rare keep-then-genuinely-unhealthy build is an availability blip, never data loss.
// Shared here (not update-apply.ts) so settleAfterPromote AND settleAfterRamp (update-ramp.ts) can both
// call the SAME rule without the sibling orchestration files importing each other (see the module header).
// settleAfterRamp layers its OWN additional baseline-regression guard on top (a ramp serves real traffic
// and settles on a genuinely separate dispatch, so a previously-alive canary that degrades is acted on
// there even though this rule alone would keep) -- see update-ramp.ts.
export function decideKeep(_baseline: import("../canary/types.ts").CanaryLiveness, verdict: import("../canary/types.ts").CanaryLiveness, selfCheckOk: boolean): { keep: boolean; reason: string } {
  if (verdict === "alive") return { keep: true, reason: "the canary sings on the new version (every byte returned exactly)" };
  if (verdict === "dead") return { keep: false, reason: "the canary is dead on the new version (a bit strayed), rolling back" };
  // verdict is ailing | pending (the canary could not complete a clean flight) -> KEEP, confirmation pending.
  if (selfCheckOk) {
    return { keep: true, reason: `the canary could not complete a flight in the post-deploy window (${verdict}), but the new version self-checked healthy (booted, answered, reported the expected version); keeping it -- the hourly canary will confirm` };
  }
  return { keep: true, reason: `the canary could not complete a flight in the post-deploy window (${verdict}) and the self-check was inconclusive (the same Durable Object reset the swap causes); keeping the verified new version -- the hourly canary will confirm it, or roll it back and alert if it proves unhealthy` };
}

// msg normalises a thrown value to a redaction-safe string. Shared by every orchestration module.
export function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// optional builds a single-key object only when the value is defined, otherwise an empty object, so result
// assembly can spread `...optional("key", val)` rather than repeating the `val !== undefined ? {...} : {}`
// conditional inline. It keeps the optional-field shaping readable in one place.
export function optional<K extends string, V>(key: K, val: V | undefined): Partial<Record<K, V>> {
  return val !== undefined ? ({ [key]: val } as Partial<Record<K, V>>) : {};
}

// GuardMessages lets each caller (the atomic apply and the opt-in ramp) supply its OWN operator-facing
// refusal wording for the guard steps it shares, so verifyAndGuard can be the single guard sequence while
// the messages stay phrased for their context ("applied automatically" vs "ramped automatically", etc.).
export interface GuardMessages {
  // R8 anti-rollback floor wording: below the settled high-water mark, or uncomparable to it.
  antiRollbackBelow(rec: string, highWater: string): string;
  antiRollbackIncomparable(rec: string, highWater: string): string;
  forwardOnlyIncomparable(rec: string, running: string): string;
  forwardOnlyNotNewer(rec: string, running: string): string;
  migration(): string;
  compat(rec: string, minEngine: string, running: string): string;
  verifyNoHash(): string;
  verifyHashError(detail: string): string;
  verifyMismatch(): string;
  recordRollbackError(detail: string): string;
  // liveSplit (asvs-HI-14): the live deployment is currently split across more than one version (typically an
  // opt-in ramp in progress or awaiting a decision), so there is no single current version to trust as the
  // rollback target. Distinct from recordRollbackError: the read did not fail, its SHAPE is unsafe to use.
  liveSplit(detail: string): string;
}

// GuardInput is the subset of an apply/ramp request the shared guard sequence inspects.
export interface GuardInput {
  artefact: Uint8Array;
  expectedSha384: string;
  meta: ArtefactMeta;
  runningVersion: string;
  recommendedVersion: string;
  allowDowngrade?: boolean;
  // settledHighWaterMark (R8) is the MONOTONIC highest engine version this customer has ever SUCCESSFULLY
  // SETTLED (canary-passed "applied"), persisted in the DO and threaded in by the route. It is the
  // anti-rollback floor: an apply/ramp whose target is BELOW it is refused EVEN with allowDowngrade set, so a
  // (correctly-signed) channel can never push the customer back below a version they have run, which would
  // re-introduce an already-patched vulnerability. Absent/empty = no version settled yet = no floor.
  settledHighWaterMark?: string;
  // dryRun relaxes ONLY the record-rollback-target step: a dry run deploys nothing, so an unreadable
  // current version (the console's tokenless Preview -- the engine holds no deploy credentials by design)
  // is reported as an honest step instead of a refusal. Every other guard is identical, and a LIVE run
  // (absent/false) still refuses before any change when the rollback target cannot be read.
  dryRun?: boolean;
  // knownRollbackTarget/knownToVersion (asvs-HI-14-r2) are the caller-supplied, PERSISTED-lifecycle rollback
  // target and the version it promoted -- NEVER invented here, never derived from the live shape. They are
  // the SAME fact router-core.ts's resolveRollbackTarget already trusts for the standalone rollback route
  // (a prior transition's recorded outcome). When the live deployment IS a split, but its slices are
  // EXACTLY {knownRollbackTarget, knownToVersion}, that is precisely the shape of a still-live, already-
  // settled ramp awaiting its documented promote-to-100% (a plain apply) -- verifyAndGuard may trust
  // knownRollbackTarget instead of refusing unconditionally, because the value is the DO's own recorded
  // OUTCOME of a prior verification, not a guess about which live slice is dominant. Any OTHER split shape
  // (unrecognised versions, e.g. one created outside this engine's own bookkeeping) still refuses exactly
  // as before. Absent = no known-good on file = the split-refusal is unconditional (unchanged behaviour).
  knownRollbackTarget?: string;
  knownToVersion?: string;
}

// GuardResult is the typed outcome of the shared verify-and-guard sequence: either the guards passed and
// the rollback target was recorded (fromVersion -- absent ONLY on a dry run whose current-version read
// failed, e.g. the tokenless Preview), or a step refused with a logged step name + reason. The caller maps
// a refusal straight into its own PromoteResult/RampResult.
export type GuardResult =
  | { ok: true; fromVersion?: string }
  | { ok: false; step: string; detail?: string; reason: string };

// verifyAndGuard runs the SHARED safety sequence both the atomic apply (planAndPromote) and the opt-in ramp
// (startGradualRamp) must pass before any deploy, in this order: forward-only guard, migration guard, compat
// guard, verify-artefact (the bytes match the signed channel's hash), then record-the-rollback-target (asvs-
// HI-14: split-aware, see below). It appends each step to `steps` via `log` and returns a typed GuardResult.
// Extracted per findings engine-src-023-02/023-11 so a guard change lands in ONE place; the caller-specific
// wording comes from `m`. It depends on sha384/hexEncode and the semver helpers; it never throws (the verify
// hash + the rollback-target read are wrapped). The already-current short-circuit stays in each caller (its
// outcome differs). Pure orchestration over the injected driver.
export async function verifyAndGuard(
  driver: Pick<DeployDriver, "currentLiveVersionId" | "currentLiveVersions">,
  input: GuardInput,
  m: GuardMessages,
  log: (step: string, ok: boolean, detail?: string) => void,
  deps: { sha384: (b: Uint8Array) => Promise<Uint8Array>; hexEncode: (b: Uint8Array) => string; isEngineCompatible: (running: string, floor?: string) => boolean; compareSemver: (a: string, b: string) => number | null },
): Promise<GuardResult> {
  const rec = input.recommendedVersion;
  // Anti-rollback floor (R8): refuse a target BELOW the highest version ever successfully settled, the
  // monotonic high-water mark, EVEN with allowDowngrade set. allowDowngrade may cross the minEngineVersion
  // compat floor for a same-or-forward re-pin, but it must NEVER push the engine below a version this customer
  // has already run (that would re-introduce an already-patched vulnerability). It runs FIRST and
  // UNCONDITIONALLY (not gated on allowDowngrade) so a signed-but-stale channel can never drive a rollback to
  // a vulnerable build; the standalone Roll back control remains the (operator-driven, version-id-targeted)
  // path back to a recorded known-good. An uncomparable target vs a set floor is refused (fail-closed: we
  // cannot prove it is not below). Absent/empty floor = no version settled yet = nothing to enforce.
  const highWater = input.settledHighWaterMark;
  if (typeof highWater === "string" && highWater.trim() !== "") {
    const vsFloor = deps.compareSemver(rec, highWater);
    if (vsFloor === null || vsFloor < 0) {
      log("anti-rollback-guard", false, vsFloor === null ? `cannot compare ${rec} to the settled high-water mark ${highWater}` : `recommended ${rec} is below the settled high-water mark ${highWater}`);
      return { ok: false, step: "anti-rollback-guard", reason: vsFloor === null ? m.antiRollbackIncomparable(rec, highWater) : m.antiRollbackBelow(rec, highWater) };
    }
  }
  // Forward-only guard: refuse a non-newer / unparseable version unless the owner opted into a downgrade.
  if (input.allowDowngrade !== true) {
    const order = deps.compareSemver(rec, input.runningVersion);
    if (order !== 1) {
      log("forward-only-guard", false, `recommended ${rec} is not newer than running ${input.runningVersion}`);
      return { ok: false, step: "forward-only-guard", reason: order === null ? m.forwardOnlyIncomparable(rec, input.runningVersion) : m.forwardOnlyNotNewer(rec, input.runningVersion) };
    }
  }
  // Migration guard: a release needing a DO migration is manual-only.
  if (input.meta.requiresMigration) {
    log("migration-guard", false, "this release requires a Durable Object migration");
    return { ok: false, step: "migration-guard", reason: m.migration() };
  }
  // Compat guard (W2): refuse a release whose minEngineVersion is newer than the running engine.
  if (!deps.isEngineCompatible(input.runningVersion, input.meta.minEngineVersion)) {
    log("compat-guard", false, `requires engine >= ${input.meta.minEngineVersion}, running ${input.runningVersion}`);
    return { ok: false, step: "compat-guard", reason: m.compat(rec, input.meta.minEngineVersion ?? "", input.runningVersion) };
  }
  // Verify-before-deploy: the bytes must match the signed channel's declared hash.
  const expected = input.expectedSha384.trim().toLowerCase();
  if (expected === "") {
    log("verify-artefact", false, "the channel declared no artefact hash");
    return { ok: false, step: "verify-artefact", reason: m.verifyNoHash() };
  }
  let actual: string;
  try {
    actual = deps.hexEncode(await deps.sha384(input.artefact));
  } catch (e) {
    log("verify-artefact", false, msg(e));
    return { ok: false, step: "verify-artefact", reason: m.verifyHashError(msg(e)) };
  }
  if (actual !== expected) {
    log("verify-artefact", false, "sha384 mismatch");
    return { ok: false, step: "verify-artefact", reason: m.verifyMismatch() };
  }
  log("verify-artefact", true, "sha384 matches the signed channel");
  // Record the rollback target (the current live version) before any change. asvs-HI-14: when the driver
  // exposes the full slice set (currentLiveVersions), read THAT instead of the dominant-only
  // currentLiveVersionId -- on a live SPLIT (an opt-in ramp still in progress, or left mid-flight)
  // currentLiveVersionId() returns only the DOMINANT slice, which during a >50% ramp IS the just-promoted,
  // not-yet-trusted release, not the true pre-ramp baseline. Trusting it here would silently record the
  // release being applied/ramped as its OWN rollback target, so a later unhealthy verdict's auto-rollback
  // would redeploy the same untrusted build while reporting a safe "rolled back, nothing was lost".
  // liveSingleVersion is the SAME split-aware check update-rollback.ts's readLiveForRollback and the settle
  // superseded-guards (router-updates.ts) already use; an UNRECOGNISED split fails this step CLOSED rather
  // than guess which slice is the real baseline (below: a RECOGNISED split, one the caller's own persisted
  // lifecycle already vouches for, is trusted instead -- asvs-HI-14-r2). router-updates.ts additionally
  // refuses a second apply/ramp while a prior one's verification is still open (the primary guard for the
  // exploit this finding closed: a repeat call reaching planAndPromote/startGradualRamp mid-verification);
  // the unrecognised-split refusal here remains defence in depth for any caller that reaches verifyAndGuard
  // some other way (a split created outside this engine's own bookkeeping, or a future code path).
  let fromVersion: string;
  try {
    if (typeof driver.currentLiveVersions === "function") {
      const slices = await driver.currentLiveVersions();
      const single = liveSingleVersion(slices);
      if (single !== null) {
        fromVersion = single;
      } else {
        // asvs-HI-14-r2: a split is not automatically fatal. If it is EXACTLY the shape of the one prior
        // transition the caller's own persisted lifecycle already vouches for (knownRollbackTarget /
        // knownToVersion, see GuardInput -- never invented here), trust it instead of refusing: this is
        // precisely what a still-live, already-settled ramp awaiting its documented promote-to-100% looks
        // like, and nothing else in this codebase ever collapses that split, so refusing it unconditionally
        // would permanently disable the ramp feature's own completion step. Any OTHER split (unrecognised
        // versions -- e.g. one created outside this engine's own bookkeeping) still refuses exactly as
        // before (fail-closed).
        const serving = slices.filter((s) => s.percentage > 0).map((s) => s.versionId);
        const trusted = input.knownRollbackTarget;
        const knownIds = new Set([trusted, input.knownToVersion].filter((v): v is string => typeof v === "string" && v !== ""));
        if (trusted && serving.length > 0 && serving.every((id) => knownIds.has(id))) {
          fromVersion = trusted;
        } else {
          const label = slices.length === 0 ? "no live version reported" : slices.map((s) => `${s.versionId}@${s.percentage}%`).join(", ");
          log("record-rollback-target", false, `live deployment is split, not a single version (${label})`);
          return { ok: false, step: "record-rollback-target", reason: m.liveSplit(label) };
        }
      }
    } else {
      fromVersion = await driver.currentLiveVersionId();
    }
    log("record-rollback-target", true, fromVersion);
  } catch (e) {
    if (input.dryRun === true) {
      // A dry run deploys nothing, so there is nothing this read protects yet. It usually fails only
      // because no deploy token was supplied (the console's tokenless Preview; the engine itself holds no
      // Cloudflare credentials). Report it honestly and let the plan proceed -- the LIVE apply below this
      // boundary still refuses, before any change, when it cannot read the rollback target.
      log("record-rollback-target", false, `not read on this preview (${msg(e)}); the live apply reads it, with your deploy token, before any change`);
      return { ok: true };
    }
    log("record-rollback-target", false, msg(e));
    return { ok: false, step: "record-rollback-target", reason: m.recordRollbackError(msg(e)) };
  }
  return { ok: true, fromVersion };
}

// liveSingleVersion answers "is the live deployment EXACTLY one version, and which?" from the full slice set.
// It returns the sole versionId when the deployment is a single 100%-of-one-version deployment (the normal,
// non-ramped shape), else null (no slices, or a multi-version SPLIT). Callers use it to decide whether it is
// safe to short-circuit an "already on target" / "superseded" check: a short-circuit is only sound when the
// live deployment is a single known version. On a split, callers must NOT short-circuit, they deploy the
// known-good at 100% (idempotent/safe), collapsing the split. A zero-percentage slice is ignored (it serves
// no traffic). Pure, so the validator drives every branch.
export function liveSingleVersion(slices: LiveVersionShare[]): string | null {
  const serving = slices.filter((s) => typeof s.versionId === "string" && s.versionId !== "" && s.percentage > 0);
  if (serving.length !== 1) return null;
  return serving[0]!.versionId;
}
