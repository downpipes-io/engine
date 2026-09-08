// Prove the safe-apply update pipeline can NEVER brick a customer: it only ever uploads/promotes a
// SHA-384-verified artefact, records a rollback target before any change, canary-gates the promotion,
// auto-rolls-back on any non-singing verdict, and is fail-safe (never throws out). Driven entirely with
// a fake DeployDriver + fake HealthGate, so the exact shipped state machine is exercised with no
// Cloudflare account and no real deploy. Run:
//   node test/validate-update-apply.ts
// In-memory only; no network, no deploy, no cost.

import { runSafeApply, planAndPromote, settleAfterPromote, decideKeep, runStandaloneRollback, startGradualRamp, rampPercentageValid, settleAfterRamp, liveSingleVersion, type DeployDriver, type HealthGate, type ArtefactMeta, type SafeApplyInput, type UpdateApplyResult, type RampInput, type LiveVersionShare } from "../src/admin/update-apply.ts";
import { engineRollbackSatisfiesConsoleFloor } from "../src/admin/update-rollback.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { hexEncode, utf8 } from "../src/crypto/bytes.ts";
import type { CanaryLiveness } from "../src/canary/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const NEW_ID = "v-new";
const OLD_ID = "v-old";

// A fake DeployDriver that records exactly what was called, so the tests can prove the ORDER and the
// PRESENCE/ABSENCE of upload/promote/rollback. Each failure mode is independently switchable.
interface DriverOpts { current?: string; newId?: string; currentFails?: boolean; uploadFails?: boolean; promoteFails?: boolean; rollbackFails?: boolean; rampFails?: boolean; noRamp?: boolean; liveSlices?: LiveVersionShare[]; readbackBytes?: Uint8Array | "throw" }
class FakeDriver implements DeployDriver {
  currentCalls = 0;
  uploadCalls = 0;
  readbackCalls = 0;
  deployCalls: string[] = []; // ids passed to deployVersion, in order (promote then rollback)
  rampCalls: Array<{ newId: string; priorId: string; percentage: number }> = [];
  rampVersion?: (newVersionId: string, priorVersionId: string, percentage: number) => Promise<void>;
  fetchVersionModule?: (versionId: string, mainModule: string) => Promise<Uint8Array>;
  // currentLiveVersions is OPTIONAL on the interface; provided only when liveSlices is set so we can test BOTH
  // the split-aware path (driver exposes slices) and the legacy single-version path (method absent).
  currentLiveVersions?: () => Promise<LiveVersionShare[]>;
  private opts: DriverOpts;
  constructor(opts: DriverOpts = {}) {
    this.opts = opts;
    // rampVersion is OPTIONAL on the interface; omit it when noRamp is set (to prove the orchestration
    // refuses cleanly against a driver that cannot ramp).
    if (!opts.noRamp) {
      this.rampVersion = async (newVersionId: string, priorVersionId: string, percentage: number): Promise<void> => {
        this.rampCalls.push({ newId: newVersionId, priorId: priorVersionId, percentage });
        if (this.opts.rampFails) throw new Error("ramp failed");
      };
    }
    if (opts.liveSlices) {
      const slices = opts.liveSlices;
      this.currentLiveVersions = async (): Promise<LiveVersionShare[]> => slices;
    }
    // fetchVersionModule is OPTIONAL on the interface; provided only when readbackBytes is set so the
    // tests cover BOTH the driver-supports-read-back arms and the honest "unavailable" absent-method arm.
    if (opts.readbackBytes !== undefined) {
      const rb = opts.readbackBytes;
      this.fetchVersionModule = async (_versionId: string, _mainModule: string): Promise<Uint8Array> => {
        this.readbackCalls++;
        if (rb === "throw") throw new Error("version read-back endpoint errored");
        return rb;
      };
    }
  }
  async currentLiveVersionId(): Promise<string> {
    this.currentCalls++;
    if (this.opts.currentFails) throw new Error("could not read current version");
    // When a split is modelled, the dominant slice is the live version (mirrors the real driver).
    if (this.opts.liveSlices && this.opts.liveSlices.length > 0) {
      let best = this.opts.liveSlices[0]!;
      for (const s of this.opts.liveSlices) if (s.percentage > best.percentage) best = s;
      return best.versionId;
    }
    return this.opts.current ?? OLD_ID;
  }
  async uploadVersion(_artefact: Uint8Array, _meta: ArtefactMeta): Promise<string> {
    this.uploadCalls++;
    if (this.opts.uploadFails) throw new Error("upload failed");
    return this.opts.newId ?? NEW_ID;
  }
  async deployVersion(versionId: string): Promise<void> {
    this.deployCalls.push(versionId);
    const newId = this.opts.newId ?? NEW_ID;
    const oldId = this.opts.current ?? OLD_ID;
    if (this.opts.promoteFails && versionId === newId) throw new Error("promote failed");
    if (this.opts.rollbackFails && versionId === oldId) throw new Error("rollback failed");
  }
}

interface GateOpts { baseline?: CanaryLiveness; verdict?: CanaryLiveness; flyThrows?: boolean; selfCheck?: boolean }
class FakeGate implements HealthGate {
  flyCalls = 0;
  selfCheckCalls = 0;
  private opts: GateOpts;
  constructor(opts: GateOpts = {}) {
    this.opts = opts;
  }
  async baseline(): Promise<CanaryLiveness> {
    return this.opts.baseline ?? "alive";
  }
  async flyNow(): Promise<CanaryLiveness> {
    this.flyCalls++;
    if (this.opts.flyThrows) throw new Error("canary flight errored");
    return this.opts.verdict ?? "alive";
  }
  async selfCheck(): Promise<boolean> {
    this.selfCheckCalls++;
    return this.opts.selfCheck ?? false;
  }
}

// Fixtures bundles the shared builders/values so each extracted scenario group receives them as a
// single parameter rather than closing over a 380-line main(). Behaviour is unchanged: the same
// builders, the same artefact and hash, run in the same order.
interface Fixtures {
  artefact: Uint8Array;
  goodHash: string;
  input: (over?: Partial<SafeApplyInput>) => SafeApplyInput;
  rampInput: (over?: Partial<RampInput>) => RampInput;
  unhashable: Uint8Array;
}

// ---- decideKeep + the core safe-apply scenarios (1..15) ----
async function testDecideKeepAndCoreApply(fx: Fixtures): Promise<void> {
  const { input } = fx;
  // ---- decideKeep: the OPTIMISTIC gate rule, every branch ( rework, after three live drills
  // rolled back healthy updates). A verified atomic promote is KEPT unless there is POSITIVE evidence the
  // build is bad -- and the ONLY such evidence is a DEAD canary (a strayed byte on a COMPLETED flight, a
  // data-integrity failure). A canary that cannot COMPLETE (pending/ailing) is the post-swap DO-reset
  // window, NOT a bad build, so it KEEPS (confirmation pending) regardless of the self-check; the hourly
  // canary confirms from clear of the window. The self-check no longer gates -- it is recorded for
  // diagnosis and shapes the reason only. ----
  ok("decideKeep: alive -> keep", decideKeep("alive", "alive", false).keep === true);
  ok("decideKeep: dead -> rollback", decideKeep("alive", "dead", true).keep === false);
  ok("decideKeep: dead always rolls back even with selfcheck ok", decideKeep("pending", "dead", true).keep === false);
  {
    // A non-dead verdict ALWAYS keeps now -- self-check true OR false, any baseline. Only the REASON differs.
    const keptSelf = decideKeep("alive", "pending", true);
    ok("decideKeep: pending + selfcheck ok -> KEEP", keptSelf.keep === true);
    ok("decideKeep: the self-checked keep reason says the hourly canary will confirm", /hourly canary will confirm/.test(keptSelf.reason));
    const keptOptimistic = decideKeep("alive", "pending", false);
    ok("decideKeep: pending + selfcheck INCONCLUSIVE -> KEEP (optimistic, no longer a rollback)", keptOptimistic.keep === true);
    ok("decideKeep: the optimistic keep reason names the swap-window DO reset + the hourly canary safety net", /Durable Object|hourly canary/.test(keptOptimistic.reason));
    ok("decideKeep: ailing + selfcheck ok -> KEEP", decideKeep("alive", "ailing", true).keep === true);
    ok("decideKeep: ailing + selfcheck FAIL -> KEEP (optimistic)", decideKeep("alive", "ailing", false).keep === true);
    ok("decideKeep: no-baseline + pending + selfcheck FAIL -> KEEP (optimistic)", decideKeep("pending", "pending", false).keep === true);
  }

  // ---- engineRollbackSatisfiesConsoleFloor (design UPDATE-UX-015 §6): the conditional-bundling rollback
  // floor check. No floor -> always satisfied (engine-only), regardless of whether the target even parses
  // (the undefined-floor short-circuit runs BEFORE any compareSemver call); a satisfied/violated floor is
  // the ordinary compareSemver >=/< read; an UNPARSEABLE comparison -- crucially including the REALISTIC
  // production shape (a bare Cloudflare version id, never a semver) -- fails CLOSED (does NOT satisfy, so
  // the caller pairs rather than strand a console on an engine it cannot prove compatible with). ----
  ok("[§6] no floor (undefined) -> satisfied regardless of the target's shape", engineRollbackSatisfiesConsoleFloor("0.5.0", undefined) === true);
  ok("[§6] no floor (blank string) -> satisfied", engineRollbackSatisfiesConsoleFloor("0.5.0", "") === true);
  ok("[§6] no floor -> satisfied even when the target itself is unparseable", engineRollbackSatisfiesConsoleFloor("not-a-version", undefined) === true);
  ok("[§6] target strictly above the floor -> satisfied", engineRollbackSatisfiesConsoleFloor("0.5.0", "0.3.0") === true);
  ok("[§6] target exactly equal to the floor -> satisfied", engineRollbackSatisfiesConsoleFloor("0.5.0", "0.5.0") === true);
  ok("[§6] target strictly below the floor -> VIOLATED (does not satisfy)", engineRollbackSatisfiesConsoleFloor("0.2.0", "0.5.0") === false);
  ok("[§6] an unparseable target vs a set floor fails CLOSED (does not satisfy)", engineRollbackSatisfiesConsoleFloor("not-a-version", "0.1.0") === false);
  ok("[§6] a genuine Cloudflare version id (the realistic rollback target) vs a set floor fails CLOSED", engineRollbackSatisfiesConsoleFloor("017e156b-2b34-4a3e-b3a4-9a5f5a5f5a5f", "0.1.0") === false);
  ok("[§6] an unparseable FLOOR vs a parseable target also fails CLOSED", engineRollbackSatisfiesConsoleFloor("0.5.0", "not-a-version") === false);

  // ---- 1. already current -> no-update, nothing touched ----
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ runningVersion: "0.2.0" }));
    ok("already current -> no-update", r.outcome === "no-update");
    ok("no-update touches no deploy machinery", d.currentCalls === 0 && d.uploadCalls === 0 && d.deployCalls.length === 0);
  }

  // ---- 2. migration guard -> refused, nothing touched ----
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ meta: { version: "0.2.0", requiresMigration: true } }));
    ok("migration required -> refused", r.outcome === "refused");
    ok("migration refusal touches no deploy machinery", d.currentCalls === 0 && d.uploadCalls === 0 && d.deployCalls.length === 0);
  }

  // ---- 2b. COMPAT GUARD: minEngineVersion newer than the running engine -> refused, nothing touched ------
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ runningVersion: "0.1.0", meta: { version: "0.2.0", minEngineVersion: "0.2.0" } }));
    ok("over-minEngineVersion -> refused", r.outcome === "refused");
    ok("compat refusal touches no deploy machinery (refuse-before-deploy)", d.currentCalls === 0 && d.uploadCalls === 0 && d.deployCalls.length === 0);
    ok("compat refusal reason names the required version", /requires engine version|0\.2\.0 or newer/i.test(r.reason ?? ""));
  }
  // an UNPARSEABLE floor is also refused (never applied blind)
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ meta: { version: "0.2.0", minEngineVersion: "not-a-version" } }));
    ok("unparseable minEngineVersion -> refused (no deploy)", r.outcome === "refused" && d.uploadCalls === 0);
  }
  // a floor the engine SATISFIES does NOT block the happy path (running 0.1.0 >= floor 0.1.0)
  {
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "alive", verdict: "alive" });
    const r = await runSafeApply(d, g, input({ runningVersion: "0.1.0", meta: { version: "0.2.0", minEngineVersion: "0.1.0" } }));
    ok("satisfied minEngineVersion does not block apply", r.outcome === "applied" && d.uploadCalls === 1);
  }

  // ---- 2c. FORWARD-ONLY GUARD (FOLD 4): a correctly-signed OLDER channel must NOT silently downgrade ----
  {
    // recommended (0.1.0) is OLDER than running (0.2.0) -> refused before ANY deploy machinery is touched
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ runningVersion: "0.2.0", recommendedVersion: "0.1.0" }));
    ok("older recommended -> refused (no silent downgrade)", r.outcome === "refused");
    ok("downgrade refusal touches NO deploy machinery", d.currentCalls === 0 && d.uploadCalls === 0 && d.deployCalls.length === 0);
    ok("downgrade refusal reason names Roll back / not newer", /not newer|Roll back/i.test(r.reason ?? ""));
  }
  {
    // an UNPARSEABLE recommended version is also refused (null compare -> refuse, never apply blind)
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ runningVersion: "0.2.0", recommendedVersion: "not-a-version" }));
    ok("unparseable recommended -> refused (no deploy)", r.outcome === "refused" && d.uploadCalls === 0);
  }
  {
    // EQUAL versions still short-circuit as no-update (the equality check precedes the forward-only guard)
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ runningVersion: "0.2.0", recommendedVersion: "0.2.0" }));
    ok("equal version -> no-update (not a downgrade refusal)", r.outcome === "no-update" && d.uploadCalls === 0);
  }
  {
    // EXPLICIT downgrade-to-recover (allowDowngrade) is permitted: an older version applies, still canary-gated
    const d = new FakeDriver({ current: NEW_ID, newId: OLD_ID });
    const g = new FakeGate({ baseline: "alive", verdict: "alive" });
    const r = await runSafeApply(d, g, input({ runningVersion: "0.2.0", recommendedVersion: "0.1.0", allowDowngrade: true }));
    ok("explicit allowDowngrade -> applies the older version (canary-gated)", r.outcome === "applied" && d.uploadCalls === 1);
  }

  // ---- 3. VERIFY BEFORE DEPLOY: a bad hash refuses with NO deploy machinery touched at all ----
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ expectedSha384: "deadbeef" }));
    ok("bad artefact hash -> refused", r.outcome === "refused");
    ok("bad artefact NEVER reads/uploads/promotes (verify-before-deploy)", d.currentCalls === 0 && d.uploadCalls === 0 && d.deployCalls.length === 0);
    ok("bad artefact reason names corruption/tampering", /hash|corrupt|tamper/i.test(r.reason ?? ""));
  }
  // empty channel hash is unverifiable -> refused
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ expectedSha384: "" }));
    ok("empty channel hash -> refused (unverifiable)", r.outcome === "refused" && d.uploadCalls === 0);
  }

  // ---- 4. DRY RUN: verifies + records rollback target + baseline, but NEVER uploads or promotes ----
  {
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "alive" });
    const r = await runSafeApply(d, g, input({ dryRun: true }));
    ok("dry-run -> outcome dry-run", r.outcome === "dry-run");
    ok("dry-run verifies + records rollback target", d.currentCalls === 1 && r.fromVersion === OLD_ID);
    ok("dry-run NEVER uploads or promotes", d.uploadCalls === 0 && d.deployCalls.length === 0 && g.flyCalls === 0);
  }

  // ---- 5. HAPPY PATH: alive canary -> applied (promote only, no rollback) ----
  {
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "alive", verdict: "alive" });
    const r = await runSafeApply(d, g, input());
    ok("alive canary -> applied", r.outcome === "applied");
    ok("applied uploads once + promotes once + does NOT roll back", d.uploadCalls === 1 && d.deployCalls.length === 1 && d.deployCalls[0] === NEW_ID);
    ok("applied records from/to versions + verdict", r.fromVersion === OLD_ID && r.toVersion === NEW_ID && r.canaryVerdict === "alive");
    // [§3] a keep the CANARY ITSELF confirmed (verdict alive) carries NO confirmationPending -- the
    // canary sang, there is nothing left to confirm in the background.
    ok("[§3] a canary-confirmed keep carries no confirmationPending", r.confirmationPending === undefined);
  }

  // ---- 6. DEAD canary -> rolled-back (promote THEN rollback to the recorded version) ----
  {
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "alive", verdict: "dead" });
    const r = await runSafeApply(d, g, input());
    ok("dead canary -> rolled-back", r.outcome === "rolled-back");
    ok("rollback promotes then re-deploys the prior version", d.deployCalls.length === 2 && d.deployCalls[0] === NEW_ID && d.deployCalls[1] === OLD_ID);
  }

  // ---- 7. ALIVE BASELINE + AILING VERDICT: OPTIMISTIC keep ( rework -- a flight that cannot
  // complete in the post-swap window is not evidence of a bad build; only a DEAD canary is, so a non-dead
  // verdict KEEPS whatever the self-check says, and the hourly canary confirms) ----
  {
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "alive", verdict: "ailing", selfCheck: false });
    const r = await runSafeApply(d, g, input());
    ok("alive->ailing + inconclusive self-check -> APPLIED (optimistic keep, no rollback deploy)", r.outcome === "applied" && d.deployCalls.length === 1 && d.deployCalls[0] === NEW_ID);
    ok("[§3] an optimistic keep is confirmation-pending", r.confirmationPending === true);
  }
  {
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "alive", verdict: "pending", selfCheck: true });
    const r = await runSafeApply(d, g, input());
    ok("alive baseline + pending verdict + passing self-check -> APPLIED (kept, no rollback deploy)", r.outcome === "applied" && d.deployCalls.length === 1 && d.deployCalls[0] === NEW_ID);
    ok("the decision step reason defers to the hourly canary", r.steps.some((st) => st.step === "decision" && /hourly canary will confirm/.test(st.detail ?? "")));
    // [§3] a keep decided while the canary never sang is honest-but-provisional.
    ok("[§3] a self-check-decided keep sets confirmationPending:true", r.confirmationPending === true);
  }

  // ---- 8. NO-DESTINATION (pending baseline + pending verdict): OPTIMISTIC keep, either self-check ----
  {
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "pending", verdict: "pending", selfCheck: true });
    const r = await runSafeApply(d, g, input());
    ok("pending+pending+selfcheck-ok -> applied (kept)", r.outcome === "applied" && d.deployCalls.length === 1);
    ok("[§3] a self-check-decided keep (no destination) also sets confirmationPending:true", r.confirmationPending === true);
  }
  {
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "pending", verdict: "pending", selfCheck: false });
    const r = await runSafeApply(d, g, input());
    ok("pending+pending+selfcheck-fail -> APPLIED (optimistic keep, hourly canary is the gate)", r.outcome === "applied" && d.deployCalls.length === 1 && d.deployCalls[0] === NEW_ID);
    ok("[§3] the optimistic no-destination keep is confirmation-pending", r.confirmationPending === true);
  }

  // ---- 9. UPLOAD fails -> refused, engine unchanged (no promote, no rollback) ----
  {
    const d = new FakeDriver({ uploadFails: true });
    const r = await runSafeApply(d, new FakeGate(), input());
    ok("upload failure -> refused", r.outcome === "refused");
    ok("upload failure never promotes (engine unchanged)", d.deployCalls.length === 0);
  }

  // ---- 10. PROMOTE fails -> refused, prior version still live (atomic deploy), no rollback needed ----
  {
    const d = new FakeDriver({ promoteFails: true });
    const r = await runSafeApply(d, new FakeGate(), input());
    ok("promote failure -> refused", r.outcome === "refused");
    ok("promote failure leaves prior version live (only the failed promote was attempted)", d.deployCalls.length === 1 && d.deployCalls[0] === NEW_ID);
    ok("promote failure reason reassures engine is unchanged", /unchanged|prior version/i.test(r.reason ?? ""));
  }

  // ---- 11. CANARY FLIGHT THROWS -> folds to "ailing" (could not complete), NOT "dead" -> OPTIMISTIC keep.
  // A thrown flight is the post-swap window, not a data-integrity failure, so it keeps (confirmation
  // pending) and the hourly canary confirms; only a DEAD verdict (a completed flight with a strayed byte)
  // rolls back. This is the exact class the three live drills got wrong. ----
  {
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "alive", flyThrows: true });
    const r = await runSafeApply(d, g, input());
    ok("canary flight error -> APPLIED (optimistic keep; a thrown flight is not a dead canary)", r.outcome === "applied" && d.deployCalls.length === 1 && d.deployCalls[0] === NEW_ID);
    ok("[§3] the flight-error keep is confirmation-pending", r.confirmationPending === true);
  }

  // ---- 12. ROLLBACK fails -> outcome 'rollback-failed', reason flags manual action + data safe -----------
  //
  // THIS ASSERTION WAS INVERTED UNTIL. It used to pin `outcome === "rolled-back"` -- the enum
  // asserting the engine had been safely reverted while it was, in fact, STILL SERVING THE DEAD BUILD. Every
  // consumer keys off this enum (the support pack's updates.last.outcome, the console badge, the notify rules,
  // the diagnostics bot's update-failed-or-rollback-needed signal), so all of them were told the exact opposite
  // of reality, with the truth surviving only in a prose `reason` field that none of them read. The test
  // encoded the lie, which is why it survived review: it asserted the behaviour rather than the requirement.
  {
    const d = new FakeDriver({ rollbackFails: true });
    const g = new FakeGate({ baseline: "alive", verdict: "dead" });
    const r = await runSafeApply(d, g, input());
    ok("rollback failure -> outcome rollback-failed (the engine is STILL on the bad version)", r.outcome === "rollback-failed");
    ok("...and it is NOT reported as rolled-back, which would be the opposite of the truth", r.outcome !== "rolled-back");
    ok("rollback failure names the manual recovery (re-deploy prior version)", /re-deploy|dashboard/i.test(r.reason ?? ""));
    ok("rollback failure reassures DATA + RECOVERY are safe", /DATA|RECOVERY|immutable|out-of-band/i.test(r.reason ?? ""));
  }

  // ---- 13. currentLiveVersionId fails -> refused BEFORE any change ----
  {
    const d = new FakeDriver({ currentFails: true });
    const r = await runSafeApply(d, new FakeGate(), input());
    ok("cannot read current version -> refused", r.outcome === "refused");
    ok("no rollback target -> nothing uploaded/promoted", d.uploadCalls === 0 && d.deployCalls.length === 0);
  }

  // ---- 13b. currentLiveVersionId fails on a DRY RUN (the console's tokenless Preview) -> still a plan,
  // reported honestly; only the LIVE arm above refuses. The engine holds no deploy credentials, so a
  // tokenless preview CANNOT read the live version -- that must not fail the preview. ----
  {
    const d = new FakeDriver({ currentFails: true });
    const r = await runSafeApply(d, new FakeGate(), input({ dryRun: true }));
    ok("tokenless dry-run -> outcome dry-run, not refused", r.outcome === "dry-run");
    ok("tokenless dry-run carries no rollback target", r.fromVersion === undefined);
    ok("tokenless dry-run logs the unread target honestly", r.steps.some((s) => s.step === "record-rollback-target" && s.ok === false && /live apply reads it/.test(s.detail ?? "")));
    ok("tokenless dry-run NEVER uploads or promotes", d.uploadCalls === 0 && d.deployCalls.length === 0);
  }

  // ---- a live SPLIT (an opt-in ramp still in progress, or left mid-flight) must NOT be trusted as -------
  // the rollback target. currentLiveVersionId() only ever returns the DOMINANT slice -- exactly the exploit
  // this finding closes: a second apply reaching planAndPromote while the account is split would otherwise
  // silently record the just-ramped, not-yet-trusted release as its OWN rollback target, so a later unhealthy
  // verdict's auto-rollback would redeploy the SAME untrusted build while reporting "rolled back, nothing was
  // lost". Modelled via liveSlices, the SAME fake testStandaloneRollback's split tests use, so
  // currentLiveVersions() reports two slices while currentLiveVersionId() would (wrongly) report only one. ----
  {
    // The just-ramped (untrusted) version is the DOMINANT slice (60%) -- the exact shape the exploit
    // describes. Before the fix this would have been silently recorded as fromVersion, then uploaded again
    // and promoted to 100%.
    const d = new FakeDriver({ liveSlices: [{ versionId: NEW_ID, percentage: 60 }, { versionId: OLD_ID, percentage: 40 }] });
    const r = await runSafeApply(d, new FakeGate({ verdict: "alive" }), input());
    ok("apply during a live split (new dominant) -> refused, NOT silently recorded", r.outcome === "refused");
    ok("split refusal NEVER uploads/promotes (the corrupted-rollback-target exploit is closed)", d.uploadCalls === 0 && d.deployCalls.length === 0);
    ok("split refusal never even reads the dominant-only currentLiveVersionId", d.currentCalls === 0);
    ok("split refusal logs a failed record-rollback-target step", r.steps.some((s) => s.step === "record-rollback-target" && s.ok === false));
    ok("split refusal names the split so the operator can settle/roll back", /split/i.test(r.reason ?? ""));
  }
  {
    // The split's dominant slice happens to be the OLD (true baseline) version -- i.e. a ramp under 50%. A
    // dominant-slice read would have coincidentally been "correct" here; the fix refuses UNIFORMLY on any
    // split regardless of which side is dominant (it cannot assume an under-50% ramp is not itself still
    // awaiting a decision), so swapping the percentages is not an escape from the guard above.
    const d = new FakeDriver({ liveSlices: [{ versionId: NEW_ID, percentage: 30 }, { versionId: OLD_ID, percentage: 70 }] });
    const r = await runSafeApply(d, new FakeGate({ verdict: "alive" }), input());
    ok("apply during a live split (old dominant) -> STILL refused, not just the >50% case", r.outcome === "refused" && d.uploadCalls === 0 && d.deployCalls.length === 0);
  }

  // ---- an UNCONDITIONAL split-refusal permanently disables the module's own -----------------------------
  // documented completion step ("Promote it to 100% with Update now", console/src/screens/licence/shared.ts)
  // for every ramp that ever settles "applied": settling one does NOT collapse the split (settleAfterRamp's
  // applied branch makes no driver call at all), so the SAME split is still live on the very next apply, and
  // nothing else in this codebase ever collapses it. The router now resolves the persisted lifecycle's own
  // recorded fromVersion/toVersion (resolveTrustedRampTarget, router-updates.ts, the SAME fact
  // resolveRollbackTarget already trusts for the standalone rollback route) and threads it through as
  // knownRollbackTarget/knownToVersion -- verifyAndGuard trusts it ONLY when the live split's slices are
  // EXACTLY that pair, so the documented flow can complete while an unrecognised split still refuses. ----
  {
    // The exact shape settling a trusted ramp leaves behind: the SAME two slices as the refused case above,
    // but this apply now carries the router's own resolved known-good (as if a prior ramp settled "applied"
    // with fromVersion=OLD_ID, toVersion=NEW_ID). Before this fix this would refuse forever; now it collapses
    // the split by promoting NEW_ID to 100%, exactly like the documented "Update now" completion step.
    const d = new FakeDriver({ liveSlices: [{ versionId: NEW_ID, percentage: 60 }, { versionId: OLD_ID, percentage: 40 }] });
    const r = await runSafeApply(d, new FakeGate({ baseline: "alive", verdict: "alive" }), input({ knownRollbackTarget: OLD_ID, knownToVersion: NEW_ID }));
    ok("[HI-14-r2] a RECOGNISED split (the router's own trusted ramp record) -> the finish-the-ramp apply succeeds", r.outcome === "applied");
    ok("[HI-14-r2] the TRUSTED fromVersion is recorded, never re-guessed from the dominant slice", r.fromVersion === OLD_ID && r.toVersion === NEW_ID);
    ok("[HI-14-r2] it genuinely collapses the split (uploads + promotes NEW_ID to 100%)", d.uploadCalls === 1 && d.deployCalls.length === 1 && d.deployCalls[0] === NEW_ID);
  }
  {
    // An UNRECOGNISED split -- a live version that is neither the known fromVersion nor toVersion (e.g. a
    // split created outside this engine's own bookkeeping, or a stale knownRollbackTarget from a much older
    // transition) -- must still refuse exactly as before. A knownRollbackTarget on file for a DIFFERENT
    // transition is not a licence to trust an unrelated live shape.
    const d = new FakeDriver({ liveSlices: [{ versionId: NEW_ID, percentage: 50 }, { versionId: "v-rogue", percentage: 50 }] });
    const r = await runSafeApply(d, new FakeGate({ verdict: "alive" }), input({ knownRollbackTarget: OLD_ID, knownToVersion: NEW_ID }));
    ok("[HI-14-r2] an UNRECOGNISED split (a version neither known endpoint names) -> STILL refused", r.outcome === "refused" && d.uploadCalls === 0 && d.deployCalls.length === 0);
    ok("[HI-14-r2] unrecognised-split refusal still names the split", /split/i.test(r.reason ?? ""));
  }

  // ---- 14. FAIL-SAFE: a driver that throws on EVERYTHING still returns a structured result (never throws out) ----
  {
    const hostile: DeployDriver = {
      currentLiveVersionId: async () => { throw new Error("boom"); },
      uploadVersion: async () => { throw new Error("boom"); },
      deployVersion: async () => { throw new Error("boom"); },
    };
    const hostileGate: HealthGate = {
      baseline: async () => { throw new Error("boom"); },
      flyNow: async () => { throw new Error("boom"); },
      selfCheck: async () => { throw new Error("boom"); },
    };
    let threw = false;
    let r: UpdateApplyResult | null = null;
    try {
      r = await runSafeApply(hostile, hostileGate, input());
    } catch {
      threw = true;
    }
    ok("runSafeApply NEVER throws out, even with a hostile driver+gate", threw === false && r !== null);
    ok("hostile driver -> a refused/rolled-back outcome with a reason", r !== null && (r.outcome === "refused" || r.outcome === "rolled-back") && typeof r.reason === "string");
  }

  // ---- 15. idempotency: re-running once applied (now current) is a clean no-op ----
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ runningVersion: "0.2.0", recommendedVersion: "0.2.0" }));
    ok("re-run when already current -> no-update (idempotent)", r.outcome === "no-update" && d.uploadCalls === 0);
  }
}

// =====================================================================================================
// STANDALONE ROLLBACK (revert to a recorded known-good version, independent of an in-flight apply).
// It is the SAFE recovery direction; it canary-verifies the rollback landed; it never throws out.
// =====================================================================================================
async function testStandaloneRollback(_fx: Fixtures): Promise<void> {
  {
    // happy: revert to the recorded known-good, canary sings -> reverted
    const d = new FakeDriver({ current: NEW_ID }); // currently on the new (suspect) version
    const g = new FakeGate({ verdict: "alive" });
    const r = await runStandaloneRollback(d, g, { toVersion: OLD_ID });
    ok("standalone rollback to known-good + canary sings -> reverted", r.outcome === "reverted" && r.toVersion === OLD_ID);
    ok("standalone rollback deploys the known-good version", d.deployCalls.length === 1 && d.deployCalls[0] === OLD_ID);
    ok("standalone rollback records fromVersion (what it reverted away from)", r.fromVersion === NEW_ID);
  }
  {
    // no recorded target -> clean no-op (NEVER a blind deploy)
    const d = new FakeDriver();
    const r = await runStandaloneRollback(d, new FakeGate(), { toVersion: "" });
    ok("standalone rollback with no target -> no-target (no deploy)", r.outcome === "no-target" && d.deployCalls.length === 0);
  }
  {
    // already on the target -> idempotent no-op
    const d = new FakeDriver({ current: OLD_ID });
    const r = await runStandaloneRollback(d, new FakeGate(), { toVersion: OLD_ID });
    ok("standalone rollback when already on target -> already (no deploy)", r.outcome === "already" && d.deployCalls.length === 0);
  }

  // ---- FOLD 3: split-aware live version. liveSingleVersion + rollback must NOT short-circuit on a split ----
  ok("liveSingleVersion: a single 100% slice -> that version", liveSingleVersion([{ versionId: OLD_ID, percentage: 100 }]) === OLD_ID);
  ok("liveSingleVersion: a two-version split -> null (no short-circuit)", liveSingleVersion([{ versionId: NEW_ID, percentage: 30 }, { versionId: OLD_ID, percentage: 70 }]) === null);
  ok("liveSingleVersion: no slices -> null", liveSingleVersion([]) === null);
  ok("liveSingleVersion: a single non-zero slice (others at 0%) -> that version", liveSingleVersion([{ versionId: OLD_ID, percentage: 100 }, { versionId: NEW_ID, percentage: 0 }]) === OLD_ID);
  {
    // SINGLE version via slices equal to the target -> idempotent "already" (short-circuit is sound here)
    const d = new FakeDriver({ liveSlices: [{ versionId: OLD_ID, percentage: 100 }] });
    const r = await runStandaloneRollback(d, new FakeGate({ verdict: "alive" }), { toVersion: OLD_ID });
    ok("single-version-via-slices == target -> already (no deploy)", r.outcome === "already" && d.deployCalls.length === 0);
  }
  {
    // A SPLIT whose larger slice IS the target must NOT short-circuit: the suspect version still serves
    // traffic, so we deploy the known-good at 100% to collapse the split (idempotent/safe).
    const d = new FakeDriver({ liveSlices: [{ versionId: NEW_ID, percentage: 40 }, { versionId: OLD_ID, percentage: 60 }] });
    const g = new FakeGate({ verdict: "alive" });
    const r = await runStandaloneRollback(d, g, { toVersion: OLD_ID });
    ok("split incl. target -> does NOT short-circuit; deploys target at 100%", r.outcome === "reverted" && d.deployCalls.length === 1 && d.deployCalls[0] === OLD_ID);
  }

  {
    // the deploy of the known-good fails -> failed, engine unchanged. (A bespoke driver: live is NEW_ID,
    // deploying the rollback target OLD_ID throws.)
    const d: DeployDriver = {
      currentLiveVersionId: async () => NEW_ID,
      uploadVersion: async () => NEW_ID,
      deployVersion: async (id: string) => { if (id === OLD_ID) throw new Error("deploy failed"); },
    };
    const r = await runStandaloneRollback(d, new FakeGate(), { toVersion: OLD_ID });
    ok("standalone rollback deploy failure -> failed (atomic; prior still live)", r.outcome === "failed");
  }
  {
    // deployed but the canary cannot confirm -> reverted-unverified (NOT auto-re-rolled; data safe)
    const d = new FakeDriver({ current: NEW_ID });
    const g = new FakeGate({ verdict: "ailing" });
    const r = await runStandaloneRollback(d, g, { toVersion: OLD_ID });
    ok("standalone rollback deployed but canary unconfirmed -> reverted-unverified", r.outcome === "reverted-unverified");
    ok("reverted-unverified reason reassures data/recovery are safe", /DATA|RECOVERY|immutable|out-of-band/i.test(r.reason ?? ""));
  }
  {
    // fail-safe: a hostile driver/gate never throws out
    const hostile: DeployDriver = { currentLiveVersionId: async () => { throw new Error("boom"); }, uploadVersion: async () => { throw new Error("boom"); }, deployVersion: async () => { throw new Error("boom"); } };
    const hostileGate: HealthGate = { baseline: async () => { throw new Error("boom"); }, flyNow: async () => { throw new Error("boom"); }, selfCheck: async () => { throw new Error("boom"); } };
    let threw = false;
    try { await runStandaloneRollback(hostile, hostileGate, { toVersion: OLD_ID }); } catch { threw = true; }
    ok("standalone rollback never throws out even with a hostile driver+gate", threw === false);
  }
}

// =====================================================================================================
// OPT-IN GRADUAL RAMP (default OFF: the normal apply path never calls this). Serves a fraction of
// real traffic.
//
// startGradualRamp is PHASE 1 ONLY -- upload + traffic-shift, nothing else. It does not even
// TAKE a HealthGate any more (a request-boundary-shaped proof, not just a runtime spy: there is no `gate`
// in scope inside this function or rampUploadAndGate for a canary flight to be flown against, so it is
// structurally impossible for this call to invoke flyNow() before rampVersion's promise resolves in the
// same call -- the old bug cannot be reintroduced without the compiler flagging the missing parameter).
// The canary-gate + auto-rollback logic that used to run inline here now lives in settleAfterRamp
// (phase 2, tested in testRampSettle below), which a genuinely separate later call must invoke.
// =====================================================================================================
async function testGradualRamp(fx: Fixtures): Promise<void> {
  const { input, rampInput } = fx;
  // rampPercentageValid bounds the opt-in (1..99; 100 is not a ramp; 0/out-of-range/non-int refused)
  ok("ramp percentage 50 valid", rampPercentageValid(50) === true);
  ok("ramp percentage 1 valid", rampPercentageValid(1) === true);
  ok("ramp percentage 99 valid", rampPercentageValid(99) === true);
  ok("ramp percentage 100 INVALID (that is the atomic promote)", rampPercentageValid(100) === false);
  ok("ramp percentage 0 invalid", rampPercentageValid(0) === false);
  ok("ramp percentage 50.5 invalid (non-integer)", rampPercentageValid(50.5) === false);

  {
    // happy: verify + upload + ramp -> ramp-pending (NEVER "ramped"/verified -- phase 1 cannot fly a
    // canary at all, see the function header). No canaryVerdict field is ever produced by this phase.
    const d = new FakeDriver();
    const r = await startGradualRamp(d, rampInput());
    ok("ramp upload+shift -> ramp-pending (NOT verified)", r.outcome === "ramp-pending" && r.percentage === 25);
    ok("ramp-pending never carries a canary verdict (phase 1 never flies one)", !("canaryVerdict" in r));
    ok("ramp uploads once + ramps once (25% new, 75% prior) + does NOT deploy 100%", d.uploadCalls === 1 && d.rampCalls.length === 1 && d.rampCalls[0]?.percentage === 25 && d.deployCalls.length === 0);
    ok("ramp reason is honest that it serves real traffic (not a preview)", /real traffic|not an isolated preview/i.test(r.reason ?? ""));
    ok("ramp-pending reason says verification is pending, not that it already sang", /pending/i.test(r.reason ?? "") && !/canary sings|canary sang/i.test(r.reason ?? ""));
  }
  {
    // verify-before-deploy still gates the ramp: a bad hash refuses before any traffic shift
    const d = new FakeDriver();
    const r = await startGradualRamp(d, rampInput({ expectedSha384: "deadbeef" }));
    ok("ramp bad hash -> refused, NEVER ramps/uploads (verify-before-deploy)", r.outcome === "refused" && d.uploadCalls === 0 && d.rampCalls.length === 0);
  }
  {
    // migration + compat guards still apply to the ramp
    const d = new FakeDriver();
    const rMig = await startGradualRamp(d, rampInput({ meta: { version: "0.2.0", requiresMigration: true } }));
    ok("ramp refuses a migration release (no traffic shift)", rMig.outcome === "refused" && d.rampCalls.length === 0);
    const d2 = new FakeDriver();
    const rCompat = await startGradualRamp(d2, rampInput({ meta: { version: "0.2.0", minEngineVersion: "0.2.0" } }));
    ok("ramp refuses an over-minEngineVersion release", rCompat.outcome === "refused" && d2.rampCalls.length === 0);
  }
  {
    // FOLD 4: the forward-only guard applies to the ramp too; an older recommended is refused before any
    // traffic shift, unless the owner explicitly opts into a downgrade.
    const d = new FakeDriver();
    const rDown = await startGradualRamp(d, rampInput({ runningVersion: "0.2.0", recommendedVersion: "0.1.0" }));
    ok("ramp refuses an older recommended (no silent downgrade)", rDown.outcome === "refused" && d.rampCalls.length === 0 && d.uploadCalls === 0);
    const d2 = new FakeDriver();
    const rDownOk = await startGradualRamp(d2, rampInput({ runningVersion: "0.2.0", recommendedVersion: "0.1.0", allowDowngrade: true }));
    ok("ramp with explicit allowDowngrade -> ramps the older version", rDownOk.outcome === "ramp-pending" && d2.rampCalls.length === 1);
  }
  {
    // a driver that cannot ramp -> clean refusal (NEVER a silent 100% promote)
    const d = new FakeDriver({ noRamp: true });
    const r = await startGradualRamp(d, rampInput());
    ok("ramp against a non-ramp driver -> refused (no silent 100% promote)", r.outcome === "refused" && d.deployCalls.length === 0 && d.uploadCalls === 0);
  }
  {
    // an invalid percentage at the orchestration boundary is refused before any work
    const d = new FakeDriver();
    const r = await startGradualRamp(d, rampInput({ percentage: 100 }));
    ok("ramp percentage 100 at orchestration -> refused (use atomic apply)", r.outcome === "refused" && d.uploadCalls === 0);
  }
  {
    // DEFAULT-OFF preserved: the NORMAL apply path (runSafeApply / planAndPromote) NEVER calls rampVersion
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "alive", verdict: "alive" });
    await runSafeApply(d, g, input());
    ok("the normal apply path never ramps (default OFF: atomic promote only)", d.rampCalls.length === 0 && d.deployCalls.length === 1 && d.deployCalls[0] === NEW_ID);
  }
  {
    // asvs-HI-14: the ramp shares verifyAndGuard with the atomic apply, so the same split-check applies here
    // too -- if the account is ALREADY split before this ramp even starts (e.g. a split created outside this
    // engine's own bookkeeping), refuse rather than record an unreliable rollback target, no traffic shift.
    const d = new FakeDriver({ liveSlices: [{ versionId: NEW_ID, percentage: 55 }, { versionId: OLD_ID, percentage: 45 }] });
    const r = await startGradualRamp(d, rampInput());
    ok("ramp when the account is ALREADY split -> refused, no traffic shift", r.outcome === "refused" && d.uploadCalls === 0 && d.rampCalls.length === 0);
    ok("ramp split refusal names the split", /split/i.test(r.reason ?? ""));
  }
}

// =====================================================================================================
// PHASE 2: settleAfterRamp. This is what actually canary-gates a ramp, invoked by a
// genuinely separate later call (in production, a fresh HTTP request Cloudflare routes independently of
// the one that ramped, giving it a real `percentage`% chance of landing on the ramped slice). Proves:
// applied (genuine hit), inconclusive (a keep-looking verdict that did NOT land on the ramped code --
// the exact false-assurance this finding closes), and every rolled-back arm.
// =====================================================================================================
async function testRampSettle(): Promise<void> {
  const settleArgs = (over: Partial<{ fromVersion: string; toVersion: string; recommendedVersion: string }> = {}) => ({ fromVersion: OLD_ID, toVersion: NEW_ID, recommendedVersion: "0.2.0", ...over });

  {
    // GENUINE HIT: verdict alive AND self-check confirms this request ran the ramped code -> applied (kept
    // at its configured percentage; no deploy call at all, the split is left exactly as ramped).
    const d = new FakeDriver();
    const g = new FakeGate({ verdict: "alive", selfCheck: true });
    const r = await settleAfterRamp(d, g, settleArgs());
    ok("ramp-settle genuine hit (alive + self-check ok) -> applied", r.outcome === "applied" && r.phase === "ramp-settle");
    ok("ramp-settle applied makes NO deploy call (still serving its configured percentage)", d.deployCalls.length === 0);
    ok("ramp-settle applied reason confirms it ran the ramped code", /ramped version's own code/i.test(r.reason ?? ""));
  }
  {
    // THE FALSE-ASSURANCE CASE THIS FINDING CLOSES: verdict alive (decideKeep's "alive" branch trusts it
    // unconditionally) but self-check FAILS -- this settle request did not actually run the ramped code
    // (it re-tested the untouched majority slice). Must be INCONCLUSIVE, never "applied" and never
    // "rolled-back": nothing is known about the ramped version's health, so nothing may be asserted about
    // it, and nothing may be undone either. No deploy call at all.
    const d = new FakeDriver();
    const g = new FakeGate({ verdict: "alive", selfCheck: false });
    const r = await settleAfterRamp(d, g, settleArgs());
    ok("ramp-settle alive verdict WITHOUT self-identity -> inconclusive (not applied, not rolled-back)", r.outcome === "inconclusive");
    ok("inconclusive makes NO deploy call (the ramp is left exactly as-is)", d.deployCalls.length === 0);
    ok("inconclusive reason tells the caller to retry, names nothing was changed", /retry|verify again/i.test(r.reason ?? "") && /unchanged/i.test(r.reason ?? ""));
  }
  {
    // dead -> always rolled back (the safe direction), regardless of self-identity.
    const d = new FakeDriver();
    const g = new FakeGate({ verdict: "dead" });
    const r = await settleAfterRamp(d, g, settleArgs());
    ok("ramp-settle dead -> rolled-back to 100% prior", r.outcome === "rolled-back" && d.deployCalls.length === 1 && d.deployCalls[0] === OLD_ID);
  }
  {
    // ailing/pending + a previously-alive baseline -> regression -> rolled back (decideKeep's own rule;
    // self-identity is irrelevant here, decideKeep never reaches keep=true for a baseline regression).
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "alive", verdict: "ailing", selfCheck: true });
    const r = await settleAfterRamp(d, g, settleArgs());
    ok("ramp-settle regression (alive baseline -> ailing) -> rolled-back even with self-check ok", r.outcome === "rolled-back" && d.deployCalls[0] === OLD_ID);
  }
  {
    // ailing/pending + NOT a healthy baseline + self-check genuinely ok -> the atomic path's own fallback
    // KEEP rule applies here too, and self-identity is ALREADY satisfied (selfCheckOk true) -> applied.
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "pending", verdict: "ailing", selfCheck: true });
    const r = await settleAfterRamp(d, g, settleArgs());
    ok("ramp-settle no-baseline + ailing + self-check ok -> applied (fallback keep, already self-verified)", r.outcome === "applied");
  }
  {
    // ailing/pending + not a healthy baseline + self-check FAILS: decideKeep is now OPTIMISTIC (..07
    // rework, adopted from the atomic path) and keeps any non-dead verdict regardless of the self-check, so
    // this is no longer decideKeep itself saying rollback -- it falls to settleAfterRamp's OWN self-identity
    // gate instead (this settle's ONLY proof it actually ran the ramped code), which a failed self-check
    // fails just as it does on an alive-but-unidentified verdict: inconclusive, never a rollback a failed
    // self-check alone cannot justify. No deploy call at all (the ramp is left exactly as-is).
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "pending", verdict: "ailing", selfCheck: false });
    const r = await settleAfterRamp(d, g, settleArgs());
    ok("ramp-settle no-baseline + ailing + self-check fails -> inconclusive (optimistic keep, unidentified)", r.outcome === "inconclusive");
    ok("the unidentified optimistic-keep case makes NO deploy call", d.deployCalls.length === 0);
  }
  {
    // the canary flight itself throws -> folded to ailing (not dead), so decideKeep's OPTIMISTIC rule would
    // keep -- but the self-check also fails here (no healthy baseline either), so settleAfterRamp's
    // self-identity gate makes it inconclusive, never a rollback the self-check alone cannot justify. No
    // deploy call at all.
    const d = new FakeDriver();
    const g: HealthGate = {
      baseline: async () => "pending",
      flyNow: async () => { throw new Error("canary errored on the ramped version"); },
      selfCheck: async () => false,
    };
    const r = await settleAfterRamp(d, g, settleArgs());
    ok("ramp-settle canary flight error -> folded to ailing -> inconclusive (optimistic keep, unidentified)", r.outcome === "inconclusive" && r.canaryVerdict === "ailing" && d.deployCalls.length === 0);
  }
  {
    // baseline read throws -> folded to "pending" (never throws out), settle proceeds normally.
    const d = new FakeDriver();
    const g: HealthGate = {
      baseline: async () => { throw new Error("baseline read failed"); },
      flyNow: async () => "alive",
      selfCheck: async () => true,
    };
    const r = await settleAfterRamp(d, g, settleArgs());
    ok("ramp-settle baseline-read error -> folded to pending, still resolves (applied)", r.outcome === "applied" && r.canaryBaseline === "pending");
  }
  {
    // A non-singing verdict AND the rollback-to-100% deploy itself FAILS -> "rollback-failed-still-split" (G219).
    // This assertion was inverted too: it pinned "rolled-back" while a LIVE TRAFFIC SPLIT was still routing a
    // share of real customer requests to the suspect version. The ramp's entire purpose is to bound blast
    // radius, and the one outcome that says the blast radius is UNBOUNDED was the one it could not express.
    const d = new FakeDriver({ rollbackFails: true });
    const g = new FakeGate({ verdict: "dead" });
    const r = await settleAfterRamp(d, g, settleArgs());
    ok("ramp-settle dead + rollback deploy fails -> rollback-failed-still-split (traffic is STILL split)", r.outcome === "rollback-failed-still-split");
    ok("...and it is NOT reported as rolled-back, which would claim a revert that never happened", r.outcome !== "rolled-back");
    ok("ramp-settle failed-rollback names the manual re-deploy and reassures data/recovery", /re-deploy|dashboard/i.test(r.reason ?? "") && /DATA|RECOVERY|immutable|out-of-band/i.test(r.reason ?? ""));
  }
  {
    // fail-safe: a hostile gate never throws out of settleAfterRamp.
    const d = new FakeDriver();
    const hostileGate: HealthGate = { baseline: async () => { throw new Error("boom"); }, flyNow: async () => { throw new Error("boom"); }, selfCheck: async () => { throw new Error("boom"); } };
    let threw = false;
    try { await settleAfterRamp(d, hostileGate, settleArgs()); } catch { threw = true; }
    ok("ramp-settle never throws out even with a hostile gate", threw === false);
  }
}

// =====================================================================================================
// ERROR + FALLBACK PATHS: the fail-safe catch arms and defensive fallbacks that the happy/guard tests
// above do not reach. Each one drives a REAL exception or boundary state and asserts the structured,
// never-throws-out result the harness promises.
// =====================================================================================================
async function testErrorAndFallbackPaths(fx: Fixtures): Promise<void> {
  const { input, rampInput, unhashable } = fx;

  // ---- msg(): a NON-Error thrown value is stringified (the String(e) fallback arm) ----
  {
    // The driver throws a bare string (not an Error). planAndPromote's record-rollback-target catch runs
    // msg(e), which must take the String(e) branch and surface the string in the reason.
    const d: DeployDriver = {
      currentLiveVersionId: async () => { throw "no deploy creds"; },
      uploadVersion: async () => NEW_ID,
      deployVersion: async () => {},
    };
    const r = await runSafeApply(d, new FakeGate(), input());
    ok("non-Error thrown value is stringified into the reason (msg String fallback)", r.outcome === "refused" && (r.reason ?? "").includes("no deploy creds"));
  }

  // ---- planAndPromote: the artefact cannot be HASHED -> verify-artefact catch -> refused, nothing deployed ----
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ artefact: unhashable }));
    ok("artefact that cannot be hashed -> refused (verify-artefact catch)", r.outcome === "refused");
    ok("hash-failure NEVER reads/uploads/promotes (verify-before-deploy holds on the error arm too)", d.currentCalls === 0 && d.uploadCalls === 0 && d.deployCalls.length === 0);
    ok("hash-failure reason names verification", /verif|hash/i.test(r.reason ?? ""));
  }

  // ---- planAndPromote: baseline() THROWS -> baseline falls back to "pending", apply still proceeds ----
  {
    // A gate whose baseline throws but whose flight sings: the harness must swallow the baseline error
    // (canary-baseline logged as "pending") and still apply on an alive verdict.
    const d = new FakeDriver();
    const g: HealthGate = {
      baseline: async () => { throw new Error("DO unreachable"); },
      flyNow: async () => "alive",
      selfCheck: async () => false,
    };
    const r = await runSafeApply(d, g, input());
    ok("baseline error in plan -> falls back to pending and still applies on an alive canary", r.outcome === "applied" && r.canaryBaseline === "pending");
  }

  // ---- settleAfterPromote (direct): canaryBaseline NOT carried in -> it reads baseline itself ----
  {
    // runSafeApply always carries the baseline from phase 1, so this no-baseline-carried branch is only
    // reachable by calling phase 2 directly (the real two-request topology does exactly this). With no
    // carried baseline and an ailing verdict, the OPTIMISTIC rule keeps (a flight that cannot complete is
    // not evidence of a bad build) -- confirmation pending, and no rollback deploy.
    const d = new FakeDriver();
    const g = new FakeGate({ baseline: "alive", verdict: "ailing" });
    const s = await settleAfterPromote(d, g, { fromVersion: OLD_ID, toVersion: NEW_ID, recommendedVersion: "0.2.0" });
    ok("settle without a carried baseline reads it from the gate (alive baseline)", s.canaryBaseline === "alive");
    ok("settle re-read alive baseline + ailing verdict -> APPLIED (optimistic keep, no rollback deploy)", s.outcome === "applied" && d.deployCalls.length === 0);
  }
  {
    // settle direct, no carried baseline, and baseline() THROWS -> falls back to "pending"; with a pending
    // verdict and a passing self-check the new version is kept (the canary-cannot-gate path).
    const d = new FakeDriver();
    const g: HealthGate = {
      baseline: async () => { throw new Error("DO unreachable"); },
      flyNow: async () => "pending",
      selfCheck: async () => true,
    };
    const s = await settleAfterPromote(d, g, { fromVersion: OLD_ID, toVersion: NEW_ID, recommendedVersion: "0.2.0" });
    ok("settle re-reads baseline; a throwing baseline falls back to pending", s.canaryBaseline === "pending");
    ok("settle pending baseline + pending verdict + self-check ok -> applied (no rollback)", s.outcome === "applied" && d.deployCalls.length === 0);
  }

  // ---- settleAfterPromote: selfCheck() THROWS -> treated as not-ok, but under the OPTIMISTIC rule a
  // failed/thrown self-check on a non-dead verdict still KEEPS (the self-check no longer gates a rollback;
  // it is recorded for diagnosis). A thrown self-check must be caught (never escape) and read as false. ----
  {
    const d = new FakeDriver();
    const g: HealthGate = {
      baseline: async () => "pending",
      flyNow: async () => "pending",
      selfCheck: async () => { throw new Error("self-check exploded"); },
    };
    const r = await runSafeApply(d, g, input());
    ok("self-check that throws is caught + treated as false, but the non-dead verdict still KEEPS (optimistic)", r.outcome === "applied" && d.deployCalls.length === 1 && d.deployCalls[0] === NEW_ID);
    ok("the optimistic keep after a thrown self-check is confirmation-pending", r.confirmationPending === true);
  }

  // ---- runStandaloneRollback: a NULL/undefined toVersion uses the ?? "" fallback -> clean no-target ----
  {
    // The router reads toVersion from the persisted record; a missing field arrives as undefined and must
    // resolve through the nullish fallback to "" -> no-target (never a blind deploy).
    const d = new FakeDriver();
    const r = await runStandaloneRollback(d, new FakeGate(), { toVersion: undefined as unknown as string });
    ok("standalone rollback with an undefined target -> no-target via the ?? fallback (no deploy)", r.outcome === "no-target" && d.deployCalls.length === 0);
  }

  // ---- runStandaloneRollback: the canary VERIFY flight THROWS after a successful deploy ----
  {
    // The known-good deploys fine, but the post-deploy canary flight errors. The catch must fold the error
    // to "ailing" and surface reverted-unverified (deployed, not confirmed; never auto-re-rolled).
    const d = new FakeDriver({ current: NEW_ID });
    const g: HealthGate = {
      baseline: async () => "alive",
      flyNow: async () => { throw new Error("canary endpoint down"); },
      selfCheck: async () => false,
    };
    const r = await runStandaloneRollback(d, g, { toVersion: OLD_ID });
    ok("standalone rollback: canary flight error after deploy -> reverted-unverified (folded to ailing)", r.outcome === "reverted-unverified" && r.canaryVerdict === "ailing");
    ok("standalone rollback canary-error still deployed the known-good once", d.deployCalls.length === 1 && d.deployCalls[0] === OLD_ID);
  }

  // =====================================================================================================
  // RAMP: error + boundary arms not reached by the ramp happy/guard tests above.
  // =====================================================================================================

  // ---- ramp: already on the recommended version -> no-update short-circuit (no traffic shift) ----
  {
    const d = new FakeDriver();
    const r = await startGradualRamp(d, rampInput({ runningVersion: "0.2.0", recommendedVersion: "0.2.0" }));
    ok("ramp when already on the recommended version -> no-update (no upload/ramp)", r.outcome === "no-update" && d.uploadCalls === 0 && d.rampCalls.length === 0);
  }

  // ---- ramp: an UNPARSEABLE recommended version -> forward-only guard, null-compare reason arm ----
  {
    // compareSemver returns null for an unparseable version; the forward-only guard's reason ternary must
    // take the "cannot be compared" arm (distinct from the "not newer" arm), and refuse before any shift.
    const d = new FakeDriver();
    const r = await startGradualRamp(d, rampInput({ runningVersion: "0.2.0", recommendedVersion: "not-a-version" }));
    ok("ramp with an unparseable recommended -> refused via the cannot-be-compared reason arm", r.outcome === "refused" && /cannot be compared/i.test(r.reason ?? "") && d.uploadCalls === 0);
  }

  // ---- ramp: an EMPTY channel hash -> unverifiable -> refused, nothing deployed ----
  {
    const d = new FakeDriver();
    const r = await startGradualRamp(d, rampInput({ expectedSha384: "" }));
    ok("ramp with an empty channel hash -> refused (unverifiable; no upload/ramp)", r.outcome === "refused" && d.uploadCalls === 0 && d.rampCalls.length === 0);
  }

  // ---- ramp: the artefact cannot be HASHED -> verify-artefact catch -> refused ----
  {
    const d = new FakeDriver();
    const r = await startGradualRamp(d, rampInput({ artefact: unhashable }));
    ok("ramp with an unhashable artefact -> refused (verify-artefact catch; no upload/ramp)", r.outcome === "refused" && d.uploadCalls === 0 && d.rampCalls.length === 0);
  }

  // ---- ramp: currentLiveVersionId fails -> refused (no rollback target -> no traffic shift) ----
  {
    const d = new FakeDriver({ currentFails: true });
    const r = await startGradualRamp(d, rampInput());
    ok("ramp cannot read the current version -> refused (no upload, no ramp)", r.outcome === "refused" && d.uploadCalls === 0 && d.rampCalls.length === 0);
  }

  // ---- ramp: uploadVersion fails -> refused, engine unchanged (no ramp attempted) ----
  {
    const d = new FakeDriver({ uploadFails: true });
    const r = await startGradualRamp(d, rampInput());
    ok("ramp upload failure -> refused, never ramps (engine unchanged)", r.outcome === "refused" && d.rampCalls.length === 0 && d.deployCalls.length === 0);
  }

  // ---- ramp: rampVersion itself fails -> refused, prior still 100% (no deploy) ----
  {
    const d = new FakeDriver({ rampFails: true });
    const r = await startGradualRamp(d, rampInput());
    ok("ramp traffic-shift failure -> refused, prior stays 100% (no full deploy)", r.outcome === "refused" && d.rampCalls.length === 1 && d.deployCalls.length === 0);
    ok("ramp-shift failure reason reassures the engine is unchanged", /unchanged|100% on the prior/i.test(r.reason ?? ""));
  }

  // asvs-HI-13: a canary-flight-error-mid-ramp -> rolled-back scenario used to live here, driving
  // startGradualRamp with a FakeGate. Phase 1 no longer takes a gate at all (it cannot fly one, see the
  // function header) -- that coverage now lives in testRampSettle (settleAfterRamp's own "canary flight
  // error -> folded to ailing -> rolled back" and "dead + rollback deploy fails" cases).
}

// ---- anti-rollback high-water-mark guard + migration-never-auto-applied invariant ----------------------
async function testAntiRollbackFloor(fx: Fixtures): Promise<void> {
  const { input, rampInput } = fx;
  const stepFailed = (steps: { step: string; ok: boolean }[], name: string): boolean => steps.some((s) => s.step === name && s.ok === false);

  // R8: a target BELOW the settled high-water mark is REFUSED even with allowDowngrade, nothing uploaded.
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ runningVersion: "0.1.0", recommendedVersion: "0.1.5", settledHighWaterMark: "0.2.0", allowDowngrade: true }));
    ok("below-HWM target + allowDowngrade -> refused (anti-rollback-guard), nothing uploaded", r.outcome === "refused" && stepFailed(r.steps, "anti-rollback-guard") && d.uploadCalls === 0);
    ok("below-HWM refusal names the floor + the Roll back control", /high.?water|0\.2\.0/i.test(r.reason ?? "") && /roll ?back/i.test(r.reason ?? ""));
  }
  // R8: a FORWARD-from-running target that is still below the HWM is refused INDEPENDENT of allowDowngrade
  // (forward-only would pass: 0.2.0 > running 0.1.0; the anti-rollback floor is the one that catches it).
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ runningVersion: "0.1.0", recommendedVersion: "0.2.0", settledHighWaterMark: "0.3.0" }));
    ok("forward-from-running but below HWM -> refused (floor independent of allowDowngrade)", r.outcome === "refused" && stepFailed(r.steps, "anti-rollback-guard") && d.uploadCalls === 0);
  }
  // R8: a target EQUAL to the HWM is allowed (a re-pin of the highest settled version still applies).
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate({ verdict: "alive" }), input({ runningVersion: "0.1.0", recommendedVersion: "0.2.0", settledHighWaterMark: "0.2.0" }));
    ok("target EQUAL to the HWM -> applies (not below the floor)", r.outcome === "applied" && d.uploadCalls === 1);
  }
  // R8: an UNCOMPARABLE target vs a set floor is refused (fail-closed: cannot prove it is at/above the floor).
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate(), input({ runningVersion: "0.1.0", recommendedVersion: "weird", settledHighWaterMark: "0.2.0", allowDowngrade: true }));
    ok("uncomparable target vs a set HWM -> refused (fail-closed)", r.outcome === "refused" && stepFailed(r.steps, "anti-rollback-guard"));
  }
  // R8 (happy path): a forward update ABOVE the HWM is unaffected, it applies exactly as before.
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate({ verdict: "alive" }), input({ runningVersion: "0.1.0", recommendedVersion: "0.2.0", settledHighWaterMark: "0.1.0" }));
    ok("forward update ABOVE the HWM -> applies (floor does not false-positive)", r.outcome === "applied" && d.uploadCalls === 1);
  }
  // R8 (no floor): an absent HWM leaves the apply unchanged (first-ever apply, nothing settled yet).
  {
    const d = new FakeDriver();
    const r = await runSafeApply(d, new FakeGate({ verdict: "alive" }), input({ runningVersion: "0.1.0", recommendedVersion: "0.2.0" }));
    ok("absent HWM -> unchanged forward apply (no floor to enforce)", r.outcome === "applied" && d.uploadCalls === 1);
  }
  // R8 on the RAMP path: below-HWM and uncomparable-vs-HWM both refuse before any traffic shift.
  {
    const dBelow = new FakeDriver();
    const rBelow = await startGradualRamp(dBelow, rampInput({ runningVersion: "0.1.0", recommendedVersion: "0.2.0", settledHighWaterMark: "0.3.0" }));
    ok("ramp below the HWM -> refused, nothing uploaded/ramped", rBelow.outcome === "refused" && stepFailed(rBelow.steps, "anti-rollback-guard") && dBelow.uploadCalls === 0 && dBelow.rampCalls.length === 0);
    const dInc = new FakeDriver();
    const rInc = await startGradualRamp(dInc, rampInput({ runningVersion: "0.1.0", recommendedVersion: "weird", settledHighWaterMark: "0.2.0", allowDowngrade: true }));
    ok("ramp uncomparable vs a set HWM -> refused (fail-closed)", rInc.outcome === "refused" && stepFailed(rInc.steps, "anti-rollback-guard"));
  }
  // R10 invariant: a migration release is NEVER silently applied, allowDowngrade cannot bypass the migration
  // guard, on BOTH the apply and the ramp path (the closest the safe-apply module comes to an "auto" path).
  {
    const dA = new FakeDriver();
    const rA = await runSafeApply(dA, new FakeGate(), input({ runningVersion: "0.1.0", recommendedVersion: "0.2.0", meta: { version: "0.2.0", requiresMigration: true }, allowDowngrade: true }));
    ok("migration release + allowDowngrade -> still refused (migration-guard), nothing uploaded", rA.outcome === "refused" && stepFailed(rA.steps, "migration-guard") && dA.uploadCalls === 0);
    const dR = new FakeDriver();
    const rR = await startGradualRamp(dR, rampInput({ runningVersion: "0.1.0", recommendedVersion: "0.2.0", meta: { version: "0.2.0", requiresMigration: true }, allowDowngrade: true }));
    ok("migration ramp + allowDowngrade -> still refused (migration-guard), nothing uploaded", rR.outcome === "refused" && stepFailed(rR.steps, "migration-guard") && dR.uploadCalls === 0);
  }
}

// ---- DP-D read-back gate (upload -> read back -> compare -> only then promote) ----
// The gate's contract: warn (the default) RECORDS the verdict and proceeds whatever it is; enforce
// promotes ONLY a verified read-back and refuses BEFORE promotion otherwise (nothing live changed, no
// rollback needed); off never calls the driver. The verdict rides the PromoteResult either way.
async function testReadbackGate(fx: Fixtures): Promise<void> {
  const { artefact, input } = fx;
  const live = (over?: Partial<SafeApplyInput>): SafeApplyInput => input({ dryRun: false, ...over });

  // RB1: warn + identical bytes -> verified, promoted, digest recorded.
  const rb1d = new FakeDriver({ readbackBytes: artefact });
  const rb1 = await planAndPromote(rb1d, new FakeGate(), live({ readbackMode: "warn" }));
  ok("warn + identical bytes -> promoted with a verified read-back", rb1.outcome === "promoted" && rb1.readback?.verdict === "verified" && rb1.readback?.mode === "warn");
  ok("the verified read-back carries the platform digest", rb1.readback?.deployedSha384 === fx.goodHash);

  // RB2: warn + DIFFERENT bytes -> mismatch recorded, still promoted (warn never blocks).
  const rb2d = new FakeDriver({ readbackBytes: new Uint8Array([1, 2, 3]) });
  const rb2 = await planAndPromote(rb2d, new FakeGate(), live({ readbackMode: "warn" }));
  ok("warn + different bytes -> promoted, mismatch recorded honestly", rb2.outcome === "promoted" && rb2.readback?.verdict === "mismatch" && rb2d.deployCalls.length === 1);

  // RB3: enforce + identical bytes -> promoted (the gate passes and the verdict rides the result).
  const rb3d = new FakeDriver({ readbackBytes: artefact });
  const rb3 = await planAndPromote(rb3d, new FakeGate(), live({ readbackMode: "enforce" }));
  ok("enforce + identical bytes -> promoted with a verified read-back", rb3.outcome === "promoted" && rb3.readback?.verdict === "verified" && rb3d.deployCalls.length === 1);

  // RB4: enforce + DIFFERENT bytes -> REFUSED before promotion; deployVersion never called.
  const rb4d = new FakeDriver({ readbackBytes: new Uint8Array([9, 9, 9]) });
  const rb4 = await planAndPromote(rb4d, new FakeGate(), live({ readbackMode: "enforce" }));
  ok("enforce + mismatch -> refused BEFORE promotion (nothing went live)", rb4.outcome === "refused" && rb4d.deployCalls.length === 0 && rb4.readback?.verdict === "mismatch");
  ok("the enforce refusal says the previous version keeps serving", /previously live version keeps serving/.test(rb4.reason ?? ""));

  // RB5: enforce + driver without read-back support -> refused (fail-closed on unverifiable).
  const rb5d = new FakeDriver({});
  const rb5 = await planAndPromote(rb5d, new FakeGate(), live({ readbackMode: "enforce" }));
  ok("enforce + no driver support -> refused as unavailable", rb5.outcome === "refused" && rb5.readback?.verdict === "unavailable" && rb5d.deployCalls.length === 0);

  // RB6: enforce + read-back endpoint error -> refused as unavailable (never a throw).
  const rb6d = new FakeDriver({ readbackBytes: "throw" });
  const rb6 = await planAndPromote(rb6d, new FakeGate(), live({ readbackMode: "enforce" }));
  ok("enforce + endpoint error -> refused as unavailable with the reason", rb6.outcome === "refused" && rb6.readback?.verdict === "unavailable" && /read-back endpoint errored/.test(rb6.readback?.detail ?? ""));

  // RB7: warn + endpoint error -> promoted, unavailable recorded (the honest non-answer).
  const rb7d = new FakeDriver({ readbackBytes: "throw" });
  const rb7 = await planAndPromote(rb7d, new FakeGate(), live({ readbackMode: "warn" }));
  ok("warn + endpoint error -> promoted with an unavailable verdict recorded", rb7.outcome === "promoted" && rb7.readback?.verdict === "unavailable");

  // RB8: off -> the driver is never asked and no verdict is recorded.
  const rb8d = new FakeDriver({ readbackBytes: artefact });
  const rb8 = await planAndPromote(rb8d, new FakeGate(), live({ readbackMode: "off" }));
  ok("off -> no read-back call, no verdict on the result", rb8.outcome === "promoted" && rb8d.readbackCalls === 0 && rb8.readback === undefined);

  // RB9: absent mode defaults to warn (the safe default records evidence on every apply).
  const rb9d = new FakeDriver({ readbackBytes: artefact });
  const rb9 = await planAndPromote(rb9d, new FakeGate(), live());
  ok("absent mode defaults to warn (verdict recorded)", rb9.outcome === "promoted" && rb9.readback?.mode === "warn" && rb9.readback?.verdict === "verified");

  // RB10: a dry-run never reads back (nothing was uploaded to read).
  const rb10d = new FakeDriver({ readbackBytes: artefact });
  const rb10 = await planAndPromote(rb10d, new FakeGate(), input({ readbackMode: "enforce", dryRun: true }));
  ok("dry-run never uploads, never reads back", rb10.outcome === "dry-run" && rb10d.readbackCalls === 0 && rb10d.uploadCalls === 0);
}

async function main(): Promise<void> {
  const artefact = utf8("downpipe-engine-bundle-v0.2.0");
  const goodHash = hexEncode(await sha384(artefact));
  const input = (over: Partial<SafeApplyInput> = {}): SafeApplyInput => ({
    artefact,
    expectedSha384: goodHash,
    meta: { version: "0.2.0" },
    runningVersion: "0.1.0",
    recommendedVersion: "0.2.0",
    dryRun: false,
    ...over,
  });
  const rampInput = (over: Partial<RampInput> = {}): RampInput => ({ artefact, expectedSha384: goodHash, meta: { version: "0.2.0" }, runningVersion: "0.1.0", recommendedVersion: "0.2.0", percentage: 25, ...over });
  // A reusable value that makes sha384 throw during verification: WebCrypto's subtle.digest rejects a
  // value that is not a real BufferSource, so a bogus "artefact" exercises the hash-failed catch arm
  // (verify-artefact -> refused) without any deploy machinery being touched. Cast through unknown because
  // the field is typed Uint8Array; at runtime the digest call is what throws.
  const unhashable = { not: "a buffer" } as unknown as Uint8Array;
  const fx: Fixtures = { artefact, goodHash, input, rampInput, unhashable };

  // Each group runs in the SAME order as the original monolithic main(), so the assertion order and the
  // shared module-level failure counter are unchanged.
  await testDecideKeepAndCoreApply(fx);
  await testAntiRollbackFloor(fx);
  await testStandaloneRollback(fx);
  await testGradualRamp(fx);
  await testRampSettle();
  await testErrorAndFallbackPaths(fx);
  await testReadbackGate(fx);

  console.log(failures === 0 ? "\nALL SAFE-APPLY VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
