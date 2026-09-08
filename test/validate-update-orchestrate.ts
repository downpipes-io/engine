// Validates the multi-component update orchestration (src/admin/update-orchestrate.ts) and the
// post-swap-tolerant settle probe (probeSettleVerdict, src/admin/update-gate.ts), driven entirely with
// fakes -- no network, no account, no deploy. Proves:
//   * parseComponentsRequest: absent = legacy engine-only; unknown/malformed component lists are loud,
//     honest refusals (the fail-safe half of the additive request contract);
// * probeSettleVerdict: a pending/ailing flight is RETRIED on the bounded
//     backoff and can resolve to alive (KEEP, no rollback); a persistently-incomplete flight falls to
//     the (retried) self-check; a DEAD verdict decides IMMEDIATELY and is never retried;
//   * applyConsoleComponent: the per-component guard order (console floor -> compat-vs-running-engine ->
//     sha384 -> rollback target), the strict bundle parse, dry-run, atomic-promote refusals, the
//     API-level promote confirmation, and the honest confirm-mismatch auto-rollback;
//   * rollbackConsoleComponent: the standalone console revert (split-aware, confirm-checked, fail-safe).
// Run: node test/validate-update-orchestrate.ts

import { parseComponentsRequest, applyConsoleComponent, rollbackConsoleComponent } from "../src/admin/update-orchestrate.ts";
import { consoleRollbackTargetFrom } from "../src/admin/router-updates-components.ts";
import { probeSettleVerdict } from "../src/admin/update-gate.ts";
import type { AssetsDeployDriver, ConsoleBundle } from "../src/admin/cf-assets-deploy.ts";
import type { HealthGate, LiveVersionShare } from "../src/admin/update-apply.ts";
import type { ComponentArtefact } from "../src/admin/updates.ts";
import type { CanaryLiveness } from "../src/canary/types.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { hexEncode, utf8, base64Encode, sha256Hex } from "../src/crypto/bytes.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- a minimal, REAL console bundle (parses strictly) + its channel component entry ---------------
const WORKER_SOURCE = utf8("export default { fetch() { return new Response('shell'); } };");
const ASSET = utf8("<!doctype html><h1>console</h1>");
const CONSOLE_VERSION = "0.9.1";
async function buildBundle(version: string): Promise<Uint8Array> {
  return utf8(
    JSON.stringify({
      format: "downpipe-console-bundle/1",
      version,
      worker: { mainModule: "worker.js", sourceB64: base64Encode(WORKER_SOURCE) },
      config: { compatibilityDate: "2026-06-01", runWorkerFirst: true },
      assets: [{ path: "/index.html", contentType: "text/html; charset=utf-8", sha256: await sha256Hex(ASSET), b64: base64Encode(ASSET) }],
    }),
  );
}

// FakeAssetsDriver records exactly what was called so the vectors prove ORDER and PRESENCE/ABSENCE of
// upload/promote/rollback, with each failure mode independently switchable (the FakeDriver mould).
interface DriverOpts {
  current?: string;
  newId?: string;
  currentFails?: boolean;
  uploadFails?: boolean;
  promoteFails?: boolean;
  rollbackFails?: boolean;
  confirmFails?: boolean; // the POST-PROMOTE confirmation read throws
  confirmLive?: string; // what the confirmation read reports live (defaults to the last deployed id)
  liveSlices?: LiveVersionShare[];
}
class FakeAssetsDriver implements AssetsDeployDriver {
  currentCalls = 0;
  uploadCalls = 0;
  deployCalls: string[] = [];
  private opts: DriverOpts;
  constructor(opts: DriverOpts = {}) {
    this.opts = opts;
  }
  async currentLiveVersionId(): Promise<string> {
    this.currentCalls++;
    // The FIRST read is the rollback-target record; later reads are the post-promote confirmation.
    if (this.deployCalls.length === 0) {
      if (this.opts.currentFails) throw new Error("could not read current console version");
      return this.opts.current ?? "cv-old";
    }
    if (this.opts.confirmFails) throw new Error("confirmation read failed");
    return this.opts.confirmLive ?? this.deployCalls[this.deployCalls.length - 1]!;
  }
  async currentLiveVersions(): Promise<LiveVersionShare[]> {
    if (this.opts.currentFails) throw new Error("could not read current console version");
    return this.opts.liveSlices ?? [{ versionId: this.opts.current ?? "cv-old", percentage: 100 }];
  }
  async uploadVersion(_bundle: ConsoleBundle): Promise<string> {
    this.uploadCalls++;
    if (this.opts.uploadFails) throw new Error("console upload failed");
    return this.opts.newId ?? "cv-new";
  }
  async deployVersion(versionId: string): Promise<void> {
    const oldId = this.opts.current ?? "cv-old";
    if (this.opts.promoteFails && versionId !== oldId) {
      throw new Error("console promote failed");
    }
    if (this.opts.rollbackFails && versionId === oldId) {
      // record the attempt, then fail (mirrors a real deploy call that errors)
      this.deployCalls.push(versionId);
      throw new Error("console rollback failed");
    }
    this.deployCalls.push(versionId);
  }
}

// ScriptedGate returns a scripted sequence of canary verdicts + self-check results for the probe vectors.
class ScriptedGate implements HealthGate {
  flights: CanaryLiveness[];
  checks: boolean[];
  flyCalls = 0;
  selfCheckCalls = 0;
  flyThrowFirst: boolean;
  selfCheckThrows: boolean;
  constructor(flights: CanaryLiveness[], checks: boolean[], flyThrowFirst = false, selfCheckThrows = false) {
    this.flights = flights;
    this.checks = checks;
    this.flyThrowFirst = flyThrowFirst;
    this.selfCheckThrows = selfCheckThrows;
  }
  async baseline(): Promise<CanaryLiveness> {
    return "alive";
  }
  async flyNow(): Promise<CanaryLiveness> {
    const i = this.flyCalls++;
    if (this.flyThrowFirst && i === 0) throw new Error("post-swap DO reset");
    return this.flights[Math.min(i, this.flights.length - 1)] ?? "pending";
  }
  async selfCheck(): Promise<boolean> {
    const i = this.selfCheckCalls++;
    if (this.selfCheckThrows) throw new Error("self-check DO round-trip failed");
    return this.checks[Math.min(i, this.checks.length - 1)] ?? false;
  }
}

async function main(): Promise<void> {
  // ================================================================================================
  console.log("-- parseComponentsRequest: the additive request contract --");
  // ================================================================================================
  {
    const absent = parseComponentsRequest(undefined);
    ok("absent -> components:null (the LEGACY engine-only apply, byte-for-byte)", absent.ok === true && absent.components === null);
    const both = parseComponentsRequest(["engine", "console", "engine"]);
    ok("a known list folds duplicates and preserves order", both.ok === true && JSON.stringify(both.components) === '["engine","console"]');
    const consoleOnly = parseComponentsRequest(["console"]);
    ok("console-only parses", consoleOnly.ok === true && JSON.stringify(consoleOnly.components) === '["console"]');
    const unknown = parseComponentsRequest(["engine", "cli"]);
    ok("an unknown component refuses loudly (fail-safe, nothing narrowed silently)", unknown.ok === false && /unknown update component/.test(unknown.ok === false ? unknown.error : ""));
    const empty = parseComponentsRequest([]);
    ok("an empty array refuses (omit the field for the legacy apply)", empty.ok === false);
    const notArray = parseComponentsRequest("console");
    ok("a non-array refuses", notArray.ok === false);
  }

  // ================================================================================================
  console.log("-- probeSettleVerdict: the post-swap tolerance --");
  // ================================================================================================
  const sleeps: number[] = [];
  const fakeSleep = async (ms: number): Promise<void> => {
    sleeps.push(ms);
  };
  {
    // (a) pending twice, then alive on the second retry -> KEEP verdict, self-check never consulted.
    sleeps.length = 0;
    const gate = new ScriptedGate(["pending", "pending", "alive"], []);
    const probe = await probeSettleVerdict(gate, { sleep: fakeSleep });
    ok("(a) pending,pending,alive -> verdict alive (the retry cleared the post-swap window)", probe.verdict === "alive");
    ok("(a) three flights flew with the two bounded backoffs between", gate.flyCalls === 3 && sleeps.length === 2);
    ok("(a) the self-check was never consulted (a clean alive needs no fallback)", gate.selfCheckCalls === 0);
    ok("(a) every attempt is a logged step", probe.attempts.filter((s) => s.step.startsWith("canary-flight")).length === 3);
  }
  {
    // (b) persistently pending + a self-check that passes -> selfCheckOk true (KEEP via self-check).
    const gate = new ScriptedGate(["pending"], [true]);
    const probe = await probeSettleVerdict(gate, { sleep: fakeSleep });
    ok("(b) persistent pending + passing self-check -> selfCheckOk (keep via self-check)", probe.verdict === "pending" && probe.selfCheckOk === true);
    ok("(b) the flight was retried to exhaustion first", gate.flyCalls === 3);
  }
  {
    // (b2) the self-check itself is retried once: first false (the DO round-trip hit the swap), then true.
    const gate = new ScriptedGate(["ailing"], [false, true]);
    const probe = await probeSettleVerdict(gate, { sleep: fakeSleep });
    ok("(b2) a transiently-failing self-check is retried once and can pass", probe.selfCheckOk === true && gate.selfCheckCalls === 2);
  }
  {
    // (c) DEAD decides IMMEDIATELY: no retry, no backoff, no self-check (a strayed byte is data evidence).
    sleeps.length = 0;
    const gate = new ScriptedGate(["dead", "alive"], [true]);
    const probe = await probeSettleVerdict(gate, { sleep: fakeSleep });
    ok("(c) dead -> immediate verdict, ONE flight, zero sleeps, no self-check", probe.verdict === "dead" && gate.flyCalls === 1 && sleeps.length === 0 && gate.selfCheckCalls === 0);
  }
  {
    // a THROWN flight reads as ailing and is retried (the incident's transient-DO-failure shape).
    const gate = new ScriptedGate(["alive"], [], true);
    const probe = await probeSettleVerdict(gate, { sleep: fakeSleep });
    ok("a thrown first flight reads ailing, the retry resolves alive", probe.verdict === "alive" && gate.flyCalls === 2);
    ok("the thrown attempt is logged honestly", probe.attempts.some((s) => !s.ok && /errored/.test(s.detail ?? "")));
  }
  {
    // a THROWN self-check reads as false (could not prove healthy), retried once, still honest.
    const gate = new ScriptedGate(["pending"], [], false, true);
    const probe = await probeSettleVerdict(gate, { sleep: fakeSleep });
    ok("a thrown self-check reads false after its retry (never a pretend pass)", probe.verdict === "pending" && probe.selfCheckOk === false && gate.selfCheckCalls === 2);
  }
  {
    // consoleRollbackTargetFrom mirrors the engine resolver's rule for the console's recorded outcomes.
    ok("console target: no console outcome -> no target", consoleRollbackTargetFrom({}) === "" && consoleRollbackTargetFrom({ lastConsole: null }) === "");
    ok("console target: an applied record's fromVersion is the prior known-good", consoleRollbackTargetFrom({ lastConsole: { outcome: "applied", fromVersion: "cv-1" } }) === "cv-1");
    ok("console target: a rolled-back record's fromVersion is the reverted-to version", consoleRollbackTargetFrom({ lastConsole: { outcome: "rolled-back", fromVersion: "cv-1" } }) === "cv-1");
    ok("console target: a refused/aborted record changed nothing -> no target", consoleRollbackTargetFrom({ lastConsole: { outcome: "refused", fromVersion: "cv-1" } }) === "");
    ok("console target: a malformed fromVersion -> no target (never a blind deploy)", consoleRollbackTargetFrom({ lastConsole: { outcome: "applied" } }) === "");
  }

  // ================================================================================================
  console.log("-- applyConsoleComponent: guards (floor / compat / hash), strict parse, promote, confirm --");
  // ================================================================================================
  const bundleBytes = await buildBundle(CONSOLE_VERSION);
  const bundleSha = hexEncode(await sha384(bundleBytes));
  const component: ComponentArtefact = { kind: "static-assets", version: CONSOLE_VERSION, url: "https://update.example.com/console.json", sha384: bundleSha };
  const input = (over: Partial<Parameters<typeof applyConsoleComponent>[1]> = {}): Parameters<typeof applyConsoleComponent>[1] => ({
    bundleBytes,
    component,
    runningEngineVersion: "0.2.0",
    dryRun: false,
    ...over,
  });

  {
    // Per-component floor: a console version BELOW floors.console refuses BEFORE anything runs.
    const d = new FakeAssetsDriver();
    const r = await applyConsoleComponent(d, input({ consoleFloor: "1.0.0" }));
    ok("[floors] a console version below floors.console -> refused (anti-rollback)", r.outcome === "refused" && /BELOW 1\.0\.0/.test(r.reason ?? ""));
    ok("[floors] the floor refusal touches no deploy machinery", d.uploadCalls === 0 && d.deployCalls.length === 0 && d.currentCalls === 0);
    // An uncomparable floor also refuses (fail-closed), and an at-floor version passes (idempotent re-push).
    const r2 = await applyConsoleComponent(new FakeAssetsDriver(), input({ consoleFloor: "not-a-version" }));
    ok("[floors] an uncomparable floor refuses (cannot prove at-or-above)", r2.outcome === "refused" && /cannot be compared/.test(r2.reason ?? ""));
    const d3 = new FakeAssetsDriver();
    const r3 = await applyConsoleComponent(d3, input({ consoleFloor: CONSOLE_VERSION }));
    ok("[floors] an AT-floor console version proceeds (re-push of the settled version is allowed)", r3.outcome === "applied");
  }
  {
    // Compat: minEngineVersion is checked against the RUNNING ENGINE version (never a console version).
    const d = new FakeAssetsDriver();
    const r = await applyConsoleComponent(d, input({ component: { ...component, minEngineVersion: "9.9.9" } }));
    ok("[compat] console minEngineVersion newer than the RUNNING ENGINE -> refused, names the engine", r.outcome === "refused" && /requires engine version 9\.9\.9/.test(r.reason ?? "") && /update the engine first/.test(r.reason ?? ""));
    ok("[compat] the compat refusal deploys nothing", d.uploadCalls === 0 && d.deployCalls.length === 0);
    // The console's own version being LOWER than the engine's is fine (no forward-only compare runs).
    const r2 = await applyConsoleComponent(new FakeAssetsDriver(), input({ component: { ...component, version: CONSOLE_VERSION, minEngineVersion: "0.1.0" }, runningEngineVersion: "5.0.0" }));
    ok("[compat] a console version LOWER than the engine version applies (component versions are not cross-ordered)", r2.outcome === "applied");
  }
  {
    // Verify-before-deploy: the bundle bytes must match the signed channel's sha384.
    const d = new FakeAssetsDriver();
    const r = await applyConsoleComponent(d, input({ component: { ...component, sha384: "f".repeat(96) } }));
    ok("[verify] a sha384 mismatch refuses before any upload", r.outcome === "refused" && /did not match the signed channel's hash/.test(r.reason ?? "") && d.uploadCalls === 0);
    const r2 = await applyConsoleComponent(new FakeAssetsDriver(), input({ component: { ...component, sha384: "" } }));
    ok("[verify] a channel entry with no hash refuses (cannot verify)", r2.outcome === "refused" && /did not declare a hash/.test(r2.reason ?? ""));
  }
  {
    // STRICT parse: bytes whose sha384 matches (the guard passes) but whose CONTENT is not a valid bundle.
    const garbage = utf8('{"format":"downpipe-console-bundle/1","version":"x"}');
    const garbageSha = hexEncode(await sha384(garbage));
    const d = new FakeAssetsDriver();
    const r = await applyConsoleComponent(d, input({ bundleBytes: garbage, component: { ...component, sha384: garbageSha } }));
    ok("[parse] a hash-valid but malformed bundle refuses at the strict parse", r.outcome === "refused" && /console bundle did not verify/.test(r.reason ?? "") && d.uploadCalls === 0);
  }
  {
    // The bundle's self-described version must agree with the signed channel's component version.
    const drifted = await buildBundle("0.9.9");
    const driftedSha = hexEncode(await sha384(drifted));
    const r = await applyConsoleComponent(new FakeAssetsDriver(), input({ bundleBytes: drifted, component: { ...component, sha384: driftedSha } }));
    ok("[parse] a bundle/channel version mismatch refuses the mismatch", r.outcome === "refused" && /self-describes as 0\.9\.9/.test(r.reason ?? ""));
  }
  {
    // DRY-RUN: verified + parsed + planned; nothing uploaded or promoted; rollback target reported.
    const d = new FakeAssetsDriver();
    const r = await applyConsoleComponent(d, input({ dryRun: true }));
    ok("[dry-run] verified + planned, nothing deployed", r.outcome === "dry-run" && d.uploadCalls === 0 && d.deployCalls.length === 0 && r.fromVersion === "cv-old");
    // A tokenless preview (the current-version read fails) still plans, reported honestly.
    const d2 = new FakeAssetsDriver({ currentFails: true });
    const r2 = await applyConsoleComponent(d2, input({ dryRun: true }));
    ok("[dry-run] a tokenless preview (unreadable current version) still plans", r2.outcome === "dry-run" && r2.fromVersion === undefined);
    // A LIVE run with an unreadable current version refuses (no rollback target -> no deploy).
    const d3 = new FakeAssetsDriver({ currentFails: true });
    const r3 = await applyConsoleComponent(d3, input());
    ok("[live] an unreadable current version refuses before any change", r3.outcome === "refused" && /nothing to roll back to/.test(r3.reason ?? "") && d3.uploadCalls === 0);
  }
  {
    // Upload failure -> refused, console unchanged.
    const d = new FakeAssetsDriver({ uploadFails: true });
    const r = await applyConsoleComponent(d, input());
    ok("[upload] an upload failure refuses (console unchanged, no promote)", r.outcome === "refused" && /could not be uploaded/.test(r.reason ?? "") && d.deployCalls.length === 0);
  }
  {
    // Promote failure -> refused (atomic: the prior version is still serving; no rollback deploy needed).
    const d = new FakeAssetsDriver({ promoteFails: true });
    const r = await applyConsoleComponent(d, input());
    ok("[promote] a promote failure refuses with the prior version still serving", r.outcome === "refused" && /previously-live version is still serving/.test(r.reason ?? ""));
  }
  {
    // HAPPY PATH: upload -> promote -> confirmation read sees the new version live -> applied.
    const d = new FakeAssetsDriver();
    const r = await applyConsoleComponent(d, input());
    ok("[applied] upload -> promote -> confirm -> applied", r.outcome === "applied" && r.fromVersion === "cv-old" && r.toVersion === "cv-new");
    ok("[applied] exactly one deploy (the promote), and the confirm step logged ok", d.deployCalls.length === 1 && d.deployCalls[0] === "cv-new" && r.steps.some((s) => s.step === "confirm-live" && s.ok));
  }
  {
    // CONFIRM MISMATCH: the promote was accepted but a different version reads live -> auto-rollback.
    const d = new FakeAssetsDriver({ confirmLive: "cv-unexpected" });
    const r = await applyConsoleComponent(d, input());
    ok("[confirm] a promote that did not land rolls back to the recorded target", r.outcome === "rolled-back" && d.deployCalls.length === 2 && d.deployCalls[1] === "cv-old");
    ok("[confirm] the rollback reason says the engine is unaffected and the console is retriable alone", /engine is unaffected/.test(r.reason ?? "") && /retry the console component alone/.test(r.reason ?? ""));
  }
  {
    // CONFIRM MISMATCH + the rollback deploy ALSO fails -> outcome "rollback-failed", never a claim that the
    // revert happened: the console is still serving the unexpected build, and the enum is the only part any
    // consumer reads.
    const d = new FakeAssetsDriver({ confirmLive: "cv-unexpected", rollbackFails: true });
    const r = await applyConsoleComponent(d, input());
    ok("[confirm] a failed confirm-rollback is reported as rollback-failed, not as a rollback that worked", r.outcome === "rollback-failed" && r.outcome !== ("rolled-back" as typeof r.outcome));
    ok("[confirm] a failed confirm-rollback surfaces the dashboard recovery path", /re-deploy version cv-old from the Cloudflare dashboard/.test(r.reason ?? ""));
  }
  {
    // CONFIRM READ THROWS: the promote API accepted the deploy (the primary confirmation), so the deploy is
    // kept and NO rollback is issued -- but the outcome is "applied-unconfirmed", not "applied".
    //
    // "applied" is a claim of PROOF: the promote landed AND the live version was read back and matched. Here the
    // read-back never happened, so the engine cannot say which version is live, and must not claim a
    // confirmation it does not have. The KEEP behaviour is unchanged (one deploy call, no revert); only the
    // claim about it must be accurate.
    const d = new FakeAssetsDriver({ confirmFails: true });
    const r = await applyConsoleComponent(d, input());
    ok("[confirm] an unreadable confirmation is applied-unconfirmed: the deploy is kept, the proof is not claimed", r.outcome === "applied-unconfirmed" && /confirmation read failed/.test(r.reason ?? "") && d.deployCalls.length === 1);
  }

  // ================================================================================================
  console.log("-- rollbackConsoleComponent: the standalone console revert --");
  // ================================================================================================
  {
    const d = new FakeAssetsDriver();
    const r = await rollbackConsoleComponent(d, { toVersion: "" });
    ok("[rollback] no recorded target -> no-target (never a blind deploy)", r.outcome === "no-target" && d.deployCalls.length === 0);
  }
  {
    const d = new FakeAssetsDriver({ currentFails: true });
    const r = await rollbackConsoleComponent(d, { toVersion: "cv-good" });
    ok("[rollback] an unreadable live version -> failed, nothing was changed", r.outcome === "failed" && /nothing was changed/.test(r.reason ?? ""));
  }
  {
    const d = new FakeAssetsDriver({ current: "cv-good" });
    const r = await rollbackConsoleComponent(d, { toVersion: "cv-good" });
    ok("[rollback] already on the target (single-version) -> idempotent no-op", r.outcome === "already" && d.deployCalls.length === 0);
  }
  {
    // A SPLIT never short-circuits, even when the target is one of the slices: deploy at 100% collapses it.
    const d = new FakeAssetsDriver({ current: "cv-good", liveSlices: [{ versionId: "cv-good", percentage: 60 }, { versionId: "cv-bad", percentage: 40 }], confirmLive: "cv-good" });
    const r = await rollbackConsoleComponent(d, { toVersion: "cv-good" });
    ok("[rollback] a split is collapsed by deploying the known-good at 100% (no short-circuit)", r.outcome === "reverted" && d.deployCalls.length === 1 && d.deployCalls[0] === "cv-good");
  }
  {
    const d = new FakeAssetsDriver({ current: "cv-bad", rollbackFails: false, promoteFails: true });
    // promoteFails throws for any non-"current" id; target cv-good != current cv-bad -> deploy fails.
    const r = await rollbackConsoleComponent(d, { toVersion: "cv-good" });
    ok("[rollback] a failed deploy -> failed with the atomic still-serving reason", r.outcome === "failed" && /still serving/.test(r.reason ?? ""));
  }
  {
    const d = new FakeAssetsDriver({ current: "cv-bad", confirmLive: "cv-good" });
    const r = await rollbackConsoleComponent(d, { toVersion: "cv-good" });
    ok("[rollback] deploy + confirm -> reverted (reload prompt in the reason)", r.outcome === "reverted" && r.fromVersion === "cv-bad" && /Reload the console/.test(r.reason ?? ""));
  }
  {
    const d = new FakeAssetsDriver({ current: "cv-bad", confirmLive: "cv-unexpected" });
    const r = await rollbackConsoleComponent(d, { toVersion: "cv-good" });
    ok("[rollback] a confirm mismatch -> reverted-unverified (investigate)", r.outcome === "reverted-unverified" && /different version/.test(r.reason ?? ""));
  }
  {
    const d = new FakeAssetsDriver({ current: "cv-bad", confirmFails: true });
    const r = await rollbackConsoleComponent(d, { toVersion: "cv-good" });
    ok("[rollback] an unreadable confirm -> reverted-unverified with the honest reason", r.outcome === "reverted-unverified" && /confirmation read failed/.test(r.reason ?? ""));
  }

  console.log(failures === 0 ? "\nUPDATE ORCHESTRATION VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
