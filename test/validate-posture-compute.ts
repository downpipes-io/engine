// The pure computePosture groups: the healthy baseline, each starter check failing on its condition, the
// immutability (WORM) suite, the score weighting, the dispose-bootstrap-token finding, the
// recovery-codes-low warning, the risk-accept fold, the sort order, snapshot + regression detection, the
// dest-cred-encryption finding, and isKnownCheckId / CHECK_SEVERITY. Pure in-memory; no DO, no network. The
// orchestrator (validate-posture.ts) calls runCompute() in order; assertions go through the shared ok().
//
// runCompute() is factored into named per-section helpers, each exercising one banner-delimited group,
// invoked here in a fixed order through the same shared ok() counter.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  computePosture,
  snapshotOf,
  detectRegressions,
  isKnownCheckId,
  isOverrideKind,
  CHECK_SEVERITY,
  type PostureInput,
} from "../src/admin/posture.ts";
import { ok, byId, healthyInput, overrideFor, NOW, DAY } from "./validate-posture-shared.ts";

export function runCompute(): void {
  computeHealthyBaseline();
  computeEachCheckFails();
  computeAdminStrongAuth();
  computeDetailPhrasings();
  computeImmutability();
  computeImmutabilityRetentionAxis();
  computeScoreWeighting();
  computeDisposeBootstrapToken();
  computeRecoveryCodesLow();
  computeRiskAcceptFold();
  computeOverrideKinds();
  computeSortOrder();
  computeSnapshotRegression();
  computeDestCredEncryption();
  computeUpdateIntegrityChecks();
  computeKnownCheckIds();
  computeSeverityMapDriftGate();
  computeRestoreTestRecencyKeyedCredit();
}

// ---- computePosture: the healthy baseline -------------------------------------------------
function computeHealthyBaseline(): void {
  const report = computePosture(healthyInput(), NOW);
  const m = byId(report);
  ok("healthy: access-enforced passes", m.get("access-enforced")?.status === "pass");
  ok("healthy: admin-strong-auth passes (all admins passkeyed, no IdP, no live token)", m.get("admin-strong-auth")?.status === "pass");
  ok("healthy: two-owners passes", m.get("two-owners")?.status === "pass");
  ok("healthy: restore-test-recency passes", m.get("restore-test-recency")?.status === "pass");
  ok("healthy: restore-test-enabled passes", m.get("restore-test-enabled")?.status === "pass");
  ok("healthy: failure-alerts passes", m.get("failure-alerts")?.status === "pass");
  ok("healthy: destination-configured passes", m.get("destination-configured")?.status === "pass");
  ok("healthy: break-glass-present passes", m.get("break-glass-present")?.status === "pass");
  ok("healthy: operational-private-weakening passes (absent = stronger posture)", m.get("operational-private-weakening")?.status === "pass");
  ok("healthy: credential-expiry passes", m.get("credential-expiry")?.status === "pass");
  ok("healthy: audit-export-available always passes (info)", m.get("audit-export-available")?.status === "pass");
  ok("healthy: beacon-off passes", m.get("beacon-off")?.status === "pass");
  ok("healthy: encryption-pq-hybrid always passes (info)", m.get("encryption-pq-hybrid")?.status === "pass");
  // immutability passes informationally in the healthy baseline: the healthy input does not configure a
  // WORM policy (worm is absent), so the check reports the honest "not configured" informational pass
  // (WORM is opt-in) rather than failing. The dedicated immutability suite below exercises the enforced /
  // configured-but-unenforced / not-configured states explicitly.
  ok("healthy: immutability passes informationally (WORM not configured)", m.get("immutability")?.status === "pass");
  // dispose-bootstrap-token passes in the healthy baseline: the token has been disposed (adminTokenPresent
  // false), so even with the bootstrap consumed there is no live break-glass string to take admin with.
  ok("healthy: dispose-bootstrap-token passes (token disposed)", m.get("dispose-bootstrap-token")?.status === "pass");
  // media-diversity carries the healthy fixture's ATTESTED-PASS override (the platform cannot verify the
  // "two media" leg itself), so it reads attested-pass -- a score-positive, distinctly-listed state.
  ok("healthy: media-diversity reads attested-pass (owner attestation)", m.get("media-diversity")?.status === "attested-pass");
  ok("healthy: media-diversity autoStatus is cannot-verify (platform cannot observe media class)", m.get("media-diversity")?.autoStatus === "cannot-verify");
  ok("healthy: media-diversity carries the override reason", m.get("media-diversity")?.override?.reason.includes("two providers") === true);
  ok("healthy: score is 100 when everything passes", report.score === 100);
  ok("healthy: all nineteen starter checks present", report.checks.length === 19);
  // Every check states how it is determined and its automatic outcome.
  ok("healthy: every check carries a how line", report.checks.every((c) => typeof c.how === "string" && c.how.length > 10));
  ok("healthy: every check carries an autoStatus", report.checks.every((c) => c.autoStatus === "pass" || c.autoStatus === "fail" || c.autoStatus === "cannot-verify"));
  // Severities match the fixed table.
  ok("severity: restore-test-recency is critical", m.get("restore-test-recency")?.severity === "critical");
  ok("severity: destination-configured is critical", m.get("destination-configured")?.severity === "critical");
  ok("severity: access-enforced is high", m.get("access-enforced")?.severity === "high");
  ok("severity: admin-strong-auth is high", m.get("admin-strong-auth")?.severity === "high");
  ok("severity: two-owners is medium", m.get("two-owners")?.severity === "medium");
  ok("severity: beacon-off is low", m.get("beacon-off")?.severity === "low");
}

// ---- computePosture: each check fails on its condition ------------------------------------
function computeEachCheckFails(): void {
  {
    // access-enforced fails when a shared-token path is EFFECTIVELY LIVE (present, not env-disabled, not
    // retired): the account-level fact, independent of who is reading.
    const i = healthyInput();
    i.status.adminTokenPresent = true;
    i.status.tokenFallbackDisabled = false;
    i.status.breakGlassTokenRetired = false;
    const m = byId(computePosture(i, NOW));
    ok("fail: access-enforced fails while a shared-token path is live", m.get("access-enforced")?.status === "fail");
  }
  {
    // access-enforced PASSES when the token is present but env-disabled (the fallback is dead).
    const i = healthyInput();
    i.status.adminTokenPresent = true;
    i.status.tokenFallbackDisabled = true;
    const m = byId(computePosture(i, NOW));
    ok("fail: access-enforced passes when token fallback disabled", m.get("access-enforced")?.status === "pass");
  }
  {
    // access-enforced PASSES when the token is present but retired in-app (the fallback is dead).
    const i = healthyInput();
    i.status.adminTokenPresent = true;
    i.status.tokenFallbackDisabled = false;
    i.status.breakGlassTokenRetired = true;
    ok("fail: access-enforced passes when the token is retired in-app", byId(computePosture(i, NOW)).get("access-enforced")?.status === "pass");
  }
  {
    // access-enforced is ACCOUNT-LEVEL: with no ADMIN_TOKEN at all it passes regardless of how the
    // reader signed in (a passkey/SSO tenant is not unfairly failed; the report is reader-independent).
    const i = healthyInput();
    i.status.adminTokenPresent = false;
    i.status.tokenFallbackDisabled = false;
    ok("fail: access-enforced passes with no token configured (attributable-only paths)", byId(computePosture(i, NOW)).get("access-enforced")?.status === "pass");
  }
  {
    const i = healthyInput();
    i.ownerCount = 1;
    ok("fail: two-owners fails with a single owner", byId(computePosture(i, NOW)).get("two-owners")?.status === "fail");
  }
  {
    // restore-test-recency fails when a downpipe HAS RUN but has never had a successful test.
    const i = healthyInput();
    i.downpipes = [{ id: "dp1", name: "Primary", restoreTestCadenceSeconds: 604800, lastRunId: "run-dp1" }];
    ok("fail: restore-test-recency fails when never tested (has archives)", byId(computePosture(i, NOW)).get("restore-test-recency")?.status === "fail");
  }
  {
    // A downpipe that has NEVER COMPLETED A RUN is not failed (there is no archive to test yet): a
    // brand-new downpipe must not open as a critical failure it cannot clear until its first run.
    const i = healthyInput();
    i.downpipes = [{ id: "dp1", name: "Brand new", restoreTestCadenceSeconds: 604800 }];
    const c = byId(computePosture(i, NOW)).get("restore-test-recency");
    ok("fair: restore-test-recency does not fail a never-run downpipe", c?.status === "pass");
    ok("fair: the never-run downpipe is named in the detail", (c?.detail ?? "").includes("not yet completed a first run"));
  }
  {
    // restore-test-recency fails when the last successful test is older than 180 days.
    const i = healthyInput();
    i.downpipes = [{ id: "dp1", name: "Primary", restoreTestCadenceSeconds: 604800, lastRestoreTestAt: NOW - 200 * DAY, lastRestoreTestOk: true, lastRunId: "run-dp1" }];
    ok("fail: restore-test-recency fails past 180 days", byId(computePosture(i, NOW)).get("restore-test-recency")?.status === "fail");
    // A last test at 100 days (within 180) still passes the critical check (the high band is detail only).
    const j = healthyInput();
    j.downpipes = [{ id: "dp1", name: "Primary", restoreTestCadenceSeconds: 604800, lastRestoreTestAt: NOW - 100 * DAY, lastRestoreTestOk: true, lastRunId: "run-dp1" }];
    ok("fail: restore-test-recency passes within 180 days (100d)", byId(computePosture(j, NOW)).get("restore-test-recency")?.status === "pass");
  }
  {
    // A FAILED last test (ok:false) counts as no successful test -> recency fails.
    const i = healthyInput();
    i.downpipes = [{ id: "dp1", name: "Primary", restoreTestCadenceSeconds: 604800, lastRestoreTestAt: NOW - DAY, lastRestoreTestOk: false, lastRunId: "run-dp1" }];
    ok("fail: restore-test-recency fails when last test failed", byId(computePosture(i, NOW)).get("restore-test-recency")?.status === "fail");
  }
  {
    const i = healthyInput();
    i.downpipes = [{ id: "dp1", name: "Primary", restoreTestCadenceSeconds: 0, lastRestoreTestAt: NOW - DAY, lastRestoreTestOk: true }];
    ok("fail: restore-test-enabled fails when cadence off (0)", byId(computePosture(i, NOW)).get("restore-test-enabled")?.status === "fail");
  }
  {
    const i = healthyInput();
    i.notifyFailureRuleSet = false;
    ok("fail: failure-alerts fails with no failure rule", byId(computePosture(i, NOW)).get("failure-alerts")?.status === "fail");
  }
  {
    const i = healthyInput();
    i.status.destConfigured = false;
    ok("fail: destination-configured fails with no destination", byId(computePosture(i, NOW)).get("destination-configured")?.status === "fail");
  }
  // environment-self-backup: healthy when an export is present, reached every destination, no auto-heal
  // refusal and not recovery-required; fails on each of those; not raised when the slice is absent.
  {
    const i = healthyInput();
    i.selfBackup = { exportPresent: true, allDestinationsWrote: true, autoHealRefused: false, recoveryRequired: false };
    const m = byId(computePosture(i, NOW));
    ok("self-backup: healthy passes", m.get("environment-self-backup")?.status === "pass");
    ok("self-backup: severity is high", m.get("environment-self-backup")?.severity === "high");
  }
  {
    const i = healthyInput();
    i.selfBackup = { exportPresent: false, allDestinationsWrote: false, autoHealRefused: false, recoveryRequired: false };
    ok("self-backup: no export written yet fails", byId(computePosture(i, NOW)).get("environment-self-backup")?.status === "fail");
  }
  {
    const i = healthyInput();
    i.selfBackup = { exportPresent: true, allDestinationsWrote: false, autoHealRefused: false, recoveryRequired: false };
    ok("self-backup: an export that missed a destination fails", byId(computePosture(i, NOW)).get("environment-self-backup")?.status === "fail");
  }
  {
    const i = healthyInput();
    i.selfBackup = { exportPresent: true, allDestinationsWrote: true, autoHealRefused: true, recoveryRequired: false };
    ok("self-backup: an auto-heal refusal fails", byId(computePosture(i, NOW)).get("environment-self-backup")?.status === "fail");
  }
  {
    const i = healthyInput();
    i.selfBackup = { exportPresent: true, allDestinationsWrote: true, autoHealRefused: false, recoveryRequired: true };
    ok("self-backup: recovery-required fails", byId(computePosture(i, NOW)).get("environment-self-backup")?.status === "fail");
  }
  {
    const i = healthyInput();
    delete i.selfBackup;
    ok("self-backup: not raised when there is nothing to back up (slice absent)", byId(computePosture(i, NOW)).get("environment-self-backup") === undefined);
  }
  {
    const i = healthyInput();
    i.status.breakGlassConfigured = false;
    ok("fail: break-glass-present fails with no break-glass", byId(computePosture(i, NOW)).get("break-glass-present")?.status === "fail");
  }
  {
    // operational-private present is a deliberate weakening, surfaced as a finding (fail until accepted).
    const i = healthyInput();
    i.operationalPrivatePresent = true;
    ok("fail: operational-private-weakening fails when present", byId(computePosture(i, NOW)).get("operational-private-weakening")?.status === "fail");

    // This check FAILS when the key is present, so its verdict pushes toward the strict posture. Its
    // copy therefore has to be right about what the strict posture costs, or the score says "remove it"
    // while the text overstates the price of doing so. It used to claim the key is what makes self-test
    // and self-restore work, and that removing it leaves recovery "break-glass, offline" -- both untrue
    // since verify-at-seal and the canary moved onto the run's own per-run key, and since the console
    // gained a break-glass restore panel for exactly that posture.
    //
    // Asserted on CLAIMS rather than exact sentences so the copy stays improvable, and asserted in both
    // directions so a revert fails rather than passing quietly.
    const present = byId(computePosture(i, NOW)).get("operational-private-weakening");
    const absent = byId(computePosture(healthyInput(), NOW)).get("operational-private-weakening");
    ok("copy: the check exists in both states", present !== undefined && absent !== undefined);
    ok("copy: 'how' names the unattended work as what the key buys", /unattended/i.test(present?.how ?? ""));
    ok("copy: the present-detail names scheduled restore tests rather than generic self-test", /scheduled restore test/i.test(present?.detail ?? ""));
    ok("copy: the absent-detail states verification at seal still runs", /verification at seal/i.test(absent?.detail ?? ""));
    ok("copy: the absent-detail states an in-console restore still works", /in-console restore still works/i.test(absent?.detail ?? ""));
    ok("copy: the retired 'recovery is break-glass, offline' claim is gone", !/recovery is break-glass, offline/i.test(absent?.detail ?? ""));
    ok("copy: the remediation no longer says to rely on offline recovery wholesale", !/rely on offline break-glass recovery/i.test(absent?.remediation ?? ""));
    ok("copy: the remediation says what removing the key actually requires", /offline rehearsal/i.test(absent?.remediation ?? ""));
  }
  {
    const i = healthyInput();
    i.expiry = [{ label: "S3 key", state: "approaching" }];
    ok("fail: credential-expiry fails on an approaching credential", byId(computePosture(i, NOW)).get("credential-expiry")?.status === "fail");
    const j = healthyInput();
    j.expiry = [{ label: "TLS cert", state: "expired" }];
    ok("fail: credential-expiry fails on an expired credential", byId(computePosture(j, NOW)).get("credential-expiry")?.status === "fail");
    // Credential lifecycle: an EPHEMERAL spent token pending cleanup is EXEMPT from the expiry FAIL (a
    // hygiene nudge surfaced via status.cleanupPending + the Needs-attention tier, not a posture failure).
    const eph = healthyInput();
    eph.expiry = [{ label: "spent attach token", state: "approaching", lifecycleClass: "ephemeral", cleanupState: "pending" }];
    ok("exempt: an ephemeral pending-cleanup token does NOT fail credential-expiry", byId(computePosture(eph, NOW)).get("credential-expiry")?.status === "pass");
    // A no-expiry credential is a deliberate state (a secret that does not expire), not an impending lapse.
    const ne = healthyInput();
    ne.expiry = [{ label: "Okta OIDC secret", state: "no-expiry", lifecycleClass: "functional" }];
    ok("exempt: a no-expiry credential does NOT fail credential-expiry", byId(computePosture(ne, NOW)).get("credential-expiry")?.status === "pass");
    // A FUNCTIONAL expired credential STILL fails (the real safety net for an expiring backup credential).
    const fexp = healthyInput();
    fexp.expiry = [{ label: "R2 destination key", state: "expired", lifecycleClass: "functional" }];
    ok("still fails: a functional expired credential fails credential-expiry", byId(computePosture(fexp, NOW)).get("credential-expiry")?.status === "fail");
  }
  {
    const i = healthyInput();
    i.beaconEnabled = true;
    ok("fail: beacon-off fails when the beacon is enabled", byId(computePosture(i, NOW)).get("beacon-off")?.status === "fail");
  }
  {
    // seal-verification (critical, weight 5): a downpipe whose LAST verify-at-seal was SUSPECT
    // (lastSealVerifyOk === false) fails the check. This drives the critical-weight fail path directly.
    const i = healthyInput();
    const first = i.downpipes[0];
    if (first) first.lastSealVerifyOk = false;
    ok("fail: seal-verification fails when the last verify-at-seal was suspect", byId(computePosture(i, NOW)).get("seal-verification")?.status === "fail");
  }
  {
    // redundant-copies (high, weight 3): a downpipe fanning out to only one destination
    // (destinationCount < 2) fails the 3-2-1 redundancy check.
    const i = healthyInput();
    const first = i.downpipes[0];
    if (first) first.destinationCount = 1;
    ok("fail: redundant-copies fails when a downpipe writes to only one destination", byId(computePosture(i, NOW)).get("redundant-copies")?.status === "fail");
  }
}

// ---- admin-strong-auth (MFA / passkeys / SSO): platform-verified or needs-attestation, never a
// fabricated red -------------------------------------------------------------------------------
function computeAdminStrongAuth(): void {
  // Healthy: all admins passkeyed, no IdP, no live token -> platform-verified pass (asserted in the
  // baseline). Here: the cannot-verify states.
  {
    // An enabled IdP connection means sign-in can happen upstream where MFA is invisible -> unattested.
    const i = healthyInput();
    i.identity = { adminIdentities: 2, adminsWithPasskey: 2, idpConnectionsEnabled: 1 };
    const c = byId(computePosture(i, NOW)).get("admin-strong-auth");
    ok("strong-auth: an enabled IdP connection reads unattested (needs attestation), never fail", c?.status === "unattested");
    ok("strong-auth: autoStatus is cannot-verify with an IdP enabled", c?.autoStatus === "cannot-verify");
    ok("strong-auth: the detail names the IdP as the unverifiable path", (c?.detail ?? "").includes("IdP"));
  }
  {
    // Admins without passkeys (e.g. signing in through Cloudflare Access) -> unattested, never fail.
    const i = healthyInput();
    i.identity = { adminIdentities: 3, adminsWithPasskey: 1, idpConnectionsEnabled: 0 };
    const c = byId(computePosture(i, NOW)).get("admin-strong-auth");
    ok("strong-auth: admins without passkeys read unattested (Access MFA is not observable)", c?.status === "unattested");
  }
  {
    // No admin identities yet -> unattested with the honest detail.
    const i = healthyInput();
    i.identity = { adminIdentities: 0, adminsWithPasskey: 0, idpConnectionsEnabled: 0 };
    const c = byId(computePosture(i, NOW)).get("admin-strong-auth");
    ok("strong-auth: no admin identities reads unattested", c?.status === "unattested");
  }
  {
    // Identity slice absent (a gather fault) -> honest cannot-verify, never a fabricated verdict.
    const i = healthyInput();
    delete i.identity;
    const c = byId(computePosture(i, NOW)).get("admin-strong-auth");
    ok("strong-auth: an absent identity slice reads unattested (honest cannot-verify)", c?.status === "unattested");
  }
  {
    // A live shared token blocks the platform-verified claim even with all admins passkeyed.
    const i = healthyInput();
    i.status.adminTokenPresent = true;
    i.status.tokenFallbackDisabled = false;
    const c = byId(computePosture(i, NOW)).get("admin-strong-auth");
    ok("strong-auth: a live shared-token path blocks the verified pass (unattested)", c?.status === "unattested");
  }
  {
    // The owner ATTESTS it (MFA enforced at the IdP): reads attested-pass and counts for the score.
    const i = healthyInput();
    i.identity = { adminIdentities: 2, adminsWithPasskey: 0, idpConnectionsEnabled: 1 };
    i.overrides = new Map([
      ...i.overrides,
      ["admin-strong-auth", overrideFor("attested-pass", "MFA enforced for all staff at our IdP (conditional access)")],
    ]);
    const report = computePosture(i, NOW);
    const c = byId(report).get("admin-strong-auth");
    ok("strong-auth: an owner attestation reads attested-pass", c?.status === "attested-pass");
    ok("strong-auth: the attestation reason is carried on the check", c?.override?.reason.includes("MFA enforced") === true);
    ok("strong-auth: an attested check counts toward the score (100)", report.score === 100);
  }
}

// ---- singular/plural + note-band phrasing branches (the detail strings auditors read) -----------
function computeDetailPhrasings(): void {
  {
    // One admin identity, passkeyed: the singular "identity" phrasing on the verified pass.
    const i = healthyInput();
    i.identity = { adminIdentities: 1, adminsWithPasskey: 1, idpConnectionsEnabled: 0 };
    const c = byId(computePosture(i, NOW)).get("admin-strong-auth");
    ok("phrasing: one admin reads 'identity' (singular)", (c?.detail ?? "").includes("1 admin identity "));
  }
  {
    // Two enabled IdP connections: the plural phrasing in the cannot-verify why.
    const i = healthyInput();
    i.identity = { adminIdentities: 2, adminsWithPasskey: 2, idpConnectionsEnabled: 2 };
    const c = byId(computePosture(i, NOW)).get("admin-strong-auth");
    ok("phrasing: two IdP connections read plural", (c?.detail ?? "").includes("2 enabled IdP connections"));
  }
  {
    // TWO never-run downpipes: the plural never-run note on an otherwise-failing recency check.
    const i = healthyInput();
    i.downpipes = [
      { id: "a", name: "New A", restoreTestCadenceSeconds: 604800 },
      { id: "b", name: "New B", restoreTestCadenceSeconds: 604800 },
      { id: "c", name: "Old", restoreTestCadenceSeconds: 604800, lastRunId: "run-c" },
    ];
    const c = byId(computePosture(i, NOW)).get("restore-test-recency");
    ok("phrasing: two never-run downpipes read plural ('s have')", (c?.detail ?? "").includes("2 downpipes have not yet completed a first run"));
    ok("phrasing: the graded downpipe still fails (never tested, has run)", c?.status === "fail");
  }
  {
    // Warn band + a never-run note on a PASSING check: both phrases co-render.
    const i = healthyInput();
    i.downpipes = [
      { id: "w", name: "Aging", restoreTestCadenceSeconds: 604800, lastRestoreTestAt: NOW - 120 * DAY, lastRestoreTestOk: true, lastRunId: "run-w" },
      { id: "n", name: "New", restoreTestCadenceSeconds: 604800 },
    ];
    const c = byId(computePosture(i, NOW)).get("restore-test-recency");
    ok("phrasing: warn band + never-run note co-render on a pass", c?.status === "pass" && (c?.detail ?? "").includes("older than 90 days") && (c?.detail ?? "").includes("not yet completed a first run"));
  }
}

// ---- immutability (WORM / Object-Lock): real status, not inferred from delete permission --------
function computeImmutability(): void {
  // not configured (worm absent) -> informational PASS.
  ok("immutability: absent worm slice -> passes informationally (not configured)", byId(computePosture(healthyInput(), NOW)).get("immutability")?.status === "pass");

  // not configured (explicit) -> informational PASS, detail says opt-in/not configured.
  const notCfg = healthyInput();
  notCfg.worm = { configured: false, misconfigured: false, bucketEnforces: false };
  const mNot = byId(computePosture(notCfg, NOW));
  ok("immutability: configured:false -> passes (opt-in, off)", mNot.get("immutability")?.status === "pass");
  ok("immutability: not-configured detail says it is opt-in", (mNot.get("immutability")?.detail ?? "").includes("opt-in"));

  // configured + bucket ENFORCES -> PASS, detail names mode + retention and the enforced property.
  const enf = healthyInput();
  enf.worm = { configured: true, misconfigured: false, mode: "compliance", retentionDays: 30, bucketEnforces: true };
  const mEnf = byId(computePosture(enf, NOW));
  ok("immutability: configured + bucket enforces -> passes", mEnf.get("immutability")?.status === "pass");
  ok("immutability: enforced detail says WORM enforced", (mEnf.get("immutability")?.detail ?? "").includes("WORM enforced"));
  ok("immutability: enforced detail names the mode", (mEnf.get("immutability")?.detail ?? "").includes("compliance"));
  ok("immutability: enforced detail names the retention window", (mEnf.get("immutability")?.detail ?? "").includes("30 day"));

  // configured but bucket does NOT enforce -> FAIL (the dangerous gap: policy set, the store refuses).
  const unenf = healthyInput();
  unenf.worm = { configured: true, misconfigured: false, mode: "governance", retentionDays: 14, bucketEnforces: false };
  const mUnenf = byId(computePosture(unenf, NOW));
  ok("immutability: configured but bucket does not enforce -> FAILS (warning)", mUnenf.get("immutability")?.status === "fail");
  ok("immutability: configured-but-unenforced is a medium warning", mUnenf.get("immutability")?.severity === "medium");
  // A bucket without Object-Lock does not accept a lock-bearing write and drop the headers, it REFUSES the
  // write, so the destination holds no archives and there is nothing there to be unprotected. The detail
  // states the refusal, and this assertion states the negation of the incorrect "unprotected" framing so
  // that framing cannot come back through this check.
  ok("immutability: unenforced detail says the store REFUSES the write", (mUnenf.get("immutability")?.detail ?? "").includes("REFUSES every write"));
  ok("immutability: unenforced detail says no archive is stored there", (mUnenf.get("immutability")?.detail ?? "").includes("no archive is stored on this destination"));
  ok("immutability: unenforced detail no longer claims archives exist but are unprotected", !(mUnenf.get("immutability")?.detail ?? "").includes("NOT protected"));

  // configured but probe UNKNOWN -> FAIL (cannot confirm; do not claim protection).
  const unk = healthyInput();
  unk.worm = { configured: true, misconfigured: false, mode: "governance", retentionDays: 14, bucketEnforces: "unknown" };
  const mUnk = byId(computePosture(unk, NOW));
  ok("immutability: configured but probe unknown -> FAILS (cannot confirm)", mUnk.get("immutability")?.status === "fail");
  ok("immutability: unknown detail says could not confirm", (mUnk.get("immutability")?.detail ?? "").includes("could not confirm"));

  // An ABSENT bucketEnforces must read the SAME as an explicit "unknown", never as the definite "it was not
  // created with Object-Lock enabled" (a positive finding from a probe that never ran). It is what
  // gatherWormSlice returns on any probe fault (no destination, transport error, a store with no
  // objectLockStatus). Driven as a loop so the two inputs cannot drift apart.
  for (const [label, bucketEnforces] of [["explicit unknown", "unknown"], ["absent verdict", undefined]] as const) {
    const cc = healthyInput();
    cc.worm = { configured: true, misconfigured: false, mode: "governance", retentionDays: 14, ...(bucketEnforces !== undefined ? { bucketEnforces } : {}) };
    const detail = byId(computePosture(cc, NOW)).get("immutability")?.detail ?? "";
    ok(`immutability cannot-confirm (${label}): says enforcement could not be confirmed`, detail.includes("could not confirm the destination bucket enforces S3 Object-Lock"));
    ok(`immutability cannot-confirm (${label}): never asserts the bucket was not created with Object-Lock`, !detail.includes("was not created with Object-Lock enabled"));
    ok(`immutability cannot-confirm (${label}): never asserts the store refuses the write`, !detail.includes("REFUSES every write"));
  }

  // configured but MISCONFIGURED (invalid policy) -> FAIL, detail says invalid.
  const mis = healthyInput();
  mis.worm = { configured: true, misconfigured: true, bucketEnforces: false };
  const mMis = byId(computePosture(mis, NOW));
  ok("immutability: configured but invalid policy -> FAILS", mMis.get("immutability")?.status === "fail");
  ok("immutability: misconfigured detail says INVALID", (mMis.get("immutability")?.detail ?? "").includes("INVALID"));

  // bucket enforces by its OWN default rule even with no policy configured -> credited as PASS, using the
  // probe's default mode/days (so a bucket pre-armed with Object-Lock is reported honestly as enforced).
  const dflt = healthyInput();
  dflt.worm = { configured: false, misconfigured: false, bucketEnforces: true, probeMode: "compliance", probeDays: 7 };
  const mDflt = byId(computePosture(dflt, NOW));
  ok("immutability: bucket enforces by default rule (no policy) -> passes as enforced", mDflt.get("immutability")?.status === "pass");
  ok("immutability: default-rule enforced detail credits the bucket default mode", (mDflt.get("immutability")?.detail ?? "").includes("bucket default"));

  // immutability can be risk-accepted (it is a known check id) -> a failing one reads risk-accepted.
  const acc = healthyInput();
  acc.worm = { configured: true, misconfigured: false, mode: "governance", retentionDays: 14, bucketEnforces: false };
  acc.overrides = new Map([...acc.overrides, ["immutability", overrideFor("risk-accepted")]]);
  ok("immutability: a failing immutability check can be risk-accepted", byId(computePosture(acc, NOW)).get("immutability")?.status === "risk-accepted");
}

// ---- immutability: the RETENTION axis on an enforcing bucket --------------------------------
// buildImmutability computed failed = !enforces, so the strongest sentence the check carries, "a
// compromised delete-credential cannot hard-delete or overwrite an archive within its retention window",
// was attached to every Object-Lock-enabled bucket. Two of those states put no retention window anywhere:
// an INVALID policy (which arms no header) and NO policy at all (which arms none either, and needs no
// misconfiguration by anyone). Object-Lock being enabled on a bucket retains nothing by itself; only the
// per-object header the engine writes under a valid policy, or the bucket's own default retention rule,
// does. The check is an automatic PASS feeding the posture SCORE, the evidence pack's framework mapping
// and the risk-accept records, so the claim reached a customer through three surfaces at once.
//
// Every assertion here pins a state on the retention axis; the wordings of the not-enforced and
// cannot-confirm readings are asserted BYTE FOR BYTE so a later change to the retention axis cannot
// quietly reword them.
function computeImmutabilityRetentionAxis(): void {
  const immOf = (worm: PostureInput["worm"]) => {
    const i = healthyInput();
    if (worm === undefined) delete i.worm;
    else i.worm = worm;
    const report = computePosture(i, NOW);
    return { check: byId(report).get("immutability"), score: report.score };
  };
  const STRONG = "A compromised delete-credential cannot hard-delete or overwrite an archive within its retention window.";
  const ARMED_ENFORCED =
    "WORM enforced: the destination bucket enforces S3 Object-Lock (compliance mode, 30 days retention). A compromised delete-credential cannot hard-delete or overwrite an archive within its retention window.";

  // CONTROL, both sides: a VALID armed policy on an enforcing bucket keeps the strong claim BYTE FOR BYTE.
  // The bucket's own default rule is beside the point, because the header the engine writes is what the
  // claim rests on, so the same string must come back with the rule present, absent and unread.
  {
    const armed = { configured: true, misconfigured: false, mode: "compliance" as const, retentionDays: 30, bucketEnforces: true as const };
    const withRule = immOf({ ...armed, defaultRetention: true, probeMode: "governance", probeDays: 3 });
    const noRule = immOf({ ...armed, defaultRetention: false });
    const unread = immOf(armed);
    ok("retention CONTROL: armed + enforcing + a bucket default rule keeps the strong claim byte for byte", withRule.check?.status === "pass" && withRule.check?.detail === ARMED_ENFORCED);
    ok("retention CONTROL: armed + enforcing + NO bucket default rule keeps the strong claim byte for byte", noRule.check?.status === "pass" && noRule.check?.detail === ARMED_ENFORCED);
    ok("retention CONTROL: armed + enforcing + an UNREAD default rule keeps the strong claim byte for byte", unread.check?.status === "pass" && unread.check?.detail === ARMED_ENFORCED);
    ok("retention CONTROL: an armed enforcing bucket scores clean", withRule.score === 100 && noRule.score === 100 && unread.score === 100);
    ok("retention CONTROL: the armed remediation is unchanged", unread.check?.remediation === "No action required; store-enforced WORM is in force. Verify the retention window meets your policy.");
  }

  // CONTROL, both sides: the not-enforced and cannot-confirm wordings are pinned byte for byte, and a
  // defaultRetention value on a non-enforcing bucket changes nothing (the probe never sets it there).
  //
  // THE NOT-ENFORCED PIN, deliberately: a bucket that was not created with Object-Lock does not accept a
  // lock-bearing PUT and discard the headers, it refuses the write outright, R2 with 501 NotImplemented and
  // AWS S3 with ObjectLockConfigurationNotFoundError. So the destination holds no archives at all, which is
  // what the detail must say rather than claiming archives exist but are unprotected. The pin is a byte pin
  // so it catches an accidental rewrite. The rule behind both this surface and the signed immutability
  // report is graded in one place by test/validate-worm-refusal-parity.ts, which stops this suite and
  // validate-reports.ts asserting opposite things about the same input.
  // buildImmutability takes its mechanism and its store noun from dest/worm-remedy.ts, as the signed report
  // does, so an Azure customer is not told to inspect a "bucket" for "S3 Object-Lock". This fixture carries
  // no provider, so what is pinned here is the S3 FALLBACK. The per-provider branches are graded in
  // test/validate-worm-refusal-parity.ts, which is where the rule about them lives.
  {
    const cfg = { configured: true, misconfigured: false, mode: "governance" as const, retentionDays: 14 };
    const unenf = immOf({ ...cfg, bucketEnforces: false });
    const unk = immOf({ ...cfg, bucketEnforces: "unknown" });
    ok(
      "retention CONTROL: the not-enforced wording is the REFUSAL wording, byte for byte",
      unenf.check?.status === "fail" &&
        unenf.check?.detail ===
          "A WORM policy is configured, but the destination bucket does NOT enforce S3 Object-Lock. Object-Lock can only be enabled when a bucket is created. The store REFUSES every write that carries the retention headers, so no archive is stored on this destination at all.",
    );
    // The remediation is now BRANCHED BY PROVIDER: Azure's mechanism is version-level
    // immutability, Google Cloud's is a bucket created with per-object retention, and Cloudflare R2 has none
    // at all by any route. This fixture carries no provider, so what is pinned here is the FALLBACK, the
    // S3-compatible sentence every caller got before the branch existed. The four branches themselves are
    // graded in test/validate-worm-refusal-parity.ts, which is where the rule about them lives.
    ok(
      "retention CONTROL: the not-enforced remediation no longer contradicts its own detail",
      unenf.check?.remediation ===
        "Re-create the destination bucket with Object-Lock ENABLED (it can only be set when the bucket is created, never afterwards) and point this destination at the new bucket, or set the WORM mode back to off to keep using this bucket without immutability. Until you do one of those, every backup written to this destination is refused by the store.",
    );
    ok(
      "retention CONTROL: the cannot-confirm wording is unchanged byte for byte",
      unk.check?.status === "fail" &&
        unk.check?.detail ===
          "A WORM policy is configured, but the engine could not confirm the destination bucket enforces S3 Object-Lock (the bucket may not have been created with it, or the probe could not read the configuration). Archives may NOT actually be protected, do not rely on WORM until this is confirmed.",
    );
    ok(
      "retention CONTROL: the invalid-policy wording on a NON-enforcing bucket is unchanged byte for byte",
      immOf({ configured: true, misconfigured: true, bucketEnforces: false }).check?.detail ===
        "A WORM policy is configured but INVALID (mode and retention days must both be set, with a positive window), so no S3 Object-Lock metadata is being written and archives are NOT protected. Fix the policy; until then immutability is not in force.",
    );
    ok("retention CONTROL: a defaultRetention value on a NON-enforcing bucket changes nothing", immOf({ ...cfg, bucketEnforces: false, defaultRetention: true }).check?.detail === unenf.check?.detail);
    ok(
      "retention CONTROL: the absent-slice not-configured wording is unchanged byte for byte",
      immOf(undefined).check?.detail ===
        "WORM (S3 Object-Lock) is not configured (it is opt-in). Archives remain tamper-evident (signed, hash-chained RUNLOG), but the destination bucket does not enforce write-once retention. Configuring it makes a compromised delete-credential unable to hard-delete archives within the retention window.",
    );
  }

  // NO POLICY on an enforcing bucket with NO default retention rule: the reachable overclaim. Nothing
  // applies a retention window, so the strong claim is REFUSED. It still PASSES: WORM is opt-in, nothing
  // was intended and nothing is intended-but-broken, which is the same posture the check already grades as
  // an informational pass on an ordinary bucket. What changes is the sentence, not the verdict, so no
  // customer who has changed nothing sees a new compliance failure here.
  {
    const r = immOf({ configured: false, misconfigured: false, bucketEnforces: true, defaultRetention: false });
    ok("retention: no policy + enforcing + no default rule -> still PASSES (opt-in, nothing intended)", r.check?.status === "pass");
    ok("retention: no policy + enforcing + no default rule REFUSES the strong claim", !(r.check?.detail ?? "").includes(STRONG));
    ok("retention: no policy + enforcing + no default rule does not say WORM enforced", !(r.check?.detail ?? "").includes("WORM enforced"));
    ok(
      "retention: no policy + enforcing + no default rule reads exactly the unretained sentence",
      r.check?.detail ===
        "WORM (S3 Object-Lock) is not configured (it is opt-in). The destination bucket has S3 Object-Lock switched on, but it carries no default retention rule and the engine writes no retention header of its own, so an archive written here carries no retention window and a compromised delete-credential can hard-delete it. S3 Object-Lock enabled on a bucket does not retain anything by itself. Archives remain tamper-evident (signed, hash-chained RUNLOG).",
    );
    ok(
      "retention: its remediation says the bucket does NOT need re-creating",
      r.check?.remediation ===
        "Set a WORM policy (mode + retention days) so the engine arms a retention header on every archive, or give the bucket a default retention rule. The bucket already has S3 Object-Lock enabled, so it does not need re-creating.",
    );
    ok("retention: no policy + enforcing + no default rule costs the score nothing", r.score === 100);
  }

  // NO POLICY on an enforcing bucket whose default rule COULD NOT BE READ: an unread rule is not an absent
  // rule, so this asserts neither direction and never fails on it.
  {
    const r = immOf({ configured: false, misconfigured: false, bucketEnforces: true });
    ok("retention: no policy + enforcing + an UNREAD default rule does NOT fail", r.check?.status === "pass" && r.score === 100);
    ok("retention: no policy + enforcing + an UNREAD default rule refuses the strong claim", !(r.check?.detail ?? "").includes(STRONG));
    ok(
      "retention: no policy + enforcing + an UNREAD default rule states neither direction, exactly",
      r.check?.detail ===
        "WORM (S3 Object-Lock) is not configured (it is opt-in) and the engine writes no retention header of its own. The destination bucket enforces S3 Object-Lock, but whether it applies a default retention rule could not be read, and that rule is the only thing that would retain an archive here, so this check states neither that archives are write-once-locked nor that they are not. Archives remain tamper-evident (signed, hash-chained RUNLOG).",
    );
  }

  // NO POLICY on an enforcing bucket that DOES carry its own default retention rule: the strong claim
  // holds, and the detail attributes it to the bucket rather than to a header the engine never wrote. The
  // rule is credited whether it arrives as the boolean or as the probe's own mode/days.
  {
    const viaProbe = immOf({ configured: false, misconfigured: false, bucketEnforces: true, probeMode: "compliance", probeDays: 7 });
    const viaBool = immOf({ configured: false, misconfigured: false, bucketEnforces: true, defaultRetention: true });
    ok("retention: no policy + a bucket default rule keeps the strong claim (it is real, the bucket applies it)", viaProbe.check?.status === "pass" && (viaProbe.check?.detail ?? "").includes(STRONG));
    ok(
      "retention: it attributes the window to the bucket, not to a header the engine wrote",
      (viaProbe.check?.detail ?? "").includes("No WORM policy is configured, so this rests entirely on the bucket's own default retention rule and the engine writes no retention header of its own here."),
    );
    ok(
      "retention: the bucket-default reading reads exactly, mode and window credited to the bucket",
      viaProbe.check?.detail ===
        "WORM enforced: the destination bucket enforces S3 Object-Lock (compliance mode (bucket default), 7 days retention). A compromised delete-credential cannot hard-delete or overwrite an archive within its retention window. No WORM policy is configured, so this rests entirely on the bucket's own default retention rule and the engine writes no retention header of its own here.",
    );
    ok(
      "retention: its remediation credits the bucket's rule and offers arming the window instead",
      viaProbe.check?.remediation ===
        "No action required; store-enforced WORM is in force through the bucket's own default retention rule. Verify that rule meets your policy, and set a WORM policy if you want the engine to arm the window itself rather than inherit it.",
    );
    ok("retention: defaultRetention:true alone credits the bucket rule the same way", viaBool.check?.status === "pass" && (viaBool.check?.detail ?? "").includes("rests entirely on the bucket's own default retention rule"));
  }

  // An INVALID policy on an ENFORCING bucket: what the function's own comment promised and did not do. The
  // writer armed nothing, so the window the operator asked for is not in force whatever the bucket does,
  // and a misconfigured policy is never a green claim. It fails in all three retention readings, and the
  // failure rests on the OBSERVED invalidity, never on the unread rule.
  {
    const noRule = immOf({ configured: true, misconfigured: true, bucketEnforces: true, defaultRetention: false });
    ok("retention: an INVALID policy on an enforcing bucket FAILS (never the strong claim)", noRule.check?.status === "fail");
    ok("retention: it is still the medium warning, not a new severity", noRule.check?.severity === "medium");
    ok("retention: the invalid-on-enforcing reading refuses the strong claim", !(noRule.check?.detail ?? "").includes(STRONG));
    ok(
      "retention: invalid + enforcing + no default rule reads exactly",
      noRule.check?.detail ===
        "A WORM policy is configured but INVALID (mode and retention days must both be set, with a positive window), so no S3 Object-Lock metadata is being written. The destination bucket has S3 Object-Lock switched on but carries no default retention rule, so nothing applies a retention window to an archive written here and archives are NOT protected. S3 Object-Lock enabled on a bucket does not retain anything by itself.",
    );
    ok(
      "retention: its remediation does NOT tell the operator to re-create an already-enforcing bucket",
      noRule.check?.remediation ===
        "Set a valid WORM policy (mode + positive retention days). The bucket already enforces S3 Object-Lock, so no re-creation is needed; only the policy is stopping the engine arming the window you intended.",
    );

    const withRule = immOf({ configured: true, misconfigured: true, bucketEnforces: true, defaultRetention: true, probeMode: "governance", probeDays: 3 });
    ok("retention: an INVALID policy fails even where the bucket's own rule does retain", withRule.check?.status === "fail");
    ok(
      "retention: invalid + enforcing + a bucket default rule reads exactly, crediting the rule without passing",
      withRule.check?.detail ===
        "A WORM policy is configured but INVALID (mode and retention days must both be set, with a positive window), so no S3 Object-Lock metadata is being written. The destination bucket enforces S3 Object-Lock and applies its own default retention rule (governance mode (bucket default), 3 days retention), which is the whole of the protection here and is not the window you asked for. Fix the policy so the window you intended is the one in force.",
    );

    const unread = immOf({ configured: true, misconfigured: true, bucketEnforces: true });
    ok("retention: an INVALID policy fails on the observed invalidity, not on the unread rule", unread.check?.status === "fail");
    ok(
      "retention: invalid + enforcing + an UNREAD default rule states neither direction on retention, exactly",
      unread.check?.detail ===
        "A WORM policy is configured but INVALID (mode and retention days must both be set, with a positive window), so no S3 Object-Lock metadata is being written. The destination bucket enforces S3 Object-Lock, but whether it applies a default retention rule of its own could not be read, and that rule is the only thing that would retain an archive here, so this check states neither that archives are write-once-locked nor that they are not. The policy is invalid either way.",
    );
  }

  // The DOWNSTREAM consequence of the one newly-failing state, stated rather than implied. Immutability is
  // weight 2 of the healthy baseline's 49, so an estate whose DEST_WORM_* knobs are set half-way on an
  // Object-Lock bucket drops from 100 to 96 and gains an open item against ISO A.8.13. That is an estate
  // whose policy is genuinely broken, and the owner can risk-accept it exactly as they can any other
  // failing check, which is asserted here so the escape hatch is not left to inference.
  {
    const i = healthyInput();
    i.worm = { configured: true, misconfigured: true, bucketEnforces: true, defaultRetention: false };
    ok("retention: the newly-failing invalid-on-enforcing state costs the weighted score 4 points (100 -> 96)", computePosture(i, NOW).score === 96);
    i.overrides = new Map([...i.overrides, ["immutability", overrideFor("risk-accepted")]]);
    const accepted = computePosture(i, NOW);
    ok("retention: the newly-failing state can be risk-accepted", byId(accepted).get("immutability")?.status === "risk-accepted");
    ok("retention: a risk-accepted immutability check scores as met again", accepted.score === 100);
  }
}

// ---- score weighting ----------------------------------------------------------------------
function computeScoreWeighting(): void {
  {
    // Fail ONLY the destination-configured (critical, weight 5).
    // Total weight of the 18 healthy-baseline checks: critical (recency 5, seal-verification 5, dest 5)
    // = 15; high (access 3, admin-strong-auth 3, dispose-bootstrap-token 3, restore-enabled 3,
    // break-glass 3, credential-expiry 3, redundant-copies 3) = 21; medium (two-owners 2,
    // failure-alerts 2, op-private 2, media-diversity 2, immutability 2) = 10; low (audit 1, beacon 1,
    // encryption 1) = 3. Total = 49. Failing dest (5) earns 44/49 -> round(89.8) = 90.
    const i = healthyInput();
    i.status.destConfigured = false;
    const report = computePosture(i, NOW);
    ok("score: failing one critical (dest, w=5) of total 49 -> 90", report.score === 90);
  }
  {
    // Fail one low-weight check (beacon, weight 1): 48/49 -> round(98.0) = 98.
    const i = healthyInput();
    i.beaconEnabled = true;
    ok("score: failing one low (beacon, w=1) -> 98", computePosture(i, NOW).score === 98);
  }
  {
    // NOT-APPLICABLE excludes a check from BOTH sides of the score. Marking the failing beacon (w=1)
    // not-applicable removes it from the 49: 48/48 = 100, not 48/49.
    const i = healthyInput();
    i.beaconEnabled = true;
    i.overrides = new Map([...i.overrides, ["beacon-off", overrideFor("not-applicable", "vendor beacon is mandated by our MSP agreement")]]);
    const report = computePosture(i, NOW);
    ok("score: a not-applicable check is excluded from the denominator (100)", report.score === 100);
    ok("score: the excluded check reads not-applicable", byId(report).get("beacon-off")?.status === "not-applicable");
  }
  {
    // An UNATTESTED check (cannot-verify, no override) is score-negative like a fail: withdraw the
    // healthy media-diversity attestation -> 47/49 -> round(95.9) = 96.
    const i = healthyInput();
    i.overrides = new Map();
    ok("score: an unattested check does not earn its weight (96)", computePosture(i, NOW).score === 96);
  }
}

// ---- dispose-bootstrap-token (the break-glass disposal finding) ---------------------------
// The predicate: FAILS only when bootstrapConsumed AND the token is still EFFECTIVE (adminTokenPresent &&
// NOT(tokenFallbackDisabled || breakGlassTokenRetired)). It must NOT fire before the bootstrap is consumed
// (a fresh tenant legitimately needs the token), and must CLEAR the moment the token is retired OR
// env-disabled OR deleted. Severity is high.
function computeDisposeBootstrapToken(): void {
  const m0 = byId(computePosture(healthyInput(), NOW));
  ok("dispose: severity is high", m0.get("dispose-bootstrap-token")?.severity === "high");

  // FAIL: bootstrap consumed AND a live token (present, not disabled, not retired) = anyone with the string
  // can take admin.
  const live = healthyInput();
  live.status = { ...live.status, adminTokenPresent: true, bootstrapConsumed: true, tokenFallbackDisabled: false, breakGlassTokenRetired: false };
  ok("dispose: FAILS when bootstrap consumed and the token is still live", byId(computePosture(live, NOW)).get("dispose-bootstrap-token")?.status === "fail");

  // PASS (pre-bootstrap): a live token but the bootstrap NOT yet consumed (a fresh tenant claiming the
  // first Owner) does not fire the finding.
  const preBootstrap = healthyInput();
  preBootstrap.status = { ...preBootstrap.status, adminTokenPresent: true, bootstrapConsumed: false, tokenFallbackDisabled: false, breakGlassTokenRetired: false };
  ok("dispose: PASSES before the bootstrap is consumed (token legitimately needed)", byId(computePosture(preBootstrap, NOW)).get("dispose-bootstrap-token")?.status === "pass");

  // CLEARS when RETIRED in-app: consumed + present but retired.
  const retired = healthyInput();
  retired.status = { ...retired.status, adminTokenPresent: true, bootstrapConsumed: true, tokenFallbackDisabled: false, breakGlassTokenRetired: true };
  ok("dispose: CLEARS when the token is retired in-app", byId(computePosture(retired, NOW)).get("dispose-bootstrap-token")?.status === "pass");

  // CLEARS when ENV-DISABLED: consumed + present but ADMIN_TOKEN_DISABLED.
  const disabled = healthyInput();
  disabled.status = { ...disabled.status, adminTokenPresent: true, bootstrapConsumed: true, tokenFallbackDisabled: true, breakGlassTokenRetired: false };
  ok("dispose: CLEARS when the token fallback is env-disabled", byId(computePosture(disabled, NOW)).get("dispose-bootstrap-token")?.status === "pass");

  // CLEARS when the SECRET IS DELETED (no token present): consumed but no adminTokenPresent.
  const deleted = healthyInput();
  deleted.status = { ...deleted.status, adminTokenPresent: false, bootstrapConsumed: true, tokenFallbackDisabled: false, breakGlassTokenRetired: false };
  ok("dispose: CLEARS when the secret is deleted (no token present)", byId(computePosture(deleted, NOW)).get("dispose-bootstrap-token")?.status === "pass");

  // The failing finding's remediation names the retire control and the secret delete (the operator's two
  // disposal routes), and the detail says the token is still live.
  const failed = byId(computePosture(live, NOW)).get("dispose-bootstrap-token");
  ok("dispose: remediation names the in-app retire control", failed !== undefined && /Retire break-glass token/.test(failed.remediation));
  ok("dispose: remediation names the secret delete", failed !== undefined && /wrangler secret delete ADMIN_TOKEN/.test(failed.remediation));
  ok("dispose: the failing detail warns the token is still live", failed !== undefined && /still live/.test(failed.detail));

  // BREAK-GLASS-IN-PLACE GATE: a live token with the bootstrap consumed but NO ongoing admin break-glass
  // (recoveryBreakGlassReady false) does NOT prompt disposal (that would strand the tenant); it PASSES the
  // finding (no "dispose now") and the detail nudges the operator to set up recovery first. The finding
  // only FAILS (prompt disposal) once break-glass is ready, matching the retire endpoint's own gate.
  const liveNotReady = healthyInput();
  liveNotReady.status = { ...liveNotReady.status, adminTokenPresent: true, bootstrapConsumed: true, tokenFallbackDisabled: false, breakGlassTokenRetired: false, recoveryBreakGlassReady: false };
  const notReady = byId(computePosture(liveNotReady, NOW)).get("dispose-bootstrap-token");
  ok("dispose: does NOT prompt disposal when no break-glass is in place (would strand the tenant)", notReady?.status === "pass");
  ok("dispose: the not-ready detail nudges setting up recovery first", notReady !== undefined && /BEFORE disposing/.test(notReady.detail));
}

// ---- recovery-codes-low (the recovery-code break-glass low warning) -----------------------
// The finding appears ONLY when the caller's own count is supplied (recoveryCodesRemaining defined); it
// FAILS at <= 2 remaining (including 0) and passes above that. It is medium severity. A caller with no
// per-email count (the bare-token break-glass) does not raise it (the field is absent).
function computeRecoveryCodesLow(): void {
  // Absent count (e.g. the token break-glass): the finding is NOT present at all.
  const noCount = healthyInput();
  ok("recovery-low: absent when no per-email count is supplied", byId(computePosture(noCount, NOW)).get("recovery-codes-low") === undefined);

  // Plenty of codes (8 remaining): present and PASSES.
  const plenty = healthyInput();
  plenty.recoveryCodesRemaining = 8;
  const plentyCheck = byId(computePosture(plenty, NOW)).get("recovery-codes-low");
  ok("recovery-low: present and passes with plenty of codes", plentyCheck?.status === "pass");
  ok("recovery-low: severity is medium", plentyCheck?.severity === "medium");

  // Low (2 remaining): FAILS and prompts a regenerate.
  const low = healthyInput();
  low.recoveryCodesRemaining = 2;
  const lowCheck = byId(computePosture(low, NOW)).get("recovery-codes-low");
  ok("recovery-low: FAILS at the low threshold (<= 2)", lowCheck?.status === "fail");
  ok("recovery-low: the failing remediation prompts a regenerate", lowCheck !== undefined && /Regenerate your recovery codes/.test(lowCheck.remediation));

  // Exhausted (0 remaining): FAILS.
  const zero = healthyInput();
  zero.recoveryCodesRemaining = 0;
  ok("recovery-low: FAILS when exhausted (0 remaining)", byId(computePosture(zero, NOW)).get("recovery-codes-low")?.status === "fail");
}

// ---- risk-accept fold ---------------------------------------------------------------------
function computeRiskAcceptFold(): void {
  // Fail dest, but risk-accept it: it reads risk-accepted and counts toward the score (back to 100).
  const i = healthyInput();
  i.status.destConfigured = false;
  i.overrides = new Map([...i.overrides, ["destination-configured", overrideFor("risk-accepted", "compensating replication in place; fix scheduled")]]);
  const report = computePosture(i, NOW);
  const m = byId(report);
  ok("accept: a failing accepted check reads risk-accepted", m.get("destination-configured")?.status === "risk-accepted");
  ok("accept: a risk-accepted check counts toward the score (100)", report.score === 100);
  ok("accept: the accepted check keeps its automatic outcome (autoStatus fail)", m.get("destination-configured")?.autoStatus === "fail");
  // Overriding a check that is PASSING does not change it (stays pass; the override is carried dormant so
  // the console can state it and offer a withdraw).
  const j = healthyInput();
  j.overrides = new Map([...j.overrides, ["destination-configured", overrideFor("risk-accepted")]]);
  const dormant = byId(computePosture(j, NOW)).get("destination-configured");
  ok("accept: accepting a passing check leaves it pass", dormant?.status === "pass");
  ok("accept: the dormant override is still carried on the passing check", dormant?.override?.kind === "risk-accepted");
}

// ---- override kinds: attested-pass / compensating-control / not-applicable -----------------
function computeOverrideKinds(): void {
  {
    // attested-pass on a FAILING check reads attested-pass (score-positive, reason carried).
    const i = healthyInput();
    i.notifyFailureRuleSet = false;
    i.overrides = new Map([...i.overrides, ["failure-alerts", overrideFor("attested-pass", "paging is wired through our external SIEM watching the audit export")]]);
    const report = computePosture(i, NOW);
    const c = byId(report).get("failure-alerts");
    ok("kinds: attested-pass on a failing check reads attested-pass", c?.status === "attested-pass");
    ok("kinds: the attested reason rides on the check", c?.override?.reason.includes("SIEM") === true);
    ok("kinds: attested-pass is score-positive (100)", report.score === 100);
  }
  {
    // compensating-control on a FAILING check reads compensating-control (score-positive).
    const i = healthyInput();
    i.status.breakGlassConfigured = false;
    i.overrides = new Map([...i.overrides, ["break-glass-present", overrideFor("compensating-control", "offline recovery is covered by our escrowed provider keys and quarterly DR runbook")]]);
    const report = computePosture(i, NOW);
    const c = byId(report).get("break-glass-present");
    ok("kinds: compensating-control on a failing check reads compensating-control", c?.status === "compensating-control");
    ok("kinds: compensating-control is score-positive (100)", report.score === 100);
  }
  {
    // not-applicable PINS regardless of the automatic outcome: on a PASSING check it still reads N/A
    // (the owner's scoping decision holds), and the check is out of the score.
    const i = healthyInput();
    i.overrides = new Map([...i.overrides, ["two-owners", overrideFor("not-applicable", "sole-trader deployment; a second owner does not exist")]]);
    const report = computePosture(i, NOW);
    ok("kinds: not-applicable pins even when the auto outcome passes", byId(report).get("two-owners")?.status === "not-applicable");
    ok("kinds: score stays 100 with an N/A (excluded, not counted)", report.score === 100);
  }
  {
    // The override kind guard: known kinds pass, unknown/legacy values are rejected.
    ok("kinds: isOverrideKind accepts the four kinds", ["risk-accepted", "attested-pass", "compensating-control", "not-applicable"].every((k) => isOverrideKind(k)));
    ok("kinds: isOverrideKind rejects an unknown kind", !isOverrideKind("waived") && !isOverrideKind(7));
  }
}

// ---- sort order ---------------------------------------------------------------------------
function computeSortOrder(): void {
  // Fail a critical (dest) and a low (beacon): the critical fail sorts before the low; passing criticals
  // sort before failing-lower-severity is NOT the rule (severity dominates), so the first check is a
  // critical (failing or passing), and within criticals the failing one comes first.
  const i = healthyInput();
  i.status.destConfigured = false;
  i.beaconEnabled = true;
  const report = computePosture(i, NOW);
  ok("sort: most-severe-first (first check is critical)", report.checks[0]?.severity === "critical");
  // Within the criticals, the failing destination-configured sorts before the passing restore-test-recency.
  const criticals = report.checks.filter((c) => c.severity === "critical");
  ok("sort: failing critical before passing critical", criticals[0]?.id === "destination-configured");
  // The low-severity beacon fail is near the end (lows sort last).
  ok("sort: low-severity checks sort last", report.checks[report.checks.length - 1]?.severity === "low");
}

// ---- snapshot + regression detection ------------------------------------------------------
function computeSnapshotRegression(): void {
  const healthy = computePosture(healthyInput(), NOW);
  const snap = snapshotOf(healthy);
  ok("snapshot: one entry per check", snap.checks.length === healthy.checks.length);
  ok("snapshot: a passing check is recorded passed:true", snap.checks.find((c) => c.id === "destination-configured")?.passed === true);

  // Now dest fails: detectRegressions against the healthy snapshot flags destination-configured.
  const i = healthyInput();
  i.status.destConfigured = false;
  const degraded = computePosture(i, NOW);
  const regs = detectRegressions(degraded, snap);
  ok("regression: a previously-passing check that now fails is a regression", regs.some((r) => r.id === "destination-configured"));
  ok("regression: the regression carries the check severity (critical)", regs.find((r) => r.id === "destination-configured")?.severity === "critical");
  // Only the one that changed is reported (nothing else regressed).
  ok("regression: only the changed check is reported", regs.length === 1);

  // A check that RECOVERS (was failing, now passes) is NOT a regression.
  const recovered = detectRegressions(healthy, snapshotOf(degraded));
  ok("regression: a recovered check is not a regression", recovered.length === 0);

  // A risk-accepted check is score-positive, so it is NOT a regression even though it was failing.
  const accepted = healthyInput();
  accepted.status.destConfigured = false;
  accepted.overrides = new Map([...accepted.overrides, ["destination-configured", overrideFor("risk-accepted")]]);
  const acceptedReport = computePosture(accepted, NOW);
  ok("regression: a risk-accepted check is not a regression", detectRegressions(acceptedReport, snap).length === 0);

  // A NOT-APPLICABLE check is an owner decision, never a regression (even against a passing snapshot).
  const na = healthyInput();
  na.overrides = new Map([...na.overrides, ["two-owners", overrideFor("not-applicable")]]);
  ok("regression: a not-applicable check is not a regression", detectRegressions(computePosture(na, NOW), snap).length === 0);

  // A previously-ATTESTED check whose attestation is withdrawn moves to unattested = needs attention,
  // and that IS a regression (the owner is told the posture dropped).
  const withdrawn = healthyInput();
  withdrawn.overrides = new Map();
  const withdrawnRegs = detectRegressions(computePosture(withdrawn, NOW), snap);
  ok("regression: a withdrawn attestation (now unattested) IS a regression", withdrawnRegs.some((r) => r.id === "media-diversity"));

  // No prior snapshot (first run) is never a regression.
  ok("regression: null prior snapshot yields no regressions", detectRegressions(degraded, null).length === 0);
}

// ---- dest-cred-encryption (at-rest encryption of console-set destination credentials) -----
function computeDestCredEncryption(): void {
  // Every caller below passes a concrete slice (the absent-slice case is tested separately with
  // healthyInput() directly), so the param is the non-nullable slice: spreading a possibly-undefined value
  // into the optional destCredEncryption field would trip exactOptionalPropertyTypes.
  const check = (e: NonNullable<PostureInput["destCredEncryption"]>) =>
    byId(computePosture({ ...healthyInput(), destCredEncryption: e }, NOW)).get("dest-cred-encryption");
  ok("dest-cred-encryption: an absent slice raises no check", byId(computePosture(healthyInput(), NOW)).get("dest-cred-encryption") === undefined);
  ok("dest-cred-encryption: no key with a plaintext destination FAILS (warn)", check({ wrapKeyConfigured: false, plaintextCount: 1, total: 1 })?.status === "fail");
  ok("dest-cred-encryption: nothing to protect (no key, no destinations) raises no check", check({ wrapKeyConfigured: false, plaintextCount: 0, total: 0 }) === undefined);
  ok("dest-cred-encryption: key set and all wrapped PASSES", check({ wrapKeyConfigured: true, plaintextCount: 0, total: 2 })?.status === "pass");
  ok("dest-cred-encryption: key set but a plaintext record remains FAILS (warn)", check({ wrapKeyConfigured: true, plaintextCount: 1, total: 2 })?.status === "fail");
  ok("dest-cred-encryption: key set, no destinations yet PASSES", check({ wrapKeyConfigured: true, plaintextCount: 0, total: 0 })?.status === "pass");
}

// ---- isKnownCheckId / CHECK_SEVERITY ------------------------------------------------------
// ---- update-apply-provenance + update-version-drift (DP-0/DP-D) ---------------------------
// Both checks are NOT APPLICABLE until a channel apply has settled (a wrangler-only install is never
// nagged for a control it could not exercise); evidence gaps read as unattested, never a red fail; a
// genuine out-of-band redeploy is the one red failure (the operator can fix or deliberately accept it).
function computeUpdateIntegrityChecks(): void {
  {
    const i = healthyInput();
    const m = byId(computePosture(i, NOW));
    ok("upd: both checks absent with no updateIntegrity slice (older caller)", !m.has("update-apply-provenance") && !m.has("update-version-drift"));
  }
  {
    const i = healthyInput();
    i.updateIntegrity = { lastEngineOutcome: "applied", expectedLiveVersionId: "v-live", liveVersionId: "v-live", lastAppliedDigestPresent: true, readbackVerdict: "verified" };
    const m = byId(computePosture(i, NOW));
    ok("upd: an evidenced apply passes update-apply-provenance", m.get("update-apply-provenance")?.status === "pass");
    ok("upd: the provenance detail names the read-back verdict", /read-back verified/.test(m.get("update-apply-provenance")?.detail ?? ""));
    ok("upd: a matching version id passes update-version-drift", m.get("update-version-drift")?.status === "pass");
  }
  {
    const i = healthyInput();
    i.updateIntegrity = { lastEngineOutcome: "applied", expectedLiveVersionId: "v-live", liveVersionId: "v-other", lastAppliedDigestPresent: true };
    const c = byId(computePosture(i, NOW)).get("update-version-drift");
    ok("upd: an out-of-band redeploy FAILS update-version-drift", c?.status === "fail");
    ok("upd: the drift failure says the deploy happened outside the update flow", /outside the update flow/.test(c?.detail ?? ""));
  }
  {
    const i = healthyInput();
    i.updateIntegrity = { lastEngineOutcome: "applied", expectedLiveVersionId: "v-live", lastAppliedDigestPresent: false };
    const m = byId(computePosture(i, NOW));
    ok("upd: a digest-less legacy apply reads unattested, never a red fail", m.get("update-apply-provenance")?.status === "unattested");
    ok("upd: an absent version_metadata binding reads unattested for drift", m.get("update-version-drift")?.status === "unattested");
  }
  {
    const i = healthyInput();
    i.updateIntegrity = { lastEngineOutcome: "rolled-back", expectedLiveVersionId: "v-good", liveVersionId: "v-good", lastAppliedDigestPresent: false };
    ok("upd: a rollback's reverted-to id is the drift expectation (pass on match)", byId(computePosture(i, NOW)).get("update-version-drift")?.status === "pass");
  }
  {
    // A ramp-settled split: version_metadata may report EITHER slice; both pass, named as a split.
    const i = healthyInput();
    i.updateIntegrity = { lastEngineOutcome: "applied", expectedLiveVersionId: "v-ramped", alternateLiveVersionIds: ["v-prior"], liveVersionId: "v-prior", lastAppliedDigestPresent: true };
    const c = byId(computePosture(i, NOW)).get("update-version-drift");
    ok("upd: a still-partial ramp's prior slice passes drift (no flap)", c?.status === "pass");
    ok("upd: the alternate-slice pass says it is a split, not a drift", /ramp still serving its split|awaiting verification/.test(c?.detail ?? ""));
  }
  {
    // The promote->settle window: the promoted-but-unsettled version is legitimately live.
    const i = healthyInput();
    i.updateIntegrity = { lastEngineOutcome: "applied", expectedLiveVersionId: "v-old-applied", alternateLiveVersionIds: ["v-promoted-pending", "v-old-applied"], liveVersionId: "v-promoted-pending", lastAppliedDigestPresent: true };
    ok("upd: a promoted-but-unsettled pending passes drift (in-flight, not out-of-band)", byId(computePosture(i, NOW)).get("update-version-drift")?.status === "pass");
  }
  {
    // A genuinely foreign id still fails even with alternates present.
    const i = healthyInput();
    i.updateIntegrity = { lastEngineOutcome: "applied", expectedLiveVersionId: "v-ramped", alternateLiveVersionIds: ["v-prior"], liveVersionId: "v-foreign", lastAppliedDigestPresent: true };
    ok("upd: a foreign id fails drift even while a split is live", byId(computePosture(i, NOW)).get("update-version-drift")?.status === "fail");
  }
  {
    const i = healthyInput();
    i.updateIntegrity = { lastEngineOutcome: "superseded", lastAppliedDigestPresent: false };
    const m = byId(computePosture(i, NOW));
    ok("upd: no expectation (superseded) -> drift not raised", !m.has("update-version-drift"));
    ok("upd: an outcome without a digest still surfaces provenance as unattested", m.get("update-apply-provenance")?.status === "unattested");
  }
}

function computeKnownCheckIds(): void {
  ok("known: a real check id is known", isKnownCheckId("restore-test-recency"));
  ok("known: dispose-bootstrap-token is a known check id", isKnownCheckId("dispose-bootstrap-token"));
  ok("known: recovery-codes-low is a known check id", isKnownCheckId("recovery-codes-low"));
  ok("known: dest-cred-encryption is a known check id", isKnownCheckId("dest-cred-encryption"));
  ok("known: admin-strong-auth is a known check id", isKnownCheckId("admin-strong-auth"));
  ok("known: environment-self-backup is a known check id", isKnownCheckId("environment-self-backup"));
  ok("known: an unknown id is rejected", !isKnownCheckId("not-a-check"));
  ok("known: a non-string is rejected", !isKnownCheckId(42));
  ok("known: update-apply-provenance is a known check id", isKnownCheckId("update-apply-provenance"));
  ok("known: update-version-drift is a known check id", isKnownCheckId("update-version-drift"));
  // 26 = the 22 checks main carried (incl. environment-self-backup), the two provenance checks
  // (update-apply-provenance + update-version-drift), attended-verification-cadence, and
  // recipient-set-expected.
  //
  // This pin exists so a new check id must be a deliberate edit here rather than something that appears in
  // a customer's compliance report because a builder was added. Confirmed by listing the ids, not by taking
  // the new total on trust.
  //
  // The count pin alone is a trip-wire only for someone EDITING CHECK_SEVERITY's size, not for someone
  // adding a check that never touches it at all (a check pushed by computePosture with no CHECK_SEVERITY
  // entry leaves this count unchanged and the line keeps passing). computeSeverityMapDriftGate below closes
  // that gap: it derives the check ids computePosture can actually PRODUCE, from the source, independent of
  // CHECK_SEVERITY, and fails if any of them lack an entry.
  ok("known: CHECK_SEVERITY has all twenty-six", Object.keys(CHECK_SEVERITY).length === 26);
  ok("known: attended-verification-cadence is a known check id", isKnownCheckId("attended-verification-cadence"));
  ok("known: recipient-set-expected is a known check id", isKnownCheckId("recipient-set-expected"));
}

// ---- structural drift gate: every check computePosture can PRODUCE has a CHECK_SEVERITY entry ------------
// A check computePosture (posture.ts) `push`es a
// CheckDraft for each builder it calls, and stamps its severity from CHECK_SEVERITY[draft.id] ?? "low" (a
// SILENT fallback -- no throw, no log). A check added to the push() list without a matching CHECK_SEVERITY
// entry therefore scores at the WRONG (lowest) weight, and isKnownCheckId (which checks membership in the
// same map) refuses acceptPostureRisk for it, so an owner cannot attest, accept or override a check they
// cannot even see rated correctly. The two structures (the push() list and CHECK_SEVERITY) had NOTHING
// cross-checking them against each other before this: computeKnownCheckIds' pin above only counts
// CHECK_SEVERITY's own size, and validate-posture-and-docs-parity.ts derives its "graded" set FROM CHECK_SEVERITY
// (treating it as ground truth), so neither could ever notice a check MISSING from it.
//
// This reads posture.ts + posture-checks.ts DIRECTLY (the same read-the-source technique validate-session.ts
// uses for the router's step-up coverage) and derives the real set of ids computePosture can push, independent
// of CHECK_SEVERITY, then asserts every one of them has an entry. THE FOUR QUESTIONS: it runs in `npm run
// validate` (validate-posture.ts -> runCompute() -> this); it FAILS if the two source files cannot be read
// (readFileSync throws, propagating to validate-posture.ts's uncaught-rejection exit(1)); it FAILS rather than
// vacuously passing if the parse finds nothing (the ids.size > 20 sanity assertion below); and it covers the
// WHOLE corpus (every push() call in computePosture, not a sampled subset).
const POSTURE_ADMIN_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "admin");

// resolveIdLiteral finds the check id a builder's body commits to, in whichever of the three shapes this
// codebase actually uses (confirmed by reading all 26): a direct literal (`id: "access-enforced"`), a local
// shorthand variable (`const id = "admin-strong-auth";` ... `id,`), or a module-level exported constant
// (`id: EMERGENCY_CHANGE_CHECK_ID`, resolved against `export const EMERGENCY_CHANGE_CHECK_ID = "...";`
// elsewhere in the combined source). Returns every id literal the body's own scope resolves to (a builder
// with multiple return branches restating `id: "..."` yields one id, repeated; that is fine, Set dedupes it).
function resolveIdLiteral(body: string, combined: string): string[] {
  const out: string[] = [];
  for (const m of body.matchAll(/id:\s*"([a-z0-9-]+)"/g)) out.push(m[1]!);
  const localIdVar = body.match(/const id = "([a-z0-9-]+)"/);
  if (localIdVar) out.push(localIdVar[1]!);
  for (const m of body.matchAll(/id:\s*([A-Z][A-Z0-9_]*)\b/g)) {
    const constName = m[1]!;
    const constDef = combined.match(new RegExp(`const ${constName}\\s*=\\s*"([a-z0-9-]+)"`));
    if (constDef) out.push(constDef[1]!);
  }
  return out;
}

// postureCheckIdsFromSource derives (id -> producing builder names) for every check computePosture can PUSH,
// by parsing posture.ts's push() call list and each named builder's body in posture.ts or posture-checks.ts.
function postureCheckIdsFromSource(): { ids: Set<string>; unresolved: string[] } {
  const postureSrc = readFileSync(join(POSTURE_ADMIN_DIR, "posture.ts"), "utf8");
  // EVERY posture-checks* MODULE, DISCOVERED, not two filenames named by hand: a builder can move between
  // posture.ts and any posture-checks-*.ts split without this gate losing track of it, while a builder that
  // moves out of the family ENTIRELY still reds.
  const checksSrcs = readdirSync(POSTURE_ADMIN_DIR)
    .filter((f) => /^posture-checks.*\.ts$/.test(f))
    .sort()
    .map((f) => readFileSync(join(POSTURE_ADMIN_DIR, f), "utf8"));
  const combined = [postureSrc, ...checksSrcs].join("\n");
  const pushed = [...postureSrc.matchAll(/push\((build\w+)\(/g)].map((m) => m[1]!);
  const ids = new Set<string>();
  const unresolved: string[] = [];
  for (const fn of pushed) {
    const start = combined.indexOf(`function ${fn}(`);
    if (start === -1) {
      unresolved.push(`${fn} (no function definition found)`);
      continue;
    }
    const nextFn = combined.indexOf("\nexport function ", start + 1);
    const body = nextFn === -1 ? combined.slice(start) : combined.slice(start, nextFn);
    const found = resolveIdLiteral(body, combined);
    if (found.length === 0) {
      unresolved.push(`${fn} (no id literal resolved)`);
      continue;
    }
    for (const id of found) ids.add(id);
  }
  return { ids, unresolved };
}

function computeSeverityMapDriftGate(): void {
  const pushCount = [...readFileSync(join(POSTURE_ADMIN_DIR, "posture.ts"), "utf8").matchAll(/push\(build\w+\(/g)].length;
  ok(`structural: computePosture's push() call list was parsed from source (${pushCount} calls found)`, pushCount > 20);
  const { ids, unresolved } = postureCheckIdsFromSource();
  // Every pushed builder must resolve to a known id shape: an unresolved builder is exactly the blind spot
  // that would let a NEW check evade this gate entirely (parsed as producing zero ids, never checked against
  // CHECK_SEVERITY at all), so it fails loudly here rather than silently shrinking the ids set.
  ok(`structural: every pushed builder's check id was resolved (${unresolved.length} unresolved)`, unresolved.length === 0);
  if (unresolved.length > 0) console.log(`       unresolved: ${unresolved.join(", ")}`);
  ok(`structural: the resolved id set is non-trivial (${ids.size} distinct ids found)`, ids.size > 20);
  const ungraded = [...ids].filter((id) => !Object.hasOwn(CHECK_SEVERITY, id));
  ok("structural: every check computePosture can push has a CHECK_SEVERITY entry", ungraded.length === 0);
  if (ungraded.length > 0) console.log(`       ungraded: ${ungraded.join(", ")}`);
  // The reverse direction is reported, not failed: a CHECK_SEVERITY entry with no producing check is inert
  // (isKnownCheckId would accept a checkId nothing ever computes), not a hidden severity, so it is not the
  // same class of danger and does not fail the gate.
  const orphaned = Object.keys(CHECK_SEVERITY).filter((id) => !ids.has(id));
  if (orphaned.length > 0) console.log(`       CHECK_SEVERITY entries with no parsed producer (informational, not a failure): ${orphaned.join(", ")}`);
}

// ---- restore-test-recency: the durable KEYED credit (compliance-stamp) --------------------
// A full attended-verification proof (restoreProven.method === "attended-blind-test") credits the check
// across a scheduled-test DEFERRAL (the break-glass-only flip-flop this feature exists to fix), but NEVER
// over a GENUINE fresh restore-test failure, never via a blind-test/keyless-attest proof, and never once
// the proof itself is stale (outside the critical window).
function computeRestoreTestRecencyKeyedCredit(): void {
  const baseDp = { id: "dp1", name: "Primary", lastRunId: "run-dp1" };
  {
    // THE FIX'S REASON TO EXIST: a break-glass-only estate's scheduled cron DEFERS every cadence tick
    // (posture, no OPERATIONAL_PRIVATE), which clobbers lastRestoreTestOk to false. A fresh, FULL attended
    // proof survives that deferral and credits the check, naming the method in the detail.
    const i = healthyInput();
    i.downpipes = [{ ...baseDp, lastRestoreTestAt: NOW - 1 * DAY, lastRestoreTestOk: false, lastRestoreTestDeferred: "posture", restoreProvenAt: NOW - 5 * DAY, restoreProvenMethod: "attended-blind-test" }];
    const check = byId(computePosture(i, NOW)).get("restore-test-recency");
    ok("keyed credit: a break-glass deferral is rescued by a fresh attended proof (PASS)", check?.status === "pass");
    ok("keyed credit: the detail names the attended-verification method", (check?.detail ?? "").includes("attended verification"));
    ok("keyed credit: the how line documents the credit rule", (check?.how ?? "").includes("attended-verification proof credits"));
  }
  {
    // An ABSENT recency (never a completed test at all, not merely a deferral) also falls back to a fresh
    // attended proof: "no ordinary recency to grade" is itself safe to credit.
    const i = healthyInput();
    i.downpipes = [{ ...baseDp, restoreProvenAt: NOW - 5 * DAY, restoreProvenMethod: "attended-blind-test" }];
    ok("keyed credit: a never-completed recency also falls back to a fresh attended proof (PASS)", byId(computePosture(i, NOW)).get("restore-test-recency")?.status === "pass");
  }
  {
    // A GENUINE fresh restore-test failure (the deferred flag absent on a not-ok completion) recorded AFTER
    // an older attended proof must NOT be masked by that stale proof. A naive maxDefined(recency, proof)
    // credit would wrongly PASS this; the correct design must FAIL it.
    const i = healthyInput();
    i.downpipes = [{ ...baseDp, lastRestoreTestAt: NOW - 1 * DAY, lastRestoreTestOk: false, restoreProvenAt: NOW - 30 * DAY, restoreProvenMethod: "attended-blind-test" }];
    const check = byId(computePosture(i, NOW)).get("restore-test-recency");
    ok("a genuine fresh failure after an attended proof still FAILS (never masked)", check?.status === "fail");
    ok("the offender is named (the genuine failure is not hidden)", (check?.detail ?? "").includes("Primary"));
  }
  {
    // A blind-test proof carries no sample rate or scope, so it must NEVER credit the check (only the full,
    // unambiguous attended-blind-test method does).
    const i = healthyInput();
    i.downpipes = [{ ...baseDp, restoreProvenAt: NOW - 5 * DAY, restoreProvenMethod: "blind-test" }];
    ok("a blind-test proof does not credit the recency check (still FAILS)", byId(computePosture(i, NOW)).get("restore-test-recency")?.status === "fail");
  }
  {
    // A keyless-attest proof (signature + completeness + anti-rollback, no decryption) never credits
    // either: it does not satisfy a check whose meaning is "a real decrypt-and-verify happened recently".
    const i = healthyInput();
    i.downpipes = [{ ...baseDp, restoreProvenAt: NOW - 5 * DAY, restoreProvenMethod: "keyless-attest" }];
    ok("keyless-attest does not credit the recency check (still FAILS)", byId(computePosture(i, NOW)).get("restore-test-recency")?.status === "fail");
  }
  {
    // A STALE attended proof (older than the 180-day critical window) does not coast forever: the owner
    // must re-verify on cadence, exactly as an ordinary scheduled pass ages out.
    const i = healthyInput();
    i.downpipes = [{ ...baseDp, lastRestoreTestDeferred: "posture", lastRestoreTestOk: false, lastRestoreTestAt: NOW - 200 * DAY, restoreProvenAt: NOW - 200 * DAY, restoreProvenMethod: "attended-blind-test" }];
    ok("a stale attended proof (past the critical window) is still an offender", byId(computePosture(i, NOW)).get("restore-test-recency")?.status === "fail");
  }
  {
    // The ordinary lastRestoreTestOk path is UNCHANGED (not tightened): a plain scheduled pass still passes
    // with no restoreProven at all, exactly as before this credit existed.
    const i = healthyInput();
    i.downpipes = [{ ...baseDp, lastRestoreTestAt: NOW - 1 * DAY, lastRestoreTestOk: true }];
    ok("ordinary scheduled pass still passes with no restoreProven at all (not tightened)", byId(computePosture(i, NOW)).get("restore-test-recency")?.status === "pass");
  }
}
