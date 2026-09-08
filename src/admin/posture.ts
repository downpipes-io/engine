// Security centre / posture (contract section 7). A PURE computePosture over the account's
// observable state produces a severity-ranked set of named-control checks and a weighted score, so
// the console can show a CISO/auditor an honest posture and a remediation per finding. The function
// does NO I/O: the DO gathers the inputs (status presence, downpipes + restore-test recency, expiry
// statuses, notify channels/rules, the owner count, the identity slice, whether operational-private is
// present, and the per-check owner-override records) and the route returns the report. The DO also owns
// the override storage and the regression snapshot; those storage SHAPES live here so the DO and
// any reader agree on one definition. Every check carries its AUTOMATIC outcome (pass / fail /
// cannot-verify) alongside the EFFECTIVE status after the owner-override fold, plus a plain-language
// "how this is determined" line, so the console and the signed reports can state, per control, what was
// observed, how, and why the customer graded it (attested pass, compensating control, N/A, accepted
// risk) when the platform could not verify it.
//
// NO-CUSTODY + REDACTION (sacred). Every check carries ONLY redaction-safe metadata: a stable id, a
// title, a severity, a status, the named control, an observed-detail one-liner and a remediation. The
// detail is computed from counts/booleans/recency the inputs already carry (a downpipe NAME may appear
// in a detail, which is the customer's own redaction-safe config, never a secret); no check can carry a
// key, value, fingerprint or selector. The inputs themselves are presence/count projections, never raw
// secrets.
//
// PRECISE CLAIMS (house style). The encryption check states "post-quantum hybrid" and "tamper-evident";
// it never says quantum-proof or tamper-proof. The immutability/WORM posture is surfaced honestly: an
// attestation of the recoverability properties actually in force, not a false WORM claim.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations.
// exactOptionalPropertyTypes: optional keys are spread in only when they carry a value.

// The per-check builders live in posture-checks.ts (file-size hygiene, finding engine-src-011-01); each
// is a pure projection of PostureInput into one finding's redaction-safe content (a CheckDraft), and
// computePosture stamps the severity + folds the risk-accept set here so the ordering and score logic
// stay in one place.
import {
  buildAccessEnforced,
  buildAdminStrongAuth,
  buildAuditExportAvailable,
  buildBeaconOff,
  buildBreakGlassPresent,
  buildCredentialExpiry,
  buildDestCredEncryption,
  buildDestinationConfigured,
  buildDisposeBootstrapToken,
  buildEmergencyChangeReview,
  buildEncryptionPqHybrid,
  buildEnvironmentSelfBackup,
  buildFailureAlerts,
  buildImmutability,
  buildMediaDiversity,
  buildOperationalPrivateWeakening,
  buildRecipientSetExpected,
  buildRecoveryCodesLow,
  buildRedundantCopies,
  buildRestoreTestEnabled,
  buildRestoreTestRecency,
  buildSealVerification,
  buildTwoOwners,
  buildUpdateApplyProvenance,
  buildUpdateVersionDrift,
  buildAttendedCadence,
  type CheckAuto,
  type CheckDraft,
} from "./posture-checks.ts";
// PostureInput is used locally by computePosture; it is defined in posture-types.ts (and re-exported
// below so importers keep importing it from "./posture.ts").
import type { PostureInput, PostureOverrideInput, PostureOverrideKind } from "./posture-types.ts";

// PostureSeverity ranks a finding's importance and weights the score (critical 5, high 3, medium 2,
// low 1). PostureStatus is the finding's EFFECTIVE outcome after the owner-override fold:
//   pass                 : the platform observed the control satisfied.
//   fail                 : the platform observed it not satisfied and no override is recorded.
//   unattested           : the platform CANNOT observe this control (auto = cannot-verify) and no
//                          attestation is recorded yet. Score-negative like fail, but presented as
//                          "needs attestation", never as a red failure the operator cannot clear.
//   risk-accepted        : failing, and an Owner deliberately accepted the risk (counts as pass for the
//                          score, listed distinctly as an accepted risk, never presented as a pass).
//   attested-pass        : an Owner attested the control IS satisfied by means the platform cannot
//                          observe (with the reason recorded). Presented as "pass (customer attested)".
//   compensating-control : an Owner recorded a compensating control that satisfies the intent.
//                          Presented as "pass (compensating control)" with the description recorded.
//   not-applicable       : an Owner determined the control does not apply. Excluded from the score
//                          entirely and shown as N/A; it pins regardless of the automatic outcome.
//   resolved-alternative : reserved (the control met by an alternative means the platform can observe).
//                          Kept in the union so previously signed reports verify and render; the engine
//                          does not currently emit it.
export type PostureSeverity = "critical" | "high" | "medium" | "low";
export type PostureStatus =
  | "pass"
  | "fail"
  | "unattested"
  | "risk-accepted"
  | "attested-pass"
  | "compensating-control"
  | "not-applicable"
  | "resolved-alternative";

// PostureCheckOverride is the override as it appears ON a check in the report: the kind, the owner's
// reason, who set it and when. Projected from the stored record; redaction-safe.
export interface PostureCheckOverride {
  kind: PostureOverrideKind;
  reason: string;
  setBy: string | null;
  setAt: string; // RFC-3339
}

// PostureCheck is one finding (contract section 7 table). id is stable (the override key and the
// regression snapshot key both reference it); control is the named standard the check maps to; detail
// is what was observed; remediation is how to fix it; how states how the determination is made (so an
// operator or auditor can understand the check without reading source); autoStatus is the AUTOMATIC
// outcome before any override fold ("cannot-verify" = the platform genuinely cannot observe this
// control); override is the owner-set override when one is recorded, INCLUDING when it is dormant (the
// automatic outcome now passes on its own), so the console can offer a withdraw. All fields are
// redaction-safe strings.
export interface PostureCheck {
  id: string; // stable id, e.g. "restore-test-recency"
  title: string;
  severity: PostureSeverity;
  status: PostureStatus;
  autoStatus: CheckAuto; // the automatic outcome before the override fold
  control: string; // the named standard, e.g. "CIS 11.5", "Essential Eight ML2"
  detail: string; // what was observed
  remediation: string; // how to fix
  how: string; // how the determination is made (one sentence, plain language)
  override?: PostureCheckOverride;
}

// PostureReport is the GET /admin/posture body and the posture report kind (section 6). score is the
// weighted pass fraction (0..100); checks are the severity-ranked findings. generatedAt is RFC-3339.
export interface PostureReport {
  score: number; // 0..100, weighted by severity over enabled checks
  generatedAt: string;
  checks: PostureCheck[];
}

// The input-shape types live in posture-types.ts (file-size hygiene + cycle break, finding
// engine-src-011-01). Re-exported here so every importer keeps importing them from "./posture.ts".
export type {
  PostureDownpipeInput,
  PostureExpiryInput,
  PostureIdentityInput,
  PostureInput,
  PostureOverrideInput,
  PostureOverrideKind,
  PostureWormInput,
} from "./posture-types.ts";

// RiskAccept is the stored record for an owner-overridden check (DO key `posture-accept:${checkId}`; the
// key prefix and the field names predate the override kinds and are kept for storage compatibility). It
// carries the check id, the override KIND (absent on a legacy record = "risk-accepted"), the Owner's
// reason, who set it and when. acceptedBy is the verified Owner email, or null for the bare-token
// break-glass (no attributable email). Redaction-safe: no field can hold a secret.
export interface RiskAccept {
  checkId: string;
  kind?: PostureOverrideKind; // absent (a pre-override-kinds record) reads as "risk-accepted"
  reason: string;
  acceptedBy: string | null;
  acceptedAt: string; // RFC-3339
}

// POSTURE_OVERRIDE_KINDS is the closed set of override kinds; isOverrideKind is the runtime guard the DO
// route uses to reject an unknown kind (mirroring isKnownCheckId's discipline).
export const POSTURE_OVERRIDE_KINDS: readonly PostureOverrideKind[] = [
  "risk-accepted",
  "attested-pass",
  "compensating-control",
  "not-applicable",
] as const;
export function isOverrideKind(v: unknown): v is PostureOverrideKind {
  return typeof v === "string" && (POSTURE_OVERRIDE_KINDS as readonly string[]).includes(v);
}

// overrideOf projects a stored RiskAccept record to the PostureOverrideInput computePosture folds (and
// the PostureCheckOverride the report carries): the legacy-kind default lives HERE, in one place.
export function overrideOf(record: RiskAccept): PostureOverrideInput {
  return {
    kind: record.kind ?? "risk-accepted",
    reason: record.reason,
    setBy: record.acceptedBy,
    setAt: record.acceptedAt,
  };
}

// PostureSnapshotEntry / PostureSnapshot are the regression-detection state the DO persists under
// POSTURE_SNAPSHOT_KEY: the last computed outcome per check id. When a previously-good check moves into
// the needs-attention set (fail / unattested) on a later computation, the DO emits a posture-regression
// notification (severity from the check). Only the id + a passed boolean + the severity are stored; no
// detail, no remediation, no secret. "passed" here means NOT needing attention: pass, every override
// kind (including not-applicable) and resolved-alternative all record true, so an owner decision is
// never later reported as a regression; only a real move into fail/unattested is.
export interface PostureSnapshotEntry {
  id: string;
  passed: boolean; // true = not in the needs-attention set (see isNeedsAttention)
  severity: PostureSeverity;
}
export interface PostureSnapshot {
  at: string; // RFC-3339 of the snapshot
  checks: PostureSnapshotEntry[];
}

// POSTURE_ACCEPT_PREFIX keys one risk-accept record per check id (`posture-accept:<checkId>`), alongside
// the dp:/expiry:/notify-channel: keys in the scheduler DO. POSTURE_SNAPSHOT_KEY holds the single
// regression snapshot. Kept here (the posture domain) so the DO and any reader agree on the exact
// strings, mirroring EXPIRY_PREFIX / NOTIFY_CHANNEL_PREFIX.
export const POSTURE_ACCEPT_PREFIX = "posture-accept:";
export const POSTURE_SNAPSHOT_KEY = "posture-snapshot";

// SEVERITY_WEIGHT is the score weighting (contract section 7): critical 5, high 3, medium 2, low 1. A
// risk-accepted or resolved-alternative check counts toward the PASS numerator (it is an accepted or
// alternatively-met control), but is listed distinctly in the checks array.
const SEVERITY_WEIGHT: Record<PostureSeverity, number> = { critical: 5, high: 3, medium: 2, low: 1 };

// POSTURE_ID_PATTERN bounds a risk-accept check id at the DO authority boundary so a crafted value
// cannot land in a storage key. It matches the stable ids this module mints (lower-case, hyphenated).
// Exported so the DO route validates the {checkId} body against the same pattern this module emits.
export const POSTURE_ID_PATTERN = /^[a-z0-9-]{1,64}$/;

// CHECK_SEVERITY is the fixed severity per stable check id (contract section 7 table). It is exported so
// the DO's risk-accept route can reject an unknown checkId (only a real check may be accepted) and so the
// regression snapshot records the right severity for the posture-regression emission. Keeping the
// severities here (the single source) means computePosture and the DO cannot disagree on a check's weight.
export const CHECK_SEVERITY: Record<string, PostureSeverity> = {
  "access-enforced": "high",
  // admin-strong-auth (high, Essential Eight MFA / NIST SP 800-63B): platform-verified only in the
  // all-passkeys state; otherwise "needs attestation" (MFA at an IdP / in an Access policy is not
  // observable from inside the engine, so it is attested, never fabricated and never auto-failed).
  "admin-strong-auth": "high",
  "dispose-bootstrap-token": "high",
  "recovery-codes-low": "medium",
  "two-owners": "medium",
  "restore-test-recency": "critical",
  "seal-verification": "critical",
  "restore-test-enabled": "high",
  "failure-alerts": "medium",
  "destination-configured": "critical",
  "environment-self-backup": "high",
  "redundant-copies": "high",
  "media-diversity": "medium",
  "break-glass-present": "high",
  "operational-private-weakening": "medium",
  // attended-verification-cadence (medium): a lapsed proof rhythm is an assurance obligation, not a failure
  // of the backup, and nothing gates on it. Omitted entirely when no interval is stated or when an
  // operational key is present (see buildAttendedCadence).
  "attended-verification-cadence": "medium",
  "credential-expiry": "high",
  "audit-export-available": "low",
  "beacon-off": "low",
  "encryption-pq-hybrid": "low",
  // immutability (medium): REAL WORM/Object-Lock status from the live capability probe + config, NOT
  // inferred from delete permission. It FAILS (medium warning) in the states where a retention window
  // was intended and none is in force: a valid policy on a bucket that does not enforce Object-Lock (or
  // whose enforcement cannot be confirmed), and an INVALID policy in every reading, INCLUDING on a bucket
  // that does enforce, because an unparseable policy arms no retention header and an enforcing bucket
  // does not make it correct. A bucket with NO policy still passes informationally, and on an enforcing
  // bucket with no default retention rule of its own it passes with the strong claim withdrawn rather
  // than promising a window nothing applies. See buildImmutability in posture-checks.ts, whose own header
  // sets out every reading; "enforced" and "not configured" both pass is no longer the whole story.
  "immutability": "medium",
  // dest-cred-encryption (medium, ISO A.8.24 / A.8.13): whether console-set destination credentials are
  // envelope-encrypted at rest in the Durable Object (CONFIG_WRAP_KEY set + no plaintext records remain),
  // rather than held on the platform-encryption-only plaintext floor. See the dest-cred-encryption block.
  "dest-cred-encryption": "medium",
  // emergency-change-review (medium, ITIL Change Management / ISO 27001 A.8.32): when the OWNER-OPT-IN
  // requireChangeNumber policy is on, fails (a medium warning) once an EMERGENCY CHANGE has been recorded,
  // prompting retrospective-record validation; not applicable (omitted) when the policy is off. See the
  // emergency-change-review block in posture-checks.ts.
  "emergency-change-review": "medium",
  // recipient-set-expected (high, no-custody): whether the recipient set the engine seals archives to
  // still matches the set recorded in the last SIGNED control-plane export (posture-checks.ts). It was PUSHED
  // by computePosture without ever being registered here: it silently fell to push()'s `?? "low"` fallback
  // (the WRONG weight for the exact check that catches an
  // attacker-added seal recipient), and isKnownCheckId gates acceptPostureRisk on membership here, so an
  // owner could not attest, accept or override a check they could not even see rated at its real severity.
  "recipient-set-expected": "high",
  // update-apply-provenance (low, SLSA v1 / NIST SSDF PS.3): whether the last applied engine update left
  // durable content-hash evidence (the signed channel digest + read-back verdict on the settled record).
  // Not applicable until a channel apply has settled here. See the builder in posture-checks.ts.
  "update-apply-provenance": "low",
  // update-version-drift (medium, ISO 27001 A.8.32 / Essential Eight patch verification): whether the
  // running isolate's version_metadata id still matches the version the last verified update left live;
  // a mismatch means an out-of-band redeploy since that apply. Not applicable until a channel apply has
  // settled here. See the builder in posture-checks.ts.
  "update-version-drift": "medium",
};

// isKnownCheckId reports whether a string is a real posture check id (only a real check may be
// risk-accepted). The DO route uses it to 400 an unknown checkId, mirroring isExpiryKind's discipline.
export function isKnownCheckId(v: unknown): v is string {
  return typeof v === "string" && Object.hasOwn(CHECK_SEVERITY, v);
}

// applyOverride folds the owner-override set onto a check's AUTOMATIC outcome. It is the single place an
// override changes a status, so the score and the listing agree:
//   - not-applicable PINS: the owner's scoping decision holds regardless of the automatic outcome.
//   - an automatic PASS wins over every other override kind: the platform's own observation is the
//     stronger claim, so the check reads "pass" and the override goes dormant (it stays attached to the
//     check for the console to surface and offer a withdraw; it re-applies if the auto outcome drops).
//   - auto fail / cannot-verify with an override reads as the override's status kind.
//   - with no override: fail stays fail; cannot-verify reads "unattested" (needs attestation, never a
//     red failure the operator has no automatic way to clear); pass stays pass.
function applyOverride(auto: CheckAuto, override: PostureOverrideInput | undefined): PostureStatus {
  if (override?.kind === "not-applicable") return "not-applicable";
  if (auto === "pass") return "pass";
  if (override !== undefined) return override.kind; // risk-accepted | attested-pass | compensating-control
  return auto === "cannot-verify" ? "unattested" : "fail";
}

// isScorePositive reports whether a status counts toward the score NUMERATOR: pass, risk-accepted,
// attested-pass, compensating-control and resolved-alternative all do (a deliberately graded control is
// "good enough" for the score); fail and unattested do not. not-applicable is neither: it is EXCLUDED
// from the score entirely (numerator and denominator), the standard compliance treatment for a control
// that does not apply.
function isScorePositive(status: PostureStatus): boolean {
  return (
    status === "pass" ||
    status === "risk-accepted" ||
    status === "attested-pass" ||
    status === "compensating-control" ||
    status === "resolved-alternative"
  );
}

// isNeedsAttention is the score-negative set (the "open items" a reviewer scans first, and the basis of
// regression detection): a red fail, or an unattested cannot-verify. Exported for the snapshot/regression
// helpers and the tests.
export function isNeedsAttention(status: PostureStatus): boolean {
  return status === "fail" || status === "unattested";
}

// computePosture is the PURE posture computation (contract section 7). Given the observable state and a
// clock, it builds the starter check set, applies the risk-accept set, sorts the findings (most severe,
// then failing-before-passing, so a CISO sees the worst open items first), and computes the weighted
// pass fraction as a 0..100 integer. It does NO I/O. Every detail/remediation is a fixed, redaction-safe
// string (a downpipe name in a detail is the customer's own config); no secret can flow through.
export function computePosture(input: PostureInput, now: number): PostureReport {
  const overrides = input.overrides;
  const checks: PostureCheck[] = [];

  // push stamps the fixed severity (CHECK_SEVERITY) and folds the owner-override set onto a builder
  // draft, appending the resulting finding. The per-check builders (posture-checks.ts) own the
  // redaction-safe content; this is the one place severity and the override fold are applied, so the
  // listing and the score agree. A null draft (a check that does not apply, e.g. recovery-codes-low with
  // no per-email count, or dest-cred-encryption with nothing to protect) appends nothing, exactly as the
  // guarded pushes did. The override is carried on the check EVEN WHEN DORMANT (auto pass won), so the
  // console can state it and offer a withdraw.
  const push = (draft: CheckDraft | null): void => {
    if (draft === null) return;
    const severity = CHECK_SEVERITY[draft.id] ?? "low";
    const override = overrides.get(draft.id);
    const status = applyOverride(draft.auto, override);
    checks.push({
      id: draft.id,
      title: draft.title,
      severity,
      status,
      autoStatus: draft.auto,
      control: draft.control,
      detail: draft.detail,
      remediation: draft.remediation,
      how: draft.how,
      ...(override !== undefined ? { override: { kind: override.kind, reason: override.reason, setBy: override.setBy, setAt: override.setAt } } : {}),
    });
  };

  // The checks are pushed in the contract's listing order (the sort below re-orders for display, but the
  // build order is preserved for the stable-id tie-break). Each builder is a pure projection of the input.
  push(buildAccessEnforced(input));
  push(buildAdminStrongAuth(input));
  push(buildDisposeBootstrapToken(input));
  push(buildRecoveryCodesLow(input));
  push(buildTwoOwners(input));
  push(buildRestoreTestRecency(input, now));
  push(buildAttendedCadence(input, now));
  push(buildSealVerification(input));
  push(buildRestoreTestEnabled(input));
  push(buildFailureAlerts(input));
  push(buildDestinationConfigured(input));
  push(buildEnvironmentSelfBackup(input));
  push(buildRedundantCopies(input));
  push(buildMediaDiversity(input));
  push(buildBreakGlassPresent(input));
  push(buildOperationalPrivateWeakening(input));
  push(buildRecipientSetExpected(input));
  push(buildCredentialExpiry(input));
  push(buildAuditExportAvailable());
  push(buildBeaconOff(input));
  push(buildEncryptionPqHybrid());
  push(buildImmutability(input));
  push(buildDestCredEncryption(input));
  push(buildEmergencyChangeReview(input));
  push(buildUpdateApplyProvenance(input));
  push(buildUpdateVersionDrift(input));

  // Sort: most severe first, then needs-attention before graded/passing within a severity (a CISO scans
  // the worst open findings first), then by id for a stable order. SEVERITY_WEIGHT gives the rank; a
  // higher weight sorts first.
  checks.sort((a, b) => {
    const sw = SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity];
    if (sw !== 0) return sw;
    const af = isNeedsAttention(a.status) ? 0 : 1;
    const bf = isNeedsAttention(b.status) ? 0 : 1;
    if (af !== bf) return af - bf; // needs-attention (0) before graded/passing (1)
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });

  // Weighted pass fraction: sum of weights of score-positive checks over the total weight of the checks
  // IN SCOPE, as a 0..100 integer. A not-applicable check is out of scope entirely (excluded from both
  // sides), so an owner's N/A neither inflates nor deflates the number. With no in-scope checks the score
  // is 100 (nothing applicable is failing).
  let total = 0;
  let earned = 0;
  for (const c of checks) {
    if (c.status === "not-applicable") continue;
    const w = SEVERITY_WEIGHT[c.severity];
    total += w;
    if (isScorePositive(c.status)) earned += w;
  }
  const score = total === 0 ? 100 : Math.round((earned / total) * 100);

  return {
    score,
    generatedAt: new Date(now).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
    checks,
  };
}

// snapshotOf projects a PostureReport to the regression snapshot (id + passed + severity per check), the
// minimal state the DO persists to detect a previously-good check moving into the needs-attention set.
// "passed" is NOT-needs-attention (pass, every override kind including not-applicable, and
// resolved-alternative), so an owner's deliberate grading never later reads as a regression, and a check
// that recovers is not a regression either.
export function snapshotOf(report: PostureReport): PostureSnapshot {
  return {
    at: report.generatedAt,
    checks: report.checks.map((c) => ({ id: c.id, passed: !isNeedsAttention(c.status), severity: c.severity })),
  };
}

// PostureRegression is one detected regression (a check that passed in the prior snapshot and fails now).
// It carries the id + the severity (which sets the posture-regression notification severity: a critical
// check regression is emitted critical, otherwise warning) and the title for a redaction-safe detail.
export interface PostureRegression {
  id: string;
  title: string;
  severity: PostureSeverity;
}

// detectRegressions compares a fresh report against the prior snapshot and returns the checks that
// regressed (were good before, need attention now: fail or unattested). A check absent from the prior
// snapshot (new check, or first run) is NOT a regression (there is no prior good state to fall from), and
// a check an owner has graded (any override kind, including not-applicable) is never one either. This is
// the pure basis of the DO's posture-regression emission; the DO maps each to a notification with
// severity from the check.
export function detectRegressions(report: PostureReport, prior: PostureSnapshot | null): PostureRegression[] {
  if (prior === null) return [];
  const priorPassed = new Map<string, boolean>();
  for (const e of prior.checks) priorPassed.set(e.id, e.passed);
  const out: PostureRegression[] = [];
  for (const c of report.checks) {
    const wasPassed = priorPassed.get(c.id);
    if (wasPassed === true && isNeedsAttention(c.status)) {
      out.push({ id: c.id, title: c.title, severity: c.severity });
    }
  }
  return out;
}
