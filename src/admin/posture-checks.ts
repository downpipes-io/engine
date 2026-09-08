// Posture check builders (extracted from posture.ts for file-size hygiene, finding engine-src-011-01).
// Each builder is a PURE projection of the redaction-safe PostureInput into one finding's content: the
// stable id, title, named control, the AUTOMATIC outcome, an observed-detail one-liner, a remediation and
// a "how this is determined" method line. The builders do NO I/O and apply NO override fold or severity
// lookup; computePosture owns the push closure that stamps the fixed severity (CHECK_SEVERITY) and folds
// the owner-override set, so the ordering, override and score logic stay in one place. A builder returns
// null when its check does not apply to the given input (the conditionally-pushed checks:
// recovery-codes-low, dest-cred-encryption, emergency-change-review).
//
// The AUTOMATIC outcome is a tri-state, not a boolean:
//   "pass"          : the platform OBSERVED the control satisfied.
//   "fail"          : the platform OBSERVED the control not satisfied, and the operator can fix it.
//   "cannot-verify" : the platform genuinely CANNOT observe this control (e.g. media diversity for
//                     cloud-only storage, MFA enforced at an external IdP). It is surfaced as "needs
//                     attestation" (score-negative but never a red "fail"), and the owner satisfies it
//                     with an attested-pass / compensating-control override, or excludes it with
//                     not-applicable. An unverifiable control must never read as a red failure the
//                     operator has no ability to clear.
//
// NO-CUSTODY + REDACTION (sacred). Every draft carries ONLY redaction-safe metadata computed from
// counts/booleans/recency the inputs already carry (a downpipe NAME may appear in a detail, which is the
// customer's own redaction-safe config, never a secret); no draft can carry a key, value, fingerprint or
// selector.

import { evaluateAttendedCadence } from "./attended-cadence.ts";
import type { PostureDownpipeInput, PostureInput } from "./posture-types.ts";
import { RECOVERY_CODES_LOW_THRESHOLD } from "./recovery-constants.ts";

// CheckAuto and CheckDraft live in the leaf posture-types.ts, not here, so posture-checks-immutability.ts
// (re-exported below) can use CheckDraft's shape without an import back to this file. Re-exported so this
// module's existing importers keep importing them from here.
import type { CheckAuto, CheckDraft } from "./posture-types.ts";
export type { CheckAuto, CheckDraft };

// DAY_MS / restore-test recency thresholds: the check FAILS (critical) when no successful test exists in the
// last RESTORE_TEST_RECENCY_CRITICAL_DAYS (180d). The 90-day band (RESTORE_TEST_RECENCY_HIGH_DAYS) is a
// warning note in the detail string of a still-passing check, not a separate severity. Kept local so this
// pure module has no dependency.
const DAY_MS = 24 * 60 * 60 * 1000;
const RESTORE_TEST_RECENCY_HIGH_DAYS = 90;
const RESTORE_TEST_RECENCY_CRITICAL_DAYS = 180;

// access-enforced (high, product no-custody): fails when a SHARED-TOKEN admin path is still live, so an
// admin action could be unattributable. The determination is ACCOUNT-LEVEL and stable across readers: the
// shared-token fallback is dead when no ADMIN_TOKEN is configured, or the fallback is env-disabled
// (ADMIN_TOKEN_DISABLED), or the token has been retired in-app. When the fallback is dead, every remaining
// sign-in path (Cloudflare Access, passkeys, native OIDC/SAML SSO, recovery codes) resolves to a verified,
// attributable identity. It deliberately does NOT read the current caller's own auth method: a per-caller
// signal would make the same account score differently depending on who looked (and would unfairly fail a
// tenant whose admins sign in with passkeys or native SSO rather than Cloudflare Access).
export function buildAccessEnforced(input: PostureInput): CheckDraft {
  const tokenEffective =
    input.status.adminTokenPresent && !input.status.tokenFallbackDisabled && !input.status.breakGlassTokenRetired;
  return {
    id: "access-enforced",
    title: "Attributable admin access enforced",
    control: "product no-custody",
    auto: tokenEffective ? "fail" : "pass",
    detail: tokenEffective
      ? "A shared break-glass admin token is still honoured, so an admin action could be performed by anyone holding the string (unattributable). Every other sign-in path (Cloudflare Access, passkeys, SSO) is attributable."
      : "Admin access is attributable-identity only (Cloudflare Access, passkeys or SSO); no shared-token path is honoured.",
    remediation:
      "Retire the break-glass admin token in-app (Security centre > Retire break-glass token) or set ADMIN_TOKEN_DISABLED / delete the ADMIN_TOKEN secret, so every admin action is attributable to a person. If you deliberately keep the token as a sealed break-glass behind Cloudflare Access, record that as an override on this check.",
    how: "Observes whether the shared ADMIN_TOKEN fallback is effectively live (present, not env-disabled, not retired in-app). Account-level and identical for every reader; it does not depend on how the current viewer signed in.",
  };
}

// admin-strong-auth (high, MFA): can the platform VERIFY that admin sign-in is phishing-resistant MFA?
// It auto-passes ONLY in the state it can actually observe end-to-end: every admin-capable identity
// (Owner / access-admin) has at least one enrolled passkey, no IdP connection is enabled (so no sign-in
// happens upstream where MFA enforcement is invisible), and no shared-token path is live. In every other
// state it does NOT fabricate a red failure, because MFA may well be enforced somewhere the platform
// cannot see (your IdP's policy, your Cloudflare Access policy): it reports cannot-verify ("needs
// attestation") and the owner attests it with an attested-pass override (e.g. "MFA enforced for all staff
// at our IdP"), or a compensating control, or marks it not applicable. This is the honest reading: a
// platform that cannot observe an IdP's MFA policy must neither claim it nor fail it.
export function buildAdminStrongAuth(input: PostureInput): CheckDraft {
  const id = "admin-strong-auth";
  const title = "Strong admin sign-in (MFA / passkeys / SSO)";
  const control = "Essential Eight MFA / NIST SP 800-63B";
  const how =
    "Verified automatically only when the platform can observe the whole sign-in surface: every Owner / access-admin identity has an enrolled passkey, no IdP connection is enabled, and no shared-token path is live. Otherwise it needs your attestation, because MFA enforced at your IdP or in your Cloudflare Access policy is not observable from inside the engine.";
  const remediation =
    "Enrol a passkey for every admin identity (platform-verified), or, if your admins sign in through Cloudflare Access or an IdP (OIDC / SAML) that enforces MFA, attest that here (Override > Pass, attested) naming the policy that enforces it.";
  const ident = input.identity;
  if (ident === undefined) {
    return {
      id, title, control, auto: "cannot-verify", how, remediation,
      detail: "The identity signals were not available on this read, so strong sign-in cannot be verified automatically.",
    };
  }
  const tokenEffective =
    input.status.adminTokenPresent && !input.status.tokenFallbackDisabled && !input.status.breakGlassTokenRetired;
  const allPasskeyed = ident.adminIdentities > 0 && ident.adminsWithPasskey >= ident.adminIdentities;
  if (allPasskeyed && ident.idpConnectionsEnabled === 0 && !tokenEffective) {
    return {
      id, title, control, auto: "pass", how, remediation,
      detail: `Platform-verified: all ${ident.adminIdentities} admin ${ident.adminIdentities === 1 ? "identity" : "identities"} sign in with passkeys (phishing-resistant MFA), no IdP connection is enabled and no shared-token path is live.`,
    };
  }
  const why =
    ident.adminIdentities === 0
      ? "no admin identities are enrolled yet"
      : ident.idpConnectionsEnabled > 0
        ? `sign-in can happen through ${ident.idpConnectionsEnabled} enabled IdP connection${ident.idpConnectionsEnabled === 1 ? "" : "s"}, where MFA enforcement is applied by your IdP and is not observable here`
        : tokenEffective
          ? "a shared break-glass token path is still live (see the attributable-admin-access check)"
          : `${ident.adminIdentities - ident.adminsWithPasskey} of ${ident.adminIdentities} admin identities have no enrolled passkey (they may sign in through Cloudflare Access, whose MFA policy is not observable here)`;
  return {
    id, title, control, auto: "cannot-verify", how, remediation,
    detail: `Strong sign-in cannot be verified automatically: ${why}. If MFA is enforced for your admins (at your IdP, in Cloudflare Access, or by policy), attest it as a pass with the reason recorded.`,
  };
}

// dispose-bootstrap-token (high, security): the ADMIN_TOKEN is a ONE-TIME bootstrap credential for the
// first Owner. Once the bootstrap is complete, leaving the token LIVE means anyone holding the string can
// take admin (it is the unattributable all-or-nothing break-glass). This check FAILS when the bootstrap is
// consumed AND the token is still EFFECTIVE: it is present (adminTokenPresent) and NOT disabled by either
// ADMIN_TOKEN_DISABLED (tokenFallbackDisabled) or the in-app retire (breakGlassTokenRetired). It CLEARS the
// moment the operator retires it in-app (Security Centre, immediate, no redeploy) or env-disables/deletes
// the secret. The check does NOT fire before the bootstrap is consumed (a fresh tenant legitimately needs
// the token to claim the first Owner), so it is a "now that you are set up, dispose of it" prompt, never a
// block. Mirrors the access-enforced finding shape (redaction-safe; no value, no fingerprint).
export function buildDisposeBootstrapToken(input: PostureInput): CheckDraft {
  const tokenEffective =
    input.status.adminTokenPresent && !input.status.tokenFallbackDisabled && !input.status.breakGlassTokenRetired;
  // The finding PROMPTS disposal only when it is SAFE to dispose: the bootstrap is complete, the token is
  // still live, AND an ongoing admin break-glass is in place (recoveryBreakGlassReady: recovery codes for
  // an Owner OR a second Owner). If the token is live but break-glass is NOT yet in place, we do NOT tell
  // the operator to dispose (that would strand them); instead the detail nudges them to set up recovery
  // first, and the recovery-codes-low finding carries the "generate codes" prompt. This mirrors the
  // retire endpoint's own gate, so the Security Centre and the action agree on when disposal is safe.
  const liveButNotReady =
    input.status.bootstrapConsumed && tokenEffective && !input.status.recoveryBreakGlassReady;
  const failed = input.status.bootstrapConsumed && tokenEffective && input.status.recoveryBreakGlassReady;
  return {
    id: "dispose-bootstrap-token",
    title: "Break-glass bootstrap token disposed",
    control: "security",
    auto: failed ? "fail" : "pass",
    how: "Observes the ADMIN_TOKEN presence, the first-Owner bootstrap latch, the in-app retire latch and whether an ongoing break-glass (recovery codes or a second Owner) exists. It only prompts disposal once disposing is safe.",
    detail: failed
      ? "Bootstrap is complete and an admin break-glass is in place; the break-glass admin token is still live and anyone holding the string can take admin. It is now safe to dispose of it."
      : liveButNotReady
        ? "The break-glass admin token is still live, but no ongoing admin break-glass is in place yet; generate and save recovery codes for an Owner (or appoint a second Owner) BEFORE disposing of the token."
        : input.status.breakGlassTokenRetired
          ? "The break-glass admin token has been retired in-app; the bearer fallback is no longer honoured."
          : !input.status.adminTokenPresent
            ? "No break-glass admin token is configured."
            : input.status.tokenFallbackDisabled
              ? "The break-glass admin token fallback is disabled (Access-only)."
              : "The break-glass admin token has not yet been consumed by a first-Owner bootstrap.",
    remediation:
      "Bootstrap is complete and a way back in is in place (recovery codes for an Owner, or a second Owner). Retire the live break-glass admin token now in-app (Security Centre > Retire break-glass token) or delete the secret (wrangler secret delete ADMIN_TOKEN); leaving it live lets anyone with the string take admin.",
  };
}

// recovery-codes-low (medium, security/availability): the caller's OWN recovery-code set is running low
// (<= RECOVERY_CODES_LOW_THRESHOLD remaining, which includes 0). Recovery codes are the ongoing admin
// break-glass; running out (or near out) risks a lock-out if a passkey is lost, so prompt a regenerate.
// It is per the CALLER's own count (recoveryCodesRemaining); a caller with no per-email count (the bare-
// token break-glass, which has no codes) does not raise it (the field is absent), so the token break-glass
// never sees a spurious low finding. With the field present, fails when remaining <= RECOVERY_CODES_LOW_THRESHOLD.
export function buildRecoveryCodesLow(input: PostureInput): CheckDraft | null {
  const remaining = input.recoveryCodesRemaining;
  if (remaining === undefined) return null;
  const failed = remaining <= RECOVERY_CODES_LOW_THRESHOLD;
  return {
    id: "recovery-codes-low",
    title: "Recovery codes available",
    control: "security",
    auto: failed ? "fail" : "pass",
    how: `Counts YOUR OWN unconsumed recovery codes (never another user's) and warns at ${RECOVERY_CODES_LOW_THRESHOLD} or fewer remaining. Only raised for a signed-in identity with a recovery-code set.`,
    detail: failed
      ? `${remaining} recovery code${remaining === 1 ? "" : "s"} remaining; regenerate a fresh set so you are not locked out if you lose your passkey.`
      : `${remaining} recovery codes remaining.`,
    remediation:
      "Regenerate your recovery codes (Security Centre > Regenerate recovery codes) and save the new set offline; this invalidates the old set.",
  };
}

// two-owners (medium, availability): fails with fewer than 2 Owners (a single Owner is a continuity
// risk; if they leave or lose access, no one can administer roles or accept risk).
export function buildTwoOwners(input: PostureInput): CheckDraft {
  const failed = input.ownerCount < 2;
  return {
    id: "two-owners",
    title: "At least two Owners",
    control: "availability",
    auto: failed ? "fail" : "pass",
    how: "Counts identities holding the Owner role (bound and pending invitations both count). Fails below two.",
    detail: `${input.ownerCount} Owner${input.ownerCount === 1 ? "" : "s"} configured.`,
    remediation:
      "Grant the Owner role to a second trusted person so administration survives one Owner being unavailable.",
  };
}

// restore-test-recency (critical at 180d, high at 90d): any downpipe with no SUCCESSFUL restore test
// in the window fails. "Successful" means lastRestoreTestOk === true within the window; a never-tested
// or last-failed downpipe fails. The contract fixes the check severity at critical (180d); the detail
// notes the 90d high band. We surface the worst offender by name (redaction-safe). With no downpipes
// the check passes (nothing to test).
//
// DURABLE KEYED CREDIT (compliance-stamp: thread the attended-verification proof into this check so a
// break-glass-only estate can pass on a REAL keyed verify rather than a scheduled drill it can never pass).
// A break-glass-only estate (no in-account OPERATIONAL_PRIVATE) can never pass an ORDINARY scheduled drill:
// the cron defers every cadence tick (runScheduledRestoreTest, cron/restore-test-pass.ts), and
// completeRestoreTest records that as lastRestoreTestOk=false forever. A FULL (100%), PROVEN attended
// verification (recordAttendedVerification, scheduler-do-observability.ts) stamps a durable
// restoreProven { method:"attended-blind-test" } proof that SURVIVES that deferral (completeRestoreTest
// never touches restoreProven). gradedOkAt below credits that durable proof, but STRICTLY ONLY when the
// ordinary recency is honestly explained by "never tested" or "deferred" -- NEVER over a GENUINE not-ok
// completion (a real restore-test failure), which must always stay an offender however affirmative an
// older proof is. (An earlier draft of this credit computed the
// graded time as maxDefined(ordinary recency, durable proof) unconditionally; that would sign a FALSE PASS
// into the compliance pack whenever a genuine fresh failure followed an older proof on an ORDINARY
// operational estate, precisely the estates this feature was never meant to touch. gradedOkAt's
// genuineNotOk gate below is the fix: it is what makes the credit safe.) It also credits ONLY the full
// keyed method, never a blind-test proof (which carries no sample rate or scope, so a one-record test and a
// full-run test are indistinguishable once stamped) and never a keyless-attest proof (no decryption, so it
// does not satisfy a decrypt-verify check).
export function buildRestoreTestRecency(input: PostureInput, now: number): CheckDraft {
  // A downpipe that has NEVER COMPLETED A RUN is excluded from the fail: there is no archive to
  // restore-test yet, so "no successful restore test" is not a true finding against it (a brand-new
  // downpipe must not open as a critical failure it cannot clear until its first run). It is named in
  // the detail instead; staleness/failure alerting covers a downpipe that persistently never runs. The
  // has-a-run gate keys on lastRunId (the last SUCCESSFUL run's id; absent = never completed a run),
  // the SAME predicate the restore-test scheduler uses to decide there is something to drill
  // (restoreTestsDue: d.lastRunId !== null). It deliberately does NOT key on the restore-test recency
  // fields, which are what the check then GRADES below.
  const graded = input.downpipes.filter((d) => typeof d.lastRunId === "string" && d.lastRunId !== "");
  const neverRun = input.downpipes.length - graded.length;

  // gradedOkAt is the SINGLE source of the "graded time" every filter below uses, so the ordinary-recency
  // path and the durable-proof fallback can never drift apart. Ordinary recency (lastRestoreTestOk===true)
  // always wins when present, exactly as before this credit existed: crediting the proof only ever ADDS a
  // pass over an absent/deferred recency, never removes one the ordinary recency already grants, and never
  // overrides one it already denies for real cause.
  const gradedOkAt = (d: PostureDownpipeInput): number | undefined => {
    const recencyOkAt = d.lastRestoreTestOk === true ? d.lastRestoreTestAt : undefined;
    if (recencyOkAt !== undefined) return recencyOkAt;
    // A GENUINE not-ok completion (the deferred flag absent on a not-ok completion is completeRestoreTest's
    // and stampRestoreTested's shared signal for real failure evidence, never a deferral) is fresh
    // disconfirming evidence: it must never be masked by a stale proof, however recent that proof was.
    const genuineNotOk = d.lastRestoreTestOk === false && d.lastRestoreTestDeferred === undefined;
    if (genuineNotOk) return undefined;
    // Only the FULL keyed attended proof credits (blind-test and keyless-attest are excluded; see the
    // function header for why). attended-blind-test is stamped ONLY at a full (sampleRate>=100), PROVEN
    // pass, so it alone is unambiguous.
    return d.restoreProvenMethod === "attended-blind-test" ? d.restoreProvenAt : undefined;
  };
  // viaProof: true when the graded time came from the durable proof rather than ordinary recency (used only
  // to name the credit in the detail text below; it never changes the pass/fail computation above).
  const viaProof = (d: PostureDownpipeInput): boolean =>
    (d.lastRestoreTestOk === true ? d.lastRestoreTestAt : undefined) === undefined && gradedOkAt(d) !== undefined;

  const offenders = graded.filter((d) => {
    const okAt = gradedOkAt(d);
    if (okAt === undefined) return true; // has archives but never a successful (or creditable) restore test
    return now - okAt > RESTORE_TEST_RECENCY_CRITICAL_DAYS * DAY_MS;
  });
  const warnBand = graded.filter((d) => {
    const okAt = gradedOkAt(d);
    if (okAt === undefined) return false;
    const age = now - okAt;
    return age > RESTORE_TEST_RECENCY_HIGH_DAYS * DAY_MS && age <= RESTORE_TEST_RECENCY_CRITICAL_DAYS * DAY_MS;
  });
  const provenCredited = graded.filter((d) => {
    const okAt = gradedOkAt(d);
    return viaProof(d) && okAt !== undefined && now - okAt <= RESTORE_TEST_RECENCY_CRITICAL_DAYS * DAY_MS;
  });
  const failed = offenders.length > 0;
  const first = offenders[0];
  const neverRunNote = neverRun > 0 ? ` ${neverRun} downpipe${neverRun === 1 ? " has" : "s have"} not yet completed a first run and ${neverRun === 1 ? "is" : "are"} graded once a run exists.` : "";
  const provenNote =
    provenCredited.length > 0
      ? ` ${provenCredited.length} downpipe${provenCredited.length === 1 ? "" : "s"} ${provenCredited.length === 1 ? "is" : "are"} current via attended verification rather than a scheduled test (most recent ${new Date(Math.max(...provenCredited.map((d) => gradedOkAt(d) ?? 0))).toISOString().slice(0, 10)}).`
      : "";
  const detail = failed
    ? `${offenders.length} downpipe${offenders.length === 1 ? "" : "s"} have no successful restore test in ${RESTORE_TEST_RECENCY_CRITICAL_DAYS} days (e.g. "${first?.name ?? first?.id ?? "unknown"}").${neverRunNote}${provenNote}`
    : warnBand.length > 0
      ? `All downpipes have a successful restore test, though ${warnBand.length} are older than ${RESTORE_TEST_RECENCY_HIGH_DAYS} days.${neverRunNote}${provenNote}`
      : input.downpipes.length === 0
        ? "No downpipes are configured yet."
        : `Every downpipe with archives has a recent successful restore test.${neverRunNote}${provenNote}`;
  return {
    id: "restore-test-recency",
    title: "Recent successful restore test",
    control: "CIS 11.5 / NIST CSF PR.DS-11",
    auto: failed ? "fail" : "pass",
    how: `Reads each downpipe's last successful restore-test time. Fails when any downpipe that has completed at least one run has no successful test within ${RESTORE_TEST_RECENCY_CRITICAL_DAYS} days; tests older than ${RESTORE_TEST_RECENCY_HIGH_DAYS} days are noted as a warning band. A downpipe that has never run is named but not failed (there is nothing to test yet). A durable, full (100%) attended-verification proof credits the check across a scheduled-test deferral (no in-account operational key), naming the method, but never over a genuine scheduled-test failure recorded since that proof.`,
    detail,
    remediation:
      "Enable scheduled restore tests (or run a drill) so every downpipe has a successful recovery test within the recency window; a break-glass-only estate can also satisfy this with a full (100%) attended verification.",
  };
}

// seal-verification (critical, recoverability): verify-at-seal reads each run's archive
// BACK from the destination right after the seal and verifies it. A downpipe whose LAST verify-at-seal
// verdict was SUSPECT (the readback verify failed) fails this check: the most recently written archive
// could not be verified, so it must not be trusted until a drill/restore confirms it. A downpipe that
// has never run with the feature on (lastSealVerifyOk absent) does NOT fail, there is no suspect
// verdict to surface (the feature may be off, or it is a fresh downpipe). This is the at-seal companion
// to restore-test-recency: recency proves a periodic restore test ran; this proves the LATEST write
// landed verifiably. The worst offender is named (redaction-safe).
export function buildSealVerification(input: PostureInput): CheckDraft {
  const offenders = input.downpipes.filter((d) => d.lastSealVerifyOk === false);
  const failed = offenders.length > 0;
  const first = offenders[0];
  return {
    id: "seal-verification",
    title: "Latest backup verified at seal",
    control: "recoverability",
    auto: failed ? "fail" : "pass",
    how: "Reads each downpipe's latest verify-at-seal verdict (the just-written archive is read back from the destination and verified after each run). Fails when any downpipe's last verdict was suspect; a downpipe that has never run with the feature on is not graded.",
    detail: failed
      ? `${offenders.length} downpipe${offenders.length === 1 ? "" : "s"} had a SUSPECT verify-at-seal on their last run (the just-written archive could not be verified) (e.g. "${first?.name ?? first?.id ?? "unknown"}"). The run still completed and the archive was not deleted (fail-open); confirm recoverability with a drill or restore.`
      : input.downpipes.length === 0
        ? "No downpipes are configured yet."
        : "Every downpipe's last run was verified at seal (or verify-at-seal has not run yet).",
    remediation:
      "Investigate the destination for the affected downpipe (a drill or a restore confirms recoverability). A suspect verify-at-seal means the bytes that landed did not read back cleanly; the next clean run clears the finding.",
  };
}

// restore-test-enabled (high, CIS 11.5): any downpipe with restoreTestCadenceSeconds off (0 or absent)
// fails. Best practice is on by default; an explicit opt-down is surfaced as a finding to fix.
export function buildRestoreTestEnabled(input: PostureInput): CheckDraft {
  const off = input.downpipes.filter((d) => (d.restoreTestCadenceSeconds ?? 0) <= 0);
  const failed = off.length > 0;
  const first = off[0];
  return {
    id: "restore-test-enabled",
    title: "Scheduled restore tests enabled",
    control: "CIS 11.5",
    auto: failed ? "fail" : "pass",
    how: "Reads each downpipe's restore-test cadence setting. Fails when any downpipe has scheduled restore tests off (0 or unset); the default for a new downpipe is weekly.",
    detail: failed
      ? `${off.length} downpipe${off.length === 1 ? "" : "s"} have scheduled restore tests off (e.g. "${first?.name ?? first?.id ?? "unknown"}").`
      : input.downpipes.length === 0
        ? "No downpipes are configured yet."
        : "Every downpipe has scheduled restore tests enabled.",
    remediation:
      "Set a restore-test cadence on each downpipe so recoverability is verified automatically.",
  };
}

// failure-alerts (medium, operational): fails when NO enabled notify rule selects backup-failure, so a
// failed backup would be silent. The DO computes the boolean from the rules.
export function buildFailureAlerts(input: PostureInput): CheckDraft {
  const failed = !input.notifyFailureRuleSet;
  return {
    id: "failure-alerts",
    title: "Backup-failure alerts configured",
    control: "operational",
    auto: failed ? "fail" : "pass",
    how: "Checks the enabled notification rules for one that selects the backup-failure event ACCOUNT-WIDE (a rule scoped to a single downpipe does not satisfy it, because a failure on any other downpipe would still be silent).",
    detail: failed
      ? "No account-wide notification rule alerts on backup failure; a failed backup could go unnoticed. (A rule scoped to one downpipe does not cover the rest.)"
      : "An account-wide notification rule alerts on backup failure.",
    remediation:
      "Add a notification channel and an account-wide rule that selects the backup-failure event so a failed backup pages someone.",
  };
}

// destination-configured (critical, Redundancy): fails when NO destination is configured (nothing is
// written off the source). This proves the SECOND COPY only (the live source + one archive). It is
// deliberately NOT labelled "3-2-1": one destination is not 3-2-1, and claiming so would overstate the
// posture. True 3-2-1 is the redundant-copies + media-diversity checks below.
export function buildDestinationConfigured(input: PostureInput): CheckDraft {
  const failed = !input.status.destConfigured;
  return {
    id: "destination-configured",
    title: "Archive destination configured (second copy)",
    control: "Redundancy",
    auto: failed ? "fail" : "pass",
    how: "Checks whether any archive destination (R2, S3-compatible, Google Cloud Storage or Azure Blob) is configured, from the deploy-time env or a console-set destination. Presence only; no endpoint or credential is read into the finding.",
    detail: failed
      ? "No archive destination is configured; backups have nowhere to land."
      : "An archive destination is configured, so a backed-up source has a second copy off-source.",
    remediation:
      "Configure an R2, S3-compatible, Google Cloud Storage or Azure Blob destination so each backup is written to a second location.",
  };
}

// environment-self-backup (high, Recovery): Downpipes' OWN configuration (downpipes, destinations, roles,
// policy) is signed and written to every destination as a no-custody export, so the environment can be
// rebuilt after a loss (not just the archived data). Fails when the plane needs recovery, no export has been
// written yet, the last export missed a destination, or the auto-heal is in a refused state. Not applicable
// (null) when there is nothing to back up (no destination, or no downpipes yet). No secret: booleans only.
export function buildEnvironmentSelfBackup(input: PostureInput): CheckDraft | null {
  const sb = input.selfBackup;
  if (sb === undefined) return null;
  const failed = sb.recoveryRequired || !sb.exportPresent || !sb.allDestinationsWrote || sb.autoHealRefused;
  const detail = sb.recoveryRequired
    ? "The control plane needs recovery (it was lost); rebuild it from a signed export, and this passes again."
    : !sb.exportPresent
      ? "No signed export of your configuration has been written yet, so the environment could not be rebuilt from the bucket after a loss."
      : !sb.allDestinationsWrote
        ? "The last export did not reach every destination, so some copies of your configuration are stale or missing."
        : sb.autoHealRefused
          ? "The automatic control-plane recovery is in a refused state; check the recovery banner and reconcile manually."
          : "A signed export of your configuration has been written to every destination, so the environment is recoverable from the bucket.";
  return {
    id: "environment-self-backup",
    title: "Downpipes' own configuration is backed up",
    control: "Recovery",
    auto: failed ? "fail" : "pass",
    how: "Checks that a signed, no-custody export of Downpipes' own control plane (downpipes, destinations, roles, policy) has been written to every destination, so the environment can be rebuilt after a loss. The export presence, the per-destination write outcome and the recovery state only; no config value or secret is read.",
    detail,
    remediation:
      "The export is written automatically on each configuration change to every destination (a destination and a signer are required). Clear any control-plane recovery first, and download a copy from Settings to keep with your recovery kit.",
  };
}

// redundant-copies (high, 3-2-1): the VERIFIABLE part of 3-2-1. Every protected source should write to
// >=2 distinct destinations, so a backed-up source exists in two places (3 copies incl. the live
// source). Fails when any downpipe writes to fewer than two (it follows the default, or pins one). The
// "2 different MEDIA" criterion is NOT verifiable for cloud-only storage and is the operator-attested
// media-diversity check below; "1 offsite" is inherent (all cloud is offsite from the source).
export function buildRedundantCopies(input: PostureInput): CheckDraft {
  const nonRedundant = input.downpipes.filter((d) => (d.destinationCount ?? 0) < 2);
  const failed = input.downpipes.length > 0 && nonRedundant.length > 0;
  return {
    id: "redundant-copies",
    title: "Sources fan out to two destinations",
    control: "3-2-1",
    auto: failed ? "fail" : "pass",
    how: "Counts each downpipe's distinct pinned destinations. Fails when any downpipe writes to fewer than two (the verifiable leg of 3-2-1); with no downpipes there is nothing to grade.",
    detail:
      input.downpipes.length === 0
        ? "No downpipes yet, so there is nothing to copy redundantly."
        : failed
          ? `${nonRedundant.length} of ${input.downpipes.length} downpipe(s) write to only one destination; that source exists in just one place off-source.`
          : "Every downpipe fans out to at least two destinations, so each backed-up source exists in two places.",
    remediation:
      "In a downpipe's destination picker, tick two or more destinations (the first is the primary; the rest get copies of every run). Add destinations under Destinations.",
  };
}

// media-diversity (medium, 3-2-1, OPERATOR-ATTESTED): the "2 different media" leg. downpipes is a
// cloud-only object-storage backup, so the platform cannot VERIFY media-type diversity for you (two R2
// buckets, or R2 plus an external S3, are the same media class). It is the operator's informed call:
// once a source fans out the check reports CANNOT-VERIFY ("needs attestation", never a red fail the
// operator has no way to clear automatically), until an Owner attests it (an attested-pass override:
// "our destinations meet our media-diversity policy"). Attesting is the honest tick, never a false
// platform claim. Before any fan-out exists it does not apply (passes silently).
export function buildMediaDiversity(input: PostureInput): CheckDraft {
  const anyRedundant = input.downpipes.some((d) => (d.destinationCount ?? 0) >= 2);
  return {
    id: "media-diversity",
    title: 'Media diversity attested (3-2-1 "two media")',
    control: "3-2-1",
    auto: anyRedundant ? "cannot-verify" : "pass",
    how: "The platform cannot observe media class for cloud-only storage, so this check is never platform-verified once a source fans out: it asks for YOUR attestation that the destinations meet your media-diversity policy, and records it with your reason.",
    detail: anyRedundant
      ? "Your sources fan out to multiple cloud destinations. downpipes is cloud-only, so it cannot verify the \"two different media\" leg of 3-2-1 for you. If your destinations meet your media-diversity policy, attest it (Override > Pass, attested) with the reason recorded."
      : "No fan-out destinations yet; media diversity does not apply until a source writes to two places.",
    remediation:
      "If your destinations satisfy your media-diversity requirement (for example distinct providers or accounts), attest this check as a pass with your reasoning. The platform cannot verify media type for cloud-only storage.",
  };
}

// break-glass-present (high, DR continuity): fails when no break-glass recipient is configured, so an
// archive could not be opened offline in a disaster (the no-custody recovery path).
export function buildBreakGlassPresent(input: PostureInput): CheckDraft {
  const failed = !input.status.breakGlassConfigured;
  return {
    id: "break-glass-present",
    title: "Break-glass recipient configured",
    control: "DR continuity",
    auto: failed ? "fail" : "pass",
    how: "Checks the BREAK_GLASS_PUBLIC recipient key is configured (presence only; the public key is not a secret and the private half never exists on the platform).",
    detail: failed
      ? "No break-glass recipient is configured; archives cannot be opened offline in a disaster."
      : "A break-glass recipient is configured for offline recovery.",
    remediation:
      "Generate a break-glass keypair offline and configure BREAK_GLASS_PUBLIC so archives are recoverable without the platform.",
  };
}

// operational-private-weakening (medium, no-custody): the presence of the operational-private read-back
// key is a DELIBERATE weakening of the strict no-custody posture (it lets the engine self-test and
// self-restore), so it is SURFACED, not hidden. "fails" here means the weakening is present; an Owner
// who has accepted the trade-off risk-accepts it. The absence is the stronger posture (a pass).
export function buildOperationalPrivateWeakening(input: PostureInput): CheckDraft {
  const present = input.operationalPrivatePresent;
  return {
    id: "operational-private-weakening",
    title: "Operational read-back key posture",
    control: "no-custody",
    auto: present ? "fail" : "pass",
    how: "Checks the OPERATIONAL_PRIVATE read-back key presence. Its presence is a deliberate weakening that buys the UNATTENDED work (scheduled restore tests, automated drills, in-account retention pruning), surfaced so the trade-off is a recorded decision: keep it and record an override, or remove it for strict no-custody.",
    detail: present
      ? "An operational read-back key is present: the engine can run scheduled restore tests, automated drills and in-account retention pruning unattended, a deliberate weakening of strict no-custody."
      : "No operational read-back key is held; the strict no-custody posture is in force. Verification at seal and the canary still run in-account, and an in-console restore still works with the break-glass key supplied to the browser; what needs a key present is the unattended work.",
    remediation:
      "If strict no-custody is required, remove OPERATIONAL_PRIVATE. Runs stay verified at seal and the canary keeps running; what you give up is the unattended work, so schedule an offline rehearsal and prune with the offline reader. Otherwise risk-accept this trade-off.",
  };
}

// recipient-set-expected (high): the recipient set the engine seals archives to must match the set the
// last SIGNED control-plane export recorded.
//
// The gap: checkRecipientSet requires exactly ONE break-glass recipient and then permits any number of
// others, so a compromised engine, or a mis-set OPERATIONAL_PUBLIC, can add an attacker's public key to
// every future run and those archives still verify, restore and attest clean. Nothing surfaced it.
//
// The pin lives in the signed export on the DESTINATION, not in Durable Object storage, and that placement
// is the point. Whoever can add a recipient controls the deployed code and therefore the DO, so a DO pin
// would be read by the actor it exists to catch. A signed artefact on the destination, which can sit under
// object lock, is a record the engine cannot retroactively rewrite and the offline reader can read.
//
// Honest about its own limit: the comparison is still computed inside the estate, so a fully compromised
// engine can lie about the CURRENT side. What it cannot do is alter the signed history it already wrote,
// which is what turns an added recipient into evidence rather than a silent change.
export function buildRecipientSetExpected(input: PostureInput): CheckDraft {
  // Absent and null are the same claim here: nothing to compare against. Treated together rather than
  // relying on the field always being present, because a posture computation must never throw. A crash in
  // one check takes down every other check with it, and the ones it would take down include the checks a
  // compromised estate most needs to still report.
  const drift = input.recipientPinDrift ?? null;
  if (drift === null) {
    // cannot-verify, not pass. "Nothing to compare against" and "compared and matched" are different
    // claims, and only one of them is assurance.
    return {
      id: "recipient-set-expected",
      title: "Archive recipient set matches the signed record",
      control: "no-custody",
      auto: "cannot-verify",
      how: "Compares the recipient fingerprints the engine seals to against the set recorded in the last signed control-plane export.",
      detail: "No signed control-plane export has recorded a recipient set yet, so there is nothing to compare the current one against.",
      remediation: "Let the control-plane export pass run once so a signed baseline exists.",
    };
  }
  return {
    id: "recipient-set-expected",
    title: "Archive recipient set matches the signed record",
    control: "no-custody",
    auto: drift.matches ? "pass" : "fail",
    how: "Compares the recipient fingerprints the engine seals to against the set recorded in the last signed control-plane export, which lives on your destination and can sit under object lock.",
    detail: drift.matches
      ? "The recipient set the engine seals to matches the set recorded in the last signed export."
      : "The recipient set changed since the last signed export. An ADDED recipient means archives sealed from now on can be opened by a key that was not part of your key ceremony.",
    remediation:
      "If you rotated or added a key deliberately, this clears once the next export records the new set. If you did not, treat it as an incident: an added recipient opens every archive sealed from now on. Review the Cloudflare audit log for who changed the engine's secrets.",
  };
}

// credential-expiry (high, NIST SP 800-57): fails when any tracked credential/key is expired or
// approaching (the expiry tracker already computes the coarse state per item).
export function buildCredentialExpiry(input: PostureInput): CheckDraft {
  // Ephemeral spent tokens (pending cleanup) are a hygiene reminder, not a backup-breaking expiry, so
  // they are EXEMPT from this high-severity check; they surface via status.cleanupPending + the
  // console's Needs-attention tier instead. A FUNCTIONAL credential/cert/licence still fails here.
  const offenders = input.expiry.filter(
    (e) => (e.state === "approaching" || e.state === "expired") && e.lifecycleClass !== "ephemeral",
  );
  const failed = offenders.length > 0;
  const expired = offenders.filter((e) => e.state === "expired");
  const first = offenders[0];
  return {
    id: "credential-expiry",
    title: "No expiring credentials",
    control: "NIST SP 800-57",
    auto: failed ? "fail" : "pass",
    how: "Reads the expiry tracker's per-item state. Fails when any tracked functional credential, certificate or licence is approaching expiry or expired; an ephemeral spent token pending cleanup is a hygiene nudge elsewhere, not a failure here.",
    detail: failed
      ? `${offenders.length} tracked item${offenders.length === 1 ? "" : "s"} expiring or expired${expired.length > 0 ? ` (${expired.length} already expired)` : ""} (e.g. "${first?.label ?? "unknown"}").`
      : "No tracked credential or key is expiring soon.",
    remediation: "Rotate the expiring credential or key and update its tracked expiry date.",
  };
}

// audit-export-available (low, ISO A.8.15): informational; the tamper-evident audit log and its export
// are always available, so this always passes and states the posture.
export function buildAuditExportAvailable(): CheckDraft {
  return {
    id: "audit-export-available",
    title: "Audit log export available",
    control: "ISO A.8.15",
    auto: "pass",
    how: "Informational: the tamper-evident audit log and its JSON/CSV export are built in and always available, so this states the standing capability.",
    detail: "A tamper-evident, signed audit log is retained and can be exported (JSON or CSV).",
    remediation: "No action required; export the audit log periodically for off-platform retention.",
  };
}

// beacon-off (low, no-custody): fails when the vendor beacon is enabled. The product default is no
// beacon (no phone-home); the DO supplies whether it is on. With it off, this passes and states the
// posture.
export function buildBeaconOff(input: PostureInput): CheckDraft {
  const failed = input.beaconEnabled;
  return {
    id: "beacon-off",
    title: "Vendor beacon off",
    control: "no-custody",
    auto: failed ? "fail" : "pass",
    how: "Checks whether the opt-in vendor beacon is enabled (BEACON_URL, BEACON_INGEST_KEY and CF_ACCOUNT_ID all set, which is exactly what the emitter requires before it sends anything). Off is the default and the stronger no-custody posture.",
    detail: failed
      ? "The vendor beacon is enabled; the engine reports usage to the vendor."
      : "The vendor beacon is off; the engine does not phone home.",
    remediation:
      "Disable the vendor beacon to keep the no-custody posture (the engine should not report to the vendor).",
  };
}

// encryption-pq-hybrid (low, ISO A.8.13): informational; archives are sealed with a post-quantum hybrid
// scheme and are tamper-evident. Always passes; states the posture in PRECISE terms (post-quantum
// hybrid, tamper-evident; never quantum-proof or tamper-proof).
export function buildEncryptionPqHybrid(): CheckDraft {
  return {
    id: "encryption-pq-hybrid",
    title: "Post-quantum hybrid encryption",
    control: "ISO A.8.13",
    auto: "pass",
    how: "Informational: post-quantum hybrid sealing and signing is the engine's only mode (not a setting), so this states the standing property.",
    detail:
      "Archives are sealed with post-quantum hybrid encryption and signed with a post-quantum hybrid signature (tamper-evident).",
    remediation: "No action required; the post-quantum hybrid posture is in force.",
  };
}


// buildImmutability lives in its own module: it is the one check with a dependency none
// of its neighbours have (dest/worm-remedy.ts, the per-provider WORM vocabulary), and this file crossed
// the 1000-line budget when that vocabulary landed. Re-exported here so every importer and every citation
// pinned at this module keeps working.
export { buildImmutability } from "./posture-checks-immutability.ts";

// dest-cred-encryption (medium, ISO A.8.24 / A.8.13): are console-set destination credentials encrypted
// at rest under a key in the Secrets Store, or held on the platform-encryption-only plaintext floor? The
// slice is OPTIONAL: absent (an older caller) raises no check. With no destinations and no wrap key there
// is nothing to protect (skip). Otherwise PASS when the key is set and no plaintext record remains; WARN
// when the key is unset (set it) or a plaintext record is awaiting migration (re-save the destination).
export function buildDestCredEncryption(input: PostureInput): CheckDraft | null {
  const e = input.destCredEncryption;
  if (e === undefined || !(e.total > 0 || e.wrapKeyConfigured)) return null;
  const failed = !e.wrapKeyConfigured || e.plaintextCount > 0;
  return {
    id: "dest-cred-encryption",
    title: "Destination credentials encrypted at rest",
    control: "ISO A.8.24",
    auto: failed ? "fail" : "pass",
    how: "Checks CONFIG_WRAP_KEY presence and counts stored destination credentials that are not yet wrapped in the at-rest envelope. Only raised when there is something to protect.",
    detail: !e.wrapKeyConfigured
      ? "Console-set destination credentials are stored on the Durable Object plaintext floor (protected by the platform's own at-rest encryption only). Setting CONFIG_WRAP_KEY envelope-encrypts them with AES-256-GCM under a key held in your Secrets Store, so a read of Durable Object storage alone no longer discloses them and their confidentiality roots in the same store as the signer key."
      : e.plaintextCount > 0
        ? `Destination credentials are envelope-encrypted at rest, but ${e.plaintextCount} stored destination${e.plaintextCount === 1 ? "" : "s"} still hold${e.plaintextCount === 1 ? "s" : ""} a pre-encryption plaintext credential. Re-saving the destination migrates it to the encrypted floor.`
        : "Console-set destination credentials are envelope-encrypted at rest (AES-256-GCM) under a key held in your Secrets Store; the Durable Object holds only ciphertext.",
    remediation: !e.wrapKeyConfigured
      ? "Generate a 32-byte key and set it as the CONFIG_WRAP_KEY secret, then re-save each destination so its credential is wrapped. See docs/OPERATIONS.md."
      : e.plaintextCount > 0
        ? "Re-save the listed destination(s) from the Destinations screen to migrate the credential into the at-rest envelope."
        : "No action required; destination credentials are encrypted at rest.",
  };
}

// EMERGENCY_CHANGE_CHECK_ID is the stable id of the emergency-change-review check. Exported so the DO can
// un-accept it on a fresh emergency change (a new emergency invalidates a prior acknowledgement) and so the
// check builder, CHECK_SEVERITY and the DO reference one string. It matches POSTURE_ID_PATTERN.
export const EMERGENCY_CHANGE_CHECK_ID = "emergency-change-review";

// emergency-change-review (medium, ITIL Change Management / ISO 27001 A.8.32): the COMPLIANCE FLAG for the
// OWNER-OPT-IN "Require Change Number" policy. It is NOT APPLICABLE (null, omitted) when the policy is off
// (no emergency change is possible). When the policy is on it PASSES with no emergency change on record, and
// FAILS (a medium warning) once one or more EMERGENCY CHANGES have been recorded (a deliberate bypass of the
// change-number requirement), prompting the operator to confirm each has a retrospective change approval /
// record in place. Acknowledged by risk-accepting the check; a SUBSEQUENT emergency change clears that
// acknowledgement at the DO, so the flag re-raises for re-review (correct ITIL semantics). Redaction-safe: a
// count + a date, never a value. The per-change detail lives in the change-requests report + the audit log.
export function buildEmergencyChangeReview(input: PostureInput): CheckDraft | null {
  const cm = input.changeManagement;
  if (cm === undefined || !cm.required) return null; // not applicable: the policy is off
  const count = cm.emergencyCount > 0 ? cm.emergencyCount : 0;
  const failed = count > 0;
  const when = cm.emergencyLastAt !== undefined ? cm.emergencyLastAt.slice(0, 10) : null;
  return {
    id: EMERGENCY_CHANGE_CHECK_ID,
    title: "Emergency change review",
    control: "ITIL Change Management / ISO 27001 A.8.32",
    auto: failed ? "fail" : "pass",
    how: "Only applicable when the Require Change Number policy is on. Reads the cumulative emergency-change tally; recording a new emergency change clears any prior acknowledgement so the review re-raises.",
    detail: failed
      ? `${count} emergency change${count === 1 ? "" : "s"} recorded${when ? ` (most recent ${when})` : ""}; each bypassed the change-number requirement.`
      : "Change numbers are required for change-controlled actions and no emergency changes have been recorded.",
    remediation:
      "Validate each emergency change has a retrospective change approval / record (e.g. an ECAB ratification) in place (see the Change requests report), then risk-accept this check to acknowledge it. A later emergency change re-raises it for re-review.",
  };
}

export const ATTENDED_CADENCE_CHECK_ID = "attended-verification-cadence";

// attended-verification-cadence (medium): whether every downpipe with a completed run has a FULL proven
// ATTENDED verification inside the estate's stated interval.
//
// It exists because on a break-glass-only estate the engine holds no key to reopen a run it sealed earlier,
// so attended verification is what replaces unattended proof, and until this landed the only thing that knew
// when it was due was a preference in one browser.
//
// NOT APPLICABLE (null, omitted) when no cadence is stated. An estate that has not chosen an interval has no
// obligation, and manufacturing one would turn a silent browser preference into a live finding for every
// existing customer at once. It is also omitted when the operational key is present: that
// posture proves restorability unattended, which is what restore-test-recency already grades, so a second
// finding about an attended rhythm nobody needs would be noise.
//
// NEVER-VERIFIED is reported SEPARATELY from OVERDUE, and never as the same sentence. A recovered estate
// restores its cadence through the control-plane export but not its proof history, so an estate that has just
// been rebuilt is never-verified rather than overdue, and telling that operator they have LAPSED would be
// both wrong and unhelpable in the hour it lands.
//
// It is a "fail" in the tri-state sense (the platform observed the control not satisfied and the operator can
// fix it) at MEDIUM severity, never critical: a lapsed proof rhythm is an assurance obligation, not a failure
// of the backup, and nothing here gates any work (design section 4).
export function buildAttendedCadence(input: PostureInput, now: number): CheckDraft | null {
  const cadenceDays = typeof input.attendedCadenceDays === "number" && input.attendedCadenceDays > 0 ? Math.floor(input.attendedCadenceDays) : 0;
  if (cadenceDays === 0) return null;
  if (input.operationalPrivatePresent) return null;

  const summary = evaluateAttendedCadence(input.downpipes, cadenceDays, now);
  const overdue = summary.overdue;
  const never = summary.neverVerified;
  const failed = overdue.length > 0 || never.length > 0;
  const graded = input.downpipes.length - summary.excluded.length;

  // The detail names the two states apart, and names the downpipes (the customer's own redaction-safe
  // config), capped so a large estate does not produce an unreadable finding.
  const namesOf = (v: typeof overdue): string => {
    const shown = v.slice(0, 3).map((x) => x.name);
    return v.length > 3 ? `${shown.join(", ")} and ${v.length - 3} more` : shown.join(", ");
  };
  const parts: string[] = [];
  if (overdue.length > 0) parts.push(`${overdue.length} past the ${cadenceDays}-day interval (${namesOf(overdue)})`);
  if (never.length > 0) parts.push(`${never.length} never attended-verified (${namesOf(never)})`);

  return {
    id: ATTENDED_CADENCE_CHECK_ID,
    title: "Attended verification cadence",
    control: "ISO 27001 A.8.13 / NIST SP 800-34",
    auto: failed ? "fail" : "pass",
    how: `Applies only when an attended-verification interval is stated and the engine holds no operational key. Reads each downpipe's newest FULL proven attended verification and compares its age with the ${cadenceDays}-day interval; a downpipe with no completed run is excluded, because there is no sealed archive to verify yet.`,
    detail: failed
      ? `${parts.join("; ")}, of ${graded} downpipe${graded === 1 ? "" : "s"} with a completed run.`
      : graded === 1
        ? `The one downpipe with a completed run has a full attended verification inside the ${cadenceDays}-day interval.`
        : `All ${graded} downpipes with a completed run have a full attended verification inside the ${cadenceDays}-day interval.`,
    remediation:
      "Run an attended verification at 100% for each named downpipe (Restore, Attended verification), supplying your break-glass key in the browser, or a quorum of shares if you hold it split. If the interval no longer matches how often you can convene, change it rather than leaving a stated rhythm you do not keep.",
  };
}

// update-apply-provenance (low, SLSA v1 / NIST SSDF PS.3): whether the most recent APPLIED
// engine update left durable content-hash evidence -- the signed channel digest persisted on the settled
// record (and, when the read-back gate ran, the platform-returned digest beside it). NOT APPLICABLE
// (null, omitted) until an engine update has settled through the channel at all: a wrangler-deployed
// install that has never applied a channel release has no update evidence to grade, and must not be
// nagged for a control it has had no opportunity to exercise. "cannot-verify" (needs attestation, never
// a red failure) when the record predates the evidence fields: the operator clears it by applying the
// next release through the update flow. Redaction-safe: booleans over public digests.
export function buildUpdateApplyProvenance(input: PostureInput): CheckDraft | null {
  const u = input.updateIntegrity;
  if (u === undefined || u.lastEngineOutcome === undefined) return null; // not applicable: no channel apply has ever settled here
  const evidenced = u.lastAppliedDigestPresent === true;
  const readback = u.readbackVerdict;
  return {
    id: "update-apply-provenance",
    title: "Update apply left content-hash evidence",
    control: "SLSA v1 provenance / NIST SSDF PS.3",
    auto: evidenced ? "pass" : "cannot-verify",
    how: "Reads the last settled engine update record: the signed channel digest (artefactSha384) persisted at apply time, and the read-back verdict when the post-upload gate ran. Recomputed live on every read.",
    detail: evidenced
      ? `The last applied engine update carries the signed channel digest${readback !== undefined ? `; read-back ${readback}` : ""}, so which bytes went live is durably provable.`
      : "The last settled engine update predates content-hash evidence (no digest on the record); which exact bytes went live is only provable back to the opaque platform version id.",
    remediation: evidenced
      ? "No action required; each future apply records its digest and read-back verdict automatically."
      : "Apply the next release through the update flow (Licence and updates); the apply records the signed digest and the read-back verdict on the settled record automatically.",
  };
}

// update-version-drift (medium, ISO 27001 A.8.32 change management / Essential Eight patching): whether
// the RUNNING deployment is still the one the last verified update flow left live. The engine compares
// its own version_metadata id (the isolate's immutable deploy identity) against the expectation from the
// last settled engine outcome (applied -> the promoted version id; rolled-back -> the reverted-to id).
// A mismatch means the Worker was redeployed OUTSIDE the verified flow (a wrangler deploy, a dashboard
// edit, or an unexpected actor) since that settle: legitimate operations do this deliberately (and then
// this check is the honest reminder that the running bytes are no longer the verified ones), an attacker
// does it silently -- either way it must not pass unremarked. NOT APPLICABLE (null) until a channel
// apply has settled; "cannot-verify" when the version_metadata binding is absent. Identifiers only.
export function buildUpdateVersionDrift(input: PostureInput): CheckDraft | null {
  const u = input.updateIntegrity;
  if (u === undefined || u.expectedLiveVersionId === undefined) return null; // not applicable: no verified apply to hold the deployment against
  if (u.liveVersionId === undefined) {
    return {
      id: "update-version-drift",
      title: "Running version matches the last verified apply",
      control: "ISO 27001 A.8.32 / Essential Eight patch verification",
      auto: "cannot-verify",
      how: "Compares the running isolate's version_metadata id against the version the last settled engine update left live. Recomputed live on every read.",
      detail: "The version_metadata binding is not available on this deployment, so the running version id cannot be compared to the last verified apply.",
      remediation: "Add the [version_metadata] binding (binding = \"CF_VERSION_METADATA\") to wrangler.toml and redeploy, or apply the next release through the update flow which re-establishes the expectation.",
    };
  }
  // The acceptable set (review findings #1/#3): the settled expectation, plus every id the update
  // flow itself currently has legitimately live (both slices of a still-partial ramp; a promoted-but-
  // unsettled pending). A deliberate split must never read as an out-of-band redeploy.
  const alternates = Array.isArray(u.alternateLiveVersionIds) ? u.alternateLiveVersionIds : [];
  const primaryMatch = u.liveVersionId === u.expectedLiveVersionId;
  const alternateMatch = !primaryMatch && alternates.includes(u.liveVersionId);
  const matches = primaryMatch || alternateMatch;
  return {
    id: "update-version-drift",
    title: "Running version matches the last verified apply",
    control: "ISO 27001 A.8.32 / Essential Eight patch verification",
    auto: matches ? "pass" : "fail",
    how: "Compares the running isolate's version_metadata id against the versions the update flow currently has legitimately live: the last settled outcome's version, both slices of a still-partial ramp, and a promoted-but-unsettled pending. Recomputed live on every read.",
    detail: primaryMatch
      ? "The running deployment is the one the last verified update flow left live."
      : alternateMatch
        ? "The running deployment is one of the versions the update flow currently has live (a gradual ramp still serving its split, or a promoted update awaiting verification); not a drift."
        : "The running deployment is NOT a version the update flow has live: the Worker was redeployed outside the update flow since the last apply (a wrangler deploy, a dashboard edit, or an actor to identify).",
    remediation: matches
      ? "No action required."
      : "If the out-of-band deploy was deliberate (for example a wrangler deploy from source), apply the next release through the update flow to re-establish verified state, or risk-accept this check with the reason recorded. If it was not deliberate, treat it as an incident: review the Cloudflare audit log for the deploy actor.",
  };
}
