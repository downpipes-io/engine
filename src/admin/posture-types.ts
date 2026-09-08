// Posture INPUT-SHAPE types (extracted from posture.ts for file-size hygiene + to break an import cycle,
// finding engine-src-011-01). These are the redaction-safe observable slices computePosture reads. They
// live in a leaf module so both posture.ts (the computation + public API) and posture-checks.ts (the
// per-check builders) can import them without a back-edge; posture.ts re-exports them so every importer
// keeps importing from "./posture.ts" unchanged. No I/O, no secret: presence/count/recency projections.

import type { RestoreProvenMethod } from "../sched/types.ts";

// PostureDownpipeInput is the per-downpipe slice computePosture reads: the id + name (redaction-safe),
// the restore-test recency/outcome, the restore-test cadence (0/absent = off), and whether the downpipe
// has completed a run yet. All optional fields are honestly absent when the downpipe has never had that
// event. No secret.
export interface PostureDownpipeInput {
  id: string;
  name: string;
  // destinationCount is how many DISTINCT destinations this downpipe is pinned to (3-2-1 fan-out):
  // 0 or absent = it follows the default = one effective copy (not redundant); >=2 = a source written
  // to two places (the redundant-copies check). The platform can VERIFY this; media-type diversity it
  // cannot (cloud-only), so that is the separate operator-attested media-diversity check.
  destinationCount?: number;
  restoreTestCadenceSeconds?: number; // 0 or absent = off
  lastRestoreTestAt?: number; // epoch ms of the last scheduled restore test
  lastRestoreTestOk?: boolean; // outcome of that test
  // restoreProvenAt / restoreProvenMethod project the durable "offline restorability last proven" stamp
  // (DownpipeState.restoreProven, sched/types.ts) so the restore-test-recency check can credit a KEYED
  // attended verification that SURVIVES a scheduled-cron deferral. A break-glass-only estate (no in-account
  // OPERATIONAL_PRIVATE) can never self-run the scheduled drill, so it defers every cadence tick, which
  // otherwise clobbers lastRestoreTestOk back to false forever -- "the check they can never pass". Only the
  // FULL keyed method (restoreProvenMethod === "attended-blind-test") ever credits the check: a blind-test
  // proof carries no sample rate or scope (RestoreProven has no such field), so it cannot be told apart from
  // a partial sample once stamped, and a keyless-attest proof performs no decryption at all, so neither
  // satisfies a check whose meaning is "a real decrypt-and-verify happened recently" (see the check for the
  // full predicate). Both honestly absent when the downpipe has never been proven. Redaction-safe: an
  // epoch-ms timestamp and a closed enum, never a key.
  restoreProvenAt?: number;
  restoreProvenMethod?: RestoreProvenMethod;
  // lastRestoreTestDeferred is the discriminator that makes crediting restoreProvenAt SAFE. It distinguishes
  // a DEFERRAL (the engine could not run the scheduled drill: no completed run yet, or break-glass-only
  // posture) from a GENUINE not-ok completion (a real restore-test failure). completeRestoreTest sets this
  // ONLY on a deferral and clears it on a pass or a genuine failure (stampRestoreTested, the manual/blind/
  // keyless path, never sets it either), so its ABSENCE on a not-ok completion reliably means "this was real
  // failure evidence, not a deferral". The recency check falls back to the durable restoreProven credit ONLY
  // when the ordinary recency is honestly absent or deferred; a genuine failure newer than the proof always
  // stays an offender, however affirmative an older proof was (a confirmed defect in an earlier draft of this
  // feature would otherwise sign a false PASS into the compliance pack -- see the check for the full note).
  // Closed two-value kind, never a message.
  lastRestoreTestDeferred?: "no-run" | "posture" | "no-records";
  // lastRunId is the id of this downpipe's last SUCCESSFUL run (DownpipeState.lastRunId; absent = the
  // downpipe has never completed a run, so there is no sealed archive to restore-test yet). The
  // restore-test-recency check GATES on its presence: a downpipe that has never completed a run is not
  // failed for "no successful restore test" (there is nothing to test until its first run), exactly the
  // has-a-run predicate the restore-test scheduler itself uses (restoreTestsDue: d.lastRunId !== null).
  // It is the run's OPAQUE id, redaction-safe (the same id carried in downpipe-alert webhooks), never a
  // key or value. A prior shape here carried a `lastRunAt` epoch that DownpipeState never held and
  // gatherPostureState never projected, so the gate was always empty and the critical check always
  // passed however stale the tests were; the recency itself is graded off
  // lastRestoreTestAt/Ok above, which the DO does project.
  lastRunId?: string;
  // Verify-at-seal: the latest verify-at-seal verdict for this downpipe. lastSealVerifyOk
  // is the outcome of reading the just-written archive back and verifying it after the last run on
  // which verify-at-seal ran (true = verified, false = suspect); lastSealVerifyAt is its epoch-ms time.
  // Both are honestly absent when the downpipe has never run with the feature on, in which case the
  // seal-verification check passes silently (there is no suspect verdict to surface).
  lastSealVerifyOk?: boolean;
  lastSealVerifyAt?: number;
}

// PostureWormInput is the WORM / Object-Lock slice (the immutability check). It is the OBSERVABLE
// state the router gathers: whether a WORM policy is CONFIGURED at all, whether that config is
// MISCONFIGURED (intended but invalid, fail-safe to a warning, never a green claim), the policy's
// mode/days when valid, and the live CAPABILITY PROBE result for the default destination's bucket
// (does the bucket actually ENFORCE Object-Lock). This is what lets the check report REAL WORM status
// instead of inferring it from delete permission. Shaped with inline literals so posture.ts stays
// dependency-free (it mirrors dest/types.ts WormStatus/WormMode without importing them).
//   configured        : a WORM policy is intended (env DEST_WORM_* set, or a console-set policy).
//   misconfigured     : configured but invalid (e.g. only one knob set, bad mode, non-positive days).
//   mode/retentionDays: the valid policy being applied (present only when configured && !misconfigured).
//   bucketEnforces    : the probe verdict, true (bucket enforces Object-Lock), false (bucket was not
//                       created with it; the warning case), "unknown" (could not confirm: no probe, an
//                       unparseable response, or a transport fault, the safe cannot-confirm reading).
//   probeMode/probeDays: the bucket's DEFAULT retention rule from the probe, when it reports one.
//   provider          : which STORE the default destination is, derived from its endpoint host
// (providerForEndpoint). It decides the REMEDY, and until one
//                       Amazon-shaped sentence was offered to all four: Azure's mechanism is
//                       version-level immutability, Google Cloud's is a bucket created with per-object
//                       retention, and R2 has no mechanism at all by any route (dest/worm-remedy.ts
//                       carries the 501 measurement). Honestly absent when no destination could be
//                       resolved, in which case the check falls back to the S3 wording.
//   defaultRetention  : whether the LOCK-ENABLED bucket carries a default retention rule at all. Set only
//                       when bucketEnforces is true; honestly absent otherwise (cannot-confirm, never
//                       false). ObjectLockEnabled does NOT mean anything is retained, so a lock-enabled
//                       bucket with no default rule retains nothing unless a valid policy arms a per-object
//                       retention header. The signed immutability report conditions its strongest claim on
//                       this (reports.ts); it is the same field probeDestination and the dest-verify fault
//                       ledger already carry, derived the same way.
// All optional fields are honestly absent when not observed; nothing here is a secret.
export interface PostureWormInput {
  configured: boolean;
  misconfigured: boolean;
  mode?: "governance" | "compliance";
  retentionDays?: number;
  bucketEnforces?: boolean | "unknown";
  probeMode?: "governance" | "compliance";
  probeDays?: number;
  defaultRetention?: boolean;
  // Inline literal rather than the DestProvider import, matching the rest of this file: the slice
  // crosses the DO boundary and posture-types.ts stays free of a dest dependency.
  provider?: "r2" | "s3" | "gcs" | "azure";
}

// PostureExpiryInput is the expiry slice: only the coarse state per tracked item is needed to decide
// the credential-expiry check (any approaching or expired item fails it). The label is carried so the
// detail can name the first offending item (the operator's own redaction-safe description).
export interface PostureExpiryInput {
  label: string;
  // "no-expiry" is a deliberate state (a credential that does not expire), not an impending lapse, so
  // the offenders filter (which matches only approaching/expired) never flags it. Carried in the union
  // so the scheduler-DO builder can map ExpiryStatus.state through without a narrowing cast. A later
  // wave also exempts an ephemeral pending-cleanup item from the FAIL (a hygiene nudge, not an expiry).
  state: "ok" | "approaching" | "expired" | "no-expiry";
  // lifecycleClass lets the credential-expiry check EXEMPT an ephemeral spent token (a hygiene nudge,
  // not a backup-breaking expiry); a functional credential/cert/licence still fails. cleanupState is
  // carried for completeness (the ephemeral exemption keys off lifecycleClass).
  lifecycleClass?: "ephemeral" | "functional";
  cleanupState?: "pending" | "attested-deleted";
}

// PostureOverrideKind is the closed set of owner-set override kinds for a check (the customer's own
// grading of a control the platform graded fail, or could not verify):
//   risk-accepted        : the owner deliberately accepts the risk (counts as pass for the score, listed
//                          as an accepted risk, never presented as a pass).
//   attested-pass        : the owner attests the control IS satisfied by means the platform cannot
//                          observe (e.g. MFA enforced at an external IdP). Presented as a pass, labelled
//                          as a customer attestation, with the owner's stated reason.
//   compensating-control : the owner states a compensating control is in place that satisfies the
//                          intent. Presented as a pass, labelled, with the description carried through.
//   not-applicable       : the owner determines the control does not apply to this deployment. Excluded
//                          from the score entirely (neither numerator nor denominator) and shown as N/A.
// Every kind requires a bounded reason; all are owner-only, change-controlled and audit-logged.
export type PostureOverrideKind = "risk-accepted" | "attested-pass" | "compensating-control" | "not-applicable";

// PostureOverrideInput is the per-check override slice computePosture folds: the kind, the owner's
// reason, who set it and when (projected from the stored record). Redaction-safe free text + metadata.
export interface PostureOverrideInput {
  kind: PostureOverrideKind;
  reason: string;
  setBy: string | null;
  setAt: string; // RFC-3339
}

// PostureIdentityInput is the DO-owned identity slice for the admin-strong-auth check: how many
// admin-capable identities exist (Owners + access-admins), how many of those have at least one enrolled
// passkey, and how many IdP connections are enabled (an enabled IdP means sign-in can happen upstream,
// where MFA enforcement is invisible to the platform). Counts only; no email, subject or key. OPTIONAL
// on the input: absent (a gather fault) degrades to the honest cannot-verify reading, never a verdict.
export interface PostureIdentityInput {
  adminIdentities: number;
  adminsWithPasskey: number;
  idpConnectionsEnabled: number;
}

// PostureInput is the complete, redaction-safe observable state computePosture reads (contract section
// 7). It is built by the DO from the same presence/count/recency projections the rest of the admin
// surface uses; it carries no secret, key, value or fingerprint.
//   status:               the onboarding StatusReport (presence booleans + dest kind), shaped loosely
//                         here so posture.ts has no import cycle with status.ts.
//   downpipes:            the per-downpipe recency slice.
//   expiry:               the per-item coarse expiry state.
//   notifyFailureRuleSet: whether ANY enabled notify rule selects backup-failure (the failure-alerts
//                         check). Computed in the DO from the rules; a single boolean here.
//   ownerCount:           the number of Owners (the two-owners availability check).
//   operationalPrivatePresent: whether the in-account read-back key is configured (a deliberate
//                         no-custody weakening, surfaced; also gates whether restore tests can self-run).
//   beaconEnabled:        whether the vendor beacon is enabled (the no-custody beacon-off check).
//   overrides:            the per-check owner-set override records (kind + reason + who/when), keyed by
//                         check id. A legacy record with no kind reads as risk-accepted.
export interface PostureInput {
  status: {
    destConfigured: boolean;
    breakGlassConfigured: boolean;
    operationalConfigured: { public: boolean; private: boolean };
    tokenFallbackDisabled: boolean;
    // Break-glass disposal slice (dispose-bootstrap-token check). adminTokenPresent is the env presence of
    // ADMIN_TOKEN (the break-glass bearer). bootstrapConsumed is the DO latch that the first Owner has been
    // claimed. breakGlassTokenRetired is the DO latch that the Owner has retired the token in-app. The check
    // fails only when the bootstrap is complete AND the token is still EFFECTIVE (present and neither
    // env-disabled nor retired), i.e. anyone holding the string could still take admin. All three default to
    // the SAFE reading (false) when absent, so a malformed/partial call never fabricates the failing finding.
    adminTokenPresent: boolean;
    bootstrapConsumed: boolean;
    breakGlassTokenRetired: boolean;
    // recoveryBreakGlassReady (DO-owned) is true when an ongoing admin break-glass is in place: recovery
    // codes have been generated/acknowledged for at least one Owner OR a second Owner exists. The dispose-
    // bootstrap-token finding only PROMPTS disposal (fails) when disposal is SAFE (this is true), so the
    // Security Centre never tells an operator to dispose of the token while doing so would strand the tenant.
    // Defaults to the SAFE reading (false = not ready) when absent, so a malformed/partial call never claims
    // disposal is safe when it is not.
    recoveryBreakGlassReady: boolean;
  };
  downpipes: PostureDownpipeInput[];
  expiry: PostureExpiryInput[];
  notifyFailureRuleSet: boolean;
  ownerCount: number;
  operationalPrivatePresent: boolean;
  // recipientPinDrift compares the recipient fingerprints the engine seals to against the set the last
  // SIGNED control-plane export recorded. Computed by the export cron (the recipient publics are env
  // bindings the DO cannot read) and carried on the export health record. null when no export has recorded
  // one yet, which is reported as cannot-verify rather than a pass.
  recipientPinDrift: { matches: boolean; added: number; removed: number } | null;
  beaconEnabled: boolean;
  overrides: ReadonlyMap<string, PostureOverrideInput>;
  // identity (OPTIONAL) is the DO-owned identity slice for the admin-strong-auth check (counts only, see
  // PostureIdentityInput). Absent (a gather fault or an older caller) => the check reports the honest
  // cannot-verify state rather than fabricating a verdict.
  identity?: PostureIdentityInput;
  // recoveryCodesRemaining (DO-owned) is the count of UNCONSUMED recovery codes for the CALLER'S OWN email
  // (the DO scopes it to the verified caller; another user's count is never exposed). It drives the
  // recovery-codes-low finding (warn at <= 2 remaining or 0). It is OPTIONAL: a caller with no email (the
  // bare-token break-glass) has no per-email count, so it is absent and the low finding is not raised for
  // that caller (the token caller has no codes by design).
  recoveryCodesRemaining?: number;
  // worm (OPTIONAL) is the WORM / Object-Lock observable state for the immutability check, gathered by the
  // router (env policy + live capability probe of the default destination). When ABSENT (an older caller
  // that does not supply it, or no destination to probe), the immutability check reports the honest
  // "not configured" informational state rather than fabricating a verdict. See PostureWormInput.
  worm?: PostureWormInput;
  // destCredEncryption (OPTIONAL) is the at-rest-encryption observable for console-set destination
  // credentials: wrapKeyConfigured is the router's env fact (CONFIG_WRAP_KEY present), plaintextCount and
  // total are DO-owned (how many stored destinations still hold a plaintext credential, of how many).
  // ABSENT (an older caller) => the check is not raised. See the dest-cred-encryption block.
  destCredEncryption?: { wrapKeyConfigured: boolean; plaintextCount: number; total: number };
  // changeManagement (OPTIONAL) is the OWNER-OPT-IN "Require Change Number" observable for the
  // emergency-change-review check: required is the policy flag (requireChangeNumber), emergencyCount + the
  // optional emergencyLastAt (RFC-3339) are the DO-owned emergency-change marker. ABSENT, or required=false,
  // => the check is not applicable (the policy is off) and is not raised. No secret: a flag + a count + a date.
  changeManagement?: { required: boolean; emergencyCount: number; emergencyLastAt?: string };
  // attendedCadenceDays (OPTIONAL) is the estate-wide attended-verification interval in whole days, or 0 /
  // absent when the operator has not stated one. It feeds the attended-verification-cadence check.
  //
  // Absent and 0 mean the SAME thing here and both are honest: no rhythm stated. They must never read as a
  // zero-day cadence, or every estate that has not chosen one would show as permanently overdue the moment
  // the field shipped. One integer, no secret.
  attendedCadenceDays?: number;
  // selfBackup (OPTIONAL) is the observable for the environment-self-backup check: whether Downpipes' OWN
  // control-plane export (the signed, no-custody artefact that lets the environment be rebuilt after a loss)
  // is healthy. exportPresent = an export has been written at least once; allDestinationsWrote = the last
  // export pass wrote to every destination it attempted (no per-dest fault); autoHealRefused = the auto-heal
  // recorded it could not safely auto-apply a recovery; recoveryRequired = the silence-killer latch is set
  // (the plane was wiped and not yet recovered). ABSENT (no destination configured, or no downpipes yet, so
  // there is nothing to back up) => the check is not applicable and is not raised. No secret: booleans only.
  selfBackup?: { exportPresent: boolean; allDestinationsWrote: boolean; autoHealRefused: boolean; recoveryRequired: boolean };
  // updateIntegrity (OPTIONAL) is the update-lifecycle observable for the two supply-chain
  // checks. lastEngineOutcome is the last settled ENGINE outcome ("applied"/"rolled-back"/...; absent =
  // no channel apply has ever settled here, both checks not applicable). expectedLiveVersionId is the
  // Cloudflare version id that outcome left live (applied -> the promoted id, rolled-back -> the
  // reverted-to id); liveVersionId is the running isolate's own version_metadata id (router-forwarded;
  // the DO cannot read env). lastAppliedDigestPresent says whether the last APPLIED engine record
  // carries the signed channel digest; readbackVerdict is that record's read-back verdict when the gate
  // ran. ABSENT (an older caller) => neither check is raised. Identifiers and booleans only.
  // alternateLiveVersionIds lists ids that are ALSO legitimately live right now: the prior slice of a
  // ramp-settled split still serving its percentage, and the promoted/prior versions of an unsettled
  // pending. The drift check passes on any of them (with the split named in the detail) so a deliberate
  // ramp or an in-flight apply never reads as an out-of-band redeploy.
  updateIntegrity?: { lastEngineOutcome?: string; expectedLiveVersionId?: string; alternateLiveVersionIds?: string[]; liveVersionId?: string; lastAppliedDigestPresent?: boolean; readbackVerdict?: string };
}

// CheckAuto and CheckDraft live here, not in posture-checks.ts, for the same reason as the input-shape
// types above: posture-checks-immutability.ts needs CheckDraft's shape but must not import it back from
// posture-checks.ts (that closed the two madge cycles admin/posture-checks.ts > admin/posture-checks-
// immutability.ts and admin/posture.ts > admin/posture-checks.ts > admin/posture-checks-immutability.ts,
// both introduced when the immutability check was split out into its own file). posture-checks.ts re-exports
// both so its existing importers keep importing from there.

// CheckAuto is the automatic (platform-computed) outcome of a check, before any owner override is folded.
export type CheckAuto = "pass" | "fail" | "cannot-verify";

// CheckDraft is the redaction-safe content of one finding BEFORE the push closure stamps the fixed
// severity and folds the owner-override set. id is the stable check id; auto is the raw computed outcome;
// how states, in one sentence, what is observed and how the verdict is reached (so an operator or an
// auditor can understand the determination without reading the source). Every check is recomputed live on
// every read of the posture (and on the scheduled evaluation), so `how` never needs a freshness claim.
export interface CheckDraft {
  id: string;
  title: string;
  control: string;
  auto: CheckAuto;
  detail: string;
  remediation: string;
  how: string;
}
