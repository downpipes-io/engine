// Part 1 of the SchedulerDO's shared TYPE + CONSTANT vocabulary. This leaf declares the governance +
// run + notify/expiry + discovery/licence/update at-rest record shapes (OrgPolicy, MutationCaller,
// DestReplState, ReplRecordReq, CompleteRunReq, GroupRoleEntry, the alert/expiry cooldown + emission
// shapes, RateWindow, DiscoveryConfig, LicenceTokenRecord, the Update* records, ...) and the storage-key
// prefixes, bounds and caps those domains key on (the drill-evidence / group-role / custom-role / alert
// / repl-alert / success-notify / notify-digest / org-policy / discovery / dest / canary / licence /
// update / demo prefixes + keys, the group/reason/note bounds, and the lease/cooldown/window
// constants). It is a pure leaf (no `this`, no DO state) that base.ts re-exports verbatim. The sibling
// scheduler-do-limits.ts holds the destination config types and the rate-limit/recovery/list/due/audit
// limits. A leaf the base depends on, never the reverse.

import type { WrappedSecret } from "../admin/config-secret.ts";
import type { AuthMethod, Capability, Role } from "../admin/identity.ts";
import type { OpCounts } from "../meter.ts";
import type { AlertState, Severity } from "../notify.ts";
import type { IncompleteByMarker, IncompleteIds } from "../seal/marker.ts";
import type { SealVerification } from "./types.ts";

// OrgPolicy is the single account-wide governance-policy record (DO key ORG_POLICY_KEY). It carries the
// OPT-IN dual-control change-control gate flag. An ABSENT record (or an absent field) reads as the
// default OFF, so a tenant that never touches the setting behaves byte-identically to before (no friction).
// It holds no secret and no key material, like the role/group tables.
export interface OrgPolicy {
  // requireConfigApproval: when true, a config mutation is validated then QUEUED as a pending change a
  // second identity must approve (maker != checker) before it applies; when false (the default), every
  // config mutation applies inline exactly as before. Toggled OWNER-ONLY, and applied IMMEDIATELY IN THE ARM
  // DIRECTION ONLY (which is what stops the gate deadlocking its own off switch). An attributable owner's
  // DISARM is queued for a second owner as the "dual-control-disable" owner action; only a bare-token
  // break-glass owner disarms immediately, because it cannot propose or approve owner actions at all. See the
  // asymmetric off-switch block on POST /config/approval-policy, which is where the behaviour actually lives.
  requireConfigApproval: boolean;
  // bootstrapConsumed: set true the MOMENT the FIRST Owner row is created (the whoami empty-table bootstrap
  // OR the passkey bootstrap), and never cleared from the app. It is a belt-and-braces latch OVER the
  // empty-table check: once a first Owner has ever been claimed, NO bootstrap may create another Owner even
  // if the role table later becomes empty. OPTIONAL so a pre-existing record (or a never-bootstrapped
  // tenant) reads the default false; getBootstrapConsumed treats absent as false. It holds no secret.
  bootstrapConsumed?: boolean;
  // requireChangeNumber: the OWNER-OPT-IN "Require Change Number" change-management policy (default OFF).
  // When true, a CAB-worthy change-controlled action (every owner action + a restore apply) requires the
  // operator to attach a CHANGE REFERENCE (a CR number, or an Emergency Change + justification) which the
  // engine validates and records as a change-recorded audit event; an emergency change is flagged in the
  // compliance posture and the change-requests report. OPTIONAL so an absent record (or a tenant that never
  // enabled it) reads the default false (getRequireChangeNumber), byte-identical to before. It is a process/
  // compliance control, NOT a security control, and holds no secret. Toggled OWNER-ONLY, applied immediately.
  requireChangeNumber?: boolean;
  // requireRestoreApproval: the OWNER-OPT-IN dual-control gate over a RESTORE APPLY. When true, an apply
  // over live data additionally requires a SECOND authorised identity's approval, bound to the exact plan
  // hash, with maker != checker. When false or absent (the DEFAULT) the apply proceeds on the acting
  // identity alone, still dry-run gated, step-up gated, plan-bound and fully audited.
  //
  // IT DEFAULTS OFF: an unconditional gate would lock solo estates out of restore entirely. canApprove
  // refuses a same-subject AND a same-email approval, so one human can never approve
  // their own request; with no policy check on the apply path, a one-person estate could plan a restore and
  // never apply it. The product already calls that estate valid: BASE_MIN_OWNERS is 1 while config dual
  // control is off (owner-floor.ts). So a supported configuration could not reach the product's core promise.
  //
  // ARMING IS GUARDED, DISARMING IS NOT SYMMETRIC. Arming is refused unless the estate holds two distinct
  // approver-capable identities, because arming while solo would re-create the very lockout this field
  // exists to fix. Disarming is queued for a second owner exactly as the config gate's is, which is safe
  // precisely because the arm guard means only a multi-identity estate could have armed it.
  requireRestoreApproval?: boolean;
  // attendedCadenceDays: the estate-wide interval, in whole days, within which every downpipe with a
  // completed run is expected to have a FULL proven ATTENDED verification. It exists because on a
  // break-glass-only estate the engine holds no key to reopen a
  // run it sealed earlier, so attended verification is what replaces unattended proof, and until now the only
  // thing that knew when it was due was a preference in one browser.
  //
  // OPTIONAL, and absent means NO CADENCE SET rather than a cadence of zero. That distinction is load-bearing:
  // the field arriving switched on would turn a silent browser preference into a live obligation for every
  // existing estate at once, so unset behaves byte-identically to today and
  // evaluateAttendedCadence reads a non-positive value as "no obligation".
  //
  // It is an assurance/compliance control, not a security control: nothing gates on it, and lengthening it
  // weakens no boundary. It holds no secret (one integer).
  attendedCadenceDays?: number;
  // breakGlassTokenRetired: set true by the OWNER-ONLY POST /admin/policy/retire-break-glass-token. When
  // true the engine REFUSES the ADMIN_TOKEN bearer fallback exactly as if ADMIN_TOKEN_DISABLED were set, so
  // the operator can dispose of the one-time bootstrap token in-app with no redeploy. It is ONE-WAY FROM THE
  // APP: a retired token can never un-retire itself (the retire endpoint resolves to owner, and a retired
  // token no longer resolves to owner); only a passkey/Access Owner can flip it back, or a redeploy that
  // resets the DO (the flag lives in the DO, not in env). OPTIONAL: absent reads the default false
  // (getBreakGlassTokenRetired), so a tenant that never retired behaves byte-identically to before. No secret.
  breakGlassTokenRetired?: boolean;
  // controlPlaneRecoveryRequired (INFRA-1): set true when the control plane has been detected as EMPTY
  // while the destination bucket still holds runs (a SchedulerDO storage loss / amnesia), set by the cron
  // health pass or surfaced by the operator. While true it BLOCKS the silent Access/passkey re-bootstrap to
  // Owner (whoami reports recovery-required, not Owner), so a wiped control plane cannot silently re-open
  // first-Owner to whoever calls first; the bare-token break-glass is unaffected so the reconcile can run.
  // Cleared by a successful control-plane reconcile. OPTIONAL: absent reads false (no behaviour change). No secret.
  controlPlaneRecoveryRequired?: boolean;
  // controlPlaneRecoveryReason is the redaction-safe one-line reason the latch was set (e.g. "config empty
  // but the destination bucket has runs"), surfaced by the console recovery banner. Never a secret.
  controlPlaneRecoveryReason?: string;
  // notifyNewSignInContext (ASVS V6.3.5): the OWNER-OPT-IN "notify on a sign-in from a new location" policy
  // (default OFF). When true, a successful sign-in whose COARSE network context (IPv4 /24 or IPv6 /48 prefix)
  // is not in the account's recent per-operator baseline emits a sign-in-new-context notify. It runs in the
  // customer's OWN account against a bounded, coarse seen-set (no raw IP stored, no vendor custody). OFF by
  // default because mobile/NAT churn makes it noisy for some operators; it is opt-in per account. OPTIONAL so
  // an absent record (or a tenant that never enabled it) reads the default false (getNotifyNewSignInContext),
  // byte-identical to before. Toggled OWNER-ONLY, applied immediately. No secret.
  notifyNewSignInContext?: boolean;
}

// MutationCaller is the authority a gated config mutation runs as: the forwarded caller (method/email/
// subject/role/groups) PLUS an OPTIONAL resolved capability set. subject is the STABLE principal (ASVS
// V10.3.3 / V10.5.2) the DO re-resolves authority on (roleForCaller keys the role table on it), so a
// gated mutation re-checks the caller's CEILING against the immutable subject exactly as a non-gated route
// does; it must be carried through the gate or a custom-role caller would resolve to its viewer floor.
// capabilities is populated (from the DO's OWN roleForCaller, never a client value) ONLY for a CUSTOM-ROLE
// caller, so the by-role re-checks (callerHolds) honour exactly the proposer's resolved authority instead
// of refusing them on their "viewer" built-in floor (F6). For a built-in caller it is absent and the
// checks fall back to can(role, cap) unchanged. It is always the caller's OWN live-resolved set (re-resolved
// at apply time, bounded by the live ceiling via requireGrantWithinAuthority), never a widened or
// propose-time-frozen set.
// replay marks this caller as a RECORDED identity being re-resolved with no request of theirs in hand (the
// config-change apply's stored proposer, the owner action's). It is declared here because the flag has to
// survive the whole apply: roleForCaller honours it, and so does every requireCapabilityResolved re-check
// inside the replayed mutation, which reach roleForCaller through THIS type. It suppresses the two things a
// replay may not do (bind a pending grant by email, and skip the IdP connection-liveness re-read a live
// request cannot skip); absent, every live caller behaves byte-for-byte as before. See roleForCaller.
export interface MutationCaller { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups: string[]; capabilities?: ReadonlySet<Capability>; sourceIp?: string | null; replay?: boolean }

// SecretBindingSpec, SourceSpec, BlackoutWindow and DownpipeSchedule moved to the leaf ./types.ts to
// break the scheduler-do<->admin-spoke import cycles. Imported below for use here and re-exported so
// existing by-name imports from scheduler-do keep working.

// DownpipeConfig and RetentionPolicy moved to the leaf ./types.ts to break the scheduler-do<->admin-
// spoke import cycles; imported below and re-exported so existing by-name imports keep working.

// DownpipeState, RestoreProvenMethod, RestoreProven, IntegrityVerifiedHow and IntegrityVerified moved
// to the leaf ./types.ts to break the scheduler-do<->admin-spoke import cycles; imported below and
// re-exported so existing by-name imports keep working.

// INFLIGHT_LEASE_MS bounds how long a triggered run may hold the in-flight flag before it is treated
// as crashed and reclaimable. It is set well beyond any single Worker invocation's seal (a Workers cron
// invocation is wall-clock bounded to minutes), so a genuinely-running seal is never reclaimed, while a
// crashed one self-heals within roughly two cron intervals instead of wedging the downpipe permanently.
export const INFLIGHT_LEASE_MS = 30 * 60 * 1000;

// RESTORE_TEST_DEFAULT_CADENCE_SECONDS is the best-practice-on-by-default scheduled restore test
// cadence (contract section 5: weekly = 604800). addDownpipe applies it when restoreTestCadenceSeconds
// is OMITTED on create/upsert; an explicit 0 turns the scheduled test off (opt-down), and any other
// positive value is the operator's chosen cadence. Scheduled restore tests are a metered read on a
// live deployment, but at the code level this is config only and runs nothing until the engine is live
// and scheduled (separately gated); the console shows an estimate before enabling.
export const RESTORE_TEST_DEFAULT_CADENCE_SECONDS = 604800;

// RESTORE_TEST_MIN_CADENCE_SECONDS, RETENTION_MAX_KEEP_RUNS/DAYS, SCHEDULE_TZ_DEFAULT, MINUTES_PER_DAY,
// SCHEDULE_MAX_BLACKOUT_WINDOWS and SCHEDULE_BLACKOUT_DEFER_MAX_HOPS moved to the leaf siblings
// config-validate.ts / schedule-window.ts alongside the validateConfig / blackout helpers that are
// their only users (guardrails B8-2 god-module split); none was referenced by the DO class body.

// RunHistoryEntry is one row of the bounded recent-run ring the DO keeps per downpipe so the
// console can show a run list and prefill drill/restore with a real runId. It carries no
// plaintext and no key material, only the run's id, its monotonic runlogIndex (the join key
// between the in-flight append and the completion update), the start time, the resolved
// status and coarse outcome counts. error is a SHORT coarse reason on failure, never a stack.
// archiveBytesWritten/segmentsWritten/durationMs are optional throughput fields added at
// completion for the cost calculator (observed mode) and the topology throughput view; old
// ring entries from before this version lack them and that is intentional.
// RunHistoryEntry moved to the leaf ./types.ts to break the scheduler-do<->admin-spoke import cycles;
// imported below and re-exported so existing by-name imports keep working.

// DestReplState is the per-destination replication state of ONE downpipe (storage key
// `repl:<downpipeId>` -> Record<destinationId, DestReplState>). It is the HONEST source the console
// reads to show "N of M copies" and per-destination health, never an inference: holdsRunId/holdsIndex
// is the latest run this destination is PROVEN to hold (set by the seal for the origin it wrote to,
// and by the replicate pass for a copy it mirrored), and lastOk/lastAttemptAt/reason record whether
// the most recent seal-or-mirror attempt to this destination succeeded, the reachability heartbeat
// that drives the "destination down" indicator. It carries no key material and no plaintext.
export interface DestReplState {
  holdsRunId: string | null; // latest runId this destination is known to hold, or null (none yet)
  holdsIndex: number;        // that run's account-global index (-1 when none), for "behind by N"
  // holdsFrom, when set, is the LOWEST run index this destination has CONTIGUOUSLY OBSERVED (the ring floor
  // the replicate backlog anchored its contiguity walk at). Together with holdsIndex it bounds the run
  // WINDOW the destination can PROVE it holds: [holdsFrom, holdsIndex]. It is the fix for the ring-floor
  // over-claim (BD-RETENTION-HOLDSINDEX-RINGFLOOR-OVERCLAIM) - keepRuns can exceed the 50-run history ring,
  // so a replica added after older runs aged out only observed from the floor upward and cannot prove it
  // holds a below-ring run. Forward-only UP (the ring floor only advances as runs age out), like holdsIndex.
  // Absent on a legacy record from before this field (and on the seal-origin seed, which sets only the top);
  // consumers treat absent as "proves nothing below holdsIndex" (conservative). Written by the replicate pass.
  holdsFrom?: number;
  lastOk: boolean;           // the most recent seal/mirror attempt to this destination succeeded
  lastAttemptAt: number;     // epoch ms of that attempt
  reason?: string;           // coarse, secret-free reason when !lastOk (e.g. "unreachable")
}

// ReplRecordReq is the /replication/record body the seal driver and the replicate pass post to
// update one destination's DestReplState (the scheduler DO is the single writer of `repl:` state,
// exactly as it is for run history). A success carries the runId/index the destination now holds;
// a failure carries a coarse reason. Idempotent: re-recording the same run only advances the row.
export interface ReplRecordReq {
  id: string; // downpipeId
  destinationId: string;
  ok: boolean;
  runId?: string;
  index?: number;
  holdsFrom?: number; // the replicate pass's proven FLOOR (lowest contiguously-observed run index); see DestReplState
  reason?: string;
}

// CompleteRunReq is the /complete body. The driver posts the outcome so the DO can resolve
// the in-flight history row: status (defaulting from the empty-runId convention), the run's
// record count and plaintext byte total, optional throughput fields, and a coarse error string
// on failure. The throughput fields are optional so an older caller omitting them degrades
// cleanly (the history row simply lacks them).
export interface CompleteRunReq {
  id: string;
  runId: string;
  index: number;
  status?: "ok" | "failed";
  recordCount?: number;
  bytes?: number;
  error?: string;
  // The 12-hex correlation digest (first 6 bytes of SHA-384(raw error)) posted on a FAILED completion;
  // completeRun stamps it on the history row byte-identical to the Logpush `[cause <hex>]` line.
  causeDigest?: string;
  archiveBytesWritten?: number;
  segmentsWritten?: number;
  durationMs?: number;
  // How many in-scope records the seal could not capture this run (vanished/changed mid-crawl, unsealable);
  // surfaced on the history row so a non-zero count is visible to the operator (slice-skipped-records).
  recordsSkipped?: number;
  // recordsVanished is how many in-scope objects the LIST returned but that were GONE at value-read time (a
  // KV key / R2 object deleted between the list page and the GET -- a mid-crawl live-source race, WS-P2).
  // completeRun stamps it on the history row so the support pack surfaces "N objects vanished mid-crawl".
  // Distinct from recordsSkipped (etag-changed large objects). Optional/absent when nothing vanished.
  recordsVanished?: number;
  // How many records this run sealed as INCOMPLETENESS SENTINELS (R1-1): a marker landed in the
  // archive in place of the real bytes (_truncated/_unavailable/_skipped/_pending/_refused), so the
  // backup completed but is intentionally short of the live source. Distinct from recordsSkipped
  // (etag-mid-crawl skips, which seal NOTHING). Surfaced on the history row and the success
  // notification so a backup with markers reads "completed with N items not fully captured", not a
  // clean ok. Optional: an older seal omits it and the row simply lacks it.
  recordsIncomplete?: number;
  // incompleteByMarker is the PER-MARKER breakdown of recordsIncomplete (WHICH incompleteness kinds this
  // run sealed and how many of each); completeRun stamps it on the history row so the support pack carries
  // it (the diagnostics-bot consumes it separately). KEY identity + integer count only, never the marker
  // payload (NO-CUSTODY, same posture as opCounts). Optional/absent when the run sealed no markers.
  incompleteByMarker?: IncompleteByMarker;
  // incompleteIds is the PER-KIND ATTRIBUTION of the markers (WS-P1): which surface/object was short, as a
  // bounded, deduplicated list per kind. completeRun stamps it on the history row so the support pack carries
  // it. NO-CUSTODY: only redaction-safe closed/product-token ids (cf-config surface ids today); absent when the
  // run had nothing name-attributable.
  incompleteIds?: IncompleteIds;
  // opCounts is the exact per-resource Cloudflare op tally this run made (cost Phase 3), for the cost
  // estimate's platform ledger. Optional: a legacy seal omits it and the estimate falls back.
  opCounts?: OpCounts;
  // The destination the seal wrote to (the failover-chosen origin). Recorded on the history row and
  // used to seed the per-destination replication state (this destination now holds runId at index).
  destinationId?: string;
  // DEST-1: the destination id(s) PROVEN down for this run (the failover down set, or, for a single-
  // destination downpipe, the sole destination whose write faulted with a destination-access error). On a
  // FAILED completion the DO records a lastOk:false reachability heartbeat for each, so the map's existing
  // per-destination "down" indicator surfaces a single/default-destination outage too (today the overlay
  // only ever lit for a fan-out replica via the replicate pass). It never advances holdsIndex (a down
  // destination proves nothing held), so a stale or duplicated failure can never rewind a proven copy.
  downDestinationIds?: string[];
  // The verify-at-seal verdict (ENG-RST-01) the seal driver computed by reading the just-written
  // archive back and verifying it. Recorded on the successful history row and folded into the
  // per-downpipe lastSealVerify the posture seal-verification check reads. Optional: an older driver
  // (or a feature-off deployment) omits it and the row simply lacks the verdict.
  sealVerification?: SealVerification;
  // multipartAbortFailed (multipart-abort-stranded-parts) is set when this run's destination reported that a
  // FAILED multipart upload's best-effort abort ALSO failed, leaving invisible stranded part-storage the
  // bucket's own lifecycle/abort policy must reap. A BOOLEAN only (derived from the destination's abort-
  // failure counter, never a key/id/value); completeRun stamps it on the history row so the support pack can
  // surface an otherwise-swallowed cost/clutter fault. Optional/absent when nothing was stranded (the norm).
  multipartAbortFailed?: boolean;
}

// DrillEvidenceKind and DrillEvidenceEntry moved to the leaf ./types.ts to break the scheduler-do<->
// admin-spoke import cycles; imported below and re-exported so existing by-name imports keep working.

export const DRILL_EVIDENCE_PREFIX = "drill-evidence:";

// DRILL_EVIDENCE_CAP bounds how many drill-evidence rows the DO retains (ENG-SCALE-06), mirroring
// AUDIT_CAP for the audit chain and RING_CAP for the run-history ring: every OTHER record family in
// this DO has a bound, and this one previously did not, so a long-lived account running scheduled
// restore tests (one row per downpipe per cadence, e.g. daily) would grow the drill-evidence log
// without limit. At the cap recordDrillEvidence rolls over the OLDEST rows first (the keys are
// ULID-suffixed, so a prefix list is chronological and the lowest keys are oldest) and the reads
// page the scan. 500 is generous (years of monthly drills, or 16 months of daily ones across a
// downpipe) while keeping the log bounded; it is the unbounded-evidence cousin of AUDIT_CAP's 10000
// (audit is far higher-volume). Unlike the SCALE_* knobs, this is enforced in the DO, which holds no
// env reference (the SchedulerDO constructor takes only state), so, exactly like AUDIT_CAP and
// RING_CAP, it is a module constant rather than an env-read knob; the env.d.ts DRILL_EVIDENCE_CAP
// field documents the intended override for the day the DO is given an env.
export const DRILL_EVIDENCE_CAP = 500;

// DRILL_EVIDENCE_ROLLOVER_BATCH is the headroom over the cap that recordDrillEvidence reads when it
// checks for a rollover, so a one-off backlog (a lowered cap, or any drift) drains over a few writes
// rather than in one large delete; the steady-state surplus is one row per append.
export const DRILL_EVIDENCE_ROLLOVER_BATCH = 16;

// GROUP_ROLE_PREFIX keys the OPTIONAL identity-provider group->role mapping, one entry per mapped
// group under `grouprole:<group>`, alongside the per-email `role:` table. It is ADDITIVE: it only
// affects role resolution for a caller whose verified Access JWT actually carried matching groups,
// so an account that never configures Access (or whose IdP sends no groups) has an empty mapping and
// behaves exactly as the per-email table alone. SECURITY CAP (contract section 1): a group may map to
// ANY role EXCEPT owner (viewer/operator/restore-operator/approver/access-admin), NEVER owner
// (enforced in setGroupRole and again at resolution via capGroupRole), so owner stays an explicit,
// named, per-email grant and the last-Owner guard (which counts only `role:` owner entries) is
// unaffected by groups.
export const GROUP_ROLE_PREFIX = "grouprole:";

// CUSTOM_ROLE_PREFIX keys the OPTIONAL composable custom-role records, one per role under
// `customrole:<name>`, alongside the per-email `role:` and per-group `grouprole:` tables. A custom role
// is ADDITIVE: it confers authority ONLY to a caller whose explicit email grant or group mapping
// references its NAME (RoleEntry.customRole / GroupRoleEntry.customRole). The six built-in roles are
// untouched; an account that never defines a custom role behaves exactly as before. The record's
// authority is its own capability set, folded at resolution EXACTLY like a built-in's set, but it is
// NEVER owner (owner is not a custom role) and can NEVER hold an owner-reserved capability (the
// write-time guard in validateCustomRole and the read-time re-application in capabilitiesOfCustomRole
// both bar them), so a custom role can never reach the owner break-glass authority.
export const CUSTOM_ROLE_PREFIX = "customrole:";

// GROUP_NAME_MAX bounds a single group name (after trimming), and GROUPS_MAX bounds how many
// groups the DO will ingest from any source (the groups query param or the forwarded caller
// header). These are the DO's OWN bounds: the DO is its own authority and bounds every input it
// ingests (the email via normaliseEmail, a single group key via normaliseGroup), so it must NOT
// rely on access.ts boundGroups (a different module) having already bounded the list. The values
// match access.ts (256 / 200) deliberately, but they are duplicated here on purpose rather than
// imported, so the DO has no cross-module dependency for its own input bounding. 256 keeps a group
// within a sane storage-key fragment; 200 is far above any realistic per-user group count and caps
// the worst-case loop/storage a hostile-but-signed or forged-header list could drive on the
// single-threaded DO.
export const GROUP_NAME_MAX = 256;
export const GROUPS_MAX = 200;

// REASON_MAX_LEN is the hard ceiling on the free-text restore-request reason (stored in the DO
// approval record, the audit log, and the approver inbox). 1000 characters is ample for any
// human-written justification and keeps the DO storage cost of a single approval record trivial.
// NOTE_MAX_LEN is the matching bound on drill-evidence note (same storage / audit discipline).
// Both use validateFreeText below, which also rejects bare ASCII control characters (0x00-0x1F
// except tab 0x09 and newline 0x0A, which the console may emit for multi-line text) and DEL 0x7F.
export const REASON_MAX_LEN = 1000;
export const NOTE_MAX_LEN = 1000;

// validateFreeText moved to the leaf sibling scheduler-helpers.ts (guardrails B8-2 god-module split);
// imported back above so every call site (restore-request reason, drill-evidence note) is unchanged.

// GroupRoleEntry is one row of the group->role mapping. group is the customer's own IdP group NAME
// (their directory data, not a secret, redaction-safe like a downpipe id). role is any role except
// owner (the write-time cap; see setGroupRole). grantedBy is the Owner email that set it (or
// "token-fallback"); grantedAt is RFC-3339 UTC millis, matching the role table's format.
export interface GroupRoleEntry {
  group: string;
  role: Role;
  grantedBy: string;
  grantedAt: string;
  // customRole, when present, names a custom role this mapping confers INSTEAD of the built-in role
  // field (pinned to "viewer" as the floor), mirroring RoleEntry.customRole. The mapping's authority
  // becomes the custom role's capability set, resolved at request time from the `customrole:` table; a
  // mapping referencing a deleted custom role falls back to the viewer floor (least privilege).
  customRole?: string;
  // connId (G2), when present, SCOPES this mapping to logins through that ONE IdP connection: the group name
  // matches only when the caller signed in via connId. Absent = GLOBAL (matches any connection, the legacy
  // behaviour, unchanged). This closes the cross-IdP group-name collision -- a group name a customer maps for
  // their trusted IdP (e.g. "admins" -> access-admin for Entra) can be pinned to that connection so a SECOND
  // connection asserting the same name (a GitHub org literally named "admins") does not inherit the role. One
  // mapping per group name (the grouprole:<group> key is unchanged); scope it, or leave it global.
  connId?: string;
}

// AlertCooldown is the per-downpipe last-alerted record the SRE-alerting detector uses to make
// alerting transition-based (alert a NEWLY stale/failed downpipe) and to throttle a persistently
// broken pipe to one re-nudge per cooldown window rather than one per */15 reconciliation tick. It
// holds only the last alerted STATE enum and the epoch ms of that alert; no key material, no value.
// Stored under `alert:<downpipeId>` and dropped when the downpipe is deleted or recovers.
export interface AlertCooldown {
  state: AlertState;
  at: number; // epoch ms of the last alert for this downpipe in this state
}

// ALERT_COOLDOWN_PREFIX keys the per-downpipe last-alerted records, alongside dp:/hist:/role:/etc.
export const ALERT_COOLDOWN_PREFIX = "alert:";

// ReplAlertCooldown is the per-downpipe last-alerted record the REPLICATION detector uses, mirroring
// AlertCooldown for the staleness/failure stream. It makes the replication alert transition-based
// (page once when the proven copy set first falls short, or a run first becomes at risk of eviction)
// and throttles a persistently-degraded downpipe to one re-nudge per ALERT_COOLDOWN_MS rather than one
// per reconciliation tick. The state holds which replication condition was last alerted (the most
// severe currently applicable); run-at-risk-eviction outranks replication-degraded, so a downpipe that
// crosses from degraded into at-risk re-alerts (a new state) and a recovery to neither clears the
// record so a future relapse alerts immediately. It carries no key material and no value.
export interface ReplAlertCooldown {
  state: "replication-degraded" | "run-at-risk-eviction";
  at: number; // epoch ms of the last replication alert for this downpipe in this state
  // severity (mon-autoresolve) persists the EXACT severity the TRIGGER emission used, so the recovery
  // emission built when this cooldown clears (reconcileReplicationAlerts) can reuse the identical value
  // rather than recompute a possibly-lower base severity. This matters specifically for
  // run-at-risk-eviction, which the DO may ESCALATE to critical (the last-proven-copy case): reusing the
  // escalated severity is what guarantees the recovery clears the SAME rule minSeverity bar the escalated
  // trigger did, so it reaches every channel (PagerDuty included) the trigger reached. Optional so a
  // cooldown record written before this field (a read-time migration case, the holdsFrom precedent)
  // degrades to the base severityOf(state) at the recovery call site, never a stored-shape break.
  severity?: Severity;
}

// REPL_ALERT_COOLDOWN_PREFIX keys the per-downpipe last-replication-alerted records, alongside the
// alert:/dp:/hist:/repl: keys, and is dropped when the downpipe is deleted or recovers.
export const REPL_ALERT_COOLDOWN_PREFIX = "repl-alert-cd:";
// SUCCESS_NOTIFIED_PREFIX tracks, per downpipe, the runId of the latest SUCCESSFUL run already emitted
// as a backup-success notification, so reconcileAlerts emits each new success EXACTLY ONCE
// (transition-based, the success mirror of the failure cooldown). RECENT_SUCCESS_WINDOW_MS bounds
// emission to a genuinely recent success: when this detector goes live (or a channel is first wired)
// the latest-success of every downpipe would otherwise look "new", so an OLD latest-success is recorded
// as notified WITHOUT emitting, and only a success within the window fires. Two hours generously covers
// the cron's reconciliation coarseness without back-firing notices for last week's runs.
export const SUCCESS_NOTIFIED_PREFIX = "notify-success:";
export const RECENT_SUCCESS_WINDOW_MS = 2 * 60 * 60 * 1000;
// SOURCE_DRIFT_KEY holds the SINGLE-key set of source binding names the engine has ALREADY alerted as
// detached (the edge-trigger marker for the scheduled source-drift pass). reconcileSourceDrift diffs the
// current missing set against it: names not in the marker are NEWLY detached (alerted once); it then
// REWRITES the marker to exactly the current missing set, so a re-attached binding CLEARS (its absence
// re-arms the alert) and a re-detach later fires again. One string[] under one key (the missing set is small).
export const SOURCE_DRIFT_KEY = "source-drift-alerted";

// VOLUME_REGRESSION_KEY holds the SINGLE-key set of downpipe ids the engine has ALREADY alerted for a
// retention VOLUME REGRESSION (the edge-trigger marker for the volume-guard alert, the retention-pass sibling
// of SOURCE_DRIFT_KEY). reconcileVolumeRegression diffs the currently-regressed id set against it: ids not in
// the marker are NEWLY regressed (alerted once); it then REWRITES the marker to exactly the current set, so a
// downpipe whose volume recovered CLEARS (its absence re-arms the alert) and a later re-regression fires
// again. One string[] under one key (the regressed set is bounded by the retention-configured downpipes).
export const VOLUME_REGRESSION_KEY = "volume-regression-alerted";

// ExpiryCooldown is the per-item last-notified record the credential-expiry detector uses to make the
// expiry emission transition-based: it holds the lowest notification rung the item has been notified
// about (one of NOTIFY_THRESHOLDS, see expiry.ts) and the epoch ms of that notice. A credential-expiry
// notification fires only when the item crosses to a STRICTLY LOWER rung than this (shouldNotifyExpiry),
// so a long-approaching credential alerts once per rung (30, 14, 7, 1), not every reconciliation tick.
// Stored under `expiry-cooldown:<id>` (EXPIRY_COOLDOWN_PREFIX) and dropped when the item is deleted or
// is no longer approaching, mirroring AlertCooldown. It carries no key material and no value.
export interface ExpiryCooldown {
  threshold: number; // the lowest NOTIFY_THRESHOLDS rung last notified for this item
  at: number; // epoch ms of that last notice
}

// ExpiryEmission is the redaction-safe per-item result reconcileExpiry returns for the cron driver to
// route through the notification model. It carries ONLY the item id (so the driver/DO can correlate)
// and a one-line detail (the label + days-remaining), never a secret, key, value or fingerprint. The
// event (credential-expiry) and severity (warning) are fixed by the contract, so they are not carried
// per emission; the driver supplies them. downpipeId is always null for an expiry event (it is
// account-level), which the driver sets when building the NotifyEmission.
export interface ExpiryEmission {
  id: string;
  detail: string; // redaction-safe one-liner (label + days-remaining; never a secret)
}

// NOTIFY_HISTORY_SEQ_KEY holds the monotonic sequence counter for the notification history ring
// (contract section 2.1, capped at NOTIFY_HISTORY_CAP). One entry is stored under
// `notify-history:${padded(seq)}`; the oldest are rolled off once the retained count exceeds the cap.
export const NOTIFY_HISTORY_SEQ_KEY = "notify-history-seq";

// NOTIFY_HEALTH_KEY (NOTIF needs-new-logging: do-fetch-throws-pass-skipped +
// recordnotify-skips-malformed-rows + freetext-detail-overlong-rejected + feedback-fail) holds a small
// counter record of the SILENT drops in the notification pipeline: a whole notify pass the Worker skipped
// (a DO fetch threw), per-channel delivery records dropped as malformed, emissions rejected by the input
// validator (an overlong detail / a bad enum), and delivery-feedback failures that would otherwise leave a
// pipe in cooldown with no alert delivered. Counters + a timestamp only, so "alerts silently stopped" is
// diagnosable. Redaction-safe (ints + a clamped timestamp).
export const NOTIFY_HEALTH_KEY = "notify-health";

// NotifyHealth is the persisted notify-pipeline drop-counter record.
export interface NotifyHealth {
  passSkips: number; // whole notify passes the Worker skipped (a /notify/resolve|record DO fetch threw)
  recordSkips: number; // per-channel delivery records dropped as malformed at /notify/record
  parseRejects: number; // emissions rejected by parseEmission (a bad enum / an overlong free-text detail)
  feedbackFails: number; // delivery-feedback failures (cooldown set but the alert was not delivered)
  lastAt: string; // when a counter was last bumped
}

// NOTIFY_DIGEST_PREFIX keys pending digest entries: a success-class event deferred (not sent per
// occurrence) by a rule whose digest is daily/weekly is appended here so a future digest flush (a
// later wave) can batch them. Recording the deferral here is what makes digest "batched, not sent
// per occurrence" true today; the flush route itself is deferred. Keyed by an opaque sequence so
// multiple deferrals coexist; the entries are redaction-safe (the same emission surface as history).
export const NOTIFY_DIGEST_PREFIX = "notify-digest:";
export const NOTIFY_DIGEST_SEQ_KEY = "notify-digest-seq";

// RateWindow is one persisted fixed-window rate-limit counter (see RATE_LIMIT_PREFIX). windowStart
// is the epoch ms at which the current window opened; count is how many requests have been admitted
// in it. It carries no caller identity beyond the storage key, no secret and no value, so it is
// redaction-safe like the rest of the DO's operational state. Stored under `ratelimit:<key>`.
export interface RateWindow {
  windowStart: number; // epoch ms the current window opened
  count: number; // requests admitted in the current window
}

// JITTER_FRACTION moved to the leaf sibling schedule-window.ts (guardrails B8-2 god-module split)
// alongside jitteredCadence, its only user.

// ALARM_MIN_DELAY_MS is the floor rearmAlarm applies so the next alarm is never scheduled in the
// past (XC-M8). nextRunAt advances only on completion, so a wedged enabled downpipe (a run whose
// /complete never lands after a crash in the narrow window between trigger and seal) keeps a
// past-due nextRunAt. setAlarm(past) fires straight away, and alarm() only re-arms the same past
// value, which can drive a self-refire storm of zero-work wakeups. Clamping the armed time to
// now + this floor breaks that loop: a past-due time becomes a single short-delayed wakeup, not an
// immediate refire. The floor only bites a past or near-past time (a healthy pipe's nextRunAt is at
// least a full cadence, >= 60s, in the future, so the clamp never delays a genuine near-future
// alarm). This is the narrow "never arm in the past" guard only; the underlying wedge self-heals
// via the in-flight LEASE (ENG-B2) on the next cron-driven trigger, and precise alarm-driven
// dispatch (XC-M7) is a separate, still-deferred refinement (it needs the engine wired as a service
// binding so the alarm can seal).
export const ALARM_MIN_DELAY_MS = 1000;

// RUNLOG_LEASE_MS bounds how long one run may hold the RUNLOG write lock before another
// run may take over (covers a crashed holder).
export const RUNLOG_LEASE_MS = 30_000;

// TICK_LEASE_MS bounds the cron driver's SINGLE-FLIGHT tick lease (C3-07): drive() takes it at the top of a
// scheduled() invocation and releases it at the end, so two OVERLAPPING */15 cron ticks (a slow tick still in
// flight when the platform fires the next one, possibly in a separate isolate) do not both run the pass
// sequence. Release-on-completion is the PRIMARY mechanism (a normal tick holds it for seconds); this TTL is
// only the crash backstop that lets the schedule self-heal if an isolate is evicted mid-tick before it
// releases. It is set to one cron interval (crons = "*/15 * * * *") so a lease still held when the next tick
// fires means a genuine overlap (skip the duplicate) or a very recent crash (self-heals within a tick). The
// per-run in-flight lease (INFLIGHT_LEASE_MS) and the DO alarm remain the real per-downpipe timers regardless.
export const TICK_LEASE_MS = 15 * 60 * 1000;

// ---- Per-caller anti-automation rate limiting (OWASP ASVS V2.4.1) ----------------------------
// RATE_LIMIT_PREFIX keys one fixed-window counter per CALLER (the verified Access email, or the
// stable "token" key for the bare-token break-glass), alongside the dp:/hist:/role:/audit: keys.
// The router consults it on every MUTATING (POST) admin route AFTER the caller is resolved, so an
// authenticated caller cannot drive an unbounded burst of writes (trigger, restore/request,
// downpipes, audit/intent, ...). It is deliberately keyed on the AUTHENTICATED CALLER, never the
// source IP: a per-IP limiter fails closed across a shared NAT/egress and harms legitimate
// customers (the cost/rate-limit audit calls this out), whereas a per-caller bucket throttles only
// the identity actually generating the load.
// ORG_POLICY_KEY holds the single account-wide governance-policy record in THIS DO, alongside the other
// policy/posture state (the webhook policy, the posture risk-accepts, the coverage inventory). Today it
// carries one field: requireConfigApproval, the OPT-IN dual-control change-control gate for config
// mutations (default OFF). It is stored here, not in env, because it is a runtime policy the OWNER toggles
// from the console (immediate effect), the same storage authority pattern as the role table. A new field
// added later folds into the same record.
export const ORG_POLICY_KEY = "orgpolicy";

// CONTROL_PLANE_EXPORT_STATE_KEY (INFRA-1) records the LAST signed control-plane export the cron pass
// wrote (the config-version id, the content hash it covered, and when), so the export pass is
// CHANGE-GATED: it re-exports only when the head config posture differs from the last export, never
// re-signing an unchanged slice every tick. It holds no secret (a version id, a content hash, a timestamp).
export const CONTROL_PLANE_EXPORT_STATE_KEY = "controlPlaneExportState";

// CONTROL_PLANE_STAGED_KEY (INFRA-1 AUTO-HEAL) holds the ControlPlaneRecoveryRecord: the verified signed
// export the cron auto-heal staged for the break-glass confirm (+ whether its no-authority resume slice has
// been applied), or a refusal marker when the auto-heal found nothing it could safely apply. It carries no
// plaintext secret (the staged export is no-custody by construction; a dest secret rides only as a wrapped
// envelope). Cleared by a successful authority reconcile (the staged export has been consumed).
export const CONTROL_PLANE_STAGED_KEY = "controlPlaneStaged";

// CONTROL_PLANE_AMNESIA_PROBE_KEY (CPR needs-logging: amnesia-undetectable-console-only-dest +
// amnesia-false-negative-runlog-missing) records the OUTCOME CLASS of the cron health pass's last
// amnesia-detection attempt. The recovery latch's own blind spots (a wipe with only a console-set dest =
// no bucket to probe; a bucket whose RUNLOG is absent/unreadable = misread as a brand-new account) leave
// NO signal today. This holds a closed probe-class enum + a clamped timestamp only (no secret, no config
// value), so the support pack can see WHY the latch did or did not fire.
export const CONTROL_PLANE_AMNESIA_PROBE_KEY = "controlPlaneAmnesiaProbe";

// CONTROL_PLANE_DEPLOY_OBS_KEY (CPR needs-logging: version-change-observation-gated / -first-poll-baseline /
// cfversionid-absent-redeploy-invisible) records a DETERMINISTIC per-tick deploy-identity observation the
// cron drives from the Worker (which holds env.CF_VERSION_METADATA). It complements the observation-gated
// GET /admin/status diff so a deploy is visible even when status is never polled, distinguishes the first
// (baseline) observation from a real change, and works even when cfVersionId is absent (env-fallback/local).
// It holds an engine-version string + optional cf deploy id + booleans/counts/timestamps only, no secret.
export const CONTROL_PLANE_DEPLOY_OBS_KEY = "controlPlaneDeployObs";

// CONTROL_PLANE_EXPORT_HEALTH_KEY (CPR needs-logging: export-budget-starved-stale-generation +
// export-per-dest-write-fault) records the OUTCOME of the cron control-plane export pass: whether it was
// skipped (no signer / budget-yielded) and the PER-DESTINATION write outcome. Today a budget-yield or a
// per-dest write fault is only logged and lost, so a stale recovery generation is unexplained. This holds a
// closed skip-reason enum, counts, a clamped timestamp and per-dest {id, ok} booleans only (no secret).
export const CONTROL_PLANE_EXPORT_HEALTH_KEY = "controlPlaneExportHealth";

// CONTROL_PLANE_LAST_IMPORT_KEY (G218) records the OUTCOME of the last estate import: whether it landed
// cross-account, whether either side could NAME its Cloudflare account, and whether the downpipes therefore
// landed disabled.
//
// WHY IT MUST BE PERSISTED. The import's answer is a one-shot HTTP response body, and it is long gone by the
// time a support pack is generated. Hold only the pack for "the estate is back on my screen and not one
// backup is running" and two worlds are identical:
//
//   a genuine CROSS-ACCOUNT import   every downpipe lands enabled:false. Remedy: re-point every source.
//   accountIdAbsent                  the export predates engine account discovery (or CF_ACCOUNT_ID is unset),
//                                    sameControlPlaneAccount fails SAFE on the null, crossAccount comes back
//                                    TRUE anyway, and every downpipe lands enabled:false. Remedy: there is
//                                    nothing to re-point. Set the account id and re-export.
//
// Same DO state, same audit trail (one reconcile bridge), and now the same support pack too: a
// pre-account-discovery export silently imported everything disabled, and nothing anywhere said which of
// the two had happened. Booleans, counts and one clamped
// timestamp; no account id, no export content, no downpipe id.
export const CONTROL_PLANE_LAST_IMPORT_KEY = "controlPlaneLastImport";

// DISCOVERY_KEY holds the single account-discovery configuration record: the customer's own
// READ-ONLY Cloudflare API token (set FROM THE CONSOLE, no CLI, no redeploy; the same DO custody
// as the bootstrap invite capability and the session signing key), the accounts the token saw when
// it was verified, which of those the operator browses, and which one is the ENGINE's own account
// (binding stanzas only attach there). The token leaves the DO only on the router's INTERNAL
// discovery-config fetch; the status route is presence-only; the audit trail records who set or
// cleared it and never the value.
export const DISCOVERY_KEY = "discoveryConfig";

export interface DiscoveryAccountSeen {
  id: string;
  name: string;
}

export interface DiscoveryConfig {
  // WrappedSecret whenever CONFIG_WRAP_KEY is configured (sealed under DISCOVERY_SECRET_AAD by the
  // router before it reaches the DO); a bare string only on the back-compat floor, or for a record
  // written before the token was encrypted at rest. Read it through resolveConfigSecret, never raw.
  token: string | WrappedSecret;
  setAt: number; // epoch ms
  setBy: string | null; // the verified owner email that stored it (null on the token break-glass)
  accountsSeen: DiscoveryAccountSeen[]; // what the token could list at set time (id + name)
  selected: string[]; // the account ids the operator browses (subset of accountsSeen)
  engineAccountId: string | null; // the engine's own account (stanzas bind only there)
  // enabledSources: the token-authenticated source TYPES the operator has explicitly ADDED on the
  // Sources screen (a subset of cf-config / workers / stream / images / artifacts). These need no
  // engine binding (the read-only discovery token is the credential), so without this record they
  // were "always available" in the create-downpipe wizard; recording them lets the wizard offer ONLY
  // the added types, the same add-then-protect discipline a bound source already has. Absent on an
  // older record = none added yet; the setter writes the full desired set each time (set semantics).
  enabledSources?: string[];
}

// ENGINE_ACCOUNT_VERIFIED_KEY (LICENCE-BINDING-ON-CLAIM, follow-up) holds the engine's own
// Cloudflare account id the FIRST time an attach or an update-apply proves it, for the deployments
// DISCOVERY_KEY never covers: no CF_ACCOUNT_ID env var (never written by the deploy script or
// wrangler.toml) and no read-only discovery token ever pasted on the Sources screen, which describes
// every stock self-serve deployment. Proof, not a listing: attach.ts and cf-deploy.ts both read
// /accounts/{a}/workers/scripts/{name} for THIS engine's own script name before writing to it, so a
// successful attach or promote already means Cloudflare answered that read for this exact account,
// the same certainty CF_ACCOUNT_ID gives when an operator sets it by hand. Separate from DISCOVERY_KEY
// deliberately: that record requires a token (DiscoveryConfig.token is not optional) and its
// engineAccountId is either operator-picked or derived from a token LISTING accounts, a weaker proof
// than one script-settings read confirming the exact script name. Never overwritten once set (see
// recordVerifiedEngineAccount): the account a running Worker's script lives in cannot change under it.
export const ENGINE_ACCOUNT_VERIFIED_KEY = "engineAccountVerified";

export interface VerifiedEngineAccount {
  accountId: string;
  verifiedAt: number; // epoch ms
  via: "attach" | "update-apply";
}

// DEST_CONFIG_KEY holds the single CONSOLE-SET archive-destination record: the S3-shaped
// credentials an Owner stores from the Destinations screen (set FROM THE CONSOLE, no CLI, no
// redeploy; the same DO custody and the same lifecycle discipline as the discovery token).
// The router has VERIFIED the destination live (a write probe must pass) before this record is
// stored. The secret access key leaves the DO only on the router's INTERNAL dest-config fetch;
// the status view is redaction-safe (endpoint host, bucket, region, who/when, never the key);
// the audit trail records who set or cleared the destination and never a value. Precedence:
// this record WINS over the deploy-time DEST_* env configuration (the IaC fallback).
// DEST_CONFIG_KEY is the LEGACY single-destination record (pre multi-destination). It is read
// once and migrated into DESTINATIONS_KEY as the "default" entry, then left in place (harmless).
export const DEST_CONFIG_KEY = "destConfig";
// DESTINATIONS_KEY holds the multi-destination collection: a list of stored destinations plus the
// id of the default one. A downpipe with no destinationId, and every legacy reader (the run path's
// /dest-config fetch, the singular /destination route, the drill/restore), resolves to the default,
// so adding destinations never changes where an existing downpipe writes. One storage value holds
// the whole collection; a handful of destinations is far below the DO value-size limit.
export const DESTINATIONS_KEY = "destinations";

// CANARY_KEY holds the single account-wide Canary record in THIS DO, alongside the org-policy and
// destination state. It carries the canary's operator config (enabled/destination/cadence), its
// liveness, the schedule (nextRunAt + the in-flight lease), and a bounded history ring. It holds
// no secret and no key material: the bird's known corpus lives in code, and every flight result is
// recorded as redaction-safe counts and coarse facts, never a value or a key. An ABSENT record
// reads as the on-by-default canary (see ensureCanaryState), so a tenant that never touches the
// setting still gets the bird flying.
export const CANARY_KEY = "canary";

// LICENCE_KEY holds the single CONSOLE-ACTIVATED assurance licence record: the customer's signed
// LICENCE_TOKEN plus who activated it and when (no-CLI activation; DO-stored at runtime, same custody
// and lifecycle discipline as the discovery token / destination). The router has VERIFIED the token live
// against the pinned vendor signer before this is stored (verify-before-store). It WINS over the
// deploy-time env.LICENCE_TOKEN, exactly as the console-set destination wins over the env destination.
// The token is fail-open and gates nothing; the set/clear is owner-exclusive (re-resolved here) and
// audited (who + when, never the token bytes). An ABSENT record reads as the deploy/community default.
export const LICENCE_KEY = "licenceToken";

// LicenceTokenRecord is the persisted shape under LICENCE_KEY. token is the compact dot-joined signed
// token (the one secret-ish value, though it is itself fail-open and grants only services); setAt/setBy
// are the redaction-safe activation provenance the console surfaces (never returned to a public route).
export interface LicenceTokenRecord {
  token: string;
  setAt: number;
  setBy: string | null;
}

// UPDATE_KEY holds the safe-apply update lifecycle (update-apply.ts): the pending-verification state
// BETWEEN phase 1 (promote, on the old version) and phase 2 (settle, on the new version), plus the last
// completed outcome the console surfaces. Redaction-safe: version ids, outcomes, who + when, NEVER the
// deploy token (which is never stored; it is supplied per request and used in-memory only).
export const UPDATE_KEY = "updateLifecycle";
// UPDATE_HISTORY_CAP bounds the multi-component update-outcome ring on UpdateRecord.history: 20 entries
// covers many release cycles of engine+console outcomes while keeping the record small (the full audit
// trail remains the durable history; this ring is the console's quick view).
export const UPDATE_HISTORY_CAP = 20;
// DEMO_FRESH_FIRST_RUN_KEY: a demo-only marker written by POST /demo/reset (after the storage wipe) and
// cleared by POST /keys/install, so the guided setup restarts at the key ceremony even though a DO reset
// cannot remove the surviving signer/break-glass worker secrets. Read by GET /setup-state under DEMO_MODE.
export const DEMO_FRESH_FIRST_RUN_KEY = "demoFreshFirstRun";
// engine-src-037-M1: DEMO_MODE_MARKER_KEY is the in-DO, fail-closed defence-in-depth marker that proves
// THIS DO is a genuine demo instance. The DO cannot read DEMO_MODE from env, so the router (which can)
// persists this marker via POST /demo/mark on a DEMO_MODE-gated path (GET /setup-state, read on every
// guided-setup load). POST /demo/reset REFUSES when the marker is absent, so a misrouted or forged reset
// can never wipe a non-demo instance even if it slips past the router's upstream owner/DEMO_MODE checks.
// The marker is RE-WRITTEN after the wipe (like the fresh-first-run marker) so a legitimate demo DO stays
// markable across repeated resets.
export const DEMO_MODE_MARKER_KEY = "demoModeMarker";

export interface UpdatePending {
  fromVersion: string;
  toVersion: string;
  recommendedVersion: string;
  canaryBaseline?: string;
  // riskClass is the W5 normalised risk of the release being settled (routine|migration|breaking), persisted
  // at promote time so the settle route applies the SAME dual-control rule it used at apply: a KEEP of a
  // migration/breaking release takes a second owner (when dual control is ON); a routine release does not.
  // Additive + presence-safe: an old pending record without it makes settle default to the safe gated path.
  riskClass?: string;
  promotedAt: number;
  promotedBy: string | null;
  // sourceBindingsBefore is the snapshot of the engine's LIVE source binding names taken at promote time
  // (before the new version went live), so settle can verify post-update that the update preserved them
  // and prompt a re-attach if it dropped any. NAMES only (never an id/value), the same redaction posture
  // as the rest of this record. Additive + presence-safe: an old pending record without it makes settle
  // skip the diff (no false drop). The update path preserves bindings by construction (cf-deploy re-sends
  // the live set), so this is the defence-in-depth proof, not the expected path.
  sourceBindingsBefore?: string[];
  // channelSeq/channelIssuedAt (R9) are the freshness claims from the SIGNED channel descriptor this promote
  // accepted. They are NOT part of the pending's identity; setUpdatePending uses them to ADVANCE the monotonic
  // last-seen freshness watermark (lastChannelSeq/lastChannelIssuedAt on UpdateRecord) so a later replay of an
  // older descriptor is refused. Optional + additive (an old pending without them advances nothing).
  channelSeq?: number;
  channelIssuedAt?: string;
  // percentage (asvs-HI-13) is set ONLY by the opt-in gradual ramp (never by the atomic apply): its presence
  // is what marks this record as a ramp's own pending, so POST /update/settle and POST /update/ramp/settle
  // stay mutually exclusive (each refuses the other's shape) instead of the weaker, non-split-aware apply
  // settle ever acting on a still-splitting ramp.
  percentage?: number;
  // consoleQueued (multi-component updates, ADDITIVE) records that this promote's apply also asked for the
  // CONSOLE component: the console applies ONLY after the engine settles as applied (engine-first,
  // engine-settled sequencing), so the intent must survive between the apply request and the settle
  // request. Only the console component's VERSION + risk ride here (never a url or hash -- the settle
  // re-fetches and re-verifies the signed channel and requires the version to still match, so nothing
  // stale or secret is persisted, and GET /update/status can return this record verbatim). A non-applied
  // engine settle ABORTS the queue (setUpdateSettled records the honest console outcome). Legacy pending
  // records without it read as engine-only, exactly as before.
  consoleQueued?: { version: string; riskClass?: string; queuedAt: number } | null;
  // artefactSha384 (update provenance DP-0, ADDITIVE) is the SIGNED CHANNEL's digest for the artefact this
  // promote verified and shipped -- the exact value verifyAndGuard compared the downloaded bytes against
  // before any upload. Persisting it makes the record (and the settled record it flows into) durable proof
  // of WHICH content hash went live, not merely which opaque Cloudflare version id; without it, "what bytes
  // did we run in March" is unanswerable after the channel moves on. A public digest of a public artefact
  // (redaction-safe, same class as the sha384 already shown on the licence screen); absent on legacy
  // records and on any promote whose channel entry carried no digest.
  artefactSha384?: string;
  // readback (DP-D, ADDITIVE) is the post-upload read-back verdict for this promote (verified | mismatch
  // | unavailable, the gate mode it ran under, and the platform-returned digest when bytes were read):
  // durable evidence of whether Cloudflare's own API held byte-exactly the signed bundle BEFORE the
  // promotion. Redaction-safe (an enum, a mode, a public digest, a clamped reason). Absent on legacy
  // records and when the gate ran in off mode.
  readback?: { verdict: string; mode: string; deployedSha384?: string; detail?: string };
}
export interface UpdateLast {
  outcome: string;
  recommendedVersion?: string;
  fromVersion?: string;
  toVersion?: string;
  canaryVerdict?: string;
  at: number;
  by: string | null;
  reason?: string;
  // component (multi-component updates, ADDITIVE) names which component this outcome settled: "engine"
  // (or absent -- every legacy record predates the field and was an engine settle) or "console".
  // setUpdateSettled routes a "console" record to lastConsole + floors.console and never touches the
  // engine's pending/last, so the two components' histories cannot clobber each other.
  component?: string;
  // channelSeq/channelIssuedAt (R9, ADDITIVE): a settle that is itself the accepting act for a channel
  // descriptor (a console-only apply promotes + settles in one request, recording no engine pending)
  // advances the freshness watermark here, exactly as setUpdatePending does for an engine promote.
  channelSeq?: number;
  channelIssuedAt?: string;
  // confirmationPending (ADDITIVE): true only on an ENGINE "applied" outcome that was
  // KEPT via the self-check rather than a singing canary (an honest-but-provisional keep). The hourly
  // canary's background confirmation (notify-passes.ts confirmUpdateIfSettled) flips it to false, bookkeeping
  // only, no token needed, when it next sings on this SAME recommendedVersion; a DEAD flight leaves it
  // untouched (the existing unhealthy alerting + the console's token rollback cover that). Absent/false on
  // every legacy record and on any keep the canary itself confirmed.
  confirmationPending?: boolean;
  // minEngineVersion (ADDITIVE, CONSOLE-APPLY ONLY): the applied console component's
  // OWN minEngineVersion floor, read from the verified channel's console entry and persisted here at
  // console-apply time (router-updates-components.ts executeConsoleApply). It rides on the console's
  // settled record (lastConsole), never the engine's, and is the input the engine's OWN standalone-rollback
  // reads (engineRollbackSatisfiesConsoleFloor, update-rollback.ts) to decide whether an engine rollback may
  // proceed alone or must pair the console back to its recorded known-good. Absent = the applied console
  // declared no floor, or no console has ever applied here, or the console's live state moved since (a
  // rollback record does not carry a floor -- see executeConsoleRollback), each read as "no requirement".
  minEngineVersion?: string;
  // ---- Settle DECISION TRACE ( observability rework, ADDITIVE). ----
  // The one question a rolled-back / kept-pending settle must always answer -- WHY -- previously lived
  // ONLY in the settle HTTP response (probe.attempts), which races the isolate swap and is lost, so
  // neither a re-read, the audit log, nor a SUPPORT PACK could ever reconstruct it. These persist it.
  // selfCheckOk: did the new build boot + answer + self-identify + pass its critical preflight? Recorded
  // even though it no longer GATES the keep (decideKeep is optimistic): a rollback with selfCheckOk=true
  // is a genuine dead-canary (data) failure; a keep with selfCheckOk=false is an optimistic keep the
  // hourly canary must confirm. This one boolean distinguishes the two diagnoses a bare verdict cannot.
  selfCheckOk?: boolean;
  // settleTrace: one entry per canary flight / self-check ATTEMPT the settle made (probeSettleVerdict's
  // bounded post-swap retries), each { step, ok, detail }, so the full "flight 1 ailing -> flight 2
  // ailing -> self-check ok" story is durable in the record and rides into the support pack. Clamped
  // (bounded count, clamped detail) by the writer; absent on legacy records and on a clean first-flight keep.
  settleTrace?: Array<{ step: string; ok: boolean; detail?: string }>;
  // artefactSha384 (update provenance DP-0, ADDITIVE) is the signed channel digest of the artefact this
  // outcome concerns: on an engine settle it is copied from the pending record (the digest verified at
  // promote), on a console apply it is the verified channel entry's own sha384. It rides applied AND
  // rolled-back outcomes alike (a rollback is a statement ABOUT the promoted artefact, and the digest is
  // what identifies it); absent on legacy records, on refusals that shipped nothing, and on standalone
  // rollbacks (which consult the recorded known-good, not the channel). Public digest, redaction-safe.
  artefactSha384?: string;
  // readback (DP-D, ADDITIVE): the promote's read-back verdict, copied forward from the pending record at
  // settle so the outcome row remains self-contained evidence (see UpdatePending.readback).
  readback?: { verdict: string; mode: string; deployedSha384?: string; detail?: string };
  // percentage (ADDITIVE, RAMP-SETTLED APPLIED ONLY): a gradual ramp that settles applied is DELIBERATELY
  // still serving a two-version split (toVersion at this percentage, fromVersion the rest) until the
  // operator promotes to 100%. Persisting the split on the settled record lets the update-version-drift
  // posture logic treat BOTH slices as legitimately live instead of flapping "out-of-band redeploy" on
  // whichever slice served the posture read. Absent on every atomic settle and on rollbacks (collapsed
  // to a single version).
  percentage?: number;
}
export interface UpdateRecord {
  pending: UpdatePending | null;
  last: UpdateLast | null;
  // lastAlertedVersion is the most recent recommended version a "new version available" notification was
  // fired for (W3). It dedupes the one-shot alert: the cron claims a version via claimUpdateAlert, which
  // alerts ONLY when this differs from the recommended version, then records it, so a steady "update
  // available" state never re-fires every tick, and a NEW version (the field differs again) alerts once.
  // Additive + presence-safe: an old record without it reads as null (alert once on the next new version).
  lastAlertedVersion?: string | null;
  // rollbackNeeded marks that the hourly canary found a PROMOTED-but-unsettled new version UNHEALTHY (FOLD 1):
  // the engine cannot auto-roll-back unattended (no stored deploy credential), so this records that a
  // ONE-CLICK rollback is needed and dedupes the critical page (claimRollbackNeeded fires the alert only the
  // first time it is observed for a given version). The console surfaces it as an URGENT rollback prompt. It
  // is CLEARED on any settle/rollback (setUpdateSettled) since the pending is then resolved. Additive +
  // presence-safe (absent reads as none).
  rollbackNeeded?: { recommendedVersion: string; toVersion: string; canaryVerdict: string; at: number } | null;
  // settledHighWaterMark (R8) is the MONOTONIC highest engine version ever successfully SETTLED ("applied",
  // canary-passed), bumped by setUpdateSettled and NEVER lowered. The safe-apply route reads it as the
  // anti-rollback floor: an apply/ramp targeting a version below it is refused even with allowDowngrade, so a
  // signed channel can never push the customer below a build they have run (re-introducing a patched
  // vulnerability). Additive + presence-safe (absent = no version settled yet = no floor). Every read-modify-
  // write of this record MUST carry it forward (it is sticky), or the floor would be silently lost.
  // Multi-component updates: this scalar is now the LEGACY MIRROR of floors.engine (below) -- kept
  // dual-written so every deployed reader of the flat field keeps seeing the engine's floor.
  settledHighWaterMark?: string;
  // floors (multi-component updates, ADDITIVE + MIGRATING) is the per-component R8 anti-rollback map:
  // floors.engine / floors.console each hold the highest version of THAT component ever successfully
  // settled here, bumped monotonically by setUpdateSettled and never lowered. A legacy record carrying
  // only the settledHighWaterMark scalar MIGRATES ON FIRST READ as floors = { engine: scalar }
  // (getUpdateRecord; the migrateCanaryState read-time-migration precedent), and the scalar stays
  // mirrored from floors.engine on every write. Sticky exactly like the scalar.
  floors?: Record<string, string>;
  // lastConsole (multi-component updates, ADDITIVE) is the CONSOLE component's last settled outcome, the
  // twin of `last` (which remains the ENGINE's -- every legacy reader, including the standalone-rollback
  // target resolver, keeps its exact semantics). A console outcome must never clobber the engine's last
  // record (a later engine rollback would otherwise resolve a CONSOLE version id as its target), so the
  // components get separate slots. Presence-safe: absent = no console component ever settled here.
  lastConsole?: UpdateLast | null;
  // history (multi-component updates, ADDITIVE) is the bounded update-outcome ring: every settled outcome
  // (engine and console alike, each entry carrying its `component`) appended newest-last and capped at
  // UPDATE_HISTORY_CAP, so the console can render a real multi-component update history rather than only
  // the two last-outcome slots. Redaction-safe (the same UpdateLast shape: versions, outcomes, who/when).
  history?: UpdateLast[];
  // lastChannelSeq/lastChannelIssuedAt (R9) are the freshness watermark: the highest channel sequence and the
  // latest issuedAt the engine has accepted+acted on (advanced by setUpdatePending on a promote). The route
  // refuses a descriptor that regresses below them (a replay). Additive + presence-safe + sticky (carried
  // forward by every read-modify-write, like settledHighWaterMark).
  lastChannelSeq?: number;
  lastChannelIssuedAt?: string;
}
