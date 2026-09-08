// ===========================================================================================
// scheduler-do-base.ts is the IRREDUCIBLE FOUNDATION every mixin layers over: it holds
//   (1) the BaseSchedulerDO class = the DO constructor + the single `state` field the mixins extend, and
//   (2) the SchedulerDOSurface interface = the FULL structural instance API (the method/field surface each
//       mixin's `this` is typed as, so a method in one mixin can call a method in another with the same
//       dispatch the single class gave). It is a SINGLE source of truth generated from the live method
//       signatures (tsc declaration emit) and is kept whole rather than split, since fragmenting it would
//       break the one surface every mixin depends on.
// ===========================================================================================
//
// The scheduler Durable Object: the single authority plane for an account's downpipes
// (design F11). It owns the schedules, the per-downpipe run lock, and the monotonic
// runlogIndex allocation, and it uses DO alarms as the real per-downpipe timers so the
// account is not limited by the platform cron-trigger cap. It does NOT run the seal loop
// itself; the DO alarm only re-arms the next wakeup time. The cron driver in index.ts
// is the actual seal driver: on each tick it asks the DO for due downpipes (GET /due)
// and runs each out of the DO (trigger -> seal -> complete, design F11).
//
// Key decisions encoded here:
// - DO alarms are durable, so they are the primary timer; the Worker cron is only a
//   coarse reconciliation tick (design F12).
// - Jitter spreads many same-cadence downpipes so they do not stampede the account at
//   the top of the hour.
// - Coalescing: a downpipe whose previous run is still in flight is skipped, never
//   queued twice.
// - runlogIndex is allocated EARLY inside the storage transaction and gaps are tolerated
//   (the RUNLOG chains per downpipe via prevRunId; a global gap is fine, a rollback is
//   not), so a failed run never causes a double-allocation (design F10).

// Pure this-free helpers re-exported below (RESERVED_BINDINGS, primary/replica/allDestinationIds,
// scheduleTimeZone, deferPastBlackouts) so external importers keep working unchanged.


import type { RestoreApproval } from "../admin/approvals.ts";
import type { AuditDraft, AuditEvent, StatusObservation } from "../admin/audit.ts";
import type { ChangeRef } from "../admin/change-ref.ts";
import type { AmnesiaProbeClass, AutoHealRefusalCode, AutoHealSubCause, CandidateScan, ControlPlaneAmnesiaProbe, ControlPlaneDeployObservation, ControlPlaneExport, ControlPlaneExportHealth, ControlPlaneExportState, ControlPlaneImportOutcome, ControlPlaneRecoveryRecord, StagedControlPlane } from "../admin/control-plane.ts";
import type { CoverageReport } from "../admin/coverage.ts";
import type { AdminCounterName, AdminCounters } from "../admin/diag-records.ts";
import type { ExpiryItem, ExpiryKind, ExpiryLifecycleClass, ExpiryStatus } from "../admin/expiry.ts";
import type { AuthMethod, Capability, CustomRole, CustomRoleProposal, PendingRoleEntry, Role, RoleEntry, RoleSource } from "../admin/identity.ts";
import type { IdpConnection, SamlConnection } from "../admin/idpconn.ts";
import type { KvStorage } from "../admin/oidc-store.ts";
import type { PasskeyAssertionCeremony, PasskeyCred, PasskeyOwnerEvidence } from "../admin/passkey.ts";
import type { PostureDownpipeInput, PostureExpiryInput, PostureIdentityInput, PostureInput, PostureOverrideInput, PostureRegression, PostureReport, PostureWormInput, RiskAccept } from "../admin/posture.ts";
import type { PruneApproval } from "../admin/prune-approvals.ts";
import type { ReportPeriod, RestoreTestsData, SlaComplianceData } from "../admin/reports.ts";
import type { PointInTimeRun } from "../admin/restore-types.ts";
import type { RtoDownpipeInput, RtoEstimate } from "../admin/rto.ts";
import type { RunHistoryEntryWithChain } from "../admin/run-chain.ts";
import type { SsoFailCode } from "../admin/sso-failure-class.ts";
import type { DestPruneState } from "../cron/retention-dest-prune.ts";
import type { RetentionPassRecord } from "../cron/retention-record.ts";
import type { AlertState, ChannelKind, DeliveryFailCode, DigestBatch, DigestPeriod, DownpipeAlert, NotifyChannel, NotifyEmission, NotifyHistoryEntry, NotifyRule, SinkScreenVerdict } from "../notify.ts";

import type { ReconcileSignal } from "../seal/reconcile.ts";
import type { SealFault } from "../seal/seal-faults.ts";
// Shared scheduler/admin types moved to the leaf ./types.ts to break the scheduler-do<->admin-spoke
// import cycles. Imported here for internal use AND re-exported (below) so every module that imported
// these by name from scheduler-do.ts keeps working unchanged.
import type { AttestSession, BlackoutResolve, CronResolve, DownpipeConfig, DownpipeSchedule, DownpipeState, DrillEvidenceEntry, FleetDrillProgress, SchedHealthCounters, SchedHealthKind, StateRefusal, StateRefusedClass, StorageFaultCounter, StorageFaultKind, TickOutcome, TickReport } from "./types.ts";
import type { StatedPrecondition } from "./downpipe-precondition.ts";

export type {
  BlackoutWindow,
  DownpipeConfig,
  DownpipeSchedule,
  DownpipeState,
  DrillEvidenceEntry,
  DrillEvidenceKind,
  FleetDrillCampaign,
  FleetDrillProgress,
  IntegrityVerified,
  IntegrityVerifiedHow,
  LastConfigChange,
  RestoreProven,
  RestoreProvenMethod,
  RetentionPolicy,
  RunHistoryEntry,
  SealVerification,
  SealVerificationTier,
  SecretBindingSpec,
  SourceSpec,
} from "./types.ts";

import type {
  ConfigChangeKind,
  PendingConfigChange,
} from "../admin/change-control.ts";
import type {
  ConfigChange,
  ConfigSnapshot,
  ConfigVersion,
} from "../admin/config-history.ts";
import type { listPresets, } from "../admin/oidc-presets.ts";
import type {
  OwnerActionKind,
  PendingOwnerAction,
} from "../admin/owner-action.ts";
import type {
  RecoveryBreakGlassReason,
  RecoveryRecord,
} from "../admin/recovery.ts";
import type {
  RecoveryKeyContinuity,
  RosterVerdict,
  SignInFactorRevocation,
  SignInFactorRow,
} from "../admin/signin-factors.ts";
import type {
  CanaryFlightPlan,
  CanaryLiveness,
  CanaryState,
  CanaryTransition,
  CanaryView,
} from "../canary/types.ts";
import type { RosterHygieneReport } from "./roster-hygiene.ts";

export * from "./scheduler-do-limits.ts";
// The SchedulerDO's type + constant vocabulary lives in two pure leaves (scheduler-do-records.ts and
// scheduler-do-limits.ts), re-exported here so every module that imports these by name from
// scheduler-do-base.ts keeps working, and imported back below for the SchedulerDOSurface interface's
// own method signatures.
export * from "./scheduler-do-records.ts";
// Third pure leaf: the storage-key prefixes, bounded caps and small persisted-state shapes that
// were hoisted from the old single class's statics moved WHOLE to scheduler-do-keys.ts, comments intact.
// Re-exported verbatim here so every mixin that imports them from scheduler-do-base.ts is unchanged, and the
// handful of state shapes the SchedulerDOSurface interface itself names are imported back just below.
export * from "./scheduler-do-keys.ts";
import type { BeaconAttemptState, ChangeControlRefusalState, ConfigSnapshotFailureState, DriveBudgetYieldState, LicenceActivationRefusalState, StatusBaselineState } from "./scheduler-do-keys.ts";

import type {
  AuditHead,
  AuditVerifyMeta,
  DestinationCollection,
  DestinationConfig,
  DestStatusView,
  OtlpDownpipeMetrics,
  OtlpPushDeliveryAttempt,
  OtlpPushDestinationRecord,
  OtlpPushDestinationView,
  PushDeliveryAttempt,
  PushDestinationRecord,
  PushDestinationView,
  StoredDestination,
} from "./scheduler-do-limits.ts";
import type { CompleteRunReq, DestReplState, DiscoveryAccountSeen, DiscoveryConfig, ExpiryEmission, GroupRoleEntry, LicenceTokenRecord, MutationCaller, NotifyHealth, OrgPolicy, ReplAlertCooldown, UpdateLast, UpdatePending, UpdateRecord, VerifiedEngineAccount } from "./scheduler-do-records.ts";

// CONFIG_SCHEMA_VERSION is the schema version STAMPED onto a persisted DownpipeState (the per-downpipe
// config + run state under dp:<id>) at write time by persistDownpipeState, and CHECKED at read time by
// migrateOrRejectConfig. It mirrors the seal CHECKPOINT's `v:1` fail-closed gate (seal/checkpoint.ts) and
// the on-R2 archive's unknown-major rejection: the per-downpipe DO record was the one persisted surface
// with neither a version field nor a read-time guard, so a future engine that changed a load-bearing
// config field could read an old/new-shape record back as undefined and seal the WRONG/EMPTY source set
// while still reporting ok (a silent partial). Bump this ONLY when the on-disk DownpipeState shape changes
// in a way the running code must know about, and add the matching forward migration to migrateOrRejectConfig
// in the same change (the migrateCanaryState precedent in scheduler-do-canary.ts upgrades an older shape).
export const CONFIG_SCHEMA_VERSION = 1;

// migrateOrRejectConfig is the read-time guard for a persisted DownpipeState (the dp:<id> record), the
// single seam the LOAD-BEARING source-selection reads funnel through (due() and trigger() in
// SchedulerCoreMixin). It mirrors validateCheckpoint's fail-closed version gate and migrateCanaryState's
// read-time-migration precedent. Given the exact value storage.get returned:
//   - undefined (an absent key) passes through, so a caller's existing "unknown downpipe" handling is
//     unchanged.
//   - an ABSENT schemaVersion is a LEGACY record written before this stamp shipped: treated as v1 and
//     ACCEPTED unchanged (forward-compatible, so every existing record stays readable; behaviour is
//     byte-identical today).
//   - schemaVersion === CONFIG_SCHEMA_VERSION (the current shape) is ACCEPTED unchanged.
//   - schemaVersion strictly GREATER than CONFIG_SCHEMA_VERSION is a record written by a NEWER engine that
//     this (older) code was rolled back from. The new-shape record may carry load-bearing fields this code
//     does not understand, so reading it blindly risks sealing a wrong/empty source set. FAIL LOUD (throw)
//     so the caller skips-with-alert (due) or fails the run (trigger) rather than silently mis-reading it.
//   - any OTHER value (a number BELOW current, once this code is itself a later version, or a non-number
//     from a corrupt/hand-edited record) is ACCEPTED, so the ONLY new failure path is the strictly-newer
//     case above. A future v2->v1 migration would be added here, accepting and upgrading the older shape,
//     exactly as migrateCanaryState upgrades a pre-multi-destination canary record.
//
// G095/G210: the refusal now throws a TYPED StateRefusedError carrying the closed class and the stored version,
// so the caller (due()/trigger()) can STAMP the refusal as pack-visible evidence instead of coarsening it to a
// Workers Logs line. And a PRESENT-but-non-number schemaVersion is now REFUSED rather than accepted: a corrupt or
// hand-edited stamp (e.g. the string "2") would otherwise DEFEAT the guard silently and let this older code read
// new-shape state. An ABSENT schemaVersion is still the legacy-v1 accept path, so every existing record stays
// readable and behaviour is unchanged for them.
export function migrateOrRejectConfig(raw: DownpipeState | undefined): DownpipeState | undefined {
  if (raw === undefined) return undefined;
  const v = raw.schemaVersion;
  if (v !== undefined && typeof v !== "number") {
    throw new StateRefusedError("schema-version-malformed", 0, `downpipe state schemaVersion is not a number; refusing to read a record whose version stamp is corrupt`);
  }
  if (typeof v === "number" && v > CONFIG_SCHEMA_VERSION) {
    throw new StateRefusedError("schema-newer", v, `downpipe state schemaVersion ${v} is newer than this engine supports (${CONFIG_SCHEMA_VERSION}); refusing to read new-shape state under older code`);
  }
  return raw;
}

// StateRefusedError is the TYPED read-time refusal migrateOrRejectConfig throws. It carries the closed
// StateRefusedClass and the stored version as an integer so the caller can persist redaction-safe evidence
// (a class + two ints + a count + a time). The human message stays for the internal log ONLY; it never rides
// into the stamp or the pack.
export class StateRefusedError extends Error {
  readonly refusalClass: StateRefusedClass;
  readonly storedVersion: number;
  constructor(refusalClass: StateRefusedClass, storedVersion: number, detail: string) {
    super(detail);
    this.name = "StateRefusedError";
    this.refusalClass = refusalClass;
    this.storedVersion = Number.isFinite(storedVersion) ? Math.max(0, Math.floor(storedVersion)) : 0;
  }
}

// engine-src-037-03: AuthError is the typed authorisation refusal. A capability/role/owner gate that
// denies a caller throws this rather than a bare Error, so the fetch() catch can map it to a 403 (an
// authz failure, not bad input) and return a generic public message. The capability/role detail is
// carried in the message for the INTERNAL log only; it is never echoed to the caller, so a refusal
// cannot enumerate which capability or role a route requires.
export class AuthError extends Error {
  constructor(detail: string) {
    super(detail);
    this.name = "AuthError";
  }
}

// ===========================================================================================
// SchedulerDOSurface is the FULL structural instance API of the SchedulerDO. Cohesive method groups
// live in mixin factories in sibling files; each mixin's `this` is typed as this surface, so a method
// in one mixin can call a method in another (or in the base/final class) with the same dispatch and
// `this` binding a single class would give. The body is generated from the live method signatures
// (tsc declaration emit) and kept in lockstep by the compiler. It declares the one instance field
// (state) plus the instance method set (class statics stay on their mixin, not here).
// ===========================================================================================
export interface SchedulerDOSurface {
  readonly state: DurableObjectState;
  fetch(req: Request): Promise<Response>;
  route(req: Request): Promise<Response>;
  // route() RPC dispatch is split across four cohesive sub-mixins (RoutingMixin holds route() + the core
  // data plane; RoutingSignalsMixin / RoutingConfigMixin / RoutingIdentityMixin hold the rest). route()
  // chains every per-subsystem sub-dispatch through `this`, so each must be on the surface for the
  // cross-mixin call to resolve. Each returns the handler Response for a key it owns, or null to pass.
  notFoundResponse(): Response;
  routeCore(req: Request, url: URL): Promise<Response | null>;
  routeIngestCredential(req: Request, url: URL): Promise<Response | null>;
  routeSiemPush(req: Request, url: URL): Promise<Response | null>;
  routeOtlpPush(req: Request, url: URL): Promise<Response | null>;
  routeRunlogRate(req: Request, url: URL): Promise<Response | null>;
  routeRbac(req: Request, url: URL): Promise<Response | null>;
  routeAudit(req: Request, url: URL): Promise<Response | null>;
  routeRestoreApproval(req: Request, url: URL): Promise<Response | null>;
  routePruneApproval(req: Request, url: URL): Promise<Response | null>;
  routeSreAlerting(req: Request, url: URL): Promise<Response | null>;
  routeNotify(req: Request, url: URL): Promise<Response | null>;
  routeExpiry(req: Request, url: URL): Promise<Response | null>;
  routeDemo(req: Request, url: URL): Promise<Response | null>;
  routeRestoreTests(req: Request, url: URL): Promise<Response | null>;
  routePosture(req: Request, url: URL): Promise<Response | null>;
  routeReports(req: Request, url: URL): Promise<Response | null>;
  routeCoverage(req: Request, url: URL): Promise<Response | null>;
  routeConfigVersion(req: Request, url: URL): Promise<Response | null>;
  routePolicy(req: Request, url: URL): Promise<Response | null>;
  routeDestConfig(req: Request, url: URL): Promise<Response | null>;
  routeConfigChanges(req: Request, url: URL): Promise<Response | null>;
  routePasskey(req: Request, url: URL): Promise<Response | null>;
  routeStepUp(req: Request, url: URL): Promise<Response | null>;
  routeIdp(req: Request, url: URL): Promise<Response | null>;
  routeRecovery(req: Request, url: URL): Promise<Response | null>;
  routeControlPlane(req: Request, url: URL): Promise<Response | null>;
  // The CRON + ADMIN diagnostic recorders / pack reads (SupportDiagMixin, gaps G163/G049/G158/G100/G331).
  // On the surface because they are cross-mixin: the passkey mixin records a structural WebAuthn fault, the
  // routing mixin dispatches the recording + read routes, and the Worker edge posts the rest.
  routeSupportDiag(req: Request, url: URL): Promise<Response | null>;
  recordWebauthnFault(phase: string, cls: string, coseAlg?: number): Promise<void>;
  // The IN-DO admin-counter writers (SupportDiagMixin owns the aggregate; the scheduling, reporting, expiry,
  // dual-control, restore-approval and RBAC mixins raise the counters), folding through the same bounded
  // applyAdminCounters chokepoint the Worker edge posts to. The THROTTLED form is for the hot read paths.
  bumpAdminCounterLocal(name: AdminCounterName, n?: number): Promise<void>;
  bumpAdminCounterLocalThrottled(name: AdminCounterName): Promise<void>;
  // readAdminCounters is the pack read (GET /admin-counters) surfaced on `this` so a sibling mixin (the
  // control-plane recovery-status route) can fold the "was a critical alert ever delivered" signal into an
  // ALREADY-POLLED response, not only into the reactively-pulled support pack.
  readAdminCounters(): Promise<AdminCounters>;
  // pre carries the OPERATOR'S BASE CHECK (sched/downpipe-precondition.ts): what the caller stated about
  // the revision they read, and whether this call site wants the resurrect guard. Optional so the
  // control-plane replay, which restores a signature-verified export after a wipe, can pass nothing.
  addDownpipe(
    config: DownpipeConfig,
    caller?: MutationCaller | null,
    pre?: { stated: StatedPrecondition; guardResurrect: boolean },
  ): Promise<DownpipeState>;
  setCfConfigMode(params: { id?: unknown; mode?: unknown }): Promise<{ ok: true }>;
  listAllByPrefix<T>(prefix: string): Promise<Map<string, T>>;
  listDownpipes(): Promise<DownpipeState[]>;
  // The content-free fleet aggregate the opt-in vendor beacon carries (counts only; never per-downpipe).
  beaconAggregate(): Promise<{ downpipeCount: number; healthy: number; stalled: number; runlogMaxIndex: number }>;
  // The last opt-in vendor-beacon POST outcome: recorded by the beacon pass after each attempt, read by
  // the support pack so a lost/failing beacon (beacon-post-lost) is visible without the beacon path
  // holding any state itself. Closed shape only (a timestamp + a bool + a clamped HTTP status).
  recordBeaconAttempt(req: { ok?: unknown; status?: unknown }): Promise<{ ok: true }>;
  getBeaconState(): Promise<BeaconAttemptState | null>;
  // The cumulative cron seal-loop budget-yield record (failover-probe-budget-exhaustion): recorded by the cron
  // when a low shared subrequest budget carried undispatched due downpipes to the next tick, read by the
  // support pack so an over-budget fleet's silently-starved tail is visible. Closed shape (count + ts + int).
  recordDriveBudgetYield(req: { carried?: unknown }): Promise<{ ok: true }>;
  getDriveBudgetYield(): Promise<DriveBudgetYieldState | null>;
  // The cumulative change-controlled-action refusal tally (change-number-required-refusal): bumped by
  // enforceChangeControl when a change reference is required but absent/invalid, WITHOUT touching the CR
  // ledger (a refusal records no change-recorded entry). Read by the support pack. Closed shape only.
  getChangeControlRefusals(): Promise<ChangeControlRefusalState>;
  // The cumulative config auto-snapshot failure tally (config-snapshot-best-effort-gap): a count + last time,
  // bumped when autoSnapshotConfig swallows a failed capture, so an un-versioned config change is visible.
  getConfigSnapshotHealth(): Promise<ConfigSnapshotFailureState>;
  // The lightweight config-history integrity verdict (config-history-session-key-regen): the chain verify
  // result PLUS a signingKeyRotated flag that distinguishes an in-DO signing-key rotation (recoverable) from
  // genuine content tamper (brokenAt), WITHOUT serialising the whole version list. Read by the support pack.
  configHistoryHealth(): Promise<{ count: number; headId: number; verify: { intact: boolean; checkedThrough: number; earliestId: number; brokenAt?: number; signingKeyRotated?: boolean; headTruncated?: boolean; headTruncatedAt?: number } }>;
  // The console licence-activation refusal tally (failed-activation-no-trace): recorded by the router on a
  // verify-before-store refusal (a token that did not verify), read by the support pack. Closed shape only
  // (a count + timestamp + a closed reason code); null when no activation has ever been refused.
  recordLicenceActivationRefusal(req: { reasonCode?: unknown }): Promise<{ ok: true }>;
  getLicenceActivationRefusal(): Promise<LicenceActivationRefusalState | null>;
  // The engine deploy-identity marker recorded at each status-snapshot baseline (engine-version-change-
  // baseline-suppressed / same-version-redeploy-double-blind): the version + Cloudflare deploy id + time
  // observed when the baseline was (re-)established, read by the support pack so a snapshot RESET is
  // attributable. Null until the first observation. Written by observeStatus, never a value.
  getStatusBaseline(): Promise<StatusBaselineState | null>;
  destinationForRun(runId: string): Promise<string | null>;
  destinationsForRun(runId: string): Promise<string[]>;
  removeDownpipe(
    req: {
      id: string;
    },
    pre?: { stated: StatedPrecondition; caller?: MutationCaller | null },
  ): Promise<{
    deleted: boolean;
    // How many key-id mismatch ghost rows claiming this id were swept alongside the direct delete
    // (roster-hygiene.ts); omitted when none were found (the overwhelmingly common case).
    swept?: number;
    // The CONFIG revision that was removed, so a caller can tell "I deleted the thing I was looking at"
    // from "I deleted whatever was there". Omitted when no canonical record existed (a pure ghost sweep).
    deletedRev?: number;
  }>;
  // Roster structural integrity: ghost rows (key-id mismatch / malformed) the delete route cannot
  // reach, plus well-formed never-ran rows (what a standing "Unknown" map edge is when the roster
  // is sound). Read-only; the support pack projects it. Repair via reconcileRoster.
  rosterHygiene(): Promise<RosterHygieneReport>;
  reconcileRoster(): Promise<{
    removed: number;
    rehomed: number;
    ghostsRemaining: number;
  }>;
  acquireRunlogLock(key?: string): Promise<{
    acquired: boolean;
    token?: string;
  }>;
  releaseRunlogLock(req: {
    token: string;
    key?: string;
  }): Promise<{
    ok: true;
  }>;
  acquireTickLease(): Promise<{
    acquired: boolean;
    token?: string;
  }>;
  releaseTickLease(req: {
    token?: string;
  }): Promise<{
    ok: true;
  }>;
  rateCheck(req: {
    key?: string;
    cost?: number;
    max?: number;
  }): Promise<{
    allowed: boolean;
    retryAfterMs: number;
  }>;
  normaliseEmail(raw: unknown): string | null;
  normaliseSubject(raw: unknown): string | null;
  listRoleEntries(): Promise<RoleEntry[]>;
  listPendingEntries(): Promise<PendingRoleEntry[]>;
  // How many stored role records BOTH readers above refuse to parse. Counted rather than merely dropped, so a
  // verdict computed from the rows that parsed can say so (boundaries-plan defect 31).
  countUnreadableRoleRows(): Promise<number>;
  asPending(email: string, rec: Record<string, unknown>): PendingRoleEntry;
  pendingStorageKeysFor(email: string): string[];
  roleTableIsEmpty(): Promise<boolean>;
  // FAILS OPEN: "unreadable" for a storage fault and for an empty roster; only "off-roster" refuses.
  rosterMembership(email: string | null): Promise<RosterVerdict>;
  resolveBoundEntry(subject: string, email: string | null, allowEmailBind?: boolean, emailVerifiedStrong?: boolean): Promise<RoleEntry | undefined>;
  effectiveRole(entry: RoleEntry | PendingRoleEntry | undefined, now: number): Role;
  isExpired(entry: { expiresAt?: string } | undefined, now: number): boolean;
  countOwners(entries: RoleEntry[], pending: PendingRoleEntry[], now: number): number;
  expiringOwnerGrantCount(): Promise<number>; // owner-floor.ts's strand invariant, leg 3; three mixins read it
  capGroupRole(role: Role): Role;
  normaliseGroup(raw: unknown): string | null;
  // The DO's own bounding of a groups list. `drops`/`boundary` are the OPTIONAL claim-drop tally (G271): the
  // native session mint passes them so the SAML front door's group drops name their KIND and their BOUNDARY,
  // rather than resolving to the coarse group-name-dropped count alone. Every other caller bounds silently.
  boundGroupList(raw: unknown[], drops?: Set<string>, boundary?: string): string[];
  listGroupRoleEntries(): Promise<GroupRoleEntry[]>;
  groupRoleFor(groups: string[], mapping: GroupRoleEntry[]): Role | null;
  resolveRole(emailEntry: RoleEntry | undefined, groups: string[], roleMapping: GroupRoleEntry[], now: number): {
    role: Role;
    source: RoleSource;
  };
  customRoleNamesFor(emailEntry: RoleEntry | undefined, groups: string[], mapping: GroupRoleEntry[], now: number): string[];
  resolveAuthority(emailEntry: RoleEntry | undefined, groups: string[], roleMapping: GroupRoleEntry[], customRoles: Map<string, CustomRole>, now: number): {
    role: Role;
    source: RoleSource;
    capabilities?: ReadonlySet<Capability>;
    customRole?: CustomRole;
  };
  listCustomRoleRecords(): Promise<Map<string, CustomRole>>;
  roleForCaller(caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
    // replay marks a caller that is a RECORDED identity being re-resolved, not a live authenticated request.
    // Its only effect is to suppress bind-on-first-auth; see roleForCaller for why that has to be suppressed.
    replay?: boolean;
  } | null): Promise<{
    role: Role;
    source: RoleSource;
    capabilities?: ReadonlySet<Capability>;
    customRole?: CustomRole;
  }>;
  capabilitiesOfResolved(resolved: {
    role: Role;
    capabilities?: ReadonlySet<Capability>;
  }): ReadonlySet<Capability>;
  withResolvedCaps(caller: MutationCaller | null): Promise<MutationCaller | null>;
  // The SPEND-TIME authority re-resolution: given a principal recorded on a stored governance record, what do
  // they hold NOW? It is here because the restore AND prune approval mixins both call it; its own helper
  // spendTimeGroupsFor is deliberately NOT here, being called only from within the mixin that defines it.
  resolveStoredIdentityAuthority(subject: string | undefined, email: string | undefined, recordedGroups: readonly string[] | undefined): Promise<ReadonlySet<Capability>>;
  listRoles(): Promise<RoleEntry[]>;
  parseGroupsParam(raw: string | null): string[];
  whoami(emailRaw: string | null, subjectRaw: string | null, method: string | null, groupsRaw: string | null, sourceIpRaw?: string | null): Promise<{
    role: Role;
    roleSource: RoleSource;
    subject?: string;
    groups: string[];
    isOnlyOwner: boolean;
    customRole?: CustomRole;
    capabilities?: Capability[];
    recoveryRequired?: true;
  }>;
  requireCapabilityResolved(caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null, capability: Capability): Promise<{
    role: Role;
    source: RoleSource;
    capabilities: ReadonlySet<Capability>;
  }>;
  requireNotOwnerEscalation(callerRole: Role, grantingOwner: boolean, demotingOwner: boolean): void;
  requireGrantWithinAuthority(resolved: {
    role: Role;
    capabilities?: ReadonlySet<Capability>;
  }, assignedCaps: ReadonlySet<Capability>): void;
  setRole(req: {
    email?: string;
    role?: string;
    customRole?: string;
    expiresAt?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<(RoleEntry | PendingRoleEntry) & {
    inviteToken?: string;
    inviteState?: "minted" | "already-enrolled";
  }>;
  deleteRole(req: {
    email?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    deleted: boolean;
  }>;
  listGroupRoles(): Promise<GroupRoleEntry[]>;
  setGroupRole(req: {
    group?: string;
    role?: string;
    customRole?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<GroupRoleEntry>;
  deleteGroupRole(req: {
    group?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    deleted: boolean;
  }>;
  listCustomRoles(): Promise<CustomRole[]>;
  addCustomRole(proposal: CustomRoleProposal, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<CustomRole>;
  deleteCustomRole(req: {
    name?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    deleted: boolean;
  }>;
  loadAuditHead(): Promise<AuditHead>;
  // The ONE decision about whether a PRESENT head pointer may be believed, shared by the status probe and
  // the disaster-recovery export so the two cannot disagree about a corrupt record (defect 30).
  auditHeadTrust(): Promise<{ head: AuditHead; usable: boolean }>;
  appendAudit(draft: AuditDraft): Promise<AuditEvent>;
  rollOverAudit(dropCount: number): Promise<void>;
  auditCountAndNearCap(): Promise<{
    auditCount: number;
    auditNearCap: boolean;
    // How many entries the rollover has ALREADY destroyed. auditCount saturates at AUDIT_CAP, so the
    // boolean alone reads the same before and after the first loss (scheduler-do-audit.ts has the detail).
    auditRolledOverCount: number;
  }>;
  appendAuditFromRouter(draft: AuditDraft): Promise<AuditEvent>;
  listAuditEntries(): Promise<AuditEvent[]>;
  readAudit(params: URLSearchParams): Promise<{
    events: AuditEvent[];
    headSeq: number;
    headHash: string;
  }>;
  verifyAudit(): Promise<{
    intact: boolean;
    checkedThrough: number;
    earliestSeq: number;
    rolledOver: boolean;
    rolledOverCount: number;
    brokenAt?: number;
    // G313: the head-anchor verdict. `intact` speaks only for the entries still retained; this says whether the
    // newest ones were DELETED (a recompute over the survivors cannot see a removed tail).
    headTruncated?: boolean;
    headTruncatedAt?: number;
    auditCount: number;
    auditNearCap: boolean;
    verify: AuditVerifyMeta;
  }>;
  exportAudit(params: URLSearchParams): Promise<Response>;
  observeStatus(obs: StatusObservation): Promise<{
    appended: number;
    auditCount: number;
    auditNearCap: boolean;
    auditRolledOverCount: number;
  }>;
  requireCapability(caller: {
    role: Role;
    capabilities?: ReadonlySet<Capability>;
  } | null, capability: Capability): void;
  callerHolds(caller: {
    role: Role;
    capabilities?: ReadonlySet<Capability>;
  } | null, capability: Capability): boolean;
  requestRestore(req: {
    planHash?: string;
    runId?: string;
    isLatest?: boolean;
    plannedWrites?: number;
    bytes?: number;
    redirectBinding?: string | null;
    reason?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    sourceIp?: string | null;
  } | null): Promise<RestoreApproval>;
  approveRestore(req: {
    planHash?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    sourceIp?: string | null;
  } | null): Promise<RestoreApproval>;
  rejectRestore(req: {
    planHash?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    sourceIp?: string | null;
  } | null): Promise<RestoreApproval>;
  listApprovals(caller: {
    email: string | null;
    subject: string | null;
    role: Role;
  } | null, callerIsApprover: boolean): Promise<RestoreApproval[]>;
  gateRestore(req: {
    planHash?: string;
  }): Promise<{
    usable: boolean;
    approval: RestoreApproval | null;
    required: boolean;
  }>;
  reserveRestore(req: {
    planHash?: string;
  }): Promise<{
    reserved: boolean;
  }>;
  releaseRestore(req: {
    planHash?: string;
  }): Promise<{
    released: boolean;
  }>;
  consumeApproval(req: {
    planHash?: string;
  }): Promise<{
    consumed: boolean;
    approval?: RestoreApproval;
  }>;
  // Dual control (prune-approvals.ts): the PruneApproval state machine, mirroring the eight
  // RestoreApproval methods above over the leaner prune-shaped record.
  pruneCallerHolds(caller: {
    role: Role;
    capabilities?: ReadonlySet<Capability>;
  } | null, capability: Capability): boolean;
  requestPruneApproval(req: {
    planHash?: string;
    downpipeId?: string;
    retainedRuns?: number;
    supersededRuns?: number;
    reason?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    sourceIp?: string | null;
  } | null): Promise<PruneApproval>;
  approvePruneApproval(req: {
    planHash?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    sourceIp?: string | null;
  } | null): Promise<PruneApproval>;
  rejectPruneApproval(req: {
    planHash?: string;
    rejectReason?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    sourceIp?: string | null;
  } | null): Promise<PruneApproval>;
  listPruneApprovals(caller: {
    email: string | null;
    subject: string | null;
    role: Role;
  } | null, callerIsApprover: boolean): Promise<PruneApproval[]>;
  gatePruneApproval(req: {
    planHash?: string;
  }): Promise<{
    usable: boolean;
    approval: PruneApproval | null;
  }>;
  reservePruneApproval(req: {
    planHash?: string;
  }): Promise<{
    reserved: boolean;
  }>;
  releasePruneApproval(req: {
    planHash?: string;
  }): Promise<{
    released: boolean;
  }>;
  consumePruneApproval(req: {
    planHash?: string;
  }): Promise<{
    consumed: boolean;
    approval?: PruneApproval;
  }>;
  recordDrillEvidence(req: {
    runId?: string;
    kind?: string;
    note?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    sourceIp?: string | null;
  } | null): Promise<DrillEvidenceEntry>;
  listDrillEvidence(): Promise<DrillEvidenceEntry[]>;
  reconcileAlerts(): Promise<{
    alerts: DownpipeAlert[];
    pendingTransitionIds: string[];
    successes: NotifyEmission[];
    // recoveries (mon-autoresolve): one NotifyEmission per downpipe whose backup-failure/backup-stale
    // cooldown just cleared (recovered:true, same event + downpipeId as the trigger it closes), PLUS a
    // re-emission for any downpipe with an owed resolve whose prior delivery failed (finding F4 retry).
    recoveries: NotifyEmission[];
    // pendingRecoveryIds (finding F4): the downpipe ids whose recovery was re-emitted from an owed-resolve
    // marker this tick, so the Worker knows which recoveries are retries whose outcome it must report back.
    pendingRecoveryIds: string[];
  }>;
  recordRecoveryDelivery(req: {
    deliveredIds?: string[];
    failed?: Array<{ id?: unknown; state?: unknown }>;
  }): Promise<{ cleared: number; owed: number }>;
  markAlertsDelivered(req: {
    deliveredIds?: string[];
    failedTransitionIds?: string[];
  }): Promise<{
    cleared: number;
  }>;
  runCronDeadManSweep(): Promise<void>;
  reconcileReplicationAlerts(): Promise<{
    emissions: NotifyEmission[];
    pendingTransitionIds: string[];
    // recoveries (mon-autoresolve): one NotifyEmission per downpipe whose replication-degraded/
    // run-at-risk-eviction cooldown just cleared (recovered:true, same event + downpipeId it closes).
    recoveries: NotifyEmission[];
  }>;
  markReplicationAlertsDelivered(req: {
    failedTransitionIds?: string[];
  }): Promise<{
    cleared: number;
  }>;
  reconcileSourceDrift(missing: string[]): Promise<{ newlyDetached: string[] }>;
  // needs-new-logging (SreAlertingMixin): the per-downpipe alert-cooldown state (cooldown-suppresses-renudge)
  // so "why didn't I get re-alerted" is answerable -- a still-broken pipe is suppressed until at + cooldownMs.
  listAlertCooldowns(): Promise<{ cooldownMs: number; alert: Array<{ downpipeId: string; state: AlertState; at: number }>; replication: Array<{ downpipeId: string; state: ReplAlertCooldown["state"]; at: number }> }>;
  reconcileVolumeRegression(regressed: string[]): Promise<{ newlyRegressed: string[] }>;
  requireNotifyConfig(caller: {
    role: Role;
    capabilities?: ReadonlySet<Capability>;
  } | null): void;
  listNotifyChannelsRaw(): Promise<NotifyChannel[]>;
  listNotifyRulesRaw(): Promise<NotifyRule[]>;
  listNotifyChannels(): Promise<NotifyChannel[]>;
  getNotifyChannel(id: string | null): Promise<{
    channel: NotifyChannel | null;
  }>;
  recordTestSend(caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    capabilities?: ReadonlySet<Capability>;
    sourceIp?: string | null;
  } | null, body: {
    channelId?: unknown;
    delivered?: unknown;
    detail?: unknown;
    code?: unknown;
    platformCode?: unknown;
  }): Promise<{
    ok: boolean;
    reason?: string;
  }>;
  addNotifyChannel(raw: unknown, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    capabilities?: ReadonlySet<Capability>;
    sourceIp?: string | null;
  } | null): Promise<NotifyChannel>;
  deleteNotifyChannel(req: {
    id?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    capabilities?: ReadonlySet<Capability>;
    sourceIp?: string | null;
  } | null): Promise<{
    deleted: boolean;
  }>;
  listNotifyRules(): Promise<NotifyRule[]>;
  addNotifyRule(raw: unknown, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    capabilities?: ReadonlySet<Capability>;
    sourceIp?: string | null;
  } | null): Promise<NotifyRule>;
  deleteNotifyRule(req: {
    id?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    capabilities?: ReadonlySet<Capability>;
    sourceIp?: string | null;
  } | null): Promise<{
    deleted: boolean;
  }>;
  listNotifyHistory(): Promise<NotifyHistoryEntry[]>;
  parseEmission(raw: unknown): NotifyEmission | null;
  resolveNotify(req: {
    emission?: unknown;
  }): Promise<{
    now: NotifyChannel[];
    digestedCount: number;
    emission: NotifyEmission | null;
  }>;
  appendDigestEntry(emission: NotifyEmission, channel: NotifyChannel, period: DigestPeriod): Promise<void>;
  digestDue(req: {
    nowMs?: unknown;
  }): Promise<{
    batches: DigestBatch[];
  }>;
  digestSent(req: {
    ids?: unknown;
  }): Promise<{
    cleared: number;
  }>;
  recordNotify(req: {
    emission?: unknown;
    records?: unknown;
  }): Promise<{
    recorded: number;
    skipped: number;
  }>;
  appendNotifyHistory(emission: NotifyEmission, channelId: string, channelKind: ChannelKind, delivered: boolean, extra?: { code?: DeliveryFailCode; platformCode?: string; recovered?: boolean; sinkScreen?: SinkScreenVerdict; unconfirmed?: boolean }): Promise<void>;
  // NOTIF needs-new-logging: the notify-pipeline drop counters (whole passes skipped / per-channel records
  // dropped / emissions rejected / delivery-feedback failures) so "alerts silently stopped" is diagnosable.
  bumpNotifyHealth(field: "passSkips" | "recordSkips" | "parseRejects" | "feedbackFails", by?: number): Promise<void>;
  getNotifyHealth(): Promise<NotifyHealth | null>;
  digestPending(): Promise<{ count: number; oldestAt: string | null; byPeriod: Partial<Record<DigestPeriod, { count: number; oldestAt: string; dueAt: string }>> }>;
  listExpiryItemsRaw(): Promise<ExpiryItem[]>;
  listExpiryStatuses(): Promise<ExpiryStatus[]>;
  addExpiryItem(raw: unknown, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    capabilities?: ReadonlySet<Capability>;
    sourceIp?: string | null;
  } | null): Promise<ExpiryItem>;
  deleteExpiryItem(req: {
    id?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    capabilities?: ReadonlySet<Capability>;
    sourceIp?: string | null;
  } | null): Promise<{
    deleted: boolean;
  }>;
  reconcileExpiry(): Promise<{
    emissions: ExpiryEmission[];
  }>;
  expiryWarningCount(): Promise<{
    expiryWarnings: number;
    cleanupPending: number;
    // The rows the engine could not assess at all, carried as their own figure so a damaged record can never
    // be absorbed into the zero that means "nothing to warn about" (boundaries-plan defect 32).
    expiryUnreadable: number;
  }>;
  upsertObservedItem(partial: {
    id: string;
    label: string;
    kind: ExpiryKind;
    expiresAt?: string;
    lifecycleClass?: ExpiryLifecycleClass;
    purpose?: string;
    permissionSummary?: string;
    usageLink?: {
      kind: "destination" | "idpConnection" | "sourceBinding";
      refId: string;
    };
    tokenRef?: string;
    usedAt?: string;
    cleanupState?: "pending" | "attested-deleted";
  }): Promise<void>;
  deleteObservedItem(id: string): Promise<void>;
  observeLicence(body: {
    notAfter?: unknown;
  }): Promise<{
    ok: true;
  }>;
  observeAttach(body: {
    tokenId?: unknown;
    expiresOn?: unknown;
    permissionSummary?: unknown;
    sourcesAttached?: unknown;
  }): Promise<{
    ok: true;
  }>;
  cleanupAttest(body: {
    id?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    capabilities?: ReadonlySet<Capability>;
    sourceIp?: string | null;
  } | null): Promise<{
    ok: true;
    updated: boolean;
  }>;
  restoreTestsDue(): Promise<{
    due: DownpipeState[];
  }>;
  completeRestoreTest(req: {
    id?: string;
    ok?: boolean;
    at?: number;
    reason?: string;
    durationMs?: number;
    bytesVerified?: number;
    recordsVerified?: number;
    deepVerify?: { runId?: string; cursor?: number; records?: number; wrapped?: boolean };
    oom?: { maxRecordBytes?: number; safeBytes?: number; overSafe?: boolean };
  }): Promise<{
    ok: true;
  }>;
  startRestoreTest(req: {
    id?: string;
    at?: number;
  }): Promise<{
    ok: true;
  }>;
  // The three OBSERVE writers take the posted body WHOLE. Each has a pure sanitiser (sanitiseReconcileSignal /
  // sanitiseSealFault / sanitiseRetentionPassRecord) that IS the allowlist, so re-naming the fields on the
  // surface would only let the two drift apart -- which is exactly how the reconcile split counts and the
  // retention prune evidence were being dropped before they ever reached storage.
  recordReconcileInventory(body: Record<string, unknown>): Promise<{
    ok: true;
  }>;
  reconcileInventory(): Promise<{
    byDest: ReconcileSignal[];
  }>;
  recordSealFault(body: Record<string, unknown>): Promise<{
    ok: true;
  }>;
  sealFaults(): Promise<{
    faults: SealFault[];
  }>;
  recordRetentionPass(body: Record<string, unknown>): Promise<{
    ok: true;
  }>;
  retentionState(): Promise<{
    record: RetentionPassRecord | null;
  }>;
  recordRestoreProven(req: {
    downpipeId?: string;
    method?: string;
    runId?: string;
    at?: number;
  }, caller: {
    role: Role;
    email: string | null;
  } | null): Promise<{
    ok: boolean;
  }>;
  // Attended verification (key-posture attend): the NARROW per-run compliance stamp + the session state
  // machine (scheduler-do-attest.ts). recordAttendedVerification writes only the restore-test recency fields
  // (marking the kind "attended" + the sample rate) and, on a FULL proven pass, restoreProven +
  // integrityVerified; it never touches the RTO/deep-verify/OOM/retest/fleet-drill machinery. The five
  // attestSession* methods own the durable session under `attest-session:<id>` (create pins runs + stamps the
  // owner, get/markProven/recordVerify/abort are all owner-enforced). All carry only redaction-safe state;
  // the session record holds NO key material (a sampling seed + a proof hash, never a master), enforced by
  // AttestSession's closed shape.
  recordAttendedVerification(req: {
    downpipeId?: string;
    runId?: string;
    ok?: boolean;
    sampleRate?: number;
    provenSession?: boolean;
    reason?: string;
    at?: number;
  }, caller: {
    role: Role;
    email: string | null;
    capabilities?: ReadonlySet<Capability>;
  } | null): Promise<{
    ok: boolean;
  }>;
  attestSessionCreate(req: {
    sampleRate?: number;
    seedB64?: string;
    proofHash?: string;
    runs?: Array<{ downpipeId?: string; runId?: string; name?: string; recordCount?: number }>;
  }, caller: {
    role: Role;
    email: string | null;
    subject: string | null;
    capabilities?: ReadonlySet<Capability>;
  } | null): Promise<{
    created: boolean;
    session?: AttestSession;
    alreadyActive?: boolean;
    existingId?: string;
    status?: AttestSession["status"];
  }>;
  attestSessionGet(id: string, caller: {
    role: Role;
    email: string | null;
    subject: string | null;
    capabilities?: ReadonlySet<Capability>;
  } | null): Promise<{
    session: AttestSession | null;
  }>;
  attestSessionMarkProven(id: string, caller: {
    role: Role;
    email: string | null;
    subject: string | null;
    capabilities?: ReadonlySet<Capability>;
  } | null): Promise<{
    ok: boolean;
  }>;
  attestSessionRecordVerify(req: {
    id?: string;
    results?: Array<{ runId?: string; state?: string; recordsVerified?: number; recordsTotal?: number; at?: number }>;
  }, caller: {
    role: Role;
    email: string | null;
    subject: string | null;
    capabilities?: ReadonlySet<Capability>;
  } | null): Promise<{
    progress: { verified: number; failed: number; pending: number; total: number };
    status: AttestSession["status"];
  }>;
  attestSessionAbort(id: string, caller: {
    role: Role;
    email: string | null;
    subject: string | null;
    capabilities?: ReadonlySet<Capability>;
  } | null): Promise<{
    ok: boolean;
    status: AttestSession["status"];
  }>;
  startFleetDrill(req: {
    downpipeIds?: unknown;
  }, caller: {
    role: Role;
    email: string | null;
    capabilities?: ReadonlySet<Capability>;
  } | null): Promise<{
    ok: boolean;
    campaignId?: string;
    total?: number;
    alreadyActive?: boolean;
    reason?: string;
  }>;
  fleetDrillNextBatch(cap: number): Promise<{
    due: DownpipeState[];
    campaignId: string | null;
    done: boolean;
  }>;
  fleetDrillStatus(): Promise<{
    active: boolean;
    campaign: FleetDrillProgress | null;
  }>;
  advanceFleetDrill(id: string, passed: boolean): Promise<void>;
  requirePostureRiskAccept(caller: {
    role: Role;
    capabilities?: ReadonlySet<Capability>;
  } | null): void;
  listRiskAccepts(): Promise<RiskAccept[]>;
  notifyHasFailureRule(): Promise<boolean>;
  gatherPostureState(now: number): Promise<{
    downpipes: PostureDownpipeInput[];
    expiry: PostureExpiryInput[];
    notifyFailureRuleSet: boolean;
    ownerCount: number;
    overrides: Map<string, PostureOverrideInput>;
    identity?: PostureIdentityInput;
  }>;
  gatherPostureIdentity(): Promise<PostureIdentityInput | undefined>;
  postureEvaluationDue(req: { intervalMs?: unknown }): Promise<{ due: boolean; lastEvaluatedAt: string | null }>;
  computePostureReport(req: {
    status?: unknown;
    beaconEnabled?: unknown;
    callerEmail?: unknown;
    worm?: unknown;
    configWrapKeyConfigured?: unknown;
  }): Promise<{
    report: PostureReport;
    regressions: PostureRegression[];
  }>;
  parsePostureStatusSlice(raw: unknown): PostureInput["status"];
  parsePostureWormSlice(raw: unknown): PostureWormInput | undefined;
  acceptPostureRisk(req: {
    checkId?: string;
    reason?: string;
    kind?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    capabilities?: ReadonlySet<Capability>;
    sourceIp?: string | null;
  } | null): Promise<{
    ok: true;
  }>;
  unacceptPostureRisk(req: {
    checkId?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    capabilities?: ReadonlySet<Capability>;
    sourceIp?: string | null;
  } | null): Promise<{
    ok: true;
    removed: boolean;
  }>;
  parseReportPeriod(raw: unknown): ReportPeriod;
  restoreTestsReportData(req: {
    period?: unknown;
  }): Promise<RestoreTestsData>;
  slaReportData(req: {
    period?: unknown;
  }): Promise<SlaComplianceData>;
  rtoInputs(states: DownpipeState[]): Promise<RtoDownpipeInput[]>;
  rtoData(id: string | null): Promise<{
    fleet: RtoEstimate;
    downpipes: RtoEstimate[];
  }>;
  setCoverageInventory(raw: unknown, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    stored: true;
    counts: {
      kv: number;
      r2: number;
      d1: number;
      secrets: number;
    };
  }>;
  coverage(): Promise<CoverageReport>;
  gatherConfigSnapshot(): Promise<ConfigSnapshot>;
  listConfigVersions(): Promise<ConfigVersion[]>;
  snapshotConfigNow(author: string | null): Promise<{
    created: false;
  } | {
    created: true;
    version: ConfigVersion;
  }>;
  autoSnapshotConfig(author: string | null): Promise<void>;
  rollOverConfigHistory(existingKeys: string[], dropCount: number): Promise<void>;
  manualConfigSnapshot(caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    created: boolean;
    id?: number;
    at?: string;
    summary?: string;
  }>;
  configHistoryList(): Promise<{
    versions: Array<{
      id: number;
      at: string;
      author: string | null;
      parentHash: string;
      contentHash: string;
      summary: string;
    }>;
    headId: number;
    headHash: string;
    verify: {
      intact: boolean;
      checkedThrough: number;
      earliestId: number;
      brokenAt?: number;
      // G313: the head-anchor verdict, so the console's chain banner cannot read "verified" over a deleted tail.
      headTruncated?: boolean;
      headTruncatedAt?: number;
    };
  }>;
  configVersionById(idRaw: string | null): Promise<{
    found: false;
  } | {
    found: true;
    version: ConfigVersion;
  }>;
  configDiff(fromRaw: string | null, toRaw: string | null): Promise<{
    found: false;
  } | {
    found: true;
    from: number;
    to: number;
    changes: ConfigChange[];
  }>;
  getRequireConfigApproval(): Promise<boolean>;
  getRequireRestoreApproval(): Promise<boolean>;
  effectiveOwnerActionGateOn(kind: OwnerActionKind, callerMethod: AuthMethod | null): Promise<boolean>;
  readOrgPolicy(): Promise<OrgPolicy>;
  writeOrgPolicy(patch: Partial<OrgPolicy>): Promise<OrgPolicy>;
  getAttendedCadenceDays(): Promise<number>;
  setAttendedCadenceDays(req: { attendedCadenceDays?: unknown }, caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null): Promise<{ attendedCadenceDays: number }>;
  getBootstrapConsumed(): Promise<boolean>;
  markBootstrapConsumed(actorEmail: string | null, actorMethod: AuthMethod, sourceIp?: string | null): Promise<void>;
  // INFRA-1 control-plane recovery (ControlPlaneMixin): the no-custody signed-export slice, the export
  // change-gate pointer, the silence-killing recovery-required latch, and the break-glass-gated reconcile.
  // On the surface so the routing sub-mixin + whoami reach them through `this` like every other handler.
  buildControlPlaneExport(): Promise<ControlPlaneExport>;
  getControlPlaneExportState(): Promise<ControlPlaneExportState | null>;
  setControlPlaneExportState(s: ControlPlaneExportState): Promise<void>;
  recordControlPlaneExported(configVersion: number): Promise<void>;
  getControlPlaneRecoveryRequired(): Promise<{ required: boolean; reason: string | null }>;
  setControlPlaneRecoveryRequired(reason: string, runlogSeed?: number): Promise<void>;
  clearControlPlaneRecoveryRequired(): Promise<void>;
  controlPlaneIsEmpty(): Promise<boolean>;
  reconcileControlPlane(exp: ControlPlaneExport, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    ok: true;
    downpipes: number;
    destinations: number;
    roles: number;
    bridgedFrom: { headSeq: number; headHash: string };
  }>;
  // INFRA-1 CROSS-ENVIRONMENT estate import (recovery keystone, ControlPlaneMixin): rebuild only the DEFINITION
  // (downpipes/dest/discovery) from a kit-verified export, granting NO authority; disable downpipes when the
  // export is from a different account. Run by an authenticated Owner (not the bare token); fresh-plane-only.
  importControlPlaneDefinition(exp: ControlPlaneExport, crossAccount: boolean, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null, accountIdAbsent?: boolean): Promise<{
    ok: true;
    downpipes: number;
    destinations: number;
    downpipesDisabled: boolean;
    // G218: the imported downpipes are disabled because NO ACCOUNT ID COULD BE COMPARED, not because the
    // accounts genuinely differ. A pre-account-discovery export silently imports everything disabled.
    accountIdAbsent: boolean;
    authorityImported: false;
    bridgedFrom: { headSeq: number; headHash: string };
  }>;
  // INFRA-1 AUTO-HEAL (ControlPlaneMixin): the auto-reconcile-on-detect pieces. getControlPlaneRecoveryRecord
  // reads the staged-export / refusal record; stageControlPlaneRecovery parks a verified export for the
  // break-glass confirm; recordControlPlaneRecoveryRefused remembers an unsafe-to-auto-apply verdict;
  // applyControlPlaneResumeSlice re-applies ONLY the no-authority resume slice (downpipes/dest/discovery) so
  // backups resume WITHOUT granting authority (the latch stays set); applyControlPlaneAuthoritySlice is the
  // break-glass-gated authority half (RBAC + clear latch + re-arm bootstrap + bridge audit) the confirm runs.
  getControlPlaneRecoveryRecord(): Promise<ControlPlaneRecoveryRecord | null>;
  stageControlPlaneRecovery(staged: StagedControlPlane): Promise<void>;
  recordControlPlaneRecoveryRefused(reason: string, code?: AutoHealRefusalCode, extra?: { subCause?: AutoHealSubCause; scan?: CandidateScan }): Promise<void>;
  applyControlPlaneResumeSlice(): Promise<{ ok: true; downpipes: number; downpipesExpected: number; resumeSkipped: number; appliedVersion: number; destinations: number } | { ok: false; reason: string }>;
  // needs-new-logging (ControlPlaneMixin): the recovery latch's own self-diagnosis (the amnesia-probe class),
  // the deterministic per-tick deploy-identity observation, and the export-pass health (skip reason + per-dest
  // write outcome). Recorders drive from the cron Worker; readers surface into the support pack.
  recordControlPlaneAmnesiaProbe(probe: AmnesiaProbeClass): Promise<void>;
  getControlPlaneAmnesiaProbe(): Promise<ControlPlaneAmnesiaProbe | null>;
  recordControlPlaneDeployObservation(obs: { engineVersion: string; cfVersionId?: string }): Promise<{ baseline: boolean; changed: boolean }>;
  getControlPlaneDeployObservation(): Promise<ControlPlaneDeployObservation | null>;
  recordControlPlaneExportHealth(health: ControlPlaneExportHealth): Promise<void>;
  getControlPlaneExportHealth(): Promise<ControlPlaneExportHealth | null>;
  // G218 (ControlPlaneRecordsMixin): the last ESTATE IMPORT's outcome. The import answered crossAccount +
  // accountIdAbsent on its one-shot HTTP response and persisted neither, so a genuine cross-account rebuild and
  // a pre-account-discovery export (which disables every downpipe ANYWAY, via the fail-safe null compare) left
  // an identical DO state, an identical audit trail and an identical support pack. Booleans and counts only.
  recordControlPlaneImportOutcome(outcome: { crossAccount: boolean; accountIdAbsent: boolean; downpipesDisabled: boolean; downpipes: number; destinations: number }): Promise<void>;
  getControlPlaneLastImport(): Promise<ControlPlaneImportOutcome | null>;
  applyControlPlaneAuthoritySlice(caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    ok: true;
    roles: number;
    bridgedFrom: { headSeq: number; headHash: string };
  }>;
  // CP-RECOVERY-LATCH-NO-CLEAR-PATH-AFTER-ORGANIC-RESUME: the ACKNOWLEDGE-ONLY latch clear. Both
  // reconcileControlPlane and applyControlPlaneAuthoritySlice above refuse forever once the plane has
  // organically un-emptied under a latch (break-glass activity kept creating downpipes/roles while
  // recoveryRequired stayed set), because both require an EMPTY plane AND an empty role table. This clears
  // ONLY the two latch fields -- never imports, never touches bootstrapConsumed -- and refuses when the role
  // table is empty (no owner on record to authorise it; that state's only remedy stays the break-glass
  // reconcile, never this route).
  acknowledgeControlPlaneRecovery(caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{ ok: true; acknowledged: true }>;
  getBreakGlassTokenRetired(): Promise<boolean>;
  setBreakGlassTokenRetired(req: {
    retired?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    breakGlassTokenRetired: boolean;
  }>;
  // Change management (OWNER OPT-IN "Require Change Number"); ChangeManagementMixin. enforceChangeControl is
  // the chokepoint the owner-action gate + the restore apply consult; the rest read/set the policy + the
  // emergency marker + gather the report. readEmergencyChangeMarker's return is declared inline (not a named
  // type) so this base does not import the mixin module (which imports this base) and create a cycle.
  getRequireChangeNumber(): Promise<boolean>;
  setRequireChangeNumber(req: {
    requireChangeNumber?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    requireChangeNumber: boolean;
  }>;
  enforceChangeControl(actionKind: string, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    sourceIp?: string | null;
    change?: ChangeRef | null;
  } | null): Promise<void>;
  recordChange(actionKind: string, change: ChangeRef, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    sourceIp?: string | null;
  } | null): Promise<void>;
  bumpEmergencyMarker(): Promise<void>;
  readEmergencyChangeMarker(): Promise<{
    count: number;
    lastAt: string | null;
  }>;
  gatherChangeRecordedEvents(): Promise<AuditEvent[]>;
  getDiscoveryConfig(): Promise<DiscoveryConfig | null>;
  getDiscoveryStatus(): Promise<{
    present: boolean;
    setAt?: number;
    setBy?: string | null;
    accountsSeen?: DiscoveryAccountSeen[];
    selected?: string[];
    engineAccountId?: string | null;
    enabledSources?: string[];
  }>;
  setEnabledSources(req: {
    sources?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    present: boolean;
    setAt?: number;
    setBy?: string | null;
    accountsSeen?: DiscoveryAccountSeen[];
    selected?: string[];
    engineAccountId?: string | null;
    enabledSources?: string[];
  }>;
  setDiscoveryToken(req: {
    token?: unknown;
    accountsSeen?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    present: boolean;
    setAt?: number;
    setBy?: string | null;
    accountsSeen?: DiscoveryAccountSeen[];
    selected?: string[];
    engineAccountId?: string | null;
  }>;
  setDiscoveryAccounts(req: {
    selected?: unknown;
    engineAccountId?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    present: boolean;
    setAt?: number;
    setBy?: string | null;
    accountsSeen?: DiscoveryAccountSeen[];
    selected?: string[];
    engineAccountId?: string | null;
  }>;
  getVerifiedEngineAccount(): Promise<VerifiedEngineAccount | null>;
  recordVerifiedEngineAccount(req: {
    accountId?: unknown;
    via?: unknown;
  }): Promise<{ accountId: string | null }>;
  getLicenceRecord(): Promise<LicenceTokenRecord | null>;
  setLicenceToken(req: {
    token?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    present: boolean;
    setAt?: number;
    setBy?: string | null;
  }>;
  getUpdateRecord(): Promise<UpdateRecord>;
  setUpdatePending(p: UpdatePending): Promise<UpdateRecord>;
  setUpdateSettled(last: UpdateLast): Promise<UpdateRecord>;
  confirmUpdateSettled(req: {
    recommendedVersion?: unknown;
  }): Promise<{
    cleared: boolean;
  }>;
  claimRollbackNeeded(req: {
    recommendedVersion?: unknown;
    toVersion?: unknown;
    canaryVerdict?: unknown;
  }): Promise<{
    shouldAlert: boolean;
  }>;
  claimUpdateAlert(req: {
    recommendedVersion?: unknown;
  }): Promise<{
    shouldAlert: boolean;
  }>;
  ensureCanaryState(): Promise<CanaryState>;
  migrateCanaryState(stored: unknown): CanaryState;
  saveCanaryState(s: CanaryState): Promise<void>;
  resolveEffectiveDests(s: CanaryState): Promise<(string | null)[]>;
  getCanaryView(): Promise<CanaryView>;
  setCanaryConfig(req: {
    enabled?: unknown;
    destinationIds?: unknown;
    intervalSeconds?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<CanaryView>;
  canaryDue(nowMs: number): Promise<{
    due: boolean;
    run?: CanaryFlightPlan;
  }>;
  canaryComplete(req: {
    run?: unknown;
    results?: unknown;
  }): Promise<{
    transitions: Array<{
      destinationId: string | null;
      label: string;
      transitioned: "dead" | "recovered";
    }>;
  }>;
  canaryRunNow(): Promise<{
    ok: boolean;
  }>;
  // needs-new-logging (CanaryMixin): the lightweight support-pack view of the canary's liveness + its bounded
  // transition ring (canary-transition-only-pages-once), so a standing "paged once" death stays observable.
  getCanaryTransitions(): Promise<{ enabled: boolean; status: CanaryLiveness; deadDestinations: number; transitionCount: number; transitions: CanaryTransition[] }>;
  loadDestinations(): Promise<DestinationCollection>;
  saveDestinations(c: DestinationCollection): Promise<void>;
  getDestConfigById(id?: string | null): Promise<DestinationConfig | null>;
  destStatusOf(d: StoredDestination, defaultId: string): DestStatusView;
  // The per-destination retention-prune sidecar (B61; DestConfigMixin): the fold recordRetentionPass
  // calls at its write boundary, and the map destStatusOf's lastPrune join reads.
  destPruneMap(): Promise<Record<string, DestPruneState>>;
  foldDestPruneRecord(rec: RetentionPassRecord): Promise<void>;
  getDestStatus(): Promise<DestStatusView>;
  listDestStatus(): Promise<{
    destinations: DestStatusView[];
    defaultId: string | null;
  }>;
  buildDestRecord(config: unknown, id: string, label: string, caller: {
    email: string | null;
  } | null): StoredDestination;
  auditDest(caller: {
    method: AuthMethod;
    email: string | null;
    sourceIp?: string | null;
  } | null, action: "dest-config-set" | "dest-config-cleared"): Promise<void>;
  setDestConfig(req: {
    config?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<DestStatusView>;
  putDest(req: {
    id?: unknown;
    label?: unknown;
    config?: unknown;
    envDestConfigured?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    destinations: DestStatusView[];
    defaultId: string | null;
  }>;
  ensureDeployDestSeeded(envDestConfigured: boolean, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    seeded: boolean;
    backfilled: number;
  }>;
  backfillDefaultRoutedRuns(outgoingDefaultId: string): Promise<number>;
  removeDest(id: string, force: boolean, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    destinations: DestStatusView[];
    defaultId: string | null;
  }>;
  uncoveredOriginRuns(id: string, nameById: Map<string, string>, defaultId?: string): Promise<{
    count: number;
    names: string[];
  }>;
  setDefaultDest(id: string, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    destinations: DestStatusView[];
    defaultId: string | null;
  }>;
  setRequireConfigApproval(req: {
    requireConfigApproval?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    requireConfigApproval: boolean;
    disarmed: boolean;
  }>;
  setRequireRestoreApproval(req: {
    requireRestoreApproval?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    requireRestoreApproval: boolean;
    disarmed: boolean;
  }>;
  headVersionRef(): Promise<{
    id: number;
    hash: string;
  }>;
  applyConfigMutation(kind: ConfigChangeKind, params: unknown, caller: MutationCaller | null): Promise<unknown>;
  dryRunConfigMutation(kind: ConfigChangeKind, params: unknown, caller: MutationCaller | null): Promise<ConfigSnapshot>;
  proposeConfigMutation(kind: ConfigChangeKind, params: unknown, caller: MutationCaller | null): Promise<{
    applied: true;
    result: unknown;
  } | {
    applied: false;
    pending: PendingConfigChange;
  }>;
  approveChange(req: {
    id?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<PendingConfigChange>;
  rejectChange(req: {
    id?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<PendingConfigChange>;
  listPendingChanges(): Promise<PendingConfigChange[]>;
  getOrgPolicyView(): Promise<{
    requireConfigApproval: boolean;
    requireChangeNumber: boolean;
    notifyNewSignInContext: boolean;
  }>;
  getNotifyNewSignInContext(): Promise<boolean>;
  setNotifyNewSignInContext(req: {
    notifyNewSignInContext?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    notifyNewSignInContext: boolean;
  }>;
  recordSignInContext(subject: string, sourceIp: string | null | undefined): Promise<boolean>;
  gatedOwnerAction<T>(kind: OwnerActionKind, params: unknown, summary: string, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null, execute: (authority: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
  } | null) => Promise<T>): Promise<T | {
    ownerActionQueued: true;
    id: string;
    actionHash: string;
    status: "pending";
  }>;
  recordOwnerAction(kind: OwnerActionKind, params: unknown, summary: string, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<PendingOwnerAction>;
  verifyOwnerActionIntegrity(record: PendingOwnerAction): Promise<void>;
  proposerReplayCaller(record: PendingOwnerAction): {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    // replay marks this as a RECORDED identity, not a live request, so the re-resolution cannot bind a pending
    // grant that happens to match the stored email. See the implementation for the defect that requires it.
    replay: true;
  };
  approveOwnerAction(req: {
    id?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<PendingOwnerAction>;
  executeOwnerActionDO(record: PendingOwnerAction): Promise<void>;
  consumeOwnerAction(req: {
    id?: unknown;
    expectedActionHash?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    ok: true;
    id: string;
    actionHash: string;
  }>;
  checkOwnerActionGate(req: {
    kind?: unknown;
    params?: unknown;
    summary?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    gate: "off";
  } | {
    gate: "pending";
    id: string;
    actionHash: string;
  } | {
    gate: "armed";
    id: string;
    actionHash: string;
  }>;
  rejectOwnerAction(req: {
    id?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    role: Role;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<PendingOwnerAction>;
  listPendingOwnerActions(caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<PendingOwnerAction[]>;
  summariseDestConfig(verb: string, config: unknown): string;
  dueIndexKeyFor(ds: DownpipeState): string | null;
  persistDownpipeState(ds: DownpipeState): Promise<void>;
  rebuildDueIndex(): Promise<void>;
  maybeReconcileDueIndex(): Promise<boolean>;
  due(): Promise<{
    due: DownpipeState[];
  }>;
  leased(d: DownpipeState, now: number): boolean;
  trigger(req: {
    id: string;
  }): Promise<{
    runId: string;
    index: number;
    prevRunId: string | null;
    config: DownpipeConfig;
  } | {
    skipped: string;
  }>;
  heartbeat(req: {
    id: string;
    runId: string;
    index: number;
  }): Promise<{
    owned: boolean;
  }>;
  completeRun(req: CompleteRunReq): Promise<{
    ok: true;
  }>;
  recordReplicationState(id: string, r: {
    destinationId?: string;
    ok: boolean;
    runId?: string;
    index?: number;
    holdsFrom?: number;
    reason?: string;
  }): Promise<void>;
  replication(id: string | null): Promise<{
    dests: Record<string, DestReplState>;
  } | {
    byDownpipe: Record<string, Record<string, DestReplState>>;
  }>;
  history(id: string | null): Promise<{
    entries: RunHistoryEntryWithChain[];
  } | {
    byDownpipe: Record<string, RunHistoryEntryWithChain[]>;
    // The run-history counterpart of auditRolledOverCount above, and the same lesson: an EMPTY
    // byDownpipe map was byte-identical to a brand-new estate, because a count of what survives cannot
    // report what is gone. Full reasoning at the producer in scheduler-do-scheduling.ts.
    runsRecordedTotal: number;
    runsRetainedCount: number;
    runsRolledOverCount: number;
    runlogCounterReset?: true; // runlogCounter wound back below a retained index: the count is a floor.
  }>;
  runAt(downpipeId: string | null, atRaw: string | null): Promise<PointInTimeRun & {
    error?: string;
  }>;
  recordTickOutcome(report: TickReport): Promise<{ ok: true }>;
  // Declared on the surface so the routing mixin can call it across the split (the dual-control mixin owns the
  // implementation); without the declaration the composed class does not expose it and the route fails to type.
  ownerActionQueueStats(): Promise<{ pendingCount: number; approvalsOutstanding: number; expiredUndecidedCount: number; oldestProposedAt: string | null; kinds: Record<string, number> }>;
  recordStorageFault(kind: StorageFaultKind, downpipeId?: string): Promise<void>;
  recordSchedHealth(kind: SchedHealthKind): Promise<void>;
  recordStateRefusal(downpipeId: string, cls: StateRefusedClass, storedVersion: number): Promise<void>;
  clearStateRefusal(downpipeId: string): Promise<void>;
  schedulerSignals(): Promise<{
    ticks: TickOutcome[];
    dueIndex: Record<string, unknown>;
    runlog: { counter: number; maxHistoryIndex: number };
    listCaps: { pageSize: number; maxPages: number; historyRings: number };
    storageFaults: StorageFaultCounter;
    schedHealth: SchedHealthCounters & { parityStampStale: boolean };
    stateRefusals: { total: number; truncated: boolean; downpipes: Array<StateRefusal & { downpipeId: string }> };
  }>;
  alarm(): Promise<void>;
  rearmAlarm(): Promise<void>;
  nextWithJitter(cadenceSeconds: number, schedule?: DownpipeSchedule): { next: number; cronResolve: CronResolve | null; blackoutResolve: BlackoutResolve | null };
  sessionSigningKey(): Promise<Uint8Array>;
  recoverySigningKey(): Promise<Uint8Array>;
  blockConcurrencyWhile<T>(fn: () => Promise<T>): Promise<T>;
  terminateAllSessions(caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    ok: boolean;
  }>;
  passkeySessionIssue(body: {
    email?: unknown;
  }): Promise<{
    ok: true;
    token: string;
  } | {
    ok: false;
  }>;
  getSessionEpoch(canonicalEmail: string): Promise<number>;
  bumpSessionEpoch(canonicalEmail: string): Promise<number>;
  passkeySessionVerify(body: {
    token?: unknown;
  }): Promise<{
    verdict: "verified";
    email: string;
    subject: string;
    method: AuthMethod;
    connId: string | null;
    groups: string[];
    slidToken?: string;
  } | {
    verdict: "rejected";
    email: null;
  }>;
  terminateOwnOtherSessions(caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    connId?: string | null;
    sourceIp?: string | null;
  } | null, body: {
    token?: unknown;
  }): Promise<{
    ok: true;
    token: string;
  } | {
    ok: false;
  }>;
  terminateUserSessions(req: {
    email?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    ok: boolean;
  }>;
  passkeySessionLogout(body: {
    token?: unknown;
    sourceIp?: unknown;
  }): Promise<{
    ok: boolean;
  }>;
  get idpKv(): KvStorage;
  getIdpEpoch(connId: string): Promise<number>;
  bumpIdpEpoch(connId: string, nowMs: number): Promise<void>;
  getSessionEpochSub(subject: string): Promise<number>;
  bumpSessionEpochSub(subject: string, nowMs: number): Promise<void>;
  nativeSessionIssue(principal: {
    subject: string;
    email: string | null;
    emailVerified: boolean;
    groups: string[];
  }, connId: string, method: "oidc" | "saml", nowMs: number, sessionNotOnOrAfter?: number | null): Promise<{
    ok: true;
    token: string;
  } | {
    ok: false;
    reason: string;
  }>;
  idpProviders(): Promise<{
    ok: true;
    providers: Array<{
      id: string;
      label: string;
      kind: "oidc" | "oauth2" | "saml";
      presetId: string;
    }>;
  }>;
  idpConnCreate(body: {
    presetId?: unknown;
    vars?: unknown;
    proposal?: unknown;
    id?: unknown;
    label?: unknown;
    clientId?: unknown;
    secret?: unknown;
    secretMode?: unknown;
    clientAuth?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    ok: true;
    conn: IdpConnection;
  } | {
    ok: false;
    reason: string;
  }>;
  idpPresets(caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    ok: true;
    presets: ReturnType<typeof listPresets>;
  }>;
  idpConnList(caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    ok: true;
    connections: IdpConnection[];
  }>;
  idpConnDelete(body: {
    connId?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    ok: true;
    // `deleted` separates a real removal from a no-op over an ABSENT connection, which is NOT a refusal: both
    // answer ok:true, and only the first one writes an audit row. Without it the caller cannot tell them apart.
    deleted: boolean;
  } | {
    ok: false;
    reason: string;
  }>;
  idpConnSetEnabled(body: {
    connId?: unknown;
    enabled?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    ok: true;
  } | {
    ok: false;
    reason: string;
  }>;
  connectionRemovalPreflight(connId: string): Promise<{ lastEnabledConnection: boolean; passkeyOwnerEnrolled: boolean; recoveryReady: boolean }>;
  idpConnSamlCertUpdate(body: {
    connId?: unknown;
    addCerts?: unknown;
    certs?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    ok: true;
    conn: IdpConnection;
  } | {
    ok: false;
    reason: string;
  }>;
  idpOidcStart(body: {
    connId?: unknown;
    redirectUri?: unknown;
    returnTo?: unknown;
  }): Promise<{
    ok: true;
    authorizeUrl: string;
    state: string;
    txnId: string;
  } | {
    ok: false;
    reason: string;
  }>;
  idpOidcCallback(body: {
    connId?: unknown;
    code?: unknown;
    state?: unknown;
    txnId?: unknown;
    iss?: unknown;
    sourceIp?: unknown;
  }): Promise<{
    ok: true;
    token: string;
    returnTo: string;
    newSignInContext?: boolean;
  } | {
    ok: false;
    reason: string;
  }>;
  samlConnFor(connId: string): Promise<SamlConnection | undefined>;
  samlRequestId(): string;
  idpSamlMetadata(body: {
    connId?: unknown;
    acsUrl?: unknown;
  }): Promise<{
    ok: true;
    metadata: string;
  } | {
    ok: false;
    reason: string;
  }>;
  idpSamlStart(body: {
    connId?: unknown;
    returnTo?: unknown;
    acsUrl?: unknown;
  }): Promise<{
    ok: true;
    redirectUrl: string;
    browserBind: string;
  } | {
    ok: false;
    reason: string;
  }>;
  idpSamlAcs(body: {
    connId?: unknown;
    samlResponse?: unknown;
    relayState?: unknown;
    acsUrl?: unknown;
    browserBind?: unknown;
    sourceIp?: unknown;
  }): Promise<{
    ok: true;
    token: string;
    returnTo: string;
    newSignInContext?: boolean;
  } | {
    ok: false;
    reason: string;
  }>;
  // The bounded SSO sign-in FAILURE aggregate (support diagnosis, D2): a map keyed by the closed classifier code
  // -> { count, lastAt }. Redaction-safe by construction (closed keys + int counts + timestamps).
  recordSsoFail(reason: string, connKind?: string, connId?: string): Promise<void>;
  // G140: the same write path for a failure whose closed code is known by its PATH (start / metadata) rather
  // than by parsing a message, plus the opaque-ordinal chokepoint and the per-connection read.
  recordSsoFailCode(code: SsoFailCode, connKind?: string, connId?: string): Promise<void>;
  ssoConnOrdinal(connId: string): Promise<string | null>;
  readSsoFailuresByConn(): Promise<Record<string, Record<string, { count: number; lastAt: string }>>>;
  readSsoFailures(): Promise<Record<string, { count: number; lastAt: string }>>;
  // The per-connection-KIND breakdown of the same aggregate (P1): connKind (oidc|oauth2|saml) -> code -> {count,lastAt}.
  readSsoFailuresByKind(): Promise<Record<string, Record<string, { count: number; lastAt: string }>>>;
  // The bounded auth/RBAC defensive-branch signal aggregate (P2): a closed event name -> { count, lastAt }. The
  // recorder is best-effort and drops an out-of-vocabulary name; both are cross-mixin (the rate-limiter in the base,
  // the recovery / rbac mixins record; the routing mixin reads), so both sit on the surface.
  recordAuthSignal(name: string): Promise<void>;
  // The same recorder carrying HOW MANY events one write stands for (G270: the throttled recorder flushes the
  // window it accumulated). Declared on the surface because the throttle and the pack-read flush both call it.
  recordAuthSignalN(name: string, n: number): Promise<void>;
  // The THROTTLED variant, for signals recorded on a hot read path (the RBAC authority resolution runs on
  // every authenticated request). It throttles the storage WRITE and ACCUMULATES the events it defers, so the
  // counters are event counts, not window counts. See recordAuthSignalThrottled in scheduler-do-idp.ts.
  recordAuthSignalThrottled(name: string): Promise<void>;
  // Writes out the throttle's deferred tally (a burst that ends inside its own window has no later hit to carry
  // its events to disk). Called on the pack read; see readAuthSignals.
  flushAuthSignalPending(): Promise<void>;
  // G253: the per-METHOD credential-path usage aggregate (a posture record, not a fault signal). Same bounded
  // day-ring as the auth signals, its own key, its own closed vocabulary.
  recordAuthMethodUse(method: string, n: number): Promise<void>;
  recordAuthMethodUseSerial(method: string, n: number): Promise<void>;
  readAuthMethodUsage(): Promise<Record<string, { count: number; lastAt: string }>>;
  readAuthSignals(): Promise<Record<string, { count: number; lastAt: string }>>;
  // The bounded ADMIN-COUNTER aggregate (G080/G081/G082, and the G271/G274/G275/G332 posture family). It is
  // owned by the SupportDiagMixin and normally written from the Worker EDGE via POST /diag/admin-counters, but
  // two writers are DO-side and cannot go through the edge: the caller-header claim-bounding drops (the routing
  // mixin, which is where the header is decoded) and the OIDC callback's claim drops (the idp mixin, which is
  // where the principal is resolved). Hence the recorder sits on the surface. applyAdminCounters remains the
  // single redaction chokepoint for every writer.
  recordAdminCounters(body: { bumps?: unknown }): Promise<{ ok: true }>;
  // The THROTTLED variant, for the G312 anomalies observed on a HOT READ path (a corrupt approval, expiry row
  // or custom role is re-read on every request that touches it). See recordAdminCountersThrottled.
  recordAdminCountersThrottled(names: readonly string[]): Promise<void>;
  // G053: the pinned IdP signing-CERTIFICATE health record. Cross-mixin: the SAML ACS (IdpSamlMixin) drains the
  // pure verifier's cert observation and records it; the SupportDiagMixin owns the storage + the pack read. Counts,
  // booleans and closed key classes only -- never a PEM, an SPKI, a subject or a connId.
  recordIdpCertHealth(obs: unknown): Promise<{ ok: true }>;
  // P4 auth posture probes: session signing-key presence + age + adequate-length (never the key), the count of
  // confidential do-plaintext IdP connections whose stored secret is absent, and the count of ALTERNATIVE admin
  // credential paths (registered passkeys + enabled IdP connections) for the token-fallback-lockout cross-check.
  // All read cross-mixin state; the routing mixin reads them for the /auth-posture support projection.
  sessionSigningKeyHealth(): Promise<{ present: boolean; ageMs?: number; adequateLength?: boolean }>;
  doPlaintextSecretsMissing(): Promise<number>;
  // G140: which confidential connections are secretless, by OPAQUE ORDINAL (never a connId).
  doPlaintextSecretsMissingConns(): Promise<string[]>;
  adminCredentialPaths(): Promise<{ passkeyCredentials: number; enabledIdpConnections: number }>;
  recoveryKey(canonicalEmail: string): string;
  getRecoveryRecord(canonicalEmail: string): Promise<RecoveryRecord | null>;
  dummyRecoveryRecord(): Promise<RecoveryRecord>;
  // onStored (G177) fires the moment the FRESH record is persisted over the old one: the exact line past which
  // the prior recovery codes are dead. The regenerate route uses it to say which side of that boundary a failure
  // landed on, because "your old codes still work" and "you now hold no codes at all" are opposite remedies.
  generateRecoveryFor(canonicalEmail: string, actorMethod: AuthMethod, sourceIp?: string | null, onStored?: () => void): Promise<string[]>;
  // STAGED-RECOVERY-CODES-CONFIRM-GATE: mint-without-invalidating + the confirm that promotes it.
  // See scheduler-do-recovery.ts for the full rationale.
  stagedRecoveryKey(canonicalEmail: string): string;
  generateRecoveryStaged(canonicalEmail: string, actorMethod: AuthMethod, sourceIp?: string | null): Promise<string[]>;
  confirmRecoveryStaged(canonicalEmail: string, actorMethod: AuthMethod, sourceIp?: string | null): Promise<{ ok: true; promoted: boolean }>;
  recoveryRegenerate(body: {
    email?: unknown;
    ip?: unknown;
  }): Promise<{
    ok: true;
    codes: string[];
  } | {
    ok: false;
  }>;
  recoveryRecover(body: {
    email?: unknown;
    code?: unknown;
    ip?: unknown;
  }): Promise<{
    ok: true;
    email: string;
    token: string;
    role: Role;
    remaining: number;
    // The roster's answer at consumption, not a constant. The ENFORCING check is the self-add arm of
    // resolveRegistrationAuthorisation, which re-reads at registration time.
    enrolPasskey: boolean;
  } | {
    ok: false;
    alert: "recovery-code-used" | "recovery-code-abuse" | null;
  }>;
  recoveryRemaining(rawEmail: string | null): Promise<{
    remaining: number;
    low: boolean;
  }>;
  recoveryRateAllow(emailKey: string, ipKey: string | null): Promise<boolean>;
  recoveryRateCheck(key: string, max: number): Promise<{
    allowed: boolean;
  }>;
  recoveryBreakGlassVerdict(): Promise<{
    ready: boolean;
    reason: RecoveryBreakGlassReason;
  }>;
  recoveryRecordKeyLive(record: RecoveryRecord, keyRec: {
    key?: string;
    createdAt?: string;
    adoptedFromSessionKey?: boolean;
    sessionKeyCreatedAt?: string;
  } | undefined, sessionRec: {
    key?: string;
    createdAt?: string;
  } | undefined): Promise<boolean>;
  // The SIGN-IN FACTOR union (scheduler-do-signin-factors.ts). recoveryRecordKeyContinuity is
  // recoveryRecordKeyLive's boolean split three ways: this read's dangerous failure is the FALSE NEGATIVE
  // (an operator told nobody can sign in, who then stops looking), which is the opposite polarity to the
  // lockout pre-flight above, so "refuted" and "unprovable" must not share an answer here.
  recoveryRecordKeyContinuity(record: RecoveryRecord, keyRec: {
    key?: string;
    createdAt?: string;
    adoptedFromSessionKey?: boolean;
    sessionKeyCreatedAt?: string;
  } | undefined, sessionRec: {
    key?: string;
    createdAt?: string;
  } | undefined): Promise<RecoveryKeyContinuity>;
  listSignInFactors(emailParam: string | null, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    scope: "account" | "email";
    factors: SignInFactorRow[];
    witnessSince: string | null;
    groupRoleMappings: number;
  }>;
  // revokeSignInFactors is the union read's WRITE twin: every way one email can authenticate, removed as one
  // audited act. Two of the three stores had no delete at all before it. See the method for why it is neither
  // folded into deleteRole nor keyed by anything but an email.
  revokeSignInFactors(req: {
    email?: unknown;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    email: string;
    revoked: SignInFactorRevocation;
    sessionsTerminated: boolean;
    // Present ONLY when the destructive half was deliberately skipped, and it names why. Absent on every
    // ordinary revoke, so a caller cannot mistake "nothing was there to close" for "we chose not to look".
    declined?: "unattended-owner";
  }>;
  lockoutPreflight(): Promise<{
    passkeyOwnerEnrolled: boolean;
    passkeyOwnerEvidence: PasskeyOwnerEvidence;
    passkeyWitnessSince: string | null;
    recoveryReady: boolean;
    recoveryReadyReason: RecoveryBreakGlassReason;
    secondOwner: boolean;
  }>;
  getPasskeyCred(credIdB64: string): Promise<PasskeyCred | undefined>;
  putPasskeyCred(cred: PasskeyCred): Promise<void>;
  // recordPasskeyAssertion is the ONLY sanctioned write on the success side of a verifyAssertion: it persists
  // the advanced signCount AND stamps the usability witness in one put, unconditionally. Calling
  // putPasskeyCred directly from an assertion path would reintroduce the counter-conditional write that made
  // the witness blind to platform passkeys.
  recordPasskeyAssertion(cred: PasskeyCred, newSignCount: number, via: PasskeyAssertionCeremony): Promise<void>;
  ensurePasskeyWitnessSince(): Promise<void>;
  getPasskeyWitnessSince(): Promise<string | null>;
  listPasskeyCredsForEmail(email: string): Promise<PasskeyCred[]>;
  listPasskeyCredentials(emailParam: string | null, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    credentials: {
      credentialId: string;
      createdAt: string;
      aaguid: string;
      transports: string[];
      alg: number;
      lastAssertedAt: string | null;
      lastAssertedVia: PasskeyAssertionCeremony | null;
    }[];
    witnessSince: string | null;
  }>;
  listAllPasskeyCredentialsForAccount(caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    credentials: {
      credentialId: string;
      email: string;
      createdAt: string;
      aaguid: string;
      transports: string[];
      alg: number;
      lastAssertedAt: string | null;
      lastAssertedVia: PasskeyAssertionCeremony | null;
      hasRoleEntry: boolean;
    }[];
    witnessSince: string | null;
  }>;
  revokePasskeyCredential(req: {
    credentialId?: string;
  }, caller: {
    method: AuthMethod;
    email: string | null;
    subject: string | null;
    groups: string[];
    sourceIp?: string | null;
  } | null): Promise<{
    deleted: boolean;
  }>;
  putPasskeyChallenge(scope: string, challengeB64: string, now: number): Promise<void>;
  consumeChallenge(scope: string, now: number): Promise<string | null>;
  sweepAndBoundLoginChallenges(now: number): Promise<void>;
  mintRegistrationInvite(email: string, now: number): Promise<string | null>;
  mintBootstrapInvite(rawEmail: unknown, now: number): Promise<string | null>;
  bootstrapInviteMatches(token: string, now: number): Promise<string | null>;
  peekBootstrapInvite(token: string, now: number): Promise<string | null>;
  consumeBootstrapInvite(token: string, now: number): Promise<string | null>;
  peekInvite(token: string, now: number): Promise<string | null>;
  consumeInvite(token: string, now: number): Promise<string | null>;
  passkeyRpId(raw: unknown): string | null;
  passkeyOrigin(raw: unknown): string | null;
  passkeyDisplayName(raw: unknown, fallback: string): string;
  decodeB64urlField(raw: unknown, name: string, maxBytes: number): Uint8Array;
  coarsePasskeyError(stage: string, e: unknown): {
    ok: false;
    reason: string;
    errorId: string;
  };
  resolveRegistrationAuthorisation(clientEmail: string, body: {
    inviteToken?: unknown;
    authMethod?: unknown;
    authEmail?: unknown;
    bootstrapAuthorised?: unknown;
  }, now: number): Promise<{
    path: "bootstrap" | "invite" | "self-add";
    boundEmail: string;
    allowExistingCreds: boolean;
    inviteToken?: string;
    bootstrapInviteToken?: string;
  } | null>;
  passkeyRegisterBegin(body: {
    email?: unknown;
    displayName?: unknown;
    rpId?: unknown;
    inviteToken?: unknown;
    authMethod?: unknown;
    authEmail?: unknown;
    bootstrapAuthorised?: unknown;
  }): Promise<{
    ok: true;
    publicKey: unknown;
    challengeScope: string;
  } | {
    ok: false;
    reason: string;
    errorId?: string;
  }>;
  passkeyRegisterFinish(body: {
    email?: unknown;
    credential?: unknown;
    rpId?: unknown;
    origin?: unknown;
    displayName?: unknown;
    inviteToken?: unknown;
    authMethod?: unknown;
    authEmail?: unknown;
    bootstrapAuthorised?: unknown;
    sourceIp?: unknown;
  }): Promise<{
    ok: true;
    email: string;
    bootstrapped: boolean;
    role: Role;
    recoveryCodes: string[];
  } | {
    ok: false;
    reason: string;
    errorId?: string;
  }>;
  passkeyTransports(raw: unknown): string[];
  passkeyLoginBegin(body: {
    email?: unknown;
    rpId?: unknown;
  }): Promise<{
    ok: true;
    publicKey: unknown;
    challengeId: string;
  } | {
    ok: false;
    reason: string;
    errorId?: string;
  }>;
  passkeyLoginFinish(body: {
    challengeId?: unknown;
    credential?: unknown;
    rpId?: unknown;
    origin?: unknown;
  }): Promise<{
    ok: true;
    email: string;
  } | {
    ok: false;
    reason: string;
    errorId?: string;
  }>;
  sweepStepUpChallenges(now: number): Promise<void>;
  stepUpBegin(body: {
    rpId?: unknown;
  }, caller: {
    email: string | null;
    subject: string | null;
  } | null): Promise<{
    ok: true;
    publicKey: unknown;
    challengeId: string;
  } | {
    ok: false;
    reason: string;
  }>;
  stepUpFinish(body: {
    challengeId?: unknown;
    credential?: unknown;
    rpId?: unknown;
    origin?: unknown;
  }, caller: {
    email: string | null;
    subject: string | null;
  } | null): Promise<{
    ok: true;
    stepUpToken: string;
  } | {
    ok: false;
    reason: string;
    errorId?: string;
  }>;
  stepUpCheck(body: {
    token?: unknown;
    stepUpToken?: unknown;
  }): Promise<{
    satisfied: boolean;
  }>;
  // SIEM audit-log push destination (SiemPushMixin): the outbound egress
  // config + cursor + bounded delivery trail, and the owner-exclusive set/clear + the cron drain's outcome
  // recorder. On the surface so routeSiemPush + the dual-control execute dispatch reach them through `this`.
  getSiemPushRecordRaw(): Promise<PushDestinationRecord | null>;
  getSiemPushCursor(): Promise<number>;
  getSiemPushTrail(): Promise<PushDeliveryAttempt[]>;
  getSiemPushView(): Promise<PushDestinationView>;
  buildPushRecord(
    req: { endpoint?: unknown; format?: unknown; authHeaderName?: unknown; authHeaderValue?: unknown; enabled?: unknown; sink?: unknown; authInUrl?: unknown; s3Target?: unknown; syslog?: unknown },
    caller: { email: string | null } | null,
  ): PushDestinationRecord;
  summarisePushConfig(req: unknown): string;
  auditPushChange(
    caller: { method: AuthMethod; email: string | null; sourceIp?: string | null } | null,
    action: "push-destination-set" | "push-destination-cleared",
    detail: { op: "set" | "clear"; rejectReason?: "endpoint-invalid" | "format-invalid" | "missing-fields" },
  ): Promise<void>;
  setSiemPushDestination(
    req: { endpoint?: unknown; format?: unknown; authHeaderName?: unknown; authHeaderValue?: unknown; enabled?: unknown; sink?: unknown; authInUrl?: unknown; s3Target?: unknown; syslog?: unknown },
    caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
  ): Promise<PushDestinationView>;
  clearSiemPushDestination(caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null): Promise<{ ok: true }>;
  recordSiemPushOutcome(req: {
    ok?: unknown;
    httpStatus?: unknown;
    reason?: unknown;
    count?: unknown;
    fromSeq?: unknown;
    toSeq?: unknown;
    gen?: unknown;
    causeDigest?: unknown; // G164: the 12-hex Workers-Logs join key, shape-gated by the recorder
  }): Promise<{ ok: true }>;
  // OTLP/HTTP metrics push destination (OtlpPushMixin): the SNAPSHOT sibling
  // of the SIEM push above (no cursor -- every tick pushes the current state), the owner-exclusive set/clear,
  // the cron drain's outcome recorder, and the metrics-snapshot READ off the same run/replication state
  // reconcileAlerts/reconcileReplicationAlerts already read. On the surface so routeOtlpPush reaches them.
  getOtlpPushRecordRaw(): Promise<OtlpPushDestinationRecord | null>;
  getOtlpPushTrail(): Promise<OtlpPushDeliveryAttempt[]>;
  getOtlpPushView(): Promise<OtlpPushDestinationView>;
  buildOtlpPushRecord(
    req: { endpoint?: unknown; authHeaderName?: unknown; authHeaderValue?: unknown; enabled?: unknown },
    caller: { email: string | null } | null,
  ): OtlpPushDestinationRecord;
  summariseOtlpPushConfig(req: unknown): string;
  auditOtlpPushChange(
    caller: { method: AuthMethod; email: string | null; sourceIp?: string | null } | null,
    action: "otlp-push-destination-set" | "otlp-push-destination-cleared",
    detail: { op: "set" | "clear"; rejectReason?: "endpoint-invalid" | "missing-fields" },
  ): Promise<void>;
  setOtlpPushDestination(
    req: { endpoint?: unknown; authHeaderName?: unknown; authHeaderValue?: unknown; enabled?: unknown },
    caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
  ): Promise<OtlpPushDestinationView>;
  clearOtlpPushDestination(caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null): Promise<{ ok: true }>;
  recordOtlpPushOutcome(req: {
    ok?: unknown;
    httpStatus?: unknown;
    reason?: unknown;
    downpipeCount?: unknown;
    truncated?: unknown;
    droppedCount?: unknown;
    rejectedDataPoints?: unknown;
    gen?: unknown;
    causeDigest?: unknown; // G164: the 12-hex Workers-Logs join key, shape-gated by the recorder
  }): Promise<{ ok: true }>;
  otlpMetricsSnapshot(): Promise<{ downpipes: OtlpDownpipeMetrics[] }>;
  json(v: unknown): Response;
  jsonStatus(v: unknown, status: number): Response;
  ownerActionJson(outcome: unknown): Response;
  gatedConfigMutation(kind: ConfigChangeKind, params: unknown, caller: MutationCaller | null): Promise<Response>;
  bulkUpsertDownpipes(body: { downpipes?: unknown }, caller: MutationCaller | null): Promise<Response>;
}

// BaseSchedulerDO holds the ONE instance field (state) and the constructor; every method lives in a
// mixin layered over it (or on the final SchedulerDO in scheduler-do.ts). state is a PUBLIC readonly
// field so a mixin (whose `this` is SchedulerDOSurface) can read it; it was `private` on the old single
// class, a TYPE-visibility relaxation only (the field, its name and its value are byte-identical at
// runtime). The mixin chain is assembled, and the final SchedulerDO declared, in scheduler-do.ts.
export class BaseSchedulerDO {
  readonly state: DurableObjectState;
  constructor(state: DurableObjectState) {
    this.state = state;
  }
}

// SchedulerDOCtor is the mixin constructor-constraint: a constructor yielding a SchedulerDOSurface, so a
// mixin layered on it sees the WHOLE instance API through `this` (the cross-group visibility above).
// biome-ignore lint/suspicious/noExplicitAny: a mixin base constructor is necessarily (...args: any[]).
export type SchedulerDOCtor = new (...args: any[]) => SchedulerDOSurface;
