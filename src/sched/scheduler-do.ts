// The scheduler Durable Object: the single authority plane for an account's downpipes (design F11).
// It owns the schedules, the per-downpipe run lock, and the monotonic runlogIndex allocation, and it
// uses DO alarms as the real per-downpipe timers so the account is not limited by the platform
// cron-trigger cap. It does NOT run the seal loop itself; the DO alarm only re-arms the next wakeup
// time. The cron driver in index.ts is the actual seal driver: on each tick it asks the DO for due
// downpipes (GET /due) and runs each out of the DO (trigger -> seal -> complete, design F11).
//
// engine-sys-struct-06 / engine-sys-arch-01 (god-module split): the shared substrate (imports, constants, record
// types, AuthError, the SchedulerDOSurface instance API, and BaseSchedulerDO which holds the one `state` field +
// constructor) lives in the leaf module ./scheduler-do-base.ts. Cohesive method groups are moving into mixin
// factories in sibling ./scheduler-do-*.ts files; each mixin's `this` is typed as SchedulerDOSurface so a method
// that now lives in one mixin still calls a method in another with the SAME dispatch and `this` binding. This file
// assembles the mixin chain over the base, declares the final SchedulerDO, and re-exports the public surface so
// every importer is unchanged. Base and mixins are leaves this file depends on, never the reverse (madge 0 cycles).
//
// engine-src-037-02: the route() RPC dispatch (formerly one switch with 160 case arms) lives in
// ./scheduler-do-routing.ts as a thin chain of per-subsystem sub-dispatch methods; the case keys, bodies, status
// codes and dispatch results are byte-identical. Only fetch() (the error-to-status mapping) stays here, and the
// step-up ceremony moved to ./scheduler-do-stepup.ts. What remains on the final SchedulerDO is the downpipe-core
// apply path (addDownpipe + the listAllByPrefix/list/destination-for-run/remove helpers), the runlog lock, the
// per-caller rate-check and the Response helpers, all reached through `this` from the mixins exactly as before.
//
// Key decisions in the base/mixins: DO alarms are durable (the primary timer; the Worker cron is only a coarse
// reconciliation tick, F12) with jitter spreading same-cadence downpipes; an in-flight downpipe is COALESCED, never
// queued twice; runlogIndex is allocated EARLY in the storage transaction and gaps are tolerated (RUNLOG chains per
// downpipe via prevRunId, so a global gap is fine and a rollback is not), design F10.

import type { ConfigChangeKind, } from "../admin/change-control.ts";
import { OWNER_FLOOR_REFUSAL_CODE, OwnerFloorRefusal } from "../admin/owner-floor.ts";
import {
  checkDeletePrecondition,
  checkUpsertPrecondition,
  currentConfigRev,
  DOWNPIPE_TOMBSTONE_PREFIX,
  type DownpipeTombstone,
  movedConfigFields,
  nextConfigRev,
  PRECONDITION_REFUSAL_CODE,
  PreconditionRefusal,
  type StatedPrecondition,
  TOMBSTONE_RETENTION_MS,
  tombstoneKey,
} from "./downpipe-precondition.ts";
import { log } from "../log.ts";
import { isApiDiscoverySourceType } from "../sources/types.ts";
import { accountInDiscoveryScope, BULK_DOWNPIPES_MAX, BULK_DOWNPIPES_MAX_GATED, validateConfig } from "./config-validate.ts";
import { allDestinationIds, nextReplAnchors, primaryDestinationId } from "./destinations.ts";
import { embeddedConfigId } from "./roster-hygiene.ts";
import { classifyAuthzGate, classifyConfigReject, classifyConfigSurface, recordAuthzRefusal, recordConfigRejection, recordRecentError } from "./sched-fault-ledger.ts";
import { AccountConfigMixin } from "./scheduler-do-account-config.ts";
import { AttestMixin } from "./scheduler-do-attest.ts";
import { AuditMixin } from "./scheduler-do-audit.ts";
import {
  ALERT_COOLDOWN_PREFIX,
  AuthError,
  BaseSchedulerDO,
  DO_LIST_MAX_PAGES,
  DO_LIST_PAGE,
  type DownpipeConfig,
  type DownpipeState,
  type LastConfigChange,
  type MutationCaller,
  RATE_LIMIT_MAX_PER_WINDOW,
  RATE_LIMIT_PREFIX,
  RATE_LIMIT_WINDOW_MS,
  type RateWindow,
  REPL_ALERT_COOLDOWN_PREFIX,
  RESTORE_TEST_DEFAULT_CADENCE_SECONDS,
  RUNLOG_LEASE_MS,
  type RunHistoryEntry,
  type SchedulerDOCtor,
} from "./scheduler-do-base.ts";
import { CanaryMixin } from "./scheduler-do-canary.ts";
import { ChangeControlMixin } from "./scheduler-do-change-control.ts";
import { ChangeManagementMixin } from "./scheduler-do-change-management.ts";
import { ConfigVersionMixin } from "./scheduler-do-config-version.ts";
import { ControlPlaneMixin } from "./scheduler-do-control-plane.ts";
import { ControlPlaneRecordsMixin } from "./scheduler-do-control-plane-records.ts";
import { DestConfigMixin } from "./scheduler-do-dest-config.ts";
import { SchedulerDiagMixin } from "./scheduler-do-diag.ts";
import { DualControlMixin } from "./scheduler-do-dual-control.ts";
import { ExpiryMixin } from "./scheduler-do-expiry.ts";
import { IdpMixin } from "./scheduler-do-idp.ts";
import { IdpSamlMixin } from "./scheduler-do-idp-saml.ts";
import { NotifyMixin } from "./scheduler-do-notify.ts";
import { ObservabilityMixin } from "./scheduler-do-observability.ts";
import { OrgPolicyMixin } from "./scheduler-do-org-policy.ts";
import { OtlpPushMixin } from "./scheduler-do-otlp-push.ts";
import { PasskeyMixin } from "./scheduler-do-passkey.ts";
import { PasskeyInvitesMixin } from "./scheduler-do-passkey-invites.ts";
import { PruneApprovalMixin } from "./scheduler-do-prune-approval.ts";
import { RbacMixin } from "./scheduler-do-rbac.ts";
import { RbacAuthorityMixin } from "./scheduler-do-rbac-authority.ts";
import { RbacMutationsMixin } from "./scheduler-do-rbac-mutations.ts";
import { RecoveryMixin } from "./scheduler-do-recovery.ts";
import { ReportingMixin } from "./scheduler-do-reporting.ts";
import { RestoreApprovalMixin } from "./scheduler-do-restore-approval.ts";
import { RosterMixin } from "./scheduler-do-roster.ts";
import { RoutingMixin } from "./scheduler-do-routing.ts";
import { RoutingConfigMixin } from "./scheduler-do-routing-config.ts";
import { RoutingControlPlaneMixin } from "./scheduler-do-routing-control-plane.ts";
import { RoutingIdentityMixin } from "./scheduler-do-routing-identity.ts";
import { RoutingSignalsMixin } from "./scheduler-do-routing-signals.ts";
import { SchedulerCoreMixin } from "./scheduler-do-scheduling.ts";
import { SessionMixin } from "./scheduler-do-session.ts";
import { SiemPushMixin } from "./scheduler-do-siem-push.ts";
import { SignInFactorsMixin } from "./scheduler-do-signin-factors.ts";
import { SreAlertingMixin } from "./scheduler-do-sre-alerting.ts";
import { StepUpMixin } from "./scheduler-do-stepup.ts";
import { SupportDiagMixin } from "./scheduler-do-support-diag.ts";
import { sameSourceIdentity } from "./scheduler-helpers.ts";

// Re-export the public constants external importers pull from this module (they now live in the base module);
// behaviour-identical: same names, same values, same module specifier for every importer.
export {
  ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW,
  AUDIT_ROLLOVER_KEY,
  AUTH_RATE_LIMIT_MAX_PER_WINDOW,
  RATE_LIMIT_MAX_PER_WINDOW,
  RATE_LIMIT_WINDOW_MS,
} from "./scheduler-do-base.ts";
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

// engine-sys-struct-06 / engine-sys-arch-01: assemble the mixin chain over BaseSchedulerDO. Each mixin factory is
// constrained to a constructor that yields SchedulerDOSurface; BaseSchedulerDO supplies only `state` + the
// constructor, so it is cast up to SchedulerDOCtor ONCE here (the standard mixin-base cast) so each layered mixin's
// `this` sees the WHOLE instance API. Runtime is a normal prototype chain: the methods, their `this` binding and
// their dispatch are byte-identical to the former single class. The mixins hold DISJOINT method sets, so the
// LAYERING ORDER below does not affect dispatch; it is grouped only for readability. The remaining
// (not-yet-extracted) methods stay on the final SchedulerDO below, where `this` sees the surface too.
let SchedulerDOAssembled = NotifyMixin(BaseSchedulerDO as unknown as SchedulerDOCtor);
SchedulerDOAssembled = ExpiryMixin(SchedulerDOAssembled);
SchedulerDOAssembled = ObservabilityMixin(SchedulerDOAssembled);
// Attended verification (key-posture attend): the `attest-session:<id>` state machine; its routes are dispatched by RoutingSignalsMixin's routeRestoreTests, the narrow per-run stamp lives on Observability above.
SchedulerDOAssembled = AttestMixin(SchedulerDOAssembled);
SchedulerDOAssembled = ReportingMixin(SchedulerDOAssembled);
SchedulerDOAssembled = ConfigVersionMixin(SchedulerDOAssembled);
SchedulerDOAssembled = AccountConfigMixin(SchedulerDOAssembled);
SchedulerDOAssembled = CanaryMixin(SchedulerDOAssembled);
SchedulerDOAssembled = DestConfigMixin(SchedulerDOAssembled);
// SIEM audit-log push destination: a sibling of the destination config
// above (console-set, owner-exclusive egress config + cursor + trail). Its routes are dispatched by
// RoutingMixin's routeSiemPush.
SchedulerDOAssembled = SiemPushMixin(SchedulerDOAssembled);
// OTLP/HTTP metrics push destination (mon-otlp): the snapshot sibling of the SIEM
// push above (console-set, owner-exclusive egress config + bounded trail; no cursor). Its routes are
// dispatched by RoutingMixin's routeOtlpPush.
SchedulerDOAssembled = OtlpPushMixin(SchedulerDOAssembled);
SchedulerDOAssembled = ChangeControlMixin(SchedulerDOAssembled);
SchedulerDOAssembled = SreAlertingMixin(SchedulerDOAssembled);
SchedulerDOAssembled = RestoreApprovalMixin(SchedulerDOAssembled);
SchedulerDOAssembled = PruneApprovalMixin(SchedulerDOAssembled);
SchedulerDOAssembled = AuditMixin(SchedulerDOAssembled);
SchedulerDOAssembled = RbacMixin(SchedulerDOAssembled);
SchedulerDOAssembled = RbacAuthorityMixin(SchedulerDOAssembled);
SchedulerDOAssembled = RbacMutationsMixin(SchedulerDOAssembled);
SchedulerDOAssembled = OrgPolicyMixin(SchedulerDOAssembled);
SchedulerDOAssembled = ChangeManagementMixin(SchedulerDOAssembled);
SchedulerDOAssembled = DualControlMixin(SchedulerDOAssembled);
// The diagnostic recorders (scheduler-do-diag.ts): never-throwing writers that promote an otherwise-silent
// scheduler fault into durable, redaction-safe support-pack evidence. Layered under the core, which calls them.
SchedulerDOAssembled = SchedulerDiagMixin(SchedulerDOAssembled);
// The CRON + ADMIN diagnostic recorders (scheduler-do-support-diag.ts): the same never-throwing, closed-
// vocabulary shape as SchedulerDiagMixin, for the pre-run seal faults the cron loop swallows (G163), the
// /metrics scrape surface's own health (G049), the structural WebAuthn fault classes (G158), and the
// recorders' OWN dropped writes (G100/G331). Layered here so the passkey mixin (which records a structural
// fault) and the routing chain (which dispatches its routes) both reach it through the same `this`.
SchedulerDOAssembled = SupportDiagMixin(SchedulerDOAssembled);
SchedulerDOAssembled = SchedulerCoreMixin(SchedulerDOAssembled);
// The roster-hygiene report/repair pair (scheduler-do-roster.ts): the dp: roster census the support pack
// projects and the heal-to-invariant repair of the ghost classes it names. Layered beside the core for
// readability; it reaches listAllByPrefix / persistDownpipeState / rebuildDueIndex through the same `this`
// as every sibling, and the routing dispatch reaches it the same way.
SchedulerDOAssembled = RosterMixin(SchedulerDOAssembled);
SchedulerDOAssembled = SessionMixin(SchedulerDOAssembled);
SchedulerDOAssembled = IdpMixin(SchedulerDOAssembled);
SchedulerDOAssembled = IdpSamlMixin(SchedulerDOAssembled);
SchedulerDOAssembled = RecoveryMixin(SchedulerDOAssembled);
// The SIGN-IN FACTOR union (scheduler-do-signin-factors.ts): the one read that spans `passkeyCred:`,
// `recovery:` and `passkeyInvite:` together, so "who can still sign in" stops being three separate questions
// an operator has to know to ask. Layered after RecoveryMixin because it calls recoveryRecordKeyLive and
// recoverySigningKey through `this`; the ordering is for readability, since every mixin's `this` is the same
// SchedulerDOSurface.
SchedulerDOAssembled = SignInFactorsMixin(SchedulerDOAssembled);
// INFRA-1: the control-plane recovery subsystem (no-custody signed export + recovery-required latch +
// break-glass-gated reconcile). Layered as a leaf method group like every sibling mixin; its routes are
// dispatched by RoutingControlPlaneMixin below.
SchedulerDOAssembled = ControlPlaneMixin(SchedulerDOAssembled);
SchedulerDOAssembled = ControlPlaneRecordsMixin(SchedulerDOAssembled);
SchedulerDOAssembled = PasskeyMixin(SchedulerDOAssembled);
SchedulerDOAssembled = PasskeyInvitesMixin(SchedulerDOAssembled);
SchedulerDOAssembled = StepUpMixin(SchedulerDOAssembled);
// engine-src-037-02 / engine-sys-struct-06: the route() RPC dispatch. route() + the core data-plane
// sub-dispatch live in RoutingMixin; the remaining sub-dispatches are split across three cohesive sibling
// sub-mixins (signals / config governance / identity) so no routing file exceeds the module-size guardrail.
// All four are layered LAST only for readability; each one's `this` is the same SchedulerDOSurface, so
// route() (in RoutingMixin) reaches every sub-dispatch regardless of which sub-mixin owns it, and each
// sub-dispatch reaches every handler the same way. The four key sets are disjoint, so the layering order is
// immaterial to dispatch.
SchedulerDOAssembled = RoutingSignalsMixin(SchedulerDOAssembled);
SchedulerDOAssembled = RoutingConfigMixin(SchedulerDOAssembled);
SchedulerDOAssembled = RoutingIdentityMixin(SchedulerDOAssembled);
SchedulerDOAssembled = RoutingControlPlaneMixin(SchedulerDOAssembled);
SchedulerDOAssembled = RoutingMixin(SchedulerDOAssembled);

// runlogLockSlot maps a destination id to its RUNLOG-lock storage slot (SCALE-3 per-destination keying).
// An absent/blank key (the default destination, and the legacy unkeyed callers) maps to the historical
// "runlogLock" slot so the persisted lease shape and behaviour are unchanged for them; a named destination
// gets its own "runlogLock:<id>" slot, so independent destinations do not serialise on each other.
function runlogLockSlot(key?: string): string {
  return key && key.length > 0 ? `runlogLock:${key}` : "runlogLock";
}



export class SchedulerDO extends SchedulerDOAssembled {
  async fetch(req: Request): Promise<Response> {
    try {
      return await this.route(req);
    } catch (e) {
      // engine-src-037-03: branch on the error type rather than collapsing every failure into a 400 with
      // the raw message.
      //  - AuthError -> 403 (an authorisation refusal, not bad input). The PUBLIC body is a generic
      //    "forbidden" with no capability or role name; the detail is logged internally only, so a refusal
      //    cannot enumerate the capability/role a route requires.
      //  - A validation failure (a plain Error a guard threw, e.g. "id required") stays a 400 and keeps its
      //    message, which is the actionable client error it was before.
      //  - Anything else (a TypeError, an unexpected fault) is a 500 carrying only an OPAQUE error id; the
      //    detail is logged internally so an operator can correlate it, but it is never echoed and never
      //    leaks an internal name to the caller.
      if (e instanceof AuthError) {
        log("warn", `DO route authorisation refusal: ${e.message}`, { status: 403 });
        // G187 / G249: THE authorisation-refusal funnel. Every capability gate, owner gate, escalation guard
        // and break-glass guard in this DO throws AuthError and lands exactly here, so counting the closed
        // GATE at this one point cannot miss a site and cannot be forgotten at a new one. The public body
        // stays the bare "forbidden" (anti-enumeration, unchanged); classifyAuthzGate reads the INTERNAL
        // detail only to select a closed gate member and returns it -- the detail, and the caller's email,
        // subject and IP (never in it to begin with), are stored nowhere. Best-effort: recordAuthzRefusal
        // never throws, so the 403 is byte-identical whether or not the ledger write lands.
        await recordAuthzRefusal(this.state.storage, classifyAuthzGate(e));
        return new Response(JSON.stringify({ error: "forbidden" }), { status: 403, headers: { "content-type": "application/json" } });
      }
      const message = e instanceof Error ? e.message : String(e);
      // Heuristic 500 detection: an unexpected RUNTIME fault (a TypeError/RangeError/ReferenceError, e.g. a
      // null dereference or a logic bug) is a server error, not a client validation failure. The guards in
      // this file throw a plain Error with a curated, client-safe message, and malformed JSON throws a
      // SyntaxError (a genuine client error); both stay 400. Only the runtime-fault subclasses get the
      // opaque 500 path, which logs the detail internally and returns just an error id, never an internal name.
      if (e instanceof TypeError || e instanceof RangeError || e instanceof ReferenceError) {
        const errId = crypto.randomUUID();
        log("error", `DO route unexpected fault [${errId}]: ${e.name}: ${message.slice(0, 200)}`, { status: 500, error_code: errId });
        // G013: file the OPAQUE id the customer will quote from their console toast in the bounded ring
        // (sched-fault-ledger.ts) so the pack can dereference it: stage + coarse class + a recurrence count.
        // The message (which can embed an email, an rpId or a URL) is never stored; it stays in Workers Logs.
        await recordRecentError(this.state.storage, errId, "do-route", "internal");
        return new Response(JSON.stringify({ error: "internal error", errorId: errId }), { status: 500, headers: { "content-type": "application/json" } });
      }
      // Malformed JSON or a validation failure is a client error, not a 500.
      // G139 / G141: THE rejected-config-write funnel. Every refused configuration save in this DO -- a
      // downpipe upsert, a cron/retention/blackout edit, a source binding (including the SECURITY-significant
      // reserved-binding attempt), a role grant, a group mapping, a custom role, a notify channel/rule, an IdP
      // connection or the cert rollover that expires tomorrow, an expiry item, an OTLP/SIEM destination, and
      // the DR-critical break-glass control-plane reconcile/import -- reaches the customer's browser as this
      // 400 and used to be persisted NOWHERE. The SURFACE comes from the DO's own static route key (the DO's
      // routes carry no path ids), and classifyConfigReject reads the validator message only to SELECT a
      // closed reason and returns it: the message quotes the submitted cron string, bucket, URL, email or
      // account id, and is discarded at that boundary. The 400 body is unchanged.
      {
        const url = new URL(req.url);
        await recordConfigRejection(this.state.storage, classifyConfigSurface(req.method, url.pathname), classifyConfigReject(e));
      }
      // THE OWNER-FLOOR REFUSAL CARRIES A CODE, so a caller can file it without reading the sentence. The
      // status, the `error` field and the sentence itself are byte-identical to what this arm returned
      // before; `refusal` and `ownerFloor` are additive, and they are the only structured facts about the
      // refusal that leave this boundary. It is inside the 400 arm rather than ahead of it deliberately: an
      // Owner-floor refusal IS a rejected config write, and lifting it out would have quietly dropped it from
      // recordConfigRejection's ledger, which is a second, subtler version of the same defect.
      if (e instanceof OwnerFloorRefusal) {
        return new Response(JSON.stringify({ error: message, refusal: OWNER_FLOOR_REFUSAL_CODE, ownerFloor: e.reason }), { status: 400, headers: { "content-type": "application/json" } });
      }
      // A COLLIDING WRITE IS NOT A BAD REQUEST, and the status is the part a machine reads. The request was
      // well formed and the caller was entitled to make it; what failed is the base it was formed against.
      // 409 is what says that, and it is what the admin hub's existing adminRefusalReasonForStatus already
      // reads as the closed reason "conflict" rather than "validation", so the support pack tells a
      // collision apart from a typo without a new counter class. It sits INSIDE this arm, after
      // recordConfigRejection above, deliberately: a refused precondition IS a rejected config write, and
      // lifting it out would have quietly dropped it from that ledger, which is the same defect one layer
      // down. The sentence rides in `error` exactly as every other refusal's does.
      if (e instanceof PreconditionRefusal) {
        return new Response(JSON.stringify({ error: message, refusal: PRECONDITION_REFUSAL_CODE, precondition: { reason: e.reason, ...e.detail } }), {
          status: 409,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ error: message }), { status: 400, headers: { "content-type": "application/json" } });
    }
  }

  // addDownpipe upserts a downpipe config and returns the stored DownpipeState. It is the SINGLE apply
  // path for a downpipe write: the route reaches it through gatedConfigMutation (gate OFF applies inline
  // and auto-snapshots; gate ON validates + queues), and the change-control replay calls it directly. The
  // caller is used ONLY for the narrower scheduledtest.config re-check below (types.ts's
  // restoreTestCadenceSeconds doc, router-pipelines.ts POST /downpipes); it is optional because the
  // control-plane reconcile replay (applyResumeDownpipes) supplies its own synthetic owner authority
  // instead of a real caller, restoring the account's own previously-accepted state rather than enacting
  // a live edit.
  // pre is the OPERATOR'S BASE CHECK, and it is the repair for "two operators both told 200 and one edit
  // discarded" and for "a delete that says {"deleted":true} over a downpipe that is still running". It is
  // deliberately an EXPLICIT ARGUMENT rather than a field sniffed out of `config`, because two callers
  // reach this method and they want different things: the wire routes (applyConfigMutation's
  // downpipe-upsert arm) forward what the operator stated and ask for the resurrect guard, and the
  // control-plane replay (applyResumeDownpipes) is restoring a signature-verified export of the account's
  // OWN previously-accepted state after a wipe, where every downpipe is legitimately absent and a
  // tombstone from before the wipe must not block the restore.
  //
  // IT DOES NOT READ requireConfigApproval, ON PURPOSE. Detecting that a configuration moved under an
  // operator is honesty and is unconditional; requiring a second person to approve the move is governance
  // and stays opt-in. See sched/downpipe-precondition.ts for why those two rode on one flag.
  async addDownpipe(
    config: DownpipeConfig,
    caller?: MutationCaller | null,
    pre?: { stated: StatedPrecondition; guardResurrect: boolean },
  ): Promise<DownpipeState> {
    // Best-practice-on-by-default scheduled restore tests (contract section 5): when the upsert OMITS
    // restoreTestCadenceSeconds, default it to weekly so a new downpipe is recoverability-tested out of
    // the box. An explicit value (including 0 = off, the opt-down) is respected verbatim. Applied
    // BEFORE validateConfig so the stored config carries the resolved cadence and validateConfig bounds
    // it. A re-upsert that omits the field re-defaults to weekly, which is the intended "the field is
    // managed through the upsert" behaviour (a console that wants it off sends an explicit 0).
    const resolved: DownpipeConfig = {
      ...config,
      restoreTestCadenceSeconds: config.restoreTestCadenceSeconds === undefined ? RESTORE_TEST_DEFAULT_CADENCE_SECONDS : config.restoreTestCadenceSeconds,
    };
    // Preserve restore-test recency across a re-upsert: if the downpipe already exists, carry its
    // lastRestoreTestAt/Ok onto the new state so editing the config (e.g. changing the cadence) does
    // not reset the recency posture/reports read. A brand-new downpipe has neither (honestly absent).
    // Read early (before validateConfig): the cadence-change gate right below needs the PRIOR stored
    // cadence too, and only the DO holds it.
    const prior = await this.state.storage.get<DownpipeState>(`dp:${resolved.id}`);
    // THE BASE CHECK. It sits here, between the read of dp:<id> and the write of dp:<id>, and everything
    // between the two is a STORAGE await or synchronous JS. That is what makes it a real check rather than
    // a narrower race: a Durable Object's input gate holds concurrent events out while a storage operation
    // is in flight, so no second request can be delivered between this read and persistDownpipeState below.
    // (The window interleave found and could not reach is the OTHER shape, a CRYPTO await between a read
    // and a write, which is a yield point; there is none on this path.)
    //
    // THE READ DECIDES, IT DOES NOT REFRESH. A refused save is refused and named. Re-reading and writing
    // anyway would shrink the window from the lifetime of an open screen to one round trip and would still
    // overwrite silently, which is the shape this workspace records as a repair that looks done.
    {
      const stated = pre?.stated ?? { kind: "unstated" as const };
      const guardResurrect = pre?.guardResurrect === true;
      // The tombstone read is skipped unless it can change the verdict, so an ordinary stated-precondition
      // save pays nothing for it.
      const tombstone =
        guardResurrect && prior === undefined && stated.kind === "unstated"
          ? ((await this.state.storage.get<DownpipeTombstone>(tombstoneKey(resolved.id))) ?? null)
          : null;
      const verdict = checkUpsertPrecondition({ stated, prior, tombstone, guardResurrect, id: resolved.id });
      if (!verdict.ok) {
        // An ordinary no-write refusal, thrown BEFORE anything is written, so there is no rollback to do
        // and no partial state. The DO's fetch() catch recognises the type and answers 409 rather than the
        // generic 400, because a client that retries a 400 is retrying a bad request and a client that
        // retries a 409 is meant to re-read first, which is exactly what the operator must do.
        throw new PreconditionRefusal(verdict.reason, verdict.message, verdict.detail);
      }
    }
    // scheduledtest.config is a SECOND, narrower gate than the router's blanket downpipe.write: a custom
    // role can hold downpipe.write while deliberately lacking scheduledtest.config, so its holders can
    // manage downpipes but can never weaken the mandatory recoverability test. Gate on an actual CHANGE
    // only -- an explicit value that differs from what is already stored, or from the on-by-default
    // weekly floor on create -- so a create that omits the field and an edit that round-trips the same
    // value stay ungated (matching the six built-ins, where downpipe.write always implies
    // scheduledtest.config, so this is invisible to them).
    const priorCadence = prior ? (prior.config.restoreTestCadenceSeconds ?? RESTORE_TEST_DEFAULT_CADENCE_SECONDS) : RESTORE_TEST_DEFAULT_CADENCE_SECONDS;
    if (config.restoreTestCadenceSeconds !== undefined && config.restoreTestCadenceSeconds !== priorCadence) {
      this.requireCapability(caller ?? null, "scheduledtest.config");
    }
    validateConfig(resolved);
    // Cross-account confused-deputy guard (ASVS V4, HI-11): validateConfig above only shape-checks a
    // token-authenticated source's accountId (a hex regex); it never checked the id is one the Owner's
    // own discovery config actually covers, so any downpipe.write-only caller (operator/approver, or a
    // composable custom role -- keys.ceremony can never enter a custom role) could point a
    // cf-config/workers/stream/images/artifacts source at ANY account the shared discovery token can
    // reach and use rediscover/trigger to probe or seal it. A null discovery config (env/IaC-only
    // DISCOVERY_API_TOKEN) is a no-op here (accountInDiscoveryScope), matching resolveDiscoveryToken's
    // own documented fallback. Re-checked defensively at rediscover, the scheduled discovery pass and the
    // run path's token resolution, since `selected` can narrow AFTER this downpipe was created.
    if (isApiDiscoverySourceType(resolved.source.type) && resolved.source.accountId !== undefined) {
      const discoveryCfg = await this.getDiscoveryConfig();
      if (!accountInDiscoveryScope(resolved.source.accountId, discoveryCfg)) {
        throw new Error(`accountId "${resolved.source.accountId}" is not one of the discovery-selected Cloudflare accounts; select it under Sources first`);
      }
    }
    // Every destination the downpipe PINS (primary + replicas) must reference a LIVE one, reject a
    // typo or a since-removed destination at save time rather than failing the run/replication later.
    {
      const pins = allDestinationIds(resolved);
      if (pins.length > 0) {
        const { list } = await this.loadDestinations();
        for (const id of pins) {
          if (!list.some((d) => d.id === id)) throw new Error(`destinationId "${id}" is not a known destination`);
        }
      }
    }
    // Compute the first run time AND the cron-resolution outcome in one pass (scheduler-liveness new-logging):
    // a create/edit with a cron that no longer parses, an unknown timezone, or an impossible date falls back
    // to cadence, and the closed cronResolve class records that for the support pack (never the cron string).
    const firstRun = this.nextWithJitter(resolved.cadenceSeconds, resolved.schedule);
    const ds: DownpipeState = {
      config: resolved,
      nextRunAt: firstRun.next,
      // Preserve the latest-run pointer across a re-upsert of the SAME source: every config edit
      // (rename, cadence, retention, destination pin, the enable/disable toggle, which round-trips
      // the whole config) must not reset lastRunId to null, or the next scheduled restore test would see
      // "no completed run yet" and defer on a downpipe with a full archive, and the console's run hints
      // would read "no runs yet" until the next run. The pointer describes THIS source's archive, so it
      // survives any edit that keeps the source identity and resets only when the source itself changes
      // (a different resource honestly has no runs yet). The seal path is unaffected either way: RUNLOG-1
      // relinks prevRunId from the destination-local tail, never from this pointer.
      lastRunId: prior !== undefined && sameSourceIdentity(prior.config.source, resolved.source) ? prior.lastRunId : null,
      inFlight: false,
      ...(firstRun.cronResolve ? { cronResolve: firstRun.cronResolve } : {}),
      // Blackout-resolution outcome (G322): a hop-ceiling exhaustion fires the run INSIDE the declared change
      // freeze; a start === end window is INERT. Closed class + time; the window minutes never ride.
      ...(firstRun.blackoutResolve ? { blackoutResolve: firstRun.blackoutResolve } : {}),
      ...(prior?.lastRestoreTestAt !== undefined ? { lastRestoreTestAt: prior.lastRestoreTestAt } : {}),
      ...(prior?.lastRestoreTestOk !== undefined ? { lastRestoreTestOk: prior.lastRestoreTestOk } : {}),
      // Preserve the restore-test failure cause + consecutive-failure streak across a config edit, for the
      // same reason as the recency above: editing the cadence/source must not erase why the last scheduled
      // restore test failed (or how many have failed in a row), which the support pack reads.
      ...(prior?.lastRestoreTestReason !== undefined ? { lastRestoreTestReason: prior.lastRestoreTestReason } : {}),
      ...(prior?.restoreTestConsecutiveFailures !== undefined ? { restoreTestConsecutiveFailures: prior.restoreTestConsecutiveFailures } : {}),
      // Preserve the deferral kind and a pending post-backup retest request for the same reason: an
      // edit must not erase why the last completion was a deferral, nor drop a prompt retest that a
      // successful run already asked for.
      ...(prior?.lastRestoreTestDeferred !== undefined ? { lastRestoreTestDeferred: prior.lastRestoreTestDeferred } : {}),
      ...(prior?.restoreTestRetestAt !== undefined ? { restoreTestRetestAt: prior.restoreTestRetestAt } : {}),
      // Preserve the "offline restorability last proven" record across a config edit: editing a
      // downpipe's cadence/source must not erase the affirmative proof that its archives were recovered.
      ...(prior?.restoreProven !== undefined ? { restoreProven: prior.restoreProven } : {}),
      // Preserve the "archive integrity last verified" stamp across a config edit too, for the same reason:
      // changing the cadence/source must not erase the affirmative integrity recency the protection
      // statement reads (it would otherwise fall back to "never integrity-checked" after any edit).
      ...(prior?.integrityVerified !== undefined ? { integrityVerified: prior.integrityVerified } : {}),
      // Preserve the latest verify-at-seal verdict (ENG-RST-01) across a config edit: editing the
      // cadence/source must not erase a SUSPECT verdict (which a posture finding depends on) nor a
      // verified one. The next successful run overwrites it with a fresh verdict.
      ...(prior?.lastSealVerify !== undefined ? { lastSealVerify: prior.lastSealVerify } : {}),
      // Preserve the cf-config discovery cache across a config edit: changing the cadence/exclude must
      // not erase the discovered present set (which the capture path uses to avoid one GET per all ~200
      // surfaces). A source-type change away from cf-config leaves it harmlessly unused.
      ...(prior?.cfConfigDiscovery !== undefined ? { cfConfigDiscovery: prior.cfConfigDiscovery } : {}),
      // createdAt is stamped ONCE, on a genuine create (prior === undefined), and carried forward
      // UNCHANGED on every later edit -- unlike configRev/lastConfigChange, which move on every write,
      // this must never move, or a rename or cadence edit would reset "how long has this downpipe
      // existed" and the SLA report's window clamp (buildSlaComplianceReport) would silently widen back
      // to the report's default period on the downpipe's next edit. A legacy record that already has no
      // createdAt (written before this field shipped) stays honestly absent through every future edit
      // too -- it is never backfilled to the edit time, which would understate its true age and make the
      // SLA report read a months-old downpipe as created moments ago. The SLA report falls back to the
      // earliest run its history ring still holds for exactly that case (slaReportData).
      ...(prior === undefined ? { createdAt: Date.now() } : prior.createdAt !== undefined ? { createdAt: prior.createdAt } : {}),
      // G299 (the never-reported replica): carry the monotone sealed-run counter across the edit -- it counts
      // successful backups for all time, so an edit must never reset it -- and re-derive the per-destination
      // ANCHOR map from the config being saved. nextReplAnchors preserves the anchor of a destination that is
      // STILL in the fan-out (a rename or a cadence change cannot restart the clock on a destination that has
      // been holding nothing for months), anchors a destination NEW to this edit at the CURRENT count (it is
      // owed no copy yet, so it can never be reported as failing on the day it is added), and drops the anchor
      // of a destination the operator removed. Counts only; no timestamp of a customer event is recorded.
      ...(prior?.sealedRuns !== undefined ? { sealedRuns: prior.sealedRuns } : {}),
      ...((): { replAnchors?: Record<string, number> } => {
        const anchors = nextReplAnchors(prior?.replAnchors, allDestinationIds(resolved), prior?.sealedRuns ?? 0);
        return anchors !== undefined ? { replAnchors: anchors } : {};
      })(),
      // THE REVISION THE NEXT OPERATOR WILL STATE BACK. Bumped HERE and nowhere else, so it counts config
      // writes and not backups: persistDownpipeState is also the run path's writer (heartbeats,
      // completions, restore-test stamps) and those read this same object, mutate their own fields and
      // persist it, carrying the revision through untouched. A record written before this shipped has no
      // field, reads as 0 and becomes 1 on its first edit.
      configRev: nextConfigRev(prior),
      // WHAT THIS WRITE MOVED, so the operator whose save collides with it is told what changed rather than
      // only that something did. Field NAMES only. On a create nothing moved, so it is honestly absent; on
      // a re-upsert that changes nothing the PRIOR record is carried forward rather than erased, because
      // "the last change to this downpipe" is still true of it and dropping it would make the next refusal
      // less informative than the one before.
      ...((): { lastConfigChange?: LastConfigChange } => {
        const fields = movedConfigFields(prior?.config, resolved);
        if (fields.length === 0) return prior?.lastConfigChange !== undefined ? { lastConfigChange: prior.lastConfigChange } : {};
        return {
          lastConfigChange: {
            rev: nextConfigRev(prior),
            at: new Date().toISOString(),
            by: caller?.email ?? null,
            fields,
          },
        };
      })(),
    };
    // persistDownpipeState maintains the due-time index alongside the dp: write (it re-reads the prior
    // state to drop the old due: key and writes the new one iff enabled), so an upsert that toggles
    // enabled or changes nextRunAt keeps the index correct. (It re-reads dp:<id> independently of the
    // `prior` above; the extra O(1) read is negligible and keeps a SINGLE index-maintaining writer.)
    await this.persistDownpipeState(ds);
    // A CREATE clears the tombstone: the id exists again, so the resurrect guard has nothing left to say
    // about it and a stale marker would only be read by the prune. A no-op when there was none.
    if (prior === undefined) await this.state.storage.delete(tombstoneKey(resolved.id));
    await this.rearmAlarm();
    return ds;
  }

  // listAllByPrefix enumerates EVERY storage entry under a prefix, paging past the platform's DO list page limit
  // (ENG-SCALE-08): a single storage.list() returns at most ~1000 keys, so a bigger prefix silently TRUNCATES, and
  // for `dp:` that means downpipes past the page are NEVER enumerated, hence never scheduled. We page with an
  // explicit limit + startAfter cursor (the prior page's last key, exclusive) until a page comes back SHORT, the
  // exhaustion signal; ascending key order means the cursor advances with no overlap and no gap. The guard bound is
  // a defence-in-depth ceiling against a store that never shrinks a page (a degenerate store breaks the loop rather
  // than spinning). The test mock ignores cursor/limit (one whole-set page) so it is page-1-short and identical;
  // the fleet-scale validator's mock HONOURS startAfter+limit, proving >DO_LIST_PAGE entries are all enumerated.
  // G040: exhausting the guard bound TRUNCATES the enumeration -- silently, so the caller acted on an incomplete
  // fleet and the missing downpipes read as NONEXISTENT everywhere (the pack included). It is now COUNTED.
  async listAllByPrefix<T>(prefix: string): Promise<Map<string, T>> {
    const out = new Map<string, T>();
    let startAfter: string | undefined;
    let truncated = true; // cleared the moment a SHORT page proves the prefix is exhausted
    for (let guard = 0; guard < DO_LIST_MAX_PAGES; guard++) {
      const page = await this.state.storage.list<T>({ prefix, limit: DO_LIST_PAGE, ...(startAfter !== undefined ? { startAfter } : {}) });
      let lastKey: string | undefined;
      for (const [k, v] of page) {
        out.set(k, v);
        lastKey = k;
      }
      // A short (or empty) page means the prefix is exhausted (the last page is rarely exactly full); stop.
      // Only when a page came back FULL do we ask for the next page, after the last key we saw.
      if (page.size < DO_LIST_PAGE || lastKey === undefined) {
        truncated = false;
        break;
      }
      startAfter = lastKey;
    }
    // The loop ran out of PAGES before it ran out of KEYS: the caller is about to act on an incomplete view of
    // the fleet. Count it (never throw: a diagnostic must not break dispatch).
    if (truncated) await this.recordSchedHealth("list-truncated");
    return out;
  }

  async listDownpipes(): Promise<DownpipeState[]> {
    const map = await this.listAllByPrefix<DownpipeState>("dp:");
    return [...map.values()];
  }

  // engine-src-038-03 / engine-src-038-04: findRunRing is the shared run -> ring resolver that
  // destinationForRun and destinationsForRun (formerly duplicated bodies, 038-04) both go through.
  // It maps a runId to the downpipe whose recent-run ring carries it, returning that downpipe's state
  // and the matched history row (or null when the run is in no ring, having aged out of the ring or
  // belonged to a removed downpipe). The lookup is BATCHED (038-03): the old shape issued one
  // storage.get(`hist:<id>`) PER downpipe, an O(N) round-trip fan that grew with the fleet. The
  // platform's DurableObjectStorage.get accepts an ARRAY of up to DO_GET_BATCH keys and returns a Map
  // in ONE round trip, so we collect every `hist:<id>` key and read them in chunks of DO_GET_BATCH,
  // then search the rings, bounding the read count to ceil(N / DO_GET_BATCH) batches instead of N.
  // Resolution order is UNCHANGED: the rings are searched in the SAME order listAllByPrefix yields
  // (ascending key order via map.values()), and the FIRST downpipe whose ring contains the run wins,
  // exactly as the per-downpipe loop returned on its first match. Legacy rows (no recorded origin) are
  // handled by the callers, identically to before.
  private async findRunRing(runId: string): Promise<{ ds: DownpipeState; entry: RunHistoryEntry } | null> {
    if (!runId) return null;
    const map = await this.listAllByPrefix<DownpipeState>("dp:");
    // Preserve the resolution ORDER: iterate the downpipes once to fix the search order, collecting
    // each ring key alongside its state. map.values() is ascending key order, the same order the old
    // loop walked, so the first-match semantics below are byte-identical.
    const states = [...map.values()];
    const keys = states.map((ds) => `hist:${ds.config.id}`);
    // BATCH-read the ring keys: storage.get(string[]) returns a Map<key, value> in one round trip, capped
    // at DO_GET_BATCH keys per call, so we chunk. A key with no stored ring is simply absent from the Map.
    const rings = new Map<string, RunHistoryEntry[]>();
    const DO_GET_BATCH = 128; // platform cap: at most 128 keys per storage.get(array) call
    for (let i = 0; i < keys.length; i += DO_GET_BATCH) {
      const chunk = keys.slice(i, i + DO_GET_BATCH);
      const got = await this.state.storage.get<RunHistoryEntry[]>(chunk);
      for (const [k, v] of got) rings.set(k, v);
    }
    // Search in the fixed order: the first downpipe whose ring carries the run resolves it.
    for (const ds of states) {
      const ring = rings.get(`hist:${ds.config.id}`) ?? [];
      const entry = ring.find((r) => r.runId === runId);
      if (entry) return { ds, entry };
    }
    return null;
  }

  // destinationForRun maps a runId to the destinationId of the downpipe that produced it, by scanning
  // the per-downpipe recent-run rings (the same rings the console lists runs from, so any run a user
  // can navigate to restore resolves here). It lets a restore/drill READ from the run's OWN bucket
  // without the caller having to know the downpipe. Returns null when the run is in no ring (aged out
  // of the ring, or a removed downpipe) OR when its downpipe follows the default, the caller then
  // resolves the DEFAULT destination, exactly as a single-destination deployment always has.
  async destinationForRun(runId: string): Promise<string | null> {
    const found = await this.findRunRing(runId);
    if (!found) return null;
    // Resolve to the destination the run was actually SEALED to (the failover-chosen origin recorded
    // on the row), NOT the configured primary: with failover the run may live on a non-primary. A
    // legacy row carries no origin, so fall back to the configured primary, as a single-dest deployment did.
    return found.entry.destinationId ?? primaryDestinationId(found.ds.config) ?? null;
  }

  // destinationsForRun is the FAN-OUT sibling: it returns EVERY destination a run was written to (primary
  // first, then replicas), so a restore can fall back to a replica when the primary bucket is lost (the
  // DR case 3-2-1 exists for). Empty when the run is in no ring or its downpipe follows the default.
  async destinationsForRun(runId: string): Promise<string[]> {
    const found = await this.findRunRing(runId);
    if (!found) return [];
    const all = allDestinationIds(found.ds.config);
    // Try the recorded origin FIRST (it holds the run with a clean chain), then the rest deduped:
    // a DR restore reads its own bucket first, falling back to a replica only if the origin is lost.
    const origin = found.entry.destinationId;
    return origin && all.includes(origin) ? [origin, ...all.filter((d) => d !== origin)] : all;
  }

  // removeDownpipe deletes a downpipe's schedule, lock and run-history ring. The
  // runlogCounter is left untouched (indices stay monotonic) and existing archives are
  // unaffected; the ring is dropped so history does not outlive its downpipe.
  async removeDownpipe(
    req: { id: string },
    pre?: { stated: StatedPrecondition; caller?: MutationCaller | null },
  ): Promise<{ deleted: boolean; swept?: number; deletedRev?: number }> {
    // Drop the downpipe's due-time index entry BEFORE deleting dp:<id>, so a removed downpipe leaves no
    // orphaned due: key (the next due() would otherwise find the key, fail to load dp:, and skip it,
    // harmless but the reconcile would also clean it; deleting it here keeps the index tight). Read the
    // prior state to derive the exact key (disabled / no-nextRunAt downpipes have none, so this is a
    // no-op for them).
    const prior = await this.state.storage.get<DownpipeState>(`dp:${req.id}`);
    // THE DELETE'S OWN BASE CHECK, between this read and the delete below, with only storage awaits and
    // synchronous JS in between (the Durable Object's input gate holds concurrent events out across a
    // storage operation, so no second request lands in the middle). A delete whose base has moved is
    // refused and named, rather than removing an object the operator has not seen the current state of.
    {
      const stated = pre?.stated ?? { kind: "unstated" as const };
      const verdict = checkDeletePrecondition({ stated, prior, id: req.id });
      if (!verdict.ok) throw new PreconditionRefusal(verdict.reason, verdict.message, verdict.detail);
    }
    if (prior) {
      const dueKey = this.dueIndexKeyFor(prior);
      if (dueKey !== null) await this.state.storage.delete(dueKey);
    }
    const deleted = await this.state.storage.delete(`dp:${req.id}`);
    await this.state.storage.delete(`hist:${req.id}`);
    await this.state.storage.delete(`repl:${req.id}`);
    // Drop the per-downpipe SRE-alert cooldown record too, so a downpipe id that is later recreated
    // starts with a clean alerting slate (no stale last-alerted state lingering under the same id).
    await this.state.storage.delete(`${ALERT_COOLDOWN_PREFIX}${req.id}`);
    // Drop the per-downpipe replication-alert cooldown for the same reason.
    await this.state.storage.delete(`${REPL_ALERT_COOLDOWN_PREFIX}${req.id}`);
    // GHOST SWEEP (roster-hygiene): also remove any row that CLAIMS this id under a different storage
    // key (a key-id mismatch ghost). Such a row renders on the console (list and map key off the
    // embedded config.id) yet the direct delete above can never remove it, so without this sweep a
    // delete "succeeds" while the ghost keeps the downpipe visible forever (the undeletable grey map
    // edge). The sweep pays one paged dp: scan per delete, which is operator-initiated and rare. The
    // ghost's own residue is keyed by ITS key suffix (not a real downpipe id), so it goes too.
    let swept = 0;
    const all = await this.listAllByPrefix<unknown>("dp:");
    for (const [key, value] of all) {
      if (key === `dp:${req.id}`) continue;
      if (embeddedConfigId(value) !== req.id) continue;
      const suffix = key.slice("dp:".length);
      await this.state.storage.delete(key);
      await this.state.storage.delete(`hist:${suffix}`);
      await this.state.storage.delete(`repl:${suffix}`);
      await this.state.storage.delete(`${ALERT_COOLDOWN_PREFIX}${suffix}`);
      await this.state.storage.delete(`${REPL_ALERT_COOLDOWN_PREFIX}${suffix}`);
      swept++;
    }
    // THE TOMBSTONE. It is the SECOND line under the delete, and it is here because the first line only
    // works for a caller who states a precondition: an unconditioned upsert that arrives after this delete
    // would otherwise RECREATE the downpipe, and the operator who was answered {"deleted":true} would go on
    // being charged for a backup they cancelled, writing to a destination they believe they stopped, with
    // no later screen that corrects the impression because from their side the thing is gone. addDownpipe
    // reads this and refuses the resurrection. A deliberate recreate is still one request away (state
    // ifMatchRev:null), so this stops a race and never stops an operator.
    if (deleted || swept > 0) {
      await this.state.storage.put<DownpipeTombstone>(tombstoneKey(req.id), {
        id: req.id,
        at: new Date().toISOString(),
        by: pre?.caller?.email ?? null,
        rev: currentConfigRev(prior),
      });
    }
    // Prune tombstones this delete has made stale. THIS TIME BOUND IS NOT A RACE WINDOW: the resurrection
    // race is milliseconds wide and is closed exactly, without any bound, by the precondition on the
    // upsert; the bound exists only so a lifetime of deletes does not accumulate keys. Paid on the delete,
    // which is operator-initiated and rare, and which already pays a paged dp: scan for the ghost sweep.
    {
      const cutoff = Date.now() - TOMBSTONE_RETENTION_MS;
      const tombs = await this.listAllByPrefix<DownpipeTombstone>(DOWNPIPE_TOMBSTONE_PREFIX);
      for (const [key, t] of tombs) {
        if (key === tombstoneKey(req.id)) continue;
        const at = t && typeof t.at === "string" ? Date.parse(t.at) : Number.NaN;
        if (Number.isFinite(at) && at < cutoff) await this.state.storage.delete(key);
      }
    }
    await this.rearmAlarm();
    // A swept ghost counts as a deletion: the caller asked for this id to be gone and it now is,
    // even when the canonical dp:<id> key never existed (the mismatch case). deletedRev says WHICH
    // revision was removed, so an operator's client can tell "I deleted the thing I was looking at" from
    // "I deleted whatever was there", which is the same distinction the upsert's precondition draws.
    return {
      deleted: deleted || swept > 0,
      ...(swept > 0 ? { swept } : {}),
      ...(prior !== undefined ? { deletedRev: currentConfigRev(prior) } : {}),
    };
  }

  // acquireRunlogLock serialises a destination's RUNLOG read-modify-write across runs so
  // the RUNLOG and its detached .sig are always written by one run at a time (closing the
  // two-object window, design F10). A lease bounds a crashed holder; the next run takes
  // over after it expires and the idempotent append + re-sign repairs any half-write.
  // The read-check-write below is safe because Durable Objects execute storage operations
  // on a single thread: no concurrent I/O round-trip can interleave between the get and the
  // put within one DO instance, so two callers cannot both observe an expired lease and both
  // acquire it. Do not rely on this method outside a single-threaded DO without wrapping the
  // body in blockConcurrencyWhile or a transactional compare-and-set.
  //
  // PER-DESTINATION KEYING (SCALE-3): each self-contained destination archive has its OWN RUNLOG object,
  // so finalisers writing DIFFERENT destinations never contend -- only those racing for the SAME
  // destination's one RUNLOG must serialise. `key` is that destination id; an absent/blank key (the
  // default destination, and the legacy unkeyed callers) maps to the SAME slot as before so behaviour and
  // the persisted lease shape are unchanged for them. A 30-way storm now spreads across as many lock
  // slots as there are destinations instead of all queueing on one, raising the throughput ceiling.
  async acquireRunlogLock(key?: string): Promise<{ acquired: boolean; token?: string }> {
    const slot = runlogLockSlot(key);
    const cur = await this.state.storage.get<{ token: string; expiresAt: number }>(slot);
    const now = Date.now();
    if (cur && cur.expiresAt > now) return { acquired: false };
    const token = crypto.randomUUID();
    await this.state.storage.put(slot, { token, expiresAt: now + RUNLOG_LEASE_MS });
    return { acquired: true, token };
  }

  async releaseRunlogLock(req: { token: string; key?: string }): Promise<{ ok: true }> {
    // The lock token is a UUID minted by this DO and handed back to the same holder; it is internal-only,
    // never sent to a client and never leaves the DO. It is not a secret under the ASVS constant-time table,
    // so a plain equality compare here has no observable timing channel to a remote attacker.
    const slot = runlogLockSlot(req.key);
    const cur = await this.state.storage.get<{ token: string; expiresAt: number }>(slot);
    if (cur && cur.token === req.token) await this.state.storage.delete(slot);
    return { ok: true };
  }

  // ---- Per-caller rate limiting (OWASP ASVS V2.4.1) -------------------------------------
  // rateCheck maintains a FIXED-WINDOW counter per caller key and reports whether the request is
  // within RATE_LIMIT_MAX_PER_WINDOW for the current RATE_LIMIT_WINDOW_MS window. It is the same
  // cheap read-modify-write shape as the runlog lock above: ONE storage read and ONE storage write
  // per check, on the single-threaded DO, so it cannot itself become a hot bottleneck. A blank/
  // missing key resolves to a shared "anon" bucket rather than failing closed (the router never
  // sends a blank key on the live path; this only avoids a 500 on a malformed internal call).
  //
  // ALGORITHM: read the stored window; if there is none, or the stored window has fully elapsed,
  // open a fresh window at `now` with this request's cost as the count and ADMIT it (a new window
  // always admits the first request). Otherwise the request falls in the live window: if admitting
  // it would exceed the cap, REFUSE and report retryAfterMs as the time left until the window
  // resets; if not, increment the count and admit. retryAfterMs is 0 on an admit (nothing to wait
  // for) and a positive, capped-at-the-window value on a refusal.
  async rateCheck(req: { key?: string; cost?: number; max?: number }): Promise<{ allowed: boolean; retryAfterMs: number }> {
    const key = typeof req.key === "string" && req.key.length > 0 ? req.key : "anon";
    // cost is at least 1 (a request always costs something); a malformed/absent cost is treated as 1.
    const cost = typeof req.cost === "number" && Number.isFinite(req.cost) && req.cost >= 1 ? Math.floor(req.cost) : 1;
    // max is the per-window ceiling for THIS bucket; an absent/malformed value uses the default per-caller
    // cap. The unauthenticated /admin/auth/* per-IP limiter passes a tighter AUTH_RATE_LIMIT_MAX_PER_WINDOW
    // and a separate `ip:` key, so the two buckets are independent.
    const max = typeof req.max === "number" && Number.isFinite(req.max) && req.max >= 1 ? Math.floor(req.max) : RATE_LIMIT_MAX_PER_WINDOW;
    const now = Date.now();
    const storageKey = `${RATE_LIMIT_PREFIX}${key}`;
    const cur = (await this.state.storage.get<RateWindow>(storageKey)) ?? null;
    // No live window (none stored, or the stored one has fully elapsed): open a fresh one and admit.
    if (cur === null || now - cur.windowStart >= RATE_LIMIT_WINDOW_MS) {
      await this.state.storage.put(storageKey, { windowStart: now, count: cost } satisfies RateWindow);
      return { allowed: true, retryAfterMs: 0 };
    }
    // Inside the live window. The time left until it resets is the same whether we admit or refuse.
    const retryAfterMs = Math.max(0, RATE_LIMIT_WINDOW_MS - (now - cur.windowStart));
    if (cur.count + cost > max) {
      // Over the cap: refuse WITHOUT incrementing (so a denied request does not push the window even
      // further over and a caller that backs off is not penalised past the window it actually filled).
      // P2: the tighter per-IP `ip:` bucket is the unauthenticated auth-ceremony limiter, so a cap hit here is
      // the shared-NAT / brute-force lockout signal (auth-ratelimit-shared-nat). Record it best-effort (bounded,
      // never throws); the generic per-caller/CF-API buckets use other key namespaces and are not counted.
      if (key.startsWith("ip:")) await this.recordAuthSignal("auth-ratelimited");
      return { allowed: false, retryAfterMs };
    }
    cur.count += cost;
    await this.state.storage.put(storageKey, cur);
    return { allowed: true, retryAfterMs: 0 };
  }

  json(v: unknown): Response {
    return new Response(JSON.stringify(v), { headers: { "content-type": "application/json" } });
  }

  // jsonStatus is json() with an explicit status, used by the gated config-mutation routes to return 202
  // (Accepted) carrying the pending change id when the dual-control gate is ON and a write was QUEUED
  // rather than applied. The gate-off path keeps the plain 200 via json().
  jsonStatus(v: unknown, status: number): Response {
    return new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
  }

  // ownerActionJson shapes the Response for a DO-EXECUTED gated owner op dispatched through gatedOwnerAction:
  //  - gate OFF (the value is the method's own result): a plain 200 with that result, byte-identical to the
  //    pre-gate route.
  //  - gate ON (the value is the queued sentinel { ownerActionQueued }): a 202 with { ownerActionQueued:true,
  //    id, actionHash, status } so the console can route the owner to "awaiting a second owner's approval"
  //    with the action id. No state was changed (the action did not run), mirroring the 202 the config-change
  //    gate returns. The sentinel shape is internal (it is recognised by the queued flag) and never collides
  //    with a method result (no DO method returns ownerActionQueued).
  ownerActionJson(outcome: unknown): Response {
    if (outcome !== null && typeof outcome === "object" && (outcome as { ownerActionQueued?: unknown }).ownerActionQueued === true) {
      const s = outcome as { id: string; actionHash: string; status: string };
      return this.jsonStatus({ ownerActionQueued: true, id: s.id, actionHash: s.actionHash, status: s.status }, 202);
    }
    return this.json(outcome);
  }

  // gatedConfigMutation is the ONE place every config-mutating route dispatches through the change-control
  // gate, so all 15 mutations share identical gate semantics and there is no per-route drift. It calls
  // proposeConfigMutation (gate OFF -> inline apply; gate ON -> validate + queue a pending change) and
  // shapes the Response:
  //  - applied (gate OFF): auto-snapshot config history (best-effort, exactly as the pre-gate routes did)
  //    and return the mutation's own result as a plain 200, so the gate-off path is byte-identical to
  //    before (same body, same status, same side effect). proposeConfigMutation runs the SAME method the
  //    route used to call directly, so a result the route returned verbatim is preserved.
  //  - queued (gate ON): return 202 + { queued:true, id, status, contentHash } so the console can route the
  //    caller to "awaiting approval" with the change id. No state was written (the dry-run rolled back) and
  //    NO auto-snapshot runs (nothing committed to snapshot), which is what keeps a queued change inert.
  // A validation/guard/authority failure inside proposeConfigMutation THROWS, which the DO fetch() catch
  // maps to a 400 { error } exactly as the gate-off route would have, so a bad/unauthorised request is
  // rejected at propose time on BOTH paths.
  async gatedConfigMutation(
    kind: ConfigChangeKind,
    params: unknown,
    caller: MutationCaller | null,
  ): Promise<Response> {
    const outcome = await this.proposeConfigMutation(kind, params, caller);
    if (outcome.applied) {
      await this.autoSnapshotConfig(caller?.email ?? null);
      return this.json(outcome.result);
    }
    const p = outcome.pending;
    return this.jsonStatus({ queued: true, id: p.id, status: p.status, contentHash: p.contentHash }, 202);
  }

  // bulkUpsertDownpipes is the many-at-once companion to the single downpipe upsert (POST /downpipes/bulk):
  // one DO invocation creates a whole selection (the console's multi-source wizard / bulk protect) instead
  // of one HTTP round trip per downpipe. Each item runs the SAME gated path as a single upsert
  // (proposeConfigMutation: gate OFF applies inline through addDownpipe's full validation; gate ON queues a
  // pending change per item), so no validation, authority re-check or change-control semantic is bypassed.
  // CONTINUE-ON-ERROR: one bad item never voids its siblings; the response carries an index-aligned
  // per-item outcome ("applied" | "pending" | "error") so the console reports exactly what landed. The
  // batch is CAPPED (BULK_DOWNPIPES_MAX, far lower when change approval is on, since each gated item
  // dry-runs against a full keyspace checkpoint) and an oversized request is refused WHOLE with the cap
  // echoed as maxBatch, so a client re-batches deterministically rather than guessing. Duplicate ids
  // within one batch are refused per item (the first occurrence wins; an intra-batch self-overwrite is a
  // client bug, not an upsert). Each applied/failed item appends its own downpipe-create audit row here
  // (the DO side, mirroring the router's single-create rows; actor = the forwarded caller); a QUEUED item
  // appends none, because proposeConfigMutation already audits the propose itself. One config-history
  // snapshot covers the whole batch (one bulk action = one version), rather than N near-identical versions.
  async bulkUpsertDownpipes(body: { downpipes?: unknown }, caller: MutationCaller | null): Promise<Response> {
    const items = Array.isArray(body?.downpipes) ? body.downpipes : null;
    if (items === null || items.length === 0) throw new Error("downpipes must be a non-empty array");
    const gateOn = await this.getRequireConfigApproval();
    const cap = gateOn ? BULK_DOWNPIPES_MAX_GATED : BULK_DOWNPIPES_MAX;
    if (items.length > cap) {
      return this.jsonStatus(
        { error: `at most ${cap} downpipes per bulk request${gateOn ? " while config approval is on" : ""}; send the rest in further batches`, maxBatch: cap },
        400,
      );
    }
    const seen = new Set<string>();
    const results: Array<{ id: string; status: "applied" | "pending" | "error"; changeId?: string; error?: string }> = [];
    let applied = 0;
    let pending = 0;
    let failed = 0;
    for (const raw of items) {
      const cfg = raw as Partial<DownpipeConfig>;
      const id = typeof cfg?.id === "string" ? cfg.id : "";
      const name = typeof cfg?.name === "string" && cfg.name !== "" ? cfg.name : undefined;
      // The redaction-safe audit row for this item (id + name are the customer's own config, never a
      // secret), appended at the item's own outcome so the trail matches the per-request rows a
      // client-side loop of single creates would have produced.
      const record = (outcome: "success" | "failed"): Promise<unknown> =>
        this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "token",
          sourceIp: caller?.sourceIp ?? null,
          action: "downpipe-create",
          outcome,
          target: { kind: "downpipe", id, ...(name !== undefined ? { name } : {}) },
        });
      if (id !== "" && seen.has(id)) {
        results.push({ id, status: "error", error: "duplicate id in this batch" });
        failed++;
        await record("failed");
        continue;
      }
      if (id !== "") seen.add(id);
      try {
        const outcome = await this.proposeConfigMutation("downpipe-upsert", cfg, caller);
        if (outcome.applied) {
          results.push({ id, status: "applied" });
          applied++;
          await record("success");
        } else {
          results.push({ id, status: "pending", changeId: outcome.pending.id });
          pending++;
        }
      } catch (e) {
        // An AuthError stays the generic "forbidden" (never the capability name, matching the fetch()
        // catch's disclosure discipline); a validation failure keeps its actionable message, bounded.
        const message = e instanceof AuthError ? "forbidden" : e instanceof Error ? e.message : String(e);
        results.push({ id, status: "error", error: message.slice(0, 240) });
        failed++;
        await record("failed");
      }
    }
    if (applied > 0) await this.autoSnapshotConfig(caller?.email ?? null);
    return this.json({ results, applied, pending, failed });
  }
}

// Re-export the this-free helpers that were exported from this file before the guardrails B8-2
// god-module split, so every existing by-name importer (src/admin/*, src/seal/*, src/cron/*) keeps
// working unchanged. The definitions now live in the leaf sibling modules imported above; these
// modules are leaves that this file depends on, never the reverse, so madge stays at 0 cycles.
export { RESERVED_BINDINGS } from "./config-validate.ts";
export { allDestinationIds, primaryDestinationId, replicaDestinationIds } from "./destinations.ts";
export { deferPastBlackouts, scheduleTimeZone } from "./schedule-window.ts";

