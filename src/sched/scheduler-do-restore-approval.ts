// The restore dual-control subsystem (D2: the restore APPROVAL state machine) plus the drill-evidence
// log. RestoreApprovalMixin layers these over a base whose `this` is
// SchedulerDOSurface, so the maker/checker gates (requestRestore/approveRestore/rejectRestore
// /gateRestore/consumeApproval) and the drill-evidence rollover call `this.appendAudit` etc.

import { APPROVAL_PREFIX, APPROVAL_TTL_MS, type ApprovalSpendVerdict, approvalAnchorMs, approvalIdentitiesStillAuthorised, approvalKey, approvalTimestampUnparseable, canApprove, canReject, canRequesterSee, classifyRestoreApplyRefusal, effectiveStatus, isUsableApproval, PLAN_SEEN_PREFIX, RESTORE_APPLY_DEADLINE_MS, RESTORE_REJECT_REASON_SET, type RestoreApproval, type RestoreRejectReason, viewStatus } from "../admin/approvals.ts";
import { type AuthMethod, type Capability, can, type Role } from "../admin/identity.ts";
import { classifyApprovalRefusal, recordAdminRefusal, recordApprovalFault, recordDrillDrop, recordGovernanceRefusal } from "./sched-fault-ledger.ts";
import { AuthError, DRILL_EVIDENCE_CAP, DRILL_EVIDENCE_PREFIX, DRILL_EVIDENCE_ROLLOVER_BATCH, type DrillEvidenceEntry, NOTE_MAX_LEN, REASON_MAX_LEN, type SchedulerDOCtor } from "./scheduler-do-base.ts";

import { newULID, nowMillisISO, validateFreeText } from "./scheduler-helpers.ts";

// ---- THE PLAN ANCHOR: an approval may not outlive the plan it was read from ---------------------
//
// PlanAnchorStorage is the minimal storage surface these two need: a structural subset of
// DurableObjectStorage, so a test can drive them with a Map-backed fake. They are module-level rather than
// methods on SchedulerDOSurface deliberately -- neither reads a caller, neither gates on a capability, and
// the shared surface is at its size ceiling for a reason: a declaration that does not need to be visible to
// thirty mixins should not be on it.
interface PlanAnchorStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  list<T>(options?: { prefix?: string; limit?: number }): Promise<Map<string, T>>;
}

// notePlanSeen records the instant a DRY RUN for a plan hash was first shown to an operator, and it is what
// makes the dry run's fidelity warnings TRUE rather than optimistic. Without it the approval's TTL started at
// REQUEST time, so the last instant an apply could write was `request + the deadline` while the plan had
// computed its warnings from `plan + the deadline`. The difference is however long the operator spent reading
// the plan, which is unbounded (a plan sits in a browser tab), so a key that lapsed in that gap was dropped
// by the sink with nothing in the approved plan naming it. And because restorePlanHash binds no timestamp,
// the SAME displayed plan could be re-requested after every expiry, reopening that gap for ever.
//
// PUT-IF-ABSENT, deliberately. The anchor is the OLDEST dry run still in play for this plan, so EVERY card an
// operator may be holding is covered, not merely the most recent one. A second dry run for a plan someone
// else has already previewed must not move the deadline forward under them.
//
// BOUNDED. Each note first sweeps entries older than RESTORE_APPLY_DEADLINE_MS: past that instant an approval
// anchored to them would already be expired, so they can authorise nothing and are only storage. An anchor is
// also dropped when its approval reaches a terminal state (consumed/rejected), so the next cycle anchors to a
// fresh dry run rather than to a plan nobody is holding any more.
//
// requestRestore refuses on an ABSENT anchor and not only on a stale one, because the sweep runs on every
// dry run, for every plan hash, on the SAME condition the stale-plan refusal tests: `now - at >
// RESTORE_APPLY_DEADLINE_MS`. The two sets COINCIDE: an entry is swept only when it is already past that
// deadline, which is exactly when a request anchored to it must be refused, and a request with no anchor
// at all is refused too. So the sweep's deletion set is a SUBSET of the refusal set, and deleting an
// anchor can never change any request's verdict. Anchors younger than the deadline -- every card an
// operator could still legitimately request against -- are untouched by the sweep, so ordinary traffic
// cannot refuse a customer holding a valid plan.
//
// The anchor is the PLAN'S OWN instant (the plannedAt the dry run published), not the instant this note
// reached the DO. They differ by the milliseconds the preview spent being serialised and dispatched, and that
// is not a rounding detail: the plan computed its deadline from plannedAt, so anchoring to a LATER instant
// would put the last permitted write a few milliseconds past the deadline the plan warned on, which is
// under-warning by a small number instead of a large one. Clamped to now by approvalAnchorMs, so a
// caller-supplied value can only ever shorten its own approval.
//
// Router-only, like every other route on this DO. It carries a plan hash and an instant and nothing else: no
// selector, no binding name, no identity.
export async function notePlanSeen(storage: PlanAnchorStorage, req: { planHash?: string; plannedAt?: number }): Promise<{ noted: boolean; anchoredAt: string | null }> {
  if (typeof req.planHash !== "string" || !req.planHash.startsWith("sha384:")) return { noted: false, anchoredAt: null };
  const now = Date.now();
  const anchorAt = approvalAnchorMs(req.plannedAt, now);
  // Sweep first, so a stale anchor for THIS plan is cleared before the put-if-absent below re-anchors it to
  // the fresh dry run. Bounded scan: anchors live at most RESTORE_APPLY_DEADLINE_MS, so the live set is the
  // plans previewed in the last day, and a page is ample.
  for (const [key, value] of await storage.list<{ at: number }>({ prefix: PLAN_SEEN_PREFIX, limit: 256 })) {
    const at = typeof value?.at === "number" ? value.at : Number.NaN;
    if (!Number.isFinite(at) || now - at > RESTORE_APPLY_DEADLINE_MS) await storage.delete(key);
  }
  const key = PLAN_SEEN_PREFIX + req.planHash;
  const existing = await storage.get<{ at: number }>(key);
  if (existing !== undefined && Number.isFinite(existing.at)) return { noted: false, anchoredAt: new Date(existing.at).toISOString() };
  await storage.put(key, { at: anchorAt });
  return { noted: true, anchoredAt: new Date(anchorAt).toISOString() };
}

// planAnchorMs returns the recorded plan instant for a hash, or null when none is recorded.
//
// NULL IS NOT A FALLBACK: requestRestore refuses on null, so an approval is only ever minted against a
// preview this engine recorded and can date. The re-plan the request route does is not a substitute,
// because its fidelity warnings are never shown to anyone: the operator approved the card they read, not
// the plan the request route recomputed behind them.
//
// A STALE anchor is returned AS IT IS rather than being softened to null, and requestRestore refuses on that
// too. The two refusals carry different closed classes so support can tell "the operator sat on the plan"
// from "no dry run was recorded for it", but the remedy printed for the operator is the same one: run the dry
// run again and request from the plan it returns.
export async function planAnchorMs(storage: PlanAnchorStorage, planHash: string): Promise<number | null> {
  const rec = await storage.get<{ at: number }>(PLAN_SEEN_PREFIX + planHash);
  return rec === undefined || !Number.isFinite(rec.at) ? null : rec.at;
}

export function RestoreApprovalMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- Dual control (D2): the restore APPROVAL state machine ----------------------------
    // A restore apply over live data requires a SECOND authorised identity's approval, bound to the
    // exact plan, with maker != checker. The records live under the `approval:` prefix keyed by the
    // request's plan-binding hash (so a re-plan that changes a decision field has no matching record).
    // The state machine (requested -> approved -> consumed, plus rejected/expired) and the maker !=
    // checker rule are enforced HERE, in the DO, inside one storage read-modify-write, because the DO
    // is the single authority; the router gates the role first (defence in depth) and forwards the
    // verified caller via CALLER_HEADER. approvals.ts owns the pure logic so the request, the approve,
    // the apply gate and the validator can never compute the binding or the state two different ways.

    // requireCapability is the DO-side authority re-check for the dual-control + drill-evidence
    // mutations, parameterised by the CAPABILITY the action needs. It TRUSTS the router-resolved role on
    // the forwarded caller header (the documented "FROM THE ROUTER ONLY" trust for these routes), unlike
    // the people-management requireCapabilityResolved, which RE-RESOLVES the role from the DO's own tables
    // (the people routes never trust the asserted role). It is capability-based so the two narrow roles
    // work end to end: restore-operator holds the restore caps + drill.run; access-admin holds none of
    // these. The caller the router forwarded must hold the capability; an absent/malformed caller fails
    // closed. It THROWS an AuthError on refusal so the fetch()
    // catch maps it to a 403; the router returns the first-class 403 before forwarding, so reaching this
    // throw means the router gate was bypassed and failing closed is correct. For the four cumulative
    // roles this is identical allow/deny to the prior min-role rank check (operator holds restore.request
    // + drill.run; approver holds restore.approve; viewer holds none of these write capabilities).
    requireCapability(caller: { role: Role; capabilities?: ReadonlySet<Capability> } | null, capability: Capability): void {
      // engine-src-037-03: a capability denial is an authorisation refusal -> AuthError -> 403, with the
      // capability name kept for the internal log only (the catch returns a generic "forbidden" body).
      if (!this.callerHolds(caller, capability)) throw new AuthError(`forbidden: ${capability} capability required`);
    }

    // callerHolds is the DO-side analogue of callerCan (identity.ts): if the caller carries a RESOLVED
    // capability set (a custom-role caller, whose set the gated propose/replay forwards), the check is that
    // set's has(); otherwise it falls back to can(caller.role, cap) over the built-in ROLE_CAPABILITIES.
    // A null caller holds nothing (fail closed). This is the one convergence point so a by-role re-check
    // (requireCapability/requireNotifyConfig/requirePostureRiskAccept) honours a custom-role proposer's
    // resolved authority instead of refusing them on their "viewer" built-in floor, WITHOUT widening
    // authority: the forwarded set is the proposer's own LIVE-resolved set (bounded by their live ceiling),
    // never a client-supplied or propose-time-frozen value.
    callerHolds(caller: { role: Role; capabilities?: ReadonlySet<Capability> } | null, capability: Capability): boolean {
      if (caller === null) return false;
      if (caller.capabilities !== undefined) return caller.capabilities.has(capability);
      return can(caller.role, capability);
    }

    // requestRestore writes a `requested` approval for a plan-binding hash the router computed from
    // the restore request, with the blast-radius cues for the approver (stored, not hashed) and the
    // requester's free-text reason. Operator+ (DO re-check). A re-request for the SAME plan hash
    // overwrites a prior requested/expired/rejected record with a fresh requested one (a new TTL),
    // which is the natural "raise it again" behaviour; it refuses to clobber a still-usable APPROVED
    // record (so a requester cannot reset an approval back to pending and re-approve it themselves) OR
    // an in-flight "applying" RESERVATION (HI-03 / ASVS 2.1.6): without this, a re-request would silently
    // destroy a running apply's reservation and reset the plan to pending, and a second request+approve
    // cycle (the same maker/checker pair) would then mint a second, independent reservation for the
    // SAME plan hash -- reopening exactly the "more than one apply per approval" race reserveRestore's
    // atomic reserve closes, via this sibling mutator instead of a concurrent reserve. This is the
    // same clobber canApprove/canReject already refuse for the same reason.
    // It records a restore-request audit event at the commit point (maker = the requester; no checker
    // yet), carrying only names/counts/the plan hash, never a value.
    // readApprovalRecord is the ONE read every approval path now goes through (G312). It is a plain
    // storage.get with one addition: a stored record whose expiresAt does not PARSE never reads as expired
    // (effectiveStatus guards the check on Number.isFinite), so a single-use dual-control approval for a
    // DESTRUCTIVE restore silently loses its 24-hour TTL and stays usable indefinitely. The guard is correct;
    // its silence is the gap. Counting the anomaly here catches it on every path (request, approve, reject,
    // reserve, release, consume) rather than at one of them. Throttled (a corrupt record would otherwise write
    // once per read) and best-effort. Counts only: never the record, the plan hash or the corrupt timestamp.
    async readApprovalRecord(planHash: string): Promise<RestoreApproval | null> {
      const record = (await this.state.storage.get<RestoreApproval>(approvalKey(planHash))) ?? null;
      if (record !== null && approvalTimestampUnparseable(record)) void this.recordAdminCountersThrottled(["stored-approval-unparseable-timestamp"]);
      return record;
    }

    // approvalSpendVerdict is the SPEND-TIME IDENTITY BINDING (approvals.ts, approvalIdentitiesStillAuthorised):
    // it re-resolves BOTH recorded principals' LIVE effective capability sets from their immutable subjects and
    // asks whether the maker still holds restore.request and the checker still holds restore.approve. It is the
    // restore counterpart of what executeOwnerActionDO does when an armed owner action is spent.
    //
    // Called from gateRestore (so the operator's 403 is classified, and the refusal is a counted, dated fact
    // rather than a shrug) and again from reserveRestore (the authoritative one: the atomic transition adjacent
    // to the write). It is deliberately NOT called from consumeApproval, and that is not an omission: consume
    // runs AFTER a successful apply has already written customer data back, so a refusal there could not stop
    // anything and would leave a spent approval un-terminated and therefore spendable a SECOND time, which is
    // strictly worse than the residue it would be trying to close.
    //
    // Only ever called on a record isUsableApproval has already accepted, so a null/expired/consumed record is
    // classified by classifyRestoreApplyRefusal as it always was and never reaches here to be mis-labelled as
    // an authority lapse.
    async approvalSpendVerdict(record: RestoreApproval): Promise<ApprovalSpendVerdict> {
      const makerCaps = await this.resolveStoredIdentityAuthority(record.requesterSubject, record.requestedBy, record.requesterGroups);
      const checkerCaps = await this.resolveStoredIdentityAuthority(record.approverSubject, record.approvedBy, record.approverGroups);
      return approvalIdentitiesStillAuthorised(makerCaps, checkerCaps);
    }

    async requestRestore(
      req: { planHash?: string; runId?: string; isLatest?: boolean; plannedWrites?: number; bytes?: number; redirectBinding?: string | null; reason?: string; destinationId?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups?: string[]; sourceIp?: string | null } | null,
    ): Promise<RestoreApproval> {
      this.requireCapability(caller, "restore.request");
      if (typeof req.planHash !== "string" || !req.planHash.startsWith("sha384:")) throw new Error("planHash must be a sha384 plan-binding hash");
      if (typeof req.runId !== "string" || req.runId.length < 1) throw new Error("runId required");
      if (typeof req.reason !== "string" || req.reason.trim().length === 0) throw new Error("reason required");
      const reasonErr = validateFreeText(req.reason, "reason", REASON_MAX_LEN);
      if (reasonErr !== null) throw new Error(reasonErr);
      const now = Date.now();
      const existing = await this.readApprovalRecord(req.planHash);
      // Do not let a re-request overwrite a still-usable approval (effective status approved) OR a LIVE
      // RESERVATION (effective status applying, HI-03 / ASVS 2.1.6): either would silently drop a checker's
      // approval (or an in-flight apply's own reservation) and reset the whole record to pending out from
      // under it, reopening the plan hash for a second, independent request+approve+reserve cycle -- the
      // same clobber canApprove/canReject already refuse. An expired/rejected/consumed or merely-requested
      // record may be replaced by a fresh request (a new attempt at the same plan).
      const existingStatus = existing ? effectiveStatus(existing, now) : null;
      if (existingStatus === "approved" || existingStatus === "applying") {
        // G094: every refusal in this state machine is a thrown Error whose text reaches one operator's screen
        // and nowhere else. The pack could not answer "who tried what" for the one subsystem whose entire
        // purpose is to be answerable. Counters only: stage + closed class, never the plan or the actor.
        await recordApprovalFault(this.state.storage, "request", "already-exists");
        throw new Error("an approval already exists for this plan; consume or reject it before re-requesting");
      }
      // AN APPROVAL IS ONLY EVER MINTED AGAINST A PREVIEW THIS ENGINE RECORDED AND CAN DATE. Two refusals,
      // one remedy.
      //
      // NO ANCHOR AT ALL. Reading this as "then the request route's re-plan is the plan, anchor to now" is
      // what made the stale-plan refusal below unreachable in practice: notePlanSeen sweeps every anchor past
      // RESTORE_APPLY_DEADLINE_MS on every dry run for every plan hash, so a colleague previewing an
      // unrelated plan deleted the very anchor this refusal reads, and the operator holding yesterday's card
      // was handed a clean 24 hours. Once per cycle, indefinitely, because the plan hash carries no timestamp
      // of its own. The same reading covered two more ways to lose an anchor: the dry-run route's anchor note
      // swallows its faults, so a DO hiccup left none; and rejectRestore/consumeRestore delete the anchor, so
      // reject-then-re-request with no fresh dry run minted a clean window against a plan read days earlier.
      // All three are the same defect and all three are closed here. The re-plan the request route performs
      // is NOT the missing disclosure: its fidelityWarnings are computed and dropped, so no human ever reads
      // them, and the operator is approving the card they were shown.
      //
      // The cost is that a request raised with no recorded dry run is refused, including a direct API caller
      // who skipped the preview. That is the correct trade: dual control means a human read a plan, and a dry
      // run is read-only, cheap and already the documented first step. It cannot refuse a legitimate holder
      // of a current plan, because the sweep only ever removes anchors ALREADY past the deadline -- exactly
      // the ones the stale refusal below would reject anyway.
      const anchoredAt = await planAnchorMs(this.state.storage, req.planHash);
      if (anchoredAt === null) {
        await recordApprovalFault(this.state.storage, "request", "no-plan-anchor");
        throw new Error("this request is not raised against a dry run this engine recorded; run the dry run for this restore and request from the plan it returns");
      }
      // THE STALE PLAN. A recorded anchor older than RESTORE_APPLY_DEADLINE_MS means the operator is raising
      // this request against a preview the engine can no longer vouch for: the plan's fidelity warnings were
      // computed against a deadline that has already gone by, so an approval minted now would let the apply
      // drop expirations that plan described as safe. The remedy is the one the operator needs anyway: run
      // the dry run again and read what it now says.
      if (now - anchoredAt > RESTORE_APPLY_DEADLINE_MS) {
        await recordApprovalFault(this.state.storage, "request", "expired");
        throw new Error("the plan this request is raised against is older than this engine will vouch for; run the dry run again and request from the plan it returns");
      }
      // The requester (MAKER) is the verified caller. The maker != checker axis is the STABLE SUBJECT: a
      // caller with no subject (the bare-token break-glass) cannot be a maker, so a request from it is
      // refused (dual control needs two attributable, stable identities). The email is recorded for display
      // only. This keeps maker != checker meaningful AND keyed on the immutable identity.
      const requesterSubject = caller ? caller.subject : null;
      const requestedBy = caller?.email ? caller.email : null;
      if (requesterSubject === null) {
        await recordApprovalFault(this.state.storage, "request", "identity-unattributable");
        throw new Error("dual control requires an attributable identity; the bare-token fallback cannot raise a request");
      }
      const record: RestoreApproval = {
        planHash: req.planHash,
        runId: req.runId,
        isLatest: req.isLatest === true,
        plannedWrites: typeof req.plannedWrites === "number" && Number.isFinite(req.plannedWrites) ? req.plannedWrites : 0,
        bytes: typeof req.bytes === "number" && Number.isFinite(req.bytes) ? req.bytes : 0,
        redirectBinding: typeof req.redirectBinding === "string" ? req.redirectBinding : null,
        // destinationId (HI-15): WHICH archive copy the cues were computed against, so the approver's
        // inbox and the audit trail can show it. Included only when set (exactOptionalPropertyTypes).
        ...(typeof req.destinationId === "string" ? { destinationId: req.destinationId } : {}),
        requesterSubject,
        requestedBy: requestedBy ?? requesterSubject,
        // The maker's verified group claims, recorded as an INPUT to the spend-time re-resolution (see
        // approvalIdentitiesStillAuthorised). Bounded by the DO's own boundGroupList like every other group
        // input; an oidc/saml maker's stored copy is never read back (their live snapshot is).
        requesterGroups: this.boundGroupList(Array.isArray(caller?.groups) ? caller.groups : []),
        requestedAt: nowMillisISO(),
        reason: req.reason.trim(),
        status: "requested",
        // THE TTL STARTS AT THE PLAN, NOT AT THIS REQUEST. approvalAnchorMs takes the recorded dry-run
        // instant for this plan hash when there is one (clamped to now, so it can only ever shorten), so
        // the last instant an apply of this approval may still be writing is exactly the applyDeadline the
        // plan already published and computed its fidelity warnings against. Stamping `now` here was what
        // let a lapsed KV expiration be dropped with nothing in the approved plan naming it, and what let
        // the same displayed plan be re-requested after each expiry to reopen that gap indefinitely.
        expiresAt: new Date(approvalAnchorMs(anchoredAt, now) + APPROVAL_TTL_MS).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
      };
      await this.state.storage.put(approvalKey(req.planHash), record);
      await this.appendAudit({
        actorSubject: requesterSubject,
        actorEmail: requestedBy,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "restore-request",
        outcome: "success",
        target: { kind: "restore", runId: record.runId, redirectBinding: record.redirectBinding, planHash: record.planHash, isLatest: record.isLatest, reason: record.reason, ...(record.destinationId !== undefined ? { destinationId: record.destinationId } : {}) },
      });
      return record;
    }

    // approveRestore moves a requested record to approved, enforcing maker != checker SERVER-SIDE: a
    // self-approval (caller == requestedBy) is refused even if the caller holds Approver/Owner.
    // Approver+ (DO re-check). The state rule (only a still-open record can be approved) and the
    // maker != checker rule both live in approvals.canApprove, evaluated inside this read-modify-write
    // so the decision is atomic with the write. The restore-approve audit event attributes the
    // CHECKER's act of approving (actor = checker, target.approverEmail = checker); the maker is the
    // record's requestedBy, already recorded by the paired restore-request event. The restore-APPLY
    // event the router records carries BOTH the maker (actor) and the approver (target.approverEmail),
    // which is the event the "both identities audited" requirement points at.
    async approveRestore(
      req: { planHash?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups?: string[]; sourceIp?: string | null } | null,
    ): Promise<RestoreApproval> {
      this.requireCapability(caller, "restore.approve");
      if (typeof req.planHash !== "string") throw new Error("planHash required");
      const now = Date.now();
      const record = await this.readApprovalRecord(req.planHash);
      if (record === null) {
        await recordApprovalFault(this.state.storage, "approve", "no-such-request");
        throw new Error("no such request");
      }
      const checkerSubject = caller ? caller.subject : null;
      const checkerEmail = caller?.email ? caller.email : null;
      // A token-fallback caller has no STABLE subject and so cannot be a distinct checker; refuse (dual
      // control needs two attributable, stable identities, maker != checker by subject).
      if (checkerSubject === null) {
        await recordApprovalFault(this.state.storage, "approve", "identity-unattributable");
        throw new Error("dual control requires an attributable identity; the bare-token fallback cannot approve");
      }
      // canApprove compares the caller's SUBJECT to the record's requesterSubject (primary axis): a
      // self-approval (same subject) is refused even across email-case variance; a recycled email whose
      // subject differs is a legitimate distinct checker. It ALSO compares the caller's email to the
      // record's requestedBy (belt-and-suspenders floor), since one human can legitimately hold two
      // distinct, IdP-bound subjects sharing one verified email.
      const verdict = canApprove(record, checkerEmail, checkerSubject, now);
      if (!verdict.ok) {
        // The SELF-APPROVAL case is the one a maker-checker attestation is asked to prove never happened, and
        // it was recorded nowhere: the DO refused it and threw prose. classifyApprovalRefusal reads the
        // record's STRUCTURED effective status (never verdict.reason, which is operator prose) to pick the
        // closed class, so a blocked maker-checker violation is now a counted, dated fact in the pack. The
        // self-approval flag is read straight off canApprove's OWN verdict (not recomputed here) so this
        // evidence classification can never disagree with the decision that actually refused the approval --
        // recomputing it from checkerSubject alone would have missed the email-floor refusal case.
        const selfApproval = verdict.reasonCode === "self-approval";
        await recordApprovalFault(this.state.storage, "approve", classifyApprovalRefusal(effectiveStatus(record, now), selfApproval));
        // G182: the closed reasonCode the decision helper ITSELF returned, so the refusal's cause survives into
        // the pack rather than into prose the pack cannot carry. This is the difference between "an approval was
        // refused" and "the approval was refused because it had EXPIRED" -- one is a shrug, the other is a fix.
        await recordGovernanceRefusal(this.state.storage, "restore-approve", verdict.reasonCode);
        throw new Error(verdict.reason);
      }
      record.status = "approved";
      record.approverSubject = checkerSubject;
      record.approvedBy = checkerEmail ?? checkerSubject;
      // The checker's verified group claims, the counterpart of requesterGroups above.
      record.approverGroups = this.boundGroupList(Array.isArray(caller?.groups) ? caller.groups : []);
      record.approvedAt = nowMillisISO();
      await this.state.storage.put(approvalKey(req.planHash), record);
      // Attribute the checker's act of approving: actor = checker (subject + email), target.approverEmail =
      // checker email (display). The maker is the record's requesterSubject/requestedBy (recorded by the
      // paired restore-request event). The restore-apply event the router records carries both identities.
      await this.appendAudit({
        actorSubject: checkerSubject,
        actorEmail: checkerEmail,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "restore-approve",
        outcome: "success",
        target: { kind: "restore", runId: record.runId, redirectBinding: record.redirectBinding, planHash: record.planHash, isLatest: record.isLatest, reason: record.reason, ...(record.destinationId !== undefined ? { destinationId: record.destinationId } : {}), ...(record.approvedBy !== undefined ? { approverEmail: record.approvedBy } : {}), ...(record.approverSubject !== undefined ? { approverSubject: record.approverSubject } : {}) },
      });
      return record;
    }

    // rejectRestore moves an open (requested or approved) record to rejected. Approver+ (DO re-check).
    // A reject does not require maker != checker (a requester may withdraw their own request). It
    // records a restore-reject audit event (actor = the rejecter).
    async rejectRestore(
      req: { planHash?: string; rejectReason?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; sourceIp?: string | null } | null,
    ): Promise<RestoreApproval> {
      this.requireCapability(caller, "restore.approve");
      if (typeof req.planHash !== "string") throw new Error("planHash required");
      const now = Date.now();
      const record = await this.readApprovalRecord(req.planHash);
      if (record === null) {
        await recordApprovalFault(this.state.storage, "reject", "no-such-request");
        throw new Error("no such request");
      }
      const verdict = canReject(record, now);
      if (!verdict.ok) {
        // G182: the refused VETO records under its OWN stage. It used to borrow "restore-approve", so "the
        // approval was refused" and "our reject of a live restore kept failing while the apply went through"
        // -- the highest-signal event this machine produces -- landed on the same key (e.g.
        // restore-approve|applying-lease) and coalesced into one count.
        await recordGovernanceRefusal(this.state.storage, "restore-reject", verdict.reasonCode);
        // "We tried to veto a restore and the reject kept failing while the apply went through": a repeatedly
        // refused VETO is the highest-signal event this machine produces, and it left no trace. The class is
        // taken from the record's effective status (mid-apply, expired, already terminal), never the prose.
        const st = effectiveStatus(record, now);
        await recordApprovalFault(this.state.storage, "reject", st === "applying" ? "applying-in-flight" : st === "expired" ? "expired" : st === "consumed" ? "consumed" : "not-rejectable");
        throw new Error(verdict.reason);
      }
      record.status = "rejected";
      // G288: the CLOSED rejection reason, re-gated HERE (defence in depth: the router validates it too, and a
      // value outside the set is DROPPED rather than persisted, so no prose can reach the record or the audit
      // event even if a future caller sends some). The requester's own free-text justification (`record.reason`)
      // is a different field and is unchanged; this is the CHECKER's verdict, and it is an enum precisely so it
      // can ride into the sealed pack.
      const rejectReason = typeof req.rejectReason === "string" && RESTORE_REJECT_REASON_SET.has(req.rejectReason)
        ? (req.rejectReason as RestoreRejectReason)
        : undefined;
      if (rejectReason !== undefined) record.rejectReason = rejectReason;
      await this.state.storage.put(approvalKey(req.planHash), record);
      // TERMINAL: drop the plan anchor. Nobody is acting on that dry run any more, so the next cycle for
      // this plan hash must anchor to a fresh one rather than to a card nobody is holding. Since
      // requestRestore refuses on an ABSENT anchor, this no longer merely re-anchors the next request to
      // "now" (which is how a reject-then-re-request used to mint a clean 24 hours against a plan read days
      // earlier): it refuses the next request until a fresh dry run is run, which is what a vetoed plan
      // deserves.
      await this.state.storage.delete(PLAN_SEEN_PREFIX + req.planHash);
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null,
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "restore-reject",
        outcome: "success",
        target: { kind: "restore", runId: record.runId, redirectBinding: record.redirectBinding, planHash: record.planHash, isLatest: record.isLatest, reason: record.reason, ...(rejectReason !== undefined ? { reasonClass: rejectReason } : {}), ...(record.destinationId !== undefined ? { destinationId: record.destinationId } : {}) },
      });
      return record;
    }

    // listApprovals returns the pending inbox with EFFECTIVE statuses (lapsed records read as
    // expired without a storage mutation). Approver/Owner see every record; a requester also sees
    // their own (canRequesterSee). Newest-first by requestedAt for a usable inbox.
    async listApprovals(caller: { email: string | null; subject: string | null; role: Role } | null, callerIsApprover: boolean): Promise<RestoreApproval[]> {
      const now = Date.now();
      const map = await this.state.storage.list<RestoreApproval>({ prefix: APPROVAL_PREFIX });
      // The "requester also sees their own" rule keys on the STABLE subject (the maker != checker axis), so
      // a requester sees their own requests regardless of email-case variance and a recycled email never
      // sees a departed member's requests. Approvers see everything (the router's role check decides that).
      const subject = caller ? caller.subject : null;
      const visible = [...map.values()].filter((r) => canRequesterSee(r, subject, callerIsApprover));
      return visible.map((r) => viewStatus(r, now)).sort((a, b) => (a.requestedAt < b.requestedAt ? 1 : a.requestedAt > b.requestedAt ? -1 : 0));
    }

    // gateRestore is the read-only apply-time gate: it reports whether a USABLE approval exists for a
    // plan hash and returns the record (with the checker email) so the router can attribute the
    // approver in the restore-apply audit event and refuse an unapproved apply BEFORE any write. It
    // does not mutate; reserveRestore (immediately before the write) is the mutating gate that actually
    // makes the apply exclusive (HI-03 / ASVS 2.1.6: the single-use transition is atomic with the START
    // of the write, not only at consume time), and the single-use consume is a separate, post-success step.
    async gateRestore(req: { planHash?: string }): Promise<{ usable: boolean; approval: RestoreApproval | null; required: boolean }> {
      // DUAL CONTROL OVER A RESTORE APPLY IS OWNER-OPT-IN (requireRestoreApproval), and OFF by default. Asked
      // FIRST, before the plan hash is even inspected, because when the policy is off there is no approval
      // record to look for and demanding one is precisely the lockout this flag exists to end: canApprove
      // refuses a same-subject and a same-email approval, so on a one-person estate no approval can ever
      // exist, and an unconditional gate made restore-apply unreachable for a configuration the product
      // itself calls valid (BASE_MIN_OWNERS is 1).
      //
      // `required` is returned rather than folded into `usable` so the ROUTER can tell "no approval needed"
      // apart from "approved", and skip the reserve and the single-use consume that only mean something when
      // a record exists. Collapsing the two would leave the router reserving a record that was never created.
      const required = await this.getRequireRestoreApproval();
      if (!required) return { usable: true, approval: null, required: false };
      if (typeof req.planHash !== "string") return { usable: false, approval: null, required: true };
      const now = Date.now();
      const record = await this.readApprovalRecord(req.planHash);
      let usable = isUsableApproval(record, now);
      // SPEND-TIME IDENTITY BINDING. The record is otherwise usable; the question left is whether the two
      // identities it rests on are still the two identities they were. Asked HERE as well as at the reserve so
      // the operator's 403 carries a classified cause with a real remedy ("re-approve" and "re-request" are
      // different fixes) instead of the same flat not-approved every other cause collapses into.
      if (usable && record !== null) {
        const spend = await this.approvalSpendVerdict(record);
        if (!spend.ok) {
          usable = false;
          await recordGovernanceRefusal(this.state.storage, "restore-apply", spend.reasonCode);
          return { usable, approval: viewStatus(record, now), required: true };
        }
      }
      if (!usable) {
        // G182: THE ROW THE WHOLE GAP IS ABOUT. This gate is the FIRST approval check a restore apply makes,
        // and its refusal is the 403 the operator actually sees ("restore not approved"). It classified
        // NOTHING: the router wrote one adminRefusal, "restore-apply|not-approved", for an approval that had
        // EXPIRED between approve and apply, one already CONSUMED by an apply that worked, one whose apply is
        // IN FLIGHT right now, and one that was never approved at all. Four remedies, one row -- and
        // governanceRefusals stayed EMPTY, so a support engineer reading it would conclude no refusal happened.
        //
        // The one site that DID classify (reserveRestore, below) is reached only AFTER this gate says usable,
        // so it fires only in the millisecond TOCTOU window between the two, never on the ticket.
        //
        // Recorded from the record's own STRUCTURED status, never from prose. Best-effort: it never gates the
        // refusal (the 403 is unchanged), and an out-of-vocabulary reason writes nothing at all.
        await recordGovernanceRefusal(this.state.storage, "restore-apply", classifyRestoreApplyRefusal(record, now));
      }
      return { usable, approval: record ? viewStatus(record, now) : null, required: true };
    }

    // reserveRestore is the ATOMIC gate-to-write reservation (HI-03 / ASVS 2.1.6): the router calls this
    // immediately before the write (nothing else runs in between), re-checking the approval is still usable
    // and flipping it approved -> applying, stamping appliedAt (the lease start), in ONE storage
    // read-modify-write -- there is no interceding external fetch/await between the get and the put, so
    // this is atomic under the DO's automatic input-gate exactly like consumeApproval below. A second
    // concurrent reserve for the SAME plan hash (e.g. a double-clicked Apply, a client retry-on-timeout,
    // or two deliberate concurrent requests) finds effectiveStatus "applying" (not "approved") and is
    // refused, closing the window the read-only gate above cannot: this is the actual single-use
    // transition, made atomic with the START of execution rather than its end.
    async reserveRestore(req: { planHash?: string }): Promise<{ reserved: boolean }> {
      if (typeof req.planHash !== "string") return { reserved: false };
      const now = Date.now();
      const record = await this.readApprovalRecord(req.planHash);
      if (!isUsableApproval(record, now)) {
        // G094: five distinct causes ("nobody raised this plan", "it expired", "it was already used", "another
        // apply holds it", "it was never approved") collapse into one `reserved: false` boolean, and the
        // operator is told only "approval not usable" while the approver insists they just approved it. Split
        // the refusal into its closed class at the site that knows which one it was.
        await recordApprovalFault(this.state.storage, "reserve", classifyApprovalRefusal(record === null ? null : effectiveStatus(record, now)));
        return { reserved: false };
      }
      // SPEND-TIME IDENTITY BINDING, and THIS is the authoritative one: the read-only gate above answered a
      // question about the world some milliseconds ago, and this is the transition that actually spends the
      // authority, immediately adjacent to the write. Every await between the get and the put here is a DO
      // STORAGE read (the role table, the group mapping, the custom-role catalogue, the group snapshot), the
      // same class of interceding storage call requestRestore and approveRestore already take between their own
      // get and put; nothing external is fetched, so the read-modify-write stays exactly as atomic as it was.
      const spend = await this.approvalSpendVerdict(record!);
      if (!spend.ok) {
        await recordGovernanceRefusal(this.state.storage, "restore-apply", spend.reasonCode);
        return { reserved: false };
      }
      record!.status = "applying";
      record!.appliedAt = nowMillisISO();
      await this.state.storage.put(approvalKey(req.planHash), record!);
      return { reserved: true };
    }

    // releaseRestore is the failure-path counterpart to reserveRestore: the router calls it when the
    // apply it reserved did NOT succeed (result.ok false, or an exception propagated out of the write),
    // reverting applying -> approved (clearing appliedAt) so a failed apply still leaves the approval
    // usable for a retry without a fresh round of dual control -- unchanged from the pre-reservation UX.
    // It only reverts a record CURRENTLY "applying" (the raw stored status, not the lease-lapsed
    // effective one): a lease that already lapsed means a fresh reserveRestore may have reclaimed it for
    // a NEW reservation, and this stale release must not clobber that newer one back to approved.
    async releaseRestore(req: { planHash?: string }): Promise<{ released: boolean }> {
      if (typeof req.planHash !== "string") return { released: false };
      const record = await this.readApprovalRecord(req.planHash);
      if (record === null || record.status !== "applying") {
        // G094: a STALE release (the lease lapsed and a fresh reserve reclaimed the record) is correctly
        // refused so it cannot clobber the newer reservation, and the fact that a long-running apply outlived
        // its own lease was recorded nowhere. That is the precursor to the two-applies-one-approval race.
        await recordApprovalFault(this.state.storage, "release", record === null ? "no-such-request" : "lease-reclaimed");
        return { released: false };
      }
      record.status = "approved";
      delete record.appliedAt;
      await this.state.storage.put(approvalKey(req.planHash), record);
      return { released: true };
    }

    // consumeApproval is the atomic single-use consume the router calls AFTER a successful apply: it
    // flips THIS request's own reservation (the raw stored status is "applying", set by reserveRestore
    // just before the write) to consumed in one read-modify-write, so a consumed approval can never
    // authorise a second apply. It checks the raw status directly (rather than isUsableApproval/
    // effectiveStatus) because by the time a caller reaches consume, reserveRestore already re-validated
    // usability at reserve time; this only needs to confirm the reservation this request took is still
    // the one on record (a stale reservation whose lease lapsed and was reclaimed by a fresh reserve must
    // not be consumed out from under that newer reservation). A failed apply does NOT call this (it
    // releases instead), so its approval stays usable for a retry. Returns the consumed record (with the
    // checker email) or { consumed: false } if the record was no longer this request's reservation.
    async consumeApproval(req: { planHash?: string }): Promise<{ consumed: boolean; approval?: RestoreApproval }> {
      if (typeof req.planHash !== "string") return { consumed: false };
      const record = await this.readApprovalRecord(req.planHash);
      if (record === null || record.status !== "applying") {
        // G094, THE ACCOUNTING HOLE. This branch is reached AFTER a restore apply SUCCEEDED: the write landed
        // on the customer's live data, and the approval that authorised it is not marked consumed (its lease
        // lapsed and a fresh reserve reclaimed it, or the record is gone). Single-use is therefore not proven
        // for that apply, and nothing anywhere recorded it. A non-zero consume|lease-reclaimed count is the
        // signal support must escalate on: it is the only evidence that one approval may have authorised two
        // applies.
        await recordApprovalFault(this.state.storage, "consume", record === null ? "no-such-request" : "lease-reclaimed");
        return { consumed: false };
      }
      record.status = "consumed";
      delete record.appliedAt;
      await this.state.storage.put(approvalKey(req.planHash), record);
      // TERMINAL: drop the plan anchor (see rejectRestore). The apply has happened; a later request for the
      // same plan hash is a new decision and is REFUSED until the dry run that informs it has been run.
      await this.state.storage.delete(PLAN_SEEN_PREFIX + req.planHash);
      return { consumed: true, approval: record };
    }

    // ---- Drill evidence: non-hash-chained evidence log ---------------
    // A flat list of dated drill/rehearsal records, keyed by `drill-evidence:<ulid>` so the list
    // is chronologically ordered (ULID encodes time). It is NOT a tamper-evident chain; it is
    // an evidence log (distinct purpose). The same redaction discipline applies: no key material,
    // no secret, no plaintext value, only the run id, kind, actor email, timestamp, and an
    // optional note. The log is BOUNDED by DRILL_EVIDENCE_CAP (ENG-SCALE-06): recordDrillEvidence
    // rolls over the oldest rows once the count exceeds the cap (mirroring AUDIT_CAP / RING_CAP), so
    // an account running daily scheduled restore tests across many downpipes cannot grow it without
    // limit. The reads page the scan rather than assuming one storage list page holds the whole log.

    // recordDrillEvidence appends one evidence entry. Operator+ (DO re-check). The key is a ULID
    // minted from the DO clock so entries list in chronological order without a separate counter.
    // The caller the router forwarded (CALLER_HEADER) provides the recordedBy identity; the
    // bare-token fallback records null (no attributable email).
    async recordDrillEvidence(
      req: { runId?: string; kind?: string; note?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; sourceIp?: string | null } | null,
    ): Promise<DrillEvidenceEntry> {
      this.requireCapability(caller, "drill.run");
      // G097: the DATED evidence trail is what a customer's auditor reads, and the console's POST that writes
      // it is caught-and-discarded on failure (not even a toast). So "we drilled weekly and the trail is empty
      // for a month" could not be told from "every evidence write has been failing since a route regression".
      // The two ENGINE-OBSERVABLE halves are recorded here: a REFUSED entry (this validation block) and a
      // FAULTED append (the storage write below). The network faults the engine never sees are the console's
      // half of the gap and ride in the clientDiagnostics ring (CLIENT_FAULT_KINDS evidence-write-failed).
      const refuseEvidence = async (): Promise<void> => {
        await recordDrillDrop(this.state.storage, "evidence-refused");
        await recordAdminRefusal(this.state.storage, "drill-evidence", "shape-rejected");
      };
      if (typeof req.runId !== "string" || req.runId.trim().length === 0) {
        await refuseEvidence();
        throw new Error("runId required");
      }
      if (req.kind !== "in-account" && req.kind !== "offline-rehearsal") {
        await refuseEvidence();
        throw new Error("kind must be in-account or offline-rehearsal");
      }
      if (req.note !== undefined && typeof req.note !== "string") {
        await refuseEvidence();
        throw new Error("note must be a string");
      }
      if (req.note !== undefined) {
        const noteErr = validateFreeText(req.note, "note", NOTE_MAX_LEN);
        if (noteErr !== null) {
          await refuseEvidence();
          throw new Error(noteErr);
        }
      }
      const now = Date.now();
      const entry: DrillEvidenceEntry = {
        runId: req.runId.trim(),
        kind: req.kind,
        recordedBy: caller?.email ? caller.email : null,
        recordedAt: nowMillisISO(),
        ...(req.note !== undefined ? { note: req.note } : {}),
      };
      try {
        await this.state.storage.put(`${DRILL_EVIDENCE_PREFIX}${newULID(now)}`, entry);
      } catch (e) {
        // G097: the drill HAPPENED (downpipes[].lastRestoreTestAt proves it) and its evidence row does not
        // exist. Record the divergence, then rethrow so the caller still sees the failure (behaviour unchanged).
        await recordDrillDrop(this.state.storage, "evidence-write-failed");
        throw e;
      }
      // Roll over the OLDEST rows once the count exceeds DRILL_EVIDENCE_CAP (ENG-SCALE-06), mirroring
      // rollOverAudit. The keys are ULID-suffixed, so a prefix list is ascending = oldest-first; we
      // read a BOUNDED oldest window (cap + a small batch headroom) and delete only the surplus oldest
      // keys (page.size - cap). recordDrillEvidence adds exactly one row per call, so the steady-state
      // surplus is one; the batch headroom lets a one-off backlog (e.g. a lowered cap) drain over a few
      // calls without ever reading the whole log. It runs inside the same single-threaded DO storage
      // turn as the put, so the cap is enforced atomically with the append. Best-effort by construction:
      // the entry is already durably written; a rollover fault would only leave a few extra old rows.
      const window = await this.state.storage.list<DrillEvidenceEntry>({ prefix: DRILL_EVIDENCE_PREFIX, limit: DRILL_EVIDENCE_CAP + DRILL_EVIDENCE_ROLLOVER_BATCH });
      if (window.size > DRILL_EVIDENCE_CAP) {
        const oldestFirst = [...window.keys()]; // ascending key order == oldest-first
        const dropCount = window.size - DRILL_EVIDENCE_CAP;
        for (let i = 0; i < dropCount; i++) await this.state.storage.delete(oldestFirst[i]!);
      }
      return entry;
    }

    // listDrillEvidence returns all drill-evidence entries newest-first. The keys are ULIDs so the
    // storage list (lexicographic) is chronological; reversing gives newest-first for the console.
    // Any authenticated role may read the evidence list. It pages the scan (listAllByPrefix) so the
    // read is correct even if the (capped) log ever spans more than one storage list page, and bounded
    // by DRILL_EVIDENCE_CAP regardless.
    async listDrillEvidence(): Promise<DrillEvidenceEntry[]> {
      const map = await this.listAllByPrefix<DrillEvidenceEntry>(DRILL_EVIDENCE_PREFIX);
      return [...map.values()].reverse();
    }
  };
}
