// Dual control: the scheduler DO storage authority for PruneApproval (admin/prune-approvals.ts),
// mirroring RestoreApprovalMixin's shape (scheduler-do-restore-approval.ts) verbatim in structure --
// request -> approve (maker != checker) -> reserve (atomic, HI-03/ASVS 2.1.6) -> consume/release -- over
// the leaner PruneApproval record. Kept as its OWN mixin (not folded into RestoreApprovalMixin) so a
// change to either dual-control machine can never silently reshape the other; see prune-approvals.ts's
// header for why this does not simply reuse RestoreApproval.

import {
  canApprovePrune,
  canRejectPrune,
  canRequesterSeePrune,
  effectivePruneStatus,
  isUsablePruneApproval,
  PRUNE_APPROVAL_PREFIX,
  PRUNE_APPROVAL_TTL_MS,
  pruneApprovalKey,
  pruneApprovalTimestampUnparseable,
  PRUNE_REJECT_REASON_SET,
  type PruneApproval,
  type PruneRejectReason,
  viewPruneStatus,
} from "../admin/prune-approvals.ts";
import { approvalIdentitiesStillAuthorised, type ApprovalSpendVerdict } from "../admin/approvals.ts";
import type { AuthMethod, Capability, Role } from "../admin/identity.ts";
import { can } from "../admin/identity.ts";
import { recordGovernanceRefusal } from "./sched-fault-ledger.ts";
import { REASON_MAX_LEN, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { nowMillisISO, validateFreeText } from "./scheduler-helpers.ts";

export function PruneApprovalMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // pruneCallerHolds mirrors RestoreApprovalMixin's callerHolds: a custom-role caller is checked
    // against its resolved capability set; a built-in caller falls back to can(role, cap). A null
    // caller holds nothing.
    pruneCallerHolds(caller: { role: Role; capabilities?: ReadonlySet<Capability> } | null, capability: Capability): boolean {
      if (caller === null) return false;
      if (caller.capabilities !== undefined) return caller.capabilities.has(capability);
      return can(caller.role, capability);
    }

    async readPruneApprovalRecord(planHash: string): Promise<PruneApproval | null> {
      const record = (await this.state.storage.get<PruneApproval>(pruneApprovalKey(planHash))) ?? null;
      // G312 parity: a stored record whose expiresAt does not parse must not silently read as
      // non-expired forever. Best-effort and silent beyond the read itself (diagnostics only).
      if (record !== null) pruneApprovalTimestampUnparseable(record);
      return record;
    }

    // requestPruneApproval writes a `requested` record for a plan-binding hash the router computed
    // from the downpipe's CURRENT retained/superseded split (prunePlanHash, keyless -- no browser
    // master is ever needed to raise or approve a request). Mirrors requestRestore: a re-request for
    // the SAME plan hash overwrites a prior requested/expired/rejected record (a fresh attempt) but
    // refuses to clobber a still-usable APPROVED record or a live "applying" reservation.
    // pruneApprovalSpendVerdict mirrors approvalSpendVerdict (scheduler-do-restore-approval.ts) and shares its
    // RULE (approvalIdentitiesStillAuthorised), so the two dual-control machines cannot enforce the spend-time
    // binding two different ways. The reasoning for binding at the reserve rather than at the consume is
    // identical and is written out there; it applies with more force here, because what a prune apply spends
    // authority to do is delete the archive itself.
    async pruneApprovalSpendVerdict(record: PruneApproval): Promise<ApprovalSpendVerdict> {
      const makerCaps = await this.resolveStoredIdentityAuthority(record.requesterSubject, record.requestedBy, record.requesterGroups);
      const checkerCaps = await this.resolveStoredIdentityAuthority(record.approverSubject, record.approvedBy, record.approverGroups);
      return approvalIdentitiesStillAuthorised(makerCaps, checkerCaps);
    }

    async requestPruneApproval(
      req: { planHash?: string; downpipeId?: string; retainedRuns?: number; supersededRuns?: number; reason?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups?: string[]; sourceIp?: string | null } | null,
    ): Promise<PruneApproval> {
      if (!this.pruneCallerHolds(caller, "restore.request")) throw new Error("forbidden: restore.request capability required");
      if (typeof req.planHash !== "string" || !req.planHash.startsWith("sha384:")) throw new Error("planHash must be a sha384 plan-binding hash");
      if (typeof req.downpipeId !== "string" || req.downpipeId.length < 1) throw new Error("downpipeId required");
      if (typeof req.reason !== "string" || req.reason.trim().length === 0) throw new Error("reason required");
      const reasonErr = validateFreeText(req.reason, "reason", REASON_MAX_LEN);
      if (reasonErr !== null) throw new Error(reasonErr);
      const now = Date.now();
      const existing = await this.readPruneApprovalRecord(req.planHash);
      const existingStatus = existing ? effectivePruneStatus(existing, now) : null;
      if (existingStatus === "approved" || existingStatus === "applying") {
        throw new Error("an approval already exists for this plan; consume or reject it before re-requesting");
      }
      const requesterSubject = caller ? caller.subject : null;
      const requestedBy = caller?.email ? caller.email : null;
      if (requesterSubject === null) {
        throw new Error("dual control requires an attributable identity; the bare-token fallback cannot raise a request");
      }
      const record: PruneApproval = {
        planHash: req.planHash,
        downpipeId: req.downpipeId,
        retainedRuns: typeof req.retainedRuns === "number" && Number.isFinite(req.retainedRuns) ? req.retainedRuns : 0,
        supersededRuns: typeof req.supersededRuns === "number" && Number.isFinite(req.supersededRuns) ? req.supersededRuns : 0,
        requesterSubject,
        requestedBy: requestedBy ?? requesterSubject,
        // The maker's verified group claims, the input to the spend-time re-resolution; see requestRestore.
        requesterGroups: this.boundGroupList(Array.isArray(caller?.groups) ? caller.groups : []),
        requestedAt: nowMillisISO(),
        reason: req.reason.trim(),
        status: "requested",
        expiresAt: new Date(now + PRUNE_APPROVAL_TTL_MS).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
      };
      await this.state.storage.put(pruneApprovalKey(req.planHash), record);
      await this.appendAudit({
        actorSubject: requesterSubject,
        actorEmail: requestedBy,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "retention-prune-request",
        outcome: "success",
        target: { kind: "prune-approval", downpipeId: record.downpipeId, planHash: record.planHash, retainedRuns: record.retainedRuns, supersededRuns: record.supersededRuns, reason: record.reason },
      });
      return record;
    }

    // approvePruneApproval mirrors approveRestore: maker != checker enforced SERVER-SIDE on the stable
    // subject, atomic with the write (read-modify-write inside one DO storage call).
    async approvePruneApproval(
      req: { planHash?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups?: string[]; sourceIp?: string | null } | null,
    ): Promise<PruneApproval> {
      if (!this.pruneCallerHolds(caller, "restore.approve")) throw new Error("forbidden: restore.approve capability required");
      if (typeof req.planHash !== "string") throw new Error("planHash required");
      const now = Date.now();
      const record = await this.readPruneApprovalRecord(req.planHash);
      if (record === null) throw new Error("no such request");
      const checkerSubject = caller ? caller.subject : null;
      const checkerEmail = caller?.email ? caller.email : null;
      if (checkerSubject === null) {
        throw new Error("dual control requires an attributable identity; the bare-token fallback cannot approve");
      }
      // canApprovePrune compares BOTH the caller's subject (primary) and email (belt-and-suspenders
      // floor) against the record's requester -- see canApprovePrune's own comment in prune-approvals.ts.
      const verdict = canApprovePrune(record, checkerEmail, checkerSubject, now);
      if (!verdict.ok) throw new Error(verdict.reason);
      record.status = "approved";
      record.approverSubject = checkerSubject;
      record.approvedBy = checkerEmail ?? checkerSubject;
      record.approverGroups = this.boundGroupList(Array.isArray(caller?.groups) ? caller.groups : []);
      record.approvedAt = nowMillisISO();
      await this.state.storage.put(pruneApprovalKey(req.planHash), record);
      await this.appendAudit({
        actorSubject: checkerSubject,
        actorEmail: checkerEmail,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "retention-prune-approve",
        outcome: "success",
        target: { kind: "prune-approval", downpipeId: record.downpipeId, planHash: record.planHash, retainedRuns: record.retainedRuns, supersededRuns: record.supersededRuns, reason: record.reason, approverEmail: record.approvedBy, approverSubject: record.approverSubject },
      });
      return record;
    }

    // rejectPruneApproval mirrors rejectRestore: any still-open record can be rejected (no maker !=
    // checker requirement -- the requester may withdraw their own request).
    async rejectPruneApproval(
      req: { planHash?: string; rejectReason?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; sourceIp?: string | null } | null,
    ): Promise<PruneApproval> {
      if (!this.pruneCallerHolds(caller, "restore.approve")) throw new Error("forbidden: restore.approve capability required");
      if (typeof req.planHash !== "string") throw new Error("planHash required");
      const now = Date.now();
      const record = await this.readPruneApprovalRecord(req.planHash);
      if (record === null) throw new Error("no such request");
      const verdict = canRejectPrune(record, now);
      if (!verdict.ok) throw new Error(verdict.reason);
      record.status = "rejected";
      const rejectReason = typeof req.rejectReason === "string" && PRUNE_REJECT_REASON_SET.has(req.rejectReason) ? (req.rejectReason as PruneRejectReason) : undefined;
      if (rejectReason !== undefined) record.rejectReason = rejectReason;
      await this.state.storage.put(pruneApprovalKey(req.planHash), record);
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null,
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "retention-prune-reject",
        outcome: "success",
        target: { kind: "prune-approval", downpipeId: record.downpipeId, planHash: record.planHash, retainedRuns: record.retainedRuns, supersededRuns: record.supersededRuns, reason: record.reason, ...(rejectReason !== undefined ? { reasonClass: rejectReason } : {}) },
      });
      return record;
    }

    // listPruneApprovals mirrors listApprovals: Approver/Owner see every record; a requester also sees
    // their own (canRequesterSeePrune). Newest-first.
    async listPruneApprovals(caller: { email: string | null; subject: string | null; role: Role } | null, callerIsApprover: boolean): Promise<PruneApproval[]> {
      const now = Date.now();
      const map = await this.state.storage.list<PruneApproval>({ prefix: PRUNE_APPROVAL_PREFIX });
      const subject = caller ? caller.subject : null;
      const visible = [...map.values()].filter((r) => canRequesterSeePrune(r, subject, callerIsApprover));
      return visible.map((r) => viewPruneStatus(r, now)).sort((a, b) => (a.requestedAt < b.requestedAt ? 1 : a.requestedAt > b.requestedAt ? -1 : 0));
    }

    // gatePruneApproval is the read-only apply-time gate: does a USABLE approval exist for this plan
    // hash? Mirrors gateRestore; does not mutate. reservePruneApproval (below) is the exclusive,
    // mutating gate the router calls immediately before the delete.
    async gatePruneApproval(req: { planHash?: string }): Promise<{ usable: boolean; approval: PruneApproval | null }> {
      if (typeof req.planHash !== "string") return { usable: false, approval: null };
      const now = Date.now();
      const record = await this.readPruneApprovalRecord(req.planHash);
      let usable = isUsablePruneApproval(record, now);
      // SPEND-TIME IDENTITY BINDING, mirroring gateRestore: an otherwise-usable approval is refused when either
      // recorded identity no longer holds what they held when they acted. Recorded under the prune-apply stage,
      // which is this machine's own: "our approved prune refuses to run" must never coalesce onto the restore's
      // key, because deleting an archive and overwriting live data are different incidents.
      if (usable && record !== null) {
        const spend = await this.pruneApprovalSpendVerdict(record);
        if (!spend.ok) {
          usable = false;
          await recordGovernanceRefusal(this.state.storage, "prune-apply", spend.reasonCode);
        }
      }
      return { usable, approval: record ? viewPruneStatus(record, now) : null };
    }

    // reservePruneApproval is the ATOMIC gate-to-write reservation (HI-03/ASVS 2.1.6), mirroring
    // reserveRestore: re-checks usability and flips approved -> applying, stamping the lease start, in
    // ONE read-modify-write, so a second concurrent reserve for the same plan hash is refused.
    async reservePruneApproval(req: { planHash?: string }): Promise<{ reserved: boolean }> {
      if (typeof req.planHash !== "string") return { reserved: false };
      const now = Date.now();
      const record = await this.readPruneApprovalRecord(req.planHash);
      if (!isUsablePruneApproval(record, now)) return { reserved: false };
      // The AUTHORITATIVE spend-time binding, adjacent to the delete; see reserveRestore for why every
      // interceding await here is a DO storage read and the read-modify-write stays as atomic as it was.
      const spend = await this.pruneApprovalSpendVerdict(record!);
      if (!spend.ok) {
        await recordGovernanceRefusal(this.state.storage, "prune-apply", spend.reasonCode);
        return { reserved: false };
      }
      record!.status = "applying";
      record!.appliedAt = nowMillisISO();
      await this.state.storage.put(pruneApprovalKey(req.planHash), record!);
      return { reserved: true };
    }

    // releasePruneApproval is the failure-path counterpart: reverts applying -> approved (clearing
    // appliedAt) so a failed/errored apply still leaves the approval usable for a retry with no fresh
    // round of dual control. Only reverts a record CURRENTLY "applying" (the raw stored status), so a
    // stale release cannot clobber a newer reservation that reclaimed a lapsed lease.
    async releasePruneApproval(req: { planHash?: string }): Promise<{ released: boolean }> {
      if (typeof req.planHash !== "string") return { released: false };
      const record = await this.readPruneApprovalRecord(req.planHash);
      if (record === null || record.status !== "applying") return { released: false };
      record.status = "approved";
      delete record.appliedAt;
      await this.state.storage.put(pruneApprovalKey(req.planHash), record);
      return { released: true };
    }

    // consumePruneApproval is the atomic single-use consume, called AFTER a successful apply: flips
    // THIS request's own reservation (raw status "applying") to consumed, so it can never authorise a
    // second apply. Mirrors consumeApproval exactly.
    async consumePruneApproval(req: { planHash?: string }): Promise<{ consumed: boolean; approval?: PruneApproval }> {
      if (typeof req.planHash !== "string") return { consumed: false };
      const record = await this.readPruneApprovalRecord(req.planHash);
      if (record === null || record.status !== "applying") return { consumed: false };
      record.status = "consumed";
      delete record.appliedAt;
      await this.state.storage.put(pruneApprovalKey(req.planHash), record);
      return { consumed: true, approval: record };
    }
  };
}
