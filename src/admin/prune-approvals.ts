// Dual control: a retention-prune APPLY deletes archive bytes outright, a less reversible act than a
// restore apply (which overwrites live data but leaves the archive itself untouched, recoverable by a
// later restore). The standing platform precedent for a write this consequential is restore's
// request -> approve -> apply flow (admin/approvals.ts): a single identity plus step-up is NOT enough on its
// own -- retention.enforce is armed via plain downpipe.write (dual-controlled only when the OPT-IN
// requireConfigApproval gate is on, which is off by default), so without this module a default estate's
// single owner could flip Enforce and delete the archive solo through the batched-capsule route. This
// module mirrors admin/approvals.ts's shape (the planHash binding, the requested -> approved -> applying
// -> consumed/rejected state machine, maker != checker on the STABLE subject) as its own, independent,
// PARALLEL mechanism -- not a reuse of RestoreApproval, which is typed for restore-specific blast-radius
// cues (target binding, cf-config surfaces, media/D1 scope) this action has none of. Kept separate so a
// change to either mechanism can never silently reshape the other.
//
// SINGLE-OWNER ESTATES. This module invents NO carve-out for a sole owner: exactly like restore's approval flow, a
// self-approval is refused even for an Owner, and the bare-token break-glass (no stable subject) can
// neither request nor approve. A sole-owner estate is simply blocked from a real apply until a second
// authorised identity exists, precisely the posture restore-flow/confirm.ts already states in the
// console ("This apply needs a second authorised identity to approve this exact plan first; the approver
// must differ from you"). Preview (previewOnly:true) needs no approval at all: it deletes nothing.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations only.
// TypeScript 6 + exactOptionalPropertyTypes: every optional key is included only when it carries a value.

import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { canonicalJSON } from "../format/canonjson.ts";

// PruneApprovalStatus mirrors ApprovalStatus (approvals.ts) exactly; see its comment for the full
// rationale of each state. requested -> approved (maker != checker) -> applying (the atomic reserve,
// HI-03/ASVS 2.1.6 lease-guarded) -> consumed (single-use, on a successful apply) or, on a failed/errored
// apply, released back to approved for a retry with no fresh round of dual control. rejected and expired
// are terminal-by-action and terminal-by-time respectively.
export type PruneApprovalStatus = "requested" | "approved" | "applying" | "rejected" | "consumed" | "expired";

// PruneApproval is one dual-control record, held in the scheduler DO under `prune-approval:${planHash}`.
export interface PruneApproval {
  planHash: string; // "sha384:..." the binding key; the storage key is `prune-approval:${planHash}`
  downpipeId: string;
  retainedRuns: number; // blast-radius cue for the approver's inbox: how many runs the plan keeps
  supersededRuns: number; // blast-radius cue: how many runs the plan would supersede + prune
  requesterSubject: string; // the requester's STABLE subject (the MAKER); the primary maker != checker key
  // requestedBy is the requester's verified email, also a belt-and-suspenders comparison axis (see
  // canApprovePrune) -- subject alone does not catch one human holding two IdP-bound subjects that share
  // this email, so requestedBy is no longer display/audit only.
  requestedBy: string;
  // requesterGroups / approverGroups mirror RestoreApproval's fields exactly: the verified group claims each
  // identity presented when they acted, recorded as an INPUT to the spend-time authority re-resolution
  // (approvalIdentitiesStillAuthorised, approvals.ts) and never as an authority in themselves.
  requesterGroups: string[];
  requestedAt: string; // RFC-3339 UTC millis
  reason: string; // the requester's free-text justification (redaction-safe text, not a secret)
  status: PruneApprovalStatus;
  approverSubject?: string; // the CHECKER's STABLE subject; MUST differ from requesterSubject
  approvedBy?: string; // the CHECKER's verified email (DISPLAY/AUDIT only); present once approved
  approverGroups?: string[]; // the CHECKER's verified group claims at approve time; present once approved
  approvedAt?: string;
  appliedAt?: string; // RFC-3339 UTC millis; the reservation lease start (cleared on release/consume)
  expiresAt: string; // RFC-3339 UTC millis; status reads as "expired" past this
  rejectReason?: PruneRejectReason;
}

// PRUNE_REJECT_REASONS mirrors RESTORE_REJECT_REASONS' shape with prune-appropriate remedies: each maps
// to a different fix, which is the point (a checker's free prose would describe the customer's own
// archive contents and must never ride into the sealed pack).
export const PRUNE_REJECT_REASONS = [
  "stale-plan", // the plan is against an out-of-date split; the requester should re-plan and re-request
  "policy", // a change-control / governance rule forbids this prune now
  "too-broad", // the plan would supersede more than the incident/cleanup calls for; narrow the retention window first
  "other", // none of the above. Residual, never a message
] as const;
export type PruneRejectReason = (typeof PRUNE_REJECT_REASONS)[number];
export const PRUNE_REJECT_REASON_SET: ReadonlySet<string> = new Set(PRUNE_REJECT_REASONS);

export const PRUNE_APPROVAL_PREFIX = "prune-approval:";

export function pruneApprovalKey(planHash: string): string {
  return PRUNE_APPROVAL_PREFIX + planHash;
}

// PRUNE_APPROVAL_TTL_MS / PRUNE_APPLY_LEASE_MS mirror APPROVAL_TTL_MS / RESTORE_APPLY_LEASE_MS exactly
// (approvals.ts): a 24h request/approval TTL, and a 30-minute reservation lease well beyond any single
// apply's real duration, so a crashed reservation self-heals rather than wedging the approval forever.
export const PRUNE_APPROVAL_TTL_MS = 24 * 60 * 60 * 1000;
export const PRUNE_APPLY_LEASE_MS = 30 * 60 * 1000;

// PrunePlanBinding is the canonical, redaction-safe object the planHash is computed over: the downpipe id
// and its CURRENT retained/superseded run-id sets (sorted, so caller ordering cannot change the hash) plus
// the retention policy's window (keepRuns/keepDays, never enforce -- enforce does not change WHAT would be
// deleted, only whether this call commits it, and the apply route re-reads it fresh regardless). Computed
// keylessly from partitionRuns (seal/prune.ts), the SAME pure split the candidate route already serves, so
// request/approve/apply can never disagree about which runs a plan covers without re-running a decrypt.
// A change to either run-id set (a new run sealed, a run's status changing) yields a DIFFERENT hash that
// simply has no matching approval -- the same re-arm-on-change teeth restorePlanHash relies on.
interface PrunePlanBinding {
  downpipeId: string;
  retainedRunIds: string[];
  supersededRunIds: string[];
  keepRuns?: number;
  keepDays?: number;
}

export async function prunePlanHash(input: { downpipeId: string; retainedRunIds: readonly string[]; supersededRunIds: readonly string[]; keepRuns?: number; keepDays?: number }): Promise<string> {
  const binding: PrunePlanBinding = {
    downpipeId: input.downpipeId,
    retainedRunIds: [...input.retainedRunIds].sort(),
    supersededRunIds: [...input.supersededRunIds].sort(),
    ...(input.keepRuns !== undefined ? { keepRuns: input.keepRuns } : {}),
    ...(input.keepDays !== undefined ? { keepDays: input.keepDays } : {}),
  };
  return `sha384:${hexEncode(await sha384(canonicalJSON(binding)))}`;
}

// approvalTimestampUnparseable mirrors approvals.ts's guard (G312): a stored expiresAt that does not parse
// must never silently read as non-expired forever; counted at the one read site (the DO caller), never here.
export function pruneApprovalTimestampUnparseable(record: PruneApproval): boolean {
  return !Number.isFinite(Date.parse(record.expiresAt));
}

// effectiveStatus mirrors approvals.ts's lazy-expiry + lease-reclaim projection exactly, over the leaner
// PruneApproval shape.
export function effectivePruneStatus(record: PruneApproval, now: number): PruneApprovalStatus {
  if (record.status === "rejected" || record.status === "consumed") return record.status;
  const exp = Date.parse(record.expiresAt);
  if (Number.isFinite(exp) && exp <= now) return "expired";
  if (record.status === "applying") {
    const applied = record.appliedAt ? Date.parse(record.appliedAt) : NaN;
    if (!Number.isFinite(applied) || now - applied > PRUNE_APPLY_LEASE_MS) return "approved";
    return "applying";
  }
  return record.status;
}

// isUsablePruneApproval mirrors isUsableApproval: a valid approval for an apply iff its effective status
// is "approved", a checker subject is recorded, and that subject differs from the requester's (maker !=
// checker, on the STABLE principals). A null record is never usable.
export function isUsablePruneApproval(record: PruneApproval | null, now: number): boolean {
  if (record === null) return false;
  if (effectivePruneStatus(record, now) !== "approved") return false;
  if (!record.approverSubject) return false;
  if (record.approverSubject === record.requesterSubject) return false;
  return true;
}

export type PruneGovernanceDecision = { ok: true } | { ok: false; reason: string };

// canApprovePrune mirrors canApprove: a self-approval (by stable subject) is refused even for an Owner;
// only a "requested" record can be approved (not already approved/rejected/consumed/expired/applying).
// It also refuses a same-EMAIL self-approval (belt-and-suspenders, on top of the subject check),
// mirroring canApproveChange / canApproveOwnerAction -- one human can legitimately hold two distinct,
// IdP-bound subjects sharing one verified email, so the subject check alone does not catch a
// request-as-A / approve-as-B self-approval by that human.
export function canApprovePrune(record: PruneApproval, approverEmail: string | null, approverSubject: string | null, now: number): PruneGovernanceDecision {
  if (approverSubject !== null && approverSubject === record.requesterSubject) {
    return { ok: false, reason: "cannot approve your own request" };
  }
  if (approverEmail !== null && approverEmail === record.requestedBy) {
    return { ok: false, reason: "cannot approve your own request" };
  }
  const status = effectivePruneStatus(record, now);
  if (status === "expired") return { ok: false, reason: "the request has expired; raise a new one" };
  if (status === "rejected") return { ok: false, reason: "the request was rejected" };
  if (status === "consumed") return { ok: false, reason: "the approval was already used" };
  if (status === "approved") return { ok: false, reason: "the request is already approved" };
  if (status === "applying") return { ok: false, reason: "the approval is currently being applied" };
  return { ok: true };
}

// canRejectPrune mirrors canReject: a still-open (requested or approved) record can be rejected; a reject
// does not require maker != checker (the requester may withdraw their own request).
export function canRejectPrune(record: PruneApproval, now: number): PruneGovernanceDecision {
  const status = effectivePruneStatus(record, now);
  if (status === "rejected") return { ok: false, reason: "the request was already rejected" };
  if (status === "consumed") return { ok: false, reason: "the approval was already used" };
  if (status === "expired") return { ok: false, reason: "the request has expired" };
  if (status === "applying") return { ok: false, reason: "the approval is currently being applied" };
  return { ok: true };
}

// viewPruneStatus mirrors viewStatus: the read-time EFFECTIVE-status projection for the inbox listing,
// a pure copy that never mutates storage.
export function viewPruneStatus(record: PruneApproval, now: number): PruneApproval {
  const status = effectivePruneStatus(record, now);
  return status === record.status ? record : { ...record, status };
}

// canRequesterSeePrune mirrors canRequesterSee: Approver/Owner see the whole inbox; a requester also sees
// their own requests (keyed on the stable subject, never the email).
export function canRequesterSeePrune(record: PruneApproval, callerSubject: string | null, callerIsApprover: boolean): boolean {
  if (callerIsApprover) return true;
  return callerSubject !== null && record.requesterSubject === callerSubject;
}
