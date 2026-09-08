// Dual-control approval state for a restore APPLY. A restore apply over live data is the
// only path that writes customer data back, so beyond the F1 role gate (apply requires
// Approver/Owner, enforced in the router) it requires a SECOND authorised identity's approval,
// bound to the exact plan, with maker != checker. This module owns the approval record shape,
// the plan-binding hash an approval is keyed to, the requested -> approved -> consumed state
// machine, the maker != checker rule, and the lazy-expiry computation. The scheduler Durable
// Object holds the records (it is the single storage authority); this module is the pure logic
// the DO and the validators share so the request, the approve, the apply lookup and the verify
// can never compute the binding or the state two different ways.
//
// THE BINDING KEY (maker != checker, re-arm-on-change). An approval is keyed by a canonical hash
// of the restore request's DECISION-RELEVANT fields (the run, the target binding/namespace/bucket
// NAMES, the selectors, the record cap), so approving "this exact restore" cannot be reused for a
// different one, and a re-plan that changes any decision-relevant field yields a DIFFERENT hash
// that simply has no matching approval (the server-side teeth behind the visible re-arm-on-change
// UX). The hash is recomputable from the apply request ALONE, so the apply route looks the
// approval up without re-running the dry-run and without a race. It folds in NO plaintext and NO
// key; it is over names, counts and selectors only, the same shape and the same primitives
// (canonical JSON + SHA-384, "sha384:" prefix) the codebase uses for fingerprints. The dry-run
// plan's blast-radius facts (isLatest, plannedWrites, bytes) are stored ON the record for the
// approver to review and for the audit trail, not folded into the key, so the key stays
// request-evaluable.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations only.
// TypeScript 6 + exactOptionalPropertyTypes: every optional key is included only when it carries a
// value.

import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { canonicalJSON } from "../format/canonjson.ts";
import type { GovernanceRefusalReason } from "../sched/sched-fault-ledger.ts";
// the plan hash binds the resolved cf-config surface allow-list, which is derived from the live
// registry so that adding a writer re-arms outstanding approvals automatically.
import { CF_CONFIG_SURFACES } from "../sources/cf-config-surfaces.ts";
import { PROVEN_WRITE_SURFACES } from "../sources/cf-config-write-generated.ts";
import type { Capability } from "./identity-rbac.ts";
import type { RestoreRequest } from "./restore-types.ts";

// ApprovalStatus is the closed set of states a restore approval moves through. requested: an
// Operator+ raised a request bound to a planHash (it sits in the Approver inbox). approved: a
// DIFFERENT authorised identity (Approver/Owner) approved that exact planHash (maker != checker);
// apply is now permitted for that plan. applying: the router has RESERVED the approval for the
// write it is about to perform (ASVS 2.1.6: the usability check and the single-use transition
// are now atomic, so the gate-to-write window is exclusive, not just gated, closing the TOCTOU between
// a read-only gate and the eventual consume) -- a genuinely in-flight reservation refuses a second
// reserve, while a crashed one (appliedAt older than RESTORE_APPLY_LEASE_MS) is lazily reclaimed back
// to approved, mirroring the in-flight lease already used for scheduled runs and the canary rather than
// inventing a new concurrency primitive; the router resolves it via releaseRestore (back to approved on
// a failed/errored apply) or consumeApproval (on a successful one). consumed: a successful apply
// consumed the approval (single use); a re-apply needs a fresh request + approval. rejected: an
// Approver refused it. expired: the TTL lapsed (computed lazily from expiresAt, the role table's
// lazy-expiry pattern). A re-plan that changes the request's decision fields does not transition a
// record; it simply yields a different planHash that has no matching approval (the re-arm-on-change teeth).
export type ApprovalStatus = "requested" | "approved" | "applying" | "rejected" | "consumed" | "expired";

// RestoreApproval is one approval record, held in the scheduler DO under `approval:${planHash}`.
// It carries the binding key, the blast-radius cues for the approver (stored, not hashed), the
// requester (the maker), the operator's free-text reason (not a secret, recorded for the trail),
// the status, and the checker once approved.
//
// MAKER != CHECKER COMPARES ON SUBJECT (ASVS V10.3.3 / V10.5.2) AS THE PRIMARY AXIS. approverSubject
// MUST differ from requesterSubject (the STABLE principals), enforced server-side in the DO. requestedBy/
// approvedBy are the verified EMAILS; a recycled email whose subject differs is a different identity and a
// legitimate distinct checker, so email is never enough ON ITS OWN to prove two callers are the same
// person. The reverse direction is NOT true. One human can legitimately hold two distinct, IdP-bound
// subjects that share one verified email (a passkey identity plus a native-IdP identity, or two separate
// group-role-mapped SSO connections), so subject alone is not enough either: request under subject A,
// approve under subject B, same human throughout. canApprove therefore also refuses a same-EMAIL approval
// as a belt-and-suspenders floor on top of the subject check, mirroring canApproveChange (change-control.ts)
// and canApproveOwnerAction (owner-action.ts), which both carry the identical floor. The type cannot encode
// either inequality, so both are runtime invariants proved by the validator. Every string here is escaped
// on display like every server-supplied value.
export interface RestoreApproval {
  planHash: string; // "sha384:..." the binding key; the storage key is `approval:${planHash}`
  runId: string; // the run the plan restores (for the inbox display)
  isLatest: boolean; // blast-radius cue: restoring a non-latest run is higher impact
  plannedWrites: number; // blast-radius cue: how many records an apply would write
  bytes: number; // blast-radius cue: the summed plaintext size an apply would write (upper bound)
  redirectBinding: string | null; // target.binding NAME if a redirect, else null (blast-radius cue)
  // destinationId records WHICH archive destination the plan was reviewed against (bound into
  // planHash below), so the approver's inbox and every audit event can show exactly which physical copy
  // underlay the shown cues. Absent for the single-destination back-compat default. Display/audit only,
  // like redirectBinding; the re-arm-on-change teeth live in the planHash binding, not here.
  destinationId?: string;
  requesterSubject: string; // the requester's STABLE subject (the MAKER); the maker != checker key
  requestedBy: string; // the requester's verified email (DISPLAY/AUDIT only, never the comparison axis)
  // requesterGroups / approverGroups are the VERIFIED group claims each identity presented at the moment they
  // acted, recorded for the SPEND-TIME AUTHORITY RE-RESOLUTION (see approvalIdentitiesStillAuthorised below),
  // exactly as PendingOwnerAction.proposedByGroups is recorded for the owner-action execute's replay. They are
  // an INPUT to a re-resolution, never an authority in themselves: the role table, the group->role mapping and
  // the custom-role catalogue are all re-read LIVE at the spend, so a recorded group confers nothing once the
  // mapping that gave it meaning is gone. For an oidc/saml subject they are not even read (the engine holds its
  // own live group snapshot for that subject and uses it instead); they exist for the Cloudflare-Access caller,
  // whose groups arrive only inside the inbound token and are stored nowhere else. Redaction-safe: group NAMES
  // are the customer's own directory labels, the same values the role table's mapping already holds.
  requesterGroups: string[];
  requestedAt: string; // RFC-3339 UTC millis
  reason: string; // the requester's free-text justification (redaction-safe text, not a secret)
  status: ApprovalStatus;
  approverSubject?: string; // the CHECKER's STABLE subject; MUST differ from requesterSubject (maker != checker)
  approvedBy?: string; // the CHECKER's verified email (DISPLAY/AUDIT only); present once approved
  approverGroups?: string[]; // the CHECKER's verified group claims at approve time; see requesterGroups above. Present once approved
  approvedAt?: string;
  appliedAt?: string; // RFC-3339 UTC millis; the reservation lease start, set when status flips to "applying"
  // and cleared on release back to "approved" (or on consume). Read ONLY by effectiveStatus's lazy lease
  // reclaim, the applying-side counterpart to expiresAt (ASVS 2.1.6).
  expiresAt: string; // RFC-3339 UTC millis; status reads as "expired" past this
  // rejectReason: WHY the checker turned this restore down, as a CLOSED enum. The reject wire had no
  // reason field at all, so the requester's "why was my restore rejected?" could not be answered by the console,
  // by this record, or by the audit event, and the approver's actual reasoning existed only in whatever they
  // said out loud. A closed enum and not free text on purpose: the operator's prose would carry into the sealed
  // support pack, and it is exactly the field a checker would use to describe the data they are refusing to
  // touch. Absent on records rejected before this shipped, which is honest.
  rejectReason?: RestoreRejectReason;
}

// RESTORE_REJECT_REASONS -- the fixed picker the checker chooses from. Each maps to a different remedy,
// which is the point: wrong-target and too-broad tell the requester to raise a NARROWER request and it will go
// through; stale-plan tells them to re-plan against the current run; policy tells them not to bother.
export const RESTORE_REJECT_REASONS = [
  "wrong-target", // the plan writes to the wrong binding / namespace / bucket
  "too-broad", // the plan restores more than the incident calls for
  "stale-plan", // the plan is against an out-of-date run, or the state has moved under it
  "policy", // a change-control / governance rule forbids this restore now (a freeze, a window, an approval that must come from elsewhere)
  "other", // none of the above. Residual, never a message
] as const;
export type RestoreRejectReason = (typeof RESTORE_REJECT_REASONS)[number];
export const RESTORE_REJECT_REASON_SET: ReadonlySet<string> = new Set(RESTORE_REJECT_REASONS);

// APPROVAL_PREFIX is the DO storage key prefix; the key is `approval:${planHash}`. Kept here so
// the DO and any reader agree on the exact string.
export const APPROVAL_PREFIX = "approval:";

// approvalKey is the storage key for a record: `approval:sha384:...`. The planHash already carries
// its "sha384:" scheme prefix, so the key is unambiguous and stable.
export function approvalKey(planHash: string): string {
  return APPROVAL_PREFIX + planHash;
}

// APPROVAL_TTL_MS bounds a stale approval (and a stale request): 24 hours. A short TTL means an
// approval cannot be banked indefinitely against a future apply; past it the record reads as
// expired (lazily) and an apply is refused, forcing a fresh request + approval. Pinned with the
// engine workstream per the contract; 24h is the documented default.
export const APPROVAL_TTL_MS = 24 * 60 * 60 * 1000;

// RESTORE_APPLY_LEASE_MS bounds how long a reservation ("applying") may hold the approval before a crashed
// apply (the router's Worker died mid-write) is treated as abandoned and lazily reclaimed back to "approved"
// for a retry -- the applying-side counterpart of APPROVAL_TTL_MS (ASVS 2.1.6), mirroring the
// in-flight lease pattern already proven for scheduled runs (INFLIGHT_LEASE_MS, scheduler-do-scheduling.ts)
// and the canary (CANARY_LEASE_MS, scheduler-do-canary.ts). Set well beyond any single restore apply's real
// duration (a Workers invocation is wall-clock bounded to minutes) so a genuinely in-flight apply is never
// reclaimed out from under itself, while an abandoned reservation self-heals instead of wedging the approval
// permanently.
export const RESTORE_APPLY_LEASE_MS = 30 * 60 * 1000;

// RESTORE_APPLY_DEADLINE_MS is the whole distance from the instant a plan is DISCLOSED to the LAST instant at
// which an apply of an approval anchored to that plan may still be WRITING. It is the approval's own life
// plus the reservation lease an apply holds while it writes: the reserve happens while the record is still
// "approved" (so no later than expiresAt), and the writing continues under that reservation, which the DO
// treats as live for RESTORE_APPLY_LEASE_MS.
//
// It exists as ONE constant because a plan that predicts what an apply will do and a DO that decides how long
// an apply may run must not compute that distance separately. The lapsed-KV warning was wrong for exactly
// that reason twice over: it used APPROVAL_TTL_MS alone (so it did not cover the lease at all) and it
// measured from the PLAN while the DO measured from the REQUEST, and a "superset" that is derived twice is
// a superset by coincidence.
export const RESTORE_APPLY_DEADLINE_MS = APPROVAL_TTL_MS + RESTORE_APPLY_LEASE_MS;

// PLAN_SEEN_PREFIX is the DO storage prefix for the PLAN ANCHOR: `planseen:${planHash}` -> { at }, the
// instant a dry run for that plan hash was first shown to an operator since the last terminal approval
// event. It is what makes an approval unable to outlive the plan it was read from. See notePlanSeen.
export const PLAN_SEEN_PREFIX = "planseen:";

// approvalAnchorMs is the instant an approval's TTL starts from: the plan the operator read, when the engine
// recorded one, otherwise now.
//
// WHY IT IS NOT SIMPLY `now`. A dry run is read, and only then is an approval requested. Stamping the TTL at
// REQUEST time makes the last possible write instant `request + RESTORE_APPLY_DEADLINE_MS`, which is later
// than any horizon the plan could have computed from its own clock, by exactly the time the operator spent
// reading it. That gap is unbounded (a plan sits in a browser tab), and because a plan hash carries no
// timestamp the SAME displayed plan can be re-requested after each expiry, reopening it for ever. Anchoring
// the TTL to the plan closes both: an approval expires 24 hours after the PLAN, so a plan the engine can no
// longer vouch for mints an approval that is already expired and the operator must re-run the dry run,
// which is exactly the disclosure they need.
//
// The anchor is CLAMPED to now, never taken on trust: a caller-influenced value can only ever SHORTEN its own
// approval, never extend it past what the engine itself would have granted.
export function approvalAnchorMs(plannedAtMs: number | null | undefined, nowMs: number): number {
  return typeof plannedAtMs === "number" && Number.isFinite(plannedAtMs) ? Math.min(plannedAtMs, nowMs) : nowMs;
}

// restoreApplyDeadlineMs is the LAST instant an apply of an approval anchored to this plan can write. The
// plan's fidelity warnings are computed against exactly this instant, so what a plan warns about is a
// superset of what the sink can drop at every instant the approval permits, including the whole apply lease.
export function restoreApplyDeadlineMs(plannedAtMs: number | null | undefined, nowMs: number): number {
  return approvalAnchorMs(plannedAtMs, nowMs) + RESTORE_APPLY_DEADLINE_MS;
}

// PlanBinding is the canonical, redaction-safe object the planHash is computed over: the run, the
// target binding/namespace/bucket NAMES (never a value), and the selectors + record cap. It is the
// request's DECISION-RELEVANT fields only, so two requests that would restore the same data the
// same way hash equal, and any change to a decision field changes the hash (re-arm-on-change). It
// carries NO plaintext and NO key.
interface PlanBinding {
  runId: string;
  target: { binding?: string; namespaceId?: string; bucketName?: string } | null;
  include: string[];
  exclude: string[];
  maxRecords?: number;
  // recordName binds a GRANULAR single-record restore into the plan hash, so a single-record apply
  // carries its OWN distinct approval (a whole-run approval can never be reused to apply a single
  // record and vice-versa, and changing WHICH record re-arms the approval). Included only when set,
  // so a whole-run plan hashes exactly as it did before recordName existed (stable back-compat).
  recordName?: string;
  // destinationId binds WHICH archive copy the plan was reviewed against, so switching
  // destinations re-arms the approval like every other decision field: an apply whose destinationId
  // differs from (or omits) the request-time value can never reuse that approval. Without this, the
  // SAME approved planHash would authorise an apply reading a DIFFERENT destination than the one whose
  // freshness cues the approver actually reviewed. Included only when set, so a request that never names
  // one (the single-destination back-compat default) hashes exactly as it did before this field existed.
  destinationId?: string;
  // cfConfig binds a Cloudflare-config APPLY target (account + optional zone) into the plan hash so a
  // cf-config restore carries its OWN distinct approval (an approval for one account/zone can never be
  // reused for another). The TOKEN is deliberately EXCLUDED: a secret must never enter the hash or the
  // approval record; only the non-secret account/zone are bound. Included only when set, so a non-cf-config
  // plan hashes exactly as before.
  // the cf-config apply target AND the exact set of surfaces the apply may write. Binding only the
  // account and zone was a latent dual-control hole: an approver reviewing "re-apply Cloudflare config
  // into this account" approved whatever the engine's in-band set happened to be, so widening that set
  // silently widened what an ALREADY-GRANTED approval authorised, under an identical hash and with no
  // operator action. Harmless at 7 surfaces, serious at 60.
  //
  // `surfaces` is the RESOLVED, sorted, deduped list the apply will write: the caller's explicit
  // allow-list when supplied, otherwise every in-band surface in the registry. Binding the resolved set
  // rather than a pinned constant is what makes this self-maintaining: adding a writer changes the hash,
  // which re-arms every outstanding approval exactly as changing the destination or the selector does.
  cfConfig?: { accountId: string; zoneId?: string; surfaces: string[] };
  // mediaRestore binds a media RE-UPLOAD target (account) into the plan hash, so a media restore carries
  // its OWN distinct approval: a plain-restore approval can never be reused to authorise an in-account
  // media re-upload, and an approval for one account cannot be reused for another. The TOKEN is EXCLUDED
  // (a secret never enters the hash). Included only when set, so a non-media plan hashes exactly as before.
  mediaRestore?: { accountId: string };
  // d1Tables binds the D1 table-subset scope (database + the chosen table names) into the plan hash, so a
  // table-subset apply carries its OWN approval: an approval for "restore tables A,B of database X" can
  // never be reused to apply a different table set or a whole-database restore. The tables are lower-cased
  // (matching the case-INSENSITIVE resolution in resolveD1TableScope, so ["Users"] and ["users"] are one
  // selection), deduped and sorted (a set, order-free) so the same selection hashes identically however
  // the caller cased or ordered it. createOnly is bound too (it changes what the restore creates, so a
  // createOnly apply must not reuse a full-schema approval). Included only when set, so a non-table-subset
  // plan hashes as before.
  d1Tables?: { database: string; tables: string[]; createOnly?: boolean };
}

// restorePlanHash computes the binding hash an approval is keyed to, from a restore request ALONE
// (so the request route, the approve flow and the apply lookup all agree without re-running the
// dry-run). It reads only the request's decision-relevant fields, builds the canonical PlanBinding,
// and returns "sha384:" + hex(SHA-384(canonicalJSON(binding))), the same primitives the codebase
// uses for fingerprints. exactOptionalPropertyTypes: each optional key is included only when it
// carries a value, so an absent field and an explicit-undefined field hash identically and the key
// is stable.
// resolveCfConfigSurfaces returns the exact surface ids a cf-config apply is permitted to write, sorted
// and deduped so the hash is stable under caller ordering. An explicit allow-list NARROWS (intersected
// with the in-band set, so a caller cannot name an ordered/reprovision surface and have it honoured);
// an absent list means every in-band surface. Both paths resolve to a concrete list, so the approver's
// hash always covers the real write scope rather than a moving default.
//
// This is also the enforcement point's source of truth: restore-plan.ts filters the config plan through
// the same function, so the set that was approved and the set that is written cannot diverge.
export function resolveCfConfigSurfaces(explicit?: readonly string[]): string[] {
  const inBand = CF_CONFIG_SURFACES.filter((s) => typeof s.write === "function").map((s) => s.id);
  // The DEFAULT is the PROVEN set, not every surface that happens to carry a write(). Most writers are
  // generated from Cloudflare's schema, which fixes the path and the method but says nothing about the
  // natural key or which server-computed fields an update refuses. Those two decide whether a writer
  // corrupts data, so an unproven one must never run just because a restore did not name a scope.
  //
  // An explicit list can still reach an unproven writer: an operator who wants one names it, and the
  // resolved list is hashed into the approval, so an approver sees exactly which unproven surface
  // they are authorising. Complete catalogue, honest default.
  const allowed = explicit === undefined ? inBand.filter((id) => PROVEN_WRITE_SURFACES.has(id)) : inBand.filter((id) => explicit.includes(id));
  return [...new Set(allowed)].sort();
}

export async function restorePlanHash(req: RestoreRequest): Promise<string> {
  const binding: PlanBinding = {
    runId: req.runId,
    target: req.target
      ? {
          ...(req.target.binding !== undefined ? { binding: req.target.binding } : {}),
          ...(req.target.namespaceId !== undefined ? { namespaceId: req.target.namespaceId } : {}),
          ...(req.target.bucketName !== undefined ? { bucketName: req.target.bucketName } : {}),
        }
      : null,
    include: req.include ?? [],
    exclude: req.exclude ?? [],
    ...(req.maxRecords !== undefined ? { maxRecords: req.maxRecords } : {}),
    ...(req.recordName !== undefined ? { recordName: req.recordName } : {}),
    // destinationId binds WHICH archive copy the plan was reviewed against, so switching
    // destinations re-arms the approval like every other decision field.
    ...(req.destinationId !== undefined ? { destinationId: req.destinationId } : {}),
    // The cf-config apply target (account/zone) and the resolved surface allow-list are bound; the token
    // is NEVER hashed (it is a secret). See the PlanBinding.cfConfig comment for why the surface set is
    // in here.
    ...(req.cfConfig ? { cfConfig: { accountId: req.cfConfig.accountId, ...(req.cfConfig.zoneId !== undefined ? { zoneId: req.cfConfig.zoneId } : {}), surfaces: resolveCfConfigSurfaces(req.cfConfig.surfaces) } } : {}),
    // The media re-upload target (account) is bound; the token is NEVER hashed (it is a secret).
    ...(req.mediaRestore ? { mediaRestore: { accountId: req.mediaRestore.accountId } } : {}),
    // The D1 table-subset scope is bound (database + lower-cased, deduped, sorted table names), so a
    // table-subset apply carries its own approval, distinct from a whole-DB restore or a different table
    // selection. Lower-casing matches the case-insensitive resolution; the Array guard keeps a malformed
    // tables value (a non-array from the wire) from hashing over its characters (resolveD1TableScope
    // refuses it anyway, so the apply never proceeds -- this just keeps the bound value well-formed).
    ...(req.d1Tables && Array.isArray(req.d1Tables.tables)
      ? { d1Tables: { database: req.d1Tables.database, tables: [...new Set(req.d1Tables.tables.map((t) => String(t).toLowerCase()))].sort(), ...(req.d1Tables.createOnly === true ? { createOnly: true } : {}) } }
      : {}),
  };
  return `sha384:${hexEncode(await sha384(canonicalJSON(binding)))}`;
}

// effectiveStatus applies lazy expiry: a record whose expiresAt is in the past reads as "expired"
// unless it is already in a terminal-by-action state (rejected or consumed, which an expiry should
// not overwrite). A requested or approved record past its TTL reads as expired, mirroring the role
// table's lazy self-revoke, so a stale approval cannot authorise an apply without a sweep. The
// stored record is left as-is; only the reported value changes.
//
// An "applying" record additionally applies the RESERVATION lease (ASVS 2.1.6): still within
// RESTORE_APPLY_LEASE_MS of appliedAt it reads back as "applying" (so isUsableApproval, gated on
// "approved", refuses a second concurrent reserve for the same plan hash -- the actual TOCTOU fix);
// past the lease it reads back as "approved" (a crashed/killed apply that never reached releaseRestore/
// consumeApproval self-heals and its reservation is reclaimed for a retry, so a crash can never
// permanently strand the approval), the same lazy self-heal as the expiresAt check two lines above,
// never mutating storage.
// THE GARBLED APPROVAL. effectiveStatus reads a stored expiresAt with Date.parse and guards the expiry
// check on Number.isFinite -- so a record whose timestamp does NOT parse (a corrupted write, a half-flushed
// storage page, a hand-edited record) is never "expired". It stays usable, potentially for ever, and the
// single-use dual-control approval that authorises a destructive restore silently loses its TTL. The guard is
// right (a corrupt value must not fail the restore machine closed on a healthy approval); its SILENCE is the
// bug. This is the PURE predicate the DO reads at every load, so the anomaly is counted once per read of the
// bad record. It carries nothing: the corrupt timestamp text is exactly what must never be stored.
export function approvalTimestampUnparseable(record: RestoreApproval): boolean {
  return !Number.isFinite(Date.parse(record.expiresAt));
}

export function effectiveStatus(record: RestoreApproval, now: number): ApprovalStatus {
  if (record.status === "rejected" || record.status === "consumed") return record.status;
  const exp = Date.parse(record.expiresAt);
  if (Number.isFinite(exp) && exp <= now) return "expired";
  if (record.status === "applying") {
    const applied = record.appliedAt ? Date.parse(record.appliedAt) : NaN;
    if (!Number.isFinite(applied) || now - applied > RESTORE_APPLY_LEASE_MS) return "approved";
    return "applying";
  }
  return record.status;
}

// isUsableApproval is the apply-time gate over a found record: it is a valid approval for this plan
// iff its EFFECTIVE status is "approved" (not expired, not rejected, not consumed, not currently
// reserved "applying" for another in-flight apply, not still merely requested) AND a checker SUBJECT
// is recorded AND the checker subject differs from the requester
// subject (maker != checker, on the STABLE principals). The maker != checker is enforced at approve
// time too (the DO refuses a self-approval), so this is defence in depth: even a record that somehow
// carried approverSubject == requesterSubject would be rejected here. A null record (no approval at
// all) is never usable.
export function isUsableApproval(record: RestoreApproval | null, now: number): boolean {
  if (record === null) return false;
  if (effectiveStatus(record, now) !== "approved") return false;
  if (!record.approverSubject) return false;
  if (record.approverSubject === record.requesterSubject) return false; // maker != checker (by subject)
  return true;
}

// classifyRestoreApplyRefusal is isUsableApproval's bare `false`, un-collapsed. It is the EXACT
// inverse of the predicate above, in the same order, so a refusal can never be classified as something the
// gate did not actually refuse on.
//
// WHY. isUsableApproval returns one indistinguishable `false` for SEVEN different worlds, and the apply gate
// (gateRestore) recorded nothing at all before the router's flat 403 "restore not approved". So "our approved
// restore refuses to apply" -- an approval that EXPIRED in the minutes between approve and apply, one already
// CONSUMED by an earlier apply that actually worked, one whose apply is IN FLIGHT (the concurrent-apply loser,
// which reads to the operator as a flat no), and one that was never really approved -- all produced the SAME
// pack row: adminRefusals["restore-apply|not-approved"]. Four different remedies, one row, and governanceRefusals
// was EMPTY for every one of them while the pack's own legend advertised restore-apply|expired and
// restore-apply|applying-lease as the discriminators. Nothing could write them.
//
// The remedies are genuinely different, which is why the collapse matters:
//   no-such-request  nobody ever raised this plan (or the plan hash moved under the operator): request it
//   expired          the TTL lapsed between approve and apply: raise a fresh request, approve it again
//   consumed         an earlier apply ALREADY SUCCEEDED with this approval: the retry is the mistake
//   applying-lease   another apply holds the reservation RIGHT NOW: wait, do not raise anything
//   pending          it was never approved: the console badge is stale, go and get a second person
//   missing-approver / self-approval  the record is not a valid dual-control approval at all
//
// NO-CUSTODY: it reads the record's STRUCTURED status and subjects and returns a closed enum member. No
// subject, e-mail, plan hash or prose crosses the boundary.
export function classifyRestoreApplyRefusal(record: RestoreApproval | null, now: number): GovernanceRefusalReason {
  if (record === null) return "no-such-request";
  const status = effectiveStatus(record, now);
  if (status === "expired") return "expired";
  if (status === "consumed") return "consumed";
  if (status === "rejected") return "terminal-state";
  if (status === "applying") return "applying-lease";
  if (status === "requested") return "pending";
  // status === "approved" from here: the record IS approved and the maker/checker rule is what refused it.
  if (!record.approverSubject) return "missing-approver";
  if (record.approverSubject === record.requesterSubject) return "self-approval";
  return "terminal-state"; // unreachable while this mirrors isUsableApproval; never invent a cause, never widen the enum
}

// canApprove decides whether a caller may APPROVE a given record (the maker != checker rule and
// the state rule), returning a precise refusal reason or null to allow. The DO calls this inside
// its read-modify-write so the decision is atomic with the write. The role check (Approver/Owner)
// is the router's gate and is not repeated here; this is the dual-control-specific logic.
//  - a self-approval (caller SUBJECT == record.requesterSubject) is refused even if the caller holds
//    Approver/Owner; the comparison is on the STABLE subject, so a recycled email whose subject differs
//    is a legitimate distinct checker, and the same person in a different email case (same subject) is
//    still recognised as the maker (a self-approval, refused);
//  - A same-EMAIL self-approval is ALSO refused (belt-and-suspenders, on top of the subject check),
//    mirroring canApproveChange / canApproveOwnerAction. One human can legitimately hold two distinct,
//    IdP-bound subjects sharing one verified email (a passkey identity plus a native-IdP identity, or two
//    group-role-mapped SSO connections), so the subject check ALONE does not catch a request-as-A /
//    approve-as-B self-approval by that human; the email floor does;
//  - a caller with NO subject (the bare-token break-glass) cannot be a checker (the DO refuses it before
//    reaching here; this guards defensively too: a null callerSubject never matches a real requester);
//  - only a record whose effective status is "requested" can be approved (an already-approved,
//    rejected, consumed or expired record cannot be re-approved). A record reserved "applying" (an
//    apply is in flight for it) is refused too (ASVS 2.1.6): without this, re-approving it would
//    flip it straight back to "approved" mid-apply, letting a second reservation and a second, concurrent
//    apply run against the SAME approval -- reopening exactly the race the reserve-at-gate-time fix
//    closes, and trivially so, since restore-operator/approver/owner each hold both restore.apply and
//    restore.approve (one identity can fire the apply, then re-approve it themselves).
// G182: `reasonCode` is the CLOSED companion to `reason`. The prose is what the operator reads and it is
// deliberately NEVER persisted (it interpolates ids and, on other surfaces, e-mails); the code is what the
// support pack carries. Without it every refusal below collapsed into the single "guard-refused" fault class,
// so "my approved restore refuses to apply" could not tell an EXPIRED request from a SELF-approval from a
// CONCURRENT apply holding the reservation lease -- three different remedies, one indistinguishable row.
export function canApprove(record: RestoreApproval, approverEmail: string | null, approverSubject: string | null, now: number): GovernanceDecision {
  if (approverSubject !== null && approverSubject === record.requesterSubject) {
    return { ok: false, reason: "cannot approve your own request", reasonCode: "self-approval" };
  }
  // Email floor (belt-and-suspenders): refuse a same-display-email self-approval even when the
  // subjects differ, exactly as canApproveChange / canApproveOwnerAction do.
  if (approverEmail !== null && approverEmail === record.requestedBy) {
    return { ok: false, reason: "cannot approve your own request", reasonCode: "self-approval" };
  }
  const status = effectiveStatus(record, now);
  if (status === "expired") return { ok: false, reason: "the request has expired; raise a new one", reasonCode: "expired" };
  if (status === "rejected") return { ok: false, reason: "the request was rejected", reasonCode: "terminal-state" };
  if (status === "consumed") return { ok: false, reason: "the approval was already used", reasonCode: "consumed" };
  if (status === "approved") return { ok: false, reason: "the request is already approved", reasonCode: "terminal-state" };
  // ASVS 2.1.6: a record reserved for an in-flight apply must not be re-approved out from under
  // the reserver (that would overwrite the reservation back to "approved" mid-write and let a second
  // reserve race in).
  if (status === "applying") return { ok: false, reason: "the approval is currently being applied", reasonCode: "applying-lease" };
  return { ok: true };
}

// GovernanceDecision is the shared shape of every pure dual-control decision helper: the operator prose, and
// the closed reasonCode the DO records. Declared here (approvals.ts is the oldest of the three surfaces) and
// re-used by change-control.ts and owner-action.ts so the three cannot drift.
export type GovernanceDecision = { ok: true } | { ok: false; reason: string; reasonCode: GovernanceRefusalReason };

// ---- SPEND-TIME IDENTITY BINDING -------------------------------------------------------------------
// THE RESIDUE THIS CLOSES. An approval record is ARMED, SINGLE-USE authority to apply a destructive restore,
// and it is keyed by the PLAN, not by a person: approvalKey is a hash of the request's decision fields and
// nothing else. reserveRestore and consumeApproval took a plan hash and no caller argument at all, so at the
// moment the authority was actually spent nothing anywhere re-checked either of the two identities the
// dual-control claim rests on. The 24-hour TTL bounds it in TIME and says nothing about WHOM: what survived a
// person's removal was not their access (their sessions die) but their intended destructive act, still armed
// and still spendable by anyone holding restore.apply.
//
// EXPIRY IS THE WRONG REMEDY AND BINDING IS THE RIGHT ONE. Shortening the TTL strands the second approver
// mid-ceremony during the very incident the restore was raised for, which is the one person a dual-control
// approval must never be taken away from. Binding strands nobody whose authority is intact: it refuses exactly
// when one of the two identities no longer holds what they held when they acted.
//
// approvalIdentitiesStillAuthorised is the RULE, pure and shared, so the restore and prune machines cannot
// enforce it two different ways. The CAPABILITY SETS are resolved by the caller (the DO, which is the only
// thing that can read the live role table, the live group->role mapping and the live custom-role catalogue).
// This mirrors exactly what executeOwnerActionDO does at the owner-action spend, where the approved action runs
// AS THE PROPOSER re-resolved live from their immutable subject, so a proposer who lost owner between propose
// and approve cannot have their action executed.
//
// The MAKER is checked as well as the CHECKER, and both are load-bearing for different reasons. A lapsed
// CHECKER means the approval is no longer backed by a second authorised identity, which is the whole claim. A
// lapsed MAKER means the plan itself was chosen by somebody the account has since removed, which is precisely
// the residue: the removed person's intended act, not their access. The two refusals carry DIFFERENT closed
// reasons because they have different remedies (re-approve versus re-request), the same discrimination
// classifyRestoreApplyRefusal exists to provide.
//
// WHAT IT CANNOT SEE, stated rather than implied: a person removed from a directory GROUP at the customer's own
// IdP, with no engine-side change at all. The engine's copy of that person's groups is refreshed at a login
// that will never happen again, so the group they were in still reads as held. The mapping and the role table
// ARE re-read live, so deleting the mapping, deleting their grant, demoting them, letting a time-boxed grant
// lapse, or deleting the custom role they held all refuse. This is the same boundary the owner-action replay
// has, and it is bounded by the 24-hour TTL either way.
export type ApprovalSpendVerdict = { ok: true } | { ok: false; reasonCode: "maker-authority-lapsed" | "checker-authority-lapsed" };

export function approvalIdentitiesStillAuthorised(makerCapabilities: ReadonlySet<Capability>, checkerCapabilities: ReadonlySet<Capability>): ApprovalSpendVerdict {
  // The MAKER first, in the record's own order (requester, then approver), so a refusal can never be
  // classified as the axis that did not actually fail.
  if (!makerCapabilities.has("restore.request")) return { ok: false, reasonCode: "maker-authority-lapsed" };
  if (!checkerCapabilities.has("restore.approve")) return { ok: false, reasonCode: "checker-authority-lapsed" };
  return { ok: true };
}

// canReject mirrors canApprove for a rejection: only a still-open (effective "requested" or "approved")
// record can be rejected. A reject does NOT require maker != checker (the requester may withdraw their
// own request), but it must not overwrite a terminal state -- nor a live reservation (ASVS 2.1.6):
// rejecting a record that is currently "applying" would silently overwrite the in-flight reservation, so
// the apply's own eventual consume/release would land on the wrong stored status (orphaning the
// bookkeeping) and a fresh reserve could race in under it.
export function canReject(record: RestoreApproval, now: number): GovernanceDecision {
  const status = effectiveStatus(record, now);
  if (status === "rejected") return { ok: false, reason: "the request was already rejected", reasonCode: "terminal-state" };
  if (status === "consumed") return { ok: false, reason: "the approval was already used", reasonCode: "consumed" };
  if (status === "expired") return { ok: false, reason: "the request has expired", reasonCode: "expired" };
  if (status === "applying") return { ok: false, reason: "the approval is currently being applied", reasonCode: "applying-lease" };
  // requested or approved -> a reject is allowed (an Approver can revoke an approval they regret
  // before it is consumed).
  return { ok: true };
}

// viewStatus is the read-time projection for GET /restore/approvals: the record with its EFFECTIVE
// status substituted, so the inbox shows "expired" for a lapsed record without the DO mutating
// storage on a read. It is a pure copy; the stored record is untouched.
export function viewStatus(record: RestoreApproval, now: number): RestoreApproval {
  const status = effectiveStatus(record, now);
  return status === record.status ? record : { ...record, status };
}

// canRequesterSee decides whether a given caller may see a given approval in the inbox listing.
// Approver/Owner see the whole inbox (the role check is the router's); the requester also sees
// THEIR OWN requests even if they are only an Operator (so an Operator who raised a request can
// track it). This function encodes the "requester also sees their own" rule for the DO's listing,
// keyed on the STABLE subject (so it matches the maker != checker axis); the router passes whether
// the caller is Approver+. A caller with no subject (the token break-glass) sees only the Approver
// view (callerIsApprover); it never matches a requester subject.
export function canRequesterSee(record: RestoreApproval, callerSubject: string | null, callerIsApprover: boolean): boolean {
  if (callerIsApprover) return true;
  return callerSubject !== null && record.requesterSubject === callerSubject;
}
