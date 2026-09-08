// downpipe-precondition.ts -- the base check that stands in front of the downpipe upsert and delete.
//
// WHAT THIS CLOSES, in one sentence: `POST /admin/downpipes` was a whole-object upsert with no
// precondition of any kind, so two operators who loaded the same downpipe and saved a different edit to
// it were BOTH answered 200, one edit was discarded with nothing said, and a delete racing a save
// answered {"deleted":true} over a downpipe that was still there, still enabled and still on its cadence.
//
// THE DISTINCTION THIS FILE IS BUILT ON, and it is the reason the check does not live in the
// change-control gate. proposeConfigMutation (scheduler-do-change-control.ts) already owns a base check:
// baseMoved, which refuses an approved change whose config head has moved and answers "the configuration
// changed since this change was proposed; it is superseded, please raise it again". That check is
// reachable ONLY on the gate-ON path, and requireConfigApproval is FALSE by default, so the sentence was
// written, paid for, and unreachable for every account that had not turned change control on.
//
// Change control being optional is a real product decision and this file does not touch it. But LOSING AN
// EDIT SILENTLY IS NOT A FEATURE OF HAVING CHANGE CONTROL SWITCHED OFF, and those are two different
// things that rode on one flag:
//   - DETECTING that a configuration moved under an operator is HONESTY. It is unconditional here, on
//     every path, at every account, whatever requireConfigApproval reads.
//   - REQUIRING A SECOND PERSON to approve that the configuration move is GOVERNANCE. It stays exactly as
//     opt-in as it was.
// So the check below is enforced inside addDownpipe / removeDownpipe, which sit DOWNSTREAM of both
// branches of proposeConfigMutation (the gate-off inline apply, the gate-on dry run and the gate-on
// approve all reach them), and it never reads the approval flag.
//
// THE CHECK IS A DECISION, NOT A REFRESH. A read-then-write-anyway repair would take the window from the
// lifetime of an open screen down to one round trip and would STILL overwrite silently, which would still be
// a repair that only looks done. The read here decides: a moved record REFUSES and
// names the field that moved, so an operator who is told nothing happened is told the truth.

import type { DownpipeConfig, DownpipeState, LastConfigChange } from "./types.ts";

// Re-exported so a reader who arrives at the precondition logic finds the shape it decides on beside it.
// It is DEFINED in types.ts to keep that leaf's leaf-only import discipline intact (it names
// DownpipeState, so the type cannot live here and be named there).
export type { LastConfigChange } from "./types.ts";

// A downpipe's CONFIG revision. It is bumped by addDownpipe and by nothing else, which is what makes it
// usable as an operator-facing precondition: the run path rewrites dp:<id> constantly (heartbeats, run
// completions, restore-test stamps) through persistDownpipeState, and if the revision moved on those the
// operator's save would be refused because a BACKUP RAN, which is not a collision and would make the check
// hated and then switched off. A run carries the revision through untouched because it reads the stored
// state, mutates its run fields and persists the same object.
//
// It starts at 1 on create. ABSENT on a record written before this shipped, which reads as 0 (see
// currentConfigRev): a stale-page save against a pre-existing record therefore states a revision that
// cannot match 0 and is refused, which is the fail-closed direction.
export function currentConfigRev(state: DownpipeState | undefined | null): number {
  if (!state) return 0;
  const r = (state as { configRev?: unknown }).configRev;
  return typeof r === "number" && Number.isFinite(r) && r >= 0 ? r : 0;
}

export function nextConfigRev(prior: DownpipeState | undefined | null): number {
  return currentConfigRev(prior) + 1;
}

// The tombstone key. removeDownpipe writes one; addDownpipe reads it to refuse a RESURRECTION.
export const DOWNPIPE_TOMBSTONE_PREFIX = "dptomb:";
export function tombstoneKey(id: string): string {
  return `${DOWNPIPE_TOMBSTONE_PREFIX}${id}`;
}

export interface DownpipeTombstone {
  id: string;
  at: string;
  by: string | null;
  rev: number;
}

// Tombstones are pruned by removeDownpipe's own sweep once they are older than this. THIS IS NOT A RACE
// WINDOW AND MUST NOT BE READ AS ONE: the resurrection race is milliseconds wide, the precondition below
// closes it exactly and without any time bound at all, and the tombstone is the SECOND line that also
// closes it for a caller who states no precondition. The bound exists only so a lifetime of deletes does
// not accumulate keys in the Durable Object.
export const TOMBSTONE_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

// ---- What the caller stated -------------------------------------------------------------------------
//
// Three states, and the difference between the first two is the whole point of reading the key with `in`
// rather than reading its value: a body that OMITS ifMatchRev has stated nothing, and a body that sends
// ifMatchRev:null has stated something specific and falsifiable, namely "I believe this downpipe does not
// exist and I mean to create it".
export type StatedPrecondition =
  | { kind: "unstated" }
  | { kind: "expect-absent" }
  | { kind: "expect-rev"; rev: number };

export const IF_MATCH_REV_KEY = "ifMatchRev";

export function readPrecondition(params: unknown): StatedPrecondition {
  if (params === null || typeof params !== "object") return { kind: "unstated" };
  if (!(IF_MATCH_REV_KEY in (params as Record<string, unknown>))) return { kind: "unstated" };
  const v = (params as Record<string, unknown>)[IF_MATCH_REV_KEY];
  if (v === null) return { kind: "expect-absent" };
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) return { kind: "expect-rev", rev: v };
  // A stated-but-unreadable precondition is NOT treated as unstated. The caller tried to say something
  // and the engine could not read it, and a could-not-check outranks a pass: it refuses.
  return { kind: "expect-rev", rev: Number.NaN };
}

// ---- What actually moved ----------------------------------------------------------------------------
//
// The operator-meaningful config fields, compared structurally. This names what the WINNING write changed
// (recorded on the record at write time), which is what the losing operator needs, and never a value: a
// source spec can carry an accountId and a destination pin, and a refusal message is read by whoever
// holds the losing session, so field NAMES ride and values do not.
const COMPARED_FIELDS: Array<keyof DownpipeConfig> = [
  "name",
  "cadenceSeconds",
  "enabled",
  "source",
  "destinationId",
  "destinationIds",
  "restoreTestCadenceSeconds",
  "retention",
  "schedule",
];

export function movedConfigFields(prior: DownpipeConfig | undefined | null, next: DownpipeConfig): string[] {
  if (!prior) return [];
  const moved: string[] = [];
  for (const f of COMPARED_FIELDS) {
    const a = JSON.stringify(prior[f] ?? null);
    const b = JSON.stringify(next[f] ?? null);
    if (a !== b) moved.push(String(f));
  }
  return moved;
}

// A refusal reads as one clause, so a console can print it verbatim. Australian English, no value ever
// interpolated except the downpipe id, which is the customer's own label and is already in their request.
function namedFields(fields: string[]): string {
  if (fields.length === 0) return "";
  if (fields.length === 1) return ` (another operator changed ${fields[0]})`;
  return ` (another operator changed ${fields.slice(0, -1).join(", ")} and ${fields[fields.length - 1]})`;
}

// The closed refusal classes. A reason is a class, never a message: the message interpolates the
// customer's own downpipe id and is for a human, the reason is for a counter, a support pack and a test.
export const PRECONDITION_REFUSAL_REASONS = [
  "base-moved", // the record is there and its revision is not the one the caller read
  "deleted-under-you", // the caller read a record that another operator has since deleted
  "already-exists", // the caller declared a create and the record is there
  "resurrect-refused", // an unconditioned upsert would have recreated a downpipe another operator deleted
  "already-deleted", // a stated delete found nothing to delete
  "precondition-unreadable", // the caller stated a precondition the engine could not read, so it refused
] as const;
export type PreconditionRefusalReason = (typeof PRECONDITION_REFUSAL_REASONS)[number];

export const PRECONDITION_REFUSAL_CODE = "precondition-failed";

// PreconditionRefusal is modelled on OwnerFloorRefusal (admin/owner-floor.ts): a typed Error the DO's own
// fetch() catch recognises, so the refusal leaves the boundary as a 409 with a machine-readable class
// beside the sentence, rather than being flattened into the generic 400 every validation failure returns.
// 409 is the point: a client that retries a 400 is retrying a bad request, and a client that retries a 409
// is meant to RE-READ first, which is exactly what the operator must do.
export class PreconditionRefusal extends Error {
  readonly reason: PreconditionRefusalReason;
  readonly detail: PreconditionDetail;
  constructor(reason: PreconditionRefusalReason, message: string, detail: PreconditionDetail) {
    super(message);
    this.name = "PreconditionRefusal";
    this.reason = reason;
    this.detail = detail;
  }
}

// What the losing operator is told BESIDES the sentence. Revisions and field NAMES only: no value from
// either config rides, because the losing session may be held by an operator whose authority is narrower
// than the winner's.
export interface PreconditionDetail {
  id: string;
  yourRev: number | null;
  currentRev: number | null;
  changedFields: string[];
  changedAt: string | null;
}

export type PreconditionVerdict =
  | { ok: true }
  | { ok: false; reason: PreconditionRefusalReason; message: string; detail: PreconditionDetail };

// detailOf assembles the operator-facing facts from what is on the record, so every refusal below carries
// the same shape and a caller never has to guess which fields a given reason populates.
function detailOf(id: string, stated: StatedPrecondition, prior: DownpipeState | undefined | null): PreconditionDetail {
  const last = prior ? ((prior as { lastConfigChange?: LastConfigChange }).lastConfigChange ?? null) : null;
  return {
    id,
    yourRev: stated.kind === "expect-rev" && Number.isInteger(stated.rev) ? stated.rev : stated.kind === "expect-absent" ? null : null,
    currentRev: prior ? currentConfigRev(prior) : null,
    changedFields: last?.fields ?? [],
    changedAt: last?.at ?? null,
  };
}

// ---- The upsert check --------------------------------------------------------------------------------
export function checkUpsertPrecondition(args: {
  stated: StatedPrecondition;
  prior: DownpipeState | undefined | null;
  tombstone: DownpipeTombstone | undefined | null;
  guardResurrect: boolean;
  id: string;
}): PreconditionVerdict {
  const { stated, prior, tombstone, guardResurrect, id } = args;
  const lastFields = prior ? ((prior as { lastConfigChange?: LastConfigChange }).lastConfigChange?.fields ?? []) : [];

  if (stated.kind === "expect-rev") {
    if (!Number.isInteger(stated.rev)) {
      return {
        ok: false,
        reason: "precondition-unreadable",
        message: `ifMatchRev must be a whole number or null; the save for "${id}" was refused rather than applied without a base check`,
        detail: detailOf(id, stated, prior),
      };
    }
    if (!prior) {
      // The delete-versus-save collision, from the SAVE's side. The operator's screen still shows a
      // downpipe that another operator has removed, so the upsert would have RECREATED it and the deleting
      // operator's {"deleted":true} would have become false behind them.
      return {
        ok: false,
        reason: "deleted-under-you",
        message: `this downpipe was deleted since you loaded it; your edit to "${id}" was not saved and the downpipe was not recreated`,
        detail: detailOf(id, stated, prior),
      };
    }
    const live = currentConfigRev(prior);
    if (live !== stated.rev) {
      return {
        ok: false,
        reason: "base-moved",
        message: `this downpipe changed since you loaded it${namedFields(lastFields)}; your edit to "${id}" was not saved, please reload it and make the change again`,
        detail: detailOf(id, stated, prior),
      };
    }
    return { ok: true };
  }

  if (stated.kind === "expect-absent") {
    if (prior) {
      return {
        ok: false,
        reason: "already-exists",
        message: `a downpipe with id "${id}" already exists; it was not overwritten by a create`,
        detail: detailOf(id, stated, prior),
      };
    }
    return { ok: true };
  }

  // UNSTATED. This is where a caller who says nothing still cannot silently falsify somebody else's
  // delete. It is deliberately NOT a refusal of every unconditioned write (that would be the whole wire
  // contract and would break every API client at once for a defect that has an exact fix); it refuses the
  // one unconditioned write that can make a completed destructive operation a lie.
  if (guardResurrect && !prior && tombstone) {
    return {
      ok: false,
      reason: "resurrect-refused",
      message: `this downpipe was deleted since this request was formed; "${id}" was not recreated, send it again with ifMatchRev set to null if you mean to create it`,
      detail: { ...detailOf(id, stated, prior), changedAt: tombstone.at },
    };
  }
  return { ok: true };
}

// ---- The delete check --------------------------------------------------------------------------------
export function checkDeletePrecondition(args: {
  stated: StatedPrecondition;
  prior: DownpipeState | undefined | null;
  id: string;
}): PreconditionVerdict {
  const { stated, prior, id } = args;
  if (stated.kind === "unstated") return { ok: true };
  if (stated.kind === "expect-absent") {
    // Nonsensical on a delete, and it refuses rather than being quietly read as "unstated": a caller who
    // states a precondition the route cannot honour has not had it checked.
    return {
      ok: false,
      reason: "precondition-unreadable",
      message: `ifMatchRev must be the whole number this downpipe was read at; the delete of "${id}" was refused rather than applied without a base check`,
      detail: detailOf(id, stated, prior),
    };
  }
  if (!Number.isInteger(stated.rev)) {
    return {
      ok: false,
      reason: "precondition-unreadable",
      message: `ifMatchRev must be a whole number; the delete of "${id}" was refused rather than applied without a base check`,
      detail: detailOf(id, stated, prior),
    };
  }
  if (!prior) {
    return {
      ok: false,
      reason: "already-deleted",
      message: `this downpipe was already deleted; nothing named "${id}" was deleted by this request`,
      detail: detailOf(id, stated, prior),
    };
  }
  const lastFields = (prior as { lastConfigChange?: LastConfigChange }).lastConfigChange?.fields ?? [];
  const live = currentConfigRev(prior);
  if (live !== stated.rev) {
    return {
      ok: false,
      reason: "base-moved",
      message: `this downpipe changed since you loaded it${namedFields(lastFields)}; "${id}" was not deleted, please reload it and delete it again`,
      detail: detailOf(id, stated, prior),
    };
  }
  return { ok: true };
}
