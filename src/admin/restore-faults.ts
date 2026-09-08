// The RESTORE / DRILL / VERIFY fault projection + its CHECKED best-effort writer.
//
// THE GAP: the pack's restore evidence is OUTCOME-PLUS-COUNTS. A failed restore-apply keystone says HOW MANY
// records failed, never WHICH one, in WHICH phase, or in WHICH failure mode -- so "the restore failed" and
// "the restore silently wrote nothing" and "the archive is corrupt" arrive looking identical. Worse, the two
// most alarming cases leave NOTHING at all: an apply that THREW (the router's reservation-release finally
// runs and the throw propagates PAST the recordAudit below it, so no outcome row is ever written), and every
// dry-run refusal (an oversized in-account window, a reserved target binding, a plan that could not open).
//
// THE SHAPE: this module is the SEAM between the restore core (which stays a pure, stub-free computation)
// and the DO's bounded restoreFaults ring. The Worker edge already holds BOTH the scheduler stub and the
// finished RestorePlan / RestoreResult, so it projects the fault rows from the ALREADY-COMPUTED result: no
// restore behaviour changes, no DO stub is threaded into restore-apply.ts, and the classifier is the single
// place that ever looks at a reason string.
//
// NO-CUSTODY: every row is {closed op, closed phase, closed class, clamped record label, 8-hex errId, int
// count}. classifyRestoreFaultClass (admin/diag-records.ts) READS the engine's reason string ONLY to SELECT
// an enum member and returns THAT; applyRestoreFault in the DO re-validates every field and drops anything
// out of vocabulary. So a raw S3 <Code>, a Cloudflare API message, a SQLite error, a bucket, an endpoint or
// a token structurally cannot reach the record, from either side of the wire.

import { classifyRestoreFaultClass, RESTORE_FAULT_ROWS_PER_OP, type RestoreBindingName, type RestoreFaultClass, type RestoreFaultOp, type RestoreFaultPhase, type RestoreFaultRow } from "./diag-records.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { reportIntegrityFaults } from "./integrity-fault-report.ts";
import { RESERVED_REASON } from "./restore-sinks.ts";
import { doURL, recordAuthSignalEdge } from "./router-helpers.ts";

// The subset of the restore result shapes this projection reads. Deliberately STRUCTURAL (not the imported
// RestorePlan / RestoreResult / BlindRestoreTest / KeylessAttestationResult unions), so one projector covers
// all four shapes and a new result field can never silently widen what is recorded: this is the ONLY surface
// of a restore result the fault ring can see.
export interface RestoreOutcomeView {
  readonly ok: boolean;
  readonly reason?: string;
  readonly failures?: ReadonlyArray<{ name: string; reason: string }>;
  readonly skipped?: ReadonlyArray<{ name: string; reason: string }>;
  readonly outOfWindow?: number;
  // The downpipe the opened run belongs to. Every restore result already carries it once the run was opened
  // (a break-glass-only posture that never opened one does not), and it is the attribution key the FORMAT +
  // CRYPTO integrity evidence of this same restore is filed under.
  readonly downpipeId?: string;
}

// phaseOfClass maps a fault class to the phase of the restore it can only have come from. The phase is what
// answers "did my restore write anything?": a `verify` fault aborted with NOTHING written, a `write` fault
// wrote some records and not this one, a `readback` fault means the bytes WERE written and could not be
// proven. Total over the closed class set, so a new class must be given a phase here (the type enforces it).
const PHASE_OF_CLASS: Record<RestoreFaultClass, RestoreFaultPhase> = {
  integrity: "verify",
  freshness: "open",
  "object-missing": "open",
  "dest-access": "write",
  "recovery-check": "open",
  "origin-removed": "dest-fallback",
  "not-configured": "plan",
  "readback-failed": "readback",
  "readback-mismatch": "readback",
  "d1-partial": "write",
  "cf-config-write-failed": "cf-config",
  "media-upload-failed": "media",
  "media-readback-mismatch": "media",
  "binding-missing": "plan",
  "reserved-binding": "plan",
  "too-large": "plan",
  windowed: "plan",
  "scope-miss": "plan",
  "marker-skipped": "write",
  "apply-threw": "write",
  "apply-crashed-lease-reclaimed": "write",
  // G029: the break-glass-only refusal is a PLAN-phase honest refusal (nothing was opened, nothing written).
  "posture-unexercisable": "plan",
  // G069: a D1 decode refusal is an ARCHIVE-readability verdict reached before any write, so it is a `verify`
  // fault (nothing was written). A version-skew format hint is reached even earlier -- the record cannot be
  // opened by this engine at all -- so it is an `open` fault.
  "d1-decode-tamper": "verify",
  "d1-decode-corrupt": "verify",
  "d1-format-unknown": "open",
  other: "open",
  "readback-absent": "readback",
  "readback-bodyless": "readback",
  "over-single-put-limit": "plan",
  "d1-target-not-empty": "plan",
  "secret-sink-unwired": "plan",
};

// The per-record skip reasons that are NORMAL operation and must never be recorded as faults: a record the
// caller's own selector excluded is not a fault, and a secrets record is out of band BY DESIGN (Secrets Store
// bindings are read-only at runtime, so a secrets record is never a planned write).
function isBenignSkip(reason: string): boolean {
  return reason === "excluded by selector" || reason === "not the selected record" || reason.startsWith("secrets");
}

/**
 * restoreFaultRows projects a finished restore outcome into the bounded fault rows. PURE (no I/O, no clock):
 * the DO stamps `at`. It AGGREGATES by (phase, class) -- a 5,000-record failure yields ONE row per distinct
 * mode carrying an occurrence count and the FIRST record's label, not 5,000 rows -- and returns at most
 * RESTORE_FAULT_ROWS_PER_OP rows, so a pathological restore can never flood the ring or the subrequest budget.
 *
 * A CLEAN outcome yields no rows at all (the healthy steady state costs nothing).
 *
 * @param op - the closed operation (dry-run | apply | drill | blind-test | attest).
 * @param out - the finished outcome (structurally: ok + reason + failures + skipped + outOfWindow).
 * @returns the rows to record, newest-relevant first, capped.
 */
export function restoreFaultRows(op: RestoreFaultOp, out: RestoreOutcomeView): Array<Omit<RestoreFaultRow, "at">> {
  // key "<phase>:<class>" -> the aggregated row.
  const agg = new Map<string, { phase: RestoreFaultPhase; cls: RestoreFaultClass; recordName?: string; count: number }>();
  const bump = (reason: string, name?: string): void => {
    const cls = classifyRestoreFaultClass(reason);
    const phase = PHASE_OF_CLASS[cls];
    const key = `${phase}:${cls}`;
    const prev = agg.get(key);
    if (prev) {
      prev.count += 1;
      return;
    }
    agg.set(key, { phase, cls, ...(name !== undefined && name !== "" ? { recordName: name } : {}), count: 1 });
  };

  // The WHOLE-OP refusal (a dry-run that could not be planned, an apply that aborted, a drill/attest that
  // failed): it is the reason the operator sees, and today it persists nowhere for a dry-run at all.
  if (out.ok !== true && typeof out.reason === "string" && out.reason !== "") bump(out.reason);
  for (const f of out.failures ?? []) bump(f.reason, f.name);
  for (const s of out.skipped ?? []) {
    if (isBenignSkip(s.reason)) continue;
    bump(s.reason, s.name);
  }
  return [...agg.values()]
    .slice(0, RESTORE_FAULT_ROWS_PER_OP)
    .map(({ phase, cls, recordName, count }) => ({ op, phase, cls, ...(recordName !== undefined ? { recordName } : {}), ...(count > 1 ? { count } : {}) }));
}

/**
 * recordRestoreFaults writes the projected rows to the DO's bounded ring in ONE round trip, CHECKED: a
 * dropped write is counted in the droppedWrites aggregate (kind "restore-fault") rather than vanishing, so
 * a pack with an empty ring during a restore outage says so instead of implying a clean restore. It NEVER
 * throws and NEVER alters the caller's response (the restore result is already decided); a no-op when the
 * outcome was clean.
 *
 * @param scheduler - the scheduler DO stub.
 * @param rows - the projected rows (already bounded by restoreFaultRows).
 */
export async function recordRestoreFaults(scheduler: DurableObjectStub, rows: Array<Omit<RestoreFaultRow, "at">>): Promise<void> {
  if (rows.length === 0) return;
  await recordDiagWrite(scheduler, "restore-fault", () =>
    scheduler.fetch(doURL("/diag/restore-faults"), {
      method: "POST",
      body: JSON.stringify({ rows }),
      headers: { "content-type": "application/json" },
    }),
  );
}

/**
 * recordRestoreOutcome is the one-call form the router uses: project, then record. Best-effort and never
 * throwing.
 *
 * @param scheduler - the scheduler DO stub.
 * @param op - the closed operation.
 * @param out - the finished outcome.
 */
export async function recordRestoreOutcome(scheduler: DurableObjectStub, op: RestoreFaultOp, out: RestoreOutcomeView): Promise<void> {
  try {
    await recordRestoreFaults(scheduler, restoreFaultRows(op, out));
  } catch {
    /* best-effort: observing a restore fault must never break the restore path that hit it */
  }
  // THE CONFUSED-DEPUTY ATTEMPT. A restore that named one of the ENGINE'S OWN reserved bindings as a
  // write target -- an attempt to make the restore path overwrite the engine's keys, its config or its
  // scheduler state -- is refused at the sink chokepoint (restore-sinks.ts guardTarget) and short-circuits the
  // whole restore before any write. The refusal is correct and complete; it was also recorded NOWHERE, so
  // "did anyone probe reserved bindings via restore?" had no answer at all. The engine's own reason literal is
  // the discriminator (it is engine-set, never caller text), and the binding NAME never rides.
  try {
    if (out.reason === RESERVED_REASON) await recordAuthSignalEdge(scheduler, "reserved-binding-refused");
  } catch {
    /* best-effort */
  }
  // The FORMAT + CRYPTO evidence the pure verify core recorded WHILE this restore ran: which SPEC 8.3 stage
  // failed (a signer rotation vs a capsule unwrap vs a record hash: three different tickets that all read as
  // "integrity check failed"), which record/shard and by how much, which key role was mis-provisioned, and the
  // segment/chunk a streaming open aborted on. The drain is UNCONDITIONAL (reportIntegrityFaults drains before
  // it checks anything), so even a restore that could not open a run cannot leak its ledger into the next
  // operation this warm isolate serves.
  await reportIntegrityFaults(scheduler, out.downpipeId ?? "");
}

/**
 * recordRestoreFaultRow records ONE explicitly-classed row (the paths that have no result to project: an
 * apply that THREW, and a reclaimed apply lease). Best-effort and never throwing.
 *
 * @param scheduler - the scheduler DO stub.
 * @param row - the row (closed op / phase / class; optional 8-hex errId + clamped label + count).
 */
export async function recordRestoreFaultRow(scheduler: DurableObjectStub, row: Omit<RestoreFaultRow, "at">): Promise<void> {
  try {
    await recordRestoreFaults(scheduler, [row]);
  } catch {
    /* best-effort */
  }
}

// ---- the DRILL's own fault row -----------------------------------------------------------------------
//
// drillFaultRows is the drill's own projector, carrying the blast radius (failed record count), the failing
// index, the missing-object name and the missing binding, so a deploy that wiped SIGNER_PRIVATE reads
// differently from a corrupt archive, and the BREAK-GLASS-ONLY posture (an honest refusal, not a failure)
// files under its own class rather than a genuine one. It reuses the SAME bounded ring, the SAME closed vocabularies
// and the SAME DO-side chokepoint (applyRestoreFault re-validates every field), and adds only fields that
// vocabulary already accepts: `count` (failed records), `index` (the first failing one), `recordName` (the
// ENGINE-WRITTEN archive key, the incompleteIds redaction class) and `binding` (a closed member of
// RESTORE_BINDING_NAMES). A PASS projects nothing at all.

/** The subset of a DrillResult this projection reads. Structural, so it can never silently widen. */
export interface DrillOutcomeView {
  readonly ok: boolean;
  readonly reason?: string;
  readonly failedRecordCount?: number;
  readonly firstFailedIndex?: number;
  readonly missingObjectKey?: string;
  readonly missingBinding?: RestoreBindingName;
}

/**
 * drillFaultRows projects a finished drill into at most ONE bounded fault row. PURE (the DO stamps `at`).
 *
 * @param out - the finished drill result.
 * @returns the row, or [] for a passing drill.
 */
export function drillFaultRows(out: DrillOutcomeView): Array<Omit<RestoreFaultRow, "at">> {
  if (out.ok) return [];
  const cls = classifyRestoreFaultClass(out.reason);
  // The phase is the one the class can only have come from, EXCEPT that a per-record decrypt failure is a
  // `verify` fault (the drill decrypts and hash-checks; it never writes), so the ring never implies a write.
  const phase: RestoreFaultPhase = (out.failedRecordCount ?? 0) > 0 ? "verify" : PHASE_OF_CLASS[cls];
  const count = typeof out.failedRecordCount === "number" && out.failedRecordCount > 0 ? out.failedRecordCount : undefined;
  const index = typeof out.firstFailedIndex === "number" && out.firstFailedIndex >= 0 ? out.firstFailedIndex : undefined;
  return [
    {
      op: "drill",
      phase,
      cls,
      ...(out.missingObjectKey !== undefined ? { recordName: out.missingObjectKey } : {}),
      ...(count !== undefined ? { count } : {}),
      ...(index !== undefined ? { index } : {}),
      ...(out.missingBinding !== undefined ? { binding: out.missingBinding } : {}),
    },
  ];
}

/**
 * recordDrillOutcome is the one-call form both drill paths use (the manual POST /admin/drill and the scheduled
 * restore-test cron pass). Best-effort and never throwing: a drill's verdict is already decided.
 *
 * @param scheduler - the scheduler DO stub.
 * @param out - the finished drill result.
 */
export async function recordDrillOutcome(scheduler: DurableObjectStub, out: DrillOutcomeView): Promise<void> {
  try {
    await recordRestoreFaults(scheduler, drillFaultRows(out));
  } catch {
    /* best-effort */
  }
}
