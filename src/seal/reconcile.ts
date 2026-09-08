import type { KeylessAttestation } from "../format/keyless.ts";
import type { RootManifest } from "../format/manifest.ts";
import { decodeULID } from "../format/ulid.ts";

// ORPHAN RECONCILE - DRY-RUN INVENTORY (report-only). This is the uncommitted-run counterpart of
// seal/prune.ts (retention), but it ONLY INVENTORIES: it discovers the run-trees that are physically
// present in a destination but ABSENT from that bucket's signed RUNLOG (the orphaned-but-recoverable
// bytes a contended/throttled/crashed finalise leaves behind), classifies each, and reports a per-class
// count. It DELETES NOTHING and SALVAGES NOTHING.
//
// SCOPE (the tonight-buildable slice): Phase A-D of the
// classifier + per-class inventory + the mass-orphan CIRCUIT-BREAKER + a per-pass READ-BUDGET. The
// enforced GC (the segment-GC protected-set subtraction, Phase E/F) and the salvage path both RIDE the
// (a) sharded-RUNLOG keystone + the topology-aware committed accessor lockstep (R7) and are a multi-day
// project; they are deliberately NOT here. Because this module proposes NO deletion at all, it is
// dedup-safe BY CONSTRUCTION: there is no gcSegs/gcRunTrees set, so it can never even propose deleting a
// content-addressed segment that a committed (or another orphan) run shares. The set-difference GC that
// makes that safe (prune.ts computeOrphanSegs, with the WIDER protected set) is the enforce build's job.
//
// FAIL-CLOSED / COMPLETE-OR-ABSTAIN: every ambiguous case is bucketed conservatively and NOTHING is ever
// acted on. Two whole-pass abstains exist even for the report: an unverifiable RUNLOG signature (the one
// input that tells us what is committed) and the mass-orphan circuit-breaker (an implausibly high orphan
// fraction is the signature of a wrong-source / version-skew read of the committed set, R7). Both return
// an EMPTY classification with a deferred reason - the report-only analogue of "delete nothing".
//
// NO-CUSTODY: the inventory is KEYLESS (it uses attestKeyless, which needs only the operator-pinned
// PUBLIC verifier - no in-account read-back key), so it works in every posture including break-glass.
// It holds no customer key/secret and the inventory surface is ids + indices + counts only (the same
// redaction-safe surface the audit log and prune.ts already expose), never a key, value or plaintext.

/**
 * One physically-present run-tree's classification for the inventory. The five report-only verdicts
 * the dry-run pass actually produces are salvageable / stale / broken / within-grace / unreadable;
 * "deferred-no-key" is reserved for the enforce-GC build (where seg enumeration needs a key) and is
 * carried in the union for forward-compatibility but is never emitted by the report-only inventory.
 *
 *  - "salvageable": intact, root signature valid, complete, and newest-or-only for its downpipe (a
 *    perfectly good backup stranded outside the RUNLOG - the recoverable-but-invisible case).
 *  - "stale": intact + signed but a NEWER COMMITTED run of the same downpipe exists (GC-eligible later).
 *  - "broken": root signature invalid / absent, or the tree is incomplete (missing shards) - not a
 *    recoverable backup (GC-eligible later).
 *  - "within-grace": too young to touch this pass (its own ULID/createdAt time is inside the grace
 *    window) - it may be a finalise still in flight (a parked/sliced run).
 *  - "unreadable": a transient read failure this pass - abstain on this candidate, retry next tick.
 *  - "deferred-no-key": break-glass-only enforce posture cannot enumerate segs (enforce build only).
 */
export type OrphanClassification = "salvageable" | "stale" | "broken" | "within-grace" | "unreadable" | "deferred-no-key";

// The ordered set of classifications, so an empty by-class tally always carries every key (a missing
// key would make a Record<OrphanClassification, number> structurally incomplete).
export const ORPHAN_CLASSES: readonly OrphanClassification[] = ["salvageable", "stale", "broken", "within-grace", "unreadable", "deferred-no-key"];

/**
 * One orphan run-tree in the inventory. Redaction-safe: ids, an index and a millisecond timestamp are
 * the same surface prune.ts / the audit log already expose. It carries NO delete set (the report-only
 * contract) and NO plaintext/secret.
 */
export interface OrphanRun {
  readonly runId: string;
  // The run's downpipe id from the SIGNATURE-VERIFIED root when it verified, else from the keyless
  // attestation (also signature-anchored), else null when no trustworthy root could be read.
  readonly downpipeId: string | null;
  // root.freshness.runlogIndex when the root verified, else null. Used (against committedMaxIndex) to
  // tell salvageable (newest-or-only) from stale (a newer committed run exists).
  readonly index: number | null;
  // The run's own time: the signed root.createdAt when it verified, else the ULID timestamp decoded
  // from the runId (a broken/unverifiable orphan's only clock), else 0.
  readonly createdAtMs: number;
  // root.freshness.prevRunId when the root verified, else null. Carried for the FUTURE salvage build's
  // reader-binding pre-flight (§4.2); the report-only inventory does not act on it.
  readonly globalPrevRunId: string | null;
  readonly classification: OrphanClassification;
}

/**
 * The inventory for ONE destination bucket. Report-only: it has NO gcSegs / gcRunTrees / salvage set
 * (those ride the keystone), so by construction it never proposes deleting a (possibly shared,
 * content-addressed) segment. deferred, when set, means the WHOLE pass abstained (RUNLOG signature
 * unverifiable, or the circuit-breaker tripped) and byClass/orphans are empty.
 */
export interface ReconcileInventory {
  readonly destKey: string; // "" = the default destination
  readonly committedCount: number; // distinct runIds in this bucket's RUNLOG (the circuit-breaker denominator)
  readonly physicalRunCount: number; // distinct run/<runId>/ trees physically present
  readonly orphansFound: number; // physical-but-uncommitted run-trees seen this pass
  readonly byClass: Readonly<Record<OrphanClassification, number>>; // the per-class tally
  readonly orphans: readonly OrphanRun[]; // the per-orphan detail (redaction-safe)
  readonly pendingClassify: number; // orphans past grace not classified this pass (read-budget exhausted), retried next tick
  readonly circuitBreakerTripped: boolean; // true when the mass-orphan guard abstained the pass (R7)
  readonly deferred?: string; // present iff the whole pass abstained; byClass/orphans then empty
  // brokenSigInvalid / brokenAttestIncomplete SPLIT the "broken" verdict into the two causes the probe already
  // distinguishes but the single verdict folded away (gap G211): a root whose SIGNATURE did not verify (or that
  // could not be read as a trustworthy root at all) is a TAMPER/corruption signal, while a signed-but-INCOMPLETE
  // tree is a crashed finalise. Support could not tell them apart without bucket access. Counts only; optional so
  // a caller-built inventory (validators) stays valid without them.
  readonly brokenSigInvalid?: number;
  readonly brokenAttestIncomplete?: number;
}

/**
 * The reconcile policy knobs (all optional, all with safe defaults). The report-only pass has no
 * enforce/salvage gate - it never acts - so those knobs from the full design are intentionally absent
 * here; they belong to the enforce build.
 */
export interface ReconcilePolicy {
  readonly graceHours?: number; // default 48; MUST exceed the max finalise/park horizon so an in-flight run is never mistaken for an orphan
  readonly maxOrphanFraction?: number; // default 0.5; above this (orphans/physical) the pass abstains (the wrong-source-read guard, R7)
  readonly maxClassifyPerPass?: number; // default 32; bounds the per-pass attest READ load - the rest defer to pendingClassify (R9)
}

export const DEFAULT_GRACE_HOURS = 48;
export const DEFAULT_MAX_ORPHAN_FRACTION = 0.5;
export const DEFAULT_MAX_CLASSIFY_PER_PASS = 32;
const MS_PER_HOUR = 60 * 60 * 1000;
// ULID_TIME_BYTES is the 48-bit (6-byte) millisecond timestamp prefix of a 16-byte binary ULID (SPEC 11.6).
const ULID_TIME_BYTES = 6;

/**
 * Decodes the millisecond timestamp embedded in a runId's ULID (the first 48 bits), with NO I/O. This
 * is Phase C's cheap grace gate: a contended/abandoned run's own clock, available from the id string
 * alone, and the AUTHORITATIVE clock for a broken/unverifiable orphan that has no trustworthy
 * root.createdAt. Returns null for a non-ULID id (then the caller relies on the signed createdAt, or
 * keeps the orphan when neither clock is available - never deletes, since this is report-only anyway).
 */
export function ulidTimeMs(runId: string): number | null {
  let bytes: Uint8Array;
  try {
    bytes = decodeULID(runId);
  } catch {
    return null;
  }
  let ms = 0;
  for (let i = 0; i < ULID_TIME_BYTES; i++) ms = ms * 256 + bytes[i]!;
  return ms;
}

/**
 * The mass-orphan CIRCUIT-BREAKER (R7, the catastrophic-case guard). A correct steady state has FEW
 * orphans; an implausibly high orphan fraction - or an empty committed set while physical trees exist -
 * is the signature of a WRONG-SOURCE read of the committed set (a RUNLOG topology / version skew), where
 * LIVE COMMITTED runs masquerade as orphans. The complete-or-abstain rule does NOT catch this (it would
 * guard an UNREADABLE protected run, not a run ABSENT because we read the wrong source), so the breaker
 * does: above the threshold the whole pass abstains and the caller fires a loud, high-severity alert.
 * Pure (no I/O); exported so the validator can drive the truth-table without standing up a destination.
 */
export function circuitBreakerTripped(orphansFound: number, physicalRunCount: number, committedCount: number, maxOrphanFraction: number): boolean {
  // An implausible fraction of the physical trees are orphans: the wrong-source-read signature.
  if (physicalRunCount > 0 && orphansFound > maxOrphanFraction * physicalRunCount) return true;
  // The committed set is empty while physical trees exist: a finalised bucket whose committed source
  // read as empty is the same skew (every physical tree then looks like an orphan). Subsumed by the
  // fraction check when maxOrphanFraction < 1, kept explicit for clarity and for a mis-set fraction.
  if (committedCount === 0 && physicalRunCount > 0) return true;
  return false;
}

/**
 * The probe result for ONE orphan: the keyless attestation (signature + completeness, no key needed)
 * and the signature-verified root (present iff the attestation's signature verified, so its fields -
 * downpipeId / freshness / createdAt - are trustworthy). A probe THROWS on a TRANSIENT read failure so
 * the planner classifies that candidate "unreadable" (abstain, retry) rather than committing to a
 * verdict on bytes it could not read.
 */
export interface OrphanProbeResult {
  readonly attestation: Pick<KeylessAttestation, "signatureValid" | "complete" | "downpipeId">;
  readonly root: Pick<RootManifest, "downpipeId" | "createdAt" | "freshness"> | null;
}

/** Probes one orphan run-tree (Phase D). Injected so the pure planner and the IO are separable and the
 * validator can drive the classifier with in-memory doubles. MUST throw on a transient read failure. */
export type OrphanProbe = (runId: string) => Promise<OrphanProbeResult>;

/**
 * Classifies one orphan from its (already-resolved, non-transient) probe result. PURE; this is the
 * Phase D truth table. It keys ONLY on signatureValid / complete / index - NEVER on a freshness
 * not-rolled-back flag (an orphan is by definition absent from the RUNLOG, so any rollback flag is
 * trivially true for it and would mis-classify every orphan). The signed-createdAt grace double-check
 * lives here too (it catches a young run whose ULID clock the planner could not read).
 *
 *  - signature did not verify (root null/unverifiable) -> "broken".
 *  - signed but inside the grace window by its own createdAt -> "within-grace".
 *  - signed but incomplete (missing/short shards) -> "broken".
 *  - signed, complete, index < the downpipe's max COMMITTED index -> "stale" (a newer committed run exists).
 *  - signed, complete, newest-or-only for its downpipe -> "salvageable".
 */
export function classifyProbedOrphan(
  attestation: Pick<KeylessAttestation, "signatureValid" | "complete">,
  root: Pick<RootManifest, "downpipeId" | "createdAt" | "freshness"> | null,
  committedMaxIndex: ReadonlyMap<string, number>,
  now: number,
  graceMs: number,
): OrphanClassification {
  if (!attestation.signatureValid || root === null) return "broken";
  const createdAtMs = Date.parse(root.createdAt);
  if (Number.isFinite(createdAtMs) && now - createdAtMs < graceMs) return "within-grace";
  if (!attestation.complete) return "broken";
  // committedMaxIndex absent for this downpipe => no committed run of it exists, so the orphan is the
  // newest-or-only => salvageable (the NEGATIVE_INFINITY default makes "index < max" false).
  const maxCommitted = committedMaxIndex.get(root.downpipeId) ?? Number.NEGATIVE_INFINITY;
  if (root.freshness.runlogIndex < maxCommitted) return "stale";
  return "salvageable";
}

// emptyByClass builds a zeroed per-class tally that carries EVERY classification key, so the returned
// Record is structurally complete (a missing key would be a type hole).
function emptyByClass(): Record<OrphanClassification, number> {
  const out = {} as Record<OrphanClassification, number>;
  for (const c of ORPHAN_CLASSES) out[c] = 0;
  return out;
}

/** The inputs planReconcileInventory needs for ONE destination, all pre-resolved by the caller (the
 * cron does the I/O: the verified-RUNLOG-derived committed set, the listPage physical-tree
 * enumeration, and the keyless probe). Keeping the planner pure makes the truth-table + circuit-breaker
 * + read-budget validatable with in-memory doubles. */
export interface ReconcileInventoryInput {
  readonly destKey: string;
  // The committed set, derived from the VERIFIED RUNLOG (the caller MUST have checked the signature
  // first; an unverifiable RUNLOG is a whole-pass abstain the caller raises via deferredInventory).
  // This is the topology-aware "committedRunIds" accessor's result - the SINGLE place that knows the
  // RUNLOG topology, which under (a) sharded-RUNLOG must ship in lockstep with the topology change (R7).
  readonly committedRunIds: ReadonlySet<string>;
  readonly committedMaxIndex: ReadonlyMap<string, number>;
  readonly physicalRunIds: readonly string[];
  readonly now: number;
  readonly policy?: ReconcilePolicy;
  readonly probe: OrphanProbe;
}

/**
 * Builds the dry-run orphan inventory for ONE destination (Phase B-D). It computes orphanIds =
 * physical - committed, runs the circuit-breaker, then for each orphan applies the cheap ULID grace
 * gate, the per-pass read-budget, and (within budget) the keyless probe + classifier. It DELETES
 * NOTHING and SALVAGES NOTHING - there is no apply path in this module. Deterministic given its inputs
 * (idempotent: a re-run over the same bucket state yields an identical inventory).
 */
export async function planReconcileInventory(input: ReconcileInventoryInput): Promise<ReconcileInventory> {
  const { destKey, committedRunIds, committedMaxIndex, physicalRunIds, now, probe } = input;
  const policy = input.policy ?? {};
  const graceMs = (policy.graceHours ?? DEFAULT_GRACE_HOURS) * MS_PER_HOUR;
  const maxOrphanFraction = policy.maxOrphanFraction ?? DEFAULT_MAX_ORPHAN_FRACTION;
  let classifyBudget = policy.maxClassifyPerPass ?? DEFAULT_MAX_CLASSIFY_PER_PASS;

  const committedCount = committedRunIds.size;
  const physicalRunCount = physicalRunIds.length;
  const orphanIds = physicalRunIds.filter((id) => !committedRunIds.has(id));
  const orphansFound = orphanIds.length;

  // Phase A/B circuit-breaker: an implausible orphan fraction (or an empty committed source) abstains
  // the WHOLE pass - we will not even classify, let alone (in a future build) GC, on a probable
  // wrong-source read. The caller turns this into a high-severity alert.
  if (circuitBreakerTripped(orphansFound, physicalRunCount, committedCount, maxOrphanFraction)) {
    return {
      destKey,
      committedCount,
      physicalRunCount,
      orphansFound,
      byClass: emptyByClass(),
      orphans: [],
      pendingClassify: 0,
      circuitBreakerTripped: true,
      deferred: `circuit-breaker: ${orphansFound}/${physicalRunCount} physical trees are orphans (> ${maxOrphanFraction}) - probable wrong-source read of the committed set; abstaining`,
    };
  }

  const byClass = emptyByClass();
  const orphans: OrphanRun[] = [];
  let pendingClassify = 0;
  // The two causes behind a "broken" verdict (gap G211), counted at the classification site where the probe's
  // signatureValid / complete flags are still in hand: sigInvalid = the root did not verify (tamper/corruption),
  // attestIncomplete = it verified but the tree is short of shards (a crashed finalise). Counts only.
  let brokenSigInvalid = 0;
  let brokenAttestIncomplete = 0;

  for (const runId of orphanIds) {
    const ulidMs = ulidTimeMs(runId);
    // Phase C - the cheapest gate first: too young by its own ULID clock => within-grace, no probe (no
    // I/O, no read-budget spent). It may be a finalise still in flight (a parked/sliced run).
    if (ulidMs !== null && now - ulidMs < graceMs) {
      byClass["within-grace"]++;
      orphans.push({ runId, downpipeId: null, index: null, createdAtMs: ulidMs, globalPrevRunId: null, classification: "within-grace" });
      continue;
    }
    // Phase D read-budget (R9): bound the per-pass probe (attest) READ load; the rest defer to the
    // next tick. Only the (expensive) probe consumes budget - within-grace above did not.
    if (classifyBudget <= 0) {
      pendingClassify++;
      continue;
    }
    classifyBudget--;
    let result: OrphanProbeResult;
    try {
      result = await probe(runId);
    } catch {
      // A TRANSIENT read failure: abstain on THIS candidate (retry next tick), never commit to a verdict
      // on bytes we could not read.
      byClass.unreadable++;
      orphans.push({ runId, downpipeId: null, index: null, createdAtMs: ulidMs ?? 0, globalPrevRunId: null, classification: "unreadable" });
      continue;
    }
    const classification = classifyProbedOrphan(result.attestation, result.root, committedMaxIndex, now, graceMs);
    if (classification === "broken") {
      // The classifier's own precedence: an unverifiable/absent root is sigInvalid; otherwise the tree verified
      // but was incomplete. (A within-grace run never reaches "broken", so no third arm exists here.)
      if (!result.attestation.signatureValid || result.root === null) brokenSigInvalid++;
      else brokenAttestIncomplete++;
    }
    const root = result.root;
    const rootCreatedMs = root ? Date.parse(root.createdAt) : Number.NaN;
    const createdAtMs = Number.isFinite(rootCreatedMs) ? rootCreatedMs : (ulidMs ?? 0);
    byClass[classification]++;
    orphans.push({
      runId,
      downpipeId: root?.downpipeId ?? result.attestation.downpipeId ?? null,
      index: root?.freshness.runlogIndex ?? null,
      createdAtMs,
      globalPrevRunId: root?.freshness.prevRunId ?? null,
      classification,
    });
  }

  return { destKey, committedCount, physicalRunCount, orphansFound, byClass, orphans, pendingClassify, circuitBreakerTripped: false, brokenSigInvalid, brokenAttestIncomplete };
}

/** Builds a whole-pass ABSTAIN inventory for the non-circuit-breaker abstain (an unverifiable RUNLOG
 * signature): empty classification, deferred reason set, deletes nothing. The caller raises this when
 * the one input that tells us what is committed cannot be trusted. */
export function deferredInventory(destKey: string, reason: string): ReconcileInventory {
  return { destKey, committedCount: 0, physicalRunCount: 0, orphansFound: 0, byClass: emptyByClass(), orphans: [], pendingClassify: 0, circuitBreakerTripped: false, deferred: reason };
}

/** The high-level three-way summary the operator reads first: the committed runs, the
 * orphaned-but-RECOVERABLE backups (salvageable + stale: each has a valid
 * signed root, so it is restorable today, just invisible to the freshness path), and the NEVER-REFERENCED orphan trees
 * (broken: no valid signed root). within-grace / unreadable / deferred-no-key / pendingClassify are
 * UNDETERMINED this pass (re-evaluated next tick), reported separately rather than forced into a bucket. */
export interface InventorySummary {
  readonly committed: number;
  readonly orphanedRecoverable: number;
  readonly neverReferenced: number;
  readonly undetermined: number;
}

export function summariseInventory(inv: ReconcileInventory): InventorySummary {
  return {
    committed: inv.committedCount,
    orphanedRecoverable: inv.byClass.salvageable + inv.byClass.stale,
    neverReferenced: inv.byClass.broken,
    undetermined: inv.byClass["within-grace"] + inv.byClass.unreadable + inv.byClass["deferred-no-key"] + inv.pendingClassify,
  };
}

/**
 * A BOUNDED, redaction-safe per-destination summary of the orphan-reconcile dry-run AND the RUNLOG health
 * the pass reads, for the SUPPORT PACK (support-pack modes reconcile-orphans-invisible + reconcile-circuit-
 * breaker + the read-side of runlog-corrupt-parse / runlog-sig-stale-window). The reconcile pass is report-
 * only (deletes nothing) and today only LOGS its inventory, so a "recoverable-but-invisible orphan run" or a
 * corrupt destination RUNLOG never reached the bundle. This carries only the three-way summary counts, a
 * pair of RUNLOG-health booleans (present / signature-verified -- both ALREADY computed by the pass), the
 * circuit-breaker flag, and a coarse abstain class; never a runId / key / value / plaintext. destKey is the
 * customer's own console destination label ("" = the default bucket), the SAME surface the replication
 * heartbeats already expose in the pack.
 */
export interface ReconcileSignal {
  readonly destKey: string;
  readonly at: number; // epoch ms of the inventory pass
  readonly runlogPresent: boolean; // false = nothing has been finalised to this bucket
  readonly runlogSigVerified: boolean; // false + present = the corrupt/unverifiable-RUNLOG signal
  // runlogHealth (support-pack mode runlog-sig-stale-window) REFINES the two health booleans into a closed
  // diagnosis of WHY a present RUNLOG did not verify: "ok" (present + signature-verified), "stale-window"
  // (present + signature UNVERIFIED but the body still PARSES as a valid RUNLOG -- a body-vs-sig staleness
  // window, i.e. the read-after-write / lagging-detached-signature case, which heals), "corrupt" (present +
  // unverified AND the body does not parse -- the hard runlog-corrupt-parse case), or "absent" (no RUNLOG). It
  // separates a TRANSIENT stale window from a hard corruption that runlogSigVerified alone conflated.
  readonly runlogHealth: "ok" | "stale-window" | "corrupt" | "absent";
  readonly committed: number; // distinct committed runs in the RUNLOG
  readonly orphanedRecoverable: number; // salvageable + stale: recoverable bytes INVISIBLE to the freshness path
  readonly neverReferenced: number; // broken: no valid signed root
  readonly undetermined: number; // within-grace + unreadable + pending (re-evaluated next pass)
  // freshnessResiduals (support-pack mode freshness-rollback-residual): how many COMMITTED entries carry a
  // non-null prevRunId that DANGLES (points to a runId absent from this bucket's RUNLOG). Superseded runs are
  // KEPT in the RUNLOG (a removal is a rollback the reader rejects), so a non-null prevRunId should always
  // resolve; a dangling one is a per-downpipe freshness-chain residual (a rollback/rewrite left the chain
  // referencing an uncommitted run). Computed from the parsed entries alone (no extra reads); 0 on an abstain.
  readonly freshnessResiduals: number;
  readonly circuitBreakerTripped: boolean; // the mass-orphan wrong-source-read guard fired (R7)
  readonly deferred?: "circuit-breaker" | "runlog-unverifiable"; // set iff the whole pass abstained
  // ---- gap G211: the distinctions the DO inventory ALREADY makes, folded away by the three-way summary -----
  // undetermined splits into its three causes, so support can tell a READ-BUDGET deferral (pendingClassify: the
  // count never drains because every pass runs out of budget) from a hard per-object READ FAULT (unreadable) from
  // a run that is simply too YOUNG to judge (withinGrace, which drains on its own).
  readonly undeterminedWithinGrace?: number;
  readonly undeterminedUnreadable?: number;
  readonly undeterminedPendingClassify?: number;
  // neverReferenced (the "broken" class) splits into TAMPER (the root signature did not verify) vs a CRASHED
  // FINALISE (signed but incomplete attestation): the same count, two very different tickets.
  readonly neverReferencedSigInvalid?: number;
  readonly neverReferencedAttestIncomplete?: number;
  // On a CIRCUIT-BREAKER abstain the fraction that tripped the guard is the whole diagnosis (how far over the
  // threshold, and against what denominator). Carried as the raw numerator/denominator counts, never a ratio
  // string. Absent on a pass that did not trip the breaker.
  readonly orphanFractionNumerator?: number;
  readonly orphanFractionDenominator?: number;
}

// classifyRunlogHealth maps the two RUNLOG-health booleans + whether the body PARSES into the closed
// runlogHealth diagnosis (support-pack mode runlog-sig-stale-window). PURE. runlogBodyParses is only
// consulted on the present-but-unverified branch (it distinguishes a stale-window from a hard corrupt body).
export function classifyRunlogHealth(runlogPresent: boolean, runlogSigVerified: boolean, runlogBodyParses: boolean): "ok" | "stale-window" | "corrupt" | "absent" {
  if (!runlogPresent) return "absent";
  if (runlogSigVerified) return "ok";
  return runlogBodyParses ? "stale-window" : "corrupt";
}

// countFreshnessResiduals counts COMMITTED entries whose non-null prevRunId does NOT resolve to any runId
// present in the RUNLOG (a DANGLING per-downpipe freshness-chain link, support-pack mode
// freshness-rollback-residual). Because superseded runs are RETAINED in the RUNLOG, a non-null prevRunId
// should always resolve to a committed entry; a dangling one is the residual of a rollback/rewrite. PURE (no
// I/O): the caller passes the already-parsed entries the reconcile pass read. Redaction-safe (a count only).
export function countFreshnessResiduals(entries: readonly { runId: string; prevRunId?: string | null }[]): number {
  const present = new Set<string>();
  for (const e of entries) present.add(e.runId);
  let residuals = 0;
  for (const e of entries) {
    if (typeof e.prevRunId === "string" && e.prevRunId.length > 0 && !present.has(e.prevRunId)) residuals++;
  }
  return residuals;
}

/**
 * reconcileSignalFor maps ONE destination's reconcile pass result to the bounded pack signal. PURE (no I/O).
 * inv === null encodes a pass that could not inventory: pass runlogPresent=false for a bucket with no RUNLOG
 * (nothing committed), or runlogPresent=true + runlogSigVerified=false for an unverifiable RUNLOG (the
 * corrupt-RUNLOG signal); both zero the counts and, for the corrupt case, set deferred="runlog-unverifiable".
 * A non-null inv (RUNLOG present + verified) carries the three-way summary and the circuit-breaker abstain.
 */
// extra carries the read-side facts the reconcile pass computes from the RUNLOG bytes it already read but
// that are not in the ReconcileInventory: runlogBodyParses distinguishes a stale-window from a hard corrupt
// body on the sig-unverified abstain path (mode runlog-sig-stale-window), and freshnessResiduals is the
// dangling-prev-link count on the verified path (mode freshness-rollback-residual). Both default safe (a
// stale window is only claimed when the caller proved the body parses; residuals default to 0).
export function reconcileSignalFor(
  destKey: string,
  at: number,
  runlogPresent: boolean,
  runlogSigVerified: boolean,
  inv: ReconcileInventory | null,
  extra: { runlogBodyParses?: boolean; freshnessResiduals?: number } = {},
): ReconcileSignal {
  if (inv === null) {
    return {
      destKey,
      at,
      runlogPresent,
      runlogSigVerified,
      runlogHealth: classifyRunlogHealth(runlogPresent, runlogSigVerified, extra.runlogBodyParses === true),
      committed: 0,
      orphanedRecoverable: 0,
      neverReferenced: 0,
      undetermined: 0,
      freshnessResiduals: 0,
      circuitBreakerTripped: false,
      ...(runlogPresent && !runlogSigVerified ? { deferred: "runlog-unverifiable" as const } : {}),
    };
  }
  const s = summariseInventory(inv);
  return {
    destKey,
    at,
    runlogPresent: true,
    runlogSigVerified: true,
    runlogHealth: "ok",
    committed: s.committed,
    orphanedRecoverable: s.orphanedRecoverable,
    neverReferenced: s.neverReferenced,
    undetermined: s.undetermined,
    freshnessResiduals: typeof extra.freshnessResiduals === "number" && extra.freshnessResiduals >= 0 ? Math.floor(extra.freshnessResiduals) : 0,
    circuitBreakerTripped: inv.circuitBreakerTripped,
    // gap G211: carry the inventory's OWN distinctions instead of folding them into two totals. All counts.
    undeterminedWithinGrace: inv.byClass["within-grace"],
    undeterminedUnreadable: inv.byClass.unreadable,
    undeterminedPendingClassify: inv.pendingClassify,
    neverReferencedSigInvalid: inv.brokenSigInvalid ?? 0,
    neverReferencedAttestIncomplete: inv.brokenAttestIncomplete ?? 0,
    ...(inv.circuitBreakerTripped ? { deferred: "circuit-breaker" as const, orphanFractionNumerator: inv.orphansFound, orphanFractionDenominator: inv.physicalRunCount } : {}),
  };
}

// RECONCILE_DEFER_CLASSES is the closed abstain vocabulary the signal already used inline; named here so the
// sanitiser and any reader gate on ONE set.
export const RECONCILE_DEFER_CLASSES = ["circuit-breaker", "runlog-unverifiable"] as const;
const RECONCILE_DEFER_SET: ReadonlySet<string> = new Set(RECONCILE_DEFER_CLASSES);
const RECONCILE_INT_MAX = 1_000_000_000;
const RECONCILE_KEY_MAX = 128;

/**
 * sanitiseReconcileSignal validates + clamps ONE posted reconcile signal into a bounded, redaction-safe
 * ReconcileSignal. It is the SINGLE redaction chokepoint for this signal (the seal-fault ring's sanitiseSealFault
 * is its twin): every count is a clamped non-negative int, every flag a strict boolean, the health and abstain
 * values are closed enums, and destKey (the customer's own console destination label, "" = the default bucket) is
 * length-bounded. Nothing else can survive, so a raw message or key can never enter the DO state or the pack.
 * PURE, so the DO record path, the pack projection and the validator share one definition and cannot drift.
 */
export function sanitiseReconcileSignal(body: Record<string, unknown>, now: number): ReconcileSignal {
  const int = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), RECONCILE_INT_MAX) : 0);
  const destKey = typeof body.destKey === "string" ? body.destKey.slice(0, RECONCILE_KEY_MAX) : "";
  const runlogPresent = body.runlogPresent === true;
  const runlogSigVerified = body.runlogSigVerified === true;
  const runlogHealth =
    body.runlogHealth === "ok" || body.runlogHealth === "stale-window" || body.runlogHealth === "corrupt" || body.runlogHealth === "absent"
      ? body.runlogHealth
      : classifyRunlogHealth(runlogPresent, runlogSigVerified, false);
  const deferred = typeof body.deferred === "string" && RECONCILE_DEFER_SET.has(body.deferred) ? (body.deferred as "circuit-breaker" | "runlog-unverifiable") : undefined;
  return {
    destKey,
    at: typeof body.at === "number" && Number.isFinite(body.at) ? body.at : now,
    runlogPresent,
    runlogSigVerified,
    runlogHealth,
    committed: int(body.committed),
    orphanedRecoverable: int(body.orphanedRecoverable),
    neverReferenced: int(body.neverReferenced),
    undetermined: int(body.undetermined),
    freshnessResiduals: int(body.freshnessResiduals),
    circuitBreakerTripped: body.circuitBreakerTripped === true,
    ...(body.undeterminedWithinGrace !== undefined ? { undeterminedWithinGrace: int(body.undeterminedWithinGrace) } : {}),
    ...(body.undeterminedUnreadable !== undefined ? { undeterminedUnreadable: int(body.undeterminedUnreadable) } : {}),
    ...(body.undeterminedPendingClassify !== undefined ? { undeterminedPendingClassify: int(body.undeterminedPendingClassify) } : {}),
    ...(body.neverReferencedSigInvalid !== undefined ? { neverReferencedSigInvalid: int(body.neverReferencedSigInvalid) } : {}),
    ...(body.neverReferencedAttestIncomplete !== undefined ? { neverReferencedAttestIncomplete: int(body.neverReferencedAttestIncomplete) } : {}),
    ...(body.orphanFractionNumerator !== undefined ? { orphanFractionNumerator: int(body.orphanFractionNumerator) } : {}),
    ...(body.orphanFractionDenominator !== undefined ? { orphanFractionDenominator: int(body.orphanFractionDenominator) } : {}),
    ...(deferred !== undefined ? { deferred } : {}),
  };
}
