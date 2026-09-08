// Support-pack section gatherers: the seal / WORM / replication / canary domain (the
// per-destination replication heartbeats, the orphan-reconcile inventory + RUNLOG health,
// the seal-fault OBSERVE ring, the resolved seal/verify-at-seal/scale knobs, the canary
// liveness + transition ring, and the live WORM / Object-Lock posture probe). Moved
// verbatim out of support.ts, which assembles the bundle from these gatherers; each keeps
// its original redaction contract (see the per-function comments). Behaviour is unchanged.

import { RETENTION_DEFERRAL_CLASSES, RETENTION_ERROR_CLASSES, RETENTION_OUTCOMES, RETENTION_SKIP_CODES } from "../cron/retention-record.ts";
import { buildDestination, fetchDestConfig, parseWormPolicy, type RuntimeDestConfig } from "../dest/factory.ts";
import { WORM_UNKNOWN_REASONS } from "../dest/types.ts";
import type { Env } from "../env.d.ts";
import { resolveScaleKnobs, resolveSliceKnobs } from "../seal/budget.ts";
import { CHECKPOINT_FIELDS, CHECKPOINT_UNWRAP_CODES } from "../seal/checkpoint-fault.ts";
import { CONFIG_FAULT_CODES } from "../seal/config-fault.ts";
import { sealKnobSources } from "../seal/knob-sources.ts";
import { RECONCILE_DEFER_CLASSES } from "../seal/reconcile.ts";
import { SEAL_ATTEMPT_CLASSES } from "../seal/run-pressure.ts";
import {
  ALERT_EVENT_CLASSES,
  FANOUT_DISCARD_CLASSES,
  FANOUT_DOWNGRADE_REASONS,
  PRUNE_DEFER_CLASSES,
  REPLICA_FAULT_REASONS,
  REPLICATION_PASS_OUTCOMES,
  SEAL_FAULT_DROP_CLASSES,
  SEAL_FAULT_KINDS,
  SEAL_MODES,
  SKIP_CAUSES,
  STRAND_CLASSES,
  VERIFY_MODES,
  WORM_REFUSAL_CLASSES,
} from "../seal/seal-faults.ts";
import { resolveSealVerifyKnobs } from "../seal/verify-at-seal.ts";
import { loadConfigWrapKey } from "./config-secret.ts";
import { doURL } from "../do-url.ts";
import { clampInt, clampTs } from "./support-shared.ts";

// fetchReplication pulls the per-downpipe per-destination replication heartbeats (`repl:` DestReplState) so
// the pack can answer WHICH destination is failing. This revives a dead signal: a FAILED run records the
// down destination(s) into this `repl:` state (lastOk:false + a coarse "unreachable"-class reason), NOT onto
// the run-history row, so a pack that only read the run rows could never see which destination was down (a
// single/default-destination outage left no failed-run attribution at all). Returns a downpipe-id → array of
// per-destination heartbeats map. Every field is redaction-safe: the destination id is the customer's own
// console label, lastOk/at/holdsIndex are a bool/timestamp/count, the reason is a coarse secret-free class,
// and holdsRunId is an opaque run id.
//
// IT RETURNS NULL WHEN THE READ ITSELF FAULTED, and that is not fussiness. A fault must not be conflated
// with an empty map: the projector reads an empty map as "no destination has ever replicated", so an
// unreadable heartbeat store must never make the pack assert, of every configured destination on every
// downpipe, that it holds no copy of any backup. Null is the honest "I could not read this", and the
// projector suppresses the never-reported claim on it rather than making one up.
//
// A FAULT IS NOT ONLY A THROW, AND THAT IS THE WHOLE OF THE r.ok CHECK. SchedulerDO.fetch CATCHES the DO's
// own faults and NORMALLY RESOLVES a JSON error body: a plain Error out of replication() (the `repl:`
// storage.list -- a DO storage timeout or overload, exactly the transient blip this null exists for)
// becomes HTTP 400 {"error":"..."}, and a TypeError becomes HTTP 500 {"error":"internal error"}. Both
// bodies PARSE, so `r.ok` must be checked explicitly rather than relying on json() to throw.
type DestReplHeartbeat = { holdsRunId?: string | null; holdsIndex?: number; lastOk?: boolean; lastAttemptAt?: number; reason?: string };
export async function fetchReplication(scheduler: DurableObjectStub): Promise<Record<string, Array<Record<string, unknown>>> | null> {
  try {
    const r = await scheduler.fetch(doURL("/replication"), { method: "GET" });
    if (!r.ok) return null;
    const j = (await r.json()) as { byDownpipe?: Record<string, Record<string, DestReplHeartbeat>> };
    const out: Record<string, Array<Record<string, unknown>>> = {};
    for (const [dpId, dests] of Object.entries(j.byDownpipe ?? {})) {
      const rows = Object.entries(dests ?? {}).map(([destId, s]) => ({
        id: destId,
        ok: s.lastOk === true,
        ...(typeof s.lastAttemptAt === "number" ? { at: s.lastAttemptAt } : {}),
        ...(typeof s.holdsIndex === "number" ? { holdsIndex: s.holdsIndex } : {}),
        ...(typeof s.holdsRunId === "string" ? { holdsRunId: s.holdsRunId } : {}),
        ...(s.lastOk !== true && typeof s.reason === "string" ? { reason: s.reason } : {}),
      }));
      if (rows.length > 0) out[dpId] = rows;
    }
    return out;
  } catch {
    return null;
  }
}

// fetchReconcileInventory pulls the bounded orphan-reconcile + RUNLOG-health signal (support-pack modes
// reconcile-orphans-invisible / reconcile-circuit-breaker / runlog-corrupt-parse) the cron's REPORT-ONLY
// reconcile pass persists per destination. It answers "are there recoverable-but-invisible orphan runs, or
// a corrupt / unverifiable destination RUNLOG" -- the reconcile pass previously only LOGGED this, so it was
// absent from every bundle. Redaction-safe by construction: per-destination counts + two RUNLOG-health
// booleans + a coarse abstain class + the customer's own destination label (the same surface the
// replication heartbeats already expose); never a runId/key/value/plaintext. Every field is re-clamped
// defensively. Best-effort: [] on failure, or when the (opt-in, ORPHAN_RECONCILE-gated) pass has never run.
const RECONCILE_DEFER_CLASS_SET: ReadonlySet<string> = new Set(RECONCILE_DEFER_CLASSES);
export async function fetchReconcileInventory(scheduler: DurableObjectStub): Promise<unknown[]> {
  {
    const r = await scheduler.fetch(doURL("/reconcile-inventory"), { method: "GET" });
    const j = (await r.json()) as { byDest?: Array<Record<string, unknown>> };
    const rows = Array.isArray(j.byDest) ? j.byDest : [];
    const intOr0 = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), 1_000_000_000) : 0);
    // intOpt projects an OPTIONAL count: absent when the DO row does not carry it (a legacy signal persisted
    // before the G211 split existed), so a missing field is never fabricated as a 0 the bot would read as
    // "measured zero". canonicalJSON rejects an explicit undefined, hence the conditional spread at each site.
    const intOpt = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), 1_000_000_000) : undefined);
    return rows.slice(0, 32).map((s) => ({
      destKey: typeof s.destKey === "string" ? s.destKey.slice(0, 128) : "",
      ...(typeof s.at === "number" && Number.isFinite(s.at) ? { at: s.at } : {}),
      runlogPresent: s.runlogPresent === true,
      runlogSigVerified: s.runlogSigVerified === true,
      // runlogHealth (mode runlog-sig-stale-window): the closed WHY-it-did-not-verify diagnosis (ok /
      // stale-window / corrupt / absent), gated on the closed vocabulary (defence-in-depth); omitted on a
      // legacy signal persisted before this field existed.
      ...(s.runlogHealth === "ok" || s.runlogHealth === "stale-window" || s.runlogHealth === "corrupt" || s.runlogHealth === "absent" ? { runlogHealth: s.runlogHealth } : {}),
      committed: intOr0(s.committed),
      orphanedRecoverable: intOr0(s.orphanedRecoverable),
      neverReferenced: intOr0(s.neverReferenced),
      undetermined: intOr0(s.undetermined),
      // freshnessResiduals (mode freshness-rollback-residual): dangling per-downpipe prev-links in the committed
      // chain (a rollback/rewrite residual). A non-negative int; 0 when the chain is intact.
      freshnessResiduals: intOr0(s.freshnessResiduals),
      circuitBreakerTripped: s.circuitBreakerTripped === true,
      ...(typeof s.deferred === "string" && RECONCILE_DEFER_CLASS_SET.has(s.deferred) ? { deferred: s.deferred } : {}),
      // ---- G211: the distinctions the DO inventory ALREADY made, which the three-way summary folded away ----
      // `undetermined` conflated three very different tickets. Split: withinGrace is a run simply too YOUNG to
      // judge (it drains on its own, benign); unreadable is a HARD per-object read fault; pendingClassify is a
      // READ-BUDGET deferral -- the count that never drains because every pass runs out of budget, which is the
      // one that silently never resolves. Each optional (absent on a legacy signal), each a clamped count.
      ...((v) => (v !== undefined ? { undeterminedWithinGrace: v } : {}))(intOpt(s.undeterminedWithinGrace)),
      ...((v) => (v !== undefined ? { undeterminedUnreadable: v } : {}))(intOpt(s.undeterminedUnreadable)),
      ...((v) => (v !== undefined ? { undeterminedPendingClassify: v } : {}))(intOpt(s.undeterminedPendingClassify)),
      // `neverReferenced` (the "broken" class) conflated TAMPER (the root signature did not verify) with a
      // CRASHED FINALISE (signed but an incomplete attestation). Same count, opposite tickets.
      ...((v) => (v !== undefined ? { neverReferencedSigInvalid: v } : {}))(intOpt(s.neverReferencedSigInvalid)),
      ...((v) => (v !== undefined ? { neverReferencedAttestIncomplete: v } : {}))(intOpt(s.neverReferencedAttestIncomplete)),
      // On a CIRCUIT-BREAKER abstain the fraction that tripped the guard IS the diagnosis (how far over the
      // threshold, against what denominator). Carried as the two raw counts, never as a ratio sentence.
      ...((v) => (v !== undefined ? { orphanFractionNumerator: v } : {}))(intOpt(s.orphanFractionNumerator)),
      ...((v) => (v !== undefined ? { orphanFractionDenominator: v } : {}))(intOpt(s.orphanFractionDenominator)),
    }));
  }
}

// fetchSealFaults pulls the bounded seal-fault OBSERVE ring (support-pack seal-integrity modes
// shard-list-truncated / shard-truncation-stalekeys / lease-lost-abandon / orphan-root-worm-leak /
// signer-rotation-strands-runs) the per-downpipe seal DO posts at each fault's detection point. It answers a
// class of otherwise-invisible seal-lifecycle faults: a finalise that refused to sign a TRUNCATED archive
// (found X of Y shards), an abandoned prior run's stale shard rows cleaned at a fresh /start, a resuming run
// that lost its lease and abandoned, an orphan run-tree the contention give-up path reclaimed (or a WORM
// destination refused to reclaim), and a checkpoint that could not be unwrapped under the current signer (a
// signer-rotation strand). The seal DO previously only LOGGED these, so they were absent from every bundle.
// Redaction-safe by construction: a CLOSED kind + the customer's own downpipe/run ids (the same surface the
// reconcile inventory + replication heartbeats already expose) + non-negative ints / a boolean; never a
// key/value/plaintext. Every field is re-clamped defensively, the kind re-gated on the closed vocabulary
// (defence-in-depth), and the list capped. Best-effort: [] on failure, or when no seal-fault has been seen.
const SEAL_FAULT_KIND_SET: ReadonlySet<string> = new Set(SEAL_FAULT_KINDS);
// PRUNE_DEFER_CLASS_SET re-gates the retention abstain class at the PACK boundary (defence in depth: the DO's
// sanitiser already coarsens it, but a drifted/legacy row must never push free text into the bundle).
const PRUNE_DEFER_CLASS_SET: ReadonlySet<string> = new Set(PRUNE_DEFER_CLASSES);
// FANOUT_DISCARD_CLASS_SET / SEAL_FAULT_DROP_CLASS_SET re-gate the two NEW closed classes at the pack boundary
// (G062 / G326): WHY a fan-out worker's report was discarded by the coordinator, and WHY a seal-fault OBSERVE
// never landed in the ring at all (the scheduler-DO was unreachable, or the posted kind had drifted out of the
// vocabulary). Without the second one the ring's own ingestion losses were invisible: the pack under-reported
// during the very outage it should explain, and read byte-identically to a healthy fleet.
const FANOUT_DISCARD_CLASS_SET: ReadonlySet<string> = new Set(FANOUT_DISCARD_CLASSES);
const SEAL_FAULT_DROP_CLASS_SET: ReadonlySet<string> = new Set(SEAL_FAULT_DROP_CLASSES);
// The round-4 seal-fault vocabularies, re-gated at the pack boundary (defence in depth).
const CONFIG_FAULT_CODE_SET: ReadonlySet<string> = new Set(CONFIG_FAULT_CODES);
const REPLICA_FAULT_REASON_SET: ReadonlySet<string> = new Set(REPLICA_FAULT_REASONS);
const REPLICATION_PASS_OUTCOME_SET: ReadonlySet<string> = new Set(REPLICATION_PASS_OUTCOMES);
const SKIP_CAUSE_SET: ReadonlySet<string> = new Set(SKIP_CAUSES);
const STRAND_CLASS_SET: ReadonlySet<string> = new Set(STRAND_CLASSES);
const WORM_REFUSAL_CLASS_SET: ReadonlySet<string> = new Set(WORM_REFUSAL_CLASSES);
const VERIFY_MODE_SET: ReadonlySet<string> = new Set(VERIFY_MODES);
const SEAL_MODE_SET: ReadonlySet<string> = new Set(SEAL_MODES);
const FANOUT_DOWNGRADE_REASON_SET: ReadonlySet<string> = new Set(FANOUT_DOWNGRADE_REASONS);
const ALERT_EVENT_CLASS_SET: ReadonlySet<string> = new Set(ALERT_EVENT_CLASSES);
// The three SHAPE gates on the only non-enum, non-integer fields a seal-fault row may carry. Each is an
// ENGINE-MINTED token, never a customer value: the config-fault binding NAME (an operator label on the bare
// identifier charset), the one-way `h:<12 hex>` record handle (a RAW object key fails this and is dropped),
// and the 8-16 hex cause digest that lets two recurring reader faults be correlated WITHOUT their text.
const BINDING_NAME_SHAPE = /^[A-Za-z0-9_]{1,64}$/;
const RECORD_HANDLE_SHAPE = /^h:[0-9a-f]{12}$/;
const CAUSE_DIGEST_SHAPE = /^[0-9a-f]{8,16}$/;
// The ROUND-5 closed sets, re-gated at the PACK boundary as well as at the ring's sanitiser (defence in depth).
const SEAL_ATTEMPT_CLASS_SET: ReadonlySet<string> = new Set(SEAL_ATTEMPT_CLASSES);
const CHECKPOINT_FIELD_SET: ReadonlySet<string> = new Set(CHECKPOINT_FIELDS);
const CHECKPOINT_UNWRAP_CODE_SET: ReadonlySet<string> = new Set(CHECKPOINT_UNWRAP_CODES);
const WORM_UNKNOWN_REASON_SET: ReadonlySet<string> = new Set(WORM_UNKNOWN_REASONS);
export async function fetchSealFaults(scheduler: DurableObjectStub): Promise<unknown[]> {
  {
    const r = await scheduler.fetch(doURL("/seal-faults"), { method: "GET" });
    const j = (await r.json()) as { faults?: Array<Record<string, unknown>> };
    const rows = Array.isArray(j.faults) ? j.faults : [];
    const intOr0 = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), 1_000_000_000) : 0);
    return rows
      .filter((s) => typeof s.kind === "string" && SEAL_FAULT_KIND_SET.has(s.kind)) // only the CLOSED vocabulary reaches the pack
      .slice(0, 64)
      .map((s) => ({
        kind: s.kind,
        ...(typeof s.at === "number" && Number.isFinite(s.at) ? { at: s.at } : {}),
        ...(typeof s.downpipeId === "string" ? { downpipeId: s.downpipeId.slice(0, 128) } : {}),
        ...(typeof s.runId === "string" ? { runId: s.runId.slice(0, 128) } : {}),
        ...(s.found !== undefined ? { found: intOr0(s.found) } : {}),
        ...(s.expected !== undefined ? { expected: intOr0(s.expected) } : {}),
        ...(s.cleaned !== undefined ? { cleaned: intOr0(s.cleaned) } : {}),
        ...(s.reclaimed !== undefined ? { reclaimed: intOr0(s.reclaimed) } : {}),
        ...(s.wormBlocked !== undefined ? { wormBlocked: s.wormBlocked === true } : {}),
        // RETENTION prune evidence (G190), on the prune-deferred / prune-runs-skipped / prune-partial-apply
        // kinds. deferClass is the CLOSED reason a prune ABSTAINED (the planner's free-text sentence is
        // coarsened at the recording site and NEVER rides), re-gated here on the closed vocabulary; skipped /
        // unparseableTime / superseded are counts; partial marks an ENFORCED prune that died partway through its
        // delete loop (the RUNLOG is already consistent but the deletes are half-applied, so storage keeps
        // growing). Together with wormBlocked (a WORM/Object-Lock refusal = an IRREDUCIBLE remainder, not a
        // transient flake) these are the "retention never reclaims anything" diagnosis.
        ...(typeof s.deferClass === "string" && PRUNE_DEFER_CLASS_SET.has(s.deferClass) ? { deferClass: s.deferClass } : {}),
        ...(s.skipped !== undefined ? { skipped: intOr0(s.skipped) } : {}),
        ...(s.unparseableTime !== undefined ? { unparseableTime: intOr0(s.unparseableTime) } : {}),
        ...(s.superseded !== undefined ? { superseded: intOr0(s.superseded) } : {}),
        ...(s.partial !== undefined ? { partial: s.partial === true } : {}),
        // FAN-OUT evidence (G062). rangeIndex names WHICH parallel worker wedged on a fanout-range-stalled row
        // (a wedged worker throws nothing, so that row can carry no causeDigest -- the integer IS the
        // attribution); discardClass says WHY the coordinator dropped a worker's report (a stale phase, a
        // duplicate range, an out-of-bounds index), which is how a fan-out run silently loses a range's records.
        ...(s.rangeIndex !== undefined ? { rangeIndex: intOr0(s.rangeIndex) } : {}),
        ...(typeof s.discardClass === "string" && FANOUT_DISCARD_CLASS_SET.has(s.discardClass) ? { discardClass: s.discardClass } : {}),
        // The RING'S OWN ingestion losses (G326), on an observe-dropped row: dropClass is WHY the observation
        // never landed (transport = the scheduler-DO was unreachable, which a DO-side counter structurally
        // CANNOT see because the DO is the unreachable party; unknown-kind = an engine kind that drifted out of
        // SEAL_FAULT_KINDS), and `dropped` is how many were lost. countsMalformed rides on ANY kind: the posted
        // count was NaN/negative, so the fail-closed clamp to 0 must NOT be read as a measured zero -- which is
        // exactly the input a false severe-truncation escalation fires on.
        ...(typeof s.dropClass === "string" && SEAL_FAULT_DROP_CLASS_SET.has(s.dropClass) ? { dropClass: s.dropClass } : {}),
        ...(s.dropped !== undefined ? { dropped: intOr0(s.dropped) } : {}),
        ...(s.countsMalformed !== undefined ? { countsMalformed: s.countsMalformed === true } : {}),
        // ---- the ROUND-4 seal/replication/destination evidence -------------------------------------------
        // Each field is re-gated against the SAME closed vocabulary its recording site used (defence in depth:
        // a drifted, older or tampered row must never push free text into the bundle), and every count is
        // re-clamped. The kind gate above already admitted only closed kinds; these are the fields that make
        // each kind DIAGNOSTIC rather than merely present.
        //
        // config-fault (G041/G142): WHICH prerequisite the run was missing, by closed code, plus the offending
        // BINDING NAME (an operator label, charset-gated at the write site). secret-binding-wrong-type is the
        // one that was silently sealing the literal string "[object Object]" as the customer's secret on every
        // single run -- a green backup of nothing.
        ...(typeof s.configCode === "string" && CONFIG_FAULT_CODE_SET.has(s.configCode) ? { configCode: s.configCode } : {}),
        ...(typeof s.bindingName === "string" && BINDING_NAME_SHAPE.test(s.bindingName) ? { bindingName: s.bindingName } : {}),
        // replica-target-fault (G063): the REAL reason a replica is not there, instead of the old two-word
        // vocabulary {not configured, unreachable}. integrity-verify-failed means the copy IS there and is
        // CORRUPT (support was previously told to check networking); strandedRuns counts the runs that can
        // NEVER be mirrored to this target (their origin is gone), which no retry will ever fix.
        ...(typeof s.destinationId === "string" ? { destinationId: s.destinationId.slice(0, 128) } : {}),
        ...(typeof s.replicaReason === "string" && REPLICA_FAULT_REASON_SET.has(s.replicaReason) ? { replicaReason: s.replicaReason } : {}),
        ...(s.strandedRuns !== undefined ? { strandedRuns: intOr0(s.strandedRuns) } : {}),
        // replication-pass (G064): the PASS's own execution health. verifySampleShortfall is the quiet one --
        // the budget cut the read-back verification sample short, so segments were COPIED and never
        // structurally checked, and the replication row says "replicated" either way.
        ...(typeof s.passOutcome === "string" && REPLICATION_PASS_OUTCOME_SET.has(s.passOutcome) ? { passOutcome: s.passOutcome } : {}),
        ...(s.deferredDownpipes !== undefined ? { deferredDownpipes: intOr0(s.deferredDownpipes) } : {}),
        ...(s.stateWriteFailures !== undefined ? { stateWriteFailures: intOr0(s.stateWriteFailures) } : {}),
        ...(s.verifySampleShortfall !== undefined ? { verifySampleShortfall: intOr0(s.verifySampleShortfall) } : {}),
        ...(s.segmentVanishDeferrals !== undefined ? { segmentVanishDeferrals: intOr0(s.segmentVanishDeferrals) } : {}),
        // record-skipped-changed (G065): a persistent INFRA fault (a 403 on the resume range-read, a short
        // read) is no longer masked as ordinary content churn. The handles are the engine's one-way
        // `h:<12 hex>` attribution tokens -- a RAW object key is refused at the write site AND dropped here.
        ...(typeof s.skipCause === "string" && SKIP_CAUSE_SET.has(s.skipCause) ? { skipCause: s.skipCause } : {}),
        ...(Array.isArray(s.handles) ? { handles: s.handles.filter((h): h is string => typeof h === "string" && RECORD_HANDLE_SHAPE.test(h)).slice(0, 25) } : {}),
        ...(s.partialsAbandoned !== undefined ? { partialsAbandoned: intOr0(s.partialsAbandoned) } : {}),
        // dest-stranding (G066): stranded destination bytes, by closed class. scratch-delete-failed on a WORM
        // bucket permanently strands the whole scratch set of EVERY run -- the "why does the archive bucket
        // grow far faster than the data?" ticket. wormRefusalClass SPLITS the old wormBlocked boolean: a bare
        // 403 with no lock vocabulary is access-denied (a FIXABLE credential), not "locked by design".
        ...(typeof s.strandClass === "string" && STRAND_CLASS_SET.has(s.strandClass) ? { strandClass: s.strandClass } : {}),
        ...(s.stranded !== undefined ? { stranded: intOr0(s.stranded) } : {}),
        ...(typeof s.wormRefusalClass === "string" && WORM_REFUSAL_CLASS_SET.has(s.wormRefusalClass) ? { wormRefusalClass: s.wormRefusalClass } : {}),
        ...(s.listFailed !== undefined ? { listFailed: s.listFailed === true } : {}),
        // verify-suspect (G067): what a SUSPECT verdict on a 50,000-record run actually needs. ordinal is the
        // record INDEX the decrypt died on (never a key); verifiedBeforeFail is how many verified CLEAN first;
        // causeDigest is a one-way correlation handle so two recurring reader faults can be joined WITHOUT the
        // text (which can embed a shard id or an object key) ever riding; and verifyMode makes a DISABLED
        // verification distinguishable from a legacy-absent verdict.
        ...(typeof s.verifyMode === "string" && VERIFY_MODE_SET.has(s.verifyMode) ? { verifyMode: s.verifyMode } : {}),
        ...(typeof s.causeDigest === "string" && CAUSE_DIGEST_SHAPE.test(s.causeDigest) ? { causeDigest: s.causeDigest } : {}),
        ...(s.ordinal !== undefined ? { ordinal: intOr0(s.ordinal) } : {}),
        ...(s.verifiedBeforeFail !== undefined ? { verifiedBeforeFail: intOr0(s.verifiedBeforeFail) } : {}),
        ...(s.attemptsRun !== undefined ? { attemptsRun: intOr0(s.attemptsRun) } : {}),
        ...(s.recovered !== undefined ? { recovered: s.recovered === true } : {}),
        // seal-mode (G189): the SILENT SERIAL DOWNGRADE. A downpipe with fan-out enabled that quietly runs
        // serial still takes days on a backup the customer believes is parallel -- and the fan-out knobs are
        // deliberately omitted from sealKnobs, so the pack carried nothing at all about it.
        ...(typeof s.requestedMode === "string" && SEAL_MODE_SET.has(s.requestedMode) ? { requestedMode: s.requestedMode } : {}),
        ...(typeof s.effectiveMode === "string" && SEAL_MODE_SET.has(s.effectiveMode) ? { effectiveMode: s.effectiveMode } : {}),
        ...(s.fanoutRanges !== undefined ? { fanoutRanges: intOr0(s.fanoutRanges) } : {}),
        ...(typeof s.downgradeReason === "string" && FANOUT_DOWNGRADE_REASON_SET.has(s.downgradeReason) ? { downgradeReason: s.downgradeReason } : {}),
        // alert-routing-failed (G212): "we never got the suspect-archive alert" is no longer evidence-free.
        // historyWriteFailed is the distinction that matters: true = the alert WAS delivered and only its
        // history row was lost; false = the routing itself threw and the critical alert was never sent.
        ...(typeof s.alertEventClass === "string" && ALERT_EVENT_CLASS_SET.has(s.alertEventClass) ? { alertEventClass: s.alertEventClass } : {}),
        ...(s.historyWriteFailed !== undefined ? { historyWriteFailed: s.historyWriteFailed === true } : {}),
        // lock-plane (G222): a SCHEDULER-plane blip (a lock round-trip that faulted) used to be swallowed, after
        // which the run parked "runlog contended" or died with a DESTINATION-access class -- sending support to
        // a perfectly healthy bucket. releaseFaults happen AFTER the archive and the RUNLOG entry are provably
        // committed, so they are never a data fault; sigPublishSkipped means a concurrent winner moved the
        // RUNLOG body, so OUR signature was never published.
        ...(s.lockAcquireFaults !== undefined ? { lockAcquireFaults: intOr0(s.lockAcquireFaults) } : {}),
        ...(s.lockWindowExhausted !== undefined ? { lockWindowExhausted: intOr0(s.lockWindowExhausted) } : {}),
        ...(s.casExhausted !== undefined ? { casExhausted: intOr0(s.casExhausted) } : {}),
        ...(s.sigPublishSkipped !== undefined ? { sigPublishSkipped: intOr0(s.sigPublishSkipped) } : {}),
        ...(s.releaseFaults !== undefined ? { releaseFaults: intOr0(s.releaseFaults) } : {}),
        // ---- the ROUND-5 seal evidence -------------------------------------------------------------------
        // This projection is a FIELD ALLOWLIST, not a spread: a new ring field is stored and served by the DO
        // and rides into the pack ONLY when it is named here. The kind gate above admits the new kinds
        // automatically (it is derived from the imported SEAL_FAULT_KINDS), so without these lines the new
        // rows would arrive in the bundle STRIPPED OF THE VERY FIELDS THAT DIAGNOSE THEM -- present, and
        // useless. Each is re-gated against the same closed vocabulary its recording site used.
        //
        // completion-lost (G109): the run's computed verdict never reached the scheduler. The completion POST
        // was not even status-checked at any call site, so a REFUSED (non-2xx) completion never threw and no
        // fail-soft arm ever saw it -- the verdict was dropped in silence and the row resolved later as a
        // generic "abandoned". `outcome` is the fact that makes the run history and the destination
        // reconcilable: outcome "ok" on a runId the pack shows as ABANDONED is a DIRECT contradiction between
        // the run history and the bucket, and it is why "the run says abandoned but the archive restores fine"
        // was unfalsifiable.
        ...(typeof s.outcome === "string" && (s.outcome === "ok" || s.outcome === "failed") ? { outcome: s.outcome } : {}),
        ...(Array.isArray(s.attemptClasses)
          ? { attemptClasses: s.attemptClasses.filter((c): c is string => typeof c === "string" && SEAL_ATTEMPT_CLASS_SET.has(c)).slice(0, 8) }
          : {}),
        // checkpoint-invalid / checkpoint-unwrap-failed / checkpoint-coerced / resume-abandoned (G107): the
        // corrupt checkpoint now NAMES ITSELF and SIZES the loss. unwrapCode splits an AEAD that FAILED
        // (master-unwrap: a SIGNER_PRIVATE rotation stranded the run, or tamper) from one that SUCCEEDED onto
        // a non-32-byte plaintext (wrong-length: a corrupt write; the wrap key was RIGHT -- a different
        // remedy). legacyAbsent splits a benign forward-compat absent counter from a PRESENT-but-malformed one
        // being silently coerced (a miscounted archive waiting to be discovered at restore).
        // slicesDiscarded/recordsDiscarded are the actual mechanism behind "the big backup restarts from
        // scratch every night" -- and they finally size it.
        ...(typeof s.checkpointField === "string" && CHECKPOINT_FIELD_SET.has(s.checkpointField) ? { checkpointField: s.checkpointField } : {}),
        ...(typeof s.unwrapCode === "string" && CHECKPOINT_UNWRAP_CODE_SET.has(s.unwrapCode) ? { unwrapCode: s.unwrapCode } : {}),
        ...(s.coerced !== undefined ? { coerced: intOr0(s.coerced) } : {}),
        ...(s.legacyAbsent !== undefined ? { legacyAbsent: s.legacyAbsent === true } : {}),
        ...(s.slicesDiscarded !== undefined ? { slicesDiscarded: intOr0(s.slicesDiscarded) } : {}),
        ...(s.recordsDiscarded !== undefined ? { recordsDiscarded: intOr0(s.recordsDiscarded) } : {}),
        // runlog-absent (G283): the history chain RESTARTED on this destination. An absent RUNLOG alone is not
        // evidence (a brand-new downpipe's first run on a fresh bucket is the identical read); the signal is
        // that the SCHEDULER says a prior run SUCCEEDED and yet THIS destination has no entry to chain onto --
        // precisely a downpipe repointed at a re-created or wrong bucket, whose root is about to be signed
        // with prevRunId=null and whose prune will find nothing to supersede. This is the always-on complement
        // to reconcile.runlogPresent, which most bundles omit because the reconcile pass is opt-in.
        ...(s.priorRuns !== undefined ? { priorRuns: intOr0(s.priorRuns) } : {}),
        ...(s.historyChainRestarted !== undefined ? { historyChainRestarted: s.historyChainRestarted === true } : {}),
      }));
  }
}

// fetchRetentionState projects the LATEST retention-prune pass record (gaps G071/G190) the cron's retention
// pass posts each tick. Before this the whole "storage keeps growing despite my retention policy" family was
// invisible: the pass only ever wrote Workers Logs lines, which remote support structurally cannot read. The
// record names the CAUSE, and the causes are very different tickets:
//   - passSkipCode / destinations[].skipCode : the pass (or one destination) never pruned at all -- a
//     break-glass-only engine, keys unavailable, no destination configured, an absent/unreadable RUNLOG.
//   - downpipes[].outcome "dry-run"          : the single commonest cause. `enforce` was never set, so the prune
//     computed a plan and deleted nothing, exactly as designed -- and the customer never knew.
//   - "deferred" + deferralClass             : a retained run could not be read, so nothing was safe to delete.
//     A downpipe that defers EVERY tick forever is the perpetual-deferral case; the planner's free-text sentence
//     is coarsened to a closed class at the recording site and never rides.
//   - "applied"                              : the counts are what was COMMITTED, so a half-applied prune reads
//     as applied-with-fewer-deletes rather than as the full plan (the sealFaults ring carries the WORM refusal).
//   - "error" + errorClass                   : the per-downpipe throw the fail-open guard swallowed.
//   - "paused" + downpipesPaused             : the downpipe is PAUSED, so the cron pass deliberately did not
//     plan and did not delete (RL-RETENTION-PRUNES-A-PAUSED-DOWNPIPE). The counterpart ticket to "dry-run":
//     the customer's storage keeps growing and the reason is a switch THEY set. The row is emitted rather
//     than the downpipe being absent, because a paused downpipe and a downpipe retention never saw are the
//     same silence otherwise. The dual-controlled prune route still deletes on request.
//   - replicationUnreadable                  : the M7 replica-coverage gate ran on NO coverage proof, so every
//     replicated run was HELD -- the invisible reason retention deletes nothing on a healthy-looking fleet.
//   - auditWriteFailures                     : a prune that really deleted runs but whose AUDIT write was lost.
// Redaction-safe by construction (the DO re-runs sanitiseRetentionPassRecord on the posted body): closed enums,
// clamped counts, booleans, and the customer's own downpipe/destination ids. Every enum is RE-GATED here at the
// pack boundary (defence in depth) and a non-member is DROPPED. A fetch/parse fault PROPAGATES to section()
// (recorded "error"); a pass that has never run reads "empty" (honest absence, a real posture in its own right).
const RETENTION_SKIP_CODE_SET: ReadonlySet<string> = new Set(RETENTION_SKIP_CODES);
const RETENTION_OUTCOME_SET: ReadonlySet<string> = new Set(RETENTION_OUTCOMES);
const RETENTION_DEFERRAL_CLASS_SET: ReadonlySet<string> = new Set(RETENTION_DEFERRAL_CLASSES);
const RETENTION_ERROR_CLASS_SET: ReadonlySet<string> = new Set(RETENTION_ERROR_CLASSES);
export async function fetchRetentionState(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/retention-state"), { method: "GET" });
    const j = (await r.json()) as { record?: unknown };
    const rec = (typeof j.record === "object" && j.record !== null ? j.record : null) as Record<string, unknown> | null;
    if (rec === null) return {}; // the retention pass has never run: honest absence
    const destinations = (Array.isArray(rec.destinations) ? rec.destinations : []).slice(0, 16).map((row) => {
      const d = (typeof row === "object" && row !== null ? row : {}) as Record<string, unknown>;
      return {
        destKey: typeof d.destKey === "string" ? d.destKey.slice(0, 128) : "",
        downpipeCount: clampInt(d.downpipeCount) ?? 0,
        ...(typeof d.skipCode === "string" && RETENTION_SKIP_CODE_SET.has(d.skipCode) ? { skipCode: d.skipCode } : {}),
      };
    });
    const downpipes = (Array.isArray(rec.downpipes) ? rec.downpipes : []).slice(0, 64).flatMap((row) => {
      const d = (typeof row === "object" && row !== null ? row : {}) as Record<string, unknown>;
      // The OUTCOME is load-bearing: a row whose outcome is not a vocabulary member carries no meaning at all,
      // so it is dropped whole rather than emitted as a row a reader would have to guess at.
      if (typeof d.id !== "string" || typeof d.outcome !== "string" || !RETENTION_OUTCOME_SET.has(d.outcome)) return [];
      return [{
        id: d.id.slice(0, 128),
        outcome: d.outcome,
        ...(typeof d.deferralClass === "string" && RETENTION_DEFERRAL_CLASS_SET.has(d.deferralClass) ? { deferralClass: d.deferralClass } : {}),
        ...(typeof d.errorClass === "string" && RETENTION_ERROR_CLASS_SET.has(d.errorClass) ? { errorClass: d.errorClass } : {}),
        supersededRuns: clampInt(d.supersededRuns, 1_000_000_000) ?? 0,
        runTreeObjects: clampInt(d.runTreeObjects, 1_000_000_000) ?? 0,
        orphanSegs: clampInt(d.orphanSegs, 1_000_000_000) ?? 0,
        retainedRuns: clampInt(d.retainedRuns, 1_000_000_000) ?? 0,
        ...(clampInt(d.volumeHeld, 1_000_000_000) !== undefined ? { volumeHeld: clampInt(d.volumeHeld, 1_000_000_000) } : {}),
      }];
    });
    return {
      at: clampInt(rec.at, Number.MAX_SAFE_INTEGER) ?? 0,
      downpipesWithRetention: clampInt(rec.downpipesWithRetention) ?? 0,
      // PAUSE MEANS PAUSE: how many of them the pass deliberately left alone because the downpipe is
      // paused. Without it, "retention pruned nothing" reads the same in the pack whether there was
      // nothing over the cap or the whole fleet had been paused and the prune had stood down.
      downpipesPaused: clampInt(rec.downpipesPaused) ?? 0,
      replicationUnreadable: rec.replicationUnreadable === true,
      auditWriteFailures: clampInt(rec.auditWriteFailures) ?? 0,
      ...(typeof rec.passSkipCode === "string" && RETENTION_SKIP_CODE_SET.has(rec.passSkipCode) ? { passSkipCode: rec.passSkipCode } : {}),
      destinations,
      downpipes,
    };
  }
}

// sealKnobs resolves the seal / verify-at-seal / scale TUNING KNOBS to the effective values a run and its
// at-seal verify actually use -- each via the SAME pure resolver the seal path uses (env is shared by the
// Worker and the scheduler DO, so these ARE the values in force). It answers a class of otherwise-invisible
// seal-integrity faults the pack could not diagnose (support-pack modes verify-at-seal-disabled /
// seal-verify-knobs-invisible / scale-knobs-invisible / sliced-runs-disabled + the "verify off vs not-run"
// ambiguity, disambiguated by `verifyAtSeal.enabled` alongside a downpipe's lastSealVerify presence):
// verify-at-seal turned OFF; a decrypt sample of 0 or a tiny max-bytes cutoff forcing Tier-0-only; an
// over-set slice budget that cannot leave finalise headroom (the cpu-kill/wedged-slice context); a shrunken
// shard/segment target; the v1 no-resume path. It records NOTHING and touches no seal write / sign / verify
// path -- it only reflects config. NO-CUSTODY safe by construction: every value is a resolved int or bool,
// never a secret / value / record name. Fan-out (SCALE_FANOUT_*) is deliberately omitted here: it is opt-in
// throughput tuning (default off), not a seal-integrity signal, and its resolvers live in the heavy
// runstate-helpers graph this admin module intentionally does not import.
export function sealKnobs(env: Env): Record<string, unknown> {
  const vas = resolveSealVerifyKnobs(env);
  return {
    verifyAtSeal: {
      enabled: vas.enabled,
      sample: vas.sample,
      maxBytes: vas.maxBytes,
      fullBytes: vas.fullBytes,
      attempts: vas.attempts,
      fullShards: vas.fullShards,
      shardSample: vas.shardSample,
    },
    slice: resolveSliceKnobs(env),
    ...resolveScaleKnobs(env),
    // knobSources (G169): HOW each of the 19 seal knobs got its running value -- default | env | clamped |
    // invalid. The resolved INTEGER alone cannot tell "the operator never set this" from "the operator set it
    // and the engine silently overrode them": a typo'd SCALE_SLICE_WALL_MS and an unset one both resolve to the
    // same default, and an over-set value that was CLAMPED reads as a deliberate choice. Each owning module
    // classifies its own knobs through the SAME resolver the seal path runs, so the classification cannot drift
    // from the resolution. The rejected RAW STRING is never carried: an invalid value reports source:"invalid"
    // plus the integer default that is actually in force.
    knobSources: sealKnobSources(env),
  };
}

// fetchCanaryHealth pulls the canary's liveness + its bounded TRANSITION ring (NOTIF: canary-transition-only-
// pages-once) into the pack. The canary pages exactly once per threshold crossing (a persistent death does NOT
// re-page every hour), so after the first page the standing dead state leaves no fresh alert; the ring is the
// durable record of WHEN each destination flipped dead/recovered. It projects ONLY closed vocabularies: the
// aggregate liveness (a fixed enum), the currently-dead-destination count, and each transition's clamped time
// + the customer's own destination id (or null for the env default) + the closed to-state + the flight number.
// Never a byte value, a key, or an object key. Best-effort {}; OMITTED when there is nothing to report.
const CANARY_LIVENESS_CODES: ReadonlySet<string> = new Set(["alive", "dead", "ailing", "pending", "disabled"]);
// CANARY_ASPECT_KEYS is the closed 8-member flight-aspect vocabulary (canary/types.ts CanaryAspectKey). The
// pack forwards only a member key on the failed-aspect list (defence-in-depth: an unknown key is dropped).
const CANARY_ASPECT_KEYS: ReadonlySet<string> = new Set(["write-probe", "delete-probe", "seal", "read-signature", "runlog-freshness", "decrypt-integrity", "restore", "restore-verify"]);
export async function fetchCanaryHealth(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/canary/transitions"), { method: "GET" });
    const j = (await r.json()) as { enabled?: unknown; status?: unknown; deadDestinations?: unknown; transitionCount?: unknown; transitions?: unknown; nextRunAt?: unknown; deadDetail?: unknown };
    const status = typeof j.status === "string" && CANARY_LIVENESS_CODES.has(j.status) ? j.status : undefined;
    // The ring is stored oldest -> newest. Project the whole (bounded) ring first, then SELECT: the recency
    // window PLUS the smart-retained boundary rows (G342).
    const projected = (Array.isArray(j.transitions) ? j.transitions : []).slice(-500).map((t) => {
      const tt = (typeof t === "object" && t !== null ? t : {}) as { at?: unknown; destinationId?: unknown; to?: unknown; runSeq?: unknown };
      const to = tt.to === "dead" || tt.to === "recovered" ? tt.to : undefined;
      if (to === undefined) return null;
      const destinationId = typeof tt.destinationId === "string" ? tt.destinationId.slice(0, 128) : null;
      return {
        to,
        destinationId,
        ...(clampTs(tt.at) !== undefined ? { at: clampTs(tt.at) } : {}),
        ...(clampInt(tt.runSeq) !== undefined ? { runSeq: clampInt(tt.runSeq) } : {}),
      };
    }).filter((x): x is NonNullable<typeof x> => x !== null);
    // SMART-RETAIN THE BOUNDARY ROW (G342), mirroring the configEvents keystone pattern. A fixed last-50 window
    // is a recency window, and the canary pages exactly ONCE per threshold crossing: on a busy fleet the ORIGINAL
    // death (the transition that answers "when did this destination actually die, and had anything else changed
    // that day?") is pushed out by later churn, leaving 50 identical-looking recent rows and no onset. So the
    // OLDEST `dead` transition PER DESTINATION is always carried, even when it predates the window. Bounded by
    // the destination count; a healthy fleet has none and the projection is byte-identical to before.
    const keep = new Set<number>();
    for (let i = Math.max(0, projected.length - 50); i < projected.length; i++) keep.add(i);
    const oldestDeadSeen = new Set<string>();
    for (let i = 0; i < projected.length; i++) {
      const t = projected[i]!;
      if (t.to !== "dead") continue;
      const key = t.destinationId ?? "\u0000default";
      if (oldestDeadSeen.has(key)) continue;
      oldestDeadSeen.add(key);
      keep.add(i);
    }
    const transitions = [...keep].sort((a, b) => a - b).map((i) => projected[i]!);
    // deadDetail (Wave A2, G035/G058/G290): the WHY of each current death -- the coarse deadReason (clamped; the
    // CanaryCheck contract guarantees it carries no key/value/object-key), the stray byteDelta, and WHICH of the
    // 8 closed flight aspects failed or was skipped. reasonAbsent flags a death record with no stored reason
    // (itself a diagnostic: "the worker died without reporting why"), so the console no longer fabricates it.
    const deadDetail = (Array.isArray(j.deadDetail) ? j.deadDetail : []).slice(0, 32).map((d) => {
      const dd = (typeof d === "object" && d !== null ? d : {}) as { destinationId?: unknown; at?: unknown; deadReason?: unknown; byteDelta?: unknown; failedAspects?: unknown };
      const failedAspects = (Array.isArray(dd.failedAspects) ? dd.failedAspects : []).filter((a): a is string => typeof a === "string" && CANARY_ASPECT_KEYS.has(a));
      const hasReason = typeof dd.deadReason === "string" && dd.deadReason !== "";
      return {
        destinationId: typeof dd.destinationId === "string" ? dd.destinationId.slice(0, 128) : null,
        ...(clampTs(dd.at) !== undefined ? { at: clampTs(dd.at) } : {}),
        ...(hasReason ? { deadReason: (dd.deadReason as string).slice(0, 64) } : { reasonAbsent: true }),
        ...(typeof dd.byteDelta === "number" && Number.isFinite(dd.byteDelta) ? { byteDelta: Math.max(-1_000_000_000, Math.min(1_000_000_000, Math.floor(dd.byteDelta))) } : {}),
        ...(failedAspects.length > 0 ? { failedAspects } : {}),
      };
    });
    const nextRunAt = clampInt(j.nextRunAt, Number.MAX_SAFE_INTEGER);
    // Nothing to report (no resolvable status AND no transitions): honest absence.
    if (status === undefined && transitions.length === 0) return {};
    return {
      enabled: j.enabled === true,
      // scheduleArmed: the bird is enabled AND has a next flight scheduled -- a disarmed schedule is WHY an
      // enabled canary stopped flying (the console fabricated this state before it rode in the pack, G290).
      scheduleArmed: j.enabled === true && nextRunAt !== undefined && nextRunAt > 0,
      ...(status !== undefined ? { status } : {}),
      ...(nextRunAt !== undefined ? { nextRunAt } : {}),
      deadDestinations: clampInt(j.deadDestinations) ?? 0,
      transitionCount: clampInt(j.transitionCount) ?? transitions.length,
      transitions,
      ...(deadDetail.length > 0 ? { deadDetail } : {}),
    };
  }
}

// ---- WORM / Object-Lock posture (item 3) --------------------------------------------------------------
// The pack's per-(default-)destination WORM / Object-Lock posture: whether a WORM policy is CONFIGURED (and
// whether that config is MISCONFIGURED), the valid policy's mode/days, and the LIVE capability-probe verdict
// of whether the destination BUCKET actually ENFORCES S3 Object-Lock. This is the same observable state the
// GET /admin/posture immutability check reads (objectLockStatus() on the default destination); plumbing it
// into the pack answers "my archive bucket does NOT actually enforce Object-Lock while a WORM policy is set"
// (the dangerous immutability SHADOW) from the bundle alone. Redaction-safe by construction: only closed
// enums (mode governance|compliance), booleans / "unknown", and integer retention days ever cross, never an
// endpoint, bucket, region or credential.
//
// It is the DEFAULT (primary) destination's posture from a LIVE probe (one GetObjectLockConfiguration read),
// mirroring the posture route (which probes the default destination only), so it is ONE bounded probe, not
// one per downpipe. It is BEST-EFFORT, TIME-BOXED and FAIL-SOFT: the whole probe is raced against
// WORM_PROBE_TIMEOUT_MS and wrapped in try/catch, so a slow or erroring probe degrades to {} (the posture is
// OMITTED from the pack) and can NEVER block or fail the bundle build. buildDestination THROWS on a
// misconfigured/absent destination; the catch turns that into an omitted probe verdict (honest absence).
const WORM_PROBE_TIMEOUT_MS = 4000;
export async function fetchWormPosture(env: Env, scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const timeout = new Promise<Record<string, unknown>>((resolve) => {
      // Resolve (never reject) with a distinct probeOutcome so a slow live probe is visible as a TIMEOUT in the
      // pack, not omitted as honest absence (G031). The catch below carries probeOutcome "error" for a throw.
      timer = setTimeout(() => resolve({ probeOutcome: "timeout" }), WORM_PROBE_TIMEOUT_MS);
    });
    return await Promise.race([gatherWormPosture(env, scheduler), timeout]);
  } catch {
    // A probe fault/timeout is NOT honest absence (an unconfigured WORM policy still returns a populated
    // block). Carry a probeOutcome marker so a diagnoser can tell "could not probe Object-Lock" from a
    // genuine posture read (G031). The timeout arm resolves rather than throws, so reaching here is a fault.
    return { probeOutcome: "error" };
  } finally {
    // Clear the timeout so a dangling timer never keeps the isolate/event loop alive after the race settles.
    if (timer !== undefined) clearTimeout(timer);
  }
}

// gatherWormPosture resolves the effective WORM policy (env DEST_WORM_* with a console-set per-destination
// policy taking PRECEDENCE, the same precedence the factory + posture apply) and probes the default
// destination's live Object-Lock enforcement. It mirrors router-posture.ts's gatherWormSlice but is
// reimplemented here with lightweight dest/factory deps only, so the redaction-boundary support module does
// NOT pull the posture-report / PDF import graph. Every returned field is a closed enum / boolean / integer.
async function gatherWormPosture(env: Env, scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const envParse = parseWormPolicy(env);
  // Resolve the default console-set destination (for the console-policy precedence + something to probe). A
  // read fault is non-fatal: the env config still answers and the probe is skipped.
  let override: RuntimeDestConfig | null = null;
  try {
    override = await fetchDestConfig(scheduler, undefined, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
  } catch {
    override = null;
  }
  // The effective configured policy: a console-set per-destination policy wins over env; else the env policy.
  let configured = envParse.configured;
  let misconfigured = envParse.configured ? envParse.misconfigured : false;
  let mode: "governance" | "compliance" | undefined = envParse.configured && !envParse.misconfigured ? envParse.policy.mode : undefined;
  let retentionDays: number | undefined = envParse.configured && !envParse.misconfigured ? envParse.policy.retentionDays : undefined;
  const consoleWorm = override?.worm;
  if (consoleWorm !== undefined) {
    // A console-set policy is INTENDED; validate it the same way the factory does. Invalid => misconfigured.
    configured = true;
    if (typeof consoleWorm.mode === "string" && (consoleWorm.mode === "governance" || consoleWorm.mode === "compliance") && Number.isInteger(consoleWorm.retentionDays) && consoleWorm.retentionDays > 0) {
      misconfigured = false;
      mode = consoleWorm.mode;
      retentionDays = consoleWorm.retentionDays;
    } else {
      misconfigured = true;
      mode = undefined;
      retentionDays = undefined;
    }
  }
  // The LIVE capability probe (best-effort): buildDestination throws on a misconfigured/absent destination, so
  // guard it; objectLockStatus is optional on the interface, so feature-detect it. Any fault leaves
  // bucketEnforces unset (the SAFE cannot-confirm reading), never a false enforcement claim.
  let bucketEnforces: boolean | "unknown" | undefined;
  let probeMode: "governance" | "compliance" | undefined;
  let probeDays: number | undefined;
  // unknownReason (G279): WHY the probe could not confirm enforcement. bucketEnforces:"unknown" would
  // otherwise collapse six completely different faults into one word, and they route to OPPOSITE remedies --
  // `denied` is an IAM policy the customer can fix, `not-implemented` means the store does not do
  // Object-Lock at all, and `network` will simply heal. `r2-binding-unsupported` is STRUCTURAL AND HAS NO
  // REMEDY AT ALL: R2's S3 endpoint answers a PUT carrying x-amz-object-lock-mode: COMPLIANCE with 501
  // NotImplemented and its Object-Lock configuration GET with 404, so no R2 destination can enforce
  // Object-Lock; moving to a store that does is the only thing that changes the reading. A closed enum
  // only: the probe's response body, endpoint and bucket never ride.
  // probe's response body, endpoint and bucket never ride.
  let unknownReason: string | undefined;
  try {
    const dest = await buildDestination(env, undefined, override);
    if (typeof dest.objectLockStatus === "function") {
      const wormStatus = await dest.objectLockStatus();
      bucketEnforces = wormStatus.enabled;
      if (wormStatus.defaultMode !== undefined) probeMode = wormStatus.defaultMode;
      if (wormStatus.defaultDays !== undefined) probeDays = wormStatus.defaultDays;
      // Re-gated at the pack boundary against the closed set the probe classifies into, and carried ONLY on
      // the "unknown" verdict (a 404 is an honest not-enabled and must stay reason-free: a reason there would
      // read as a probe fault where there was none).
      if (wormStatus.enabled === "unknown" && typeof wormStatus.unknownReason === "string" && WORM_UNKNOWN_REASON_SET.has(wormStatus.unknownReason)) {
        unknownReason = wormStatus.unknownReason;
      }
    }
  } catch {
    // cannot-confirm: leave bucketEnforces unset so the pack never claims enforcement it could not probe.
  }
  return {
    configured,
    misconfigured,
    ...(mode !== undefined ? { mode } : {}),
    ...(retentionDays !== undefined ? { retentionDays } : {}),
    ...(bucketEnforces !== undefined ? { bucketEnforces } : {}),
    ...(unknownReason !== undefined ? { unknownReason } : {}),
    ...(probeMode !== undefined ? { probeMode } : {}),
    ...(probeDays !== undefined ? { probeDays } : {}),
  };
}
