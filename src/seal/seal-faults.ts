// SEAL-FAULT OBSERVE SIGNALS (support-pack seal-integrity modes shard-list-truncated /
// shard-truncation-stalekeys / lease-lost-abandon / orphan-root-worm-leak /
// signer-rotation-strands-runs). These are DIAGNOSTIC observations the per-downpipe seal DO
// (RunSealDO) records at a fault's DETECTION POINT and posts to the scheduler DO's bounded ring,
// so a fault that today only LOGS (or throws into the strike ladder, where the raw cause is
// redacted) still reaches the support bundle with its coarse shape + the counts the fault already
// computed. They OBSERVE only: recording one NEVER changes the seal write / sign / verify /
// finalise path, the sealed-archive bytes, the Merkle root or the signature. Each observe is
// best-effort + fail-open on the RunSealDO side, so a persist hiccup can never affect a run.
//
// NO-CUSTODY: kind is a CLOSED enum, downpipeId / runId are the customer's OWN opaque ids (the same
// surface the reconcile inventory + replication heartbeats already expose in the pack), and every
// other field is a non-negative integer or a strict boolean. Never a key, value, record name or
// plaintext. This module is PURE (no I/O): the DO record path and the validator share the one
// sanitiser so the redaction can never drift.

import { type CheckpointField, type CheckpointUnwrapCode, isCheckpointField, isCheckpointUnwrapCode } from "./checkpoint-fault.ts";
import { type ConfigFaultCode, isConfigFaultCode, isConfigFaultName } from "./config-fault.ts";
import { ATTEMPT_CLASSES_MAX, isRetrySubsystem, isSealAttemptClass, type RetrySubsystem, type SealAttemptClass } from "./run-pressure.ts";

// SEAL_FAULT_KINDS is the closed observe vocabulary. Each fault is recorded at the exact point the
// existing seal path DETECTS it; the enum is what the diagnosis reasons over (never a raw message).
export const SEAL_FAULT_KINDS = [
  // finaliseAndComplete's completeness guard refuses to sign a truncated archive: fewer shards are
  // enumerated back than the checkpoint declared (found < expected). This observes the found/expected
  // counts the guard already computes; the refusal itself is unaffected.
  "shard-list-truncated",
  // /start cleans stale shard/open-batch rows left behind by an abandoned prior run. The cleanup is
  // integrity-load-bearing: a leaked stale row could leak a prior run's tail into a new root. This
  // observes only the count cleaned; it never touches the cleanup.
  "stale-shard-rows-cleaned",
  // A resuming sliced run finds a newer run owns the downpipe and abandons cleanly (the lease-reclaim
  // event). Recorded so the abandon is visible, not just logged.
  "lease-lost-abandon",
  // The RUNLOG-contention give-up path reclaims the orphan run-tree finaliseRun wrote before the
  // (never-committed) RUNLOG append, or a WORM / Object-Lock destination refuses the delete (an
  // irreducible orphan by design). Records the reclaim outcome plus the WORM signal.
  "orphan-root-reclaim",
  // A resume that cannot unwrap its stored checkpoint under the current signer: a SIGNER_PRIVATE
  // rotation strands the in-flight run (its checkpoint was wrapped under the prior signer), or DO
  // corruption. The run still fails loudly via the strike ladder; this makes the strand observable.
  "checkpoint-unwrap-failed",
  // RETENTION: the prune planner abstains for a downpipe when a retained run cannot be enumerated,
  // so the protected reference set is incomplete and no delete is safe. The only other sink is a
  // Workers Logs line carrying a free-text reason; this records the closed defer class, the blocking
  // (opaque) run id, and the unparseable-RUNLOG-time count, so "retention never deletes anything" is
  // diagnosable from the pack. Never the reason text.
  "prune-deferred",
  // RETENTION: the prune silently excludes one or more superseded runs this pass when they cannot be
  // read (fail-safe: they are not superseded and nothing is deleted). The exclusion otherwise leaves
  // no trace; this counts it.
  "prune-runs-skipped",
  // RETENTION: an enforced prune can die partway through its delete loop (a destination delete
  // throws, or a WORM/Object-Lock policy refuses it). The RUNLOG stays consistent (supersede commits
  // first) but the progress counts would otherwise be thrown away with the exception; this records
  // what the apply had actually done when it failed, plus whether WORM refused the delete (an
  // irreducible remainder).
  "prune-partial-apply",
  // FAN-OUT: the coordinator's await ladder strikes out a range whose worker persists nothing for
  // MAX_SLICE_FAILURES consecutive ticks (the uncatchable wedge) and fails the run closed. The
  // generic "fan-out worker stalled" completion does not say which range; this records the stalled
  // range index (a small integer, never a key or a range bound).
  "fanout-range-stalled",
  // FAN-OUT: the coordinator discards a worker's /range-done or /range-failed report when the doc is
  // past the await phase (a stale re-send after the merge began), the range is already recorded (a
  // duplicate report), or the index is out of bounds. Each discard is correct (it is what makes the
  // report idempotent), but without this a run that hangs or under-counts because reports were being
  // dropped would leave no trace. Records the closed discard class plus the range index.
  "fanout-report-discarded",
  // OBSERVE-PATH SELF-REPORT: the seal-fault ring's own ingestion can drop an observation, so a clean
  // ring is not misread as a clean engine. Two closed drop classes: "transport" (the fire-and-forget
  // POST to the scheduler DO failed or was refused -- a DO outage; counted in the poster and flushed
  // on the next observation that lands) and "unknown-kind" (an engine-side kind that is not a member
  // of this vocabulary was posted).
  "observe-dropped",
  // CONFIG FAULT: the run cannot be constructed when a prerequisite is missing -- a source binding a
  // deploy wiped, a secrets binding, the read-only discovery token, an accountId now outside the
  // discovery scope, SIGNER_PRIVATE (absent or not the 64-byte seed form), or another required env
  // var. The failed row otherwise says only "source binding error" / "run failed"; this records the
  // closed code and the offending binding / env-var name (an operator label, the same redaction class
  // sourcesDetached already carries), so a redeploy that silently unbinds a source is attributable
  // from the pack alone. The name comes from the config, never from an error message.
  "config-fault",
  // REPLICATION: one replica target's mirror fault, with the real reason instead of a collapsed
  // two-word vocabulary {not configured, unreachable}. Without this, a post-copy integrity verify
  // failure (possible corruption in transit) and a corrupt replica RUNLOG both read as "the replica
  // is down", steering support to check networking while the 3-2-1 promise is silently unfillable.
  // Also carries strandedRuns: runs that can never be mirrored (their origin is gone, or they are
  // absent from their own origin), which permanently freeze holdsIndex.
  "replica-target-fault",
  // REPLICATION: the replication pass's own execution health. Every per-tick deferral -- no
  // SIGNER_PRIVATE, fleet history unreadable, budget exhausted, repl-state writes failing, the
  // read-back verification sample cut short, a segment that vanished mid-sync -- would otherwise
  // exist only in Workers Logs, so replicas fleet-wide falling behind (worst case: discovered after
  // losing the primary bucket) would look exactly like replicas that are simply idle. Counts plus a
  // closed outcome only.
  "replication-pass",
  // SEAL: a record the crawl skips as changed-mid-crawl. The aggregate count alone tells support a
  // restore is missing objects but never which, and a persistent 403 / timeout / short read on the
  // resume range-read is otherwise indistinguishable from genuine content churn. Carries the closed
  // cause, the count, the one-way handles (safeMarkerAttribution's h:<12 hex>, never an object name),
  // and the partials the slice abandons (whose segments are orphaned).
  "record-skipped-changed",
  // SEAL: destination bytes the engine strands and would otherwise go uncounted -- a fan-out run's
  // whole scratch set on a WORM bucket (an empty catch), a merge give-up's leaked run-tree (outside
  // the GC ring), multipart parts (a boolean, never a count). This is the evidence behind "why does
  // the archive bucket grow far faster than the data". Closed class plus an integer count.
  "dest-stranding",
  // SEAL: the extra evidence a suspect seal-verification verdict needs -- a correlation digest (are
  // two recurring reader faults the same fault?), the failing shard/record ordinal (an integer index,
  // never a key), how many records verified clean before the fault (sampled is zeroed on a failure,
  // so a 50k-record run's verdict alone says nothing about how far it got), and the run's verify mode
  // (so a deliberately-disabled verification is distinguishable from a legacy-absent verdict).
  "verify-suspect",
  // SEAL: the requested vs effective seal mode of one run. A downpipe with fan-out enabled can
  // silently downgrade to serial (no sampler, a sample too small, splits that collapsed, a run below
  // the threshold) and still take days; the fan-out knobs are deliberately omitted from sealKnobs and
  // the run row carries no mode field, so this records it directly. Closed enums plus small ints.
  "seal-mode",
  // SEAL: the critical suspect-archive alert's routing fails, a case with no evidence elsewhere --
  // the fail-open path dies before or around the notify history write itself, so the pack's notify
  // history shows no attempt was ever made. This separates "the alert never went out" from "the alert
  // went out and only its history row was lost".
  "alert-routing-failed",
  // SEAL: the RUNLOG lock / CAS plane's own telemetry. A scheduler-DO hiccup can make a run park
  // "runlog contended" or fail "destination access error" while the destination is perfectly healthy
  // and the archive plus RUNLOG entry are provably committed (lock-release and heartbeat faults
  // coarsen to the destination class), which would otherwise send support to the wrong system
  // entirely. Counters only.
  "lock-plane",
  // RUN PRESSURE: the retry / throttle-park / RUNLOG-park / strike pressure one run spends, emitted
  // when the run resolves (ok or failed). Without this every one of these counters dies with the
  // transient run doc, so a run that rides out weeks of 503s before finally failing would be
  // indistinguishable from one that failed on a clean estate, and eight strikes with one cause would
  // look exactly like eight strikes with eight. Counts and closed classes only.
  "run-pressure",
  // CHECKPOINT: a stored checkpoint fails validation on resume. "checkpoint-unwrap-failed" above says
  // only that a resume state was unreadable; this says which field of it was malformed
  // (checkpointField, a closed engine vocabulary), which separates a tampered / corrupted DO write
  // from a signer rotation from an engine format fault. The run still fails exactly as it otherwise
  // would; this is the evidence behind "the big backup restarts from scratch every night".
  "checkpoint-invalid",
  // CHECKPOINT: the run's durable progress is thrown away. A resume that cannot open its checkpoint
  // abandons N slices and M already-sealed records and starts the next cadence from zero -- the
  // mechanism behind a backup that never completes -- and this records the size of that loss. Counts
  // only (slicesDiscarded / recordsDiscarded), read from the stored doc's still-plaintext progress
  // fields.
  "resume-abandoned",
  // CHECKPOINT: validateCheckpoint defaults a missing counter rather than rejecting it, so an engine
  // upgrade never strands an in-flight run. That forward-compatibility means a legacy doc (the
  // counter simply predates the field: benign) and a corrupted doc (the counter came back a
  // non-number and was silently coerced: a miscounted archive) would otherwise look identical.
  // legacyAbsent is that distinction; `coerced` counts how many counters were defaulted. Never the
  // corrupt value.
  "checkpoint-coerced",
  // FAN-OUT MERGE: the merge refuses to sign when a worker's scratch shard cannot be read back. Three
  // closed kinds because they are three different investigations:
  //   scratch-shard-missing     the object is gone from the destination (a lifecycle rule / bulk
  //                             delete ate the scratch prefix, or the worker never wrote it)
  //   scratch-hash-mismatch     the object is there but its sha384 does not match the worker's
  //                             report: the bytes changed underneath -- corruption or tamper, never
  //                             a lifecycle event
  //   scratch-preamble-mismatch the shard decrypted but names a different run/shard: a cross-run
  //                             mix-up
  // Each carries found/expected = the scratch shards merged OK so far vs the total the run declared,
  // so the shortfall can be sized. Shard ids stay out; `ordinal` is the shard's position in the merge
  // order.
  "scratch-shard-missing",
  "scratch-hash-mismatch",
  "scratch-preamble-mismatch",
  // FAN-OUT MERGE: the merged record total does not equal the count the run declares, so the merge
  // refuses to sign a count the shards do not hold. found = merged, expected = declared. Without this
  // the two integers exist only inside a raw thrown message that coarsens to a generic failed run
  // row, and the run produces no archive with no way to size the shortfall.
  "merge-count-mismatch",
  // FAN-OUT MERGE: the workers encounter fewer in-scope keys than the independent count pass found,
  // so the run refuses to sign short of its own authoritative key count. found = encountered,
  // expected = the count pass's total. The delta is what distinguishes a benign bulk deletion between
  // the count and the crawl from a real under-crawl (a range that silently dropped keys).
  "under-crawl",
  // OPEN SHARD: the carried open-shard buffer reloads short of the count the checkpoint declared, at
  // the serial finalise, at a fan-out worker's range finalise, or at the /start handoff. found = lines
  // loaded, expected = lines declared.
  "open-shard-count-mismatch",
  // OPEN SHARD: a wrapped open-shard batch is missing from inside the live range -- DO storage lost a
  // row, so the records it held can never be sealed. found = the missing sequence, expected = the end
  // of the live range.
  "open-batch-missing",
  // COMPLETION: the engine computes the run's true terminal outcome and the /complete POST does not
  // land, so the run's real verdict vanishes: the pack's run history then says "abandoned" (the lease
  // reclaim's generic resolution) for a run whose archive is complete and restores fine, or shows a
  // failed row for a fully-sealed buffered archive. This records the verdict that was lost (outcome
  // ok|failed), the coarse class of a failed one (attemptClasses, a closed member) and the cause
  // digest, so the row and the destination can be reconciled instead of the pack contradicting
  // itself.
  "completion-lost",
  // RUNLOG: the destination's RUNLOG is absent while this downpipe has prior runs on it (runlogIndex
  // > 0). The engine normalises this silently -- the signed root gets prevRunId=null (the history
  // chain restarts) and a prune finds nothing to supersede -- so a customer who repointed a downpipe
  // at a re-created or wrong bucket looks identical to a first run. `priorRuns` is the run index the
  // engine expected to chain onto; historyChainRestarted marks the root that signed null.
  "runlog-absent",
] as const;
export type SealFaultKind = (typeof SEAL_FAULT_KINDS)[number];
const SEAL_FAULT_KIND_SET: ReadonlySet<string> = new Set(SEAL_FAULT_KINDS);

// isSealFaultKind reports whether a kind is a member of the closed observe vocabulary. Exported so
// the poster can pre-gate a kind at the send side (otherwise a drifted engine-side kind is dropped
// silently by the DO sanitiser and nothing records that it happened), using the same set the DO
// re-gates on.
export function isSealFaultKind(kind: unknown): kind is SealFaultKind {
  return typeof kind === "string" && SEAL_FAULT_KIND_SET.has(kind);
}

// SEAL_FAULT_DROP_CLASSES is the closed vocabulary for why an observation never reached the ring,
// carried on the "observe-dropped" kind. Counters only: never the failed transport's message, never
// the drifted kind's string, never the malformed value.
// `malformed-count` is deliberately not a member: this vocabulary answers one question -- why an
// observation never reached the ring -- and a malformed count does not stop it reaching the ring.
// sanitiseSealFault clamps the count, persists the record, and stamps countsMalformed:true on it so
// a clamped-to-0 figure cannot be misread as a measured 0. That sentinel rides in the pack
// (support-sections-seal.ts); the observation itself is not dropped.
export const SEAL_FAULT_DROP_CLASSES = ["transport", "unknown-kind"] as const;
export type SealFaultDropClass = (typeof SEAL_FAULT_DROP_CLASSES)[number];
const SEAL_FAULT_DROP_CLASS_SET: ReadonlySet<string> = new Set(SEAL_FAULT_DROP_CLASSES);

// FANOUT_DISCARD_CLASSES is the closed vocabulary for why a coordinator discarded a worker report,
// carried on the "fanout-report-discarded" kind.
export const FANOUT_DISCARD_CLASSES = ["stale-phase", "duplicate-range", "out-of-bounds"] as const;
export type FanoutDiscardClass = (typeof FANOUT_DISCARD_CLASSES)[number];
const FANOUT_DISCARD_CLASS_SET: ReadonlySet<string> = new Set(FANOUT_DISCARD_CLASSES);

// PRUNE_DEFER_CLASSES is the closed vocabulary for why a retention prune abstained. The planner
// returns a free-text `deferred` sentence that only ever reaches a log line; this is the pack-bound
// class it is coarsened to at the recording site. "retained-run-unreadable" is the planner's own
// abstain (a retained run would not open, so the protected segment set was incomplete); "other" is
// the defensive arm so a future abstain reason can never leak as free text.
// "runlog-absent": the prune finds no RUNLOG on a destination that has prior runs, so it abstains as
// a no-op returning 0 -- indistinguishable, remotely, from "there was nothing to prune".
export const PRUNE_DEFER_CLASSES = ["retained-run-unreadable", "runlog-absent", "other"] as const;
export type PruneDeferClass = (typeof PRUNE_DEFER_CLASSES)[number];
const PRUNE_DEFER_CLASS_SET: ReadonlySet<string> = new Set(PRUNE_DEFER_CLASSES);

// REPLICA_FAULT_REASONS is the closed vocabulary for why one replica target could not be brought up
// to date. It replaces a collapsed two-string vocabulary ({"not configured", "unreachable"}) in
// which a post-copy integrity verify failure -- possible corruption in transit, the most serious
// thing replication can find -- would be indistinguishable from a network blip. Each member names a
// different investigation:
//   unreachable                 the target faulted on a transport/HTTP level (the honest "down")
//   not-configured              the target has no stored destination config (a removed destination under a live downpipe)
//   runlog-unreadable           the target's RUNLOG could not be read this tick
//   runlog-corrupt              the target's RUNLOG parsed but is structurally invalid (a manual repair is needed)
//   copy-failed                 an object copy (seg/ or run-tree) failed
//   integrity-verify-failed     the just-copied run FAILED its keyless post-copy attestation on the replica: the
//                               copy is CORRUPT, not merely absent, and re-copying is the remedy (never "check networking")
//   origin-runlog-unreadable    the run's ORIGIN RUNLOG could not be read, so nothing can be sourced from it
//   origin-run-missing          the run is absent from its own origin: it can never be mirrored (a permanent hole)
//   origin-dest-unconfigured    the run's ORIGIN destination has been removed: no credential can address the bytes
export const REPLICA_FAULT_REASONS = [
  "unreachable",
  "not-configured",
  "runlog-unreadable",
  "runlog-corrupt",
  "copy-failed",
  "integrity-verify-failed",
  "origin-runlog-unreadable",
  "origin-run-missing",
  "origin-dest-unconfigured",
] as const;
export type ReplicaFaultReason = (typeof REPLICA_FAULT_REASONS)[number];
const REPLICA_FAULT_REASON_SET: ReadonlySet<string> = new Set(REPLICA_FAULT_REASONS);

// REPLICATION_PASS_OUTCOMES is the closed vocabulary for how a whole replication pass ends.
export const REPLICATION_PASS_OUTCOMES = ["ok", "no-signer", "history-unreadable", "budget-exhausted"] as const;
export type ReplicationPassOutcome = (typeof REPLICATION_PASS_OUTCOMES)[number];
const REPLICATION_PASS_OUTCOME_SET: ReadonlySet<string> = new Set(REPLICATION_PASS_OUTCOMES);

// SKIP_CAUSES is the closed vocabulary for why a record was skipped as changed-mid-crawl. The point
// is that an infra fault (a persistent 403/timeout on the resume range-read, a short read) would
// otherwise be masked as ordinary content churn, making a restore that is missing objects look like
// a healthy source that happened to be busy.
export const SKIP_CAUSES = ["etag-changed", "size-changed", "no-etag", "range-read-failed", "short-read", "partial-mismatch"] as const;
export type SkipCause = (typeof SKIP_CAUSES)[number];
const SKIP_CAUSE_SET: ReadonlySet<string> = new Set(SKIP_CAUSES);

// STRAND_CLASSES is the closed vocabulary for destination bytes the engine strands and would
// otherwise go uncounted.
export const STRAND_CLASSES = ["scratch-delete-failed", "merge-orphan-runtree", "reclaim-list-failed", "multipart-parts"] as const;
export type StrandClass = (typeof STRAND_CLASSES)[number];
const STRAND_CLASS_SET: ReadonlySet<string> = new Set(STRAND_CLASSES);

// WORM_REFUSAL_CLASSES splits what would otherwise be a single wormBlocked boolean. A classifier
// that matches only "access ?denied" and "status 40[39]" would mark a plain, fixable credential
// fault as WORM -- steering support to "locked by design, nothing to fix" when the real fault is a
// rotated or under-scoped key. Three classes, three remedies:
//   worm-locked    a genuine Object-Lock / retention / compliance / governance refusal: irreducible by design
//   access-denied  a 403 / AccessDenied with no lock vocabulary: a credential or policy fault, and fixable
//   transient      anything else (a 5xx, a network fault): it will retry
export const WORM_REFUSAL_CLASSES = ["worm-locked", "access-denied", "transient"] as const;
export type WormRefusalClass = (typeof WORM_REFUSAL_CLASSES)[number];
const WORM_REFUSAL_CLASS_SET: ReadonlySet<string> = new Set(WORM_REFUSAL_CLASSES);

// VERIFY_MODES is the closed per-run verify posture, so an absent verdict is not ambiguous between
// "verification is switched off" and "this run predates the verdict field".
export const VERIFY_MODES = ["off", "tier-0", "sampled", "full"] as const;
export type VerifyMode = (typeof VERIFY_MODES)[number];
const VERIFY_MODE_SET: ReadonlySet<string> = new Set(VERIFY_MODES);

// SEAL_MODES is the closed requested/effective seal mode. The range count rides separately as an int.
export const SEAL_MODES = ["serial", "fanout"] as const;
export type SealMode = (typeof SEAL_MODES)[number];
const SEAL_MODE_SET: ReadonlySet<string> = new Set(SEAL_MODES);

// FANOUT_DOWNGRADE_REASONS is the closed vocabulary for why a run that asked for fan-out sealed
// serially.
export const FANOUT_DOWNGRADE_REASONS = ["no-sampler", "sample-too-small", "split-collapsed", "below-threshold"] as const;
export type FanoutDowngradeReason = (typeof FANOUT_DOWNGRADE_REASONS)[number];
const FANOUT_DOWNGRADE_REASON_SET: ReadonlySet<string> = new Set(FANOUT_DOWNGRADE_REASONS);

// ALERT_EVENT_CLASSES is the closed class of the alert whose routing failed. It is the engine's own
// notification event vocabulary, never a channel, an address or a URL.
// `backup-fail` is deliberately not a member: this class rides on the seal ring's
// `alert-routing-failed` kind, and the seal plane routes exactly one alert, the critical
// suspect-archive verdict (routeSealVerifyAlert). A backup failure alert is routed by the cron alert
// pass, a different plane with no seal ring to post to, and its delivery failures are already
// recorded where they happen (the DO's per-transition delivery feedback, notifyHealth.feedbackFails,
// and the undelivered-critical latch). Nothing that can post to this ring can ever be routing a
// backup-failure alert, so that member would promise an attribution the ring cannot make.
export const ALERT_EVENT_CLASSES = ["restore-test-fail", "other"] as const;
export type AlertEventClass = (typeof ALERT_EVENT_CLASSES)[number];
const ALERT_EVENT_CLASS_SET: ReadonlySet<string> = new Set(ALERT_EVENT_CLASSES);

// HANDOFF_REFUSAL_CLASSES is the closed vocabulary for why a seal-DO handoff was refused: the worker
// hands an over-budget run to the per-downpipe seal DO (/start), a fan-out run to the coordinator
// (/start-fanout), and a finished range back to the coordinator (/range-done). Without this, every
// one of those refusals arrives as `... refused: status 500`, which coarseRunError's generic status
// catch-all classifies as a destination access error -- so the failed row blames the customer's
// bucket (and DEST-1 lights the map's down-destination indicator) for a fault entirely inside the
// engine's own control plane. The refusing DO answers with a fixed, engine-authored error body;
// classifyHandoffRefusal reads it only to select a member here and returns that member. The body
// text itself never rides.
//   invalid-payload      the DO rejected the handoff document (a 400: an unparseable body, or an open-shard
//                        buffer whose length disagrees with the checkpoint's declared count)
//   worker-spawn-refused the coordinator could not spawn its fan-out workers
//   do-error             the DO answered but errored (a 5xx with no named cause)
//   unreachable          the fetch itself never got an answer (DO routing / outage)
export const HANDOFF_REFUSAL_CLASSES = ["invalid-payload", "worker-spawn-refused", "do-error", "unreachable"] as const;
export type HandoffRefusalClass = (typeof HANDOFF_REFUSAL_CLASSES)[number];
const HANDOFF_REFUSAL_CLASS_SET: ReadonlySet<string> = new Set(HANDOFF_REFUSAL_CLASSES);

/** isHandoffRefusalClass gates a value against the closed handoff-refusal vocabulary. Exported so
 * coarseRunError can re-gate the class it lifts out of a handoff message rather than trusting it. */
export function isHandoffRefusalClass(v: unknown): v is HandoffRefusalClass {
  return typeof v === "string" && HANDOFF_REFUSAL_CLASS_SET.has(v);
}

// WORKER_SPAWN_BODY / OPEN_SHARD_BODY are the two NAMED error bodies the seal DO answers a refused
// handoff with. They are ENGINE-AUTHORED constants (they carry no customer data by construction),
// and they are the only bodies classifyHandoffRefusal reads.
const WORKER_SPAWN_BODY = "fan-out worker spawn refused";
const OPEN_SHARD_BODY = "open-shard buffer does not match the checkpoint count";

/**
 * classifyHandoffRefusal folds a refused seal-DO handoff into a closed class. It reads the DO's
 * fixed error body only to select a member of HANDOFF_REFUSAL_CLASSES and returns that member: the
 * body -- and the status -- never leave this function, and nothing the caller can do makes a raw
 * string ride.
 *
 * @param status - the refusing DO's HTTP status (0 when the fetch itself threw: the DO never answered).
 * @param body - the DO's `error` field, when one could be read. Never retained.
 * @returns the closed refusal class.
 */
export function classifyHandoffRefusal(status: number, body?: string): HandoffRefusalClass {
  if (status === 0) return "unreachable";
  if (typeof body === "string") {
    if (body === WORKER_SPAWN_BODY) return "worker-spawn-refused";
    if (body === OPEN_SHARD_BODY) return "invalid-payload";
  }
  if (status === 400) return "invalid-payload";
  return "do-error";
}

// DIGEST_RE gates the one correlation field on this ring, causeDigest: 8 to 16 lower-case hex
// characters, the same convention slice.ts's causeDigest and the restore ring's errId use. A
// message, a key, an object name or a URL structurally cannot pass it, so the digest can carry
// correlation without carrying content.
const DIGEST_RE = /^[0-9a-f]{8,16}$/;
// HANDLE_RE gates a marker attribution handle: exactly the `h:<12 lower-case hex>` shape
// seal/marker.ts safeMarkerAttribution produces (a one-way SHA-384 prefix of a customer object name). A raw
// object key -- which carries slashes, dots, upper case or punctuation -- structurally cannot match.
const HANDLE_RE = /^h:[0-9a-f]{12}$/;
// HANDLES_MAX mirrors MARKER_ATTRIBUTION_MAX_PER_KIND: past 25 the attribution is a representative sample and
// the exact count still rides in `skipped`.
const HANDLES_MAX = 25;

// SEAL_FAULT_INT_MAX bounds a posted count so a malformed value can never bloat the ring (mirrors the
// reconcile-signal clamp). Real shard/reclaim counts are far below this; it is only an abuse ceiling.
const SEAL_FAULT_INT_MAX = 1_000_000_000;
// SEAL_FAULT_ID_MAX bounds a posted id length (a runId is a 26-char ULID; a downpipe id is short). It is
// the same defence the reconcile signal's destKey uses.
const SEAL_FAULT_ID_MAX = 128;

/**
 * One recorded seal-fault observation. Redaction-safe by construction: a closed kind, the customer's
 * own opaque ids, and non-negative ints / a boolean. It carries NO delete set, key, value, record
 * name or plaintext. Only the fields RELEVANT to a kind are set; the rest are absent (never emitted
 * as undefined).
 */
export interface SealFault {
  readonly kind: SealFaultKind;
  readonly at: number; // epoch ms the fault was observed
  readonly downpipeId?: string; // the customer's own downpipe id
  readonly runId?: string; // the customer's own opaque run id
  readonly found?: number; // shard-list-truncated: shards enumerated back at finalise
  readonly expected?: number; // shard-list-truncated: shards the checkpoint declared (found < expected)
  readonly cleaned?: number; // stale-shard-rows-cleaned: stale shard/open rows deleted at /start
  readonly reclaimed?: number; // orphan-root-reclaim / prune-partial-apply: objects the delete path actually deleted
  readonly wormBlocked?: boolean; // orphan-root-reclaim / prune-partial-apply: a delete was refused by WORM/object-lock (irreducible remainder)
  readonly deferClass?: PruneDeferClass; // prune-deferred: the closed reason class (never the planner's free-text sentence)
  readonly skipped?: number; // prune-runs-skipped: superseded runs silently excluded this pass (unreadable)
  readonly unparseableTime?: number; // prune-deferred / prune-runs-skipped: RUNLOG entries whose time did not parse (silently outside the keepDays window)
  readonly superseded?: number; // prune-partial-apply: RUNLOG entries the apply had already marked superseded when it failed
  readonly partial?: boolean; // prune-partial-apply: the apply committed the supersede but did not finish its deletes
  readonly rangeIndex?: number; // fanout-range-stalled / fanout-report-discarded: WHICH fan-out range (a small integer, never a key or a range bound)
  readonly discardClass?: FanoutDiscardClass; // fanout-report-discarded: the closed reason the coordinator dropped a worker report
  readonly dropClass?: SealFaultDropClass; // observe-dropped: the closed reason an observation never reached the ring
  readonly dropped?: number; // observe-dropped: how many observations that class swallowed since the last one that landed
  // countsMalformed marks a record whose posted count was NaN / negative / non-numeric and was therefore
  // CLAMPED to 0. Without it a malformed `found` reads back as an honest found:0 -- which is exactly the input a
  // severe-truncation escalation triggers on. The clamp is unchanged (fail-closed, bounded); this is the sentinel
  // that says the 0 is not a measurement. A strict boolean, set only when a clamp actually fired.
  readonly countsMalformed?: boolean;
  // ---- config-fault ----
  readonly configCode?: ConfigFaultCode; // WHICH prerequisite was missing (CLOSED vocabulary, config-fault.ts)
  readonly bindingName?: string; // the offending binding / env-var NAME: an operator label, gated to the bare
  // identifier charset by isConfigFaultName. Never a value, token, URL, endpoint or message. Absent for the
  // codes whose only candidate name would be a customer account id.
  // ---- run-pressure ----
  readonly retries?: number; // retries the data path actually TOOK across the whole run
  readonly retriesBySubsystem?: Partial<Record<RetrySubsystem, number>>; // which subsystem ate them (CLOSED keys)
  readonly throttleParks?: number; // consecutive throttle parks the run rode (the patient 503/429 ladder)
  readonly runlogParks?: number; // consecutive RUNLOG-contention parks the run rode
  readonly strikes?: number; // hard-fault strikes charged (MAX_SLICE_FAILURES is terminal)
  readonly probeFlaps?: number; // resume-liveness probe faults SWALLOWED between slices (silent until now)
  readonly throttledSubsystem?: RetrySubsystem; // WHO asked the run to slow down (CLOSED vocabulary)
  readonly attemptClasses?: SealAttemptClass[]; // ordered, capped (8) coarse cause of each strike (CLOSED)
  readonly outcome?: "ok" | "failed"; // how the pressured run RESOLVED (a run can succeed under heavy pressure)
  // ---- replica-target-fault ----
  readonly destinationId?: string; // WHICH replica target (the customer's own opaque destination id)
  readonly replicaReason?: ReplicaFaultReason; // the REAL reason (CLOSED), not the old {not configured, unreachable}
  readonly strandedRuns?: number; // runs that can NEVER be mirrored to this target (origin gone / run absent from its origin)
  // ---- replication-pass ----
  readonly passOutcome?: ReplicationPassOutcome; // how the whole pass ended (CLOSED)
  readonly deferredDownpipes?: number; // downpipes the pass could not even attempt this tick
  readonly stateWriteFailures?: number; // repl-state writes that failed (so the replication rows go stale with no cause)
  readonly verifySampleShortfall?: number; // read-back verification samples the budget CUT SHORT (copied-but-unverified segments)
  readonly segmentVanishDeferrals?: number; // segments that vanished mid-sync while their run was still live
  // ---- record-skipped-changed ----
  readonly skipCause?: SkipCause; // WHY the record was skipped (CLOSED): infra fault vs genuine churn
  readonly handles?: string[]; // one-way `h:<12 hex>` handles of the skipped records (never an object name), capped 25
  readonly partialsAbandoned?: number; // multi-GiB partial seals ABANDONED mid-record (their segments orphaned)
  // ---- dest-stranding ----
  readonly strandClass?: StrandClass; // WHICH stranding (CLOSED)
  readonly stranded?: number; // how many objects/parts were stranded (a COUNT, never a boolean)
  readonly wormRefusalClass?: WormRefusalClass; // orphan-root-reclaim / dest-stranding: the SPLIT of the old wormBlocked boolean
  readonly listFailed?: boolean; // orphan-root-reclaim: the reclaim LIST itself failed, so reclaimed:0 is not "nothing was there"
  // ---- verify-suspect ----
  readonly verifyMode?: VerifyMode; // the run's verify posture (CLOSED): "off" is now distinguishable from legacy-absent
  readonly causeDigest?: string; // 8-16 hex correlation digest: are two recurring reader faults the SAME fault?
  readonly ordinal?: number; // the FAILING shard/record index (an integer, never a key)
  readonly verifiedBeforeFail?: number; // records that verified CLEAN before the fault (sampled is zeroed on failure)
  readonly attemptsRun?: number; // whole verification attempts actually run
  readonly recovered?: boolean; // the verdict SELF-HEALED on a retry (a read-after-write lag, not corruption)
  // ---- seal-mode ----
  readonly requestedMode?: SealMode; // what the downpipe ASKED for (CLOSED)
  readonly effectiveMode?: SealMode; // what the run actually DID (CLOSED) -- the silent-serial-downgrade signal
  readonly fanoutRanges?: number; // the effective range count
  readonly downgradeReason?: FanoutDowngradeReason; // WHY fan-out downgraded to serial (CLOSED)
  readonly underCrawlChecked?: boolean; // whether the under-crawl defence actually RAN on this run
  readonly budgetOverrideForced?: boolean; // a legacy no-etag source forced an over-budget whole-record seal
  // ---- alert-routing-failed ----
  readonly alertEventClass?: AlertEventClass; // WHICH critical alert failed to route (CLOSED); never a channel or URL
  readonly historyWriteFailed?: boolean; // true = the alert WAS sent and only its history row was lost (the distinction)
  // ---- lock-plane ----
  readonly lockAcquireFaults?: number; // lock-acquire round-trips that FAULTED (a scheduler-plane blip, not a destination one)
  readonly lockWindowExhausted?: number; // the whole patient acquire window elapsed with the lock held
  readonly casExhausted?: number; // the lock-free CAS backstop exhausted under contention
  readonly sigPublishSkipped?: number; // the RUNLOG signature was NOT published (a concurrent winner moved the body)
  readonly releaseFaults?: number; // lock RELEASE faults: the archive + RUNLOG entry are COMMITTED, so this is never a data fault
  // ---- checkpoint-invalid / checkpoint-unwrap-failed / checkpoint-coerced / resume-abandoned ----
  readonly checkpointField?: CheckpointField; // WHICH field of the stored checkpoint was malformed (CLOSED)
  readonly unwrapCode?: CheckpointUnwrapCode; // WHICH unwrap failed (CLOSED): master vs open-shard batch vs a wrong-length plaintext
  readonly coerced?: number; // checkpoint-coerced: how many counters validateCheckpoint DEFAULTED
  readonly legacyAbsent?: boolean; // checkpoint-coerced: true = the counter was simply absent (a legacy doc); false = it was PRESENT and malformed (corruption)
  readonly slicesDiscarded?: number; // resume-abandoned: slices of durable progress thrown away when the run restarts from zero
  readonly recordsDiscarded?: number; // resume-abandoned: records already sealed by those slices
  // ---- runlog-absent ----
  readonly priorRuns?: number; // the RUNLOG index this run expected to chain onto (0 would be a genuine first run)
  readonly historyChainRestarted?: boolean; // the signed root went out with prevRunId=null despite prior runs
}

// isWormRefusal reports whether a destination-delete failure message is a WORM / Object-Lock refusal (the
// orphan-root-reclaim's irreducible-orphan case) rather than a transient flake. PURE; exported so the seal DO
// reclaim path and the validator pin the same classifier.
//
// It delegates to classifyWormRefusal rather than carrying its own regex, so the two callers can never
// disagree on the same failure message. `wormBlocked` (set from this function's result) rides into the
// support pack, so a wrong answer here would tell support "locked by design, nothing to fix" when the real
// fault is a rotated or under-scoped credential.
//
// Precedence is inherited rather than restated: classifyWormRefusal tests the lock vocabulary FIRST, so
// S3's own shape for a locked object, a lock refusal that also says "AccessDenied", still classifies as
// worm-locked. Only a bare 403 with no lock vocabulary classifies as a plain denial.
export function isWormRefusal(message: string): boolean {
  return classifyWormRefusal(message) === "worm-locked";
}

// WORM_LOCK_RE matches only the Object-Lock / retention / compliance / governance / immutability
// vocabulary. It deliberately excludes "access denied" / "forbidden" / "status 403" wording: folding
// that into the lock vocabulary would report a rotated or under-scoped credential to support as
// "locked by design, nothing to fix" when the real fault is a fixable key.
const WORM_LOCK_RE = /object.?lock|worm|retention|compliance|governance|immutab/i;
// DENIED_RE is the AUTHORISATION half: a 403/AccessDenied/forbidden with NO lock vocabulary in it.
const DENIED_RE = /access ?denied|forbidden|status 40[39]/i;

/**
 * classifyWormRefusal splits a refused destination delete into the three classes that have three different
 * remedies: a genuine Object-Lock refusal (irreducible by design), a plain authorisation denial (a
 * credential the operator can fix), or a transient fault (it will retry). It READS the failure message ONLY to
 * SELECT a member of WORM_REFUSAL_CLASSES and RETURNS that member: the message -- which can embed an object key
 * or a bucket -- never leaves this function.
 *
 * PRECEDENCE is load-bearing: the LOCK vocabulary is tested FIRST, so a genuine lock refusal that also says
 * "AccessDenied" (S3's own shape for a locked object) still classifies as worm-locked, while a bare 403 with no
 * lock vocabulary classifies as a plain denial.
 *
 * @param message - the delete failure message (never retained).
 * @returns the closed refusal class.
 */
export function classifyWormRefusal(message: string): WormRefusalClass {
  if (WORM_LOCK_RE.test(message)) return "worm-locked";
  if (DENIED_RE.test(message)) return "access-denied";
  return "transient";
}

// clampInt maps a posted value to a bounded non-negative integer (0 on absent / malformed / negative),
// so a ring entry can never carry a NaN / negative / unbounded count.
function clampInt(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), SEAL_FAULT_INT_MAX) : 0;
}

// clampId maps a posted id to a bounded string, or undefined when absent / not a non-empty string, so an
// absent id is OMITTED (never emitted as undefined, which canonicalJSON rejects on the pack path).
function clampId(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v.slice(0, SEAL_FAULT_ID_MAX) : undefined;
}

// isMalformedCount reports whether a posted count is not a measurement at all: present, but NaN / Infinity /
// negative / not a number. clampInt still folds it to a bounded 0 (fail-closed), but the record also carries
// countsMalformed:true so a diagnoser can tell "the guard measured zero" from "the guard's count did not
// survive the wire". A fractional or over-ceiling value is a clamp, not a malformation, so it is not flagged:
// it is a real measurement. PURE; it reads only the value's shape, never its content.
function isMalformedCount(v: unknown): boolean {
  if (v === undefined) return false;
  return !(typeof v === "number" && Number.isFinite(v) && v >= 0);
}

// anyMalformedCount reports whether ANY of the posted count fields was malformed, so the sanitiser can stamp the
// one countsMalformed sentinel on the record it is about to persist.
function anyMalformedCount(vs: readonly unknown[]): boolean {
  return vs.some(isMalformedCount);
}

/**
 * sanitiseSealFault validates + clamps ONE posted observation into a bounded, redaction-safe SealFault, or
 * null when the kind is not a member of the closed vocabulary (defence-in-depth: a bad internal value is
 * dropped, never persisted). Every int is clamped non-negative + bounded, the WORM flag is strict-boolean,
 * the ids are length-bounded, and `at` defaults to `now` (the DO clock, injected) on an absent / malformed
 * timestamp. Each optional field is set ONLY when it was posted (so an absent field is omitted, not zeroed):
 * the diagnosis reads a field only for the kind that produces it. PURE; the DO record path + the validator
 * share it so the sanitiser can never drift.
 */
export function sanitiseSealFault(
  body: {
    kind?: unknown;
    at?: unknown;
    downpipeId?: unknown;
    runId?: unknown;
    found?: unknown;
    expected?: unknown;
    cleaned?: unknown;
    reclaimed?: unknown;
    wormBlocked?: unknown;
    deferClass?: unknown;
    skipped?: unknown;
    unparseableTime?: unknown;
    superseded?: unknown;
    partial?: unknown;
    rangeIndex?: unknown;
    discardClass?: unknown;
    dropClass?: unknown;
    dropped?: unknown;
    configCode?: unknown;
    bindingName?: unknown;
    retries?: unknown;
    retriesBySubsystem?: unknown;
    throttleParks?: unknown;
    runlogParks?: unknown;
    strikes?: unknown;
    probeFlaps?: unknown;
    throttledSubsystem?: unknown;
    attemptClasses?: unknown;
    outcome?: unknown;
    destinationId?: unknown;
    replicaReason?: unknown;
    strandedRuns?: unknown;
    passOutcome?: unknown;
    deferredDownpipes?: unknown;
    stateWriteFailures?: unknown;
    verifySampleShortfall?: unknown;
    segmentVanishDeferrals?: unknown;
    skipCause?: unknown;
    handles?: unknown;
    partialsAbandoned?: unknown;
    strandClass?: unknown;
    stranded?: unknown;
    wormRefusalClass?: unknown;
    listFailed?: unknown;
    verifyMode?: unknown;
    causeDigest?: unknown;
    ordinal?: unknown;
    verifiedBeforeFail?: unknown;
    attemptsRun?: unknown;
    recovered?: unknown;
    requestedMode?: unknown;
    effectiveMode?: unknown;
    fanoutRanges?: unknown;
    downgradeReason?: unknown;
    underCrawlChecked?: unknown;
    budgetOverrideForced?: unknown;
    alertEventClass?: unknown;
    historyWriteFailed?: unknown;
    lockAcquireFaults?: unknown;
    lockWindowExhausted?: unknown;
    casExhausted?: unknown;
    sigPublishSkipped?: unknown;
    releaseFaults?: unknown;
    checkpointField?: unknown;
    unwrapCode?: unknown;
    coerced?: unknown;
    legacyAbsent?: unknown;
    slicesDiscarded?: unknown;
    recordsDiscarded?: unknown;
    priorRuns?: unknown;
    historyChainRestarted?: unknown;
  },
  now: number,
): SealFault | null {
  if (!isSealFaultKind(body.kind)) return null;
  const downpipeId = clampId(body.downpipeId);
  const runId = clampId(body.runId);
  // The fan-out discard reason is gated on its closed vocabulary (an out-of-vocabulary value is dropped,
  // never carried as text), and the range index is a clamped small integer.
  const discardClass: FanoutDiscardClass | undefined = typeof body.discardClass === "string" && FANOUT_DISCARD_CLASS_SET.has(body.discardClass) ? (body.discardClass as FanoutDiscardClass) : undefined;
  // The observe-drop reason is gated the same way. An unknown drop class is dropped rather than coerced,
  // so a drifted internal value can never invent a class the diagnosis reasons over.
  const dropClass: SealFaultDropClass | undefined = typeof body.dropClass === "string" && SEAL_FAULT_DROP_CLASS_SET.has(body.dropClass) ? (body.dropClass as SealFaultDropClass) : undefined;
  // One sentinel for the whole record. Every count below is still clamped to a bounded non-negative int
  // (fail-closed), but a clamp that fired on a malformed input is visible instead of reading as a real 0.
  const countsMalformed = anyMalformedCount([body.found, body.expected, body.cleaned, body.reclaimed, body.skipped, body.unparseableTime, body.superseded, body.rangeIndex, body.dropped, body.retries, body.throttleParks, body.runlogParks, body.strikes, body.probeFlaps, body.strandedRuns, body.deferredDownpipes, body.stateWriteFailures, body.verifySampleShortfall, body.segmentVanishDeferrals, body.partialsAbandoned, body.stranded, body.ordinal, body.verifiedBeforeFail, body.fanoutRanges, body.lockAcquireFaults, body.lockWindowExhausted, body.casExhausted, body.sigPublishSkipped, body.releaseFaults, body.coerced, body.slicesDiscarded, body.recordsDiscarded, body.priorRuns]);
  // The config-fault evidence is gated on its closed vocabulary, and the binding/env-var name on the bare
  // OPERATOR-LABEL charset (isConfigFaultName). This is the redaction chokepoint for the one field on the whole
  // ring that is not an enum or an int: a value, a token, a URL or a message shape structurally cannot pass it,
  // so even a drifted call site that passed a customer string would have it dropped here, never persisted.
  const configCode: ConfigFaultCode | undefined = isConfigFaultCode(body.configCode) ? body.configCode : undefined;
  const bindingName: string | undefined = isConfigFaultName(body.bindingName) ? body.bindingName : undefined;
  // The pressure evidence. Every subsystem key and every attempt class is re-gated against its closed
  // vocabulary (an out-of-vocabulary member is dropped, never coerced and never carried as text), the class list
  // is capped at the strike ceiling, and each count is clamped by the shared clampInt.
  const throttledSubsystem: RetrySubsystem | undefined = isRetrySubsystem(body.throttledSubsystem) ? body.throttledSubsystem : undefined;
  const attemptClasses: SealAttemptClass[] | undefined = Array.isArray(body.attemptClasses) ? body.attemptClasses.filter(isSealAttemptClass).slice(0, ATTEMPT_CLASSES_MAX) : undefined;
  const retriesBySubsystem: Partial<Record<RetrySubsystem, number>> | undefined = sanitiseBySubsystem(body.retriesBySubsystem);
  const outcome: "ok" | "failed" | undefined = body.outcome === "ok" || body.outcome === "failed" ? body.outcome : undefined;
  // Every enum below is re-gated against its closed vocabulary here -- an out-of-vocabulary value is
  // dropped, never coerced and never carried as text -- and every count goes through the shared clampInt. This
  // is the redaction chokepoint for this evidence: nothing on these paths can carry a message, a key, a bucket,
  // an endpoint or a customer value, because the only string-shaped fields are (a) the customer's own opaque
  // ids (the class the pack already carries), (b) closed enum members, and (c) the two hash-shaped fields
  // below, which are gated to hex.
  const replicaReason: ReplicaFaultReason | undefined = gate(body.replicaReason, REPLICA_FAULT_REASON_SET);
  const passOutcome: ReplicationPassOutcome | undefined = gate(body.passOutcome, REPLICATION_PASS_OUTCOME_SET);
  const skipCause: SkipCause | undefined = gate(body.skipCause, SKIP_CAUSE_SET);
  const strandClass: StrandClass | undefined = gate(body.strandClass, STRAND_CLASS_SET);
  const wormRefusalClass: WormRefusalClass | undefined = gate(body.wormRefusalClass, WORM_REFUSAL_CLASS_SET);
  const verifyMode: VerifyMode | undefined = gate(body.verifyMode, VERIFY_MODE_SET);
  const requestedMode: SealMode | undefined = gate(body.requestedMode, SEAL_MODE_SET);
  const effectiveMode: SealMode | undefined = gate(body.effectiveMode, SEAL_MODE_SET);
  const downgradeReason: FanoutDowngradeReason | undefined = gate(body.downgradeReason, FANOUT_DOWNGRADE_REASON_SET);
  const alertEventClass: AlertEventClass | undefined = gate(body.alertEventClass, ALERT_EVENT_CLASS_SET);
  // The checkpoint evidence is re-gated against its closed vocabularies (checkpoint-fault.ts). An
  // out-of-vocabulary field or unwrap code is dropped, never coerced and never carried as text, so a drifted
  // call site can never invent a field name -- and the corrupt value has no field on this record to ride in.
  const checkpointField: CheckpointField | undefined = isCheckpointField(body.checkpointField) ? body.checkpointField : undefined;
  const unwrapCode: CheckpointUnwrapCode | undefined = isCheckpointUnwrapCode(body.unwrapCode) ? body.unwrapCode : undefined;
  // destinationId is the customer's OWN opaque destination id -- the same redaction class as downpipeId/runId,
  // which the pack already carries in downpipes[] and replication[]. Length-clamped like the others.
  const destinationId = clampId(body.destinationId);
  // causeDigest is accepted only as 8-16 lower-case hex: a correlation handle, never content.
  const causeDigest = typeof body.causeDigest === "string" && DIGEST_RE.test(body.causeDigest) ? body.causeDigest : undefined;
  // handles are accepted only as the one-way `h:<12 hex>` shape seal/marker.ts produces. A raw object key
  // (slashes, dots, upper case) structurally cannot pass, so the pack can say which objects were skipped without
  // ever carrying the customer's object names. Deduplicated and capped.
  const handles = sanitiseHandles(body.handles);
  // deferClass is gated on the closed vocabulary: an out-of-vocabulary value (or a leaked sentence) becomes
  // "other", never free text. This is the redaction chokepoint for the prune abstain reason.
  const deferClass: PruneDeferClass | undefined =
    body.deferClass === undefined ? undefined : typeof body.deferClass === "string" && PRUNE_DEFER_CLASS_SET.has(body.deferClass) ? (body.deferClass as PruneDeferClass) : "other";
  return {
    kind: body.kind as SealFaultKind,
    at: typeof body.at === "number" && Number.isFinite(body.at) ? body.at : now,
    ...(downpipeId !== undefined ? { downpipeId } : {}),
    ...(runId !== undefined ? { runId } : {}),
    ...(body.found !== undefined ? { found: clampInt(body.found) } : {}),
    ...(body.expected !== undefined ? { expected: clampInt(body.expected) } : {}),
    ...(body.cleaned !== undefined ? { cleaned: clampInt(body.cleaned) } : {}),
    ...(body.reclaimed !== undefined ? { reclaimed: clampInt(body.reclaimed) } : {}),
    ...(body.wormBlocked !== undefined ? { wormBlocked: body.wormBlocked === true } : {}),
    ...(deferClass !== undefined ? { deferClass } : {}),
    ...(body.skipped !== undefined ? { skipped: clampInt(body.skipped) } : {}),
    ...(body.unparseableTime !== undefined ? { unparseableTime: clampInt(body.unparseableTime) } : {}),
    ...(body.superseded !== undefined ? { superseded: clampInt(body.superseded) } : {}),
    ...(body.partial !== undefined ? { partial: body.partial === true } : {}),
    ...(body.rangeIndex !== undefined ? { rangeIndex: clampInt(body.rangeIndex) } : {}),
    ...(discardClass !== undefined ? { discardClass } : {}),
    ...(dropClass !== undefined ? { dropClass } : {}),
    ...(body.dropped !== undefined ? { dropped: clampInt(body.dropped) } : {}),
    ...(configCode !== undefined ? { configCode } : {}),
    ...(bindingName !== undefined ? { bindingName } : {}),
    ...(body.retries !== undefined ? { retries: clampInt(body.retries) } : {}),
    ...(retriesBySubsystem !== undefined ? { retriesBySubsystem } : {}),
    ...(body.throttleParks !== undefined ? { throttleParks: clampInt(body.throttleParks) } : {}),
    ...(body.runlogParks !== undefined ? { runlogParks: clampInt(body.runlogParks) } : {}),
    ...(body.strikes !== undefined ? { strikes: clampInt(body.strikes) } : {}),
    ...(body.probeFlaps !== undefined ? { probeFlaps: clampInt(body.probeFlaps) } : {}),
    ...(throttledSubsystem !== undefined ? { throttledSubsystem } : {}),
    ...(attemptClasses !== undefined ? { attemptClasses } : {}),
    ...(outcome !== undefined ? { outcome } : {}),
    ...(countsMalformed ? { countsMalformed: true } : {}),
    ...(destinationId !== undefined ? { destinationId } : {}),
    ...(replicaReason !== undefined ? { replicaReason } : {}),
    ...(body.strandedRuns !== undefined ? { strandedRuns: clampInt(body.strandedRuns) } : {}),
    ...(passOutcome !== undefined ? { passOutcome } : {}),
    ...(body.deferredDownpipes !== undefined ? { deferredDownpipes: clampInt(body.deferredDownpipes) } : {}),
    ...(body.stateWriteFailures !== undefined ? { stateWriteFailures: clampInt(body.stateWriteFailures) } : {}),
    ...(body.verifySampleShortfall !== undefined ? { verifySampleShortfall: clampInt(body.verifySampleShortfall) } : {}),
    ...(body.segmentVanishDeferrals !== undefined ? { segmentVanishDeferrals: clampInt(body.segmentVanishDeferrals) } : {}),
    ...(skipCause !== undefined ? { skipCause } : {}),
    ...(handles !== undefined ? { handles } : {}),
    ...(body.partialsAbandoned !== undefined ? { partialsAbandoned: clampInt(body.partialsAbandoned) } : {}),
    ...(strandClass !== undefined ? { strandClass } : {}),
    ...(body.stranded !== undefined ? { stranded: clampInt(body.stranded) } : {}),
    ...(wormRefusalClass !== undefined ? { wormRefusalClass } : {}),
    ...(body.listFailed !== undefined ? { listFailed: body.listFailed === true } : {}),
    ...(verifyMode !== undefined ? { verifyMode } : {}),
    ...(causeDigest !== undefined ? { causeDigest } : {}),
    ...(body.ordinal !== undefined ? { ordinal: clampInt(body.ordinal) } : {}),
    ...(body.verifiedBeforeFail !== undefined ? { verifiedBeforeFail: clampInt(body.verifiedBeforeFail) } : {}),
    ...(body.attemptsRun !== undefined ? { attemptsRun: clampInt(body.attemptsRun) } : {}),
    ...(body.recovered !== undefined ? { recovered: body.recovered === true } : {}),
    ...(requestedMode !== undefined ? { requestedMode } : {}),
    ...(effectiveMode !== undefined ? { effectiveMode } : {}),
    ...(body.fanoutRanges !== undefined ? { fanoutRanges: clampInt(body.fanoutRanges) } : {}),
    ...(downgradeReason !== undefined ? { downgradeReason } : {}),
    ...(body.underCrawlChecked !== undefined ? { underCrawlChecked: body.underCrawlChecked === true } : {}),
    ...(body.budgetOverrideForced !== undefined ? { budgetOverrideForced: body.budgetOverrideForced === true } : {}),
    ...(alertEventClass !== undefined ? { alertEventClass } : {}),
    ...(body.historyWriteFailed !== undefined ? { historyWriteFailed: body.historyWriteFailed === true } : {}),
    ...(body.lockAcquireFaults !== undefined ? { lockAcquireFaults: clampInt(body.lockAcquireFaults) } : {}),
    ...(body.lockWindowExhausted !== undefined ? { lockWindowExhausted: clampInt(body.lockWindowExhausted) } : {}),
    ...(body.casExhausted !== undefined ? { casExhausted: clampInt(body.casExhausted) } : {}),
    ...(body.sigPublishSkipped !== undefined ? { sigPublishSkipped: clampInt(body.sigPublishSkipped) } : {}),
    ...(body.releaseFaults !== undefined ? { releaseFaults: clampInt(body.releaseFaults) } : {}),
    ...(checkpointField !== undefined ? { checkpointField } : {}),
    ...(unwrapCode !== undefined ? { unwrapCode } : {}),
    ...(body.coerced !== undefined ? { coerced: clampInt(body.coerced) } : {}),
    ...(body.legacyAbsent !== undefined ? { legacyAbsent: body.legacyAbsent === true } : {}),
    ...(body.slicesDiscarded !== undefined ? { slicesDiscarded: clampInt(body.slicesDiscarded) } : {}),
    ...(body.recordsDiscarded !== undefined ? { recordsDiscarded: clampInt(body.recordsDiscarded) } : {}),
    ...(body.priorRuns !== undefined ? { priorRuns: clampInt(body.priorRuns) } : {}),
    ...(body.historyChainRestarted !== undefined ? { historyChainRestarted: body.historyChainRestarted === true } : {}),
  };
}

// gate is the ONE closed-vocabulary membership test the new evidence uses: a member rides, anything else is
// DROPPED (never coerced, never carried as text). Generic over the enum type so a caller cannot widen it.
function gate<T extends string>(v: unknown, allowed: ReadonlySet<string>): T | undefined {
  return typeof v === "string" && allowed.has(v) ? (v as T) : undefined;
}

// sanitiseHandles gates the attribution list: only the one-way `h:<12 hex>` shape survives, deduplicated
// and capped. A raw object key can never pass the shape gate, so this seam cannot leak a customer name even if a
// future write site regressed and posted one.
function sanitiseHandles(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: string[] = [];
  for (const raw of v) {
    if (typeof raw !== "string" || !HANDLE_RE.test(raw) || out.includes(raw)) continue;
    out.push(raw);
    if (out.length >= HANDLES_MAX) break;
  }
  return out.length > 0 ? out : undefined;
}

// sanitiseBySubsystem gates the per-subsystem retry tally: only closed vocabulary keys survive, each
// value is clamped to a bounded non-negative int, and an absent / non-object input yields undefined (the field
// is then omitted rather than emitted as an empty object). A drifted key is dropped, never carried.
function sanitiseBySubsystem(v: unknown): Partial<Record<RetrySubsystem, number>> | undefined {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return undefined;
  const out: Partial<Record<RetrySubsystem, number>> = {};
  for (const [k, n] of Object.entries(v as Record<string, unknown>)) {
    if (!isRetrySubsystem(k)) continue;
    out[k] = clampInt(n);
  }
  return Object.keys(out).length > 0 ? out : undefined;
}
