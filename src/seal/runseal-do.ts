import { doURL, schedulerStub } from "../admin/router-helpers.ts";
import type { RuntimeDestConfig } from "../dest/factory.ts";
import type { Destination } from "../dest/types.ts";
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import type { DownpipeConfig, DownpipeState } from "../sched/scheduler-do.ts";
import { hasLivenessProbe, SourceResourceMissingError } from "../sources/source-errors.ts";
import { hasKeySampler, type Selector } from "../sources/types.ts";
import { budgetFromEnv, type SliceBudget } from "./budget.ts";
import { type CheckpointCounts, openOpenShardBatch, openStoredCheckpoint, type RunCheckpoint, type StoredRunCheckpoint, sealCheckpointForStorage, sealOpenShardBatch, unwrapMaster, validateCheckpoint, zeroCounts } from "./checkpoint.ts";
import { checkpointCoercions, checkpointInvalidOf, checkpointUnwrapOf } from "./checkpoint-fault.ts";
import { configFaultOf } from "./config-fault.ts";
import { addCheckpointCounts, chunkLines, countPage, deleteScratchShards, FANOUT_MAX_RANGE_KEYS, FANOUT_MAX_RANGES, type FanoutPlanScan, type FanoutRange, finishCount, type MergeState, type MergeStepResult, mergeStep, newMergeState, newPlanScan, type RangeDone, rangesFromSplitKeys, sealRangeOpenShard, stridePage, zeroFanoutCounts } from "./fanout.ts";
import { RunlogContendedError } from "./pipeline.ts";
import { runTreePrefix } from "./prune.ts";
import { beginRunFaults, reportRunFaults } from "./run-fault-report.ts";
import { dominantSubsystem, foldRetryMeter, hasPressure, type RunPressure, sealAttemptClass, throttledSubsystemOf, withAttemptClass, withProbeFlap, withThrottledSubsystem } from "./run-pressure.ts";
import {
  cfConfigToken,
  DOC_KEY,
  downDestinationFlag,
  fanoutMinRecords,
  fanoutRangeCount,
  json,
  MAX_SLICE_FAILURES,
  multipartAbortFlag,
  NEXT_SLICE_DELAY_MS,
  OPEN_PREFIX,
  openBatchKey,
  RETRY_BASE_MS,
  RETRY_CAP_MS,
  requireEnv,
  runlogLockVia,
  runSealVerification,
  SHARD_LIST_MAX_PAGES,
  SHARD_LIST_PAGE,
  SHARD_PREFIX,
  sliceDepsFromEnv,
  THROTTLE_BASE_MS,
  THROTTLE_CAP_MS,
  throttleMaxYields,
} from "./runstate-helpers.ts";
import { postSealFault, type SealFaultPost } from "./seal-fault-post.ts";
import { classifyWormRefusal, isWormRefusal, type WormRefusalClass } from "./seal-faults.ts";
import { causeDigest, coarseRunError, finaliseRun, redactedRunError, runSlice, type ShardEntry, type SliceDeps, type SliceResult } from "./slice.ts";
import type { SealVerification } from "./verify-at-seal.ts";

// BACKOFF_EXP_CAP clamps the exponent before the 2 ** shift so a large attempt count cannot evaluate
// 2 ** n to Infinity. The Math.min against the *_CAP_MS ceilings already bounds the resulting delay, so
// this only makes the overflow-safety explicit; the capped delay is reached long before this cap bites.
const BACKOFF_EXP_CAP = 20;

// COORDINATOR_HEARTBEAT_MS is how often a fan-out COORDINATOR re-arms while WAITING for its workers, so the
// scheduler in-flight lease is kept warm through a long parallel seal (the workers do not heartbeat; only
// the coordinator holds the lease). 30 s is well inside the lease-reclaim window while not busy-spinning.
const COORDINATOR_HEARTBEAT_MS = 30_000;
// MERGE_BATCH_LINES caps how many renumbered manifest lines the coordinator wraps into one carried-merge DO
// batch, so each batch stays under the ~128 KiB DO value cap (256 lines * ~300 B ~= 77 KiB). The carried
// buffer is < shardMax lines, so it spans at most a handful of batches.
const MERGE_BATCH_LINES = 256;

// CompleteOptions groups the optional outcome detail (failure reason, the failover-chosen origin
// id and the at-seal verification) so complete() keeps to the 4-parameter guardrail.
interface CompleteOptions {
  error?: string;
  // 12-hex correlation digest of the raw fault (causeDigest(m)), stamped on a FAILED row so it reads back
  // byte-identical to the `[cause <hex>]` this DO ladder already logs via redactedRunError(m), letting
  // support join the give-up row to its Logpush lines. One-way SHA-384 prefix; never the raw message.
  causeDigest?: string;
  destinationId?: string;
  sealVerification?: SealVerification;
  // The destination this invocation sealed through, so the completion body can carry the SAME two
  // destination-attributed signals the inline path stamps (gap G062): the stranded-multipart-parts boolean
  // (multipartAbortFlag) on either outcome, and the proven-down destination id (downDestinationFlag) on a
  // destination-access failure. Absent when the invocation faulted before the destination was built (nothing
  // was written, so nothing can be stranded and no bucket can be blamed).
  dest?: Destination;
}

interface RunDoc {
  config: DownpipeConfig;
  // The AT-REST checkpoint form: the resume cursor (which embeds the last-committed
  // record NAME in its source token) is wrapped under the checkpoint wrap key before it
  // is persisted (NC-1). The in-memory RunCheckpoint with the plaintext cursor exists
  // only within an invocation.
  checkpoint: StoredRunCheckpoint;
  attempt: number; // consecutive HARD slice failures (reset on progress); strikes toward MAX_SLICE_FAILURES
  // throttleAttempt is the SEPARATE patient ladder for destination/source throttling (503/429): it counts
  // consecutive throttle waits, backs off, and parks the run (checkpoint preserved) without ever charging
  // `attempt`. Optional/absent = 0; a successful slice writes a fresh doc without it, which resets it.
  throttleAttempt?: number;
  // runlogAttempt is the SEPARATE patient ladder for RUNLOG write CONTENTION (SCALE-3): when another
  // finaliser holds the same destination's RUNLOG, this run parks (checkpoint preserved) and resumes, the
  // same shape as throttleAttempt and never charging the hard-fault `attempt`. Optional/absent = 0; a
  // successful finalise clears the doc, which resets it.
  runlogAttempt?: number;
  // The console-set destination PINNED at handoff (absent/null = the env destination).
  // Pinning is the correctness rule: a mid-run destination change must never split one
  // run across two stores, so every alarm slice writes through the destination the run
  // STARTED with. The credential rests here only for the run's life (cleanup deletes the
  // doc); the scheduler DO record remains the durable custody, exactly like the wrapped
  // master beside it.
  destConfig?: RuntimeDestConfig | null;
  // The failover-chosen destinationId this run sealed to, pinned beside destConfig so the resumed
  // seal reports the same origin at /complete (the destination that now holds this run).
  destinationId?: string;
  // Fix 2a open-shard spanning: the half-open live range [openBatchSeqStart, openBatchSeqEnd) of
  // append-only AES-256-GCM-wrapped open-shard batches in DO storage (open:<seq>). The seq is monotonic
  // across the run; a flush advances start past the consumed batches and writes the leftover at a fresh
  // seq, so the live batches are always exactly the carried (unflushed) buffer. Absent = {0,0} (no
  // buffered lines, e.g. a legacy in-flight doc). The line BYTES rest in the batches; only the COUNT
  // rides in the checkpoint, cross-checked against the re-loaded batch lines at finalise.
  openBatchSeqStart?: number;
  openBatchSeqEnd?: number;
  // coordinatorId (Fix 2b fan-out) is set ONLY on a WORKER doc: the per-downpipe DO id of the COORDINATOR
  // this worker reports its finished range to (POST /range-done). Its presence is the discriminator that
  // routes the alarm to the worker path (composite-id seal + /range-done) rather than the serial path
  // (signed root + /complete). Absent on every serial run, so the serial alarm is untouched.
  coordinatorId?: string;
  // pressure (gap G143) accumulates the retry / park / strike cost this run has already paid, so it SURVIVES
  // the eviction of the isolate that paid it and is still there when the run finally resolves. Every counter
  // is bounded and every class is a closed enum (run-pressure.ts); nothing here is read by the seal path, only
  // written by it. Absent on a clean run (nothing was spent), which is the steady state.
  pressure?: RunPressure;
}

// RunBase is the run identity shared with the fan-out coordinator and every worker (the fields a normal
// run carries in its checkpoint, hoisted so the coordinator -- which holds no per-record checkpoint until
// the merge -- and the workers all stamp the SAME runId/index/window/prev into their output).
export interface RunBase {
  runId: string;
  runlogIndex: number;
  prevRunId: string | null;
  downpipeId: string;
  downpipeName: string;
  cadence: string;
  sourceType: string;
  startedAt: string;
}

// StartFanout is the COORDINATOR's POST /start-fanout payload (from sealRunSliced when planFanout fans a
// run out): the downpipe config, the run identity, the base record selector, the ONE wrapped run master to
// distribute to every worker (so all derive identical keys), and the pinned destination. `ranges` is the
// DIRECT plan (present = the front-sample partition; the coordinator spawns those workers immediately);
// ABSENT = a SCAN plan (Fix 2b H2) where the namespace is larger than the front sample, so the coordinator
// first runs a sliced count-then-stride to size BALANCED ranges before spawning. It holds the scheduler lease.
export interface StartFanout {
  config: DownpipeConfig;
  base: RunBase;
  selector: { include: string[]; exclude: string[] };
  wrappedMaster: { iv: string; ct: string };
  ranges?: FanoutRange[];
  destConfig?: RuntimeDestConfig | null;
  destinationId?: string;
}

// StartRange is a WORKER's POST /start-range payload: its range index + half-open range, the SHARED wrapped
// master (NEVER re-generated -- an independently-generated master would derive different content addresses
// and corrupt the merge), the coordinator id to report to, and the pinned destination.
export interface StartRange {
  config: DownpipeConfig;
  base: RunBase;
  selector: { include: string[]; exclude: string[] };
  range: FanoutRange;
  rangeIndex: number;
  wrappedMaster: { iv: string; ct: string };
  coordinatorId: string;
  destConfig?: RuntimeDestConfig | null;
  destinationId?: string;
}

// RangeFailed is the WORKER -> COORDINATOR terminal-failure report (POST /range-failed). Gap G062 widened it
// from a bare coarse `reason` to the same evidence set an INLINE failure carries, because the fan-out
// population is exactly the one whose failures were least diagnosable:
//   - reason      : the coarse, closed failure class the worker's ladder resolved (coarseRunError), unchanged.
//   - causeDigest : the 12-hex one-way SHA-384 prefix of the RAW fault, computed in the WORKER at the fault's
//                   detection point. The raw message never crosses the wire; the digest joins the failed run row
//                   to the customer's own Logpush `[cause <hex>]` line. Re-gated by isCauseDigest on arrival.
//   - multipartAbortFailed : a FAILED multipart upload whose best-effort abort ALSO failed on this worker's
//                   destination (invisible stranded part-storage). A boolean; never a key or a count.
// Every field is a closed class, a hex digest or a boolean: no message, key, value or bucket ever rides.
export interface RangeFailed {
  rangeIndex?: number;
  reason?: string;
  causeDigest?: string;
  multipartAbortFailed?: true;
}

// CAUSE_DIGEST_RE pins the shape causeDigest() emits: exactly 12 lowercase hex characters. The coordinator
// re-gates a worker-supplied digest against it before stamping it on the run row (a cross-DO body is a trust
// boundary), so a drifted or hostile worker can never smuggle free text into the pack through this field.
const CAUSE_DIGEST_RE = /^[0-9a-f]{12}$/;
function isCauseDigest(v: unknown): v is string {
  return typeof v === "string" && CAUSE_DIGEST_RE.test(v);
}

// CoordinatorDoc is the per-downpipe DO's stored state while it COORDINATES a fan-out run (DOC_KEY; the
// `kind` field discriminates it from a serial RunDoc). It holds the single lease (heartbeats while waiting),
// the run identity + wrapped master, the ranges + each range's /range-done report, the summed global
// counts, the phase, and -- once every range is in -- the sliced-merge checkpoint. The carried merge line
// buffer rests as wrapped OPEN batches (mergeOpenSeqStart/End), exactly like a serial run's open shard.
export interface CoordinatorDoc {
  kind: "coordinator";
  config: DownpipeConfig;
  base: RunBase;
  selector: { include: string[]; exclude: string[] };
  wrappedMaster: { iv: string; ct: string };
  ranges: FanoutRange[];
  doneRanges: (RangeDone | null)[];
  counts: CheckpointCounts;
  phase: "plan" | "await" | "merge";
  // Fix 2b H2 PLAN phase (the SLICED, keys-only balanced planner). planScan is the bounded-memory
  // count-then-stride state; planToken is the source's opaque resume token for the current sub-pass scan.
  // Both present only while phase==="plan" (a namespace larger than the front sample); a DIRECT-plan run
  // skips straight to "await" with ranges already set. ranges/doneRanges are empty until the STRIDE pass
  // completes and the coordinator spawns the balanced workers (beginAwait).
  planScan?: FanoutPlanScan;
  planToken?: string | null;
  // plannedRecordTotal (defense-in-depth under-crawl cross-check): the AUTHORITATIVE in-scope key count the
  // COUNT pass found (FanoutPlanScan.total), captured when the SCAN plan completes (beginAwait) and carried
  // onto the merge (newMergeState) so the finalise can cross-check the workers' summed reports against it and
  // fail loud on a shortfall. Present ONLY on a SCAN-planned run (a DIRECT plan fanned out from the front
  // sample with no count pass, so there is no independent total); absent then, and the cross-check is skipped.
  plannedRecordTotal?: number;
  merge?: MergeState;
  mergeOpenSeqStart?: number;
  mergeOpenSeqEnd?: number;
  attempt: number;
  // throttleAttempt is the merge's PATIENT throttle/contention parking ladder (separate from the hard-fault
  // `attempt` strikes), bounded by throttleMaxYields so a destination down for the whole parking window
  // gives up honestly instead of parking the coordinator (which holds the lease) forever.
  throttleAttempt?: number;
  // H1 no-progress strike ladder (await phase). progress[i] is range i's worker-liveness FINGERPRINT
  // ("sliceCount:attempt:throttleAttempt") from the last coordinator poll (null = not yet polled /
  // unreachable); rangeStrikes[i] counts CONSECUTIVE await ticks on which that fingerprint did NOT advance,
  // i.e. the worker persisted nothing -- the UNCATCHABLE wedge no worker ladder can catch. A range frozen
  // for MAX_SLICE_FAILURES ticks strikes the whole RUN out (failed completion, no signed root, lease
  // released), mirroring the serial strike-out, so a stalled worker can no longer hold the lease forever.
  // Both absent on a legacy in-flight coordinator doc; awaitTick re-seeds them from the range list.
  progress?: (string | null)[];
  rangeStrikes?: number[];
  destConfig?: RuntimeDestConfig | null;
  destinationId?: string;
}

// startSliceRun is the /start payload: the downpipe config (the seal DO rebuilds its
// source adapter from env per slice), the checkpoint after the inline slice, the shards
// that slice flushed, and the pinned destination override (null/absent = env).
export interface StartSliceRun {
  config: DownpipeConfig;
  checkpoint: RunCheckpoint;
  shards: ShardEntry[];
  // Fix 2a: the inline first slice's leftover open-shard buffer (plaintext lines, in-memory transit on a
  // DO-to-DO call). /start wraps it into an open-shard batch at the storage boundary. Absent/empty = the
  // inline slice left nothing buffered. Its length must equal checkpoint.openShard.count.
  openShardLines?: Record<string, unknown>[];
  destConfig?: RuntimeDestConfig | null;
  // The failover-chosen destinationId this run is sealing to (recorded as the run's origin at
  // /complete). Pinned alongside destConfig for the run's life so the resumed seal reports the
  // same origin the inline slice would have.
  destinationId?: string;
}

export function runSealStub(env: Env, downpipeId: string): DurableObjectStub {
  const ns = env.RUNSEAL as DurableObjectNamespace;
  return ns.get(ns.idFromName(downpipeId));
}

// The per-downpipe seal Durable Object (design F11: "dispatch sealing to per-downpipe
// workers or child DOs"). A run too large for one invocation is handed here after its
// first inline slice; each ALARM invocation seals one budget's worth (a fresh
// per-invocation subrequest budget every alarm), persists the checkpoint and the
// accumulated shard list atomically, heartbeats the scheduler's in-flight lease so a
// long run is never reclaimed mid-flight, and finalises (root + bundle + RUNLOG +
// /complete) when the crawl is done. Alarms are durable, so a crashed slice resumes from
// its checkpoint instead of restarting the run; content addressing makes the re-seal
// idempotent. The seal still never runs inside the SCHEDULER DO (the cheap, serial
// authority plane); this is a separate, per-downpipe worker object.
export class RunSealDO {
  private state: DurableObjectState;
  private env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(req: Request): Promise<Response> {
    try {
      const url = new URL(req.url);
      switch (`${req.method} ${url.pathname}`) {
        case "POST /start": {
          let body: StartSliceRun;
          try {
            body = (await req.json()) as StartSliceRun;
          } catch {
            // A body that does not parse as JSON is a malformed client request, the only 4xx case here.
            return json({ error: "invalid request body" }, 400);
          }
          // The /start payload carries the in-memory checkpoint form (an in-account
          // DO-to-DO call, never persisted as-is); the cursor is wrapped here, at the
          // storage boundary, before the doc is written.
          const signerKey = requireEnv(this.env.SIGNER_PRIVATE, "SIGNER_PRIVATE");
          const cp = validateCheckpoint(body.checkpoint);
          // Fix 2a: the inline slice's leftover open-shard buffer rides the handoff in memory; wrap it into
          // an open-shard batch (seq 0) HERE, at the storage boundary, exactly as the cursor is wrapped
          // (NC-1). Its length must equal the checkpoint's recorded open-shard count, or the handoff is
          // internally inconsistent (a malformed client request), so reject it rather than persist a
          // checkpoint whose count disagrees with the bytes it points at.
          const openLines = body.openShardLines ?? [];
          if (openLines.length !== (cp.openShard?.count ?? 0)) {
            // G108: the handoff is internally inconsistent and the run dies here, before a single DO slice runs.
            // The refusal is unchanged; the two counts that size it are recorded so the pack does not show a bare
            // "seal DO handoff refused" with nothing behind it. (The worker side classifies THIS 400 as the closed
            // handoff class "invalid-payload", so the row and the ring agree.)
            await this.observeSealFault(schedulerStub(this.env), { kind: "open-shard-count-mismatch", at: Date.now(), downpipeId: body.config.id, runId: cp.runId, found: openLines.length, expected: cp.openShard?.count ?? 0 });
            return json({ error: "open-shard buffer does not match the checkpoint count" }, 400);
          }
          const stored = await sealCheckpointForStorage(signerKey, cp);
          // Overwrite any stale doc: the scheduler's lease + reclaim is the authority on
          // which run owns the downpipe, and a fresh /start means a fresh in-flight run
          // (a still-set alarm from a dead run simply advances the new doc).
          const puts: Record<string, unknown> = {};
          let openEnd = 0;
          if (openLines.length > 0) {
            puts[openBatchKey(0)] = await sealOpenShardBatch(signerKey, cp.runId, 0, openLines);
            openEnd = 1;
          }
          puts[DOC_KEY] = { config: body.config, checkpoint: stored, attempt: 0, destConfig: body.destConfig ?? null, openBatchSeqStart: 0, openBatchSeqEnd: openEnd, ...(body.destinationId !== undefined ? { destinationId: body.destinationId } : {}) } satisfies RunDoc;
          for (const s of body.shards) puts[`${SHARD_PREFIX}${s.id}`] = s;
          // Clear shard rows AND open-shard batches from any abandoned previous run before writing the new
          // ones, batched into one bulk delete. The enumeration is PAGED with a startAfter cursor (M2/R0-1):
          // a bare un-paged list() returns at most one page, so an aborted prior run that left MORE than a
          // page of stale keys would only have its first page cleaned. The keys the fresh run is
          // (over)writing are in `puts` and kept.
          const staleKeys = [...(await this.collectStaleKeys(SHARD_PREFIX, puts)), ...(await this.collectStaleKeys(OPEN_PREFIX, puts))];
          if (staleKeys.length > 0) {
            await this.state.storage.delete(staleKeys);
            // OBSERVE how many stale shard/open rows an ABANDONED prior run left behind (support-pack mode
            // shard-truncation-stalekeys). The cleanup itself is UNCHANGED and stays integrity-load-bearing;
            // this only records the count cleaned (a leaked-tail risk signal) AFTER the delete, best-effort +
            // fail-open, so a fresh run's /start is never blocked or altered by the observe. Emitted only when
            // stale rows were actually found (the healthy case leaves none, so it stays silent).
            await this.observeSealFault(schedulerStub(this.env), { kind: "stale-shard-rows-cleaned", at: Date.now(), downpipeId: body.config.id, runId: cp.runId, cleaned: staleKeys.length });
          }
          await this.state.storage.put(puts);
          await this.state.storage.setAlarm(Date.now() + NEXT_SLICE_DELAY_MS);
          return json({ ok: true });
        }
        case "POST /start-fanout":
          return this.handleStartFanout(req);
        case "POST /start-range":
          return this.handleStartRange(req);
        case "POST /range-done":
          return this.handleRangeDone(req);
        case "POST /range-failed":
          return this.handleRangeFailed(req);
        case "GET /status": {
          const doc = await this.state.storage.get<RunDoc>(DOC_KEY);
          if (!doc) return json({ active: false });
          return json({
            active: true,
            runId: doc.checkpoint.runId,
            sliceCount: doc.checkpoint.sliceCount,
            records: doc.checkpoint.counts.records,
            bytes: doc.checkpoint.counts.bytes,
            sourceDone: doc.checkpoint.sourceDone,
            attempt: doc.attempt,
            // throttleAttempt completes the worker-liveness fingerprint a fan-out COORDINATOR polls (H1):
            // a survived worker alarm bumps sliceCount (a slice), attempt (a hard fault) OR throttleAttempt
            // (a throttle park), so all three frozen across a coordinator tick means the worker persisted
            // NOTHING -- the uncatchable wedge -- while ANY advancing keeps the coordinator off a worker's
            // own bounded ladder. Absent on a serial doc / a fresh worker = 0.
            throttleAttempt: doc.throttleAttempt ?? 0,
          });
        }
        default:
          return json({ error: "not found" }, 404);
      }
    } catch (e) {
      // An unexpected exception here (storage or crypto failure) is a server-side fault, not a client
      // error: returning 500 lets the caller treat it as transient and retry rather than fail the run.
      // NC-2: the body carries a fixed class, never the raw message (which can embed a storage key or
      // key name); the detail is logged with the coarse digest for the operator instead.
      log("error", `runseal /start fault: ${await redactedRunError((e as Error).message)}`);
      return json({ error: "internal error" }, 500);
    }
  }

  // alarm advances the active run by one slice (or finalises it). It NEVER throws: a
  // fault increments the attempt counter and re-arms with backoff, and a run past
  // MAX_SLICE_FAILURES is completed as failed so the downpipe is never wedged. Each
  // alarm invocation has its own platform subrequest budget, which is exactly why the
  // run is chained through alarms rather than looped in one invocation.
  async alarm(): Promise<void> {
    const raw = await this.state.storage.get<RunDoc & { kind?: string }>(DOC_KEY);
    if (!raw) return; // completed or aborted; nothing to do
    // Fix 2b fan-out dispatch: a coordinator doc (kind:"coordinator") drives the spawn/await/merge state
    // machine; a worker doc (coordinatorId set) seals its range and reports /range-done; everything else is
    // the unchanged SERIAL alarm below.
    if (raw.kind === "coordinator") {
      await this.coordinatorAlarm(raw as unknown as CoordinatorDoc);
      return;
    }
    if (raw.coordinatorId !== undefined) {
      await this.workerAlarm(raw);
      return;
    }
    const doc = raw;
    const scheduler = schedulerStub(this.env);
    // The destination this invocation sealed to, hoisted so the RUNLOG-contention give-up path can reclaim
    // the orphan run-tree it wrote before the RUNLOG append failed (SCALE-3 orphan-root GC). Stays undefined
    // if the invocation faults before the destination is built (in which case nothing was written to clean).
    let dest: SliceDeps["dest"] | undefined;
    try {
      // Heartbeat the scheduler lease FIRST: if a newer run owns the downpipe (this one was reclaimed
      // while dead), abandon cleanly and let the owner proceed.
      if (!(await this.heartbeatOwned(scheduler, doc))) {
        log("error", `sliced run ${doc.checkpoint.runId} lost its lease; abandoning (a newer run owns ${doc.checkpoint.downpipeId})`);
        // OBSERVE the clean abandon (support-pack mode lease-lost-abandon): a resuming run yielded because a
        // NEWER run owns the downpipe (the lease-reclaim event). Recording the runId makes the abandon visible
        // in the pack, not just in the log. Best-effort + fail-open; it never changes the abandon.
        await this.observeSealFault(scheduler, { kind: "lease-lost-abandon", at: Date.now(), downpipeId: doc.checkpoint.downpipeId, runId: doc.checkpoint.runId });
        await this.cleanup();
        return;
      }

      const budget = budgetFromEnv(this.env);
      const signerKey = requireEnv(this.env.SIGNER_PRIVATE, "SIGNER_PRIVATE");
      // An API-based source (cf-config / workers / stream / images / artifacts) needs the read-only
      // discovery token on the RESUME path too; binding sources (KV/R2/D1/secrets) resolve to undefined
      // and make no DO fetch. The token resolves DO-first then the DISCOVERY_API_TOKEN env fallback.
      const cfToken = await cfConfigToken(scheduler, { config: doc.config } as DownpipeState, this.env);
      const deps = await sliceDepsFromEnv(this.env, doc.config, budget, { destOverride: doc.destConfig ?? null, ...(cfToken !== undefined ? { cfToken } : {}) });
      dest = deps.dest;
      try {
        // The stored cursor is unwrapped only here, inside the invocation (NC-1). A failure to unwrap the
        // checkpoint under the CURRENT signer is OBSERVED (signer-rotation-strands-runs) then re-thrown so the
        // existing strike ladder still fails the run loudly (behaviour unchanged; the observe is additive).
        const { cp, master } = await this.openCheckpointForResume(scheduler, signerKey, doc);
        try {
          // Run one slice when the source is not exhausted. A null result means the step re-armed the
          // alarm to resume (more source, or no finalise headroom), so this invocation is done.
          const advanced = cp.sourceDone ? cp : await this.runSliceStep(signerKey, deps, budget, doc, cp, master);
          if (advanced === null) return;
          // Source exhausted and headroom available: finalise + verify + complete on this invocation.
          await this.finaliseAndComplete(scheduler, deps, doc, advanced, master, signerKey);
        } finally {
          master.fill(0);
        }
      } finally {
        // NC-6: zeroise the per-invocation signer load on every path (sealRunBuffered discipline; the
        // recovery-bundle write inside finaliseRun is the last legitimate reader of the ML-DSA secret).
        deps.signer.mldsaSecret.fill(0);
      }
    } catch (e) {
      const m = (e as Error).message;
      // G142: name the missing prerequisite BEFORE the ladders redact the cause. A config fault (a wiped source
      // binding, a rotated-away discovery token, an absent/malformed SIGNER_PRIVATE, an out-of-scope account) is
      // recorded by TYPE with a closed code + the binding/env-var name; anything else is a no-op here. The
      // routing below is untouched.
      await this.observeConfigFault(scheduler, e, doc.checkpoint.downpipeId, doc.checkpoint.runId);
      // RUNLOG CONTENTION (SCALE-3): a typed RunlogContendedError means another finaliser is writing the
      // SAME destination's RUNLOG and the patient lock + lock-free CAS could not commit this tick. The
      // run-tree is already committed and the append is idempotent, so this is PARK-and-resume, NOT a strike:
      // route it to handleContention (its own patient ladder) so a busy fleet finalises eventually rather
      // than shedding part of a trigger storm to terminal failure. Checked FIRST so a contended write is
      // never miscounted as a hard fault.
      if (e instanceof RunlogContendedError) {
        await this.handleContention(scheduler, doc, m, dest);
        return;
      }
      // Classify a THROTTLE (503 SlowDown / 429) distinctly from a hard fault and ride it on the
      // separate, far more patient parking ladder (the rationale is in handleThrottle below).
      // The match is over the raw message text from the whole try block; record data is encrypted so a
      // record name cannot inject "status 503", and a 503/429 from any phase is correctly treated as a
      // throttle. A typed throttle error from the write paths would make this structural; this is a known
      // text-based classification, not a defect.
      if (/(status|HTTP) (503|429)/.test(m)) {
        await this.handleThrottle(scheduler, doc, m, dest);
        return;
      }
      // G143: append THIS strike's coarse class to the run's ordered, capped list before the ladder charges it,
      // so a terminal failure can say whether the 8 strikes had one consistent cause (a rotated credential) or
      // several (a flapping estate). sealAttemptClass returns a closed enum member and nothing else.
      doc.pressure = withAttemptClass(foldRetryMeter(doc.pressure), e);
      await this.handleHardFault(scheduler, doc, m, dest);
    }
  }

  // heartbeatOwned asks the scheduler whether this run still owns the downpipe lease, reading the
  // identity fields from the stored form directly (the cursor stays wrapped until a slice needs it).
  private async heartbeatOwned(scheduler: DurableObjectStub, doc: RunDoc): Promise<boolean> {
    const hb = (await (await scheduler.fetch(doURL("/heartbeat"), {
      method: "POST",
      body: JSON.stringify({ id: doc.checkpoint.downpipeId, runId: doc.checkpoint.runId, index: doc.checkpoint.runlogIndex }),
      headers: { "content-type": "application/json" },
    })).json()) as { owned: boolean };
    return hb.owned;
  }

  // openAndMigrate unwraps the stored checkpoint and, for a LEGACY doc (persisted before the cursor
  // wrap shipped) carrying a plaintext cursor, re-seals it NOW rather than leaving the plaintext form
  // to survive up to MAX_SLICE_FAILURES re-persists (the failure path below re-persists doc verbatim).
  private async openAndMigrate(signerKey: string, doc: RunDoc): Promise<RunCheckpoint> {
    const cp = await openStoredCheckpoint(signerKey, doc.checkpoint);
    // The double cast probes for a legacy plaintext `cursor` field that the current StoredRunCheckpoint
    // type no longer declares (it shipped before the cursor wrap). The escape hatch is deliberate: it lets
    // us detect and re-seal an old-format doc. It is safe to remove once no legacy docs remain in storage.
    if ("cursor" in (doc.checkpoint as unknown as Record<string, unknown>)) {
      doc.checkpoint = await sealCheckpointForStorage(signerKey, cp);
      await this.state.storage.put(DOC_KEY, doc);
    }
    return cp;
  }

  // openCheckpointForResume unwraps the stored checkpoint + its run master for an alarm resume, OBSERVING a
  // signer-strand on failure (support-pack mode signer-rotation-strands-runs). openAndMigrate / unwrapMaster
  // both derive the wrap key from the CURRENT SIGNER_PRIVATE, so a signer rotation between the write and this
  // resume leaves the checkpoint unwrappable (the AEAD fails); DO corruption fails it the same way. Either way
  // the run must still fail LOUDLY: this records the strand (with the runId read from the still-plaintext
  // identity fields) then RE-THROWS unchanged, so the existing strike ladder resolves the run exactly as
  // before. The observe is best-effort + fail-open, so it can never turn a strand into anything worse.
  private async openCheckpointForResume(scheduler: DurableObjectStub, signerKey: string, doc: RunDoc): Promise<{ cp: RunCheckpoint; master: Uint8Array }> {
    // G107: the SILENT COERCIONS first. validateCheckpoint DEFAULTS a missing counter rather than rejecting it
    // (so an engine upgrade never strands an in-flight run) -- but that made a LEGACY doc (the counter predates
    // the field: benign) and a CORRUPTED doc (the counter came back a non-number and is being silently coerced:
    // a miscounted archive) identical. The inspector is PURE and runs BEFORE the in-place defaulting; it reads
    // the doc's shape, never its values.
    const coercions = checkpointCoercions(doc.checkpoint);
    if (coercions.length > 0) {
      await this.observeSealFault(scheduler, {
        kind: "checkpoint-coerced",
        at: Date.now(),
        downpipeId: doc.checkpoint.downpipeId,
        runId: doc.checkpoint.runId,
        checkpointField: "counts",
        coerced: coercions.length,
        legacyAbsent: coercions.every((c) => c.legacyAbsent),
      });
    }
    try {
      const cp = await this.openAndMigrate(signerKey, doc);
      const master = await unwrapMaster(signerKey, cp.runId, cp.wrappedMaster);
      return { cp, master };
    } catch (e) {
      // G107: this resume is DEAD, and the run will restart from ZERO next cadence. Record three things the pack
      // never had: WHICH field of the checkpoint was malformed (a corrupted / tampered DO write), or WHICH unwrap
      // failed (a signer rotation vs a wrong-length plaintext vs an open-shard batch), and HOW MUCH DURABLE
      // PROGRESS is being thrown away. The identity + progress fields ride PLAINTEXT in the stored form, so the
      // discard can be sized even though the checkpoint itself cannot be opened. The throw is re-raised unchanged.
      const field = checkpointInvalidOf(e);
      const unwrapCode = checkpointUnwrapOf(e);
      const ids = { downpipeId: doc.checkpoint.downpipeId, runId: doc.checkpoint.runId };
      if (field !== null) {
        await this.observeSealFault(scheduler, { kind: "checkpoint-invalid", at: Date.now(), ...ids, checkpointField: field });
      } else {
        await this.observeSealFault(scheduler, { kind: "checkpoint-unwrap-failed", at: Date.now(), ...ids, ...(unwrapCode !== null ? { unwrapCode } : {}) });
      }
      await this.observeSealFault(scheduler, {
        kind: "resume-abandoned",
        at: Date.now(),
        ...ids,
        slicesDiscarded: typeof doc.checkpoint.sliceCount === "number" ? doc.checkpoint.sliceCount : 0,
        recordsDiscarded: typeof doc.checkpoint.counts?.records === "number" ? doc.checkpoint.counts.records : 0,
      });
      throw e;
    }
  }

  // observeSealFault posts ONE seal-fault OBSERVE signal to the scheduler DO's bounded ring (support-pack
  // seal-integrity modes shard-list-truncated / shard-truncation-stalekeys / lease-lost-abandon /
  // orphan-root-worm-leak / signer-rotation-strands-runs, and the fan-out modes fanout-range-stalled /
  // fanout-report-discarded). It is DIAGNOSTIC only and STRICTLY BEST-EFFORT: postSealFault never throws, so a
  // routing/persist hiccup degrades to "no observation" and can NEVER affect the run (the same fail-open
  // discipline verify-at-seal + the reconcile persist follow). It reads/mutates no archive, RUNLOG or seal path;
  // the DO side re-validates + clamps + drops an out-of-vocabulary kind. Gap G326: the fire-and-forget POST's own
  // failure is no longer silent -- postSealFault tallies a dropped observation (transport / unknown-kind) and
  // flushes it into the ring as an "observe-dropped" record, so a clean ring is no longer indistinguishable from
  // a ring whose writes were being lost.
  private async observeSealFault(scheduler: DurableObjectStub, fault: SealFaultPost): Promise<void> {
    await postSealFault(scheduler, fault);
  }

  // observeConfigFault records WHICH prerequisite a run died for (gap G142): a source binding a deploy wiped, a
  // secrets binding, the read-only discovery token, an accountId now outside the discovery scope, SIGNER_PRIVATE
  // (absent or malformed), or another required env var. It classifies the caught error by TYPE (configFaultOf
  // matches a ConfigFaultError raised at the throw site), NEVER by reading the message, and records a CLOSED code
  // plus the offending binding / env-var NAME -- an operator label of the same redaction class the pack's
  // sourcesDetached already carries, gated to the bare identifier charset by the sanitiser. A non-config fault is
  // a no-op. Best-effort + fail-open like every other observe: it cannot change the strike ladder or the run.
  private async observeConfigFault(scheduler: DurableObjectStub, e: unknown, downpipeId: string, runId: string): Promise<void> {
    const fault = configFaultOf(e);
    if (fault === null) return;
    await this.observeSealFault(scheduler, {
      kind: "config-fault",
      at: Date.now(),
      downpipeId,
      runId,
      configCode: fault.code,
      ...(fault.bindingName !== undefined ? { bindingName: fault.bindingName } : {}),
    });
  }

  // observeRunPressure records what ONE run's retry / throttle-park / RUNLOG-park / strike pressure COST, at the
  // moment the run resolves (gap G143). It fires on BOTH outcomes: a run that succeeded after riding out a
  // multi-hour throttle is exactly the evidence a "backups suddenly started failing" diagnosis needs, and it
  // would otherwise vanish with the doc cleanup(). A run that spent nothing records nothing, so the
  // ring stays quiet on a healthy fleet. Counts and closed classes only -- no message, no key, no object name.
  // Best-effort + fail-open; called AFTER the completion has been posted so it can never delay a resolution.
  private async observeRunPressure(scheduler: DurableObjectStub, doc: RunDoc, outcome: "ok" | "failed"): Promise<void> {
    const pressure = foldRetryMeter(doc.pressure);
    const strikes = doc.attempt ?? 0;
    const throttleParks = doc.throttleAttempt ?? 0;
    const runlogParks = doc.runlogAttempt ?? 0;
    if (!hasPressure(pressure, strikes, throttleParks, runlogParks)) return;
    const throttled = pressure.throttledSubsystem ?? dominantSubsystem(pressure);
    await this.observeSealFault(scheduler, {
      kind: "run-pressure",
      at: Date.now(),
      downpipeId: doc.checkpoint.downpipeId,
      runId: doc.checkpoint.runId,
      outcome,
      retries: pressure.retries,
      retriesBySubsystem: pressure.bySubsystem as Record<string, number>,
      throttleParks,
      runlogParks,
      strikes,
      probeFlaps: pressure.probeFlaps,
      ...(throttled !== undefined ? { throttledSubsystem: throttled } : {}),
      ...(pressure.attemptClasses.length > 0 ? { attemptClasses: [...pressure.attemptClasses] } : {}),
    });
  }

  // runSliceStep runs ONE slice and atomically persists the advanced checkpoint (cursor re-wrapped at
  // the storage boundary) plus this slice's shards, so the cursor can never run ahead of the recorded
  // shard list. It returns the advanced checkpoint when the source is now exhausted AND there is
  // finalise headroom (the caller finalises), or null when it re-armed the alarm to resume (more
  // source, or no headroom) and this invocation is done.
  private async runSliceStep(signerKey: string, deps: SliceDeps, budget: SliceBudget, doc: RunDoc, cp: RunCheckpoint, master: Uint8Array): Promise<RunCheckpoint | null> {
    // SRC-1 liveness preflight: on the FIRST slice of a run (no records committed yet), prove the bound
    // resource still exists with one cheap probe BEFORE the crawl. A deleted KV/R2/D1 behind a still-truthy
    // binding otherwise dies deep in the crawl on a raw platform throw that folds into a generic "run
    // failed"; probing here raises a named SourceResourceMissingError that coarseRunError classifies as
    // "source resource missing", so the failed history row tells the operator which source/resource to fix.
    // Sources without a cheap liveness call (secrets / API sources) are skipped, not failed.
    if (hasLivenessProbe(deps.source)) {
      if (cp.sliceCount === 0 && cp.cursor === null) {
        // Slice 0: fail-closed on ANY probe fault. A run whose source is not live should not start.
        await deps.source.probeLiveness();
      } else {
        // Resume slice (SRC-1b): re-probe so a source resource DELETED between slices (a namespace,
        // bucket or database dropped mid-run, the owner-named "deleted mid-process" case) is named
        // legibly as "source resource missing" instead of folding into a generic "run failed" deep in
        // the crawl. Only a CONFIRMED deletion or misconfiguration fails the slice here; a transient
        // "unavailable" probe blip is swallowed so a long multi-slice run is not made fragile to one
        // probe hiccup (the crawl's own reads still surface a real transient fault, and the checkpoint
        // is preserved so the next tick resumes).
        try {
          await deps.source.probeLiveness();
        } catch (e) {
          if (e instanceof SourceResourceMissingError && e.kind !== "unavailable") throw e;
          // G143: the SWALLOW is deliberate (a probe blip must not make a long run fragile), but it was also
          // SILENT: a source that is flapping for hours shows up nowhere until a run finally dies of it. Count
          // the flap on the run's pressure (a bounded integer, never the probe's error) so "backups suddenly
          // started failing" carries the run-up. Counting cannot change the swallow.
          doc.pressure = withProbeFlap(doc.pressure);
        }
      }
    }
    // Fix 2a: load the carried open-shard buffer (the wrapped batches in the live range) and seed
    // runSlice with it, so the in-crawl shardMax flush accounts for records sealed in earlier slices and
    // finally fires at 5000 instead of at the ~220-record slice budget.
    const priorStart = doc.openBatchSeqStart ?? 0;
    const priorEnd = doc.openBatchSeqEnd ?? 0;
    const priorOpen = await this.loadOpenLines(signerKey, cp.runId, priorStart, priorEnd);
    // The SLICED path's crawl runs in THIS (the seal DO's) isolate, so this is the only place its source-fault
    // ledger can be read. Clear it before the slice and DRAIN it after -- including on a throw, which is
    // exactly where the run-fatal transport class and crawl stage (G144) live. reportRunFaults never throws
    // and posts nothing for a clean slice, so it cannot affect the seal.
    beginRunFaults();
    let r: SliceResult;
    try {
      r = await runSlice(deps, cp, master, priorOpen);
    } finally {
      await reportRunFaults(schedulerStub(this.env), cp.downpipeId, deps.dest);
    }
    const stored = await sealCheckpointForStorage(signerKey, r.checkpoint);
    // Reconcile the open-shard batches with the slice's outcome (Fix 2a). A flush (openReset) consumed the
    // prior batches, so they are CLEARED and the leftover written at a fresh seq; otherwise this slice's
    // new lines are APPENDED beyond the live range (append-only, never rewriting prior batches). Either new
    // batch is bounded by one slice's record count, so it fits a single DO value. The wrapped batch + the
    // new shard rows + the advanced checkpoint (carrying openShard.count + the seq pointers) land in ONE
    // atomic put; the consumed batches are deleted AFTER it -- a crash in between only LEAKS them, because
    // the advanced doc's live range no longer references them, so resume ignores them and cleanup()
    // reclaims them (no data loss, no double-count).
    let openStart = priorStart;
    let openEnd = priorEnd;
    const consumed: string[] = [];
    if (r.openReset) {
      for (let seq = priorStart; seq < priorEnd; seq++) consumed.push(openBatchKey(seq));
      openStart = priorEnd;
      openEnd = priorEnd;
    }
    // The re-persist carries the pinned destConfig forward (losing it mid-run would silently repoint
    // the remaining slices at the env destination and split the archive).
    const puts: Record<string, unknown> = {};
    if (r.openWrite.length > 0) {
      puts[openBatchKey(openEnd)] = await sealOpenShardBatch(signerKey, cp.runId, openEnd, r.openWrite);
      openEnd += 1;
    }
    // G143: DRAIN this slice's retries out of the isolate meter and carry the run's accumulated pressure into
    // the fresh doc. The doc is deliberately rewritten without attempt/throttleAttempt (progress resets those
    // ladders), but the pressure is CUMULATIVE evidence, not a ladder: dropping it here would lose the
    // history of a run that "recovered every time, until it did not".
    const pressure = foldRetryMeter(doc.pressure);
    puts[DOC_KEY] = { config: doc.config, checkpoint: stored, attempt: 0, destConfig: doc.destConfig ?? null, openBatchSeqStart: openStart, openBatchSeqEnd: openEnd, ...(doc.destinationId !== undefined ? { destinationId: doc.destinationId } : {}), ...(doc.coordinatorId !== undefined ? { coordinatorId: doc.coordinatorId } : {}), pressure } satisfies RunDoc;
    for (const s of r.newShards) puts[`${SHARD_PREFIX}${s.id}`] = s;
    await this.state.storage.put(puts);
    doc.checkpoint = stored;
    doc.openBatchSeqStart = openStart;
    doc.openBatchSeqEnd = openEnd;
    doc.pressure = pressure;
    // Keep the in-memory attempt counter in step with the persisted attempt: 0 (progress resets the
    // ladder). Without this, a fault later in THIS invocation (finalise, setAlarm) would compute
    // oldAttempt + 1 and could terminal-fail a run one step from completion despite fresh progress.
    doc.attempt = 0;
    if (consumed.length > 0) await this.state.storage.delete(consumed);
    if (!r.checkpoint.sourceDone || !budget.canFinalise()) {
      await this.state.storage.setAlarm(Date.now() + NEXT_SLICE_DELAY_MS);
      return null;
    }
    return r.checkpoint;
  }

  // listAllShards enumerates EVERY shard row this run flushed, paging past the platform's DO list
  // page limit (R0-1). A single un-paged storage.list() returns at most one page (~1000 keys), so a
  // run with more shards than the page silently TRUNCATES: finaliseRun would then sign root.manifest
  // over only the listed shards while declaring the full record count and the Merkle root over ALL
  // records, an internally inconsistent, spec-violating archive that still reports ok (verify-at-seal
  // only checks the LISTED shards). We loop with a startAfter cursor (the last key of the prior page,
  // exclusive) until a page comes back SHORT, the exhaustion signal; the keys are ascending
  // lexicographic, so startAfter advances with no overlap and no gap. The max-pages guard is the
  // defence-in-depth ceiling against a degenerate store that never shortens a page. This mirrors the
  // scheduler DO's listAllByPrefix (ENG-SCALE-08).
  private async listAllShards(): Promise<ShardEntry[]> {
    const out: ShardEntry[] = [];
    let startAfter: string | undefined;
    for (let guard = 0; guard < SHARD_LIST_MAX_PAGES; guard++) {
      const page = await this.state.storage.list<ShardEntry>({ prefix: SHARD_PREFIX, limit: SHARD_LIST_PAGE, ...(startAfter !== undefined ? { startAfter } : {}) });
      if (page.size === 0) break;
      let lastKey: string | undefined;
      for (const [k, v] of page) {
        out.push(v);
        lastKey = k;
      }
      if (page.size < SHARD_LIST_PAGE || lastKey === undefined) break;
      startAfter = lastKey;
    }
    return out;
  }

  // loadOpenLines reads the live open-shard batches [seqStart, seqEnd) (Fix 2a), unwraps each (the AEAD is
  // bound to its runId + seq, so a batch read under the wrong run or seq is rejected), and returns the
  // concatenated manifest lines in order. A batch MISSING from inside the live range is a real gap (DO
  // corruption), so it throws rather than silently seal a short shard; finaliseAndComplete additionally
  // cross-checks the total against the checkpoint's recorded count. DO storage reads are not subrequests.
  private async loadOpenLines(signerKey: string, runId: string, seqStart: number, seqEnd: number, downpipeId?: string): Promise<Record<string, unknown>[]> {
    const lines: Record<string, unknown>[] = [];
    for (let seq = seqStart; seq < seqEnd; seq++) {
      const wrapped = await this.state.storage.get<{ iv: string; ct: string }>(openBatchKey(seq));
      if (wrapped === undefined) {
        // G108: DO storage lost a wrapped open-shard batch from INSIDE the live range, so the records it held
        // can never be sealed and the run refuses to sign. The refusal is unchanged; the two integers that size
        // it (which sequence went missing, where the live range ends) are recorded rather than left inside the
        // thrown message alone.
        await this.observeSealFault(schedulerStub(this.env), { kind: "open-batch-missing", at: Date.now(), runId, found: seq, expected: seqEnd, ...(downpipeId !== undefined ? { downpipeId } : {}) });
        throw new Error(`open-shard batch ${seq} is missing from the live range [${seqStart}, ${seqEnd})`);
      }
      lines.push(...(await openOpenShardBatch(signerKey, runId, seq, wrapped)));
    }
    return lines;
  }

  // collectStaleKeys paginates a DO storage prefix and returns the keys NOT in `keep` (the keys the fresh
  // run is about to (over)write), so /start can bulk-delete an abandoned prior run's rows. A single
  // un-paged list() returns at most one page, so the startAfter cursor loop is what reaches every key; the
  // max-pages guard is the defence-in-depth ceiling (mirrors listAllShards / the scheduler listAllByPrefix).
  private async collectStaleKeys(prefix: string, keep: Record<string, unknown>): Promise<string[]> {
    const stale: string[] = [];
    let after: string | undefined;
    for (let guard = 0; guard < SHARD_LIST_MAX_PAGES; guard++) {
      const page = await this.state.storage.list({ prefix, limit: SHARD_LIST_PAGE, ...(after !== undefined ? { startAfter: after } : {}) });
      if (page.size === 0) break;
      let lastKey: string | undefined;
      for (const k of page.keys()) {
        lastKey = k;
        if (!(k in keep)) stale.push(k);
      }
      if (page.size < SHARD_LIST_PAGE || lastKey === undefined) break;
      after = lastKey;
    }
    return stale;
  }

  // finaliseAndComplete seals the run from the recorded shards, verifies the just-written archive
  // (ENG-RST-01, fail-open: a suspect verdict flags the row + alerts but the run still completes
  // "ok"), posts the ok completion and cleans up the DO state.
  private async finaliseAndComplete(scheduler: DurableObjectStub, deps: SliceDeps, doc: RunDoc, cp: RunCheckpoint, master: Uint8Array, signerKey: string): Promise<void> {
    // Sort by NUMERIC id (Fix 2a): the signed root lists shards in seal order, and a paged DO-storage
    // enumeration is lexicographic, so the numeric sort re-establishes the canonical order regardless of
    // page order. With every id 5 digits (pad5 guards the range) numeric == lexicographic.
    const shards = (await this.listAllShards()).sort((a, b) => Number(a.id) - Number(b.id));
    // Completeness guard (R0-1): the run flushed exactly cp.nextShardIndex shards (sequential ids
    // pad5(0)..pad5(nextShardIndex-1)), so the enumerated set MUST be that many. If the enumeration
    // came back SHORT (a truncated list, a missing shard row), signing now would declare the full
    // record count and the Merkle root over ALL records while the manifest lists only a SUBSET, a
    // silently incomplete archive. FAIL LOUD instead: throw before signing so the run is left
    // incomplete and retryable (the alarm re-arms on the strike ladder; a re-flush is idempotent
    // under content addressing) rather than sealed inconsistent. cp.nextShardIndex === 0 means a
    // truly empty run, which finaliseRun handles by flushing one empty shard for buffered-path parity.
    if (cp.nextShardIndex > 0 && shards.length < cp.nextShardIndex) {
      // OBSERVE the found/expected shard counts (support-pack mode shard-list-truncated) BEFORE the refuse
      // throw. The refuse decision is UNCHANGED -- this only records the two counts the completeness guard
      // already computed, so the truncation is visible in the pack (the throw is otherwise redacted through
      // the strike ladder). Best-effort + fail-open: recording it can never change the refuse-to-sign.
      await this.observeSealFault(scheduler, { kind: "shard-list-truncated", at: Date.now(), downpipeId: doc.config.id, runId: cp.runId, found: shards.length, expected: cp.nextShardIndex });
      throw new Error(`shard enumeration incomplete: found ${shards.length} of ${cp.nextShardIndex} shards; refusing to sign a truncated archive`);
    }
    // Fix 2a: load the carried OPEN shard (the records buffered across slices but not yet flushed) and
    // cross-check the re-loaded line total against the checkpoint's recorded count. A short read (a
    // truncated/missing batch) must FAIL LOUD before signing, not silently drop the buffered records from
    // the archive (the signed root would then declare more records than the shards hold, which the offline
    // reader flags incomplete). finaliseRun seals these as the final shard. A re-flush after a strike is
    // idempotent: re-loading the same batches yields the same lines, and the final shard overwrites its key.
    const openLines = await this.loadOpenLines(signerKey, cp.runId, doc.openBatchSeqStart ?? 0, doc.openBatchSeqEnd ?? 0, doc.config.id);
    const expectedOpen = cp.openShard?.count ?? 0;
    if (openLines.length !== expectedOpen) {
      // G108: the OPEN-shard half of the completeness guard. The serial shard guard above already observed its
      // found/expected into the ring; this one -- the carried buffer that spans slices -- did not, so a run that
      // refused to sign a short archive for THIS reason produced no archive and no evidence.
      await this.observeSealFault(scheduler, { kind: "open-shard-count-mismatch", at: Date.now(), downpipeId: doc.config.id, runId: cp.runId, found: openLines.length, expected: expectedOpen });
      throw new Error(`open-shard enumeration incomplete: loaded ${openLines.length} of ${expectedOpen} buffered lines; refusing to sign a short archive`);
    }
    // PER-DESTINATION lock keying (SCALE-3): key the RUNLOG lock by the destination this run sealed to
    // (the failover-chosen origin, or the default slot when unpinned), so runs to different destinations
    // finalise without serialising on each other.
    const lock = runlogLockVia(scheduler, doc.destinationId);
    await finaliseRun(deps, cp, master, shards, openLines, lock);
    // DRAIN the FINALISE's own observations. runSliceStep drains the ledger around the CRAWL, but finaliseRun
    // runs AFTER that window and notes into the same ledger: the RUNLOG lock/CAS plane counters (G222) and the
    // absent-RUNLOG chain restart (G283) are both detected here, and on the sliced path they were being cleared
    // by the next run's begin without ever reaching the pack. Never throws; posts nothing for a clean finalise.
    await reportRunFaults(scheduler, doc.config.id, deps.dest);
    const sealVerification = await runSealVerification({ env: this.env, scheduler, dest: deps.dest, downpipe: { id: doc.config.id, name: doc.config.name }, master }, cp.runId, cp.counts.bytes);
    await this.complete(scheduler, cp, "ok", { ...(doc.destinationId !== undefined ? { destinationId: doc.destinationId } : {}), ...(sealVerification !== undefined ? { sealVerification } : {}), dest: deps.dest });
    // G143: a run that SUCCEEDED under pressure is the one whose evidence is otherwise lost entirely once
    // cleanup() runs. Record it before the doc is deleted. A clean run records nothing.
    await this.observeRunPressure(scheduler, doc, "ok");
    await this.cleanup();
  }

  // handleThrottle rides a destination/source THROTTLE (503 SlowDown / 429 Too Many Requests, from the
  // destination OR the source's rate-limited API) on a SEPARATE, far more patient ladder than a hard
  // fault. The destination/source is UP and the source data is unchanged; striking a run toward terminal
  // failure because something asked us to slow down would ABANDON a backup that only needs to wait. So a
  // throttle rides throttleAttempt, which NEVER charges the hard-fault strike counter (attempt) and NEVER
  // cleans up the checkpoint while it waits. That makes this PARK-AND-RESUME: the SAME run resumes from
  // its last checkpoint the moment the destination recovers (content addressing makes the re-seal
  // idempotent), instead of a fresh run re-crawling the whole source from zero every cadence for the
  // outage. A slice that SUCCEEDS writes a fresh doc without throttleAttempt, which resets the ladder, so
  // a slow-but-progressing destination never reaches the terminal bound. (A 500 or a 4xx is NOT a
  // throttle: those stay on the strike ladder in handleHardFault.)
  private async handleThrottle(scheduler: DurableObjectStub, doc: RunDoc, m: string, dest?: Destination): Promise<void> {
    const throttleAttempt = (doc.throttleAttempt ?? 0) + 1;
    const maxYields = throttleMaxYields(this.env);
    // G143: name WHO asked the run to slow down (destination / source API / scheduler). The classifier reads the
    // throttle message ONLY to select a member of the closed RETRY_SUBSYSTEMS vocabulary and returns that enum;
    // the message itself never leaves this frame (it is already redacted before it reaches the log below).
    doc.pressure = withThrottledSubsystem(foldRetryMeter(doc.pressure), throttledSubsystemOf(m));
    log("error", `sliced run ${doc.checkpoint.runId} slice throttled (waiting ${throttleAttempt}/${maxYields}, checkpoint preserved): ${await redactedRunError(m)}`);
    if (throttleAttempt >= maxYields) {
      // The destination/source has been unavailable for the entire parking window. Give up now with an
      // honest reason; the source data is unchanged, so a fresh run next cadence backs it up.
      try {
        await this.complete(scheduler, doc.checkpoint, "failed", { error: "destination unavailable (sustained throttling)", causeDigest: await causeDigest(m), ...(doc.destinationId !== undefined ? { destinationId: doc.destinationId } : {}), ...(dest !== undefined ? { dest } : {}) });
      } catch (ce) {
        log("error", `sliced run ${doc.checkpoint.runId} failure completion did not land: ${await redactedRunError((ce as Error).message)}`);
        // G109: the run rode the WHOLE parking window and was abandoned for a sustained outage. Losing that
        // verdict is what makes "our backups just stopped" unattributable a week later.
        await this.observeSealFault(scheduler, { kind: "completion-lost", at: Date.now(), downpipeId: doc.checkpoint.downpipeId, runId: doc.checkpoint.runId, outcome: "failed", causeDigest: await causeDigest(m), attemptClasses: [sealAttemptClass(new Error(m))] });
      }
      // G143: the run is being abandoned after riding the WHOLE parking window. Record how long it waited and on
      // whom, before cleanup() deletes the doc that knows.
      doc.throttleAttempt = throttleAttempt;
      await this.observeRunPressure(scheduler, doc, "failed");
      await this.cleanup();
      return;
    }
    // Park: persist ONLY the advanced throttleAttempt (doc.checkpoint and doc.attempt are untouched,
    // so the checkpoint survives the outage) and re-arm on the throttle backoff to wait it out.
    doc.throttleAttempt = throttleAttempt;
    await this.state.storage.put(DOC_KEY, doc);
    await this.state.storage.setAlarm(Date.now() + Math.min(THROTTLE_BASE_MS * 2 ** Math.min(throttleAttempt - 1, BACKOFF_EXP_CAP), THROTTLE_CAP_MS));
  }

  // handleContention rides RUNLOG write CONTENTION (SCALE-3) on its OWN patient ladder, mirroring
  // handleThrottle: another finaliser holds the SAME destination's RUNLOG, so this run's append could not
  // commit this tick. The destination is UP and the run-tree is already committed; the append is idempotent
  // (a duplicate runId/index is not re-added) and the resume re-runs finaliseAndComplete from its preserved
  // checkpoint. Striking such a run toward terminal failure would shed part of a same-destination trigger
  // storm loud, orphaning committed bytes. So contention rides runlogAttempt, which NEVER charges the
  // hard-fault strike counter (attempt) and NEVER cleans up the checkpoint while it waits: bounded
  // cross-invocation QUEUEING. Per-destination keying keeps the lock held only briefly, so a parked run
  // almost always finalises within a few rounds; the SAME maxYields bound the throttle uses caps the window
  // so a pathologically stuck RUNLOG eventually gives up with an honest reason rather than parking forever.
  private async handleContention(scheduler: DurableObjectStub, doc: RunDoc, m: string, dest?: SliceDeps["dest"]): Promise<void> {
    const runlogAttempt = (doc.runlogAttempt ?? 0) + 1;
    const maxYields = throttleMaxYields(this.env);
    log("error", `sliced run ${doc.checkpoint.runId} RUNLOG contended (parking ${runlogAttempt}/${maxYields}, checkpoint preserved): ${await redactedRunError(m)}`);
    if (runlogAttempt >= maxYields) {
      // The destination's RUNLOG has been contended for the entire parking window (a wedged holder, or a
      // truly massive same-destination fleet). finaliseRun wrote the signed root (+ shard manifests) BEFORE
      // the RUNLOG append, so by here there is a committed run-tree with NO RUNLOG entry: an ORPHAN ROOT that
      // a reader can only reach with --allow-stale and whose bytes nothing reclaims. Before giving up, GC
      // that just-written run-tree so the orphan never accumulates (the source data is unchanged, so a fresh
      // run next cadence re-seals it). Then give up with an honest reason.
      const reclaim = await this.reclaimOrphanRunTree(dest, doc.checkpoint.runId);
      // OBSERVE the reclaim OUTCOME (support-pack mode orphan-root-worm-leak): how many orphan-root objects
      // were reclaimed and whether a WORM / Object-Lock destination REFUSED the delete (leaving an irreducible
      // orphan root). Best-effort + fail-open; it never changes the reclaim or the give-up.
      await this.observeSealFault(scheduler, {
        kind: "orphan-root-reclaim",
        at: Date.now(),
        downpipeId: doc.checkpoint.downpipeId,
        runId: doc.checkpoint.runId,
        reclaimed: reclaim.reclaimed,
        wormBlocked: reclaim.wormBlocked,
        // G066: the closed refusal class (worm-locked / access-denied / transient), the LIST-failed sentinel (so
        // reclaimed:0 is no longer ambiguous between "nothing was there" and "we could not look"), and the count
        // of objects actually STRANDED. Counters and enums only.
        ...(reclaim.refusalClass !== undefined ? { wormRefusalClass: reclaim.refusalClass } : {}),
        ...(reclaim.listFailed === true ? { listFailed: true } : {}),
        // G066: the strand CLASS, which is the diagnosis, and the two cases are not the same fault. A delete
        // the destination REFUSED strands a KNOWN set of objects (merge-orphan-runtree, counted). A LIST that
        // failed strands an UNKNOWN set: the engine could not even enumerate what it is leaking, so there is no
        // count to attach -- which is exactly what STRAND_CLASSES means by "bytes the engine stranded and never
        // counted", and why reclaim-list-failed rides on the listFailed arm with no `stranded` figure rather
        // than being folded into the counted class and reported as a smaller leak than it is.
        ...(reclaim.listFailed === true
          ? { strandClass: "reclaim-list-failed" as const }
          : reclaim.stranded > 0
            ? { stranded: reclaim.stranded, strandClass: "merge-orphan-runtree" as const }
            : {}),
      });
      try {
        await this.complete(scheduler, doc.checkpoint, "failed", { error: "RUNLOG persistently contended", causeDigest: await causeDigest(m), ...(doc.destinationId !== undefined ? { destinationId: doc.destinationId } : {}), ...(dest !== undefined ? { dest } : {}) });
      } catch (ce) {
        log("error", `sliced run ${doc.checkpoint.runId} failure completion did not land: ${await redactedRunError((ce as Error).message)}`);
      }
      // G143: a run given up after the whole RUNLOG parking window. Record the park count (the scheduler is the
      // subsystem that held it) before the doc is deleted.
      doc.runlogAttempt = runlogAttempt;
      doc.pressure = withThrottledSubsystem(foldRetryMeter(doc.pressure), "scheduler");
      await this.observeRunPressure(scheduler, doc, "failed");
      await this.cleanup();
      return;
    }
    // Park: persist ONLY the advanced runlogAttempt (doc.checkpoint and doc.attempt untouched, so the
    // checkpoint survives) and re-arm on the same backoff the throttle ladder uses to let the holder finish.
    doc.runlogAttempt = runlogAttempt;
    await this.state.storage.put(DOC_KEY, doc);
    await this.state.storage.setAlarm(Date.now() + Math.min(THROTTLE_BASE_MS * 2 ** Math.min(runlogAttempt - 1, BACKOFF_EXP_CAP), THROTTLE_CAP_MS));
  }

  // reclaimOrphanRunTree best-effort deletes the run/<runId>/ tree (root.manifest.json, its .sig and the
  // shard manifests) that finaliseRun wrote BEFORE the RUNLOG append. It is called ONLY on the contention
  // give-up path, where the RUNLOG append definitively never committed (a committed append completes the run
  // "ok" and we never reach here; the append is an all-or-nothing CAS, never a partial write), so no RUNLOG
  // entry references this tree and deleting it cannot orphan a referenced run. It deletes ONLY the run-tree
  // prefix: the content-addressed seg/ blobs are addressed under PER-RUN keys (a fresh per-run master ->
  // per-run CAK -> per-run segment address, derive.ts), so identical content across runs yields DISTINCT
  // seg/ objects -- a concurrent or next-cadence run does NOT reference this run's keys (dedup is within-run
  // only). This run's seg/ blobs are therefore its OWN, but the best-effort contention give-up deliberately
  // limits itself to the small run-tree manifest prefix and leaves the (potentially many) per-run seg/ blobs
  // untouched, as an accepted orphan a reconcile pass surfaces (the same handling as the WORM-refused orphan
  // below) -- never another run's data. The _RECOVERY/ bundle is destination-global, so it too is left. Every
  // delete is best-effort: a WORM /
  // Object-Lock destination refuses it (that orphan is irreducible by design, and a reconcile pass surfaces
  // it), and a flaky enumerate/delete only logs -- the run still completes failed so the downpipe is never
  // wedged. delete of an absent key is a no-op, so a partial reclaim is harmless.
  // It RETURNS the reclaim OUTCOME (support-pack mode orphan-root-worm-leak): reclaimed = objects actually
  // deleted, wormBlocked = at least one delete was REFUSED with a WORM / Object-Lock / immutability signal
  // (an irreducible orphan by design). The caller records this so a persistently-leaked orphan root on a WORM
  // destination is visible in the pack, not just in the log. undefined dest / an enumerate failure yields a
  // zeroed, un-blocked outcome (nothing was written, or nothing could be enumerated this pass).
  private async reclaimOrphanRunTree(dest: SliceDeps["dest"] | undefined, runId: string): Promise<{ reclaimed: number; wormBlocked: boolean; refusalClass?: WormRefusalClass; listFailed?: boolean; stranded: number }> {
    if (dest === undefined) return { reclaimed: 0, wormBlocked: false, stranded: 0 }; // faulted before the destination was built: nothing written
    let reclaimed = 0;
    let wormBlocked = false;
    let stranded = 0;
    // G066: the SPLIT of the old wormBlocked boolean. WORM_REFUSAL_RE folded "access denied" and "status 403"
    // into the WORM arm, so a ROTATED or UNDER-SCOPED credential was reported to support as "locked by design,
    // nothing to fix" -- while the real fault was a key the operator could fix in a minute. The strictest class
    // seen WINS (worm-locked over access-denied over transient), so one genuine lock refusal is never masked by
    // a transient one. The message is READ only to SELECT the class and is never recorded.
    let refusalClass: WormRefusalClass | undefined;
    const raise = (c: WormRefusalClass): void => {
      const rank = { transient: 0, "access-denied": 1, "worm-locked": 2 } as const;
      if (refusalClass === undefined || rank[c] > rank[refusalClass]) refusalClass = c;
    };
    try {
      const keys = await dest.list(runTreePrefix(runId));
      for (const key of keys) {
        try {
          await dest.delete(key);
          reclaimed++;
        } catch (de) {
          // A delete REFUSED by object-lock / WORM / immutability is the irreducible-orphan case (the SPEC
          // reason this path is best-effort): flag it so the reclaim outcome records WHY the orphan persists.
          // A non-WORM transient failure only lowers `reclaimed`; it does not set the WORM signal.
          if (isWormRefusal((de as Error).message)) wormBlocked = true;
          raise(classifyWormRefusal((de as Error).message));
          stranded++;
          log("error", `orphan-root GC could not delete ${key} (run ${runId}): ${await redactedRunError((de as Error).message)}`);
        }
      }
      log("info", `orphan-root GC reclaimed ${reclaimed} of ${keys.length} run-tree object(s) for contended run ${runId}${wormBlocked ? " (some refused by object-lock/WORM)" : ""}`);
    } catch (le) {
      // G066: an empty reclaim reads identically whether nothing existed or the LIST call failed, which would
      // make a permanently-leaking run-tree look like a clean one. listFailed is that distinction.
      log("error", `orphan-root GC could not enumerate ${runTreePrefix(runId)}: ${await redactedRunError((le as Error).message)}`);
      return { reclaimed, wormBlocked, ...(refusalClass !== undefined ? { refusalClass } : {}), listFailed: true, stranded };
    }
    return { reclaimed, wormBlocked, ...(refusalClass !== undefined ? { refusalClass } : {}), stranded };
  }

  // handleHardFault is the strike ladder for a hard slice fault (anything that is NOT a 503/429 throttle).
  // It increments attempt, and at MAX_SLICE_FAILURES resolves the history row failed + frees the lease so
  // the next due tick starts a FRESH run; otherwise it re-arms on the strike backoff.
  private async handleHardFault(scheduler: DurableObjectStub, doc: RunDoc, m: string, dest?: Destination): Promise<void> {
    doc.attempt += 1;
    // NC-2: the raw message can embed a record name; the log line carries the coarse
    // class + a one-way digest for correlation instead.
    log("error", `sliced run ${doc.checkpoint.runId} slice failed (attempt ${doc.attempt}): ${await redactedRunError(m)}`);
    if (doc.attempt >= MAX_SLICE_FAILURES) {
      // Terminal: resolve the history row with the coarse reason and free the lease; the
      // next due tick starts a FRESH run. A fresh run derives a NEW per-run master, so its
      // content addresses differ and it does NOT dedup against segments this failed run
      // landed (those become unreferenced destination objects). Re-seal dedup holds only
      // WITHIN a resumed run under the same master (the checkpoint resume path above).
      try {
        await this.complete(scheduler, doc.checkpoint, "failed", { error: coarseRunError(m), causeDigest: await causeDigest(m), ...(doc.destinationId !== undefined ? { destinationId: doc.destinationId } : {}), ...(dest !== undefined ? { dest } : {}) });
      } catch (ce) {
        log("error", `sliced run ${doc.checkpoint.runId} failure completion did not land: ${await redactedRunError((ce as Error).message)}`);
        // G109: the run struck out, the engine knows WHY, and the verdict did not land -- so the row resolves via
        // lease reclaim as a generic "abandoned" and the real cause is gone. Record the computed verdict + its
        // CLOSED coarse class (sealAttemptClass reads the error's type/shape and returns an enum member; the raw
        // message never rides) and the cause digest that joins it to the customer's own log line.
        await this.observeSealFault(scheduler, { kind: "completion-lost", at: Date.now(), downpipeId: doc.checkpoint.downpipeId, runId: doc.checkpoint.runId, outcome: "failed", causeDigest: await causeDigest(m), attemptClasses: [sealAttemptClass(new Error(m))] });
      }
      // G143: the run has struck out. Record the whole pressure history (retries, parks, the ordered strike
      // classes) before cleanup() deletes the only thing that holds it.
      await this.observeRunPressure(scheduler, doc, "failed");
      await this.cleanup();
      return;
    }
    await this.state.storage.put(DOC_KEY, doc);
    const backoff = Math.min(RETRY_BASE_MS * 2 ** Math.min(doc.attempt - 1, BACKOFF_EXP_CAP), RETRY_CAP_MS);
    await this.state.storage.setAlarm(Date.now() + backoff);
  }

  // complete reads only the identity + count fields, which the in-memory and the stored
  // checkpoint forms share (they differ only in the cursor representation).
  private async complete(scheduler: DurableObjectStub, cp: RunCheckpoint | StoredRunCheckpoint, status: "ok" | "failed", opts: CompleteOptions = {}): Promise<void> {
    const { error, causeDigest: cause, destinationId, sealVerification, dest } = opts;
    // The coarse failure class the row records. Hoisted because the DEST-1 down-destination attribution keys on
    // it (gap G062): only a DESTINATION-ACCESS class may name a bucket down, never a source or config fault.
    const coarse = error ?? "run failed";
    const resp = await scheduler.fetch(doURL("/complete"), {
      method: "POST",
      body: JSON.stringify({
        id: cp.downpipeId,
        runId: status === "ok" ? cp.runId : "",
        index: cp.runlogIndex,
        status,
        ...(status === "ok"
          ? {
              destinationId, // the failover-chosen origin this run sealed to (recorded + seeds repl state)
              recordCount: cp.counts.records,
              bytes: cp.counts.bytes,
              archiveBytesWritten: cp.counts.archiveBytesWritten,
              segmentsWritten: cp.counts.objectsWritten,
              durationMs: cp.counts.durationMs,
              recordsSkipped: cp.counts.recordsSkippedChanged, // surface records the seal could not capture
              ...(cp.counts.recordsVanished > 0 ? { recordsVanished: cp.counts.recordsVanished } : {}), // WS-P2: in-scope objects deleted between list and read (mid-crawl); only when non-zero
              recordsIncomplete: cp.counts.recordsIncomplete, // R1-1: records sealed as incompleteness sentinels (not the real bytes)
              ...(Object.keys(cp.counts.incompleteByMarker).length > 0 ? { incompleteByMarker: cp.counts.incompleteByMarker } : {}), // R1-1 per-marker breakdown (which kinds); only when non-empty
              ...(Object.keys(cp.counts.incompleteIds).length > 0 ? { incompleteIds: cp.counts.incompleteIds } : {}), // WS-P1 per-kind attribution (which surface); only when non-empty
              opCounts: cp.counts.opCounts, // exact per-resource Cloudflare op tally (cost Phase 3)
              ...(sealVerification !== undefined ? { sealVerification } : {}),
              // G062 parity: the inline ok body stamps the stranded-multipart-parts boolean; a SLICED run that
              // stranded parts on a later slice must report it too (a strand can accompany an ok run).
              ...multipartAbortFlag(dest),
            }
          : {
              error: coarse,
              ...(cause !== undefined ? { causeDigest: cause } : {}),
              // G062 parity: a sliced run whose seal faulted ON THE DESTINATION names that destination down, so
              // the map's per-destination indicator lights up for a sole-destination outage exactly as it does
              // for an inline run. Only on a destination-access class, only with a resolved destination id.
              ...downDestinationFlag(coarse, destinationId),
              ...multipartAbortFlag(dest),
            }),
      }),
      headers: { "content-type": "application/json" },
    });
    // G109: a REFUSED completion (a non-2xx: the scheduler DO answered and rejected it) never threw, so not one
    // of the fail-soft catch arms around this call ever saw it -- the computed verdict was dropped on the floor
    // in complete SILENCE and the row resolved later as a generic "abandoned". This is the arm that made "the
    // run says abandoned but the archive restores fine" unfalsifiable. The control flow is UNCHANGED (still no
    // throw: a completion blip must never re-run a sealed downpipe under a fresh master); the verdict is now
    // recorded on the ring instead of lost.
    if (!resp.ok) {
      await this.observeSealFault(scheduler, {
        kind: "completion-lost",
        at: Date.now(),
        downpipeId: cp.downpipeId,
        runId: cp.runId,
        outcome: status,
        ...(cause !== undefined ? { causeDigest: cause } : {}),
      });
    }
  }

  // ---- Fix 2b fan-out: COORDINATOR + WORKER roles -----------------------------------------------------

  // handleStartFanout initialises the per-downpipe DO as the fan-out COORDINATOR and takes the scheduler
  // lease. A DIRECT plan (body.ranges present: the run fit the front sample) goes straight to the AWAIT
  // phase and spawns its workers now -- the original behaviour. A SCAN plan (body.ranges absent: the run is
  // larger than the front sample, Fix 2b H2) persists a PLAN-phase doc and lets the alarm run the sliced,
  // keys-only count-then-stride that sizes BALANCED ranges before spawning. Either way a refused worker
  // spawn fails the handoff loudly so sealRunSliced can post a failed completion rather than strand the run.
  private async handleStartFanout(req: Request): Promise<Response> {
    let body: StartFanout;
    try {
      body = (await req.json()) as StartFanout;
    } catch {
      return json({ error: "invalid request body" }, 400);
    }
    if (body.ranges !== undefined && body.ranges.length > 0) {
      const ranges = body.ranges;
      const doc: CoordinatorDoc = {
        kind: "coordinator",
        config: body.config,
        base: body.base,
        selector: body.selector,
        wrappedMaster: body.wrappedMaster,
        ranges,
        doneRanges: ranges.map(() => null),
        counts: zeroFanoutCounts(),
        phase: "await",
        attempt: 0,
        progress: ranges.map(() => null), // H1: per-range last-polled liveness fingerprint
        rangeStrikes: ranges.map(() => 0), // H1: per-range consecutive no-progress tick count
        destConfig: body.destConfig ?? null,
        ...(body.destinationId !== undefined ? { destinationId: body.destinationId } : {}),
      };
      await this.state.storage.put(DOC_KEY, doc);
      try {
        await this.spawnWorkers(doc, ranges);
      } catch {
        return json({ error: "fan-out worker spawn refused" }, 500);
      }
      await this.heartbeatBase(schedulerStub(this.env), body.base);
      await this.state.storage.setAlarm(Date.now() + COORDINATOR_HEARTBEAT_MS);
      return json({ ok: true });
    }
    // SCAN plan: persist a plan-phase coordinator doc (ranges deferred to the sliced count-then-stride).
    const doc: CoordinatorDoc = {
      kind: "coordinator",
      config: body.config,
      base: body.base,
      selector: body.selector,
      wrappedMaster: body.wrappedMaster,
      ranges: [],
      doneRanges: [],
      counts: zeroFanoutCounts(),
      phase: "plan",
      attempt: 0,
      planScan: newPlanScan(),
      planToken: null,
      destConfig: body.destConfig ?? null,
      ...(body.destinationId !== undefined ? { destinationId: body.destinationId } : {}),
    };
    await this.state.storage.put(DOC_KEY, doc);
    await this.heartbeatBase(schedulerStub(this.env), body.base);
    await this.state.storage.setAlarm(Date.now() + NEXT_SLICE_DELAY_MS);
    return json({ ok: true });
  }

  // spawnWorkers spawns ONE worker DO per range (named <downpipeId>#r<i>), each given the SHARED wrapped
  // master so it derives identical keys / content addresses, the half-open range in its selector, and the
  // coordinator id to report /range-done to. A refused spawn THROWS so the caller fails the handoff / strikes
  // rather than leave a half-spawned run reporting ok. (One worker per range is the documented first-cut
  // model; a bounded-worker work queue draining the ranges is the follow-up -- see fanout.ts FANOUT_MAX_RANGES.)
  private async spawnWorkers(doc: CoordinatorDoc, ranges: FanoutRange[]): Promise<void> {
    for (let i = 0; i < ranges.length; i++) {
      const payload: StartRange = {
        config: doc.config,
        base: doc.base,
        selector: doc.selector,
        range: ranges[i]!,
        rangeIndex: i,
        wrappedMaster: doc.wrappedMaster,
        coordinatorId: doc.base.downpipeId,
        destConfig: doc.destConfig ?? null,
        ...(doc.destinationId !== undefined ? { destinationId: doc.destinationId } : {}),
      };
      const resp = await runSealStub(this.env, `${doc.base.downpipeId}#r${i}`).fetch(new Request("https://runseal.internal/start-range", { method: "POST", body: JSON.stringify(payload), headers: { "content-type": "application/json" } }));
      if (!resp.ok) throw new Error(`fan-out worker spawn refused for range ${i}: status ${resp.status}`);
    }
  }

  // handleStartRange initialises this DO as a fan-out WORKER for one range: a fresh slice-0 checkpoint with
  // rangeIndex set (so the slice emits composite SCRATCH ids) and the range in its selector, sealing under
  // the SHARED wrapped master. It reports to coordinatorId on completion. The cursor wrap happens at the
  // storage boundary exactly as a serial /start does.
  private async handleStartRange(req: Request): Promise<Response> {
    let body: StartRange;
    try {
      body = (await req.json()) as StartRange;
    } catch {
      return json({ error: "invalid request body" }, 400);
    }
    const signerKey = requireEnv(this.env.SIGNER_PRIVATE, "SIGNER_PRIVATE");
    const cp: RunCheckpoint = {
      v: 1,
      downpipeId: body.base.downpipeId,
      downpipeName: body.base.downpipeName,
      cadence: body.base.cadence,
      sourceType: body.base.sourceType,
      selector: { include: body.selector.include, exclude: body.selector.exclude, range: body.range },
      runId: body.base.runId,
      runlogIndex: body.base.runlogIndex,
      prevRunId: body.base.prevRunId,
      startedAt: body.base.startedAt,
      wrappedMaster: body.wrappedMaster,
      cursor: null,
      sourceDone: false,
      nextRecordIndex: 0,
      nextShardIndex: 0,
      frontier: { count: 0, nodes: [] },
      counts: zeroCounts(),
      sliceCount: 0,
      partialRecord: null,
      rangeIndex: body.rangeIndex,
    };
    const stored = await sealCheckpointForStorage(signerKey, cp);
    const doc: RunDoc = { config: body.config, checkpoint: stored, attempt: 0, coordinatorId: body.coordinatorId, destConfig: body.destConfig ?? null, openBatchSeqStart: 0, openBatchSeqEnd: 0, ...(body.destinationId !== undefined ? { destinationId: body.destinationId } : {}) };
    await this.state.storage.put(DOC_KEY, doc);
    await this.state.storage.setAlarm(Date.now() + NEXT_SLICE_DELAY_MS);
    return json({ ok: true });
  }

  // handleRangeDone records a worker's finished range. When the LAST range arrives it arms the sliced
  // merge (newMergeState over every range's global-sorted scratch shards). It is idempotent: a duplicate
  // report (a re-sent /range-done after a worker retry) is ignored once the range is recorded or the merge
  // has started, so a range can never be double-counted into the global counts.
  private async handleRangeDone(req: Request): Promise<Response> {
    let body: RangeDone;
    try {
      body = (await req.json()) as RangeDone;
    } catch {
      return json({ error: "invalid request body" }, 400);
    }
    const doc = await this.state.storage.get<CoordinatorDoc>(DOC_KEY);
    const scheduler = schedulerStub(this.env);
    // OBSERVE every DISCARDED worker report (support-pack mode fanout-report-discarded, gap G062). Each discard
    // below is CORRECT -- it is what makes /range-done idempotent -- but a fan-out run that hangs (or whose
    // counts look short) because reports are being dropped would otherwise leave NO trace anywhere. Recording the
    // closed class + the range index makes it diagnosable. Best-effort + fail-open; the discard is unchanged.
    if (doc?.kind !== "coordinator" || doc.phase !== "await") {
      await this.observeSealFault(scheduler, { kind: "fanout-report-discarded", at: Date.now(), discardClass: "stale-phase", rangeIndex: Number.isInteger(body.rangeIndex) ? body.rangeIndex : 0, ...(doc?.kind === "coordinator" ? { downpipeId: doc.base.downpipeId, runId: doc.base.runId } : {}) });
      return json({ ok: true }); // stale / already merging
    }
    if (!Number.isInteger(body.rangeIndex) || body.rangeIndex < 0 || body.rangeIndex >= doc.doneRanges.length) {
      await this.observeSealFault(scheduler, { kind: "fanout-report-discarded", at: Date.now(), discardClass: "out-of-bounds", downpipeId: doc.base.downpipeId, runId: doc.base.runId });
      return json({ error: "range index out of bounds" }, 400);
    }
    if (doc.doneRanges[body.rangeIndex] === null) {
      doc.doneRanges[body.rangeIndex] = body;
      doc.counts = addCheckpointCounts(doc.counts, body.counts);
    } else {
      await this.observeSealFault(scheduler, { kind: "fanout-report-discarded", at: Date.now(), discardClass: "duplicate-range", rangeIndex: body.rangeIndex, downpipeId: doc.base.downpipeId, runId: doc.base.runId });
    }
    const allDone = doc.doneRanges.every((d) => d !== null);
    if (allDone) {
      // Carry the COUNT-pass authoritative total onto the merge (defense-in-depth under-crawl cross-check);
      // absent on a DIRECT-planned run, so the cross-check is skipped there.
      doc.merge = newMergeState(doc.doneRanges.flatMap((d) => d!.shards), doc.plannedRecordTotal);
      doc.phase = "merge";
      doc.mergeOpenSeqStart = 0;
      doc.mergeOpenSeqEnd = 0;
    }
    await this.state.storage.put(DOC_KEY, doc);
    if (allDone) await this.state.storage.setAlarm(Date.now() + NEXT_SLICE_DELAY_MS);
    return json({ ok: true });
  }

  // handleRangeFailed fails the whole run honestly when a worker reports its range terminally failed (its
  // own strike ladder exhausted). The source data is unchanged, so a fresh run next cadence re-seals it;
  // the lease is freed so the next due tick starts that fresh run. (Worker-crash/retry RECOVERY -- re-
  // spawning just the failed range under the shared master -- is a documented DEFER; this fails closed.)
  private async handleRangeFailed(req: Request): Promise<Response> {
    let body: RangeFailed;
    try {
      body = (await req.json()) as RangeFailed;
    } catch {
      return json({ error: "invalid request body" }, 400);
    }
    const doc = await this.state.storage.get<CoordinatorDoc>(DOC_KEY);
    const scheduler = schedulerStub(this.env);
    if (doc?.kind !== "coordinator" || doc.phase !== "await") {
      // A range-failed report arriving after the merge began is DISCARDED (mirrors handleRangeDone). Observe it:
      // a run that completed ok while a worker was reporting a terminal range failure is worth seeing (G062).
      await this.observeSealFault(scheduler, { kind: "fanout-report-discarded", at: Date.now(), discardClass: "stale-phase", rangeIndex: Number.isInteger(body.rangeIndex) ? (body.rangeIndex ?? 0) : 0, ...(doc?.kind === "coordinator" ? { downpipeId: doc.base.downpipeId, runId: doc.base.runId } : {}) });
      return json({ ok: true });
    }
    const coarse = body.reason ?? "fan-out range failed";
    try {
      // G062 parity: the FAILED fan-out row now reads like a failed inline row. The worker's 12-hex causeDigest
      // (computed at the fault's detection point, over the raw message it never sends) rides through so support
      // can join the row to the customer's Logpush `[cause <hex>]` line; a destination-class failure names the
      // destination down (DEST-1); a stranded multipart abort is flagged. Each value is RE-GATED here at the
      // trust boundary (the coordinator is receiving a cross-DO body), so a drifted/hostile worker cannot push
      // free text or an arbitrary id onto the run row.
      await scheduler.fetch(doURL("/complete"), {
        method: "POST",
        body: JSON.stringify({
          id: doc.base.downpipeId,
          runId: "",
          index: doc.base.runlogIndex,
          status: "failed",
          error: coarse,
          ...(isCauseDigest(body.causeDigest) ? { causeDigest: body.causeDigest } : {}),
          ...downDestinationFlag(coarse, doc.destinationId),
          ...(body.multipartAbortFailed === true ? { multipartAbortFailed: true } : {}),
        }),
        headers: { "content-type": "application/json" },
      });
    } catch (e) {
      log("error", `fan-out range-failed completion did not land: ${await redactedRunError((e as Error).message)}`);
    }
    await this.cleanup();
    return json({ ok: true });
  }

  // heartbeatBase asks the scheduler whether this run still owns the downpipe lease, from an explicit run
  // identity (the coordinator holds no per-record checkpoint, so it cannot use heartbeatOwned's doc form).
  private async heartbeatBase(scheduler: DurableObjectStub, base: RunBase): Promise<boolean> {
    const hb = (await (await scheduler.fetch(doURL("/heartbeat"), { method: "POST", body: JSON.stringify({ id: base.downpipeId, runId: base.runId, index: base.runlogIndex }), headers: { "content-type": "application/json" } })).json()) as { owned: boolean };
    return hb.owned;
  }

  // workerAlarm advances a WORKER by one slice (reusing the serial runSliceStep, which emits composite ids
  // because the checkpoint carries rangeIndex) and, when its range crawl is exhausted, range-finalises:
  // seals the leftover open shard and reports /range-done. It does NOT heartbeat the scheduler (the
  // coordinator holds the single lease). A fault rides workerFault's ladder.
  private async workerAlarm(doc: RunDoc): Promise<void> {
    // The destination this worker sealed through, hoisted so workerFault can carry the SAME destination-attributed
    // signals an inline failure does (gap G062). Undefined when the invocation faulted before the destination was
    // built (nothing written, so nothing stranded and no bucket to blame).
    let dest: Destination | undefined;
    try {
      const budget = budgetFromEnv(this.env);
      const signerKey = requireEnv(this.env.SIGNER_PRIVATE, "SIGNER_PRIVATE");
      // KV (the only fanned-out source) is a binding source, so it needs no discovery token.
      const deps = await sliceDepsFromEnv(this.env, doc.config, budget, { destOverride: doc.destConfig ?? null });
      dest = deps.dest;
      try {
        const cp = await this.openAndMigrate(signerKey, doc);
        const master = await unwrapMaster(signerKey, cp.runId, cp.wrappedMaster);
        try {
          const advanced = cp.sourceDone ? cp : await this.runSliceStep(signerKey, deps, budget, doc, cp, master);
          if (advanced === null) return; // re-armed for the next slice
          await this.rangeFinalise(deps, doc, advanced, master, signerKey);
        } finally {
          master.fill(0);
        }
      } finally {
        deps.signer.mldsaSecret.fill(0);
      }
    } catch (e) {
      await this.workerFault(doc, (e as Error).message, dest);
    }
  }

  // rangeFinalise seals the worker's leftover OPEN shard as its final composite SCRATCH shard, gathers all
  // its scratch shards in seal order, and reports /range-done to the coordinator. The open-shard count is
  // cross-checked against the re-loaded batch lines (the same fail-loud guard the serial finalise uses), so
  // a short read refuses to report a truncated range rather than silently drop records.
  private async rangeFinalise(deps: SliceDeps, doc: RunDoc, cp: RunCheckpoint, master: Uint8Array, signerKey: string): Promise<void> {
    const openLines = await this.loadOpenLines(signerKey, cp.runId, doc.openBatchSeqStart ?? 0, doc.openBatchSeqEnd ?? 0, cp.downpipeId);
    const expectedOpen = cp.openShard?.count ?? 0;
    // G108: the WORKER's completeness guards are the ones the serial finalise's observes never had. A fan-out
    // range that refuses to report itself fails the WHOLE run (the coordinator can never merge), and both of
    // these refusals are recorded here rather than leaving only a raw message that coarsens to a generic
    // failed row.
    const scheduler = schedulerStub(this.env);
    if (openLines.length !== expectedOpen) {
      await this.observeSealFault(scheduler, { kind: "open-shard-count-mismatch", at: Date.now(), downpipeId: cp.downpipeId, runId: cp.runId, found: openLines.length, expected: expectedOpen, ...(cp.rangeIndex !== undefined ? { rangeIndex: cp.rangeIndex } : {}) });
      throw new Error(`worker open-shard enumeration incomplete: loaded ${openLines.length} of ${expectedOpen} buffered lines; refusing to report a short range`);
    }
    const flushed = await this.listAllShards();
    if (flushed.length < cp.nextShardIndex) {
      await this.observeSealFault(scheduler, { kind: "shard-list-truncated", at: Date.now(), downpipeId: cp.downpipeId, runId: cp.runId, found: flushed.length, expected: cp.nextShardIndex, ...(cp.rangeIndex !== undefined ? { rangeIndex: cp.rangeIndex } : {}) });
      throw new Error(`worker shard enumeration incomplete: found ${flushed.length} of ${cp.nextShardIndex}; refusing to report a truncated range`);
    }
    const openEntry = await sealRangeOpenShard(deps, cp, master, openLines);
    const shards = openEntry !== null ? [...flushed, openEntry] : flushed;
    shards.sort((a, b) => Number(a.id) - Number(b.id));
    const report: RangeDone = { rangeIndex: cp.rangeIndex ?? 0, shards, recordCount: cp.counts.records, counts: cp.counts };
    const resp = await runSealStub(this.env, doc.coordinatorId!).fetch(new Request("https://runseal.internal/range-done", { method: "POST", body: JSON.stringify(report), headers: { "content-type": "application/json" } }));
    if (!resp.ok) throw new Error(`coordinator /range-done refused: status ${resp.status}`);
    await this.cleanup();
  }

  // reportRangeFailed best-effort tells the coordinator that this worker's range terminally failed (its
  // strike or throttle ladder is exhausted), then cleans up the worker. The coordinator fails the whole run
  // honestly; a delivery hiccup only logs (the coordinator's lease reclaim is the backstop).
  private async reportRangeFailed(doc: RunDoc, reason: string, m: string, dest?: Destination): Promise<void> {
    try {
      // G062: the worker computes the 12-hex causeDigest of the RAW fault HERE, at the detection point (the raw
      // message never leaves this DO: causeDigest is a one-way SHA-384 prefix), and reports it with the coarse
      // reason + the stranded-parts boolean. The coordinator forwards them onto the failed run row, which is what
      // gives a fan-out failure the same joinable, destination-attributed evidence an inline failure has.
      const report: RangeFailed = { rangeIndex: doc.checkpoint.rangeIndex ?? 0, reason, causeDigest: await causeDigest(m), ...multipartAbortFlag(dest) };
      await runSealStub(this.env, doc.coordinatorId!).fetch(new Request("https://runseal.internal/range-failed", { method: "POST", body: JSON.stringify(report), headers: { "content-type": "application/json" } }));
    } catch (re) {
      log("error", `fan-out worker could not report range failure: ${await redactedRunError((re as Error).message)}`);
    }
    await this.cleanup();
  }

  // workerFault rides a worker slice fault: a THROTTLE (503/429) parks-and-resumes (no strike, checkpoint
  // preserved) on its own patient ladder bounded by throttleMaxYields; a hard fault strikes. On EITHER
  // ladder's exhaustion (MAX_SLICE_FAILURES strikes, or a sustained throttle past the parking window) the
  // worker reports /range-failed and the coordinator fails the run honestly, so a permanently stuck worker
  // can never hang the coordinator in await forever.
  private async workerFault(doc: RunDoc, m: string, dest?: Destination): Promise<void> {
    if (/(status|HTTP) (503|429)/.test(m)) {
      const throttleAttempt = (doc.throttleAttempt ?? 0) + 1;
      const maxYields = throttleMaxYields(this.env);
      if (throttleAttempt >= maxYields) {
        log("error", `fan-out worker ${doc.checkpoint.runId} throttled for the whole parking window; failing the range`);
        await this.reportRangeFailed(doc, "destination unavailable (sustained throttling)", m, dest);
        return;
      }
      log("error", `fan-out worker ${doc.checkpoint.runId} throttled (parking ${throttleAttempt}/${maxYields}, checkpoint preserved): ${await redactedRunError(m)}`);
      doc.throttleAttempt = throttleAttempt;
      await this.state.storage.put(DOC_KEY, doc);
      await this.state.storage.setAlarm(Date.now() + Math.min(THROTTLE_BASE_MS * 2 ** Math.min(throttleAttempt - 1, BACKOFF_EXP_CAP), THROTTLE_CAP_MS));
      return;
    }
    doc.attempt += 1;
    log("error", `fan-out worker ${doc.checkpoint.runId} slice failed (attempt ${doc.attempt}): ${await redactedRunError(m)}`);
    if (doc.attempt >= MAX_SLICE_FAILURES) {
      await this.reportRangeFailed(doc, coarseRunError(m), m, dest);
      return;
    }
    await this.state.storage.put(DOC_KEY, doc);
    await this.state.storage.setAlarm(Date.now() + Math.min(RETRY_BASE_MS * 2 ** Math.min(doc.attempt - 1, BACKOFF_EXP_CAP), RETRY_CAP_MS));
  }

  // coordinatorAlarm drives the coordinator state machine. While WAITING it heartbeats the lease and re-
  // arms (the workers seal in parallel; /range-done flips it to merge). In the MERGE phase it runs one
  // mergeStep on a fresh budget, persists the advanced merge state + carried buffer, and on completion
  // reclaims the scratch shards, verifies-at-seal and posts the ok /complete. A merge fault rides
  // coordinatorFault. It heartbeats first: a lost lease (a newer run reclaimed the downpipe) abandons cleanly.
  private async coordinatorAlarm(doc: CoordinatorDoc): Promise<void> {
    const scheduler = schedulerStub(this.env);
    // The destination the merge sealed through, hoisted so coordinatorFault can attribute a destination-class
    // merge failure to it (gap G062), exactly as the serial alarm does.
    let dest: Destination | undefined;
    try {
      if (!(await this.heartbeatBase(scheduler, doc.base))) {
        log("error", `fan-out coordinator ${doc.base.runId} lost its lease; abandoning (a newer run owns ${doc.base.downpipeId})`);
        // OBSERVE the clean abandon (support-pack mode lease-lost-abandon), which a SERIAL resume already posts
        // and the coordinator never did (gap G062): the fan-out population -- the biggest customers -- were the
        // ones whose lease-reclaim events left no record at all. Best-effort + fail-open; the abandon is unchanged.
        await this.observeSealFault(scheduler, { kind: "lease-lost-abandon", at: Date.now(), downpipeId: doc.base.downpipeId, runId: doc.base.runId });
        await this.cleanup();
        return;
      }
      if (doc.phase === "plan") {
        await this.planTick(scheduler, doc); // Fix 2b H2: one sliced count/stride step, then spawn or downgrade
        return;
      }
      if (doc.phase === "await") {
        await this.awaitTick(scheduler, doc); // H1: poll worker progress, strike a stall, re-arm/fail-closed
        return;
      }
      const signerKey = requireEnv(this.env.SIGNER_PRIVATE, "SIGNER_PRIVATE");
      const budget = budgetFromEnv(this.env);
      const deps = await sliceDepsFromEnv(this.env, doc.config, budget, { destOverride: doc.destConfig ?? null });
      dest = deps.dest;
      try {
        const master = await unwrapMaster(signerKey, doc.base.runId, doc.wrappedMaster);
        try {
          const cp = this.mergeCheckpoint(doc);
          const carried = await this.loadOpenLines(signerKey, doc.base.runId, doc.mergeOpenSeqStart ?? 0, doc.mergeOpenSeqEnd ?? 0, doc.base.downpipeId);
          // G108: the merge is where a fan-out run REFUSES TO SIGN -- a missing / corrupted scratch shard, a
          // merged-vs-declared count mismatch, an under-crawl against the authoritative key count. Every one of
          // those guards computes the counts that size the shortfall and then throws them away with the
          // exception. mergeStep is PURE (a Destination and a budget, no DO stub), so it NOTES them into the
          // isolate-local run-observation ledger; this -- the one place the merge's isolate ends -- drains and
          // posts them, exactly as the crawl path does. The finally runs BEFORE the fault ladder, so a refusal
          // reaches the ring even though the run produced no archive at all. reportRunFaults never throws.
          beginRunFaults();
          let r: MergeStepResult;
          try {
            r = await mergeStep(deps, cp, master, doc.merge!, carried, runlogLockVia(scheduler, doc.destinationId));
          } finally {
            await reportRunFaults(scheduler, doc.base.downpipeId, deps.dest);
          }
          if (!r.done) {
            await this.persistMerge(signerKey, doc, r);
            await this.state.storage.setAlarm(Date.now() + NEXT_SLICE_DELAY_MS);
            return;
          }
          // The merge is complete (the single signed root + bundle + RUNLOG are written). Verify the
          // just-written archive (fail-open), post the ok completion, and ONLY THEN reclaim the scratch
          // shards. The ordering matters for crash safety: scratch shards are deleted from the destination,
          // so deleting them BEFORE /complete would let a crash mid-delete re-fire this alarm, re-read a
          // now-missing scratch shard and falsely fail an archive that is in fact complete. With the delete
          // last, a crash before /complete re-runs the merge cleanly (scratch still present, re-seal
          // idempotent), and a crash after /complete only leaves harmless orphan scratch shards (a reconcile
          // pass reclaims them) on an already-ok run. verify reads the signed root's FINAL shards, never the
          // scratch shards, so their lingering presence does not affect the verdict.
          const sealVerification = await runSealVerification({ env: this.env, scheduler, dest: deps.dest, downpipe: { id: doc.base.downpipeId, name: doc.base.downpipeName }, master }, doc.base.runId, doc.counts.bytes);
          try {
            await this.completeFanout(scheduler, doc, deps.dest, sealVerification);
          } catch (ce) {
            // G109: the merged archive is COMPLETE -- root signed, bundle written, RUNLOG appended -- and the ok
            // completion did not land. The strike ladder below will retry (the merge is idempotent and the scratch
            // shards are still present, which is exactly why the delete comes last), but if it strikes out the run
            // is booked FAILED against a bucket holding a perfect archive. Record the computed verdict, then
            // re-throw so the ladder behaves exactly as before.
            await this.observeSealFault(scheduler, { kind: "completion-lost", at: Date.now(), downpipeId: doc.base.downpipeId, runId: doc.base.runId, outcome: "ok" });
            throw ce;
          }
          await deleteScratchShards(deps, r.state.scratchShards);
          await this.cleanup();
        } finally {
          master.fill(0);
        }
      } finally {
        deps.signer.mldsaSecret.fill(0);
      }
    } catch (e) {
      await this.coordinatorFault(scheduler, doc, (e as Error).message, dest);
    }
  }

  // planTick advances the SLICED, keys-only balanced plan (Fix 2b H2) by one budget's worth of list pages.
  // It drives listKeysFrom over the WHOLE keyspace (NO value reads) in two sub-passes: COUNT tallies the
  // in-scope keys, then STRIDE captures the M-1 balanced boundary keys at floor(i*total/M). The scan is
  // bounded-memory (it never holds the key list) and RESUMES across alarms via the persisted planScan +
  // planToken, mirroring the serial sliced crawl. When STRIDE completes it sizes BALANCED ranges and either
  // SPAWNS the workers (beginAwait) or, when the true count is below the min-records threshold (the un-clamp)
  // or the keyspace cannot split, DOWNGRADES to the byte-identical serial seal. A fault rides coordinatorFault,
  // which re-persists the doc with planScan/planToken intact so the strike ladder RESUMES the plan, not restart.
  private async planTick(scheduler: DurableObjectStub, doc: CoordinatorDoc): Promise<void> {
    const budget = budgetFromEnv(this.env);
    const deps = await sliceDepsFromEnv(this.env, doc.config, budget, { destOverride: doc.destConfig ?? null });
    try {
      const src = deps.source;
      if (!hasKeySampler(src)) throw new Error("fan-out plan: source does not support a keys-only planning scan");
      // Work on a CLONE so a fault mid-slice leaves the persisted planScan/planToken consistent: a partly
      // advanced scan paired with the stale persisted token would otherwise double-count on resume.
      const prev = doc.planScan ?? newPlanScan();
      const scan: FanoutPlanScan = { pass: prev.pass, scanned: prev.scanned, total: prev.total, rangeCount: prev.rangeCount, targets: [...prev.targets], splits: [...prev.splits] };
      let token = doc.planToken ?? null;
      const selector: Selector = { include: doc.selector.include, exclude: doc.selector.exclude }; // whole keyspace (no range)
      let complete = false;
      let broke = false;
      for await (const ev of src.listKeysFrom(selector, token, deps.budget)) {
        if (scan.pass === "count") countPage(scan, ev.keys.length);
        else stridePage(scan, ev.keys);
        token = ev.token;
        if (ev.last) {
          complete = true;
          broke = true;
          break;
        }
        if (deps.budget.shouldYield()) {
          broke = true;
          break;
        }
      }
      if (!broke) complete = true; // the scan exhausted naturally (the final page carried no in-range keys)
      if (!complete) {
        // Paused mid-pass for the budget: persist progress + the resume token and re-arm (the sliced resume).
        doc.planScan = scan;
        doc.planToken = token;
        await this.state.storage.put(DOC_KEY, doc);
        await this.state.storage.setAlarm(Date.now() + NEXT_SLICE_DELAY_MS);
        return;
      }
      if (scan.pass === "count") {
        // COUNT done: size the plan from the REAL total (the SCALE_FANOUT_MIN_RECORDS un-clamp) and run STRIDE.
        finishCount(scan, fanoutRangeCount(this.env), FANOUT_MAX_RANGE_KEYS, FANOUT_MAX_RANGES);
        doc.planScan = scan;
        doc.planToken = null; // STRIDE re-scans from the start
        await this.state.storage.put(DOC_KEY, doc);
        await this.state.storage.setAlarm(Date.now() + NEXT_SLICE_DELAY_MS);
        return;
      }
      // STRIDE done: build the BALANCED ranges from the captured boundary keys.
      const ranges = rangesFromSplitKeys(scan.splits);
      if (scan.total < fanoutMinRecords(this.env) || ranges.length < 2) {
        // The true count is below the threshold (now KNOWN, not clamped to the front sample), or the keyspace
        // cannot split into >= 2 ranges: a fan-out would only add merge overhead, so downgrade to serial.
        await this.downgradeToSerial(doc, scan.total);
        return;
      }
      await this.beginAwait(scheduler, doc, ranges, scan.total);
    } finally {
      deps.signer.mldsaSecret.fill(0);
    }
  }

  // beginAwait transitions the coordinator from PLAN to AWAIT: it records the balanced ranges, seeds the
  // per-range done/progress/strike state, clears the plan scratch, persists, then spawns ONE worker per
  // range and arms the heartbeat. The doc is persisted BEFORE the spawn so a half-spawn self-heals via the
  // H1 await ladder (an unreachable worker strikes the run closed) rather than leaving the coordinator inert.
  // plannedRecordTotal is the COUNT-pass authoritative in-scope key total, captured here (before planScan is
  // dropped) and carried to the merge for the defense-in-depth under-crawl cross-check.
  private async beginAwait(scheduler: DurableObjectStub, doc: CoordinatorDoc, ranges: FanoutRange[], plannedRecordTotal: number): Promise<void> {
    doc.phase = "await";
    doc.ranges = ranges;
    doc.doneRanges = ranges.map(() => null);
    doc.progress = ranges.map(() => null);
    doc.rangeStrikes = ranges.map(() => 0);
    doc.plannedRecordTotal = plannedRecordTotal;
    delete doc.planScan;
    delete doc.planToken;
    await this.state.storage.put(DOC_KEY, doc);
    await this.spawnWorkers(doc, ranges);
    await this.heartbeatBase(scheduler, doc.base);
    await this.state.storage.setAlarm(Date.now() + COORDINATOR_HEARTBEAT_MS);
  }

  // downgradeToSerial converts the coordinator into a SERIAL run when the planned count is below the fan-out
  // threshold (or the keyspace cannot split): it OVERWRITES the coordinator doc with a fresh slice-0 serial
  // RunDoc -- reusing the SAME wrapped master and run identity -- so the next alarm runs the unchanged serial
  // seal over the whole keyspace and finalises one archive, paying no merge overhead. The scheduler lease is
  // already held; the serial path heartbeats it forward from here.
  private async downgradeToSerial(doc: CoordinatorDoc, total: number): Promise<void> {
    const signerKey = requireEnv(this.env.SIGNER_PRIVATE, "SIGNER_PRIVATE");
    const cp: RunCheckpoint = {
      v: 1,
      downpipeId: doc.base.downpipeId,
      downpipeName: doc.base.downpipeName,
      cadence: doc.base.cadence,
      sourceType: doc.base.sourceType,
      selector: { include: doc.selector.include, exclude: doc.selector.exclude },
      runId: doc.base.runId,
      runlogIndex: doc.base.runlogIndex,
      prevRunId: doc.base.prevRunId,
      startedAt: doc.base.startedAt,
      wrappedMaster: doc.wrappedMaster,
      cursor: null,
      sourceDone: false,
      nextRecordIndex: 0,
      nextShardIndex: 0,
      frontier: { count: 0, nodes: [] },
      counts: zeroCounts(),
      sliceCount: 0,
      partialRecord: null,
    };
    const stored = await sealCheckpointForStorage(signerKey, cp);
    const rdoc: RunDoc = { config: doc.config, checkpoint: stored, attempt: 0, destConfig: doc.destConfig ?? null, openBatchSeqStart: 0, openBatchSeqEnd: 0, ...(doc.destinationId !== undefined ? { destinationId: doc.destinationId } : {}) };
    log("info", `fan-out coordinator ${doc.base.runId} counted ${total} keys below the fan-out threshold; downgrading to a serial seal`);
    await this.state.storage.put(DOC_KEY, rdoc); // replaces the coordinator doc: the next alarm runs the serial path
    await this.state.storage.setAlarm(Date.now() + NEXT_SLICE_DELAY_MS);
  }

  // awaitTick is the coordinator's WAITING step (H1). Unconditionally re-arming the heartbeat while waiting
  // would let a worker stalled in an UNCATCHABLE wedge (a CPU/subrequest hard-kill loop -- the KV
  // watermark-rescan wedge -- that never trips the worker's own strike ladder) leave the coordinator awaiting
  // forever while its heartbeat kept the lease owned:true, removing the recovery backstop the serial path has
  // (a dead serial worker stops heartbeating -> the lease expires -> reclaim). So each tick instead polls
  // every not-yet-done range's worker for a liveness fingerprint and STRIKES any range
  // whose worker persisted NOTHING since the last poll. A range frozen for MAX_SLICE_FAILURES consecutive
  // ticks fails the WHOLE run closed (mirroring the serial strike-out): a failed completion (empty runId =>
  // the scheduler clears inFlight + the lease) and cleanup() (which deletes the alarm so the coordinator
  // STOPS heartbeating owned:true), so the wedged run becomes reclaimable instead of an eternal lease hold.
  // A worker that ADVANCES -- real progress OR its OWN catchable fault/throttle ladder, both already bounded
  // -- resets its strike, so this never PREEMPTS those ladders; the coordinator's ladder catches only the
  // uncatchable silent stall. Poll failures are fail-safe (treated as no progress, toward a strike).
  private async awaitTick(scheduler: DurableObjectStub, doc: CoordinatorDoc): Promise<void> {
    const progress = doc.progress ?? doc.ranges.map(() => null);
    const strikes = doc.rangeStrikes ?? doc.ranges.map(() => 0);
    for (let i = 0; i < doc.ranges.length; i++) {
      if (doc.doneRanges[i] !== null) {
        strikes[i] = 0; // reported done: no longer awaited (it never strikes the run out)
        continue;
      }
      const fp = await this.pollRangeFingerprint(doc.base.downpipeId, i);
      if (fp !== null && fp !== (progress[i] ?? null)) {
        // First poll, or the worker persisted SOMETHING since the last poll (a slice, or a catchable
        // fault/throttle advancing its own bounded ladder): the range is alive -- reset its strike.
        progress[i] = fp;
        strikes[i] = 0;
      } else {
        // Unreachable, or the fingerprint is FROZEN: the worker persisted nothing -- the uncatchable wedge.
        strikes[i] = (strikes[i] ?? 0) + 1;
      }
    }
    // The polls above (and coordinatorAlarm's earlier heartbeatBase) each release the DO's input gate for a
    // fetch() round trip; a concurrent handleRangeDone/handleRangeFailed can be admitted and persist during
    // any of those windows, so the `doc` this function started with -- and the strikes[] just computed from
    // its stale doneRanges -- may now be wrong. Re-read and merge BEFORE the strike-out decision below, not
    // just before the final persist: a range the fresh read shows done just reported and self-destructed, so
    // this tick's poll of it (null/unreachable, since its worker is gone) is stale and must be discarded here
    // too, or a range that is genuinely a single tick from tripping the ladder (an honest, tolerated
    // straggler) would strike out an otherwise fully-completed run on the strength of that stale poll alone
    // (the gate-release rule this exploits is the one runtime.input-gate-probe.test.mjs pins down).
    const fresh = await this.state.storage.get<CoordinatorDoc>(DOC_KEY);
    if (fresh?.kind !== "coordinator" || fresh.phase !== "await") return; // a concurrent handler already advanced/tore down the coordinator and armed the next alarm itself
    for (let i = 0; i < fresh.doneRanges.length; i++) {
      if (fresh.doneRanges[i] !== null) {
        // A completion landed concurrently: the reporting worker is gone, so this tick's poll (or the lack
        // of one) for that range is stale and meaningless -- discard it rather than let it strike out the run.
        progress[i] = null;
        strikes[i] = 0;
      }
    }
    const stalled = strikes.findIndex((s) => s >= MAX_SLICE_FAILURES);
    if (stalled >= 0) {
      // A range made no progress across the whole ladder: the worker is wedged and will never report. Fail
      // the run CLOSED, exactly as a serial strike-out / handleRangeFailed does, which releases the lease.
      log("error", `fan-out coordinator ${doc.base.runId} struck out a stalled range (no worker progress in ${MAX_SLICE_FAILURES} ticks); failing the run closed`);
      // OBSERVE WHICH range wedged (support-pack mode fanout-range-stalled, gap G062). The completion row can only
      // carry the generic "fan-out worker stalled" class -- there is no raw fault to digest, because the whole
      // point of this ladder is that the worker threw nothing -- so the RANGE INDEX is the only handle support
      // has on a wedged big-customer run. A small integer; never a key or a range bound.
      await this.observeSealFault(scheduler, { kind: "fanout-range-stalled", at: Date.now(), downpipeId: doc.base.downpipeId, runId: doc.base.runId, rangeIndex: stalled });
      try {
        await scheduler.fetch(doURL("/complete"), { method: "POST", body: JSON.stringify({ id: doc.base.downpipeId, runId: "", index: doc.base.runlogIndex, status: "failed", error: "fan-out worker stalled (no progress)" }), headers: { "content-type": "application/json" } });
      } catch (ce) {
        log("error", `fan-out stalled-range failure completion did not land: ${await redactedRunError((ce as Error).message)}`);
      }
      await this.cleanup();
      return;
    }
    fresh.progress = progress;
    fresh.rangeStrikes = strikes;
    await this.state.storage.put(DOC_KEY, fresh);
    await this.state.storage.setAlarm(Date.now() + COORDINATOR_HEARTBEAT_MS); // keep the lease warm + re-poll
  }

  // pollRangeFingerprint reads range i's WORKER /status (the worker doc is a serial RunDoc, so /status
  // returns its checkpoint counters cheaply WITHOUT crawling) and returns its liveness fingerprint
  // "sliceCount:attempt:throttleAttempt", which advances on EVERY survived worker alarm and freezes only in
  // the uncatchable wedge. Returns null on an unreachable worker or one that already cleaned up (active
  // false) -- fail-safe: the caller treats null as no progress (a done range is skipped before this runs).
  private async pollRangeFingerprint(downpipeId: string, rangeIndex: number): Promise<string | null> {
    try {
      const resp = await runSealStub(this.env, `${downpipeId}#r${rangeIndex}`).fetch(new Request("https://runseal.internal/status", { method: "GET" }));
      if (!resp.ok) return null;
      const s = (await resp.json()) as { active?: boolean; sliceCount?: number; attempt?: number; throttleAttempt?: number };
      if (s.active !== true) return null;
      return `${s.sliceCount ?? 0}:${s.attempt ?? 0}:${s.throttleAttempt ?? 0}`;
    } catch {
      return null; // unreachable worker: fail-safe (counts toward a strike, never a coordinator fault)
    }
  }

  // mergeCheckpoint builds the RunCheckpoint the merge needs from the coordinator doc: the run identity +
  // base selector + the summed global counts (declaredRecordCount). The frontier / shard cursor live in the
  // MergeState, not here, so the per-record fields are zero placeholders.
  private mergeCheckpoint(doc: CoordinatorDoc): RunCheckpoint {
    return {
      v: 1,
      downpipeId: doc.base.downpipeId,
      downpipeName: doc.base.downpipeName,
      cadence: doc.base.cadence,
      sourceType: doc.base.sourceType,
      selector: { include: doc.selector.include, exclude: doc.selector.exclude },
      runId: doc.base.runId,
      runlogIndex: doc.base.runlogIndex,
      prevRunId: doc.base.prevRunId,
      startedAt: doc.base.startedAt,
      wrappedMaster: doc.wrappedMaster,
      cursor: null,
      sourceDone: true,
      nextRecordIndex: 0,
      nextShardIndex: 0,
      frontier: { count: 0, nodes: [] },
      counts: doc.counts,
      sliceCount: 0,
      partialRecord: null,
    };
  }

  // persistMerge stores the advanced merge state and the carried (renumbered, not-yet-sealed) line buffer.
  // The buffer carries record NAMES, so it rests as AES-256-GCM-wrapped append-only batches (the SAME
  // machinery the serial open shard uses), in a live range [mergeOpenSeqStart, mergeOpenSeqEnd): a fresh
  // batch run is written beyond the consumed range and the doc + new batches land in ONE atomic put, then
  // the consumed batches are deleted (a crash in between only LEAKS them, since the live range no longer
  // references them).
  private async persistMerge(signerKey: string, doc: CoordinatorDoc, r: MergeStepResult): Promise<void> {
    doc.merge = r.state;
    const oldStart = doc.mergeOpenSeqStart ?? 0;
    const oldEnd = doc.mergeOpenSeqEnd ?? 0;
    const puts: Record<string, unknown> = {};
    let seq = oldEnd; // append-only: write the new buffer beyond the consumed range
    const newStart = seq;
    for (const chunk of chunkLines(r.carriedLines, MERGE_BATCH_LINES)) {
      puts[openBatchKey(seq)] = await sealOpenShardBatch(signerKey, doc.base.runId, seq, chunk);
      seq++;
    }
    doc.mergeOpenSeqStart = newStart;
    doc.mergeOpenSeqEnd = seq;
    puts[DOC_KEY] = doc;
    await this.state.storage.put(puts);
    const consumed: string[] = [];
    for (let s = oldStart; s < oldEnd; s++) consumed.push(openBatchKey(s));
    if (consumed.length > 0) await this.state.storage.delete(consumed);
  }

  // completeFanout posts the ok /complete for a merged fan-out run, declaring the run's SUMMED global counts
  // (every worker's records/bytes/ops folded together) and the at-seal verification, exactly as a serial
  // run's /complete does.
  private async completeFanout(scheduler: DurableObjectStub, doc: CoordinatorDoc, dest: Destination | undefined, sealVerification?: SealVerification): Promise<void> {
    const resp = await scheduler.fetch(doURL("/complete"), {
      method: "POST",
      body: JSON.stringify({
        id: doc.base.downpipeId,
        runId: doc.base.runId,
        index: doc.base.runlogIndex,
        status: "ok",
        ...(doc.destinationId !== undefined ? { destinationId: doc.destinationId } : {}),
        recordCount: doc.counts.records,
        bytes: doc.counts.bytes,
        archiveBytesWritten: doc.counts.archiveBytesWritten,
        segmentsWritten: doc.counts.objectsWritten,
        durationMs: doc.counts.durationMs,
        recordsSkipped: doc.counts.recordsSkippedChanged,
        // G062: the fields addCheckpointCounts had ALREADY summed across every worker but the fan-out completion
        // never sent, so a fanned-out run -- the biggest customers' runs -- reported an archive that looked whole
        // while the inline path reported the same shortfalls honestly. recordsVanished (in-scope objects deleted
        // mid-crawl), the per-marker incompleteness breakdown and its per-kind attribution now ride exactly as
        // they do inline; each is carried only when non-zero / non-empty, matching the inline body byte for byte.
        ...(doc.counts.recordsVanished > 0 ? { recordsVanished: doc.counts.recordsVanished } : {}),
        recordsIncomplete: doc.counts.recordsIncomplete,
        ...(Object.keys(doc.counts.incompleteByMarker).length > 0 ? { incompleteByMarker: doc.counts.incompleteByMarker } : {}),
        ...(Object.keys(doc.counts.incompleteIds).length > 0 ? { incompleteIds: doc.counts.incompleteIds } : {}),
        opCounts: doc.counts.opCounts,
        ...(sealVerification !== undefined ? { sealVerification } : {}),
        // A merge that stranded multipart parts on the destination flags it on the ok row, as inline does.
        ...multipartAbortFlag(dest),
      }),
      headers: { "content-type": "application/json" },
    });
    // G109: a REFUSED ok completion for a MERGED archive (root signed, RUNLOG appended, bytes in the bucket).
    // Same silence as the serial path above, on the population that can least afford it.
    if (!resp.ok) {
      await this.observeSealFault(scheduler, { kind: "completion-lost", at: Date.now(), downpipeId: doc.base.downpipeId, runId: doc.base.runId, outcome: "ok" });
    }
  }

  // coordinatorFault rides a MERGE fault: a transient (throttle 503/429 or RUNLOG contention) parks-and-
  // resumes without a strike (the merge resumes from its checkpointed frontier); a hard fault strikes, and
  // at MAX_SLICE_FAILURES the run is failed honestly and the lease freed (a fresh run next cadence re-seals
  // the unchanged source).
  private async coordinatorFault(scheduler: DurableObjectStub, doc: CoordinatorDoc, m: string, dest?: Destination): Promise<void> {
    if (m.includes("RUNLOG") || /(status|HTTP) (503|429)/.test(m)) {
      const throttleAttempt = (doc.throttleAttempt ?? 0) + 1;
      const maxYields = throttleMaxYields(this.env);
      if (throttleAttempt >= maxYields) {
        // The destination has been throttled/contended for the entire parking window. Give up honestly so
        // the coordinator does not hold the lease and park forever; a fresh run next cadence re-seals.
        log("error", `fan-out merge ${doc.base.runId} throttled/contended for the whole window; failing the run`);
        try {
          // G062: stamp the 12-hex causeDigest of the raw fault on the failed row (never the message itself), so a
          // merge that died on a sustained destination outage joins to its Logpush lines like an inline failure.
          await scheduler.fetch(doURL("/complete"), { method: "POST", body: JSON.stringify({ id: doc.base.downpipeId, runId: "", index: doc.base.runlogIndex, status: "failed", error: "destination unavailable (sustained throttling during merge)", causeDigest: await causeDigest(m), ...multipartAbortFlag(dest) }), headers: { "content-type": "application/json" } });
        } catch (ce) {
          log("error", `fan-out merge throttle-terminal completion did not land: ${await redactedRunError((ce as Error).message)}`);
          // G109: the fan-out population is exactly the one whose lost verdicts were never recoverable.
          await this.observeSealFault(scheduler, { kind: "completion-lost", at: Date.now(), downpipeId: doc.base.downpipeId, runId: doc.base.runId, outcome: "failed", causeDigest: await causeDigest(m), attemptClasses: [sealAttemptClass(new Error(m))] });
        }
        await this.cleanup();
        return;
      }
      log("error", `fan-out merge ${doc.base.runId} parked (transient ${throttleAttempt}/${maxYields}): ${await redactedRunError(m)}`);
      doc.throttleAttempt = throttleAttempt;
      await this.state.storage.put(DOC_KEY, doc);
      await this.state.storage.setAlarm(Date.now() + Math.min(THROTTLE_BASE_MS * 2 ** Math.min(throttleAttempt - 1, BACKOFF_EXP_CAP), THROTTLE_CAP_MS));
      return;
    }
    doc.attempt += 1;
    log("error", `fan-out merge ${doc.base.runId} slice failed (attempt ${doc.attempt}): ${await redactedRunError(m)}`);
    if (doc.attempt >= MAX_SLICE_FAILURES) {
      const coarse = coarseRunError(m);
      try {
        // G062 parity: coarse class + causeDigest + DEST-1 down-destination attribution + the stranded-parts flag,
        // the same four signals an inline strike-out posts. A merge that struck out on the destination now lights
        // the map's per-destination indicator instead of failing silently against a healthy-looking bucket.
        await scheduler.fetch(doURL("/complete"), { method: "POST", body: JSON.stringify({ id: doc.base.downpipeId, runId: "", index: doc.base.runlogIndex, status: "failed", error: coarse, causeDigest: await causeDigest(m), ...downDestinationFlag(coarse, doc.destinationId), ...multipartAbortFlag(dest) }), headers: { "content-type": "application/json" } });
      } catch (ce) {
        log("error", `fan-out merge failure completion did not land: ${await redactedRunError((ce as Error).message)}`);
        // G109: as above -- the merge struck out with a known coarse class and the verdict evaporated.
        await this.observeSealFault(scheduler, { kind: "completion-lost", at: Date.now(), downpipeId: doc.base.downpipeId, runId: doc.base.runId, outcome: "failed", causeDigest: await causeDigest(m), attemptClasses: [sealAttemptClass(new Error(m))] });
      }
      await this.cleanup();
      return;
    }
    await this.state.storage.put(DOC_KEY, doc);
    await this.state.storage.setAlarm(Date.now() + Math.min(RETRY_BASE_MS * 2 ** Math.min(doc.attempt - 1, BACKOFF_EXP_CAP), RETRY_CAP_MS));
  }

  private async cleanup(): Promise<void> {
    await this.state.storage.deleteAll();
    await this.state.storage.deleteAlarm();
  }
}
