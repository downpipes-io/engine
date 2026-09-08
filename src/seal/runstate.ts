import { doURL, schedulerStub } from "../admin/router-helpers.ts";
import { isThrottleClass } from "../dest/classify.ts";
import { buildDestination, type RuntimeDestConfig } from "../dest/factory.ts";
import type { Destination } from "../dest/types.ts";
import type { Env } from "../env.d.ts";
import type { Signer } from "../format/writer.ts";
import { loadRecipients, loadSigner } from "../keys-env.ts";
import { log } from "../log.ts";
import type { DownpipeState } from "../sched/scheduler-do.ts";
import { hasLivenessProbe } from "../sources/source-errors.ts";
import type { Selector } from "../sources/types.ts";
import { buildAdapter } from "./adapters.ts";
import { budgetFromEnv, type SliceBudget } from "./budget.ts";
import { type RunCheckpoint, wrapMaster, zeroCounts } from "./checkpoint.ts";
import { type FanoutRange, planFanout } from "./fanout.ts";
import { type RunClock, type RunConfig, type RunSummary, runBackup } from "./pipeline.ts";
import { throttleRetryFromEnv } from "./retry.ts";
import { beginRunFaults, reportRunFaults } from "./run-fault-report.ts";
import { noteSealMode } from "./run-observations.ts";
import { sealAttemptClass } from "./run-pressure.ts";
import { type RunBase, runSealStub, type StartFanout, type StartSliceRun } from "./runseal-do.ts";
import {
  cfConfigToken,
  downDestinationFlag,
  fanoutMinRecords,
  fanoutRangeCount,
  fanoutSampleCap,
  multipartAbortFlag,
  requireEnv,
  runlogLockVia,
  runSealVerification,
  runSelector,
  sliceDepsFromEnv,
  truthyKnob,
} from "./runstate-helpers.ts";
import { postSealFault } from "./seal-fault-post.ts";
import { classifyHandoffRefusal } from "./seal-faults.ts";
import { causeDigest, coarseRunError, finaliseRun, redactedRunError, runSlice, type ShardEntry, type SliceDeps } from "./slice.ts";

// The per-downpipe seal Durable Object and its /start payload type live in runseal-do.ts; they are
// re-exported here so existing importers (index.ts registers RunSealDO; the slice validator drives both)
// keep their import path. The module-level helpers live in runstate-helpers.ts. This file holds the
// worker-side seal entry points sealRunSliced / sealRunBuffered (finding engine-src-046-01).
export { RunSealDO, runSealStub, type StartSliceRun } from "./runseal-do.ts";

// RunTrigger is the (runId, index, prevRunId) tuple the cron driver hands a seal entry point.
type RunTrigger = { runId: string; index: number; prevRunId: string | null };

// completeInline finalises a run that fits the inline budget, verifies the just-written archive
// (ENG-RST-01, fail-open), and posts the "ok" completion. The archive is COMPLETE from finaliseRun
// on, so a blip on the completion POST is a DIFFERENT failure class from a seal failure: it must NOT
// throw (that would page a false backup-failure and re-run the whole downpipe under a fresh master);
// it is logged and the row left in flight, which the scheduler's lease reclaim resolves to
// "abandoned", the honest outcome. Extracted from sealRunSliced (finding engine-src-046-13).
async function completeInline(env: Env, scheduler: DurableObjectStub, deps: SliceDeps, state: DownpipeState, trig: RunTrigger, cp: RunCheckpoint, master: Uint8Array, newShards: ShardEntry[], openShardLines: Record<string, unknown>[], destinationId?: string): Promise<void> {
  // Fix 2a: an inline run finalises in one invocation, so the open-shard buffer lives only in memory
  // (openShardLines, the leftover the single slice carried); finaliseRun seals it as the final shard.
  await finaliseRun(deps, cp, master, newShards, openShardLines, runlogLockVia(scheduler, destinationId));
  const sealVerification = await runSealVerification({ env, scheduler, dest: deps.dest, downpipe: { id: state.config.id, name: state.config.name }, master }, trig.runId, cp.counts.bytes);
  try {
    const resp = await scheduler.fetch(doURL("/complete"), {
      method: "POST",
      body: JSON.stringify({
        id: state.config.id,
        runId: trig.runId,
        index: trig.index,
        status: "ok",
        destinationId, // the failover-chosen origin this run sealed to (recorded + seeds repl state)
        recordCount: cp.counts.records,
        bytes: cp.counts.bytes,
        archiveBytesWritten: cp.counts.archiveBytesWritten,
        segmentsWritten: cp.counts.objectsWritten,
        durationMs: cp.counts.durationMs,
        recordsSkipped: cp.counts.recordsSkippedChanged, // surface records the seal could not capture
        ...(cp.counts.recordsVanished > 0 ? { recordsVanished: cp.counts.recordsVanished } : {}), // WS-P2: in-scope objects deleted between list and read (mid-crawl); only when non-zero
        recordsIncomplete: cp.counts.recordsIncomplete, // R1-1: records sealed as incompleteness sentinels (not the real bytes)
        ...(Object.keys(cp.counts.incompleteByMarker).length > 0 ? { incompleteByMarker: cp.counts.incompleteByMarker } : {}), // R1-1 per-marker breakdown (which kinds); only carried when non-empty
        ...(Object.keys(cp.counts.incompleteIds).length > 0 ? { incompleteIds: cp.counts.incompleteIds } : {}), // WS-P1 per-kind attribution (which surface); only carried when non-empty
        opCounts: cp.counts.opCounts, // exact per-resource Cloudflare op tally (cost Phase 3)
        ...(sealVerification !== undefined ? { sealVerification } : {}),
        // Stranded multipart parts (multipart-abort-stranded-parts): surface the destination's abort-failure
        // signal on the run row so invisible part-storage is visible. Only set when something was stranded.
        ...multipartAbortFlag(deps.dest),
      }),
    });
    // G109: a REFUSED completion (a non-2xx) never threw, so this arm never saw it and the run's SUCCESS was
    // dropped in silence -- the archive is complete and the pack later shows the row as "abandoned".
    if (!resp.ok) await observeCompletionLost(scheduler, state.config.id, trig.runId, "ok");
  } catch (ce) {
    log("error", `run ${state.config.id} (${trig.runId}) sealed fully but the ok completion did not land: ${await redactedRunError((ce as Error).message)}`);
    // G109: the archive is COMPLETE and the run is a SUCCESS -- and its verdict just evaporated. Without this
    // the row resolves later as a generic "abandoned" and the pack contradicts a destination that restores fine.
    await observeCompletionLost(scheduler, state.config.id, trig.runId, "ok");
  }
}

// observeCompletionLost records a terminal outcome the engine COMPUTED and then FAILED TO DELIVER (gap G109,
// support-pack mode terminal-outcome-lost). The /complete POST is the ONLY thing that writes a run's verdict
// into the history the pack projects, and every caller of it is deliberately fail-soft: a blip must not page a
// false backup failure or re-run a fully-sealed downpipe under a fresh master. The cost of that discipline was
// that the verdict simply VANISHED -- the row later resolves via lease reclaim as a generic "abandoned" for a
// run whose archive restores perfectly, or (on the buffered path) as FAILED for an archive that is complete.
// The pack then CONTRADICTS the destination, which is the worst possible support artefact.
//
// This puts the computed verdict on the seal-fault ring instead: the outcome (ok|failed), the closed coarse
// class of a failed one (sealAttemptClass, a CLOSED member -- never the raw message) and the 12-hex cause
// digest, so the run row and the bucket can be reconciled. Best-effort + fail-open (postSealFault never
// throws): recording a lost completion can never make the loss worse.
async function observeCompletionLost(scheduler: DurableObjectStub, downpipeId: string, runId: string, outcome: "ok" | "failed", failure?: { cause: string; error: unknown }): Promise<void> {
  await postSealFault(scheduler, {
    kind: "completion-lost",
    at: Date.now(),
    downpipeId,
    runId,
    outcome,
    ...(failure !== undefined ? { causeDigest: failure.cause, attemptClasses: [sealAttemptClass(failure.error)] } : {}),
  });
}

// refusedHandoff turns a REFUSED seal-DO handoff into a throw whose class is CLOSED (gap G106). The DO answers
// a refusal with a FIXED, engine-authored error body; classifyHandoffRefusal reads it ONLY to select a member
// of HANDOFF_REFUSAL_CLASSES and returns that member, so the body never rides. The old form ("... : status
// 500") fell through coarseRunError's generic status catch-all to "destination access error", which blamed the
// customer's bucket -- and lit the map's down-destination indicator -- for a fault entirely inside the engine's
// own control plane.
async function refusedHandoff(resp: Response): Promise<Error> {
  let bodyError: string | undefined;
  try {
    const body = (await resp.json()) as { error?: unknown };
    if (typeof body.error === "string") bodyError = body.error;
  } catch {
    // A refusal with no readable body is still a refusal; the status alone selects the class.
  }
  return new Error(`seal DO handoff refused: ${classifyHandoffRefusal(resp.status, bodyError)}`);
}

// handoffToDO hands a run that did NOT finish within the inline budget to the per-downpipe seal DO,
// which resumes from the checkpoint on its own alarm budget. The wrapped master in the checkpoint is
// what crosses over (the in-memory copy is zeroised by the caller's finally). A refused handoff (the
// DO's catch answers a non-2xx) THROWS so the caller posts the failed completion immediately, instead
// of leaving the run dangling in-flight until the 30-minute lease reclaim. Extracted from
// sealRunSliced (finding engine-src-046-13).
async function handoffToDO(env: Env, state: DownpipeState, b: SliceBudget, cp: RunCheckpoint, newShards: ShardEntry[], openShardLines: Record<string, unknown>[], destOverride?: RuntimeDestConfig | null, destinationId?: string): Promise<void> {
  b.spend(1); // the handoff fetch is a platform subrequest on the shared tick budget
  // Fix 2a: the inline slice's leftover open-shard buffer (openShardLines) rides the handoff in memory
  // (a DO-to-DO call, never persisted as-is); the seal DO wraps it into an open-shard batch at the
  // storage boundary, exactly as it wraps the checkpoint cursor.
  const startResp = await runSealStub(env, state.config.id).fetch("https://runseal.internal/start", {
    method: "POST",
    body: JSON.stringify({ config: state.config, checkpoint: cp, shards: newShards, openShardLines, destConfig: destOverride ?? null, ...(destinationId !== undefined ? { destinationId } : {}) } satisfies StartSliceRun),
    headers: { "content-type": "application/json" },
  });
  if (!startResp.ok) throw await refusedHandoff(startResp);
}

// handoffToCoordinator hands a fanned-out run to the per-downpipe COORDINATOR DO (Fix 2b): it wraps the ONE
// run master (so every worker derives identical keys), assembles the run identity + base selector + the N
// ranges, and POSTs /start-fanout. The coordinator spawns the workers and takes over; this invocation does
// NOT run an inline slice. A refused handoff THROWS so the caller posts the failed completion immediately,
// the same discipline as handoffToDO (rather than strand the run in-flight until lease reclaim).
async function handoffToCoordinator(env: Env, state: DownpipeState, trig: RunTrigger, b: SliceBudget, master: Uint8Array, nowIso: string, selector: Selector, ranges: FanoutRange[] | undefined, destOverride: RuntimeDestConfig | null, destinationId?: string): Promise<void> {
  b.spend(1); // the handoff fetch is a platform subrequest on the shared tick budget
  const wrappedMaster = await wrapMaster(requireEnv(env.SIGNER_PRIVATE, "SIGNER_PRIVATE"), trig.runId, master);
  const base: RunBase = { runId: trig.runId, runlogIndex: trig.index, prevRunId: trig.prevRunId, downpipeId: state.config.id, downpipeName: state.config.name, cadence: `${state.config.cadenceSeconds}s`, sourceType: state.config.source.type, startedAt: nowIso };
  // ranges present (a DIRECT plan from the front sample) -> the coordinator spawns immediately; absent (a
  // SCAN plan, the namespace is larger than the sample) -> the coordinator runs the sliced balanced plan.
  const payload: StartFanout = { config: state.config, base, selector: { include: selector.include, exclude: selector.exclude }, wrappedMaster, ...(ranges !== undefined ? { ranges } : {}), destConfig: destOverride, ...(destinationId !== undefined ? { destinationId } : {}) };
  const resp = await runSealStub(env, state.config.id).fetch(new Request("https://runseal.internal/start-fanout", { method: "POST", body: JSON.stringify(payload), headers: { "content-type": "application/json" } }));
  if (!resp.ok) throw await refusedHandoff(resp);
}

// initialCheckpoint builds the fresh (slice 0) checkpoint for a triggered run, sealing the per-run
// master into wrappedMaster. Extracted from sealRunSliced (finding engine-src-046-13).
async function initialCheckpoint(env: Env, state: DownpipeState, trig: RunTrigger, master: Uint8Array, nowIso: string): Promise<RunCheckpoint> {
  return {
    v: 1,
    downpipeId: state.config.id,
    downpipeName: state.config.name,
    cadence: `${state.config.cadenceSeconds}s`,
    sourceType: state.config.source.type,
    selector: runSelector(state),
    runId: trig.runId,
    runlogIndex: trig.index,
    prevRunId: trig.prevRunId,
    startedAt: nowIso,
    wrappedMaster: await wrapMaster(requireEnv(env.SIGNER_PRIVATE, "SIGNER_PRIVATE"), trig.runId, master),
    cursor: null,
    sourceDone: false,
    nextRecordIndex: 0,
    nextShardIndex: 0,
    frontier: { count: 0, nodes: [] },
    counts: zeroCounts(),
    sliceCount: 0,
    partialRecord: null,
  };
}

// sealRunSliced is the worker-side seal for an ALREADY-TRIGGERED run: it replaces the
// buffered whole-run call in index.ts. It runs the FIRST slice inline (sharing the
// invocation budget the cron driver passes, so a tick with many due downpipes spreads
// the cap rather than dying on it); a run that completes within that budget completes
// inline, never wraps its master, and behaves exactly like the v1 path. A run that does
// not is handed to the per-downpipe seal DO, which chains alarms (fresh budget each)
// until done. SLICED_RUNS_DISABLED reverts to the v1 whole-run buffered seal, which
// keeps the hard per-invocation ceiling but never persists a wrapped master.
export async function sealRunSliced(env: Env, state: DownpipeState, trig: { runId: string; index: number; prevRunId: string | null }, opts: SealRunOptions = {}): Promise<void> {
  const { budget, destOverride, destinationId } = opts;
  const scheduler = schedulerStub(env);
  if (truthyKnob(env.SLICED_RUNS_DISABLED)) {
    await sealRunBuffered(env, state, trig, { destOverride: destOverride ?? null, ...(destinationId !== undefined ? { destinationId } : {}) });
    return;
  }
  const b = budget ?? budgetFromEnv(env);
  // Clear the isolate-local source-fault ledger before the crawl: a Workers isolate is WARM and serves many
  // runs, so a previous downpipe's faults must never be attributed to this one (a mis-attributed fault sends
  // support to the wrong source, which is worse than a missing one). The matching drain is in the finally.
  beginRunFaults();
  const master = crypto.getRandomValues(new Uint8Array(32));
  const nowIso = new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
  let deps: SliceDeps | undefined;
  // The latest checkpoint + shards, tracked OUTSIDE the try so a throttle-classified inline failure can
  // be park-and-resumed on the DO ladder (Layer 1c). They start at the initial (slice-0) checkpoint and
  // advance to the post-slice checkpoint; either is a sound resume point for the DO (segs are content-
  // addressed and idempotent, so re-running a slice re-writes byte-identical objects).
  let cp: RunCheckpoint | undefined;
  let resumeShards: ShardEntry[] = [];
  // Fix 2a: the inline slice's leftover open-shard buffer, tracked beside cp/resumeShards so a
  // throttle-classified inline failure can park-and-resume the SAME open shard on the DO ladder.
  let resumeOpen: Record<string, unknown>[] = [];
  try {
    cp = await initialCheckpoint(env, state, trig, master, nowIso);
    const cfToken = await cfConfigToken(scheduler, state, env);
    deps = await sliceDepsFromEnv(env, state.config, b, { destOverride: destOverride ?? null, ...(cfToken !== undefined ? { cfToken } : {}) });
    // Fix 2b fan-out (opt-in via SCALE_FANOUT_RANGES): a high-cardinality LEX-ORDERED KV run is sealed by N
    // parallel WORKER DOs and merged into ONE byte-identical archive by the COORDINATOR, instead of the
    // serial inline-then-DO path. planFanout returns null -- stay serial -- in every fail-safe case (fan-out
    // off, not KV, below the record threshold, un-splittable), so a non-fan-out run falls straight through to
    // the unchanged inline path below and is byte-for-byte as before.
    const selector = runSelector(state);
    const decision = await planFanout(deps.source, selector, { ranges: fanoutRangeCount(env), minRecords: fanoutMinRecords(env), sampleCap: fanoutSampleCap(env) });
    // G189: the REQUESTED vs EFFECTIVE seal mode. A downpipe with fan-out enabled that silently downgrades to
    // serial still takes days on a backup the customer believes is parallel, and the pack carried NOTHING (the
    // fan-out knobs are deliberately omitted from sealKnobs and the run row has no mode field). Closed enums and
    // small integers only; no key-space sample rides.
    const requestedRanges = fanoutRangeCount(env);
    noteSealMode({
      requested: requestedRanges >= 2 ? "fanout" : "serial",
      effective: decision.mode === "serial" ? "serial" : "fanout",
      ...(decision.mode === "direct" ? { ranges: decision.ranges.length } : {}),
      ...(decision.mode === "serial" && decision.downgradeReason !== undefined ? { downgradeReason: decision.downgradeReason } : {}),
    });
    if (decision.mode !== "serial") {
      // direct = ranges computed from the cheap front sample; scan = the coordinator runs the sliced balanced
      // count-then-stride plan (no ranges yet). Either way the coordinator owns the run from here (Fix 2b H2).
      await handoffToCoordinator(env, state, trig, b, master, nowIso, selector, decision.mode === "direct" ? decision.ranges : undefined, destOverride ?? null, destinationId);
      return;
    }
    // The inline first slice is a fresh run, so it carries no prior open-shard buffer (priorOpen = []);
    // r.openWrite is therefore the WHOLE leftover open buffer for this run.
    const r = await runSlice(deps, cp, master);
    cp = r.checkpoint;
    resumeShards = r.newShards;
    resumeOpen = r.openWrite;
    if (r.checkpoint.sourceDone && b.canFinalise()) {
      // The run fits the inline budget: finalise + verify + complete on this invocation.
      await completeInline(env, scheduler, deps, state, trig, r.checkpoint, master, r.newShards, r.openWrite, destinationId);
      return;
    }
    // It did not: hand it to the per-downpipe seal DO to resume on its own alarm budget.
    await handoffToDO(env, state, b, r.checkpoint, r.newShards, r.openWrite, destOverride ?? null, destinationId);
  } catch (e) {
    const m = (e as Error).message;
    // NC-2: the coarse class + one-way digest, never the raw message (it can embed a
    // record name, and console.error ships to customer Logpush).
    log("error", `run ${state.config.id} (${trig.runId}) failed: ${await redactedRunError(m)}`);
    // Layer 1c: a THROTTLE (503/429) on this INLINE run is NOT a hard failure -- the inline path has no
    // RunSealDO ladder, so without this a sub-budget throttle would terminate a run the over-budget path
    // would have ridden out. Hand the latest checkpoint to the seal DO so the SAME run park-and-resumes on
    // the patient handleThrottle ladder when the store recovers. Only a true throttle routes here (a
    // transient 5xx that exhausts retry, or any auth/permanent fault, still fails inline as before).
    //
    // CLASSIFY THE ERROR, NOT ITS MESSAGE. The throttle evidence lives on the error OBJECT, not its string: the
    // Retry-After tag a CF 429 carries (seal/retry.ts rateLimitError) and the status a CfApiError carries as a
    // field are both gone from a plain string, so classifying against `m` would read a Cloudflare 429 that
    // arrived WITH error text as NOT a throttle and fail the inline run hard instead of parking it for the
    // patient ladder that resumes the same run when the rate-limit window passes.
    if (isThrottleClass(e) && cp !== undefined) {
      try {
        await handoffToDO(env, state, b, cp, resumeShards, resumeOpen, destOverride ?? null, destinationId);
        return;
      } catch (he) {
        // The DO refused the handoff (e.g. unreachable): fall through to the loud failed completion below
        // rather than leaving the run wedged. A refused park is the honest signal, not a silent green.
        log("error", `run ${state.config.id} (${trig.runId}) throttle park-and-resume handoff refused: ${await redactedRunError((he as Error).message)}`);
      }
    }
    const coarse = coarseRunError(m);
    // The 12-hex correlation digest of the SAME raw error the coarse class is derived from. It rides on the
    // failed completion so the DO stamps it on the run-history row, byte-identical to the `[cause <hex>]` the
    // redacted log line above already carries (both single-sourced via causeDigest), so support joins a
    // customer's Logpush line to the pack's failed row by the digest. Never the raw error text (NC-2).
    const cause = await causeDigest(m);
    // A double fault (seal failed AND the scheduler is unreachable for the completion POST)
    // must not escape this function and break the cron caller; log it non-fatally and let the
    // lease's reclaim path recover the wedged run, mirroring the alarm() discipline.
    try {
      await scheduler.fetch(doURL("/complete"), {
        method: "POST",
        // DEST-1: when the seal faulted on the DESTINATION (a single-dest downpipe never probes/fails over,
        // so a sole-destination outage previously surfaced ONLY as a failed run while the map read healthy),
        // name the sole destination as down so the DO records a lastOk:false heartbeat and the map indicator
        // lights up. Only on a destination-access classification (never a source/config fault, which would
        // wrongly blame the bucket) and only when the run had a resolved destination id to attribute it to.
        body: JSON.stringify({ id: state.config.id, runId: "", index: trig.index, status: "failed", error: coarse, causeDigest: cause, ...downDestinationFlag(coarse, destinationId), ...multipartAbortFlag(deps?.dest) }),
      });
    } catch (ce) {
      log("error", `run ${state.config.id} (${trig.runId}) failure completion did not land: ${await redactedRunError((ce as Error).message)}`);
      // G109: the run FAILED, the engine knew why, and the verdict did not land. The row will resolve as a
      // generic "abandoned" via lease reclaim, which reads as "we lost track of it" rather than "it failed for
      // THIS reason". Record the computed verdict + its closed class so the real cause survives the lost POST.
      await observeCompletionLost(scheduler, state.config.id, trig.runId, "failed", { cause, error: e });
    }
  } finally {
    master.fill(0);
    // NC-6: zeroise the per-run signer load on every path (sealRunBuffered discipline).
    if (deps !== undefined) deps.signer.mldsaSecret.fill(0);
    // DRAIN the crawl's source-fault ledger and the destination's fault / degradation snapshots, and post
    // them to the scheduler DO (the pack's sourceFaults / destFaults sections). In the finally so it runs on
    // EVERY exit -- the clean inline completion, the hand-off to the seal DO (the inline slice's faults still
    // count), and the failure arms, which is where the run-fatal transport class and crawl stage live. Never
    // throws, posts nothing for a clean run, and the drain is unconditional so a warm isolate cannot carry
    // this run's faults into the next.
    await reportRunFaults(scheduler, state.config.id, deps?.dest);
  }
}

// postBufferedOk verifies the just-written archive (ENG-RST-01, fail-open) and posts the "ok"
// completion for the buffered (v1 whole-run) seal. The per-run master/signer are already zeroised by
// the caller before this runs; verifyAtSeal loads its own (public) verifier/identity from env, so it
// never touches them. Extracted from sealRunBuffered (finding engine-src-046-14).
//
// DELIBERATELY NOT master-threaded (opkey-reduction, review decision D5). The other three
// runSealVerification call sites hand the per-run master to the verify step so a break-glass-only
// downpipe reaches the keyed decrypt tier; this one cannot without restructuring sealRunBuffered,
// because postBufferedOk is called AFTER that function's finally has already zeroised the master, and
// deferring the zeroise would stretch the master's life across a DO fetch, the verify retry loop and
// the /complete POST. This path is reachable only under SLICED_RUNS_DISABLED (no shipped wrangler
// config sets it), so it stays on the operational key or Tier-0, exactly as before.
async function postBufferedOk(env: Env, scheduler: DurableObjectStub, dest: Destination, state: DownpipeState, trig: RunTrigger, summary: RunSummary, destinationId?: string): Promise<void> {
  const sealVerification = await runSealVerification({ env, scheduler, dest, downpipe: { id: state.config.id, name: state.config.name } }, trig.runId, summary.bytes);
  const resp = await scheduler.fetch(doURL("/complete"), {
    method: "POST",
    body: JSON.stringify({
      id: state.config.id,
      runId: trig.runId,
      index: trig.index,
      status: "ok",
      destinationId, // the failover-chosen origin this run sealed to (recorded + seeds repl state)
      recordCount: summary.records,
      bytes: summary.bytes,
      archiveBytesWritten: summary.archiveBytesWritten,
      segmentsWritten: summary.objectsWritten,
      durationMs: summary.durationMs,
      ...(summary.recordsVanished > 0 ? { recordsVanished: summary.recordsVanished } : {}), // WS-P2: KV/R2 objects deleted between list and read (mid-crawl); only when non-zero (mirrors the sliced path)
      recordsIncomplete: summary.recordsIncomplete, // R1-1: records sealed as incompleteness sentinels (not the real bytes)
      ...(Object.keys(summary.incompleteByMarker).length > 0 ? { incompleteByMarker: summary.incompleteByMarker } : {}), // R1-1 per-marker breakdown (which kinds); only carried when non-empty
      ...(Object.keys(summary.incompleteIds).length > 0 ? { incompleteIds: summary.incompleteIds } : {}), // WS-P1 per-kind attribution (which surface); only carried when non-empty
      ...(sealVerification !== undefined ? { sealVerification } : {}),
      // Stranded multipart parts (multipart-abort-stranded-parts): surface the destination's abort-failure signal.
      ...multipartAbortFlag(dest),
    }),
  });
  // G109: a REFUSED ok completion for a FULLY SEALED buffered archive. It never threw, so the caller's catch
  // never saw it either; the verdict simply vanished.
  if (!resp.ok) await observeCompletionLost(scheduler, state.config.id, trig.runId, "ok");
}

// SealRunOptions groups the optional run context (the slice budget, the per-run destination
// override and the failover-chosen origin id) so the seal entry points keep to the
// 4-parameter guardrail.
interface SealRunOptions {
  budget?: SliceBudget;
  destOverride?: RuntimeDestConfig | null;
  destinationId?: string;
}

// sealRunBuffered is the v1 whole-run seal (the pre-slicing behaviour), kept verbatim
// behind SLICED_RUNS_DISABLED for deployments that refuse the wrapped-master trade-off.
async function sealRunBuffered(env: Env, state: DownpipeState, trig: { runId: string; index: number; prevRunId: string | null }, opts: SealRunOptions = {}): Promise<void> {
  const { destOverride, destinationId } = opts;
  const scheduler = schedulerStub(env);
  const signer: Signer = await loadSigner(requireEnv(env.SIGNER_PRIVATE, "SIGNER_PRIVATE"));
  const recipients = loadRecipients(requireEnv(env.BREAK_GLASS_PUBLIC, "BREAK_GLASS_PUBLIC"), env.OPERATIONAL_PUBLIC);
  const dest = await buildDestination(env, undefined, destOverride ?? null);
  const sources = [buildAdapter(env, state, await cfConfigToken(scheduler, state, env))];

  const cfg: RunConfig = {
    downpipeId: state.config.id,
    downpipeName: state.config.name,
    cadence: `${state.config.cadenceSeconds}s`,
    selector: runSelector(state),
    recipients,
    throttleRetry: throttleRetryFromEnv(env),
  };
  const clock: RunClock = {
    runId: trig.runId,
    runlogIndex: trig.index,
    prevRunId: trig.prevRunId,
    now: new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
    randomNonce: () => crypto.getRandomValues(new Uint8Array(16)),
    randomSalt: () => crypto.getRandomValues(new Uint8Array(16)),
    master: crypto.getRandomValues(new Uint8Array(32)),
  };
  const lock = runlogLockVia(scheduler, destinationId);
  // G109: the sealed summary of a run that COMPLETED. It is held OUTSIDE the try/catch because posting the ok
  // completion must NOT sit inside the failure catch: postBufferedOk performs a verify + a network POST, and
  // catching a fault in either there would book the run as FAILED for an archive that is fully sealed, signed
  // and in the bucket, a correctness fault, not just a reporting one. The seal and the completion are two
  // separate phases with two separate failure meanings.
  let sealed: RunSummary | undefined;
  // As on the sliced path: clear the isolate-local source-fault ledger before the crawl, and drain it in the
  // finally below so the buffered path's evidence reaches the pack too.
  beginRunFaults();
  try {
    // SRC-1 liveness preflight (buffered path): prove each binding-backed source's resource still exists
    // before the whole-run crawl starts, so a deleted KV/R2/D1 behind a truthy binding raises a named
    // "source resource missing" rather than dying mid-crawl on a raw platform throw. Sources without a
    // cheap liveness call (secrets / API sources) are skipped.
    for (const source of sources) {
      if (hasLivenessProbe(source)) await source.probeLiveness();
    }
    sealed = await runBackup(sources, cfg, signer, dest, clock, lock);
  } catch (e) {
    const m = (e as Error).message;
    // NC-2 applies to this path too: a buffered-run failure can interpolate a record
    // or table name (writer.ts / d1-format.ts size errors), so the log line carries
    // the coarse class + digest, never the raw message.
    log("error", `run ${state.config.id} (${trig.runId}) failed: ${await redactedRunError(m)}`);
    const coarse = coarseRunError(m);
    // The 12-hex correlation digest of the same raw error (single-sourced via causeDigest), stamped on the
    // failed run-history row byte-identical to the `[cause <hex>]` the redacted log line above carries (see
    // the sliced path). Support joins the customer's Logpush line to the pack's failed row by it.
    const cause = await causeDigest(m);
    // As on the sliced path: a completion POST that itself fails (scheduler unreachable) must not
    // escape and break the cron caller; log non-fatally and lean on lease reclaim to recover.
    try {
      await scheduler.fetch(doURL("/complete"), {
        method: "POST",
        // DEST-1: name the sole destination down on a destination-access fault (see the sliced path above).
        body: JSON.stringify({ id: state.config.id, runId: "", index: trig.index, status: "failed", error: coarse, causeDigest: cause, ...downDestinationFlag(coarse, destinationId), ...multipartAbortFlag(dest) }),
      });
    } catch (ce) {
      log("error", `run ${state.config.id} (${trig.runId}) failure completion did not land: ${await redactedRunError((ce as Error).message)}`);
      // G109: as on the sliced path -- the computed FAILED verdict did not land, so record it on the ring.
      await observeCompletionLost(scheduler, state.config.id, trig.runId, "failed", { cause, error: e });
    }
  } finally {
    // The per-run master and the per-run signer load, ended on EVERY exit via this one `finally` (the same
    // discipline the sliced path uses, and what validate-master-zeroisation asserts). Zeroised FIRST, so a
    // throw from the drain below cannot strand them.
    clock.master.fill(0);
    // NC-6: zeroise the per-run signer load on every path (matches the sliced path's discipline).
    signer.mldsaSecret.fill(0);
    // The buffered path's drain (see the sliced path above): the crawl ran in THIS isolate, so this is the
    // only place its source-fault ledger and the destination's fault snapshot can be read.
    await reportRunFaults(scheduler, state.config.id, dest);
  }
  // G109: the archive is SEALED. Completing it is a SEPARATE phase whose failure is a completion fault, never a
  // backup fault: a verify hiccup or a scheduler blip here must not re-brand a good archive as a failed run. A
  // lost ok completion is recorded on the seal-fault ring so the pack can be reconciled against the bucket.
  if (sealed !== undefined) {
    try {
      await postBufferedOk(env, scheduler, dest, state, trig, sealed, destinationId);
    } catch (ce) {
      log("error", `run ${state.config.id} (${trig.runId}) sealed fully but the ok completion did not land: ${await redactedRunError((ce as Error).message)}`);
      await observeCompletionLost(scheduler, state.config.id, trig.runId, "ok");
    }
    // The completion phase runs AFTER the drain in the finally above, and postBufferedOk performs the SEAL
    // VERIFICATION -- which notes into the format/crypto integrity ledger. Drain again so that evidence reaches
    // the pack. The reporter never throws, posts nothing when clean, and the ledgers it drains are already
    // empty on a healthy run, so this costs a warm isolate nothing.
    await reportRunFaults(scheduler, state.config.id, dest);
  }
}
