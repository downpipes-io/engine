// Replication (3-2-1 fan-out): after a downpipe's runs finalise, copy each run from the destination it
// SEALED to (its recorded origin, failover may have made it a non-primary) to every OTHER configured
// destination, so the same sealed bytes live in all of them. Each destination is an INDEPENDENT,
// restorable mirror: the content-addressed DATA segments (seg/<aa>/<id>.seg) AND the run-tree
// objects (run/<runId>/...) are copied, and the run's RUNLOG entry is appended to that destination's
// OWN RUNLOG with a re-linked, index-ordered per-downpipe chain (relinkLocalPrev), so a destination
// added mid-life, or back-filled out of global order, keeps a valid, fork-free chain rather than a
// dangling pointer.
//
// DEST-2 (data, not just manifests): record bytes live in content-addressed seg/ objects OUTSIDE the
// run/<runId>/ tree (see format/writer.ts segmentObjectKey), so copying only the run-tree leaves a
// replica whose manifests reference ABSENT segments: a silently non-restorable copy. Replication is
// KEYLESS (it holds the signer for the RUNLOG, not the operational key), so it cannot decrypt the
// shards to enumerate a single run's segments; instead it syncs the whole content-addressed store
// (delta only, dedup-by-exists, since segments are shared across runs). The RUNLOG done-marker for a
// run is written ONLY after that run's data is provably present, so a run is never recorded as held
// on a replica that lacks its bytes. Per-segment CRYPTOGRAPHIC verification needs the operational key
// and stays the keyed blind-restore drill's job, exactly as the keyless attestation defers record
// verification (format/reader.ts attestKeyless).
//
// STRUCTURAL SEG CHECK (Finding 6, REPL_VERIFY_SEGMENTS / opts.verifySegments, DEFAULT ON for the cron
// pass): after a run's NEW seg/ objects are copied a bounded sample is read BACK from the replica and
// unframed (format/container.ts unframeSeg), so a TRUNCATED, EMPTY or WRONG-OBJECT copy throws and the run
// is never recorded held. What this DOES: catch container-framing damage (short container, bad "DPS1"
// magic, unsupported version byte) on the just-copied bytes, keylessly, so a replica is verified-not-blind.
// What this does NOT do: it CANNOT detect a flipped plaintext byte inside a well-framed segment (the
// content-address is a keyed HMAC over the plaintext, replication holds no operational key). Cryptographic
// plaintext integrity is deferred to the keyed restore drill. The cron pass DEFAULTS this ON
// (replVerifySegmentsEnabled below): only an explicit
// falsey REPL_VERIFY_SEGMENTS disables it, so a production replica is never copied without a readback of
// the segment bytes. The injectable core mirrorRunToReplica keeps it an explicit per-call opt-in (default
// off) so a direct caller / the validator chooses; the cron pass passes the env-resolved value (exported
// replVerifySegmentsEnabled so the validator can assert the default-on cron posture).
//
// It runs as its OWN cron pass (not inline after the seal) because a sliced run finalises later on the
// seal DO's alarms; the pass re-checks every tick and catches each destination up on its WHOLE BACKLOG
// (every run it is missing, not just the latest, so a run that landed while a destination was briefly
// down is not stranded forever). It is:
//   - idempotent: a destination's RUNLOG already carrying a runId is the DONE marker (appended LAST,
//     after the objects), so a present run is skipped cheaply (one RUNLOG read per destination per tick).
//   - fail-open per destination AND per downpipe: a fault is logged and skipped, NEVER failing a sealed
//     run (its origin copy is already safe); the next tick re-attempts.
//   - read-only on every source; it only writes the destination it is catching up.

import { loadConfigWrapKey } from "../admin/config-secret.ts";
import { buildDestination, fetchDestConfig } from "../dest/factory.ts";
import type { Destination } from "../dest/types.ts";
import type { Env } from "../env.d.ts";
import { unframeSeg } from "../format/container.ts";
import { attestKeyless, type ObjectStore } from "../format/reader.ts";
import { parseRunlog, type RunlogEntry, type Signer } from "../format/writer.ts";
import { loadSigner, verifierFrom } from "../keys-env.ts";
import { log } from "../log.ts";
import { allDestinationIds, type DownpipeConfig, type DownpipeState, primaryDestinationId, type RunHistoryEntry } from "../sched/scheduler-do.ts";
import { classifyFlagKnob, type KnobResolution, type SliceBudget } from "./budget.ts";
import { appendRunlog, type RunlogLock } from "./pipeline.ts";
import { runTreePrefix } from "./prune.ts";
import { postSealFault } from "./seal-fault-post.ts";
import type { ReplicaFaultReason, ReplicationPassOutcome } from "./seal-faults.ts";

// ---------------------------------------------------------------------------------------------------------
// G064: the replication PASS's own execution health. Every deferral below (no SIGNER_PRIVATE, an unreadable
// fleet history, an exhausted budget, a repl-state write that failed, a read-back verification sample the budget
// cut short, a segment that vanished mid-sync) existed ONLY in Workers Logs -- so replicas fleet-wide falling
// behind, the worst case being discovered only after the primary bucket is lost, looked exactly like replicas
// that were simply idle. This isolate-local tally is posted ONCE per pass. Counts only.
// ---------------------------------------------------------------------------------------------------------
interface ReplPassTally {
  deferredDownpipes: number;
  stateWriteFailures: number;
  verifySampleShortfall: number;
  segmentVanishDeferrals: number;
}
let passTally: ReplPassTally = { deferredDownpipes: 0, stateWriteFailures: 0, verifySampleShortfall: 0, segmentVanishDeferrals: 0 };

/** resetReplicationPassTally clears the per-pass counters. Called at the start of every pass; exported so a
 * validator can isolate a case. */
export function resetReplicationPassTally(): void {
  passTally = { deferredDownpipes: 0, stateWriteFailures: 0, verifySampleShortfall: 0, segmentVanishDeferrals: 0 };
}

/** replicationPassTally is the read-only peek into the replication pass counters. Counts only.
 *
 * @knipignore Built-but-unwired observability hook: no current caller reads it, but it is the seam a
 * future replication-pass assertion needs, so it is kept rather than deleted. */
export function replicationPassTally(): ReplPassTally {
  return { ...passTally };
}

const RUNLOG_KEY = "_RECOVERY/RUNLOG";
// SEG_PREFIX is the content-addressed data-segment store the seal writes record bytes into
// (format/writer.ts segmentObjectKey: seg/<aa>/<id>.seg). It is a SEPARATE top-level prefix from the
// per-run manifest tree (run/<runId>/), shared across runs by content hash, and is what a replica
// must hold to be restorable.
const SEG_PREFIX = "seg/";
const doURL = (path: string): string => `https://scheduler.internal${path}`;

// runlogLockVia adapts the scheduler DO's /runlog-lock routes to the RunlogLock interface, keyed by the
// REPLICA destination (SCALE-3 per-destination keying), so a back-fill append serialises with seals to the
// same replica destination's RUNLOG rather than racing its CAS. A local copy (like retention-pass.ts) keeps
// the leaf module dependency-free; an absent/blank key targets the default destination's slot.
function runlogLockVia(scheduler: DurableObjectStub, destKey?: string): RunlogLock {
  const keyed = typeof destKey === "string" && destKey.length > 0 ? destKey : undefined;
  return {
    acquire: async () => {
      const init: RequestInit = keyed
        ? { method: "POST", body: JSON.stringify({ key: keyed }), headers: { "content-type": "application/json" } }
        : { method: "POST" };
      const r = (await (await scheduler.fetch(doURL("/runlog-lock/acquire"), init)).json()) as { acquired: boolean; token?: string };
      return r.acquired && r.token ? r.token : null;
    },
    release: async (token: string) => {
      await scheduler.fetch(doURL("/runlog-lock/release"), { method: "POST", body: JSON.stringify({ token, ...(keyed ? { key: keyed } : {}) }) });
    },
  };
}

// replVerifySegmentsEnabled reports whether the cron replication pass runs the keyless structural seg/
// check. It DEFAULTS ON: only an explicit falsey REPL_VERIFY_SEGMENTS ("0"/"false"/"no"/"off") disables
// it, mirroring the VERIFY_AT_SEAL truthy-string-in-reverse idiom (verify-at-seal.ts verifyAtSealEnabled),
// so a deployment that sets nothing verifies every replica's segment bytes rather than copying them blind
// (M5(a)). A real cost reason to skip the readback can set REPL_VERIFY_SEGMENTS=off, the deliberate opt-out.
export function replVerifySegmentsEnabled(env: Env): boolean {
  const v = env.REPL_VERIFY_SEGMENTS;
  if (v === undefined) return true; // default ON
  const s = v.trim().toLowerCase();
  if (s === "0" || s === "false" || s === "no" || s === "off") return false;
  return true;
}

// replVerifyKnobSources reports whether the replica read-back verification flag is the DEFAULT (on) or an
// operator value (gap G169). The knob is deliberately default-ON and accepts any string, so it has no invalid
// arm; what the pack could not previously answer is "did someone turn the replica verification off, or has it
// simply never been set?" -- a live question when replicas are being copied blind. A closed enum only.
export function replVerifyKnobSources(env: Env): Record<string, KnobResolution> {
  return { replVerifySegments: { source: classifyFlagKnob(env.REPL_VERIFY_SEGMENTS) } };
}
// The destinations this pass builds are given the slice budget as their Meter (getDest below), so every
// real list/get/put/RUNLOG subrequest charges the budget directly (repl-dest-unmetered): there is no flat
// per-mirror or per-segment estimate to keep in step with the code any more.

// recordReplicationOutcome reports one destination's mirror result to the scheduler DO (the single
// writer of `repl:` state), so the console shows "N of M copies" and the per-destination "down"
// indicator from PROVEN outcomes rather than an inference. Fail-open: a failed record is logged and
// dropped (the next tick re-records), never failing the mirror it is only describing.
async function recordReplicationOutcome(scheduler: DurableObjectStub, id: string, destinationId: string, ok: boolean, opts?: { runId?: string; index?: number; holdsFrom?: number; reason?: ReplicaFaultReason }): Promise<void> {
  try {
    const resp = await scheduler.fetch(doURL("/replication/record"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id, destinationId, ok, runId: opts?.runId, index: opts?.index, holdsFrom: opts?.holdsFrom, reason: opts?.reason }),
    });
    // G064: a repl-state write that FAILS leaves the replication row stale with no explanation -- the console
    // shows an old "N of M copies" and support has no way to know the record simply never landed. The write is
    // still best-effort (the next tick re-records); the loss is now COUNTED.
    if (!resp.ok) passTally.stateWriteFailures++;
  } catch (e) {
    passTally.stateWriteFailures++;
    log("error", `replicate: recording ${destinationId} state failed (non-fatal): ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ReplicaFaultError TAGS a per-target fault with its CLOSED reason at the site that knows it, so processTarget's
// catch does not have to re-read a raw message to attribute it (G063). The original error rides as `cause` for
// the Workers Logs line only; the reason enum is the only thing ever recorded.
class ReplicaFaultError extends Error {
  readonly replicaReason: ReplicaFaultReason;
  constructor(reason: ReplicaFaultReason, message: string) {
    super(message);
    this.name = "ReplicaFaultError";
    this.replicaReason = reason;
  }
}

// replicaReasonOf reads the CLOSED reason off a tagged fault and coarsens anything else to "unreachable" (the
// honest default for an untagged transport/HTTP throw). It NEVER inspects an untagged error's message: guessing
// from text is exactly the free-text leak this vocabulary exists to prevent.
function replicaReasonOf(e: unknown): ReplicaFaultReason {
  const r = (e as { replicaReason?: unknown } | null)?.replicaReason;
  return typeof r === "string" && (REPLICA_REASONS as readonly string[]).includes(r) ? (r as ReplicaFaultReason) : "unreachable";
}
const REPLICA_REASONS = ["unreachable", "not-configured", "runlog-unreadable", "runlog-corrupt", "copy-failed", "integrity-verify-failed", "origin-runlog-unreadable", "origin-run-missing", "origin-dest-unconfigured"] as const;

// RunOrigin is one finalised (ok) run with the destination it SEALED to (its recorded origin, which
// 3-2-1 failover may have made a non-primary). A legacy run with no recorded origin falls back to the
// configured primary, the only place it could have sealed before failover existed.
export interface RunOrigin {
  runId: string;
  index: number;
  origin: string | undefined;
}

// highestContiguousRun returns the highest run a destination is PROVEN to hold with NO gap below it: the
// last run in ascending-index order such that it and every prior run are in `placed`. The first missing
// run stops it. This is what makes the recorded holdsIndex honest ("holds all runs <= this index") so the
// console copy-count and the removal orphan-guard cannot be fooled by a later run that arrived while an
// earlier one is still missing. `runs` MUST be sorted ascending by index. Pure; exported for the validator.
export function highestContiguousRun(runs: RunOrigin[], placed: Set<string>): RunOrigin | undefined {
  let held: RunOrigin | undefined;
  for (const run of runs) {
    if (!placed.has(run.runId)) break; // first gap: every run at or above this index is not yet provable
    held = run;
  }
  return held;
}

// replicateBacklog brings EVERY configured destination up to date on EVERY run it is missing, not just
// the latest. Latest-only mirroring stranded any run that landed while a destination was briefly down;
// this catches each destination up on its whole backlog, copying each missing run FROM that run's own
// origin (oldest-first). It is now safe to deliver runs to a destination out of global order because
// appendRunlog re-links the per-destination chain by index on every write, so a back-filled older run
// never forges a rollback. Read-only on every source; writes only the destination being caught up;
// idempotent (a present run is skipped cheaply); fail-open per destination (an unreachable one is recorded
// down and re-attempted next tick); and budget-aware (it yields before the cron's subrequest cap).
//   SCOPE: the backlog is the runs the scheduler still retains in its history ring (RING_CAP). A
//   destination down for LONGER than that window loses the runs that aged out of the ring before it
//   recovered, those are not back-filled here (recovering them would need a multi-source RUNLOG scan).
//   In practice the ring spans many cadence periods and retention prunes old runs anyway; this is a far
//   smaller gap than the latest-only behaviour it replaces, not a regression.
export async function replicateBacklog(env: Env, scheduler: DurableObjectStub, config: DownpipeConfig, history: RunHistoryEntry[], budget?: SliceBudget): Promise<void> {
  const all = allDestinationIds(config);
  if (all.length < 2) return; // need >=2 destinations for a mirror target to exist
  if (!env.SIGNER_PRIVATE) {
    // G064: no signer means NOTHING can be mirrored, fleet-wide, and the replication rows simply go stale. The
    // pass outcome below records it as a closed enum, so "our replicas silently stopped populating" has a cause.
    passTally.deferredDownpipes++;
    await postSealFault(scheduler, { kind: "replication-pass", at: Date.now(), downpipeId: config.id, passOutcome: "no-signer" });
    log("error", `replicate ${config.id}: no SIGNER_PRIVATE; backlog deferred`);
    return;
  }
  // The downpipe's finalised runs (oldest-first) with the origin each sealed to. A failed/in-flight run
  // appended no RUNLOG entry anywhere, so only ok runs are mirrorable.
  const runs: RunOrigin[] = history
    .filter((e) => e.status === "ok" && e.runId)
    .map((e) => ({ runId: e.runId, index: e.index, origin: e.destinationId ?? primaryDestinationId(config) }))
    .sort((a, b) => a.index - b.index);
  if (runs.length === 0) return;

  const signer = await loadSigner(env.SIGNER_PRIVATE);
  const ctx = buildReplicaContext(env, scheduler, config, runs, signer, budget);
  try {
    for (const targetId of all) {
      if (budget?.shouldYield()) break; // out of budget: the remaining destinations catch up next tick
      await processTarget(ctx, targetId);
    }
  } finally {
    // NC-6: zeroise the per-pass signer's ML-DSA secret on every path (appendRunlog was the last reader).
    signer.mldsaSecret.fill(0);
  }
}

// ReplicaContext carries the per-pass caches, the resolved run list and the per-pass signer so the
// per-target catch-up loop is a thin function over them rather than a closure-heavy inline block.
interface ReplicaContext {
  env: Env;
  scheduler: DurableObjectStub;
  config: DownpipeConfig;
  runs: RunOrigin[];
  signer: Signer;
  verifySegments: boolean;
  budget?: SliceBudget;
  getDest(id: string | undefined): Promise<Destination | null>;
  getRunlog(id: string | undefined, dest: Destination): Promise<RunlogEntry[] | null>;
}

// buildReplicaContext sets up the per-pass destination/runlog caches (each destination built at most
// once, each RUNLOG read at most once) and the opt-in seg/ verify flag, returning the context the
// per-target loop reads. A destination with no stored config (a removed origin) caches null.
function buildReplicaContext(env: Env, scheduler: DurableObjectStub, config: DownpipeConfig, runs: RunOrigin[], signer: Signer, budget?: SliceBudget): ReplicaContext {
  const destCache = new Map<string, Destination | null>();
  const getDest = async (id: string | undefined): Promise<Destination | null> => {
    const key = id ?? "";
    if (destCache.has(key)) return destCache.get(key)!;
    let cfg = null;
    if (id) {
      // At-rest credential decryption: pass the wrap key so an AES-256-GCM envelope is opened before
      // buildDestination signs with it (no-op decrypt when CONFIG_WRAP_KEY is unset).
      cfg = await fetchDestConfig(scheduler, id, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
      budget?.spend(1); // the config read is a DO subrequest (cache miss only)
    }
    // Build the destination WITH the slice budget as its Meter, so every list/get/put it performs (the
    // seg/ sync, the run-tree copy, the RUNLOG read/append, the post-copy verify reads) charges the budget
    // honestly and the pass yields before the platform cap (repl-dest-unmetered).
    const dest = id && !cfg ? null : await buildDestination(env, budget, cfg);
    destCache.set(key, dest);
    return dest;
  };
  const runlogCache = new Map<string, RunlogEntry[] | null>();
  const getRunlog = async (id: string | undefined, dest: Destination): Promise<RunlogEntry[] | null> => {
    const key = id ?? "";
    if (runlogCache.has(key)) return runlogCache.get(key)!;
    // The RUNLOG read below goes through the metered destination, so it charges the budget automatically;
    // a manual spend here would double-count.
    let parsed: RunlogEntry[] | null;
    try {
      const rl = await dest.get(RUNLOG_KEY);
      parsed = rl ? parseRunlog(rl.body) : [];
    } catch {
      parsed = null; // unreadable this tick
    }
    runlogCache.set(key, parsed);
    return parsed;
  };
  // Keyless structural check of the just-copied seg/ bytes on each replica (Finding 6); ON by default for
  // the cron pass unless REPL_VERIFY_SEGMENTS is an explicit falsey string, so a production replica's bytes
  // are read back and unframed rather than copied blind (M5(a)). Framing only, not plaintext integrity.
  const verifySegments = replVerifySegmentsEnabled(env);
  return { env, scheduler, config, runs, signer, verifySegments, ...(budget ? { budget } : {}), getDest, getRunlog };
}

// processTarget catches ONE destination up on its whole backlog from each run's origin (oldest-first),
// then records the highest CONTIGUOUS run it now holds. Fail-open per target: a fault records the target
// down (the reachability heartbeat) and re-attempts next tick (idempotent).
async function processTarget(ctx: ReplicaContext, targetId: string): Promise<void> {
  const { scheduler, config, runs, signer, verifySegments, budget } = ctx;
  // G063: runs this target can NEVER hold -- their origin destination is gone, their origin RUNLOG will not read,
  // or the run is absent from its own origin. Each one FREEZES holdsIndex below it forever, so the 3-2-1 promise
  // is permanently unfillable and the pack said only "unreachable". Counted, with the reason that dominates.
  let strandedRuns = 0;
  let strandReason: ReplicaFaultReason | undefined;
  try {
    const targetDest = await ctx.getDest(targetId);
    if (!targetDest) {
      // A target with no stored config cannot receive a copy; record it so "N of M copies" stays honest.
      await recordReplicationOutcome(scheduler, config.id, targetId, false, { reason: "not-configured" });
      await postReplicaFault(scheduler, config.id, targetId, "not-configured", 0);
      return;
    }
    const targetRl = await ctx.getRunlog(targetId, targetDest);
    if (targetRl === null) throw new ReplicaFaultError("runlog-unreadable", "destination RUNLOG unreadable"); // routes to the down record below
    // The set of runs this destination holds: everything already in its RUNLOG, plus everything we
    // mirror this pass. `placed` is seeded from `have` UP FRONT so that even if the budget cuts the loop
    // short, an already-present later run still counts toward held (no break-induced under-report).
    const placed = new Set(targetRl.map((e) => e.runId));
    let copiedRuns = 0;
    for (const run of runs) {
      if (placed.has(run.runId)) continue; // already here (sealed here, or mirrored on a prior tick)
      if (run.origin === targetId) {
        // G063: the run's own ORIGIN is this target, and it is NOT in the target's RUNLOG -- a gap NOTHING can
        // source. It permanently freezes holdsIndex at the run below it, and today the pack says "unreachable".
        strandedRuns++;
        strandReason = "origin-run-missing";
        continue;
      }
      const originDest = await ctx.getDest(run.origin);
      if (originDest) {
        const originRl = await ctx.getRunlog(run.origin, originDest);
        if (originRl === null) {
          strandedRuns++; // G063: the ORIGIN's RUNLOG will not read, so this run cannot be sourced this tick
          strandReason = strandReason ?? "origin-runlog-unreadable";
          continue;
        }
        const entry = originRl.find((e) => e.runId === run.runId);
        if (entry === undefined) {
          strandedRuns++; // G063: the run is absent from its own origin's RUNLOG: unmirrorable, forever
          strandReason = "origin-run-missing";
          continue;
        }
        {
          // verify:true runs the keyless post-copy integrity check on the replica (DEST-1); a
          // failure throws to the per-target catch, which records the target down and retries.
          // budget is threaded so the seg/ DATA sync (DEST-2) charges the shared cron budget and
          // yields before the platform cap. An incomplete return means the data did not fully sync
          // this tick: the run is NOT marked held (no done-marker was written), so stop and resume
          // next tick rather than recording a copy whose bytes are not all present.
          const res = await mirrorRunToReplica(originDest, targetDest, signer, entry, { verify: true, verifySegments, ...(budget ? { budget } : {}), lock: runlogLockVia(scheduler, targetId) });
          // No flat estimate: the metered destinations charged every real list/get/put/RUNLOG op, so
          // the budget already reflects the actual subrequest spend (repl-dest-unmetered).
          if (res.incomplete) break; // data sync out of budget; resume next tick (run not yet held)
          placed.add(run.runId);
          copiedRuns++;
        }
      }
      if (!originDest) {
        // G063: the run's ORIGIN destination has been REMOVED, so no credential can address its bytes. This run
        // can never be mirrored anywhere: an unfillable hole in the 3-2-1 promise, previously reported as an
        // unreachable REPLICA -- which sends support to investigate the wrong destination entirely.
        strandedRuns++;
        strandReason = strandReason ?? "origin-dest-unconfigured";
      }
      // Stop a LONG backlog mid-way once the budget runs low (only after real copying, so a
      // fully-present target is never cut short); record contiguous progress + resume next tick.
      if (copiedRuns > 0 && budget?.shouldYield()) break;
    }
    // held = the highest CONTIGUOUS run the destination holds (every run up to it present, no gap
    // below). Recording a higher index would OVER-CLAIM a copy it lacks, poisoning the console "N of M
    // copies" count AND the removal orphan-guard (uncoveredOriginRuns trusts holdsIndex == "holds all
    // runs <= index"). A run skipped because its origin was unreadable freezes held below it.
    const held = highestContiguousRun(runs, placed);
    // holdsFrom is the FLOOR of the contiguous prefix the destination holds: when `held` is defined the
    // prefix runs from runs[0] (highestContiguousRun walks from there and stops at the first gap), so the
    // proven window is [runs[0].index, held.index]. runs[0] is the RING FLOOR the backlog can see, which is
    // AT OR ABOVE any below-ring run that already aged out of the history ring, so the prune's coverage gate
    // never claims the destination holds a below-ring run it never observed (the ring-floor over-claim fix).
    const holdsFrom = held !== undefined ? runs[0]!.index : undefined;
    // Record the highest CONTIGUOUS run the destination holds (forward-only) PLUS that proven floor. A
    // reachable target that could place nothing records ok with no run advance (lastOk refreshed, holds unchanged).
    await recordReplicationOutcome(scheduler, config.id, targetId, true, held ? { runId: held.runId, index: held.index, ...(holdsFrom !== undefined ? { holdsFrom } : {}) } : {});
    // G063: a target that is REACHABLE but holds STRANDED runs is not healthy -- its holdsIndex is frozen below a
    // gap that can never be filled. The replication row still records ok (it IS reachable, and over-reporting it
    // down would be dishonest); the seal-fault ring carries the strand count and the reason, which is the fact
    // the customer's 3-2-1 promise actually turns on.
    if (strandedRuns > 0) await postReplicaFault(scheduler, config.id, targetId, strandReason ?? "origin-run-missing", strandedRuns);
    if (copiedRuns > 0) log("info", `replicate ${config.id} -> ${targetId}: caught up ${copiedRuns} run(s)`);
  } catch (e) {
    // Fail-open per target: every origin copy is safe. Record the target down (the reachability
    // heartbeat the "destination down" indicator reads) and re-attempt next tick (idempotent).
    //
    // G063: the reason is now the REAL one (a post-copy INTEGRITY VERIFY failure -- possible corruption in
    // transit -- a corrupt replica RUNLOG, a failed copy), not the single word "unreachable" that sent support to
    // check networking while the archive was quietly unrestorable. It is read off the TYPED fault, never parsed
    // out of a message.
    const reason = replicaReasonOf(e);
    await recordReplicationOutcome(scheduler, config.id, targetId, false, { reason });
    await postReplicaFault(scheduler, config.id, targetId, reason, strandedRuns);
    log("error", `replicate ${config.id} -> ${targetId} failed (retry next tick): ${e instanceof Error ? e.message : String(e)}`);
  }
}

// postReplicaFault records ONE replica target's fault in the seal-fault ring (G063). Best-effort and fail-open
// (postSealFault never throws): observing a replication fault must never break the replication it describes.
async function postReplicaFault(scheduler: DurableObjectStub, downpipeId: string, destinationId: string, reason: ReplicaFaultReason, strandedRuns: number): Promise<void> {
  await postSealFault(scheduler, {
    kind: "replica-target-fault",
    at: Date.now(),
    downpipeId,
    destinationId,
    replicaReason: reason,
    ...(strandedRuns > 0 ? { strandedRuns } : {}),
  });
}

// syncSegmentStore copies every content-addressed data segment present on `origin` but missing on
// `target`, so the replica holds the RECORD BYTES (DEST-2), not just the run-tree manifests. Segments
// are content-addressed and shared across runs, and replication is keyless, so this syncs the whole
// store as a DELTA (dedup-by-exists) rather than enumerating one run's segments from the encrypted
// shards. Idempotent (a present segment is skipped) and budget-aware: it returns complete:false when
// the budget cut the copy short, so the caller defers the run's done-marker until the data is fully
// present (a run is only "held" once its bytes are there). A put failure throws (the per-target catch
// records the target down and retries next tick). Per-segment CRYPTOGRAPHIC verification needs the
// operational key and is deferred to the keyed blind-restore drill (keyless attestation cannot
// recompute a segment's content-address, which derives from the content key + plaintext).
//
// It returns the keys it actually copied this pass (newly: empty when every segment was already
// present) so the caller can run a keyless structural check over JUST the new copies (verifySegments),
// not re-walk the whole store every tick.
//
// L3 (vanished-segment distinction): a segment listed on the origin can be ABSENT by the time it is
// GET. There are two cases and they MUST be handled differently or one becomes the other's failure:
//   - BENIGN PRUNE: the run we are mirroring has itself aged out of the origin (retention pruned the
//     run-tree AND its now-unreferenced segments). The run is GONE from the origin, so not finalising it
//     here is correct anyway; skip the segment (continue) and let the sync finish. Returning complete:false
//     here would re-attempt this run EVERY tick forever (a livelock) because the bytes can never appear.
//   - TRANSIENT VANISH: the run we are mirroring is STILL LIVE in the origin (its RUNLOG entry still
//     references it) but a listed segment is momentarily absent (a racing GC pass, eventual-consistency
//     window). The bytes are expected back, so we must NOT finalise the run as held on a replica that is
//     missing them: return complete:false so the caller defers the done-marker and resumes next tick.
// The caller supplies isRunLive (re-reads the origin RUNLOG for the run being mirrored) so the two cases
// are distinguished by the run's own liveness, not by guessing which run a content-addressed segment owns
// (which is unknowable keylessly). Absent isRunLive (a direct caller that did not supply it) keeps the
// benign-skip behaviour, the conservative default for the self-contained core.
async function syncSegmentStore(origin: Destination, target: Destination, budget?: SliceBudget, isRunLive?: () => Promise<boolean>): Promise<{ copied: number; complete: boolean; newly: string[] }> {
  // origin/target carry the budget as their Meter (getDest), so list/listPage/get/put charge the slice
  // budget automatically; this only reads shouldYield() to decide when to checkpoint and resume next tick.
  //
  // M6 (bounded memory): the content-addressed seg/ store can hold MILLIONS of segments across a fleet.
  // The old path materialised BOTH the whole origin keyspace AND the whole target keyspace into in-memory
  // arrays/Sets on every tick (origin.list + new Set(target.list)), which OOMs the replication isolate on
  // a mature store and silently breaks the off-site 3-2-1 copy, the exact thing the list() docstring
  // forbids. When both destinations expose the native page primitive (listPage), stream the sync as a
  // SORTED MERGE-WALK: page the origin keyspace one page at a time and advance a target pager in lockstep
  // (both stores page in sorted key order), so at most ONE page of each keyspace is resident at once. The
  // content-addressed dedup is unchanged: a key present on the target is byte-identical, so it is skipped.
  if (origin.listPage && target.listPage) {
    return mergeWalkSync(origin, target, budget, isRunLive);
  }
  // Fallback for a destination double that cannot page natively: materialise both keyspaces as before.
  // The real S3/R2 destinations always implement listPage, so production replication never reaches here;
  // this keeps a self-contained in-memory test double (and any future non-paging impl) correct.
  const originSegs = await origin.list(SEG_PREFIX);
  const present = new Set(await target.list(SEG_PREFIX));
  if (originSegs.length > SEG_KEYSPACE_WARN_KEYS || present.size > SEG_KEYSPACE_WARN_KEYS) {
    log("error", `replicate: large seg/ keyspace (origin ${originSegs.length}, target ${present.size} keys) over ${SEG_KEYSPACE_WARN_KEYS}; non-paging destination, sync proceeds delta-only and budget-bounded`);
  }
  const newly: string[] = [];
  for (const key of originSegs) {
    if (present.has(key)) continue; // content-addressed: a present segment is byte-identical, skip cheaply
    if (budget?.shouldYield()) return { copied: newly.length, complete: false, newly }; // out of budget: resume next tick, run not yet held
    const out = await copyMissingSegment(origin, target, key, isRunLive);
    if (out === "defer") return { copied: newly.length, complete: false, newly };
    if (out === "skip") continue;
    newly.push(key);
  }
  return { copied: newly.length, complete: true, newly };
}

// mergeWalkSync streams the seg/ delta in BOUNDED MEMORY (M6): it walks the origin keyspace page by page
// and advances a target pager in lockstep, both in sorted key order, so a key's presence on the target is
// decided by a sorted-merge comparison rather than a materialised Set of the whole target keyspace. At
// most one page of each store is resident, independent of the store's total segment count, so a fleet's
// millions of segments no longer OOM the replication isolate. Dedup correctness is identical: a key that
// is present on the target (equal in the merge) is byte-identical (content-addressed) and is skipped; only
// the origin keys with no target match are GET and copied. Budget-aware and L3-correct exactly as before.
async function mergeWalkSync(origin: Destination, target: Destination, budget?: SliceBudget, isRunLive?: () => Promise<boolean>): Promise<{ copied: number; complete: boolean; newly: string[] }> {
  const targetPager = new SortedKeyPager(target, SEG_PREFIX);
  const newly: string[] = [];
  let originCursor: string | undefined;
  let firstPage = true;
  for (;;) {
    // listPage charges the budget via the metered destination; one page is resident at a time.
    const page = firstPage || originCursor !== undefined ? await origin.listPage!(SEG_PREFIX, originCursor) : { keys: [] as string[] };
    firstPage = false;
    for (const key of page.keys) {
      // present(key) advances the target pager up to (and possibly past) key in sorted order, returning
      // true when the target holds it. The pager only ever holds one target page in memory.
      if (await targetPager.has(key)) continue; // content-addressed: present == byte-identical, skip cheaply
      if (budget?.shouldYield()) return { copied: newly.length, complete: false, newly }; // out of budget: resume next tick
      const out = await copyMissingSegment(origin, target, key, isRunLive);
      if (out === "defer") return { copied: newly.length, complete: false, newly };
      if (out === "skip") continue;
      newly.push(key);
    }
    if (page.cursor === undefined) break; // origin keyspace exhausted
    originCursor = page.cursor;
  }
  return { copied: newly.length, complete: true, newly };
}

// SortedKeyPager walks a destination's keyspace under a prefix one native page at a time, in sorted key
// order, exposing a forward-only membership probe has(key). It assumes the queried keys arrive in sorted
// order (the merge-walk feeds it the origin keys in sorted order) and advances the underlying target pages
// only as far as needed, so at most ONE target page is resident regardless of the store's total size.
// has(key) returns true iff the target holds exactly key; a key the target lacks (the next target key is
// already greater, or the target is exhausted) returns false without over-reading.
class SortedKeyPager {
  private page: string[] = [];
  private idx = 0;
  private cursor: string | undefined;
  private done = false;
  private dest: Destination;
  private prefix: string;
  constructor(dest: Destination, prefix: string) {
    this.dest = dest;
    this.prefix = prefix;
  }
  async has(key: string): Promise<boolean> {
    for (;;) {
      // Refill the current page when it is exhausted and more pages remain.
      if (this.idx >= this.page.length) {
        if (this.done) return false; // target keyspace fully consumed; key is beyond it -> missing
        const next = await this.dest.listPage!(this.prefix, this.cursor);
        this.page = next.keys;
        this.idx = 0;
        if (next.cursor === undefined) this.done = true;
        else this.cursor = next.cursor;
        if (this.page.length === 0) {
          if (this.done) return false;
          continue; // an empty non-final page (rare): fetch the next
        }
      }
      const cur = this.page[this.idx]!;
      if (cur < key) {
        this.idx++; // target key precedes the queried key; advance past it (it has no origin match here)
        continue;
      }
      if (cur === key) {
        this.idx++; // consume the match so a later equal-or-greater query does not re-test it
        return true;
      }
      return false; // cur > key: the target has no entry for key (it would sort here), so key is missing
    }
  }
}

// copyMissingSegment GETs one origin segment that the target lacks and PUTs it to the target, handling the
// L3 vanished-segment race exactly as before: a segment listed on the origin can be ABSENT by the GET.
//   - "defer": the run is STILL LIVE in the origin but the segment is gone (a real mid-sync vanish): the
//     caller must NOT finalise the run on a replica missing the bytes; return defer so it resumes next tick.
//   - "skip": the run itself is pruned from the origin (retention removed it and its orphaned segments), so
//     not finalising is already correct; skip the orphaned segment to avoid a permanent re-attempt livelock.
//   - "copied": the bytes were GET and PUT to the target (a newly-copied key the caller records).
async function copyMissingSegment(origin: Destination, target: Destination, key: string, isRunLive?: () => Promise<boolean>): Promise<"copied" | "skip" | "defer"> {
  const obj = await origin.get(key);
  if (!obj) {
    if (isRunLive && (await isRunLive())) {
      passTally.segmentVanishDeferrals++; // G064: a live run's segment vanished mid-sync; the mirror defers again
      log("info", `replicate: origin segment ${key} vanished mid-sync while the run is still live; deferring finalisation (retry next tick)`);
      return "defer";
    }
    log("info", `replicate: origin segment ${key} absent and its run is pruned from the origin; skipping (benign)`);
    return "skip";
  }
  await target.put(key, obj.body);
  return "copied";
}

// SEG_VERIFY_SAMPLE bounds the opt-in verifySegments check: at most this many of the newly-copied seg/
// objects are read back and structurally unframed per pass, so the cost stays bounded and charges the
// slice budget like any other get. The sample is deterministic (an even stride across the new keys) so
// repeated passes cover different segments; over the backlog the whole new set is checked.
const SEG_VERIFY_SAMPLE = 8;

// SEG_KEYSPACE_WARN_KEYS is the segment-key count above which syncSegmentStore logs a single warning that
// the content-addressed keyspace is large (dest.list() returns it as one array). 100,000 keys is well past
// a small-to-moderate store and is the point worth surfacing in the logs; it is an observability threshold
// only, the sync stays delta-only and budget-bounded regardless.
const SEG_KEYSPACE_WARN_KEYS = 100_000;

// verifyCopiedSegments runs a KEYLESS, STRUCTURAL check of the just-copied seg/ bytes on the REPLICA:
// it GETs a bounded sample of the newly-copied objects back FROM the target and calls unframeSeg, which
// throws on a container shorter than the 5-byte header (a truncated or empty copy) or a wrong DPS1 magic
// / version byte (a wrong-object copy). A throw propagates to mirrorRunToReplica's caller (the per-target
// catch), so a structurally-bad copy is never recorded held. This is FRAMING ONLY: it CANNOT detect a
// flipped plaintext byte inside an otherwise well-framed segment, because the content-address is an HMAC
// over the key-derived CAK and the plaintext (crypto/derive.ts) and replication holds no operational
// key. Cryptographic plaintext integrity stays the keyed restore drill's job.
async function verifyCopiedSegments(target: Destination, newly: string[], budget?: SliceBudget): Promise<void> {
  if (newly.length === 0) return;
  // A deterministic even stride keeps the per-pass cost <= SEG_VERIFY_SAMPLE gets while still touching the
  // ends of the set; the get charges the budget via the metered destination.
  const stride = Math.max(1, Math.ceil(newly.length / SEG_VERIFY_SAMPLE));
  for (let i = 0; i < newly.length; i += stride) {
    if (budget?.shouldYield()) {
      // G064: the read-back verification sample was CUT SHORT by the budget, so some just-copied segments were
      // never structurally checked -- and the run is still recorded held. Silent today; counted now.
      passTally.verifySampleShortfall++;
      break; // sampling is best-effort within the slice; the next tick re-covers it
    }
    const key = newly[i]!;
    const obj = await target.get(key);
    if (!obj) throw new ReplicaFaultError("integrity-verify-failed", `replica segment ${key} missing immediately after copy`);
    unframeSeg(obj.body); // throws on a short container, a bad DPS1 magic, or an unsupported version byte
  }
}

// mirrorRunToReplica is the injectable per-replica core (the run path resolves the two Destinations;
// the validator drives it with in-memory ones). It copies the run's DATA segments (seg/) AND the
// run-tree objects the replica is missing, then appends the run to the replica's OWN RUNLOG with a
// REPLICA-LOCAL prevRunId, so the replica keeps a valid per-downpipe chain even when added mid-life.
// IDEMPOTENT: when the replica RUNLOG already carries this runId (the done marker, written LAST after
// the data AND the objects) it returns {alreadyDone:true} and writes nothing. When the budget cut the
// data sync short it returns {incomplete:true} WITHOUT a done-marker, so the run is retried (never
// recorded held) next tick. opts.syncSegments:false skips the per-call data sync when the backlog pass
// already synced the store for this origin/target pair this tick; the default true keeps the exported
// core self-contained (a direct caller, and the validator, get a fully restorable replica).
//
// opts.verifySegments (default false, like opts.verify) adds a KEYLESS, STRUCTURAL check of the
// just-copied seg/ bytes on the REPLICA: after a completed seg sync, a bounded sample of the newly-copied
// objects is read back and unframed (container.ts), catching a truncated, empty or wrong-object copy
// before the done-marker is written. It does NOT verify cryptographic plaintext integrity (the
// content-address is a keyed HMAC over the plaintext and replication holds no operational key), and the
// flag is OFF by default, so the default posture is unchanged: closing Finding 6 requires opting in.
// verifyRunOnReplica runs the keyless attest of the just-mirrored run-tree against the replica's
// own object store and throws if the signed root does not verify or the tree is incomplete.
async function verifyRunOnReplica(replica: Destination, signer: Signer, runId: string): Promise<void> {
  const store: ObjectStore = {
    get: async (k: string): Promise<Uint8Array> => {
      const r = await replica.get(k);
      if (!r) throw new Error(`object ${k} is missing`);
      return r.body;
    },
  };
  const att = await attestKeyless(store, runId, verifierFrom(signer), { allowStale: true });
  if (!att.signatureValid || !att.complete) {
    // G063: THE most serious thing replication can find -- the just-copied run does not verify on the replica, so
    // the copy is CORRUPT, not merely absent. It reported as "unreachable", so support told the customer to check
    // their networking. Typed with its own closed reason; the attestation text is never carried.
    throw new ReplicaFaultError("integrity-verify-failed", `replica integrity verify failed: ${att.reason ?? "integrity check failed"}`);
  }
}

export async function mirrorRunToReplica(primary: Destination, replica: Destination, signer: Signer, entry: RunlogEntry, opts: { verify?: boolean; verifySegments?: boolean; syncSegments?: boolean; budget?: SliceBudget; lock?: RunlogLock } = {}): Promise<{ copied: number; alreadyDone: boolean; incomplete?: boolean }> {
  const rl = await replica.get(RUNLOG_KEY);
  const existing = rl ? parseRunlog(rl.body) : [];
  if (existing.some((e) => e.runId === entry.runId)) return { copied: 0, alreadyDone: true };
  // DEST-2: copy the DATA first (the content-addressed seg/ store) so the run-tree manifests copied
  // below never reference an absent segment. Skipped only when the backlog pass already synced this pair.
  // isRunLive re-reads the ORIGIN RUNLOG so syncSegmentStore can tell a transient mid-sync segment vanish
  // (run still referenced on the origin -> defer, do not finalise) from a benign retention prune (the run
  // itself is gone from the origin -> skip the orphaned segment, no livelock). See syncSegmentStore (L3).
  const isRunLive = async (): Promise<boolean> => {
    const r = await primary.get(RUNLOG_KEY);
    return r ? parseRunlog(r.body).some((e) => e.runId === entry.runId) : false;
  };
  const seg = opts.syncSegments === false ? { copied: 0, complete: true, newly: [] as string[] } : await syncSegmentStore(primary, replica, opts.budget, isRunLive);
  const treeKeys = await primary.list(runTreePrefix(entry.runId));
  const present = new Set(await replica.list(runTreePrefix(entry.runId)));
  let copied = seg.copied;
  for (const key of treeKeys) {
    if (present.has(key)) continue;
    const obj = await primary.get(key);
    if (!obj) continue;
    await replica.put(key, obj.body);
    copied++;
  }
  // The data sync did not finish this tick: the manifests are now copied (idempotent, harmless), but the
  // bytes are NOT all present, so do NOT verify-or-mark-held. The run stays unfinished on the replica;
  // the next tick resumes the sync, and only once the store is fully synced is the done-marker written.
  if (!seg.complete) return { copied, alreadyDone: false, incomplete: true };
  // Opt-in keyless STRUCTURAL check of the just-copied seg/ bytes on the replica (Finding 6): a truncated,
  // empty or wrong-object copy throws here, routing to the per-target catch so the run is never recorded
  // held. OFF by default; framing only, not cryptographic plaintext integrity (see verifyCopiedSegments).
  if (opts.verifySegments) await verifyCopiedSegments(replica, seg.newly, opts.budget);
  // DEST-1: post-copy integrity verify of the just-mirrored run-tree on the REPLICA, before the RUNLOG
  // done-marker is written. attestKeyless confirms the signed root verifies AND every shard manifest is
  // present and hashes to the signed root, so a silent get/put corruption or a truncated manifest copy is
  // caught here and the replica is never recorded as holding a good copy (it throws; the caller records
  // the target down and retries next tick). Segment data is now present (above) but is cryptographically
  // verified only with the operational key (the keyed blind-restore drill), not here. The anti-rollback
  // flag is intentionally NOT required: the replica-local RUNLOG entry that proves freshness is appended
  // just below, so only signature + completeness apply.
  if (opts.verify) await verifyRunOnReplica(replica, signer, entry.runId);
  // Append to the replica RUNLOG LAST (its presence is the done marker that proves the objects landed
  // first), relinking the prevRunId to the replica-LOCAL tail ATOMICALLY with the conditional write
  // (relinkLocalPrev): a replica added mid-life, or one that skipped a run under failover, keeps a
  // fork-free per-downpipe chain, never a dangling cross-bucket prevRunId the reader reads as a rollback.
  // Take the replica destination's PER-DESTINATION RUNLOG lock (SCALE-3) so a back-fill append serialises
  // with any seal landing on the SAME replica destination rather than racing its CAS lock-free (the
  // "lock-free mirror racing the lock-holding seal" the appendRunlog relink note calls out). The lock is
  // best-effort: a held lock falls through to the lock-free CAS, and sustained contention throws
  // RunlogContendedError, which the per-target catch records down and retries next tick (idempotent).
  await appendRunlog(replica, signer, entry, opts.lock, { relinkLocalPrev: true });
  return { copied, alreadyDone: false };
}

// runReplications is the cron pass: for each downpipe that fans out to >=2 destinations and has a
// completed run, catch every destination up on its whole backlog from each run's origin. Cheap when no
// downpipe fans out (one /downpipes read), and fail-open per downpipe so one fault never crashes the tick.
export async function runReplications(env: Env, scheduler: DurableObjectStub, budget?: SliceBudget): Promise<void> {
  resetReplicationPassTally(); // G064: this pass's own health, from a clean slate
  if (budget?.shouldYield()) {
    // G064: the seal loop ate the whole tick, so replication ran at all. Repeated ticks like this are exactly how
    // replicas fall behind fleet-wide with nothing in the pack to say so.
    await postSealFault(scheduler, { kind: "replication-pass", at: Date.now(), passOutcome: "budget-exhausted" });
    return;
  }
  const resp = await scheduler.fetch(doURL("/downpipes"), { method: "GET" });
  budget?.spend(1);
  const states = (await resp.json()) as DownpipeState[];
  const fanOut = states.filter((s) => allDestinationIds(s.config).length >= 2 && typeof s.lastRunId === "string" && s.lastRunId !== "");
  if (fanOut.length === 0) return;
  // One history read for the whole fleet; each downpipe's ring carries the per-run origin the backlog
  // needs to know where each run can be sourced from. A history fault defers the pass (the next tick retries).
  let histByDp: Record<string, RunHistoryEntry[]>;
  try {
    const hr = await scheduler.fetch(doURL("/history"), { method: "GET" });
    budget?.spend(1);
    histByDp = ((await hr.json()) as { byDownpipe?: Record<string, RunHistoryEntry[]> }).byDownpipe ?? {};
  } catch (e) {
    await postSealFault(scheduler, { kind: "replication-pass", at: Date.now(), passOutcome: "history-unreadable" });
    log("error", `replication: history unreadable this tick, deferred: ${e instanceof Error ? e.message : String(e)}`);
    return;
  }
  let exhausted = false;
  for (const s of fanOut) {
    if (budget?.shouldYield()) {
      // G064: the remaining downpipes are DEFERRED to the next tick. On a large fleet the tail of this list can
      // be deferred every tick, forever -- the "replicas never populate" case -- with no evidence anywhere.
      passTally.deferredDownpipes += fanOut.length - fanOut.indexOf(s);
      exhausted = true;
      break;
    }
    try {
      await replicateBacklog(env, scheduler, s.config, histByDp[s.config.id] ?? [], budget);
    } catch (e) {
      passTally.deferredDownpipes++;
      log("error", `replication for ${s.config.id} skipped this tick: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  // G064: one record per pass, and ONLY when the pass had something to say (a clean pass on a healthy fleet posts
  // nothing at all). Counts and a closed outcome; never a destination, a bucket or a message.
  const outcome: ReplicationPassOutcome = exhausted ? "budget-exhausted" : "ok";
  if (outcome !== "ok" || passTally.deferredDownpipes > 0 || passTally.stateWriteFailures > 0 || passTally.verifySampleShortfall > 0 || passTally.segmentVanishDeferrals > 0) {
    await postSealFault(scheduler, { kind: "replication-pass", at: Date.now(), passOutcome: outcome, ...passTally });
  }
}
