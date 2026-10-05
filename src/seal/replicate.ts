// Replication (3-2-1 fan-out): after a downpipe's runs finalise, copy each run from the destination it
// SEALED to (its recorded origin, failover may have made it a non-primary) to every OTHER configured
// destination, so the same sealed bytes live in all of them. Each destination is an INDEPENDENT,
// restorable mirror: the content-addressed DATA segments (seg/<aa>/<id>.seg) AND the run-tree
// objects (run/<runId>/...) are copied, and the run's RUNLOG entry is appended to that destination's
// OWN RUNLOG with a re-linked, index-ordered per-downpipe chain (relinkLocalPrev), so a destination
// added mid-life, or back-filled out of global order, keeps a valid, fork-free chain rather than a
// dangling pointer.
//
// Record bytes live in content-addressed seg/ objects OUTSIDE the
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
// STRUCTURAL SEG CHECK (REPL_VERIFY_SEGMENTS / opts.verifySegments, DEFAULT ON for the cron
// pass): after a run's NEW seg/ objects are copied a bounded sample is read BACK from the replica and
// unframed (format/container.ts unframeSeg), so a TRUNCATED, EMPTY or WRONG-OBJECT copy throws and the run
// is never recorded held. What this DOES: catch container-framing damage (short container, bad "DPS1"
// magic, unsupported version byte) on the just-copied bytes, keylessly, so a replica is verified-not-blind.
// What this does NOT do: it CANNOT detect a flipped plaintext byte inside a well-framed segment (the
// content-address is a keyed HMAC over the plaintext, replication holds no operational key). Cryptographic
// plaintext integrity is deferred to the keyed restore drill. The cron pass DEFAULTS this ON (replVerifySegmentsEnabled below): only an explicit
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
import { buildDestination, type DestResolutionRefusal, resolveDestination } from "../dest/factory.ts";
import type { Destination } from "../dest/types.ts";
import type { Env } from "../env.d.ts";
import { unframeSeg } from "../format/container.ts";
import { attestKeyless, type ObjectStore } from "../format/reader.ts";
import { parseRunlog, type RunlogEntry, type Signer } from "../format/writer.ts";
import { loadSigner, verifierFrom } from "../keys-env.ts";
import { log } from "../log.ts";
import { CRON_CADENCE_MS } from "../cron/cron-cadence.ts";
import { allDestinationIds, type DownpipeConfig, type DownpipeState, primaryDestinationId, type RunHistoryEntry } from "../sched/scheduler-do.ts";
import { classifyFlagKnob, type KnobResolution, type SliceBudget } from "./budget.ts";
import { appendRunlog, type RunlogLock } from "./pipeline.ts";
import { entryMatchesRoot, makeRunlogReader, type RunlogReader } from "./replicate-runlog.ts";
import { copyStep, ReplicaFaultError, replicaReasonOf } from "./replica-fault.ts";
import { runTreePrefix } from "./prune.ts";
import { postSealFault } from "./seal-fault-post.ts";
import type { ReplReasonSite } from "../sched/scheduler-do-records.ts";
import { type ReplicaFaultReason, type ReplicationPassOutcome, type StrandCause, type StrandedRun, STRANDS_MAX } from "./seal-faults.ts";

// ---------------------------------------------------------------------------------------------------------
// The replication PASS's own execution health. Every deferral below (no SIGNER_PRIVATE, an unreadable
// fleet history, an exhausted budget, a repl-state write that failed, a read-back verification sample the budget
// cut short, a segment that vanished mid-sync) would otherwise show ONLY in Workers Logs -- so replicas fleet-wide
// falling behind, the worst case being discovered only after the primary bucket is lost, would look exactly like
// replicas that are simply idle. This isolate-local tally is posted ONCE per pass. Counts only.
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
 * @knipignore Kept as an observability seam for a replication-pass assertion, even though nothing
 * currently calls it: replication is one of the thinner areas of the test suite, and removing this
 * would remove the hook that coverage needs. */
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
// REPLICA destination, so a back-fill append serialises with seals to the
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
    // The same destination's anti-rollback floor (GET /runlog-floor), which the RUNLOG writers check before
    // they modify anything (seal/pipeline.ts verifyRunlogForWrite).
    floor: async () => {
      const r = (await (await scheduler.fetch(doURL(`/runlog-floor${keyed ? `?id=${encodeURIComponent(keyed)}` : ""}`), { method: "GET" })).json()) as { floor?: unknown };
      return typeof r.floor === "number" ? r.floor : undefined;
    },
  };
}

// replVerifySegmentsEnabled reports whether the cron replication pass runs the keyless structural seg/
// check. It DEFAULTS ON: only an explicit falsey REPL_VERIFY_SEGMENTS ("0"/"false"/"no"/"off") disables
// it, mirroring the VERIFY_AT_SEAL truthy-string-in-reverse idiom (verify-at-seal.ts verifyAtSealEnabled),
// so a deployment that sets nothing verifies every replica's segment bytes rather than copying them blind.
// A real cost reason to skip the readback can set REPL_VERIFY_SEGMENTS=off, the deliberate opt-out.
export function replVerifySegmentsEnabled(env: Env): boolean {
  const v = env.REPL_VERIFY_SEGMENTS;
  if (v === undefined) return true; // default ON
  const s = v.trim().toLowerCase();
  if (s === "0" || s === "false" || s === "no" || s === "off") return false;
  return true;
}

// replVerifyKnobSources reports whether the replica read-back verification flag is the DEFAULT (on) or an
// operator value. The knob is deliberately default-ON and accepts any string, so it has no invalid
// arm; this lets an operator be told apart from a never-set default -- a live question when replicas
// are being copied blind. A closed enum only.
export function replVerifyKnobSources(env: Env): Record<string, KnobResolution> {
  return { replVerifySegments: { source: classifyFlagKnob(env.REPL_VERIFY_SEGMENTS) } };
}
// The destinations this pass builds are given the slice budget as their Meter (getDest below), so every
// real list/get/put/RUNLOG subrequest charges the budget directly: there is no flat
// per-mirror or per-segment estimate to keep in step with the code any more.

// recordReplicationOutcome reports one destination's mirror result to the scheduler DO (the single
// writer of `repl:` state), so the console shows "N of M copies" and the per-destination "down"
// indicator from PROVEN outcomes rather than an inference. Fail-open: a failed record is logged and
// dropped (the next tick re-records), never failing the mirror it is only describing.
async function recordReplicationOutcome(scheduler: DurableObjectStub, id: string, destinationId: string, ok: boolean, opts?: { runId?: string; index?: number; holdsFrom?: number; holdsAbove?: number[]; reason?: ReplicaFaultReason; reasonSite?: ReplReasonSite }): Promise<void> {
  try {
    const resp = await scheduler.fetch(doURL("/replication/record"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id, destinationId, ok, runId: opts?.runId, index: opts?.index, holdsFrom: opts?.holdsFrom, holdsAbove: opts?.holdsAbove, reason: opts?.reason, reasonSite: opts?.reasonSite }),
    });
    // A repl-state write that FAILS leaves the replication row stale with no explanation -- the console
    // shows an old "N of M copies" and support has no way to know the record simply never landed. The write is
    // still best-effort (the next tick re-records); the loss is COUNTED.
    if (!resp.ok) passTally.stateWriteFailures++;
  } catch (e) {
    passTally.stateWriteFailures++;
    log("error", `replicate: recording ${destinationId} state failed (non-fatal): ${e instanceof Error ? e.message : String(e)}`);
  }
}

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
// It serves ONE downpipe with no share limit. The cron pass (runReplications) does not call it: it gives
// each downpipe a fair share per round (backlogRound) so one downpipe cannot use the whole window.
export async function replicateBacklog(env: Env, scheduler: DurableObjectStub, config: DownpipeConfig, history: RunHistoryEntry[], budget?: SliceBudget): Promise<void> {
  if (allDestinationIds(config).length < 2) return; // need >=2 destinations for a mirror target to exist
  if (!env.SIGNER_PRIVATE) {
    await deferNoSigner(scheduler, config.id);
    return;
  }
  const signer = await loadSigner(env.SIGNER_PRIVATE);
  try {
    const pass = prepareBacklog(env, scheduler, config, history, signer, budget, newPassCaches());
    if (pass === null) return;
    // No share limit: each destination is walked to the end of its backlog in one call, so one round is all.
    await backlogRound(pass, undefined);
  } finally {
    // Zeroise the per-pass signer's ML-DSA secret on every path (appendRunlog was the last reader).
    signer.mldsaSecret.fill(0);
  }
}

// deferNoSigner records that a fan-out downpipe was not replicated because the engine has no SIGNER_PRIVATE.
// No signer means NOTHING can be mirrored, fleet-wide, and the replication rows simply go stale. The pass
// outcome records it as a closed enum, so "our replicas silently stopped populating" has a cause.
async function deferNoSigner(scheduler: DurableObjectStub, downpipeId: string): Promise<void> {
  passTally.deferredDownpipes++;
  await postSealFault(scheduler, { kind: "replication-pass", at: Date.now(), downpipeId, passOutcome: "no-signer" });
  log("error", `replicate ${downpipeId}: no SIGNER_PRIVATE; backlog deferred`);
}

// BacklogPass is one downpipe's replication state for one pass: its context and, per destination, whether
// the pass has visited it and whether its walk has ended this pass. It lets the cron pass come back to a
// downpipe in a later round without a new RUNLOG read or a second strand record.
interface BacklogPass {
  ctx: ReplicaContext;
  targets: string[];
  visited: Set<string>;
  ended: Set<string>;
}

// prepareBacklog builds one downpipe's BacklogPass: the finalised (ok) runs, oldest first, with the origin
// each sealed to, and the destinations to catch up. A failed or in-flight run appended no RUNLOG entry
// anywhere, so only ok runs are mirrorable. Null when there is nothing to do.
function prepareBacklog(env: Env, scheduler: DurableObjectStub, config: DownpipeConfig, history: RunHistoryEntry[], signer: Signer, budget: SliceBudget | undefined, caches: PassCaches): BacklogPass | null {
  const targets = allDestinationIds(config);
  if (targets.length < 2) return null;
  const runs: RunOrigin[] = history
    .filter((e) => e.status === "ok" && e.runId)
    .map((e) => ({ runId: e.runId, index: e.index, origin: e.destinationId ?? primaryDestinationId(config) }))
    .sort((a, b) => a.index - b.index);
  if (runs.length === 0) return null;
  return { ctx: buildReplicaContext(env, scheduler, config, runs, signer, budget, caches), targets: rotateForTick(targets), visited: new Set(), ended: new Set() };
}

// backlogRound gives each destination of one downpipe one turn: processTarget copies at most `quota` runs to
// it (no limit when undefined), oldest first. It returns true when a destination still has runs to copy
// after its turn, so the caller gives the downpipe another round if the window allows.
async function backlogRound(p: BacklogPass, quota: number | undefined): Promise<boolean> {
  for (const targetId of p.targets) {
    if (p.ended.has(targetId)) continue;
    if (p.ctx.budget?.shouldYield()) break; // out of window: the remaining destinations catch up next tick
    const first = !p.visited.has(targetId);
    p.visited.add(targetId);
    if ((await processTarget(p.ctx, targetId, quota, first)) === "ended") p.ended.add(targetId);
  }
  return p.ended.size < p.targets.length;
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
  // Why getDest answered null for an id: the resolver's closed refusal (a removed destination, or the deploy-time
  // id with no env destination behind it). Absent for an id that resolved.
  refusalOf(id: string | undefined): DestResolutionRefusal | undefined;
  // verified: the caller copies entries out of it (a source). The target's own read only seeds what it holds.
  getRunlog: RunlogReader;
  // The runs each destination holds, kept for the whole pass: seeded once from its RUNLOG, then each run this
  // pass copies there. A later round reads it instead of the RUNLOG, which it cached before the copies.
  placed: Map<string, Set<string>>;
}

// PassCaches is what one pass reads at most once for ALL its downpipes: each destination built once, the
// resolver's refusal for an id it refused, and each destination's RUNLOG as first read this pass. Sharing
// them across downpipes keeps a downpipe with nothing to copy from spending the window on the same reads
// again. A RUNLOG read earlier in the pass answers a later downpipe exactly as a fresh read would, for the two
// questions it is asked: (a) which of THIS downpipe's runs a destination holds, to seed `placed`: only this
// downpipe's own copies add its runs during the pass, and `placed` records those; (b) whether a run's
// origin holds the run: a run the history lists as finalised was in its origin's RUNLOG before the pass read
// the history, so before any RUNLOG read of the pass.
interface PassCaches {
  dests: Map<string, Destination | null>;
  refusals: Map<string, DestResolutionRefusal>;
  runlogs: Map<string, RunlogEntry[] | null>;
  runlogBodies: Map<string, Uint8Array | null>; // the raw RUNLOG read once per destination per pass
  verifiedRunlogs: Map<string, RunlogEntry[] | null>; // the SOURCE read: verified under the engine key
}

function newPassCaches(): PassCaches {
  return { dests: new Map(), refusals: new Map(), runlogs: new Map(), runlogBodies: new Map(), verifiedRunlogs: new Map() };
}

// buildReplicaContext sets up the per-pass destination/runlog caches (each destination built at most
// once, each RUNLOG read at most once, shared by every downpipe of the pass through `caches`) and the
// opt-in seg/ verify flag, returning the context the per-target loop reads. A destination with no stored
// config (a removed origin) caches null.
function buildReplicaContext(env: Env, scheduler: DurableObjectStub, config: DownpipeConfig, runs: RunOrigin[], signer: Signer, budget: SliceBudget | undefined, caches: PassCaches): ReplicaContext {
  const destCache = caches.dests;
  const refusals = caches.refusals;
  const getDest = async (id: string | undefined): Promise<Destination | null> => {
    const key = id ?? "";
    if (destCache.has(key)) return destCache.get(key)!;
    let cfg = null;
    if (id) {
      // At-rest credential decryption: pass the wrap key so an AES-256-GCM envelope is opened before
      // buildDestination signs with it (no-op decrypt when CONFIG_WRAP_KEY is unset). The deploy-time id
      // resolves ok with a null config, which buildDestination turns into the env-backed destination.
      const res = await resolveDestination(env, scheduler, id, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
      budget?.spend(1); // the config read is a DO subrequest (cache miss only)
      if (!res.ok) {
        refusals.set(key, res.reason);
        destCache.set(key, null);
        return null;
      }
      cfg = res.config;
    }
    // Build the destination WITH the slice budget as its Meter, so every list/get/put it performs (the
    // seg/ sync, the run-tree copy, the RUNLOG read/append, the post-copy verify reads) charges the budget
    // honestly and the pass yields before the platform cap.
    const dest = await buildDestination(env, budget, cfg, id);
    destCache.set(key, dest);
    return dest;
  };
  const refusalOf = (id: string | undefined): DestResolutionRefusal | undefined => refusals.get(id ?? "");
  const getRunlog = makeRunlogReader(caches, signer);
  // Keyless structural check of the just-copied seg/ bytes on each replica; ON by default for
  // the cron pass unless REPL_VERIFY_SEGMENTS is an explicit falsey string, so a production replica's bytes
  // are read back and unframed rather than copied blind. Framing only, not plaintext integrity.
  const verifySegments = replVerifySegmentsEnabled(env);
  return { env, scheduler, config, runs, signer, verifySegments, ...(budget ? { budget } : {}), getDest, refusalOf, getRunlog, placed: new Map() };
}

// sourceOf finds where one run can be copied from: its origin, or, when the origin cannot source it (removed,
// its RUNLOG will not read, or the run is absent from it), another destination of this downpipe whose RUNLOG
// holds the run as active. That entry was appended only after its copy passed the post-copy checks, so it is
// as good a source as the origin. A holder's RUNLOG read earlier in the pass can miss a run copied to it later
// in the pass: that run is copied on a later tick, never over-claimed. With no source, it returns the
// ORIGIN's strand cause.
async function sourceOf(ctx: ReplicaContext, run: RunOrigin, targetId: string): Promise<{ dest: Destination; entry: RunlogEntry } | { cause: StrandCause; originHolds: false | "unknown" }> {
  const originDest = await ctx.getDest(run.origin);
  const originRl = originDest ? await ctx.getRunlog(run.origin, originDest, true) : null;
  const originEntry = originRl?.find((e) => e.runId === run.runId);
  if (originDest && originEntry !== undefined) return { dest: originDest, entry: originEntry };
  for (const id of allDestinationIds(ctx.config)) {
    if (id === targetId || id === run.origin) continue;
    const dest = await ctx.getDest(id);
    const entry = dest ? (await ctx.getRunlog(id, dest, true))?.find((e) => e.runId === run.runId && e.status === "active") : undefined;
    if (dest && entry !== undefined) return { dest, entry };
  }
  if (!originDest) return { cause: ctx.refusalOf(run.origin) === "deploy-binding-missing" ? "deploy-binding-missing" : "origin-dest-unconfigured", originHolds: "unknown" };
  return originRl === null ? { cause: "origin-runlog-unreadable", originHolds: "unknown" } : { cause: "origin-run-missing", originHolds: false };
}

// processTarget catches ONE destination up on its backlog from each run's source (sourceOf, oldest-first), then
// records the highest CONTIGUOUS run it now holds. Fail-open per target: a fault records the target down
// (the reachability heartbeat) and re-attempts next tick (idempotent).
//
// FAIR SHARE. `quota` is the most runs this call copies (no limit when undefined). When it is reached, the
// walk goes on to the end WITHOUT copying, so a stranded run later in the ring is still counted, and the call
// returns "more": the caller gives the other downpipes their turn and comes back in a later round. Oldest
// first still holds: a run is copied only when every older run of this downpipe that can be copied here is
// held here. `first` is true on the pass's first call for this destination. Only that call records a pass
// with no copy (the reachability heartbeat) and the strands, so a later round adds no duplicate record.
//
// NO COPY THE WINDOW CANNOT START. The window is checked before each copy starts, not only after a copy, so
// a pass with no window left reads the RUNLOGs and records, and copies nothing it would have to abandon.
async function processTarget(ctx: ReplicaContext, targetId: string, quota: number | undefined, first: boolean): Promise<"ended" | "more"> {
  const { scheduler, config, runs, signer, verifySegments, budget } = ctx;
  // Runs no destination can source -- their origin is gone, its RUNLOG will not read, or the run is absent from
  // it, and no other destination holds it. Each one FREEZES holdsIndex below it, so the 3-2-1 promise
  // is permanently unfillable and reporting only "unreachable" would hide why. Counted, with the reason that dominates.
  let strandedRuns = 0;
  let strandReason: ReplicaFaultReason | undefined;
  // WHICH runs are stranded and whether their origin still holds them, capped (strandedRuns stays the full count).
  const strands: StrandedRun[] = [];
  const strand = (run: RunOrigin, cause: StrandCause, originHolds: false | "unknown"): void => {
    strandedRuns++;
    strandReason = cause === "origin-run-missing" ? cause : (strandReason ?? cause);
    if (strands.length < STRANDS_MAX) strands.push({ runId: run.runId, ...(run.origin !== undefined ? { originId: run.origin } : {}), cause, originHolds });
  };
  try {
    const targetDest = await ctx.getDest(targetId);
    if (!targetDest) {
      // A target the resolver refused cannot receive a copy; record it so "N of M copies" stays honest, with
      // the resolver's own reason: not-configured (the record was removed) or deploy-binding-missing (the
      // deploy-time id with no env destination behind it), two different remedies.
      const reason: ReplicaFaultReason = ctx.refusalOf(targetId) ?? "not-configured";
      await recordReplicationOutcome(scheduler, config.id, targetId, false, { reason, reasonSite: "target-resolution" });
      await postReplicaFault(scheduler, config.id, targetId, reason, 0);
      return "ended";
    }
    let placed = ctx.placed.get(targetId);
    if (placed === undefined) {
      const targetRl = await ctx.getRunlog(targetId, targetDest);
      if (targetRl === null) throw new ReplicaFaultError("runlog-unreadable", "destination RUNLOG unreadable"); // routes to the down record below
      // The set of runs this destination holds: everything already in its RUNLOG, plus everything we
      // mirror this pass. `placed` is seeded from the RUNLOG UP FRONT so that even if the budget cuts the loop
      // short, an already-present later run still counts toward held (no break-induced under-report).
      placed = new Set(targetRl.map((e) => e.runId));
      ctx.placed.set(targetId, placed);
    }
    let copiedRuns = 0;
    let more = false;
    for (const run of runs) {
      if (placed.has(run.runId)) continue; // already here (sealed here, or mirrored on a prior tick)
      if (run.origin === targetId) {
        // The run's own ORIGIN is this target, and it is NOT in the target's RUNLOG -- a gap NOTHING can
        // source. It permanently freezes holdsIndex at the run below it.
        strand(run, "origin-run-missing", false);
        continue;
      }
      // The origin, or another destination of this downpipe that holds the run (sourceOf).
      const src = await sourceOf(ctx, run, targetId);
      if ("dest" in src) {
        if (quota !== undefined && copiedRuns >= quota) {
          more = true; // this downpipe's share for the round is used: the walk goes on, the copy waits a round
          continue;
        }
        // The window is spent: start no copy (it would stop part-way and hold nothing). Resume next tick.
        if (budget?.shouldYield()) break;
        {
          // verify:true runs the keyless post-copy integrity check on the replica; a
          // failure throws to the per-target catch, which records the target down and retries.
          // budget is threaded so the seg/ DATA sync charges the shared cron budget and
          // yields before the platform cap. An incomplete return means the data did not fully sync
          // this tick: the run is NOT marked held (no done-marker was written), so stop and resume
          // next tick rather than recording a copy whose bytes are not all present.
          const res = await mirrorRunToReplica(src.dest, targetDest, signer, src.entry, { verify: true, verifySegments, ...(budget ? { budget } : {}), lock: runlogLockVia(scheduler, targetId) });
          // No flat estimate: the metered destinations charged every real list/get/put/RUNLOG op, so
          // the budget already reflects the actual subrequest spend.
          if (res.incomplete) break; // data sync out of budget; resume next tick (run not yet held)
          placed.add(run.runId);
          copiedRuns++;
        }
      }
      if ("cause" in src) {
        // No destination can source the run. The reason recorded names the ORIGIN's fault (removed, RUNLOG
        // unreadable, or the run absent from it) rather than the generic "unreachable", so support is pointed
        // at the right destination.
        strand(run, src.cause, src.originHolds);
      }
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
    // never claims the destination holds a below-ring run it never observed.
    const holdsFrom = held !== undefined ? runs[0]!.index : undefined;
    // holdsAbove lists the ring runs this destination holds ABOVE that window. A run no destination can
    // source stops the window for good, and without this list the removal guard counted the newer runs the
    // destination does hold as held nowhere else until the missing run left the ring. It is evidence of the
    // same kind as the window: the destination's RUNLOG plus the runs copied and checked this pass.
    const holdsAbove = runs.filter((r) => r.index > (held?.index ?? -1) && placed.has(r.runId)).map((r) => r.index);
    // Record the highest CONTIGUOUS run the destination holds (forward-only) PLUS that proven floor. A
    // reachable target that could place nothing records ok with no run advance (lastOk refreshed, holds unchanged).
    // A later round that copied nothing has nothing new to record.
    if (first || copiedRuns > 0) await recordReplicationOutcome(scheduler, config.id, targetId, true, { ...(held ? { runId: held.runId, index: held.index, ...(holdsFrom !== undefined ? { holdsFrom } : {}) } : {}), holdsAbove });
    // A target that is REACHABLE but holds STRANDED runs is not healthy -- its holdsIndex is frozen below a
    // gap that can never be filled. The replication row still records ok (it IS reachable, and over-reporting it
    // down would be dishonest); the seal-fault ring carries the strand count and the reason, which is the fact
    // the customer's 3-2-1 promise actually turns on.
    if (first && strandedRuns > 0) await postReplicaFault(scheduler, config.id, targetId, strandReason ?? "origin-run-missing", strandedRuns, strands);
    if (copiedRuns > 0) log("info", `replicate ${config.id} -> ${targetId}: caught up ${copiedRuns} run(s)`);
    return more ? "more" : "ended";
  } catch (e) {
    // Fail-open per target: every origin copy is safe. Record the target down (the reachability
    // heartbeat the "destination down" indicator reads) and re-attempt next tick (idempotent).
    //
    // The reason recorded is the specific one (a post-copy INTEGRITY VERIFY failure -- possible corruption in
    // transit -- a corrupt replica RUNLOG, a failed copy), not a generic "unreachable" that would send support to
    // check networking while the archive is actually unrestorable. It is read off the TYPED fault, never parsed
    // out of a message.
    const reason = replicaReasonOf(e);
    await recordReplicationOutcome(scheduler, config.id, targetId, false, { reason, reasonSite: "target-pass" });
    await postReplicaFault(scheduler, config.id, targetId, reason, strandedRuns, strands);
    log("error", `replicate ${config.id} -> ${targetId} failed (retry next tick): ${e instanceof Error ? e.message : String(e)}`);
    return "ended";
  }
}

// postReplicaFault records ONE replica target's fault in the seal-fault ring. Best-effort and fail-open
// (postSealFault never throws): observing a replication fault must never break the replication it describes.
async function postReplicaFault(scheduler: DurableObjectStub, downpipeId: string, destinationId: string, reason: ReplicaFaultReason, strandedRuns: number, strands: StrandedRun[] = []): Promise<void> {
  await postSealFault(scheduler, {
    kind: "replica-target-fault",
    at: Date.now(),
    downpipeId,
    destinationId,
    replicaReason: reason,
    ...(strandedRuns > 0 ? { strandedRuns } : {}),
    ...(strands.length > 0 ? { strands, ...(strandedRuns > strands.length ? { strandsTruncated: true } : {}) } : {}),
  });
}

// syncSegmentStore copies every content-addressed data segment present on `origin` but missing on
// `target`, so the replica holds the RECORD BYTES, not just the run-tree manifests. Segments
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
// A segment listed on the origin can be ABSENT by the time it is
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
  // The content-addressed seg/ store can hold MILLIONS of segments across a fleet. Materialising BOTH the
  // whole origin keyspace AND the whole target keyspace into in-memory arrays/Sets on every tick
  // (origin.list + new Set(target.list)) would OOM the replication isolate on a mature store and silently
  // break the off-site 3-2-1 copy, the exact thing the list() docstring forbids. When both destinations
  // expose the native page primitive (listPage), the sync instead streams as a
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

// mergeWalkSync streams the seg/ delta in BOUNDED MEMORY: it walks the origin keyspace page by page
// and advances a target pager in lockstep, both in sorted key order, so a key's presence on the target is
// decided by a sorted-merge comparison rather than a materialised Set of the whole target keyspace. At
// most one page of each store is resident, independent of the store's total segment count, so a fleet's
// millions of segments do not OOM the replication isolate. Dedup correctness is identical: a key that
// is present on the target (equal in the merge) is byte-identical (content-addressed) and is skipped; only
// the origin keys with no target match are GET and copied. Budget-aware, and handles the vanished-segment
// race the same way as the non-paging path.
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
// vanished-segment race described above: a segment listed on the origin can be ABSENT by the GET.
//   - "defer": the run is STILL LIVE in the origin but the segment is gone (a real mid-sync vanish): the
//     caller must NOT finalise the run on a replica missing the bytes; return defer so it resumes next tick.
//   - "skip": the run itself is pruned from the origin (retention removed it and its orphaned segments), so
//     not finalising is already correct; skip the orphaned segment to avoid a permanent re-attempt livelock.
//   - "copied": the bytes were GET and PUT to the target (a newly-copied key the caller records).
async function copyMissingSegment(origin: Destination, target: Destination, key: string, isRunLive?: () => Promise<boolean>): Promise<"copied" | "skip" | "defer"> {
  const obj = await copyStep(key, () => origin.get(key));
  if (!obj) {
    if (isRunLive && (await isRunLive())) {
      passTally.segmentVanishDeferrals++; // a live run's segment vanished mid-sync; the mirror defers again
      log("info", `replicate: origin segment ${key} vanished mid-sync while the run is still live; deferring finalisation (retry next tick)`);
      return "defer";
    }
    log("info", `replicate: origin segment ${key} absent and its run is pruned from the origin; skipping (benign)`);
    return "skip";
  }
  await copyStep(key, () => target.put(key, obj.body));
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
// key. Cryptographic plaintext integrity stays the keyed restore drill's job (see the drill scope doc).
async function verifyCopiedSegments(target: Destination, newly: string[], budget?: SliceBudget): Promise<void> {
  if (newly.length === 0) return;
  // A deterministic even stride keeps the per-pass cost <= SEG_VERIFY_SAMPLE gets while still touching the
  // ends of the set; the get charges the budget via the metered destination.
  const stride = Math.max(1, Math.ceil(newly.length / SEG_VERIFY_SAMPLE));
  for (let i = 0; i < newly.length; i += stride) {
    if (budget?.shouldYield()) {
      // The read-back verification sample was CUT SHORT by the budget, so some just-copied segments were
      // never structurally checked -- and the run is still recorded held. Counted.
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
// flag is OFF by default, so the default posture is unchanged unless a caller opts in.
// verifyRunOnReplica runs the keyless attest of the just-mirrored run-tree against the replica's
// own object store and throws if the signed root does not verify or the tree is incomplete.
// It returns the root manifest bytes the attestation read (and verified), so the caller can check the RUNLOG
// entry against the signed root with no second read.
async function verifyRunOnReplica(replica: Destination, signer: Signer, runId: string): Promise<Uint8Array | null> {
  const rootKey = `run/${runId}/root.manifest.json`;
  let rootBytes: Uint8Array | null = null;
  const store: ObjectStore = {
    get: async (k: string): Promise<Uint8Array> => {
      const r = await replica.get(k);
      if (!r) throw new Error(`object ${k} is missing`);
      if (k === rootKey) rootBytes = r.body;
      return r.body;
    },
  };
  const att = await attestKeyless(store, runId, verifierFrom(signer), { allowStale: true });
  if (!att.signatureValid || !att.complete) {
    // The most serious thing replication can find -- the just-copied run does not verify on the replica, so
    // the copy is CORRUPT, not merely absent. Reporting this as a generic "unreachable" would send support to
    // check the customer's networking instead. Typed with its own closed reason; the attestation text is never carried.
    throw new ReplicaFaultError("integrity-verify-failed", `replica integrity verify failed: ${att.reason ?? "integrity check failed"}`);
  }
  return rootBytes;
}

export async function mirrorRunToReplica(primary: Destination, replica: Destination, signer: Signer, entry: RunlogEntry, opts: { verify?: boolean; verifySegments?: boolean; syncSegments?: boolean; budget?: SliceBudget; lock?: RunlogLock } = {}): Promise<{ copied: number; alreadyDone: boolean; incomplete?: boolean }> {
  const rl = await replica.get(RUNLOG_KEY);
  const existing = rl ? parseRunlog(rl.body) : [];
  if (existing.some((e) => e.runId === entry.runId)) return { copied: 0, alreadyDone: true };
  // Copy the DATA first (the content-addressed seg/ store) so the run-tree manifests copied
  // below never reference an absent segment. Skipped only when the backlog pass already synced this pair.
  // isRunLive re-reads the ORIGIN RUNLOG so syncSegmentStore can tell a transient mid-sync segment vanish
  // (run still referenced on the origin -> defer, do not finalise) from a benign retention prune (the run
  // itself is gone from the origin -> skip the orphaned segment, no livelock). See syncSegmentStore.
  const isRunLive = async (): Promise<boolean> => {
    const r = await primary.get(RUNLOG_KEY);
    return r ? parseRunlog(r.body).some((e) => e.runId === entry.runId) : false;
  };
  const seg = opts.syncSegments === false ? { copied: 0, complete: true, newly: [] as string[] } : await syncSegmentStore(primary, replica, opts.budget, isRunLive);
  // The data sync did not finish this tick: the bytes are NOT all present, so do NOT copy the run-tree,
  // verify or mark held. The segments already copied stay (the next sync skips them), so the next tick
  // resumes the sync, and only once the store is fully synced are the run-tree and the done-marker written.
  // The run-tree copy has no window check of its own, so copying it here would spend the window on objects
  // no restore can use yet, at every tick the sync stays incomplete.
  if (!seg.complete) return { copied: seg.copied, alreadyDone: false, incomplete: true };
  const treeKeys = await primary.list(runTreePrefix(entry.runId));
  const present = new Set(await replica.list(runTreePrefix(entry.runId)));
  let copied = seg.copied;
  for (const key of treeKeys) {
    if (present.has(key)) continue;
    const obj = await copyStep(key, () => primary.get(key));
    if (!obj) continue;
    await copyStep(key, () => replica.put(key, obj.body));
    copied++;
  }
  // Opt-in keyless STRUCTURAL check of the just-copied seg/ bytes on the replica: a truncated,
  // empty or wrong-object copy throws here, routing to the per-target catch so the run is never recorded
  // held. OFF by default; framing only, not cryptographic plaintext integrity (see verifyCopiedSegments).
  if (opts.verifySegments) await verifyCopiedSegments(replica, seg.newly, opts.budget);
  // Post-copy integrity verify of the just-mirrored run-tree on the REPLICA, before the RUNLOG
  // done-marker is written. attestKeyless confirms the signed root verifies AND every shard manifest is
  // present and hashes to the signed root, so a silent get/put corruption or a truncated manifest copy is
  // caught here and the replica is never recorded as holding a good copy (it throws; the caller records
  // the target down and retries next tick). Segment data is now present (above) but is cryptographically
  // verified only with the operational key (the keyed blind-restore drill), not here. The anti-rollback
  // flag is intentionally NOT required: the replica-local RUNLOG entry that proves freshness is appended
  // just below, so only signature + completeness apply.
  if (opts.verify) {
    const rootBody = await verifyRunOnReplica(replica, signer, entry.runId);
    // The entry about to be signed into the replica's RUNLOG must agree with the run's own signed root (just
    // verified above): the same run, downpipe and RUNLOG index (root.freshness.runlogIndex). An entry that
    // disagrees came from a RUNLOG that does not describe this run, and appending it would sign that
    // disagreement into the replica.
    if (!entryMatchesRoot(rootBody, entry)) throw new ReplicaFaultError("integrity-verify-failed", "replica integrity verify failed: the RUNLOG entry does not match the run's signed root (run, downpipe or index)");
  }
  // Append to the replica RUNLOG LAST (its presence is the done marker that proves the objects landed
  // first), relinking the prevRunId to the replica-LOCAL tail ATOMICALLY with the conditional write
  // (relinkLocalPrev): a replica added mid-life, or one that skipped a run under failover, keeps a
  // fork-free per-downpipe chain, never a dangling cross-bucket prevRunId the reader reads as a rollback.
  // Take the replica destination's PER-DESTINATION RUNLOG lock so a back-fill append serialises
  // with any seal landing on the SAME replica destination rather than racing its CAS lock-free (the
  // "lock-free mirror racing the lock-holding seal" the appendRunlog relink note calls out). The lock is
  // best-effort: a held lock falls through to the lock-free CAS, and sustained contention throws
  // RunlogContendedError, which the per-target catch records down and retries next tick (idempotent).
  await appendRunlog(replica, signer, entry, opts.lock, { relinkLocalPrev: true });
  return { copied, alreadyDone: false };
}

// REPL_FAIR_ROTATE moves the downpipe that starts a pass, and the destination a downpipe serves first, on by
// one at each cron tick, so a copy direction that used the window does not come first again at the next tick.
// REPL_FAIR_QUOTA is the most runs a downpipe copies to one destination in one round of a pass.
// test/validate-repl-fairness.ts replaces both lines to build its negative control, so keep each one on a
// line of its own.
const REPL_FAIR_ROTATE = true;
const REPL_FAIR_QUOTA: number | undefined = 1;

// rotateForTick rotates a list by the cron tick number, so each member comes first once every N ticks. The
// tick number comes from the clock: a cron invocation fires on the CRON_CADENCE_MS grid and holds the tick
// lease, so every read in one tick gives the same number and the next tick gives the next one. With
// REPL_FAIR_ROTATE off it returns the list unchanged. Pure apart from the clock.
function rotateForTick<T>(list: readonly T[]): T[] {
  if (!REPL_FAIR_ROTATE || list.length < 2) return [...list];
  const start = Math.floor(Date.now() / CRON_CADENCE_MS) % list.length;
  return [...list.slice(start), ...list.slice(0, start)];
}

// fairOrder puts the fan-out downpipes in id order (the DO's list order is its storage order, not a promise)
// and rotates it by the cron tick number, so each downpipe starts a pass once every N ticks.
function fairOrder(fanOut: DownpipeState[]): DownpipeState[] {
  return rotateForTick([...fanOut].sort((a, b) => (a.config.id < b.config.id ? -1 : a.config.id > b.config.id ? 1 : 0)));
}

// roundFailOpen runs one round of one downpipe and keeps a fault inside it: the downpipe is skipped for the
// rest of this pass, never the pass. True when the downpipe has runs left to copy.
async function roundFailOpen(pass: BacklogPass, quota: number | undefined): Promise<boolean> {
  try {
    return await backlogRound(pass, quota);
  } catch (e) {
    noteSkipped(pass.ctx.config.id, e instanceof Error ? e.message : String(e));
    return false;
  }
}

// noteSkipped counts one downpipe as deferred for this pass and logs why.
function noteSkipped(downpipeId: string, why: string): void {
  passTally.deferredDownpipes++;
  log("error", `replication for ${downpipeId} skipped this tick: ${why}`);
}

// runReplications is the cron pass: for each downpipe that fans out to >=2 destinations and has a
// completed run, catch every destination up on its whole backlog from each run's origin. Cheap when no
// downpipe fans out (one /downpipes read), and fail-open per downpipe so one fault never crashes the tick.
//
// THE PASS HAS ITS OWN WALL WINDOW. `tickBudget` is the cron invocation's budget, and its wall clock
// started before the seal loop. The pass runs on tickBudget.passWindow(): the same subrequest tally (the
// platform cap is per invocation), with a wall clock that starts here. On the shared clock, the passes
// before this one used the whole allowance on a live account, so this pass started with none left. It then
// either returned "budget-exhausted" at once, or copied one segment and a run-tree with no RUNLOG entry, and
// it did the same at every tick: a destination added to a downpipe never received the older runs. With its
// own window the pass moves every tick, and a copy it could not finish carries over (segments already
// copied are skipped the next time), so the backlog ends.
export async function runReplications(env: Env, scheduler: DurableObjectStub, tickBudget?: SliceBudget): Promise<void> {
  resetReplicationPassTally(); // this pass's own health, from a clean slate
  const budget = tickBudget?.passWindow();
  if (budget?.shouldYield()) {
    // The seal loop spent the tick's whole subrequest budget, so replication never ran at all. Repeated ticks
    // like this are exactly how replicas fall behind fleet-wide with nothing in the pack to say so.
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
  // FAIR ORDER. The downpipes take turns in rounds: in each round each downpipe copies at most
  // REPL_FAIR_QUOTA run(s) to each of its destinations, and a downpipe with more to copy comes back in the
  // next round. The downpipe that starts the first round moves on by one at each cron tick, so when the
  // window fits fewer copies than there are downpipes, a different downpipe is served first at the next tick.
  // A pass that copies nothing spends only its RUNLOG reads: no copy starts once the window is spent
  // (processTarget), and a run-tree is not copied before its segments are (mirrorRunToReplica).
  const order = fairOrder(fanOut);
  let exhausted = false;
  // One signer for the whole pass. A signer that will not load skips every downpipe this tick, and each one
  // is counted as deferred.
  let signer: Signer | undefined;
  let signerFault: string | undefined;
  if (env.SIGNER_PRIVATE) {
    try {
      signer = await loadSigner(env.SIGNER_PRIVATE);
    } catch (e) {
      signerFault = e instanceof Error ? e.message : String(e);
    }
  }
  try {
    const passes: BacklogPass[] = [];
    const caches = newPassCaches();
    let reached = 0;
    for (const s of order) {
      if (budget?.shouldYield()) {
        // The remaining downpipes are DEFERRED to the next tick; the next tick starts one downpipe later.
        passTally.deferredDownpipes += order.length - reached;
        exhausted = true;
        break;
      }
      reached++;
      if (signer === undefined) {
        if (signerFault === undefined) await deferNoSigner(scheduler, s.config.id);
        else noteSkipped(s.config.id, signerFault);
        continue;
      }
      const pass = prepareBacklog(env, scheduler, s.config, histByDp[s.config.id] ?? [], signer, budget, caches);
      if (pass === null) continue;
      if (await roundFailOpen(pass, REPL_FAIR_QUOTA)) passes.push(pass);
    }
    // The later rounds: only the downpipes with runs left to copy, in the same order, while the window lasts.
    let active = exhausted ? [] : passes;
    while (active.length > 0) {
      const next: BacklogPass[] = [];
      for (const pass of active) {
        if (budget?.shouldYield()) {
          exhausted = true;
          break;
        }
        if (await roundFailOpen(pass, REPL_FAIR_QUOTA)) next.push(pass);
      }
      if (exhausted) break;
      active = next;
    }
  } finally {
    // Zeroise the per-pass signer's ML-DSA secret on every path (appendRunlog was the last reader).
    signer?.mldsaSecret.fill(0);
  }
  // One record per pass, and ONLY when the pass had something to say (a clean pass on a healthy fleet posts
  // nothing at all). Counts and a closed outcome; never a destination, a bucket or a message.
  const outcome: ReplicationPassOutcome = exhausted ? "budget-exhausted" : "ok";
  if (outcome !== "ok" || passTally.deferredDownpipes > 0 || passTally.stateWriteFailures > 0 || passTally.verifySampleShortfall > 0 || passTally.segmentVanishDeferrals > 0) {
    await postSealFault(scheduler, { kind: "replication-pass", at: Date.now(), passOutcome: outcome, ...passTally });
  }
}
