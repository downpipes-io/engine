// Retention prune pass for the cron driver (cron/drive.ts), ASVS V14.2.7. For every downpipe that has a
// retention policy, runRetentionPrunes computes the prune PLAN and, ONLY when retention.enforce === true,
// applies it (mark superseded RUNLOG entries + re-sign under the lock, then delete run-trees + orphaned
// segments); runOneRetentionPrune is the per-downpipe plan-and-apply; runlogLockVia adapts the DO lock;
// requireConfig is the required-env helper. Everything here was MOVED VERBATIM out of src/index.ts to
// keep that entry module a thin handler; the behaviour is unchanged. This module imports nothing from
// index.ts, so there is no cycle.

import type { AuditDraft } from "../admin/audit.ts";
import { loadConfigWrapKey } from "../admin/config-secret.ts";
import { recordDiagWrite } from "../admin/diag-writer.ts";
import { buildDestination, fetchDestConfig } from "../dest/factory.ts";
import { doURL } from "../do-url.ts";
import type { Destination } from "../dest/types.ts";
import type { Env } from "../env.d.ts";
import type { ObjectStore } from "../format/reader.ts";
import { parseRunlog } from "../format/writer.ts";
import { loadIdentity, loadSigner, verifierFrom } from "../keys-env.ts";
import { log } from "../log.ts";
import { type NotifyEvent, severityOf } from "../notify.ts";
import { primaryDestinationId, replicaDestinationIds } from "../sched/destinations.ts";
import type { DownpipeState } from "../sched/scheduler-do.ts";
import type { DestReplState } from "../sched/scheduler-do-records.ts";
import type { RunlogLock } from "../seal/pipeline.ts";
import { applyPrune, openRunSegEnumerator, PruneApplyError, type PrunePlan, planPrune, postPruneObservations, type ReplicaCoverage, type RunTreeLister, runTreePrefix, type SegEnumerator, type SizeLookup } from "../seal/prune.ts";
import { noteUndeliveredCriticalAlert } from "./cron-fault-ledger.ts";
import { routeNotification } from "./notify-passes.ts";
// RETENTION EVIDENCE (support-pack G071 / G190). Until this record existed, the retention pass was the one
// data-lifecycle subsystem with NO durable trace at all: every skip, deferral and applied prune reduced to a
// Workers Logs line, so "storage keeps growing despite retention.enforce=true" and "retention deleted my run
// X" both arrived at support with an empty pack. The pass now builds ONE bounded, redaction-safe record per
// tick and posts it to the scheduler DO (recordRetentionPass). The record's vocabulary, shape, classifiers and
// sanitiser live in the LEAF module cron/retention-record.ts so the DO and the pack can share them without
// dragging this pass's import graph (which reaches the seal, dest and admin layers) into the DO base and
// closing a cycle. It no longer reaches admin/router.ts: doURL comes from the do-url.ts leaf, because taking
// it from the router closed a cycle of exactly this kind once the test-fault seam was added.
import { classifyDeferral, classifyPruneError, type RetentionDestOutcome, type RetentionDownpipeOutcome, type RetentionSkipCode, sanitiseRetentionPassRecord } from "./retention-record.ts";

// MutableRetentionRecord is the accumulator the pass fills as it walks its destinations + downpipes; it is
// sanitised into the posted RetentionPassRecord at the end (or at whichever early return the pass takes).
interface MutableRetentionRecord {
  at: number;
  downpipesWithRetention: number;
  downpipesPaused: number;
  replicationUnreadable: boolean;
  auditWriteFailures: number;
  passSkipCode?: RetentionSkipCode;
  destinations: RetentionDestOutcome[];
  downpipes: RetentionDownpipeOutcome[];
}

// recordRetentionPass posts the sanitised pass record to the scheduler DO (POST /retention-record, the
// bounded latest-pass slot the pack's `retention` section reads back via GET /retention-state). Best-effort:
// the retention pass must never fail over its own diagnostics, and recordDiagWrite never throws and never
// alters the caller's path. But no longer SILENT: until this was a bare `catch {}`, the last such
// write in the engine, so a dropped record left the pack showing the previous pass as the latest one. The
// loss is now counted as "retention-record" in the droppedWrites aggregate and lands when the DO recovers.
// An engine whose DO predates the slot answers not-found, which recordDiagWrite counts as a drop: that is
// the honest reading, since the pack's retention section is stale on such an engine either way.
async function recordRetentionPass(scheduler: DurableObjectStub, rec: MutableRetentionRecord): Promise<void> {
  await recordDiagWrite(scheduler, "retention-record", () =>
    scheduler.fetch(doURL("/retention-record"), {
      method: "POST",
      body: JSON.stringify(sanitiseRetentionPassRecord(rec)),
      headers: { "content-type": "application/json" },
    }),
  );
}

// runRetentionPrunes runs the per-downpipe retention prune (ASVS V14.2.7) for EVERY downpipe that
// has a retention policy. It asks the DO for the full downpipe list (GET /downpipes), keeps only the
// ones with a retention policy, and prunes each. A break-glass-only posture (no OPERATIONAL_PRIVATE)
// cannot decrypt manifests to compute the orphan set, so the prune is honestly skipped (the same
// honest deferral the in-account drill makes); the data format already retains superseded entries, so
// nothing is at risk. The destination, signer, verifier and identity are loaded ONCE for the whole
// pass and reused across downpipes (each prune is otherwise a per-downpipe read of the RUNLOG +
// manifests). The whole pass is fail-open: a missing key, a DO hiccup, or a per-downpipe fault
// degrades to "no prune this tick", never a crashed cron.
//
// M7 (3-2-1 durability): the prune is REPLICA-COVERAGE-AWARE. The same-tick "replicate before prune"
// ordering (drive.ts) protects only a replica caught up within the tick; a replica that was down for a
// tick or is behind by more than one tick of backlog is not. So the pass reads the per-destination
// replication state once (loadReplicationState) and gates each downpipe's prune on it: a run over the
// retention cap is RETAINED on the primary until every configured replica is proven to hold it
// (replicaCoverageFor + the planner's coverage gate), so retention can never silently drop a run below
// its configured off-site copy count. A single-destination downpipe has no replicas and is unaffected.
//
// PAUSE MEANS PAUSE (RL-RETENTION-PRUNES-A-PAUSED-DOWNPIPE). A PAUSED downpipe is not pruned. Until
// the selection below was `retention !== undefined` alone, with no test of `config.enabled`
// anywhere in this file, so a downpipe the operator had paused kept having its run trees deleted on the
// cron's own cadence, and its LAST remaining backup became eligible the moment its window elapsed. That
// is the most expensive reading of the switch: `enabled: false` is called "Paused" on every console
// surface an operator reads, which is the customer-facing word for "stop doing things to my data", and
// the documented account-exit tells a departing customer to pause every downpipe and then stop watching.
// It also inverted the danger of the two controls: DELETING a downpipe takes it out of GET /downpipes so
// it is never selected here again, while PAUSING it left it selected and still being pruned, so the
// destructive-sounding action was the safe one.
//
// The suspension is NOT SILENT, which is the half that answers the case for pruning regardless (retention
// is also a storage-cost and data-minimisation promise, and a customer who set `enforce` for a legal
// reason must not silently stop pruning). Every paused-with-retention downpipe is stamped on the pass
// record with the first-class `"paused"` outcome and counted in `downpipesPaused`, so a downpipe that is
// not being pruned is VISIBLY not being pruned, in the pack section support already reads. And an
// ATTENDED prune still deletes: the batched-capsule route (admin/router-retention-prune.ts) is
// dual-controlled (a request, a DISTINCT approver, a matching apply) and does not consult this pass. What
// stops is the unattended background deletion of a downpipe the operator has told the product to stop.
export async function runRetentionPrunes(env: Env, scheduler: DurableObjectStub): Promise<void> {
  // The list is the only cost when no downpipe has retention configured (the common case): we fetch
  // it, find nothing to prune, and return.
  const resp = await scheduler.fetch(doURL("/downpipes"), { method: "GET" });
  const states = (await resp.json()) as DownpipeState[];
  const withRetention = states.filter((s) => s.config.retention !== undefined);
  if (withRetention.length === 0) return;

  // PAUSE MEANS PAUSE: partition on the downpipe's own enabled switch. `!s.config.enabled` rather than
  // `s.config.enabled === false` deliberately, so a state record that carries NO enabled field (a legacy
  // or malformed shape) counts as paused and is RETAINED. Every ambiguity in this file resolves towards
  // keeping bytes, the same direction the replica-coverage gate and the planner's abstention take.
  const paused = withRetention.filter((s) => !s.config.enabled);
  const active = withRetention.filter((s) => s.config.enabled);

  // The pass evidence record (G071/G190): filled as the pass walks, posted at whichever exit it takes.
  // downpipesWithRetention stays the TOTAL carrying a policy (it is what the pack's "how many downpipes
  // does retention apply to" line means); downpipesPaused is how many of them this pass did not touch.
  const rec: MutableRetentionRecord = {
    at: Date.now(),
    downpipesWithRetention: withRetention.length,
    downpipesPaused: paused.length,
    replicationUnreadable: false,
    auditWriteFailures: 0,
    destinations: [],
    downpipes: [],
  };
  // One row per paused downpipe, with zero counts: the pack shows the downpipe was SEEN and deliberately
  // left alone, which is a different sentence from its absence (retention silently doing nothing).
  // destKey resolves the SAME way the bucketing below does (primaryDestinationId, "" = default), so the
  // per-destination fold (B61) can attribute the stand-down to the bucket it would have pruned.
  for (const s of paused) {
    rec.downpipes.push({ id: s.config.id, destKey: primaryDestinationId(s.config) ?? "", outcome: "paused", supersededRuns: 0, runTreeObjects: 0, orphanSegs: 0, retainedRuns: 0 });
  }
  // Every retention downpipe is paused: post the record (so the pack still shows the pass ran and why it
  // deleted nothing) and stop before loading keys or building a destination.
  if (active.length === 0) {
    await recordRetentionPass(scheduler, rec);
    return;
  }

  // M7 (3-2-1 durability): read the per-destination replication state ONCE for the whole pass so the
  // prune can gate on replica coverage (a run is not pruned from the primary until every configured
  // replica is proven to hold it). A failure to read it degrades to an EMPTY map, which makes the
  // gate HOLD every replicated run (the conservative direction: a downpipe with replicas configured
  // but no readable coverage proof prunes nothing this tick rather than risk dropping an off-site
  // copy). A single-destination downpipe is unaffected (it has no replicas to wait for).
  const repl = await loadReplicationState(scheduler);
  const replByDownpipe = repl.byDownpipe;
  rec.replicationUnreadable = repl.unreadable;

  // Break-glass-only posture: the engine holds no in-account read-back key, so it cannot decrypt the
  // shard manifests to compute the retained/orphan segment sets. Skip honestly (a prune here would be
  // a guess, and the format already keeps superseded entries, so retention is simply deferred to an
  // offline tool). This mirrors runDrill's break-glass-only deferral.
  if (!env.OPERATIONAL_PRIVATE) {
    log("error", `retention prune deferred: break-glass-only posture (no OPERATIONAL_PRIVATE); ${active.length} downpipe(s) with retention await an offline prune`);
    rec.passSkipCode = "break-glass-only";
    await recordRetentionPass(scheduler, rec);
    return;
  }

  // Each destination is a SELF-CONTAINED archive with its OWN RUNLOG, so group the retention
  // downpipes by their destination and prune each bucket once (read that bucket's RUNLOG, prune the
  // downpipes that write to it). Downpipes with no pinned destination share the default. A destination
  // that cannot be resolved is skipped (logged), never pruned against the wrong bucket.
  // ACTIVE only: a paused downpipe was already stamped on the record above and never reaches a bucket,
  // so it also never causes a destination to be built or a RUNLOG to be read on its behalf.
  const groups = groupRetentionByPrimaryDest(active);

  // Load the operational identity + verifier + signer once for the whole pass; a missing required key
  // degrades the whole pass to a skipped tick (loadPassKeys logs and returns null).
  const keys = await loadPassKeys(env, env.OPERATIONAL_PRIVATE);
  if (keys === null) {
    rec.passSkipCode = "keys-unavailable";
    await recordRetentionPass(scheduler, rec);
    return;
  }
  const { signer } = keys;
  try {
    // The volume guard's held-run reports accumulate here across every destination + downpipe, then the pass
    // edge-triggers ONE backup-volume-regression alert per newly-regressed downpipe after the prune finishes.
    const regressed: VolumeRegressionAlert[] = [];
    const infra: RetentionPruneInfra = { scheduler, ...keys, lock: runlogLockVia(scheduler), replByDownpipe, regressed, rec, destKey: "" };
    const now = new Date();
    for (const [key, group] of groups) {
      await runRetentionPrunesForDest(env, infra, key, group, now);
    }
    // The pass evidence record (G071/G190): posted AFTER every destination has reported, so one bounded
    // record carries the whole tick (skips, deferrals, applied counts, lost audit writes).
    await recordRetentionPass(scheduler, rec);
    // Route the edge-triggered volume-regression alerts (fail-open; the DO dedups per episode). It runs AFTER
    // the whole prune so it never delays it, and a delivery fault degrades to "no alert this tick".
    await emitVolumeRegressionAlerts(env, scheduler, regressed);
  } finally {
    // Zeroise the per-pass signer's ML-DSA secret on every path (the NC-6 discipline the seal paths
    // follow); the RUNLOG re-sign inside applyPrune is the last legitimate reader.
    signer.mldsaSecret.fill(0);
  }
}

// groupRetentionByPrimaryDest buckets the retention downpipes by the destination their runs ACTUALLY
// seal to, i.e. the PRIMARY of destinationIds[] (first non-blank), falling back to the legacy single
// destinationId, then to the default ("") -- exactly the resolution the seal path uses
// (primaryDestinationId), so every downpipe lands in the bucket whose RUNLOG actually holds its runs,
// including a console-created downpipe that pins a NON-DEFAULT primary via destinationIds[] with no legacy
// destinationId. A legacy single-destinationId downpipe resolves to the SAME key as before
// (primaryDestinationId returns destinationId when there is no list), so its behaviour is unchanged.
// Exported so the retention validator can assert the key without standing up a DO. Replicas are not
// bucketed here: retention prunes the primary archive's RUNLOG, and a replica is an additional copy of
// finalised runs, not a separate retention scope.
export function groupRetentionByPrimaryDest(withRetention: DownpipeState[]): Map<string, DownpipeState[]> {
  const groups = new Map<string, DownpipeState[]>();
  for (const s of withRetention) {
    const key = primaryDestinationId(s.config) ?? "";
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(s);
  }
  return groups;
}

// loadReplicationState reads the whole fleet's per-destination replication state ONCE (GET
// /replication => { byDownpipe }), the holdsIndex map the M7 prune gate reads. Fail-open: an
// unreadable replication state degrades to an EMPTY map, which makes replicaCoverageFor report a
// configured replica as holding NOTHING (holdsIndex -1), so a downpipe with replicas prunes nothing
// this tick rather than risk dropping an off-site copy on a missing proof. A single-destination
// downpipe is unaffected (it has no replicas to gate on).
// The `unreadable` boolean rides the pass evidence record (G071): a pass that gated on NO coverage proof
// prunes nothing for every replicated downpipe, which otherwise looks identical to "retention is working
// and there is simply nothing to delete".
// THE SIBLING OF fetchReplication'S OWN FAULT CHECK (G299), and it needs the same r.ok. SchedulerDO.fetch
// catches the DO's faults and NORMALLY RESOLVES a JSON error body (a `repl:` storage.list fault becomes a 400,
// a runtime fault a 500), so a non-2xx parses cleanly, byDownpipe is undefined, and the map is {} with
// `unreadable: false`. The PRUNE behaviour is safe either way (an empty map proves no coverage, so a
// replicated downpipe prunes nothing), but the pass evidence record this boolean rides into the support pack
// (G071) then ASSERTS the replication state was read and was empty, when it was never read at all. Support
// reads a pass that gated on no coverage proof as "retention is working and there is nothing to delete".
// Exported so the batched-capsule admin prune route (router-retention-prune.ts) can gate its OWN
// planPrune call on the same proven replica coverage the cron pass uses, rather than re-deriving it: a
// break-glass-only estate's admin-triggered prune must honour the 3-2-1 gate exactly as the cron would,
// never a looser or re-implemented copy of it.
export async function loadReplicationState(scheduler: DurableObjectStub): Promise<{ byDownpipe: Record<string, Record<string, DestReplState>>; unreadable: boolean }> {
  try {
    const r = await scheduler.fetch(doURL("/replication"), { method: "GET" });
    if (!r.ok) {
      log("error", `retention prune: replication state unreadable this tick (DO ${r.status}), gating on no-coverage (conservative)`);
      return { byDownpipe: {}, unreadable: true };
    }
    const body = (await r.json()) as { byDownpipe?: Record<string, Record<string, DestReplState>> };
    return { byDownpipe: body.byDownpipe ?? {}, unreadable: false };
  } catch (e) {
    log("error", `retention prune: replication state unreadable this tick, gating on no-coverage (conservative): ${(e as Error).message}`);
    return { byDownpipe: {}, unreadable: true };
  }
}

// replicaCoverageFor computes the M7 ReplicaCoverage for one downpipe from its CONFIGURED replica
// destinations (replicaDestinationIds, the primary excluded) and the proven per-destination holds state.
// hasReplicas is false for a single-destination downpipe, which makes the gate inert (retention applies
// normally). With replicas, minReplicaHoldsIndex is the MINIMUM holdsIndex across them (the most-behind
// replica; -1 for a configured replica with no recorded state, i.e. it holds nothing yet), so a run is
// only prunable when EVERY configured replica is caught up to it. maxReplicaHoldsFrom is the MAXIMUM
// holdsFrom (proven floor) across them: a replica whose observation only started at the ring floor (a
// replica added after older runs aged out of the 50-run history ring) can prove nothing BELOW that floor,
// so a run below maxReplicaHoldsFrom is treated as uncovered and RETAINED (BD-RETENTION-HOLDSINDEX-
// RINGFLOOR-OVERCLAIM). A replica with no recorded floor contributes +Infinity (proves nothing below its
// holdsIndex), the conservative retains-more default that self-heals when the replicate pass records a
// floor. Pure; exported so the validator can assert the gate without standing up a DO.
export function replicaCoverageFor(config: DownpipeState["config"], replState: Record<string, DestReplState>): ReplicaCoverage {
  const replicas = replicaDestinationIds(config);
  if (replicas.length === 0) return { hasReplicas: false, minReplicaHoldsIndex: -1, maxReplicaHoldsFrom: Number.POSITIVE_INFINITY };
  let min = Number.POSITIVE_INFINITY;
  let maxFrom = Number.NEGATIVE_INFINITY;
  for (const destId of replicas) {
    const st = replState[destId];
    const holds = st?.holdsIndex ?? -1; // no recorded state => holds nothing yet
    if (holds < min) min = holds;
    // The proven FLOOR for this replica: the lowest run it has contiguously observed. Absent (a legacy
    // record from before the floor was tracked, or a replica with no state) => it can prove NOTHING below
    // its holdsIndex, so contribute +Infinity: the aggregate floor then excludes every run until the
    // replicate pass records a real floor (conservative, retains-more; self-heals next tick).
    const from = st?.holdsFrom ?? Number.POSITIVE_INFINITY;
    if (from > maxFrom) maxFrom = from;
  }
  return { hasReplicas: true, minReplicaHoldsIndex: min === Number.POSITIVE_INFINITY ? -1 : min, maxReplicaHoldsFrom: maxFrom };
}

// loadPassKeys loads the run signer, the operational identity and the verifier ONCE for the whole pass
// (the same wiring the drill builds). A missing required key (SIGNER_PRIVATE) or an unloadable identity
// logs coarsely and returns null, which the caller turns into a skipped tick rather than a crashed cron.
// The caller owns zeroising the returned signer's ML-DSA secret on every path.
async function loadPassKeys(env: Env, operationalPrivate: string): Promise<{ signer: Awaited<ReturnType<typeof loadSigner>>; identity: ReturnType<typeof loadIdentity>; verifier: ReturnType<typeof verifierFrom> } | null> {
  try {
    const signer = await loadSigner(requireConfig(env.SIGNER_PRIVATE, "SIGNER_PRIVATE"));
    const identity = loadIdentity(operationalPrivate);
    const verifier = verifierFrom(signer);
    return { signer, identity, verifier };
  } catch (e) {
    log("error", `retention prune skipped: ${(e as Error).message}`);
    return null;
  }
}

// runRetentionPrunesForDest prunes ONE destination bucket: it resolves and builds the destination,
// reads ITS self-contained RUNLOG once, then prunes every retention downpipe that writes to it. Each
// destination is independent, so a per-destination fault (unresolvable destination, unreadable RUNLOG)
// skips just that bucket's downpipes, never the whole pass; a per-downpipe fault inside the loop skips
// just that downpipe (the next tick retries, the planner is idempotent). "" is the default destination.
async function runRetentionPrunesForDest(env: Env, infra: RetentionPruneInfra, key: string, group: DownpipeState[], now: Date): Promise<void> {
  // Every exit below stamps ONE destination outcome on the pass record (G071): a closed skip code, or no code
  // when the bucket was pruned. destKey is the customer's own opaque destination id ("" = default).
  const noteDest = (skipCode?: RetentionSkipCode): void => {
    infra.rec.destinations.push({ destKey: key, downpipeCount: group.length, ...(skipCode !== undefined ? { skipCode } : {}) });
  };
  let dest: Awaited<ReturnType<typeof buildDestination>>;
  try {
    const destCfg = await fetchDestConfig(infra.scheduler, key || undefined, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
    if (key && !destCfg) {
      log("error", `retention prune skipped for destination ${key}: not configured`);
      noteDest("dest-not-configured");
      return;
    }
    dest = await buildDestination(env, undefined, destCfg ?? null);
  } catch (e) {
    log("error", `retention prune skipped for destination ${key || "default"}: ${(e as Error).message}`);
    noteDest("dest-build-failed");
    return;
  }
  const store: ObjectStore = {
    get: async (k: string) => {
      const r = await dest.get(k);
      if (!r) throw new Error(`object ${k} is missing`);
      return r.body;
    },
  };
  let entries: ReturnType<typeof parseRunlog>;
  try {
    const runlog = await dest.get("_RECOVERY/RUNLOG");
    if (!runlog) {
      noteDest("runlog-absent"); // nothing finalised in this bucket
      return;
    }
    entries = parseRunlog(runlog.body);
  } catch (e) {
    log("error", `retention prune skipped for destination ${key || "default"}: RUNLOG unreadable (${(e as Error).message})`);
    noteDest("runlog-unreadable");
    return;
  }
  noteDest(); // the bucket was pruned: its downpipes' own outcomes follow
  // Key the RUNLOG lock by THIS destination bucket (SCALE-3): the prune serialises only against seals to
  // the same destination's RUNLOG, not the whole fleet. `key` is "" for the default destination, which
  // runlogLockVia maps to the default slot the unpinned seal path uses.
  const destInfra: RetentionPruneInfra = { ...infra, lock: runlogLockVia(infra.scheduler, key), destKey: key };
  for (const state of group) {
    try {
      await runOneRetentionPrune(destInfra, dest, store, entries, state, now);
    } catch (e) {
      // A per-downpipe fault must not abort the rest of the pass or crash the cron; log coarsely and
      // continue. The next tick retries (the planner is idempotent and delete is a no-op on an absent
      // key, so a partially-applied prune simply finishes next time). The fault is CLASSED onto the pass
      // record (G071/G190) so a half-applied or perpetually-throwing prune is diagnosable from the pack.
      // A PruneApplyError's wormBlocked boolean rides the row (B61): a WORM/Object-Lock delete refusal is
      // an irreducible remainder, and the per-destination fold must not read it as a transient flake.
      log("error", `retention prune for ${state.config.id} skipped: ${(e as Error).message}`);
      destInfra.rec.downpipes.push({
        id: state.config.id,
        destKey: key,
        outcome: "error",
        errorClass: classifyPruneError(e),
        ...(e instanceof PruneApplyError && e.wormBlocked ? { wormBlocked: true } : {}),
        supersededRuns: 0,
        runTreeObjects: 0,
        orphanSegs: 0,
        retainedRuns: 0,
      });
    }
  }
}

// RetentionPruneInfra groups the per-pass shared wiring (loaded ONCE and reused across every
// destination + downpipe in the pass): the scheduler stub, the RUNLOG lock, the run signer, the
// operational identity and the verifier. Passing it as one argument keeps runOneRetentionPrune (and the
// per-destination loop that calls it) within the max-4-params rule (GUARDRAILS §6).
interface RetentionPruneInfra {
  scheduler: DurableObjectStub;
  signer: Awaited<ReturnType<typeof loadSigner>>;
  identity: ReturnType<typeof loadIdentity>;
  verifier: ReturnType<typeof verifierFrom>;
  lock: RunlogLock;
  // M7: the per-downpipe per-destination replication state (holdsIndex per destination), read ONCE for
  // the whole pass, so each downpipe's prune can gate on whether its configured replicas hold a run.
  replByDownpipe: Record<string, Record<string, DestReplState>>;
  // The volume-regression reports accumulated across the pass (one per downpipe the volume guard held a
  // high-water run for), routed as edge-triggered alerts after the whole prune (emitVolumeRegressionAlerts).
  regressed: VolumeRegressionAlert[];
  // The pass EVIDENCE accumulator (G071/G190): every destination skip and per-downpipe outcome is stamped
  // here, sanitised, and posted to the DO once at the end of the pass.
  rec: MutableRetentionRecord;
  // The destination bucket this infra copy prunes ("" = default): stamped onto each downpipe row so the
  // per-destination fold (B61) can attribute it. Set by the per-destination loop; "" at construction.
  destKey: string;
}

// VolumeRegressionAlert is one downpipe's redaction-safe volume-regression report: its id + name + the
// held-vs-retained record counts. It is what the prune pass accumulates and the DO edge-trigger turns into
// a backup-volume-regression alert. Counts only, never a value, key, selector or secret.
export interface VolumeRegressionAlert {
  id: string;
  name: string;
  heldMaxRecordCount: number; // the largest HELD (volume high-water) run's record count
  retainedMaxRecordCount: number; // the max record count among the runs the cap retained (the replacements)
  heldCount: number; // how many runs the guard held this pass
}

// runOneRetentionPrune plans (and, when enforced, applies) the prune for ONE downpipe. The planner
// computes the plan from the shared RUNLOG entries, this downpipe's policy and now, decrypting each
// run's manifests via openRun (the operational identity). DRY-RUN is the default: when
// retention.enforce is not exactly true, it logs the plan and returns WITHOUT writing or deleting
// anything. ONLY enforce === true reaches applyPrune (mark superseded + re-sign under the lock, then
// delete run-trees + orphans) and records a first-class retention-prune AUDIT event with the counts.
async function runOneRetentionPrune(
  infra: RetentionPruneInfra,
  dest: Awaited<ReturnType<typeof buildDestination>>,
  store: ObjectStore,
  entries: ReturnType<typeof parseRunlog>,
  state: DownpipeState,
  now: Date,
): Promise<void> {
  const retention = state.config.retention;
  if (retention === undefined) return;
  const { scheduler, signer, identity, verifier, lock, replByDownpipe } = infra;
  const id = state.config.id;
  const io = prunePlannerInputs(dest, store, identity, verifier);
  // M7: the replica-coverage gate for THIS downpipe, computed from its configured replicas and their
  // proven holdsIndex. The planner uses it to hold any over-cap run that a configured replica has not
  // yet received, so retention can never drop a run below its 3-2-1 copy count.
  const coverage = replicaCoverageFor(state.config, replByDownpipe[id] ?? {});
  const plan: PrunePlan = await planPrune(entries, id, { ...(retention.keepRuns !== undefined ? { keepRuns: retention.keepRuns } : {}), ...(retention.keepDays !== undefined ? { keepDays: retention.keepDays } : {}) }, now, io.enumerateSegs, io.listRunTree, io.sizeOf, coverage);
  // postPruneObservations (G190) writes the PLANNER's fault rows onto the bounded seal-fault ring: the abstain
  // (with the CLOSED defer class + the opaque id of the blocking retained run -- the run that defers every pass
  // forever), the superseded runs the planner SILENTLY excluded because they could not be read, and the RUNLOG
  // entries whose timestamp did not parse (which silently changes eligibility). A CLEAN plan emits nothing, so a
  // healthy fleet's ring is untouched. Best-effort and fail-open by construction: it can never colour the prune.
  await postPruneObservations(scheduler, plan, now.getTime());

  // VOLUME-REGRESSION: the guard held a volume high-water run this pass (an emptied/shrunken source would
  // else evict the last FULL backup). Collect it for the edge-triggered alert; the hold already happened in
  // the partition, so this fires regardless of dry-run/enforce/deferred (it never deleted anything either way).
  if (plan.volumeRegression !== undefined) {
    infra.regressed.push({ id, name: state.config.name, heldMaxRecordCount: plan.volumeRegression.heldMaxRecordCount, retainedMaxRecordCount: plan.volumeRegression.retainedMaxRecordCount, heldCount: plan.volumeRegression.heldRunIds.length });
  }

  // The counts every outcome below carries: planned (or, on the applied path, committed) work + the volume
  // guard's held-run count. Counts only, never an object key.
  const planned = {
    supersededRuns: plan.supersededRunIds.length,
    runTreeObjects: plan.runTreeObjects.length,
    orphanSegs: plan.orphanSegs.length,
    retainedRuns: plan.retainedRunIds.length,
    ...(plan.volumeRegression !== undefined ? { volumeHeld: plan.volumeRegression.heldRunIds.length } : {}),
  };

  // Abstained pass: a retained run could not be read, so the planner returned empty delete sets to
  // keep segment GC safe. Log why and return; a later tick retries when the run is readable. The deferral's
  // operator-facing TEXT never rides the record: classifyDeferral coarsens it to a closed class (G190), so a
  // downpipe that defers every tick forever ("retention never deletes anything") is visible as a class.
  if (plan.deferred !== undefined) {
    log("error", `retention prune deferred ${id}: ${plan.deferred}`);
    infra.rec.downpipes.push({ id, destKey: infra.destKey, outcome: "deferred", deferralClass: classifyDeferral(plan.deferred), ...planned });
    return;
  }
  // THE GATE: enforce must be the literal boolean true to delete. Absent or false is dry-run: report
  // the plan in the structured log and return. Nothing is written or deleted on the default path.
  if (retention.enforce !== true) {
    // The byte total is intentionally not reported: it would require a full-body read of every
    // deletable segment (see the planPrune call above), so the dry-run line counts objects, not bytes.
    log("info",
      `retention prune (dry-run) ${id}: would supersede ${plan.supersededRunIds.length} run(s), delete ${plan.runTreeObjects.length} run-tree object(s) + ${plan.orphanSegs.length} orphan segment(s) (retain ${plan.retainedRunIds.length})`,
    );
    // A dry-run is the DEFAULT posture, and the "storage keeps growing despite retention" ticket is most
    // often exactly this: enforce was never set. The record says so in counts (G071).
    infra.rec.downpipes.push({ id, destKey: infra.destKey, outcome: "dry-run", ...planned });
    return;
  }
  // Nothing to do: no run falls outside the window. Skip the apply (and the audit) entirely so an
  // enforced prune with no work neither writes nor records (idempotent: a second prune is a no-op).
  if (plan.supersededRunIds.length === 0 && plan.runTreeObjects.length === 0 && plan.orphanSegs.length === 0) {
    infra.rec.downpipes.push({ id, destKey: infra.destKey, outcome: "no-op", ...planned });
    return;
  }
  // ENFORCED apply: mark superseded + re-sign under the RUNLOG lock, then delete run-trees + orphans.
  // A PruneApplyError means the apply died PARTWAY through its delete loop: the RUNLOG is already consistent
  // (supersede commits first) but the deletes are half-done, so storage keeps growing with no trace -- the
  // progress counts used to be thrown away with the exception. Record what the apply had actually committed
  // (plus whether WORM/Object-Lock REFUSED the delete, an irreducible remainder rather than a transient flake)
  // and then RE-THROW unchanged, so the fail-open retry behaviour above is byte-for-byte what it was (G190).
  let result: Awaited<ReturnType<typeof applyPrune>>;
  try {
    result = await applyPrune(dest, signer, plan, lock);
  } catch (e) {
    if (e instanceof PruneApplyError) await postPruneObservations(scheduler, plan, now.getTime(), e);
    throw e;
  }
  log("info",
    `retention prune (applied) ${id}: superseded ${result.superseded} run(s), deleted ${result.runTreeDeleted} run-tree object(s) + ${result.orphansDeleted} orphan segment(s)`,
  );
  // The APPLIED record carries what was COMMITTED (result), not what was planned, so a half-applied prune
  // (a delete that threw partway) is visible as applied-with-fewer-deletes rather than as the full plan.
  infra.rec.downpipes.push({
    id,
    destKey: infra.destKey,
    outcome: "applied",
    supersededRuns: result.superseded,
    runTreeObjects: result.runTreeDeleted,
    orphanSegs: result.orphansDeleted,
    retainedRuns: plan.retainedRunIds.length,
    ...(planned.volumeHeld !== undefined ? { volumeHeld: planned.volumeHeld } : {}),
  });
  // A LOST audit write means the chain never records a deletion that really happened ("retention deleted my
  // run X" with no audit event to show for it): count it on the pass record so the loss is visible.
  if (!(await recordPruneAudit(scheduler, id, state.config.name))) infra.rec.auditWriteFailures++;
}

// recordPruneAudit records a first-class audit event on an APPLIED prune (the dry-run path does not
// audit; it is reported in the engine log only). actorMethod "engine": the cron applied it on the
// configured schedule with no human actor, exactly like the engine-observed events. The target is the
// downpipe (redaction-safe: id + name). A failed audit write must not undo the prune, so it is best-effort:
// it returns whether the chain entry was accepted, and the caller counts a false onto the pass record's
// auditWriteFailures (G071) so an applied-but-unaudited prune is not invisible.
async function recordPruneAudit(scheduler: DurableObjectStub, id: string, name: string): Promise<boolean> {
  try {
    const draft: AuditDraft = {
      actorEmail: null,
      actorMethod: "engine",
      sourceIp: null,
      action: "retention-prune",
      outcome: "success",
      target: { kind: "downpipe", id, name },
    };
    const r = await scheduler.fetch(doURL("/audit"), { method: "POST", body: JSON.stringify(draft), headers: { "content-type": "application/json" } });
    return r.ok;
  } catch (e) {
    log("error", `retention-prune audit record failed for ${id} (non-critical): ${(e as Error).message}`);
    return false;
  }
}

// emitVolumeRegressionAlerts routes the EDGE-TRIGGERED backup-volume-regression alerts for the pass. It
// ALWAYS reconciles the current regressed id set with the DO (even when empty) so the marker CLEARS when a
// downpipe's volume recovers and a future re-regression re-alerts; the DO returns only the NEWLY regressed
// ids, and this routes exactly one warning per new regression through the same fail-open notification model
// as the source-drift alert (routeNotification swallows every delivery error). Fully guarded: a DO hiccup or
// a delivery fault degrades to "no alert this tick", never a thrown prune. It carries only redaction-safe
// data (the downpipe name + the held-vs-retained record counts), never a value or key. Exported so the
// retention validator can drive it directly without standing up the whole prune pass.
export async function emitVolumeRegressionAlerts(env: Env, scheduler: DurableObjectStub, regressed: VolumeRegressionAlert[]): Promise<void> {
  try {
    const byId = new Map(regressed.map((r) => [r.id, r] as const));
    const reconResp = await scheduler.fetch(doURL("/volume-regression/reconcile"), { method: "POST", body: JSON.stringify({ regressed: [...byId.keys()] }), headers: { "content-type": "application/json" } });
    const { newlyRegressed } = (await reconResp.json()) as { newlyRegressed: string[] };
    if (newlyRegressed.length === 0) return;
    const at = new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
    for (const dpId of newlyRegressed) {
      const r = byId.get(dpId);
      if (r === undefined) continue; // a marker id with no current report (a raced recovery): nothing to say
      const detail = `${r.name}: retention held a ${r.heldMaxRecordCount}-record backup that newer ${r.retainedMaxRecordCount}-record run(s) would have evicted; the larger backup is retained, not deleted. Check whether the source has emptied.`;
      const event: NotifyEvent = "backup-volume-regression";
      // G184: the DO's reconcile above ALREADY LATCHED this downpipe as alerted (that is what makes the alert
      // edge-triggered: it re-arms only when the volume recovers), so a routing failure here loses the warning
      // for the WHOLE regression episode -- and this call site discarded the delivered boolean. Latch it, so a
      // pack can say the page was consumed and never delivered instead of showing an unexplained silence.
      const delivered = await routeNotification(env, scheduler, { event, severity: severityOf(event), downpipeId: dpId, downpipeName: r.name, detail, at });
      if (!delivered) noteUndeliveredCriticalAlert(event, true);
    }
  } catch (e) {
    log("error", `volume-regression alert pass skipped this tick: ${(e as Error).message}`);
  }
}

// prunePlannerInputs builds the IO the prune planner needs for ONE destination: the segment
// enumerator (openRun under the operational identity) and the run-tree lister (dest.list). It
// DELIBERATELY returns NO sizeOf lookup (engine-src-025-08), so planPrune reports reclaimableBytes
// = 0. The only size signal the Destination contract gives is a full dest.get(), and a deletable
// object is a sealed segment up to 1 GiB, so summing a precise reclaimable-byte total would fetch
// every whole body into memory only to read its length. That full-body read is not worth a cosmetic
// byte count in a log line. The Destination interface has no HEAD primitive that would return a size
// cheaply, and adding one would touch every Destination implementation, so the prune simply forgoes
// the precise total. The plan is complete either way: which runs are superseded and which objects
// are deletable do not depend on their sizes. Exported so the retention validator can assert that the
// production path supplies no body-reading sizeOf (the regression this finding fixed).
export function prunePlannerInputs(
  dest: Destination,
  store: ObjectStore,
  identity: ReturnType<typeof loadIdentity>,
  verifier: ReturnType<typeof verifierFrom>,
): { enumerateSegs: SegEnumerator; listRunTree: RunTreeLister; sizeOf?: SizeLookup } {
  return {
    enumerateSegs: openRunSegEnumerator(store, identity, verifier),
    listRunTree: (runId: string) => dest.list(runTreePrefix(runId)),
    // sizeOf intentionally omitted: see the rationale above. reclaimableBytes is forgone, not bought
    // with a full-body read of every deletable segment.
  };
}

// runlogLockVia adapts the scheduler DO's /runlog-lock routes to the RunlogLock interface (the same
// adapter the seal DO uses, runstate.ts), so an enforced prune serialises its RUNLOG re-sign against
// concurrent runs through the lock. destKey is the destination bucket being pruned (SCALE-3 per-destination
// keying): the prune contends only with seals to the SAME destination's RUNLOG, never the whole fleet. An
// absent/blank destKey targets the default destination's slot (the legacy unkeyed behaviour).
// Exported so the batched-capsule admin prune route can serialise its own applyPrune call against
// the SAME per-destination lock the cron pass uses, rather than an unlocked write or a second, divergent
// adapter; a human-triggered apply and a cron tick must never race the same destination's RUNLOG.
export function runlogLockVia(scheduler: DurableObjectStub, destKey?: string): RunlogLock {
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

// requireConfig is the local "a required env value must be present" helper (the same shape drill.ts
// and the seal paths use), so a missing SIGNER_PRIVATE fails with a clear message that the prune
// pass's guard turns into a skipped tick rather than a crash.
function requireConfig(v: string | undefined, name: string): string {
  if (!v) throw new Error(`missing required configuration: ${name}`);
  return v;
}
