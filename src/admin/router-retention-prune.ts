// router-retention-prune.ts -- the batched-capsule retention-prune route. It closes the ONE case the
// standing engine cron pass (cron/retention-pass.ts) honestly refuses: on a break-glass-only estate (no
// OPERATIONAL_PRIVATE) the engine holds no in-account read-back key, so it cannot decrypt a run's shard
// manifests to compute the retained/orphan segment sets, and runRetentionPrunes defers the whole pass every
// tick. Until this route existed the console's only answer was "prune offline with the reader instead" -- a
// terminal instruction, which the house no-customer-CLI rule forbids (see the editor-retention-section.ts hint
// this route lets us finally shorten).
//
// The fix reuses the SAME shape the attended-verification session (router-attest.ts) and the break-glass
// restore panel (router-restore.ts POST /restore/capsule) already established for this exact problem: the
// engine never asks for the break-glass PRIVATE. It serves each candidate run's NON-SECRET master capsule
// (POST /retention-prune/candidate), the browser recovers each run's 32-byte master locally (keydecap.ts
// openCapsule, entirely client-side), and the browser hands back ONLY those per-run masters, batched, on
// POST /retention-prune/apply. The masters are used to build a SegEnumerator for exactly one call and are
// never stored; every recovered master this router touches is zeroed before the response is built, on
// every exit path (see the try/finally around the plan phase below).
//
// PRUNE LOGIC REUSE (the load-bearing safety property): this route calls the SAME PURE planner
// (seal/prune.ts planPrune) and the SAME apply (applyPrune) the cron pass calls, unmodified. It does not
// reimplement retention or segment-GC. The only thing this route supplies that the cron cannot, in this
// posture, is the SegEnumerator: cron builds one from the held OPERATIONAL_PRIVATE identity
// (openRunSegEnumerator); this route builds one from the browser-supplied per-run masters
// (openRunWithMaster).
//
// THE ABSTAIN GAP. planPrune's own ABSTAIN invariant only protects a
// segment referenced by a RETAINED run: if a SUPERSEDED run cannot be opened, buildSupersededSegRefs
// silently EXCLUDES it from the superseded reference set (fail-safe on its own downpipe-wide view) -- but a
// segment that run shares with a DIFFERENT superseded run that DID open is then computed as an orphan and
// deleted, even though the excluded run's own RUNLOG entry stays "active" (never superseded) and its
// manifest still references that now-missing segment. planPrune itself is
// NOT changed (it stays the cron's unmodified, exhaustively-tested planner); instead this route now
// requires the operator's batch to open EVERY candidate run (retained AND superseded) before planPrune is
// ever called at all (precheckCandidateCoverage below). A batch that cannot open every candidate is refused
// outright, naming every run that failed, whether the master was omitted or simply wrong -- so planPrune's
// own internal enumeration can never hit a run this route has not already proven readable, and the shared-
// segment scenario above cannot arise: either every superseded run opens (nothing is silently excluded) or
// the whole call refuses before any delete.
//
// DUAL CONTROL. retention.enforce is armed via plain downpipe.write
// (dual-controlled only when the OPT-IN requireConfigApproval gate is on, which is OFF by default), and a
// restore apply -- overwriting live data, but leaving the archive untouched -- unconditionally requires a
// SECOND authorised identity's approval (router-restore.ts, admin/approvals.ts D2). A prune apply deletes
// the archive itself, a LESS reversible act, so a single identity plus step-up was not enough: this route
// now requires its OWN maker != checker approval (admin/prune-approvals.ts, mirroring the D2
// RestoreApproval/planHash pattern) bound to a keyless planHash over the downpipe's CURRENT retained/
// superseded split, before ANY real delete. Preview (previewOnly:true, or a downpipe whose stored enforce
// is not true) needs no approval: it can never delete. See prune-approvals.ts's header for the single-
// owner-estate posture (no carve-out: identical to restore's, a sole owner is blocked until a second
// identity exists).
//
// AUTHORITY MODEL. candidate is gated on restore.verify (the read-safe viewer floor restore/capsule already
// uses at router-restore.ts:535): it discloses only non-secret capsule wraps already sitting in the
// customer's own bucket, undecryptable without the break-glass private, which never leaves the browser.
// request/reject mirror restore.request/restore.approve; approve is additionally step-up gated
// (STEPUP_SUBS), mirroring /restore/approve. apply is gated on restore.apply (restore-operator/approver/
// owner) PLUS step-up: every restore.apply holder already holds drill.run (identity-rbac.ts
// ROLE_CAPABILITIES), so this can never sit BELOW the attend session's drill.run floor.
//
// This route deliberately does NOT go through the gatedOwnerAction "202 owner action queued" machinery
// (scheduler-do-dual-control.ts): that machinery is reserved for CONFIG/identity/destination mutations
// (dest-set/remove, idp-conn-*, push-dest-set, discovery-*), never a data-plane action. A prune apply is a
// data-plane action, so it gets the platform's DATA-PLANE dual-control precedent (D2) instead, per fix 1.
import { classifyPruneError, type RetentionDownpipeOutcome, type RetentionPassRecord, sanitiseRetentionPassRecord } from "../cron/retention-record.ts";
import { openRunWithMaster, readRunCapsule, type ObjectStore, type RunCapsule } from "../format/reader.ts";
import { parseRunlog, type RunlogEntry } from "../format/writer.ts";
import { buildDestination, fetchDestConfig } from "../dest/factory.ts";
import { loadConfigWrapKey } from "./config-secret.ts";
import { loadSigner, verifierFrom } from "../keys-env.ts";
import { loadReplicationState, replicaCoverageFor, runlogLockVia } from "../cron/retention-pass.ts";
import { primaryDestinationId } from "../sched/destinations.ts";
import type { DownpipeState } from "../sched/scheduler-do.ts";
import type { DestReplState } from "../sched/scheduler-do-records.ts";
import { applyPrune, partitionRuns, planPrune, postPruneObservations, PruneApplyError, type PrunePlan, runTreePrefix, type RunTreeLister, type SegEnumerator } from "../seal/prune.ts";
import { classifyRestoreFailure } from "../restore-reasons.ts";
import { prunePlanHash } from "./prune-approvals.ts";
import { b64urlDecode } from "../crypto/bytes.ts";
import { isValidRunId } from "../format/ulid.ts";
import { callerHeaders, gate, jsonError, jsonResponse, rateLimited, recordAudit } from "./router-core.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";
import { callerCan } from "./identity.ts";

// RETENTION_PRUNE_MAX_RUNS bounds how many runs one candidate/apply call can carry, mirroring the
// ATTEST_VERIFY_BATCH_MAX cap on the sibling attend route: a single request must not be able to fan out an
// unbounded number of destination reads + open/verify passes.
//
// THE BOUND IS A CORRECTNESS LIMIT, NOT A USABILITY ONE, on the posture this route exists for.
//
//  1. THERE IS NO SECOND CALL. The candidate route takes downpipeId and nothing else: it derives
//     candidateIds from partitionRuns over the whole RUNLOG, so the count is this downpipe's ACTIVE run
//     count and no parameter narrows it. And on the apply side the two conditions are MUTUALLY
//     UNSATISFIABLE above the cap: `batch.length > RETENTION_PRUNE_MAX_RUNS` refuses a batch that covers
//     every candidate, and precheckCandidateCoverage (deliberately) refuses any batch that
//     does not; every batch size above the cap refuses.
//  2. THE CRON PATH IS EXACTLY THE PATH THIS POSTURE HAS LOST. retention-pass.ts returns at its own
//     `if (!env.OPERATIONAL_PRIVATE)` guard and logs that the downpipes with retention "await an OFFLINE
//     prune". The offline prune is THIS route. So on a break-glass-only estate the cron cannot prune, this
//     route is the only prune, and nothing else moves a run out of `status: "active"` -- the count rises
//     with every run and never falls. Past the cap it is a correctness limit, not a usability one.
//
// THE BOUND STAYS. The fan-out reason for it is sound, and validateConfig permits keepRuns up to
// RETENTION_MAX_KEEP_RUNS (10000), so raising this to match would defeat its own purpose. What changes is
// that the refusal now says which population it counted and names the remedy that actually lowers it:
// POST /keys/add-operational, the console's "add operational key" card, which restores the scheduled pass
// that has no such bound. That remedy is another control in this product and it was named nowhere.
export const RETENTION_PRUNE_MAX_RUNS = 200;

// pruneScopeRefusal is the SINGLE sentence for "this downpipe has more active runs than one call of this
// route can carry", shared by the candidate route and the apply route's batch check so the two can never
// drift, and exported so a validator drives the REAL decision rather than a copy of it. It names the
// count, the bound, the population the count is over, and the step that lowers it.
// `what` names the population the count is over, because the two call sites count different things: the
// candidate route counts the downpipe's ACTIVE RUNS (which no parameter narrows) and the apply route
// counts the RUNS IN THE SUBMITTED BATCH. Saying "active runs" on the apply path would be a false claim
// about a number the caller chose, so the label travels with the number rather than being assumed.
export function pruneScopeRefusal(count: number, what: "active runs" | "runs in this batch"): string {
  return (
    `${count} ${what}, and one offline prune call carries at most ${RETENTION_PRUNE_MAX_RUNS}. ` +
    `Every active run must be opened in the same call (a batch that does not cover them all is refused outright), so splitting this across requests cannot work. ` +
    `Add an operational key (Keys, "add operational key") so the scheduled retention pass, which has no such bound, prunes this downpipe instead`
  );
}

// pruneBatchSatisfiable answers the arithmetic the old sentence assumed: is there ANY batch size that both
// fits the per-request cap AND covers every candidate run? It is exported so the impossibility above the
// cap is measured rather than argued.
export function pruneBatchSatisfiable(activeRuns: number, batchSize: number): boolean {
  if (batchSize > RETENTION_PRUNE_MAX_RUNS) return false; // "batch too large"
  return batchSize >= activeRuns; // anything less leaves a candidate unopened -> "incomplete-batch"
}

// reqSignerPrivate mirrors retention-pass.ts's requireConfig: a clear, value-free reason when SIGNER_PRIVATE
// is unset. SIGNER_PRIVATE (the ML-DSA re-signing key) is NOT one of the two secrets a break-glass-only
// switch removes (attach.ts removeOperationalSecrets touches only OPERATIONAL_PUBLIC/OPERATIONAL_PRIVATE),
// so it is present on a break-glass-only estate exactly as it is on an operational one; this route's only
// missing ingredient in that posture is the per-run masters the browser supplies.
function reqSignerPrivate(v: string | undefined): string {
  if (!v) throw new Error("missing required configuration: SIGNER_PRIVATE");
  return v;
}

// PruneCapsule is one candidate run's non-secret master-capsule wraps + key commitment, or (in the
// candidate route's failures[]) an honest per-run read failure.
interface PruneCapsule {
  runId: string;
  masterCapsule: RunCapsule["masterCapsule"];
  keyCommitment: string;
  recordCount: number;
}

// loadRetentionTarget resolves the downpipe, its stored retention policy, its primary destination's RUNLOG
// and the M7 replica-coverage gate for it -- the same four inputs runOneRetentionPrune reads for one
// downpipe, re-derived FRESH on every call (never taken from the client) so a candidate read and a later
// apply cannot be driven by a stale or forged split. Returns a Response to propagate verbatim on any of the
// honest refusal paths (not found, no retention policy, destination unresolvable/unreadable).
async function loadRetentionTarget(
  ctx: RouterCtx,
  downpipeId: string,
): Promise<
  | Response
  | {
      state: DownpipeState;
      entries: RunlogEntry[];
      store: ObjectStore;
      dest: Awaited<ReturnType<typeof buildDestination>>;
      destKey: string;
      coverage: ReturnType<typeof replicaCoverageFor>;
      replUnreadable: boolean;
    }
> {
  const { env, scheduler } = ctx;
  const dpsResp = await scheduler.fetch(doURL("/downpipes"), { method: "GET" });
  const states = (await dpsResp.json()) as DownpipeState[];
  const state = states.find((s) => s.config.id === downpipeId);
  if (!state) return jsonError("downpipe not found", 404);
  if (state.config.retention === undefined) return jsonError("this downpipe has no retention policy configured", 400);

  const destKey = primaryDestinationId(state.config) ?? "";
  let dest: Awaited<ReturnType<typeof buildDestination>>;
  try {
    const destCfg = await fetchDestConfig(scheduler, destKey || undefined, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
    if (destKey && !destCfg) return jsonError(`destination ${destKey} is not configured`, 400);
    dest = await buildDestination(env, undefined, destCfg ?? null);
  } catch (e) {
    return jsonError(`destination could not be resolved: ${(e as Error).message}`, 400);
  }
  const store: ObjectStore = {
    get: async (k: string) => {
      const r = await dest.get(k);
      if (!r) throw new Error(`object ${k} is missing`);
      return r.body;
    },
  };
  let entries: RunlogEntry[];
  try {
    const runlog = await dest.get("_RECOVERY/RUNLOG");
    if (!runlog) return jsonError("nothing has been sealed to this downpipe's destination yet", 400);
    entries = parseRunlog(runlog.body);
  } catch (e) {
    return jsonError(`the destination's RUNLOG could not be read: ${(e as Error).message}`, 400);
  }

  // M7 replica coverage, read fresh (best-effort/conservative on a hiccup, exactly as the cron reads it):
  // an over-cap run still owed to a lagging/down replica is retained regardless of what this call supplies.
  const repl = await loadReplicationState(scheduler);
  const coverage = replicaCoverageFor(state.config, (repl.byDownpipe as Record<string, Record<string, DestReplState>>)[downpipeId] ?? {});

  // replUnreadable is carried so the attended pass record (B61) can say honestly, exactly as the cron
  // record does, that the coverage gate ran on NO proof rather than on a proven-empty state.
  return { state, entries, store, dest, destKey, coverage, replUnreadable: repl.unreadable };
}

// buildBatchSegEnumerator builds a MEMOIZING SegEnumerator over ONLY the browser-supplied {runId -> master}
// batch, verified under the operator-pinned verifier via openRunWithMaster -- the identical open+verify path
// attended verification and the break-glass restore panel already use for a browser-recovered master. A
// runId with no supplied master, or a master that fails the signed key-commitment check, THROWS (and the
// failure is cached, so a repeated call for the same runId fails identically without re-attempting the
// open). Memoised because this route now opens every candidate run TWICE by construction: once in
// precheckCandidateCoverage (fix 2, below) and once inside planPrune's own internal enumeration -- the cache
// means the real cryptographic open happens only once per runId either way. Every opened run is disposed
// immediately after its segment list is read, so no recovered master or key state outlives this one call.
function buildBatchSegEnumerator(store: ObjectStore, byRunId: Map<string, Uint8Array>, verifier: ReturnType<typeof verifierFrom>): SegEnumerator {
  const cache = new Map<string, string[] | Error>();
  return async (runId: string): Promise<string[]> => {
    const cached = cache.get(runId);
    if (cached !== undefined) {
      if (cached instanceof Error) throw cached;
      return cached;
    }
    try {
      const master = byRunId.get(runId);
      if (!master) throw new Error(`no master supplied for run ${runId}`);
      const run = await openRunWithMaster(store, runId, master, verifier, { verifyFreshness: true, allowStale: true });
      let segs: string[];
      try {
        segs = [];
        for (const rec of run.records) for (const seg of rec.segments) segs.push(seg.object);
      } finally {
        run.dispose();
      }
      cache.set(runId, segs);
      return segs;
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      cache.set(runId, err);
      throw err;
    }
  };
}

// precheckCandidateCoverage opens EVERY candidate run (retained and superseded alike) before
// planPrune is ever called, and returns the ids of any that failed -- whether the master was omitted or
// simply wrong. A non-empty result means the batch is INCOMPLETE and the whole call must refuse before any
// plan is computed: a superseded run planPrune's own downpipe-wide view would otherwise silently exclude
// (and so never protect a segment it shares with a sibling superseded run that DID open) can no longer
// reach planPrune at all.
async function precheckCandidateCoverage(candidateIds: readonly string[], enumerateSegs: SegEnumerator): Promise<string[]> {
  const missing: string[] = [];
  for (const runId of candidateIds) {
    try {
      await enumerateSegs(runId);
    } catch {
      missing.push(runId);
    }
  }
  return missing;
}

// buildRunTreeLister mirrors prunePlannerInputs' listRunTree (retention-pass.ts): the run/<runId>/ tree
// listing for a destination, identical between the held-identity and the browser-master enumerators (it
// reads no key at all).
function buildRunTreeLister(dest: Awaited<ReturnType<typeof buildDestination>>): RunTreeLister {
  return (runId: string) => dest.list(runTreePrefix(runId));
}

// planSummary is the redaction-safe shape every apply-family response shares: counts only, plus the closed
// ABSTAIN evidence when the plan deferred (the DEFENSIVE backstop path -- see the apply handler's comment on
// why this should be unreachable once precheckCandidateCoverage has run).
function planSummary(plan: PrunePlan): Record<string, unknown> {
  return {
    retainedRuns: plan.retainedRunIds.length,
    supersededRuns: plan.supersededRunIds.length,
    runTreeObjects: plan.runTreeObjects.length,
    orphanSegs: plan.orphanSegs.length,
    ...(plan.deferredClass !== undefined ? { deferredClass: plan.deferredClass, blockingRunId: plan.blockingRunId } : {}),
  };
}

// postAttendedPassRecord posts the SAME sanitised pass-record shape the cron posts (cron/
// retention-pass.ts recordRetentionPass): without it, an attended prune recorded fault observations only
// and never reached the retention telemetry a cron pass feeds. The record is marked `attended` and scoped to the ONE downpipe this call actually pruned
// (downpipesWithRetention: 1 counts this call's own scope, never a claim about the fleet); the DO folds
// it into the per-destination sidecar and deliberately keeps the latest CRON pass slot untouched.
// Best-effort and SILENT on failure, the same posture as postPruneObservations: a recording failure must
// never fail the pass.
async function postAttendedPassRecord(scheduler: RouterCtx["scheduler"], at: number, target: { destKey: string; replUnreadable: boolean }, row: RetentionDownpipeOutcome): Promise<void> {
  const rec: RetentionPassRecord = {
    at,
    attended: true,
    downpipesWithRetention: 1,
    downpipesPaused: 0,
    replicationUnreadable: target.replUnreadable,
    auditWriteFailures: 0,
    destinations: [{ destKey: target.destKey, downpipeCount: 1 }],
    downpipes: [row],
  };
  try {
    await scheduler.fetch(doURL("/retention-record"), {
      method: "POST",
      body: JSON.stringify(sanitiseRetentionPassRecord(rec)),
      headers: { "content-type": "application/json" },
    });
  } catch {
    // Deliberately silent: the record is diagnostics, never a reason to fail an attended prune.
  }
}

// gatePruneApprovalDo / reservePruneApprovalDo / releasePruneApprovalDo / consumePruneApprovalDo are thin
// scheduler.fetch wrappers over the dual-control DO routes (prune-approvals.ts / scheduler-do-prune-
// approval.ts), mirroring the restore apply route's own gate/reserve/release/consume calls verbatim in shape.
async function gatePruneApprovalDo(scheduler: RouterCtx["scheduler"], planHash: string): Promise<{ usable: boolean }> {
  const r = await scheduler.fetch(doURL("/prune-approval/gate"), { method: "POST", body: JSON.stringify({ planHash }), headers: { "content-type": "application/json" } });
  return (await r.json()) as { usable: boolean };
}
async function reservePruneApprovalDo(scheduler: RouterCtx["scheduler"], planHash: string): Promise<{ reserved: boolean }> {
  const r = await scheduler.fetch(doURL("/prune-approval/reserve"), { method: "POST", body: JSON.stringify({ planHash }), headers: { "content-type": "application/json" } });
  return (await r.json()) as { reserved: boolean };
}
async function releasePruneApprovalDo(scheduler: RouterCtx["scheduler"], planHash: string): Promise<void> {
  await scheduler.fetch(doURL("/prune-approval/release"), { method: "POST", body: JSON.stringify({ planHash }), headers: { "content-type": "application/json" } });
}
async function consumePruneApprovalDo(scheduler: RouterCtx["scheduler"], planHash: string): Promise<void> {
  await scheduler.fetch(doURL("/prune-approval/consume"), { method: "POST", body: JSON.stringify({ planHash }), headers: { "content-type": "application/json" } });
}

// handleRetentionPrune dispatches the route group. Returns the route's Response, or null when no case here
// matched (the hub falls to the next spoke).
export async function handleRetentionPrune(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, scheduler, caller, sub, sourceIp } = ctx;
  switch (`${req.method} ${sub}`) {
    // ---- serve the candidate runs' non-secret master capsules for a downpipe's CURRENT retained/superseded
    // split, so the browser can recover each one's master locally before a request/apply is attempted ------
    case "POST /retention-prune/candidate": {
      const denied = gate(caller, "restore.verify");
      if (denied) return denied;
      const body = (await req.json().catch(() => ({}))) as { downpipeId?: unknown };
      const downpipeId = typeof body.downpipeId === "string" ? body.downpipeId : "";
      if (downpipeId === "") return jsonError("downpipeId required", 400);
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const target = await loadRetentionTarget(ctx, downpipeId);
      if (target instanceof Response) return target;
      const { state, entries, store } = target;
      const retention = state.config.retention!;
      const split = partitionRuns(entries, downpipeId, retention, new Date(), target.coverage);
      const candidateIds = [...split.retainedRunIds, ...split.supersededRunIds];
      if (candidateIds.length > RETENTION_PRUNE_MAX_RUNS) {
        return jsonError(pruneScopeRefusal(candidateIds.length, "active runs"), 400);
      }
      const verifier = verifierFrom(await loadSigner(reqSignerPrivate(env.SIGNER_PRIVATE)));
      const capsules: PruneCapsule[] = [];
      const failures: Array<{ runId: string; reason: string }> = [];
      for (const runId of candidateIds) {
        try {
          const capsule = await readRunCapsule(store, runId, verifier);
          capsules.push({ runId, masterCapsule: capsule.masterCapsule, keyCommitment: capsule.keyCommitment, recordCount: capsule.declaredRecordCount });
        } catch (e) {
          failures.push({ runId, reason: classifyRestoreFailure(e) });
        }
      }
      return jsonResponse({
        downpipeId,
        policy: { ...(retention.keepRuns !== undefined ? { keepRuns: retention.keepRuns } : {}), ...(retention.keepDays !== undefined ? { keepDays: retention.keepDays } : {}), enforce: retention.enforce === true },
        retainedRunIds: split.retainedRunIds,
        supersededRunIds: split.supersededRunIds,
        capsules,
        ...(failures.length > 0 ? { failures } : {}),
      });
    }

    // ---- dual control: request -> approve (maker != checker) -> reject, mirroring
    // restore.request/restore.approve/restore.reject over a KEYLESS planHash (partitionRuns needs no key,
    // so a request can be raised and approved without anyone recovering a master) --------------------------
    case "POST /retention-prune/request": {
      const denied = gate(caller, "restore.request");
      if (denied) return denied;
      const body = (await req.json().catch(() => ({}))) as { downpipeId?: unknown; reason?: unknown };
      const downpipeId = typeof body.downpipeId === "string" ? body.downpipeId : "";
      if (downpipeId === "") return jsonError("downpipeId required", 400);
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const target = await loadRetentionTarget(ctx, downpipeId);
      if (target instanceof Response) return target;
      const { state, entries, coverage } = target;
      const retention = state.config.retention!;
      const split = partitionRuns(entries, downpipeId, retention, new Date(), coverage);
      const planHash = await prunePlanHash({ downpipeId, retainedRunIds: split.retainedRunIds, supersededRunIds: split.supersededRunIds, ...(retention.keepRuns !== undefined ? { keepRuns: retention.keepRuns } : {}), ...(retention.keepDays !== undefined ? { keepDays: retention.keepDays } : {}) });
      return scheduler.fetch(doURL("/prune-approval/request"), {
        method: "POST",
        body: JSON.stringify({ planHash, downpipeId, retainedRuns: split.retainedRunIds.length, supersededRuns: split.supersededRunIds.length, reason: typeof body.reason === "string" ? body.reason : "" }),
        headers: callerHeaders(caller),
      });
    }
    case "POST /retention-prune/approve": {
      const denied = gate(caller, "restore.approve");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/prune-approval/approve"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "POST /retention-prune/reject": {
      const denied = gate(caller, "restore.approve");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/prune-approval/reject"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "GET /retention-prune/approvals": {
      const isApprover = callerCan(caller, "restore.approve");
      return scheduler.fetch(doURL(`/prune-approval/list${isApprover ? "?approver=1" : ""}`), { method: "GET", headers: callerHeaders(caller) });
    }

    // ---- apply: plan (and, only when this downpipe's OWN stored enforce is true, previewOnly is not set,
    // AND a usable dual-control approval for this exact plan exists) commit the prune from a batch of
    // browser-recovered per-run masters --------------------------------------------------------------------
    case "POST /retention-prune/apply": {
      const denied = gate(caller, "restore.apply");
      if (denied) {
        await recordAudit(scheduler, caller, sourceIp, "retention-prune", "denied", { kind: "downpipe", id: "" });
        return denied;
      }
      const body = (await req.json().catch(() => ({}))) as { downpipeId?: unknown; batch?: unknown; previewOnly?: unknown };
      const downpipeId = typeof body.downpipeId === "string" ? body.downpipeId : "";
      if (downpipeId === "") return jsonError("downpipeId required", 400);
      const batch = Array.isArray(body.batch) ? body.batch : [];
      // The cheap guard, kept BEFORE the destination read so an obviously-oversized batch costs nothing.
      // It now says why a smaller batch does not rescue it: precheckCandidateCoverage below refuses any
      // batch that does not open EVERY candidate run, so the two conditions have no overlap above the cap
      // and the operator would otherwise re-split a batch forever. Same remedy as the candidate route's.
      if (batch.length > RETENTION_PRUNE_MAX_RUNS) return jsonError(pruneScopeRefusal(batch.length, "runs in this batch"), 400);
      const previewOnly = body.previewOnly === true;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;

      const target = await loadRetentionTarget(ctx, downpipeId);
      if (target instanceof Response) return target;
      const { state, entries, store, dest, destKey, coverage } = target;
      const retention = state.config.retention!;

      // Decode the batch's masters (fail 400 on a malformed value, never a 500), keyed by runId. A duplicate
      // runId in the batch keeps its LAST entry; a non-ULID runId is dropped rather than trusted verbatim.
      const byRunId = new Map<string, Uint8Array>();
      for (const item of batch) {
        const { runId, masterB64 } = (item ?? {}) as { runId?: unknown; masterB64?: unknown };
        if (typeof runId !== "string" || !isValidRunId(runId) || typeof masterB64 !== "string") continue;
        let bytes: Uint8Array;
        try {
          bytes = b64urlDecode(masterB64);
        } catch {
          return jsonError(`the master supplied for run ${runId} is not valid base64url`, 400);
        }
        if (bytes.length !== 32) return jsonError(`the master supplied for run ${runId} must decode to 32 bytes`, 400);
        byRunId.set(runId, bytes);
      }

      // ONE shared instant for the split below AND the planPrune call further down, so the two agree
      // byte-for-byte on which runs are candidates (partitionRuns is pure given the same inputs).
      const now = new Date();
      const policy = { ...(retention.keepRuns !== undefined ? { keepRuns: retention.keepRuns } : {}), ...(retention.keepDays !== undefined ? { keepDays: retention.keepDays } : {}) };
      const split = partitionRuns(entries, downpipeId, retention, now, coverage);
      const candidateIds = [...split.retainedRunIds, ...split.supersededRunIds];

      const verifier = verifierFrom(await loadSigner(reqSignerPrivate(env.SIGNER_PRIVATE)));
      const enumerateSegs = buildBatchSegEnumerator(store, byRunId, verifier);
      const listRunTree = buildRunTreeLister(dest);

      // EVERY candidate run (retained and superseded alike) must open before planPrune is ever
      // called. A partial batch is refused outright, naming every run that failed to open -- see the file
      // header and precheckCandidateCoverage's own comment for the shared-segment exploit this closes.
      const missingRunIds = await precheckCandidateCoverage(candidateIds, enumerateSegs);
      if (missingRunIds.length > 0) {
        for (const m of byRunId.values()) m.fill(0);
        return jsonResponse({ downpipeId, mode: "incomplete-batch", missingRunIds, retainedRuns: split.retainedRunIds.length, supersededRuns: split.supersededRunIds.length });
      }

      // This call intends a REAL delete iff the downpipe's OWN stored enforce is true and the
      // caller did not ask for a preview. Only THAT path needs dual control; preview can never delete.
      const wantsRealApply = retention.enforce === true && !previewOnly;
      let planHash: string | undefined;
      if (wantsRealApply) {
        planHash = await prunePlanHash({ downpipeId, retainedRunIds: split.retainedRunIds, supersededRunIds: split.supersededRunIds, ...policy });
        const gateResult = await gatePruneApprovalDo(scheduler, planHash);
        if (!gateResult.usable) {
          for (const m of byRunId.values()) m.fill(0);
          await recordAudit(scheduler, caller, sourceIp, "retention-prune", "denied", { kind: "downpipe", id: downpipeId, name: state.config.name });
          return new Response(JSON.stringify({ error: "prune not approved", downpipeId, planHash, mode: "not-approved", retainedRuns: split.retainedRunIds.length, supersededRuns: split.supersededRunIds.length }), { status: 403, headers: { "content-type": "application/json" } });
        }
        // The ATOMIC gate-to-work reservation (HI-03/ASVS 2.1.6 parity): flips approved -> applying so a
        // concurrent second apply for the SAME plan hash cannot also reserve it while THIS call plans.
        const reserveResult = await reservePruneApprovalDo(scheduler, planHash);
        if (!reserveResult.reserved) {
          for (const m of byRunId.values()) m.fill(0);
          await recordAudit(scheduler, caller, sourceIp, "retention-prune", "denied", { kind: "downpipe", id: downpipeId, name: state.config.name });
          return new Response(JSON.stringify({ error: "prune not approved", downpipeId, planHash, mode: "not-approved", retainedRuns: split.retainedRunIds.length, supersededRuns: split.supersededRunIds.length }), { status: 403, headers: { "content-type": "application/json" } });
        }
      }

      // THE RESERVATION LEAK: from the moment reserve() above succeeds, this call HOLDS a
      // dual-control reservation that MUST be settled exactly once, on EVERY exit path, including a throw.
      // settleAction is the single source of truth for what the outer finally does; it defaults to the SAFE
      // choice (release, so a genuinely-approved plan is never stuck) and is flipped to "consume" at the
      // ONE point below where the apply genuinely, fully succeeded. This replaces the earlier per-branch
      // release() calls (abstain / no-op / PruneApplyError / other-throw), which left planPrune's OWN call
      // (listRunTree -> dest.list(), a real, reachable R2 failure mode) outside any release-guarded region:
      // a throw there propagated straight out with the reservation stuck "applying" until the 30-minute
      // PRUNE_APPLY_LEASE_MS lease self-healed it, refusing an immediate honest retry of an already-approved
      // plan. Closed by moving the WHOLE reserve-to-consume window (planPrune included) inside the guarded
      // region below.
      let settleAction: "consume" | "release" = "release";
      try {
        let plan: PrunePlan;
        try {
          plan = await planPrune(entries, downpipeId, policy, now, enumerateSegs, listRunTree, undefined, coverage);
        } finally {
          // Zeroise every supplied master immediately after the one planPrune call that may have used it,
          // regardless of outcome. Nothing below this line reads byRunId again.
          for (const m of byRunId.values()) m.fill(0);
        }
        await postPruneObservations(scheduler, plan, now.getTime());
        // The counts each attended pass-record row below carries (B61), the same planned-or-committed
        // discipline runOneRetentionPrune's `planned` uses; destKey ties the row to this bucket.
        const plannedCounts = {
          destKey,
          supersededRuns: plan.supersededRunIds.length,
          runTreeObjects: plan.runTreeObjects.length,
          orphanSegs: plan.orphanSegs.length,
          retainedRuns: plan.retainedRunIds.length,
          ...(plan.volumeRegression !== undefined ? { volumeHeld: plan.volumeRegression.heldRunIds.length } : {}),
        };

        // DEFENSIVE BACKSTOP, expected unreachable: precheckCandidateCoverage above already proved every
        // candidate run opens under this exact batch, computed from the SAME entries/policy/now/coverage
        // planPrune re-derives internally, so plan.deferred should never fire here. If it somehow does
        // (e.g. a future planPrune change widens what it treats as a candidate), report the abstain
        // honestly rather than silently downgrading it; the outer finally releases.
        if (plan.deferred !== undefined) {
          // The record's own deferral vocabulary (RETENTION_DEFERRAL_CLASSES) is narrower than
          // PruneDeferClass: any member it does not hold coarsens to "other", never a dropped row.
          await postAttendedPassRecord(scheduler, now.getTime(), target, {
            id: downpipeId,
            outcome: "deferred",
            deferralClass: plan.deferredClass === "retained-run-unreadable" ? "retained-run-unreadable" : "other",
            ...plannedCounts,
          });
          return jsonResponse({ downpipeId, mode: "abstained", ...planSummary(plan) });
        }
        // No stored enforce, or the caller explicitly asked for a preview: report the plan, delete nothing.
        // This is the SAME dry-run posture the cron reports when enforce is not exactly true; not audited.
        // wantsRealApply is false on this path, so planHash was never set and the outer finally is a no-op.
        if (!wantsRealApply) {
          // A dry-run record rides ONLY when the downpipe's own stored enforce is off (the cron's exact
          // dry-run meaning). An explicit previewOnly rehearsal of an ENFORCED downpipe records nothing:
          // it is a read of the plan, not a pass outcome, and stamping "dry-run" on that fleet would
          // falsely say enforcement is off (B61).
          if (retention.enforce !== true) {
            await postAttendedPassRecord(scheduler, now.getTime(), target, { id: downpipeId, outcome: "dry-run", ...plannedCounts });
          }
          return jsonResponse({ downpipeId, mode: "preview", ...planSummary(plan) });
        }
        // Nothing in scope this pass (idempotent no-op, mirrors runOneRetentionPrune): not audited. The
        // outer finally releases (there is nothing to consume it on) rather than leave it dangling.
        if (plan.supersededRunIds.length === 0 && plan.runTreeObjects.length === 0 && plan.orphanSegs.length === 0) {
          await postAttendedPassRecord(scheduler, now.getTime(), target, { id: downpipeId, outcome: "no-op", ...plannedCounts });
          return jsonResponse({ downpipeId, mode: "no-op", ...planSummary(plan) });
        }

        // ENFORCED apply: this downpipe's OWN stored retention.enforce is true, the plan is not deferred,
        // and a usable dual-control approval was just reserved above, so this call fulfils the authority
        // the estate's owner already granted AND a second authorised identity already reviewed. Locked
        // against the SAME destination-keyed RUNLOG lock the cron uses, so a concurrent seal or a
        // concurrent cron tick cannot race this re-sign.
        const signer = await loadSigner(reqSignerPrivate(env.SIGNER_PRIVATE));
        try {
          let result: Awaited<ReturnType<typeof applyPrune>>;
          try {
            result = await applyPrune(dest, signer, plan, runlogLockVia(scheduler, destKey));
          } catch (e) {
            if (e instanceof PruneApplyError) {
              await postPruneObservations(scheduler, plan, now.getTime(), e);
              // A half-applied prune leaves the approval usable for a retry (mirroring restore's own
              // failure-path release): the retry re-plans and finishes the remainder, needing no fresh
              // round of dual control for the SAME downpipe's SAME already-approved plan. settleAction
              // stays "release" (the outer finally settles it).
              // The record row mirrors the cron's own treatment of a PruneApplyError (a classed "error"
              // outcome), but carries what the apply COMMITTED before dying plus the wormBlocked posture,
              // which this route knows and the cron's catch site does not (B61).
              await postAttendedPassRecord(scheduler, now.getTime(), target, {
                id: downpipeId,
                destKey,
                outcome: "error",
                errorClass: classifyPruneError(e),
                ...(e.wormBlocked ? { wormBlocked: true } : {}),
                supersededRuns: e.progress.superseded,
                runTreeObjects: e.progress.runTreeDeleted,
                orphanSegs: e.progress.orphansDeleted,
                retainedRuns: plan.retainedRunIds.length,
              });
              await recordAudit(scheduler, caller, sourceIp, "retention-prune", "failed", { kind: "downpipe", id: downpipeId, name: state.config.name });
              return jsonResponse({
                downpipeId,
                mode: "partial",
                supersededRuns: e.progress.superseded,
                runTreeObjects: e.progress.runTreeDeleted,
                orphanSegs: e.progress.orphansDeleted,
                retainedRuns: plan.retainedRunIds.length,
                wormBlocked: e.wormBlocked,
              });
            }
            // Any OTHER throw (e.g. applyPrune's own RUNLOG lock/signing step faulting outright): propagate
            // unchanged, exactly as before; settleAction stays "release", so the outer finally still frees
            // the reservation for a retry rather than leaving it stuck for 30 minutes.
            throw e;
          }
          // THE ONE POINT settleAction ever becomes "consume": applyPrune returned without throwing, i.e.
          // the enforced delete genuinely, fully committed.
          settleAction = "consume";
          // The APPLIED record carries what was COMMITTED (result), not what was planned, exactly as the
          // cron's applied row does (B61).
          await postAttendedPassRecord(scheduler, now.getTime(), target, {
            id: downpipeId,
            destKey,
            outcome: "applied",
            supersededRuns: result.superseded,
            runTreeObjects: result.runTreeDeleted,
            orphanSegs: result.orphansDeleted,
            retainedRuns: plan.retainedRunIds.length,
            ...(plan.volumeRegression !== undefined ? { volumeHeld: plan.volumeRegression.heldRunIds.length } : {}),
          });
          await recordAudit(scheduler, caller, sourceIp, "retention-prune", "success", { kind: "downpipe", id: downpipeId, name: state.config.name });
          return jsonResponse({
            downpipeId,
            mode: "applied",
            supersededRuns: result.superseded,
            runTreeObjects: result.runTreeDeleted,
            orphanSegs: result.orphansDeleted,
            retainedRuns: plan.retainedRunIds.length,
          });
        } finally {
          signer.mldsaSecret.fill(0);
        }
      } finally {
        // THE FIX: this fires on EVERY exit from the try above -- a normal return (abstained/preview/no-op/
        // partial/applied) OR an uncaught throw from planPrune, postPruneObservations, loadSigner or
        // applyPrune's own non-PruneApplyError faults alike. wantsRealApply false means planHash was never
        // set, so this is a no-op on the preview path (nothing was ever reserved to settle).
        if (wantsRealApply && planHash) {
          if (settleAction === "consume") await consumePruneApprovalDo(scheduler, planHash);
          else await releasePruneApprovalDo(scheduler, planHash);
        }
      }
    }

    default:
      return null;
  }
}
