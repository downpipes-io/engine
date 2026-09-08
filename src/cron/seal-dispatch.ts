// Seal dispatch + destination failover for the cron driver (cron/drive.ts) and the manual run-now
// handler (the Worker entry's sealNow runtime). runDownpipe allocates a run via the scheduler DO and
// seals it; selectSealDestination chooses the destination with 3-2-1 FAILOVER (probing each with a real
// write); destinationReachable is that write probe; resolveDestForState resolves a single downpipe's
// pinned-or-default destination; sealRun drives the sliced seal. Everything here was MOVED VERBATIM out
// of src/index.ts to keep that entry module a thin handler; the behaviour is unchanged. index.ts
// re-exports destinationReachable + selectSealDestination (the behaviour-neutral test seams) so the
// validators that import them from ../src/index.ts keep working. This module imports nothing from
// index.ts, so there is no cycle.

import { loadConfigWrapKey } from "../admin/config-secret.ts";
import { classifySealDestError, SealDispatchError } from "../admin/diag-records.ts";
import { doURL, schedulerStub } from "../admin/router.ts";
import { buildDestination, fetchDestConfig, type RuntimeDestConfig } from "../dest/factory.ts";
import type { Env } from "../env.d.ts";
import { allDestinationIds, type DownpipeState, primaryDestinationId } from "../sched/scheduler-do.ts";
import type { SliceBudget } from "../seal/budget.ts";
import { sealRunSliced } from "../seal/runstate.ts";
import { causeDigest } from "../seal/slice.ts";
import { noteDanglingDestinationRef, noteDestProbeFault } from "./cron-fault-ledger.ts";

// runDownpipe allocates a run, assembles the configured source and the destination from
// env, seals the archive and records completion. The crypto, writer, sources, dest and
// key loading are all in place; this is the binding-to-seal wiring.
// RunDispatchOutcome is what runDownpipe reports to the seal loop so the per-tick outcome ring can count
// what actually happened this tick (SCHED coalesced-runs-invisible + the dispatched-vs-due signal):
// "coalesced" = a prior run was still in flight, so this trigger was skipped; "dispatched" = a run was
// allocated (whether it sealed or recorded an all-destinations-down failure). A throw is caught by the loop
// and counted as a seal error separately.
export type RunDispatchOutcome = "coalesced" | "dispatched";

export async function runDownpipe(env: Env, state: DownpipeState, budget?: SliceBudget, probeCache?: Map<string, boolean>): Promise<RunDispatchOutcome> {
  const scheduler = schedulerStub(env);
  // Resolve THIS downpipe's seal destination BEFORE allocating a run, so a resolution fault leaves no
  // in-flight row to clean up (matching the cron loop's pre-trigger failure handling). Fan-out FAILOVER
  // picks the first REACHABLE destination here, so a down primary falls over to a healthy replica. The
  // failover probe is metered against the shared tick budget and memoised per-tick (ENG-SCALE-02).
  //
  // G163 (pre-run-seal-failures-unattributed): BOTH pre-run steps below can THROW before a run index exists,
  // so the seal loop's fallback /complete is a runId-"" history NO-OP: run history shows a silent GAP and the
  // pack shows only an anonymous scheduler.ticks.sealErrors integer ("one downpipe just stopped producing
  // runs"). Each throw is TAGGED here, at the site that knows what it means, with a CLOSED SealErrorClass; the
  // loop's catch records that class against this downpipe. The tag carries no text: the original error is kept
  // only as `cause` for the Workers Logs line, and the class is the only thing that is ever recorded.
  let sel: Awaited<ReturnType<typeof selectSealDestination>>;
  try {
    sel = await selectSealDestination(env, scheduler, state, { ...(budget ? { budget } : {}), ...(probeCache ? { probeCache } : {}) });
  } catch (e) {
    // A pinned destination whose record was DELETED (dest-not-configured, the fail-loud refusal that stops a
    // downpipe silently writing to a different bucket and splitting its archive), a destination-config read
    // that faulted (dest-config-unreadable), or a malformed CONFIG_WRAP_KEY (wrap-key-invalid).
    throw new SealDispatchError(classifySealDestError(e), e);
  }
  budget?.spend(1); // the /trigger DO round-trip below counts against the platform cap
  let trig: { runId: string; index: number; prevRunId: string | null } | { skipped: string };
  try {
    trig = (await (await scheduler.fetch(doURL("/trigger"), { method: "POST", body: JSON.stringify({ id: state.config.id }) })).json()) as
      | { runId: string; index: number; prevRunId: string | null }
      | { skipped: string };
  } catch (e) {
    // The scheduler DO would not allocate a run at all: an ENGINE availability fault, not a destination fault
    // (the distinction that sends triage to the right side).
    throw new SealDispatchError("trigger-transport", e);
  }
  if ("skipped" in trig) return "coalesced"; // a prior run was still in flight
  if ("allDown" in sel) {
    // Every destination is unreachable: there is nowhere to write a copy. Record an HONEST failed run
    // (the operator sees the backup failed because all destinations were down) and free the lease so the
    // next tick retries, a transient outage clears itself; the down state is also visible per-destination.
    // DEST-1: carry the PROVEN-down set (every destination the failover probe found unwritable) so the DO
    // records a lastOk:false heartbeat for each and the map shows them down, not merely a failed run.
    // The 12-hex correlation digest of the SAME error string (single-sourced via causeDigest) rides on the
    // failed completion so the run-history row carries it byte-identical to the Logpush `[cause <hex>]`.
    const cause = await causeDigest("all destinations unreachable");
    await scheduler.fetch(doURL("/complete"), { method: "POST", body: JSON.stringify({ id: state.config.id, runId: "", index: trig.index, status: "failed", error: "all destinations unreachable", causeDigest: cause, downDestinationIds: sel.tried }) });
    return "dispatched"; // a run WAS allocated and recorded (as a failed run), so the tick did dispatch it
  }
  await sealRun(env, state, trig, budget, sel.destConfig, sel.destinationId);
  return "dispatched";
}

// resolveDestForState resolves the archive destination a downpipe writes to: its PINNED destinationId,
// else the default. A pinned id that no longer resolves THROWS (fail loud) rather than returning null
// and letting buildDestination fall back to the env destination, a pinned downpipe must never silently
// write to a different bucket (which would split its archive and break its RUNLOG chain).
export async function resolveDestForState(scheduler: DurableObjectStub, state: DownpipeState, wrapKey?: Uint8Array): Promise<RuntimeDestConfig | null> {
  const primary = primaryDestinationId(state.config);
  const cfg = await fetchDestConfig(scheduler, primary, wrapKey);
  if (primary && !cfg) {
    throw new Error(`destination ${primary} for downpipe ${state.config.id} is not configured`);
  }
  return cfg;
}

// destinationReachable probes whether a destination is reachable AND WRITABLE right now, the failover
// gate. It WRITES a tiny marker under _RECOVERY/ and deletes it, rather than just listing: a read probe
// passes on a list-capable-but-write-denied credential (or a bucket that has gone read-only) and the run
// would then fail the seal with no second failover. Probing with the SAME PUT the seal needs closes that
// gap, every genuine "down" cause (network fault, expired/denied credential, missing bucket, redirect;
// dest/s3.ts put() throws on every non-2xx) is caught here, at selection time, so the run fails over to a
// healthy destination instead. The marker key is FIXED and overwritten in place (not a per-run nonce):
// on an immutable / object-lock bucket the put succeeds but the delete is refused, so a nonce'd key would
// leave one undeletable marker PER run (unbounded); overwriting one key bounds the residue to a single
// object. Concurrent probes on a shared bucket race harmlessly, each needs only its OWN put to succeed
// (that is what proves writability), and the delete is best-effort. Never throws: down is a false, not an error.
//
// METERED (ENG-SCALE-02): the probe's put (and the best-effort delete) are real platform subrequests
// that, on a multi-dest fleet, were INVISIBLE to the tick budget and could blow the per-invocation
// subrequest cap before the budget noticed. The optional meter counts each attempted subrequest against
// the SAME shared tick budget the seal loop spends, so a fleet's failover probing is now accounted for
// (the caller pairs this with a per-tick probe cache so a shared destination is probed once per tick).
export async function destinationReachable(dest: Awaited<ReturnType<typeof buildDestination>>, meter?: SliceBudget, destinationId?: string): Promise<boolean> {
  const key = "_RECOVERY/.reachable";
  try {
    meter?.spend(1); // the probe put is a platform subrequest on the shared tick budget
    await dest.put(key, new Uint8Array([1]));
  } catch (e) {
    // G133: this catch used to DROP the S3 error before any sink, so "backups failing: all destinations
    // unreachable" could not separate an expired STS credential (rotate it) from a deleted bucket (recreate
    // it) from a DNS fault (wait) -- the three tickets have three completely different remedies. Classify the
    // fault HERE, at the only site that ever holds it, into the closed DEST_PROBE_REASONS vocabulary the
    // destination record already speaks. The message, the endpoint, the bucket and the key stay in the driver.
    if (destinationId !== undefined) noteDestProbeFault(destinationId, e);
    return false; // not writable / unreachable: fail over to the next destination
  }
  try {
    meter?.spend(1); // the best-effort cleanup delete is also a subrequest
    await dest.delete(key);
  } catch {
    // best-effort cleanup only; an immutable bucket refuses the delete and the single 1-byte marker is harmless
  }
  return true;
}

// selectSealDestination chooses the destination a run SEALS to, with 3-2-1 FAILOVER. A downpipe that
// fans out to >=2 destinations seals to the FIRST REACHABLE one (the configured primary, then each
// replica in destinationIds order), so one bucket being down no longer means total data loss while
// another is up, the run is captured to a healthy destination and the replicate pass then mirrors it
// to the rest (back-filling the recovered primary when it returns). It returns the chosen config + its
// destinationId (recorded as the run's origin) or { allDown:true } when EVERY destination is unreachable
// (the caller records an honest failed run). A SINGLE-destination downpipe keeps the prior fail-loud
// resolveDestForState path verbatim, no probe, no failover, and a pinned-but-unconfigured id still
// THROWS rather than silently writing to the env fallback (which would split the archive).
export async function selectSealDestination(
  env: Env,
  scheduler: DurableObjectStub,
  state: DownpipeState,
  opts?: { budget?: SliceBudget; probeCache?: Map<string, boolean> },
): Promise<{ destConfig: RuntimeDestConfig | null; destinationId: string | undefined } | { allDown: true; tried: string[] }> {
  const ids = allDestinationIds(state.config);
  // At-rest credential decryption: the stored secret is an AES-256-GCM envelope when CONFIG_WRAP_KEY is
  // set, so fetchDestConfig must be given the wrap key to open it before buildDestination signs with it.
  // When the key is unset this is undefined and fetchDestConfig is a no-op decrypt (back-compat floor).
  const wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
  if (ids.length <= 1) {
    const destConfig = await resolveDestForState(scheduler, state, wrapKey);
    return { destConfig, destinationId: primaryDestinationId(state.config) };
  }
  const budget = opts?.budget;
  const probeCache = opts?.probeCache;
  const tried: string[] = [];
  for (const id of ids) {
    tried.push(id);
    // fetchDestConfig throws only on a scheduler-DO transport fault (in-account); a missing config
    // returns null and is SKIPPED like an unreachable destination (it cannot be written), never failing
    // the whole run when a sibling destination is healthy.
    const cfg = await fetchDestConfig(scheduler, id, wrapKey);
    if (!cfg) {
      // G133: a fan-out destinationId with NO config record. The run proceeds happily to its remaining
      // destinations and reports SUCCESS, so the customer durably holds FEWER copies than they configured --
      // silently, on a green run, for as long as the dangling reference survives. A count is all that is
      // needed to make it visible (the id itself already rides in the downpipe's own config).
      noteDanglingDestinationRef();
      continue;
    }
    // Reuse a probe result already taken THIS tick for this destination (ENG-SCALE-02): a fan-out
    // fleet where many downpipes share destinations probes each destination once per invocation, not
    // once per downpipe, so the failover probing no longer scales with the fleet size and stays inside
    // the tick budget. A cache MISS does the real metered probe and records its verdict; failover
    // correctness is intact (the probe is still REAL within the tick, and a fresh tick re-probes, so a
    // recovered destination is picked up on the very next */15, the cost/staleness trade-off).
    let reachable = probeCache?.get(id);
    if (reachable === undefined) {
      reachable = await destinationReachable(await buildDestination(env, undefined, cfg), budget, id);
      probeCache?.set(id, reachable);
    }
    if (reachable) {
      return { destConfig: cfg, destinationId: id };
    }
  }
  return { allDown: true, tried };
}

// sealRun seals the archive for an ALREADY-TRIGGERED run (the caller allocated the runId/index via the
// DO /trigger and holds the in-flight lease). Both the cron driver (runDownpipe) and the manual run-now
// handler reach the seal through here, so run-now genuinely writes bytes and resolves the in-flight
// history row instead of stranding the downpipe in flight (XC-B1/B2). The seal itself is the SLICED
// path (seal/runstate.ts): a run that fits the invocation budget completes inline exactly as before; a
// larger one checkpoints and continues on the per-downpipe seal DO's alarms (design F11), so a large
// namespace is no longer capped by one invocation's subrequest budget. /complete (ok with the counts,
// or failed with the coarse reason) is posted inside sealRunSliced on every path.
export async function sealRun(env: Env, state: DownpipeState, trig: { runId: string; index: number; prevRunId: string | null }, budget?: SliceBudget, destCfg?: RuntimeDestConfig | null, destinationId?: string): Promise<void> {
  await sealRunSliced(env, state, trig, { ...(budget !== undefined ? { budget } : {}), destOverride: destCfg ?? null, ...(destinationId !== undefined ? { destinationId } : {}) });
}
