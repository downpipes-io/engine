// Scheduler reconcile preamble + due-downpipe seal loop for the cron driver (cron/drive.ts).
// reconcileAndDue runs the /tick + /due preamble and returns the due set (null on a DO blip =
// skip this tick); runSealLoop dispatches the due set oldest-due-first under the shared
// per-invocation subrequest budget. Both moved VERBATIM out of cron/drive.ts to finish the
// *-pass.ts split of that orchestrator; the behaviour is unchanged.

import { type SealErrorClass, sealErrorClassOf } from "../admin/diag-records.ts";
import { recordDiagWrite } from "../admin/diag-writer.ts";
import { doURL, schedulerStub } from "../admin/router.ts";
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import type { DownpipeState } from "../sched/scheduler-do.ts";
import { type budgetFromEnv, FINALISE_RESERVE } from "../seal/budget.ts";
import { runDownpipe } from "./seal-dispatch.ts";

// recordSealError ATTRIBUTES one pre-run dispatch fault to the downpipe that hit it (G163). Before it, a
// throw that escaped runDownpipe left NOTHING per-downpipe: the /complete below is a runId-"" history no-op,
// so the pack showed a run-history GAP and one anonymous sealErrors integer, and "this downpipe silently
// stopped producing runs" could not be told from "its destination record was deleted" or "the DO was down".
//
// BEST-EFFORT and FIRE-AND-FORGET by contract: this runs inside the loop's own error path, so it must never
// throw (a fault while recording a fault would reject drive() and crash the whole cron invocation, stranding
// the remaining due downpipes). Only the CLOSED class and the customer's own downpipe id cross the wire --
// never the error message, which carries destination ids and store text.
async function recordSealError(env: Env, downpipeId: string, cls: SealErrorClass): Promise<void> {
  // G104: the LOSS of this record is itself evidence, and the `seal-error` droppedWrites kind was declared for
  // it and never wired: the write went out with a bare catch, so a DO that refused or was unreachable took the
  // downpipe's only cause with it and the pack showed a run-history GAP with nothing to explain it -- which is
  // exactly the state ("this downpipe silently stopped producing runs") this recorder exists to end.
  //
  // The old comment here reasoned that the DO is the sink, so a DO outage cannot record its own outage. That is
  // true of a DIRECT write and it is precisely what the dropped-write protocol solves: recordDiagWrite counts
  // the loss in an isolate-local tally and folds it into the aggregate on the next write that SUCCEEDS, so the
  // gap lands the moment the DO comes back -- which is when the pack is generated. Still fire-and-forget and
  // still never throwing (recordDiagWrite swallows both a transport throw and a non-2xx), so the loop's error
  // path is unchanged. Only the closed class and the customer's own downpipe id cross the wire.
  const scheduler = schedulerStub(env);
  await recordDiagWrite(scheduler, "seal-error", () =>
    scheduler.fetch(doURL("/seal-error"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: downpipeId, class: cls }),
    }),
  );
}

// DRIVE_PER_DOWNPIPE_RESERVE is the minimum shared-budget headroom the seal loop requires
// before it will START another due downpipe (ENG-SCALE-01). A crowded tick (many due
// downpipes) must STOP dispatching cleanly while budget remains, carrying the rest to the
// next tick, rather than push past the platform's per-invocation subrequest cap and be
// KILLED mid-loop, a cap death persists no progress and strands the rest of the tick's
// work. Each downpipe the loop starts spends, at minimum: the failover probe(s) on
// selectSealDestination, the /trigger round-trip, then its inline first slice (which itself
// yields via the same shared budget) and the /complete. This reserve is the floor below
// which there is no longer room to do useful work on one more downpipe AND let it finalise,
// so the loop breaks and the undispatched downpipes stay DUE (their nextRunAt is unchanged
// and they were never triggered, so the very next */15 tick, or the DO alarm, picks them
// up). It is deliberately a few multiples of the seal's FINALISE_RESERVE so a started
// downpipe is not immediately forced to yield with nothing done.
//
// DERIVED FROM FINALISE_RESERVE (rather than a second bare literal): a thin, fixed reserve is exactly wide
// enough for the failover probe(s) and the /trigger round-trip to eat before a non-resumable source
// (secrets, D1, cf-config; see seal/slice.ts crawlNonResumable) seals even its first record, so
// shouldYield() (remaining <= FINALISE_RESERVE) can trip immediately and the source throws
// "source too large for one slice" -- a false diagnosis for a source that is not large at all, just unlucky
// in tick order (a small downpipe sandwiched between several other due downpipes on a busy tick, versus an
// on-demand run with the full budget). Deriving this from FINALISE_RESERVE keeps the two constants from
// drifting apart.
// drifting apart the way the literal did.
export const DRIVE_PER_DOWNPIPE_RESERVE = FINALISE_RESERVE * 3;

// reconcileAndDue runs the scheduler reconciliation preamble (/tick then /due) and returns the due
// set, or null when the DO is momentarily unavailable (the thrown /tick or /due fetch). A null return
// is the caller's signal to skip this tick: without the guard the thrown promise rejects ctx.waitUntil
// and the whole cron invocation crashes; the next */15 tick would retry, but a crash is noisy and
// needless. Degrade to a skipped tick instead (the durable DO alarms remain the real per-downpipe
// timers anyway). Per-downpipe destinations: the destination is no longer resolved once per tick. Each
// pass that writes or reads an archive (seal, scheduled restore test, retention prune) resolves the
// relevant downpipe's OWN destination (its pinned one, else the default), so different downpipes can
// write to different buckets and a per-downpipe resolution fault fails only that downpipe, not the tick.
export async function reconcileAndDue(scheduler: ReturnType<typeof schedulerStub>): Promise<DownpipeState[] | null> {
  try {
    await scheduler.fetch(doURL("/tick"), { method: "POST" });
    const dueResp = await scheduler.fetch(doURL("/due"), { method: "GET" });
    const { due } = (await dueResp.json()) as { due: DownpipeState[] };
    return due;
  } catch (e) {
    log("error", `scheduler reconciliation unavailable, skipping this tick: ${(e as Error).message}`);
    return null;
  }
}

// runSealLoop dispatches the due downpipes oldest-due-first under the shared per-invocation budget. It
// processes the due set OLDEST-DUE-FIRST (fairness, ENG-SCALE-01) so a crowded tick that runs out of
// budget serves the most-overdue downpipes first and the same tail is not starved tick after tick, stops
// cleanly the moment there is no longer headroom to start one more and let it finalise (the undispatched
// downpipes stay DUE for the next tick), and guards each per-downpipe step so a fault degrades to "retry
// that downpipe next tick", never a crashed cron invocation.
export async function runSealLoop(env: Env, due: DownpipeState[], budget: ReturnType<typeof budgetFromEnv>): Promise<{ dispatched: number; coalesced: number; carried: number; sealErrors: number }> {
  // FAIRNESS (ENG-SCALE-01): process the due downpipes OLDEST-DUE-FIRST so a crowded tick that
  // runs out of budget before the end serves the most-overdue downpipes first, and the SAME tail
  // is not starved tick after tick (the longer a downpipe stays undispatched, the older its
  // nextRunAt becomes, so it rises to the front of the next tick's order). The DO returns the due
  // set in storage order, not due-time order, so sort here. A stable sort by nextRunAt ascending.
  const ordered = [...due].sort((a, b) => a.nextRunAt - b.nextRunAt);
  // PER-INVOCATION failover-probe cache (ENG-SCALE-02): many downpipes on a fan-out fleet share the
  // same destinations, so a per-destination reachability result is memoised for the rest of THIS
  // tick, N downpipes fanning out to the same 2 buckets then cost 2 probes this tick, not 2N. The
  // cache lives only for this invocation (a fresh tick re-probes), so a destination that recovers is
  // re-checked on the very next */15; this is the safe staleness bound (see selectSealDestination).
  const probeCache = new Map<string, boolean>();
  // Per-tick outcome tally (scheduler-liveness new-logging): what actually happened to the due set this
  // tick -- dispatched vs coalesced (a prior run still in flight) vs carried (the clean budget break) vs a
  // per-downpipe dispatch error. drive() folds these into the TickReport it posts to the DO, so a false-green
  // tick (dispatched 0 of N due, or a budget starve) is durably visible in the support pack.
  let dispatched = 0;
  let coalesced = 0;
  let sealErrors = 0;
  let i = 0;
  for (; i < ordered.length; i++) {
    const state = ordered[i]!;
    // BUDGET EARLY-EXIT (ENG-SCALE-01): stop dispatching new downpipes once there is no longer
    // enough shared-budget headroom to start one more and let it finalise. The undispatched
    // downpipes were never triggered and their nextRunAt is unchanged, so they stay DUE and the
    // next tick (or the DO alarm) runs them. This is the clean stop that keeps a crowded tick from
    // being killed mid-loop at the platform subrequest cap (which would persist no progress).
    if (budget.remaining() < DRIVE_PER_DOWNPIPE_RESERVE) {
      const carried = ordered.length - i;
      log("info", `seal loop yielded: budget low (${budget.remaining()} subrequests left), ${carried} due downpipe(s) carried to the next tick`);
      // Record the yield so it is not just a log line (failover-probe-budget-exhaustion): a fleet too large for
      // the per-tick shared budget silently starves its tail otherwise. Best-effort + fail-open -- a persist
      // hiccup must never delay or fail the backup path, so the POST is fire-and-forget with its error swallowed.
      schedulerStub(env)
        .fetch(doURL("/drive-budget-yield"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ carried }) })
        .catch(() => {});
      break;
    }
    try {
      const outcome = await runDownpipe(env, state, budget, probeCache);
      if (outcome === "coalesced") coalesced++;
      else dispatched++;
    } catch (e) {
      sealErrors++;
      // A failure that escaped runDownpipe happened before a run index was allocated (e.g.
      // at trigger), so there is no in-flight history row to resolve; clear the lock with an
      // empty-runId completion (index 0 matches nothing, a history no-op) so the next tick
      // retries and lastRunId is NOT advanced (the prevRunId chain stays intact). A failure
      // AFTER allocation is handled inside runDownpipe, which knows the real index and posts
      // a coarse error onto the matching history row.
      //
      // GUARDED separately: this best-effort completion runs inside the error path itself, so a DO
      // blip HERE (the scheduler momentarily unavailable while we clear the lock) must not throw out
      // of the per-downpipe catch and reject drive() (which would crash the whole cron invocation and
      // strand the remaining due runs). A failed clear degrades to "the lock clears on a later tick"
      // (the DO alarm / next */15 reconciliation re-attempts); we log it coarsely and continue.
      //
      // G163: the fault is now ATTRIBUTED. The class comes off the TAG runDownpipe's sites attached (never
      // re-read from the message), and a lock-clear that ALSO fails OVERRIDES it: a wedged lease is the worse
      // fault (the downpipe then reads as permanently in-flight / "stalled" until a later tick clears it), and
      // it is the one the pack could previously see only as an unexplained stall.
      let cls = sealErrorClassOf(e);
      try {
        await schedulerStub(env).fetch(doURL("/complete"), { method: "POST", body: JSON.stringify({ id: state.config.id, runId: "", index: 0 }) });
      } catch (ce) {
        cls = "lock-clear-failed";
        log("error", `run ${state.config.id} completion (lock clear) failed: ${(ce as Error).message}`);
      }
      await recordSealError(env, state.config.id, cls);
      log("error", `run ${state.config.id} failed: ${(e as Error).message}`);
    }
  }
  // carried = the due downpipes the loop never STARTED because it broke on the budget floor (0 when the loop
  // ran the whole set). Together with dispatched/coalesced this reconstructs the tick: due = dispatched +
  // coalesced + sealErrors + carried.
  return { dispatched, coalesced, carried: ordered.length - i, sealErrors };
}
