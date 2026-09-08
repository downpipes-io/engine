// Scheduled restore-test pass for the cron driver (cron/drive.ts), contract section 5. For each
// downpipe whose restore-test cadence is due, runScheduledRestoreTest runs the in-account drill OUT OF
// THE DO (read-only), records a drill-evidence entry + the recency on the downpipe state, and emits a
// pass/fail notification; recordRestoreTestOutcome is the two-place best-effort recorder. Everything
// here was MOVED VERBATIM out of src/index.ts to keep that entry module a thin handler; the behaviour is
// unchanged. index.ts re-exports runScheduledRestoreTest (the behaviour-neutral test seam) so the
// scheduled-restore-test validator that imports it from ../src/index.ts keeps working. This module
// imports the notification routing from cron/notify-passes.ts and the destination resolver from
// cron/seal-dispatch.ts (not from index.ts), so there is no cycle.

import { loadConfigWrapKey } from "../admin/config-secret.ts";
import { NOTHING_TO_VERIFY_REASON, runDrill } from "../admin/drill.ts";
import { CALLER_HEADER, type Caller, encodeCaller } from "../admin/identity.ts";
import { recordDrillOutcome } from "../admin/restore-faults.ts";
import { doURL, type schedulerStub } from "../admin/router.ts";
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { severityOf } from "../notify.ts";
import { coarseRestoreTestReasonCode } from "../restore-reasons.ts";
import type { DownpipeState } from "../sched/scheduler-do.ts";
import type { budgetFromEnv } from "../seal/budget.ts";
import { noteCronPass, noteFleetDrillBatch, noteRestoreTestPassDeferred, noteRestoreTestSkip } from "./cron-fault-ledger.ts";
import { routeNotification } from "./notify-passes.ts";
import { resolveDestForState } from "./seal-dispatch.ts";

// ENGINE_DRILL_CALLER is the caller header the cron uses when it records a SCHEDULED restore test's
// drill-evidence entry (contract section 5). A scheduled restore test is an engine-run drill, so it
// needs the drill.run capability the DO's POST /drill-evidence re-checks; the engine acts with full
// authority for its own scheduled drill (this DO fetch never leaves the account, the same internal
// trust as the router's forwarded caller header). It is the bare-token break-glass shape (no email),
// so the evidence row's recordedBy is null, which is honest: a scheduled test has no human actor. It
// has no stable subject either (the bare-token break-glass is the all-or-nothing owner, resolved without
// the role table), so subject is null, exactly like the router's token-fallback caller.
const ENGINE_DRILL_CALLER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };

// runScheduledRestoreTest runs ONE downpipe's scheduled restore test (contract section 5): the
// in-account drill (reuse admin/drill.ts: open the latest run with the operational read-back key,
// verify the chain, restore a sample record, write NOTHING), then records a drill-evidence entry with
// kind "in-account" and a pass/fail note, tracks lastRestoreTestAt/Ok on the downpipe state, and
// emits restore-test-pass (info) or restore-test-fail (critical) via the notification model. In a
// BREAK-GLASS-ONLY posture (no operational private), runDrill returns ok:false with the posture
// message and writes nothing; this is NOT a failure of the downpipe, so it is recorded as an
// offline-rehearsal-required note and emitted as an INFO event, NEVER a false pass and never a
// critical false alarm. The drill targets the downpipe's most recent run (lastRunId); a downpipe with
// no successful run yet has nothing to read back, recorded as a coarse "no run to test" info note.
//
// It is fully fail-open: runDrill never throws (it returns a coarse reason), the drill-evidence /
// recency / emission steps are each best-effort, and routeNotification swallows all delivery errors.
// The drill is read-only (admin/drill.ts asserts no write), so a scheduled test can never mutate an
// archive. Cost honesty: a scheduled drill is a metered read on a live deployment; this runs only when
// the engine is live and scheduled (separately gated) and only for a downpipe whose cadence is on.
export async function runScheduledRestoreTest(env: Env, scheduler: DurableObjectStub, state: DownpipeState): Promise<void> {
  const name = state.config.name;
  const now = Date.now();
  const at = new Date(now).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
  // BREAK-GLASS-ONLY posture: no in-account read-back key, so the engine cannot self-test. Record an
  // offline-rehearsal-required note and emit an INFO event; do NOT record a pass (ok stays false) and do NOT
  // emit a critical fail (it is a posture, not a downpipe failure). recordRestoreTestOutcome records ok:false
  // so posture/reports show "no successful in-account test", which is honest.
  if (!env.OPERATIONAL_PRIVATE) {
    await deferRestoreTest(env, scheduler, state, now, at, "offline-rehearsal", "posture", "break-glass-only posture: in-account restore test not possible; exercise recovery offline with the break-glass key", `${name}: scheduled restore test deferred (break-glass-only posture; rehearse offline)`);
    return;
  }
  // A downpipe with no successful run has nothing to read back; record an info note and skip the drill.
  if (!state.lastRunId) {
    await deferRestoreTest(env, scheduler, state, now, at, "in-account", "no-run", "no completed run available to restore-test yet", `${name}: scheduled restore test skipped (no completed run yet)`);
    return;
  }
  // Run the in-account drill against the most recent run, reading from THIS downpipe's destination
  // (its pinned one, else the default). runDrill is read-only and never throws. The scheduled drill runs
  // in WINDOWED mode (INT-1): it decrypts a window of records starting at the persisted cursor and
  // advances it, so over ceil(records / window) ticks every record of the run is decrypted-and-verified,
  // not just the same strided sample forever. The cursor is bound to the run: a new lastRunId resets it
  // to 0 so the new run is covered from the start; a killed tick simply resumes from the unadvanced
  // cursor next time (no coverage is silently lost).
  const destCfg = await resolveDestForState(scheduler, state, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
  const prior = state.deepVerify;
  const cursor = prior && prior.runId === state.lastRunId ? prior.cursor : 0;
  // restore-test-tick-killed: stamp the "drill in flight" marker BEFORE the (potentially tick-killed) drill.
  // If this cron tick is killed mid-drill, recordDrillResult never fires and the marker is left behind, which
  // the pack reads as an "attempted but incomplete" restore test (vs the recency alone showing "never tested").
  // Best-effort: a marker hiccup never blocks the drill; completeRestoreTest clears it on any completion.
  await markRestoreTestStart(scheduler, state.config.id, now);
  const result = await runDrill(env, state.lastRunId, destCfg, { cursor, window: DEEP_VERIFY_WINDOW });
  // G029: the SCHEDULED drill is the one that runs unattended, so it is the one whose failures nobody reads.
  // Project it into the bounded restoreFaults ring with its blast radius (how many records failed), its first
  // failing index, the missing ARCHIVE OBJECT key and WHICH engine binding was absent. A PASS records nothing.
  await recordDrillOutcome(scheduler, result);
  await recordDrillResult(env, scheduler, state, now, at, result);
}

// markRestoreTestStart posts the "restore-test in flight" marker to the scheduler DO just before a scheduled
// drill (support-pack mode restore-test-tick-killed). Best-effort + fail-open: a marker hiccup degrades to "no
// incomplete signal", never a thrown/blocked drill. It writes a single timestamp; no seal path is touched.
async function markRestoreTestStart(scheduler: DurableObjectStub, id: string, at: number): Promise<void> {
  try {
    const resp = await scheduler.fetch(doURL("/restore-test-start"), { method: "POST", body: JSON.stringify({ id, at }), headers: { "content-type": "application/json" } });
    // G295: the response was never read. A lost marker means a tick-KILLED drill leaves no "attempted" trace at
    // all, so the pack cannot tell "the drill was killed part way, every tick" from "the drill never started".
    if (!resp.ok) noteRestoreTestSkip(id, "start-marker-failed");
  } catch (e) {
    noteRestoreTestSkip(id, "start-marker-failed");
    log("error", `restore-test start marker not recorded for ${id} (non-critical): ${(e as Error).message}`);
  }
}

// DEEP_VERIFY_WINDOW is how many records one scheduled tick decrypts in the rotating windowed cursor
// (INT-1). It bounds the per-tick metered read on the customer's account; over ceil(records / window)
// ticks the cursor covers every record. It matches the historical per-drill sample size so a tick's cost
// is unchanged, but rotation means coverage is FULL over time rather than only the same strided sample.
const DEEP_VERIFY_WINDOW = 8;

// deferRestoreTest is the shared no-evidence branch (break-glass-only posture, no completed run yet, or a
// run that holds no records so the drill decrypted nothing): it
// records the ok:false outcome with the given evidence kind/note and emits an INFO restore-test-pass with the
// given detail. Both cases are a deferral, NEVER a downpipe failure, so neither records a pass nor pages.
async function deferRestoreTest(
  env: Env,
  scheduler: DurableObjectStub,
  state: DownpipeState,
  now: number,
  at: string,
  evidenceKind: "in-account" | "offline-rehearsal",
  deferred: "no-run" | "posture" | "no-records",
  note: string,
  detail: string,
): Promise<void> {
  await recordRestoreTestOutcome(scheduler, state.config.id, { ok: false, at: now, evidenceKind, deferred, note });
  await routeNotification(env, scheduler, {
    event: "restore-test-pass",
    severity: "info",
    downpipeId: state.config.id,
    downpipeName: state.config.name,
    detail,
    at,
  });
}

// recordDrillResult records the drill outcome and emits the pass/fail notification. A pass threads the
// MEASURED recovery cost (durationMs / bytesVerified / recordsVerified, present only when the drill verified a
// record) as an RTO signal and emits an INFO restore-test-pass. A failure records the drill's coarse,
// enumerated reason (never a stack or internal detail) and emits a CRITICAL restore-test-fail.
async function recordDrillResult(
  env: Env,
  scheduler: DurableObjectStub,
  state: DownpipeState,
  now: number,
  at: string,
  result: Awaited<ReturnType<typeof runDrill>>,
): Promise<void> {
  const id = state.config.id;
  const name = state.config.name;
  // The windowed-cursor advance (INT-1) is recorded on BOTH a pass and a drained per-record failure, so a
  // corrupted record reports the failure AND still advances coverage past it (the cursor never wedges).
  // runId binds the cursor to the run that was drilled, so the DO resets it when the latest run changes.
  const deepVerify = result.deepVerify ? { runId: state.lastRunId ?? "", cursor: result.deepVerify.cursor, records: result.deepVerify.records, wrapped: result.deepVerify.wrapped } : undefined;
  // The restore-subsystem OOM-risk marker (INFRA isolate-oom-restore): forwarded on BOTH a pass and a failure
  // (the drill buffers records whole regardless of the verdict), so completeRestoreTest can stamp the isolate-
  // OOM early warning on the downpipe state for the pack.
  // NOTHING TO VERIFY IS A DEFERRAL, NOT A FAILURE AND NOT A PASS. The drill sets nothingToVerify when the
  // run opened and its chain verified but it holds ZERO records, so the rehearsal decrypted nothing and
  // established nothing about recoverability. Routed here, ahead of both branches below, because it belongs
  // to NEITHER: the pass branch was writing "scheduled restore test passed (records verified: 0)" into the
  // customer's own compliance evidence, and the fail branch would tell them their backup failed its restore
  // test and point them at the archive, when the thing to look at is whether the SOURCE is genuinely empty.
  // deferRestoreTest records ok:false WITH a deferral kind, which is the discriminator posture-checks reads
  // to keep a deferral from counting as fresh disconfirming evidence.
  if (result.nothingToVerify === true) {
    await deferRestoreTest(
      env,
      scheduler,
      state,
      now,
      at,
      "in-account",
      "no-records",
      `scheduled restore test could not verify: ${NOTHING_TO_VERIFY_REASON}`,
      `${name}: scheduled restore test deferred (the last run holds no records; check whether the source is empty)`,
    );
    return;
  }
  if (result.ok) {
    const note = `scheduled restore test passed (records verified: ${result.recordsVerified ?? 0}${result.sampleRestored ? ", sample restored" : ""})`;
    await recordRestoreTestOutcome(scheduler, id, {
      ok: true,
      at: now,
      evidenceKind: "in-account",
      note,
      ...(typeof result.durationMs === "number" ? { durationMs: result.durationMs } : {}),
      ...(typeof result.bytesVerified === "number" ? { bytesVerified: result.bytesVerified } : {}),
      ...(typeof result.recordsVerified === "number" ? { recordsVerified: result.recordsVerified } : {}),
      ...(deepVerify ? { deepVerify } : {}),
      ...(result.oom ? { oom: result.oom } : {}),
    });
    await routeNotification(env, scheduler, {
      event: "restore-test-pass",
      severity: severityOf("restore-test-pass"),
      downpipeId: id,
      downpipeName: name,
      detail: `${name}: scheduled restore test passed`,
      at,
    });
  } else {
    const note = `scheduled restore test failed: ${result.reason ?? "recovery check failed"}`;
    // scheduled-restore-fail-reason (support pack): classify the drill's reason to a CLOSED short code and
    // forward it so the DO persists the cause + a consecutive-failure streak on the downpipe state (survives
    // past the bounded notify ring / evidence note). Only the coarse code travels, never the raw reason.
    const reason = coarseRestoreTestReasonCode(result.reason);
    await recordRestoreTestOutcome(scheduler, id, { ok: false, at: now, evidenceKind: "in-account", note, reason, ...(deepVerify ? { deepVerify } : {}), ...(result.oom ? { oom: result.oom } : {}) });
    await routeNotification(env, scheduler, {
      event: "restore-test-fail",
      severity: severityOf("restore-test-fail"),
      downpipeId: id,
      downpipeName: name,
      detail: `${name}: scheduled restore test failed (${result.reason ?? "recovery check failed"})`,
      at,
    });
  }
}

// recordRestoreTestOutcome records a scheduled restore test's outcome in TWO places, both best-effort
// (a failed record degrades to "less evidence/recency", never a thrown cron): a drill-evidence entry
// (the audited evidence log, kind in-account or offline-rehearsal, with a redaction-safe pass/fail
// note) and the per-downpipe recency on the downpipe state (lastRestoreTestAt/Ok, so posture and
// reports can read recency without scanning the evidence log). The drill-evidence write goes through
// the SAME DO route the console uses (POST /drill-evidence), with an engine caller header so the DO's
// drill.run capability re-check passes (a scheduled test is an engine-run drill, the same authority a
// human drill needs). The recency write is the internal /restore-test-complete callback.
async function recordRestoreTestOutcome(
  scheduler: DurableObjectStub,
  downpipeId: string,
  outcome: { ok: boolean; at: number; evidenceKind: "in-account" | "offline-rehearsal"; note: string; reason?: string; deferred?: "no-run" | "posture" | "no-records"; durationMs?: number; bytesVerified?: number; recordsVerified?: number; deepVerify?: { runId: string; cursor: number; records: number; wrapped: boolean }; oom?: { maxRecordBytes: number; safeBytes: number; overSafe: boolean } },
): Promise<void> {
  // Record the recency on the downpipe state (internal callback). The MEASURED recovery cost (durationMs /
  // bytesVerified / recordsVerified), when present, is forwarded so the DO appends an RTO sample; the DO
  // appends one only for a successful, positive-byte measurement, so a failed/break-glass test contributes
  // no sample and the estimate stays honestly unknown.
  try {
    const resp = await scheduler.fetch(doURL("/restore-test-complete"), {
      method: "POST",
      body: JSON.stringify({
        id: downpipeId,
        ok: outcome.ok,
        at: outcome.at,
        // The coarse failure code (scheduled-restore-fail-reason): forwarded ONLY on a real failure, so its
        // presence discriminates a FAILURE from a DEFERRAL (the DO leaves the streak untouched when absent).
        ...(outcome.reason !== undefined ? { reason: outcome.reason } : {}),
        // The deferral kind (no-run / posture): forwarded ONLY on a deferral, so the DO can persist WHICH
        // no-evidence case this was and the console can stop rendering a deferral as a failure.
        ...(outcome.deferred !== undefined ? { deferred: outcome.deferred } : {}),
        ...(typeof outcome.durationMs === "number" ? { durationMs: outcome.durationMs } : {}),
        ...(typeof outcome.bytesVerified === "number" ? { bytesVerified: outcome.bytesVerified } : {}),
        ...(typeof outcome.recordsVerified === "number" ? { recordsVerified: outcome.recordsVerified } : {}),
        ...(outcome.deepVerify ? { deepVerify: outcome.deepVerify } : {}),
        ...(outcome.oom ? { oom: outcome.oom } : {}),
      }),
      headers: { "content-type": "application/json" },
    });
    // G295: the response was never read, so a non-2xx passed for a recorded outcome.
    if (!resp.ok) noteRestoreTestSkip(downpipeId, "record-failed");
  } catch (e) {
    // G295: BOTH outcome writes can fail, leaving a week-long hole in the evidence behind a perfectly healthy
    // engine -- "this downpipe shows never-tested for months" when it has been tested every night.
    noteRestoreTestSkip(downpipeId, "record-failed");
    log("error", `restore-test recency record failed for ${downpipeId} (non-critical): ${(e as Error).message}`);
  }
  // Record the drill-evidence entry. The DO's POST /drill-evidence re-checks the drill.run capability
  // from the forwarded caller, so an engine-run scheduled test forwards an owner caller header (the
  // engine acts with full authority for its own scheduled drill; this never leaves the account). The
  // runId is the downpipe id here (the evidence is "this downpipe was restore-tested"); the note is the
  // redaction-safe pass/fail one-liner. A validation/capability failure degrades to "no evidence row".
  try {
    const resp = await scheduler.fetch(doURL("/drill-evidence"), {
      method: "POST",
      body: JSON.stringify({ runId: downpipeId, kind: outcome.evidenceKind, note: outcome.note }),
      headers: { [CALLER_HEADER]: encodeCaller(ENGINE_DRILL_CALLER), "content-type": "application/json" },
    });
    if (!resp.ok) noteRestoreTestSkip(downpipeId, "record-failed"); // G295: a capability/validation refusal ate the evidence row
  } catch (e) {
    noteRestoreTestSkip(downpipeId, "record-failed"); // G295: the evidence row for a drill that RAN was lost
    log("error", `drill-evidence record failed for ${downpipeId} (non-critical): ${(e as Error).message}`);
  }
}

// ---- the cron driver's restore-test passes (moved VERBATIM out of cron/drive.ts to finish
// the *-pass.ts split of that orchestrator; the behaviour is unchanged) --------------------

// RESTORE_TEST_MAX_PER_TICK_DEFAULT bounds how many scheduled restore-test drills run per cron tick when
// RESTORE_TEST_MAX_PER_TICK is unset, so a large fleet does not dispatch every due drill at once.
const RESTORE_TEST_MAX_PER_TICK_DEFAULT = 5;
// RESTORE_TEST_DRILL_COST is a conservative per-drill subrequest estimate (open the latest run: root +
// shards + a sample segment, then verify) charged to the shared budget so restore tests yield and the
// trailing passes see the cost. runDrill does not yet self-meter into the cron budget; this is the bound.
// Known approximation tracked as engine-src-024-05: once runDrill meters its own subrequests, replace this
// proxy or re-validate the value.
const RESTORE_TEST_DRILL_COST = 10;

// restoreTestMaxPerTick reads the RESTORE_TEST_MAX_PER_TICK knob (a positive integer), falling back to the
// default; an invalid value falls back rather than throwing, so a typo never stops the pass.
function restoreTestMaxPerTick(env: Env): number {
  const raw = env.RESTORE_TEST_MAX_PER_TICK;
  if (typeof raw === "string" && raw.trim() !== "") {
    const n = Number(raw);
    if (Number.isFinite(n) && n >= 1) return Math.floor(n);
  }
  return RESTORE_TEST_MAX_PER_TICK_DEFAULT;
}

// runRestoreTestPass runs the due scheduled restore-test drills, capped per tick and budget-gated.
export async function runRestoreTestPass(env: Env, scheduler: ReturnType<typeof schedulerStub>, budget: ReturnType<typeof budgetFromEnv>): Promise<boolean> {
  // Scheduled restore tests (contract section 5): ask the DO for the downpipes whose restore test is
  // due (last test older than the cadence), run the in-account drill for each OUT OF THE DO (the same
  // seal-stays-out-of-the-DO separation as runs), record a drill-evidence entry and the recency on the
  // downpipe state, and emit restore-test-pass (info) or restore-test-fail (critical). It runs AFTER
  // the run loop so a scheduled test never delays a backup, and the whole block plus each per-downpipe
  // step is guarded so a drill failure or a DO hiccup degrades to "no scheduled test this tick", never
  // a crashed cron. The DO returns no due downpipes when none have the cadence on, so the common case
  // costs one read.
  // CAP the herd (sched-restore-tests-no-budget-cap): each drill is a metered read against a destination,
  // so running EVERY due test in one tick competes with backups for the shared cap. Bound it three ways:
  // skip the pass entirely when the seal loop already drained the budget (backups outrank restore tests),
  // cap the count per tick (RESTORE_TEST_MAX_PER_TICK), and charge a conservative per-drill estimate to the
  // shared budget so the in-loop yield and the trailing passes (prune, canary, digest) see the cost. A test
  // not run this tick stays due (recency unchanged) and runs next tick; a PASSED test updates recency and
  // drops out of "due", so the cap rotates fairly across the fleet.
  if (budget.shouldYield()) {
    // G295: one deferral is routine (backups outrank drills, which is correct). A RUN of them is chronic
    // starvation on a crowded fleet -- the reason a compliance report reads "restore tests overdue fleet-wide"
    // -- and it left nothing behind but an info log. Count it.
    noteRestoreTestPassDeferred();
    log("info", "scheduled restore tests deferred this tick (backups consumed the budget); they resume next tick");
    return true; // a deliberate budget deferral is not a fault (the pass made its decision and completed)
  }
  const cap = restoreTestMaxPerTick(env);
  let ran = 0;
  let ok = true;
  try {
    const dueResp = await scheduler.fetch(doURL("/restore-tests-due"), { method: "POST" });
    budget.spend(1);
    const { due: testsDue } = (await dueResp.json()) as { due: DownpipeState[] };
    for (const state of testsDue) {
      if (ran >= cap || budget.shouldYield()) {
        // G295: a DUE downpipe that never got its turn this tick. Correct (the herd is capped on purpose), and
        // invisible: a downpipe permanently at the back of the queue is exactly the one that reads "never
        // tested" forever, with the pack showing a healthy cron.
        noteRestoreTestSkip(state.config.id, "budget-deferred");
        continue;
      }
      try {
        await runScheduledRestoreTest(env, scheduler, state);
      } catch (e) {
        // A failure that escaped runScheduledRestoreTest must not crash the cron; log coarsely and move
        // on. The recency is left unchanged for this downpipe, so the next tick retries the test.
        // G295: a PRE-DRILL throw (an unresolvable destination, an unusable CONFIG_WRAP_KEY) lands BEFORE every
        // recording step inside runScheduledRestoreTest, so it wrote nothing at all -- not an outcome, not a
        // marker, not an evidence row. This is the "never tested for months" ticket, and the class names it.
        noteRestoreTestSkip(state.config.id, "pre-drill-fault");
        log("error", `scheduled restore test for ${state.config.id} skipped: ${(e as Error).message}`);
      }
      // Charge a conservative per-drill estimate (open run + verify + sample restore) so the shared
      // budget reflects restore-test cost even though runDrill does not yet self-meter into it.
      budget.spend(RESTORE_TEST_DRILL_COST);
      ran++;
    }
    if (testsDue.length > ran) {
      log("info", `scheduled restore tests: ran ${ran} of ${testsDue.length} due this tick (capped/budget); the rest run next tick`);
    }
  } catch (e) {
    // G132: classify the throw here; the driver only sees the false return.
    noteCronPass("restore-tests", false, e);
    log("error", `scheduled restore tests skipped this tick: ${(e as Error).message}`);
    ok = false;
  }
  // SCALE-2: drain an on-demand FLEET-DRILL campaign within the SAME per-tick cap and shared budget, AFTER
  // the cadence-due tests (routine recency outranks an on-demand sweep, and sharing the cap keeps total
  // restore-test work per tick bounded). A fleet drill thus completes over a bounded number of ticks
  // (e.g. a 100-downpipe fleet at the default cap of 5/tick sweeps in ~20 ticks, ~100 min at */5, vs the
  // ~weeks the weekly cadence alone would take), respecting the budget + the CF rate limiter exactly as
  // the scheduled tests do, and never bypassing the per-downpipe integrity drill.
  await runFleetDrillPass(env, scheduler, budget, cap - ran);
  return ok;
}

// runFleetDrillPass drains up to `remainingCap` members of the active on-demand fleet-drill campaign (SCALE-2)
// this tick, running each downpipe's in-account drill via the SAME runScheduledRestoreTest path the scheduled
// test uses (so the integrity-drill semantics are identical) and charging the same per-drill estimate to the
// shared budget. The DO's fleetDrillNextBatch marks each returned member in flight and advances the campaign as
// the /restore-test-complete callbacks land; a member dispatched but not run this tick (budget ran out) is
// re-queued by the DO's in-flight timeout, so the campaign self-heals and always converges. Fail-open: any
// fault degrades to "resume next tick", never a crashed cron. Cheap when no campaign is active (one read).
async function runFleetDrillPass(env: Env, scheduler: ReturnType<typeof schedulerStub>, budget: ReturnType<typeof budgetFromEnv>, remainingCap: number): Promise<void> {
  if (remainingCap <= 0 || budget.shouldYield()) return;
  try {
    const resp = await scheduler.fetch(doURL("/fleet-drill/next"), { method: "POST", body: JSON.stringify({ cap: remainingCap }) });
    budget.spend(1);
    const { due: batch, campaignId } = (await resp.json()) as { due: DownpipeState[]; campaignId: string | null; done: boolean };
    if (campaignId === null || batch.length === 0) return;
    // G295: the fleet-drill campaign moved a BATCH. A campaign that is stuck (dispatching members that never
    // drill) previously moved no counter anywhere, so "the fleet drill has been running for a week" had no
    // engine-side evidence at all. Booleans and counts; never the campaign's membership.
    noteFleetDrillBatch(false);
    let ran = 0;
    for (const state of batch) {
      // Stop cleanly if the budget is exhausted mid-batch: the undrilled members stay marked in flight in the
      // campaign and the DO re-queues them after the in-flight timeout, so no campaign member is lost.
      if (budget.shouldYield()) break;
      try {
        await runScheduledRestoreTest(env, scheduler, state);
      } catch (e) {
        noteRestoreTestSkip(state.config.id, "pre-drill-fault"); // G295: same pre-drill hole, on the fleet path
        log("error", `fleet-drill restore test for ${state.config.id} skipped: ${(e as Error).message}`);
      }
      budget.spend(RESTORE_TEST_DRILL_COST);
      ran++;
    }
    log("info", `fleet drill ${campaignId}: drilled ${ran} of ${batch.length} dispatched this tick`);
  } catch (e) {
    // G132: the fleet drill NEVER moved passErrors at all -- a drill campaign could fail every tick for
    // days and the pack showed a clean cron. It is folded into the restore-tests pass health, which is the
    // pass the operator recognises ("no restore tests are running").
    noteCronPass("restore-tests", false, e);
    noteFleetDrillBatch(true); // G295: the campaign's OWN batch health (a stuck campaign, named as such)

    log("error", `fleet drill pass skipped this tick: ${(e as Error).message}`);
  }
}
