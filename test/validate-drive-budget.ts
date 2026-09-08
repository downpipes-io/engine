// Prove the cron seal-loop SCALE fixes end to end with in-memory doubles only. No network, no
// deploy, no cost. Run:
//   node test/validate-drive-budget.ts
//
// What this proves:
//
//  the cron drive() seal-dispatch loop is BUDGET-AWARE and FAIR.
//    The loop shares ONE per-invocation subrequest budget across every due downpipe. Previously it
//    iterated the WHOLE due set with no early-exit, so a crowded tick could push past the platform's
//    per-invocation subrequest cap and be KILLED mid-loop (a cap death persists no progress, so the
//    rest of the tick's work is lost). The fix:
//      - STOPS dispatching new downpipes once the shared budget drops below the per-downpipe reserve,
//        carrying the undispatched downpipes to the next tick (they were never /trigger'd, so they
//        stay DUE on the real DO and the next */15, or the alarm, runs them);
//      - is FAIR: it processes OLDEST-DUE-FIRST, so a crowded tick serves the most-overdue downpipes
//        and the same tail is not starved tick after tick.
//    Driven through the REAL worker.scheduled() -> drive() with a cron stub that returns many due
//    downpipes and records every DO round-trip, so the /trigger count IS the dispatch count.
//
//  the 3-2-1 failover destination probe is METERED + per-tick CACHED.
//    destinationReachable issues real subrequests (a PUT, and a best-effort DELETE) that were
//    INVISIBLE to the tick budget, so on a multi-dest fleet they could blow the cap before the budget
//    noticed. The fix counts each probe subrequest against the SAME shared budget, and memoises the
//    per-destination verdict for the rest of the tick so a fan-out fleet probes each destination once
//    per tick, not once per downpipe. Proven directly via the exported destinationReachable (the
//    meter is spent) and selectSealDestination (a per-tick cache hit skips the metered probe).

import { DRIVE_PER_DOWNPIPE_RESERVE } from "../src/cron/seal-loop-pass.ts";
import type { Env } from "../src/env.d.ts";
import worker, { destinationReachable, selectSealDestination } from "../src/index.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";
import { FINALISE_RESERVE, SliceBudget } from "../src/seal/budget.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// Mirrors DRIVE_OVERHEAD_SUBREQUESTS in src/cron/drive.ts (not exported). Must be kept in lockstep:
// if the source constant changes, update this so the low-budget early-exit sub-test stays meaningful.
const DRIVE_OVERHEAD_SUBREQUESTS = 30;
// A LOW slice budget: once the overhead and one reserve's worth are spent, only a handful of the
// stub's 1-subrequest-per-downpipe dispatches remain before the loop's early-exit check trips again,
// so it stops well before the 40th downpipe and exercises the early-exit + carry path. Derived (not a
// bare literal) so it tracks DRIVE_PER_DOWNPIPE_RESERVE automatically: remaining-after-overhead sits a
// little above the reserve floor (never below it, or nothing would dispatch at all; never far above
// it, or all 40 would dispatch and the early-exit path would go unexercised).
const LOW_SLICE_BUDGET = DRIVE_OVERHEAD_SUBREQUESTS + DRIVE_PER_DOWNPIPE_RESERVE + 10;
// An AMPLE slice budget: large enough that the probe sub-tests never hit the cap and the meter
// arithmetic is the only thing under test.
const AMPLE_SLICE_BUDGET = 700;

// ---- stubs (the same shapes validate-worker uses) -----------------------------------------
function makeSchedulerStub(fetchFn: (url: string, init?: RequestInit) => Promise<Response>): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return fetchFn(url, init);
    },
  } as unknown as DurableObjectStub;
}
function makeEnv(stub: DurableObjectStub, extra?: Partial<Env>): Env {
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { SCHEDULER: namespace, ...extra } as unknown as Env;
}

// A single-destination due downpipe with a chosen nextRunAt (so the fairness order is controllable).
// It names an ABSENT source binding and follows the DEFAULT destination, so the cron stub's
// /trigger -> { skipped } short-circuits runDownpipe before any seal runs: the loop spends exactly
// the per-downpipe trigger subrequest and moves on, making the budget arithmetic deterministic.
function dueAt(id: string, nextRunAt: number): DownpipeState {
  return {
    config: { id, name: `dp ${id}`, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: `KV_${id}`, include: [], exclude: [] } },
    nextRunAt,
    lastRunId: null,
    inFlight: false,
  };
}

// cronStub answers exactly the routes drive() reaches, returning the given due set, and RECORDS the
// id of every /trigger so a test can see which downpipes were dispatched (and which were carried).
// /trigger returns { skipped } so the heavy seal never runs (the budget test isolates the loop's
// dispatch decision, not the seal). Every trailing pass returns the empty/no-op shape so the whole
// drive() promise resolves network-free.
function cronStub(due: DownpipeState[]): { stub: DurableObjectStub; triggered: string[] } {
  const triggered: string[] = [];
  const stub = makeSchedulerStub(async (url: string, init?: RequestInit) => {
    const path = new URL(url).pathname;
    const j = (o: unknown) => new Response(JSON.stringify(o), { headers: { "content-type": "application/json" } });
    // single-flight tick lease: grant it (fresh tick) and accept the release, so the budget loop runs.
    if (path === "/tick-lease/acquire") return j({ acquired: true, token: "tick-lease-test" });
    if (path === "/tick-lease/release") return j({ ok: true });
    if (path === "/tick") return j({ ok: true });
    if (path === "/due") return j({ due });
    if (path === "/dest-config") return j({ config: null });
    if (path === "/trigger") {
      const body = typeof init?.body === "string" ? (JSON.parse(init.body) as { id: string }) : { id: "?" };
      triggered.push(body.id);
      return j({ skipped: "coalesced (test: no seal)" });
    }
    if (path === "/complete") return j({ ok: true });
    if (path === "/reconcile-alerts") return j({ alerts: [], pendingTransitionIds: [] });
    if (path === "/source-drift/reconcile") return j({ newlyDetached: [] });
    if (path === "/expiry/reconcile") return j({ emissions: [] });
    if (path === "/restore-tests-due") return j({ due: [] });
    if (path === "/notify/digest-due") return j({ batches: [] });
    if (path === "/downpipes") return j([]); // no retention pass
    if (path === "/canary/due") return j({ due: false });
    if (path === "/push-config") return j({ record: null }); // SIEM push drain: unconfigured -> opt-in no-op
    return new Response(JSON.stringify({ unexpected: path }), { status: 500, headers: { "content-type": "application/json" } });
  });
  return { stub, triggered };
}

// runScheduled drives the REAL worker.scheduled() and awaits the drive() promise it hands waitUntil.
async function runScheduled(env: Env): Promise<void> {
  let captured: Promise<unknown> | undefined;
  const ctx = { waitUntil: (p: Promise<unknown>) => { captured = p; }, passThroughOnException: () => {} } as unknown as ExecutionContext;
  await worker.scheduled({} as unknown as ScheduledController, env, ctx);
  if (captured !== undefined) await captured;
}

// ---- a fake Destination for the probe-metering unit (no network) --------------------------
// destinationReachable only calls put() then delete(); a reachable double resolves both, a down
// double throws on put() (every non-2xx cause). It counts the calls so the test can confirm the
// probe issued exactly the subrequests the meter was charged for.
// FakeDest implements only the { put, delete } subset of Destination that destinationReachable uses,
// so the `as never` casts below are safe: the probe never touches any other member.
class FakeDest {
  puts = 0;
  deletes = 0;
  private readonly up: boolean;
  constructor(up: boolean) {
    this.up = up;
  }
  async put(_k: string, _v: Uint8Array): Promise<void> {
    this.puts++;
    if (!this.up) throw new Error("status 403 (write denied)");
  }
  async delete(_k: string): Promise<void> {
    this.deletes++;
  }
}

async function main(): Promise<void> {
    ok(
      `DRIVE_PER_DOWNPIPE_RESERVE (${DRIVE_PER_DOWNPIPE_RESERVE}) is at least 3x FINALISE_RESERVE (${FINALISE_RESERVE}), leaving real headroom for a non-resumable source's first record above the finalise floor`,
      DRIVE_PER_DOWNPIPE_RESERVE >= FINALISE_RESERVE * 3,
    );

  // ============================================================================================
  // budget early-exit + fairness, through the REAL cron
  // ============================================================================================

  // --- A crowded tick with a LOW budget stops early and carries the rest -----------------------
  {
    const N = 40;
    // Scramble nextRunAt so the fairness sort is meaningful: id dp_00..dp_39, but nextRunAt is a
    // shuffled-ish function of i (a fixed permutation), so storage order != due-time order.
    const due: DownpipeState[] = [];
    for (let i = 0; i < N; i++) {
      const id = "dp_" + String(i).padStart(2, "0");
      const nextRunAt = ((i * 37) % N) * 1000; // a deterministic permutation of due-times
      due.push(dueAt(id, nextRunAt));
    }
    const { stub, triggered } = cronStub(due);
    // A LOW budget: after DRIVE_OVERHEAD_SUBREQUESTS is spent, only a handful of per-downpipe reserves
    // remain, so the loop must stop well before the 40th downpipe.
    ok("the low budget exceeds the cron overhead (the loop can dispatch at least one downpipe)", LOW_SLICE_BUDGET > DRIVE_OVERHEAD_SUBREQUESTS);
    const env = makeEnv(stub, { SCALE_SLICE_SUBREQUESTS: String(LOW_SLICE_BUDGET) });
    await runScheduled(env);

    ok("the loop dispatched at least one downpipe (it did real work)", triggered.length >= 1);
    ok("the loop STOPPED EARLY: not all due downpipes were dispatched (budget early-exit)", triggered.length < N);
    ok("every dispatched downpipe was triggered exactly once (no double-dispatch)", new Set(triggered).size === triggered.length);

    // FAIRNESS: the dispatched downpipes are the OLDEST-DUE ones (lowest nextRunAt). Compute the
    // expected oldest-`k` ids and assert the triggered set equals them.
    const byDue = [...due].sort((a, b) => a.nextRunAt - b.nextRunAt);
    const expectedOldest = new Set(byDue.slice(0, triggered.length).map((d) => d.config.id));
    ok("the dispatched downpipes are the OLDEST-DUE ones (fair, oldest-first)", triggered.every((id) => expectedOldest.has(id)) && triggered.length === expectedOldest.size);

    // CARRIED: every UNdispatched downpipe was never /trigger'd, so on the real DO its nextRunAt is
    // unchanged and it stays DUE for the next tick (not dropped).
    const triggeredSet = new Set(triggered);
    const carried = due.filter((d) => !triggeredSet.has(d.config.id));
    ok("the undispatched downpipes were NEVER triggered (carried, still due, not dropped)", carried.length === N - triggered.length && carried.every((d) => !triggeredSet.has(d.config.id)));

    // PROGRESS ACROSS TICKS: a second tick over the SAME carried set (still due) dispatches the next
    // oldest band, so the tail is not starved forever; repeated ticks drain the whole fleet.
    const { stub: stub2, triggered: triggered2 } = cronStub(carried);
    const env2 = makeEnv(stub2, { SCALE_SLICE_SUBREQUESTS: String(LOW_SLICE_BUDGET) });
    await runScheduled(env2);
    ok("a follow-up tick dispatches MORE of the carried downpipes (the tail drains, no starvation)", triggered2.length >= 1 && triggered2.every((id) => !triggeredSet.has(id)));
  }

  // --- An AMPLE budget dispatches the WHOLE due set (no false early-exit) -----------------------
  {
    const N = 40;
    const due: DownpipeState[] = [];
    for (let i = 0; i < N; i++) due.push(dueAt("dp_" + String(i).padStart(2, "0"), i * 1000));
    const { stub, triggered } = cronStub(due);
    // The default budget (700) minus overhead (30) is far more than 40 * the per-downpipe reserve, so
    // every downpipe is dispatched in one tick (the early-exit only fires under real pressure).
    const env = makeEnv(stub);
    await runScheduled(env);
    ok("with ample budget the loop dispatches the WHOLE due set (no premature stop)", triggered.length === N);
    ok("with ample budget every distinct due downpipe is dispatched once", new Set(triggered).size === N);
  }

  // --- scheduled restore tests are CAPPED per tick (sched-restore-tests-no-budget-cap) ----------
  // With NO backups due (ample budget) and 20 restore tests due, only RESTORE_TEST_MAX_PER_TICK run this
  // tick; the rest stay due for the next tick (no thundering herd). Each test's recency callback
  // (/restore-test-complete) is counted; the downpipes have no lastRunId so each takes the lightweight
  // "no completed run" path (no real drill), which still records the outcome.
  {
    const N = 20;
    const tests: DownpipeState[] = [];
    for (let i = 0; i < N; i++) tests.push(dueAt("rt_" + String(i).padStart(2, "0"), 0));
    let testsRun = 0;
    const stub = makeSchedulerStub(async (url: string) => {
      const path = new URL(url).pathname;
      const j = (o: unknown): Response => new Response(JSON.stringify(o), { headers: { "content-type": "application/json" } });
      if (path === "/due") return j({ due: [] }); // no backups => budget ample, the CAP is the only limit
      if (path === "/restore-tests-due") return j({ due: tests });
      if (path === "/restore-test-complete") { testsRun++; return j({ ok: true }); }
      if (path === "/reconcile-alerts") return j({ alerts: [], pendingTransitionIds: [] });
    if (path === "/source-drift/reconcile") return j({ newlyDetached: [] });
      if (path === "/expiry/reconcile") return j({ emissions: [] });
      if (path === "/notify/digest-due") return j({ batches: [] });
      if (path === "/downpipes") return j([]);
      if (path === "/canary/due") return j({ due: false });
      return j({ ok: true }); // tick, drill-evidence, notification routing: benign (routeNotification swallows errors)
    });
    const env = makeEnv(stub, { RESTORE_TEST_MAX_PER_TICK: "3" });
    await runScheduled(env);
    ok("scheduled restore tests are CAPPED per tick (ran the cap of 3, not all 20 due)", testsRun === 3);
  }

  // ============================================================================================
  // the failover probe is metered + per-tick cached
  // ============================================================================================

  // --- destinationReachable charges the meter for the probe's subrequests ----------------------
  {
    const budget = new SliceBudget({ subrequests: AMPLE_SLICE_BUDGET });
    const before = budget.subrequestsSpent;
    const upDest = new FakeDest(true);
    const reachable = await destinationReachable(upDest as never, budget);
    ok("a writable destination probes reachable", reachable === true);
    ok("the reachable probe charged the meter for BOTH subrequests (put + delete)", budget.subrequestsSpent - before === 2);
    ok("the probe issued exactly the subrequests it was charged for (1 put, 1 delete)", upDest.puts === 1 && upDest.deletes === 1);

    const before2 = budget.subrequestsSpent;
    const downDest = new FakeDest(false);
    const down = await destinationReachable(downDest as never, budget);
    ok("a write-denied destination probes NOT reachable", down === false);
    ok("the down probe charged the meter for the put only (it returns before the delete)", budget.subrequestsSpent - before2 === 1);
    ok("the down probe issued only the put (no delete after a failed put)", downDest.puts === 1 && downDest.deletes === 0);

    // Back-compat: destinationReachable still works with NO meter (the manual run-now path).
    const noMeter = await destinationReachable(new FakeDest(true) as never);
    ok("destinationReachable still works with no meter (back-compat)", noMeter === true);
  }

  // --- selectSealDestination: a per-tick probe-cache HIT skips the metered probe ----------------
  {
    // A scheduler stub that serves /dest-config?id=<X> with a valid (placeholder) config for any id,
    // so selectSealDestination can resolve each destination's config. The PROBE itself must not run
    // here (no real bucket), which is exactly the point: with the cache pre-seeded, the probe is
    // skipped, so buildDestination/destinationReachable are never reached.
    const cfg = { endpoint: "https://example.r2.cloudflarestorage.com", bucket: "b", region: "auto", accessKeyId: "AK", secretAccessKey: "SK" };
    const destStub = makeSchedulerStub(async (url: string) => {
      const path = new URL(url).pathname;
      if (path === "/dest-config") return new Response(JSON.stringify({ config: cfg }), { headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ unexpected: path }), { status: 500, headers: { "content-type": "application/json" } });
    });
    const env = makeEnv(destStub);
    // A FAN-OUT downpipe (>=2 destinations): primary "down", replica "up". Pre-seed the per-tick
    // cache with both verdicts, so selectSealDestination uses the cache and never probes.
    const fanState: DownpipeState = {
      config: { id: "dp_fan", name: "fan", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_fan", include: [], exclude: [] }, destinationIds: ["primary", "replica"] },
      nextRunAt: 0,
      lastRunId: null,
      inFlight: false,
    };
    const budget = new SliceBudget({ subrequests: AMPLE_SLICE_BUDGET });
    const probeCache = new Map<string, boolean>([["primary", false], ["replica", true]]);
    const spentBefore = budget.subrequestsSpent;
    const sel = await selectSealDestination(env, destStub, fanState, { budget, probeCache });
    ok("selectSealDestination FELL OVER to the reachable replica (per cache)", !("allDown" in sel) && sel.destinationId === "replica");
    ok("a per-tick cache HIT skipped the metered probe ENTIRELY (no probe subrequests spent)", budget.subrequestsSpent === spentBefore);

    // And the cache is shared across downpipes within a tick: a SECOND fan-out downpipe on the SAME
    // destinations reuses the cached verdicts, again with no probe: N downpipes, the destinations
    // probed at most once per tick (here zero, because pre-seeded).
    const fanState2: DownpipeState = { ...fanState, config: { ...fanState.config, id: "dp_fan2" } };
    const sel2 = await selectSealDestination(env, destStub, fanState2, { budget, probeCache });
    ok("a second downpipe sharing the destinations reuses the cache (fleet probing does not scale with N)", !("allDown" in sel2) && sel2.destinationId === "replica" && budget.subrequestsSpent === spentBefore);
  }

  console.log(failures === 0 ? "\nDRIVE-BUDGET VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
