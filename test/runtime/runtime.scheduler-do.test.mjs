// REAL-WORKERD runtime tests for the SchedulerDO (assessment finding QA-3).
//
// Run (NOT part of `npm run validate`; a separate, additive target):
//   npm run test:runtime
//   # or directly:  node test/runtime/runtime.scheduler-do.test.mjs
//
// WHY THIS EXISTS — what these tests cover that the Node doubles CANNOT
// --------------------------------------------------------------------
// test/validate-scheduler.ts and test/validate-runlog-lock.ts drive the SchedulerDO class
// directly over an in-memory MockStorage. That harness is single-threaded and SERIAL: it awaits
// one DO.fetch() before issuing the next, so it can never put two requests in flight at once. It
// also stubs setAlarm() to a no-op and never runs under a real isolate. Consequently the run
// lock's mutual exclusion, the runlogIndex (runlogCounter) allocation, and the alarm scheduling
// are all asserted only under an environment where concurrency is impossible by construction —
// the exact gap QA-3 names.
//
// These tests load the PRODUCTION SchedulerDO (src/sched/scheduler-do.ts, bundled unchanged) into
// a REAL workerd isolate via Miniflare, with a SQLite-backed Durable Object namespace exactly as
// the production wrangler.toml declares (v1 migration, new_sqlite_classes = ["SchedulerDO"]). They
// then issue genuinely concurrent requests (Promise.all over many dispatchFetch calls) against the
// single DO instance, so the DO's real INPUT GATE — the platform's per-object request serialiser —
// is what enforces the invariants, not a serial test driver.
//
// INVARIANTS NOW EXERCISED IN REAL WORKERD (vs still only in Node doubles):
//   [workerd] RL-1  concurrent runlog-lock acquire: 8 simultaneous acquires -> EXACTLY ONE wins,
//                   7 are refused, no token leaks to a loser. (Node doubles: serial, the 2nd acquire
//                   is only ever observed AFTER the 1st fully returned, so no real race is tested.)
//   [workerd] RL-2  lock release frees the lease and a re-acquire mints a DIFFERENT token, with the
//                   release driven through the same real-isolate HTTP surface.
//   [workerd] RL-3  release with a WRONG token is a no-op under the real gate (the holder keeps it);
//                   concurrent acquire is still refused.
//   [workerd] IDX-1 monotonic runlogIndex under concurrency: N simultaneous triggers across N
//                   downpipes allocate N DISTINCT, contiguous indices (no two runs read the same
//                   runlogCounter). This is the headline QA-3 invariant: the counter read-modify-write
//                   has NO blockConcurrencyWhile around it, so ONLY the real input gate prevents a
//                   duplicate index. (Node doubles cannot create the contended read at all.)
//   [workerd] IDX-2 concurrent triggers on the SAME downpipe coalesce: exactly one starts a run, the
//                   rest are skipped — the in-flight guard holds under a real race, not just serially.
//   [workerd] ALM-1 the alarm() handler + rearmAlarm()->setAlarm() execute end to end in workerd
//                   against REAL DurableObjectStorage (driven via POST /tick), returning cleanly and
//                   re-arming idempotently. Under the Node double setAlarm is a no-op; here setAlarm
//                   is a real workerd storage operation. (See the ALM-1 note for the one alarm facet
//                   these tests deliberately do NOT assert and why.)
//
// STILL ONLY IN NODE DOUBLES (by design, not regressed here): the fine-grained state assertions
// that need to backdate a stored lease/nextRunAt or read raw storage keys — lease-expiry reclaim,
// the suspended-writer stale-token hazard, RING_CAP truncation, completeRun idempotency/stale-row
// guards, the rearm-clamp floor and soonest-pipe selection. Those remain in validate-scheduler.ts /
// validate-runlog-lock.ts, which keep the direct raw-storage seam this runtime harness intentionally
// does not (it talks only to the DO's public HTTP surface, like the real router). This suite
// COMPLEMENTS them with the concurrency dimension; it does not duplicate them.

import { startScheduler, makeReporter, kvConfig } from "./harness.mjs";

async function main() {
  const { req, reqAll, dispose } = await startScheduler();
  const { ok, done } = makeReporter("SchedulerDO REAL-WORKERD runtime vectors");

  try {
    // ---- RL-1: concurrent runlog-lock acquire — exactly one winner under the real input gate ----
    // Fire 8 acquires AT ONCE. In a live deployment, two runs (e.g. the cron driver and a manual
    // run) can call acquire concurrently; the single-writer RUNLOG guarantee depends on the DO
    // serialising the read-modify-write on the "runlogLock" key. We assert the race resolves to one
    // holder. The Node double cannot construct this: it awaits each acquire before the next.
    {
      const acquires = await reqAll("POST", "/runlog-lock/acquire", Array.from({ length: 8 }, () => undefined));
      ok("RL-1: all 8 concurrent acquires returned 200", acquires.every((a) => a.status === 200));
      const winners = acquires.filter((a) => a.body && a.body.acquired === true);
      const losers = acquires.filter((a) => a.body && a.body.acquired === false);
      ok("RL-1: EXACTLY ONE concurrent acquire wins (real input gate serialises the RMW)", winners.length === 1);
      ok("RL-1: the other 7 concurrent acquires are refused", losers.length === 7);
      ok("RL-1: the winner carries a non-empty token", typeof winners[0]?.body?.token === "string" && winners[0].body.token.length > 0);
      ok("RL-1: no refused acquire leaked a token", losers.every((l) => l.body.token === undefined));
      ok("RL-1: the single winner token is unique", new Set(winners.map((w) => w.body.token)).size === 1);

      // ---- RL-2: release frees the lock; re-acquire mints a DIFFERENT token (real isolate) -------
      const winnerToken = winners[0].body.token;
      const rel = await req("POST", "/runlog-lock/release", { token: winnerToken });
      ok("RL-2: release returns { ok: true }", rel.status === 200 && rel.body?.ok === true);
      const reAcq = await req("POST", "/runlog-lock/acquire");
      ok("RL-2: re-acquire after release succeeds", reAcq.body?.acquired === true);
      ok("RL-2: re-acquire mints a genuinely new token (lease was really freed)", typeof reAcq.body?.token === "string" && reAcq.body.token !== winnerToken);

      // ---- RL-3: a WRONG-token release is a no-op under the real gate; lock stays held -----------
      const wrong = await req("POST", "/runlog-lock/release", { token: "not-the-holder-token" });
      ok("RL-3: wrong-token release still returns { ok: true } (a no-op, not an error)", wrong.body?.ok === true);
      const stillHeld = await req("POST", "/runlog-lock/acquire");
      ok("RL-3: lock still held after a wrong-token release (concurrent acquire refused)", stillHeld.body?.acquired === false);
      // Clean up: the real holder releases so later sections start from a free lock.
      await req("POST", "/runlog-lock/release", { token: reAcq.body.token });
      const freeNow = await req("POST", "/runlog-lock/acquire");
      ok("RL-3: correct-token release truly freed the lock (re-acquire succeeds)", freeNow.body?.acquired === true);
      await req("POST", "/runlog-lock/release", { token: freeNow.body.token });
    }

    // ---- IDX-1: monotonic runlogIndex allocation under TRUE concurrency -------------------------
    // The QA-3 headline. trigger() allocates the next index as: read "runlogCounter", +1, write back
    // — with NO blockConcurrencyWhile around it. Correctness rests ENTIRELY on the DO input gate
    // serialising the contended read-modify-write. Create N enabled downpipes, then trigger ALL of
    // them at once. Each must get a distinct index, and across N runs the indices must be exactly the
    // contiguous set {1..N}: a duplicate (two runs reading the same counter) would collapse the set
    // below N distinct values; a lost write would leave a gap. The Node double cannot create the
    // contended read, so this monotonicity-under-contention property is untested there.
    {
      const N = 16;
      const ids = Array.from({ length: N }, (_, i) => `idx${i}`);
      const adds = await reqAll("POST", "/downpipes", ids.map((id) => kvConfig(id)));
      ok("IDX-1: all N downpipes created (200)", adds.every((a) => a.status === 200));

      const trigs = await reqAll("POST", "/trigger", ids.map((id) => ({ id })));
      ok("IDX-1: all N concurrent triggers returned 200", trigs.every((t) => t.status === 200));
      const indices = trigs.map((t) => t.body?.index).filter((v) => typeof v === "number");
      ok("IDX-1: every concurrent trigger allocated an index", indices.length === N);

      const distinct = new Set(indices);
      ok("IDX-1: NO two concurrent runs share an index (all N distinct)", distinct.size === N);
      const sorted = [...indices].sort((a, b) => a - b);
      const min = sorted[0];
      const max = sorted[sorted.length - 1];
      ok("IDX-1: indices are the contiguous set {min..min+N-1} (no gap, no rollback under contention)", sorted.every((v, k) => v === min + k));
      ok("IDX-1: the contiguous block spans exactly N (max - min + 1 === N)", max - min + 1 === N);
      ok("IDX-1: allocation started at index 1 on a fresh DO", min === 1);

      // The runlogCounter must now sit at max (next allocation is max+1): a single fresh trigger
      // proves the counter advanced past the whole concurrent block, not to some duplicated value.
      const extra = await req("POST", "/downpipes", kvConfig("idx-after"));
      ok("IDX-1: post-block downpipe created", extra.status === 200);
      const afterTrig = await req("POST", "/trigger", { id: "idx-after" });
      ok("IDX-1: a subsequent trigger allocates max+1 (counter advanced past the whole block)", afterTrig.body?.index === max + 1);
    }

    // ---- IDX-2: concurrent triggers on the SAME downpipe coalesce (in-flight guard under a race) -
    // A single downpipe hit by many concurrent triggers (the realistic "double-fire" from overlapping
    // cron + manual run) must start exactly ONE run; the rest must coalesce ({ skipped }). The guard
    // is the in-flight lease check inside trigger(); under the real gate the first trigger commits
    // inFlight=true before any sibling reads it. The Node double can only ever see the post-commit
    // state, so it never tests the contended path.
    {
      await req("POST", "/downpipes", kvConfig("coal-rt"));
      const fires = await reqAll("POST", "/trigger", Array.from({ length: 8 }, () => ({ id: "coal-rt" })));
      ok("IDX-2: all 8 concurrent same-pipe triggers returned 200", fires.every((f) => f.status === 200));
      const started = fires.filter((f) => typeof f.body?.runId === "string");
      const skipped = fires.filter((f) => typeof f.body?.skipped === "string");
      ok("IDX-2: EXACTLY ONE concurrent trigger started a run", started.length === 1);
      ok("IDX-2: the other 7 coalesced (skipped), never double-running the pipe", skipped.length === 7);
      ok("IDX-2: no coalesced response carried a runId", skipped.every((s) => s.body.runId === undefined));
    }

    // ---- ALM-1: alarm() + rearmAlarm()->setAlarm() run end to end in REAL workerd ---------------
    // POST /tick drives the DO's alarm() exactly as a fired DO alarm would: it runs the housekeeping
    // sweep (over real DurableObjectStorage list/delete) and then rearmAlarm()->setAlarm(armAt). Under
    // the Node double setAlarm is a stubbed no-op; HERE it is a genuine workerd storage operation that
    // must complete without error, against a real isolate, for an enabled downpipe. We assert the path
    // runs cleanly and re-arms idempotently, and that the DO is fully responsive afterwards (the alarm
    // did not wedge the object).
    //
    // DELIBERATELY NOT ASSERTED HERE (honest scope): the AUTONOMOUS delivery of the alarm — workerd
    // invoking alarm() on its own at the scheduled time — and the exact armed timestamp. Reading the
    // scheduled alarm or receiving an external alarm callback requires Miniflare's RPC/alarm proxy,
    // which is only available for a DO declared `extends DurableObject`. The production SchedulerDO is
    // a plain class (constructor(state); fetch(); alarm()) and MUST NOT be changed to add an RPC base
    // just for a test. The rearm-CLAMP and soonest-pipe SELECTION (the actual armAt value logic) are
    // already covered deterministically in validate-scheduler.ts (TC-15/15b/15c/15d) via the MockStorage
    // setAlarm spy; this runtime test adds that the same code executes in workerd without faulting.
    {
      await req("POST", "/downpipes", kvConfig("alarm-rt", { enabled: true }));
      const tick1 = await req("POST", "/tick");
      ok("ALM-1: POST /tick (drives real alarm()+setAlarm in workerd) returns { ok: true }", tick1.status === 200 && tick1.body?.ok === true);
      const info = await req("GET", "/tick-info");
      ok("ALM-1: the tick instant was persisted to real DO storage (lastTickAt set)", typeof info.body?.lastTickAt === "number" && Number.isFinite(info.body.lastTickAt));
      const tick2 = await req("POST", "/tick");
      ok("ALM-1: a second tick re-arms idempotently (alarm()/rearmAlarm run again cleanly)", tick2.status === 200 && tick2.body?.ok === true);
      // The DO remains fully responsive after the alarm path ran (it did not wedge the object).
      const list = await req("GET", "/downpipes");
      ok("ALM-1: the DO is responsive after alarm()/setAlarm executed in workerd", list.status === 200 && Array.isArray(list.body));
    }
  } finally {
    await dispose();
  }

  const failures = done("SCHEDULER-DO RUNTIME (REAL WORKERD) VECTORS PASS");
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
