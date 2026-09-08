// Due-time index vectors: due() in O(due) not O(N), the persisted index, and the
// reconciliation backstop. Covers index create/advance/delete on add/
// complete/remove/disable, brute-force parity, drift reconciliation, build-from-empty, the small-env
// transparency case and the O(due) cost at scale.
import {
  ok,
  MockStorage,
  makeScheduler,
  syncDueIndex,
  seedDueIndex,
  stubFetch,
  makeConfig,
  DUE_INDEX_PREFIX,
  pad16,
  INFLIGHT_LEASE_MS,
  LEASE_EXPIRED_MS,
} from "./validate-scheduler-shared.ts";
import type { SchedulerDOSurface } from "../src/sched/scheduler-do-base.ts";

export async function run(): Promise<void> {
  // helpers local to the index suite
  const dueKeys = (storage: MockStorage): string[] => storage.rawListKeys().filter((k) => k.startsWith(DUE_INDEX_PREFIX)).sort();
  const dueKeysFor = (storage: MockStorage, id: string): string[] => dueKeys(storage).filter((k) => k.endsWith(`:${id}`));

  // ---- TC-IDX-01: the index is CREATED on add, ADVANCED on completeRun, deleted on remove/disable --
  {
    const { stub, storage } = makeScheduler();

    // (a) CREATED on add: an enabled downpipe with a numeric nextRunAt gets exactly one due: entry,
    //     keyed by pad16(nextRunAt), pointing at its id.
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-idx", { enabled: true }));
    const created = storage.rawGet<{ nextRunAt: number }>("dp:dp-idx")!;
    const idxAfterAdd = dueKeysFor(storage, "dp-idx");
    ok("idx-create: add() writes exactly ONE due: entry for the new downpipe", idxAfterAdd.length === 1);
    ok("idx-create: the due: key encodes pad16(nextRunAt):id", idxAfterAdd[0] === `${DUE_INDEX_PREFIX}${pad16(created.nextRunAt)}:dp-idx`);

    // (b) ADVANCED on completeRun: after a run completes, the OLD due: key is gone and a NEW one at the
    //     advanced nextRunAt is present (completeRun reschedules forward through persistDownpipeState).
    const oldKey = idxAfterAdd[0]!;
    const t = await (await stubFetch(stub, "POST", "/trigger", { id: "dp-idx" })).json() as { runId: string; index: number };
    // trigger does not change nextRunAt, so the key is still the original one while in flight.
    ok("idx-trigger: the due: key is unchanged by trigger (nextRunAt not advanced yet)", dueKeysFor(storage, "dp-idx")[0] === oldKey);
    await stubFetch(stub, "POST", "/complete", { id: "dp-idx", runId: t.runId, index: t.index, status: "ok" });
    const advanced = storage.rawGet<{ nextRunAt: number }>("dp:dp-idx")!;
    const idxAfterComplete = dueKeysFor(storage, "dp-idx");
    ok("idx-advance: completeRun leaves exactly ONE due: entry (old deleted, new written)", idxAfterComplete.length === 1);
    ok("idx-advance: the OLD due: key is gone after completion", !dueKeys(storage).includes(oldKey));
    ok("idx-advance: the NEW due: key encodes the advanced nextRunAt", idxAfterComplete[0] === `${DUE_INDEX_PREFIX}${pad16(advanced.nextRunAt)}:dp-idx`);
    ok("idx-advance: the schedule actually advanced (new key differs from old)", idxAfterComplete[0] !== oldKey);

    // (c) DELETED on disable: re-upsert the same id DISABLED -> no due: entry (disabled downpipes are
    //     not indexed, so the dispatcher never even considers them).
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-idx", { enabled: false }));
    ok("idx-disable: disabling a downpipe removes its due: entry (no entry for a disabled pipe)", dueKeysFor(storage, "dp-idx").length === 0);

    // re-enable -> the entry comes back
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-idx", { enabled: true }));
    ok("idx-reenable: re-enabling re-creates exactly one due: entry", dueKeysFor(storage, "dp-idx").length === 1);

    // (d) DELETED on remove: /delete removes the due: entry as well as dp:/hist:.
    await stubFetch(stub, "POST", "/delete", { id: "dp-idx" });
    ok("idx-remove: removeDownpipe deletes the due: entry", dueKeysFor(storage, "dp-idx").length === 0);
    ok("idx-remove: no due: keys leak for a removed downpipe", dueKeys(storage).length === 0);
  }

  // ---- TC-IDX-02: PARITY: due() (index path) === brute-force listDownpipes().filter(...) ----------
  // The load-bearing equivalence: for a random fleet the index-driven due() must return EXACTLY the
  // same set as the old O(N) predicate over the full list. This is the zero-behaviour-change guarantee.
  {
    const { stub, storage } = makeScheduler();
    const now = Date.now();
    // A pseudo-random but DETERMINISTIC fleet (seeded LCG) so a failure reproduces. Mix every dimension
    // the predicate keys on: enabled/disabled, past/future nextRunAt, in-flight (fresh lease vs expired
    // lease), so the parity check exercises the full filter.
    let seed = 1234567;
    const rnd = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
    const FLEET = 60;
    for (let i = 0; i < FLEET; i++) {
      const id = `dp-par-${String(i).padStart(3, "0")}`;
      const enabled = rnd() > 0.3;
      await stubFetch(stub, "POST", "/downpipes", makeConfig(id, { enabled }));
      const ds = storage.rawGet<{ nextRunAt: number; inFlight: boolean; inFlightSince?: number }>(`dp:${id}`)!;
      // randomise nextRunAt around now (past or future)
      ds.nextRunAt = now + Math.floor((rnd() - 0.6) * 3_600_000);
      // randomly mark some in-flight: half of those with a FRESH lease (still leased), half EXPIRED.
      if (rnd() > 0.6) {
        ds.inFlight = true;
        ds.inFlightSince = rnd() > 0.5 ? now - 1000 /* fresh */ : now - LEASE_EXPIRED_MS /* expired */;
      }
      await storage.put(`dp:${id}`, ds);
      await syncDueIndex(storage, id);
    }

    // Brute force: the EXACT predicate due() applied before the index existed.
    const all = await stubFetch(stub, "GET", "/downpipes").then((r) => r.json()) as Array<{ config: { id: string; enabled: boolean }; nextRunAt: number; inFlight: boolean; inFlightSince?: number }>;
    // INFLIGHT_LEASE_MS is imported from the production DO (via the shared module), not mirrored, so the
    // brute-force lease check can never silently diverge from the indexed due() if the DO constant changes.
    const leasedBrute = (d: { inFlight: boolean; inFlightSince?: number }): boolean => d.inFlight && d.inFlightSince !== undefined && now - d.inFlightSince <= INFLIGHT_LEASE_MS;
    const brute = new Set(all.filter((d) => d.config.enabled && !leasedBrute(d) && d.nextRunAt <= now).map((d) => d.config.id));

    // Index path:
    const { due } = await stubFetch(stub, "GET", "/due").then((r) => r.json()) as { due: Array<{ config: { id: string } }> };
    const indexed = new Set(due.map((d) => d.config.id));

    // Sets must be IDENTICAL (same size, every brute member present in index and vice versa).
    let parity = brute.size === indexed.size;
    for (const id of brute) if (!indexed.has(id)) parity = false;
    for (const id of indexed) if (!brute.has(id)) parity = false;
    ok(`idx-parity: due() returns the SAME set as the brute-force filter (brute=${brute.size}, index=${indexed.size})`, parity);
    ok("idx-parity: due() returned a NON-empty set (the fleet has due pipes; a vacuous pass is not accepted)", indexed.size > 0);
    ok("idx-parity: due() never returns a disabled pipe", due.every((d) => all.find((a) => a.config.id === d.config.id)?.config.enabled === true));
  }

  // ---- TC-IDX-03: RECONCILIATION: inject drift, due() misses it, rebuildDueIndex() heals it -------
  {
    const { stub, storage } = makeScheduler();
    // Two enabled, due downpipes; both are indexed and both appear in due().
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-rec-a", { enabled: true }));
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-rec-b", { enabled: true }));
    for (const id of ["dp-rec-a", "dp-rec-b"]) {
      const ds = storage.rawGet<{ nextRunAt: number }>(`dp:${id}`)!;
      ds.nextRunAt = Date.now() - 10_000; // due
      await storage.put(`dp:${id}`, ds);
      await syncDueIndex(storage, id);
    }
    const { due: dueBefore } = await stubFetch(stub, "GET", "/due").then((r) => r.json()) as { due: Array<{ config: { id: string } }> };
    ok("idx-reconcile: both due pipes present before drift", dueBefore.some((d) => d.config.id === "dp-rec-a") && dueBefore.some((d) => d.config.id === "dp-rec-b"));

    // INJECT DRIFT: delete dp-rec-b's index entry directly (simulating a missed write / manual edit),
    // WITHOUT touching its dp: state. The dp: truth still says it is enabled + due.
    for (const k of dueKeysFor(storage, "dp-rec-b")) await storage.delete(k);
    ok("idx-reconcile: precondition, dp-rec-b's index entry was deleted (drift injected)", dueKeysFor(storage, "dp-rec-b").length === 0);

    // due() now MISSES dp-rec-b (the index no longer points at it), proving the index is the read path.
    // (We bypass the periodic/lazy reconcile by reading the raw index range the way due() does, so this
    // assertion is about the index state, not whatever a reconcile might have just rebuilt.)
    const now2 = Date.now();
    const rangeMiss = await storage.list<unknown>({ start: DUE_INDEX_PREFIX, end: `${DUE_INDEX_PREFIX}${pad16(now2 + 1)}` });
    const missedIds = new Set([...rangeMiss.keys()].map((k) => k.slice(DUE_INDEX_PREFIX.length + 16 + 1)));
    ok("idx-reconcile: with drift, the index range no longer contains dp-rec-b (due() would miss it)", !missedIds.has("dp-rec-b") && missedIds.has("dp-rec-a"));

    // HEAL: run the reconciliation backstop directly. It rebuilds the index from the dp: truth. The cast
    // is to the production SchedulerDOSurface interface (which declares rebuildDueIndex as part of the
    // testable contract), so a rename or signature change in the DO fails the typecheck here rather than
    // silently at runtime.
    await (stub as unknown as SchedulerDOSurface).rebuildDueIndex();
    ok("idx-reconcile: rebuildDueIndex re-creates dp-rec-b's index entry from dp: truth", dueKeysFor(storage, "dp-rec-b").length === 1);

    // due() now finds it again (drift self-healed; a drifted downpipe is recovered, never lost).
    const { due: dueAfter } = await stubFetch(stub, "GET", "/due").then((r) => r.json()) as { due: Array<{ config: { id: string } }> };
    ok("idx-reconcile: after rebuild, due() finds the previously-drifted downpipe again", dueAfter.some((d) => d.config.id === "dp-rec-b"));
    ok("idx-reconcile: the other downpipe is still present (rebuild did not drop it)", dueAfter.some((d) => d.config.id === "dp-rec-a"));
  }

  // ---- TC-IDX-04: BUILD-FROM-EMPTY: several dp: states, no due: keys -> reconcile builds correctly --
  // The first-deploy case: a DO upgraded to this version has dp: records (written by the old code) but
  // NO due: index yet. The reconcile must build the index from the dp: truth so nothing is missed.
  {
    const { stub, storage } = makeScheduler();
    // Seed dp: states DIRECTLY with NO index entries (the pre-index on-disk shape). Mix enabled/disabled
    // and due/future so the build is non-trivial.
    const now = Date.now();
    const seedRaw = async (id: string, enabled: boolean, nextRunAt: number) => {
      await storage.put(`dp:${id}`, { config: makeConfig(id, { enabled }), nextRunAt, lastRunId: null, inFlight: false });
    };
    await seedRaw("dp-emp-due1", true, now - 5_000);   // enabled + due -> should end up indexed AND in due()
    await seedRaw("dp-emp-due2", true, now - 60_000);  // enabled + due
    await seedRaw("dp-emp-fut", true, now + 3_600_000); // enabled + future -> indexed but NOT due
    await seedRaw("dp-emp-dis", false, now - 5_000);    // disabled + due -> NOT indexed, NOT due
    ok("idx-empty: precondition, dp: states exist but the due: index is empty", storage.rawListKeys().some((k) => k.startsWith("dp:")) && dueKeys(storage).length === 0);

    // due() itself must heal this lazily (empty index + non-empty dp: triggers a rebuild inside due()).
    const { due } = await stubFetch(stub, "GET", "/due").then((r) => r.json()) as { due: Array<{ config: { id: string } }> };
    const ids = new Set(due.map((d) => d.config.id));
    ok("idx-empty: due() lazily built the index and returned both enabled+due pipes", ids.has("dp-emp-due1") && ids.has("dp-emp-due2"));
    ok("idx-empty: due() excluded the enabled-but-future pipe", !ids.has("dp-emp-fut"));
    ok("idx-empty: due() excluded the disabled pipe", !ids.has("dp-emp-dis"));
    ok("idx-empty: exactly the two due pipes were returned", ids.size === 2);
    // And the index was actually populated (enabled pipes only): due1, due2, fut = 3 entries; dis = none.
    ok("idx-empty: the lazy rebuild populated the index for all THREE enabled pipes (incl. the future one)", dueKeys(storage).length === 3);
    ok("idx-empty: the disabled pipe got no index entry even after the rebuild", dueKeysFor(storage, "dp-emp-dis").length === 0);
  }

  // ---- TC-IDX-05: SMALL ENV: a 3-downpipe account schedules EXACTLY as before --------------------
  // Zero behaviour change for small fleets: the index is transparent. Three pipes (one due, one future,
  // one disabled-and-due) yield precisely the one expected due pipe.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-sm-due", { enabled: true }));
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-sm-future", { enabled: true }));
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-sm-disabled", { enabled: false }));
    // Backdate the "due" one; the "future" one keeps its default (a full cadence out); disable stays.
    const due1 = storage.rawGet<{ nextRunAt: number }>("dp:dp-sm-due")!;
    due1.nextRunAt = Date.now() - 1000;
    await storage.put("dp:dp-sm-due", due1);
    await syncDueIndex(storage, "dp-sm-due");
    const disabled = storage.rawGet<{ nextRunAt: number }>("dp:dp-sm-disabled")!;
    disabled.nextRunAt = Date.now() - 1000; // due-by-time but disabled
    await storage.put("dp:dp-sm-disabled", disabled);
    await syncDueIndex(storage, "dp-sm-disabled");

    const { due } = await stubFetch(stub, "GET", "/due").then((r) => r.json()) as { due: Array<{ config: { id: string } }> };
    ok("idx-small: exactly one pipe is due in a 3-pipe account", due.length === 1);
    ok("idx-small: the due pipe is the backdated enabled one", due[0]?.config.id === "dp-sm-due");
    ok("idx-small: the future pipe is excluded", !due.some((d) => d.config.id === "dp-sm-future"));
    ok("idx-small: the disabled-but-past pipe is excluded", !due.some((d) => d.config.id === "dp-sm-disabled"));
  }

  // ---- TC-IDX-06: O(due): at large N, due() reads only the due CANDIDATES, not the whole fleet -----
  // The scale guarantee. Seed a large fleet where only a SMALL fraction is due, then assert the due()
  // index range-scan returns a page sized by the DUE set, not the fleet. The MockStorage here honours
  // { start, end } (so the range scan is real) and records per-call key counts (listKeysScanned).
  {
    const { stub, storage } = makeScheduler();
    const N = 2000;     // fleet size
    const DUE_N = 25;   // only these are due
    const now = Date.now();
    for (let i = 0; i < N; i++) {
      const id = `dp-scale-${String(i).padStart(5, "0")}`;
      // First DUE_N are due (past); the rest are far in the future. All enabled.
      const nextRunAt = i < DUE_N ? now - 60_000 : now + 7 * 24 * 3_600_000;
      await storage.put(`dp:${id}`, { config: makeConfig(id, { enabled: true }), nextRunAt, lastRunId: null, inFlight: false });
      // seedDueIndex writes the index entry directly (no per-id full prefix scan), so seeding N pipes is
      // O(N) not O(N^2); the fleet is fresh so there is no stale entry to clear (engine-test-018-06).
      await seedDueIndex(storage, id);
    }
    ok("idx-bigO: precondition, the fleet is large and the index has one entry per pipe", storage.rawListKeys().filter((k) => k.startsWith("dp:")).length === N && dueKeys(storage).length === N);

    // Reset the per-call scan recorder, then call due() ONCE via the route.
    storage.listKeysScanned = [];
    const { due } = await stubFetch(stub, "GET", "/due").then((r) => r.json()) as { due: Array<{ config: { id: string } }> };
    ok("idx-bigO: due() returns exactly the DUE subset at scale", due.length === DUE_N);

    // The due() RANGE scan (the candidate fetch) must have returned only ~DUE_N keys, NOT N. due() also
    // makes a couple of tiny limit:1 probe lists (the reconcile detector) and per-candidate dp: GETs, but
    // NO list() call may return anywhere near the whole fleet; that is the O(due)-not-O(N) property.
    const maxPage = Math.max(...storage.listKeysScanned);
    ok(`idx-bigO: no list() page returned near the whole fleet (max page ${maxPage} << N=${N})`, maxPage < DUE_N * 4 && maxPage < N / 10);
    // Belt-and-braces: the range scan specifically returned exactly DUE_N candidate keys.
    const rangeNow = await storage.list<unknown>({ start: DUE_INDEX_PREFIX, end: `${DUE_INDEX_PREFIX}${pad16(Date.now() + 1)}` });
    ok("idx-bigO: the due-index range scan returns exactly the DUE candidates (O(due))", rangeNow.size === DUE_N);
  }
}
