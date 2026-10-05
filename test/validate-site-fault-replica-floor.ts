// Site fault 1 of 3: the replica anti-rollback floor write (scheduler DO, POST /replication/record).
//
// A replicate pass reports an ok copy at index N; the DO then raises that replica's RUNLOG floor to N. When the
// floor write throws, the catch keeps the old floor. Before site faults it recorded nothing, so a later restore
// from that replica would not refuse an older RUNLOG and the pack could not say why.
//
// The proof: two worlds, identical except that the floor write throws in one. The real SchedulerDO serves both;
// the real buildSupportBundle builds a pack from each.
//   - The fault world's pack must differ from its healthy twin, and only under siteFaults.
//   - siteFaults must name sched.replica-floor-write with its class and legend line.
//   - The sentinel planted in the thrown error must reach neither the pack nor DO storage.
//
// Run: node test/validate-site-fault-replica-floor.ts

import { diffPaths, normalise, ok, packOver, SENTINEL, sentinelError, siteFaultRows, storageText, stubOver, tally } from "./lib/site-fault-proof.ts";
import { makeScheduler, stubFetch } from "./validate-scheduler-shared.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const DESTS = { list: [{ id: "d1", name: "Primary", provider: "r2", bucket: "b1" }, { id: "d2", name: "Replica", provider: "r2", bucket: "b2" }], defaultId: "d1" };

async function world(fault: boolean, errName = "Error"): Promise<{ pack: Record<string, unknown>; stored: string }> {
  const { storage, stub: dobj } = makeScheduler();
  await storage.put("destinations", DESTS);
  if (fault) {
    const put = storage.put.bind(storage);
    storage.put = (async (key: unknown, value: unknown) => {
      if (key === "runlogFloor") throw sentinelError(errName);
      return put(key as string, value);
    }) as typeof storage.put;
  }
  const res = await stubFetch(dobj, "POST", "/replication/record", { id: "p1", destinationId: "d2", ok: true, runId: "01JAAAAAAAAAAAAAAAAAAAAAAA", index: 7 });
  ok(`${fault ? "fault" : "healthy"} world: the replication record still answers 200`, res.status === 200);
  const pack = await packOver({}, stubOver(dobj));
  return { pack, stored: storageText(storage) };
}

async function main(): Promise<void> {
  console.log("the replica floor write fails; the pack must name it:");
  const healthy = await world(false);
  const faulty = await world(true);
  ok("control: the healthy world's pack carries no siteFaults", siteFaultRows(healthy.pack).length === 0);
  const diff = diffPaths(normalise(healthy.pack), normalise(faulty.pack));
  console.log(`  pack paths that differ between the healthy and fault worlds: ${diff.length === 0 ? "none" : diff.join(", ")}`);
  ok("the fault world's pack differs from its healthy twin", diff.length > 0);
  ok("every differing path is under siteFaults or the section summary", diff.length > 0 && diff.every((p) => p.startsWith("$.siteFaults") || p.startsWith("$.sections") || p.startsWith("$.sectionsSummary")));
  const row = siteFaultRows(faulty.pack).find((r) => r.id === "sched.replica-floor-write");
  ok("siteFaults names sched.replica-floor-write", row !== undefined);
  ok("the row carries the closed class of the thrown error (error)", row?.cls === "error");
  ok("the row carries a count and first/last times", row?.count === 1 && typeof row?.firstAt === "string" && typeof row?.lastAt === "string");
  ok("the row carries its legend line (subsystem, what failed, fix class)", row?.subsystem === "replication" && typeof row?.what === "string" && String(row?.what).length > 20 && row?.fixClass === "storage-health");

  console.log("redaction:");
  ok("the sentinel from the error's message, stack, cause and own property is not in the pack", !JSON.stringify(faulty.pack).includes(SENTINEL));
  ok("the sentinel is not in any value the scheduler DO stored", !faulty.stored.includes(SENTINEL));
  const renamed = await world(true, SENTINEL);
  const rrow = siteFaultRows(renamed.pack).find((r) => r.id === "sched.replica-floor-write");
  ok("an error whose name is the sentinel is recorded as class other, and the name does not ride", rrow?.cls === "other" && !JSON.stringify(renamed.pack).includes(SENTINEL) && !renamed.stored.includes(SENTINEL));

  const { failures, checks } = tally();
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-site-fault-replica-floor (${failures} failure(s) of ${checks})`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
