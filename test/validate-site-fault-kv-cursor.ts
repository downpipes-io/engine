// Site fault 3 of 3: KV refuses a saved list cursor when a sliced backup resumes (KVSource.listKeysFrom).
//
// The catch falls back to re-listing from the watermark. The backup still completes, but each resumed slice
// reads more list pages than it should, and before site faults nothing recorded that the cursor was refused.
//
// This proof exercises the seal-side path: the catch notes the fault in the isolate that runs the listing, and
// the RunSealDO alarm entry drains the isolate's ledger to the scheduler DO when the alarm ends (here, an alarm
// on a DO with no run document, which returns at once). Two worlds: KV accepts the cursor, or KV refuses it.
//
// Run: node test/validate-site-fault-kv-cursor.ts

import type { Env } from "../src/env.d.ts";
import { RunSealDO } from "../src/seal/runseal-do.ts";
import { KVSource } from "../src/sources/kv.ts";
import { diffPaths, namespaceOver, normalise, ok, packOver, SENTINEL, sentinelError, siteFaultRows, storageText, stubOver, tally } from "./lib/site-fault-proof.ts";
import { makeScheduler } from "./validate-scheduler-shared.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

async function world(refuse: boolean): Promise<{ pack: Record<string, unknown>; stored: string; storedAfterAlarm: string; keys: string[] }> {
  const { storage, stub: dobj } = makeScheduler();
  const scheduler = stubOver(dobj);
  const kv = {
    async list(opts: { cursor?: string }): Promise<unknown> {
      if (opts.cursor !== undefined && refuse) throw sentinelError();
      if (opts.cursor !== undefined) return { keys: [{ name: "k3" }, { name: "k4" }], list_complete: true };
      return { keys: [{ name: "k1" }, { name: "k2" }, { name: "k3" }, { name: "k4" }], list_complete: true };
    },
  } as unknown as KVNamespace;
  const src = new KVSource(kv, "ns-1");
  const keys: string[] = [];
  for await (const ev of src.listKeysFrom({ include: [], exclude: [] }, JSON.stringify({ cursor: "c-saved", after: "k2" }))) keys.push(...ev.keys);
  // The alarm entry of the DO that ran the slice. No run document is stored, so it returns at once.
  const seal = new RunSealDO({ storage: { get: async () => undefined } } as unknown as DurableObjectState, { SCHEDULER: namespaceOver(scheduler) } as unknown as Env);
  await seal.alarm();
  const storedAfterAlarm = storageText(storage);
  const pack = await packOver({}, scheduler);
  return { pack, stored: storageText(storage), storedAfterAlarm, keys };
}

async function main(): Promise<void> {
  console.log("KV refuses the saved cursor; the backup continues and the pack must say why it was slow:");
  const healthy = await world(false);
  const faulty = await world(true);
  ok("control: the listing resumes past the watermark in both worlds (the fallback changes no keys)", JSON.stringify(healthy.keys) === JSON.stringify(["k3", "k4"]) && JSON.stringify(faulty.keys) === JSON.stringify(["k3", "k4"]));
  ok("control: the healthy world's pack carries no siteFaults", siteFaultRows(healthy.pack).length === 0);
  const diff = diffPaths(normalise(healthy.pack), normalise(faulty.pack));
  console.log(`  pack paths that differ between the healthy and fault worlds: ${diff.length === 0 ? "none" : diff.join(", ")}`);
  ok("the fault world's pack differs from its healthy twin", diff.length > 0);
  ok("every differing path is under siteFaults or the section summary", diff.length > 0 && diff.every((p) => p.startsWith("$.siteFaults") || p.startsWith("$.sections") || p.startsWith("$.sectionsSummary")));
  const row = siteFaultRows(faulty.pack).find((r) => r.id === "source.kv-resume-cursor");
  ok("siteFaults names source.kv-resume-cursor", row !== undefined);
  ok("the row carries class error and a count of 1", row?.cls === "error" && row?.count === 1);
  ok("the row carries its legend line", row?.subsystem === "sources" && row?.fixClass === "slow-path-fallback" && typeof row?.what === "string");
  ok("the row reached the scheduler DO's storage through the alarm drain (not only this isolate's memory)", faulty.storedAfterAlarm.includes("source.kv-resume-cursor"));

  console.log("redaction:");
  ok("the sentinel is not in the pack", !JSON.stringify(faulty.pack).includes(SENTINEL));
  ok("the sentinel is not in the scheduler DO's storage", !faulty.stored.includes(SENTINEL));

  const { failures, checks } = tally();
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-site-fault-kv-cursor (${failures} failure(s) of ${checks})`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
