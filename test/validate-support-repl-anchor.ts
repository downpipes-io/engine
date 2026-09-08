// THE REVERSAL: can the pack tell "configured five minutes ago" from "has held no copy since March"?
//
// The never-reported-replication signal was previously withheld until the bot could model which
// destinations a downpipe actually fans out to -- the engine
// now projects that fan-out (configuredIds / neverReportedIds), so that half is met. But the criterion behind
// the criterion is the false-positive one: a destination configured minutes ago has reported no heartbeat, and
// so has a destination that has silently held nothing since March. Fire on the first and the bot cries wolf at
// the customer who did nothing wrong, which devalues every true finding it will ever report.
//
// The ANCHOR is the discriminator, and this suite is its proof. It drives:
//   1. the pure producer (nextReplAnchors / replNeverReportedSince): preserve, add, drop, and the honest
//      absence when a destination has no anchor at all,
//   2. the REAL SchedulerDO: the upsert stamps the anchor, a successful run advances the monotone counter, a
//      FAILED run does not (a downpipe whose runs all fail owes its replicas no copy), an unrelated edit does
//      NOT reset a months-old anchor, and a legacy record is BACKFILLED at the current head (conservative),
//   3. the PACK: the two states -- the destination added today and the destination dark since March -- which
//      were byte-identical rows, and must not be any more.
//
// Run: node test/validate-support-repl-anchor.ts

import { buildSupportBundle } from "../src/admin/support.ts";
import type { Env } from "../src/env.d.ts";
import { nextReplAnchors, replNeverReportedSince } from "../src/sched/destinations.ts";
import type { DownpipeState } from "../src/sched/types.ts";
import { makeConfig, makeScheduler, stubFetch } from "./validate-scheduler-shared.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- 1. the pure producer -------------------------------------------------------------------------------
function pureAnchors(): void {
  console.log("\nthe anchor producer (nextReplAnchors / replNeverReportedSince):");

  ok("a downpipe with NO configured fan-out gets no anchor map (an env-default downpipe names nothing to fail)", nextReplAnchors(undefined, [], 4) === undefined);
  ok("a destination NEW to the list anchors at the CURRENT count (it is owed no copy yet)", JSON.stringify(nextReplAnchors(undefined, ["d1", "d2"], 6)) === JSON.stringify({ d1: 6, d2: 6 }));
  ok("an EXISTING anchor is preserved across an edit (a rename cannot restart a months-old clock)", nextReplAnchors({ d1: 0, d2: 0 }, ["d1", "d2"], 40)?.d2 === 0);
  ok("a destination ADDED to an old downpipe anchors at the current count, beside the old anchors", JSON.stringify(nextReplAnchors({ d1: 0 }, ["d1", "d3"], 40)) === JSON.stringify({ d1: 0, d3: 40 }));
  ok("a destination REMOVED from the list drops its anchor (re-adding it starts the count again)", nextReplAnchors({ d1: 0, d2: 0 }, ["d1"], 40)?.d2 === undefined);
  ok("a corrupt anchor ABOVE the head is clamped to the head, never to a negative age", nextReplAnchors({ d1: 999 }, ["d1"], 5)?.d1 === 5);

  const dark = replNeverReportedSince(["d2"], { d1: 0, d2: 0 }, 40);
  ok("READ: a destination configured before 40 successful backups reads since=40", dark.maxSince === 40 && dark.unanchored === 0);
  const fresh = replNeverReportedSince(["d3"], { d1: 0, d3: 40 }, 40);
  ok("READ: a destination configured at the current head reads since=0 (nothing is owed)", fresh.maxSince === 0 && fresh.unanchored === 0);
  const both = replNeverReportedSince(["d2", "d3"], { d2: 0, d3: 40 }, 40);
  ok("READ: with a new AND a long-dark destination, the MAXIMUM rides (the worst one is the one to tell)", both.maxSince === 40);
  const legacy = replNeverReportedSince(["d2"], undefined, 40);
  ok("READ: an UNANCHORED destination is counted, never guessed at (no since is forged)", legacy.maxSince === undefined && legacy.unanchored === 1);
  const zero = replNeverReportedSince(["d2"], { d2: 0 }, 0);
  ok("READ: since=0 is EMITTED, not swallowed as absent (0 means 'no backup has succeeded since you added it')", zero.maxSince === 0);
}

// ---- 2. the real SchedulerDO ----------------------------------------------------------------------------
const DESTS = {
  list: [
    { id: "d1", name: "Primary", provider: "r2", bucket: "b1" },
    { id: "d2", name: "Replica", provider: "r2", bucket: "b2" },
    { id: "d3", name: "Third", provider: "r2", bucket: "b3" },
  ],
  defaultId: "d1",
};

async function completed(dobj: ReturnType<typeof makeScheduler>["stub"], id: string, okRun: boolean): Promise<void> {
  const trig = await stubFetch(dobj, "POST", "/trigger", { id });
  const t = (await trig.json()) as { runId: string; index: number };
  await stubFetch(dobj, "POST", "/complete", {
    id,
    index: t.index,
    runId: okRun ? t.runId : "",
    status: okRun ? "ok" : "failed",
    ...(okRun ? { destinationId: "d1" } : {}),
  });
}

async function doAnchors(): Promise<void> {
  console.log("\nthe SchedulerDO: the anchor is stamped, advanced by SUCCESS only, and never reset by an edit:");

  const { storage, stub: dobj } = makeScheduler();
  await storage.put("destinations", DESTS);
  const read = async (id: string): Promise<DownpipeState> => (await storage.get(`dp:${id}`)) as DownpipeState;

  await stubFetch(dobj, "POST", "/downpipes", makeConfig("p1", { destinationIds: ["d1", "d2"] }));
  ok("the upsert stamps an anchor for EVERY configured destination, at count 0", JSON.stringify((await read("p1")).replAnchors) === JSON.stringify({ d1: 0, d2: 0 }));
  ok("a fresh downpipe carries no sealed-run count yet (absent, not a forged 0)", (await read("p1")).sealedRuns === undefined);

  await completed(dobj, "p1", false);
  ok("a FAILED run does NOT advance the counter (a downpipe whose runs fail owes its replicas no copy)", ((await read("p1")).sealedRuns ?? 0) === 0);

  await completed(dobj, "p1", true);
  await completed(dobj, "p1", true);
  ok("two SUCCESSFUL runs advance the monotone counter to 2", (await read("p1")).sealedRuns === 2);
  ok("the anchors are untouched by the runs, so d2's silence is now two backups deep", JSON.stringify((await read("p1")).replAnchors) === JSON.stringify({ d1: 0, d2: 0 }));

  // A rename must not restart the clock on the destination that is failing.
  await stubFetch(dobj, "POST", "/downpipes", makeConfig("p1", { name: "renamed", destinationIds: ["d1", "d2"] }));
  const edited = await read("p1");
  ok("an unrelated EDIT preserves the anchors (a rename cannot mask a fault by resetting its age)", JSON.stringify(edited.replAnchors) === JSON.stringify({ d1: 0, d2: 0 }));
  ok("the edit preserves the sealed-run count too (it counts successful backups for all time)", edited.sealedRuns === 2);

  // The destination added TODAY, on a downpipe with a long run history: it must anchor at the head, so it can
  // never be reported as failing on the day it was added.
  await stubFetch(dobj, "POST", "/downpipes", makeConfig("p1", { destinationIds: ["d1", "d2", "d3"] }));
  const added = await read("p1");
  ok("a destination added TODAY anchors at the CURRENT count, so it is owed nothing yet", added.replAnchors?.d3 === 2);
  ok("adding it did not disturb the destination that has been dark since the beginning", added.replAnchors?.d2 === 0);

  // The LEGACY record (persisted before the anchor existed): backfilled on the next successful run, at the
  // head, which understates its age. Conservative on purpose.
  await storage.put("dp:old", {
    config: makeConfig("old", { destinationIds: ["d1", "d2"] }),
    nextRunAt: Date.now(),
    lastRunId: null,
    inFlight: false,
  });
  await completed(dobj, "old", true);
  const backfilled = await read("old");
  ok("a LEGACY record with no anchor is backfilled on its next successful run", backfilled.replAnchors?.d2 === 1);
  ok("the backfill anchors at the head, so the pack claims NO history it did not observe (since=0)", replNeverReportedSince(["d2"], backfilled.replAnchors, backfilled.sealedRuns ?? 0).maxSince === 0);
}

// ---- 3. the pack ----------------------------------------------------------------------------------------
// TWO DESTINATIONS THAT HAVE NEVER REPORTED. One was configured today. One has held no copy of any backup
// since March. Without the anchor these would be the same row.
const FLEET = [
  { config: { id: "new", name: "new", source: { type: "kv", binding: "KV", namespaceId: "ns" }, destinationIds: ["d1", "d2"] }, sealedRuns: 12, replAnchors: { d1: 0, d2: 12 } },
  { config: { id: "dark", name: "dark", source: { type: "kv", binding: "KV", namespaceId: "ns" }, destinationIds: ["d1", "d2"] }, sealedRuns: 90, replAnchors: { d1: 0, d2: 0 } },
  { config: { id: "legacy", name: "legacy", source: { type: "kv", binding: "KV", namespaceId: "ns" }, destinationIds: ["d1", "d2"] }, sealedRuns: 90 },
  // THE DOUBLE-COUNT. This config names d2 TWICE. The anchor map is stamped from allDestinationIds (primary +
  // DE-DUPLICATED replicas, which is what the run path writes to), so it holds ONE key for d2. The pack's
  // configured list must match the anchor keys, or a duplicated id would inflate neverReportedCount, and the
  // count is what the bot thresholds on. One destination is silent here, and the count must say one.
  { config: { id: "dupe", name: "dupe", source: { type: "kv", binding: "KV", namespaceId: "ns" }, destinationIds: ["d1", "d2", "d2"] }, sealedRuns: 90, replAnchors: { d1: 0, d2: 0 } },
];
const HEARTBEATS = {
  new: { d1: { lastOk: true, lastAttemptAt: 1, holdsIndex: 12, holdsRunId: "01A" } },
  dark: { d1: { lastOk: true, lastAttemptAt: 1, holdsIndex: 90, holdsRunId: "01B" } },
  legacy: { d1: { lastOk: true, lastAttemptAt: 1, holdsIndex: 90, holdsRunId: "01C" } },
  dupe: { d1: { lastOk: true, lastAttemptAt: 1, holdsIndex: 90, holdsRunId: "01D" } },
};

function packStub(): DurableObjectStub {
  return {
    fetch: async (input: string | URL): Promise<Response> => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      const json = (v: unknown): Response => new Response(JSON.stringify(v), { status: 200, headers: { "content-type": "application/json" } });
      if (url.pathname === "/replication") return json({ byDownpipe: HEARTBEATS });
      if (url.pathname === "/downpipes") return json(FLEET);
      return json({});
    },
  } as unknown as DurableObjectStub;
}

async function pack(): Promise<void> {
  console.log("\nthe pack: the new destination and the long-dark destination are no longer the same row:");

  const bundle = await buildSupportBundle({} as unknown as Env, packStub());
  const rows = (bundle.downpipes ?? []) as Array<Record<string, unknown>>;
  const repl = (id: string): Record<string, unknown> => ((rows.find((d) => d.id === id) ?? {}).replication ?? {}) as Record<string, unknown>;

  ok("BOTH destinations are still named never-reported (the fan-out join is unchanged)", repl("new").neverReportedCount === 1 && repl("dark").neverReportedCount === 1);
  ok("THE NEW DESTINATION reads since=0: no backup has succeeded since it was configured", repl("new").neverReportedSealedRunsSince === 0);
  ok("THE DARK DESTINATION reads since=90: ninety backups have succeeded and it holds none of them", repl("dark").neverReportedSealedRunsSince === 90);
  ok("THE REVERSAL CRITERION: the two rows are DISTINGUISHABLE, which is the whole bar the no-ship set", JSON.stringify(repl("new")) !== JSON.stringify(repl("dark")) && repl("new").neverReportedSealedRunsSince !== repl("dark").neverReportedSealedRunsSince);
  ok("THE LEGACY ROW claims no age at all: it is COUNTED as unanchored, never guessed at", repl("legacy").neverReportedSealedRunsSince === undefined && repl("legacy").neverReportedUnanchoredCount === 1);

  // THE DOUBLE-COUNT: one silent destination named twice in the config is ONE silent destination.
  const dupeIds = repl("dupe").neverReportedIds as string[] | undefined;
  ok("A DUPLICATED destination id counts ONCE: neverReportedCount is the number of silent DESTINATIONS", repl("dupe").neverReportedCount === 1);
  ok("A DUPLICATED destination id appears ONCE in neverReportedIds (the ids the bot names)", JSON.stringify(dupeIds) === JSON.stringify(["d2"]));
  ok("A DUPLICATED destination id appears ONCE in configuredIds (the configured set matches the anchor keys)", JSON.stringify(repl("dupe").configuredIds) === JSON.stringify(["d1", "d2"]));
  ok("THE DE-DUPLICATION does not change the AGE: the duplicated destination still reads its true since=90", repl("dupe").neverReportedSealedRunsSince === 90);

  const text = JSON.stringify(bundle);
  ok("REDACTION: the anchor rides as counts only, no timestamp of a customer event is added", !text.includes("configuredAt") && !text.includes("addedAt"));
}

async function main(): Promise<void> {
  pureAnchors();
  await doAnchors();
  await pack();
  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILED`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await main();
