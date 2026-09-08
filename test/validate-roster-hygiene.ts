// Prove the roster-hygiene analysis, the deterministic repair plan, and the DO shells (the
// removeDownpipe ghost sweep, rosterHygiene, reconcileRoster) with in-memory doubles only.
// No network, no deploy, no cost. Run:
//   node test/validate-roster-hygiene.ts
//
// THE CASE this guards (the "permanent grey line on the map" support question): a dp: row whose
// storage key does not name its embedded config.id renders on the console (list and map key off the
// embedded id) yet POST /downpipes/delete can never remove it (it deletes dp:<config.id>, which is a
// different key), so the map shows an undeletable "Unknown" edge forever. The sweep makes the normal
// delete remove such ghosts; the hygiene report names them (the support pack projects it); the
// reconcile heals a whole roster back to the "key = config.id" invariant while ABSTAINING from
// anything that is a valid config (never-ran rows are reported, never repaired).

import {
  analyseRoster,
  planRosterRepair,
  embeddedConfigId,
  ROSTER_LIST_CAP,
  type RosterRepairAction,
} from "../src/sched/roster-hygiene.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";
import { ok, getFailures, makeScheduler, makeConfig, DUE_INDEX_PREFIX } from "./validate-scheduler-shared.ts";

// state builds a minimal well-formed DownpipeState for direct storage seeding (the ghost tests write
// raw rows on purpose; production never writes these shapes, which is exactly the point).
function state(id: string, overrides: Partial<DownpipeState> = {}): DownpipeState {
  return { config: makeConfig(id), nextRunAt: Date.now() + 60_000, lastRunId: null, inFlight: false, ...overrides };
}

function planActs(plan: RosterRepairAction[]): string {
  return plan.map((a) => `${a.act}:${a.key}${a.act === "rehome" ? `->${a.toId}` : ""}`).join(",");
}

async function main(): Promise<void> {
  console.log("roster-hygiene: pure analysis");
  {
    ok("embeddedConfigId reads a well-formed value", embeddedConfigId(state("a")) === "a");
    ok("embeddedConfigId is null for a malformed value", embeddedConfigId({ junk: 1 }) === null && embeddedConfigId(null) === null && embeddedConfigId("s") === null);

    const entries = new Map<string, unknown>([
      ["dp:healthy", state("healthy", { lastRunId: "run-1" })],
      ["dp:ghost-key", state("real-id")], // key-id mismatch
      ["dp:broken", { config: { name: "no id" } }], // malformed
      ["dp:fresh", state("fresh")], // well-formed, never ran, enabled
      ["dp:failed-only", state("failed-only")], // never SUCCEEDED but HAS run (ring below)
    ]);
    const report = analyseRoster(entries, new Set(["failed-only"]));
    ok("scanned counts every row", report.scanned === 5);
    ok("ghostCount is exact", report.ghostCount === 2);
    ok("mismatch ghost named with its embedded id", report.ghosts.some((g) => g.key === "dp:ghost-key" && g.kind === "key-id-mismatch" && g.embeddedId === "real-id"));
    ok("malformed ghost named with a null embedded id", report.ghosts.some((g) => g.key === "dp:broken" && g.kind === "malformed" && g.embeddedId === null));
    ok("never-ran reports the fresh pipe only", report.neverRanCount === 1 && report.neverRan[0]?.id === "fresh" && report.neverRan[0]?.enabled === true);
    ok("a ring with only failed runs is NOT never-ran (lastRunId alone must not decide)", !report.neverRan.some((n) => n.id === "failed-only"));
    ok("a healthy run is not never-ran", !report.neverRan.some((n) => n.id === "healthy"));
  }

  {
    // An in-flight FIRST run is not a standing unknown (the map shows it running): excluded.
    const entries = new Map<string, unknown>([["dp:starting", state("starting", { inFlight: true })]]);
    const report = analyseRoster(entries, new Set());
    ok("an in-flight first run is not reported never-ran", report.neverRanCount === 0);
  }

  {
    // The report lists are bounded; the counts stay exact.
    const entries = new Map<string, unknown>();
    for (let i = 0; i < ROSTER_LIST_CAP + 10; i++) entries.set(`dp:m${String(i).padStart(3, "0")}`, { junk: i });
    const report = analyseRoster(entries, new Set());
    ok("ghost list capped at ROSTER_LIST_CAP", report.ghosts.length === ROSTER_LIST_CAP);
    ok("ghostCount stays exact past the cap", report.ghostCount === ROSTER_LIST_CAP + 10);
  }

  console.log("roster-hygiene: repair plan");
  {
    const entries = new Map<string, unknown>([
      ["dp:healthy", state("healthy")],
      ["dp:broken", { nope: true }],
      ["dp:ghost-with-twin", state("healthy")], // mismatch, healthy twin exists
      ["dp:ghost-lone", state("lost-id")], // mismatch, no twin: rehome
      ["dp:ghost-lone-2", state("lost-id")], // second claimant of the same id: delete after the rehome
    ]);
    const plan = planRosterRepair(entries);
    ok("well-formed rows are never in the plan", !plan.some((a) => a.key === "dp:healthy"));
    ok("malformed row is delete-ghost", plan.some((a) => a.act === "delete-ghost" && a.key === "dp:broken"));
    ok("twinned mismatch is delete-ghost (the twin is authoritative)", plan.some((a) => a.act === "delete-ghost" && a.key === "dp:ghost-with-twin"));
    ok("twinless mismatch is rehomed (state preserved)", plan.some((a) => a.act === "rehome" && a.key === "dp:ghost-lone" && a.toId === "lost-id"));
    ok("second twinless claimant of the same id is delete-ghost (ascending-first survives)", plan.some((a) => a.act === "delete-ghost" && a.key === "dp:ghost-lone-2"), );
    ok("plan is deterministic regardless of map order", planActs(planRosterRepair(new Map([...entries.entries()].reverse()))) === planActs(plan));
  }

  console.log("roster-hygiene: removeDownpipe ghost sweep (the undeletable grey line dies)");
  {
    const { storage, stub } = makeScheduler();
    await stub.addDownpipe(makeConfig("real"));
    // Seed the ghost RAW: a row claiming id "real" under the wrong key, with residue under its
    // key suffix, exactly the shape a historical writer fault leaves behind.
    await storage.put("dp:stale-key", state("real"));
    await storage.put("hist:stale-key", [{ runId: "r0", index: 0, status: "ok", startedAt: new Date().toISOString() }]);
    const res = await stub.removeDownpipe({ id: "real" });
    ok("delete reports deleted", res.deleted === true);
    ok("delete swept exactly the one ghost", res.swept === 1);
    ok("canonical row gone", storage.rawGet("dp:real") === undefined);
    ok("ghost row gone", storage.rawGet("dp:stale-key") === undefined);
    ok("ghost residue ring gone", storage.rawGet("hist:stale-key") === undefined);
  }

  {
    // The mismatch-ONLY shape (no canonical row at all): without the sweep, the console's delete would return
    // deleted:false forever here; the sweep makes it succeed.
    const { storage, stub } = makeScheduler();
    await storage.put("dp:only-ghost", state("visible-id"));
    const res = await stub.removeDownpipe({ id: "visible-id" });
    ok("a swept ghost counts as a deletion even with no canonical key", res.deleted === true && res.swept === 1);
    ok("ghost gone", storage.rawGet("dp:only-ghost") === undefined);
  }

  {
    // A normal delete (no ghosts anywhere) is unchanged: deleted true, no swept field.
    const { storage, stub } = makeScheduler();
    await stub.addDownpipe(makeConfig("plain"));
    const res = await stub.removeDownpipe({ id: "plain" });
    ok("plain delete unchanged (deleted, no sweep field)", res.deleted === true && res.swept === undefined);
    ok("plain delete removes the row", storage.rawGet("dp:plain") === undefined);
    const miss = await stub.removeDownpipe({ id: "absent" });
    ok("deleting an absent id still reports deleted:false", miss.deleted === false && miss.swept === undefined);
  }

  console.log("roster-hygiene: DO report + reconcile");
  {
    const { storage, stub } = makeScheduler();
    await stub.addDownpipe(makeConfig("healthy"));
    await stub.addDownpipe(makeConfig("fresh")); // never ran: reported, never repaired
    await storage.put("dp:bad-key", state("lost-id", { lastRunId: "run-9" }));
    await storage.put("hist:bad-key", [{ runId: "run-9", index: 3, status: "ok", startedAt: new Date().toISOString() }]);
    await storage.put("dp:junk", { widget: true });

    const report = await stub.rosterHygiene();
    ok("report sees both ghosts", report.ghostCount === 2);
    ok("report names the mismatch", report.ghosts.some((g) => g.key === "dp:bad-key" && g.embeddedId === "lost-id"));
    ok("report includes never-ran rows (healthy has no run yet either: both are never-ran)", report.neverRanCount === 2);

    const healed = await stub.reconcileRoster();
    ok("reconcile removed the malformed row", healed.removed === 1);
    ok("reconcile rehomed the twinless mismatch", healed.rehomed === 1);
    ok("reconcile reports a clean roster after", healed.ghostsRemaining === 0);
    ok("rehomed row lives under its embedded id", storage.rawGet("dp:lost-id") !== undefined);
    ok("rehomed row keeps its state", (storage.rawGet<DownpipeState>("dp:lost-id"))?.lastRunId === "run-9");
    ok("rehomed ring moved with it", Array.isArray(storage.rawGet("hist:lost-id")));
    ok("old ghost key gone", storage.rawGet("dp:bad-key") === undefined && storage.rawGet("hist:bad-key") === undefined);
    ok("malformed row gone", storage.rawGet("dp:junk") === undefined);
    ok("valid never-ran configs untouched (abstain)", storage.rawGet("dp:fresh") !== undefined && storage.rawGet("dp:healthy") !== undefined);
    // The rebuilt due index covers exactly the enabled well-formed rows (healthy, fresh, lost-id).
    const dueKeys = storage.rawListKeys().filter((k) => k.startsWith(DUE_INDEX_PREFIX));
    ok("due index rebuilt over the healed roster", dueKeys.length === 3 && dueKeys.some((k) => k.endsWith(":lost-id")));

    // Idempotent: a second reconcile finds nothing to do.
    const again = await stub.reconcileRoster();
    ok("reconcile is idempotent", again.removed === 0 && again.rehomed === 0 && again.ghostsRemaining === 0);
  }

  {
    // Rehome must never clobber real history: when the embedded id ALREADY has a ring, the ghost's
    // ring is dropped, not moved over it.
    const { storage, stub } = makeScheduler();
    await storage.put("dp:wrong", state("kept-id"));
    await storage.put("hist:wrong", [{ runId: "ghost-run", index: 1, status: "ok", startedAt: new Date().toISOString() }]);
    await storage.put("hist:kept-id", [{ runId: "real-run", index: 7, status: "ok", startedAt: new Date().toISOString() }]);
    await stub.reconcileRoster();
    const ring = storage.rawGet<Array<{ runId: string }>>("hist:kept-id");
    ok("an existing ring under the target id is never clobbered", ring?.length === 1 && ring[0]?.runId === "real-run");
    ok("the ghost's own ring residue is dropped", storage.rawGet("hist:wrong") === undefined);
  }

  const failures = getFailures();
  console.log(failures === 0 ? "\nROSTER-HYGIENE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
