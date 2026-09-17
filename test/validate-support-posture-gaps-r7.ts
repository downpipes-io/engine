// POSTURE (ENGINE half): the /replication read's error responses, not only its throw.
//
// A GUARD ON THE THROW ALONE IS NOT ENOUGH: fetchReplication returns null, and projectReplication makes no
// never-reported claim on a null. It never checked r.ok. And SchedulerDO.fetch (src/sched/scheduler-do.ts:204)
// does not let the DO's own faults reach the caller as throws: it CATCHES them and normally resolves a JSON
// error body. A plain Error out of replication() -- the `repl:` storage.list, i.e. a DO storage timeout, which
// is exactly the transient blip the null was written for -- comes back as HTTP 400 {"error":"..."}, and a
// runtime fault as HTTP 500 {"error":"internal error","errorId":"..."}. Both bodies PARSE. byDownpipe is
// undefined. The map is {} and it is READABLE, so every configured destination on every downpipe in the fleet
// is stamped neverReported at maximal severity -- the row a support engineer escalates on, asserting that no
// copy of any backup exists anywhere -- and sections.replication reads "empty", not "error", so nothing else in
// the pack contradicts it.
//
// So this suite drives the bundle over the DO's REAL error responses, not only over a throw. It also drives:
//   - the SECTION STATUS in the other direction: fetchReplication SWALLOWS the fault (it returns null rather
//     than throwing, because the projector needs the null), so section()'s catch never ran and the status read
//     "ok" on a read that never answered.
//   - the SIBLING /replication READER: the retention pass (src/cron/retention-pass.ts) had the identical
//     missing r.ok, so a DO error response set its pack-borne `replicationUnreadable` flag to FALSE, asserting
//     the coverage proof was read and was empty when it was never read at all.
//
// Run with `node test/validate-support-posture-gaps-r7.ts`.

import { buildSupportBundle } from "../src/admin/support.ts";
import { runRetentionPrunes } from "../src/cron/retention-pass.ts";
import type { RetentionPassRecord } from "../src/cron/retention-record.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The four ways the /replication read can go. `healthy` is the steady state; `throws` is the fetch itself
// failing (a dispatch/transport fault); `do400` and `do500` are the DO's OWN
// error responses, byte-identical to the ones SchedulerDO.fetch builds at scheduler-do.ts:257 (a validation or
// storage Error) and :247 (a runtime fault). They are the likelier fault and they were the unguarded one.
type ReplMode = "healthy" | "throws" | "do400" | "do500";

// D1 HOLDS EVERY RUN. That is the fact the false row denied, so it is the fact the fleet must carry: p1 and p2
// both fan out to D1 and D2; p2's D2 has genuinely never reported (the real escalate state); p3 is a single
// destination; p4 is on the default destination (no pin, so it names no fan-out to fail).
const FLEET = [
  { config: { id: "p1", name: "p1", source: { type: "kv", binding: "KV", namespaceId: "ns" }, destinationIds: ["d1", "d2"] } },
  { config: { id: "p2", name: "p2", source: { type: "kv", binding: "KV", namespaceId: "ns" }, destinationIds: ["d1", "d2"] } },
  { config: { id: "p3", name: "p3", source: { type: "kv", binding: "KV", namespaceId: "ns" }, destinationIds: ["d1"] } },
  { config: { id: "p4", name: "p4", source: { type: "kv", binding: "KV", namespaceId: "ns" } } },
];
const HEARTBEATS = {
  p1: { d1: { lastOk: true, lastAttemptAt: 1, holdsIndex: 7, holdsRunId: "01RUN" }, d2: { lastOk: true, lastAttemptAt: 1, holdsIndex: 5, holdsRunId: "01OLD" } },
  p2: { d1: { lastOk: true, lastAttemptAt: 1, holdsIndex: 7, holdsRunId: "01RUN" } },
  p3: { d1: { lastOk: true, lastAttemptAt: 1, holdsIndex: 7, holdsRunId: "01RUN" } },
};

function replResponse(mode: ReplMode): Response {
  const json = (v: unknown, status: number): Response => new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
  if (mode === "healthy") return json({ byDownpipe: HEARTBEATS }, 200);
  // Verbatim the two bodies SchedulerDO.fetch normally-resolves when route() throws.
  if (mode === "do400") return json({ error: "replication state unavailable" }, 400);
  return json({ error: "internal error", errorId: "1a2b3c4d" }, 500);
}

// A DO double that answers the bundle's many section reads with honest empties and serves the roster and the
// heartbeats. Every other route degrades through section() exactly as it does against a real DO under load.
function stub(mode: ReplMode): DurableObjectStub {
  return {
    fetch: async (input: string | URL, _init?: RequestInit): Promise<Response> => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      const json = (v: unknown): Response => new Response(JSON.stringify(v), { status: 200, headers: { "content-type": "application/json" } });
      if (url.pathname === "/replication") {
        if (mode === "throws") throw new Error("dispatch failed");
        return replResponse(mode);
      }
      if (url.pathname === "/downpipes") return json(FLEET);
      return json({});
    },
  } as unknown as DurableObjectStub;
}

type Bundle = Record<string, unknown>;
const replOf = (b: Bundle, id: string): Record<string, unknown> => {
  const rows = (b.downpipes ?? []) as Array<Record<string, unknown>>;
  const row = rows.find((d) => d.id === id) ?? {};
  return (row.replication ?? {}) as Record<string, unknown>;
};
const sectionOf = (b: Bundle): string => ((b.sections ?? {}) as Record<string, string>).replication ?? "(absent)";

async function g299(): Promise<void> {
  console.log("\na DO error response is a read fault, not an empty heartbeat store:");

  const bundle = async (mode: ReplMode): Promise<Bundle> => await buildSupportBundle({} as unknown as Env, stub(mode));

  // ---- THE HEALTHY PATH, WHICH MUST NOT MOVE ------------------------------------------------------------
  const healthy = await bundle("healthy");
  ok("HEALTHY: the section reads ok", sectionOf(healthy) === "ok");
  ok("HEALTHY: p1's two destinations both reported (one behind: holdsIndex 5 against 7)", (replOf(healthy, "p1").destinations as unknown[])?.length === 2 && replOf(healthy, "p1").neverReportedIds === undefined);
  ok("HEALTHY: p2's d2 IS named as never-reported -- the true escalate state still fires", JSON.stringify(replOf(healthy, "p2").neverReportedIds) === JSON.stringify(["d2"]) && replOf(healthy, "p2").neverReportedCount === 1);
  ok("HEALTHY: p3 (single destination, reporting) names nothing as never-reported", replOf(healthy, "p3").neverReportedIds === undefined);
  ok("HEALTHY: p4 (default destination) carries no replication block at all", replOf(healthy, "p4").configuredIds === undefined);
  ok("HEALTHY: nothing claims the heartbeats were unreadable", (healthy.downpipes as Array<Record<string, unknown>>).every((d) => ((d.replication ?? {}) as Record<string, unknown>).heartbeatsUnreadable === undefined));

  // ---- THE THREE FAULTS. NOT ONE OF THEM MAY CLAIM A DESTINATION HAS NEVER REPORTED ---------------------
  for (const mode of ["throws", "do400", "do500"] as const) {
    const b = await bundle(mode);
    const rows = (b.downpipes ?? []) as Array<Record<string, unknown>>;
    const anyNeverReported = rows.some((d) => ((d.replication ?? {}) as Record<string, unknown>).neverReportedIds !== undefined);
    // do400 and do500 used to produce this row on EVERY downpipe: d1 holds every run and the pack asserted it
    // had never held anything, fleet-wide, at maximal severity.
    ok(`${mode}: NOT ONE never-reported claim anywhere in the fleet (d1 holds every run)`, !anyNeverReported);
    ok(`${mode}: every downpipe with a configured fan-out says the heartbeats were UNREADABLE`, replOf(b, "p1").heartbeatsUnreadable === true && replOf(b, "p2").heartbeatsUnreadable === true && replOf(b, "p3").heartbeatsUnreadable === true);
    ok(`${mode}: the intended fan-out still rides (it comes off the config, which is always readable)`, JSON.stringify(replOf(b, "p1").configuredIds) === JSON.stringify(["d1", "d2"]));
    // THE STATUS VECTOR. On the DO-error modes it read "empty"; on the throw it read "ok", because
    // fetchReplication swallowed the fault. Both told support the section could be trusted.
    ok(`${mode}: sections.replication reads "error", not "empty" and not "ok"`, sectionOf(b) === "error");
    ok(`${mode}: p4 (default destination) is still silent -- a read fault is not an excuse for noise`, replOf(b, "p4").heartbeatsUnreadable === undefined);
  }

  // A DO ERROR RESPONSE AND A HEALTHY READ ARE NOT THE SAME ROW. This is the whole of bar 1.
  const do400 = await bundle("do400");
  ok("DISCRIMINATION: the do-400 row differs from the healthy row on the SAME downpipe", JSON.stringify(replOf(do400, "p2")) !== JSON.stringify(replOf(healthy, "p2")));
  ok("DISCRIMINATION: a read fault and the true escalate state are distinguishable in the pack", replOf(do400, "p2").neverReportedCount === undefined && replOf(healthy, "p2").neverReportedCount === 1);

  // REDACTION: the DO's 500 body carries an errorId and its 400 an internal message. Neither may ride.
  const do500 = await bundle("do500");
  const text = JSON.stringify(do500) + JSON.stringify(do400);
  ok("REDACTION: no errorId, no DO error message and no status code rides into the pack", !text.includes("1a2b3c4d") && !text.includes("internal error") && !text.includes("replication state unavailable"));
}

// ---------------------------------------------------------------------------------------------------------
// THE SIBLING READER. The retention pass reads /replication for the M7 replica-coverage gate, and it had the
// identical missing r.ok. The PRUNE is safe either way (an empty map proves no coverage, so a replicated
// downpipe prunes nothing), but the pass evidence record that rides into the pack asserted the state HAD been
// read: `replicationUnreadable: false`. Support reads that as "retention is working and there is simply nothing
// to delete", which is the exact ticket the flag was added for.
// ---------------------------------------------------------------------------------------------------------
async function g299Sibling(): Promise<void> {
  console.log("\nthe sibling /replication reader (the retention pass):");

  // `enabled: true` is what makes this arm reach the subject. retention-pass.ts partitions on the
  // downpipe's own switch with `!s.config.enabled`, so a fixture omitting the field is PAUSED, and an
  // all-paused pass posts its record and returns at :137-140 -- BEFORE the replication read at :149 that
  // sets replicationUnreadable. Without the flag the three "unreadable" arms below read the field's
  // `false` initialiser and fail, while the healthy arm's `=== false` passes for the wrong reason: it
  // would hold just as well over a pass that never read replication at all.
  const WITH_RETENTION = [{ config: { id: "dp-1", name: "dp-1", enabled: true, retention: { keepRuns: 3, enforce: true }, source: {} }, nextRunAt: 0, lastRunId: null, inFlight: false }];
  const record = async (mode: ReplMode): Promise<RetentionPassRecord> => {
    const recorded: string[] = [];
    const sched = {
      fetch: async (input: string | URL, init?: RequestInit): Promise<Response> => {
        const url = new URL(typeof input === "string" ? input : input.toString());
        const json = (v: unknown): Response => new Response(JSON.stringify(v), { status: 200, headers: { "content-type": "application/json" } });
        if (url.pathname === "/downpipes") return json(WITH_RETENTION);
        if (url.pathname === "/replication") {
          if (mode === "throws") throw new Error("dispatch failed");
          return replResponse(mode);
        }
        if (url.pathname === "/retention-record") {
          recorded.push(String(init?.body ?? "{}"));
          return json({ ok: true });
        }
        throw new Error(`unexpected DO fetch in test: ${url.pathname}`);
      },
    } as unknown as DurableObjectStub;
    // No OPERATIONAL_PRIVATE: the pass records and skips (break-glass-only), which is enough to file the record
    // this assertion reads. The replication read happens before that skip.
    await runRetentionPrunes({} as unknown as Env, sched);
    return JSON.parse(recorded[0] ?? "{}") as RetentionPassRecord;
  };

  ok("healthy: the record honestly says the coverage proof WAS read", (await record("healthy")).replicationUnreadable === false);
  ok("throws: flagged unreadable (this arm already held)", (await record("throws")).replicationUnreadable === true);
  ok("do400: flagged unreadable -- it used to claim the coverage proof was read and was empty", (await record("do400")).replicationUnreadable === true);
  ok("do500: flagged unreadable", (await record("do500")).replicationUnreadable === true);
}

async function main(): Promise<void> {
  await g299();
  await g299Sibling();
  console.log(failures === 0 ? "\nPOSTURE (ENGINE) PASS" : `\nPOSTURE (ENGINE): ${failures} FAILED`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
