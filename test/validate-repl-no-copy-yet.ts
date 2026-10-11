// validate-repl-no-copy-yet: a destination whose replication record reads ok:true while it holds no run
// (holdsIndex -1) says so in the support pack, and the Security centre does not count it as a copy.
//
// A destination can be reachable on every pass and still hold nothing yet: a new fan-out leg before its
// first completed copy. Its record is ok:true with holdsIndex -1. Read alone, ok:true looks like a healthy
// copy, so the pack row carries copy: "none-yet", which the support bundle documents as "no restorable copy
// yet". The posture grader (sched/destinations.ts assessRedundancy) counts a destination only when its
// holdsIndex reaches the graded run, so a destination that holds nothing never counts.
//
// THIS FILE PROVES:
//   1. fetchReplication marks an ok:true row with holdsIndex -1 as copy "none-yet";
//   2. an ok:true row that holds a run carries no copy field, and neither does a failed row (its reason says
//      more than "none-yet" would);
//   3. assessRedundancy counts the origin and the holding destination, and lists the empty one as a gap with
//      heldRuns 0.
//
// Run: node test/validate-repl-no-copy-yet.ts

import { fetchReplication } from "../src/admin/support-sections-seal.ts";
import { assessRedundancy } from "../src/sched/destinations.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 400)}`);
  }
}

const NOW = Date.parse("2026-10-06T00:00:00.000Z");
const HOUR = 3_600_000;

// A scheduler stub that answers GET /replication with one downpipe and three destinations.
const byDownpipe = {
  dp_pay: {
    origin: { holdsRunId: "run-3", holdsIndex: 3, lastOk: true, lastAttemptAt: NOW - HOUR },
    empty: { holdsRunId: null, holdsIndex: -1, lastOk: true, lastAttemptAt: NOW - HOUR },
    down: { holdsRunId: null, holdsIndex: -1, lastOk: false, lastAttemptAt: NOW - HOUR, reason: "unreachable" },
  },
};
const scheduler = {
  async fetch(input: string | Request): Promise<Response> {
    const path = new URL(typeof input === "string" ? input : input.url).pathname;
    if (path === "/replication") return new Response(JSON.stringify({ byDownpipe }), { headers: { "content-type": "application/json" } });
    return new Response("not found", { status: 404 });
  },
} as unknown as DurableObjectStub;

async function main(): Promise<void> {
  console.log("-- the support pack row --");
  const map = await fetchReplication(scheduler);
  const rows = map?.dp_pay ?? [];
  const row = (id: string): Record<string, unknown> | undefined => rows.find((r) => r.id === id);
  ok("CONTROL: the pack read all three destinations", rows.length === 3, rows);
  ok('an ok:true row holding no run carries copy "none-yet"', row("empty")?.ok === true && row("empty")?.copy === "none-yet", row("empty"));
  ok("an ok:true row that holds a run carries no copy field", row("origin")?.ok === true && !("copy" in (row("origin") ?? {})), row("origin"));
  ok("a failed row carries its reason and no copy field", row("down")?.ok === false && row("down")?.reason === "unreachable" && !("copy" in (row("down") ?? {})), row("down"));

  console.log("\n-- the Security centre grader --");
  const runs = [1, 2, 3].map((i) => ({ index: i, startedAt: new Date(NOW - (4 - i) * 6 * HOUR).toISOString() }));
  const repl = { origin: byDownpipe.dp_pay.origin, empty: byDownpipe.dp_pay.empty, down: byDownpipe.dp_pay.down };
  const r = assessRedundancy(["origin", "empty", "down"], "origin", runs, repl, NOW);
  ok(`the empty destination does not count as a copy (provenCopies ${r.provenCopies})`, r.provenCopies === 1, r);
  const gap = r.gaps.find((g) => g.destinationId === "empty");
  ok("the empty destination is a gap that holds 0 runs and is not failing", gap !== undefined && gap.heldRuns === 0 && gap.lastOk === true, r.gaps);

  console.log(failures === 0 ? "\nVERDICT: PASS failures=0\n" : `\nVERDICT: FAIL failures=${failures}\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
