// validate-run-history-empty-versus-new.ts
//
// AN ESTATE THAT HAS LOST ITS RUN HISTORY AND AN ESTATE THAT NEVER HAD ANY WERE THE SAME RESPONSE.
//
// Four console surfaces were repaired, and one gap was named openly as not yet repaired:
// "a run-history map that settles ok:true and EMPTY is byte-identical to a brand-new estate, and no
// console change can separate them". That is correct, and the reason it is correct is that the fact
// which separates them was never on the wire. GET /history returned byDownpipe and nothing else, so an
// empty map was the whole of the answer in both states.
//
// THE SIBLING HAD ALREADY SOLVED IT FOR THE AUDIT LOG. auditCountAndNearCap returns auditCount BESIDE
// auditRolledOverCount because a count of what survives cannot report what was destroyed, and verifyAudit
// keeps a stored rollover record AS WELL AS deriving one from earliestSeq, because the derivation has
// nothing left to read once the log empties (see validate-audit-rollover-count-honesty.ts, which is this
// file's sibling in every sense). The run-history chain already had the derived half: run-chain.ts
// annotates the oldest retained row "pruned" when its predecessor aged out of RING_CAP, which is
// derivedRolledOver = firstSeq > 1 under another name. It had no half that still answers when the rings
// are empty, and the empty ring is the ONLY case in which the conflation bites.
//
// THE COLLIDING STATE IS REACHED THROUGH THE PRODUCT'S OWN PATHS, NOT BUILT BY HAND. removeDownpipe
// deletes hist:<id> and its own comment states that "the runlogCounter is left untouched (indices stay
// monotonic)". So a fleet that has run backups and then had its downpipes deleted holds a positive
// runlogCounter and no rings at all. Part 1 drives real trigger/complete calls and a real delete, then
// reads GET /history. That is the state, and it is ordinary operator behaviour rather than corruption.
//
// WHY THE COUNTER IS DERIVED FROM runlogCounter RATHER THAN FROM A NEW STORED COUNTER. A cumulative
// counter introduced now would start at zero across the installed base and answer "nothing has rolled
// over" for every estate that has ALREADY lost its history, reproducing the defect behind a field that
// looks like a fix. runlogCounter is account-global, monotonic, and already populated everywhere.
//
// THE NEGATIVE CONTROLS ARE THE POINT. "These two responses differ" is also true of an instrument that
// makes every response differ, so Part 1 also requires two genuinely IDENTICAL states to stay identical
// byte for byte, and Part 2 requires a healthy estate to keep reporting a zero loss. A repair that starts
// crying wolf on a live fleet fails here rather than passing unnoticed.
//
// No network, no deploy, no estate. Run: node test/validate-run-history-empty-versus-new.ts
import type { DurableObjectState } from "@cloudflare/workers-types";
import type { RunHistoryEntryWithChain } from "../src/admin/run-chain.ts";
import { SchedulerDO, type DownpipeState, type RunHistoryEntry } from "../src/sched/scheduler-do.ts";
import { RING_CAP } from "../src/sched/scheduler-do-limits.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// statesDriven is the POPULATION assertion's counter. "No two states collided" is also true of a run that
// drove no states at all, so a run that reaches the end having built fewer than the states below REFUSES
// rather than printing a clean sheet.
let statesDriven = 0;

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  statesDriven++;
  return { storage, stub: new SchedulerDO(state) };
}

function fetchDO(dobj: SchedulerDO, method: string, path: string, body?: unknown): Promise<Response> {
  const url = `https://scheduler.internal${path}`;
  const headers: Record<string, string> = body !== undefined ? { "content-type": "application/json" } : {};
  const init: RequestInit = { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
  return dobj.fetch(new Request(url, init));
}

const T0 = Date.parse("2026-06-01T00:00:00.000Z");

interface FleetHistory {
  byDownpipe: Record<string, RunHistoryEntryWithChain[]>;
  runsRecordedTotal: number;
  runsRetainedCount: number;
  runsRolledOverCount: number;
  runlogCounterReset?: true;
}

async function readFleetHistory(stub: SchedulerDO): Promise<{ body: FleetHistory; raw: string }> {
  const resp = await fetchDO(stub, "GET", "/history");
  const raw = await resp.text();
  return { body: JSON.parse(raw) as FleetHistory, raw };
}

function makeDownpipe(id: string, name: string): DownpipeState {
  return {
    config: { id, name, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: `KV_${id}`, include: [], exclude: [] } } as DownpipeState["config"],
    nextRunAt: T0,
    lastRunId: null,
    inFlight: false,
  };
}

// runN drives n REAL trigger/complete pairs against the downpipe, which is what allocates run indices out
// of runlogCounter and appends the ring rows. Nothing here writes storage by hand.
async function runN(stub: SchedulerDO, id: string, n: number): Promise<void> {
  for (let i = 0; i < n; i++) {
    const t = (await (await fetchDO(stub, "POST", "/trigger", { id })).json()) as { runId: string; index: number };
    await fetchDO(stub, "POST", "/complete", { id, runId: t.runId, index: t.index, status: "ok" });
  }
}

async function main(): Promise<void> {
  // =========================================================================================
  // PART 1: THE COLLISION. Two genuinely different estates, one response.
  // =========================================================================================
  const RUNS = 7;

  // STATE A: a brand-new estate. Nothing has ever been created and nothing has ever run.
  const fresh = makeScheduler();
  const a = await readFleetHistory(fresh.stub);

  // STATE B: an estate that ran RUNS backups and then had its downpipe deleted, through removeDownpipe,
  // which is the operator-initiated product path and not a corruption.
  const used = makeScheduler();
  await used.storage.put("dp:dp1", makeDownpipe("dp1", "Primary"));
  await runN(used.stub, "dp1", RUNS);
  ok(`SETUP: the used estate really did run ${RUNS} backups (its ring holds them)`, used.storage.rawKeys("hist:").length === 1);
  await used.stub.removeDownpipe({ id: "dp1" });
  const b = await readFleetHistory(used.stub);

  // The two states are only comparable if BOTH really are empty. If the delete left rows behind, this
  // would not be the empty-map case this file exists to close, and the rest of Part 1 would be grading
  // something else entirely.
  ok("SETUP: the brand-new estate's map is empty", Object.keys(a.body.byDownpipe).length === 0);
  ok("SETUP: the used estate's map is ALSO empty (removeDownpipe drops hist:<id>)", Object.keys(b.body.byDownpipe).length === 0);
  ok("SETUP: and the used estate's runlogCounter SURVIVED the delete, which is what makes the fix possible", (await used.storage.get<number>("runlogCounter")) === RUNS);

  // THE ASSERTION THAT FAILS ON UNFIXED MAIN. Before this repair both responses were the string
  // {"byDownpipe":{}} and there was nothing else to read.
  ok("THE DEFECT: a lost run history and a brand-new estate are NOT byte-identical responses", a.raw !== b.raw);

  ok("the brand-new estate honestly reports nothing has ever run", a.body.runsRecordedTotal === 0 && a.body.runsRolledOverCount === 0);
  ok(`the used estate reports the ${RUNS} runs it actually performed`, b.body.runsRecordedTotal === RUNS);
  ok(`the used estate reports all ${RUNS} of them as no longer retained`, b.body.runsRolledOverCount === RUNS && b.body.runsRetainedCount === 0);
  ok("neither estate claims a counter reset, because neither has had one", a.body.runlogCounterReset === undefined && b.body.runlogCounterReset === undefined);

  // NEGATIVE CONTROL 1: two states that genuinely ARE the same must stay byte-identical. Without this,
  // an instrument that perturbed every response would pass the arm above while measuring nothing.
  const freshTwin = makeScheduler();
  const aTwin = await readFleetHistory(freshTwin.stub);
  ok("CONTROL: two brand-new estates are still byte-identical to each other", a.raw === aTwin.raw);

  // NEGATIVE CONTROL 2: and two estates with the SAME history are identical too, so the discrimination is
  // on the state and not on the object identity of the estate.
  const usedTwin = makeScheduler();
  await usedTwin.storage.put("dp:dp1", makeDownpipe("dp1", "Primary"));
  await runN(usedTwin.stub, "dp1", RUNS);
  await usedTwin.stub.removeDownpipe({ id: "dp1" });
  const bTwin = await readFleetHistory(usedTwin.stub);
  ok("CONTROL: two estates with the same lost history are byte-identical to each other", b.raw === bTwin.raw);

  // =========================================================================================
  // PART 2: NO CRYING WOLF. A live estate whose rings hold everything reports no loss at all.
  // =========================================================================================
  {
    const live = makeScheduler();
    await live.storage.put("dp:dpA", makeDownpipe("dpA", "A"));
    await live.storage.put("dp:dpB", makeDownpipe("dpB", "B"));
    await runN(live.stub, "dpA", 3);
    await runN(live.stub, "dpB", 2);
    const { body } = await readFleetHistory(live.stub);
    ok("healthy fleet: every run performed is still retained", body.runsRetainedCount === 5 && body.runsRecordedTotal === 5);
    ok("healthy fleet: the rolled-over count is ZERO, which is the one place a zero is the right answer", body.runsRolledOverCount === 0);
    ok("healthy fleet: no counter-reset claim", body.runlogCounterReset === undefined);
    ok("healthy fleet: and the map is NOT empty, so this is a different state from Part 1 in both halves", Object.keys(body.byDownpipe).length === 2);
  }

  // =========================================================================================
  // PART 3: THE RING_CAP CASE, where the stored half and the derived half must agree.
  // =========================================================================================
  {
    const overflow = makeScheduler();
    await overflow.storage.put("dp:dpC", makeDownpipe("dpC", "C"));
    const OVER = 3;
    await runN(overflow.stub, "dpC", RING_CAP + OVER);
    const { body } = await readFleetHistory(overflow.stub);
    ok(`RING_CAP: the ring retains exactly ${RING_CAP} rows`, body.runsRetainedCount === RING_CAP);
    ok(`RING_CAP: the response reports the ${OVER} runs that were shifted off`, body.runsRolledOverCount === OVER && body.runsRecordedTotal === RING_CAP + OVER);

    // The derived half must say the same thing. The OLDEST retained row's predecessor was shifted out of
    // the ring, so run-chain.ts classifies it "pruned". A stored half that disagreed with the derivation
    // already in the response would be a second answer to one question, which is the shape of defect this
    // file exists to catch.
    const ring = body.byDownpipe.dpC ?? [];
    const oldest = ring[ring.length - 1];
    ok("RING_CAP: the derived half agrees, the oldest retained row's predecessor reads 'pruned'", oldest?.prevRunIdStatus === "pruned");
  }

  // =========================================================================================
  // PART 4: A COUNTER WOUND BACK BELOW THE RINGS. The figure becomes a floor and says so.
  // =========================================================================================
  {
    const reset = makeScheduler();
    await reset.storage.put("dp:dpD", makeDownpipe("dpD", "D"));
    await runN(reset.stub, "dpD", 4);
    // The SCHED runlog-counter-reset state: the counter is wound back (a DO wipe, a restored-from-behind
    // record) while the rings still carry higher indices. The support pack already derives this exact
    // condition as counter < maxHistoryIndex; the point here is that the run-history read must not serve a
    // loss figure off a counter in that state without saying so.
    await reset.storage.put("runlogCounter", 1);
    const { body } = await readFleetHistory(reset.stub);
    ok("counter reset: the response says the counter has been wound back", body.runlogCounterReset === true);
    ok("counter reset: the rolled-over count is clamped at zero, never negative", body.runsRolledOverCount === 0);
    ok("counter reset: the retained count is still the truth about what IS there", body.runsRetainedCount === 4);

    // And the control: the same fleet with an untouched counter makes no such claim, so the flag is
    // reporting the wound-back counter rather than firing on any estate with runs in it.
    const notReset = makeScheduler();
    await notReset.storage.put("dp:dpD", makeDownpipe("dpD", "D"));
    await runN(notReset.stub, "dpD", 4);
    const clean = await readFleetHistory(notReset.stub);
    ok("CONTROL: the identical fleet with an untouched counter claims no reset", clean.body.runlogCounterReset === undefined);
  }

  // =========================================================================================
  // PART 5: A CORRUPT COUNTER NEVER REACHES THE WIRE AS ITSELF (the sibling's sanitisation rule).
  // =========================================================================================
  {
    const cases: Array<[string, unknown]> = [
      ["NaN", Number.NaN],
      ["negative", -12],
      ["fractional", 3.7],
      ["string", "9"],
      ["null", null],
      ["Infinity", Number.POSITIVE_INFINITY],
    ];
    for (const [name, value] of cases) {
      const dirty = makeScheduler();
      await dirty.storage.put("dp:dpE", makeDownpipe("dpE", "E"));
      await runN(dirty.stub, "dpE", 2);
      await dirty.storage.put("runlogCounter", value);
      const { body } = await readFleetHistory(dirty.stub);
      ok(`corrupt counter (${name}): never reaches the wire as itself`, !Object.is(body.runsRecordedTotal as unknown, value));
      ok(`corrupt counter (${name}): the total is a non-negative integer`, Number.isInteger(body.runsRecordedTotal) && body.runsRecordedTotal >= 0);
      ok(`corrupt counter (${name}): the loss figure is a non-negative integer`, Number.isInteger(body.runsRolledOverCount) && body.runsRolledOverCount >= 0);
    }
  }

  // =========================================================================================
  // PART 6: CONTROL. The per-downpipe shape is deliberately unchanged.
  // =========================================================================================
  {
    const one = makeScheduler();
    await one.storage.put("dp:dpF", makeDownpipe("dpF", "F"));
    await runN(one.stub, "dpF", 2);
    const resp = await fetchDO(one.stub, "GET", "/history?id=dpF");
    const body = (await resp.json()) as { entries?: RunHistoryEntry[]; runsRecordedTotal?: number };
    ok("CONTROL: GET /history?id= still answers the entries shape", Array.isArray(body.entries) && body.entries.length === 2);
    // runlogCounter is account-global. Putting it on a per-downpipe read would state a fleet figure as
    // though it were that downpipe's, which is a confident wrong answer in place of a missing one.
    ok("CONTROL: and it carries NO fleet counter, because the counter cannot speak for one downpipe", body.runsRecordedTotal === undefined);
  }

  // =========================================================================================
  // POPULATION. A clean sheet from a run that drove nothing is not a pass.
  // =========================================================================================
  const MIN_STATES = 14;
  ok(`POPULATION: at least ${MIN_STATES} estates were driven (drove ${statesDriven})`, statesDriven >= MIN_STATES);
  ok("POPULATION: this run made assertions at all", checks > 30);

  console.log(failures === 0 ? `\nALL RUN-HISTORY EMPTY-VERSUS-NEW VALIDATIONS PASS (${checks} checks over ${statesDriven} estates)` : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
