// validate-dest-last-copy-guard: removing a destination that holds the last proven copy of a run is refused,
// whichever destination the run first sealed to.
//
// THE DEFECTS THIS PINS (ASVS 5.0 v5.0.0-2.2.3 and v5.0.0-2.3.2).
//   1. The orphan guard (uncoveredOriginRuns) counted only the runs whose seal ORIGIN is the destination
//      being removed. A run whose origin was already removed lives only on a replica B. Removing B was not
//      refused, so the run then had no copy anywhere.
//   2. The guard trusted the replication record of a destination that was already removed. A removed
//      destination B keeps its `repl:` entry, so its proven window still "covered" runs. Removing their
//      origin A was then not refused, and the runs had no copy anywhere.
//   3. The replication record proved only a CONTIGUOUS window. One run that no destination holds froze the
//      window below it, so the newer runs a replica does hold stayed in the removal count until that run
//      left the 50-run history ring. The replicate pass now also records the ring runs a destination holds
//      above that window (holdsAbove), and the guard reads them.
//   4. The singular clear of the default (setDestConfig with config:null) ran only the in-use guard, so it
//      removed the only copy of default-routed runs with no refusal.
//
// The real SchedulerDO over an in-memory storage double; nothing under test is stubbed.
// Run: node test/validate-dest-last-copy-guard.ts

import type { AuthMethod } from "../src/admin/identity.ts";
import { classifyDestProbeRefusal } from "../src/sched/sched-fault-ledger.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DestReplState } from "../src/sched/scheduler-do-base.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

type Caller = { method: AuthMethod; email: string | null; subject: string | null; groups: string[] };
const OWNER: Caller = { method: "token", email: null, subject: null, groups: [] };

const A = "dest-a";
const B = "dest-b";
const C = "dest-c";
const DP = "dp-1";

function storedDest(id: string): Record<string, unknown> {
  return { id, label: id, endpoint: "https://acct.r2.cloudflarestorage.com", bucket: `bk-${id}`, region: "auto", accessKeyId: "AK", secretAccessKey: "SK", setAt: 1, setBy: "owner@acme.example", verifiedAt: 1, deleteProbe: "ok" };
}
function downpipe(destinationIds: string[], sealedRuns: number): Record<string, unknown> {
  return { config: { id: DP, name: "src-1", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] }, destinationIds }, nextRunAt: 0, lastRunId: "r5", inFlight: false, sealedRuns };
}
function row(index: number, origin: string): Record<string, unknown> {
  return { runId: `r${index}`, index, startedAt: "2026-09-27T08:00:00.000Z", status: "ok", destinationId: origin };
}
function window(from: number, to: number, extra: Partial<DestReplState> = {}): DestReplState {
  return { holdsRunId: `r${to}`, holdsIndex: to, holdsFrom: from, lastOk: true, lastAttemptAt: 1, ...extra };
}

function makeDO(live: string[], defaultId: string, destinationIds: string[], ring: Record<string, unknown>[], repl: Record<string, DestReplState>): SchedulerDO {
  const storage = new MockStorage();
  storage.seed("destinations", { list: live.map(storedDest), defaultId });
  storage.seed(`dp:${DP}`, downpipe(destinationIds, ring.length));
  storage.seed(`hist:${DP}`, ring);
  storage.seed(`repl:${DP}`, repl);
  return new SchedulerDO({ storage } as unknown as DurableObjectState);
}

async function caught(fn: () => Promise<unknown>): Promise<Error | null> {
  try {
    await fn();
    return null;
  } catch (err) {
    return err as Error;
  }
}

async function main(): Promise<void> {
  // 1. The origin A is gone (removed earlier). B holds runs 1, 3 and 5; the downpipe now writes to C only,
  //    and C holds none of them. B is the last holder, so removing B must be refused.
  console.log("-- 1. the last holder of runs whose origin is gone: removal refused --");
  {
    const ring = [row(1, A), row(3, A), row(5, A)];
    const dobj = makeDO([B, C], C, [C], ring, { [A]: window(1, 5), [B]: window(1, 5) });
    const refusal = await caught(() => dobj.removeDest(B, false, OWNER));
    ok(`removing B without force is refused (got: ${refusal?.message ?? "removed"})`, refusal !== null);
    ok("the refusal is the orphan guard and counts the 3 runs", refusal !== null && classifyDestProbeRefusal(refusal) === "orphan-guard" && /only proven copy of 3 backed-up run\(s\) \(src-1\)/.test(refusal.message));
    const forcedDO = makeDO([B, C], C, [C], ring, { [A]: window(1, 5), [B]: window(1, 5) });
    const forced = await forcedDO.removeDest(B, true, OWNER);
    ok("force still removes it and states the 3 runs it dropped", forced.notice?.startsWith("Destination removed with force. Downpipes cannot restore the 3 backed-up run(s) that were only here.") === true);
  }
  console.log("-- 1 control. C holds the same runs: removing B is allowed --");
  {
    const ring = [row(1, A), row(3, A), row(5, A)];
    const dobj = makeDO([B, C], C, [C], ring, { [B]: window(1, 5), [C]: window(1, 5) });
    ok("removing B succeeds without force", (await caught(() => dobj.removeDest(B, false, OWNER))) === null);
  }
  console.log("-- 1 control. a run whose origin C is still configured: removing the replica B is allowed --");
  {
    const ring = [row(1, C), row(3, C)];
    const dobj = makeDO([B, C], C, [C], ring, { [B]: window(1, 3) });
    ok("removing B succeeds without force", (await caught(() => dobj.removeDest(B, false, OWNER))) === null);
  }

  // 2. B was removed earlier, and its repl entry is still stored. A is the origin and the only live holder
  //    of runs 1, 3 and 5. Removing A must be refused: the removed B proves nothing.
  console.log("-- 2. a removed destination's replication record proves nothing --");
  {
    const ring = [row(1, A), row(3, A), row(5, A)];
    const dobj = makeDO([A, C], C, [C], ring, { [A]: window(1, 5), [B]: window(1, 5) });
    const refusal = await caught(() => dobj.removeDest(A, false, OWNER));
    ok(`removing A without force is refused (got: ${refusal?.message ?? "removed"})`, refusal !== null && classifyDestProbeRefusal(refusal) === "orphan-guard" && /only proven copy of 3 backed-up run\(s\)/.test(refusal.message));
  }

  // 3. The downpipe writes to B and C. Run 1's origin is gone and no destination holds it. B holds runs 3 and
  //    5 (above the gap), so its contiguous window is empty, and it records them in holdsAbove. Removing A
  //    must be allowed: every run A holds is also on B.
  console.log("-- 3. runs a replica holds above a gap count as held --");
  {
    const ring = [row(1, "dest-gone"), row(3, A), row(5, A)];
    const dobj = makeDO([A, B, C], A, [B, C], ring, { [A]: window(3, 5), [B]: { holdsRunId: null, holdsIndex: -1, holdsAbove: [3, 5], lastOk: true, lastAttemptAt: 1 } });
    const refusal = await caught(() => dobj.removeDest(A, false, OWNER));
    ok(`removing A succeeds without force (got: ${refusal?.message ?? "removed"})`, refusal === null);
  }
  console.log("-- 3 control. B holds run 3 only: run 5 is still at risk --");
  {
    const ring = [row(1, "dest-gone"), row(3, A), row(5, A)];
    const dobj = makeDO([A, B, C], A, [B, C], ring, { [B]: { holdsRunId: null, holdsIndex: -1, holdsAbove: [3], lastOk: true, lastAttemptAt: 1 } });
    const refusal = await caught(() => dobj.removeDest(A, false, OWNER));
    ok("removing A is refused for 1 run", refusal !== null && /only proven copy of 1 backed-up run\(s\)/.test(refusal.message));
  }

  // 4. The replicate pass writes holdsAbove through the DO route: kept above holdsIndex only, and dropped as
  //    the contiguous window rises past it.
  console.log("-- 4. recordReplicationState keeps holdsAbove above the window --");
  {
    const dobj = makeDO([A, B], A, [A, B], [row(1, "dest-gone"), row(3, A), row(5, A)], {});
    const post = async (body: Record<string, unknown>): Promise<void> => {
      await dobj.fetch(new Request("https://do/replication/record", { method: "POST", body: JSON.stringify({ id: DP, destinationId: B, ok: true, ...body }) }));
    };
    const read = async (): Promise<DestReplState | undefined> => ((await dobj.replication(DP)) as { dests: Record<string, DestReplState> }).dests[B];
    await post({ holdsAbove: [5, 3, 3, -2, 1.5, "x"] });
    ok(`an ok record with no window stores the valid indexes, sorted (got ${JSON.stringify((await read())?.holdsAbove)})`, JSON.stringify((await read())?.holdsAbove) === "[3,5]");
    await post({ runId: "r3", index: 3, holdsFrom: 3, holdsAbove: [5] });
    ok(`a window up to 3 keeps 5 above it (got ${JSON.stringify(await read())})`, (await read())?.holdsIndex === 3 && JSON.stringify((await read())?.holdsAbove) === "[5]");
    await post({ runId: "r5", index: 5, holdsFrom: 3, holdsAbove: [] });
    ok("a window up to 5 leaves nothing above it", (await read())?.holdsIndex === 5 && (await read())?.holdsAbove === undefined);
    await post({ holdsAbove: [2] });
    ok("an index at or below the window is not stored", (await read())?.holdsAbove === undefined);
  }

  // 5. The singular clear (POST /destination with config:null) removes the default through setDestConfig. It
  //    ran only the in-use guard, so with no downpipe naming the default it dropped the only copy of every
  //    run with no refusal and no force. It must refuse on the same orphan guard as removeDest.
  console.log("-- 5. the singular clear of the default is refused while it holds the only copy --");
  {
    const ring = [row(1, A), row(3, A)];
    const dobj = makeDO([A, B], A, [], ring, {});
    const refusal = await caught(() => dobj.setDestConfig({ config: null }, OWNER));
    ok(`clearing the default A is refused (got: ${refusal?.message ?? "cleared"})`, refusal !== null && classifyDestProbeRefusal(refusal) === "orphan-guard" && /only proven copy of 2 backed-up run\(s\)/.test(refusal.message));
    const left = await dobj.listDestStatus();
    ok("A is still configured and still the default", left.defaultId === A && left.destinations.some((d) => d.id === A));
  }
  console.log("-- 5 control. B holds the runs: the singular clear of A is allowed --");
  {
    const ring = [row(1, A), row(3, A)];
    const dobj = makeDO([A, B], A, [], ring, { [B]: window(1, 3) });
    ok("clearing the default A succeeds", (await caught(() => dobj.setDestConfig({ config: null }, OWNER))) === null);
  }

  console.log(failures === 0 ? "\nVALIDATE-DEST-LAST-COPY-GUARD VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
