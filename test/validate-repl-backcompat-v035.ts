// validate-repl-backcompat-v035: a run that engine 0.3.5's replication made held on a second destination is
// still held after this engine's replication runs over it, and the orphan guard and the prune coverage
// still count it as held.
//
// THE STATE. test/fixtures/repl-v035/state.json was written by the 0.3.5 source (release commit 6a093886)
// through test/fixtures/repl-v035/generate.ts: runs 1 to 4 sealed to A and completed through the 0.3.5
// SchedulerDO, the 0.3.5 replication pass run until B's RUNLOG held runs 1 to 4, then runs 5 and 6 sealed to
// A only. So B's RUNLOG, its run-trees and segments, and the repl:<dp> rows with [holdsFrom, holdsIndex] are
// the ones 0.3.5 writes, not a hand-made copy. dp-0 has runs 1, 3, 5 and dp-1 has runs 2, 4, 6.
//
// WHAT IS GRADED, with this engine's SchedulerDO over the 0.3.5 storage rows and this engine's replication
// over the 0.3.5 buckets:
//   1. Before any tick: the orphan guard (removeDest's scan) counts only runs 5 and 6 as held on A alone, and
//      the prune coverage (replicaCoverageFor) covers runs 1 to 3 of dp-0 and 2 to 4 of dp-1 on B.
//   2. After REPL_TICKS ticks of this engine's replication: B's RUNLOG holds runs 1 to 6, each once, with a
//      per-downpipe chain that links each run to the one before it; every run attests keylessly on B; B's
//      windows are [1, 5] and [2, 6] and never fell below 0.3.5's at any tick; the guard counts nothing held
//      only on A, and with A taken off the downpipes, removing A succeeds without force.
//   3. NEGATIVE CONTROL: the same 0.3.5 state with holdsFrom taken off B's rows (the shape of a record from
//      before the floor was tracked). The guard must then count all 6 runs as held on A alone and the
//      coverage must cover nothing, so the checks in 1 read the rows and cannot pass on their own.
//
// Run: node test/validate-repl-backcompat-v035.ts

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { replicaCoverageFor } from "../src/cron/retention-pass.ts";
import type { Env } from "../src/env.d.ts";
import { attestKeyless } from "../src/format/keyless.ts";
import { parseRunlog, type RunlogEntry } from "../src/format/writer.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import type { AuthMethod } from "../src/admin/identity.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DestReplState } from "../src/sched/scheduler-do-base.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { runReplications } from "../src/seal/replicate.ts";
import { fixtureSigner } from "./fixtures/repl-v035/shared.ts";
import { S3Wire } from "./lib/s3-wire.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const REPL_TICKS = 2;
const OWNER = { method: "token" as AuthMethod, email: null, subject: null, groups: [] };
const RUNS: Record<string, number[]> = { "dp-0": [1, 3, 5], "dp-1": [2, 4, 6] };

interface Fixture {
  engine: { version: string; commit: string };
  endpoint: string;
  destinations: { A: string; B: string };
  buckets: Record<string, string>;
  objects: Record<string, Record<string, string>>;
  storage: Record<string, unknown>;
}
const FIXTURE = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "fixtures", "repl-v035", "state.json"), "utf8")) as Fixture;
const { A, B } = FIXTURE.destinations;

interface Estate {
  dobj: SchedulerDO;
  storage: MockStorage;
  scheduler: DurableObjectStub;
  env: Env;
}

// load puts the 0.3.5 buckets on the wire and the 0.3.5 storage rows under this engine's SchedulerDO.
async function load(wire: S3Wire, edit?: (rows: Record<string, unknown>) => void): Promise<Estate> {
  wire.buckets.clear();
  for (const [bucket, objs] of Object.entries(FIXTURE.objects)) for (const [k, v] of Object.entries(objs)) wire.put(bucket, k, new Uint8Array(Buffer.from(v, "base64")));
  const rows = structuredClone(FIXTURE.storage);
  edit?.(rows);
  const storage = new MockStorage();
  for (const [k, v] of Object.entries(rows)) storage.seed(k, v);
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const scheduler = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(input, init)) } as unknown as DurableObjectStub;
  return { dobj, storage, scheduler, env: { SIGNER_PRIVATE: await fixtureSigner() } as unknown as Env };
}

function runlogOf(wire: S3Wire, dest: string): RunlogEntry[] {
  const rl = wire.bucket(FIXTURE.buckets[dest]!).get("_RECOVERY/RUNLOG");
  return rl ? parseRunlog(rl.bytes) : [];
}

async function replOf(e: Estate, dp: string): Promise<DestReplState | undefined> {
  return (await e.storage.get<Record<string, DestReplState>>(`repl:${dp}`))?.[B];
}

// heldOnlyOnA is the orphan guard's count, read from the in-use refusal removeDest returns while the
// downpipes still name A: the runs A holds that no other destination's proven window covers.
async function heldOnlyOnA(e: Estate): Promise<number> {
  try {
    await e.dobj.removeDest(A, false, OWNER);
    return 0;
  } catch (err) {
    const m = /it holds (\d+) backed-up run/.exec((err as Error).message);
    return m ? Number(m[1]) : 0;
  }
}

// covered is the runs of a downpipe that the prune coverage counts as held on its replicas.
async function covered(e: Estate, dp: string): Promise<number[]> {
  const st = (await e.storage.get<DownpipeState>(`dp:${dp}`))!;
  const c = replicaCoverageFor(st.config, (await e.storage.get<Record<string, DestReplState>>(`repl:${dp}`)) ?? {});
  return RUNS[dp]!.filter((i) => c.hasReplicas && c.maxReplicaHoldsFrom <= i && i <= c.minReplicaHoldsIndex);
}

async function main(): Promise<void> {
  const wire = new S3Wire(FIXTURE.endpoint);
  wire.install();
  try {
    console.log(`-- 0. the state is the one engine ${FIXTURE.engine.version} (${FIXTURE.engine.commit}) wrote --`);
    ok("the fixture was written by engine 0.3.5", FIXTURE.engine.version === "0.3.5" && FIXTURE.engine.commit === "6a093886");
    const e = await load(wire);
    const b0 = runlogOf(wire, B).map((x) => x.index).sort((p, q) => p - q);
    ok(`B's RUNLOG, as 0.3.5 wrote it, holds runs 1 to 4 (holds [${b0}])`, JSON.stringify(b0) === "[1,2,3,4]");
    const w0 = { "dp-0": await replOf(e, "dp-0"), "dp-1": await replOf(e, "dp-1") };
    ok(`B's windows, as 0.3.5 recorded them, are [1, 3] and [2, 4] (got [${w0["dp-0"]?.holdsFrom}, ${w0["dp-0"]?.holdsIndex}] and [${w0["dp-1"]?.holdsFrom}, ${w0["dp-1"]?.holdsIndex}])`, w0["dp-0"]?.holdsFrom === 1 && w0["dp-0"]?.holdsIndex === 3 && w0["dp-1"]?.holdsFrom === 2 && w0["dp-1"]?.holdsIndex === 4);

    console.log("-- 1. before any tick, this engine counts 0.3.5's copies as held --");
    ok("the orphan guard counts only runs 5 and 6 as held on A alone", (await heldOnlyOnA(e)) === 2);
    ok(`the prune coverage covers dp-0's runs 1 and 3 on B (got [${await covered(e, "dp-0")}])`, JSON.stringify(await covered(e, "dp-0")) === "[1,3]");
    ok(`the prune coverage covers dp-1's runs 2 and 4 on B (got [${await covered(e, "dp-1")}])`, JSON.stringify(await covered(e, "dp-1")) === "[2,4]");

    console.log(`-- 2. this engine's replication runs over 0.3.5's copies for ${REPL_TICKS} ticks --`);
    let neverLower = true;
    for (let t = 1; t <= REPL_TICKS; t++) {
      await runReplications(e.env, e.scheduler, new SliceBudget());
      for (const dp of ["dp-0", "dp-1"] as const) {
        const r = await replOf(e, dp);
        if (!(r !== undefined && r.holdsFrom === w0[dp]!.holdsFrom && r.holdsIndex >= w0[dp]!.holdsIndex)) neverLower = false;
      }
    }
    const rl = runlogOf(wire, B);
    const idx = rl.map((x) => x.index).sort((p, q) => p - q);
    ok(`B's RUNLOG holds runs 1 to 6, each once (holds [${idx}])`, JSON.stringify(idx) === "[1,2,3,4,5,6]");
    let chained = true;
    for (const dp of ["dp-0", "dp-1"]) {
      const mine = rl.filter((x) => x.downpipeId === dp).sort((p, q) => p.index - q.index);
      mine.forEach((x, i) => {
        if (x.prevRunId !== (i === 0 ? null : mine[i - 1]!.runId)) chained = false;
      });
    }
    ok("each downpipe's chain on B links every run to the one before it, over 0.3.5's entries", chained);
    const verifier = verifierFrom(await loadSigner(await fixtureSigner()));
    const store = { get: async (k: string): Promise<Uint8Array> => wire.bucket(FIXTURE.buckets[B]!).get(k)?.bytes.slice() ?? Promise.reject(new Error(`object ${k} is missing`)) };
    let attested = true;
    for (const x of rl) {
      const att = await attestKeyless(store, x.runId, verifier, { allowStale: true });
      if (!att.signatureValid || !att.complete) attested = false;
    }
    ok("every run on B, the 0.3.5 copies and the new ones, attests keylessly (signed and complete)", attested);
    ok("B's windows never fell below the ones 0.3.5 recorded, at any tick", neverLower);
    const w1 = { "dp-0": await replOf(e, "dp-0"), "dp-1": await replOf(e, "dp-1") };
    ok(`B's windows are now [1, 5] and [2, 6] (got [${w1["dp-0"]?.holdsFrom}, ${w1["dp-0"]?.holdsIndex}] and [${w1["dp-1"]?.holdsFrom}, ${w1["dp-1"]?.holdsIndex}])`, w1["dp-0"]?.holdsFrom === 1 && w1["dp-0"]?.holdsIndex === 5 && w1["dp-1"]?.holdsFrom === 2 && w1["dp-1"]?.holdsIndex === 6);
    ok("the prune coverage covers every run of both downpipes on B", JSON.stringify(await covered(e, "dp-0")) === "[1,3,5]" && JSON.stringify(await covered(e, "dp-1")) === "[2,4,6]");
    ok("the orphan guard counts no run as held on A alone", (await heldOnlyOnA(e)) === 0);
    for (const dp of ["dp-0", "dp-1"]) {
      const st = (await e.storage.get<Record<string, unknown>>(`dp:${dp}`)) as { config: Record<string, unknown> };
      st.config.destinationIds = [B];
      await e.storage.put(`dp:${dp}`, st);
    }
    let removed = true;
    try {
      await e.dobj.removeDest(A, false, OWNER);
    } catch {
      removed = false;
    }
    ok("with A taken off the downpipes, removing A succeeds without force", removed);

    console.log("-- 3. negative control: 0.3.5's rows for B without holdsFrom prove nothing --");
    const c = await load(wire, (rows) => {
      for (const dp of ["dp-0", "dp-1"]) delete (rows[`repl:${dp}`] as Record<string, DestReplState>)[B]!.holdsFrom;
    });
    ok("the orphan guard then counts all 6 runs as held on A alone", (await heldOnlyOnA(c)) === 6);
    ok("and the prune coverage covers no run", (await covered(c, "dp-0")).length === 0 && (await covered(c, "dp-1")).length === 0);
  } finally {
    wire.uninstall();
  }
  console.log(failures === 0 ? "\nREPL BACKCOMPAT V035 PASS\n" : `\nREPL BACKCOMPAT V035 FAIL (${failures})\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
