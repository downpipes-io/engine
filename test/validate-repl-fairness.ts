// validate-repl-fairness: every downpipe makes progress to a second destination at every cron tick, and
// the second destination catches up within a stated number of ticks.
//
// THE DEFECT (fresh-estate check, five downpipes, both destinations on every downpipe, engine ef0d5398).
// Every replication pass ended "budget-exhausted" with 4 of 5 downpipes deferred. In 23 minutes the second
// destination gained no run and its holdsIndex stayed -1 for every downpipe, so the step the orphan refusal
// names could not finish, and only force ended it.
//
// THE CAUSE (src/seal/replicate.ts at ef0d5398):
//   - runReplications walked the fan-out downpipes in one fixed order (:786) and checked the window only
//     BETWEEN downpipes (:787-792). replicateBacklog walked the destinations in one fixed order, the primary
//     first (:243-246), and processTarget copied the WHOLE backlog of a destination before it returned
//     (:359-403). So the first downpipe used the window first at every tick, and the downpipes after it
//     started only when it had no work left.
//   - A copy that the window cut short still used the window: syncSegmentStore stops before the first
//     segment it cannot afford (:538), but mirrorRunToReplica then copied the run-tree with no window check
//     (:707-716) and returned "incomplete" (:720). processTarget stopped (:389), replicateBacklog stopped
//     (:244) and runReplications deferred the rest (:787). With a small window left, this is a spin: the
//     same downpipe starts the same copy at every tick, copies a run-tree and no segment, and no run
//     becomes held anywhere.
//
// THE FIX, and what this file proves against the real code path (the real SchedulerDO over in-memory
// storage, real sealed archives with real signatures, a stateful S3 wire for both buckets, and a clock that
// charges LATENCY_MS for each destination request):
//   1. FAIR: with N downpipes and M runs each on A, every downpipe holds a run on B after FAIR_TICKS
//      tick(s), and B holds all N*M runs after CATCH_UP_TICKS ticks.
//   2. NO SPIN: when the window left for the pass fits about one copy, the pass does not start a copy it
//      cannot finish, does not copy a run-tree without its segments, and the downpipe that goes first
//      changes from tick to tick, so every downpipe holds a run on B within SPIN_TICKS ticks.
//   2b. THE LIVE SHAPE: about LIVE_LEFT subrequests left for the pass. Every tick copies a segment or holds a
//      run; once the first run is held every downpipe holds one within N-1 more ticks; all N*M within
//      LIVE_TICKS. On ef0d5398 this shape stalls for good: B held 6 of 15 runs and gained nothing from tick
//      20 on, because the caught-up downpipes at the head of the fixed order spent the window on reads.
//   3. SAFETY: within a downpipe runs are copied oldest first, and the recorded window [holdsFrom,
//      holdsIndex] never claims a run B does not hold in its RUNLOG, at every tick.
//   4. NEGATIVE CONTROL: the same checks run against a copy of replicate.ts with the fair order removed
//      (the first downpipe first at every tick, its whole backlog before the next). The fairness checks of
//      sections 1 and 2b must FAIL there, so this file cannot pass without the fair order.
//
// Run: node test/validate-repl-fairness.ts

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { x25519 } from "@noble/curves/ed25519.js";
import { b64urlEncode, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { CRON_CADENCE_MS } from "../src/cron/cron-cadence.ts";
import { S3Destination } from "../src/dest/s3.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type RunlogEntry } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DestReplState } from "../src/sched/scheduler-do-base.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import { runReplications as realRunReplications } from "../src/seal/replicate.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { S3Wire } from "./lib/s3-wire.ts";
import { MockStorage } from "./mock-storage.ts";

type RunReplications = typeof realRunReplications;

// ---- the stated bounds ---------------------------------------------------------------------------------
const N = 5; // downpipes
const M = 3; // runs of each downpipe on A
const LATENCY_MS = 150; // wall time charged for each destination request
// The wall time the passes before replication took: past the 20-second allowance, as on a live tick.
const PRIOR_PASSES_MS = 25_000;
// Section 1: every downpipe holds a run on B after FAIR_TICKS ticks; B holds all N*M runs after
// CATCH_UP_TICKS ticks. FAIR_TICKS is 2, not 1: replication is keyless, so it cannot tell which segments
// belong to a run, and it copies the whole seg/ store from A before the first run from A is held on B
// (syncSegmentStore). The first tick pays that for every downpipe, so one run is held after it.
const FAIR_TICKS = 2;
const CATCH_UP_TICKS = 4;
// Section 2: the tick's earlier passes leave SPIN_LEFT subrequests above the finalise reserve, which fits
// about one copy. Every downpipe holds a run on B within SPIN_TICKS ticks (one lead per downpipe).
const SPIN_LEFT = 90;
const SPIN_TICKS = N;
// Section 2b, the live shape: about 20 subrequests left above the finalise reserve. The smallest guarantee:
// at every tick the pass copies a segment or holds a run (the count of segments and held runs on B rises).
// While the whole seg/ delta is copied no run can be held (4 segments a tick here); from the tick the first
// run is held, every downpipe holds a run within N-1 more ticks, one run is held at every tick, and B holds all
// N*M runs within LIVE_TICKS ticks.
const LIVE_LEFT = 20;
// 35, not 30: each pass now reads the source RUNLOG's signature (one more destination call) before it copies
// an entry out of it, so a RUNLOG this engine cannot vouch for is never a source. In this 20-call window that
// call holds one run a tick where a tick sometimes held two; measured 34 ticks.
const LIVE_TICKS = 35;

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- the clock: a fixed start plus the time this test charges (request latency, the passes before) ------
// The clock does not read real time, so a slow host spends none of the 20-second allowance: the bound holds
// on the charged time alone, the same on every machine.
const realNow = Date.now.bind(Date);
const START = realNow();
let skew = 0;
Date.now = () => START + skew;

const ENDPOINT = "https://s3.example.test";

// ---- the estate: destinations A (default) and B, downpipes dp-0 .. dp-(N-1) ---------------------------
const A = "dest-a";
const B = "dest-b";
const BUCKET: Record<string, string> = { [A]: "archive", [B]: "archive2" };
const DPS = Array.from({ length: N }, (_, d) => `dp-${d}`);

function storedDest(id: string): Record<string, unknown> {
  return { id, label: id, endpoint: ENDPOINT, bucket: BUCKET[id], region: "auto", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "not-a-real-secret", addressing: "path", setAt: 1, setBy: "owner@acme.example", verifiedAt: 1, deleteProbe: "ok" };
}
function runId(i: number): string {
  return `01K5ZZKBKACTAV9WEVGEMMVR${String(i).padStart(2, "0")}`;
}

interface Estate {
  dobj: SchedulerDO;
  storage: MockStorage;
  scheduler: DurableObjectStub;
  env: Env;
  // The run indexes of each downpipe, oldest first.
  runsOf: Record<string, number[]>;
}

// makeEstate seals M runs of each of the N downpipes to A, interleaved in index order as a live estate
// seals them (run index r*N+d+1 is downpipe d's run r), writes the history rings and seeds the DO. Every
// downpipe is configured with [A, B], the state the orphan refusal asks for.
async function makeEstate(wire: S3Wire): Promise<Estate> {
  const signerPrivateB64 = b64urlEncode(crypto.getRandomValues(new Uint8Array(64)));
  const signer = await loadSigner(signerPrivateB64);
  const recipients: RecipientEntry[] = ["break-glass", "operational"].map((role) => ({ role, pub: { x25519: x25519.keygen().publicKey, mlkemEk: mlkemKeygen(crypto.getRandomValues(new Uint8Array(64))).encapKey } }));
  wire.buckets.clear();
  const a = new S3Destination(ENDPOINT, BUCKET[A]!, "auto", "AKIDEXAMPLE", "not-a-real-secret", { addressing: "path" });
  const hist: Record<string, Array<Record<string, unknown>>> = {};
  const prev: Record<string, string | null> = {};
  const runsOf: Record<string, number[]> = {};
  for (const dp of DPS) {
    hist[dp] = [];
    prev[dp] = null;
    runsOf[dp] = [];
  }
  for (let i = 1; i <= N * M; i++) {
    const dp = DPS[(i - 1) % N]!;
    const id = runId(i);
    const archive = await buildArchive({
      downpipeId: dp, downpipeName: dp, cadence: "86400s", runId: id, master: crypto.getRandomValues(new Uint8Array(32)), recipients, signer,
      records: Array.from({ length: 4 }, (_, r) => ({ sourceType: "kv" as const, name: `rec-${r}`, namespace: "ns", value: utf8(`value-${i}-${r}-${"x".repeat(200)}`) })),
      windowStart: "2026-09-27T08:00:00.000Z", windowEnd: "2026-09-27T08:00:01.000Z", createdAt: "2026-09-27T08:00:01.000Z",
      runlogIndex: i, prevRunId: prev[dp]!, skipRunlog: true, randomNonce: () => crypto.getRandomValues(new Uint8Array(16)), randomSalt: () => crypto.getRandomValues(new Uint8Array(16)),
    });
    for (const [k, v] of archive) await a.put(k, v);
    const entry: RunlogEntry = { index: i, runId: id, downpipeId: dp, time: `2026-09-27T08:${String(i).padStart(2, "0")}:00.000Z`, recordCount: 4, prevRunId: prev[dp]!, status: "active" };
    await appendRunlog(a, signer, entry, undefined, { relinkLocalPrev: true });
    hist[dp]!.push({ runId: id, index: i, startedAt: entry.time, status: "ok", destinationId: A, prevRunId: prev[dp] });
    prev[dp] = id;
    runsOf[dp]!.push(i);
  }
  const storage = new MockStorage();
  storage.seed("destinations", { list: [storedDest(A), storedDest(B)], defaultId: A });
  for (const dp of DPS) {
    storage.seed(`dp:${dp}`, { config: { id: dp, name: dp, cadenceSeconds: 86400, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] }, destinationIds: [A, B] }, nextRunAt: Date.now() + 86_400_000, lastRunId: prev[dp], inFlight: false, sealedRuns: M });
    storage.seed(`hist:${dp}`, hist[dp]);
    const top = runsOf[dp]!.at(-1)!;
    storage.seed(`repl:${dp}`, { [A]: { holdsRunId: runId(top), holdsIndex: top, lastOk: true, lastAttemptAt: 1 } });
  }
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const scheduler = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(input, init)) } as unknown as DurableObjectStub;
  const env = { SIGNER_PRIVATE: signerPrivateB64 } as unknown as Env;
  return { dobj, storage, scheduler, env, runsOf };
}

// tick runs the replication pass the way drive() does: the tick budget is built, the overhead lump is spent,
// the passes before replication take PRIOR_PASSES_MS of wall time and `priorSpend` subrequests, and the
// next cron tick is CRON_CADENCE_MS after the previous one.
async function tick(e: Estate, run: RunReplications, priorSpend = 0): Promise<void> {
  skew += CRON_CADENCE_MS - (Date.now() % CRON_CADENCE_MS); // the cron fires on the CRON_CADENCE_MS grid
  const tickBudget = new SliceBudget();
  tickBudget.spend(30 + priorSpend); // DRIVE_OVERHEAD_SUBREQUESTS plus the passes before replication
  skew += PRIOR_PASSES_MS;
  await run(e.env, e.scheduler, tickBudget);
}

function runlogOf(wire: S3Wire, dest: string): RunlogEntry[] {
  const rl = wire.bucket(BUCKET[dest]!).get("_RECOVERY/RUNLOG");
  return rl ? parseRunlog(rl.bytes) : [];
}

// onB is the run indexes of each downpipe that B's RUNLOG holds (the done-marker), in RUNLOG order.
function onB(wire: S3Wire): Record<string, number[]> {
  const out: Record<string, number[]> = {};
  for (const dp of DPS) out[dp] = [];
  for (const x of runlogOf(wire, B)) out[x.downpipeId]?.push(x.index);
  return out;
}

// segmentsOn counts the seg/ objects in a bucket.
function segmentsOn(wire: S3Wire, dest: string): number {
  return [...wire.bucket(BUCKET[dest]!).keys()].filter((k) => k.startsWith("seg/")).length;
}

// treesWithoutMarker counts the run-trees on B whose run B's RUNLOG does not hold: a copy that used the
// window and made nothing restorable.
function treesWithoutMarker(wire: S3Wire): number {
  const held = new Set(runlogOf(wire, B).map((x) => x.runId));
  const trees = new Set<string>();
  for (const k of wire.bucket(BUCKET[B]!).keys()) if (k.startsWith("run/")) trees.add(k.split("/")[1]!);
  return [...trees].filter((t) => !held.has(t)).length;
}

async function replOf(e: Estate, dp: string): Promise<DestReplState | undefined> {
  return (await e.storage.get<Record<string, DestReplState>>(`repl:${dp}`))?.[B];
}

// safetyHolds checks the rules the fix must keep, at one tick: within each downpipe B's RUNLOG holds an
// oldest-first prefix of the downpipe's runs (no run copied before an older one), and the recorded window
// [holdsFrom, holdsIndex] names only runs B's RUNLOG holds.
async function safetyHolds(e: Estate, wire: S3Wire): Promise<string | null> {
  const b = onB(wire);
  for (const dp of DPS) {
    const want = e.runsOf[dp]!.slice(0, b[dp]!.length);
    if (JSON.stringify(b[dp]) !== JSON.stringify(want)) return `${dp}: B holds [${b[dp]}], not the oldest-first prefix [${want}]`;
    const r = await replOf(e, dp);
    if (r === undefined || r.holdsIndex < 0) continue;
    const claimed = e.runsOf[dp]!.filter((i) => i >= (r.holdsFrom ?? Number.POSITIVE_INFINITY) && i <= r.holdsIndex);
    if (r.holdsFrom === undefined || claimed.some((i) => !b[dp]!.includes(i))) return `${dp}: window [${r.holdsFrom}, ${r.holdsIndex}] claims a run B does not hold ([${b[dp]}])`;
  }
  return null;
}

// Verdict is one section's result for one implementation, so the control can require the opposite.
interface Verdict {
  fair: boolean;
  caughtUp: boolean;
  noSpin: boolean;
  spinFair: boolean;
  liveProgress: boolean;
  liveTicks: number;
  liveFirstHeld: number;
  liveAllHaveOne: number;
  safe: boolean;
}

async function sections(wire: S3Wire, run: RunReplications, label: string): Promise<Verdict> {
  const v: Verdict = { fair: false, caughtUp: false, noSpin: true, spinFair: false, liveProgress: true, liveTicks: -1, liveFirstHeld: -1, liveAllHaveOne: -1, safe: true };
  console.log(`-- 1. ${label}: ${N} downpipes, ${M} runs each on A, both destinations on every downpipe --`);
  {
    const e = await makeEstate(wire);
    for (let t = 1; t <= CATCH_UP_TICKS; t++) {
      await tick(e, run);
      const b = onB(wire);
      const bad = await safetyHolds(e, wire);
      if (bad !== null) {
        v.safe = false;
        console.log(`       tick ${t}: SAFETY ${bad}`);
      }
      console.log(`       tick ${t}: runs on B per downpipe [${DPS.map((dp) => b[dp]!.length).join(", ")}]`);
      if (t === FAIR_TICKS) v.fair = DPS.every((dp) => b[dp]!.length > 0);
    }
    const b = onB(wire);
    v.caughtUp = DPS.every((dp) => b[dp]!.length === M);
    let windows = true;
    for (const dp of DPS) {
      const r = await replOf(e, dp);
      if (!(r !== undefined && r.holdsFrom === e.runsOf[dp]![0] && r.holdsIndex === e.runsOf[dp]!.at(-1))) windows = false;
    }
    v.caughtUp &&= windows;
  }
  console.log(`-- 2. ${label}: the passes before replication leave about one copy of the window --`);
  {
    const e = await makeEstate(wire);
    const leads: string[] = [];
    for (let t = 1; t <= SPIN_TICKS; t++) {
      const before = onB(wire);
      await tick(e, run, 700 - 30 - 40 - SPIN_LEFT);
      const after = onB(wire);
      const gained = DPS.filter((dp) => after[dp]!.length > before[dp]!.length);
      leads.push(gained.join("+") || "none");
      const bad = await safetyHolds(e, wire);
      if (bad !== null) {
        v.safe = false;
        console.log(`       tick ${t}: SAFETY ${bad}`);
      }
      const orphanTrees = treesWithoutMarker(wire);
      if (orphanTrees > 0) v.noSpin = false;
      console.log(`       tick ${t}: gained a run on B: ${leads.at(-1)}; run-trees on B with no RUNLOG entry: ${orphanTrees}`);
    }
    const b = onB(wire);
    v.spinFair = DPS.every((dp) => b[dp]!.length > 0);
  }
  console.log(`-- 2b. ${label}: the live shape, about ${LIVE_LEFT} subrequests left for the pass --`);
  {
    const e = await makeEstate(wire);
    const progressOf = (): number => segmentsOn(wire, B) + runlogOf(wire, B).length;
    for (let t = 1; t <= LIVE_TICKS; t++) {
      const before = progressOf();
      await tick(e, run, 700 - 30 - 40 - LIVE_LEFT);
      const after = progressOf();
      if (after <= before) v.liveProgress = false;
      if (treesWithoutMarker(wire) > 0) v.noSpin = false;
      const bad = await safetyHolds(e, wire);
      if (bad !== null) {
        v.safe = false;
        console.log(`       tick ${t}: SAFETY ${bad}`);
      }
      const b = onB(wire);
      console.log(`       tick ${t}: segments on B ${segmentsOn(wire, B)}, runs on B per downpipe [${DPS.map((dp) => b[dp]!.length).join(", ")}]`);
      if (v.liveFirstHeld < 0 && DPS.some((dp) => b[dp]!.length > 0)) v.liveFirstHeld = t;
      if (v.liveAllHaveOne < 0 && DPS.every((dp) => b[dp]!.length > 0)) v.liveAllHaveOne = t;
      if (DPS.every((dp) => b[dp]!.length === M)) {
        v.liveTicks = t;
        break;
      }
      if (!v.liveProgress) break;
    }
  }
  return v;
}

// withoutFairness writes a copy of src/seal/replicate.ts with the fair order removed and imports it. Each
// replacement must match exactly once, so a rename in replicate.ts fails this control rather than turning it
// into a copy of the fixed code.
async function withoutFairness(): Promise<{ run: RunReplications; cleanup: () => void }> {
  const here = dirname(fileURLToPath(import.meta.url));
  const srcSeal = resolve(here, "../src/seal");
  let text = readFileSync(join(srcSeal, "replicate.ts"), "utf8");
  const swaps: Array<[string, string]> = [
    ["const REPL_FAIR_ROTATE = true;", "const REPL_FAIR_ROTATE = false;"],
    ["const REPL_FAIR_QUOTA: number | undefined = 1;", "const REPL_FAIR_QUOTA: number | undefined = undefined;"],
  ];
  for (const [from, to] of swaps) {
    const count = text.split(from).length - 1;
    if (count !== 1) throw new Error(`negative control: expected exactly one "${from}" in replicate.ts, found ${count}`);
    text = text.replace(from, to);
  }
  text = text.replace(/from "\.\.\//g, `from "${pathToFileURL(resolve(srcSeal, ".."))}/`).replace(/from "\.\//g, `from "${pathToFileURL(srcSeal)}/`);
  const dir = mkdtempSync(join(tmpdir(), "repl-fairness-"));
  const file = join(dir, "replicate-unfair.ts");
  writeFileSync(file, text);
  const mod = (await import(pathToFileURL(file).href)) as { runReplications: RunReplications };
  return { run: mod.runReplications, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

async function main(): Promise<void> {
  const wire = new S3Wire(ENDPOINT, () => {
    skew += LATENCY_MS;
  });
  wire.install();
  try {
    const fixed = await sections(wire, realRunReplications, "the engine");
    ok(`1. after ${FAIR_TICKS} tick(s) every one of the ${N} downpipes holds a run on B`, fixed.fair);
    ok(`1. after ${CATCH_UP_TICKS} ticks B holds all ${N * M} runs, and each downpipe's window on B is [first, last]`, fixed.caughtUp);
    ok("2. no tick leaves a run-tree on B without its RUNLOG entry (no copy is started that the window cannot finish)", fixed.noSpin);
    ok(`2. with about one copy of window per tick, every downpipe holds a run on B within ${SPIN_TICKS} ticks`, fixed.spinFair);
    ok(`2b. with about ${LIVE_LEFT} subrequests left, every tick copies a segment or holds a run on B`, fixed.liveProgress);
    ok(`2b. from the tick B holds its first run (${fixed.liveFirstHeld}), every downpipe holds a run within ${N - 1} more ticks (tick ${fixed.liveAllHaveOne})`, fixed.liveFirstHeld > 0 && fixed.liveAllHaveOne > 0 && fixed.liveAllHaveOne - fixed.liveFirstHeld <= N - 1);
    ok(`2b. with about ${LIVE_LEFT} subrequests left, B holds all ${N * M} runs within ${LIVE_TICKS} ticks (took ${fixed.liveTicks})`, fixed.liveTicks > 0 && fixed.liveTicks <= LIVE_TICKS);
    ok("3. at every tick, oldest first within a downpipe, and [holdsFrom, holdsIndex] names only runs B holds", fixed.safe);

    console.log("\n-- 4. negative control: the same checks with the fair order removed must fail --");
    const unfair = await withoutFairness();
    try {
      const control = await sections(wire, unfair.run, "fair order removed");
      ok("4. without the fair order, some downpipe holds no run on B after the first tick", !control.fair);
      ok(`4. without the fair order, with about ${LIVE_LEFT} subrequests left, some downpipe waits more than ${N - 1} ticks after the first run is held (first ${control.liveFirstHeld}, all ${control.liveAllHaveOne})`, !(control.liveFirstHeld > 0 && control.liveAllHaveOne > 0 && control.liveAllHaveOne - control.liveFirstHeld <= N - 1));
      ok("4. the safety rules hold without the fair order too (fairness is not what keeps them)", control.safe);
    } finally {
      unfair.cleanup();
    }
  } finally {
    wire.uninstall();
    Date.now = realNow;
  }
  console.log(failures === 0 ? "\nREPL FAIRNESS PASS\n" : `\nREPL FAIRNESS FAIL (${failures})\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
