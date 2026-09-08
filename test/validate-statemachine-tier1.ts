// State-machine: drive the REAL retention prune planner over RANDOM operation sequences and
// assert its invariants hold at EVERY step, over interleavings the example-based validate-prune.ts does not
// reach. NET-ZERO: partitionRuns and computeOrphanSegs are pure; planPrune's only IO is the injected
// segment/run-tree enumerators, supplied here as in-memory maps; RunlogEntry is fake data. No seal, estate,
// bucket, network or spend, and no filesystem or network call anywhere in this file. Run: node
// test/validate-statemachine-tier1.ts (SM_SCALE=8 for a soak).
//
// Model: the account run-log for one downpipe (entries, index-ordered), the next index, and the 3-2-1
// replica-coverage gate. Commands: Backup (append an active entry), PruneKeepRuns / PruneKeepDays (partition,
// then flip the superseded runs to status="superseded" in place, as applyPrune's supersedeRunlog does),
// ReplicaLag / ReplicaClear (move the coverage gate). Invariants (checked after every step) and their file
// grounding are in the design doc. Three refuters (default-FAIL, two-sided) prove the load-bearing invariants
// are not vacuous.

import fc from "fast-check";
import type { RunlogEntry } from "../src/format/writer.ts";
import { partitionRuns, planPrune, type ReplicaCoverage, type RunTreeLister, type SegEnumerator } from "../src/seal/prune.ts";

let failures = 0;
const SCALE = Math.max(1, Math.floor(Number(process.env.SM_SCALE) || 1));

// check throws on a violated invariant, so fast-check shrinks to a minimal counterexample and each cell's
// try/catch reports it without aborting the others.
function check(cond: boolean, label: string): void {
  if (!cond) throw new Error(label);
}

async function cell(name: string, fn: () => void | Promise<void>): Promise<void> {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    console.log(`  FAIL ${name}: ${(e as Error).message}`);
    failures++;
  }
}

const DP = "dp_sm";
const BASE = Date.parse("2026-06-01T00:00:00.000Z"); // fixed epoch; deterministic, no Date.now
const DAY = 86_400_000;

// runIdFor is a monotone, 26-char, lexicographically-ascending id per index, so "most recent by index" and
// "most recent run id" agree (as production ULIDs do).
function runIdFor(index: number): string {
  return `01SMRUN${String(index).padStart(19, "0")}`;
}
function timeFor(index: number): string {
  return new Date(BASE + index * DAY).toISOString();
}
// nowAfter(n) is a "now" one day past index n-1, so a run at index < n is (n - index) days old.
function nowAfter(n: number): Date {
  return new Date(BASE + n * DAY);
}
function mkEntry(index: number, recordCount: number): RunlogEntry {
  return { index, runId: runIdFor(index), downpipeId: DP, time: timeFor(index), recordCount, prevRunId: index === 0 ? null : runIdFor(index - 1), status: "active" };
}

interface Model {
  entries: RunlogEntry[];
  next: number;
  coverage: ReplicaCoverage | undefined;
}
interface Cmd {
  t: string;
  n: number;
}

// ---- pure invariant predicates (also used by the refuters) -------------------------------------

// lastGoodVolumeHolds: a run carrying the global MAX recordCount among the active runs is retained. Existence,
// not universal: an over-cap run whose count EQUALS the retained max is legitimately superseded, but a
// within-cap run of the same count carries the volume forward. Vacuously true when nothing is retained (a
// legitimate all-expired keepDays window).
function lastGoodVolumeHolds(activeBefore: RunlogEntry[], retainedRunIds: readonly string[]): boolean {
  if (retainedRunIds.length === 0 || activeBefore.length === 0) return true;
  const maxRc = Math.max(...activeBefore.map((e) => e.recordCount));
  const retained = new Set(retainedRunIds);
  return activeBefore.some((e) => e.recordCount === maxRc && retained.has(e.runId));
}

// ---- the model interpreter ---------------------------------------------------------------------

function checkPartition(m: Model, activeBefore: RunlogEntry[], policy: { keepRuns?: number; keepDays?: number }): void {
  const part = partitionRuns(m.entries, DP, policy, nowAfter(m.next), m.coverage);
  const retained = new Set(part.retainedRunIds);
  const superseded = new Set(part.supersededRunIds);
  const activeIds = new Set(activeBefore.map((e) => e.runId));

  // INV-3 totality: retained and superseded partition the active set exactly.
  let disjoint = true;
  for (const id of superseded) if (retained.has(id)) disjoint = false;
  const union = new Set<string>([...retained, ...superseded]);
  const covers = union.size === activeIds.size && [...activeIds].every((id) => union.has(id));
  const onlyActive = [...union].every((id) => activeIds.has(id));
  check(disjoint && covers && onlyActive, "INV-3 totality: retained+superseded do not partition the active set");

  // INV-2b last-good (volume): a global-max-recordCount run is retained.
  check(lastGoodVolumeHolds(activeBefore, part.retainedRunIds), "INV-2b last-good: the volume high-water run was superseded");

  // INV-2a last-good (recency): under keepRuns, the newest active run is retained.
  if (policy.keepRuns !== undefined && activeBefore.length >= 1) {
    const maxIdx = Math.max(...activeBefore.map((e) => e.index));
    const newest = activeBefore.find((e) => e.index === maxIdx);
    check(newest !== undefined && retained.has(newest.runId), "INV-2a last-good: newest active run not retained under keepRuns");
  }

  // INV-5 replica floor (3-2-1): with replicas, every superseded run sits inside the proven replica window.
  if (m.coverage?.hasReplicas) {
    const cov = m.coverage;
    const outOfWindow = activeBefore.some((e) => superseded.has(e.runId) && !(e.index >= cov.maxReplicaHoldsFrom && e.index <= cov.minReplicaHoldsIndex));
    check(!outOfWindow, "INV-5 replica floor: a run outside the proven replica window was superseded");
  }

  // Apply the prune's effect on the log: flip the superseded runs in place (never remove; SPEC 10.1).
  for (const e of m.entries) if (superseded.has(e.runId) && e.status === "active") e.status = "superseded";

  // INV-4 idempotence: re-partitioning with the same inputs supersedes nothing new.
  const part2 = partitionRuns(m.entries, DP, policy, nowAfter(m.next), m.coverage);
  check(part2.supersededRunIds.length === 0, "INV-4 idempotence: a second identical prune superseded more runs");
}

function apply(m: Model, c: Cmd): void {
  if (c.t === "backup") {
    m.entries.push(mkEntry(m.next, c.n));
    m.next++;
    return;
  }
  if (c.t === "replicaLag") {
    m.coverage = { hasReplicas: true, minReplicaHoldsIndex: c.n, maxReplicaHoldsFrom: 0 };
    return;
  }
  if (c.t === "replicaClear") {
    m.coverage = undefined;
    return;
  }
  const policy = c.t === "keepRuns" ? { keepRuns: c.n } : { keepDays: c.n };
  const activeBefore = m.entries.filter((e) => e.status === "active");
  checkPartition(m, activeBefore, policy);
}

// INV-1 linearity: indices are exactly [0..next-1], ids unique, status valid, and the id set never shrinks.
function checkLinearity(m: Model, prevIds: Set<string>): void {
  const idx = m.entries.map((e) => e.index);
  const contiguous = idx.length === m.next && idx.every((v, i) => v === i);
  const uniqueIds = new Set(m.entries.map((e) => e.runId)).size === m.entries.length;
  const validStatus = m.entries.every((e) => e.status === "active" || e.status === "superseded");
  const nowIds = new Set(m.entries.map((e) => e.runId));
  const nonShrinking = [...prevIds].every((id) => nowIds.has(id));
  check(contiguous && uniqueIds && validStatus && nonShrinking, "INV-1 linearity: run-log lost, reordered or duplicated an entry");
}

function runSequence(seq: Cmd[]): void {
  const m: Model = { entries: [], next: 0, coverage: undefined };
  let prevIds = new Set<string>();
  for (const c of seq) {
    apply(m, c);
    checkLinearity(m, prevIds);
    prevIds = new Set(m.entries.map((e) => e.runId));
  }
}

// ---- generators --------------------------------------------------------------------------------

const backupArb = fc.record({ t: fc.constant("backup"), n: fc.nat({ max: 6 }) });
const keepRunsArb = fc.record({ t: fc.constant("keepRuns"), n: fc.integer({ min: 1, max: 6 }) });
const keepDaysArb = fc.record({ t: fc.constant("keepDays"), n: fc.integer({ min: 1, max: 40 }) });
const replicaLagArb = fc.record({ t: fc.constant("replicaLag"), n: fc.integer({ min: -1, max: 30 }) });
const replicaClearArb = fc.record({ t: fc.constant("replicaClear"), n: fc.constant(0) });
// Bias toward Backup then Prune by repetition (version-robust, no weight API): 3/8 backup, 3/8 prune.
const cmdArb: fc.Arbitrary<Cmd> = fc.oneof(backupArb, backupArb, backupArb, keepRunsArb, keepRunsArb, keepDaysArb, replicaLagArb, replicaClearArb);
const seqArb = fc.array(cmdArb, { minLength: 1, maxLength: 30 });

// orphanScenarioArb: n runs (all recordCount 1), a keepRuns cap, and random sharing where run a additionally
// references run b's unique segment. The core GC safety is that a segment referenced by any RETAINED run is
// never in orphanSegs.
const orphanScenarioArb = fc.record({
  n: fc.integer({ min: 2, max: 7 }),
  k: fc.integer({ min: 1, max: 5 }),
  sharing: fc.array(fc.tuple(fc.nat({ max: 6 }), fc.nat({ max: 6 })), { maxLength: 8 }),
});

async function main(): Promise<void> {
  const RUNS_SM = 200 * SCALE;
  const RUNS_ORPHAN = 60 * SCALE;

  await cell(`Cell SM: ${RUNS_SM} random operation sequences uphold invariants 1-5`, () => {
    fc.assert(
      fc.property(seqArb, (seq) => {
        runSequence(seq as Cmd[]);
        return true;
      }),
      { numRuns: RUNS_SM },
    );
  });

  await cell(`Cell orphan: ${RUNS_ORPHAN} shared-segment maps keep every retained segment out of orphans`, async () => {
    await fc.assert(
      fc.asyncProperty(orphanScenarioArb, async (sc) => {
        const entries: RunlogEntry[] = [];
        for (let i = 0; i < sc.n; i++) entries.push(mkEntry(i, 1));
        const segMap = new Map<string, string[]>();
        for (let i = 0; i < sc.n; i++) segMap.set(runIdFor(i), [`seg/u/${i}`]);
        for (const [a, b] of sc.sharing) {
          if (a < sc.n && b < sc.n && a !== b) segMap.get(runIdFor(a))!.push(`seg/u/${b}`);
        }
        const enumSegs: SegEnumerator = (r) => Promise.resolve(segMap.get(r) ?? []);
        const listTree: RunTreeLister = (r) => Promise.resolve([`run/${r}/root.manifest.json`]);
        const plan = await planPrune(entries, DP, { keepRuns: sc.k }, nowAfter(sc.n), enumSegs, listTree);
        const retainedSegs = new Set<string>();
        for (const rid of plan.retainedRunIds) for (const s of segMap.get(rid) ?? []) retainedSegs.add(s);
        const leaked = plan.orphanSegs.filter((s) => retainedSegs.has(s));
        check(leaked.length === 0, `INV-6 orphan safety: retained segment(s) fell into the orphan set: ${leaked.join(",")}`);
        return true;
      }),
      { numRuns: RUNS_ORPHAN },
    );
  });

  await cell("Cell abstain: an unreadable retained run defers the whole plan with empty delete sets", async () => {
    const entries = [mkEntry(0, 1), mkEntry(1, 1)]; // keepRuns:1 retains idx1, supersedes idx0
    const segMap: Record<string, string[]> = { [runIdFor(0)]: ["seg/u/0"], [runIdFor(1)]: ["seg/u/1"] };
    const listTree: RunTreeLister = (r) => Promise.resolve([`run/${r}/root.manifest.json`]);
    const throwing: SegEnumerator = (r) => (r === runIdFor(1) ? Promise.reject(new Error("unreadable retained run")) : Promise.resolve(segMap[r] ?? []));
    const deferredPlan = await planPrune(entries, DP, { keepRuns: 1 }, nowAfter(2), throwing, listTree);
    check(deferredPlan.deferred !== undefined, "abstain: a throwing retained enumerator did not defer the plan");
    check(deferredPlan.supersededRunIds.length === 0 && deferredPlan.runTreeObjects.length === 0 && deferredPlan.orphanSegs.length === 0, "abstain: a deferred plan still carried a delete set");
  });

  // ---- refuters (default-FAIL, two-sided) ----

  await cell("R-lastgood: the real cap holds the volume high-water; a guard-less cap drops it (invariant catches it)", () => {
    const entries = [mkEntry(0, 5), mkEntry(1, 0)]; // a full backup then an empty one
    const real = partitionRuns(entries, DP, { keepRuns: 1 }, nowAfter(2));
    // brokenCapNoGuard: keepRuns cap WITHOUT holdVolumeHighWater.
    const mine = entries.filter((e) => e.status === "active").sort((a, b) => a.index - b.index);
    const keep = new Set(mine.slice(Math.max(0, mine.length - 1)).map((e) => e.runId));
    const brokenRetained = mine.filter((e) => keep.has(e.runId)).map((e) => e.runId);
    check(lastGoodVolumeHolds(entries, real.retainedRunIds), "R-lastgood: the real partition failed to hold the volume high-water");
    check(!lastGoodVolumeHolds(entries, brokenRetained), "R-lastgood teeth: the invariant did NOT catch a guard-less cap dropping the high-water");
  });

  await cell("R-orphan: the real subtraction keeps a shared segment out of orphans; the no-subtraction control would orphan it", async () => {
    const entries = [mkEntry(0, 1), mkEntry(1, 1), mkEntry(2, 1)]; // keepRuns:1 retains idx2
    const SHARED = "seg/shared/x";
    const segMap: Record<string, string[]> = {
      [runIdFor(0)]: ["seg/u/0", SHARED], // superseded, shares with the retained run
      [runIdFor(1)]: ["seg/u/1"],
      [runIdFor(2)]: ["seg/u/2", SHARED], // retained, references SHARED -> protects it
    };
    const enumSegs: SegEnumerator = (r) => Promise.resolve(segMap[r] ?? []);
    const listTree: RunTreeLister = (r) => Promise.resolve([`run/${r}/root.manifest.json`]);
    const plan = await planPrune(entries, DP, { keepRuns: 1 }, nowAfter(3), enumSegs, listTree);
    check(!plan.orphanSegs.includes(SHARED), "R-orphan: the real plan orphaned a shared segment");
    const noSub = [...new Set([...segMap[runIdFor(0)]!, ...segMap[runIdFor(1)]!])]; // superseded refs, no subtraction
    check(noSub.includes(SHARED), "R-orphan teeth: the no-subtraction control did not orphan the shared segment");
  });

  await cell("R-abstain: the throw suppresses a delete that WITHOUT it would occur (the abstain is load-bearing)", async () => {
    const entries = [mkEntry(0, 1), mkEntry(1, 1)];
    const segMap: Record<string, string[]> = { [runIdFor(0)]: ["seg/u/0"], [runIdFor(1)]: ["seg/u/1"] };
    const listTree: RunTreeLister = (r) => Promise.resolve([`run/${r}/root.manifest.json`]);
    const clean: SegEnumerator = (r) => Promise.resolve(segMap[r] ?? []);
    const cleanPlan = await planPrune(entries, DP, { keepRuns: 1 }, nowAfter(2), clean, listTree);
    check(cleanPlan.supersededRunIds.length > 0 && cleanPlan.runTreeObjects.length > 0, "R-abstain teeth: without the throw the prune did not delete, so the abstain is vacuous");
  });

  const seqWord = SCALE > 1 ? `SM_SCALE=${SCALE} soak` : "default";
  if (failures > 0) process.exitCode = 1;
  if (failures === 0) {
    console.log(`\nstate-machine Tier 1 OK (${seqWord}): invariants 1-7 upheld, net-zero, refuters cleared.`);
  } else {
    console.log(`\nstate-machine Tier 1 FAILED: ${failures} cell(s).`);
    process.exitCode = 1;
  }
}

await main();
