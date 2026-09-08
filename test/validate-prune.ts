// Prove the retention prune (ASVS V14.2.7: classification-driven retention with automatic
// deletion). This drives the REAL planner (src/seal/prune.ts planPrune/partitionRuns), the REAL
// apply path (applyPrune + supersedeRunlog in src/seal/pipeline.ts) and the REAL freshness check
// (src/format/freshness.ts checkRunlogFreshness) with in-memory doubles. No network, no deploy, no
// cost. Run: node test/validate-prune.ts
//
// Two layers:
//   PART A (pure set logic): partitionRuns + planPrune with INJECTED segment/run-tree enumerators,
//   so the keepRuns/keepDays partition and the orphan set difference are exercised with exact
//   control over which segments are shared and what each run's RUNLOG time is. Proves:
//     (a) keepRuns retains the N most-recent and supersedes the rest,
//     (b) keepDays retains by RUNLOG time and supersedes older runs,
//     (c) a segment SHARED by a retained and a superseded run is NEVER an orphan (the core safety),
//     (d) a segment referenced ONLY by superseded runs IS an orphan.
//   PART B (full integration over real seals): build genuine downpipe/0.1.0 runs into a MemDest (a
//   FIXED master so an unchanged value content-addresses to the SAME seg object across runs, the
//   real shared-segment case), enumerate via the REAL openRun, and prove:
//     (e) DRY-RUN (enforce absent/false) deletes NOTHING and leaves the RUNLOG byte-identical,
//     (f) ENFORCE marks superseded + deletes the run-tree + orphans + re-signs the RUNLOG, while
//         the SHARED segment survives (still referenced by the retained run),
//     (g) the pruned RUNLOG still verifies and freshness does NOT flag a rollback (superseded
//         entries are retained, the reader's own anti-rollback check passes),
//     (h) a second prune is a no-op (idempotent): no further supersede, no further delete.
//   PART C (sizing does not read object bodies): the cron's retention pass calls
//   planPrune the way src/cron/retention-pass.ts does, i.e. WITHOUT a sizeOf lookup, over a
//   Destination spy that counts dest.get() calls. A deletable object is a sealed segment up to 1 GiB,
//   so summing reclaimableBytes via a full-body GET would fetch whole bodies into memory only to read
//   their length. Proves the production-shaped call:
//     (i) reports reclaimableBytes = 0 and issues NO extra body read for sizing, and
//     (j) the OLD body-reading sizeOf is what regressed it (one extra full GET per deletable object),
//         so the spy actually detects the read the fix removed (red-before-green guard).

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { concat, utf8 } from "../src/crypto/bytes.ts";
import type { RecipientEntry, Signer, RunlogEntry } from "../src/format/writer.ts";
import { buildArchive, parseRunlog } from "../src/format/writer.ts";
import { appendRunlog, type RunlogLock } from "../src/seal/pipeline.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { checkRunlogFreshness } from "../src/format/freshness.ts";
import { eqBytes, randomBytes as rand } from "./testutil.ts";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { MemoryDestination } from "./memdest.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import { prunePlannerInputs, groupRetentionByPrimaryDest, replicaCoverageFor, emitVolumeRegressionAlerts, type VolumeRegressionAlert } from "../src/cron/retention-pass.ts";
import type { DownpipeState, DownpipeConfig } from "../src/sched/types.ts";
import type { DestReplState } from "../src/sched/scheduler-do-records.ts";
import type { Env } from "../src/env.d.ts";
import {
  partitionRuns,
  planPrune,
  applyPrune,
  openRunSegEnumerator,
  runTreePrefix,
  type SegEnumerator,
  type RunTreeLister,
  type ReplicaCoverage,
} from "../src/seal/prune.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const DP = "dp_ret";
// A pool of monotonically-increasing ULIDs (lexicographically/numerically ascending) so "most
// recent by index" and "most recent run" line up with the array order.
const RUNS = [
  "01ARZ3NDEKTSV4RRFFQ69G5FA0",
  "01ARZ3NDEKTSV4RRFFQ69G5FA1",
  "01ARZ3NDEKTSV4RRFFQ69G5FA2",
  "01ARZ3NDEKTSV4RRFFQ69G5FA3",
  "01ARZ3NDEKTSV4RRFFQ69G5FA4",
];

// entry builds a RUNLOG entry; status defaults to "active" (the only state a prune supersedes).
function entry(index: number, runId: string, time: string, prevRunId: string | null, status = "active"): RunlogEntry {
  return { index, runId, downpipeId: DP, time, recordCount: 1, prevRunId, status };
}

// entryV is `entry` with an explicit recordCount and derived time/prevRunId, for the volume-regression
// guard (which reads recordCount) and the ring-floor tests (which use arbitrary indices). runId is passed
// so a below-ring index can carry a synthetic id.
function entryV(index: number, runId: string, recordCount: number, prevRunId: string | null, status = "active"): RunlogEntry {
  return { index, runId, downpipeId: DP, time: `2026-06-${String(index).padStart(2, "0")}T00:00:00.000Z`, recordCount, prevRunId, status };
}

// ---- PART A: pure set logic with injected enumerators ------------------------------------------

async function partANbyRuns(): Promise<void> {
  console.log("PART A: keepRuns partition (a) + shared-segment safety (c) + orphan GC (d):");
  // Five active runs, indices 1..5. keepRuns:2 retains the two most-recent (4,5), supersedes 1,2,3.
  const entries: RunlogEntry[] = RUNS.map((r, i) => entry(i + 1, r, `2026-06-0${i + 1}T00:00:00.000Z`, i === 0 ? null : RUNS[i - 1]!));

  const part = partitionRuns(entries, DP, { keepRuns: 2 }, new Date("2026-06-10T00:00:00.000Z"));
  ok("keepRuns:2 retains the 2 most-recent runs (by index)", part.retainedRunIds.length === 2 && part.retainedRunIds.includes(RUNS[3]!) && part.retainedRunIds.includes(RUNS[4]!));
  ok("keepRuns:2 supersedes the other 3", part.supersededRunIds.length === 3 && part.supersededRunIds.includes(RUNS[0]!) && !part.supersededRunIds.includes(RUNS[4]!));

  // Inject a segment map: each run has a UNIQUE segment, PLUS one segment SHARED between a
  // superseded run (RUNS[2], index 3) and a retained run (RUNS[3], index 4). The shared segment
  // must NEVER be an orphan; each superseded run's unique segment MUST be an orphan.
  const SHARED = "seg/sh/shared.seg";
  const segsByRun: Record<string, string[]> = {
    [RUNS[0]!]: ["seg/00/u0.seg"],
    [RUNS[1]!]: ["seg/01/u1.seg"],
    [RUNS[2]!]: ["seg/02/u2.seg", SHARED], // superseded, but also references the shared seg
    [RUNS[3]!]: ["seg/03/u3.seg", SHARED], // RETAINED, references the shared seg -> protects it
    [RUNS[4]!]: ["seg/04/u4.seg"],
  };
  const enumSegs: SegEnumerator = async (runId) => segsByRun[runId] ?? [];
  const listTree: RunTreeLister = async (runId) => [`run/${runId}/root.manifest.json`, `run/${runId}/root.manifest.json.sig`];

  const plan = await planPrune(entries, DP, { keepRuns: 2 }, new Date("2026-06-10T00:00:00.000Z"), enumSegs, listTree);
  // (d) the superseded runs' UNIQUE segments are orphans.
  ok("orphans include each superseded run's unique segment", plan.orphanSegs.includes("seg/00/u0.seg") && plan.orphanSegs.includes("seg/01/u1.seg") && plan.orphanSegs.includes("seg/02/u2.seg"));
  // (c) THE CORE SAFETY PROPERTY: the shared segment is NOT an orphan (a retained run references it).
  ok("the SHARED segment is NOT an orphan (referenced by a retained run)", !plan.orphanSegs.includes(SHARED));
  // The retained runs' unique segments are never orphans either.
  ok("retained runs' segments are not orphans", !plan.orphanSegs.includes("seg/03/u3.seg") && !plan.orphanSegs.includes("seg/04/u4.seg"));
  // The plan's run-tree objects cover exactly the 3 superseded runs (2 objects each).
  ok("run-tree objects cover the 3 superseded runs", plan.runTreeObjects.length === 6 && plan.runTreeObjects.includes(`run/${RUNS[0]!}/root.manifest.json`));
  ok("supersededRunIds on the plan match the partition", plan.supersededRunIds.length === 3);

  // CRITICAL SAFETY (retained-incomplete): if a RETAINED run cannot be enumerated, the protected
  // reference set is incomplete, so the pass MUST abstain entirely rather than risk deleting a
  // segment that retained run shares with a superseded run. Here the retained run RUNS[3] (which
  // shares SHARED with the superseded RUNS[2]) fails to open; the prune must delete NOTHING.
  const enumSegsRetainedFails: SegEnumerator = async (runId) => {
    if (runId === RUNS[3]!) throw new Error("simulated unreadable retained run");
    return segsByRun[runId] ?? [];
  };
  const deferredPlan = await planPrune(entries, DP, { keepRuns: 2 }, new Date("2026-06-10T00:00:00.000Z"), enumSegsRetainedFails, listTree);
  ok("an unreadable RETAINED run makes the pass abstain (deferred set)", typeof deferredPlan.deferred === "string");
  ok("the abstaining plan deletes NO segments (the shared segment is safe)", deferredPlan.orphanSegs.length === 0);
  ok("the abstaining plan supersedes nothing and deletes no run-trees", deferredPlan.supersededRunIds.length === 0 && deferredPlan.runTreeObjects.length === 0);
  // Contrast: an unreadable SUPERSEDED run is simply skipped (not superseded this pass), the rest proceed.
  const enumSegsSupersededFails: SegEnumerator = async (runId) => {
    if (runId === RUNS[0]!) throw new Error("simulated unreadable superseded run");
    return segsByRun[runId] ?? [];
  };
  const skipPlan = await planPrune(entries, DP, { keepRuns: 2 }, new Date("2026-06-10T00:00:00.000Z"), enumSegsSupersededFails, listTree);
  ok("an unreadable SUPERSEDED run is skipped, not abstained", skipPlan.deferred === undefined && skipPlan.supersededRunIds.length === 2 && !skipPlan.supersededRunIds.includes(RUNS[0]!));
  ok("the skipped superseded run's segment is not deleted", !skipPlan.orphanSegs.includes("seg/00/u0.seg"));

  // PRUNE-ABSTAIN regression: after a PRIOR enforced prune, the superseded runs stay in the RUNLOG with
  // status="superseded" and their run-trees are DELETED. A SECOND pass must NOT treat them as protected
  // retained references (openRun would fail on the deleted tree and abstain forever -- the prune-abstain
  // bug). Here RUNS[0..2] are already superseded with unreadable (deleted) trees; the pass must proceed on
  // the active runs and not abstain.
  const afterFirstPrune: RunlogEntry[] = RUNS.map((r, i) =>
    entry(i + 1, r, `2026-06-0${i + 1}T00:00:00.000Z`, i === 0 ? null : RUNS[i - 1]!, i < 3 ? "superseded" : "active"),
  );
  const enumSegsSupersededDeleted: SegEnumerator = async (runId) => {
    if (runId === RUNS[0]! || runId === RUNS[1]! || runId === RUNS[2]!) throw new Error("superseded run tree already deleted");
    return segsByRun[runId] ?? [];
  };
  const secondPass = await planPrune(afterFirstPrune, DP, { keepRuns: 1 }, new Date("2026-06-10T00:00:00.000Z"), enumSegsSupersededDeleted, listTree);
  ok("a second prune after deletes does NOT abstain (prune-abstain fixed)", secondPass.deferred === undefined);
  ok("the second pass supersedes only the newly out-of-window ACTIVE run, ignoring already-superseded runs", secondPass.supersededRunIds.length === 1 && secondPass.supersededRunIds.includes(RUNS[3]!));
}

async function partAByDays(): Promise<void> {
  console.log("PART A: keepDays partition (b):");
  // Three runs at 1, 5 and 20 days before now. keepDays:7 retains the two within 7 days (1d, 5d),
  // supersedes the 20-day-old one.
  const now = new Date("2026-06-30T00:00:00.000Z");
  const day = 24 * 60 * 60 * 1000;
  const entries: RunlogEntry[] = [
    entry(1, RUNS[0]!, new Date(now.getTime() - 20 * day).toISOString(), null),
    entry(2, RUNS[1]!, new Date(now.getTime() - 5 * day).toISOString(), RUNS[0]!),
    entry(3, RUNS[2]!, new Date(now.getTime() - 1 * day).toISOString(), RUNS[1]!),
  ];
  const part = partitionRuns(entries, DP, { keepDays: 7 }, now);
  ok("keepDays:7 retains runs within 7 days (5d, 1d)", part.retainedRunIds.length === 2 && part.retainedRunIds.includes(RUNS[1]!) && part.retainedRunIds.includes(RUNS[2]!));
  ok("keepDays:7 supersedes the 20-day-old run", part.supersededRunIds.length === 1 && part.supersededRunIds[0] === RUNS[0]!);

  // Union semantics: keepRuns:1 OR keepDays:7 retains a run satisfying EITHER bound. The 20-day-old
  // run is outside BOTH; the 5d and 1d runs are within keepDays; the most-recent is also kept by
  // keepRuns. So the same one run is superseded, and combining the bounds never deletes MORE.
  const both = partitionRuns(entries, DP, { keepRuns: 1, keepDays: 7 }, now);
  ok("keepRuns+keepDays union keeps a run satisfying EITHER bound", both.retainedRunIds.length === 2 && both.supersededRunIds.length === 1);

  // An already-superseded entry stays retained-in-place and is NOT re-superseded (idempotence at
  // the partition level): mark the oldest superseded and re-partition; it must not reappear.
  const withSuperseded: RunlogEntry[] = [entry(1, RUNS[0]!, new Date(now.getTime() - 20 * day).toISOString(), null, "superseded"), entries[1]!, entries[2]!];
  const again = partitionRuns(withSuperseded, DP, { keepDays: 7 }, now);
  ok("an already-superseded entry is not re-superseded (stays retained-in-place)", again.supersededRunIds.length === 0);

  // THE CUTOFF ITSELF, pinned to the millisecond. The vectors above are 1, 5 and 20 days against
  // keepDays:7, so the nearest they come to the boundary is two days on the retain side and thirteen on
  // the delete side. A cutoff that silently drifted a day or two either way would not be caught by those
  // coarse vectors, so a customer's 7-day retention could be served as 5-day retention with every archive
  // in the gap deleted. These four vectors close that to one millisecond in both directions.
  //
  // The two ends are asymmetric on purpose: the SHORT end deletes archives the customer asked to keep,
  // which is the direction that loses data, and the LONG end keeps archives past the policy, which
  // costs storage and breaks a retention commitment. Both are wrong, so both are asserted.
  const boundary: RunlogEntry[] = [
    entry(1, RUNS[0]!, new Date(now.getTime() - 7 * day - 1).toISOString(), null), // one ms OUTSIDE
    entry(2, RUNS[1]!, new Date(now.getTime() - 7 * day).toISOString(), RUNS[0]!), // exactly ON the cutoff
    entry(3, RUNS[2]!, new Date(now.getTime() - 6 * day).toISOString(), RUNS[1]!), // one day inside
    entry(4, RUNS[3]!, new Date(now.getTime() - 8 * day).toISOString(), RUNS[2]!), // one day outside
  ];
  const edge = partitionRuns(boundary, DP, { keepDays: 7 }, now);
  ok("keepDays:7 retains a run sitting EXACTLY on the cutoff (the bound is inclusive)", edge.retainedRunIds.includes(RUNS[1]!));
  ok("keepDays:7 supersedes a run ONE MILLISECOND past the cutoff", edge.supersededRunIds.includes(RUNS[0]!));
  ok("keepDays:7 retains a 6-day-old run, so the cutoff cannot silently shorten by a day", edge.retainedRunIds.includes(RUNS[2]!));
  ok("keepDays:7 supersedes an 8-day-old run, so the cutoff cannot silently lengthen by a day", edge.supersededRunIds.includes(RUNS[3]!));
}

// ---- PART B: full integration over real seals -------------------------------------------------

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// A best-effort in-memory RUNLOG lock (acquire -> write -> release), proving the apply path takes
// and releases it; correctness does not depend on it (the conditional write is the backstop).
function memLock(): { lock: RunlogLock; acquires: () => number } {
  let held = false;
  let acquires = 0;
  return {
    lock: {
      acquire: async () => {
        if (held) return null;
        held = true;
        acquires++;
        return "tok";
      },
      release: async () => {
        held = false;
      },
    },
    acquires: () => acquires,
  };
}

// sealRun writes ONE downpipe/0.1.0 run into the dest and accumulates the RUNLOG, exactly like the
// pipeline (skipRunlog on buildArchive, then appendRunlog). A FIXED master is passed so an
// unchanged record value content-addresses to the SAME seg object across runs (the real
// shared-segment case the safety property turns on); a CHANGED value yields a fresh seg.
async function sealRun(
  dest: MemoryDestination,
  signer: Signer,
  recipients: RecipientEntry[],
  master: Uint8Array,
  runId: string,
  index: number,
  prevRunId: string | null,
  time: string,
  value: string,
  lock?: RunlogLock,
): Promise<void> {
  const archive = await buildArchive({
    downpipeId: DP,
    downpipeName: "retention",
    cadence: "3600s",
    runId,
    master,
    recipients,
    signer,
    records: [{ sourceType: "kv", name: "k", value: utf8(value), namespace: "ns" }],
    windowStart: time,
    windowEnd: time,
    createdAt: time,
    runlogIndex: index,
    prevRunId,
    skipRunlog: true,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  for (const [key, body] of archive) await dest.put(key, body);
  await appendRunlog(dest, signer, { index, runId, downpipeId: DP, time, recordCount: 1, prevRunId, status: "active" }, lock);
}

async function partB(): Promise<void> {
  console.log("PART B: full integration (dry-run e, enforce f, freshness g, idempotent h):");
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
  const recipients = [breakGlass.entry, op.entry];
  const identity = parseIdentity(op.identity);
  const verifier = { ed: edPublic, mldsa: mldsa.publicKey };

  const dest = new MemoryDestination();
  const store: ObjectStore = {
    get: async (k: string) => {
      const r = await dest.get(k);
      if (!r) throw new Error(`object ${k} is missing`);
      return r.body;
    },
  };

  // THREE runs under ONE FIXED master, with run 2 and run 3 sharing the SAME record value (so they
  // content-address to the SAME seg object). Run 1 has a distinct value. With keepRuns:1 only run 3
  // is retained, so runs 1 and 2 are superseded; run 2's segment is SHARED with the retained run 3,
  // so it must survive, while run 1's segment is orphaned and deleted.
  const master = rand(32);
  await sealRun(dest, signer, recipients, master, RUNS[0]!, 1, null, "2026-06-01T00:00:00.000Z", "value-one");
  await sealRun(dest, signer, recipients, master, RUNS[1]!, 2, RUNS[0]!, "2026-06-02T00:00:00.000Z", "shared-value");
  await sealRun(dest, signer, recipients, master, RUNS[2]!, 3, RUNS[1]!, "2026-06-03T00:00:00.000Z", "shared-value");

  // Identify the seg objects each run references (via the REAL reader) so we can assert survival.
  const enumSegs = openRunSegEnumerator(store, identity, verifier);
  const segs1 = await enumSegs(RUNS[0]!);
  const segs2 = await enumSegs(RUNS[1]!);
  const segs3 = await enumSegs(RUNS[2]!);
  ok("run 2 and run 3 share the same seg object (content-addressed)", segs2.length === 1 && segs3.length === 1 && segs2[0] === segs3[0]);
  ok("run 1's seg object differs from the shared one", segs1[0] !== segs2[0]);
  const sharedSeg = segs2[0]!;
  const run1Seg = segs1[0]!;
  ok("the shared seg object is present before any prune", await dest.exists(sharedSeg));
  ok("run 1's seg object is present before any prune", await dest.exists(run1Seg));

  const runlogBefore = (await dest.get("_RECOVERY/RUNLOG"))!;
  const entries = parseRunlog(runlogBefore.body);
  ok("RUNLOG has 3 active entries before prune", entries.length === 3 && entries.every((e) => e.status === "active"));

  const listTree: RunTreeLister = (runId) => dest.list(runTreePrefix(runId));
  const now = new Date("2026-06-10T00:00:00.000Z");
  const policy = { keepRuns: 1 };

  // (e) DRY-RUN: compute the plan and DO NOT apply. Nothing is written or deleted; the RUNLOG is
  // byte-identical, every run tree and segment is intact.
  const plan = await planPrune(entries, DP, policy, now, enumSegs, listTree);
  ok("plan supersedes runs 1 and 2 (keepRuns:1 retains run 3)", plan.supersededRunIds.length === 2 && plan.supersededRunIds.includes(RUNS[0]!) && plan.supersededRunIds.includes(RUNS[1]!));
  ok("plan retains run 3 only", plan.retainedRunIds.length === 1 && plan.retainedRunIds[0] === RUNS[2]!);
  ok("plan orphans run 1's seg (only superseded references it)", plan.orphanSegs.includes(run1Seg));
  ok("plan does NOT orphan the shared seg (retained run 3 references it)", !plan.orphanSegs.includes(sharedSeg));
  ok("plan run-tree objects cover runs 1 and 2 (not run 3)", plan.runTreeObjects.some((k) => k.startsWith(runTreePrefix(RUNS[0]!))) && plan.runTreeObjects.some((k) => k.startsWith(runTreePrefix(RUNS[1]!))) && !plan.runTreeObjects.some((k) => k.startsWith(runTreePrefix(RUNS[2]!))));

  // The DRY-RUN contract: the planner is the only thing that ran; nothing was applied.
  const runlogAfterPlan = (await dest.get("_RECOVERY/RUNLOG"))!;
  ok("DRY-RUN left the RUNLOG byte-identical", eqBytes(runlogBefore.body, runlogAfterPlan.body));
  ok("DRY-RUN left run 1's run tree intact", (await dest.list(runTreePrefix(RUNS[0]!))).length > 0);
  ok("DRY-RUN left run 1's seg intact", await dest.exists(run1Seg));
  ok("DRY-RUN left the shared seg intact", await dest.exists(sharedSeg));

  // (f) ENFORCE: apply the plan. Mark superseded + re-sign, delete run-trees + orphans.
  const { lock, acquires } = memLock();
  const result = await applyPrune(dest, signer, plan, lock);
  ok("apply took and released the RUNLOG lock", acquires() === 1);
  ok("apply marked 2 RUNLOG entries superseded", result.superseded === 2);
  ok("apply deleted run 1's orphan seg", result.orphansDeleted === 1);
  ok("apply deleted the superseded run trees", result.runTreeDeleted === plan.runTreeObjects.length && result.runTreeDeleted > 0);

  // The superseded run trees and the orphan seg are gone; the SHARED seg and run 3's tree survive.
  ok("run 1's run tree is deleted", (await dest.list(runTreePrefix(RUNS[0]!))).length === 0);
  ok("run 2's run tree is deleted", (await dest.list(runTreePrefix(RUNS[1]!))).length === 0);
  ok("run 1's orphan seg is deleted", !(await dest.exists(run1Seg)));
  ok("THE SHARED SEG SURVIVES (still referenced by retained run 3)", await dest.exists(sharedSeg));
  ok("retained run 3's tree survives", (await dest.list(runTreePrefix(RUNS[2]!))).length > 0);

  // The RUNLOG entries are RETAINED (not removed): all three still present, runs 1+2 superseded.
  const prunedLog = (await dest.get("_RECOVERY/RUNLOG"))!;
  const prunedEntries = parseRunlog(prunedLog.body);
  ok("RUNLOG still has ALL 3 entries (superseded entries retained, not removed)", prunedEntries.length === 3);
  ok("runs 1 and 2 are marked superseded", prunedEntries.filter((e) => e.status === "superseded").length === 2);
  ok("run 3 stays active", prunedEntries.find((e) => e.runId === RUNS[2]!)?.status === "active");

  // (g) FRESHNESS / anti-rollback: the pruned RUNLOG still verifies and does NOT flag a rollback.
  // The retained run 3 opens with freshness and is the latest; an older superseded run still opens
  // with allowStale (its entry is retained, so it is present and not a rollback), and the chain
  // anomaly detector does NOT trip (superseded predecessors keep the prevRunId chain linear).
  const run3 = await openRun(store, RUNS[2]!, identity, verifier, { verifyFreshness: true });
  ok("(g) retained run 3 verifies and is the latest (no rollback flagged)", run3.freshness?.isLatestForDownpipe === true);
  const run3root = run3.root;
  const fresh = await checkRunlogFreshness(store, RUNS[2]!, run3root, verifier);
  ok("(g) checkRunlogFreshness on the pruned RUNLOG is ok with no anomaly reason", fresh.ok && fresh.reason === undefined);

  // (h) IDEMPOTENT: a second prune is a no-op. Re-read the pruned RUNLOG, re-plan, re-apply.
  const entries2 = parseRunlog((await dest.get("_RECOVERY/RUNLOG"))!.body);
  const plan2 = await planPrune(entries2, DP, policy, now, enumSegs, listTree);
  ok("(h) second plan supersedes nothing (already superseded)", plan2.supersededRunIds.length === 0);
  ok("(h) second plan has no run-tree objects and no orphans", plan2.runTreeObjects.length === 0 && plan2.orphanSegs.length === 0);
  const logBeforeSecond = (await dest.get("_RECOVERY/RUNLOG"))!;
  const result2 = await applyPrune(dest, signer, plan2);
  ok("(h) second apply supersedes nothing and deletes nothing", result2.superseded === 0 && result2.runTreeDeleted === 0 && result2.orphansDeleted === 0);
  ok("(h) second apply left the RUNLOG byte-identical", eqBytes(logBeforeSecond.body, (await dest.get("_RECOVERY/RUNLOG"))!.body));
  ok("(h) the shared seg STILL survives after the second prune", await dest.exists(sharedSeg));
}


// ---- PART C: retention sizing does not read object bodies -----------------

// SpyDestination wraps a MemoryDestination and counts every get(key) so a test can prove the
// retention pass does not fetch whole object bodies just to sum a byte total. Every other method
// delegates unchanged, so the spy is a faithful stand-in for the real destination the cron builds.
class SpyDestination implements Destination {
  readonly gets: string[] = [];
  private readonly inner: MemoryDestination;
  constructor(inner: MemoryDestination) {
    this.inner = inner;
  }
  async get(key: string): Promise<GetResult | null> {
    this.gets.push(key);
    return this.inner.get(key);
  }
  put(key: string, body: Uint8Array): Promise<void> {
    return this.inner.put(key, body);
  }
  putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    return this.inner.putStream(key, body);
  }
  putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    return this.inner.putConditional(key, body, opts);
  }
  exists(key: string): Promise<boolean> {
    return this.inner.exists(key);
  }
  delete(key: string): Promise<void> {
    return this.inner.delete(key);
  }
  list(prefix: string): Promise<string[]> {
    return this.inner.list(prefix);
  }
}

// isDeletableObjectKey is true for the object kinds a prune would delete and the OLD sizing path
// re-fetched whole: the run/<runId>/ tree objects and the seg/ segment payloads. (Anything else a
// get() touches, like _RECOVERY/RUNLOG, is not a deletable body the sizing read was summing.)
function isDeletableObjectKey(key: string): boolean {
  return key.startsWith("run/") || key.startsWith("seg/");
}

async function partC(): Promise<void> {
  console.log("PART C: retention sizing does not read object bodies:");
  // Build the same kind of archive PART B does: three runs under one fixed master, runs 2 and 3
  // sharing a value (one shared seg), run 1 distinct. keepRuns:1 retains run 3, supersedes 1 and 2,
  // and orphans run 1's seg. This gives the prune real run-tree objects and a real orphan seg to size.
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
  const recipients = [breakGlass.entry, op.entry];
  const identity = parseIdentity(op.identity);
  const verifier = { ed: edPublic, mldsa: mldsa.publicKey };

  const mem = new MemoryDestination();
  const master = rand(32);
  await sealRun(mem, signer, recipients, master, RUNS[0]!, 1, null, "2026-06-01T00:00:00.000Z", "value-one");
  await sealRun(mem, signer, recipients, master, RUNS[1]!, 2, RUNS[0]!, "2026-06-02T00:00:00.000Z", "shared-value");
  await sealRun(mem, signer, recipients, master, RUNS[2]!, 3, RUNS[1]!, "2026-06-03T00:00:00.000Z", "shared-value");
  const entries = parseRunlog((await mem.get("_RECOVERY/RUNLOG"))!.body);

  // The cron builds these EXACT helpers in src/cron/retention-pass.ts: an openRun-backed segment
  // enumerator over a get-only ObjectStore, and a run-tree lister over dest.list. We drive planPrune
  // through a SpyDestination so every get() is recorded.
  const spy = new SpyDestination(mem);
  const store: ObjectStore = {
    get: async (k: string) => {
      const r = await spy.get(k);
      if (!r) throw new Error(`object ${k} is missing`);
      return r.body;
    },
  };
  const now = new Date("2026-06-10T00:00:00.000Z");
  const policy = { keepRuns: 1 };

  // THE PRODUCTION BUILDER: retention-pass.ts hands planPrune exactly these inputs. The regression
  // this finding fixed is a body-reading sizeOf; the builder must supply NONE.
  const io = prunePlannerInputs(spy, store, identity, verifier);
  ok("(i) the production prune builder supplies NO sizeOf lookup (no body read for sizing)", io.sizeOf === undefined);

  // Drive the planner with the production-built inputs and count every dest.get(). With no sizeOf the
  // plan reports reclaimableBytes = 0 and no deletable object body is fetched a SECOND time to size it.
  spy.gets.length = 0;
  const plan = await planPrune(entries, DP, policy, now, io.enumerateSegs, io.listRunTree, io.sizeOf);
  const getsWithoutSize = spy.gets.length;
  ok("(i) the prune still plans the deletes (run 1 orphaned, runs 1+2 superseded)", plan.supersededRunIds.length === 2 && plan.orphanSegs.length === 1 && plan.runTreeObjects.length > 0);
  ok("(i) reclaimableBytes is 0 with no sizeOf (the plan does not buy a byte total with a full read)", plan.reclaimableBytes === 0);
  // The deletable objects (run-tree + orphan seg) the OLD sizing path would have re-read: each is read
  // AT MOST once here (only by the openRun enumeration that the plan genuinely needs), never a SECOND
  // time purely to size it. A second read of any single deletable key would be the regressed sizing GET.
  const deletableKeys = new Set<string>([...plan.runTreeObjects, ...plan.orphanSegs]);
  const noKeyReadTwiceForSizing = [...deletableKeys].every((k) => spy.gets.filter((g) => g === k).length <= 1);
  ok("(i) no deletable object body is fetched a second time to size it", noKeyReadTwiceForSizing);

  // (j) RED-BEFORE-GREEN GUARD: reinstate the OLD body-reading sizeOf and prove the spy detects it. It
  // adds exactly one full dest.get() per deletable object (the whole-body read the fix removed) and a
  // positive byte total. If a future edit re-introduced this lookup in the production builder above,
  // io.sizeOf would no longer be undefined and assertion (i) would fail; here we confirm the spy is
  // actually sensitive to that extra read, so the guard is meaningful rather than vacuous.
  spy.gets.length = 0;
  const bodyReadingSizeOf = async (key: string): Promise<number | null> => {
    const r = await spy.get(key);
    return r ? r.body.length : null;
  };
  const sizedPlan = await planPrune(entries, DP, policy, now, io.enumerateSegs, io.listRunTree, bodyReadingSizeOf);
  const getsWithSize = spy.gets.length;
  const deletableCount = sizedPlan.runTreeObjects.length + sizedPlan.orphanSegs.length;
  ok("(j) the OLD sizeOf adds exactly one full GET per deletable object (the read the fix removed)", getsWithSize - getsWithoutSize === deletableCount && deletableCount > 0);
  ok("(j) only the OLD sizeOf yields a positive reclaimableBytes (bought with full-body reads)", sizedPlan.reclaimableBytes > 0);
  // The extra reads land on the DELETABLE objects: under the OLD path every run-tree object and orphan
  // seg is fetched whole at least once (the sizeOf read), and every such key is a deletable-object key
  // (run/ or seg/), so the delta the previous assertion counted is genuinely the body read the fix
  // removed, not an unrelated get().
  const sizedDeletable = [...new Set<string>([...sizedPlan.runTreeObjects, ...sizedPlan.orphanSegs])];
  const everyDeletableReadForSize = sizedDeletable.every((k) => isDeletableObjectKey(k) && spy.gets.includes(k));
  ok("(j) under the OLD sizeOf every deletable object is fetched whole for its size", everyDeletableReadForSize);
}

// ---- PART D: retention grouping keys off the REAL primary destination -------------------

// dpState builds a minimal DownpipeState carrying just the config fields the grouping reads. The
// grouping only touches state.config, so the other DownpipeState fields are filled with inert
// placeholders (the grouping never reads them). retention is always present (the pass pre-filters to
// withRetention before grouping, so every grouped state has a policy).
function dpState(id: string, dest: Partial<Pick<DownpipeConfig, "destinationId" | "destinationIds">>): DownpipeState {
  const config: DownpipeConfig = {
    id,
    name: id,
    cadenceSeconds: 3600,
    enabled: true,
    source: { type: "kv", include: [], exclude: [] },
    retention: { keepRuns: 1, enforce: true },
    ...dest,
  };
  return { config, nextRunAt: 0, lastRunId: null, inFlight: false };
}

// keyOf finds the grouping key that a given downpipe id landed under (the bucket whose RUNLOG the
// retention pass reads for it). null if the downpipe was grouped nowhere (the R1-3 regression: a
// non-default destinationIds[] primary silently dropped from every bucket it should prune).
function keyOf(groups: Map<string, DownpipeState[]>, id: string): string | null {
  for (const [key, group] of groups) if (group.some((s) => s.config.id === id)) return key;
  return null;
}

function partD(): void {
  console.log("PART D: retention grouping keys off the REAL primary destination:");

  // THE RISK: a console-created downpipe pins a NON-DEFAULT primary via destinationIds[] and has
  // NO legacy destinationId. Its runs seal to "dest-b" (primaryDestinationId resolves the first
  // non-blank list entry), so retention MUST read dest-b's RUNLOG. The OLD grouping keyed off the bare
  // s.config.destinationId, which is undefined here, so it bucketed this downpipe under "" (the default
  // RUNLOG) where its runs never appear, and its over-cap runs were NEVER pruned. The fix groups it
  // under "dest-b", the bucket whose RUNLOG actually holds its runs.
  const consoleDp = dpState("dp_console", { destinationIds: ["dest-b"] });
  const legacyDp = dpState("dp_legacy", { destinationId: "dest-a" });
  const defaultDp = dpState("dp_default", {});
  const groups = groupRetentionByPrimaryDest([consoleDp, legacyDp, defaultDp]);

  // (red-before-green) the console downpipe is INCLUDED under its real primary "dest-b". A grouping that
  // keyed off the bare destinationId would read "" (the default bucket), NOT "dest-b".
  ok("a destinationIds[] non-default primary is grouped under that primary (not the default)", keyOf(groups, "dp_console") === "dest-b");
  ok("that downpipe is NOT mis-bucketed under the default \"\" key (the silent-skip)", keyOf(groups, "dp_console") !== "");

  // (legacy unchanged) a legacy single-destinationId downpipe keys off that id, exactly as before.
  ok("a legacy single-destinationId downpipe keys off destinationId (unchanged)", keyOf(groups, "dp_legacy") === "dest-a");
  // (default unchanged) a downpipe with no pinned destination shares the default "" bucket, as before.
  ok("a downpipe with no pinned destination keys off the default \"\" (unchanged)", keyOf(groups, "dp_default") === "");

  // destinationIds[] WINS over a legacy destinationId (the seal path's primaryDestinationId precedence):
  // when both are set the primary is the first non-blank list entry, so retention reads THAT bucket.
  const bothDp = dpState("dp_both", { destinationId: "legacy-x", destinationIds: ["primary-y"] });
  const bothGroups = groupRetentionByPrimaryDest([bothDp]);
  ok("destinationIds[] primary wins over legacy destinationId (matches the seal path)", keyOf(bothGroups, "dp_both") === "primary-y");

  // A blank-only / empty list falls back to the legacy destinationId then the default, so a malformed
  // list never resolves to "" the wrong way (primaryDestinationId drops blanks).
  const blankList = dpState("dp_blank", { destinationId: "fallback-z", destinationIds: ["", "  "] });
  const blankGroups = groupRetentionByPrimaryDest([blankList]);
  ok("a blank-only destinationIds[] falls back to the legacy destinationId", keyOf(blankGroups, "dp_blank") === "fallback-z");

  // Two downpipes that seal to the SAME primary share ONE bucket (the pass reads that RUNLOG once).
  const a = dpState("dp_a", { destinationIds: ["shared"] });
  const b = dpState("dp_b", { destinationId: "shared" });
  const shareGroups = groupRetentionByPrimaryDest([a, b]);
  ok("two downpipes with the same resolved primary share ONE bucket", (shareGroups.get("shared")?.length ?? 0) === 2);
}

// ---- PART E: replica-coverage gate (3-2-1 durability) --------------------------------------

// replState builds a per-destination DestReplState map from a {destId: holdsIndex} shorthand. It also seeds
// holdsFrom = 1 for a PROVEN replica, modelling PART E's "catching up from the first run" scenarios (indices
// 1..5), since the M7 gate now reads BOTH holdsIndex (the top) and holdsFrom (the floor). PART G covers an
// arbitrary floor. The other fields are inert placeholders the gate never touches.
function replState(holds: Record<string, number>): Record<string, DestReplState> {
  const out: Record<string, DestReplState> = {};
  for (const [destId, holdsIndex] of Object.entries(holds)) {
    out[destId] = { holdsRunId: holdsIndex >= 0 ? `run_${holdsIndex}` : null, holdsIndex, ...(holdsIndex >= 1 ? { holdsFrom: 1 } : {}), lastOk: true, lastAttemptAt: 0 };
  }
  return out;
}

// dpFanOut builds a fan-out (primary + replicas) DownpipeState with a retention policy, the shape the
// M7 gate reads (replicaDestinationIds + the configured policy).
function dpFanOut(id: string, destinationIds: string[]): DownpipeState {
  return dpState(id, { destinationIds });
}

async function partE(): Promise<void> {
  console.log("PART E: replica-coverage gate (3-2-1 durability):");

  // Five active runs at indices 1..5, keepRuns:2 => the cap supersedes 1,2,3 and retains 4,5. This is
  // the SAME partition PART A proves; PART E adds the replica gate on top.
  const entries: RunlogEntry[] = RUNS.map((r, i) => entry(i + 1, r, `2026-06-0${i + 1}T00:00:00.000Z`, i === 0 ? null : RUNS[i - 1]!));
  const now = new Date("2026-06-10T00:00:00.000Z");
  const policy = { keepRuns: 2 };

  // A fan-out downpipe: primary "dest-a", one configured replica "dest-b". The replica is LAGGING:
  // it holds only up to index 2 (holdsIndex 2), so runs 3,4,5 are not yet off-site on it.
  const dp = dpFanOut("dp_fan", ["dest-a", "dest-b"]);
  const laggingCov = replicaCoverageFor(dp.config, replState({ "dest-b": 2 }));
  ok("a configured replica makes the gate active (hasReplicas)", laggingCov.hasReplicas && laggingCov.minReplicaHoldsIndex === 2);

  // (red-before-green) run 3 is OVER the keepRuns:2 cap but the lagging replica (holdsIndex 2) does
  // NOT yet hold it, so it is RETAINED on the primary. A gate-less prune supersedes run 3 after the
  // same-tick ordering regardless of the replica lag.
  const gated = partitionRuns(entries, DP, policy, now, laggingCov);
  ok("an over-cap run a lagging replica lacks is RETAINED (not pruned from the primary)", gated.retainedRunIds.includes(RUNS[2]!) && !gated.supersededRunIds.includes(RUNS[2]!));
  // The within-cap runs 4,5 are still retained (cap unchanged) and runs 1,2 (which the replica DOES
  // hold, holdsIndex 2 >= their index) are still superseded: the cap semantics are otherwise unchanged.
  ok("runs the replica already holds AND are over cap are still superseded (cap unchanged)", gated.supersededRunIds.includes(RUNS[0]!) && gated.supersededRunIds.includes(RUNS[1]!));
  ok("within-cap runs stay retained", gated.retainedRunIds.includes(RUNS[3]!) && gated.retainedRunIds.includes(RUNS[4]!));
  // Without the gate the OLD behaviour: run 3 IS superseded (the regression the fix closes). This proves
  // the gate is what changes the outcome, not the partition itself.
  const ungated = partitionRuns(entries, DP, policy, now);
  ok("(contrast) with NO coverage gate the over-cap run 3 IS superseded (the OLD behaviour)", ungated.supersededRunIds.includes(RUNS[2]!));

  // Once the replica CATCHES UP (holdsIndex advances to 5, it now holds every run), the cap applies
  // normally: runs 1,2,3 are superseded again, exactly as the ungated partition.
  const caughtUpCov = replicaCoverageFor(dp.config, replState({ "dest-b": 5 }));
  const afterCatchUp = partitionRuns(entries, DP, policy, now, caughtUpCov);
  ok("once all replicas hold the run, the cap applies normally (run 3 superseded)", afterCatchUp.supersededRunIds.includes(RUNS[2]!) && afterCatchUp.supersededRunIds.length === ungated.supersededRunIds.length);

  // A replica with NO recorded state holds NOTHING (holdsIndex -1): every over-cap run is held until it
  // catches up, the conservative direction when there is no coverage proof.
  const noStateCov = replicaCoverageFor(dp.config, replState({}));
  ok("a replica with no recorded state holds nothing (holdsIndex -1)", noStateCov.hasReplicas && noStateCov.minReplicaHoldsIndex === -1);
  const heldAll = partitionRuns(entries, DP, policy, now, noStateCov);
  ok("with an unproven replica NO over-cap run is superseded (nothing dropped below 3-2-1)", heldAll.supersededRunIds.length === 0);

  // The MOST-BEHIND replica governs: two replicas, one caught up (5) and one lagging (1). The gate uses
  // the minimum (1), so only runs <= 1 are prunable.
  const dp2 = dpFanOut("dp_two", ["dest-a", "dest-b", "dest-c"]);
  const twoCov = replicaCoverageFor(dp2.config, replState({ "dest-b": 5, "dest-c": 1 }));
  ok("the most-behind configured replica governs coverage (min holdsIndex)", twoCov.minReplicaHoldsIndex === 1);
  const twoGated = partitionRuns(entries, DP, policy, now, twoCov);
  ok("only runs the most-behind replica holds are prunable (run 1 superseded, 2..3 held)", twoGated.supersededRunIds.includes(RUNS[0]!) && !twoGated.supersededRunIds.includes(RUNS[1]!) && !twoGated.supersededRunIds.includes(RUNS[2]!));

  // A SINGLE-destination downpipe has no replicas: the gate is inert and retention applies exactly as
  // before (this is the common case, byte-for-byte unchanged).
  const single = dpState("dp_single", { destinationId: "only" });
  const singleCov = replicaCoverageFor(single.config, replState({}));
  ok("a single-destination downpipe has no replicas (gate inert)", !singleCov.hasReplicas);
  const singleGated = partitionRuns(entries, DP, policy, now, singleCov);
  ok("an inert gate prunes exactly as the ungated partition (common case unchanged)", singleGated.supersededRunIds.length === ungated.supersededRunIds.length && singleGated.supersededRunIds.includes(RUNS[2]!));

  // The gate flows through planPrune too (not just partitionRuns): a held over-cap run produces NO
  // supersede and NO delete in the full plan, so a lagging replica genuinely stops the apply.
  const SHARED = "seg/sh/sh.seg";
  const segsByRun: Record<string, string[]> = {
    [RUNS[0]!]: ["seg/00/u0.seg"], [RUNS[1]!]: ["seg/01/u1.seg"], [RUNS[2]!]: ["seg/02/u2.seg"],
    [RUNS[3]!]: ["seg/03/u3.seg", SHARED], [RUNS[4]!]: ["seg/04/u4.seg", SHARED],
  };
  const enumSegs: SegEnumerator = async (runId) => segsByRun[runId] ?? [];
  const listTree: RunTreeLister = async (runId) => [`run/${runId}/root.manifest.json`];
  const plan = await planPrune(entries, DP, policy, now, enumSegs, listTree, undefined, laggingCov);
  ok("planPrune honours the gate: the held run 3 is not superseded and its tree is not deleted", !plan.supersededRunIds.includes(RUNS[2]!) && !plan.runTreeObjects.includes(`run/${RUNS[2]!}/root.manifest.json`));
  ok("planPrune still prunes the replica-covered over-cap runs 1,2", plan.supersededRunIds.includes(RUNS[0]!) && plan.supersededRunIds.includes(RUNS[1]!));
}

// ---- PART F: volume-regression guard -------------------

async function partF(): Promise<void> {
  console.log("PART F: volume-regression guard (never evict the volume high-water for smaller/empty runs):");
  const now = new Date("2026-06-10T00:00:00.000Z");

  // THE BUG SCENARIO: a source EMPTIED. One FULL run (1000 records, index 1) then three EMPTY runs (0
  // records, indices 2-4). keepRuns:3 keeps the newest three (the EMPTIES) and would supersede the full run
  // 1, so a single-dest downpipe with enforce:true would DELETE the last real backup, no alert.
  const emptied: RunlogEntry[] = [
    entryV(1, RUNS[0]!, 1000, null),
    entryV(2, RUNS[1]!, 0, RUNS[0]!),
    entryV(3, RUNS[2]!, 0, RUNS[1]!),
    entryV(4, RUNS[3]!, 0, RUNS[2]!),
  ];
  const part = partitionRuns(emptied, DP, { keepRuns: 3 }, now);
  // (red-before-green) run 1 (the volume high-water) is HELD, not superseded. Without the volume guard the
  // cap would supersede run 1 (outside the newest-3 window) -> the last full backup is deleted.
  ok("the volume high-water run is HELD (not superseded) when newer runs are empty", part.retainedRunIds.includes(RUNS[0]!) && !part.supersededRunIds.includes(RUNS[0]!));
  ok("the empty runs stay retained (within the keepRuns window)", part.retainedRunIds.includes(RUNS[1]!) && part.retainedRunIds.includes(RUNS[2]!) && part.retainedRunIds.includes(RUNS[3]!));
  ok("NOTHING is superseded (the only over-cap run was the high-water, now held)", part.supersededRunIds.length === 0);
  // "the alert is emitted": partitionRuns surfaces a volumeRegression signal the retention pass alerts on.
  ok("a volumeRegression signal is emitted (the alert is surfaced)", part.volumeRegression !== undefined && part.volumeRegression.heldRunIds.includes(RUNS[0]!));
  ok("the signal carries the held high-water count (1000) and the retained max (0)", part.volumeRegression?.heldMaxRecordCount === 1000 && part.volumeRegression?.retainedMaxRecordCount === 0);

  // COMPANION (no regression): normal SAME-VOLUME rollover still prunes exactly as before. Four full runs
  // (1000 each); keepRuns:3 supersedes the oldest, and the guard does NOT hold it (1000 is not > the retained
  // max 1000), so retention is byte-for-byte unchanged and NO volumeRegression signal fires.
  const steady: RunlogEntry[] = [
    entryV(1, RUNS[0]!, 1000, null),
    entryV(2, RUNS[1]!, 1000, RUNS[0]!),
    entryV(3, RUNS[2]!, 1000, RUNS[1]!),
    entryV(4, RUNS[3]!, 1000, RUNS[2]!),
  ];
  const rollover = partitionRuns(steady, DP, { keepRuns: 3 }, now);
  ok("same-volume rollover still supersedes the oldest over-cap run (no regression)", rollover.supersededRunIds.includes(RUNS[0]!) && rollover.supersededRunIds.length === 1);
  ok("same-volume rollover emits NO volumeRegression signal", rollover.volumeRegression === undefined);

  // A SHRUNKEN (not fully empty) source is held too: the guard compares record counts, so the full run is
  // held when newer runs are merely SMALLER, not only when empty.
  const shrunken: RunlogEntry[] = [entryV(1, RUNS[0]!, 1000, null), entryV(2, RUNS[1]!, 10, RUNS[0]!), entryV(3, RUNS[2]!, 10, RUNS[1]!), entryV(4, RUNS[3]!, 10, RUNS[2]!)];
  const shrunk = partitionRuns(shrunken, DP, { keepRuns: 3 }, now);
  ok("a full run is held when newer runs merely SHRANK (not only when empty)", shrunk.retainedRunIds.includes(RUNS[0]!) && shrunk.volumeRegression?.heldMaxRecordCount === 1000 && shrunk.volumeRegression?.retainedMaxRecordCount === 10);

  // keepDays that expires the WHOLE window (nothing retained) is INERT: with no replacements to compare
  // against, the guard does not resurrect an age-expired run (respect the explicit keepDays policy).
  const day = 24 * 60 * 60 * 1000;
  const allOld: RunlogEntry[] = [
    entryV(1, RUNS[0]!, 1000, null),
    entryV(2, RUNS[1]!, 0, RUNS[0]!),
  ].map((e, i) => ({ ...e, time: new Date(now.getTime() - (30 - i) * day).toISOString() }));
  const expired = partitionRuns(allOld, DP, { keepDays: 7 }, now);
  ok("an all-expired keepDays window still supersedes everything (guard inert, no resurrection)", expired.supersededRunIds.length === 2 && expired.volumeRegression === undefined);

  // The guard flows through planPrune: the held run is NOT in the supersede/delete sets, and the plan
  // surfaces the volumeRegression signal for the retention pass to alert on.
  const enumSegs: SegEnumerator = async (runId) => [`seg/xx/${runId}.seg`];
  const listTree: RunTreeLister = async (runId) => [`run/${runId}/root.manifest.json`];
  const heldPlan = await planPrune(emptied, DP, { keepRuns: 3 }, now, enumSegs, listTree);
  ok("planPrune holds the high-water run (not superseded, tree not deleted)", !heldPlan.supersededRunIds.includes(RUNS[0]!) && !heldPlan.runTreeObjects.some((k) => k.startsWith(runTreePrefix(RUNS[0]!))));
  ok("planPrune surfaces the volumeRegression signal for the alert", heldPlan.volumeRegression?.heldRunIds.includes(RUNS[0]!) === true);
}

// ---- PART G: replica holds-window floor bound ----

// arbEntry builds an active RUNLOG entry at an ARBITRARY index (the ring-floor test needs indices well
// past the 5-ULID pool), with a synthetic run id derived from the index.
function arbEntry(index: number, recordCount = 5): RunlogEntry {
  return { index, runId: `run_idx_${index}`, downpipeId: DP, time: `2026-06-01T00:00:${String(index % 60).padStart(2, "0")}.000Z`, recordCount, prevRunId: null, status: "active" };
}

async function partG(): Promise<void> {
  console.log("PART G: replica holds-window floor bound (below-ring runs the replica never held are not pruned):");
  const now = new Date("2026-06-10T00:00:00.000Z");

  // A downpipe with runs at indices 20 (BELOW the replica's ring floor), 50 (INSIDE the window) and 90
  // (above the window, within the keepRuns:1 cap). The replica PROVES it holds only [31, 80] (holdsFrom=31,
  // holdsIndex=80): it was added after run 20 aged out of the 50-run ring, so it NEVER observed run 20.
  const entries: RunlogEntry[] = [arbEntry(20), arbEntry(50), arbEntry(90)];
  const coverage: ReplicaCoverage = { hasReplicas: true, minReplicaHoldsIndex: 80, maxReplicaHoldsFrom: 31 };
  const part = partitionRuns(entries, DP, { keepRuns: 1 }, now, coverage);
  // (red-before-green) run 20 is BELOW the proven floor (31): the replica cannot prove it holds it, so it
  // is NOT replica-covered and is RETAINED on the primary. A pure index compare (20 <= holdsIndex 80 =>
  // covered) would supersede run 20 and the primary would delete its only copy.
  ok("a run BELOW the replica's proven floor is RETAINED (not pruned out from under it)", part.retainedRunIds.includes("run_idx_20") && !part.supersededRunIds.includes("run_idx_20"));
  // Companion: run 50 is genuinely INSIDE [31, 80], so it IS covered and prunes (over the keepRuns:1 cap).
  ok("a run genuinely within [holdsFrom, holdsIndex] is still superseded (normal pruning)", part.supersededRunIds.includes("run_idx_50"));
  ok("the newest run (within the cap) is retained", part.retainedRunIds.includes("run_idx_90"));

  // Contrast: with NO floor bound (floor at -Infinity) run 20 IS superseded, proving the floor bound is what
  // changes the outcome, not the partition itself (this is the OLD over-claim behaviour).
  const noFloor: ReplicaCoverage = { hasReplicas: true, minReplicaHoldsIndex: 80, maxReplicaHoldsFrom: Number.NEGATIVE_INFINITY };
  ok("(contrast) with NO floor bound the below-floor run 20 IS superseded (the OLD over-claim)", partitionRuns(entries, DP, { keepRuns: 1 }, now, noFloor).supersededRunIds.includes("run_idx_20"));

  // replicaCoverageFor plumbs holdsFrom from the repl state into maxReplicaHoldsFrom.
  const dp = dpFanOut("dp_floor", ["dest-a", "dest-b"]);
  const cov = replicaCoverageFor(dp.config, { "dest-b": { holdsRunId: "run_80", holdsIndex: 80, holdsFrom: 31, lastOk: true, lastAttemptAt: 0 } });
  ok("replicaCoverageFor surfaces holdsFrom as maxReplicaHoldsFrom", cov.maxReplicaHoldsFrom === 31 && cov.minReplicaHoldsIndex === 80);
  // A replica with NO recorded floor (a legacy record) proves nothing below its holdsIndex: maxReplicaHoldsFrom
  // is +Infinity, so EVERY over-cap run is held until the replicate pass records a floor (conservative).
  const legacyCov = replicaCoverageFor(dp.config, { "dest-b": { holdsRunId: "run_80", holdsIndex: 80, lastOk: true, lastAttemptAt: 0 } });
  ok("a replica with no recorded floor => maxReplicaHoldsFrom +Infinity (holds everything, conservative)", legacyCov.maxReplicaHoldsFrom === Number.POSITIVE_INFINITY);
  ok("with an unproven floor NO over-cap run is superseded (nothing dropped)", partitionRuns(entries, DP, { keepRuns: 1 }, now, legacyCov).supersededRunIds.length === 0);
}

// ---- PART H: volume-regression alert emission (edge-triggered, fail-open) -----------------------

// schedStub is a DurableObjectStub whose fetch delegates to fetchFn (the same shape validate-drive-budget
// uses), so emitVolumeRegressionAlerts can be driven with no DO and every route observed.
function schedStub(fetchFn: (url: string, init?: RequestInit) => Promise<Response>): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return fetchFn(url, init);
    },
  } as unknown as DurableObjectStub;
}

async function partH(): Promise<void> {
  console.log("PART H: volume-regression alert emission (edge-triggered, fail-open):");
  const calls: { path: string; body: unknown }[] = [];
  const mkStub = (newlyRegressed: string[]): DurableObjectStub =>
    schedStub(async (url, init) => {
      const path = new URL(url).pathname;
      calls.push({ path, body: init?.body ? JSON.parse(init.body as string) : undefined });
      if (path === "/volume-regression/reconcile") return new Response(JSON.stringify({ newlyRegressed }), { status: 200 });
      if (path === "/notify/resolve") return new Response(JSON.stringify({ now: [], digestedCount: 0, emission: null }), { status: 200 });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    });
  const env = {} as unknown as Env; // routeNotification never touches env when no channel resolves (now:[])
  const regressed: VolumeRegressionAlert[] = [{ id: "dp1", name: "Nightly", heldMaxRecordCount: 1000, retainedMaxRecordCount: 0, heldCount: 1 }];

  // A NEW regression -> reconcile posts the id set, gets it back as newly-regressed, and routes one alert.
  calls.length = 0;
  await emitVolumeRegressionAlerts(env, mkStub(["dp1"]), regressed);
  ok("emit posts the regressed id set to /volume-regression/reconcile", calls.some((c) => c.path === "/volume-regression/reconcile" && JSON.stringify((c.body as { regressed: string[] }).regressed) === JSON.stringify(["dp1"])));
  ok("emit routes a notification for the newly-regressed downpipe", calls.some((c) => c.path === "/notify/resolve"));

  // NO new regression -> reconcile still runs (marker upkeep) but NO alert is routed (edge-triggered).
  calls.length = 0;
  await emitVolumeRegressionAlerts(env, mkStub([]), regressed);
  ok("emit still reconciles when nothing is newly regressed (marker clears)", calls.some((c) => c.path === "/volume-regression/reconcile"));
  ok("emit routes NO notification when nothing is newly regressed (edge-triggered)", !calls.some((c) => c.path === "/notify/resolve"));

  // A newly-regressed id with no current report (a raced recovery) is skipped, not crashed or alerted.
  calls.length = 0;
  await emitVolumeRegressionAlerts(env, mkStub(["ghost"]), regressed);
  ok("a newly-regressed id with no current report is skipped (no crash, no alert)", !calls.some((c) => c.path === "/notify/resolve"));

  // Fail-open: a throwing scheduler degrades to no-alert, never throws (a prune must never crash on the alert).
  let threw = false;
  try {
    await emitVolumeRegressionAlerts(env, schedStub(async () => { throw new Error("DO down"); }), regressed);
  } catch {
    threw = true;
  }
  ok("emit is fail-open (a DO fault never throws)", !threw);
}

async function main(): Promise<void> {
  await partANbyRuns();
  await partAByDays();
  await partB();
  await partC();
  partD();
  await partE();
  await partF();
  await partG();
  await partH();
  console.log(failures === 0 ? "\nRETENTION PRUNE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
