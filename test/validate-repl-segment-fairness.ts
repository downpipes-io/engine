// validate-repl-segment-fairness: one downpipe's segment-store sync to a new destination does not starve
// the other downpipes sharing the same pass window (src/seal/replicate.ts mirrorRunToReplica, syncSegmentStore).
//
// THE DEFECT (a known issue for 0.3.8). A new destination added to an estate with data is missing the whole
// seg/ store, which is content-addressed and SHARED by every downpipe on that destination. syncSegmentStore
// copies it as a delta and checkpoints on the shared pass budget (src/seal/budget.ts SliceBudget), but a
// single mirrorRunToReplica call had no cap of its own: it kept copying until the WHOLE shared window was
// gone. REPL_FAIR_QUOTA (one run per downpipe per round) does not help, because the window is spent inside
// ONE call before the round-robin ever gets to check it again. Measured live: 5 downpipes, about 13 of 43
// segments copied per tick, catch-up near 2 hours over 8 ticks, because the downpipe ahead in the rotation
// used the whole window every time.
//
// THE FIX: mirrorRunToReplica caps its segment sync to REPL_SEGMENT_SYNC_SHARE (half) of what is left of
// the shared budget when the call starts (SliceBudget.shareWindow). This file proves it directly against
// the real exported core, with in-memory destinations and a real shared SliceBudget threaded across calls
// the way runReplications/processTarget thread ONE SliceBudget across every downpipe's turn in a pass.
//
// dp-big replicates to its OWN new destination with a large missing seg/ store (its first sync); dp-small
// replicates to a COMPLETELY SEPARATE destination pair with a tiny backlog, modelling the common shape: one
// downpipe's destination just gained a huge backlog, the others' destinations did not, and they are
// otherwise unrelated (different stores, no shared seg/ keys). The defect is that dp-big's call used the
// WHOLE shared window regardless, so dp-small never got a turn in the SAME tick even though its own
// destination had almost nothing to do.
//   1. dp-big's sync, given a budget too small to finish in one call, leaves its sync incomplete but does
//      NOT drain the whole shared budget down to the finalise-reserve floor.
//   2. dp-small, sharing the same budget object (as the round-robin does), still has enough of the window
//      left to make progress: it copies its run and its own replica's RUNLOG records it.
//   3. SAFETY: dp-big's run-tree is never copied onto its replica while its segments are incomplete (no
//      run-tree key appears under its run/ prefix there).
//
// Run: node test/validate-repl-segment-fairness.ts

import { mldsaKeygen } from "../src/crypto/pq.ts";
import type { GetResult, ListPage } from "../src/dest/types.ts";
import type { RunlogEntry, Signer } from "../src/format/writer.ts";
import { parseRunlog } from "../src/format/writer.ts";
import type { Meter } from "../src/meter.ts";
import { mirrorRunToReplica } from "../src/seal/replicate.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { MemoryDestination } from "./memdest.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const RUNLOG_KEY = "_RECOVERY/RUNLOG";

// MeteredMemoryDestination spends 1 against a shared Meter on every store round-trip, mirroring how the
// real destinations (S3Destination, R2Destination) report through SliceBudget. The offline MemoryDestination
// does not meter itself, so without this the shared budget's remaining() never moves and every call either
// yields at once or never yields at all; this is what lets ONE call make PARTIAL progress and leave the rest
// of the window for the next.
class MeteredMemoryDestination extends MemoryDestination {
  meter?: Meter;
  override async get(key: string): Promise<GetResult | null> {
    this.meter?.spend(1);
    return super.get(key);
  }
  override async put(key: string, body: Uint8Array): Promise<void> {
    this.meter?.spend(1);
    return super.put(key, body);
  }
  override async list(prefix: string): Promise<string[]> {
    this.meter?.spend(1);
    return super.list(prefix);
  }
  override async listPage(prefix: string, cursor?: string): Promise<ListPage> {
    this.meter?.spend(1);
    return super.listPage(prefix, cursor);
  }
}

function entryFor(downpipeId: string, runId: string): RunlogEntry {
  return { index: 1, runId, downpipeId, time: "2026-09-27T08:00:00.000Z", recordCount: 4, prevRunId: null, status: "active" };
}

// seedRun writes a run-tree (2 objects) plus `count` DISTINCT content-addressed segments under a tag that
// keeps this run's segment ids from colliding with any other run's on the shared store.
function seedRun(dest: MemoryDestination, runId: string, tag: string, count: number): { treeKeys: string[]; segKeys: string[] } {
  const treeKeys = [`run/${runId}/root.manifest.json`, `run/${runId}/manifest/00000.dpe`];
  const segKeys: string[] = [];
  for (let i = 0; i < count; i++) {
    const h = `${tag}${String(i).padStart(4, "0")}`;
    segKeys.push(`seg/${h.slice(0, 2)}/${h}.seg`);
  }
  let i = 0;
  for (const k of treeKeys) void dest.put(k, new TextEncoder().encode(`obj:${k}:${i++}`));
  for (const k of segKeys) void dest.put(k, new TextEncoder().encode(`data:${k}`));
  return { treeKeys, segKeys };
}

async function main(): Promise<void> {
  console.log("-- segment-sync fairness: a large backlog on one downpipe leaves budget for another sharing the same window --");

  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };

  // The shared pass window: ONE SliceBudget, exactly as runReplications threads a single budget across
  // every downpipe's turn in a round (processTarget / mirrorRunToReplica both read the same instance).
  const budget = new SliceBudget({ subrequests: 500, wallMs: 60_000 });

  // dp-big: its OWN new destination pair, with a large missing seg/ store (250 unique segments, far more
  // than the shared window can move in one call).
  const aBig = new MeteredMemoryDestination();
  const bBig = new MeteredMemoryDestination();
  aBig.meter = budget;
  bBig.meter = budget;
  const big = seedRun(aBig, "run-big", "aa", 250);

  // dp-small: a COMPLETELY SEPARATE destination pair (its own origin and replica, no shared seg/ keys with
  // dp-big's), with a tiny backlog, the common shape of "one downpipe's destination just got a lot bigger,
  // the others didn't".
  const aSmall = new MeteredMemoryDestination();
  const bSmall = new MeteredMemoryDestination();
  aSmall.meter = budget;
  bSmall.meter = budget;
  const small = seedRun(aSmall, "run-small", "bb", 2);

  const spentBefore = budget.subrequestsSpent;
  const rBig = await mirrorRunToReplica(aBig, bBig, signer, entryFor("dp-big", "run-big"), { budget });
  const spentAfterBig = budget.subrequestsSpent;
  console.log(`       dp-big: spent ${spentAfterBig - spentBefore} of the shared window; incomplete=${rBig.incomplete === true}`);

  ok("dp-big's sync is genuinely incomplete (the backlog is too large for one call)", rBig.incomplete === true);
  ok("dp-big did NOT drain the whole shared budget to the finalise-reserve floor (headroom is left for the next downpipe)", budget.remaining() > 60);
  ok("dp-big's run-tree is NOT copied before its segments (no run/ key for it on its replica)", (await bBig.list("run/run-big/")).length === 0);

  // dp-small's turn, sharing the SAME budget object, exactly as the round-robin does within one pass.
  const rSmall = await mirrorRunToReplica(aSmall, bSmall, signer, entryFor("dp-small", "run-small"), { budget });
  console.log(`       dp-small: copied=${rSmall.copied}, incomplete=${rSmall.incomplete === true}, remaining=${budget.remaining()}`);

  ok("a SECOND, UNRELATED downpipe sharing the window still makes progress while the first's sync is incomplete", rSmall.incomplete !== true && rSmall.copied > 0 && !rSmall.alreadyDone);
  ok("the small run's segments are all on its replica", (await Promise.all(small.segKeys.map((k) => bSmall.get(k)))).every((v) => v !== null));
  ok("the small run's tree is all on its replica", (await Promise.all(small.treeKeys.map((k) => bSmall.get(k)))).every((v) => v !== null));
  const rl = await bSmall.get(RUNLOG_KEY);
  const entries = rl ? parseRunlog(rl.body) : [];
  ok("dp-small's replica RUNLOG records its run (the done marker)", entries.some((e) => e.runId === "run-small" && e.downpipeId === "dp-small"));
  {
    const copiedSoFar = (await Promise.all(big.segKeys.map((k) => bBig.get(k)))).filter((v) => v !== null).length;
    console.log(`       dp-big: ${copiedSoFar} of ${big.segKeys.length} segments already on its replica (resumes next tick, none re-copied)`);
    ok("dp-big made SOME progress (segments already on its replica)", copiedSoFar > 0);
    ok("dp-big did NOT finish (segments remain missing, consistent with incomplete=true)", copiedSoFar < big.segKeys.length);
  }

  console.log(failures === 0 ? "\nREPL SEGMENT FAIRNESS PASS\n" : `\nREPL SEGMENT FAIRNESS FAIL (${failures})\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
