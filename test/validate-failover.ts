// Validates 3-2-1 destination FAILOVER (src/index.ts selectSealDestination/destinationReachable,
// src/seal/pipeline.ts relinkLocalPrev, src/seal/replicate.ts origin-based mirror) end to end against
// the REAL anti-rollback verifier (src/format/freshness.ts checkRunlogFreshness). The custody claim is
// that failover, a run sealing to the first REACHABLE destination, not a fixed primary, never forges a
// chain anomaly the reader would read as a rollback, even when a destination skips runs while it is down.
//
// It drives the production append/mirror code on in-memory Destinations with a genuine hybrid signature,
// then verifies each destination's signed RUNLOG with the real freshness check, proving:
//   1. CHAIN CLEANLINESS: every destination's RUNLOG is internally anomaly-free under a failover sequence
//      where one destination is down for several runs and then recovers (the relinkLocalPrev property);
//   2. RESTORE TOLERATED: with the REAL (global-prev) signed manifest, a restore (allowStale) still opens
//      from any destination: clean from one holding the contiguous chain, and with only a benign
//      "prevRunId disagrees with the signed root" note (NEVER a chain-rewritten anomaly) from a gapped one;
//   3. REGRESSION GUARD: had the seal written the GLOBAL prevRunId into the entry (no relink), the gapped
//      destination WOULD dangle and the reader WOULD reject it, so the relink is load-bearing, not cosmetic;
//   4. PROBE: destinationReachable reports a throwing destination down and a responsive one up.
// In-memory doubles only; no network, no deploy, no cost. Run: node test/validate-failover.ts.

import fc from "fast-check";
import { MemoryDestination } from "./memdest.ts";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import { mirrorRunToReplica } from "../src/seal/replicate.ts";
import { signRunlog, parseRunlog, type RunlogEntry, type Signer } from "../src/format/writer.ts";
import { checkRunlogFreshness } from "../src/format/freshness.ts";
import type { HybridVerifier } from "../src/crypto/sign.ts";
import type { ObjectStore } from "../src/format/reader.ts";
import type { RootManifest } from "../src/format/manifest.ts";
import { b64urlEncode, utf8 } from "../src/crypto/bytes.ts";
import { destinationReachable } from "../src/index.ts";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const DP = "dp-A";
const ANOMALY = /chain rewritten|dangling prevRunId|share prevRunId|appears twice|does not chain/;

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

interface SignerCtx {
  signer: Signer;
  verifier: HybridVerifier;
}
async function makeSigner(): Promise<SignerCtx> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  return {
    signer: { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey },
    verifier: { ed: edPublic, mldsa: mldsa.publicKey },
  };
}

// entryFor is the canonical (GLOBAL-prev) RUNLOG line the scheduler hands the seal; the seal's
// relinkLocalPrev overrides prevRunId to the destination-local tail at write time, so the value here is
// only the global lineage the signed manifest records.
function entryFor(index: number, runId: string, globalPrev: string | null): RunlogEntry {
  return { index, runId, downpipeId: DP, time: `2026-06-15T00:0${index}:00.000Z`, recordCount: 2, prevRunId: globalPrev, status: "active" };
}

// seedRun writes a run-tree the mirror copies (a manifest + two segments under run/<runId>/).
function seedRun(dest: MemoryDestination, runId: string): void {
  for (const k of [`run/${runId}/manifest`, `run/${runId}/segments/0`, `run/${runId}/segments/1`]) {
    void dest.put(k, new TextEncoder().encode(`obj:${k}`));
  }
}

// sealTo mimics finaliseRun on a destination: write the run tree, then append the RUNLOG entry with the
// per-destination LOCAL relink (the signed manifest keeps the global prev, which entryFor carries).
async function sealTo(dest: MemoryDestination, s: SignerCtx, entry: RunlogEntry): Promise<void> {
  seedRun(dest, entry.runId);
  await appendRunlog(dest, s.signer, entry, undefined, { relinkLocalPrev: true });
}

// storeFor adapts a MemoryDestination to the ObjectStore checkRunlogFreshness reads (get throws on a
// missing object, exactly as the in-account read-back store does).
function storeFor(dest: MemoryDestination): ObjectStore {
  return {
    get: async (k: string) => {
      const r = await dest.get(k);
      if (!r) throw new Error(`missing ${k}`);
      return r.body;
    },
  };
}

function root(index: number, prevRunId: string | null): RootManifest {
  return { downpipeId: DP, freshness: { runlogIndex: index, prevRunId } } as unknown as RootManifest;
}

// latestEntry reads a destination's RUNLOG and returns the highest-index entry for the downpipe.
async function latestEntry(dest: MemoryDestination): Promise<RunlogEntry> {
  const rl = await dest.get("_RECOVERY/RUNLOG");
  const entries = rl ? parseRunlog(rl.body) : [];
  return entries.filter((e) => e.downpipeId === DP).reduce((m, e) => (e.index > m.index ? e : m));
}

class DownDestination extends MemoryDestination {
  // A destination that cannot accept a write: the put (the failover write-probe) throws, exactly as
  // S3Destination's put does on a network fault / 403 / 404 NoSuchBucket / redirect. A list-only-credential
  // destination would pass a READ probe but fail this PUT: the case the write-probe exists to catch.
  override async put(): Promise<void> {
    throw new Error("the destination refused the write (status 403)");
  }
}

async function main(): Promise<void> {
  const s = await makeSigner();

  // The failover sequence over three destinations A,B,C (configured order [A,B,C]); global runs 1..4.
  // A is the primary but goes DOWN for runs 2 and 3, so they fail over to B; A recovers for run 4. The
  // mirror copies each run from the destination it sealed to (its origin) to the others that are up.
  const A = new MemoryDestination();
  const B = new MemoryDestination();
  const C = new MemoryDestination();

  // run1: A up -> seal A; mirror A->B, A->C.
  await sealTo(A, s, entryFor(1, "run-1", null));
  await mirrorRunToReplica(A, B, s.signer, await latestEntry(A));
  await mirrorRunToReplica(A, C, s.signer, await latestEntry(A));
  // run2: A DOWN -> fail over to B; mirror B->C (A is down and skipped).
  await sealTo(B, s, entryFor(2, "run-2", "run-1"));
  await mirrorRunToReplica(B, C, s.signer, entryFor(2, "run-2", "run-1"));
  // run3: A still DOWN -> seal B; mirror B->C.
  await sealTo(B, s, entryFor(3, "run-3", "run-2"));
  await mirrorRunToReplica(B, C, s.signer, entryFor(3, "run-3", "run-2"));
  // run4: A RECOVERS -> seal A (it skipped 2,3); mirror A->B, A->C.
  await sealTo(A, s, entryFor(4, "run-4", "run-3"));
  await mirrorRunToReplica(A, B, s.signer, entryFor(4, "run-4", "run-3"));
  await mirrorRunToReplica(A, C, s.signer, entryFor(4, "run-4", "run-3"));

  console.log("-- 1. chain cleanliness: every destination's RUNLOG is anomaly-free under failover --");
  for (const [name, dest] of [["A (gapped: held run1, then run4)", A], ["B (sealed 2&3 on failover)", B], ["C (all via mirror)", C]] as const) {
    const e = await latestEntry(dest);
    // Verify against a root that matches this destination's LOCAL prev, so line-43 passes and the
    // internal chain-anomaly detector is what is exercised: it must find NO anomaly.
    const res = await checkRunlogFreshness(storeFor(dest), e.runId, root(e.index, e.prevRunId ?? null), s.verifier, { allowStale: true });
    ok(`${name}: chain is well-formed (no rollback anomaly)`, res.ok === true && !ANOMALY.test(res.reason ?? ""));
  }
  // The gap is real: A genuinely skipped runs 2 and 3 (only run1 and run4 live there), and its local
  // chain still links run4 -> run1 cleanly. That is the relinkLocalPrev property under failover.
  {
    const rl = await A.get("_RECOVERY/RUNLOG");
    const idx = (rl ? parseRunlog(rl.body) : []).filter((e) => e.downpipeId === DP).map((e) => e.index).sort((a, b) => a - b);
    ok("A really skipped runs 2 and 3 (a true gap, not back-filled)", JSON.stringify(idx) === JSON.stringify([1, 4]));
    const e4 = await latestEntry(A);
    ok("A's run4 entry relinked to its LOCAL tail run1 (not the global prev run3)", e4.prevRunId === "run-1");
  }

  console.log("-- 2. restore tolerated: real (global-prev) manifest opens from any destination --");
  {
    // From B, which holds the contiguous chain, run4's local prev IS the global prev -> a clean restore.
    const fromB = await checkRunlogFreshness(storeFor(B), "run-4", root(4, "run-3"), s.verifier, { allowStale: true });
    ok("restore of run4 from a contiguous destination (B) is clean (ok, no reason)", fromB.ok === true && fromB.reason === undefined);
    // From A (the gapped origin of run4) the global manifest prev (run3) disagrees with A's local tail
    // (run1): restore still opens under allowStale with only that benign note, NEVER a chain anomaly.
    const fromA = await checkRunlogFreshness(storeFor(A), "run-4", root(4, "run-3"), s.verifier, { allowStale: true });
    ok("restore of run4 from the gapped origin (A) still opens (allowStale)", fromA.ok === true);
    ok("the gapped-origin note is the benign prev-vs-root disagreement, not a rollback anomaly", /disagrees with the signed root/.test(fromA.reason ?? "") && !ANOMALY.test(fromA.reason ?? ""));
  }

  console.log("-- 3. regression guard: the GLOBAL prev (no relink) WOULD dangle and be rejected --");
  {
    // Had the seal written run4's GLOBAL prev (run3) into A's entry, A = [run1, run4->run3] dangles
    // (run3 is not in A). The real reader must reject it, proving the relink is load-bearing.
    const naive = [entryFor(1, "run-1", null), entryFor(4, "run-4", "run-3")];
    const { runlog, sig } = await signRunlog(naive, s.signer.edPrivate, s.signer.mldsaSecret);
    const store: ObjectStore = {
      get: async (k: string) => {
        const m = new Map<string, Uint8Array>([["_RECOVERY/RUNLOG", runlog], ["_RECOVERY/RUNLOG.sig", utf8(b64urlEncode(sig))]]);
        const v = m.get(k);
        if (!v) throw new Error(`missing ${k}`);
        return v;
      },
    };
    const strict = await checkRunlogFreshness(store, "run-4", root(4, "run-3"), s.verifier);
    ok("a global-prev (un-relinked) gapped chain IS rejected by the reader (ok:false)", strict.ok === false);
    ok("the rejection names a chain anomaly (dangling / does-not-chain)", ANOMALY.test(strict.reason ?? ""));
  }

  console.log("-- 4. out-of-order arrival (the mirror-vs-seal race on one destination) forges NO rollback --");
  {
    // The race: the lock-holding SEAL of run3 lands on destination D first (D had no earlier runs yet),
    // then the lock-free MIRROR of run2 lands LATE (lower index), then run1. A naive "link to the current
    // max-index tail" relink would write run2 -> run3 (a forward link) and the reader would read it as a
    // "chain rewritten" rollback. The whole-chain relink must instead leave a clean ascending chain.
    const D = new MemoryDestination();
    await appendRunlog(D, s.signer, entryFor(3, "run-3", "run-2"), undefined, { relinkLocalPrev: true });
    await appendRunlog(D, s.signer, entryFor(2, "run-2", "run-1"), undefined, { relinkLocalPrev: true });
    await appendRunlog(D, s.signer, entryFor(1, "run-1", null), undefined, { relinkLocalPrev: true });
    const rl = await D.get("_RECOVERY/RUNLOG");
    const es = (rl ? parseRunlog(rl.body) : []).filter((e) => e.downpipeId === DP).sort((a, b) => a.index - b.index);
    ok("out-of-order arrival still yields a linear chain (run1 -> null)", es[0]?.prevRunId === null);
    ok("out-of-order arrival still yields a linear chain (run2 -> run1)", es[1]?.prevRunId === "run-1");
    ok("out-of-order arrival still yields a linear chain (run3 -> run2)", es[2]?.prevRunId === "run-2");
    const res = await checkRunlogFreshness(storeFor(D), "run-3", root(3, "run-2"), s.verifier, { allowStale: true });
    ok("the real reader finds NO anomaly after out-of-order arrival (no false rollback)", res.ok === true && !ANOMALY.test(res.reason ?? ""));
  }

  console.log("-- 5. write-probe: destinationReachable distinguishes writable from down --");
  {
    ok("a writable destination (put succeeds) is reachable", (await destinationReachable(new MemoryDestination())) === true);
    ok("a write-denied destination (put throws) is NOT reachable", (await destinationReachable(new DownDestination())) === false);
    // The write-probe leaves no marker behind on a healthy destination (best-effort delete ran), and uses
    // a single fixed key (no per-run nonce) so a delete-refusing immutable bucket accrues at most one marker.
    const d = new MemoryDestination();
    await destinationReachable(d);
    await destinationReachable(d);
    ok("the write-probe cleans up its fixed marker (no _RECOVERY/.reachable left)", (await d.list("_RECOVERY/.reachable")).length === 0);
  }

  console.log("-- 6. backlog catch-up: a destination that missed runs gets ALL of them back-filled --");
  {
    // The E fix: replicateBacklog catches each destination up on EVERY run it is missing, not just the
    // latest, so a run that landed while a destination was briefly down is not stranded forever. Here the
    // origin O holds runs 1..4; destination G was down for 2 and 3 (it only ever received run 1). The
    // backlog mirrors every missing run from O to G (the inner operation replicateBacklog performs per
    // destination), and the reader must then see a COMPLETE, clean chain on G.
    const O = new MemoryDestination();
    const G = new MemoryDestination();
    const runs: Array<[number, string, string | null]> = [[1, "b1", null], [2, "b2", "b1"], [3, "b3", "b2"], [4, "b4", "b3"]];
    for (const [i, rid, prev] of runs) await sealTo(O, s, entryFor(i, rid, prev)); // O is the origin of all four
    await mirrorRunToReplica(O, G, s.signer, entryFor(1, "b1", null)); // G only ever got run 1 (down for 2,3,4)
    ok("precondition: G holds only run 1 (a real gap)", JSON.stringify((parseRunlog((await G.get("_RECOVERY/RUNLOG"))!.body)).map((e) => e.index).sort((a, b) => a - b)) === JSON.stringify([1]));

    // Backlog: mirror every run G is missing from its origin O (oldest-first, as replicateBacklog does).
    const oEntries = parseRunlog((await O.get("_RECOVERY/RUNLOG"))!.body);
    const have = new Set(parseRunlog((await G.get("_RECOVERY/RUNLOG"))!.body).map((e) => e.runId));
    for (const e of oEntries.sort((a, b) => a.index - b.index)) {
      if (!have.has(e.runId)) await mirrorRunToReplica(O, G, s.signer, e);
    }

    const gIdx = parseRunlog((await G.get("_RECOVERY/RUNLOG"))!.body).map((e) => e.index).sort((a, b) => a - b);
    ok("G is caught up on the WHOLE backlog (runs 1,2,3,4 not just the latest)", JSON.stringify(gIdx) === JSON.stringify([1, 2, 3, 4]));
    const gLatest = await latestEntry(G);
    const res = await checkRunlogFreshness(storeFor(G), gLatest.runId, root(gLatest.index, gLatest.prevRunId ?? null), s.verifier, { allowStale: true });
    ok("the back-filled chain on G is clean (no anomaly)", res.ok === true && !ANOMALY.test(res.reason ?? ""));
    // Every run-tree object came across too (G is independently restorable for each run, not just RUNLOG entries).
    const treesPresent = await Promise.all(["b1", "b2", "b3", "b4"].map(async (rid) => (await G.list(`run/${rid}/`)).length >= 3));
    ok("every back-filled run's tree objects are present on G (independently restorable)", treesPresent.every(Boolean));
  }

  console.log("-- 7. replication runs BEFORE retention so a trailing replica catches up before the primary prunes --");
  {
    // The integrity-pair risk: retention prunes the PRIMARY (deletes a superseded run-tree + its now-orphaned
    // seg/ data), so a replica that was briefly down and never received a run is permanently stranded without
    // the bytes if the prune ran FIRST in the tick. The fix orders replication before retention. We model one
    // tick's two operations in each order on in-memory destinations: "replicate" mirrors the run to the
    // trailing replica; "prune" removes the run's tree + data segments from the PRIMARY (what applyPrune does).
    // A replica is restorable iff it holds the run's tree objects AND its data segments.
    type Tick = Array<"replicate" | "prune">;
    async function runTick(order: Tick): Promise<{ replicaRestorable: boolean }> {
      const primary = new MemoryDestination();
      const replica = new MemoryDestination(); // trailing: it has NOT received the run yet
      // Seed the run on the primary the way the seal produces it: a run-tree under run/<id>/ AND content-
      // addressed data segments under seg/ (a SEPARATE prefix), so a manifest-only copy is non-restorable.
      const runId = "tick-run-1";
      const treeKeys = [`run/${runId}/root.manifest.json`, `run/${runId}/manifest/00000.dpe`];
      const segKeys = ["seg/aa/aa00.seg", "seg/bb/bb11.seg"];
      for (const k of treeKeys) await primary.put(k, utf8(`obj:${k}`));
      for (const k of segKeys) await primary.put(k, utf8(`data:${k}`));
      const entry = entryFor(1, runId, null);
      for (const step of order) {
        if (step === "replicate") {
          await mirrorRunToReplica(primary, replica, s.signer, entry);
        } else {
          // Retention prunes the PRIMARY: delete the superseded run-tree and its now-orphaned seg/ data.
          for (const k of [...treeKeys, ...segKeys]) await primary.delete(k);
        }
      }
      const repKeys = new Set([...replica.entries().keys()]);
      const replicaRestorable = treeKeys.every((k) => repKeys.has(k)) && segKeys.every((k) => repKeys.has(k));
      return { replicaRestorable };
    }
    // The OLD order (prune BEFORE replicate) strands the trailing replica: the primary deleted the run's data
    // before replication could source it, so the replica ends up without the bytes (the red-before-green case).
    const stale = await runTick(["prune", "replicate"]);
    ok("prune-before-replicate (the OLD order) STRANDS the trailing replica (no data to restore from)", stale.replicaRestorable === false);
    // The FIX (replicate BEFORE prune) lets the trailing replica catch up first, so it is independently
    // restorable even though the primary then prunes the run in the same tick.
    const fixed = await runTick(["replicate", "prune"]);
    ok("replicate-before-prune (the FIX) leaves the trailing replica independently restorable", fixed.replicaRestorable === true);

    // Ground the model in the PRODUCTION orchestrator: drive() must actually call runReplications BEFORE
    // runRetentionPrunes in the tick. Reading the source order guards the invariant directly rather than
    // just the in-memory model above.
    // The two passes are invoked through drive()'s `guarded(...)` wrapper (which tallies AND classifies each
    // pass's fault for the support pack), so they are matched by the FUNCTION NAME rather than by an
    // `await ` prefix. The invariant this guards is unchanged and is the load-bearing one: replication must be
    // called BEFORE retention, or a trailing replica is stranded when the primary prunes the run first.
    const driveSrc = readFileSync(fileURLToPath(new URL("../src/cron/drive.ts", import.meta.url)), "utf8");
    const replIdx = driveSrc.indexOf("runReplications(env");
    const retIdx = driveSrc.indexOf("runRetentionPrunes(env");
    ok("drive() calls runReplications and runRetentionPrunes (sanity)", replIdx >= 0 && retIdx >= 0);
    ok("drive() orders replication BEFORE retention (replicate-first, M5(b))", replIdx >= 0 && retIdx >= 0 && replIdx < retIdx);
  }

  // ---- SM-FAILOVER (broad DO state-machine, the failover half): fuzz a run->destination routing sequence with
  // destinations randomly UP/DOWN each run. A run seals to the first REACHABLE destination and mirrors to the
  // other reachable ones; over EVERY fuzzed sequence, each destination's RUNLOG must chain cleanly, because
  // relinkLocalPrev keeps even a GAPPED destination internally consistent -- so checkRunlogFreshness finds NO
  // forged-rollback anomaly. This extends the fixed failover vectors above to RANDOM up/down interleavings
  // (retention + prune are the E2 state-machine; this is the failover routing half the tick asks for).
  console.log("-- SM-FAILOVER: fuzzed failover routing keeps every destination's chain anomaly-free --");
  {
    const upMasksArb = fc.array(fc.integer({ min: 1, max: 7 }), { minLength: 2, maxLength: 12 }); // per-run 3-bit up-mask, always >=1 dest up
    let smThrew = 0;
    let sawGap = false;
    try {
      await fc.assert(
        fc.asyncProperty(upMasksArb, async (masks) => {
          const dests = [new MemoryDestination(), new MemoryDestination(), new MemoryDestination()];
          const held: number[][] = [[], [], []];
          let globalPrev: string | null = null;
          for (let i = 0; i < masks.length; i++) {
            const up = [0, 1, 2].filter((d) => (masks[i]! >> d) & 1);
            const primary = up[0]!; // the first REACHABLE destination is where the run seals
            const runId = `run-${i + 1}`;
            const entry = entryFor(i + 1, runId, globalPrev);
            await sealTo(dests[primary]!, s, entry);
            held[primary]!.push(i + 1);
            for (const d of up) {
              if (d === primary) continue;
              await mirrorRunToReplica(dests[primary]!, dests[d]!, s.signer, entry);
              held[d]!.push(i + 1);
            }
            globalPrev = runId;
          }
          for (let d = 0; d < 3; d++) {
            if (held[d]!.length === 0) continue;
            if (held[d]!.length < masks.length) sawGap = true; // this destination genuinely skipped some runs
            const e = await latestEntry(dests[d]!);
            const res = await checkRunlogFreshness(storeFor(dests[d]!), e.runId, root(e.index, e.prevRunId ?? null), s.verifier, { allowStale: true });
            if (!(res.ok === true && !ANOMALY.test(res.reason ?? ""))) {
              throw new Error(`dest ${d} (holds [${held[d]!.join(",")}]) chain anomaly under fuzzed failover: ${res.reason}`);
            }
          }
        }),
        { numRuns: 60 },
      );
    } catch (e) {
      smThrew = 1;
      console.error(`  SM-FAILOVER counterexample: ${(e as Error).message}`);
    }
    ok("SM-FAILOVER: every fuzzed failover routing leaves each destination's chain anomaly-free (relinkLocalPrev)", smThrew === 0);
    ok("SM-FAILOVER exercised genuinely GAPPED destinations (a destination that skipped some runs)", sawGap);
  }

  // SM-FAILOVER refuter (default-FAIL): a GAPPED destination sealed with the GLOBAL prev (no relink) MUST be
  // flagged anomalous, so the clean-chain property above is non-vacuous (checkRunlogFreshness has teeth).
  {
    const X = new MemoryDestination();
    await sealTo(X, s, entryFor(1, "run-1", null)); // X holds run1
    // runs 2 and 3 went elsewhere (X is gapped); now seal run4 into X WITHOUT the local relink, so its prev is
    // the GLOBAL run3 -- which X does not hold.
    seedRun(X, "run-4");
    await appendRunlog(X, s.signer, entryFor(4, "run-4", "run-3"), undefined, { relinkLocalPrev: false });
    const e = await latestEntry(X);
    const res = await checkRunlogFreshness(storeFor(X), e.runId, root(e.index, e.prevRunId ?? null), s.verifier, { allowStale: true });
    ok("SM-FAILOVER refuter: a gapped destination sealed with the GLOBAL prev (no relink) IS flagged anomalous", !(res.ok === true && !ANOMALY.test(res.reason ?? "")));
  }

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nFAILOVER VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
