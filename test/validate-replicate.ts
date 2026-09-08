// Validates 3-2-1 fan-out replication (src/seal/replicate.ts): the per-replica core mirrorRunToReplica
// copies a finalised run's tree objects to a replica and appends the run to the replica's OWN RUNLOG
// with a REPLICA-LOCAL prevRunId, idempotently (a second pass copies nothing and never duplicates the
// RUNLOG entry). Also checks the primary/replica resolution helpers. In-memory Destinations, a real
// signer; no network. Run: node test/validate-replicate.ts.

import { MemoryDestination, flipBit } from "./memdest.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type RunlogEntry, type Signer } from "../src/format/writer.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import type { GetResult } from "../src/dest/types.ts";
import { x25519 } from "@noble/curves/ed25519.js";
import { utf8 } from "../src/crypto/bytes.ts";
import { mirrorRunToReplica, highestContiguousRun, replVerifySegmentsEnabled, type RunOrigin } from "../src/seal/replicate.ts";
import type { Env } from "../src/env.d.ts";
import { primaryDestinationId, replicaDestinationIds, allDestinationIds } from "../src/sched/scheduler-do.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { frame } from "../src/format/container.ts";
import { MAGIC_SEG, MAGIC_DPE } from "../src/format/version.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

function entryFor(runId: string, index: number, prevRunId: string | null): RunlogEntry {
  return { index, runId, downpipeId: "dp-A", time: "2026-06-13T00:00:00.000Z", recordCount: 3, prevRunId, status: "active" };
}

// seedRun writes the shape the seal ACTUALLY produces: a run-tree manifest under run/<runId>/ AND the
// record DATA in content-addressed seg/ objects, which are a SEPARATE top-level prefix (seg/<aa>/<id>.seg)
// shared across runs, NOT under run/<runId>/ (see format/writer.ts segmentObjectKey). It returns the
// run-tree keys and the seg keys separately so a test can assert the replica holds BOTH: a manifest-only
// copy (run-tree without seg/ data) would be a silently non-restorable replica. The seg ids
// default the same across runs to model the real content-addressed dedup (two runs sharing a value share
// a segment object), which a second mirror then skips.
function seedRun(dest: MemoryDestination, runId: string, segIds: string[] = ["aa00", "bb11"]): { treeKeys: string[]; segKeys: string[]; all: string[] } {
  const treeKeys = [`run/${runId}/root.manifest.json`, `run/${runId}/manifest/00000.dpe`];
  const segKeys = segIds.map((h) => `seg/${h.slice(0, 2)}/${h}.seg`);
  let i = 0;
  for (const k of treeKeys) void dest.put(k, new TextEncoder().encode(`obj:${k}:${i++}`));
  for (const k of segKeys) void dest.put(k, new TextEncoder().encode(`data:${k}`));
  return { treeKeys, segKeys, all: [...treeKeys, ...segKeys] };
}

// seedFramedRun is like seedRun but writes PROPERLY-FRAMED seg/ containers (the 5-byte DPS1 header that
// format/container.ts unframeSeg checks), so the opt-in verifySegments structural check passes on a
// faithful copy. The run-tree objects stay plain (verifySegments only inspects seg/ bytes).
function seedFramedRun(dest: MemoryDestination, runId: string, segIds: string[]): { treeKeys: string[]; segKeys: string[] } {
  const treeKeys = [`run/${runId}/root.manifest.json`, `run/${runId}/manifest/00000.dpe`];
  const segKeys = segIds.map((h) => `seg/${h.slice(0, 2)}/${h}.seg`);
  let i = 0;
  for (const k of treeKeys) void dest.put(k, new TextEncoder().encode(`obj:${k}:${i++}`));
  for (const k of segKeys) void dest.put(k, frame(MAGIC_SEG, new TextEncoder().encode(`payload:${k}`)));
  return { treeKeys, segKeys };
}

function testResolutionHelpers(): void {
  console.log("-- resolution helpers: primary, replicas (dedup + primary excluded), back-compat --");
  {
    ok("destinationIds[0] is the primary", primaryDestinationId({ destinationIds: ["a", "b", "c"] }) === "a");
    ok("replicas are the rest", JSON.stringify(replicaDestinationIds({ destinationIds: ["a", "b", "c"] })) === JSON.stringify(["b", "c"]));
    ok("duplicates and the primary are dropped from replicas", JSON.stringify(replicaDestinationIds({ destinationIds: ["a", "a", "b", "a"] })) === JSON.stringify(["b"]));
    ok("legacy single destinationId is the primary, no replicas", primaryDestinationId({ destinationId: "x" }) === "x" && replicaDestinationIds({ destinationId: "x" }).length === 0);
    ok("destinationIds wins over destinationId", primaryDestinationId({ destinationId: "x", destinationIds: ["a", "b"] }) === "a");
    ok("absent everywhere => no primary (the default), no replicas", primaryDestinationId({}) === undefined && replicaDestinationIds({}).length === 0);
    ok("allDestinationIds is primary + replicas", JSON.stringify(allDestinationIds({ destinationIds: ["a", "b"] })) === JSON.stringify(["a", "b"]));
    ok("blanks never resolve to an empty-string id", primaryDestinationId({ destinationIds: ["", "  ", "a"] }) === "a");
  }
}

async function testMirrorToEmptyReplica(signer: Signer): Promise<void> {
  console.log("-- mirror a finalised run to an empty replica: objects copied + RUNLOG appended (prevRunId null) --");
  {
    const primary = new MemoryDestination();
    const replica = new MemoryDestination();
    const { treeKeys, segKeys, all } = seedRun(primary, "run-1");
    const r = await mirrorRunToReplica(primary, replica, signer, entryFor("run-1", 1, "run-0"));
    ok("every run-tree object AND data segment was copied", r.copied === all.length && !r.alreadyDone);
    const rep = replica.entries();
    ok("the replica holds every run-tree object", treeKeys.every((k) => rep.has(k)));
    ok("the replica holds every DATA segment (a restorable copy, not manifests-only)", segKeys.every((k) => rep.has(k)));
    ok("copied run-tree bytes are identical to the primary", treeKeys.every((k) => new TextDecoder().decode(rep.get(k)!) === `obj:${k}:${treeKeys.indexOf(k)}`));
    ok("copied segment bytes are identical to the primary", segKeys.every((k) => new TextDecoder().decode(rep.get(k)!) === `data:${k}`));
    const rl = await replica.get("_RECOVERY/RUNLOG");
    const entries = rl ? parseRunlog(rl.body) : [];
    ok("the replica RUNLOG has exactly this run", entries.length === 1 && entries[0]!.runId === "run-1");
    ok("the replica-local prevRunId is null (the downpipe's first run HERE, not the primary's prev)", entries[0]!.prevRunId === null);
  }
}

async function testIdempotentSecondPass(signer: Signer): Promise<void> {
  console.log("-- idempotent: a second pass copies nothing and never duplicates the RUNLOG entry --");
  {
    const primary = new MemoryDestination();
    const replica = new MemoryDestination();
    seedRun(primary, "run-1");
    await mirrorRunToReplica(primary, replica, signer, entryFor("run-1", 1, "run-0"));
    const again = await mirrorRunToReplica(primary, replica, signer, entryFor("run-1", 1, "run-0"));
    ok("the second pass is a no-op (alreadyDone, nothing copied)", again.alreadyDone && again.copied === 0);
    const rl = await replica.get("_RECOVERY/RUNLOG");
    const entries = rl ? parseRunlog(rl.body) : [];
    ok("the replica RUNLOG still has a SINGLE entry for the run (no duplicate index)", entries.filter((e) => e.runId === "run-1").length === 1);
  }
}

async function testSecondRunChains(signer: Signer): Promise<void> {
  console.log("-- a second run chains to the FIRST on the replica (replica-local prevRunId) --");
  {
    const primary = new MemoryDestination();
    const replica = new MemoryDestination();
    seedRun(primary, "run-1");
    seedRun(primary, "run-2");
    await mirrorRunToReplica(primary, replica, signer, entryFor("run-1", 1, "run-0"));
    await mirrorRunToReplica(primary, replica, signer, entryFor("run-2", 2, "run-1"));
    const rl = await replica.get("_RECOVERY/RUNLOG");
    const entries = rl ? parseRunlog(rl.body) : [];
    const e2 = entries.find((e) => e.runId === "run-2");
    ok("both runs are on the replica", entries.length === 2);
    ok("the second run's prevRunId points at the first run ON THE REPLICA (intact chain)", e2?.prevRunId === "run-1");
  }
}

function testBacklogContiguity(): void {
  console.log("-- backlog contiguity: a recorded copy-count never advances past a gap (the over-claim guard) --");
  {
    const r = (index: number): RunOrigin => ({ runId: `r${index}`, index, origin: "o" });
    const runs = [r(1), r(2), r(3), r(4)]; // ascending by index
    ok("all present -> the highest contiguous run is the latest", highestContiguousRun(runs, new Set(["r1", "r2", "r3", "r4"]))?.index === 4);
    // A LATER run is present but an EARLIER one is missing (its origin was unreadable this
    // tick) -> held must FREEZE below the gap, so holdsIndex cannot over-claim a copy the destination lacks
    // which would otherwise defeat the removal orphan-guard and let a real run be orphaned.
    ok("a gap (r3 missing) freezes held at r2 even though r4 is present", highestContiguousRun(runs, new Set(["r1", "r2", "r4"]))?.index === 2);
    ok("the FIRST run missing yields no held (cannot claim any prefix)", highestContiguousRun(runs, new Set(["r2", "r3", "r4"])) === undefined);
    ok("nothing placed -> no held", highestContiguousRun(runs, new Set<string>()) === undefined);
    ok("only the first placed -> held is r1", highestContiguousRun(runs, new Set(["r1"]))?.index === 1);
  }
}

async function testKeylessVerify(signer: Signer): Promise<void> {
  console.log("-- post-copy keyless integrity verify (verify:true) passes a faithful copy, rejects a corrupted shard --");
  {
    const RUN_OK = "01ARZ3NDEKTSV4RRFFQ69G5FAV"; // valid 26-char ULIDs (buildArchive decodes the runId)
    const RUN_BAD = "01ARZ3NDEKTSV4RRFFQ69G5FB1";
    const makeRecipient = (role: string): RecipientEntry => {
      const xk = x25519.keygen();
      return { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(crypto.getRandomValues(new Uint8Array(64))).encapKey } };
    };
    const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
    const buildRun = (runId: string): Promise<Map<string, Uint8Array>> =>
      buildArchive({
        downpipeId: "dp-A", downpipeName: "verify-test", cadence: "3600s", runId,
        master: rand(32), recipients: [makeRecipient("break-glass"), makeRecipient("operational")], signer,
        records: [
          { sourceType: "kv", name: "key:a", value: utf8("value-a"), namespace: "ns" },
          { sourceType: "kv", name: "key:b", value: utf8("value-b-longer"), namespace: "ns" },
        ],
        windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
        runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
      });

    // A faithfully-copied REAL sealed run passes the keyless post-copy verify (signature + shard completeness).
    {
      const primary = new MemoryDestination();
      const replica = new MemoryDestination();
      for (const [k, v] of await buildRun(RUN_OK)) await primary.put(k, v);
      let threw = false;
      try { await mirrorRunToReplica(primary, replica, signer, entryFor(RUN_OK, 1, null), { verify: true }); } catch { threw = true; }
      ok("a faithful copy passes the post-copy verify (no throw)", !threw);
      ok("the verified replica carries the RUNLOG done-marker", (await replica.get("_RECOVERY/RUNLOG")) !== null);
      // On a REAL sealed archive: the replica must hold the run's DATA segments (seg/), not just the
      // manifests. Without the seg-store sync this set would be EMPTY on the replica while the verify still
      // passed (attestKeyless cannot see segment data), so the "copy" would be silently non-restorable.
      const primSegs = [...primary.entries().keys()].filter((k) => k.startsWith("seg/"));
      const repKeys = new Set([...replica.entries().keys()]);
      ok("the real run wrote data segments under seg/ (sanity)", primSegs.length > 0);
      ok("every primary data segment is present on the replica (independently restorable)", primSegs.every((k) => repKeys.has(k)));
    }

    // A shard the signed root pins is corrupted in transit: the verify must REJECT (throw) and leave NO
    // done-marker, so the replica is never recorded as holding a good copy (the fail-closed guarantee).
    {
      const primary = new MemoryDestination();
      const replica = new MemoryDestination();
      const archive = await buildRun(RUN_BAD);
      const root = JSON.parse(new TextDecoder().decode(archive.get(`run/${RUN_BAD}/root.manifest.json`)!)) as { shards: Array<{ object: string }> };
      const shardKey = root.shards[0]!.object;
      for (const [k, v] of archive) {
        if (k === shardKey) { const bad = new Uint8Array(v); flipBit(bad, 0); await primary.put(k, bad); }
        else await primary.put(k, v);
      }
      let threw = false;
      try { await mirrorRunToReplica(primary, replica, signer, entryFor(RUN_BAD, 1, null), { verify: true }); } catch { threw = true; }
      ok("a corrupted shard fails the post-copy verify (throws)", threw);
      ok("the rejected copy left NO RUNLOG done-marker on the replica", (await replica.get("_RECOVERY/RUNLOG")) === null);
    }
  }
}

async function testIncompleteDataSync(signer: Signer): Promise<void> {
  console.log("-- an incomplete data sync does NOT mark the run held (no done-marker; resumes next tick) --");
  {
    const primary = new MemoryDestination();
    const replica = new MemoryDestination();
    seedRun(primary, "run-1", ["aa00", "bb11", "cc22"]);
    // A budget too small to finish the seg/ sync: shouldYield() fires on the first missing segment, so the
    // data is left incomplete. The run must NOT be finalised on the replica (a copy is only "held" once its
    // bytes are present), so no RUNLOG done-marker is written and the caller resumes on the next tick.
    const budget = new SliceBudget({ subrequests: 1 });
    const r = await mirrorRunToReplica(primary, replica, signer, entryFor("run-1", 1, null), { budget });
    ok("an incomplete data sync reports incomplete", r.incomplete === true);
    ok("no RUNLOG done-marker is written when the data is not fully synced", (await replica.get("_RECOVERY/RUNLOG")) === null);
    ok("the replica is missing a data segment (the sync was genuinely cut short)", ["aa00", "bb11", "cc22"].some((h) => !replica.entries().has(`seg/${h.slice(0, 2)}/${h}.seg`)));
  }
}

async function testStructuralSegCheck(signer: Signer): Promise<void> {
  console.log("-- opt-in keyless STRUCTURAL seg/ check (verifySegments) catches truncated/empty/wrong-object copies; default OFF unchanged --");
  {
    // A faithful copy of properly-framed seg/ containers passes the structural check (no throw) and writes
    // the RUNLOG done-marker, so a real copy is still recorded held.
    {
      const primary = new MemoryDestination();
      const replica = new MemoryDestination();
      const { segKeys } = seedFramedRun(primary, "run-1", ["aa00", "bb11"]);
      let threw = false;
      try { await mirrorRunToReplica(primary, replica, signer, entryFor("run-1", 1, null), { verifySegments: true }); } catch { threw = true; }
      ok("a faithful framed copy passes the structural seg check (no throw)", !threw);
      ok("the structurally-verified replica carries the RUNLOG done-marker", (await replica.get("_RECOVERY/RUNLOG")) !== null);
      ok("the replica holds every framed seg (sanity)", segKeys.every((k) => replica.entries().has(k)));
    }

    // A copied seg/ object that is TRUNCATED below the 5-byte header on the replica: unframeSeg throws
    // ("container shorter than the 5-byte header"), so the mirror throws and writes NO done-marker. The
    // structurally-bad copy is never recorded held. Modelled with a destination whose put corrupts seg/.
    {
      const primary = new MemoryDestination();
      seedFramedRun(primary, "run-1", ["aa00", "bb11"]);
      // A replica that TRUNCATES every seg/ object it stores to a single byte (below the 5-byte header),
      // simulating a silent partial copy (e.g. an interrupted multipart that the destination still ACKed).
      class TruncatingReplica extends MemoryDestination {
        override async put(key: string, body: Uint8Array): Promise<void> {
          await super.put(key, key.startsWith("seg/") ? body.subarray(0, 1) : body);
        }
      }
      const replica = new TruncatingReplica();
      let threw = false;
      try { await mirrorRunToReplica(primary, replica, signer, entryFor("run-1", 1, null), { verifySegments: true }); } catch { threw = true; }
      ok("a truncated seg/ copy fails the structural check (throws)", threw);
      ok("the rejected truncated copy left NO RUNLOG done-marker", (await replica.get("_RECOVERY/RUNLOG")) === null);
    }

    // A copied seg/ object with the WRONG MAGIC on the replica (a wrong-object copy: a .dpe written under a
    // seg/ key, or zeroed magic): unframeSeg throws ("bad container magic"), so the mirror throws.
    {
      const primary = new MemoryDestination();
      seedFramedRun(primary, "run-1", ["aa00", "bb11"]);
      class WrongMagicReplica extends MemoryDestination {
        override async put(key: string, body: Uint8Array): Promise<void> {
          // Reframe seg/ payloads under the DPE1 (manifest) magic: a wrong-object copy that is the right
          // length but the wrong container type, which a length-only check would miss.
          await super.put(key, key.startsWith("seg/") ? frame(MAGIC_DPE, body.subarray(5)) : body);
        }
      }
      const replica = new WrongMagicReplica();
      let threw = false;
      try { await mirrorRunToReplica(primary, replica, signer, entryFor("run-1", 1, null), { verifySegments: true }); } catch { threw = true; }
      ok("a wrong-object seg/ copy (DPE1 magic under a seg/ key) fails the structural check (throws)", threw);
      ok("the rejected wrong-object copy left NO RUNLOG done-marker", (await replica.get("_RECOVERY/RUNLOG")) === null);
    }

    // CORE PER-CALL OPT-IN OFF: the injectable core mirrorRunToReplica keeps opts.verifySegments an
    // explicit per-call opt-in (default OFF) so a direct caller / validator chooses; the same truncated-copy
    // replica with verifySegments UNSET runs NO structural check, so the mirror does NOT throw and the run IS
    // recorded held. The CRON pass resolves the flag from the env (replVerifySegmentsEnabled, default ON,
    // tested in testSegVerifyDefaultOn), so production replicas are verified, not blind. This block proves
    // the core's per-call default is unchanged.
    {
      const primary = new MemoryDestination();
      seedFramedRun(primary, "run-1", ["aa00", "bb11"]);
      class TruncatingReplica extends MemoryDestination {
        override async put(key: string, body: Uint8Array): Promise<void> {
          await super.put(key, key.startsWith("seg/") ? body.subarray(0, 1) : body);
        }
      }
      const replica = new TruncatingReplica();
      let threw = false;
      try { await mirrorRunToReplica(primary, replica, signer, entryFor("run-1", 1, null)); } catch { threw = true; }
      ok("the default (verifySegments unset) does NOT run the structural check (no throw on a truncated copy)", !threw);
      ok("the default still writes the RUNLOG done-marker (posture unchanged)", (await replica.get("_RECOVERY/RUNLOG")) !== null);
    }
  }
}

function testSegVerifyDefaultOn(): void {
  console.log("-- the cron replication pass VERIFIES replica segment bytes BY DEFAULT (not opt-in/blind) --");
  {
    // The fix for the 3-2-1 integrity pair: production replicas must be VERIFIED, not copied blind. The cron
    // pass reads replVerifySegmentsEnabled(env); a deployment that sets REPL_VERIFY_SEGMENTS to NOTHING must
    // get the structural readback ON. The OLD code returned false on absence (opt-in/blind by default), so
    // this assertion is red-before-green.
    const env = (v?: string): Env => ({ REPL_VERIFY_SEGMENTS: v } as unknown as Env);
    ok("absent REPL_VERIFY_SEGMENTS => segment verification is ON by default (replicas verified, not blind)", replVerifySegmentsEnabled(env(undefined)) === true);
    ok("an explicit falsey value (\"off\") is the deliberate cost opt-out (verification disabled)", replVerifySegmentsEnabled(env("off")) === false);
    ok("\"false\"/\"0\"/\"no\" also disable (the VERIFY_AT_SEAL idiom)", !replVerifySegmentsEnabled(env("false")) && !replVerifySegmentsEnabled(env("0")) && !replVerifySegmentsEnabled(env("no")));
    ok("any other value keeps it ON (e.g. \"1\"/\"on\")", replVerifySegmentsEnabled(env("1")) && replVerifySegmentsEnabled(env("on")));
  }
}

async function testVanishingSegment(signer: Signer): Promise<void> {
  console.log("-- a segment that vanishes mid-sync is deferred when its run is still live, but skipped (no livelock) when the run is pruned --");
  {
    // VanishingOrigin lists a seg/ key (so the sync attempts to copy it) but returns null on get for that
    // key, modelling a segment that disappears between the list and the get. Whether the run being mirrored
    // is still live in the origin is controlled by the test itself: it appends the origin RUNLOG (run live)
    // or leaves it absent (run pruned), which is exactly the distinguishing signal isRunLive reads.
    class VanishingOrigin extends MemoryDestination {
      private vanishKey: string;
      constructor(vanishKey: string) {
        super();
        this.vanishKey = vanishKey;
      }
      override async list(prefix: string): Promise<string[]> {
        const real = await super.list(prefix);
        // Advertise the vanishing seg key in the seg/ listing even though get returns null for it.
        if (prefix === "seg/" && !real.includes(this.vanishKey)) return [...real, this.vanishKey].sort();
        return real;
      }
      override async listPage(prefix: string, cursor?: string): Promise<{ keys: string[]; cursor?: string }> {
        // The streamed merge-walk (replicate.ts) reads listPage, not list, so the vanishing key must be
        // advertised here too. The seg/ store fits in one page in this test (a couple of keys), so append the
        // vanishing key to the final page in sorted order; get() still returns null for it (the mid-sync
        // vanish). The merge-walk then GETs it, sees null, and applies the distinction by run liveness.
        const page = await super.listPage(prefix, cursor);
        if (prefix === "seg/" && page.cursor === undefined && !page.keys.includes(this.vanishKey)) {
          return { keys: [...page.keys, this.vanishKey].sort() };
        }
        return page;
      }
      override async get(key: string): Promise<GetResult | null> {
        if (key === this.vanishKey) return null; // the segment vanished between the list and the get
        return super.get(key);
      }
    }

    // (1) VANISH-WHILE-REFERENCED: the run is still live in the origin RUNLOG but a listed seg get returns
    // null -> a real mid-sync vanish. The mirror must report incomplete and write NO done-marker, so the
    // run is not recorded held on a replica missing the bytes (the silent-held fix).
    {
      const vanishKey = "seg/zz/zz99.seg";
      const origin = new VanishingOrigin(vanishKey);
      const replica = new MemoryDestination();
      seedRun(origin, "run-1", ["aa00"]); // one real seg present; the vanishing one is in the listing only
      // Append a REAL signed origin RUNLOG so isRunLive sees the run-1 entry as still referenced.
      await appendRunlog(origin, signer, entryFor("run-1", 1, null), undefined, { relinkLocalPrev: true });
      const r = await mirrorRunToReplica(origin, replica, signer, entryFor("run-1", 1, null));
      ok("a still-referenced segment vanishing mid-sync reports incomplete", r.incomplete === true);
      ok("no RUNLOG done-marker is written when a live run's segment vanished (not held)", (await replica.get("_RECOVERY/RUNLOG")) === null);
    }

    // (2) BENIGN-PRUNE: the run is GONE from the origin RUNLOG (retention pruned it and its orphaned
    // segments). A listed seg get returns null and the origin RUNLOG no longer references the run (isRunLive
    // false) -> a benign skip. The mirror must NOT return incomplete (which would re-attempt the
    // unobtainable bytes every tick forever, a livelock); it finalises with the segments it does hold.
    {
      const vanishKey = "seg/zz/zz99.seg";
      const origin = new VanishingOrigin(vanishKey);
      const replica = new MemoryDestination();
      seedRun(origin, "run-1", ["aa00"]); // present seg only; NO origin RUNLOG written -> the run is pruned
      const r = await mirrorRunToReplica(origin, replica, signer, entryFor("run-1", 1, null));
      ok("a pruned run's vanished segment does NOT report incomplete (no livelock)", r.incomplete !== true);
      ok("the pruned-run mirror finalises (writes the RUNLOG done-marker, not a permanent re-attempt)", (await replica.get("_RECOVERY/RUNLOG")) !== null);
      ok("the real present segment was still copied to the replica", replica.entries().has("seg/aa/aa00.seg"));
    }
  }
}

async function testBoundedMemorySegSync(signer: Signer): Promise<void> {
  console.log("-- a seg/ store larger than one page syncs in BOUNDED memory (page-by-page, never materialising the whole keyspace) --");
  {
    // PAGE_SIZE pages a large store many times over; MEMORY_BOUND is the number of seg/ keys above which a
    // SINGLE materialisation (list() over the whole store) is treated as an OOM. With more than one page of
    // segments on each side, a sync that streams (listPage page-by-page) holds at most one page (PAGE_SIZE)
    // resident and stays under the bound; a sync that materialises either whole keyspace (the OLD
    // origin.list() / new Set(target.list()) path) trips the bound and FAILS. This is the red-before-green:
    // before the merge-walk fix the sync called list() on both sides and would breach the bound here.
    const PAGE_SIZE = 4;
    const TOTAL = 40; // ten pages of segments; well past one page
    const MEMORY_BOUND = 8; // a single full-keyspace array (40 keys) blows past this; one page (4) stays under

    // PagingDest pages with a small PAGE_SIZE and FORBIDS list() materialising a large keyspace: list()
    // throws when it would return more than MEMORY_BOUND keys, so any code path that materialises the whole
    // seg/ store (rather than streaming via listPage) fails loudly instead of silently OOMing. It also
    // tracks the largest page it ever returned via listPage, so the test can assert the working set stayed
    // bounded to a page (the proof that the sync did not accumulate the whole keyspace in memory).
    let maxListPageKeys = 0;
    let fullMaterialisations = 0;
    class PagingDest extends MemoryDestination {
      constructor() {
        super();
        this.pageSize = PAGE_SIZE;
      }
      override async list(prefix: string): Promise<string[]> {
        const keys = await super.list(prefix);
        if (keys.length > MEMORY_BOUND) {
          fullMaterialisations++;
          throw new Error(`list() materialised ${keys.length} keys for "${prefix}" (> ${MEMORY_BOUND}); a large keyspace must be streamed via listPage, not materialised whole`);
        }
        return keys;
      }
      override async listPage(prefix: string, cursor?: string): Promise<{ keys: string[]; cursor?: string }> {
        const page = await super.listPage(prefix, cursor);
        if (prefix === "seg/") maxListPageKeys = Math.max(maxListPageKeys, page.keys.length);
        return page;
      }
    }

    const origin = new PagingDest();
    const target = new PagingDest();
    // A 4-hex content-address per segment, zero-padded so the keys sort the same way the stores page them.
    const segId = (n: number): string => n.toString(16).padStart(4, "0");
    const segKey = (id: string): string => `seg/${id.slice(0, 2)}/${id}.seg`;
    // Seed the origin with TOTAL segments and a run-tree for run-1. Pre-place HALF the segments on the
    // target (the even-numbered ones) so the sync must SKIP the present ones (content-addressed dedup) and
    // COPY only the missing (odd-numbered) ones, proving the merge-walk's present-skip / missing-copy logic.
    const allSegIds: string[] = [];
    for (let i = 0; i < TOTAL; i++) {
      const id = segId(i);
      allSegIds.push(id);
      await origin.put(segKey(id), new TextEncoder().encode(`data:${id}`));
      if (i % 2 === 0) await target.put(segKey(id), new TextEncoder().encode(`data:${id}`)); // already present
    }
    for (const k of [`run/run-1/root.manifest.json`, `run/run-1/manifest/00000.dpe`]) {
      await origin.put(k, new TextEncoder().encode(`obj:${k}`));
    }

    let threw = false;
    let r: { copied: number; incomplete?: boolean } | undefined;
    try {
      // No budget: the sync runs to completion in ONE pass, so a correct streaming sync copies every
      // missing segment without ever materialising a whole keyspace. syncSegments is on by default.
      r = await mirrorRunToReplica(origin, target, signer, entryFor("run-1", 1, null));
    } catch {
      threw = true;
    }
    ok("the seg sync completed without a full-keyspace materialisation (did not OOM)", !threw && fullMaterialisations === 0);
    ok("the streaming sync held at most one page in memory (working set bounded to PAGE_SIZE)", maxListPageKeys > 0 && maxListPageKeys <= PAGE_SIZE);
    ok("the run finalised (data fully synced, done-marker written)", r?.incomplete !== true && (await target.get("_RECOVERY/RUNLOG")) !== null);
    // Every origin segment is now on the target: the present (even) ones were skipped, the missing (odd)
    // ones copied. Content-addressed dedup correctness across the page boundary.
    const repKeys = new Set([...target.entries().keys()]);
    ok("every origin data segment is present on the target (missing copied, present skipped)", allSegIds.every((id) => repKeys.has(segKey(id))));
    // The copy-count reflects ONLY the missing (odd) segments, so a present segment was genuinely skipped
    // (the dedup did not blindly re-copy the whole store).
    const expectedCopied = allSegIds.filter((_id, i) => i % 2 === 1).length + 2; // odd segs + 2 run-tree objects
    ok("only the missing segments were copied (present ones skipped, not re-copied)", r?.copied === expectedCopied);
  }
}

async function main(): Promise<void> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };

  testResolutionHelpers();
  await testMirrorToEmptyReplica(signer);
  await testIdempotentSecondPass(signer);
  await testSecondRunChains(signer);
  testBacklogContiguity();
  await testKeylessVerify(signer);
  await testIncompleteDataSync(signer);
  await testStructuralSegCheck(signer);
  testSegVerifyDefaultOn();
  await testVanishingSegment(signer);
  await testBoundedMemorySegSync(signer);

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nREPLICATION VECTORS PASS");
}

void main();
