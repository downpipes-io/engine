// Prove the 3-2-1 RESTORE side end to end: a REAL sealed archive is MIRRORED to a replica destination with the
// production mirrorRunToReplica, and then the records are RESTORED FROM THE REPLICA -- byte-identical to the
// seeds -- by BOTH independent readers (the TS openRun in process AND the Go offline reader). validate-replicate
// proves the mirror copies bytes; validate-slice/B1/B2 prove the PRIMARY restores; this closes the gap between
// them: that a mirrored replica is a genuine, byte-faithful recovery source for REAL encrypted records (a mirror
// that dropped a real archive object would leave a silently non-restorable copy). Refuter (default-FAIL): a
// replica MISSING one segment makes the restore REFUSE, so no partial/wrong data is ever recovered from a
// replica. In-memory doubles + the offline Go reader; net-zero, no network, no deploy.
// Run: node test/validate-replica-restore.ts
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { x25519 } from "@noble/curves/ed25519.js";

import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type Signer, type WriteRecord, type RunlogEntry } from "../src/format/writer.ts";
import { runSlice, finaliseRun, type SliceDeps, type ShardEntry } from "../src/seal/slice.ts";
import { wrapMaster, unwrapMaster, zeroCounts, type RunCheckpoint } from "../src/seal/checkpoint.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { KVSource } from "../src/sources/kv.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import { mirrorRunToReplica } from "../src/seal/replicate.ts";
import { MemoryDestination } from "./memdest.ts";
import { assertEphemeralWorkdir, buildReader, goPresent, runReader, writeArchiveDir } from "./scale-go-reader.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVRY";
const DP = "dp_replica";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function newTmp(): string {
  const d = mkdtempSync(join(tmpdir(), "replica-restore-"));
  assertEphemeralWorkdir(d);
  return d;
}
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}
async function makeSigner(): Promise<{ signer: Signer; signerPub: Uint8Array }> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  return { signer: { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey }, signerPub: concat(edPublic, mldsa.publicKey) };
}
class MapStore implements ObjectStore {
  private map: Map<string, Uint8Array>;
  constructor(map: Map<string, Uint8Array>) {
    this.map = map;
  }
  // ObjectStore.get returns the bytes and THROWS on a missing key (src/format/types.ts): a store that
  // answered null for a hole would hand the reader a non-Uint8Array and mask the miss. Throwing is what
  // the refuters below rely on to see a holed replica refused rather than silently read as empty.
  async get(key: string): Promise<Uint8Array> {
    const v = this.map.get(key);
    if (!v) throw new Error(`object not found: ${key}`);
    return v;
  }
}
function restoreFileArgs(archiveDir: string, runId: string, identityFile: string, signerFile: string, outDir: string): string[] {
  return ["restore", "--archive", archiveDir, "--run", runId, "--identity", identityFile, "--signer", signerFile, "--sink", "file", "--apply", "--out", outDir];
}
function walkFiles(dir: string): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (const nm of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, nm.name);
    if (nm.isDirectory()) out.push(...walkFiles(p));
    else out.push(new Uint8Array(readFileSync(p)));
  }
  return out;
}

// Seal a real archive to a MemoryDestination + append the RUNLOG entry (as finaliseRun would), so the run is
// mirrorable. Returns the origin destination + the identity/signer material for the readers.
async function sealToOrigin(records: WriteRecord[]): Promise<{ origin: MemoryDestination; entry: RunlogEntry; bgIdentity: Uint8Array; signer: Signer; signerPub: Uint8Array }> {
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const { signer, signerPub } = await makeSigner();
  const origin = new MemoryDestination();
  const archive = await buildArchive(
    {
      downpipeId: DP,
      downpipeName: "replica-restore",
      cadence: "0 * * * *",
      runId: RUN_ID,
      master: rand(32),
      recipients: [bg.entry, op.entry],
      signer,
      records,
      windowStart: "2026-06-07T00:00:00.000Z",
      windowEnd: "2026-06-07T00:00:01.000Z",
      createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1,
      prevRunId: null,
      randomNonce: () => rand(16),
      randomSalt: () => rand(16),
    },
    { dest: origin },
  );
  for (const [k, b] of archive) await origin.put(k, b);
  const entry: RunlogEntry = { index: 1, runId: RUN_ID, downpipeId: DP, time: "2026-06-07T00:00:01.000Z", recordCount: records.length, prevRunId: null, status: "active" };
  await appendRunlog(origin, signer, entry, undefined, { relinkLocalPrev: true });
  return { origin, entry, bgIdentity: bg.identity, signer, signerPub };
}

// MemKV is a minimal KVNamespace double the KVSource reads, paginated so the seal genuinely slices.
class MemKV {
  private seeds: { name: string; value: Uint8Array }[];
  private pageSize: number;
  private epoch = 0;
  constructor(seeds: { name: string; value: Uint8Array }[], pageSize: number) {
    this.seeds = [...seeds].sort((a, b) => (a.name < b.name ? -1 : 1));
    this.pageSize = pageSize;
  }
  invalidateCursors(): void {
    this.epoch++;
  }
  async list(options?: { prefix?: string; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string; cacheStatus: null }> {
    let start = 0;
    if (options?.cursor !== undefined) {
      const m = /^e(\d+)c(\d+)$/.exec(options.cursor);
      if (!m || Number(m[1]) !== this.epoch) throw new Error("cursor: invalid or expired");
      start = Number(m[2]);
    }
    const prefix = options?.prefix;
    const all = prefix === undefined ? this.seeds : this.seeds.filter((x) => x.name.startsWith(prefix));
    const page = all.slice(start, start + this.pageSize);
    const next = start + this.pageSize;
    const complete = next >= all.length;
    return { keys: page.map((x) => ({ name: x.name })), list_complete: complete, ...(complete ? {} : { cursor: `e${this.epoch}c${next}` }), cacheStatus: null };
  }
  async getWithMetadata(key: string, _t: "arrayBuffer"): Promise<{ value: ArrayBuffer | null; metadata: unknown; cacheStatus: null }> {
    const x = this.seeds.find((y) => y.name === key);
    if (!x) return { value: null, metadata: null, cacheStatus: null };
    const out = new ArrayBuffer(x.value.byteLength);
    new Uint8Array(out).set(x.value);
    return { value: out, metadata: null, cacheStatus: null };
  }
}

// sealSlicedToOrigin seals a MULTI-SHARD PRODUCTION archive (runSlice/finaliseRun, shardMaxRecords small) to a
// MemoryDestination, so the replica-restore is exercised on the real production seal layout, not just buffered.
async function sealSlicedToOrigin(seeds: { name: string; value: Uint8Array }[]): Promise<{ origin: MemoryDestination; entry: RunlogEntry; bgIdentity: Uint8Array; signer: Signer; signerPub: Uint8Array; shards: number }> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer = await loadSigner(signerPrivateB64);
  const signerPub = concat(signer.edPublic, signer.mldsaPublic);
  const bg = makeRecipient("break-glass");
  const kv = new MemKV(seeds, 4);
  const origin = new MemoryDestination();
  const master = rand(32);
  let cp: RunCheckpoint = {
    v: 1, downpipeId: DP, downpipeName: "replica-sliced", cadence: "3600s", sourceType: "kv",
    selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 1, prevRunId: null,
    startedAt: "2026-06-07T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master),
    cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
    frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
  };
  master.fill(0);
  const allShards: ShardEntry[] = [];
  let openBuffer: Record<string, unknown>[] = [];
  for (let i = 0; i < 800 && !cp.sourceDone; i++) {
    cp = JSON.parse(JSON.stringify(cp)) as RunCheckpoint;
    const m = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
    const deps: SliceDeps = { source: new KVSource(kv as unknown as KVNamespace, "ns1"), dest: origin, signer, recipients: [bg.entry], budget: new SliceBudget({ subrequests: 60, wallMs: 60_000 }), shardMaxRecords: 3 };
    const r = await runSlice(deps, cp, m, openBuffer);
    m.fill(0);
    cp = r.checkpoint;
    allShards.push(...r.newShards);
    openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
  }
  const mf = await unwrapMaster(signerPrivateB64, RUN_ID, cp.wrappedMaster);
  await finaliseRun({ source: new KVSource(kv as unknown as KVNamespace, "ns1"), dest: origin, signer, recipients: [bg.entry], budget: new SliceBudget({ subrequests: 900, wallMs: 60_000 }) }, cp, mf, allShards, openBuffer);
  mf.fill(0);
  const rl = await origin.get("_RECOVERY/RUNLOG");
  const entries = rl ? parseRunlog(rl.body) : [];
  const entry = entries.filter((e) => e.downpipeId === DP).reduce((a, b) => (b.index > a.index ? b : a));
  return { origin, entry, bgIdentity: bg.identity, signer, signerPub, shards: allShards.length };
}

async function main(): Promise<void> {
  const go = goPresent();
  const bin = go.ok ? join(newTmp(), "downpipe") : "";
  const built = go.ok ? buildReader(process.cwd(), bin) : { ok: false, detail: "go absent" };
  if (!built.ok) console.log(`  (Go reader unavailable: ${built.detail}; the TS-reader replica restore still runs)`);

  const seeds: WriteRecord[] = Array.from({ length: 8 }, (_, i) => ({ sourceType: "kv", name: `rec/${String(i).padStart(2, "0")}`, value: rand(50 + i * 90) }));

  // 1. Seal the real archive to the origin, then MIRROR the whole run to a fresh replica destination.
  const { origin, entry, bgIdentity, signer, signerPub } = await sealToOrigin(seeds);
  const replica = new MemoryDestination();
  const res = await mirrorRunToReplica(origin, replica, signer, entry);
  ok(`the mirror copied the run to the replica (copied ${res.copied}, not alreadyDone)`, res.copied > 0 && !res.alreadyDone && res.incomplete !== true);

  const replicaMap = new Map(replica.entries());
  ok("the replica holds the run-tree root manifest", replicaMap.has(`run/${RUN_ID}/root.manifest.json`));
  ok("the replica holds data segments (seg/ objects), not manifests only", [...replicaMap.keys()].some((k) => k.startsWith("seg/")));

  // 2. RESTORE FROM THE REPLICA with the TS reader -- byte-identical to the seeds.
  const identity = parseIdentity(bgIdentity);
  const verifier = verifierFrom(signer);
  const run = await openRun(new MapStore(replicaMap), RUN_ID, identity, verifier, {});
  let tsAllExact = run.records.length === seeds.length;
  for (const s of seeds) {
    const rec = run.records.find((r) => r.name === s.name);
    if (!rec) { tsAllExact = false; break; }
    if (!bytesEqual(await run.restoreRecord(rec), s.value!)) { tsAllExact = false; break; }
  }
  ok(`the TS reader restored every record FROM THE REPLICA byte-identical to the seed (${seeds.length} records)`, tsAllExact);

  // 3. RESTORE FROM THE REPLICA with the independent Go offline reader -- byte-identical.
  if (built.ok) {
    const paths = writeArchiveDir(newTmp(), replicaMap, b64urlEncode(bgIdentity), b64urlEncode(signerPub));
    const outDir = join(newTmp(), "out");
    const gr = runReader(bin, restoreFileArgs(paths.archiveDir, RUN_ID, paths.identityFile, paths.signerFile, outDir));
    ok(`the Go offline reader restored FROM THE REPLICA (exit ${gr.exitCode})`, gr.exitCode === 0);
    if (gr.exitCode === 0) {
      const pool = walkFiles(outDir);
      const allFound = seeds.every((s) => pool.some((b) => bytesEqual(b, s.value!)));
      ok("every seed record is recovered byte-identical from the replica by the Go reader (Go == TS == seed)", allFound && pool.length === seeds.length);
    }
  }

  // 4. REFUTER (default-FAIL): a replica MISSING one segment makes the restore REFUSE (no partial recovery).
  {
    const holed = new Map(replicaMap);
    const segKey = [...holed.keys()].find((k) => k.startsWith("seg/"));
    if (segKey) holed.delete(segKey);
    let tsRefused = false;
    try {
      const r = await openRun(new MapStore(holed), RUN_ID, identity, verifier, {});
      for (const rec of r.records) await r.restoreRecord(rec);
    } catch {
      tsRefused = true;
    }
    ok("REFUTER: a replica missing a segment makes the TS restore REFUSE (never a partial/wrong recovery)", tsRefused);
    if (built.ok && segKey) {
      const paths = writeArchiveDir(newTmp(), holed, b64urlEncode(bgIdentity), b64urlEncode(signerPub));
      const gr = runReader(bin, restoreFileArgs(paths.archiveDir, RUN_ID, paths.identityFile, paths.signerFile, join(newTmp(), "out")));
      ok(`REFUTER: the Go reader also REFUSES a replica missing a segment (exit ${gr.exitCode})`, gr.exitCode !== 0);
    }
  }

  // ---- SLICED / MULTI-SHARD variant: the same replica-restore on a REAL PRODUCTION (multi-shard) archive,
  // so a mirror that dropped a manifest SHARD (which the single-shard buffered case cannot expose) is caught.
  console.log("-- sliced/multi-shard production archive: mirror -> restore from the replica --");
  {
    const sslSeeds = Array.from({ length: 20 }, (_, i) => ({ name: `k/${String(i).padStart(3, "0")}`, value: rand(40 + i * 25) }));
    const { origin, entry, bgIdentity: sBg, signer: sSigner, signerPub: sPub, shards } = await sealSlicedToOrigin(sslSeeds);
    ok(`the sliced seal is genuinely MULTI-SHARD (${shards} shards)`, shards > 1);
    const rep = new MemoryDestination();
    const mres = await mirrorRunToReplica(origin, rep, sSigner, entry);
    ok(`the mirror copied the multi-shard run to the replica (copied ${mres.copied})`, mres.copied > 0 && mres.incomplete !== true);
    const repMap = new Map(rep.entries());
    const shardObjs = [...repMap.keys()].filter((k) => k.startsWith(`run/${RUN_ID}/manifest/`)).length;
    ok(`the replica holds every manifest SHARD (${shardObjs} shard objects, >1)`, shardObjs > 1);
    const sIdentity = parseIdentity(sBg);
    const sVerifier = verifierFrom(sSigner);
    const sRun = await openRun(new MapStore(repMap), RUN_ID, sIdentity, sVerifier, {});
    let sExact = sRun.records.length === sslSeeds.length;
    for (const seed of sslSeeds) {
      const rec = sRun.records.find((r) => r.name === seed.name);
      if (!rec || !bytesEqual(await sRun.restoreRecord(rec), seed.value)) { sExact = false; break; }
    }
    ok(`the TS reader restored every record from the MULTI-SHARD replica byte-identical (${sslSeeds.length} records)`, sExact);
    if (built.ok) {
      const paths = writeArchiveDir(newTmp(), repMap, b64urlEncode(sBg), b64urlEncode(sPub));
      const outDir = join(newTmp(), "out");
      const gr = runReader(bin, restoreFileArgs(paths.archiveDir, RUN_ID, paths.identityFile, paths.signerFile, outDir));
      const pool = gr.exitCode === 0 ? walkFiles(outDir) : [];
      ok("the Go reader restored every record from the MULTI-SHARD replica byte-identical (Go == TS == seed)", gr.exitCode === 0 && sslSeeds.every((seed) => pool.some((b) => bytesEqual(b, seed.value))) && pool.length === sslSeeds.length);
    }
    // REFUTER (sliced, default-FAIL): a replica MISSING one manifest SHARD must NOT yield a full, clean-looking
    // restore -- the reader either refuses or honestly returns fewer records, never silently ignores the gap.
    {
      const holed = new Map(repMap);
      const shardKey = [...holed.keys()].find((k) => k.startsWith(`run/${RUN_ID}/manifest/`));
      if (shardKey) holed.delete(shardKey);
      let tsRefused = false;
      try {
        const r = await openRun(new MapStore(holed), RUN_ID, sIdentity, sVerifier, {});
        let got = 0;
        for (const rec of r.records) {
          await r.restoreRecord(rec);
          got++;
        }
        if (got < sslSeeds.length) tsRefused = true;
      } catch {
        tsRefused = true;
      }
      ok("REFUTER: a replica missing a manifest SHARD makes the TS restore REFUSE / go incomplete (no silent full recovery)", tsRefused);
      if (built.ok && shardKey) {
        const paths = writeArchiveDir(newTmp(), holed, b64urlEncode(sBg), b64urlEncode(sPub));
        const gr = runReader(bin, restoreFileArgs(paths.archiveDir, RUN_ID, paths.identityFile, paths.signerFile, join(newTmp(), "out")));
        ok(`REFUTER: the Go reader also REFUSES a replica missing a manifest SHARD (exit ${gr.exitCode})`, gr.exitCode !== 0);
      }
    }
  }

  console.log(failures === 0 ? "\nREPLICA RESTORE OK: a mirrored replica is a byte-faithful recovery source for both readers; an incomplete replica is refused." : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
