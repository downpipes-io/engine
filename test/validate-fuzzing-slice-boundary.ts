// Production sliced-seal chunk-boundary differential (recovery-redundancy, net-zero). validate-slice fuzzes
// the PRODUCTION runSlice/finaliseRun/sealChainedStreamRecord path but its only multi-chunk records are ~70KB
// (2 chunks, size 70040 -- NOT chunk-aligned), so the production large-object seal is NEVER exercised at the
// EXACT, off-by-one-prone chunk boundaries (65536, 131072, 196608) or at deeper multi-chunk depths. (My
// validate-fuzzing-chunkboundary covers those, but on the SIMPLE buildArchive seal, not the production chained
// seal.) This seals single records at the aligned + off-by-one boundaries THROUGH runSlice/finaliseRun and
// proves BYTE-IDENTICAL recovery by the Go offline reader AND the TS reader (openRun.restoreRecord == seed).
// Default-FAIL refuter: a mid-segment tamper is refused by both (the differential is not vacuous, proving the
// seal+read pipeline is real). Net-zero: in-memory MemoryDestination + the offline Go binary. Custody: no
// secret logged; the master is re-derived from its wrapped form per slice and zeroed. Run: node the file.
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { x25519 } from "@noble/curves/ed25519.js";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import type { RecipientEntry, Signer } from "../src/format/writer.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { finaliseRun, runSlice, type ShardEntry, type SliceDeps } from "../src/seal/slice.ts";
import { unwrapMaster, wrapMaster, zeroCounts, type RunCheckpoint } from "../src/seal/checkpoint.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import type { Meter, Selector, SourceAdapter, SourceRecord } from "../src/sources/types.ts";
import { MemoryDestination } from "./memdest.ts";
import { assertEphemeralWorkdir, buildReader, goPresent, restoreDiscardArgs, runReader, writeArchiveDir } from "./scale-go-reader.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

const CHUNK = 65536;
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const rand = (n: number): Uint8Array => {
  const out = new Uint8Array(n);
  for (let off = 0; off < n; off += 65536) crypto.getRandomValues(out.subarray(off, Math.min(off + 65536, n)));
  return out;
};

let assertions = 0;
let failures = 0;
function ok(label: string, cond: boolean, detail = ""): void {
  assertions++;
  console.log(cond ? `  ok   ${label}${detail ? ` (${detail})` : ""}` : `  FAIL ${label}${detail ? ` (${detail})` : ""}`);
  if (!cond) failures++;
}
function newTmp(): string {
  const d = mkdtempSync(join(tmpdir(), "downpipes-sliceb-"));
  assertEphemeralWorkdir(d);
  return d;
}
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function listFilesRecursive(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => { for (const e of readdirSync(d, { withFileTypes: true })) { const p = join(d, e.name); if (e.isDirectory()) walk(p); else out.push(p); } };
  try { walk(dir); } catch { /* none */ }
  return out;
}
function restoreFileArgs(archiveDir: string, runId: string, identityFile: string, signerFile: string, outDir: string): string[] {
  return ["restore", "--archive", archiveDir, "--run", runId, "--identity", identityFile, "--signer", signerFile, "--sink", "file", "--apply", "--out", outDir];
}
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  const ek = mlkemKeygen(seed).encapKey;
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: ek } }, identity: concat(xk.secretKey, seed) };
}
class MapStore implements ObjectStore {
  private readonly map: Map<string, Uint8Array>;
  constructor(map: Map<string, Uint8Array>) { this.map = map; }
  async get(key: string): Promise<Uint8Array> {
    const v = this.map.get(key);
    if (!v) throw new Error(`object not found: ${key}`);
    return v;
  }
  list(prefix: string): Promise<string[]> {
    return Promise.resolve([...this.map.keys()].filter((k) => k.startsWith(prefix)));
  }
}
// A crawl-only source that yields exactly one record (the boundary-sized value under test).
class OneRecordSource implements SourceAdapter {
  readonly sourceType = "kv" as const;
  private readonly recName: string;
  private readonly recValue: Uint8Array;
  constructor(name: string, value: Uint8Array) { this.recName = name; this.recValue = value; }
  async *crawl(_selector: Selector, _meter?: Meter): AsyncIterable<SourceRecord> {
    yield { sourceType: "kv", name: this.recName, value: this.recValue };
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: 1, bytes: this.recValue.length };
  }
}

// sealViaSlice seals ONE record through the PRODUCTION runSlice/finaliseRun path and returns the archive map.
// The master is re-derived from its wrapped form per slice + at finalise, then zeroed (custody hygiene).
async function sealViaSlice(name: string, value: Uint8Array): Promise<{ map: Map<string, Uint8Array>; bgIdentity: Uint8Array; signer: Signer; signerPub: Uint8Array }> {
  const signerPrivateB64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer = await loadSigner(signerPrivateB64);
  const signerPub = concat(signer.edPublic, signer.mldsaPublic);
  const bg = makeRecipient("break-glass");
  const dest = new MemoryDestination();
  const master0 = rand(32);
  const cp: RunCheckpoint = {
    v: 1, downpipeId: "dp_sliceb", downpipeName: "slice-boundary", cadence: "3600s", sourceType: "kv",
    selector: { include: [], exclude: [] }, runId: RUN_ID, runlogIndex: 2, prevRunId: null,
    startedAt: "2026-06-10T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, RUN_ID, master0),
    cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
    frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
  };
  master0.fill(0);
  const deps: SliceDeps = { source: new OneRecordSource(name, value), dest, signer, recipients: [bg.entry], budget: new SliceBudget({ subrequests: 5000, wallMs: 120_000 }) };
  const allShards: ShardEntry[] = [];
  let openBuffer: Record<string, unknown>[] = [];
  let cur = cp;
  let guard = 0;
  while (!cur.sourceDone && guard++ < 500) {
    const m = await unwrapMaster(signerPrivateB64, RUN_ID, cur.wrappedMaster);
    const r = await runSlice(deps, cur, m, openBuffer);
    m.fill(0);
    cur = r.checkpoint;
    allShards.push(...r.newShards);
    openBuffer = r.openReset ? r.openWrite : [...openBuffer, ...r.openWrite];
  }
  const mFin = await unwrapMaster(signerPrivateB64, RUN_ID, cur.wrappedMaster);
  await finaliseRun(deps, cur, mFin, allShards, openBuffer);
  mFin.fill(0);
  return { map: dest.entries(), bgIdentity: bg.identity, signer, signerPub };
}

async function main(): Promise<void> {
  if (!goPresent().ok) { console.log("  SKIP: Go reader toolchain not present");
  verdictSkipped("  SKIP: Go reader toolchain not present"); return; }
  const bin = join(newTmp(), "downpipe-reader");
  const built = buildReader(process.cwd(), bin);
  if (!built.ok) {
    // A reader that is ABSENT is a precondition of the environment. A reader that is HERE and does not
    // compile is a broken second reader, and calling that a skip is how this differential goes green at
    // the exact moment it has stopped existing.
    if (built.reason === "build-failed") {
      console.log(`  FAIL the sibling Go reader is present and did not build (${built.detail})`);
      verdictReached(1);
      process.exit(1);
    }
    console.log(`  SKIP: the sibling Go reader repo is not here (${built.detail})`);
    verdictSkipped(`  SKIP: the sibling Go reader repo is not here (${built.detail})`);
    return;
  }
  ok("Go offline reader built", true);

  // Aligned boundaries (exact multiples of CHUNK, where the writer emits N full chunks + NO partial) and the
  // off-by-one neighbours, plus a deeper multi-chunk record -- on the PRODUCTION runSlice path.
  const SIZES = [CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 1, 3 * CHUNK, 5 * CHUNK + 7];
  for (const size of SIZES) {
    const chunks = Math.ceil(size / CHUNK);
    const value = rand(size);
    const name = `slice-boundary-${size}`;
    const { map, bgIdentity, signer, signerPub } = await sealViaSlice(name, value);
    const root = newTmp();
    const paths = writeArchiveDir(root, map, b64urlEncode(bgIdentity), b64urlEncode(signerPub));

    const outDir = join(newTmp(), "out");
    runReader(bin, restoreFileArgs(paths.archiveDir, RUN_ID, paths.identityFile, paths.signerFile, outDir));
    const goOk = listFilesRecursive(outDir).some((p) => bytesEqual(new Uint8Array(readFileSync(p)), value));

    const run = await openRun(new MapStore(map), RUN_ID, parseIdentity(bgIdentity), verifierFrom(signer), {});
    const rec = run.records.find((r) => r.name === name);
    const tsOk = rec !== undefined && bytesEqual(await run.restoreRecord(rec), value);
    ok(`PRODUCTION runSlice ${size}B (${chunks} chunks${size % CHUNK === 0 ? ", aligned" : ""}): Go == TS == seed`, goOk && tsOk, `go=${goOk} ts=${tsOk}`);
  }

  // REFUTER (default-FAIL): a mid-segment tamper in a production-sliced multi-chunk record -> BOTH readers refuse.
  {
    const value = rand(3 * CHUNK + 19);
    const name = "slice-refuter";
    const { map, bgIdentity, signer, signerPub } = await sealViaSlice(name, value);
    let segKey = "";
    let segLen = 0;
    for (const [k, v] of map) if (v.length > segLen) { segLen = v.length; segKey = k; }
    const tv = new Uint8Array(map.get(segKey)!);
    tv[Math.floor(tv.length / 2)] = tv[Math.floor(tv.length / 2)]! ^ 1;
    const tampered = new Map(map);
    tampered.set(segKey, tv);
    const root = newTmp();
    const paths = writeArchiveDir(root, tampered, b64urlEncode(bgIdentity), b64urlEncode(signerPub));
    const goRefused = runReader(bin, restoreDiscardArgs(paths.archiveDir, RUN_ID, paths.identityFile, paths.signerFile)).exitCode !== 0;
    let tsRefused = false;
    try {
      const run = await openRun(new MapStore(tampered), RUN_ID, parseIdentity(bgIdentity), verifierFrom(signer), {});
      const rec = run.records.find((r) => r.name === name);
      if (rec) await run.restoreRecord(rec);
    } catch { tsRefused = true; }
    ok("REFUTER (default-FAIL): a mid-segment tamper in a production-sliced record is refused by BOTH readers", goRefused && tsRefused, `go=${goRefused} ts=${tsRefused}`);
  }

  console.log(failures === 0
    ? `\nPRODUCTION SLICE-BOUNDARY DIFFERENTIAL OK: ${SIZES.length} aligned/off-by-one boundary sizes sealed via runSlice/finaliseRun recovered byte-identical by Go + TS; tamper refused by both. ${assertions} assertions, net-zero.`
    : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error("SLICE-BOUNDARY FUZZER FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
