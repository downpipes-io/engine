// Chunk-boundary differential fuzzer (recovery-redundancy, net-zero). The tier-1 fuzzer caps record VALUES at
// 3072 bytes, so it NEVER crosses the 65536-byte CHUNK boundary -- multi-chunk single-record REASSEMBLY (the
// off-by-one-prone path) is never differentially validated across readers. A reader divergence there silently
// corrupts a large-object restore. This seals single records AT and around the chunk boundary (64K/128K/192K
// +/- 1) and at larger multi-chunk sizes, and asserts BYTE-IDENTICAL recovery by THREE independent readers --
// the Go offline reader, the TS buffered restoreRecord, and the TS constant-memory restoreRecordStream -- all
// equal to the seed (Go == TS-buffered == TS-streaming == seed). Default-FAIL refuter: a tamper in the MIDDLE
// of a multi-chunk record's segment makes ALL THREE readers refuse (the multi-chunk differential is not
// vacuous, and a mid-segment flip proves non-terminal chunks are validated). Net-zero: in-memory + the offline
// Go binary. Custody: no secret logged. Run: node test/validate-fuzzing-chunkboundary.ts
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { x25519 } from "@noble/curves/ed25519.js";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { buildArchive, type RecipientEntry, type Signer, type WriteRecord } from "../src/format/writer.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { verifierFrom } from "../src/keys-env.ts";
import { MemoryDestination } from "./memdest.ts";
import { assertEphemeralWorkdir, buildReader, goPresent, restoreDiscardArgs, runReader, writeArchiveDir } from "./scale-go-reader.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

const CHUNK = 65536; // src/format/version.ts CHUNK_SIZE
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
// crypto.getRandomValues caps at 65536 bytes/call, so fill large buffers in 64KB slices.
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
  const d = mkdtempSync(join(tmpdir(), "downpipes-chunkbound-"));
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
  const walk = (d: string): void => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else out.push(p);
    }
  };
  try { walk(dir); } catch { /* absent out dir => no restored files */ }
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
async function makeSigner(): Promise<{ signer: Signer; signerPub: Uint8Array }> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  return { signer: { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey }, signerPub: concat(edPublic, mldsa.publicKey) };
}
class MapStore implements ObjectStore {
  private readonly map: Map<string, Uint8Array>;
  constructor(map: Map<string, Uint8Array>) {
    this.map = map;
  }
  async get(key: string): Promise<Uint8Array> {
    const v = this.map.get(key);
    if (!v) throw new Error(`object not found: ${key}`);
    return v;
  }
  list(prefix: string): Promise<string[]> {
    return Promise.resolve([...this.map.keys()].filter((k) => k.startsWith(prefix)));
  }
}
async function sealToDir(records: WriteRecord[]): Promise<{ root: string; archiveDir: string; identityFile: string; signerFile: string; map: Map<string, Uint8Array>; bgIdentity: Uint8Array; signer: Signer }> {
  const root = newTmp();
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const { signer, signerPub } = await makeSigner();
  const mem = new MemoryDestination();
  const archive = await buildArchive(
    { downpipeId: "dp_chunkbound", downpipeName: "chunk-boundary", cadence: "0 * * * *", runId: RUN_ID, master: rand(32), recipients: [bg.entry, op.entry], signer, records, windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z", runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16) },
    { dest: mem },
  );
  for (const [k, b] of archive) await mem.put(k, b);
  const full = new Map(mem.entries());
  const paths = writeArchiveDir(root, full, b64urlEncode(bg.identity), b64urlEncode(signerPub));
  return { root, ...paths, map: full, bgIdentity: bg.identity, signer };
}

// streamToBytes drains restoreRecordStream's ReadableStream into one Uint8Array (throws propagate = refusal).
async function streamToBytes(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) { parts.push(value); total += value.length; }
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

async function main(): Promise<void> {
  const go = goPresent();
  if (!go.ok) { console.log("  SKIP: Go reader toolchain not present; cannot run the offline-reader differential");
  verdictSkipped("  SKIP: Go reader toolchain not present; cannot run the offline-reader differential"); return; }
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

  // Sizes straddling every chunk boundary (off-by-one-prone) plus larger multi-chunk records. n chunks =
  // ceil(n/CHUNK); the tier-1 fuzzer never exceeds CHUNK, so every size here is NEW multi-chunk coverage.
  const SIZES = [CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK - 1, 2 * CHUNK, 2 * CHUNK + 1, 3 * CHUNK - 1, 3 * CHUNK, 3 * CHUNK + 1, 4 * CHUNK + 13, 8 * CHUNK + 7];

  for (const size of SIZES) {
    const chunks = Math.ceil(size / CHUNK);
    const value = rand(size);
    const name = `boundary-${size}`;
    const { archiveDir, identityFile, signerFile, map, bgIdentity, signer } = await sealToDir([{ sourceType: "kv", name, value }]);

    // Reader 1: the Go offline reader restores to files; byte-identical to the seed.
    const outDir = join(newTmp(), "out");
    const goRun = runReader(bin, restoreFileArgs(archiveDir, RUN_ID, identityFile, signerFile, outDir));
    const goPool = listFilesRecursive(outDir).map((p) => new Uint8Array(readFileSync(p)));
    const goOk = goRun.exitCode === 0 && goPool.some((b) => bytesEqual(b, value));

    // Reader 2: the TS buffered restoreRecord. Reader 3: the TS constant-memory restoreRecordStream.
    const run = await openRun(new MapStore(map), RUN_ID, parseIdentity(bgIdentity), verifierFrom(signer), {});
    const rec = run.records.find((r) => r.name === name);
    const tsBuf = rec ? await run.restoreRecord(rec) : new Uint8Array(0);
    const tsStream = rec ? await streamToBytes(run.restoreRecordStream(rec)) : new Uint8Array(0);
    const bufOk = rec !== undefined && bytesEqual(tsBuf, value);
    const strOk = rec !== undefined && bytesEqual(tsStream, value);

    ok(`${size}B (${chunks} chunks): Go == TS-buffered == TS-streaming == seed`, goOk && bufOk && strOk, `go=${goOk} buf=${bufOk} stream=${strOk}`);
  }

  // Refuter (default-FAIL): a MID-SEGMENT byte flip on a multi-chunk record must make ALL THREE readers refuse.
  // Flipping the middle (not the last byte) proves non-terminal chunks are integrity-checked, incl. by the
  // streaming reader which validates as it flows.
  {
    const size = 3 * CHUNK + 17; // 4 chunks
    const value = rand(size);
    const name = "refuter-multichunk";
    const { archiveDir, identityFile, signerFile, map, bgIdentity, signer } = await sealToDir([{ sourceType: "kv", name, value }]);
    // The record's data segment is the largest object; flip a byte in its MIDDLE.
    let segKey = "";
    let segLen = 0;
    for (const [k, v] of map) if (v.length > segLen) { segLen = v.length; segKey = k; }
    const tampered = new Uint8Array(map.get(segKey)!);
    const mid = Math.floor(tampered.length / 2);
    tampered[mid] = tampered[mid]! ^ 1;
    map.set(segKey, tampered);

    // Rewrite the archive dir from the tampered map so the Go reader sees the tamper too.
    const troot = newTmp();
    const bgB64 = b64urlEncode(bgIdentity);
    // signer pub for the dir: re-derive from the signer (edPublic+mldsaPublic).
    const signerPub = concat(signer.edPublic, signer.mldsaPublic);
    const tpaths = writeArchiveDir(troot, map, bgB64, b64urlEncode(signerPub));

    const goRefused = runReader(bin, restoreDiscardArgs(tpaths.archiveDir, RUN_ID, tpaths.identityFile, tpaths.signerFile)).exitCode !== 0;
    let bufRefused = false;
    let strRefused = false;
    try {
      const run = await openRun(new MapStore(map), RUN_ID, parseIdentity(bgIdentity), verifierFrom(signer), {});
      const rec = run.records.find((r) => r.name === name);
      if (rec) await run.restoreRecord(rec);
    } catch { bufRefused = true; }
    try {
      const run = await openRun(new MapStore(map), RUN_ID, parseIdentity(bgIdentity), verifierFrom(signer), {});
      const rec = run.records.find((r) => r.name === name);
      if (rec) await streamToBytes(run.restoreRecordStream(rec));
    } catch { strRefused = true; }

    ok("REFUTER (default-FAIL): a mid-segment flip in a multi-chunk record is refused by ALL THREE readers", goRefused && bufRefused && strRefused, `go=${goRefused} buf=${bufRefused} stream=${strRefused}`);
    // reference archiveDir/identityFile/signerFile so the tuple is used
    void archiveDir; void identityFile; void signerFile;
  }

  console.log(failures === 0
    ? `\nCHUNK-BOUNDARY DIFFERENTIAL OK: ${SIZES.length} multi-chunk sizes recovered byte-identical by Go + TS-buffered + TS-streaming; mid-segment tamper refused by all three. ${assertions} assertions, net-zero.`
    : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error("CHUNK-BOUNDARY FUZZER FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
