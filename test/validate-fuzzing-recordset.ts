// Record-set edge-case differential fuzzer (recovery-redundancy, net-zero). The tier-1 fuzzer NEVER seals a
// 0-byte (EMPTY) value (sizeArb min is 1 -- a stated multiset-oracle bound) and caps a run at 8 records, so
// two edges go undifferentiated: (a) EMPTY records (0-length is a classic off-by-one bug source), and (b) a
// LARGE record set (the manifest / segment index at scale). This cell seals a run with EMPTY records and a
// large mixed-size set (empty + 1-byte + small + multi-chunk, unique names) and proves BYTE-IDENTICAL recovery
// PER NAME by the TS reader (openRun.restoreRecord == seed, incl. empty -- name-keyed, no multiset collision)
// AND that the Go offline reader ACCEPTS the full set (discard-verify decrypts + hash-checks every record,
// name-path independent) AND recovers the non-empty bytes (file-sink multiset). Default-FAIL refuter: a
// segment tamper makes BOTH readers refuse. Net-zero: in-memory + the offline Go binary. Custody: no secret
// logged. Run: node test/validate-fuzzing-recordset.ts
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

const CHUNK = 65536;
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
// The source-adapter tokens the large set cycles through, so the mixed set spans four adapters rather than one.
const SOURCE_TYPES = ["kv", "r2", "d1", "secrets"] as const;
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
  const d = mkdtempSync(join(tmpdir(), "downpipes-recordset-"));
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
  try { walk(dir); } catch { /* absent => none */ }
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
async function sealToDir(records: WriteRecord[]): Promise<{ root: string; archiveDir: string; identityFile: string; signerFile: string; map: Map<string, Uint8Array>; bgIdentity: Uint8Array; signer: Signer; signerPub: Uint8Array }> {
  const root = newTmp();
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const { signer, signerPub } = await makeSigner();
  const mem = new MemoryDestination();
  const archive = await buildArchive(
    { downpipeId: "dp_recordset", downpipeName: "record-set", cadence: "0 * * * *", runId: RUN_ID, master: rand(32), recipients: [bg.entry, op.entry], signer, records, windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z", runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16) },
    { dest: mem },
  );
  for (const [k, b] of archive) await mem.put(k, b);
  const full = new Map(mem.entries());
  const paths = writeArchiveDir(root, full, b64urlEncode(bg.identity), b64urlEncode(signerPub));
  return { root, ...paths, map: full, bgIdentity: bg.identity, signer, signerPub };
}

// tsRecoversAll: every seeded record's plaintext is recovered byte-identical BY NAME (handles empties + a big
// set with no multiset collision). Returns false on any mismatch or missing record (reader divergence).
async function tsRecoversAll(map: Map<string, Uint8Array>, bgIdentity: Uint8Array, signer: Signer, records: WriteRecord[]): Promise<boolean> {
  const run = await openRun(new MapStore(map), RUN_ID, parseIdentity(bgIdentity), verifierFrom(signer), {});
  for (const seeded of records) {
    const rec = run.records.find((r) => r.name === seeded.name);
    if (!rec) return false;
    const plain = await run.restoreRecord(rec);
    if (!bytesEqual(plain, seeded.value!)) return false;
  }
  return records.length === run.records.length; // no extra/missing records
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

  // CELL 1: EMPTY records. A run with several 0-byte values (unique names) plus a couple non-empty so the run
  // is not degenerate. The byte-identical FILE-sink oracle cannot tell empties apart (all 0-byte), so empties
  // are verified BY NAME via the TS reader + accepted by the Go discard-verify (name-path independent).
  {
    const records: WriteRecord[] = [
      { sourceType: "kv", name: "empty-a", value: new Uint8Array(0) },
      { sourceType: "kv", name: "empty-b", value: new Uint8Array(0) },
      { sourceType: "d1", name: "empty-c", value: new Uint8Array(0) },
      { sourceType: "kv", name: "nonempty-1", value: rand(37) },
      { sourceType: "kv", name: "nonempty-2", value: rand(4096) },
    ];
    const { archiveDir, identityFile, signerFile, map, bgIdentity, signer } = await sealToDir(records);
    const tsOk = await tsRecoversAll(map, bgIdentity, signer, records);
    const goVerify = runReader(bin, restoreDiscardArgs(archiveDir, RUN_ID, identityFile, signerFile)).exitCode === 0;
    ok("EMPTY records: TS recovers all 0-byte values by name AND the Go reader accepts the set (discard-verify)", tsOk && goVerify, `ts=${tsOk} goVerify=${goVerify}`);
  }

  // CELL 2: a LARGE mixed-size record set (64 records: empty + 1-byte + small + a couple multi-chunk). Proves
  // the manifest / segment index scales far past the tier-1 cap of 8, with three verification modes.
  {
    const N = 64;
    const records: WriteRecord[] = [];
    for (let i = 0; i < N; i++) {
      let size: number;
      if (i % 13 === 0) size = 0;             // empties sprinkled in
      else if (i % 7 === 0) size = 1;          // single byte
      else if (i === 5) size = CHUNK + 11;     // a multi-chunk record in the set
      else if (i === 41) size = 2 * CHUNK + 3; // another multi-chunk record
      else size = 1 + (i * 97) % 2000;         // deterministic-ish spread of small sizes
      // i % 4 is 0..3, so the lookup into the four-member tuple is always a hit; the assertion is what tells
      // the checker that (noUncheckedIndexedAccess widens every index read to `| undefined`).
      const sourceType = SOURCE_TYPES[i % 4]!;
      records.push({ sourceType, name: `rec-${i}-${size}`, value: rand(size) });
      const last = records[records.length - 1]!;
      if (last.sourceType === "r2") last.bucket = "media";
    }
    const { archiveDir, identityFile, signerFile, map, bgIdentity, signer, signerPub } = await sealToDir(records);
    const tsOk = await tsRecoversAll(map, bgIdentity, signer, records);
    const goVerify = runReader(bin, restoreDiscardArgs(archiveDir, RUN_ID, identityFile, signerFile)).exitCode === 0;
    // Go file-sink: the NON-EMPTY values (unique random => no multiset collision) must all be recovered byte-identical.
    const outDir = join(newTmp(), "out");
    runReader(bin, restoreFileArgs(archiveDir, RUN_ID, identityFile, signerFile, outDir));
    const pool = listFilesRecursive(outDir).map((p) => new Uint8Array(readFileSync(p)));
    const nonEmpty = records.filter((r) => r.value!.length > 0);
    const goBytesOk = nonEmpty.every((r) => pool.some((b) => bytesEqual(b, r.value!)));
    ok(`LARGE SET (${N} records, incl. empties + multi-chunk): TS recovers all by name, Go accepts + recovers non-empty bytes`, tsOk && goVerify && goBytesOk, `ts=${tsOk} goVerify=${goVerify} goBytes=${goBytesOk}`);

    // REFUTER (default-FAIL): tamper the largest segment in the set -> BOTH readers refuse.
    let segKey = "";
    let segLen = 0;
    for (const [k, v] of map) if (v.length > segLen) { segLen = v.length; segKey = k; }
    const tv = new Uint8Array(map.get(segKey)!);
    tv[Math.floor(tv.length / 2)] = tv[Math.floor(tv.length / 2)]! ^ 1;
    const tamperedMap = new Map(map);
    tamperedMap.set(segKey, tv);
    const troot = newTmp();
    const tpaths = writeArchiveDir(troot, tamperedMap, b64urlEncode(bgIdentity), b64urlEncode(signerPub));
    const goRefused = runReader(bin, restoreDiscardArgs(tpaths.archiveDir, RUN_ID, tpaths.identityFile, tpaths.signerFile)).exitCode !== 0;
    let tsRefused = false;
    try { await tsRecoversAll(tamperedMap, bgIdentity, signer, records); } catch { tsRefused = true; }
    ok("REFUTER (default-FAIL): a tampered segment in the large set is refused by BOTH readers", goRefused && tsRefused, `go=${goRefused} ts=${tsRefused}`);
  }

  console.log(failures === 0
    ? `\nRECORD-SET EDGE DIFFERENTIAL OK: empty (0-byte) records + a 64-record mixed set recovered byte-identical (TS by name, Go accepts + recovers); tamper refused by both. ${assertions} assertions, net-zero.`
    : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error("RECORD-SET FUZZER FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
