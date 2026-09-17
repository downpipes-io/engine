// Axis fuzzing Tier 1 (net-zero, deploy-free): property-based and differential fuzzing of the
// recovery-critical path. The genuinely un-fuzzed surface is the PRODUCTION TypeScript seal buildArchive
// (writer.ts:194) over a RANDOMISED input domain, read differentially by the independent Go reader. A fixed
// six-record example (write-archive.ts) does not exercise that domain. This drives buildArchive over a
// fast-check-generated WriteRecord[] and asserts the independent Go reader both verifies, decrypts and
// hash-checks every record (the discard sink) AND restores every record to byte-identical plaintext (the file
// sink, compared against the harness's OWN seeded plaintext, which is the load-bearing external oracle: an
// internal-consistency verify alone would pass a wrong-but-self-consistent seal).
//
// Cell A here is the fuzzed round-trip. Its two refuters default to FAIL: R1 proves the byte-compare has teeth
// (a one-bit-flipped copy of a seeded value is NOT found in the restore), and R2 proves the differential has
// teeth (a one-byte-tampered archive makes the Go reader REFUSE, so the exit-0 in the positive case is not
// vacuous). Go absent degrades to a named GAP, never a false pass.
//
// NET-ZERO: in-process seal, a locally built Go binary, harness-minted keys, fuzzed fake data; ephemeral temp
// dirs only (assertEphemeralWorkdir refuses a repo-tree or live-keys path). No estate, bucket, network, seed
// or spend. House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import fc from "fast-check";
import { x25519 } from "@noble/curves/ed25519.js";

import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer, type WriteRecord } from "../src/format/writer.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { verifierFrom } from "../src/keys-env.ts";
import { MemoryDestination } from "./memdest.ts";
import { assertEphemeralWorkdir, buildReader, goPresent, restoreDiscardArgs, runReader, writeArchiveDir } from "./scale-go-reader.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"; // a fixed valid ULID; each seal is independent in a fresh dir

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function newTmp(): string {
  const d = mkdtempSync(join(tmpdir(), "downpipes-fuzz-"));
  assertEphemeralWorkdir(d);
  return d;
}

// The --sink file materialise argv (offline by construction: --archive, never --s3-endpoint), mirroring
// offline-cold-restore-drive.ts restoreArgs(..., "file", out).
function restoreFileArgs(archiveDir: string, runId: string, identityFile: string, signerFile: string, outDir: string): string[] {
  return ["restore", "--archive", archiveDir, "--run", runId, "--identity", identityFile, "--signer", signerFile, "--sink", "file", "--apply", "--out", outDir];
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
  try {
    walk(dir);
  } catch {
    /* an absent out dir grades as no restored files */
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// multisetTake finds a byte-equal blob in the pool and removes it (so duplicate seeded values each need their
// own restored copy). Returns true when a match was found and consumed.
function multisetTake(pool: Uint8Array[], want: Uint8Array): boolean {
  const i = pool.findIndex((b) => bytesEqual(b, want));
  if (i < 0) return false;
  pool.splice(i, 1);
  return true;
}

function flipOneByte(v: Uint8Array): Uint8Array {
  const c = new Uint8Array(v);
  if (c.length === 0) return new Uint8Array([1]); // a non-empty distinct value for the empty case
  c[c.length - 1] = c[c.length - 1]! ^ 1;
  return c;
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

// sealToDir drives the REAL buildArchive over the given records and lays the archive out on disk in the Go
// CLI's layout, returning the reader's argv anchors. Streamed segments (none here, this cell is buffered) land
// in mem; the returned map holds the manifest and buffered segments.
async function sealToDir(records: WriteRecord[]): Promise<{ root: string; archiveDir: string; identityFile: string; signerFile: string; map: Map<string, Uint8Array>; bgIdentity: Uint8Array; signer: Signer }> {
  const root = newTmp();
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const { signer, signerPub } = await makeSigner();
  const mem = new MemoryDestination();
  const archive = await buildArchive(
    {
      downpipeId: "dp_fuzz",
      downpipeName: "fuzz-roundtrip",
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
    { dest: mem },
  );
  for (const [k, b] of archive) await mem.put(k, b);
  const full = new Map(mem.entries());
  const paths = writeArchiveDir(root, full, b64urlEncode(bg.identity), b64urlEncode(signerPub));
  return { root, ...paths, map: full, bgIdentity: bg.identity, signer };
}

// A minimal in-memory ObjectStore over the archive map, for driving the TS reader openRun in process (Cell D).
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

// --- boundary-biased generators over the seal-input domain (design section 3.1) ---
const PATHO_NAMES = ["", "a", "\u0000null", "fire\u{1f525}", "\u202ertl", "uploads/x/y.txt", "x".repeat(400), "  spaced  ", "dot..dot", "a/../b"];
// Cell A's byte-identical oracle materialises through the FILE sink, whose destinations are filesystem paths,
// so its sound domain is filesystem-valid non-empty names. Pathological names (NUL, empty, path-colliding,
// which cannot be filesystem paths at all) go instead to the discard-verify cell, which decrypts and
// hash-checks every record over the FULL fuzzed domain and is name-path independent, plus Cell C name-MAC.
// Lowercase only: names differing only in case (H vs h) collide on a case-insensitive filesystem, where the
// byte-identical file-sink oracle would lose one to a silent overwrite. Case-differing names are still
// exercised by the discard-verify cell (name-path independent). This is a stated bound of the file sink.
const CLEAN_NAME_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789._-".split("");
// The file sink REFUSES a Windows reserved device name rather than mangling it, which is deliberate and
// documented (downpipe internal/restore/target_dir.go firstReservedWindowsElement). The clean alphabet
// below can spell one: "con", "nul", "com1", and with the dot, "con.". Cell A's oracle is "every record
// is byte-identical in the restored directory", and that is soundly UNCHECKABLE for a name the sink will
// not write, so drawing one made Cell A fail as a byte mismatch when the product was behaving correctly.
// Those names are not dropped from the fuzz: the pathological cell below drives them through the discard
// sink, which is name-path independent, and the reserved-name cell asserts the refusal itself.
//
// The rule mirrors the Go one: take the element's base up to the first "." or ":", strip trailing spaces,
// compare case-insensitively.
const WINDOWS_RESERVED = new Set(["CON", "PRN", "AUX", "NUL", ...Array.from({ length: 9 }, (_, i) => `COM${i + 1}`), ...Array.from({ length: 9 }, (_, i) => `LPT${i + 1}`)]);
function namesAWindowsDevice(name: string): boolean {
  return name.split(/[/\\]/).some((part) => {
    const cut = part.search(/[.:]/);
    return WINDOWS_RESERVED.has((cut >= 0 ? part.slice(0, cut) : part).replace(/ +$/, "").toUpperCase());
  });
}
// A path element of "." or ".." is a DIRECTORY REFERENCE, not a filename, so the file sink refuses it for
// the same reason it refuses a Windows device name: it will not mangle a name into something the archive
// did not say. The clean alphabet includes the dot, so it spells both, and a one-character name of "."
// took nine runs to appear.
//
// It is excluded for the reason already written above for Windows devices: the oracle here is "every
// record is byte-identical in the restored directory", and that is soundly UNCHECKABLE for a name the
// sink will not write. Leaving it in did not find a product bug, it made Cell E read the sink's advisory
// exit 10 as "the Go reader refused a clean archive", which is a false accusation against the reader.
// The refusal path itself is asserted deterministically by Cell A phase 4, so excluding it here loses no
// coverage.
function namesADirectoryReference(name: string): boolean {
  return name.split(/[/\\]/).some((part) => part === "." || part === "..");
}
const cleanNameArb = fc
  .array(fc.constantFrom(...CLEAN_NAME_CHARS), { minLength: 1, maxLength: 32 })
  .map((a) => a.join(""))
  .filter((n) => !namesAWindowsDevice(n) && !namesADirectoryReference(n));
const pathoNameArb = fc.oneof(fc.constantFrom(...PATHO_NAMES), fc.string({ maxLength: 48 }));
const sizeArb = fc.oneof(fc.constant(1), fc.constant(64), fc.integer({ min: 1, max: 3072 })); // non-empty: an empty blob is indistinguishable from a metadata 0-byte file in the multiset oracle (a stated bound)
const valueArb = sizeArb.map((n) => rand(n));
const sourceTypeArb = fc.constantFrom("kv", "r2", "secrets", "d1");
const recordArb: fc.Arbitrary<WriteRecord> = fc.record({ sourceType: sourceTypeArb, name: cleanNameArb, value: valueArb }).map((r) => {
  const rec: WriteRecord = { sourceType: r.sourceType, name: r.name, value: r.value };
  if (r.sourceType === "r2") rec.bucket = "media";
  return rec;
});
// Name COLLISIONS are Cell C's domain, not the round-trip's, so make names unique within a run without
// losing the pathological base (a colliding name gets a control-char + index suffix).
const recordsArb = fc.array(recordArb, { minLength: 1, maxLength: 8 }).map((recs) => {
  const seen = new Set<string>();
  return recs.map((r, i) => {
    let name = r.name;
    while (seen.has(name)) name = `${r.name}\u0001${i}`;
    seen.add(name);
    return { ...r, name };
  });
});

const pathoRecordArb: fc.Arbitrary<WriteRecord> = fc.record({ sourceType: sourceTypeArb, name: pathoNameArb, value: valueArb }).map((r) => {
  const rec: WriteRecord = { sourceType: r.sourceType, name: r.name, value: r.value };
  if (r.sourceType === "r2") rec.bucket = "media";
  return rec;
});
const pathoRecordsArb = fc.array(pathoRecordArb, { minLength: 1, maxLength: 8 }).map((recs) => {
  const seen = new Set<string>();
  return recs.map((r, i) => {
    let name = r.name;
    while (seen.has(name)) name = `${r.name}${i}`;
    seen.add(name);
    return { ...r, name };
  });
});

async function roundTripHolds(records: WriteRecord[], bin: string): Promise<void> {
  const { root, archiveDir, identityFile, signerFile } = await sealToDir(records);
  const verify = runReader(bin, restoreDiscardArgs(archiveDir, RUN_ID, identityFile, signerFile));
  if (verify.exitCode !== 0) throw new Error(`discard-verify REFUSED a clean fuzzed seal (exit ${verify.exitCode}): ${verify.stderr.slice(-300)}`);
  const outDir = join(root, "restored");
  const restore = runReader(bin, restoreFileArgs(archiveDir, RUN_ID, identityFile, signerFile, outDir));
  if (restore.exitCode !== 0) throw new Error(`file-restore failed (exit ${restore.exitCode}): ${restore.stderr.slice(-300)}`);
  const pool = listFilesRecursive(outDir).map((p) => new Uint8Array(readFileSync(p)));
  for (const r of records) {
    if (!multisetTake(pool, r.value!)) throw new Error(`record "${r.name}" (${r.value!.length}B, ${r.sourceType}) NOT byte-identical in the Go restore`);
  }
}

// FUZZ_SCALE multiplies every cell's iteration budget (default 1, a smoke test). Set it high for the
// owner-gated coverage-guided soak, e.g. FUZZ_SCALE=8 npm run validate:fuzzing-tier1.
const SCALE = Math.max(1, Math.floor(Number(process.env.FUZZ_SCALE) || 1));

// FUZZ_SEED replays a specific failure. fast-check prints the seed and path of any counterexample it
// finds, but without a way to feed them back the report is unreproducible: the next run draws a new seed
// and passes, which is exactly how a real property failure gets written off as a flake. Setting both
// pins the generator to the failing draw. FUZZ_PATH is optional and jumps straight to the shrunk case.
const REPLAY: { seed?: number; path?: string } = {};
if (process.env.FUZZ_SEED) REPLAY.seed = Number(process.env.FUZZ_SEED);
if (process.env.FUZZ_PATH) REPLAY.path = process.env.FUZZ_PATH;

async function main(): Promise<void> {
  const go = goPresent();
  if (!go.ok) {
    verdictSkipped("Go toolchain absent; the differential fuzz cell needs the sibling Go reader. Not a pass, not a fail.");
    process.exit(0);
  }
  const engineDir = process.cwd(); // the validators run from the engine dir; buildReader looks for ../downpipe
  const bin = join(newTmp(), "downpipe");
  const built = buildReader(engineDir, bin);
  if (!built.ok) {
    // A reader that is ABSENT is a precondition of the environment. A reader that is HERE and does not
    // compile is a broken second reader, and calling that a skip is how this differential goes green at
    // the exact moment it has stopped existing.
    if (built.reason === "build-failed") {
      console.log(`  FAIL the sibling Go reader is present and did not build (${built.detail})`);
      verdictReached(1);
      process.exit(1);
    }
    verdictSkipped(`${built.detail}. The differential fuzz cell needs the built Go reader. Not a pass, not a fail.`);
    process.exit(0);
  }
  console.log(`fuzzing Tier 1: Go present (${go.version}), reader ${built.detail}`);

  let assertions = 0;

  // Refuter R2 (differential teeth, default-FAIL): a one-byte-tampered archive segment MUST make the Go reader
  // refuse, else the exit-0 in Cell A is vacuous. Run before the positive cell.
  {
    const recs: WriteRecord[] = [{ sourceType: "kv", name: "r2-probe", value: rand(64) }];
    const { archiveDir, identityFile, signerFile } = await sealToDir(recs);
    const clean = runReader(bin, restoreDiscardArgs(archiveDir, RUN_ID, identityFile, signerFile));
    if (clean.exitCode !== 0) throw new Error(`R2 setup: a clean archive should verify, got exit ${clean.exitCode}`);
    // flip one byte of the largest object under the archive dir
    const objs = listFilesRecursive(archiveDir).sort((a, b) => readFileSync(b).length - readFileSync(a).length);
    if (objs.length === 0) throw new Error("R2 setup: no archive objects to tamper");
    const target = objs[0]!;
    const buf = readFileSync(target);
    buf[buf.length - 1] = buf[buf.length - 1]! ^ 1;
    const fs = await import("node:fs");
    fs.writeFileSync(target, buf);
    const tampered = runReader(bin, restoreDiscardArgs(archiveDir, RUN_ID, identityFile, signerFile));
    if (tampered.exitCode === 0) throw new Error("REFUTER R2 FAILED: the Go reader accepted a one-byte-tampered archive (the differential is vacuous)");
    assertions++;
    console.log(`differential-teeth refuter cleared: tampered archive refused (exit ${tampered.exitCode})`);
  }

  // Refuter R1 (byte-compare teeth, default-FAIL): a one-bit-flipped copy of a seeded value must NOT be found
  // in the restore, while the true value IS, else the multiset oracle is vacuous.
  {
    const v = rand(128);
    const recs: WriteRecord[] = [{ sourceType: "kv", name: "oracle-probe", value: v }];
    const { root, archiveDir, identityFile, signerFile } = await sealToDir(recs);
    const outDir = join(root, "restored");
    const restore = runReader(bin, restoreFileArgs(archiveDir, RUN_ID, identityFile, signerFile, outDir));
    if (restore.exitCode !== 0) throw new Error(`R1 setup: clean restore should exit 0, got ${restore.exitCode}: ${restore.stderr.slice(-200)}`);
    const pool = listFilesRecursive(outDir).map((p) => new Uint8Array(readFileSync(p)));
    const poolCopy = pool.slice();
    if (!multisetTake(pool, v)) throw new Error("R1 setup: the true seeded value was not found in a clean restore (the oracle cannot see the plaintext)");
    if (multisetTake(poolCopy, flipOneByte(v))) throw new Error("REFUTER R1 FAILED: a one-bit-flipped value was found in the restore (the byte-compare is vacuous)");
    assertions++;
    console.log("byte-compare-teeth refuter cleared: true value found, flipped value rejected");
  }

  // Cell A (positive property): every fuzzed buffered record set round-trips to byte-identical plaintext
  // through the independent Go reader.
  const NUM_RUNS = 40 * SCALE;
  await fc.assert(
    fc.asyncProperty(recordsArb, async (records) => {
      await roundTripHolds(records, bin);
    }),
    { numRuns: NUM_RUNS, verbose: false, ...REPLAY },
  );
  assertions += NUM_RUNS;
  console.log(`Cell A cleared: ${NUM_RUNS} fuzzed record sets round-tripped byte-identical through the Go reader`);

  // Cell A phase 2 (full name domain): over pathological names (NUL, empty, path-separators, RTL, long) the
  // independent Go reader must still verify, decrypt and hash-check every record. This is name-path
  // independent (the discard sink materialises nothing), so it covers the domain the byte-identical file-sink
  // oracle soundly cannot, without a vacuous pass (R2 above proves discard-verify refuses a tampered archive).
  const PATHO_RUNS = 40 * SCALE;
  await fc.assert(
    fc.asyncProperty(pathoRecordsArb, async (records) => {
      const { archiveDir, identityFile, signerFile } = await sealToDir(records);
      const v = runReader(bin, restoreDiscardArgs(archiveDir, RUN_ID, identityFile, signerFile));
      if (v.exitCode !== 0) throw new Error(`discard-verify REFUSED a fuzzed seal over pathological names (exit ${v.exitCode}): ${v.stderr.slice(-300)}`);
    }),
    { numRuns: PATHO_RUNS, verbose: false, ...REPLAY },
  );
  assertions += PATHO_RUNS;
  console.log(`Cell A phase 2 cleared: ${PATHO_RUNS} record sets over pathological names verified + decrypted in the Go reader`);

  // Cell A phase 4 (reserved-name refusal, deterministic). Phase 1 excludes Windows device names because
  // its byte-identical oracle cannot check a name the file sink refuses to write. That exclusion must not
  // become a blind spot, so the refusal itself is asserted here, and it is worth asserting because the
  // product got it wrong: the record was skipped, the conflict was printed to stderr, and the restore
  // exited 0. A DR script reading that exit code concluded a clean full restore while a record from the
  // archive was absent from disk. It now exits ExitUnwritten (10), an advisory distinct from the hard
  // failure codes because nothing is corrupt, and the other records in the same run still land.
  {
    const RESERVED = "con.";
    const companion = "kept-alongside";
    const records: WriteRecord[] = [
      { sourceType: "kv", name: RESERVED, value: rand(24) },
      { sourceType: "kv", name: companion, value: rand(24) },
    ];
    const { root, archiveDir, identityFile, signerFile } = await sealToDir(records);
    // It seals fine: the refusal is the file TARGET's, not the format's, and the record is recoverable
    // by any target that can represent it. The discard sink proves that separately.
    const discard = runReader(bin, restoreDiscardArgs(archiveDir, RUN_ID, identityFile, signerFile));
    if (discard.exitCode !== 0) throw new Error(`a reserved-name record must still verify and decrypt through the discard sink (the data IS recoverable), got exit ${discard.exitCode}: ${discard.stderr.slice(-200)}`);

    const outDir = join(root, "restored-reserved");
    const res = runReader(bin, restoreFileArgs(archiveDir, RUN_ID, identityFile, signerFile, outDir));
    if (res.exitCode === 0) throw new Error("the file restore exited 0 after SKIPPING a record: a DR script reads that as a clean full restore while a record from the archive is absent from disk");
    if (res.exitCode !== 10) throw new Error(`the file restore must exit the unwritten advisory 10, got ${res.exitCode}: ${res.stderr.slice(-200)}`);
    if (!res.stderr.includes(RESERVED) || !/reserved device name/i.test(res.stderr)) throw new Error(`the refusal must name the record and why, got: ${res.stderr.slice(-300)}`);
    // The advisory must not become an excuse to drop the rest of the run.
    const pool = listFilesRecursive(outDir).map((p) => new Uint8Array(readFileSync(p)));
    if (!multisetTake(pool, records[1]!.value as Uint8Array)) throw new Error("the companion record did not land byte-identical: one refused name must not drop the rest of the run");
    if (pool.length !== 0) throw new Error(`the refused record left ${pool.length} unexpected file(s) behind (a mangled or placeholder write)`);
    assertions += 6;
  }
  console.log("Cell A phase 4 cleared: a reserved-name record is refused by the file sink, reported, and exits the unwritten advisory while its siblings still restore");

  // Cell A phase 3 (invalid-UTF-8 / lone-surrogate names -- the offline-recovery differential). The concern is
  // that a lone-surrogate record name might MAC or round-trip DIFFERENTLY in the
  // independent Go reader than in the TS engine (the TS port collapses a lone surrogate to U+FFFD via utf8()).
  // It cannot, and by a stronger mechanism than collapse-agreement: the engine REFUSES to seal such a name at
  // all. canonString (src/format/canonjson.ts:56) rejects any string that is not valid UTF-8 -- "a name must
  // not be quietly rewritten" -- so buildArchive throws before any archive is emitted, fail-closed. No archive
  // with a non-UTF-8 name ever reaches the Go reader, so there is nothing for it to diverge on. Two-sided: every
  // lone-surrogate name is refused at seal, and the valid-UTF-8 control (the same shapes with the surrogate
  // replaced by a real char) seals and verifies, so the refusal is surrogate-specific, not a blanket failure.
  {
    const badNames = ["\uD800", "lo\uDC00ne", "pair\uD800tail\uDFFF", "\uDBFFx", "mix\uDC00x\uD800end"];
    for (const name of badNames) {
      let threw = false;
      try {
        await sealToDir([{ sourceType: "kv", name, value: rand(32) }]);
      } catch {
        threw = true; // canonString refuses to transcode the lone surrogate (fail-closed)
      }
      if (!threw) throw new Error(`a lone-surrogate name ${JSON.stringify(name)} was SEALED instead of refused -- a non-UTF-8 name in an archive is an offline-recovery divergence risk`);
      assertions++;
    }
    const ctrl = ["Qgood", "loONEne", "pairXtailY", "wzx", "mixQxRend"];
    const recs: WriteRecord[] = ctrl.map((name, i) => ({ sourceType: "kv", name, value: rand(48 + i) }));
    const { archiveDir, identityFile, signerFile } = await sealToDir(recs);
    const v = runReader(bin, restoreDiscardArgs(archiveDir, RUN_ID, identityFile, signerFile));
    if (v.exitCode !== 0) throw new Error(`control: the valid-UTF-8 companion of the surrogate names should verify, got exit ${v.exitCode}: ${v.stderr.slice(-200)}`);
    assertions++;
    console.log(`Cell A phase 3 cleared: ${badNames.length} lone-surrogate names refused at seal (canonString fail-closed, canonjson.ts:56), valid-UTF-8 control verified -- no non-UTF-8 name can reach the Go offline reader`);
  }

  // Cell E (two-reader differential, the recovery-redundancy property): the independent Go reader and the TS
  // reader (openRun) must recover BYTE-IDENTICAL plaintext from the SAME fuzzed archive. The two readers are the
  // recovery redundancy; a divergence means a customer could recover DIFFERENT data depending on which reader.
  // This is FUZZED, where the both-reader conformance replay only ever covered a fixed corpus.
  const DIFF_RUNS = 40 * SCALE;
  await fc.assert(
    fc.asyncProperty(recordsArb, async (records) => {
      const { archiveDir, identityFile, signerFile, map, bgIdentity, signer } = await sealToDir(records);
      const outDir = join(newTmp(), "out");
      const goRun = runReader(bin, restoreFileArgs(archiveDir, RUN_ID, identityFile, signerFile, outDir));
      if (goRun.exitCode !== 0) throw new Error(`Go reader refused a clean archive (exit ${goRun.exitCode})`);
      const goPool = listFilesRecursive(outDir).map((p) => new Uint8Array(readFileSync(p)));
      const run = await openRun(new MapStore(map), RUN_ID, parseIdentity(bgIdentity), verifierFrom(signer), {});
      for (const seeded of records) {
        const rec = run.records.find((r) => r.name === seeded.name);
        if (!rec) throw new Error(`the TS reader is missing record "${seeded.name}" (reader divergence)`);
        const tsPlain = await run.restoreRecord(rec);
        if (!bytesEqual(tsPlain, seeded.value!)) throw new Error(`the TS reader recovered wrong plaintext for "${seeded.name}"`);
        if (!goPool.some((b) => bytesEqual(b, tsPlain))) throw new Error(`the Go reader did NOT recover "${seeded.name}" that the TS reader did (READER DIVERGENCE)`);
      }
    }),
    { numRuns: DIFF_RUNS, verbose: false },
  );
  assertions += DIFF_RUNS;
  console.log(`Cell E cleared: ${DIFF_RUNS} fuzzed archives recovered byte-identical by BOTH the Go reader and the TS reader (recovery redundancy holds)`);

  // Refuter R3 (two-reader teeth, default-FAIL): a byte-tampered archive must make the TS reader REFUSE, so the
  // differential is not a vacuous both-accept (R2 already proves the Go reader refuses a tamper).
  {
    const { map, bgIdentity, signer } = await sealToDir([{ sourceType: "kv", name: "r3probe", value: rand(96) }]);
    let largestKey = "";
    let largestLen = 0;
    for (const [k, v] of map) if (v.length > largestLen) { largestLen = v.length; largestKey = k; }
    const tv = new Uint8Array(map.get(largestKey)!);
    tv[tv.length - 1] = tv[tv.length - 1]! ^ 1;
    map.set(largestKey, tv);
    let tsRefused = false;
    try {
      const run = await openRun(new MapStore(map), RUN_ID, parseIdentity(bgIdentity), verifierFrom(signer), {});
      for (const r of run.records) await run.restoreRecord(r);
    } catch {
      tsRefused = true;
    }
    if (!tsRefused) throw new Error("REFUTER R3 FAILED: the TS reader accepted a byte-tampered archive (the two-reader differential is vacuous)");
    assertions++;
    console.log("R3 two-reader-teeth cleared: a byte-tampered archive is refused by the TS reader (the Go refusal is R2)");
  }

  // Cell B (fuzzed tamper, the negative property): over a clean sealed archive, a one-byte flip at a FUZZED
  // position (any object, any byte) is EITHER caught (the Go reader refuses) OR a proven no-op (the restored
  // plaintext is unchanged), NEVER a silent wrong plaintext. A pass that changed a plaintext is the highest
  // value finding and throws with the exact object and offset. This generalises the single R2 tamper to the
  // whole archive-byte domain.
  const TAMPER_RUNS = 60 * SCALE;
  const fsMod = await import("node:fs");
  await fc.assert(
    fc.asyncProperty(recordsArb, fc.nat(), fc.nat(), async (records, objSel, byteSel) => {
      const { root, archiveDir, identityFile, signerFile } = await sealToDir(records);
      const objs = listFilesRecursive(archiveDir);
      if (objs.length === 0) return;
      const target = objs[objSel % objs.length]!;
      const buf = readFileSync(target);
      if (buf.length === 0) return;
      const pos = byteSel % buf.length;
      buf[pos] = buf[pos]! ^ 0x01;
      fsMod.writeFileSync(target, buf);
      const verify = runReader(bin, restoreDiscardArgs(archiveDir, RUN_ID, identityFile, signerFile));
      if (verify.exitCode !== 0) return; // CAUGHT
      // verify passed: it must be a no-op. Restore and confirm every seeded plaintext is unchanged.
      const outDir = join(root, "tamper-restored");
      const restore = runReader(bin, restoreFileArgs(archiveDir, RUN_ID, identityFile, signerFile, outDir));
      if (restore.exitCode !== 0) return; // refused at the file sink: still caught, not silent-wrong
      const pool = listFilesRecursive(outDir).map((p) => new Uint8Array(readFileSync(p)));
      for (const r of records) {
        if (!multisetTake(pool, r.value!)) {
          throw new Error(`SILENT WRONG: a flip at ${target.split("/").slice(-2).join("/")} byte ${pos} passed verify but changed the restored plaintext of "${r.name}"`);
        }
      }
    }),
    { numRuns: TAMPER_RUNS, verbose: false },
  );
  assertions += TAMPER_RUNS;
  console.log(`Cell B cleared: ${TAMPER_RUNS} fuzzed single-byte tampers each caught or a proven no-op, never silent-wrong`);

  // Cell D (format-robustness, the TS reader openRun in process): openRun is a TOTAL, non-lying parser over
  // malformed input. On a fuzz-malformed archive (an object removed, truncated, or zeroed) it never crashes
  // (never a non-Error throw) and never resolves a WRONG record count; it either rejects with a clean Error or
  // opens with the correct count (some objects are optional to a metadata open, so a benign open is allowed).
  // The refuter below (a fully-zeroed archive MUST be rejected while the clean one opens) keeps this
  // non-vacuous. This is the TS reader; the Go FuzzReaderOpen covers only the Go side.
  const MALFORM_RUNS = 50 * SCALE;
  await fc.assert(
    fc.asyncProperty(recordsArb, fc.nat(), fc.constantFrom("remove", "truncate", "zero"), async (records, objSel, how) => {
      const { map, bgIdentity, signer } = await sealToDir(records);
      const identity = parseIdentity(bgIdentity);
      const verifier = verifierFrom(signer);
      const clean = await openRun(new MapStore(new Map(map)), RUN_ID, identity, verifier, { verifyFreshness: false });
      if (clean.records.length !== records.length) throw new Error(`clean archive opened with ${clean.records.length} records, expected ${records.length}`);
      const keys = [...map.keys()];
      const key = keys[objSel % keys.length]!;
      const orig = map.get(key)!;
      const broken = new Map(map);
      if (how === "remove") broken.delete(key);
      else if (how === "truncate") broken.set(key, orig.subarray(0, Math.floor(orig.length / 2)));
      else broken.set(key, new Uint8Array(orig.length));
      try {
        const run = await openRun(new MapStore(broken), RUN_ID, identity, verifier, { verifyFreshness: false });
        if (run.records.length !== records.length) throw new Error(`SILENT WRONG-COUNT: openRun opened a ${how}-broken archive (${key}) with ${run.records.length} records, expected ${records.length}`);
      } catch (e) {
        if (!(e instanceof Error)) throw new Error(`openRun threw a non-Error (crash) on ${how} of ${key}`);
      }
    }),
    { numRuns: MALFORM_RUNS, verbose: false },
  );
  // Cell D refuter (default-FAIL): openRun MUST reject a fully-zeroed archive while opening the clean one, so
  // the total-parser property is not vacuous (openRun genuinely distinguishes a valid archive from garbage).
  {
    const { map, bgIdentity, signer } = await sealToDir([{ sourceType: "kv", name: "d-refuter", value: rand(48) }]);
    const identity = parseIdentity(bgIdentity);
    const verifier = verifierFrom(signer);
    const clean = await openRun(new MapStore(new Map(map)), RUN_ID, identity, verifier, { verifyFreshness: false });
    if (clean.records.length !== 1) throw new Error(`Cell D refuter: clean archive should open with 1 record, got ${clean.records.length}`);
    const zeroed = new Map<string, Uint8Array>();
    for (const [k, v] of map) zeroed.set(k, new Uint8Array(v.length));
    let rejected = false;
    try {
      await openRun(new MapStore(zeroed), RUN_ID, identity, verifier, { verifyFreshness: false });
    } catch {
      rejected = true;
    }
    if (!rejected) throw new Error("REFUTER FAILED: openRun accepted a fully-zeroed archive as valid");
    assertions++;
  }
  assertions += MALFORM_RUNS;
  console.log(`Cell D cleared: ${MALFORM_RUNS} malformed archives handled with no crash and no wrong-count; garbage archive rejected, clean opened`);
  // NOTE (cross-reader rejection differential): a "both readers
  // must agree to accept-or-reject a malformed archive" property does NOT hold and is NOT a bug. Over fuzzed
  // remove/truncate/zero/bitflip malformations the two INDEPENDENT readers legitimately differ in ROBUSTNESS --
  // one tolerates a missing NON-ESSENTIAL object the other requires. It is not a data-integrity divergence: each
  // reader verifies both the record data (AEAD/hash) and the declared record COUNT before accepting (Cell B for
  // Go, Cell D for TS), so neither ever silently recovers wrong data or a wrong count. The security-critical
  // cross-reader property -- agreement on CLEAN archives -- is proven by Cell E (buffered) + the sliced B2.

  // Cell G (adversarial / crafted-hostile archive, the negative property): a reader must REFUSE STRUCTURALLY
  // crafted attacks, not just the random byte flips of Cell B. Three crafted archives -- one signed by a
  // different signer than the reader is told to expect, one with a truncated segment, one with two segments'
  // contents swapped -- must each be refused by BOTH the Go offline reader and the TS reader. Default-FAIL:
  // every branch throws unless the reader refused.
  {
    const advRecs: WriteRecord[] = Array.from({ length: 6 }, (_, i) => ({ sourceType: "kv", name: `adv/${i}`, value: rand(64 + i * 40) }));
    let advChecks = 0;
    const goRefuses = (dir: string, idFile: string, sgFile: string): boolean => runReader(bin, restoreDiscardArgs(dir, RUN_ID, idFile, sgFile)).exitCode !== 0;
    const tsRefuses = async (map: Map<string, Uint8Array>, identity: Uint8Array, verifier: ReturnType<typeof verifierFrom>): Promise<boolean> => {
      try {
        const run = await openRun(new MapStore(map), RUN_ID, parseIdentity(identity), verifier, {});
        for (const r of run.records) await run.restoreRecord(r);
        return false;
      } catch {
        return true;
      }
    };

    // G1: WRONG SIGNER. The archive is self-consistent but signed by its own signer; hand the readers a
    // DIFFERENT signer's public. A valid-looking archive from the wrong key must be rejected (the recipient
    // pins the expected signer out of band; this is what stops a forged-provenance archive being trusted).
    {
      const s = await sealToDir(advRecs);
      const other = await makeSigner();
      const paths = writeArchiveDir(newTmp(), s.map, b64urlEncode(s.bgIdentity), b64urlEncode(other.signerPub));
      if (!goRefuses(paths.archiveDir, paths.identityFile, paths.signerFile)) throw new Error("Cell G1: the Go reader ACCEPTED an archive under the WRONG signer public");
      if (!(await tsRefuses(s.map, s.bgIdentity, verifierFrom(other.signer)))) throw new Error("Cell G1: the TS reader ACCEPTED an archive under the WRONG signer verifier");
      advChecks++;
    }

    // G2: TRUNCATED SEGMENT. Cut bytes off the largest object; the reader must refuse, never partial-recover.
    {
      const s = await sealToDir(advRecs);
      const correctPub = b64urlEncode(concat(s.signer.edPublic, s.signer.mldsaPublic));
      let bigKey = "";
      let bigLen = -1;
      for (const [k, v] of s.map) if (v.length > bigLen) { bigLen = v.length; bigKey = k; }
      const m = new Map(s.map);
      m.set(bigKey, s.map.get(bigKey)!.slice(0, Math.max(1, bigLen - 8)));
      const paths = writeArchiveDir(newTmp(), m, b64urlEncode(s.bgIdentity), correctPub);
      if (!goRefuses(paths.archiveDir, paths.identityFile, paths.signerFile)) throw new Error("Cell G2: the Go reader ACCEPTED a TRUNCATED-segment archive");
      if (!(await tsRefuses(m, s.bgIdentity, verifierFrom(s.signer)))) throw new Error("Cell G2: the TS reader ACCEPTED a TRUNCATED-segment archive");
      advChecks++;
    }

    // G3: SWAPPED SEGMENTS. Put the two largest objects' contents under each other's keys; the content-address
    // + hash binding must reject the confusion (a reader must not accept an object served under the wrong key).
    {
      const s = await sealToDir(advRecs);
      const correctPub = b64urlEncode(concat(s.signer.edPublic, s.signer.mldsaPublic));
      const entries = [...s.map.entries()].sort((a, b) => b[1].length - a[1].length);
      const m = new Map(s.map);
      m.set(entries[0]![0], entries[1]![1]);
      m.set(entries[1]![0], entries[0]![1]);
      const paths = writeArchiveDir(newTmp(), m, b64urlEncode(s.bgIdentity), correctPub);
      if (!goRefuses(paths.archiveDir, paths.identityFile, paths.signerFile)) throw new Error("Cell G3: the Go reader ACCEPTED a SWAPPED-segment archive");
      if (!(await tsRefuses(m, s.bgIdentity, verifierFrom(s.signer)))) throw new Error("Cell G3: the TS reader ACCEPTED a SWAPPED-segment archive");
      advChecks++;
    }

    assertions += advChecks;
    console.log(`Cell G cleared: ${advChecks} crafted-hostile archive attacks (wrong signer, truncated segment, swapped segments) refused by BOTH readers`);
  }

  console.log(`\nfuzzing Tier 1 OK: ${assertions} assertions, net-zero, refuters cleared.`);
  // Pass the count, because this validator reports per CELL rather than per assertion. The guard counts
  // printed assertion lines and this run prints none, so without the count it correctly refuses a verdict
  // it cannot corroborate: a validator that asserted nothing did not pass, it abstained. The number is the
  // same one the line above prints, so the claim and the evidence cannot drift apart.
  verdictReached(0, assertions);
  process.exit(0);
}

main().catch((e) => {
  console.error(`fuzzing Tier 1 FAILED: ${e instanceof Error ? e.message : String(e)}`);
  // fast-check reports the counterexample and the seed, but the underlying throw arrives as a cause and
  // is otherwise dropped, which leaves a failure report saying WHICH input failed and not HOW. Print it.
  for (let cause = (e as { cause?: unknown }).cause; cause; cause = (cause as { cause?: unknown }).cause) {
    console.error(`  caused by: ${cause instanceof Error ? `${cause.message}\n${cause.stack ?? ""}` : String(cause)}`);
  }
  process.exit(1);
});
