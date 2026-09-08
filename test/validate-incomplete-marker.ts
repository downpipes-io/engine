// Prove that an incompleteness-marker record is STAMPED with its marker KIND
// in the signed shard manifest, so the offline restore can treat a sentinel record as the marker it is
// (never re-materialising the sentinel bytes as real data) WITHOUT decrypting its value -- while a normal
// record stays BYTE-IDENTICAL to before (no incompleteMarker key), and every existing archive is unaffected.
//
// What this validator proves:
//   1. buildRecordLine (the single byte-determining shard-line builder both seal paths share) stamps
//      `incompleteMarker:"<kind>"` ONLY when the record is a marker; a normal record's line carries no such
//      key. The Merkle-leaf recordHash is IDENTICAL with and without the field (it is a manifest annotation,
//      not folded into the leaf), so the field never perturbs the merkleRoot -- only the shard SHA-384 (which
//      the signed root also pins), so it is signed + tamper-evident.
//   2. Round trip: buildArchive seals a marker record + a normal record, the TS reader OPENS the run (so the
//      root signature, the shard hash and every record hash verify) and the marker record's ShardRecord
//      carries incompleteMarker === the kind while the normal record's is absent; the sealed value still
//      restores byte-correct.
//   3. Byte contract: the decrypted shard manifest line carries the EXACT key `incompleteMarker` (the Go
//      reader contract) on the marker record and NO such key on the normal one.
//   4. Backward compat: an archive whose records set NO incompleteMarker has NO incompleteMarker key on any
//      decrypted line -- byte-identical to an archive sealed before this field existed.
//
// Run: node test/validate-incomplete-marker.ts
// In-memory doubles only; no network, no deploy, no cost.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, buildRecordLine, singleSegment, type RecipientEntry, type Signer, type WriteRecord, type RecordMeta, type RecordSealResult } from "../src/format/writer.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { deriveMK, deriveManifestWrapKey } from "../src/crypto/derive.ts";
import { decodeULID } from "../src/format/ulid.ts";
import { openStream } from "../src/crypto/stream.ts";
import { unframeDpe } from "../src/format/container.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { b64urlEncode, concat, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { MARKER_KEYS } from "../src/seal/marker.ts";
import { runBackup, type RunConfig, type RunClock } from "../src/seal/pipeline.ts";
import type { SourceAdapter, SourceRecord } from "../src/sources/types.ts";
import { MemoryDestination } from "./memdest.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_marker";
const KIND = "_unavailable"; // one of MARKER_KEYS
const MARKER_VALUE = utf8(JSON.stringify({ _unavailable: "the token could not read this surface" }));

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

class MapStore implements ObjectStore {
  private map: Map<string, Uint8Array>;
  constructor(map: Map<string, Uint8Array>) {
    this.map = map;
  }
  async get(key: string): Promise<Uint8Array> {
    const v = this.map.get(key);
    if (!v) throw new Error(`object not found: ${key}`);
    return v;
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix));
  }
}

// decryptShardLines opens the sealed shard manifest and returns its decoded record lines, so a test can
// assert exactly which fields each line carries (e.g. whether incompleteMarker is present).
async function decryptShardLines(map: Map<string, Uint8Array>, master: Uint8Array): Promise<Record<string, unknown>[]> {
  const runIDBytes = decodeULID(RUN_ID);
  const mk = await deriveMK(master, runIDBytes);
  const wrapKey = await deriveManifestWrapKey(mk, runIDBytes, "00000");
  const sealed = map.get(`run/${RUN_ID}/manifest/00000.dpe`)!;
  const plain = await openStream(wrapKey, unframeDpe(sealed));
  return new TextDecoder().decode(plain).split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l) as Record<string, unknown>).filter((o) => o["kind"] === "record");
}

async function main(): Promise<void> {
  ok("precondition: KIND is a real MARKER_KEYS member", (MARKER_KEYS as readonly string[]).includes(KIND));

  // ---- PART 1: buildRecordLine stamps the field ONLY on a marker; the leaf is unchanged --------------------
  console.log("marker-part-1: buildRecordLine stamps incompleteMarker only on a marker (leaf unchanged)");
  {
    const nameKey = rand(32);
    const seal: RecordSealResult = { segments: singleSegment(`seg/aa/deadbeef.seg`, 5), plaintextSha384: hexEncode(await sha384(utf8("hello"))), size: 5 };
    const baseMeta: RecordMeta = { sourceType: "kv", name: "k1", namespace: NS };

    const normal = await buildRecordLine(nameKey, "r0000", baseMeta, seal);
    const marker = await buildRecordLine(nameKey, "r0000", { ...baseMeta, incompleteMarker: KIND }, seal);

    ok("part1: a normal record line has NO incompleteMarker key", !("incompleteMarker" in normal.line));
    ok("part1: a marker record line carries incompleteMarker with the kind", marker.line.incompleteMarker === KIND);
    // The Merkle-leaf recordHash binds (recordId, plaintextSha384, keyNameHash, size) -- NOT incompleteMarker.
    // So a marker and a non-marker record with the SAME id/value/name hash to the SAME leaf: the field cannot
    // perturb the merkleRoot, only the shard SHA-384 (which the signed root also pins).
    ok("part1: the Merkle-leaf recordHash is IDENTICAL with and without the marker field (leaf excludes it)", eqBytes(normal.recordHash, marker.recordHash));
    // An empty-string marker kind is treated as absent (the `if (r.incompleteMarker)` guard), so it never
    // stamps a meaningless empty key.
    const emptyMarker = await buildRecordLine(nameKey, "r0000", { ...baseMeta, incompleteMarker: "" }, seal);
    ok("part1: an empty-string marker kind does not stamp the key", !("incompleteMarker" in emptyMarker.line));
  }

  // ---- shared archive setup -----------------------------------------------------------------------------
  const signerSeed = rand(64);
  const signer: Signer = await loadSigner(b64urlEncode(signerSeed));
  const verifier = verifierFrom(signer);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");

  // Two records: a MARKER (its value is a sentinel; incompleteMarker set, as pipeline.ts/slice.ts compute) and
  // a NORMAL data record (no incompleteMarker). Sorted by name so the shard order is deterministic.
  const markerName = "a-missing-surface";
  const normalName = "b-real-value";
  const NORMAL_VALUE = utf8("the real captured bytes");
  const records: WriteRecord[] = [
    { sourceType: "kv", name: markerName, value: MARKER_VALUE, namespace: NS, incompleteMarker: KIND },
    { sourceType: "kv", name: normalName, value: NORMAL_VALUE, namespace: NS },
  ];
  const master = rand(32);
  const archive = await buildArchive({
    downpipeId: "dp_marker", downpipeName: "marker-test", cadence: "3600s", runId: RUN_ID, master,
    recipients: [breakGlass.entry, op.entry], signer, records,
    windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
  });

  // ---- PART 2: round trip through the verifying reader ---------------------------------------------------
  console.log("marker-part-2: the marker kind round-trips on the ShardRecord and the archive verifies");
  {
    const store = new MapStore(archive);
    // openRun verifies the root signature, the shard SHA-384 and every record hash; it succeeding proves the
    // incompleteMarker field is covered by (does not break) the signed structure.
    const run = await openRun(store, RUN_ID, parseIdentity(op.identity), verifier, { verifyFreshness: false });
    ok("part2: the archive opens + verifies with the marker field present (signed/tamper-evident)", run.records.length === 2);
    const markerRec = run.records.find((r) => r.name === markerName);
    const normalRec = run.records.find((r) => r.name === normalName);
    ok("part2: the marker record carries incompleteMarker === the kind", markerRec?.incompleteMarker === KIND);
    ok("part2: the normal record has NO incompleteMarker (undefined)", normalRec !== undefined && normalRec.incompleteMarker === undefined);
    // The sealed value still restores byte-correct (the marker's VALUE is the sentinel bytes; the field is a
    // separate manifest annotation, so the value is unchanged).
    const restored = await run.restoreRecord(markerRec!);
    ok("part2: the marker record's value restores byte-correct (the sentinel bytes)", eqBytes(restored, MARKER_VALUE));
  }

  // ---- PART 3: the exact wire key on the decrypted shard line --------------------------------------------
  console.log("marker-part-3: the decrypted shard line carries the exact `incompleteMarker` key (Go contract)");
  {
    const lines = await decryptShardLines(archive, master);
    const markerLine = lines.find((l) => l["name"] === markerName)!;
    const normalLine = lines.find((l) => l["name"] === normalName)!;
    ok("part3: the marker line carries the exact key 'incompleteMarker' with the kind (string)", markerLine["incompleteMarker"] === KIND && typeof markerLine["incompleteMarker"] === "string");
    ok("part3: the normal line has NO 'incompleteMarker' key (byte-identical to before)", !("incompleteMarker" in normalLine));
  }

  // ---- PART 4: backward compat -- no field when no record is a marker ------------------------------------
  console.log("marker-part-4: an archive with no markers carries no incompleteMarker key on any line");
  {
    const cleanRecords: WriteRecord[] = [
      { sourceType: "kv", name: markerName, value: MARKER_VALUE, namespace: NS }, // same value, but NOT flagged
      { sourceType: "kv", name: normalName, value: NORMAL_VALUE, namespace: NS },
    ];
    const cleanMaster = rand(32);
    const cleanArchive = await buildArchive({
      downpipeId: "dp_marker", downpipeName: "marker-test", cadence: "3600s", runId: RUN_ID, master: cleanMaster,
      recipients: [breakGlass.entry, op.entry], signer, records: cleanRecords,
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    const lines = await decryptShardLines(cleanArchive, cleanMaster);
    ok("part4: NO decrypted line carries an incompleteMarker key when no record is flagged", lines.every((l) => !("incompleteMarker" in l)));
  }

  // ---- PART 5: the SEAL PIPELINE stamps incompleteMarker ONLY from the source adapter's OWN
  // markerKind assertion on the SourceRecord, never by re-parsing the record's value bytes. PART 1-4 above
  // prove the WRITER (buildArchive/buildRecordLine) is content-blind given an already-decided WriteRecord;
  // this proves the derivation UPSTREAM of that, in runBackup (seal/pipeline.ts), which is where the
  // finding's collision actually lived: two records here carry the IDENTICAL marker-shaped top-level key
  // ("_pending"), and only the adapter's OWN markerKind on the first says it is a sentinel. -----------------
  console.log("marker-part-5: runBackup stamps incompleteMarker from the adapter's markerKind, not the value's shape");
  {
    const GENUINE_NAME = "genuine-marker";
    const LOOKALIKE_NAME = "real-lookalike";
    const GENUINE_VALUE = utf8(JSON.stringify({ _pending: "download inprogress" }));
    // A real customer value that merely LOOKS marker-shaped (same "_pending" top-level key); no adapter ever
    // asserts markerKind for it, exactly the collision this closes.
    const LOOKALIKE_VALUE = utf8(JSON.stringify({ _pending: false, orderId: 42 }));

    class FakeMarkerSource implements SourceAdapter {
      readonly sourceType = "kv" as const;
      async *crawl(): AsyncIterable<SourceRecord> {
        yield { sourceType: "kv", name: GENUINE_NAME, value: GENUINE_VALUE, namespace: NS, markerKind: "_pending" };
        yield { sourceType: "kv", name: LOOKALIKE_NAME, value: LOOKALIKE_VALUE, namespace: NS };
      }
      async estimate(): Promise<{ records: number; bytes: number }> {
        return { records: 2, bytes: -1 };
      }
    }

    const dest = new MemoryDestination();
    const cfg: RunConfig = { downpipeId: "dp_marker", downpipeName: "marker-test", cadence: "3600s", selector: { include: [], exclude: [] }, recipients: [breakGlass.entry, op.entry] };
    const partMaster = rand(32);
    await runBackup([new FakeMarkerSource()], cfg, signer, dest, {
      runId: RUN_ID, runlogIndex: 1, prevRunId: null, now: "2026-06-07T00:00:01.000Z",
      master: partMaster, randomNonce: () => rand(16), randomSalt: () => rand(16),
    } as RunClock);

    const lines = await decryptShardLines(dest.entries(), partMaster);
    const genuineLine = lines.find((l) => l["name"] === GENUINE_NAME)!;
    const lookalikeLine = lines.find((l) => l["name"] === LOOKALIKE_NAME)!;
    ok("part5: the adapter-asserted marker IS stamped incompleteMarker on the shard line", genuineLine["incompleteMarker"] === "_pending");
    ok("part5: the un-asserted lookalike (identical shape) carries NO incompleteMarker", !("incompleteMarker" in lookalikeLine));
  }

  console.log(failures === 0 ? "\nALL INCOMPLETE-MARKER VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
