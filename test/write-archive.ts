// Write a downpipe/0.1.0 archive with the engine's TypeScript writer into the directory
// given as argv[2], plus the break-glass identity and signer public key in the Go CLI's
// labelled format. A companion shell step then runs the Go `downpipe restore` against it,
// proving the production-direction interop: engine writes, the offline Go tool recovers.

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import type { ChunkSource } from "../src/crypto/streamseal.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { D1Source } from "../src/sources/d1.ts";
import type { SourceRecord } from "../src/sources/types.ts";
import { MemoryDestination } from "./memdest.ts";
import { SqliteD1 } from "./lib/sqlite-d1.ts";

// chunkedSource exposes an in-memory value as a re-openable ChunkSource (stands in for an
// R2 object's streamed body), to exercise the streaming seal path.
function chunkedSource(value: Uint8Array): ChunkSource {
  return {
    async *chunks() {
      for (let i = 0; i < value.length; i += 9000) yield value.subarray(i, Math.min(i + 9000, value.length));
    },
  };
}

const outDirArg = process.argv[2];
if (!outDirArg) throw new Error("usage: node test/write-archive.ts <outdir>");
// Bind as a definite string: the throw-guard narrows outDirArg here, but that narrowing does not flow into
// the nested function bodies below where outDir is used, so capture the narrowed value in a typed const.
const outDir: string = outDirArg;
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// A deterministic multi-chunk value (spans several 64 KiB STREAM chunks).
function largeValue(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 131 + 17) & 0xff;
  return b;
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  const ek = mlkemKeygen(seed).encapKey;
  return {
    entry: { role, pub: { x25519: xk.publicKey, mlkemEk: ek } },
    identity: concat(xk.secretKey, seed), // x25519 scalar(32) || ML-KEM seed(64)
  };
}

// BLOB_DB is the D1 binding name of the every-byte table below. scripts/e2e-writer-reader.sh reads the Go
// reader's restored SQL for it by this name.
const BLOB_DB = "blobdb";

// crawlEveryByteD1 crawls a real SQLite table through the engine's own D1Source, so the records sealed below
// are the ones a production run writes, not a hand-built body. Row 1 holds one BLOB of the 256 byte values
// 0x00 to 0xFF in order, and row 2 holds the 32 bytes 0x80 to 0x9F. Before 0.3.7 the BLOB encoder built
// btoa's input with TextDecoder("latin1"), which is windows-1252 under the WHATWG Encoding standard, so this
// crawl threw and no archive was written. The e2e script then proves the Go reader restores both BLOBs to
// exactly these bytes.
async function crawlEveryByteD1(): Promise<SourceRecord[]> {
  const d1 = new SqliteD1();
  d1.db.exec('CREATE TABLE "blobs" (id INTEGER PRIMARY KEY, b BLOB)');
  const all = new Uint8Array(256);
  for (let i = 0; i < 256; i++) all[i] = i;
  const ins = d1.db.prepare('INSERT INTO "blobs" VALUES (?, ?)');
  ins.run(1n, all);
  ins.run(2n, all.subarray(0x80, 0xa0));
  const out: SourceRecord[] = [];
  for await (const ev of new D1Source(d1 as unknown as D1Database, BLOB_DB).crawlFrom({ include: [], exclude: [] }, null)) {
    if (ev.kind === "record") out.push(ev.record);
  }
  if (out.length === 0) throw new Error("the every-byte D1 crawl produced no records");
  return out;
}

async function main(): Promise<void> {
  const blobRecords = await crawlEveryByteD1();
  const breakGlass = makeRecipient("break-glass");
  const operational = makeRecipient("operational");

  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };

  const mem = new MemoryDestination(); // streamed segments land here
  const archive = await buildArchive({
    downpipeId: "dp_engine",
    downpipeName: "engine-roundtrip",
    cadence: "0 * * * *",
    runId: RUN_ID,
    master: rand(32),
    recipients: [breakGlass.entry, operational.entry],
    signer,
    records: [
      { sourceType: "kv", name: "greeting", value: utf8("engine wrote this, the Go tool recovers it without the vendor") },
      { sourceType: "kv", name: "second", value: utf8("a second record across the same shard") },
      { sourceType: "r2", name: "uploads/report.txt", value: utf8("an r2 object value backed up by the engine"), bucket: "media" },
      { sourceType: "r2", name: "uploads/large.bin", bucket: "media", stream: { size: 200000, open: () => chunkedSource(largeValue(200000)) } }, // STREAMED multi-chunk segment
      // A self-identifying record: carries BOTH `database` (D1's
      // native UUID) and `account` (the Cloudflare account the backup is OF), exactly as the buffered seal
      // path (writer.ts makeLine) and the sliced path (slice.ts metaFor) both stamp them onto the manifest
      // line. scripts/e2e-writer-reader.sh's `inspect` step greps the Go reader's OWN printed output for
      // both fields, so this is the one cross-repo proof that the engine WRITES them and the independent
      // reader READS them, not just that the engine's own tests believe it wrote them.
      {
        sourceType: "d1",
        name: "appdb/00-header",
        value: utf8("a D1 table backed up by the engine, self-identifying its own database and account"),
        database: "4f9a2c1e-7b3d-4e82-9f10-6a5b8c3d2e91", // a D1 native UUID (self-identifying, SPEC 6.2)
        account: "acct-e2e-writer-reader-4f3c2a1b", // the Cloudflare account this backup is OF
      },
      { sourceType: "secrets", name: "API_TOKEN", value: utf8("test-fixture-api-token-for-interop") },
      // The every-byte D1 table, as the engine's D1Source wrote it (header, rows page, schema).
      ...blobRecords.map((r) => ({ sourceType: "d1", name: r.name, value: r.value!, ...(r.descriptor ? { descriptor: r.descriptor } : {}) })),
    ],
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  }, { dest: mem });

  // The returned map holds the manifest + buffered segments; the streamed segment is in
  // mem. Merge and flush everything to disk for the Go cross-check.
  for (const [key, bytes] of archive) await mem.put(key, bytes);
  for (const [key, bytes] of mem.entries()) {
    const path = join(outDir, "archive", key);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, bytes);
  }
  await writeFile(join(outDir, "identity.key"), `downpipe-identity-v1 ${b64urlEncode(breakGlass.identity)}\n`);
  await writeFile(join(outDir, "signer.pub"), `downpipe-signer-public-v1 ${b64urlEncode(concat(edPublic, mldsa.publicKey))}\n`);
  console.log(`wrote engine archive + keys to ${outDir} (run ${RUN_ID})`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
