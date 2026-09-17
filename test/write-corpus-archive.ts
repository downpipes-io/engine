// Seals a REAL downpipe/0.1.0 archive with the engine's production TypeScript writer (buildArchive,
// writer.ts:194 -- the reference seal path the run pipeline drives) into <argv[2]>/archive, alongside a
// harness-minted break-glass identity, a DIFFERENT never-sealed-to break-glass identity, the operator
// signer public key, and an INDEPENDENT oracle sidecar (oracle.json). This is the seal half of an offline
// cold-restore round-trip check: the harness generates the fake source plaintext, hashes it with node
// crypto SHA-384 BEFORE the seal, and records the raw bytes, so the driver can compare the offline Go
// reader's recovered bytes DIRECTLY to the seeded bytes, an oracle independent of every hash the engine
// and the reader compute.
//
// It is a sibling of write-archive.ts: same in-process buildArchive to a MemoryDestination, same
// downpipe-identity-v1 / downpipe-signer-public-v1 key files, but with the record classes, the wrong-key
// fixture, and the oracle sidecar this corpus test needs. NET-ZERO: fake data, a harness-minted key
// (never a customer key), an ephemeral out dir; no estate, bucket, network, seed or spend.
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { x25519 } from "@noble/curves/ed25519.js";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { identityFingerprint, recipientFingerprint } from "../src/crypto/capsule.ts";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import type { ChunkSource } from "../src/crypto/streamseal.ts";
import { buildArchive, type RecipientEntry, type Signer, type WriteRecord } from "../src/format/writer.ts";
import { MemoryDestination } from "./memdest.ts";

const outDirArg = process.argv[2];
if (!outDirArg) throw new Error("usage: node test/write-corpus-archive.ts <outdir>");
// Bind as a definite string: the throw-guard narrows outDirArg here, but that narrowing does not flow into
// the nested closures below, so capture it in a typed const (the same idiom write-archive.ts uses).
const outDir: string = outDirArg;

// A fixed valid ULID for the run id. The seal is per-run NON-deterministic regardless (fresh 32-byte master,
// fresh ML-KEM encapsulation, hedged ML-DSA signature), so this fixes only the object-key namespace.
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// A deterministic multi-chunk value (spans several STREAM chunks) for the streamed r2 record, so its
// plaintext is known to the oracle before the seal even though the seal path never buffers it whole.
function largeValue(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 131 + 17) & 0xff;
  return b;
}

// chunkedSource exposes an in-memory value as a re-openable ChunkSource (stands in for an R2 object's
// streamed body), to exercise the production streaming seal path.
function chunkedSource(value: Uint8Array): ChunkSource {
  return {
    async *chunks() {
      for (let i = 0; i < value.length; i += 9000) yield value.subarray(i, Math.min(i + 9000, value.length));
    },
  };
}

// sha384Node is the INDEPENDENT oracle hash: node's own crypto (createHash), never the engine's sha384 or the
// Go reader's, so a shared crypto bug in both ports cannot hide from the byte oracle.
function sha384Node(bytes: Uint8Array): string {
  return createHash("sha384").update(Buffer.from(bytes)).digest("hex");
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

interface Recipient {
  entry: RecipientEntry;
  identity: Uint8Array; // downpipe-identity-v1 body: x25519 scalar(32) || ML-KEM seed(64)
  x25519Scalar: Uint8Array;
  mlkemSeed: Uint8Array;
}

function makeRecipient(role: string): Recipient {
  const xk = x25519.keygen();
  const seed = rand(64);
  const ek = mlkemKeygen(seed).encapKey;
  return {
    entry: { role, pub: { x25519: xk.publicKey, mlkemEk: ek } },
    identity: concat(xk.secretKey, seed),
    x25519Scalar: xk.secretKey,
    mlkemSeed: seed,
  };
}

// klass drives how the check grades a record: "direct" records (kv/r2/secrets) are byte-compared against the
// recovered file; "d1" is asserted via its .sql transcode path; "reprovision" (cf-config/workers/...) is
// asserted via the discard-sink verify plus the reprovision classification.
type RecordClass = "direct" | "d1" | "reprovision";

interface OracleRecord {
  index: number;
  sourceType: string;
  name: string;
  outKey: string; // the file the Go reader's file sink writes for this record (safeKey; d1 gets .sql)
  klass: RecordClass;
  sizeBytes: number;
  sha384: string; // node-crypto SHA-384 of the seeded plaintext, BEFORE the seal
  plaintextB64: string; // the seeded plaintext itself, so the oracle compares raw bytes directly
}

async function main(): Promise<void> {
  const breakGlass = makeRecipient("break-glass");
  const operational = makeRecipient("operational");
  // A DIFFERENT, freshly-minted break-glass identity the archive is NEVER sealed to: the wrong-key
  // refuter restores with this and must fail closed at the master unwrap ("no wrap matches the held identity").
  const wrong = makeRecipient("break-glass");

  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };

  // The corpus: known fake plaintext per record, spanning the direct-write classes (kv, r2, secrets) plus a
  // d1 record (its own .sql transcode path) plus a cf-config reprovision record (workers/cf-config class).
  const D1_UUID = "4f9a2c1e-7b3d-4e82-9f10-6a5b8c3d2e91"; // a D1 native UUID (self-identifying, SPEC 6.2)
  const ACCOUNT = "acct-axis3-cold-restore-4f3c2a1b"; // the Cloudflare account the backup is OF
  const kv1 = utf8("engine sealed this kv value; the offline Go reader recovers it with neither Cloudflare nor the vendor");
  const kv2 = utf8("a second kv record across the same shard, byte 0x00-0xff spread follows: \u0000þÿ");
  const r2small = utf8("an r2 object value backed up by the engine, recovered offline to a byte-identical file");
  const r2large = largeValue(Number(process.env.CORPUS_LARGE_BYTES) || 200000); // STREAMED multi-chunk segment; the largest, so tamper testing targets it. CORPUS_LARGE_BYTES env override lets a Tier-2 large-run size it past the 64 MiB verify-at-seal sampled tier; default unchanged.
  const secretVal = utf8("test-fixture-api-token-for-offline-cold-restore-only");
  const d1val = utf8(process.env.D1_CORPUS_SQL || "a D1 table dump backed up by the engine, self-identifying its own database and account"); // D1_CORPUS_SQL override lets the Tier-2 D1-apply drive seal a raw-SQL d1 record (written verbatim to .sql on restore, per d1transcode.go); default unchanged.
  const cfval = utf8('{"zone":"example.com","settings":{"ssl":"strict","min_tls":"1.2"},"note":"cf-config reprovision record"}');

  const records: WriteRecord[] = [
    { sourceType: "kv", name: "greeting", value: kv1 },
    { sourceType: "kv", name: "second", value: kv2 },
    { sourceType: "r2", name: "uploads/report.txt", value: r2small, bucket: "media" },
    { sourceType: "r2", name: "uploads/large.bin", bucket: "media", stream: { size: r2large.length, open: () => chunkedSource(r2large) } },
    { sourceType: "secrets", name: "API_TOKEN", value: secretVal },
    { sourceType: "d1", name: "appdb/00-header", value: d1val, database: D1_UUID, account: ACCOUNT },
    { sourceType: "cf-config", name: "cfzone-settings", value: cfval, account: ACCOUNT },
  ];

  // The oracle's per-record ground truth, computed from the SEEDED plaintext BEFORE the seal. outKey mirrors
  // the reader's DirTarget.safeKey (these names are chosen to map identically) plus the d1 .sql suffix; an
  // outKey error can only fail loudly (a missing file), never launder a wrong plaintext.
  const oracleRecords: OracleRecord[] = [
    { index: 0, sourceType: "kv", name: "greeting", outKey: "greeting", klass: "direct", ...digest(kv1) },
    { index: 1, sourceType: "kv", name: "second", outKey: "second", klass: "direct", ...digest(kv2) },
    { index: 2, sourceType: "r2", name: "uploads/report.txt", outKey: "uploads/report.txt", klass: "direct", ...digest(r2small) },
    { index: 3, sourceType: "r2", name: "uploads/large.bin", outKey: "uploads/large.bin", klass: "direct", ...digest(r2large) },
    { index: 4, sourceType: "secrets", name: "API_TOKEN", outKey: "API_TOKEN", klass: "direct", ...digest(secretVal) },
    { index: 5, sourceType: "d1", name: "appdb/00-header", outKey: "appdb/00-header.sql", klass: "d1", ...digest(d1val) },
    { index: 6, sourceType: "cf-config", name: "cfzone-settings", outKey: "cfzone-settings", klass: "reprovision", ...digest(cfval) },
  ];

  const mem = new MemoryDestination(); // the streamed r2 segment lands here
  const archive = await buildArchive(
    {
      downpipeId: "dp_axis3_cold_restore",
      downpipeName: "axis3-cold-restore",
      cadence: "0 * * * *",
      runId: RUN_ID,
      master: rand(32),
      recipients: [breakGlass.entry, operational.entry], // break-glass first (loadRecipients contract)
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

  // Merge the returned map (manifest + buffered segments) with the streamed segment in mem, then flush the
  // whole object map to disk in the Go reader's DirStore layout.
  for (const [key, bytes] of archive) await mem.put(key, bytes);
  for (const [key, bytes] of mem.entries()) {
    const path = join(outDir, "archive", key);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, bytes);
  }

  await writeFile(join(outDir, "identity.key"), `downpipe-identity-v1 ${b64urlEncode(breakGlass.identity)}\n`);
  await writeFile(join(outDir, "wrong-identity.key"), `downpipe-identity-v1 ${b64urlEncode(wrong.identity)}\n`);
  await writeFile(join(outDir, "signer.pub"), `downpipe-signer-public-v1 ${b64urlEncode(concat(edPublic, mldsa.publicKey))}\n`);

  // The break-glass recipient fingerprint the manifest carries (from the public), and the fingerprint derived
  // from the HELD private identity. They must be equal by construction (the public is derived from the
  // private); this check re-verifies the manifest fingerprint the Go reader reads against the held one before it
  // trusts the restore (residual-risk control: the seal must wrap to a key the harness actually holds).
  const breakGlassRecipientFingerprint = await recipientFingerprint(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk);
  const heldIdentityFingerprint = await identityFingerprint({ x25519Scalar: breakGlass.x25519Scalar, mlkemSeed: breakGlass.mlkemSeed });
  if (breakGlassRecipientFingerprint !== heldIdentityFingerprint) {
    throw new Error(`seal self-check failed: break-glass recipient fingerprint ${breakGlassRecipientFingerprint} != held identity fingerprint ${heldIdentityFingerprint}`);
  }
  const wrongIdentityFingerprint = await identityFingerprint({ x25519Scalar: wrong.x25519Scalar, mlkemSeed: wrong.mlkemSeed });

  const oracle = {
    runId: RUN_ID,
    formatVersion: "downpipe/0.1.0",
    declaredRecordCount: records.length,
    breakGlassRecipientFingerprint,
    heldIdentityFingerprint,
    wrongIdentityFingerprint,
    directWriteOutKeys: oracleRecords.filter((r) => r.klass === "direct").map((r) => r.outKey),
    allExpectedOutKeys: oracleRecords.map((r) => r.outKey),
    records: oracleRecords,
  };
  await writeFile(join(outDir, "oracle.json"), `${JSON.stringify(oracle, null, 2)}\n`);
  console.log(`wrote corpus archive + oracle to ${outDir} (run ${RUN_ID}, ${records.length} record(s))`);
}

// digest bundles a record's independent oracle facts (size, node-crypto SHA-384, raw bytes) so each
// oracleRecords entry stays a single readable literal.
function digest(value: Uint8Array): { sizeBytes: number; sha384: string; plaintextB64: string } {
  return { sizeBytes: value.length, sha384: sha384Node(value), plaintextB64: b64(value) };
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
