import { b64urlEncode, hexEncode, utf8 } from "../crypto/bytes.ts";
import { deriveCAK, deriveMK, deriveNameMACKey, deriveNonSecretFileKey, segID } from "../crypto/derive.ts";
import { sha384 } from "../crypto/primitives.ts";
import { sealNonSecretSegment, sealSecretsSegment } from "../crypto/segment.ts";
import { addressStream, type StreamingValue, sealSegmentToStream } from "../crypto/streamseal.ts";
import type { Destination } from "../dest/types.ts";
import type { RestoreDescriptor } from "../sources/types.ts";
import { addBundle } from "./bundle.ts";
import { noteDefaultedEmptyRecord, noteWriterRefusal } from "./integrity-fault-ledger.ts";
import { merkleRoot } from "./merkle.ts";
import { decodeULID } from "./ulid.ts";
import { ADDR_SECRETS, ADDR_SINGLE_NON_SECRET, CODEC_NONE } from "./version.ts";
import { buildRecordLine, type RecordMeta, type RecordSealResult, singleSegment } from "./writer-record.ts";
import { buildSignedRoot, type RecipientEntry, type Signer, sealShardManifest } from "./writer-root.ts";
import { type RunlogEntry, signRunlog, thisRunEntry } from "./writer-runlog.ts";

// The writer: turn records into a complete downpipe/0.1.0 archive the Go offline tool
// recovers. This is the reference seal path the engine's run pipeline drives; it reuses
// the same proven crypto as the reader, in the inverse direction.
//
// The cohesive helper groups live in sibling modules and are re-exported here so importers
// keep their existing "format/writer.ts" entry point: the record-line builder
// (writer-record.ts), the root and shard sealers (writer-root.ts), and the RUNLOG freshness
// anchor (writer-runlog.ts).

export type { RecordMeta, RecordSealResult, SegmentRef } from "./writer-record.ts";
export { buildRecordLine, chunkCount, segmentObjectKey, singleSegment } from "./writer-record.ts";
export type { RecipientEntry, RootSealParams, ShardSealParams, Signer } from "./writer-root.ts";
export { buildSignedRoot, sealShardManifest, signerFingerprint } from "./writer-root.ts";
export type { RunlogEntry } from "./writer-runlog.ts";
export { parseRunlog, signRunlog, thisRunEntry } from "./writer-runlog.ts";

/**
 * One record to write into an archive: its source type and name, either a buffered value (small
 * records, all secrets) or a re-openable stream (large non-secret values), the optional namespace
 * or bucket, and the optional per-source restore descriptor.
 */
export interface WriteRecord {
  sourceType: string; // "kv" | "r2" | "secrets" | "d1" | "cf-config" | "workers" | "stream" | "images" | "artifacts"
  name: string;
  value?: Uint8Array; // the buffered plaintext (small records); omit when streaming
  stream?: StreamingValue; // a re-openable large value (non-secret); streamed to the dest
  namespace?: string;
  bucket?: string;
  database?: string; // d1 native UUID (self-identifying); carried onto the manifest line like namespace/bucket
  account?: string; // the Cloudflare account an API-source backup is OF; carried onto the manifest line
  descriptor?: RestoreDescriptor; // the per-source restore metadata (SPEC 6.2, 12.3)
  // incompleteMarker (RV-CLI-MARKER): the marker KIND when this record's value is an incompleteness sentinel
  // (one of seal/marker.ts MARKER_KEYS), else absent. The buffered caller (pipeline.ts) already parses the
  // value to tally recordsIncomplete, so it passes the kind it computed and buildRecordLine stamps it without
  // a second parse; a streamed record is never a marker so it is absent there.
  incompleteMarker?: string;
}

/**
 * The full input to buildArchive: the downpipe identity and cadence, the run id and random
 * master, the recipients and signer, the records, the window and timestamps, the RUNLOG index and
 * previous run id, the optional accumulated RUNLOG, and the nonce and salt sources.
 */
export interface WriteParams {
  downpipeId: string;
  downpipeName: string;
  cadence: string;
  runId: string; // ULID
  master: Uint8Array; // 32 random
  recipients: RecipientEntry[]; // break-glass first
  signer: Signer;
  records: WriteRecord[];
  windowStart: string;
  windowEnd: string;
  createdAt: string;
  runlogIndex: number; // allocated by the scheduler DO, monotonic per account
  prevRunId: string | null; // the previous run of this downpipe, or null for the first
  runlog?: RunlogEntry[]; // the full append-only RUNLOG to write; omit for a single-run log
  skipRunlog?: boolean; // when the pipeline writes the accumulated RUNLOG conditionally itself
  randomNonce: () => Uint8Array; // 16 bytes
  randomSalt: () => Uint8Array; // 16 bytes, per secrets record
}

// SealContext carries the per-run derived keys and the Merkle-leaf accumulator the two record-seal helpers
// share, so buildArchive's per-record loop stays a short orchestrator. Split out per finding engine-src-032-02.
interface SealContext {
  p: WriteParams;
  cak: Uint8Array;
  nameKey: Uint8Array;
  runIDBytes: Uint8Array;
  leaves: Uint8Array[];
}

// makeLine builds a record's shard line and its Merkle-leaf record hash through the shared builder,
// accumulating the leaf on the context for the in-memory Merkle root.
async function makeLine(ctx: SealContext, recordId: string, r: WriteRecord, segObj: string, plaintextSha384: string, size: number, recordSalt: Uint8Array | undefined): Promise<Record<string, unknown>> {
  const meta: RecordMeta = {
    sourceType: r.sourceType,
    name: r.name,
    ...(r.namespace ? { namespace: r.namespace } : {}),
    ...(r.bucket ? { bucket: r.bucket } : {}),
    // Self-identity annotations (like namespace/bucket): the buffered path must carry them onto the manifest
    // line too, or a SLICED_RUNS_DISABLED run (and the canary) would seal D1/API-source records WITHOUT the
    // database UUID / account the sliced path (slice.ts metaFor) stamps -- the two paths must be identical.
    ...(r.database ? { database: r.database } : {}),
    ...(r.account ? { account: r.account } : {}),
    ...(r.descriptor ? { descriptor: r.descriptor } : {}),
    // RV-CLI-MARKER: carry the pre-computed marker kind through so buildRecordLine stamps it (a streamed
    // record carries none; only sealBufferedRecord's small values can be markers).
    ...(r.incompleteMarker ? { incompleteMarker: r.incompleteMarker } : {}),
  };
  const seal: RecordSealResult = {
    segments: singleSegment(segObj, size),
    plaintextSha384,
    size,
    ...(recordSalt ? { recordSalt } : {}),
  };
  const { line, recordHash } = await buildRecordLine(ctx.nameKey, recordId, meta, seal);
  ctx.leaves.push(recordHash);
  return line;
}

// sealStreamRecord seals a large non-secret value: it addresses the stream in one pass, then seals it
// straight to the destination in a second pass via a single streamed PUT, never holding it whole (design
// F11). The sealed segment is NOT placed in the object map. Split from buildArchive per finding 032-02.
async function sealStreamRecord(ctx: SealContext, recordId: string, r: WriteRecord, dest: Destination | undefined): Promise<Record<string, unknown>> {
  const { p, cak } = ctx;
  // G166: both refusals are LOUD and SELF-DESCRIBING here and then collapse into a generic "run failed" by the
  // time they cross the stream boundaries. They are the two stream-WIRING invariants, and they present as the
  // most confusing bug in the product: one downpipe fails only when a value crosses the streaming threshold,
  // so the same source works one day and not the next. The record NAME the message interpolates is a customer
  // key and never rides; the closed kind is the whole record.
  if (!dest) {
    noteWriterRefusal("stream-no-destination");
    throw new Error(`record ${r.name} streams but no destination was provided`);
  }
  if (r.sourceType === "secrets") {
    noteWriterRefusal("secrets-streamed");
    throw new Error("secrets are sealed whole, not streamed");
  }
  const addr = await addressStream(cak, ADDR_SINGLE_NON_SECRET, new Uint8Array(0), r.stream!.open());
  const segHex = hexEncode(addr.segId);
  const segObj = `seg/${segHex.slice(0, 2)}/${segHex}.seg`;
  const fileKey = await deriveNonSecretFileKey(p.master, addr.segId, CODEC_NONE);
  await dest.putStream(segObj, sealSegmentToStream(fileKey, r.stream!.open(), p.randomNonce()), addr.size);
  return makeLine(ctx, recordId, r, segObj, addr.plaintextSha384, addr.size, undefined);
}

// sealBufferedRecord seals a small buffered value (and all secrets) into the object map. The address and
// seal differ for secrets: a fresh salt makes the address unique (never deduped) and the file key is bound
// to the run, record and salt. Split from buildArchive per finding 032-02.
async function sealBufferedRecord(ctx: SealContext, recordId: string, r: WriteRecord, out: Map<string, Uint8Array>): Promise<Record<string, unknown>> {
  const { p, cak, runIDBytes } = ctx;
  // G088, THE SILENT ZERO-BYTE SEAL. A record that arrives with NEITHER a value NOR a stream is defaulted to
  // zero bytes here, then hashed, sealed, signed and reported in a GREEN run. The archive verifies perfectly
  // (it is a valid seal of empty content), so nothing is wrong anywhere -- until the customer restores it
  // months later and gets nothing back, and no record on earth can say whether the engine or the source held
  // the empty content at capture time. The default stays (refusing loudly is the stricter product change, and
  // this is the diagnostic ask), but it is no longer SILENT: the count rides the run's integrity evidence.
  //
  // The record NAME is a customer key (a KV key, an object path), so only a 12-hex one-way digest of it is
  // carried -- the causeDigest discipline. The customer can hash their own key names and match; we cannot.
  if (r.value === undefined) {
    noteDefaultedEmptyRecord(hexEncode(await sha384(utf8(r.name))).slice(0, 12));
  }
  const value = r.value ?? new Uint8Array(0);
  let segIDBytes: Uint8Array;
  let sealed: Uint8Array;
  let recordSalt: Uint8Array | undefined;
  if (r.sourceType === "secrets") {
    recordSalt = p.randomSalt();
    segIDBytes = await segID(cak, ADDR_SECRETS, recordSalt, value);
    sealed = await sealSecretsSegment(p.master, segIDBytes, utf8(recordId), recordSalt, runIDBytes, value, p.randomNonce());
  } else {
    segIDBytes = await segID(cak, ADDR_SINGLE_NON_SECRET, new Uint8Array(0), value);
    sealed = await sealNonSecretSegment(p.master, segIDBytes, CODEC_NONE, value, p.randomNonce());
  }
  const segHex = hexEncode(segIDBytes);
  const segObj = `seg/${segHex.slice(0, 2)}/${segHex}.seg`;
  out.set(segObj, sealed);
  return makeLine(ctx, recordId, r, segObj, hexEncode(await sha384(value)), value.length, recordSalt);
}

/**
 * Builds the complete object map (key to bytes) for a single-shard run: it seals each record,
 * builds and seals the shard manifest, signs the root, writes the RUNLOG (unless skipped) and adds
 * the recovery bundle. Buffered segments are placed in the returned map; a record carrying a stream
 * (a large non-secret value) is sealed straight to opts.dest via a single streamed PUT and is NOT
 * in the map.
 *
 * @param p - the full write parameters.
 * @param opts - options: dest is the destination a streamed record seals to (required when any
 *   record carries a stream).
 * @returns the archive object map; streamed segments are written to dest, not the map.
 * @throws Error when a record carries a stream but no dest is provided, or a secret is given as a
 *   stream (secrets are sealed whole).
 */
export async function buildArchive(p: WriteParams, opts: { dest?: Destination } = {}): Promise<Map<string, Uint8Array>> {
  // An empty run is never valid: the shard preamble's signed sourceType is inferred from the first record,
  // so a zero-record archive would sign a wrong (defaulted) source type. Refuse loudly rather than emit one.
  //
  // G166: this refusal is almost always a CUSTOMER fault the pack could not name -- an emptied KV namespace, a
  // de-scoped API token, a deleted bucket -- and it reached support as a generic "run failed", so the customer
  // was effectively told the engine had broken. The closed kind source-enumerated-zero says "your source
  // produced nothing", which is a completely different conversation (and routes to the verify-source-resource
  // fix path). Recorded BEFORE the throw, so a failing run still carries it.
  if (p.records.length === 0) {
    noteWriterRefusal("source-enumerated-zero");
    throw new Error("buildArchive requires at least one record");
  }
  const out = new Map<string, Uint8Array>();
  const runIDBytes = decodeULID(p.runId);
  const cak = await deriveCAK(p.master, p.downpipeId);
  const mk = await deriveMK(p.master, runIDBytes);
  const nameKey = await deriveNameMACKey(mk, runIDBytes);

  const recordLines: unknown[] = [];
  const leaves: Uint8Array[] = [];
  const ctx: SealContext = { p, cak, nameKey, runIDBytes, leaves };

  // Seal each record (stream straight to dest, or seal the buffered value into `out`) and accumulate its
  // shard line + Merkle leaf. The two seal paths are sealStreamRecord and sealBufferedRecord (finding 032-02).
  for (let i = 0; i < p.records.length; i++) {
    const r = p.records[i]!;
    const recordId = `r${String(i).padStart(15, "0")}`;
    const line = r.stream
      ? await sealStreamRecord(ctx, recordId, r, opts.dest)
      : await sealBufferedRecord(ctx, recordId, r, out);
    recordLines.push(line);
  }

  // Shard manifest, signed root, RUNLOG anchor and recovery bundle (finding 032-02).
  await finaliseArchive(p, out, recordLines, leaves);
  return out;
}

// finaliseArchive writes the run-level objects once every record is sealed: the single-shard manifest, the
// signed root (master capsule, recipient set, key commitment, Merkle root), the signed RUNLOG freshness
// anchor (unless the pipeline writes it conditionally itself), and the recovery bundle. Split from
// buildArchive per finding engine-src-032-02 so the orchestrator stays a short sequence.
async function finaliseArchive(p: WriteParams, out: Map<string, Uint8Array>, recordLines: unknown[], leaves: Uint8Array[]): Promise<void> {
  // Shard manifest: preamble then record lines, NDJSON of canonical JSON, sealed (the
  // shared builder; single shard "00000" for the buffered path).
  const shard = await sealShardManifest({
    master: p.master,
    runId: p.runId,
    shardId: "00000",
    downpipeName: p.downpipeName,
    cadence: p.cadence,
    sourceType: p.records[0]?.sourceType ?? "kv",
    windowStart: p.windowStart,
    windowEnd: p.windowEnd,
    recordLines,
    randomNonce: p.randomNonce,
  });
  out.set(shard.object, shard.bytes);

  // Master capsule, recipient set, key commitment and the signed root (shared builder).
  const { rootBytes, sigBytes } = await buildSignedRoot({
    downpipeId: p.downpipeId,
    runId: p.runId,
    createdAt: p.createdAt,
    master: p.master,
    recipients: p.recipients,
    signer: p.signer,
    shards: [{ id: "00000", object: shard.object, sha384: shard.sha384Hex }],
    declaredRecordCount: p.records.length,
    merkleRootHex: hexEncode(await merkleRoot(leaves)),
    prevRunId: p.prevRunId,
    runlogIndex: p.runlogIndex,
    randomNonce: p.randomNonce,
  });
  out.set(`run/${p.runId}/root.manifest.json`, rootBytes);
  out.set(`run/${p.runId}/root.manifest.json.sig`, sigBytes);

  // The signed RUNLOG freshness anchor. When the pipeline accumulates and writes the
  // RUNLOG conditionally across runs (design F10), it sets skipRunlog and handles this.
  if (!p.skipRunlog) {
    const entries: RunlogEntry[] = p.runlog ?? [thisRunEntry(p)];
    const { runlog, sig } = await signRunlog(entries, p.signer.edPrivate, p.signer.mldsaSecret);
    out.set("_RECOVERY/RUNLOG", runlog);
    out.set("_RECOVERY/RUNLOG.sig", utf8(b64urlEncode(sig)));
  }

  // The recovery bundle makes the destination self-sufficient (SPEC 9).
  await addBundle(out, p.signer.edPrivate, p.signer.mldsaSecret);
}
