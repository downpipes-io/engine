import { ab, concat, hexDecode, hexEncode, u64be, utf8 } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { validateCanonicalCounts } from "./canonnum.ts";
import { noteFailStage, noteLocator } from "./integrity-fault-ledger.ts";
import type { ShardPreamble, ShardRecord } from "./manifest.ts";
import { CHUNK_SIZE, MAX_SEGMENT_CHUNKS, VERSION } from "./version.ts";

// The codec, hash and segment-shape helpers the in-account verifying reader shares between its
// buffered (restoreRecord) and streaming (restoreRecordStream) paths and the keyless attestation.
// Each is a byte-for-byte port of the Go reference reader; keeping them in one leaf module keeps the
// reader's public-facing module small without changing any behaviour.

/**
 * sha384Hex returns the LOWER-CASE hex SHA-384 of the given bytes, the exact spelling the signed root
 * manifest stores for each shard, so a caller compares a fetched object against the signed digest by
 * plain string equality rather than by decoding either side. Used by the keyed reader and the keyless
 * attestation on the shard read-back path.
 */
export async function sha384Hex(b: Uint8Array): Promise<string> {
  return hexEncode(await sha384(b));
}

/**
 * recordHashOf recomputes a record's Merkle-leaf hash from its fields (SPEC 6.5): the format version
 * label as domain separation, then the record id, the plaintext and key-name digests decoded back from
 * their hex spelling, and the plaintext size as a big-endian u64. It hashes what the shard row DECLARES,
 * so it detects a rewritten manifest row once the result is checked against the signed Merkle root; the
 * bytes themselves are covered separately by the per-record plaintextSha384 comparison.
 */
export async function recordHashOf(rec: ShardRecord): Promise<Uint8Array> {
  return sha384(
    concat(
      utf8(`${VERSION} record-hash`),
      utf8(rec.recordId),
      hexDecode(rec.plaintextSha384),
      hexDecode(rec.keyNameHash),
      u64be(BigInt(rec.plaintextSize)),
    ),
  );
}

/**
 * segmentChunkBound validates a segment's signed chunkRange and returns the chunk count it
 * declares, which drives the bounded read (SPEC 6.3, 14.5). It is a byte-for-byte port of the
 * Go reference reader.go segmentChunkBound. The range is the half-open
 * [firstChunk, lastChunkExclusive). This reader opens each segment object as a whole STREAM,
 * so firstChunk MUST be 0 (a sub-segment chunk offset is not a shape this format major
 * emits); lastChunkExclusive MUST be at least 1 and at most the per-segment ceiling of 14.5.
 * Without this gate the TS reader verified LESS than the offline Go reader (a reader-parity
 * break): it never read chunkRange at all.
 *
 * The returned bound is the UPPER limit only. It is what the caller must still compare against the
 * chunk count the decrypted plaintext actually occupies (segmentStreamChunks), because an over-stated
 * range is refused there, not here. recordId names the record in the thrown message and is not
 * recorded: each refusal files a chunk-range locator carrying the bare ordinals into the integrity
 * fault ledger before throwing, so support can tell the three refusals apart.
 */
export function segmentChunkBound(recordId: string, chunkRange: [number, number]): number {
  const [first, last] = chunkRange;
  // G057: all three refusals coarsened to "integrity check failed" with no locator. The chunk ordinals are
  // bare ints and the record id is NOT carried (it is a customer key: the caller's digest, not the name).
  if (first !== 0) {
    noteLocator({ kind: "chunk-range", shardOrdinal: first });
    throw new Error(`record ${recordId} segment chunkRange firstChunk must be 0, got ${first}`);
  }
  if (last < 1) {
    noteLocator({ kind: "chunk-range", declaredCount: 0 });
    throw new Error(`record ${recordId} segment chunkRange lastChunkExclusive must be at least 1, got ${last}`);
  }
  if (last > MAX_SEGMENT_CHUNKS) {
    noteLocator({ kind: "chunk-range", declaredCount: last, recoveredCount: MAX_SEGMENT_CHUNKS });
    throw new Error(`record ${recordId} segment chunkRange lastChunkExclusive ${last} exceeds the ${MAX_SEGMENT_CHUNKS}-chunk segment ceiling`);
  }
  return last;
}

/**
 * segmentStreamChunks returns the number of STREAM chunks a decrypted plaintext of n bytes
 * occupies (SPEC 7.8), a port of the Go reference reader.go segmentStreamChunks: one chunk
 * per 65536 plaintext bytes, an extra chunk for any remainder, and a single (empty) final
 * chunk for a zero-length value. It lets the reader close the lower bound: a chunkRange that
 * over-states the segment's true chunk count is rejected (the Go whole-segment 6.3 rule).
 *
 * n is the PLAINTEXT length, not the sealed length, so a caller works it out after the AEAD tags
 * and the nonce are off. The count it returns is arithmetic on n alone and never touches the bytes.
 */
export function segmentStreamChunks(n: number): number {
  let chunks = Math.floor(n / CHUNK_SIZE);
  if (n % CHUNK_SIZE !== 0 || n === 0) chunks++;
  return chunks;
}

/**
 * gunzip decompresses a gzip member and rejects output past the declared plaintext size. The cap is
 * applied DURING decompression via capStream so a gzip bomb is errored mid-flight rather than after the
 * whole inflated output has been buffered into memory; this matches the streaming restoreRecordStream path.
 *
 * max is the manifest's declared plaintextSize for the record, and it is a refusal threshold rather than a
 * length assertion: output SHORTER than max passes here and is caught by the plaintext hash check. The
 * result is still fully buffered on return, so this path suits values below the streaming threshold.
 * recordId only names the record in the error text, hence the "buffered" default for the non-streaming call.
 */
export async function gunzip(b: Uint8Array, max: number, recordId = "buffered"): Promise<Uint8Array<ArrayBuffer>> {
  const ds = new DecompressionStream("gzip");
  const stream = new Response(ab(b)).body!.pipeThrough(ds).pipeThrough(capStream(max, recordId));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * capStream errors a stream once more than `max` bytes have flowed through it, the streaming
 * equivalent of the buffered gunzip's out.length > max guard: a gzip member that decompresses past
 * the declared plaintext size is rejected before the excess is emitted, so a decompression bomb
 * cannot exhaust memory on the recovery path.
 *
 * The running total is per TransformStream instance, so each record needs its own. The overflowing
 * chunk is dropped rather than partly enqueued, and the refusal reaches the consumer as a stream
 * error (controller.error) instead of a throw from this call, so a caller sees it when it reads.
 * A decompress-overflow locator carrying the declared and observed byte counts is filed into the
 * integrity fault ledger at the same point.
 */
export function capStream(max: number, recordId: string): TransformStream<Uint8Array, Uint8Array> {
  let seen = 0;
  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller): void {
      seen += chunk.length;
      if (seen > max) {
        // G057: an inflate running past the DECLARED plaintext size is either a corrupt gzip member or a
        // decompression bomb. Both were "integrity check failed". The two byte counts are the whole answer.
        noteLocator({ kind: "decompress-overflow", declaredCount: max, recoveredCount: seen });
        controller.error(new Error(`record ${recordId} decompressed output exceeds the declared size`));
        return;
      }
      controller.enqueue(chunk);
    },
  });
}

/**
 * parseShard decodes a DECRYPTED shard manifest: newline-delimited JSON whose first line is the
 * preamble and whose remaining lines are one record each, with empty lines dropped. The canonical-numeric
 * gate runs on the preamble's recordCountInShard and on every record's plaintextSize BEFORE that line is
 * parsed, and the preamble's declared count must equal the number of record lines, so a shard that was
 * re-signed with a padded count or a truncated tail is refused here.
 *
 * It returns the preamble and the records exactly as written, having checked only the `kind` discriminator
 * on each line: the caller still has to match the preamble against the run and hash each record. Refusals
 * are bare Errors rather than integrityError, so a caller that classifies faults handles them itself.
 */
export function parseShard(plain: Uint8Array): { preamble: ShardPreamble; recs: ShardRecord[] } {
  const lines = new TextDecoder().decode(plain).split("\n").filter((l) => l.length > 0);
  if (lines.length === 0) throw new Error("shard manifest is empty");
  // Canonical-numeric gate (SPEC 11.3) on the signed shard count/size fields, mirroring
  // the Go reference shard reader (shard.go), which calls validateCounts on the preamble's
  // recordCountInShard and on each record's plaintextSize. Without it a re-signed shard
  // carrying a non-canonical or out-of-range count is accepted here while Go rejects it
  // (exit 6).
  validateCanonicalCounts(lines[0]!, "recordCountInShard");
  const preamble = JSON.parse(lines[0]!) as ShardPreamble;
  if (preamble.kind !== "preamble") throw new Error("first shard line is not a preamble");
  const recs: ShardRecord[] = [];
  for (const line of lines.slice(1)) {
    validateCanonicalCounts(line, "plaintextSize");
    const r = JSON.parse(line) as ShardRecord;
    if (r.kind !== "record") throw new Error("shard line is not a record");
    recs.push(r);
  }
  if (preamble.recordCountInShard !== recs.length) throw new Error("shard record count mismatch");
  return { preamble, recs };
}

/**
 * segIDFromObject recovers a segment's 48-byte id from its object key: the last path component with any
 * ".seg" suffix removed, hex-decoded, and required to be a full SHA-384 length. The id is content-derived,
 * so the key IS the identifier, and this is where the reader reads it back before opening the segment.
 *
 * A key that will not decode and a key that decodes to the wrong length are both refused, each filing the
 * malformed-object-key locator and a shard-hash fail stage into the integrity fault ledger first (see the
 * G057 note in the body, which is why a damaged KEY is no longer reported as a missing OBJECT). The decode
 * error is rethrown unchanged rather than wrapped.
 */
export function segIDFromObject(object: string): Uint8Array {
  const base = object.slice(object.lastIndexOf("/") + 1).replace(/\.seg$/, "");
  // G057: a malformed object key and a genuinely missing object are distinguishable: malformed-object-key
  // means the KEY is damaged (re-derive it); absent means the OBJECT is gone.
  let raw: Uint8Array;
  try {
    raw = hexDecode(base);
  } catch (e) {
    noteLocator({ kind: "malformed-object-key" });
    noteFailStage("shard-hash");
    throw e;
  }
  if (raw.length !== 48) {
    noteLocator({ kind: "malformed-object-key" });
    noteFailStage("shard-hash");
    throw new Error(`invalid segment object ${object}`);
  }
  return raw;
}
