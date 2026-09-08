import { b64urlEncode, concat, hexDecode, hexEncode, u64be, utf8 } from "../crypto/bytes.ts";
import { nameMAC } from "../crypto/derive.ts";
import { sha384 } from "../crypto/primitives.ts";
import type { RestoreDescriptor } from "../sources/types.ts";
import type { D1Descriptor, KVDescriptor, R2Descriptor, SecretsDescriptor } from "./manifest.ts";
import { CHUNK_SIZE, CODEC_NAME_NONE, VERSION } from "./version.ts";

// The record line builder: the single byte-determining shard-line builder both seal paths
// share (the buffered buildArchive and the sliced seal), so the two cannot drift. Split out
// of writer.ts so the archive writer stays under the structural ceiling while the public API
// (re-exported from writer.ts) is unchanged.

// Mutable drops readonly from a shape's own properties so the write path can assemble a manifest
// descriptor field by field, while the manifest interfaces stay readonly for the read path.
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

/**
 * Computes the number of 64 KiB STREAM chunks for a plaintext of the given size, the half-open
 * chunkRange upper bound (SPEC 6.3); an empty value is one (empty) chunk.
 *
 * @param size - the plaintext byte count.
 * @returns the chunk count (at least 1).
 */
export function chunkCount(size: number): number {
  return size === 0 ? 1 : Math.ceil(size / CHUNK_SIZE);
}

/**
 * One entry of a record's ordered segments list (SPEC 6.2): the segment object key, its half-open
 * STREAM chunk range, and the packed slice (always null here, as the engine writer does not pack).
 */
export interface SegmentRef {
  object: string;
  chunkRange: [number, number];
  packed: null;
}

/** The line-relevant identity of a record (what it is, not its bytes): the source type and name,
 * the optional namespace or bucket, the optional restore descriptor, and the optional
 * incompleteness-marker kind. */
export interface RecordMeta {
  sourceType: string;
  name: string;
  namespace?: string;
  bucket?: string;
  database?: string;
  account?: string;
  descriptor?: RestoreDescriptor;
  // incompleteMarker (RV-CLI-MARKER): the marker KIND string when this record's value is an incompleteness
  // sentinel (one of seal/marker.ts MARKER_KEYS), else undefined. The caller (which already parses the value
  // to tally recordsIncomplete) passes the kind it computed, so buildRecordLine stamps it WITHOUT re-parsing.
  incompleteMarker?: string;
}

/**
 * The result of sealing a record's bytes: its ordered segments (one, or a chain for a value past
 * the single-segment ceiling), the whole-record plaintext SHA-384 and size, and the per-record
 * salt for a secrets record.
 */
export interface RecordSealResult {
  segments: SegmentRef[];
  plaintextSha384: string;
  size: number;
  recordSalt?: Uint8Array;
}

// descriptorFields turns the engine-internal RestoreDescriptor into the wire descriptor
// objects keyed by source ("kv"/"r2"/"secrets"/"d1"), applying the omitempty contract that
// the Go reader mirrors (spec/manifest.go): a field is emitted only when non-empty, and a
// whole descriptor object is emitted only when it has at least one non-empty field. The
// opaque metadata (kvMetadata, r2HttpMetadata, r2CustomMetadata) is carried as the PARSED
// JSON value so makeLine's canonicalJSON re-sorts and re-canonicalises it byte-identically to
// Go's CanonicalJSON over the same json.RawMessage; it is never stringified verbatim. The
// caller merges the returned fields into the record line before canonicalisation, so the
// recursive key sort makes the emit order here irrelevant.
function descriptorFields(d: RestoreDescriptor): { kv?: KVDescriptor; r2?: R2Descriptor; secrets?: SecretsDescriptor; d1?: D1Descriptor } {
  const out: { kv?: KVDescriptor; r2?: R2Descriptor; secrets?: SecretsDescriptor; d1?: D1Descriptor } = {};

  // The manifest descriptor interfaces are readonly (they are read-path deserialisation targets); the
  // writer assembles them field by field, so build through Mutable<T> locals and assign the result.
  const kv: Mutable<KVDescriptor> = {};
  if (d.kvMetadata !== undefined) kv.metadata = d.kvMetadata;
  // expiration omitempty matches Go's int64 zero-value: omit 0 and any non-positive value.
  if (typeof d.kvExpiration === "number" && d.kvExpiration > 0) kv.expiration = d.kvExpiration;
  if (Object.keys(kv).length > 0) out.kv = kv;

  const r2: Mutable<R2Descriptor> = {};
  if (d.r2HttpMetadata !== undefined && Object.keys(d.r2HttpMetadata).length > 0) r2.httpMetadata = d.r2HttpMetadata;
  if (d.r2CustomMetadata !== undefined && Object.keys(d.r2CustomMetadata).length > 0) r2.customMetadata = d.r2CustomMetadata;
  if (Object.keys(r2).length > 0) out.r2 = r2;

  const secrets: Mutable<SecretsDescriptor> = {};
  // String omitempty: omit the empty string, matching Go's string zero-value.
  if (d.secretsStore) secrets.store = d.secretsStore;
  if (d.secretsScope) secrets.scope = d.secretsScope;
  if (d.secretsComment) secrets.comment = d.secretsComment;
  if (d.secretsWorker) secrets.worker = d.secretsWorker;
  if (d.secretsBindingVar) secrets.bindingVar = d.secretsBindingVar;
  if (Object.keys(secrets).length > 0) out.secrets = secrets;

  const d1: Mutable<D1Descriptor> = {};
  if (d.d1Format) d1.format = d.d1Format;
  if (Object.keys(d1).length > 0) out.d1 = d1;

  return out;
}

/**
 * Builds one record's shard line and its Merkle-leaf record hash. It is the single byte-determining
 * builder both seal paths use (the buffered buildArchive and the sliced seal), so the two cannot
 * drift. The record hash binds the recordId, whole-record plaintext hash, name MAC and size (SPEC
 * 6.5); the segment layout is bound via the signed manifest, not the leaf.
 *
 * @param nameKey - the keyed-name MAC key for this run.
 * @param recordId - the record id.
 * @param r - the record's line-relevant identity (source type, name, namespace/bucket, descriptor).
 * @param seal - the seal result (segments, plaintext hash, size, optional salt).
 * @returns the canonical record line object and the 48-byte Merkle-leaf record hash.
 */
export async function buildRecordLine(nameKey: Uint8Array, recordId: string, r: RecordMeta, seal: RecordSealResult): Promise<{ line: Record<string, unknown>; recordHash: Uint8Array }> {
  const keyNameHashHex = hexEncode(await nameMAC(nameKey, r.sourceType, r.name));
  const recordHash = await sha384(concat(utf8(`${VERSION} record-hash`), utf8(recordId), hexDecode(seal.plaintextSha384), hexDecode(keyNameHashHex), u64be(BigInt(seal.size))));
  const line: Record<string, unknown> = {
    kind: "record",
    sourceType: r.sourceType,
    name: r.name,
    keyNameHash: keyNameHashHex,
    recordId,
    plaintextSize: seal.size,
    plaintextSha384: seal.plaintextSha384,
    recordHash: hexEncode(recordHash),
    codec: CODEC_NAME_NONE,
    segments: seal.segments,
  };
  if (r.namespace) line.namespace = r.namespace;
  if (r.bucket) line.bucket = r.bucket;
  if (r.database) line.database = r.database;
  if (r.account) line.account = r.account;
  if (seal.recordSalt) line.recordSalt = b64urlEncode(seal.recordSalt);
  // RV-CLI-MARKER: stamp the incompleteness-marker KIND onto the line ONLY when this record is a marker, so a
  // non-marker record's line stays BYTE-IDENTICAL to before (the signed-root hash is unchanged for it) and old
  // archives never carry the key. It rides in the shard bytes the root's sha384 pins (signed/tamper-evident);
  // it is NOT folded into the Merkle-leaf recordHash above (a manifest annotation, like namespace/bucket).
  if (r.incompleteMarker) line.incompleteMarker = r.incompleteMarker;
  // Per-source restore descriptors (SPEC 6.2, 12.3). Each is attached under its wire key
  // only when it carries a non-empty field, so a record with nothing to describe leaves the
  // line byte-identical to one written before descriptors existed. The nested metadata is
  // attached as parsed JSON, so the line's canonicalJSON pass canonicalises it the
  // same way the Go reader recomputes the signed bytes (recursive key sort, integer-only
  // numbers, minimal string escaping); the metadata is never embedded as a pre-stringified blob.
  if (r.descriptor) {
    const fields = descriptorFields(r.descriptor);
    if (fields.kv) line.kv = fields.kv;
    if (fields.r2) line.r2 = fields.r2;
    if (fields.secrets) line.secrets = fields.secrets;
    if (fields.d1) line.d1 = fields.d1;
  }
  return { line, recordHash };
}

/**
 * Builds the one-element segments list every buffered or single-stream record carries (the
 * pre-chaining shape).
 *
 * @param segObj - the segment object key.
 * @param size - the plaintext byte count, used to compute the half-open chunk range.
 * @returns a single-element SegmentRef list with a [0, chunkCount(size)] range and no packed slice.
 */
export function singleSegment(segObj: string, size: number): SegmentRef[] {
  return [{ object: segObj, chunkRange: [0, chunkCount(size)], packed: null }];
}

/**
 * Builds the content-addressed segment object key (seg/<aa>/<segId>.seg) from a segment address.
 *
 * @param segIDBytes - the 48-byte segment content address.
 * @returns the segment object key.
 */
export function segmentObjectKey(segIDBytes: Uint8Array): string {
  const segHex = hexEncode(segIDBytes);
  return `seg/${segHex.slice(0, 2)}/${segHex}.seg`;
}
