import { b64urlDecode, b64urlEncode, utf8 } from "../crypto/bytes.ts";
import { hkdfSha384 } from "../crypto/primitives.ts";
import type { RecordMeta, SegmentRef } from "../format/writer-record.ts";
import { type OpCounts, zeroOpCounts } from "../meter.ts";
import type { Selector } from "../sources/types.ts";
import { CheckpointInvalidError, CheckpointUnwrapError } from "./checkpoint-fault.ts";
import { ConfigFaultError } from "./config-fault.ts";
import type { IncompleteByMarker, IncompleteIds } from "./marker.ts";

// RunCheckpoint is the durable between-invocation state of a sliced run (design F11):
// where the crawl is up to, the Merkle frontier, the run counters, and the run master
// WRAPPED under an engine-held key. The PERSISTED form contains no plaintext record
// names: the frontier is hashes, and the resume CURSOR, whose source token embeds the
// last fully-committed record's NAME (the KV after/cursor pair, the R2 after key), is
// AES-256-GCM-wrapped under the same checkpoint wrap key as the master before it is
// stored (sealCheckpointForStorage / openStoredCheckpoint below). Record names are
// protected-class data in this format (the archive encrypts them end to end), so the
// at-rest checkpoint holds them to the same bar as the master: an attacker needs BOTH
// the DO storage AND SIGNER_PRIVATE. The in-memory RunCheckpoint keeps the plaintext
// cursor (the sources need it to resume); only the storage boundary transforms it.
//
// partialRecord is the OPTIONAL mid-record-resume state (PR7): a single streamed-content
// value too large to seal in one slice is sealed across MULTIPLE slices, one window at a
// time, and the prefix it has already sealed is recorded here so the next slice continues
// it rather than starting over. It carries the record NAME (in meta), so like the cursor
// it is AES-256-GCM-wrapped under the checkpoint wrap key (a DISTINCT AAD domain) before
// it rests in DO storage. It is null whenever no record is mid-seal (the common case), so
// the cursor still covers every fully-committed record and resume from cursor alone is
// unchanged. The already-written prefix segments are content-addressed (durable); the
// running whole-record SHA-384 is NOT stored, it is RECOMPUTED from the prefix bytes on
// resume, which is what keeps a multi-slice record byte-identical to a one-shot seal.
//
// The wrapped master is the one honest posture trade-off of sliced runs, documented in
// OPERATIONS.md: a run too large for one invocation must derive the SAME content keys in
// a later invocation (CAK, MK and every file key are master-derived), so its 32-byte
// master is AES-256-GCM-wrapped under a key derived from SIGNER_PRIVATE and stored in
// Durable Object storage FOR THE LIFE OF THE RUN, deleted at completion. An attacker
// needs BOTH the DO storage AND the Worker's SIGNER_PRIVATE secret to recover it, the
// same bar as stealing OPERATIONAL_PRIVATE in the operational posture (and an attacker
// holding SIGNER_PRIVATE can already forge archives outright). A small run never wraps
// its master (the inline slice completes in one invocation and the master never leaves
// memory), and SLICED_RUNS_DISABLED removes the path entirely for break-glass-only
// deployments that prefer the hard per-invocation size ceiling instead.

export interface CheckpointCounts {
  records: number;
  bytes: number; // plaintext bytes sealed (the run-history "bytes" field)
  objectsWritten: number;
  objectsSkipped: number;
  archiveBytesWritten: number;
  recordsSkippedChanged: number; // changed/vanished mid-crawl behind an etag pin
  // recordsVanished is how many in-scope objects the LIST returned but that were GONE at value-read time (a
  // KV key / R2 object DELETED between the list page and the GET -- a live-source race, SPEC 12.5, WS-P2). The
  // adapters previously skipped these silently; counting them lets a run report "N objects vanished mid-crawl"
  // (source churning under the backup). It is DISTINCT from recordsSkippedChanged (the etag-pinned large-object
  // changed-mid-crawl skip) and from recordsIncomplete (a marker that DID seal). Nothing is sealed for a
  // vanished object, so this never touches the archive; it rides the counts (checkpoint + history row) only.
  recordsVanished: number;
  recordsIncomplete: number; // sealed INCOMPLETENESS sentinels (_truncated/_unavailable/_skipped/_pending/_refused): a record landed but it is a marker, not the real bytes, so the archive is intentionally short of the live source (R1-1)
  // incompleteByMarker is the PER-MARKER breakdown of recordsIncomplete (the support pack carries WHICH
  // incompleteness kinds a run sealed, not just the aggregate). Only non-zero keys are present; an empty
  // object means no markers. KEY identity + integer count only, never the marker payload (NO-CUSTODY,
  // same posture as opCounts). The diagnostics-bot consumes it from the run-history row.
  incompleteByMarker: IncompleteByMarker;
  // incompleteIds is the PER-KIND ATTRIBUTION companion to incompleteByMarker (WS-P1): for each marker kind,
  // a bounded, deduplicated list of WHICH surface/object was short. NO-CUSTODY: only redaction-safe closed/
  // product-token ids reach it (see marker.ts safeMarkerAttribution -- today cf-config surface ids only), never
  // an operator/customer record name; each list is capped. Only non-empty kinds are present. Like the marker
  // breakdown it never touches the sealed archive (it lives on the counts, i.e. the checkpoint + history row).
  incompleteIds: IncompleteIds;
  durationMs: number; // sealing wall time accumulated across slices
  // opCounts is the per-resource metered-subrequest tally accumulated across this run's slices (cost
  // Phase 3): the exact Cloudflare operations the backup made, for the cost estimate's platform ledger.
  opCounts: OpCounts;
}

export function zeroCounts(): CheckpointCounts {
  return { records: 0, bytes: 0, objectsWritten: 0, objectsSkipped: 0, archiveBytesWritten: 0, recordsSkippedChanged: 0, recordsVanished: 0, recordsIncomplete: 0, incompleteByMarker: {}, incompleteIds: {}, durationMs: 0, opCounts: zeroOpCounts() };
}

// PartialRecord is the in-flight state of a single streamed value being sealed ACROSS
// slices (PR7 mid-record resume). recordIndex is the id the partial record will commit
// under (so the resumed seal lands the same recordId as a one-shot would). meta is the
// record's line-relevant identity used to RE-MATCH it when the crawl re-yields it on
// resume (and to build its manifest line on completion). offsetSealed is how many leading
// bytes are already sealed into segments; the window loop continues from there. segments
// are the ordered, content-addressed SegmentRefs already written for [0, offsetSealed).
// etag pins the object version: on resume the re-yielded record's stream etag MUST equal
// this, or the prefix segments (the OLD bytes) would disagree with a re-hash of the NEW
// prefix and the record is abandoned instead (the change-detection safety edge).
export interface PartialRecord {
  recordIndex: number;
  meta: RecordMeta;
  offsetSealed: number;
  segments: SegmentRef[];
  etag?: string;
}

export interface RunCheckpoint {
  v: 1;
  downpipeId: string;
  downpipeName: string;
  cadence: string;
  sourceType: string;
  selector: Selector;
  runId: string;
  runlogIndex: number;
  prevRunId: string | null;
  startedAt: string; // the run's window start (RFC 3339 UTC millis)
  wrappedMaster: { iv: string; ct: string }; // AES-256-GCM under the checkpoint wrap key
  cursor: string | null; // the source resume token of the last fully-committed record
  sourceDone: boolean; // the crawl is exhausted; only finalisation remains
  nextRecordIndex: number;
  nextShardIndex: number;
  frontier: { count: number; nodes: { sizeLog: number; hash: string }[] };
  counts: CheckpointCounts;
  sliceCount: number;
  // The mid-record-resume prefix, or null when no record is part-sealed (PR7). It holds a
  // record NAME, so the STORED form wraps it under the checkpoint wrap key (a distinct AAD
  // domain), exactly as the cursor is wrapped.
  partialRecord: PartialRecord | null;
  // openShard is the OPEN-SHARD SPANNING state (Fix 2a): the count of record manifest lines that
  // have been sealed but NOT yet flushed into a shard, carried across slices so a shard accumulates
  // to shardMax (5000) instead of being force-closed at every slice boundary. Only the COUNT lives
  // here (a non-secret number, part of the logical resume state); the actual line BYTES carry record
  // NAMES (protected-class data, NC-1) and are far larger than the DO value cap, so they rest as
  // AES-256-GCM-wrapped, append-only batches in DO storage (sealOpenShardBatch below), keyed by the
  // RunSealDO. Absent (an in-flight run that started before the upgrade) defaults to {count:0} in
  // validateCheckpoint, so the run simply starts spanning from its next slice.
  openShard?: { count: number };
  // rangeIndex is the FAN-OUT (2b) WORKER tag: when set, this checkpoint belongs to a fan-out WORKER
  // sealing one half-open key-range of a larger run, and the slice emits COMPOSITE, global-order-
  // preserving SCRATCH ids -- recordId `r{pad5(rangeIndex)}{pad10(local)}` and shardId
  // `{pad5(rangeIndex)}{pad5(local)}` -- instead of the serial `r{pad15}` / `pad5`. These ids order
  // the worker's shards range-major so the coordinator's merge reads them in global key order; the
  // merge then RENUMBERS every record to the serial `r{pad15(globalIndex)}` and re-groups into
  // shardMax FINAL shards, so the final signed archive is byte-identical to a single-DO serial seal
  // (the leaf hash binds the recordId, so the composite ids are SCRATCH and never reach the archive).
  // Absent (the common case, and every serial run) keeps today's exact ids byte-for-byte.
  rangeIndex?: number;
}

// INFO_CHECKPOINT_WRAP is engine-internal (not a downpipe/0.1.0 wire constant): the HKDF
// info string for the checkpoint wrap key derived from the signer seed.
const INFO_CHECKPOINT_WRAP = "downpipe/engine checkpoint-wrap v1";

async function wrapKey(signerPrivateB64: string): Promise<CryptoKey> {
  const seed = b64urlDecode(signerPrivateB64);
  // G142: a SIGNER_PRIVATE that is present but MALFORMED (a truncated paste, a wrong encoding) strands every
  // run at checkpoint wrap/unwrap. Same message, same throw; typed so the pack names the var and the fault
  // class instead of showing a generic "run failed". The VALUE is never touched, only the var name.
  if (seed.length !== 64) throw new ConfigFaultError("signer-format", "SIGNER_PRIVATE is not the 64-byte seed form", "SIGNER_PRIVATE");
  const raw = await hkdfSha384(seed, new Uint8Array(0), utf8(INFO_CHECKPOINT_WRAP), 32);
  const buf = new ArrayBuffer(raw.length);
  new Uint8Array(buf).set(raw);
  return crypto.subtle.importKey("raw", buf, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

// wrapMaster seals the run master for checkpoint storage. A fresh 12-byte IV per wrap;
// the AAD binds the runId so a wrapped master cannot be replayed onto another run's
// checkpoint unnoticed.
export async function wrapMaster(signerPrivateB64: string, runId: string, master: Uint8Array): Promise<{ iv: string; ct: string }> {
  const key = await wrapKey(signerPrivateB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const m = new ArrayBuffer(master.length);
  new Uint8Array(m).set(master);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(runId) }, key, m));
  return { iv: b64urlEncode(iv), ct: b64urlEncode(ct) };
}

// G107: the two ways a master unwrap can fail are two DIFFERENT investigations, and the pack could not tell
// them apart (both landed as one bare "checkpoint-unwrap-failed" row). The AEAD FAILING means the wrap key
// is wrong -- a SIGNER_PRIVATE rotation stranded the in-flight run, or the doc was tampered with. The AEAD
// SUCCEEDING onto a non-32-byte plaintext means the wrap key was RIGHT and the stored bytes are corrupt.
// Both throws keep their prior behaviour verbatim (the AEAD's own message is preserved, the wrong-length
// sentence is unchanged, so coarseRunError and the strike ladder are byte-for-byte as before); the TYPE
// carries the closed sub-code to the recorder. No key, ciphertext or plaintext enters the error.
export async function unwrapMaster(signerPrivateB64: string, runId: string, wrapped: { iv: string; ct: string }): Promise<Uint8Array> {
  const key = await wrapKey(signerPrivateB64);
  const iv = b64urlDecode(wrapped.iv);
  const ct = b64urlDecode(wrapped.ct);
  const c = new ArrayBuffer(ct.length);
  new Uint8Array(c).set(ct);
  let plain: Uint8Array;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: utf8(runId) }, key, c));
  } catch (e) {
    throw new CheckpointUnwrapError("master-unwrap", (e as Error).message);
  }
  if (plain.length !== 32) throw new CheckpointUnwrapError("wrong-length", "unwrapped checkpoint master is not 32 bytes");
  return plain;
}

// validateCheckpoint guards a checkpoint read back from storage: a malformed document
// must fail the resume loudly (the run is then abandoned and re-triggered fresh) rather
// than seal under inconsistent state.
export function validateCheckpoint(c: unknown): RunCheckpoint {
  const x = c as RunCheckpoint;
  if (x?.v !== 1) throw new CheckpointInvalidError("version", "checkpoint version is not 1");
  if (typeof x.runId !== "string" || typeof x.runlogIndex !== "number" || typeof x.downpipeId !== "string") throw new CheckpointInvalidError("identity", "checkpoint identity fields are malformed");
  if (typeof x.wrappedMaster?.iv !== "string" || typeof x.wrappedMaster?.ct !== "string") throw new CheckpointInvalidError("wrapped-master", "checkpoint wrapped master is malformed");
  if (typeof x.nextRecordIndex !== "number" || typeof x.nextShardIndex !== "number" || typeof x.sliceCount !== "number") throw new CheckpointInvalidError("progress", "checkpoint progress fields are malformed");
  if (x.cursor !== null && typeof x.cursor !== "string") throw new CheckpointInvalidError("cursor", "checkpoint cursor is malformed");
  if (typeof x.sourceDone !== "boolean" || !x.frontier || !Array.isArray(x.frontier.nodes) || !x.counts) throw new CheckpointInvalidError("progress", "checkpoint state fields are malformed");
  if (typeof x.frontier.count !== "number") throw new CheckpointInvalidError("frontier", "checkpoint frontier count is malformed");
  for (const node of x.frontier.nodes) {
    if (typeof node?.sizeLog !== "number" || typeof node?.hash !== "string") throw new CheckpointInvalidError("frontier", "checkpoint frontier node is malformed");
  }
  // counts must be an object carrying at least the numeric fields zeroCounts() produces, so a
  // corrupted write cannot resume with NaN counters and silently seal a miscounted archive.
  const counts = x.counts as unknown as Record<string, unknown>;
  for (const field of ["records", "bytes", "objectsWritten", "objectsSkipped", "archiveBytesWritten", "recordsSkippedChanged", "durationMs"]) {
    if (typeof counts[field] !== "number") throw new CheckpointInvalidError("counts", "checkpoint counts are malformed");
  }
  // recordsIncomplete shipped after the other counters (R1-1), so a checkpoint persisted by an
  // in-flight run that started before the upgrade lacks it. Default it to 0 rather than rejecting,
  // so an upgrade never strands a resuming run; the next slice's increments then accrue from 0.
  if (typeof counts.recordsIncomplete !== "number") counts.recordsIncomplete = 0;
  // recordsVanished (WS-P2) shipped AFTER the strict-checked counters, so a checkpoint persisted by an
  // in-flight run that started before this upgrade lacks it. Default it to 0 rather than rejecting (the same
  // forward-compatible discipline as recordsIncomplete), so an upgrade never strands a resuming run.
  if (typeof counts.recordsVanished !== "number") counts.recordsVanished = 0;
  // incompleteByMarker (the PER-MARKER breakdown) shipped AFTER recordsIncomplete, so a checkpoint
  // persisted by an in-flight run that started before THIS upgrade lacks it. DEFAULT it to {} rather than
  // rejecting (the same forward-compatible discipline as recordsIncomplete above), so the upgrade never
  // strands a resuming run: the next slice's per-marker increments then accrue from an empty map. A stored
  // checkpoint that carries a non-object here (a corrupted write) is coerced to {} for the same reason a
  // resuming slice must be able to index-and-increment it without crashing; an absent/garbled breakdown
  // simply means "no markers tallied yet", never a hard fail. (CRITICAL: the resume path indexes this map
  // per record, so it MUST be a real object before runSlice's shallow copy reaches sealOne.)
  if (typeof counts.incompleteByMarker !== "object" || counts.incompleteByMarker === null) counts.incompleteByMarker = {};
  // incompleteIds (the PER-KIND attribution, WS-P1) shipped AFTER incompleteByMarker, so a checkpoint persisted
  // by an in-flight run that started before THIS upgrade lacks it. DEFAULT it to {} (identical forward-compatible
  // discipline), so the upgrade never strands a resuming run; the next slice's attribution then accrues from an
  // empty map. A corrupted non-object is coerced to {} for the same reason -- the resume path indexes it per
  // record, so it MUST be a real object before runSlice's deep copy reaches sealOne.
  if (typeof counts.incompleteIds !== "object" || counts.incompleteIds === null) counts.incompleteIds = {};
  // partialRecord (PR7) shipped after the rest, so a checkpoint persisted by an in-flight run that
  // started before the upgrade lacks it. DEFAULT it to null rather than rejecting (the same
  // forward-compatible discipline as recordsIncomplete), so the upgrade never strands a resuming
  // run; an absent partial simply means "no record is mid-seal", the common case. When present it
  // must be a well-formed PartialRecord, so a corrupted write cannot resume a half-record under
  // inconsistent state and silently seal a divergent (unrecoverable) record.
  const pr = (x as unknown as { partialRecord?: unknown }).partialRecord;
  if (pr === undefined || pr === null) {
    x.partialRecord = null;
  } else {
    const p = pr as Record<string, unknown>;
    if (typeof p.recordIndex !== "number" || typeof p.offsetSealed !== "number" || !Number.isInteger(p.offsetSealed) || p.offsetSealed < 0) {
      throw new CheckpointInvalidError("partial-record", "checkpoint partialRecord offsets are malformed");
    }
    if (!p.meta || typeof (p.meta as Record<string, unknown>).sourceType !== "string" || typeof (p.meta as Record<string, unknown>).name !== "string") {
      throw new CheckpointInvalidError("partial-record", "checkpoint partialRecord meta is malformed");
    }
    if (!Array.isArray(p.segments)) throw new CheckpointInvalidError("partial-record", "checkpoint partialRecord segments are malformed");
    for (const s of p.segments as unknown[]) {
      const seg = s as Record<string, unknown>;
      if (typeof seg?.object !== "string" || !Array.isArray(seg.chunkRange) || seg.chunkRange.length !== 2) {
        throw new CheckpointInvalidError("partial-record", "checkpoint partialRecord segment is malformed");
      }
    }
    if (p.etag !== undefined && typeof p.etag !== "string") throw new CheckpointInvalidError("partial-record", "checkpoint partialRecord etag is malformed");
  }
  // openShard (Fix 2a open-shard spanning) shipped after the rest, so a checkpoint persisted by an
  // in-flight run that started before the upgrade lacks it. DEFAULT it to {count:0} rather than
  // rejecting (the same forward-compatible discipline as recordsIncomplete/partialRecord), so the
  // upgrade never strands a resuming run; an absent open shard simply means "nothing buffered yet".
  // When present, count must be a non-negative integer (a corrupt write must not resume with a NaN /
  // negative buffered-line count and then mis-guard the finalise completeness check below it).
  const os = (x as unknown as { openShard?: unknown }).openShard;
  if (os === undefined || os === null) {
    x.openShard = { count: 0 };
  } else {
    const o = os as Record<string, unknown>;
    if (typeof o.count !== "number" || !Number.isInteger(o.count) || o.count < 0) {
      throw new CheckpointInvalidError("open-shard", "checkpoint openShard count is malformed");
    }
    x.openShard = { count: o.count };
  }
  // rangeIndex (Fix 2b fan-out) is optional: present only on a WORKER checkpoint. A serial run (and
  // every legacy doc) leaves it undefined, which keeps the byte-identical serial ids. When present it
  // must be a non-negative integer, so a corrupt write cannot resume a worker with a NaN/negative range
  // and mint a malformed composite id.
  const ri = (x as unknown as { rangeIndex?: unknown }).rangeIndex;
  if (ri !== undefined && (typeof ri !== "number" || !Number.isInteger(ri) || ri < 0)) {
    throw new CheckpointInvalidError("range-index", "checkpoint rangeIndex is malformed");
  }
  return x;
}

// ---- the persisted (at-rest) checkpoint form ---------------------------------------------
// StoredRunCheckpoint is RunCheckpoint with the plaintext resume cursor AND the partialRecord
// (PR7) replaced by their AES-256-GCM wraps (NC-1): both embed the last-/part-committed record
// NAME, which is protected-class data, so neither rests in DO storage in the clear. Each wrap uses
// a DISTINCT AAD domain ("cursor|<runId>" vs "partial|<runId>") under the same wrap key and binds
// the runId, so no ciphertext can be transplanted onto another field or another run.

export type StoredRunCheckpoint = Omit<RunCheckpoint, "cursor" | "partialRecord"> & {
  wrappedCursor: { iv: string; ct: string } | null;
  wrappedPartial: { iv: string; ct: string } | null;
};

const CURSOR_AAD_PREFIX = "cursor|";
const PARTIAL_AAD_PREFIX = "partial|";
// OPEN_AAD_PREFIX domains the open-shard batch wrap (Fix 2a). It is DISTINCT from the cursor and
// partial domains AND each batch's AAD additionally binds the batch SEQUENCE (open|<runId>|<seq>),
// so a wrapped open-shard batch can never be transplanted onto another field, another run, or a
// different sequence slot without the AEAD failing.
const OPEN_AAD_PREFIX = "open|";

// sealOpenShardBatch AES-256-GCM-wraps one batch of OPEN-SHARD manifest LINES for DO storage at rest
// (NC-1, Fix 2a). The lines carry plaintext record NAMES (buildRecordLine's `name` field), which are
// protected-class data in this format (the archive encrypts them end to end), so a carried open shard
// is held to the SAME bar as the cursor and the master: AES-256-GCM under the checkpoint wrap key
// (SIGNER_PRIVATE-derived), with the DISTINCT "open|<runId>|<seq>" AAD domain. A fresh 12-byte IV per
// wrap. The batches are EPHEMERAL DO scratch (deleted at finalise) and NEVER enter the signed archive.
export async function sealOpenShardBatch(signerPrivateB64: string, runId: string, seq: number, lines: unknown[]): Promise<{ iv: string; ct: string }> {
  const key = await wrapKey(signerPrivateB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = utf8(JSON.stringify(lines));
  const p = new ArrayBuffer(plain.length);
  new Uint8Array(p).set(plain);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(`${OPEN_AAD_PREFIX}${runId}|${seq}`) }, key, p));
  return { iv: b64urlEncode(iv), ct: b64urlEncode(ct) };
}

// openOpenShardBatch reverses sealOpenShardBatch, returning the decoded manifest lines. The AAD must
// match (open|<runId>|<seq>) or the AEAD fails, so a batch read under the wrong run or sequence is
// rejected rather than silently mis-attributed. A non-array decode is refused so a corrupt batch can
// never be spliced into the shard as garbage lines.
export async function openOpenShardBatch(signerPrivateB64: string, runId: string, seq: number, wrapped: { iv: string; ct: string }): Promise<Record<string, unknown>[]> {
  const key = await wrapKey(signerPrivateB64);
  const iv = b64urlDecode(wrapped.iv);
  const ct = b64urlDecode(wrapped.ct);
  const c = new ArrayBuffer(ct.length);
  new Uint8Array(c).set(ct);
  // G107: a FAILED open-shard batch AEAD is a distinct resume fault from a failed MASTER unwrap (the carried
  // manifest lines cannot be re-read, so the final shard would be short), and the pack distinguishes them.
  // The message is preserved verbatim; only the closed sub-code is added.
  let plain: Uint8Array;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: utf8(`${OPEN_AAD_PREFIX}${runId}|${seq}`) }, key, c));
  } catch (e) {
    throw new CheckpointUnwrapError("batch-unwrap", (e as Error).message);
  }
  const parsed = JSON.parse(new TextDecoder().decode(plain)) as unknown;
  if (!Array.isArray(parsed)) throw new Error("open-shard batch did not decode to an array of manifest lines");
  return parsed as Record<string, unknown>[];
}

// wrapJsonField AES-256-GCM-wraps an arbitrary JSON-serialisable field under the checkpoint wrap
// key with the given AAD domain, the shared mechanism the cursor and the partialRecord both use.
async function wrapJsonField(key: CryptoKey, runId: string, aadPrefix: string, value: unknown): Promise<{ iv: string; ct: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = utf8(JSON.stringify(value));
  const p = new ArrayBuffer(plain.length);
  new Uint8Array(p).set(plain);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(`${aadPrefix}${runId}`) }, key, p));
  return { iv: b64urlEncode(iv), ct: b64urlEncode(ct) };
}

// unwrapJsonField reverses wrapJsonField, returning the decoded JSON text for the caller to parse.
async function unwrapJsonField(key: CryptoKey, runId: string, aadPrefix: string, wrapped: { iv: string; ct: string }): Promise<string> {
  const iv = b64urlDecode(wrapped.iv);
  const ct = b64urlDecode(wrapped.ct);
  const c = new ArrayBuffer(ct.length);
  new Uint8Array(c).set(ct);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: utf8(`${aadPrefix}${runId}`) }, key, c));
  return new TextDecoder().decode(plain);
}

export async function sealCheckpointForStorage(signerPrivateB64: string, cp: RunCheckpoint): Promise<StoredRunCheckpoint> {
  const { cursor, partialRecord, ...rest } = cp;
  const key = await wrapKey(signerPrivateB64);
  // The cursor is wrapped as a raw UTF-8 string (its historical form), not JSON, so a legacy
  // plaintext-cursor doc and a freshly-wrapped one round-trip to the same token.
  let wrappedCursor: { iv: string; ct: string } | null = null;
  if (cursor !== null) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plain = utf8(cursor);
    const p = new ArrayBuffer(plain.length);
    new Uint8Array(p).set(plain);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(`${CURSOR_AAD_PREFIX}${cp.runId}`) }, key, p));
    wrappedCursor = { iv: b64urlEncode(iv), ct: b64urlEncode(ct) };
  }
  const wrappedPartial = partialRecord === null ? null : await wrapJsonField(key, cp.runId, PARTIAL_AAD_PREFIX, partialRecord);
  return { ...rest, wrappedCursor, wrappedPartial };
}

// openStoredCheckpoint reverses sealCheckpointForStorage and validates the result. A
// LEGACY stored document (written before the cursor wrap shipped) still carries a
// plaintext `cursor` field and is accepted as-is, so an in-flight sliced run is never
// stranded by the upgrade; its next persist writes the wrapped form. A doc written before
// the partialRecord wrap shipped lacks wrappedPartial; validateCheckpoint defaults the
// unwrapped partialRecord to null, so such a doc resumes from its cursor unchanged.
export async function openStoredCheckpoint(signerPrivateB64: string, stored: unknown): Promise<RunCheckpoint> {
  const s = stored as StoredRunCheckpoint & { cursor?: string | null };
  if (s && (typeof s.cursor === "string" || s.cursor === null)) return validateCheckpoint(s);
  if (!s || (s.wrappedCursor !== null && (typeof s.wrappedCursor?.iv !== "string" || typeof s.wrappedCursor?.ct !== "string"))) {
    throw new CheckpointInvalidError("cursor", "stored checkpoint cursor wrap is malformed");
  }
  if (s.wrappedPartial !== null && s.wrappedPartial !== undefined && (typeof s.wrappedPartial.iv !== "string" || typeof s.wrappedPartial.ct !== "string")) {
    throw new CheckpointInvalidError("partial-record", "stored checkpoint partial wrap is malformed");
  }
  const { wrappedCursor, wrappedPartial, ...rest } = s;
  const key = await wrapKey(signerPrivateB64);
  // The cursor is stored as raw UTF-8 (its historical form), so unwrapJsonField's decoded text IS the
  // token; the partialRecord is stored as JSON, so its decoded text is JSON.parse'd.
  const cursor = wrappedCursor === null ? null : await unwrapJsonField(key, s.runId, CURSOR_AAD_PREFIX, wrappedCursor);
  const partialRecord = wrappedPartial === null || wrappedPartial === undefined ? null : (JSON.parse(await unwrapJsonField(key, s.runId, PARTIAL_AAD_PREFIX, wrappedPartial)) as PartialRecord);
  return validateCheckpoint({ ...rest, cursor, partialRecord });
}
