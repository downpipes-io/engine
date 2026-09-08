import { hexEncode } from "../crypto/bytes.ts";
import { deriveCAK, deriveMK, deriveNameMACKey } from "../crypto/derive.ts";
import type { Destination } from "../dest/types.ts";
import { addBundle } from "../format/bundle.ts";
import { MerkleFrontier } from "../format/frontier.ts";
import { decodeULID } from "../format/ulid.ts";
import {
  buildRecordLine,
  buildSignedRoot,
  type RecipientEntry,
  type RecordMeta,
  type Signer,
  sealShardManifest,
} from "../format/writer.ts";
import { addOpCounts } from "../meter.ts";
import { destRejectionDetail } from "../restore-reasons.ts";
import type { Selector, SourceAdapter, SourceRecord } from "../sources/types.ts";
import { isResumable } from "../sources/types.ts";
import type { SliceBudget } from "./budget.ts";
import type { CheckpointCounts, PartialRecord, RunCheckpoint } from "./checkpoint.ts";
import { addIncompleteId, cloneIncompleteIds, MARKER_ATTRIBUTION_MAX_PER_KIND, safeMarkerAttribution } from "./marker.ts";
import { appendRunlog, destinationLocalPrev, noteHistoryChainRestart, type RunlogLock } from "./pipeline.ts";
import { type ResumeFrom, sealRecordToDest } from "./record.ts";
import { throttleRetry, withRetry } from "./retry.ts";
import { isHandoffRefusalClass } from "./seal-faults.ts";

// The sliced seal (design F11): a run that cannot fit one invocation's subrequest and
// CPU budget proceeds as a chain of SLICES, each sealing records from the last
// checkpointed cursor until the budget says yield, flushing what it sealed as a manifest
// shard, and checkpointing (cursor + Merkle frontier + counters + the wrapped master).
// The final slice writes the signed root over ALL accumulated shards, the recovery
// bundle, and the RUNLOG entry, exactly the objects the buffered pipeline writes, so a
// reader cannot tell a sliced archive from a one-shot one beyond its shard count.
//
// Invariants that make resume sound:
//   - The cursor only ever advances to a mark whose records are all in FLUSHED shards
//     (the slice flushes before it checkpoints, and marks follow every record).
//   - Segments are content-addressed under the run's ONE master (unwrapped from the
//     checkpoint), so a crashed slice's re-crawl re-addresses identically and skips
//     every segment that already landed (idempotent re-seal).
//   - A shard object is recorded in the checkpoint ATOMICALLY with the cursor that
//     covers it (the caller persists both in one storage transaction), so the root never
//     lists a shard whose records the cursor still considers pending, and a re-flushed
//     shard after a crash overwrites the same object key before it is ever recorded.

export const DEFAULT_SHARD_MAX_RECORDS = 5000;

export interface ShardEntry {
  id: string;
  object: string;
  sha384: string;
}

export interface SliceDeps {
  source: SourceAdapter;
  dest: Destination;
  signer: Signer;
  recipients: RecipientEntry[];
  budget: SliceBudget;
  segmentTargetBytes?: number | undefined;
  shardMaxRecords?: number | undefined;
  // throttleRetry overrides the destination THROTTLE/transient retry budget (Layer 1b). Absent = the
  // DEST_THROTTLE_RETRY default (6 attempts / 500 ms base). Populated from DEST_THROTTLE_ATTEMPTS /
  // DEST_THROTTLE_BASE_MS in sliceDepsFromEnv; it only changes how patiently a 503 is retried.
  throttleRetry?: { attempts?: number | undefined; baseMs?: number | undefined } | undefined;
  nowIso?: () => string;
  randomNonce?: () => Uint8Array;
  randomSalt?: () => Uint8Array;
}


// PAD5_LIMIT is the exclusive ceiling of the 5-digit zero-padded shard-id space (10^5). The signed
// root lists shards and the offline reader concatenates their records in the LISTED order to recompute
// the Merkle root, so the shard listing order MUST equal the seal order. finaliseRun lists shards in
// NUMERIC id order; as long as every id is exactly 5 digits, numeric order also equals lexicographic
// order, which keeps a paged DO-storage enumeration (lexicographic) and the listing in agreement. At
// index 100000 the id would widen to 6 digits ("100000" sorts BEFORE "99999" lexicographically), so a
// run that walked past this ceiling could silently reorder the signed root's shard list and make the
// recomputed Merkle root mismatch the signature -- the sharpest latent signed-archive corruption risk.
// Fix 2a's ~25x shard reduction pushes this ceiling from ~22M to ~500M records (unreachable on the
// serial path), but does not remove it, so pad5 REFUSES to mint an out-of-range id and the seal fails
// LOUD (retryable) rather than emitting a misordered archive. Widening the pad is deliberately NOT done:
// it would change every shard id's bytes and break the byte-identical-to-before contract (and the proof
// of it) for N==1/inline runs, while merely moving the cliff; the loud refusal removes it outright. A
// future fan-out composite id will pad and assert each component the same way.
export const PAD5_LIMIT = 100000;

export function pad5(n: number): string {
  if (!Number.isInteger(n) || n < 0 || n >= PAD5_LIMIT) {
    throw new Error(`shard id index ${n} is outside the 5-digit shard-id range [0, ${PAD5_LIMIT}); refusing to seal an archive whose shard ids would overflow and silently reorder the signed root`);
  }
  return String(n).padStart(5, "0");
}

// PAD10_LIMIT bounds the per-RANGE local record index of a fan-out WORKER (Fix 2b). A composite recordId
// is `r{pad5(range)}{pad10(local)}` = r + 15 digits, so local must fit 10 digits (10 billion records per
// range, far past any real partition). pad10 REFUSES an out-of-range index loudly rather than widen the id
// past 15 digits (which would break ValidateRecordID's r+15 form). These ids are SCRATCH -- the merge
// renumbers every record to the serial `r{pad15(globalIndex)}` -- so a worker overflow fails the run
// loud-and-retryable before any archive is signed, never emits a malformed id.
export const PAD10_LIMIT = 10_000_000_000;

function pad10(n: number): string {
  if (!Number.isInteger(n) || n < 0 || n >= PAD10_LIMIT) {
    throw new Error(`fan-out local record index ${n} is outside the 10-digit per-range range [0, ${PAD10_LIMIT}); refusing to mint a composite recordId that would overflow the 16-char ValidateRecordID form`);
  }
  return String(n).padStart(10, "0");
}

// recordIdFor mints a record's id. On a SERIAL run (rangeIndex undefined) it is the byte-identical
// `r{pad15(i)}`; on a fan-out WORKER it is the composite, global-order-preserving `r{pad5(range)}{pad10(i)}`
// (16 chars, all digits, ValidateRecordID-safe). The composite id is SCRATCH: the coordinator's merge
// renumbers it to `r{pad15(globalIndex)}`, so the FINAL archive's record ids -- and hence the leaf hashes
// that bind them -- are byte-identical to a serial seal.
export function recordIdFor(i: number, rangeIndex?: number): string {
  if (rangeIndex === undefined) return `r${String(i).padStart(15, "0")}`;
  return `r${pad5(rangeIndex)}${pad10(i)}`;
}

// shardIdFor mints a shard's id. SERIAL (rangeIndex undefined): the byte-identical `pad5(i)`. Fan-out
// WORKER: the composite `{pad5(range)}{pad5(local)}` (10 digits) that string-sorts range-major, so the
// coordinator reads every worker's scratch shards in global key order during the merge. The merge re-seals
// the records into FINAL shards with serial `pad5` ids, so the archive's shard ids are byte-identical too.
export function shardIdFor(i: number, rangeIndex?: number): string {
  if (rangeIndex === undefined) return pad5(i);
  return `${pad5(rangeIndex)}${pad5(i)}`;
}

export function defaultNowIso(): string {
  return new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

// SliceCtx is the immutable plumbing one slice needs: the deps, the checkpoint being advanced, the
// derived keys, the per-record seal deps, and the nowIso/randomNonce/shardMax resolved once. It lets the
// flush/seal/crawl helpers be standalone functions taking explicit parameters rather than closures over
// runSlice's locals.
interface SliceCtx {
  deps: SliceDeps;
  cp: RunCheckpoint;
  master: Uint8Array;
  nameKey: Uint8Array;
  sealDeps: Parameters<typeof sealRecordToDest>[0];
  nowIso: () => string;
  randomNonce: () => Uint8Array;
  shardMax: number;
  // rangeIndex (Fix 2b) is this slice's fan-out worker tag, copied from cp.rangeIndex: undefined on a
  // serial run (byte-identical serial ids), set on a worker (composite scratch ids). It threads into
  // recordIdFor/shardIdFor so the id scheme is decided once per slice, not per record.
  rangeIndex: number | undefined;
}

// SliceState is the mutable accumulator advanced as records seal: the pending record lines, the shard
// list, the indices, the frontier, the running counts, and the resume cursor.
interface SliceState {
  lines: Record<string, unknown>[]; // the shape buildRecordLine returns for its `line` output
  newShards: ShardEntry[];
  recordIndex: number;
  shardIndex: number;
  frontier: MerkleFrontier;
  counts: CheckpointCounts;
  pendingCursor: string | null; // the mark covering every record sealed so far THIS slice
  // PR7 mid-record resume: when this slice left a streamed record part-sealed, its prefix is recorded
  // here and stopNow is set so the crawl ends IMMEDIATELY without advancing the cursor past it (the
  // partial is NOT committed). resumePartial is the INBOUND partial from the checkpoint, consumed by the
  // first record (matched by name) and then cleared; it is distinct from partialRecord, the OUTBOUND one.
  partialRecord: PartialRecord | null;
  stopNow: boolean;
  resumePartial: PartialRecord | null;
  // Fix 2a: true once an in-crawl shardMax flush fired this slice, which means the PRIOR open-shard
  // buffer (priorOpenLines, seeded into st.lines) was consumed into a shard. The caller (the storage
  // owner) uses this to decide whether to CLEAR the prior persisted open-shard batches (a flush
  // happened) or just APPEND this slice's new lines (no flush). priorOpenCount is the length of the
  // seeded prior buffer, so the slice's own new lines are st.lines.slice(priorOpenCount) when no flush.
  flushedThisSlice: boolean;
  priorOpenCount: number;
}

// flushShard seals the pending record lines into a manifest shard, writes it, records it, and resets the
// buffer. A no-op when nothing is pending.
async function flushShard(ctx: SliceCtx, st: SliceState): Promise<void> {
  if (st.lines.length === 0) return;
  const shardId = shardIdFor(st.shardIndex, ctx.rangeIndex);
  const shard = await sealShardManifest({
    master: ctx.master,
    runId: ctx.cp.runId,
    shardId,
    downpipeName: ctx.cp.downpipeName,
    cadence: ctx.cp.cadence,
    sourceType: ctx.cp.sourceType,
    windowStart: ctx.cp.startedAt,
    windowEnd: ctx.nowIso(),
    recordLines: st.lines,
    randomNonce: ctx.randomNonce,
  });
  await withRetry(() => ctx.deps.dest.put(shard.object, shard.bytes), throttleRetry(ctx.deps.throttleRetry));
  st.newShards.push({ id: shardId, object: shard.object, sha384: shard.sha384Hex });
  st.shardIndex++;
  st.lines = [];
  // Fix 2a: a flush consumed the open-shard buffer (which was seeded with the carried prior batches),
  // so the storage owner must REPLACE the persisted batches rather than append to them. The leftover
  // (records sealed after the flush point, if any) becomes the new buffer.
  st.flushedThisSlice = true;
}

// metaFor builds a record's line-relevant identity (what it is, not its bytes), the form both the
// manifest line and the partial-record re-match key use.
function metaFor(record: SourceRecord, accountId?: string): RecordMeta {
  return {
    sourceType: record.sourceType,
    name: record.name,
    ...(record.namespace ? { namespace: record.namespace } : {}),
    ...(record.bucket ? { bucket: record.bucket } : {}),
    // Identity self-annotations (like namespace/bucket): the D1 database UUID travels ON the record; the
    // account is the source adapter's own accountId (the API sources), stamped here so the archive names
    // which account it is a backup of. Both are omitted when absent, keeping the omitempty line shape.
    ...(record.database ? { database: record.database } : {}),
    ...(accountId ? { account: accountId } : {}),
    ...(record.descriptor ? { descriptor: record.descriptor } : {}),
  };
}

// partialMatches reports whether an inbound partial describes the SAME object the crawl just re-yielded:
// the source type, name, and any namespace/bucket must all match. A mismatch means the object the partial
// described vanished or the listing shifted, so the partial is abandoned (its segments orphaned, harmless
// and content-addressed) and the re-yielded record is sealed fresh.
function partialMatches(p: PartialRecord, record: SourceRecord): boolean {
  return (
    p.meta.sourceType === record.sourceType &&
    p.meta.name === record.name &&
    (p.meta.namespace ?? undefined) === (record.namespace ?? undefined) &&
    (p.meta.bucket ?? undefined) === (record.bucket ?? undefined)
  );
}

// sealOne seals one record to the destination and folds its line + counts into the state. Three outcomes:
// a fully-sealed record appends its line + Merkle leaf and advances the index; a record that changed
// behind its etag pin is counted as a clean skip and excluded from the manifest; a streamed record that
// ran out of slice budget mid-record is recorded as the slice's PARTIAL (no line, no leaf, no index
// advance) and STOPS the crawl, so the next slice resumes it. On RESUME, the FIRST record consumes the
// inbound partial: if it matches, the seal continues from the prefix; if not, the partial is abandoned and
// the record sealed fresh.
async function sealOne(ctx: SliceCtx, st: SliceState, record: SourceRecord): Promise<void> {
  // Consume an inbound partial on the first record only: it is matched here, then cleared whatever the
  // result (a match resumes it; a mismatch abandons it; either way it is no longer pending).
  let resumeFrom: ResumeFrom | undefined;
  const inbound = st.resumePartial;
  if (inbound !== null) {
    st.resumePartial = null;
    if (partialMatches(inbound, record)) {
      // The partial must resume under the SAME recordId it was part-sealed at: a partial never advances the
      // record index, and no record commits ahead of it, so the resuming slice's index equals the partial's.
      // If they ever diverged, the completed record would carry a recordId (hence a recordHash / Merkle
      // leaf) inconsistent with the rest of the run; refuse loudly rather than seal an inconsistent leaf.
      if (inbound.recordIndex !== st.recordIndex) {
        throw new Error(`mid-record resume index mismatch: partial at ${inbound.recordIndex}, slice at ${st.recordIndex}`);
      }
      resumeFrom = { offsetSealed: inbound.offsetSealed, segments: inbound.segments, ...(inbound.etag !== undefined ? { etag: inbound.etag } : {}) };
    }
    // A mismatch falls through with resumeFrom undefined: the partial's segments are orphaned (a later
    // sweep GCs the unreferenced content-addressed objects) and this record seals from scratch.
  }

  const outcome = await sealRecordToDest(ctx.sealDeps, recordIdFor(st.recordIndex, ctx.rangeIndex), record, resumeFrom);
  if (outcome.ok === false) {
    st.counts.recordsSkippedChanged++;
    return;
  }
  if (outcome.ok === "partial") {
    // The record is NOT committed: record its prefix as the slice's outbound partial and signal the crawl
    // to STOP immediately. No line, no Merkle leaf, no recordIndex advance, no cursor advance. The prefix
    // segment writes ARE durable (content-addressed), so the partial's objectsWritten/etc. are folded into
    // the counts (they are real archive bytes the next slice's exists() will skip).
    st.partialRecord = {
      recordIndex: st.recordIndex,
      meta: metaFor(record, ctx.deps.source.accountId),
      offsetSealed: outcome.offsetSealed,
      segments: outcome.segments,
      ...(outcome.etag !== undefined ? { etag: outcome.etag } : {}),
    };
    st.stopNow = true;
    st.counts.objectsWritten += outcome.counts.objectsWritten;
    st.counts.objectsSkipped += outcome.counts.objectsSkipped;
    st.counts.archiveBytesWritten += outcome.counts.archiveBytesWritten;
    return;
  }
  // R1-1 / RV-CLI-MARKER (CR-04): the sentinel KIND, when this record IS a marker, comes from the source
  // adapter's OWN markerKind assertion (set only at the exact call site that built a substitute value in
  // place of real bytes) -- never re-derived by sniffing record.value's content shape. A real customer value
  // that merely LOOKS marker-shaped (e.g. `{"_pending":false,"orderId":42}`) carries no markerKind and is
  // never misclassified. The kind is used TWICE: stamped into the shard line via meta.incompleteMarker (so
  // the offline restore sees the marker as the sentinel it is), AND folded into the aggregate recordsIncomplete
  // + per-marker breakdown below. NO-CUSTODY: only the marker KEY identity, never its payload.
  const markerKind = record.markerKind;
  const meta = metaFor(record, ctx.deps.source.accountId);
  if (markerKind !== undefined) meta.incompleteMarker = markerKind;
  const { line, recordHash } = await buildRecordLine(ctx.nameKey, recordIdFor(st.recordIndex, ctx.rangeIndex), meta, outcome.seal);
  st.lines.push(line);
  await st.frontier.append(recordHash);
  st.recordIndex++;
  st.counts.records++;
  if (markerKind !== undefined) {
    st.counts.recordsIncomplete++;
    st.counts.incompleteByMarker[markerKind] = (st.counts.incompleteByMarker[markerKind] ?? 0) + 1;
    // WS-P2: a _vanished marker is ALSO the distinct "mid-crawl deletion" signal. It seals + counts like any
    // incompleteness marker (above), and additionally bumps recordsVanished so a churning source stays visible
    // as its own count on the run row. Deriving it here (from the sealed marker) keeps the vanish counted at
    // most once -- the marker is a real record sealed exactly once, so no double-count across a resume.
    if (markerKind === "_vanished") st.counts.recordsVanished++;
    // WS-P1 ATTRIBUTION (all source types): record WHICH surface/object was short. safeMarkerAttribution is the
    // single NO-CUSTODY gate -- cf-config by its raw closed-registry surface id, EVERY custody source (KV/R2/D1
    // keys; workers/artifacts/stream/images object names) by a STABLE one-way HANDLE of its name, so the raw
    // customer/operator name NEVER reaches the pack. Compute it (it hashes) ONLY while the per-kind bucket has
    // ROOM, so a churning source shorting thousands of objects does not hash past the cap; addIncompleteId is
    // still the dedup+cap authority. Lives on the counts, not the sealed record -- archive bytes are unchanged.
    const idBucket = st.counts.incompleteIds[markerKind];
    if (idBucket === undefined || idBucket.length < MARKER_ATTRIBUTION_MAX_PER_KIND) {
      const attribId = await safeMarkerAttribution(record.sourceType, record.name);
      if (attribId !== undefined) addIncompleteId(st.counts.incompleteIds, markerKind, attribId);
    }
  }
  st.counts.bytes += outcome.seal.size;
  st.counts.objectsWritten += outcome.counts.objectsWritten;
  st.counts.objectsSkipped += outcome.counts.objectsSkipped;
  st.counts.archiveBytesWritten += outcome.counts.archiveBytesWritten;
}

// crawlResumable drives a resumable source from the checkpoint cursor, sealing records and flushing
// shards, advancing pendingCursor to the latest mark, and stopping when the budget says yield. Returns
// true if the source is exhausted (no yield), false if it yielded mid-crawl.
async function crawlResumable(ctx: SliceCtx, st: SliceState): Promise<boolean> {
  const selector: Selector = ctx.cp.selector;
  if (!isResumable(ctx.deps.source)) throw new Error("crawlResumable called on a non-resumable source");
  for await (const ev of ctx.deps.source.crawlFrom(selector, ctx.cp.cursor, ctx.deps.budget)) {
    if (ev.kind === "record") {
      await sealOne(ctx, st, ev.record);
      // PR7: a record left mid-record-partial STOPS the crawl HERE, before its trailing mark is consumed,
      // so pendingCursor stays at the mark BEFORE the partial record. The run is not done (return false):
      // the next slice resumes from that cursor, re-yields the partial record first, and continues it.
      if (st.stopNow) return false;
      if (st.lines.length >= ctx.shardMax) await flushShard(ctx, st);
      continue;
    }
    // A mark: everything yielded so far is resumable-after this token. Marks are where a slice may end
    // (the cursor must cover every sealed record), and they follow every record, so a yield decision is
    // never more than one record stale.
    st.pendingCursor = ev.token;
    if (ctx.deps.budget.shouldYield()) return false;
  }
  return true;
}

// crawlNonResumable drives a non-resumable source (secrets list, a D1 dump): small by construction, it
// seals whole in this slice. It refuses to resume mid-crawl, and fails LOUDLY if the source outgrows one
// invocation's budget (a non-resumable source that needs more than one invocation can never complete).
async function crawlNonResumable(ctx: SliceCtx, st: SliceState): Promise<boolean> {
  const selector: Selector = ctx.cp.selector;
  if (ctx.cp.cursor !== null) throw new Error("a non-resumable source cannot resume mid-crawl");
  if (ctx.cp.partialRecord !== null) throw new Error("a non-resumable source cannot resume a mid-record partial");
  let sealedAny = false;
  for await (const record of ctx.deps.source.crawl(selector, ctx.deps.budget)) {
    // Once at least one record is sealed AND the budget is exhausted yet the source has MORE records (we
    // are at the top of another iteration), fail LOUDLY with an actionable, enumerated reason instead of
    // dying silently at the platform subrequest/CPU cap. (Full resumability for D1/Workers/cf-config is
    // the planned 10k-scale fix; this is the interim that turns silent non-coverage into a surfaced
    // failure the operator and the alert path can see. Known, untracked debt: the fix is planned but not
    // yet filed as tracked work.)
    if (sealedAny && ctx.deps.budget.shouldYield()) {
      throw new Error(`source too large for one slice: the "${ctx.cp.sourceType}" source is not yet resumable and exceeded a single invocation's budget; narrow its selector or await resumable support for this source type`);
    }
    await sealOne(ctx, st, record);
    // A non-resumable source's records are buffered and seal whole, so a mid-record partial is impossible
    // here; if one ever arises it is a contradiction (this crawl cannot checkpoint), so refuse it loudly
    // rather than silently drop the part-sealed record.
    if (st.stopNow) throw new Error(`a non-resumable "${ctx.cp.sourceType}" source produced a mid-record partial, which it cannot resume`);
    sealedAny = true;
    if (st.lines.length >= ctx.shardMax) await flushShard(ctx, st);
  }
  return true;
}

// SliceResult is what runSlice hands back to the storage owner. Besides the advanced checkpoint and
// the shards this slice FLUSHED (the in-crawl shardMax flushes), it describes how the OPEN-SHARD buffer
// changed so the owner can update its append-only wrapped batches (Fix 2a):
//   - openReset: a flush consumed the prior buffer, so the owner CLEARS the persisted batches and
//     writes openWrite as the fresh buffer; false means the prior batches stay and openWrite is APPENDED.
//   - openWrite: the lines to persist as one new wrapped batch (the post-flush leftover when openReset,
//     else just this slice's new lines). It is ≤ one slice's record count, so it fits one DO value.
//   The full buffer size is checkpoint.openShard.count; the inline path (no prior batches) uses
//   openWrite directly as the whole open buffer to hand finaliseRun.
export interface SliceResult {
  checkpoint: RunCheckpoint;
  newShards: ShardEntry[];
  openReset: boolean;
  openWrite: Record<string, unknown>[];
}

// runSlice advances the run by one budget's worth of records. It returns the advanced checkpoint
// (cursor, frontier, counters, and the open-shard COUNT; the caller persists it atomically with the new
// shards and the open-shard batch), the shards this slice flushed, and the open-shard delta (above). It
// NEVER finalises; finaliseRun is separate so a slice that exhausts the source but lacks finalise
// headroom can yield first and let the next invocation finalise on a fresh budget.
//
// Fix 2a (open-shard spanning): the open shard is NOT closed at every slice boundary. priorOpenLines is
// the decrypted carried buffer (the lines sealed in earlier slices but not yet flushed); it seeds
// st.lines so the in-crawl `lines.length >= shardMax` flush finally fires at 5000 instead of at the
// ~220-record slice budget. The leftover after the slice is carried forward again. A shard therefore
// spans slices; the Merkle frontier (over per-record hashes, appended in seal order independent of shard
// boundaries) is unchanged, so the Merkle root is byte-identical to a one-shot seal. priorOpenLines
// defaults to [] for a fresh run / the inline first slice.
export async function runSlice(deps: SliceDeps, cp: RunCheckpoint, master: Uint8Array, priorOpenLines: Record<string, unknown>[] = []): Promise<SliceResult> {
  const nowIso = deps.nowIso ?? defaultNowIso;
  const randomNonce = deps.randomNonce ?? (() => crypto.getRandomValues(new Uint8Array(16)));
  const randomSalt = deps.randomSalt ?? (() => crypto.getRandomValues(new Uint8Array(16)));
  const shardMax = deps.shardMaxRecords ?? DEFAULT_SHARD_MAX_RECORDS;
  const sliceStart = Date.now();

  const runIdBytes = decodeULID(cp.runId);
  const cak = await deriveCAK(master, cp.downpipeId);
  const mk = await deriveMK(master, runIdBytes);
  const nameKey = await deriveNameMACKey(mk, runIdBytes);

  const ctx: SliceCtx = {
    deps,
    cp,
    master,
    nameKey,
    sealDeps: {
      cak,
      master,
      runIdBytes,
      dest: deps.dest,
      randomNonce,
      randomSalt,
      ...(deps.segmentTargetBytes !== undefined ? { segmentTargetBytes: deps.segmentTargetBytes } : {}),
      ...(deps.throttleRetry !== undefined ? { throttleRetry: deps.throttleRetry } : {}),
      meter: deps.budget,
      // PR7: the mid-record yield signal IS the slice's own shouldYield (the same boundary the crawl
      // yields on), so a single large streamed value stops at a window boundary when the slice is low and
      // the next slice resumes it.
      yieldCheck: () => deps.budget.shouldYield(),
    },
    nowIso,
    randomNonce,
    shardMax,
    rangeIndex: cp.rangeIndex,
  };
  const st: SliceState = {
    // Fix 2a: seed the open-shard buffer with the carried prior lines, so the in-crawl shardMax flush
    // accounts for records sealed in earlier slices and finally fires at 5000. A COPY, so the prior
    // array the caller still holds is never mutated.
    lines: [...priorOpenLines],
    newShards: [],
    recordIndex: cp.nextRecordIndex,
    shardIndex: cp.nextShardIndex,
    frontier: MerkleFrontier.deserialise(cp.frontier),
    // DEEP-copy the incompleteByMarker map so sealOne's per-record increments mutate THIS slice's map, not
    // the inbound checkpoint's (the same "the prior accumulated counts carried in the checkpoint are not
    // mutated" discipline the pure addOpCounts keeps for opCounts below; recordsIncomplete is a primitive so
    // the shallow spread already value-copies it). A spread of an absent map yields {}, so this is also
    // resume-safe for a pre-upgrade checkpoint that validateCheckpoint defaulted.
    counts: { ...cp.counts, incompleteByMarker: { ...cp.counts.incompleteByMarker }, incompleteIds: cloneIncompleteIds(cp.counts.incompleteIds) },
    pendingCursor: cp.cursor, // the mark covering every record sealed so far THIS slice
    partialRecord: null, // the OUTBOUND mid-record partial this slice produces (if any)
    stopNow: false,
    resumePartial: cp.partialRecord, // the INBOUND partial to continue, consumed by the first record
    flushedThisSlice: false,
    priorOpenCount: priorOpenLines.length,
  };

  const sourceDone = isResumable(deps.source) ? await crawlResumable(ctx, st) : await crawlNonResumable(ctx, st);

  // INVARIANT (PR7): a mid-record partial ALWAYS stops the crawl (crawlResumable returns false the moment
  // stopNow is set), so the source can never be reported exhausted with a record still part-sealed. If that
  // ever held, finalisation would sign a root that silently omits the partial record's bytes. Assert it.
  if (sourceDone && st.partialRecord !== null) {
    throw new Error("internal invariant: source reported done while a record is still mid-record-partial");
  }

  // Fix 2a: the unconditional end-of-slice flush is REMOVED. The open shard is NOT closed at the slice
  // boundary; its leftover lines are carried forward (persisted by the storage owner) so it accumulates
  // to shardMax across slices. The cursor-never-ahead-of-shards invariant still holds: a record's lines
  // are durable in the open-shard batch the caller persists ATOMICALLY with this checkpoint, exactly as
  // an in-crawl-flushed shard is -- so a record the cursor covers is always recoverable (from a flushed
  // shard or from the carried batch), and finaliseRun seals the final open shard before signing.
  const counts = st.counts;
  counts.durationMs += Date.now() - sliceStart;
  // Fold THIS slice's metered Cloudflare operations into the run's running tally (cost Phase 3). The
  // budget is fresh per invocation, so opCounts() is this slice's ops; addOpCounts is pure, so the prior
  // accumulated counts (carried in the checkpoint) are not mutated.
  counts.opCounts = addOpCounts(counts.opCounts, deps.budget.opCounts());
  const checkpoint: RunCheckpoint = {
    ...cp,
    cursor: st.pendingCursor,
    sourceDone,
    nextRecordIndex: st.recordIndex,
    nextShardIndex: st.shardIndex,
    frontier: st.frontier.serialise(),
    counts,
    sliceCount: cp.sliceCount + 1,
    // PR7: carry forward THIS slice's mid-record partial (null when no record is part-sealed). The ...cp
    // spread would otherwise leak the INBOUND partial; st.partialRecord is the authoritative outbound one
    // (the inbound was consumed by the first record, which either resumed it to completion or abandoned it).
    partialRecord: st.partialRecord,
    // Fix 2a: the current open-shard buffer size (all carried prior lines plus this slice's, minus any
    // flushed). The storage owner persists the line BYTES as wrapped batches; only this count rides in
    // the checkpoint, and finaliseRun cross-checks the re-loaded batch line total against it.
    openShard: { count: st.lines.length },
  };
  // Fix 2a: describe the open-buffer change for the storage owner. A flush this slice consumed the prior
  // batches (openReset), so the leftover st.lines is the WHOLE new buffer; otherwise only this slice's
  // new lines (st.lines beyond the seeded prior count) are appended. openWrite is bounded by one slice's
  // record count either way, so it always fits a single DO storage value.
  const openReset = st.flushedThisSlice;
  const openWrite = openReset ? st.lines : st.lines.slice(st.priorOpenCount);
  return { checkpoint, newShards: st.newShards, openReset, openWrite };
}

// finaliseRun writes the signed root over ALL shards, the recovery bundle and the RUNLOG
// entry (the same conditional accumulate-append the buffered pipeline uses), completing
// the archive. Fix 2a: it first seals the carried OPEN shard (openShardLines = the lines
// buffered across slices but not yet flushed, re-loaded from the open-shard batches by the
// caller) as ONE final shard at the next sequential id, so no buffered record is dropped.
// An empty run (no flushed shards, no open lines) flushes one empty shard for parity with
// the buffered path. The signed root lists shards in NUMERIC id order (== seal order ==
// Merkle frontier order); pad5 guards the id range so numeric also equals lexicographic.
export async function finaliseRun(deps: SliceDeps, cp: RunCheckpoint, master: Uint8Array, allShards: ShardEntry[], openShardLines: Record<string, unknown>[], lock?: RunlogLock): Promise<{ rootWritten: true; shards: number }> {
  const nowIso = deps.nowIso ?? defaultNowIso;
  const randomNonce = deps.randomNonce ?? (() => crypto.getRandomValues(new Uint8Array(16)));
  const shards = [...allShards];
  // sealFinal seals one closing shard at the next sequential id (cp.nextShardIndex) and records it.
  // It is used for the open shard (carried buffered lines) or the empty-run parity shard; the two are
  // mutually exclusive, so a single shard id is never reused.
  const sealFinal = async (recordLines: Record<string, unknown>[]): Promise<void> => {
    const shard = await sealShardManifest({
      master,
      runId: cp.runId,
      shardId: pad5(cp.nextShardIndex),
      downpipeName: cp.downpipeName,
      cadence: cp.cadence,
      sourceType: cp.sourceType,
      windowStart: cp.startedAt,
      windowEnd: nowIso(),
      recordLines,
      randomNonce,
    });
    await withRetry(() => deps.dest.put(shard.object, shard.bytes), throttleRetry(deps.throttleRetry));
    shards.push({ id: pad5(cp.nextShardIndex), object: shard.object, sha384: shard.sha384Hex });
  };
  if (openShardLines.length > 0) await sealFinal(openShardLines);
  else if (shards.length === 0) await sealFinal([]);
  // List shards in NUMERIC id order so the reader concatenates records in the SAME order the Merkle
  // frontier absorbed them (seal order). With every id 5 digits this equals lexicographic order too.
  shards.sort((a, b) => Number(a.id) - Number(b.id));

  // RUNLOG-1: seed the signed root's freshness.prevRunId from the destination-local RUNLOG (the SAME source
  // the append's relink uses), not from cp.prevRunId (the scheduler DO's lastRunId at trigger time, which
  // lags under churn -- rapid re-trigger / crashed-run reclaim). This keeps the signed root and the relinked
  // RUNLOG entry in agreement, so the strict offline CLI never reads an intact post-churn archive as a
  // rollback (rc=5). See destinationLocalPrev for the documented out-of-order-reclaim residual.
  const localPrev = await destinationLocalPrev(deps.dest, cp.downpipeId, cp.runlogIndex);
  // G283: a prior run SUCCEEDED (the scheduler's prevRunId) yet this destination's RUNLOG has no entry to
  // chain onto -- the downpipe was repointed at a re-created or wrong bucket, and the root about to be signed
  // will restart the history chain with prevRunId=null. Unchanged behaviour; recorded evidence.
  noteHistoryChainRestart(localPrev, cp.prevRunId, cp.runlogIndex);
  const frontier = MerkleFrontier.deserialise(cp.frontier);
  const { rootBytes, sigBytes } = await buildSignedRoot({
    downpipeId: cp.downpipeId,
    runId: cp.runId,
    createdAt: nowIso(),
    master,
    recipients: deps.recipients,
    signer: deps.signer,
    shards,
    declaredRecordCount: cp.counts.records,
    merkleRootHex: hexEncode(await frontier.root()),
    prevRunId: localPrev,
    runlogIndex: cp.runlogIndex,
    randomNonce,
  });
  await withRetry(() => deps.dest.put(`run/${cp.runId}/root.manifest.json`, rootBytes), throttleRetry(deps.throttleRetry));
  await withRetry(() => deps.dest.put(`run/${cp.runId}/root.manifest.json.sig`, sigBytes), throttleRetry(deps.throttleRetry));

  // The recovery bundle (SPEC 9) makes the destination self-sufficient.
  const bundleObjects = new Map<string, Uint8Array>();
  await addBundle(bundleObjects, deps.signer.edPrivate, deps.signer.mldsaSecret);
  for (const [k, v] of bundleObjects) {
    await withRetry(() => deps.dest.put(k, v), throttleRetry(deps.throttleRetry));
  }

  // The RUNLOG entry's prevRunId is relinked to the DESTINATION-LOCAL tail; the signed root above carries
  // the SAME destination-local prev (localPrev, not cp.prevRunId), so root and entry agree (RUNLOG-1).
  // Under 3-2-1 failover this run may have sealed to a destination that skipped the immediately-prior
  // account-global run, and a local relink keeps that destination's chain continuous (no dangling/forked
  // prevRunId the reader would read as a rollback).
  await appendRunlog(
    deps.dest,
    deps.signer,
    { index: cp.runlogIndex, runId: cp.runId, downpipeId: cp.downpipeId, time: nowIso(), recordCount: cp.counts.records, prevRunId: localPrev, status: "active" },
    lock,
    { relinkLocalPrev: true },
  );
  return { rootWritten: true, shards: shards.length };
}

// coarseRunError maps a raw seal failure to the same short, enumerated vocabulary the
// drill and restore responses use, so a failed history row never carries a stack or an
// internal detail. It is deliberately coarse. The ordering matters: source-binding
// errors are caught before source-read faults, which are caught before destination
// faults, so a crawl failure mentioning "status" is not misclassified as a destination
// error (ENG-L9). It lives here so the worker entry and the seal DO share one vocabulary.
export function coarseRunError(m: string): string {
  // A native-binding destination fault (R2Destination.guarded, src/dest/r2.ts) carries no
  // HTTP status and no S3 <Code> -- the binding never speaks HTTP, so none of the branches below (which all
  // key on a status/code/keyword in the message) can ever match it. Without this branch it would fall all
  // the way through to the generic "run failed", losing the destination attribution entirely. The wrapper's
  // prefix is fixed and self-describing (R2Destination is the only producer of it), so this is checked
  // FIRST, ahead of even the RUNLOG Layer 1d handling below: a native fault ON the RUNLOG object must read
  // as a destination fault, never as "runlog write contended" (an operator retrying CAS contention expects
  // it to clear; an auth/capability fault never will). Mapped onto the SAME "destination access error" class
  // an HTTP-attributed destination fault gets -- no new vocabulary member, and the run row still names the
  // destination as the cause rather than the undifferentiated "run failed".
  if (/^R2 native binding \S+ .* failed \(no HTTP status, no S3 code\):/.test(m)) return "destination access error";
  // Layer 1d (adaptive-dest-backpressure): a fault on the hot _RECOVERY/RUNLOG object that carries a
  // throttle/5xx status is a DESTINATION throttle on that object, NOT CAS contention. It must be checked
  // BEFORE the bare /RUNLOG/ branch below (whose substring match would otherwise eat it and mislabel it
  // "runlog write contended"), so it routes to the patient throttle ladder (isThrottleClass keys off the
  // same status) and is attributed to destination access, not contention. The bare
  // "RUNLOG write contended N times" CAS-exhaustion message has no status and still maps to contention.
  if (/RUNLOG/.test(m) && /(status|HTTP) (5\d\d|429)/.test(m)) return "destination access error";
  // A RUNLOG write the store REJECTED for a NON-throttle reason carries the real, sanitised S3 <Code>: a 403
  // AccessDenied (a credential or bucket policy that denies the _RECOVERY/ prefix while allowing segment
  // writes), a 400 InvalidRequest, or a 409/Object-Lock conflict on the RUNLOG overwrite (a WORM destination).
  // Surface that code -- the SAME treatment the segment-write path gives below -- instead of collapsing to
  // "runlog write contended", which would mislead the operator into expecting CAS contention to clear by
  // retrying when an auth/policy/WORM failure never will. A bare CAS-exhaustion "RUNLOG write contended N
  // times" carries no code, so destRejectionDetail returns undefined and it still maps to contention below.
  if (/RUNLOG/.test(m)) {
    const runlogCode = destRejectionDetail(m);
    if (runlogCode !== undefined) return `destination rejected the write (${runlogCode})`;
  }
  if (/RUNLOG write contended|RUNLOG/.test(m)) return "runlog write contended";
  // A finalise that REFUSED to sign a truncated archive (the R0-1 completeness guard: fewer shards
  // enumerated back than the checkpoint declared, or a short open-shard reload) is a named integrity
  // refusal, not a generic run fault. Surface it as a stable class so the failed row reads legibly; the
  // found/expected COUNTS ride the seal-fault OBSERVE ring, never this redacted string (mode shard-list-truncated).
  if (/shard enumeration incomplete|open-shard enumeration incomplete/.test(m)) return "shard enumeration incomplete (refused to sign a truncated archive)";
  // A resume whose stored CHECKPOINT could not be unwrapped / validated -- a SIGNER_PRIVATE rotation strands
  // the in-flight run (its checkpoint was wrapped under the PRIOR signer), or a corrupted DO write -- is a
  // named resume-state fault, not a generic run fault. The strand also rides the seal-fault OBSERVE ring
  // (mode signer-rotation-strands-runs); a pure AEAD-decrypt failure carries no keyword and still folds to
  // "run failed" below, but the ring captures it regardless of the message shape.
  if (/checkpoint (identity|progress|state|counts|frontier).*malformed|checkpoint cursor wrap is malformed|checkpoint partial wrap is malformed|unwrapped checkpoint master|checkpoint version is not/.test(m)) return "checkpoint unwrap failed (resume state unreadable; signer may have rotated)";
  // ---- G106: the LOUD, SELF-DESCRIBING refusals below, so a fault entirely inside the engine's own control
  // plane never collapses to "run failed" or gets MISATTRIBUTED as "destination access error". Each of these
  // is an engine refusal that already knows exactly what went wrong; the vocabulary below is what carries
  // that knowledge into the pack's failed run row. The classes are CLOSED and carry no operator data: the raw
  // messages can embed a record name or an object key, so they stay digest-only (causeDigest), and only these
  // fixed classes ride.
  //
  // A SEAL-DO HANDOFF REFUSAL is checked first, and the ordering is load-bearing: a bare status-only refusal
  // would fall to the generic status catch-all at the bottom as a DESTINATION ACCESS ERROR, blaming the
  // customer's bucket AND lighting the map's down-destination indicator (DEST-1 keys on exactly that class)
  // for a fault entirely inside the engine's own control plane. The sub-class is lifted out of the message
  // and RE-GATED against the closed vocabulary, so nothing but a known member can ever appear in the row.
  const handoff = /seal DO handoff refused: ([a-z-]+)/.exec(m);
  if (handoff !== null) {
    const cls = handoff[1];
    return isHandoffRefusalClass(cls) ? `seal DO handoff refused (${cls})` : "seal DO handoff refused";
  }
  if (/refused the handoff|refused the fan-out handoff|\/range-done refused/.test(m)) return "seal DO handoff refused";
  // An ENGINE INVARIANT the seal refused to violate (a source reported exhausted with a record still
  // mid-record-partial; a non-resumable source that produced a partial it cannot resume). This is an engine
  // bug, not a customer misconfiguration, and "run failed" made the two indistinguishable to support.
  if (/internal invariant|cannot resume|which it cannot resume/.test(m)) return "internal invariant violated";
  // A SHARD-ID OVERFLOW: the run walked past the 5-digit shard-id (or 10-digit per-range record-id) space, so
  // pad5/pad10 REFUSED to mint an id that would silently reorder the signed root. The sharpest latent
  // archive-corruption risk in the engine, and it read as a generic "run failed".
  if (/outside the 5-digit shard-id range|outside the 10-digit per-range range/.test(m)) return "shard id overflow (refused to seal a misordered archive)";
  // A RESUME-STATE DIVERGENCE: the mid-record partial resumed at a record index the slice does not agree with,
  // so the seal refused rather than commit a record whose Merkle leaf is inconsistent with the rest of the run.
  if (/mid-record resume index mismatch/.test(m)) return "resume state divergent (mid-record resume refused)";
  // A SOURCE THAT CANNOT RANGE-READ: the record is past the single-segment limit and its source offers no
  // range read, so it can never be chained across windows. Checked BEFORE the size-ceiling branch (the message
  // carries both facts) because THIS is the actionable one: the ceiling is not the problem, the source is.
  if (/cannot range-read/.test(m)) return "source cannot range-read (chunked capture unavailable)";
  // A RECORD PAST THE IN-BAND SIZE CEILING (the 6 GiB object): recoverable out of band, and nothing about it is
  // a "source read error" -- it is a hard, documented ceiling with a documented remedy.
  if (/single-invocation in-band capture limit|single-segment limit/.test(m)) return "record over the in-band size ceiling (recover it out of band)";
  // An UNSUPPORTED SOURCE TYPE is a CONFIG fault (the downpipe names a source this engine build cannot back
  // up), not a source READ fault; folding it into "source read error" sent support to look at a healthy source.
  if (/unsupported source type/.test(m)) return "unsupported source type";
  // SRC-1: the binding is present but the underlying resource (KV namespace / R2 bucket / D1 database)
  // is gone. Classify it AHEAD of the generic binding/source-read/destination catch-alls so the operator
  // is told the resource is missing, not handed a generic "run failed" or a misattributed destination error.
  if (/source resource missing/.test(m)) return "source resource missing";
  if (/is not present in the environment|reserved and cannot be a source/.test(m)) return "source binding error";
  if (/source too large for one slice/.test(m)) return "source too large to back up in one slice (not yet resumable)";
  if (/exceeds the .* single-segment limit|exceeds the .* single-invocation in-band capture limit|D1 database .* exceeds|D1 export:|D1_[A-Z]|unsupported source type|cannot range-read/.test(m)) return "source read error";
  // A cf-config source persisted before accountId was required (validation now rejects a zoneId-only
  // config up front) fails at crawl time asking for an accountId; name that cause so it is not a bare
  // "run failed" but an actionable "re-save with an account id".
  if (/config source needs an accountId/.test(m)) return "cf-config source needs an accountId (re-save the source with an account id)";
  // API-based sources (cf-config, workers) read the Cloudflare REST API; a throttle or 5xx from that
  // read carries a "status NNN"/"HTTP NNN" that would otherwise fall through to the destination
  // catch-all. Classify it as a source read so the operator is pointed at the right system.
  if (/Cloudflare API|cf-config|workers source/.test(m)) return "source read error";
  // A source ENUMERATION that hit the page cap (CfPaginationTruncated) is a structural discovery failure,
  // not a generic run fault: the surface has more items than one run can list. Name it so the operator
  // narrows the selector rather than staring at "run failed".
  if (/pagination exceeded \d+ pages/.test(m)) return "source listing exceeded the page cap (too many items to enumerate in one run; narrow the source selector)";
  // A native binding SOURCE read (KV get/list, R2 get/list/head) that failed with a throttle or 5xx carries
  // a "status NNN" (KV/R2 surface a status on a backend fault). Without a source-side branch here it would
  // fall through to the generic status catch-all below and be mislabelled a DESTINATION outage -- a SOURCE
  // fault attributed to the wrong system, pointing the operator at the wrong lever. Match the KV/R2 READ
  // shapes only: a destination WRITE is "PUT seg/... status NNN" (bare verb, no "KV"/"R2" token) and the
  // destination read/list paths are "GET/LIST <key>: status NNN" (also no "KV"/"R2" token), so this never
  // eats a destination fault and the destination catch-all below is unchanged. D1 read faults are already
  // named by the earlier D1_ branch.
  if (/\b(?:KV|R2)\b.*\b(?:get|list|head)\b/i.test(m) && /(?:status|HTTP) \d/i.test(m)) return "source read error";
  // A destination WRITE that the store REJECTED carries the real, sanitised S3 <Code> in parentheses
  // (s3WriteFailure: "PUT seg/0001: status 400 (InvalidRequest: object lock write requires a checksum)").
  // Surface that code instead of collapsing to the generic "destination access error", so the operator
  // sees the actionable cause (e.g. an Object-Lock checksum rejection) not a class name. The captured
  // group is built solely from a validated S3 code + a fixed hint, so it is redaction-safe. This sits
  // ABOVE the generic status catch-all; a plain "status NNN" with no code still maps to the class below.
  const code = destRejectionDetail(m);
  if (code !== undefined) return `destination rejected the write (${code})`;
  if (/status \d|fetch|network/.test(m)) return "destination access error";
  if (/missing required configuration/.test(m)) return "engine not fully configured";
  return "run failed";
}

// causeDigest is the bare 12-char correlation digest of a raw run-fault message: the first 6 bytes of
// SHA-384(m) rendered as hex. It is the SINGLE SOURCE of that digest, used BOTH by redactedRunError (which
// suffixes it as `[cause <hex>]` on the Logpush log line) AND by the failed-completion posters (which stamp
// it on the failed run-history row, so it rides in the support pack). Single-sourcing the computation here is
// what makes the row value provably byte-identical to the log line's, so support can join a customer's
// Logpush line to the pack's failed row by this 12-hex string alone. It is one-way: a record NAME (the
// record.ts / writer.ts size-bound messages embed one, protected-class data) can never be recovered from it.
export async function causeDigest(m: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-384", new TextEncoder().encode(m)));
  let hex = "";
  for (let i = 0; i < 6; i++) hex += digest[i]!.toString(16).padStart(2, "0");
  return hex;
}

// redactedRunError is the LOG form of a run fault (NC-2): the coarse class plus a short
// digest of the full raw message, so identical causes still correlate across attempts
// and runs in operator logs WITHOUT the raw text. A raw seal error can embed a record
// NAME (the record.ts / writer.ts size-bound messages); record names are protected-class
// data in this format (the archive encrypts them end to end), and console.error lines
// ship via the customer's Logpush, which commonly drains to a third-party SIEM, so the
// raw form never reaches a log line. The digest is one-way; support correlates by it.
export async function redactedRunError(m: string): Promise<string> {
  return `${coarseRunError(m)} [cause ${await causeDigest(m)}]`;
}
