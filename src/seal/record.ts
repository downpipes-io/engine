import { sha384 as nobleSha384 } from "@noble/hashes/sha2.js";
import { hexEncode, utf8 } from "../crypto/bytes.ts";
import { deriveNonSecretFileKey, segID } from "../crypto/derive.ts";
import { sha384 } from "../crypto/primitives.ts";
import { sealNonSecretSegment, sealSecretsSegment } from "../crypto/segment.ts";
import { addressStream, sealedSegmentLength, sealSegmentToStream } from "../crypto/streamseal.ts";
import type { Destination } from "../dest/types.ts";
import { MAX_STREAM_SEGMENT_BYTES } from "../dest/types.ts";
import { ADDR_SECRETS, ADDR_SINGLE_NON_SECRET, CODEC_NONE } from "../format/version.ts";
import { chunkCount, type RecordSealResult, type SegmentRef, segmentObjectKey, singleSegment } from "../format/writer.ts";
import type { Meter } from "../meter.ts";
import type { SourceRecord } from "../sources/types.ts";
import { MAX_SINGLE_RECORD_CONTENT_BYTES } from "./budget.ts";
import { throttleRetry, withRetry } from "./retry.ts";
import { notePartialAbandoned, noteSkippedChanged } from "./run-observations.ts";

// Seal ONE record's bytes straight to the destination, returning what the manifest line
// needs (the shared writer builders turn it into the canonical line). This is the
// dest-direct counterpart of buildArchive's in-map sealing, used by the sliced seal so a
// record's segments land as the crawl yields them and nothing accumulates in memory.
//
// A value past the single-segment ceiling (SPEC 14.5: 16384 STREAM chunks = 1 GiB of
// plaintext per segment) is sealed as a CHAINED multi-segment record (SPEC 6.2): the
// value is windowed, each window addressed and sealed as its own content-addressed
// segment exactly as the Go conformance writer chains (per-window segId over the
// window's own bytes, per-window file key, chunk indices restarting at 0 per segment),
// and the record line carries the ordered segments list with the WHOLE-record plaintext
// SHA-384 and size. Both readers reassemble chains today (reader.ts restoreRecord, Go
// reader.go RestoreRecord); the seg-multi-segment conformance vector pins the semantics.

export interface RecordSealDeps {
  readonly cak: Uint8Array;
  readonly master: Uint8Array;
  readonly runIdBytes: Uint8Array;
  readonly dest: Destination;
  readonly randomNonce: () => Uint8Array;
  readonly randomSalt: () => Uint8Array;
  // segmentTargetBytes caps one segment's plaintext (default and maximum: the SPEC 14.5
  // ceiling). Validators lower it to exercise real chains without gigabyte fixtures,
  // which is legal: the SPEC bounds a segment at AT MOST 16384 chunks.
  readonly segmentTargetBytes?: number;
  readonly meter?: Meter;
  // throttleRetry overrides the destination THROTTLE/transient retry budget for the seg WRITES on the
  // dominant data path (adaptive-dest-backpressure Layer 1b). Absent = the DEST_THROTTLE_RETRY default.
  readonly throttleRetry?: { attempts?: number | undefined; baseMs?: number | undefined } | undefined;
  // yieldCheck is the slice's mid-record yield signal (the SliceBudget's shouldYield, passed as a
  // closure so record.ts is not coupled to the budget type). The chained seal checks it AFTER sealing
  // each window: when it fires and windows remain, the record is left PARTIAL for the next slice to
  // continue. The after-the-window placement guarantees at least one new window seals per slice (no
  // stall). Absent = no mid-record yield (a fresh whole-record seal in one shot, the prior behaviour).
  readonly yieldCheck?: () => boolean;
}

// ResumeFrom is the mid-record-resume input to the chained seal: the prefix [0, offsetSealed) is
// ALREADY sealed into the given content-addressed segments (durable; not re-written), and etag is the
// version the prefix was sealed under. The chained seal rebuilds the running whole-record SHA-384 by
// re-hashing the prefix bytes (a single streamed read), then continues the window loop from
// offsetSealed, so the final whole-record digest is identical to a one-shot seal.
export interface ResumeFrom {
  offsetSealed: number;
  segments: SegmentRef[];
  etag?: string;
}

export interface SealCounts {
  objectsWritten: number;
  objectsSkipped: number;
  archiveBytesWritten: number;
}

// SealRecordOutcome: a fully-sealed record (ok: true) with the line inputs; a clean skip (ok: false)
// when the value changed or vanished between the listing and the seal (the etag-pinned read came back
// short, or a mid-record resume found the object changed); or a PARTIAL seal (ok: "partial") of one
// streamed value that ran out of slice budget mid-record, carrying how far it got so the next slice
// resumes it. A skipped record is EXCLUDED from the manifest entirely (SPEC 12.5); a partial record is
// NOT committed (no manifest line, no Merkle leaf, no cursor advance) until a later slice completes it.
export type SealRecordOutcome =
  | { ok: true; seal: RecordSealResult; counts: SealCounts }
  | { ok: false; reason: "changed-mid-crawl" }
  | { ok: "partial"; offsetSealed: number; segments: SegmentRef[]; etag?: string; counts: SealCounts };

// sealRecordToDest dispatches one record to the right seal path: a single streamed segment, a chained
// multi-segment stream (value past the single-segment ceiling), or a buffered value (small records and
// all secrets). Each path is a small, independently testable helper; this function validates the
// precondition (secrets are never streamed) and delegates. resumeFrom, when set, continues a chained
// record a prior slice left partial (only the chained path resumes; a value that fits one segment, or a
// buffered value, always seals whole in one go).
export async function sealRecordToDest(deps: RecordSealDeps, recordId: string, r: SourceRecord, resumeFrom?: ResumeFrom): Promise<SealRecordOutcome> {
  const counts: SealCounts = { objectsWritten: 0, objectsSkipped: 0, archiveBytesWritten: 0 };
  const secret = r.sourceType === "secrets";
  const target = Math.min(deps.segmentTargetBytes ?? MAX_STREAM_SEGMENT_BYTES, MAX_STREAM_SEGMENT_BYTES);

  if (r.stream) {
    if (secret) throw new Error("secrets are sealed whole, not streamed");
    // A resume is always a chained record (a prior slice only ever leaves the chained path partial), so
    // route a resumeFrom to the chained seal even if the remaining bytes would now fit one segment.
    return r.stream.size <= target && resumeFrom === undefined
      ? sealSingleStreamRecord(deps, r, counts)
      : sealChainedStreamRecord(deps, r, target, counts, resumeFrom);
  }
  return sealBufferedRecord(deps, recordId, r, secret, counts);
}

// sealSingleStreamRecord seals a streamed value that fits one segment: an address pass then a seal pass,
// two fresh opens (the F11 path). A short or long read means the object changed or vanished behind its
// etag pin, so the record is skipped cleanly.
async function sealSingleStreamRecord(deps: RecordSealDeps, r: SourceRecord, counts: SealCounts): Promise<SealRecordOutcome> {
  const declared = r.stream!.size;
  // G143: each withRetry on the data path names the subsystem it waits on (a closed enum), so the run's
  // retry pressure is attributable ("who throttled us") instead of an anonymous total. The address pass READS
  // the source; the exists/put passes talk to the destination.
  const addr = await withRetry(() => addressStream(deps.cak, ADDR_SINGLE_NON_SECRET, new Uint8Array(0), r.stream!.open()), { subsystem: "source-api" });
  if (addr.size !== declared) {
    // G065: the record is skipped and EXCLUDED from the archive, so a restore is legitimately missing it. The
    // aggregate skip count told support that; it never told them WHY, so a persistent infra fault looked exactly
    // like ordinary content churn. Record the CLOSED cause (a size that moved between the list and the seal).
    noteSkippedChanged("size-changed");
    return { ok: false, reason: "changed-mid-crawl" };
  }
  const segObj = segmentObjectKey(addr.segId);
  const fileKey = await deriveNonSecretFileKey(deps.master, addr.segId, CODEC_NONE);
  if (await withRetry(() => deps.dest.exists(segObj), { subsystem: "destination" })) {
    counts.objectsSkipped++;
  } else {
    // The stream body is constructed inside the retry closure so a retried put pulls
    // a fresh ranged read rather than a half-consumed stream.
    await withRetry(() => deps.dest.putStream(segObj, sealSegmentToStream(fileKey, r.stream!.open(), deps.randomNonce()), addr.size), { ...throttleRetry(deps.throttleRetry), subsystem: "destination" });
    counts.objectsWritten++;
    counts.archiveBytesWritten += sealedSegmentLength(addr.size);
  }
  return { ok: true, seal: { segments: singleSegment(segObj, addr.size), plaintextSha384: addr.plaintextSha384, size: addr.size }, counts };
}

// sealChainedStreamRecord seals a value past the single-segment ceiling as an ordered chain of
// content-addressed segments (SPEC 6.2). Bounded windows need a ranged open; a source that cannot
// range-read past the ceiling cannot be sealed (the pre-chaining refusal). The whole-record digest is
// threaded through every window's address pass via a tap; a retried window taps a CLONE of the
// digest-so-far so only a successful attempt's clone is committed (no double-feed).
// The address pass and the put pass each open the window separately. Both opens are pinned to the
// etag observed at list time (If-Match -> 412), so a same-size mutation between the two opens fails
// the second read rather than silently storing bytes that do not match the addressed segId; the
// size-change guard below catches a length change.
//
// MID-RECORD RESUME (PR7). When the slice budget runs low mid-record, the seal stops after the current
// window and returns a PARTIAL outcome (the prefix is durable: its segments are content-addressed). A
// later slice calls back with resumeFrom and CONTINUES, producing a result BYTE-IDENTICAL to a one-shot
// seal. The identity rests on two facts: (1) every window except the last is exactly `target` bytes, so
// offsetSealed is always a multiple of target and the resumed loop reproduces the SAME window boundaries;
// (2) the running whole-record SHA-384 is REBUILT by re-hashing the prefix [0, offsetSealed) (SHA-384 is
// associative over concatenation, so streaming the whole prefix yields the identical internal state as
// feeding it window by window), never by serialising hash state. The prefix re-hash is ONE subrequest
// (openStreamedRange), so the resume always makes forward progress regardless of prefix size, and it is
// pinned to the SAME etag the prefix was sealed under: if the object changed (etag differs, or the source
// has no stable etag, or it cannot do a one-subrequest streamed read), the OLD-byte prefix segments would
// disagree with a re-hash of the NEW bytes, so the record is ABANDONED (changed-mid-crawl) rather than
// sealed corrupt. Loud-and-recoverable beats silent-and-unrecoverable.
async function sealChainedStreamRecord(deps: RecordSealDeps, r: SourceRecord, target: number, counts: SealCounts, resumeFrom?: ResumeFrom): Promise<SealRecordOutcome> {
  const declared = r.stream!.size;
  // DEFENCE IN DEPTH against the whole-run wedge. With mid-record resume a chained value seals across as
  // many slices as it needs, but an object so large its prefix re-hash cannot complete within one slice's
  // wall/CPU budget still cannot be captured in band (MAX_SINGLE_RECORD_CONTENT_BYTES bounds the resumable
  // ceiling, derived in seal/budget.ts). The producing adapter declines an over-ceiling object at probe
  // time and emits an honest incompleteness marker (sources/byte-fetch.ts captureBlob, BEFORE any seal
  // cost), so the seal should never receive one; if one ever reaches here from another path, refuse it
  // LOUDLY and legibly (classified as a source read error by coarseRunError) rather than wedging. The bytes
  // are recoverable out of band with the downpipe CLI.
  if (declared > MAX_SINGLE_RECORD_CONTENT_BYTES) {
    throw new Error(`record ${r.name} (${declared} bytes) exceeds the ${MAX_SINGLE_RECORD_CONTENT_BYTES}-byte single-invocation in-band capture limit and cannot be sealed in one slice; recover it out of band`);
  }
  const openRange = r.stream!.openRange?.bind(r.stream!);
  if (!openRange) throw new Error(`record ${r.name} exceeds the ${target}-byte single-segment limit and its source cannot range-read`);

  let whole = nobleSha384.create();
  let segments: SegmentRef[] = [];
  let total = 0;
  let startOffset = 0;
  if (resumeFrom !== undefined) {
    // The object MUST be the same version the prefix was sealed under, or its OLD-byte prefix segments
    // would not match a re-hash of the NEW bytes. A missing/changed etag, or a source that cannot do a
    // one-subrequest streamed read, means we cannot SAFELY resume: abandon the partial (its segments are
    // orphaned, harmless and content-addressed) and report changed-mid-crawl.
    const etag = r.stream!.etag;
    const openStreamedRange = r.stream!.openStreamedRange?.bind(r.stream!);
    if (etag === undefined || resumeFrom.etag === undefined || etag !== resumeFrom.etag || openStreamedRange === undefined) {
      // G065: distinguish "the source has NO etag at all" (a legacy source that can never be resumed, so its
      // large objects are abandoned every time -- a standing product limitation, not a churn event) from "the
      // etag MOVED" (real churn). Both abandon a partial whose segments are now orphaned: count that too.
      noteSkippedChanged(etag === undefined || openStreamedRange === undefined ? "no-etag" : "etag-changed");
      notePartialAbandoned();
      return { ok: false, reason: "changed-mid-crawl" };
    }
    // Re-hash the already-sealed prefix [0, offsetSealed) in one streamed pass to rebuild the running
    // whole-record digest WITHOUT re-addressing or re-writing the prefix segments. A short read (the
    // streamed range came back the wrong length) or a 412 (the version moved) throws out of the streamed
    // source; treat that as the object changing under us rather than committing a divergent digest.
    let seen = 0;
    try {
      for await (const chunk of openStreamedRange(0, resumeFrom.offsetSealed).chunks()) {
        whole.update(chunk);
        seen += chunk.length;
      }
    } catch {
      // G065: the resume's prefix re-hash THREW -- a 403 the token lost mid-crawl, a timeout, a 412. This is an
      // INFRA fault, and recording it as ordinary churn is precisely how a persistent, fixable source-access
      // problem stayed invisible behind a green run for months.
      noteSkippedChanged("range-read-failed");
      notePartialAbandoned();
      return { ok: false, reason: "changed-mid-crawl" };
    }
    if (seen !== resumeFrom.offsetSealed) {
      noteSkippedChanged("short-read"); // the streamed range came back the wrong length
      notePartialAbandoned();
      return { ok: false, reason: "changed-mid-crawl" };
    }
    segments = [...resumeFrom.segments];
    total = resumeFrom.offsetSealed;
    startOffset = resumeFrom.offsetSealed;
  }

  for (let offset = startOffset; offset < declared; offset += target) {
    const len = Math.min(target, declared - offset);
    const attempt = await withRetry(
      async () => {
        const tap = whole.clone();
        const addr = await addressStream(deps.cak, ADDR_SINGLE_NON_SECRET, new Uint8Array(0), openRange(offset, len), tap);
        return { addr, tap };
      },
      { subsystem: "source-api" }, // G143: a windowed re-read waits on the SOURCE, not the destination
    );
    if (attempt.addr.size !== len) {
      // G065: a window came back a different length than the chain expected: the object moved under the pin.
      noteSkippedChanged("partial-mismatch");
      return { ok: false, reason: "changed-mid-crawl" };
    }
    whole = attempt.tap;
    total += len;
    const segObj = segmentObjectKey(attempt.addr.segId);
    const fileKey = await deriveNonSecretFileKey(deps.master, attempt.addr.segId, CODEC_NONE);
    if (await withRetry(() => deps.dest.exists(segObj), { subsystem: "destination" })) {
      counts.objectsSkipped++;
    } else {
      await withRetry(() => deps.dest.putStream(segObj, sealSegmentToStream(fileKey, openRange(offset, len), deps.randomNonce()), len), { ...throttleRetry(deps.throttleRetry), subsystem: "destination" });
      counts.objectsWritten++;
      counts.archiveBytesWritten += sealedSegmentLength(len);
    }
    segments.push({ object: segObj, chunkRange: [0, chunkCount(len)], packed: null });

    // Mid-record yield: AFTER sealing this window (so at least one window always seals per slice, no
    // stall), if the slice budget says yield AND windows remain, stop and hand the prefix on. A clone of
    // the running digest is kept ONLY in `whole`; nothing of the hash state is serialised (the next slice
    // re-hashes the prefix to rebuild it). The yield is suppressed when no etag is available, because such
    // a value cannot be safely resumed (the next slice would abandon it) and partial-then-abandon would
    // lose the whole record; better to push on and seal it whole this slice (the over-budget case is then
    // the platform's problem, the same as before mid-record resume existed for a no-etag source).
    const more = offset + target < declared;
    const etag = r.stream!.etag;
    if (more && etag !== undefined && r.stream!.openStreamedRange !== undefined && deps.yieldCheck?.()) {
      return { ok: "partial", offsetSealed: total, segments, etag, counts };
    }
  }
  return { ok: true, seal: { segments, plaintextSha384: hexEncode(whole.digest()), size: total }, counts };
}

// sealBufferedRecord seals a buffered value (small records, and all secrets). The address and seal
// differ for secrets: a fresh salt makes the address unique (never deduped) and the file key is bound to
// the run, record and salt (SPEC 7.2 case 0x03, 7.4), so a secrets segment is always new by construction
// and the exists probe is skipped (one subrequest saved per secret; an address collision would need a
// salt collision).
async function sealBufferedRecord(deps: RecordSealDeps, recordId: string, r: SourceRecord, secret: boolean, counts: SealCounts): Promise<SealRecordOutcome> {
  const value = r.value ?? new Uint8Array(0);
  if (secret) {
    const recordSalt = deps.randomSalt();
    const segIDBytes = await segID(deps.cak, ADDR_SECRETS, recordSalt, value);
    const segObj = segmentObjectKey(segIDBytes);
    const sealed = await sealSecretsSegment(deps.master, segIDBytes, utf8(recordId), recordSalt, deps.runIdBytes, value, deps.randomNonce());
    await withRetry(() => deps.dest.put(segObj, sealed), { ...throttleRetry(deps.throttleRetry), subsystem: "destination" });
    counts.objectsWritten++;
    counts.archiveBytesWritten += sealed.length;
    return { ok: true, seal: { segments: singleSegment(segObj, value.length), plaintextSha384: hexEncode(await sha384(value)), size: value.length, recordSalt }, counts };
  }
  const segIDBytes = await segID(deps.cak, ADDR_SINGLE_NON_SECRET, new Uint8Array(0), value);
  const segObj = segmentObjectKey(segIDBytes);
  if (await withRetry(() => deps.dest.exists(segObj), { subsystem: "destination" })) {
    counts.objectsSkipped++;
  } else {
    const sealed = await sealNonSecretSegment(deps.master, segIDBytes, CODEC_NONE, value, deps.randomNonce());
    await withRetry(() => deps.dest.put(segObj, sealed), { ...throttleRetry(deps.throttleRetry), subsystem: "destination" });
    counts.objectsWritten++;
    counts.archiveBytesWritten += sealed.length;
  }
  return { ok: true, seal: { segments: singleSegment(segObj, value.length), plaintextSha384: hexEncode(await sha384(value)), size: value.length }, counts };
}
