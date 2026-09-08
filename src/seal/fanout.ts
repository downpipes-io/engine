import { concat, hexDecode, hexEncode, u64be, utf8 } from "../crypto/bytes.ts";
import { deriveManifestWrapKey, deriveMK } from "../crypto/derive.ts";
import { sha384 } from "../crypto/primitives.ts";
import { openStream } from "../crypto/stream.ts";
import { addBundle } from "../format/bundle.ts";
import { unframeDpe } from "../format/container.ts";
import { MerkleFrontier } from "../format/frontier.ts";
import { parseShard } from "../format/record-codec.ts";
import { decodeULID } from "../format/ulid.ts";
import { VERSION } from "../format/version.ts";
import { buildSignedRoot, sealShardManifest } from "../format/writer.ts";
import { addOpCounts } from "../meter.ts";
import { hasKeySampler, type Selector, type SourceAdapter } from "../sources/types.ts";
import { DEFAULT_SLICE_SUBREQUESTS } from "./budget.ts";
import type { CheckpointCounts, RunCheckpoint } from "./checkpoint.ts";
import { zeroCounts } from "./checkpoint.ts";
import { mergeIncompleteIds } from "./marker.ts";
import { appendRunlog, destinationLocalPrev, noteHistoryChainRestart, type RunlogLock } from "./pipeline.ts";
import { throttleRetry, withRetry } from "./retry.ts";
import { noteCompleteness, noteStranded } from "./run-observations.ts";
import type { FanoutDowngradeReason } from "./seal-faults.ts";
import { DEFAULT_SHARD_MAX_RECORDS, defaultNowIso, pad5, recordIdFor, type ShardEntry, type SliceDeps, shardIdFor } from "./slice.ts";

// FANOUT_SAMPLE_CAP is the DIRECT-PLAN threshold (Fix 2b H2). A run whose WHOLE in-scope keyspace fits in
// this cheap front sample (sampleKeys returns more:false) is planned INLINE from the full sample
// (partitionKeyRange below), exactly as before. A run LARGER than the cap (more:true) cannot be planned from
// a front sample without skewing every split to the front and dumping the entire tail on the last range (the
// old skew-defer, finding H2), so it is handed to the coordinator's SLICED count-then-stride scan instead
// (planFanout returns {mode:"scan"}), which sizes BALANCED ranges over the REAL keyspace. So this cap no
// longer bounds plan QUALITY -- it only chooses the cheap inline plan vs the sliced scan. Tunable via
// SCALE_FANOUT_SAMPLE_CAP (the test drives a tiny cap so a small dataset exercises the scan path).
export const FANOUT_SAMPLE_CAP = 10_000;

// KV_LIST_PAGE_KEYS is the platform's KV list() page size (1000 keys per list subrequest, kv.ts header).
// The watermark fallback (kv.ts crawlFrom) re-lists from the namespace/prefix START and skips whole pages
// by their last key on a CURSOR-REFUSED resume, so reaching a resume watermark costs one list subrequest
// per 1000 keys BEFORE any value read or mark is emitted.
export const KV_LIST_PAGE_KEYS = 1000;

// FANOUT_MAX_RANGE_KEYS caps how many keys ONE fan-out worker range may span (H1), sized STRICTLY below the
// KV watermark-rescan ceiling so a single range can never reach the wedge where a cursor-refused resume
// re-lists past the slice subrequest budget with ZERO progress and is hard-killed every alarm -- the
// uncatchable stall that no worker strike ladder can catch. The rescan ceiling in keys is (slice subrequest
// budget) * KV_LIST_PAGE_KEYS (each fast-forward page is one list subrequest); we take a CONSERVATIVE
// quarter of the DEFAULT slice budget so the fast-forward leaves ample room for the value reads + finalise
// reserve that must follow it within the SAME slice for the worker to make progress, and so even a lowered
// SCALE_SLICE_SUBREQUESTS knob clears it. = floor(700 / 4) * 1000 = 175 000 keys, < the 700 000 ceiling.
// This is a per-range UPPER BOUND only: it cannot bound the namespace tail past FANOUT_SAMPLE_CAP (that
// even-stride re-split is the H2 skew-defer); the coordinator's no-progress strike ladder is the backstop.
export const FANOUT_MAX_RANGE_KEYS = Math.floor(DEFAULT_SLICE_SUBREQUESTS / 4) * KV_LIST_PAGE_KEYS;

// FANOUT_MAX_RANGES bounds how many ranges (and, in the one-worker-per-range model, how many WORKER DOs) a
// single fan-out run spawns, so the coordinator's sequential worker spawn AND its per-await-tick liveness
// poll both stay well inside one invocation's subrequest budget. The balanced planner (planRangeCount) sizes
// each range at min(ceil(total/N), FANOUT_MAX_RANGE_KEYS) and so wants ceil(total / that) ranges; when that
// would exceed this ceiling (a namespace past ~FANOUT_MAX_RANGES * FANOUT_MAX_RANGE_KEYS = ~90M keys) the
// count is CLAMPED here and each range grows back above the per-range cap -- exactly the residual the H1
// no-progress strike ladder already backstops (the cap was always best-effort, the ladder the real
// guarantee). A bounded-worker WORK QUEUE (keep N workers draining a queue of ceil(total/cap) ranges) is the
// tracked follow-up that lifts this ceiling without growing the worker fleet or the per-tick poll set.
// Known, untracked debt for now: the constraint, the consequence and the lifting path are all understood,
// the work is just not yet built.
export const FANOUT_MAX_RANGES = 512;

// Fan-out (Fix 2b) merge: split a high-cardinality LEX-ORDERED resumable run's key-space across N parallel
// WORKER RunSealDOs and merge their output into ONE deterministic signed archive.
//
// THE CORRECTNESS KEYSTONE (byte-identical to a single-DO serial seal). The signed Merkle root is folded
// over per-record LEAF HASHES, and a leaf hash BINDS the recordId (writer-record.ts buildRecordLine /
// format/record-codec.ts recordHashOf: sha384(VERSION||recordId||plaintextSha384||keyNameHash||size)).
// So a partition-dependent composite recordId kept in the FINAL archive would change every leaf hash and
// the root would NOT match a serial seal. Two further facts complete the picture: the shard GROUPING must
// be the global shardMax grouping (not per-range) or the signed shard LIST differs; and a worker's segment
// content addresses are recordId-INDEPENDENT for KV/R2 (segID is over the value bytes + CAK, record.ts),
// while keyNameHash is master-derived, so both match a serial seal under the SHARED master.
//
// Therefore the workers use composite ids as SCRATCH only: each worker seals its range with recordId
// `r{pad5(range)}{pad10(local)}` and shardId `{pad5(range)}{pad5(local)}`, which string-sort range-major so
// the coordinator reads every worker's scratch shards in GLOBAL key order. mergeStep then RENUMBERS each
// record to the serial `r{pad15(globalIndex)}` (re-hashing the leaf from the line's own master-/value-
// derived fields, which need no key), RE-GROUPS into shardMax FINAL shards with serial `pad5` ids, folds ONE
// global MerkleFrontier, and signs ONE root -- the byte-identical-to-serial output. Any merge/ordering/seam
// mistake makes the offline reader's INDEPENDENTLY recomputed root mismatch the signature (verify-at-seal
// flags it suspect; an offline `downpipe verify` refuses it), so a wrong root FAILS CLOSED, never restores.
//
// Fan-out is for KV first (R2 a stretch); NEVER secrets (segments bind the recordId, so a renumber would
// orphan them), D1, or API sources. The merge re-reads + decrypts every scratch shard once (bounded,
// sliced); the dominant per-record value seal stays parallel across the N workers (weeks -> hours).

// FanoutRange is one worker's HALF-OPEN key sub-range. startAfter is EXCLUSIVE, stopAt is INCLUSIVE
// (Selector.range semantics), so worker i covers (split[i-1], split[i]] and each boundary key is sealed
// exactly once. The first range omits startAfter (from the beginning), the last omits stopAt (to the end).
export interface FanoutRange {
  startAfter?: string;
  stopAt?: string;
}

// partitionKeyRange partitions a key-space into N contiguous half-open ranges from a SORTED key sample
// (the bounded planning scan's keys). Splits are chosen by EVEN sampling of the provided keys, and each
// split is an ACTUAL key, so the inclusive-stopAt/exclusive-startAfter seam covers a boundary key exactly
// once. Collapsed (duplicate) splits reduce the effective range count rather than minting an empty range.
// maxRangeKeys (H1) is an optional per-range UPPER BOUND in keys: when a resulting range would span more
// sample keys than the cap, the partition SPLITS FURTHER (extra even-spaced real-key splits) so no range
// can reach the KV watermark-rescan wedge. Absent / non-positive = no cap, in which case the output is
// BYTE-IDENTICAL to the uncapped even-N partition (the byte-identity seal contract depends on that).
// DEFER (documented): skew-aware adaptive re-split for a hot prefix, and a byte-space split when the source
// is larger than the planning-scan budget (here the caller passes whatever sample it can afford -- the cap
// bounds only the SAMPLED keys, so the tail past FANOUT_SAMPLE_CAP is the H2 skew-defer's concern).
export function partitionKeyRange(sortedKeys: string[], n: number, maxRangeKeys?: number): FanoutRange[] {
  if (!Number.isInteger(n) || n < 1) throw new Error(`fan-out range count ${n} must be a positive integer`);
  if (sortedKeys.length < 2) return [{}]; // degenerate / too-small to split (no distinct seam possible)
  const cap = maxRangeKeys !== undefined && Number.isInteger(maxRangeKeys) && maxRangeKeys > 0 ? maxRangeKeys : Number.POSITIVE_INFINITY;
  if (n === 1 && sortedKeys.length <= cap) return [{}]; // fan-out off and within the cap: the whole key-space
  // Split INDICES into the sorted sample: the even-N partition (unchanged), then CAP-FILL so no range spans
  // more than `cap` keys. With cap = +Infinity (the default) the cap-fill is skipped, so the indices -- and
  // therefore the emitted ranges -- are exactly the uncapped even-N partition.
  const idx: number[] = [];
  for (let i = 1; i < n; i++) idx.push(Math.min(Math.floor((i * sortedKeys.length) / n), sortedKeys.length - 1));
  if (Number.isFinite(cap)) {
    const bounds = [0, ...idx, sortedKeys.length];
    for (let b = 0; b < bounds.length - 1; b++) {
      const span = bounds[b + 1]! - bounds[b]!;
      if (span > cap) {
        const pieces = Math.ceil(span / cap);
        for (let p = 1; p < pieces; p++) idx.push(bounds[b]! + Math.floor((p * span) / pieces));
      }
    }
  }
  // Map the (sorted, index-deduplicated) split indices to their keys and build the half-open ranges. The
  // seam construction is shared with the balanced sliced planner (rangesFromSplitKeys), so a front-sample
  // partition and a scanned-stride partition produce identical seam bytes for the same split keys.
  return rangesFromSplitKeys([...new Set(idx)].sort((a, b) => a - b).map((i) => sortedKeys[i]));
}

// rangesFromSplitKeys builds the contiguous HALF-OPEN ranges from the ORDERED boundary keys (each is the
// inclusive stopAt of its lower range). It drops empties and collapses a split equal to the previous one, so
// every split is a real, distinct key and the inclusive-stopAt / exclusive-startAfter seam covers each
// boundary key EXACTLY ONCE. The first range omits startAfter (from the beginning); the last omits stopAt
// (to the end). Shared by partitionKeyRange (front-sample / direct plan) and the coordinator's STRIDE plan,
// so both yield byte-identical seams for the same split keys -- the byte-identity-to-serial contract.
export function rangesFromSplitKeys(splitKeys: readonly (string | undefined)[]): FanoutRange[] {
  const splits: string[] = [];
  for (const key of splitKeys) {
    if (key !== undefined && key.length > 0 && (splits.length === 0 || splits[splits.length - 1] !== key)) splits.push(key);
  }
  const ranges: FanoutRange[] = [];
  let prev: string | undefined;
  for (const s of splits) {
    ranges.push({ ...(prev !== undefined ? { startAfter: prev } : {}), stopAt: s });
    prev = s;
  }
  ranges.push({ ...(prev !== undefined ? { startAfter: prev } : {}) }); // the last range runs to the end
  return ranges;
}

// planRangeCount sizes the fan-out into M BALANCED ranges from the REAL total key count (Fix 2b H2): N (the
// operator's requested concurrency) when each range already fits the per-range cap, OR more ranges so none
// spans more than maxRangeKeys (H1's watermark-rescan cap), all clamped to maxRanges so the coordinator's
// sequential spawn + per-tick poll stay inside one invocation. A run too small to split (< 2 keys) is one
// range (the whole keyspace). When the cap would demand more than maxRanges ranges the count is clamped and
// ranges grow back over the cap -- the H1 strike ladder backstops that residual (see FANOUT_MAX_RANGES). The
// cap divisor is floor(total/cap)+1, NOT ceil(total/cap): an evenly-strided range whose stopAt is INCLUSIVE
// spans floor(total/M)+1 keys at most, so this is the smallest M that keeps EVERY range <= cap (the strict
// bound partitionKeyRange's cap-fill also holds).
export function planRangeCount(total: number, n: number, maxRangeKeys: number, maxRanges: number): number {
  if (total < 2) return 1;
  const byCap = Number.isFinite(maxRangeKeys) && maxRangeKeys > 0 ? Math.floor(total / maxRangeKeys) + 1 : 1;
  return Math.max(1, Math.min(Math.max(n, byCap), maxRanges));
}

// strideBoundaryIndices is the set of 0-based GLOBAL key indices at which a balanced M-way split falls:
// floor(i*total/M) for i in 1..M-1, clamped to total-1 and DE-DUPLICATED (a tiny total with a large M can
// map two i to the same index). These are the indices the STRIDE sub-pass captures the boundary KEY at, so
// each range spans about total/M keys. With M == N and total within the cap this equals partitionKeyRange's
// even-N split indices, so the resulting ranges -- and the sealed archive -- are byte-identical to serial.
export function strideBoundaryIndices(total: number, m: number): number[] {
  if (m < 2 || total < 2) return [];
  const out = new Set<number>();
  for (let i = 1; i < m; i++) out.add(Math.min(Math.floor((i * total) / m), total - 1));
  return [...out].sort((a, b) => a - b);
}

// FanoutPlanScan is the coordinator's BOUNDED-MEMORY state for the sliced, keys-only 2-pass plan (Fix 2b
// H2). Pass COUNT tallies the in-scope keys (only `scanned` advances); finishCount then sizes the plan and
// seeds Pass STRIDE, which re-lists and captures the boundary KEY each time the running index reaches the
// next target (only the <= M-1 `splits` grow). Neither pass ever holds the key list, so a namespace of any
// size plans inside the 128 MB isolate. The source resume token rides BESIDE this in the coordinator doc (it
// is opaque per-source state), so this object stays small and JSON-round-trippable across alarms.
export interface FanoutPlanScan {
  pass: "count" | "stride";
  scanned: number; // in-scope keys seen so far in THIS pass (the global 0-based cursor)
  total: number; // the COUNT result (0 until finishCount)
  rangeCount: number; // M (0 until finishCount)
  targets: number[]; // remaining STRIDE boundary indices (ascending), consumed as reached
  splits: string[]; // boundary keys captured so far (<= M-1)
}

// newPlanScan seeds a fresh COUNT pass.
export function newPlanScan(): FanoutPlanScan {
  return { pass: "count", scanned: 0, total: 0, rangeCount: 0, targets: [], splits: [] };
}

// countPage folds one keys-only page's in-scope key COUNT into the COUNT pass (bounded: a counter only).
export function countPage(scan: FanoutPlanScan, inScopeKeyCount: number): void {
  scan.scanned += inScopeKeyCount;
}

// finishCount completes the COUNT pass: it records the real total, sizes M (planRangeCount), computes the
// STRIDE boundary targets, and resets the cursor + splits for the STRIDE pass. minRecords is NOT applied
// here -- the coordinator compares the now-known total against it (the SCALE_FANOUT_MIN_RECORDS un-clamp),
// since a real count below the threshold should not have fanned out at all.
export function finishCount(scan: FanoutPlanScan, n: number, maxRangeKeys: number, maxRanges: number): void {
  scan.total = scan.scanned;
  scan.rangeCount = planRangeCount(scan.total, n, maxRangeKeys, maxRanges);
  scan.targets = strideBoundaryIndices(scan.total, scan.rangeCount);
  scan.pass = "stride";
  scan.scanned = 0;
  scan.splits = [];
}

// stridePage walks one keys-only page IN ORDER during the STRIDE pass, capturing the boundary key whenever
// the running global index reaches the next target. Bounded: it holds only the <= M-1 captured splits and
// drops every non-boundary key. If a live mutation makes this pass see FEWER keys than COUNT did, an
// unreached target is simply never captured (one fewer range); MORE keys fall into the final range. Either
// way the half-open seam over the keys that EXIST at crawl time still covers each exactly once.
export function stridePage(scan: FanoutPlanScan, pageKeys: readonly string[]): void {
  for (const key of pageKeys) {
    while (scan.targets.length > 0 && scan.targets[0] === scan.scanned) {
      scan.splits.push(key);
      scan.targets.shift();
    }
    scan.scanned++;
  }
}

// FanoutDecision is planFanout's verdict (Fix 2b H2): stay SERIAL, fan out DIRECTLY from the cheap front
// sample (a run whose whole keyspace fit the sample), or hand the run to the coordinator's SLICED balanced
// SCAN (a run larger than the sample, which must be counted + strided over the real keyspace to size
// balanced ranges instead of skewing every split to the sampled front).
// G189: a SERIAL verdict now carries WHY. A downpipe with fan-out ENABLED that silently downgrades to serial
// still takes days on a run the customer believes is parallel, and the pack carried nothing at all (the fan-out
// knobs are deliberately omitted from sealKnobs and the run row has no mode field). The reason is a member of the
// CLOSED FanoutDowngradeReason vocabulary; it is absent when fan-out was simply never asked for.
export type FanoutDecision = { mode: "serial"; downgradeReason?: FanoutDowngradeReason } | { mode: "direct"; ranges: FanoutRange[] } | { mode: "scan" };

// planFanout decides HOW a run seals. It returns {mode:"serial"} -- stay on the byte-identical single-DO
// path -- in every fail-safe case: fan-out off (ranges < 2), a non-LEX-ordered source (only KV today; R2 a
// stretch, D1/secrets/API never), or a run whose WHOLE keyspace fit the cheap front sample yet is below the
// min-records threshold / un-splittable. A run that fit the sample (more:false) and is big enough fans out
// DIRECTLY from that full sample (byte-identical to before). A run LARGER than the sample (more:true) returns
// {mode:"scan"}: the coordinator runs the sliced count-then-stride to size BALANCED ranges over the real
// keyspace and applies min-records against the TRUE count (the H2 fix + the SCALE_FANOUT_MIN_RECORDS
// un-clamp). Only ONE cheap bounded scan runs here; the expensive value crawl never does.
export async function planFanout(source: SourceAdapter, selector: Selector, opts: { ranges: number; minRecords: number; sampleCap?: number; maxRangeKeys?: number }): Promise<FanoutDecision> {
  if (opts.ranges < 2) return { mode: "serial" }; // fan-out off (the default): NOT a downgrade, so no reason rides
  if (!hasKeySampler(source)) return { mode: "serial", downgradeReason: "no-sampler" }; // only a LEX-ORDERED key sampler (KV) can be partitioned
  const { keys, more } = await source.sampleKeys(selector, opts.sampleCap ?? FANOUT_SAMPLE_CAP);
  if (more) return { mode: "scan" }; // larger than the front sample: the coordinator plans BALANCED ranges
  // The whole keyspace fit the sample, so the min-records gate is EXACT here (no clamp): a small run stays
  // serial rather than pay the merge's re-read + re-shard overhead.
  if (keys.length < opts.minRecords) return { mode: "serial", downgradeReason: "below-threshold" };
  if (keys.length < 2) return { mode: "serial", downgradeReason: "sample-too-small" }; // nothing to split
  // H1: cap each range below the KV watermark-rescan ceiling so no single range can wedge.
  const ranges = partitionKeyRange(keys, opts.ranges, opts.maxRangeKeys ?? FANOUT_MAX_RANGE_KEYS);
  if (ranges.length < 2) return { mode: "serial", downgradeReason: "split-collapsed" }; // the splits collapsed (e.g. a single dominant key); stay serial
  return { mode: "direct", ranges };
}

// RangeDone is a WORKER's completed-range report, posted to the coordinator's POST /range-done: its range
// index, the ordered composite-id SCRATCH shards it sealed, the records it captured, and its run counts
// (summed into the run's global counts so the signed root + /complete declare the whole run).
export interface RangeDone {
  rangeIndex: number;
  shards: ShardEntry[];
  recordCount: number;
  counts: CheckpointCounts;
}

// addCheckpointCounts sums two count tallies field by field (the coordinator folds each worker's
// /range-done counts into the run's global counts). It is pure (a fresh object), so neither input is
// mutated; opCounts is summed via the existing per-resource addOpCounts.
export function addCheckpointCounts(a: CheckpointCounts, b: CheckpointCounts): CheckpointCounts {
  // incompleteByMarker (the per-kind breakdown of recordsIncomplete, WS-D#1) is folded the SAME way as
  // recordsIncomplete: summed per marker kind, so a fanout run's global tally carries every parallel worker's
  // incompleteness markers (else a fanout-sealed run would silently report zero markers to the support pack).
  const incompleteByMarker: CheckpointCounts["incompleteByMarker"] = { ...a.incompleteByMarker };
  for (const [k, v] of Object.entries(b.incompleteByMarker) as [keyof CheckpointCounts["incompleteByMarker"], number][]) {
    incompleteByMarker[k] = (incompleteByMarker[k] ?? 0) + v;
  }
  // incompleteIds (the per-kind ATTRIBUTION, WS-P1) is UNIONed the same way -- each kind's ids merged, deduped
  // and capped -- so a fan-out run's global attribution carries every worker's shorted surfaces without dupes.
  const incompleteIds = mergeIncompleteIds(a.incompleteIds, b.incompleteIds);
  return {
    records: a.records + b.records,
    bytes: a.bytes + b.bytes,
    objectsWritten: a.objectsWritten + b.objectsWritten,
    objectsSkipped: a.objectsSkipped + b.objectsSkipped,
    archiveBytesWritten: a.archiveBytesWritten + b.archiveBytesWritten,
    recordsSkippedChanged: a.recordsSkippedChanged + b.recordsSkippedChanged,
    recordsVanished: a.recordsVanished + b.recordsVanished, // WS-P2: sum the mid-crawl vanished counts across workers
    recordsIncomplete: a.recordsIncomplete + b.recordsIncomplete,
    incompleteByMarker,
    incompleteIds,
    durationMs: a.durationMs + b.durationMs,
    opCounts: addOpCounts(a.opCounts, b.opCounts),
  };
}

// zeroFanoutCounts re-exports a fresh zero tally so the coordinator can seed its global counts without
// importing checkpoint.ts directly.
export function zeroFanoutCounts(): CheckpointCounts {
  return zeroCounts();
}

// chunkLines splits a renumbered-line buffer into batches of at most `max` lines, so the coordinator can
// persist the carried merge buffer as wrapped DO batches each under the ~128 KiB value cap (the buffer is
// < shardMax lines, ~1.5 MB at the 5000 default, so it spans several batches).
export function chunkLines(lines: Record<string, unknown>[], max: number): Record<string, unknown>[][] {
  const out: Record<string, unknown>[][] = [];
  for (let i = 0; i < lines.length; i += max) out.push(lines.slice(i, i + max));
  return out;
}

// MergeState is the coordinator's sliced-merge checkpoint (the task's "checkpointed across merge slices"):
// the FULL global-ordered scratch shard list, the read cursor into it, the next serial record/shard ids,
// the serialised global Merkle frontier, and the FINAL shards sealed so far. The carried (renumbered, not
// yet sealed) line buffer is NOT here -- like runSlice's openWrite, mergeStep returns it for the storage
// owner to persist (the DO as wrapped batches, a validator in memory), so this state object stays bounded.
export interface MergeState {
  scratchShards: ShardEntry[]; // ALL workers' scratch shards, SORTED by composite id == global key order
  nextScratch: number; // index of the next scratch shard to consume
  globalRecordIndex: number; // the next serial recordId to assign
  finalShardIndex: number; // the next serial final shardId
  frontier: { count: number; nodes: { sizeLog: number; hash: string }[] }; // the serialised global frontier
  finalShards: ShardEntry[]; // the FINAL (serial pad5) shards sealed so far
  // expectedRecordTotal (defense-in-depth under-crawl cross-check): the AUTHORITATIVE in-scope key count from
  // the COUNT pass (FanoutPlanScan.total), carried onto the merge so the finalise can cross-check the workers'
  // summed reports against an INDEPENDENT total, not just the merge-internal globalRecordIndex===counts.records
  // consistency (which a UNIFORM under-crawl would still satisfy). OPTIONAL + JSON-round-trippable: absent on a
  // DIRECT-planned run (which fanned out from the front sample with NO count pass, so there is no independent
  // total to check) and on a legacy in-flight merge doc; the cross-check is then skipped.
  expectedRecordTotal?: number;
}

// newMergeState seeds a fresh merge over the global-sorted scratch shard list. expectedRecordTotal is the
// COUNT-pass authoritative in-scope key total (SCAN-planned runs only) for the finalise under-crawl cross-check.
export function newMergeState(scratchShards: ShardEntry[], expectedRecordTotal?: number): MergeState {
  return { scratchShards: [...scratchShards].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)), nextScratch: 0, globalRecordIndex: 0, finalShardIndex: 0, frontier: { count: 0, nodes: [] }, finalShards: [], ...(expectedRecordTotal !== undefined ? { expectedRecordTotal } : {}) };
}

// MergeStepResult mirrors SliceResult: the advanced state, the carried (not-yet-sealed) renumbered line
// buffer for the owner to persist, and done. When done is true the final open shard is flushed and the
// single signed root + bundle + RUNLOG are written; recordCount is the global record total the root declares.
export interface MergeStepResult {
  state: MergeState;
  carriedLines: Record<string, unknown>[];
  done: boolean;
  recordCount?: number;
}

// renumberLine swaps a scratch line's SCRATCH composite recordId for the serial global recordId and
// recomputes its Merkle-leaf recordHash from the line's OWN fields. It needs no key: keyNameHash (the
// master-derived name MAC) is already in the line, and the leaf binds only (recordId, plaintextSha384,
// keyNameHash, plaintextSize). Because every OTHER field (name, keyNameHash, sizes, segments, descriptors)
// is value-/master-derived and unchanged, the renumbered line re-canonicalises BYTE-IDENTICALLY to the line
// a serial seal would build for the same record at the same global position. Returns the new line + the
// 48-byte leaf hash (folded into the global frontier).
export async function renumberLine(line: Record<string, unknown>, globalRecordId: string): Promise<{ line: Record<string, unknown>; recordHash: Uint8Array }> {
  const plaintextSha384 = line.plaintextSha384;
  const keyNameHash = line.keyNameHash;
  const plaintextSize = line.plaintextSize;
  if (typeof plaintextSha384 !== "string" || typeof keyNameHash !== "string" || typeof plaintextSize !== "number") {
    throw new Error("fan-out merge: scratch line is missing a hash/size field; refusing to renumber a malformed record");
  }
  const recordHash = await sha384(concat(utf8(`${VERSION} record-hash`), utf8(globalRecordId), hexDecode(plaintextSha384), hexDecode(keyNameHash), u64be(BigInt(plaintextSize))));
  return { line: { ...line, recordId: globalRecordId, recordHash: hexEncode(recordHash) }, recordHash };
}

// readScratchShard fetches one worker SCRATCH shard, verifies its sha384 against the worker's report (a
// corrupted scratch shard must never be merged), decrypts it under the SHARED master's manifest-wrap key,
// and returns its raw record lines IN SEAL ORDER. A missing/short/mismatched shard throws so the merge
// fails LOUD (retryable) rather than sign a truncated archive. One metered dest read.
// ScratchShardError (gap G108) TYPES a refused scratch-shard read with the CLOSED kind the seal-fault ring
// records, so the merge can observe WHICH refusal fired without any classifier ever reading the message. The
// three cases are three different investigations: a MISSING object is a lifecycle rule / bulk delete that ate
// the scratch prefix (or a worker that never wrote it); a HASH MISMATCH means the bytes are there and CHANGED
// (corruption or tamper, never a lifecycle event); a PREAMBLE MISMATCH is a cross-run mix-up. The messages are
// unchanged, so coarseRunError and the strike ladder behave exactly as before.
export class ScratchShardError extends Error {
  readonly cls: "scratch-shard-missing" | "scratch-hash-mismatch" | "scratch-preamble-mismatch";
  constructor(cls: "scratch-shard-missing" | "scratch-hash-mismatch" | "scratch-preamble-mismatch", message: string) {
    super(message);
    this.name = "ScratchShardError";
    this.cls = cls;
  }
}

async function readScratchShard(deps: SliceDeps, mk: Uint8Array, runIdBytes: Uint8Array, runId: string, entry: ShardEntry): Promise<Record<string, unknown>[]> {
  deps.budget.spend(1);
  const got = await withRetry(() => deps.dest.get(entry.object), throttleRetry(deps.throttleRetry));
  if (!got) throw new ScratchShardError("scratch-shard-missing", `fan-out merge: scratch shard ${entry.id} (${entry.object}) is missing; refusing to sign a truncated archive`);
  if (hexEncode(await sha384(got.body)) !== entry.sha384) throw new ScratchShardError("scratch-hash-mismatch", `fan-out merge: scratch shard ${entry.id} hash does not match the worker report`);
  const wrapKey = await deriveManifestWrapKey(mk, runIdBytes, entry.id);
  const { preamble, recs } = parseShard(await openStream(wrapKey, unframeDpe(got.body)));
  if (preamble.runId !== runId || preamble.shardId !== entry.id) throw new ScratchShardError("scratch-preamble-mismatch", `fan-out merge: scratch shard ${entry.id} preamble does not match the run`);
  return recs as unknown as Record<string, unknown>[];
}

// FanoutDefaults bundles the per-step injectables (the nonce source + clock) so mergeStep keeps under the
// positional-parameter limit; both default to production values when absent.
function nonceFor(deps: SliceDeps): () => Uint8Array {
  return deps.randomNonce ?? (() => crypto.getRandomValues(new Uint8Array(16)));
}

// sealOneShard seals a manifest shard (preamble + the given lines) under the SHARED master at the given
// shardId and records it. It is the byte-identical analogue of slice.ts flushShard / finaliseRun.sealFinal,
// used both for a worker's leftover OPEN shard (composite id) and for the merge's FINAL shards (serial id).
async function sealOneShard(deps: SliceDeps, cp: RunCheckpoint, master: Uint8Array, shardId: string, lines: Record<string, unknown>[]): Promise<ShardEntry> {
  const nowIso = deps.nowIso ?? defaultNowIso;
  const shard = await sealShardManifest({ master, runId: cp.runId, shardId, downpipeName: cp.downpipeName, cadence: cp.cadence, sourceType: cp.sourceType, windowStart: cp.startedAt, windowEnd: nowIso(), recordLines: lines, randomNonce: nonceFor(deps) });
  deps.budget.spend(1); // the manifest-shard put is a platform subrequest on the merge slice's budget
  await withRetry(() => deps.dest.put(shard.object, shard.bytes), throttleRetry(deps.throttleRetry));
  return { id: shardId, object: shard.object, sha384: shard.sha384Hex };
}

// sealRangeOpenShard is the WORKER's range-finalise step: it seals the leftover OPEN shard (the lines a
// worker buffered across slices but never reached shardMax to flush) as ONE more composite SCRATCH shard at
// the worker's next local shard index, so the range's records are all durably sharded before the worker
// reports /range-done. Returns the new shard entry, or null when the open shard is empty (nothing to seal).
export async function sealRangeOpenShard(deps: SliceDeps, cp: RunCheckpoint, master: Uint8Array, openShardLines: Record<string, unknown>[]): Promise<ShardEntry | null> {
  if (openShardLines.length === 0) return null;
  return sealOneShard(deps, cp, master, shardIdFor(cp.nextShardIndex, cp.rangeIndex), openShardLines);
}

// mergeStep advances the coordinator's sliced merge by one budget's worth of scratch shards. It reads each
// scratch shard in global order, RENUMBERS its records to the serial global id, folds their leaf hashes into
// the global frontier, and RE-GROUPS the renumbered lines into shardMax FINAL shards (the byte-identical
// serial grouping). It returns the advanced state + the carried (not-yet-sealed) line buffer (the owner
// persists it, exactly as runSlice returns openWrite) + done. When all scratch is consumed it flushes the
// final open shard, then builds and writes the SINGLE signed root + recovery bundle + RUNLOG entry -- the
// same finalise the serial finaliseRun runs, so the archive is byte-identical to a single-DO seal.
//
// COMPLETENESS GUARD (the task's "count merged ranges"): on done it asserts the records actually merged
// (globalRecordIndex) equals the run's declared global record count (cp.counts.records, summed from the
// worker /range-done reports). A missing/short scratch shard makes them disagree, so the merge FAILS LOUD
// before signing rather than declare a count the shards do not hold (which the offline reader flags
// incomplete). The frontier is checkpointed in state, so a crash resumes the merge without re-reading
// consumed scratch shards or re-folding their hashes.
export async function mergeStep(deps: SliceDeps, cp: RunCheckpoint, master: Uint8Array, st: MergeState, carriedLines: Record<string, unknown>[], lock?: RunlogLock): Promise<MergeStepResult> {
  const shardMax = deps.shardMaxRecords ?? DEFAULT_SHARD_MAX_RECORDS;
  const runIdBytes = decodeULID(cp.runId);
  const mk = await deriveMK(master, runIdBytes);
  const frontier = MerkleFrontier.deserialise(st.frontier);
  const buffer = [...carriedLines];
  const finalShards = [...st.finalShards];
  let nextScratch = st.nextScratch;
  let globalRecordIndex = st.globalRecordIndex;
  let finalShardIndex = st.finalShardIndex;

  // sealFromBuffer seals the next shardMax (or all remaining, for the closing shard) buffered lines as one
  // FINAL serial shard.
  const sealFromBuffer = async (): Promise<void> => {
    const lines = buffer.splice(0, shardMax);
    finalShards.push(await sealOneShard(deps, cp, master, pad5(finalShardIndex), lines));
    finalShardIndex++;
  };

  // Consume scratch shards until the budget says yield (a soft, between-shards boundary, so a shard's
  // records and any final shard they trigger are always processed together). At least ONE scratch shard is
  // consumed per step regardless of the budget, so the merge always makes forward progress and can never
  // wedge on a slice whose fresh budget is already near the finalise reserve (the runSlice "one window per
  // slice" discipline applied to the merge).
  let consumedThisStep = 0;
  while (nextScratch < st.scratchShards.length) {
    if (consumedThisStep > 0 && deps.budget.shouldYield()) break;
    // G108: OBSERVE the refusal with the counts the merge already holds -- how many scratch shards merged
    // CLEANLY before this one, and how many the run declared -- then re-throw UNCHANGED. The refuse-to-sign
    // decision is untouched; this is the evidence a run that produced NO ARCHIVE would otherwise lose entirely.
    let lines: Record<string, unknown>[];
    try {
      lines = await readScratchShard(deps, mk, runIdBytes, cp.runId, st.scratchShards[nextScratch]!);
    } catch (e) {
      if (e instanceof ScratchShardError) noteCompleteness(e.cls, nextScratch, st.scratchShards.length, nextScratch);
      throw e;
    }
    for (const line of lines) {
      const { line: renumbered, recordHash } = await renumberLine(line, recordIdFor(globalRecordIndex));
      buffer.push(renumbered);
      await frontier.append(recordHash);
      globalRecordIndex++;
      // Re-group into the global shardMax grouping the serial path produces (NOT the per-range scratch
      // grouping): flush a FINAL shard the instant shardMax renumbered lines have accumulated.
      if (buffer.length >= shardMax) await sealFromBuffer();
    }
    nextScratch++;
    consumedThisStep++;
  }

  const advanced: MergeState = { ...st, nextScratch, globalRecordIndex, finalShardIndex, frontier: frontier.serialise(), finalShards };
  if (nextScratch < st.scratchShards.length) {
    // More scratch remains: hand the carried leftover buffer back for the owner to persist and resume.
    return { state: advanced, carriedLines: buffer, done: false };
  }

  // All scratch consumed: this is the finalise. Seal the closing shard (the leftover < shardMax lines), or
  // an empty parity shard for a 0-shard run, exactly as finaliseRun does, so a sliced and a one-shot merge
  // (and a serial seal) all emit the same shard set.
  if (buffer.length > 0) await sealFromBuffer();
  else if (finalShards.length === 0) await sealFromBuffer();

  // Completeness guard: the merged record total must equal the run's declared global count.
  if (globalRecordIndex !== cp.counts.records) {
    // G108: the merged-vs-declared delta is what SIZES the shortfall. It existed only in this message.
    noteCompleteness("merge-count-mismatch", globalRecordIndex, cp.counts.records);
    throw new Error(`fan-out merge incomplete: merged ${globalRecordIndex} records but the run declares ${cp.counts.records}; refusing to sign a count the shards do not hold`);
  }
  // Defense-in-depth UNDER-CRAWL cross-check (SCAN-planned runs only). The guard above proves the merge is
  // INTERNALLY consistent -- it re-read exactly as many records as the workers REPORTED -- but a UNIFORM
  // under-crawl (every worker honestly reporting a range it silently crawled short) satisfies it, because both
  // sides derive from the same under-crawled worker data. So ALSO cross-check the workers' reports against the
  // INDEPENDENT COUNT-pass total (FanoutPlanScan.total): the keys the workers ENCOUNTERED -- sealed
  // (counts.records) PLUS etag-changed-and-skipped (counts.recordsSkippedChanged) -- must be AT LEAST the
  // in-scope keys the count pass found. A SHORTFALL means a range crawl dropped keys the count pass saw, a
  // potential SILENT PARTIAL, so FAIL LOUD rather than sign a run short of its own authoritative key count.
  // Only a SHORTFALL fails: keys ADDED between the count and the crawl legitimately RAISE the encountered
  // total (no data loss), and a record CHANGED mid-run is counted via recordsSkippedChanged so a normal churn
  // change is not read as a shortfall. The one accepted false-positive is bulk key DELETION between the count
  // and the crawl (encountered < counted); failing loud + retrying next cadence on a FRESH count is the safe
  // direction given the silent-partial aversion (a failed run is loud and recoverable; a silent partial is
  // not). SKIPPED when expectedRecordTotal is absent (a DIRECT-planned run has no independent count pass).
  if (st.expectedRecordTotal !== undefined) {
    const encountered = cp.counts.records + cp.counts.recordsSkippedChanged;
    if (encountered < st.expectedRecordTotal) {
      // G108: encountered-vs-counted is the ONLY signal that separates the accepted false positive (a benign bulk
      // DELETION between the count pass and the crawl) from a real under-crawl. Both fail the run closed; the
      // delta tells support which one it was, rather than the run dying with only the bare exception.
      noteCompleteness("under-crawl", encountered, st.expectedRecordTotal);
      throw new Error(`fan-out under-crawl: workers encountered ${encountered} in-scope keys but the count pass found ${st.expectedRecordTotal}; refusing to sign a run short of its authoritative key count`);
    }
  }
  finalShards.sort((a, b) => Number(a.id) - Number(b.id));

  const nowIso = deps.nowIso ?? defaultNowIso;
  const localPrev = await destinationLocalPrev(deps.dest, cp.downpipeId, cp.runlogIndex);
  // G283: a prior run SUCCEEDED (the scheduler's prevRunId) yet this destination's RUNLOG has no entry to
  // chain onto -- the downpipe was repointed at a re-created or wrong bucket, and the root about to be signed
  // will restart the history chain with prevRunId=null. Unchanged behaviour; recorded evidence.
  noteHistoryChainRestart(localPrev, cp.prevRunId, cp.runlogIndex);
  const { rootBytes, sigBytes } = await buildSignedRoot({
    downpipeId: cp.downpipeId,
    runId: cp.runId,
    createdAt: nowIso(),
    master,
    recipients: deps.recipients,
    signer: deps.signer,
    shards: finalShards,
    declaredRecordCount: cp.counts.records,
    merkleRootHex: hexEncode(await frontier.root()),
    prevRunId: localPrev,
    runlogIndex: cp.runlogIndex,
    randomNonce: nonceFor(deps),
  });
  await withRetry(() => deps.dest.put(`run/${cp.runId}/root.manifest.json`, rootBytes), throttleRetry(deps.throttleRetry));
  await withRetry(() => deps.dest.put(`run/${cp.runId}/root.manifest.json.sig`, sigBytes), throttleRetry(deps.throttleRetry));

  const bundleObjects = new Map<string, Uint8Array>();
  await addBundle(bundleObjects, deps.signer.edPrivate, deps.signer.mldsaSecret);
  for (const [k, v] of bundleObjects) {
    await withRetry(() => deps.dest.put(k, v), throttleRetry(deps.throttleRetry));
  }

  await appendRunlog(
    deps.dest,
    deps.signer,
    { index: cp.runlogIndex, runId: cp.runId, downpipeId: cp.downpipeId, time: nowIso(), recordCount: cp.counts.records, prevRunId: localPrev, status: "active" },
    lock,
    { relinkLocalPrev: true },
  );

  return { state: { ...advanced, finalShards, frontier: frontier.serialise() }, carriedLines: [], done: true, recordCount: globalRecordIndex };
}

// deleteScratchShards reclaims the worker SCRATCH manifest objects after a successful merge: the signed
// root lists only the FINAL shards, so the composite-id scratch shards are unreferenced and would otherwise
// linger under manifest/. It NEVER touches seg/ blobs (the final shards reference them) and is best-effort:
// a failed delete only leaves a harmless orphan a reconcile pass reclaims, never affecting the sealed run.
export async function deleteScratchShards(deps: SliceDeps, scratchShards: ShardEntry[]): Promise<void> {
  for (const s of scratchShards) {
    try {
      await deps.dest.delete(s.object);
    } catch {
      // best-effort: an immutable/WORM destination or a transient fault leaves the scratch shard as an
      // orphan (not in the signed root, so harmless); a reconcile/GC pass reclaims it.
      //
      // G066: on a WORM / Object-Lock bucket this catch fires for EVERY scratch shard of EVERY fan-out run, so
      // the archive bucket grows far faster than the data -- permanently, and with no evidence anywhere. The
      // swallow is unchanged (a failed cleanup must never fail a sealed run); it is now COUNTED, which is the
      // only thing that makes "why is my bucket so big?" answerable.
      noteStranded("scratch-delete-failed");
    }
  }
}
