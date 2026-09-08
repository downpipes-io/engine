import { sha384 as nobleSha384 } from "@noble/hashes/sha2.js";
import { b64urlDecode, concat, constantTimeEqual, hexDecode, hexEncode, utf8 } from "../crypto/bytes.ts";
import { openCapsule, parseWraps } from "../crypto/capsule.ts";
import { deriveManifestWrapKey, deriveMK, deriveNonSecretFileKey, deriveSecretsFileKey, keyCommitment } from "../crypto/derive.ts";
import type { HybridRecipientPrivate } from "../crypto/kem.ts";
import { openNonSecretSegment, openSecretsSegment } from "../crypto/segment.ts";
import { type HybridVerifier, hybridVerify } from "../crypto/sign.ts";
import { openStream, openStreamToStream } from "../crypto/stream.ts";
import { verifyBundle } from "./bundle.ts";
import { validateCanonicalCounts } from "./canonnum.ts";
import { unframeDpe, unframeSeg } from "./container.ts";
import { checkRunlogFreshness, type FreshnessOptions, type FreshnessResult } from "./freshness.ts";
import { freshnessError, freshnessUnverifiableError, integrityError, isIntegrityFailure } from "./integrity-error.ts";
import type { RootManifest, ShardRecord } from "./manifest.ts";
import { merkleRoot } from "./merkle.ts";
import {
  capStream,
  gunzip,
  parseShard,
  recordHashOf,
  segIDFromObject,
  segmentChunkBound,
  segmentStreamChunks,
  sha384Hex,
} from "./record-codec.ts";
import { checkFormatVersion, checkRecipientSet, checkRootStructure } from "./structural-gates.ts";
import { decodeULID, isValidRunId } from "./ulid.ts";
import { CODEC_GZIP, CODEC_NAME_GZIP, CODEC_NAME_NONE, CODEC_NONE, KNOWN_SOURCE_TYPES } from "./version.ts";

// The in-account verifying reader, a TypeScript port of the Go offline reader. It is the
// second independent reader the recovery story promises, used by the engine for the
// emit-and-readback drill, and the cross-implementation proof that the engine's port
// reads a real Go archive.

// ObjectStore is defined in the leaf ./types.ts to break the reader<->freshness cycle.
// Re-exported here so existing `import { ObjectStore } from "./reader.ts"` callers keep working.
export type { ObjectStore } from "./types.ts";

import type { ObjectStore } from "./types.ts";

// The Tier 0 keyless attestation lives in ./keyless.ts. Re-exported here so existing
// `import { attestKeyless } from "./reader.ts"` callers keep working.
export { attestKeyless, type KeylessAttestation } from "./keyless.ts";

// asPresentIntegrityFailure re-throws a failure raised while DECRYPTING or PARSING bytes that were ALREADY
// FETCHED from the store as a STRUCTURED integrity failure. A store.get that RETURNED bytes proves the object
// is PRESENT, so a subsequent AES-256-GCM tag / container-framing / codec / shard-parse failure is a
// DAMAGED-BACKUP (tamper / corruption) signal, NOT an availability fault. The lower crypto / container / codec
// layers throw a PLAIN Error whose message carries no integrity keyword, so without this the shared
// classifyRestoreFailure would default it to the availability catch-all ("recovery check failed") and a
// present-but-corrupt object would read as AVAILABILITY: the operator would be sent to check bucket / creds,
// and the restore path's 3-2-1 fallback could try a replica -- the exact inconsistency where a MISSING segment
// already classifies as integrity (INT-3) while a CORRUPT one did not. It is applied ONLY to the post-fetch
// decrypt / parse; the store.get itself stays OUTSIDE it, so a genuine fetch / network / 404 / status fault
// still surfaces as an availability reason. An already-typed RunIntegrityError (the reader's own integrity /
// freshness throws, and the wrapped "object ... is missing" completeness error) is passed through UNCHANGED so
// its category is preserved. It returns `never`, so a call site reads as a terminating statement.
function asPresentIntegrityFailure(e: unknown): never {
  if (isIntegrityFailure(e)) throw e;
  throw integrityError((e as Error)?.message || "a present object failed to decrypt or parse");
}

/**
 * A verified, opened run, returned by openRun. It holds the signed root, the recovered records and
 * the freshness result, and exposes restoreRecord to reassemble and verify one record's value
 * (the master and run id stay private). Constructing a Run directly bypasses verification; obtain
 * one from openRun.
 */
export class Run {
  readonly root: RootManifest;
  readonly records: ShardRecord[];
  readonly freshness: FreshnessResult | null;
  private store: ObjectStore;
  private master: Uint8Array;
  // Whether THIS object owns the master buffer. False when the caller supplied it
  // (openRunWithMaster), in which case dispose() must not touch it: the buffer belongs to the caller and
  // may be reused for another run, which is exactly what validate-restore-from-master.ts does.
  private ownsMaster: boolean;
  private runIDBytes: Uint8Array;

  constructor(store: ObjectStore, root: RootManifest, master: Uint8Array, ownsMaster: boolean, runIDBytes: Uint8Array, records: ShardRecord[], freshness: FreshnessResult | null) {
    this.store = store;
    this.root = root;
    this.master = master;
    this.ownsMaster = ownsMaster;
    this.runIDBytes = runIDBytes;
    this.records = records;
    this.freshness = freshness;
  }

  // dispose zeroises the run master this object holds.
  //
  // WHY IT IS NOT DONE IN THE CONSTRUCTOR. restoreRecord and decryptedSegments derive segment keys from
  // this.master lazily, so the master must live as long as the Run does. That makes the lifetime the
  // CALLER'S to end, and every call site therefore closes its Run in a finally.
  //
  // The path that makes this matter is attended verification. openRunWithMaster takes a master the operator
  // decapsulated in their own browser, and the posture's claim is that the key is gone when the session
  // ends. Leaving it live in the object until garbage collection is not that claim, so the object gets an
  // explicit end.
  //
  // Idempotent: filling an already-zeroed buffer is a no-op, so a caller may dispose twice without guarding.
  //
  // A SUPPLIED master is left alone. openRunWithMaster takes the caller's buffer, and a caller may open
  // several runs from one master or reuse it after a failure, so wiping it here would destroy something this
  // object never owned. Those callers zeroise their own buffer in their own finally, which is where the
  // knowledge of when it is finished with actually lives.
  dispose(): void {
    if (this.ownsMaster) this.master.fill(0);
  }

  // restoreRecord reassembles and verifies one record's value (SPEC 7.4, 8.3).
  async restoreRecord(rec: ShardRecord): Promise<Uint8Array> {
    const parts: Uint8Array[] = [];
    for (const seg of rec.segments) {
      const segIDBytes = segIDFromObject(seg.object);
      const segBytes = await this.store.get(seg.object);
      // Bound the read to the segment's signed chunkRange and reject a range that disagrees
      // with the sealed segment (SPEC 6.3, 14.5), exactly as the Go reference reader's
      // openSegment does. maxChunks (= lastChunkExclusive) stops a segment longer than its
      // declared range mid-stream (also the missing memory ceiling); the count check below
      // closes the other side, rejecting a range that over-states the real chunk count, so the
      // TS reader and a Go `downpipe verify` agree on accept/reject.
      const maxChunks = segmentChunkBound(rec.recordId, seg.chunkRange);
      // segBytes was fetched above (present); a decrypt / AEAD-tag / container-framing failure from the
      // segment-open below is therefore a DAMAGED-BACKUP integrity fault, never availability, so re-label it
      // (asPresentIntegrityFailure). The store.get stays outside this, so a genuine fetch fault (404 / status /
      // network) still classifies as availability, while a present-but-corrupt segment classifies as integrity
      // exactly as a MISSING segment already does (INT-3) -- and as the restore apply/verify passes already do.
      let plain: Uint8Array;
      if (rec.sourceType === "secrets") {
        if (rec.recordId.length !== 16) throw integrityError(`recordId must be 16 bytes`);
        const salt = b64urlDecode(rec.recordSalt ?? "");
        if (salt.length !== 16) throw integrityError(`recordSalt must be 16 bytes`);
        plain = await openSecretsSegment(this.master, segIDBytes, utf8(rec.recordId), salt, this.runIDBytes, segBytes, maxChunks).catch(asPresentIntegrityFailure);
      } else {
        const codecID = rec.codec === CODEC_NAME_GZIP ? CODEC_GZIP : CODEC_NONE;
        plain = await openNonSecretSegment(this.master, segIDBytes, codecID, segBytes, maxChunks).catch(asPresentIntegrityFailure);
      }
      // The segment's STREAM must terminate exactly at lastChunkExclusive, not merely at or
      // before it: a chunkRange that over-states the segment's chunk count is rejected here
      // (the Go whole-segment 6.3 rule, reader.go's segmentStreamChunks(plain.Len()) check).
      const got = segmentStreamChunks(plain.length);
      if (got !== maxChunks) {
        throw integrityError(`record ${rec.recordId} segment ${seg.object} terminates after ${got} chunks but chunkRange declares ${maxChunks}`);
      }
      parts.push(plain);
    }
    let value = concat(...parts);
    // A packed record owns a byte slice of one shared segment's decrypted bytes, so the
    // packed field is only meaningful on a single-segment record. Mirroring the Go reference
    // reader (reader.go), a record that carries a packed slice on any segment of a
    // multi-segment chain is a malformed shape: reject it rather than silently ignore the
    // stray field. The bounds check below never overflows because it compares length against
    // the remaining space instead of computing offset+length on attacker-controlled values.
    if (rec.segments.length === 1 && rec.segments[0]!.packed) {
      const p = rec.segments[0]!.packed;
      const n = value.length;
      if (p.offset < 0 || p.length < 0 || p.offset > n || p.length > n - p.offset) {
        throw integrityError(`record ${rec.recordId} packed slice out of range`);
      }
      value = value.subarray(p.offset, p.offset + p.length);
    } else {
      for (const seg of rec.segments) {
        if (seg.packed) throw integrityError(`record ${rec.recordId} mixes a packed slice with a multi-segment chain`);
      }
    }
    if (rec.codec === CODEC_NAME_GZIP) {
      value = await gunzip(value, rec.plaintextSize, rec.recordId);
    }
    if ((await sha384Hex(value)) !== rec.plaintextSha384) {
      throw integrityError(`record ${rec.recordId} failed its plaintext hash check`);
    }
    return value;
  }

  // restoreRecordStream is the CONSTANT-MEMORY counterpart of restoreRecord (SPEC 7.4, 8.3): it
  // returns the record's verified plaintext as a ReadableStream WITHOUT ever holding the whole value
  // (or a whole segment) in memory, so a value far larger than a Worker isolate can be restored. It
  // is the recovery-path dual of the seal side's sealSegmentToStream.
  //
  // INTEGRITY MODEL (identical strength to the buffered restoreRecord, just reordered): the buffered
  // path is "buffer the whole value, verify, then write"; this path is "verify the assembly, stream
  // authenticated chunks, then verify the final hash". The guarantees are the same and no
  // unverified byte is ever emitted:
  //   1. Pre-stream assembly check. Every segment's signed chunkRange is validated (segmentChunkBound)
  //      and a packed slice -- which is a single-segment, inherently-small shape the engine writer
  //      never emits and which cannot be sub-sliced with bounded memory -- is refused, exactly as the
  //      buffered path validates before it decrypts.
  //   2. Per-chunk authentication. openStreamToStream decrypts each 64 KiB chunk under AES-256-GCM and
  //      EMITS A CHUNK ONLY AFTER its tag verifies, so every byte that leaves this stream is
  //      authenticated; a GCM failure errors the stream rather than yielding unauthenticated bytes.
  //   3. Per-segment termination. Each segment must terminate at EXACTLY its declared chunkRange
  //      (segmentStreamChunks === maxChunks), the Go whole-segment 6.3 rule, so a segment cannot be
  //      truncated or over-stated mid-chain.
  //   4. Final content address. An incremental SHA-384 is threaded over all emitted plaintext and, at
  //      end of the last segment, checked against rec.plaintextSha384 (the same whole-record hash the
  //      buffered path checks); a mismatch errors the stream before it closes. The sink only commits
  //      the object once the stream completes, so a final-hash failure aborts the restore.
  // The caller is responsible for routing only the streamable shape here (a non-secret, non-packed
  // record); this method asserts those preconditions as defence in depth.
  restoreRecordStream(rec: ShardRecord): ReadableStream<Uint8Array> {
    // (0) Precondition, made real per the doc contract: a secrets record must never take the streaming
    // path (the caller routes only non-secret records here). shouldStream gates on sourceType === "r2",
    // so this never fires for a real caller; it is defence in depth against a future routing change.
    if (rec.sourceType === "secrets") throw integrityError(`restoreRecordStream does not handle secrets records; use the buffered restoreRecord path`);
    // (1) Assembly check, up front and key-free, mirroring restoreRecord's pre-decrypt validation.
    // A packed record is single-segment and small (the engine writer never packs); a sub-slice of a
    // segment cannot be produced with bounded memory, so refuse it and let the caller fall back to
    // the buffered path. maxChunks per segment comes from the signed chunkRange.
    const segBounds: number[] = [];
    for (const seg of rec.segments) {
      if (seg.packed) throw integrityError(`record ${rec.recordId} is packed and cannot be streamed; restore it with the buffered path`);
      segBounds.push(segmentChunkBound(rec.recordId, seg.chunkRange));
    }

    // The decrypted (codec-encoded) plaintext stream, driven one chunk per pull off the generator (a
    // module-level helper, finding 031-02). A generator error (a missing object, a GCM failure, a
    // chunkRange mismatch) surfaces as a stream error to the consumer.
    const gen = decryptedSegments(rec, segBounds, this.store, this.master, this.runIDBytes);
    const plaintext = new ReadableStream<Uint8Array>({
      async pull(controller): Promise<void> {
        try {
          const { done, value } = await gen.next();
          if (done) controller.close();
          else controller.enqueue(value);
        } catch (e) {
          controller.error(e);
        }
      },
      async cancel(reason): Promise<void> {
        await gen.return(undefined).catch(() => {});
        void reason;
      },
    });

    // The codec + final-hash pipeline is finaliseStream (finding 031-02).
    return finaliseStream(plaintext, rec);
  }
}

// decryptedSegments yields the decrypted, still-codec-encoded plaintext of every segment of a record IN
// ORDER. It opens one segment object at a time and streams its chunks through openStreamToStream, counting
// chunks and bytes per segment so it can enforce the chunkRange ceiling (a too-long segment is stopped
// mid-stream) and the terminate-exactly check (a too-short segment is rejected at its end). Nothing is
// concatenated: each chunk flows straight downstream. Extracted from restoreRecordStream per finding
// engine-src-031-02 so the per-segment decrypt loop is independently testable.
async function* decryptedSegments(rec: ShardRecord, segBounds: number[], store: ObjectStore, master: Uint8Array, runIDBytes: Uint8Array): AsyncGenerator<Uint8Array> {
  const recordId = rec.recordId;
  for (let s = 0; s < rec.segments.length; s++) {
    const seg = rec.segments[s]!;
    const maxChunks = segBounds[s]!;
    const segIDBytes = segIDFromObject(seg.object);
    const segBytes = await store.get(seg.object);
    // Derive the segment file key exactly as the buffered openNonSecretSegment / openSecretsSegment
    // do, then STREAM-open the unframed .seg container.
    let fileKey: Uint8Array;
    if (rec.sourceType === "secrets") {
      if (recordId.length !== 16) throw integrityError(`recordId must be 16 bytes`);
      const salt = b64urlDecode(rec.recordSalt ?? "");
      if (salt.length !== 16) throw integrityError(`recordSalt must be 16 bytes`);
      fileKey = await deriveSecretsFileKey({ master, segIDBytes, recordID: utf8(recordId), recordSalt: salt, runIDBytes });
    } else {
      const codecID = rec.codec === CODEC_NAME_GZIP ? CODEC_GZIP : CODEC_NONE;
      fileKey = await deriveNonSecretFileKey(master, segIDBytes, codecID);
    }
    // segBytes was fetched above (present); from the unframe + per-chunk AEAD decrypt through the
    // terminate-exactly check, any failure is a DAMAGED-BACKUP integrity fault, never availability. The whole
    // post-fetch decrypt/parse is wrapped and re-labelled (asPresentIntegrityFailure) so it matches the
    // buffered restoreRecord path and the MISSING-segment INT-3 classification; store.get stays outside, so a
    // genuine fetch fault (404 / status / network) still classifies as availability. The reader's own
    // chunk-range / terminate integrity throws pass through unchanged. A consumer-driven gen.return() (stream
    // cancel) resolves the yield with a return completion, which runs the inner finally without entering this
    // catch, so cancellation still releases the upstream reader exactly as before.
    try {
      const reader = openStreamToStream(fileKey, unframeSeg(segBytes)).getReader();
      let chunks = 0;
      let segLen = 0;
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks++;
          // The chunkRange is the upper ceiling: a segment that emits more chunks than its signed
          // range is rejected mid-stream (the missing memory ceiling the buffered openStream's
          // maxChunks enforces), before the extra plaintext is yielded downstream.
          if (chunks > maxChunks) throw integrityError(`record ${recordId} segment ${seg.object} exceeds its ${maxChunks}-chunk range`);
          segLen += value.length;
          yield value;
        }
      } finally {
        await reader.cancel().catch(() => {});
      }
      // The segment must terminate at EXACTLY lastChunkExclusive, not merely at or before it: a
      // chunkRange that over-states the segment's chunk count is rejected here (the Go
      // whole-segment 6.3 rule, restoreRecord's segmentStreamChunks(plain.length) check).
      const got = segmentStreamChunks(segLen);
      if (got !== maxChunks) {
        throw integrityError(`record ${recordId} segment ${seg.object} terminates after ${got} chunks but chunkRange declares ${maxChunks}`);
      }
    } catch (e) {
      asPresentIntegrityFailure(e);
    }
  }
}

// finaliseStream applies the run-wide codec stage (gunzip when CODEC_NAME_GZIP, capped at plaintextSize so
// an over-long decompression cannot blow memory) and the final incremental-SHA-384 stage to a record's
// decrypted plaintext stream. The hash is checked against rec.plaintextSha384 at end of stream; until it
// matches the stream does not close cleanly, so the sink commits only on a clean close and a final-hash
// failure aborts the restore. Extracted from restoreRecordStream per finding engine-src-031-02.
function finaliseStream(plaintext: ReadableStream<Uint8Array>, rec: ShardRecord): ReadableStream<Uint8Array> {
  const recordId = rec.recordId;
  let coded = plaintext;
  if (rec.codec === CODEC_NAME_GZIP) {
    // DecompressionStream's writable is typed to accept BufferSource; narrow the pair to the
    // Uint8Array shape pipeThrough expects (the same coercion the buffered gunzip sidesteps via a
    // Response body). The bytes are unchanged.
    const ds = new DecompressionStream("gzip") as unknown as ReadableWritablePair<Uint8Array, Uint8Array>;
    coded = coded.pipeThrough(ds).pipeThrough(capStream(rec.plaintextSize, recordId));
  }
  const expected = rec.plaintextSha384;
  const digest = nobleSha384.create();
  return coded.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller): void {
        digest.update(chunk);
        controller.enqueue(chunk);
      },
      flush(controller): void {
        const got = hexEncode(digest.digest());
        if (got !== expected) {
          controller.error(new Error(`record ${recordId} failed its plaintext hash check`));
          return;
        }
      },
    }),
  );
}

// signerMismatchHint refines a root-signature failure. It best-effort reads the archive's
// signingKeyFingerprint hint from the (as-yet unverified) root bytes and compares it to the CURRENT
// pinned verifier's fingerprint, recomputed by the same formula the writer stamps. A mismatch means the
// archive was signed by a DIFFERENT signer than the one now pinned, almost always because the operator
// ROTATED the signer after this run was sealed, not because the bytes were tampered. The hint is read only
// to make the error actionable (the signature still failed and the open still fails closed); reading an
// unverified field for a message, never a trust decision, is safe. Returns "" when the fingerprints match
// (a genuine tamper or corruption) or the hint cannot be read, so the message is unchanged in those cases.
function signerMismatchHint(rootBytes: Uint8Array, verifier: HybridVerifier): string {
  try {
    const declared = (JSON.parse(new TextDecoder().decode(rootBytes)) as { signingKeyFingerprint?: unknown }).signingKeyFingerprint;
    if (typeof declared !== "string" || declared.length === 0) return "";
    const current = `edmldsa1:${hexEncode(nobleSha384(concat(verifier.ed, verifier.mldsa)))}`;
    if (declared === current) return "";
    return ` (the archive was signed by ${declared}, but the pinned signer is ${current}; it was most likely sealed before a signer rotation, so verify or restore it with the prior signer's public key, for example the offline tool's --signer)`;
  } catch {
    return "";
  }
}

// AcquireMaster produces the 32-byte per-run master for openRunWith. It is given the parsed, signature-
// verified root, the key-commitment aad and the runIDBytes, and returns the master. openRun supplies it
// by unwrapping the master capsule with a held recipient identity; openRunWithMaster supplies a master
// recovered out of band (the console-side capsule decap of an attended-verification session, where the
// break-glass PRIVATE never leaves the browser). WHICHEVER master the callback produces is then validated
// by the key-commitment check, so a wrong master fails closed identically on both paths.
type AcquireMaster = (root: RootManifest, aad: Uint8Array, runIDBytes: Uint8Array) => Promise<Uint8Array>;

// openRunWith is the shared body of openRun / openRunWithMaster: it performs the full SPEC 8.3 open-and-
// verify chain and differs ONLY in how the per-run master is obtained (the acquireMaster callback). Every
// existing caller reaches it through openRun with byte-for-byte unchanged behaviour; the master path is
// the additive attended-verification entry point.
// ownsMaster says whether the master acquireMaster yields belongs to THIS function. True for openRun, which
// decapsulates a fresh one; false for openRunWithMaster, which passes the caller's buffer straight through.
// It is an explicit parameter rather than something inferred, because an implicit rule here is easy to get
// wrong silently: a version that zeroised unconditionally would wipe a caller-supplied master that the
// caller still needs.
async function openRunWith(store: ObjectStore, runID: string, verifier: HybridVerifier, opts: { verifyFreshness?: boolean; checkRecoveryBundle?: boolean } & FreshnessOptions, acquireMaster: AcquireMaster, ownsMaster: boolean): Promise<Run> {
  // HI-09: runID is interpolated raw into the object-key templates below; for an S3-style
  // destination that key becomes a request PATH, and a non-ULID shape (a "../" dot-segment) can
  // walk the signed request outside the configured bucket once new URL() normalises it
  // (dest/sigv4.ts). The router already rejects this at the API boundary, but openRun is the
  // shared chokepoint every restore/verify/drill/canary/prune caller funnels through, so assert
  // the shape here too, before any store.get, rather than trust every caller to have checked.
  if (!isValidRunId(runID)) throw integrityError("runId is not a canonical ULID");

  // F6: recovery-bundle verification runs first, before the run-specific chain, so a
  // tampered bundle is caught even when the run itself would pass. Opt-in via
  // checkRecoveryBundle so callers that have an independently trusted spec can skip it.
  if (opts.checkRecoveryBundle) {
    await verifyBundle(store, verifier);
  }

  const rootBytes = await store.get(`run/${runID}/root.manifest.json`);
  const sigText = new TextDecoder().decode(await store.get(`run/${runID}/root.manifest.json.sig`));
  const sig = b64urlDecode(sigText.trim());
  if (!(await hybridVerify(verifier, rootBytes, sig))) {
    throw integrityError(`root signature did not verify under the operator-pinned signer${signerMismatchHint(rootBytes, verifier)}`);
  }

  // F5: canonical-numeric gate (SPEC 11.3). Runs after the signature check so that a
  // non-canonical count in a validly-signed archive is a usage error (exit 6), not a
  // verification failure (exit 2). Mirrors the Go reader's validateCounts call in sign.go.
  const rootText = new TextDecoder().decode(rootBytes);
  validateCanonicalCounts(rootText, "declaredRecordCount", "shardCount", "freshness.runlogIndex");

  const root = JSON.parse(rootText) as RootManifest;
  // Confirm the parsed shape before any field is dereferenced, so a missing or mistyped required
  // field is a clear format violation rather than a generic TypeError deep in a downstream accessor.
  checkRootStructure(root);
  // Reject an unknown major version before any further processing (SPEC 13, 14.3
  // unknown-major), matching the Go reader's checkFormatVersion call right after ParseRoot.
  checkFormatVersion(root.formatVersion);
  if (root.runId !== runID) throw integrityError("manifest runId does not match the requested run");

  // The recipient-set gate runs before the capsule unwrap, matching the Go reader order.
  await checkRecipientSet(root);

  const runIDBytes = decodeULID(root.runId);
  const aad = hexDecode(root.keyCommitment);
  const master = await acquireMaster(root, aad, runIDBytes);

  // OWNERSHIP. From here until `new Run(...)` succeeds, this function owns the master and nothing else can
  // zeroise it. Every step below can throw (a key-commitment mismatch, a shard that will not open, a record
  // that fails verification, a freshness refusal); the catch below ensures none of those leaves a live master
  // with no reference left to reach it. On success ownership passes to the Run, whose dispose() ends it; a
  // finally here would therefore be wrong, because it would wipe the master the caller just received.
  try {
    const kc = await keyCommitment(master, runIDBytes);
    if (!constantTimeEqual(hexDecode(root.keyCommitment), kc)) {
      throw integrityError("key commitment does not match the run master");
    }

    const mk = await deriveMK(master, runIDBytes);
    const records = await openShards(store, root, mk, runIDBytes);
    await verifyRecords(records, root);

    let freshness: FreshnessResult | null = null;
    if (opts.verifyFreshness) {
      freshness = await checkRunlogFreshness(store, runID, root, verifier, opts);
      // HI-05: rollbackDetected is unconditional, never masked by allowStale (a chain anomaly or a
      // breach of an out-of-band minRunlogIndex pin is positive proof of rollback, not ordinary
      // staleness), matching the identical gate applied to the keyless tier in keyless.ts.
      //
      // The !checked arm exists so a future path that establishes nothing and forgets the unconditional
      // signal is refused here rather than opened. allowStale is an acknowledgement about the AGE of a run,
      // never about the integrity of the document that dates it, and the two are easy to conflate.
      //
      // It is raised FIRST and with its own category, so the restore side learns WHICH KIND of refusal this
      // is. A check that could not run is an unknown about ONE destination's own `_RECOVERY/RUNLOG` (which
      // appendRunlog writes and signs per destination), so the 3-2-1 walk may try a replica whose check CAN
      // run; a check that ran and found a rollback is a finding about the run and stays terminal on every
      // destination. Both refuse here. See integrity-error.ts.
      if (!freshness.checked) throw freshnessUnverifiableError(`freshness: ${freshness.reason ?? "not checked"}`);
      if (!freshness.ok || freshness.rollbackDetected) throw freshnessError(`freshness: ${freshness.reason ?? "stale"}`);
    }

    return new Run(store, root, master, ownsMaster, runIDBytes, records, freshness);
  } catch (e) {
    // Only if this function acquired the master. When the caller supplied it, ownership never came here and
    // wiping it would destroy a buffer the caller may still need. Rethrown unchanged: this is a zeroise on
    // the way past, not error handling.
    if (ownsMaster) master.fill(0);
    throw e;
  }
}

/**
 * Verifies a run against an operator-pinned signer and a held identity, then returns it for
 * restore. It performs the SPEC 8.3 chain: the hybrid signature over the stored root bytes, the
 * canonical-numeric and format-version gates, the recipient-set gate, the master-capsule unwrap,
 * the key commitment, the shard hashes and preamble match, the declared count, the recomputed
 * record hashes and the Merkle root, and (when requested) the RUNLOG freshness check.
 *
 * This is the in-account keyed entry point, and the master it decapsulates exists only for the
 * returned Run: ownership passes to that Run, whose dispose() zeroises it, and any failure on the
 * way there zeroises it here instead. The shard manifests are opened and verified up front, the
 * record PAYLOADS are not, so the returned Run still fetches and checks each record's bytes on demand.
 *
 * @param store - the read side of the destination holding the run objects.
 * @param runID - the run id to open.
 * @param identity - the held hybrid recipient private identity that unwraps the master capsule.
 * @param verifier - the operator-pinned hybrid signer the root and bundle must verify under.
 * @param opts - options: verifyFreshness runs the RUNLOG anti-rollback check, checkRecoveryBundle
 *   verifies the recovery bundle first, plus the FreshnessOptions (min-index pin, allow-stale).
 * @returns the opened, verified Run.
 * @throws Error when any verification step fails (a bad signature, a structural gate, a hash
 *   mismatch, the capsule cannot be unwrapped, or a failed freshness check).
 */
export async function openRun(store: ObjectStore, runID: string, identity: HybridRecipientPrivate, verifier: HybridVerifier, opts: { verifyFreshness?: boolean; checkRecoveryBundle?: boolean } & FreshnessOptions = {}): Promise<Run> {
  // ownsMaster true: openCapsule decapsulates a fresh master that exists only for this Run.
  return openRunWith(store, runID, verifier, opts, (root, aad) => openCapsule(parseWraps(root.masterCapsule), identity, aad), true);
}

/**
 * openRunWithMaster opens and verifies a run from a PRE-RECOVERED 32-byte master instead of a held
 * identity, for attended verification: the console decapsulates the run's master capsule in the operator's
 * browser (the break-glass private never leaves it) and hands the engine only this single-archive master.
 * The shared key-commitment check inside openRunWith validates the master against the signed run, so a
 * wrong or replayed-but-mismatched master fails closed exactly as a bad in-account decap would. This never
 * gives the engine a key that opens any OTHER run: the master is per-run (a fresh 32 random bytes each run,
 * bound to its own runId by the commitment), so it decrypts this run and nothing else.
 *
 * Every verification step is the one openRun runs; only the way the master is obtained differs. The master
 * stays the CALLER'S buffer: this function never zeroises it, on success or on failure, so the caller both
 * may reuse it across runs and must wipe it when done.
 */
export async function openRunWithMaster(store: ObjectStore, runID: string, master: Uint8Array, verifier: HybridVerifier, opts: { verifyFreshness?: boolean; checkRecoveryBundle?: boolean } & FreshnessOptions = {}): Promise<Run> {
  // ownsMaster false: this is the CALLER'S buffer, and it may open several runs or be reused after a failure.
  return openRunWith(store, runID, verifier, opts, () => Promise.resolve(master), false);
}

/**
 * RunCapsule is the non-secret material an attended-verification session hands to the operator's browser
 * so it can recover this run's master locally: the master-capsule wraps (each a hybrid KEM ciphertext + a
 * STREAM-sealed 32-byte master, addressed to a recipient fingerprint) and the key commitment (the DEM aad).
 * None of it is decryptable without the break-glass PRIVATE, which stays in the browser; the capsule is
 * already sitting in the customer's own destination bucket, so serving it to the authenticated customer
 * discloses nothing new. declaredRecordCount rides so the browser/engine can estimate the verify work.
 *
 * It is a strict subset of the signed root, never the manifest itself: no shard list, no object key and no
 * record name is carried, so the shape itself bounds what an attend response can leak. Every field is read
 * off a root whose signature has already been verified (readRunCapsule), so the wraps a browser is asked to
 * decapsulate cannot be attacker-substituted, and the key-vintage inventory reads the same shape KEYLESSLY.
 */
export interface RunCapsule {
  masterCapsule: Array<{ fingerprint: string; kemCiphertext: string; sealed: string }>;
  keyCommitment: string;
  declaredRecordCount: number;
  // recipients is the run's recipient set, read straight off the SIGNATURE-VERIFIED root: each recipient's
  // dpr1: fingerprint paired with its role ("break-glass" | "operational"). Public material only (the same
  // class the master capsule already carries), so serving it discloses nothing new; the key-vintage inventory
  // (admin/key-vintages.ts) reads it KEYLESSLY to tell which archives each key opens. masterCapsule[].fingerprint
  // already carries the identical fingerprint set (same values, from sealToRecipients); recipients pairs each
  // fingerprint with its role for the per-vintage rollup, which the master-capsule wraps do not carry.
  recipients: Array<{ fingerprint: string; role: string }>;
  // signingKeyFingerprint is the "edmldsa1:" fingerprint of the signer that signed this root. It is a PUBLIC
  // hint the reader never trusts for access (the signature is verified under the operator-pinned verifier, not
  // this field); the inventory uses it only to report signer continuity for the re-key surface.
  signingKeyFingerprint: string;
}

/**
 * readRunCapsule fetches and SIGNATURE-VERIFIES a run's root manifest, then returns only its master-capsule
 * wraps + key commitment (never the whole manifest). The signature check means a tampered/forged manifest
 * is refused before its capsule is served, so the route is not an oracle for attacker-controlled bytes; the
 * engine also re-verifies the full run when the browser returns the recovered master (openRunWithMaster), so
 * a bad capsule can at worst waste the browser's decap and fail closed.
 *
 * It needs no key of any kind, only the operator-pinned verifier, which is what lets the key-vintage
 * inventory walk many runs cheaply. Beyond the signature it runs the same runId, structure and format-version
 * gates openRun runs, and no other stage: the shards are not read, the capsule is not unwrapped and freshness
 * is not checked here, so a green return says the ROOT is authentic, not that the run is restorable.
 */
export async function readRunCapsule(store: ObjectStore, runID: string, verifier: HybridVerifier): Promise<RunCapsule> {
  if (!isValidRunId(runID)) throw integrityError("runId is not a canonical ULID");
  const rootBytes = await store.get(`run/${runID}/root.manifest.json`);
  const sigText = new TextDecoder().decode(await store.get(`run/${runID}/root.manifest.json.sig`));
  const sig = b64urlDecode(sigText.trim());
  if (!(await hybridVerify(verifier, rootBytes, sig))) {
    throw integrityError(`root signature did not verify under the operator-pinned signer${signerMismatchHint(rootBytes, verifier)}`);
  }
  const root = JSON.parse(new TextDecoder().decode(rootBytes)) as RootManifest;
  checkRootStructure(root);
  checkFormatVersion(root.formatVersion);
  if (root.runId !== runID) throw integrityError("manifest runId does not match the requested run");
  return {
    masterCapsule: root.masterCapsule,
    keyCommitment: root.keyCommitment,
    declaredRecordCount: root.declaredRecordCount,
    recipients: root.recipients.map((r) => ({ fingerprint: r.fingerprint, role: r.role })),
    signingKeyFingerprint: root.signingKeyFingerprint,
  };
}

// openShards fetches each signed shard, checks its sha384 against the root, unwraps and parses it,
// confirms the preamble matches the run, and returns the concatenated records. It then runs the run-wide
// codec checks (every record matches the envelope codec; a secrets record is never compressed), the
// structural format violations the Go reader's openShards tail enforces. Extracted from openRun per finding
// engine-src-031-03.
async function openShards(store: ObjectStore, root: RootManifest, mk: Uint8Array, runIDBytes: Uint8Array): Promise<ShardRecord[]> {
  const records: ShardRecord[] = [];
  for (const shard of root.shards) {
    const shardBytes = await store.get(shard.object);
    if ((await sha384Hex(shardBytes)) !== shard.sha384) {
      throw integrityError(`shard ${shard.id} hash does not match the signed root`);
    }
    const wrapKey = await deriveManifestWrapKey(mk, runIDBytes, shard.id);
    const plain = await openStream(wrapKey, unframeDpe(shardBytes));
    const { preamble, recs } = parseShard(plain);
    if (preamble.runId !== root.runId || preamble.shardId !== shard.id || preamble.formatVersion !== root.formatVersion) {
      throw integrityError(`shard ${shard.id} preamble does not match the signed run`);
    }
    records.push(...recs);
  }
  // The codec is run-wide: every record must match the envelope codec, and a secrets record
  // must never be compressed (SPEC 5.2, 7.5, 12.4). Both are structural format violations
  // (the coded usage/rejection path, ExitUsage in the Go reader) rather than verification
  // failures, and both run here, after the shards are opened and before the completeness
  // check, mirroring the tail of the Go reader's openShards.
  for (const rec of records) {
    if (!KNOWN_SOURCE_TYPES.has(rec.sourceType)) {
      throw integrityError(`record ${rec.recordId} has sourceType ${JSON.stringify(rec.sourceType)}, which is outside the supported downpipe/0.1.0 set (section 12.1); a reader refuses an unknown source type`);
    }
    if (rec.codec !== root.envelope.codec) {
      throw integrityError(`record ${rec.recordId} codec ${JSON.stringify(rec.codec)} differs from the envelope codec ${JSON.stringify(root.envelope.codec)}`);
    }
    if (rec.sourceType === "secrets" && rec.codec !== CODEC_NAME_NONE) {
      throw integrityError(`secrets record ${rec.recordId} must not be compressed (section 5.2, 12.4)`);
    }
  }
  return records;
}

// verifyRecords checks the completeness (the recovered count matches the declared count), recomputes each
// record hash against its signed recordHash, and confirms the Merkle root over the per-record leaves equals
// the signed root. Extracted from openRun per finding engine-src-031-03.
async function verifyRecords(records: ShardRecord[], root: RootManifest): Promise<void> {
  if (records.length !== root.declaredRecordCount) {
    throw integrityError(`recovered ${records.length} records, the root declares ${root.declaredRecordCount}`);
  }
  const leaves: Uint8Array[] = [];
  for (const rec of records) {
    const rh = await recordHashOf(rec);
    if (!constantTimeEqual(rh, hexDecode(rec.recordHash))) {
      throw integrityError(`record ${rec.recordId} hash does not match its fields`);
    }
    leaves.push(rh);
  }
  if (!constantTimeEqual(await merkleRoot(leaves), hexDecode(root.merkleRoot))) {
    throw integrityError("Merkle root does not match the recovered records");
  }
}
