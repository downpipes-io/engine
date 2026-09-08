import { sealedSegmentLength } from "../crypto/streamseal.ts";
import type { Meter } from "../meter.ts";
import { toArrayBuffer } from "./buffer-utils.ts";
import { DestIo, type DestIoSnapshot } from "./dest-io.ts";
import { DestFaultLog, type DestFaultSnapshot } from "./fault-log.ts";
import type { Destination, GetResult, ListPage, PutConditionalResult, WormStatus } from "./types.ts";
import { MAX_STREAM_SEGMENT_BYTES } from "./types.ts";

// A destination writer over a native Cloudflare R2 bucket binding. Unlike S3Destination
// (which speaks the S3 HTTP API with SigV4 to any S3-compatible endpoint), this talks
// directly to an in-account R2Bucket binding, so there are no credentials on the wire and
// no signing: the binding is the capability. It is the natural choice when the customer's
// archive bucket is R2 in the same account as the engine. Content-addressed seg/ writes
// are idempotent, so a re-run or a resumed run overwrites identically.
//
// ETag handling: R2 exposes the strong validator as R2Object.etag (no quotes) and the
// transport form as httpEtag (quoted). We round-trip the unquoted etag everywhere, because
// it is what get/putConditional return AND what R2Conditional.etagMatches expects, so the
// single-writer RUNLOG read-modify-write loop in seal/pipeline.ts stays internally
// consistent (the etag it reads back is the etag it later passes as ifMatch).
/**
 * A Destination over a native Cloudflare R2 bucket binding. It talks directly to the in-account
 * R2Bucket, so there are no credentials on the wire and no signing: the binding is the capability.
 * It round-trips R2's unquoted ETag everywhere, so the single-writer RUNLOG read-modify-write loop
 * stays consistent. Object-Lock cannot be set or probed through the native binding, so
 * objectLockStatus reports "unknown"; no R2 destination can enforce S3 Object-Lock by any route, so
 * there is no other R2 path to send an operator to (measured, see objectLockStatus below).
 */
export class R2Destination implements Destination {
  private bucket: R2Bucket;
  private meter: Meter | undefined;
  // io is the bounded DEGRADATION counter set (G186). The native binding has no pacer, no fetch bound and no
  // multipart retry ladder, so the ONLY degradation it can observe is the conditional-PUT conflict -- which
  // on the RUNLOG is exactly the "two engines are fighting over one log" signal, and is otherwise swallowed
  // by a successful run. Diagnostic only: noting never changes control flow.
  private readonly io = new DestIo();
  // faults is the bounded closed-vocabulary evidence ring (G135 shape). The native binding never speaks HTTP,
  // so it records no per-op status faults; what it CAN record is the engine's own guard refusals (G207), which
  // the run row otherwise coarsens away entirely.
  private readonly faults = new DestFaultLog();

  constructor(bucket: R2Bucket, meter?: Meter) {
    this.bucket = bucket;
    this.meter = meter;
  }

  // guarded wraps every native R2Bucket call with a SELF-DESCRIBING prefix naming the op
  // and the key, then the runtime's own message verbatim. The native binding speaks neither HTTP (no status)
  // nor S3 (no <Code> element) -- it is an in-process call, not a request over a wire -- so an uncaught throw
  // here used to propagate as a bare runtime message (e.g. "the R2 bucket does not exist") that coarseRunError
  // (seal/slice.ts) cannot attribute to a destination: it classifies a run fault by status/code/keyword found
  // in the text, found none, and fell through every branch to the generic "run failed", losing the fact that a
  // destination write failed at all. Naming the op + key here does NOT require knowing or guessing workerd's
  // message text (the fix the register held back on): coarseRunError only has to recognise the FIXED prefix
  // every native call is wrapped in, never the variable text after it. The key is content-addressed (seg/...)
  // or a fixed control path (_RECOVERY/RUNLOG), matching the "PUT <key>: status NNN" shape S3Destination
  // already surfaces unredacted, so nothing new is exposed. Applied uniformly to every method below (not only
  // put), because the same uncaught-native-throw shape is present on all of them, not only the reported one.
  private async guarded<T>(op: string, key: string, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error(`R2 native binding ${op} ${key} failed (no HTTP status, no S3 code): ${msg}`);
    }
  }

  // put writes an object unconditionally. R2 verifies the body against the binding's own
  // integrity; the archive's per-record and shard hashes are the end-to-end guarantee.
  async put(key: string, body: Uint8Array): Promise<void> {
    // Hand R2 a fresh ArrayBuffer slice rather than a view over a possibly-larger buffer,
    // so a subarray of a pooled buffer cannot ship trailing bytes.
    this.meter?.spend(1, "r2ClassA");
    await this.guarded("put", key, () => this.bucket.put(key, toArrayBuffer(body)));
  }

  // putConditional maps the single-writer RUNLOG preconditions onto R2 onlyIf:
  // ifNoneMatch:"*" (create-only) -> etagDoesNotMatch:"*" (write only if absent),
  // ifNoneMatch:<etag>             -> etagDoesNotMatch:<etag> (write only if current etag differs),
  // ifMatch:<etag>  (replace exact version) -> etagMatches:<etag>.
  // R2 returns null from a conditional put when the precondition does NOT hold, which is
  // the 412 equivalent: the caller re-reads and retries (the RUNLOG accumulation path).
  //
  // Guard note: unlike a truthiness check, !== undefined here means an explicit empty string
  // ifMatch is never silently dropped from onlyIf (ENG-M14). An empty-string etagMatches is
  // a value R2 will never match, so it returns null (ok:false), and the caller retries, which
  // is the correct outcome. This mirrors S3Destination.putConditional's === undefined guard.
  //
  // The returned etag is R2's unquoted form (obj.etag, no angle brackets). S3Destination
  // returns etag from the response ETag header (also unquoted after stripping quotes) or
  // omits it when absent. R2 always supplies an etag, so both impls return { ok:true, etag }
  // on success; the shapes are now aligned.
  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    const onlyIf: R2Conditional = {};
    if (opts.ifMatch !== undefined) onlyIf.etagMatches = opts.ifMatch;
    // Pass the caller's value through verbatim: "*" is R2's create-only wildcard and a
    // concrete etag means "write only if the current etag differs from this one". Both
    // semantics match the S3 If-None-Match header's documented behaviour exactly, so a
    // caller gets identical results from R2Destination and S3Destination.
    if (opts.ifNoneMatch !== undefined) onlyIf.etagDoesNotMatch = opts.ifNoneMatch;
    this.meter?.spend(1, "r2ClassA");
    const res = await this.guarded("putConditional", key, () => this.bucket.put(key, toArrayBuffer(body), { onlyIf }));
    // null => precondition failed (a concurrent write won, or the object already exists). Counted as a
    // degradation (G186): the SAME signal the S3 driver's 412 carries, so a RUNLOG being fought over by two
    // engines is visible on an R2 destination too, on a run that still succeeds.
    if (res === null) {
      this.io.note("conditionalPutConflicts");
      return { ok: false };
    }
    return { ok: true, etag: res.etag };
  }

  // destIo is the bounded DEGRADATION snapshot of this instance (G186). Implements the optional
  // Destination.destIo accessor; clamped integers only.
  destIo(): DestIoSnapshot {
    return this.io.snapshot();
  }

  // destFaults is the bounded fault/anomaly snapshot (G207 on this driver): the engine guard refusals this
  // instance recorded, with their clamped magnitudes. Implements the optional Destination.destFaults accessor.
  destFaults(): DestFaultSnapshot {
    return this.faults.snapshot();
  }

  // putStream writes a streamed body in a single put. R2 bindings accept a ReadableStream
  // body ONLY when its length is known: a live binding rejects an unframed stream, so when
  // the plaintext size is known the stream is piped through a FixedLengthStream sized to
  // the EXACT sealed byte length (sealedSegmentLength: framing + payload nonce + plaintext
  // + per-chunk tags; note a maximal 1 GiB-plaintext segment seals to slightly more than
  // 1 GiB). The plaintext ceiling (SPEC 14.5) is asserted as defence in depth; a size-less
  // stream passes through raw for the in-memory doubles, which do not enforce length.
  async putStream(key: string, body: ReadableStream<Uint8Array>, size?: number): Promise<void> {
    if (size !== undefined && size > MAX_STREAM_SEGMENT_BYTES) {
      // G207: the engine's own segment ceiling refused the write. Closed class + the CLAMPED size; never the key.
      this.faults.noteGuardRefusal("segment-over-limit", size);
      throw new Error(`segment ${key} exceeds the ${MAX_STREAM_SEGMENT_BYTES}-byte single-segment limit`);
    }
    this.meter?.spend(1, "r2ClassA");
    if (size !== undefined && typeof FixedLengthStream === "function") {
      const fixed = new FixedLengthStream(sealedSegmentLength(size));
      // Pipe without awaiting before the put: the binding consumes the readable side while
      // the seal fills the writable side; awaiting both completes the transfer.
      const pump = body.pipeTo(fixed.writable);
      await this.guarded("putStream", key, () => Promise.all([this.bucket.put(key, fixed.readable), pump]));
      return;
    }
    await this.guarded("putStream", key, () => this.bucket.put(key, body));
  }

  // get fetches an object's bytes and its (unquoted) etag, or null when absent.
  async get(key: string): Promise<GetResult | null> {
    this.meter?.spend(1, "r2ClassB");
    const obj = await this.guarded("get", key, () => this.bucket.get(key));
    if (obj === null) return null;
    const buf = await obj.arrayBuffer();
    return { body: new Uint8Array(buf), etag: obj.etag };
  }

  // exists reports whether an object is already present (content-addressed dedup, so an
  // unchanged segment is not re-uploaded). head avoids fetching the body.
  async exists(key: string): Promise<boolean> {
    this.meter?.spend(1, "r2ClassB");
    return (await this.guarded("head", key, () => this.bucket.head(key))) !== null;
  }

  // delete removes one object. It is the WRITE side of the retention prune (seal/prune.ts),
  // which only ever deletes an object the planner has proven unreferenced (a superseded run's
  // run/<runId>/ tree object, or a segment no retained run references). R2 .delete is
  // idempotent: deleting an absent key resolves without error, so a re-run of an interrupted
  // prune does not fail on an already-deleted object.
  async delete(key: string): Promise<void> {
    this.meter?.spend(1, "r2ClassA");
    await this.guarded("delete", key, () => this.bucket.delete(key));
  }

  // list enumerates the object keys under a prefix, following R2's cursor until the listing is
  // complete so the caller sees the whole set in one call. The prune uses it to find a
  // superseded run's run/<runId>/ tree objects. Each .list is one metered subrequest; a run
  // tree is a handful of objects, so this is one or two pages in practice. This method is intended
  // only for small, bounded prefix scans (a run/<runId>/ tree); it accumulates every matching key
  // into one in-memory array. A caller that needs to iterate a large result set should add an
  // async-generator streaming variant rather than extending this accumulating form.
  async list(prefix: string): Promise<string[]> {
    const keys: string[] = [];
    let cursor: string | undefined;
    for (;;) {
      this.meter?.spend(1, "r2ClassA");
      const res = await this.guarded("list", prefix, () => this.bucket.list({ prefix, ...(cursor !== undefined ? { cursor } : {}) }));
      for (const o of res.objects) keys.push(o.key);
      // R2Objects narrows to { truncated: true; cursor: string } when more pages remain, so
      // the cursor is only read on the truncated branch (the type carries no cursor otherwise).
      if (!res.truncated) break;
      cursor = res.cursor;
    }
    return keys;
  }

  // listPage returns ONE page of keys under the prefix plus the cursor for the next page (undefined
  // when R2 reports the listing is not truncated), so a caller can stream a large keyspace in bounded
  // memory rather than accumulating the whole store like list() above. The off-site replication seg/
  // sync uses it to walk the content-addressed store page by page (M6). One .list = one metered
  // subrequest. R2 returns keys in lexicographic order, contiguous across pages via the cursor.
  async listPage(prefix: string, cursor?: string): Promise<ListPage> {
    this.meter?.spend(1, "r2ClassA");
    const res = await this.guarded("listPage", prefix, () => this.bucket.list({ prefix, ...(cursor !== undefined ? { cursor } : {}) }));
    const keys = res.objects.map((o) => o.key);
    // R2Objects narrows to { truncated: true; cursor: string } when more pages remain, so the next
    // cursor is only read on the truncated branch (the type carries no cursor otherwise).
    return res.truncated ? { keys, cursor: res.cursor } : { keys };
  }

  // WORM / Object-Lock note (HONEST): the native R2Bucket binding's R2PutOptions surface
  // (onlyIf / httpMetadata / customMetadata / md5..sha512 / storageClass / ssecKey) does NOT expose
  // S3 Object-Lock mode or a retain-until-date on put, and there is no binding method to read a
  // bucket's Object-Lock configuration. So this binding path cannot SET store-enforced WORM, and the
  // probe below cannot CONFIRM it.
  //
  // THE S3 ENDPOINT IS NOT A WAY ROUND IT. R2 does not support S3 Object-Lock through its S3-compatible
  // API either, so "reach the bucket by its S3 endpoint" is not a working remedy for this limit.
  //
  // MEASURED against a real R2 bucket over https://<account>.r2.cloudflarestorage.com,
  // signed with this repo's own SigV4 signer (dest/sigv4.ts):
  //
  //   GET /<bucket>/?object-lock=                 -> 404 ObjectLockConfigurationNotFoundError
  //   PUT with x-amz-object-lock-mode: COMPLIANCE -> 501 NotImplemented, "Header
  //                                                  'x-amz-object-lock-mode' with value 'COMPLIANCE'
  //                                                  not implemented"
  //
  // R2 does not hide Object-Lock behind the binding; it REFUSES the header on the S3 arm too, by name.
  // An operator who followed the published remedy got a 501 on every write and an archive holding
  // nothing, which is worse than the destination they started with. There is no R2 remedy to name.
  // R2's own bucket-lock retention feature (wrangler r2 bucket lock / PutBucketLockConfiguration) is a
  // SEPARATE mechanism that neither this policy nor this probe reaches.
  //
  // We do NOT fake object-lock here: objectLockStatus reports "unknown" (the safe cannot-confirm
  // reading), which the posture surfaces as a warning rather than a false WORM claim. If a future
  // R2PutOptions gains an object-lock field, wire it here and update this method to read and
  // return the actual lock state instead of "unknown".
  async objectLockStatus(): Promise<WormStatus> {
    // G279: this "unknown" is STRUCTURAL, not a fault -- the native R2Bucket binding exposes no Object-Lock
    // read API, so this destination can never confirm enforcement no matter how the credential is scoped.
    // The reason names the limit; it names no remedy beside it, because the S3-endpoint one is refused 501
    // by R2 (measured above) and would break every write.
    return { enabled: "unknown", unknownReason: "r2-binding-unsupported" };
  }
}
