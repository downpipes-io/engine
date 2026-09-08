// FaultDestination is a fault-injecting in-memory Destination double for testing the seal pipeline's write-
// fault handling and verify-at-seal's post-seal tamper detection. It is modelled on the three shipped
// in-memory Destinations (memdest.ts MemoryDestination, validate-slice.ts MemDest, and
// validate-verify-at-seal.ts SpyDestination) and adds a small fault schedule so the test OWNS the ground
// truth: it knows exactly which write it faulted, which write it dropped, and which stored byte it flipped,
// and asserts the engine's verdict against THAT truth (never against the engine's self-report).
//
// It supports the two planes the axis proves:
//   PLANE 1 (a hard write fault): armWriteFault faults a chosen write of a chosen key in one of four shapes --
//     a 503 throttle (s3WriteFailure shape "PUT <k>: status 503"), a 403 auth ("... status 403"), a 400
//     permanent rejection carrying a sanitised S3 <Code> ("... status 400 (InvalidRequest)"), or the NATIVE
//     R2 binding shape ("put failed: internal error": a transient outage with NO "status NNN"). The seal
//     pipeline's real withRetry then retries a throttle/transient past a deliberately-small throttleRetry
//     budget and fails loud immediately on auth/permanent, exactly as production does. armDropWrite ACKNOWLEDGES
//     a chosen write as success while storing nothing (the store lied about the write), so the seal does NOT
//     throw and the two-plane hand-off to verify-at-seal is exercised.
//   PLANE 2 (a silent post-write corruption): the tamper helpers (tamperShard / truncateSegment / deleteObject)
//     mutate the STORED bytes of a KNOWN object AFTER a clean seal, outside the reader, so verify-at-seal's
//     read-back catches a corruption whose site the harness chose.
//
// Every faulted (thrown) write is NOT recorded in mutateLog (it did not mutate the store); a dropped write IS
// recorded (the engine believes it wrote). mutateLog therefore reads as "the writes the engine believes it
// landed", which the fail-open assertions use to prove verify-at-seal writes and deletes NOTHING.

import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import type { ObjectStore } from "../src/format/reader.ts";
import { CHUNK_SIZE, TAG_SIZE } from "../src/format/version.ts";
import { flipBit } from "./memdest.ts";

// A WriteFaultShape is one of the four thrown-write shapes the axis injects. The first three carry a
// "status NNN" (the S3 destination path always does, s3-worm.ts s3WriteFailure), so coarseRunError classifies
// them correctly; the fourth is the native R2 binding shape (workerd re-throws "internal error" with no
// status), the CONTRAST that coarseRunError coarsens to "run failed" while the retry classifier and the ring
// still name it transient (slice.ts vs classify.ts NETWORK_RE vs run-pressure.ts TRANSIENT_RE).
export type WriteFaultShape = "throttle503" | "auth403" | "code400" | "nativeInternal";

export interface WriteFaultSpec {
  // match decides which key's write faults (e.g. the root manifest PUT).
  match: (key: string) => boolean;
  shape: WriteFaultShape;
  // code is the sanitised S3 <Code> the "code400" shape carries (default "InvalidRequest").
  code?: string;
}

// buildFaultMessage renders the thrown-write message for a shape. The first three are byte-identical to what
// s3WriteFailure (s3-worm.ts) produces on a non-2xx PUT, so the shipped classifiers see the exact production
// shape; the native shape carries "internal error" and NO status, the documented coarsening contrast.
function buildFaultMessage(verb: string, key: string, spec: WriteFaultSpec): string {
  switch (spec.shape) {
    case "throttle503":
      return `${verb} ${key}: status 503`;
    case "auth403":
      return `${verb} ${key}: status 403`;
    case "code400":
      return `${verb} ${key}: status 400 (${spec.code ?? "InvalidRequest"})`;
    case "nativeInternal":
      // The native R2 binding does no HTTP and re-throws the workerd binding error verbatim; a transient
      // outage carries "internal error" but no "status NNN" (the shape slice.ts omits).
      return "put failed: internal error";
  }
}

export class FaultDestination implements Destination {
  private store = new Map<string, Uint8Array>();
  // mutateLog records every write the store BELIEVES it landed (a successful put/putStream/putConditional or a
  // delete, AND a dropped write the engine was told succeeded), so the fail-open assertions can prove
  // verify-at-seal mutated nothing. A FAULTED (thrown) write is never recorded: it did not mutate the store.
  readonly mutateLog: string[] = [];

  private writeFault: WriteFaultSpec | null = null;
  private dropMatch: ((key: string) => boolean) | null = null;

  // armWriteFault schedules a thrown-write fault for every write whose key matches; disarmed by disarm().
  armWriteFault(spec: WriteFaultSpec): void {
    this.writeFault = spec;
  }

  // armDropWrite schedules an acknowledged-but-stored-nothing write for every matching key (the store lied):
  // the write returns success, mutateLog records it, but the bytes never land.
  armDropWrite(match: (key: string) => boolean): void {
    this.dropMatch = match;
  }

  disarm(): void {
    this.writeFault = null;
    this.dropMatch = null;
  }

  // classify decides what a write of `key` does BEFORE it touches the store: throw the scheduled fault, drop
  // (ack but store nothing), or land normally. The write fault takes precedence over a drop when both match.
  private classify(verb: string, key: string): "fault" | "drop" | "store" {
    if (this.writeFault !== null && this.writeFault.match(key)) {
      throw new Error(buildFaultMessage(verb, key, this.writeFault));
    }
    if (this.dropMatch !== null && this.dropMatch(key)) return "drop";
    return "store";
  }

  async get(key: string): Promise<GetResult | null> {
    const v = this.store.get(key);
    return v ? { body: v, etag: `"${key.length}"` } : null;
  }

  async put(key: string, body: Uint8Array): Promise<void> {
    const action = this.classify("PUT", key); // throws on a faulted write (never reaches the log/store)
    this.mutateLog.push(`put:${key}`);
    if (action === "drop") return; // acknowledged as success, stores nothing
    this.store.set(key, body);
  }

  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    const action = this.classify("PUT", key);
    const parts: Uint8Array[] = [];
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) parts.push(value);
    }
    let n = 0;
    for (const p of parts) n += p.length;
    const merged = new Uint8Array(n);
    let off = 0;
    for (const p of parts) {
      merged.set(p, off);
      off += p.length;
    }
    this.mutateLog.push(`putStream:${key}`);
    if (action === "drop") return;
    this.store.set(key, merged);
  }

  async putConditional(key: string, body: Uint8Array, _opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    const action = this.classify("PUT", key);
    this.mutateLog.push(`putConditional:${key}`);
    if (action === "drop") return { ok: true, etag: `"${key.length}"` };
    this.store.set(key, body);
    return { ok: true, etag: `"${key.length}"` };
  }

  async exists(key: string): Promise<boolean> {
    return this.store.has(key);
  }

  async delete(key: string): Promise<void> {
    this.mutateLog.push(`delete:${key}`);
    this.store.delete(key);
  }

  async list(prefix: string): Promise<string[]> {
    return [...this.store.keys()].filter((k) => k.startsWith(prefix));
  }

  // ---- harness-owned ground-truth inspection (never on the real Destination interface) ----

  // seed loads a pre-built archive (e.g. buildArchive's output) directly into the store and clears mutateLog,
  // so a subsequent verify counts only verify-induced mutations (mirrors SpyDestination.seed).
  seed(archive: Map<string, Uint8Array>): void {
    for (const [k, v] of archive) this.store.set(k, v);
    this.mutateLog.length = 0;
  }

  // stored reports whether the REAL underlying store holds the key (bypassing any armed fault/drop), so the
  // harness can prove a faulted seal's root/RUNLOG did NOT durably land.
  stored(key: string): boolean {
    return this.store.has(key);
  }

  rawKeys(): string[] {
    return [...this.store.keys()];
  }

  countSegments(): number {
    return [...this.store.keys()].filter((k) => k.startsWith("seg/") && k.endsWith(".seg")).length;
  }

  // asObjectStore exposes the underlying store as the reader's read-only ObjectStore (a missing object throws
  // "object <k> is missing", exactly as verify-at-seal's storeOver does), so the harness can independently
  // drive attestKeyless over the store to prove a faulted seal is NOT a recoverable sealed run.
  asObjectStore(): ObjectStore {
    return {
      get: async (k: string): Promise<Uint8Array> => {
        const v = this.store.get(k);
        if (!v) throw new Error(`object ${k} is missing`);
        return v;
      },
      list: (prefix: string): Promise<string[]> => this.list(prefix),
    };
  }

  // firstShardKey / tamperShard flip one byte of a stored shard manifest object. The shard's SHA-384 is in the
  // SIGNED root, so a flipped byte breaks the keyless Tier-0 completeness check (no key needed).
  firstShardKey(): string {
    for (const k of this.store.keys()) if (k.includes("/manifest/") && k.endsWith(".dpe")) return k;
    throw new Error("no shard manifest object in the store");
  }

  tamperShard(): string {
    const key = this.firstShardKey();
    const bytes = this.store.get(key)!;
    const copy = new Uint8Array(bytes);
    flipBit(copy, copy.length - 1);
    this.store.set(key, copy);
    return key;
  }

  // largestSegmentKey returns the biggest stored segment object (the multi-chunk record's segment), so
  // truncateSegment removes a WHOLE trailing chunk from a segment that has more than one.
  largestSegmentKey(): string {
    let best: string | undefined;
    let bestLen = -1;
    for (const [k, v] of this.store) {
      if (k.startsWith("seg/") && k.endsWith(".seg") && v.length > bestLen) {
        best = k;
        bestLen = v.length;
      }
    }
    if (best === undefined) throw new Error("no segment object in the store");
    return best;
  }

  // truncateSegment lops exactly the final WHOLE stream chunk (CHUNK_SIZE ciphertext + TAG_SIZE tag) off the
  // largest stored segment. Removing a whole chunk (not a partial one) means the remaining chunks still decrypt
  // and authenticate cleanly, so the reader reaches its structural per-record gate and reports the segment
  // "terminates after N chunks but chunkRange declares M" -- a RECORD-INTEGRITY corruption caught by the
  // decrypt tier (a partial-chunk cut would instead fail AEAD mid-chunk and read as the generic catch-all).
  // The shard hash is unaffected (the segment is not in a shard), so Tier-0 passes and the decrypt tier catches
  // it. Requires the record to span at least two chunks (a >= CHUNK_SIZE-byte value).
  truncateSegment(): string {
    const key = this.largestSegmentKey();
    const bytes = this.store.get(key)!;
    const drop = CHUNK_SIZE + TAG_SIZE;
    if (bytes.length <= drop) throw new Error(`segment ${key} is not multi-chunk; cannot drop a whole chunk`);
    this.store.set(key, bytes.subarray(0, bytes.length - drop));
    return key;
  }

  // deleteObject removes a stored object outright (the missing-root object-missing case, and the RUNLOG-absent
  // freshness case). Bypasses mutateLog: this is a harness setup mutation, not a verify-induced one.
  deleteObject(key: string): void {
    this.store.delete(key);
  }
}
