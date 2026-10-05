// A shared in-memory Destination for the offline tests, with ETag-based optimistic
// concurrency and a streamed-PUT path, mirroring the S3 destination's contract.

import type { Destination, GetResult, ListPage, PutConditionalResult } from "../src/dest/types.ts";

// flipBit XORs the byte at an in-bounds index of a buffer (the tamper injection the negative controls use).
// Under noUncheckedIndexedAccess a typed-array element read is number | undefined, so a bare `buf[i] ^= m`
// reads a possibly-undefined operand; this asserts the index is in bounds (always true for the non-empty
// buffers the callers build) and then flips, leaving the tamper behaviour identical.
export function flipBit(buf: Uint8Array, index: number, mask = 0xff): void {
  const b = buf[index];
  if (b === undefined) throw new Error(`flipBit: index ${index} out of bounds (length ${buf.length})`);
  buf[index] = b ^ mask;
}

export class MemoryDestination implements Destination {
  private store = new Map<string, { body: Uint8Array; etag: string }>();
  private counter = 0;
  private nextEtag(): string {
    return `"${++this.counter}"`;
  }
  async get(key: string): Promise<GetResult | null> {
    const v = this.store.get(key);
    return v ? { body: v.body, etag: v.etag } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    this.store.set(key, { body, etag: this.nextEtag() });
  }
  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    const parts: Uint8Array[] = [];
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
    }
    let n = 0;
    for (const p of parts) n += p.length;
    const merged = new Uint8Array(n);
    let off = 0;
    for (const p of parts) {
      merged.set(p, off);
      off += p.length;
    }
    this.store.set(key, { body: merged, etag: this.nextEtag() });
  }
  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    const cur = this.store.get(key);
    if (opts.ifNoneMatch === "*" && cur) return { ok: false };
    if (opts.ifMatch && (!cur || cur.etag !== opts.ifMatch)) return { ok: false };
    const etag = this.nextEtag();
    this.store.set(key, { body, etag });
    return { ok: true, etag };
  }
  async exists(key: string): Promise<boolean> {
    return this.store.has(key);
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key); // idempotent: deleting an absent key is a no-op success
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.store.keys()].filter((k) => k.startsWith(prefix)).sort();
  }
  // listPage exposes the in-memory store's keyspace one bounded page at a time, mirroring the native
  // S3/R2 pagination (sorted key order, an opaque cursor that is the last key of the page). pageSize
  // defaults to a large value so most tests see a single page; the replication seg/ sync test sets a
  // small pageSize on a large store to drive the multi-page streaming path. Keys are returned sorted
  // so the cursor (a key) is a stable resume point, exactly as the real stores page in sorted order.
  protected pageSize = 1000;
  async listPage(prefix: string, cursor?: string): Promise<ListPage> {
    const all = [...this.store.keys()].filter((k) => k.startsWith(prefix)).sort();
    const start = cursor !== undefined ? all.findIndex((k) => k > cursor) : 0;
    if (start < 0) return { keys: [] }; // cursor past the end
    const slice = all.slice(start, start + this.pageSize);
    const last = slice[slice.length - 1];
    // More pages remain only when this page filled AND a key beyond it exists.
    const more = last !== undefined && all.indexOf(last) < all.length - 1 && slice.length === this.pageSize;
    return more ? { keys: slice, cursor: last } : { keys: slice };
  }
  entries(): Map<string, Uint8Array> {
    return new Map([...this.store].map(([k, v]) => [k, v.body]));
  }
}
