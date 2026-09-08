import type { Destination, GetResult, PutConditionalResult, WormStatus } from "../dest/types.ts";
import type { ObjectStore } from "../format/reader.ts";

// PrefixedDestination wraps a real Destination and prepends a fixed key prefix to every
// operation, giving the canary a private namespace inside whatever bucket it flies to. The
// seal pipeline and the reader both address objects by their logical keys (seg/..., run/...,
// _RECOVERY/RUNLOG); through this wrapper those land under <prefix>seg/... etc., so a whole
// flight is self-contained and can never collide with a customer archive. The wrapper is a
// pure key rewrite: it adds no behaviour, so the canary exercises the identical put / get /
// conditional-put / delete / list / putStream code paths a real backup uses, only namespaced.
export class PrefixedDestination implements Destination {
  private inner: Destination;
  private prefix: string;

  constructor(inner: Destination, prefix: string) {
    this.inner = inner;
    this.prefix = prefix;
  }

  private k(key: string): string {
    return this.prefix + key;
  }

  get(key: string): Promise<GetResult | null> {
    return this.inner.get(this.k(key));
  }

  put(key: string, body: Uint8Array): Promise<void> {
    return this.inner.put(this.k(key), body);
  }

  putStream(key: string, body: ReadableStream<Uint8Array>, size?: number): Promise<void> {
    return this.inner.putStream(this.k(key), body, size);
  }

  putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    return this.inner.putConditional(this.k(key), body, opts);
  }

  exists(key: string): Promise<boolean> {
    return this.inner.exists(this.k(key));
  }

  delete(key: string): Promise<void> {
    return this.inner.delete(this.k(key));
  }

  async list(prefix: string): Promise<string[]> {
    const keys = await this.inner.list(this.k(prefix));
    // Strip the namespace prefix back off so the caller sees logical keys, the mirror of how
    // the prune lists run/<runId>/ trees; an object outside the namespace (there should be none)
    // is left as-is rather than silently mangled.
    return keys.map((key) => (key.startsWith(this.prefix) ? key.slice(this.prefix.length) : key));
  }
  // No listPage here: the canary never replicates through this wrapper (replicate.ts is the only
  // listPage caller), so the streamed-page primitive is left off and list() covers the canary's
  // small bounded run/<prefix> scans. listPage is optional on the Destination interface for exactly
  // this case (an impl that does not need to stream a large keyspace omits it).

  // objectLockStatus is BUCKET-level (Object-Lock configuration is a property of the whole bucket, not a
  // key prefix), so it forwards to the inner destination unchanged, the canary's namespace prefix does
  // not affect it. Forwarded only when the inner supports the probe; otherwise the canary's wrapped dest
  // honestly reports "unknown" (cannot confirm), never a fabricated verdict.
  async objectLockStatus(): Promise<WormStatus> {
    return this.inner.objectLockStatus ? this.inner.objectLockStatus() : { enabled: "unknown" };
  }
}

// prefixedStore adapts a Destination into the read-side ObjectStore the reader (openRun /
// freshness / attestation) consumes, prepending the same namespace prefix. A missing object
// throws (the reader's contract), so an absent canary object fails the read-back loudly rather
// than verifying nothing.
export function prefixedStore(inner: Destination, prefix: string): ObjectStore {
  return {
    get: async (key: string): Promise<Uint8Array> => {
      const r = await inner.get(prefix + key);
      if (!r) throw new Error(`object ${key} is missing`);
      return r.body;
    },
  };
}
