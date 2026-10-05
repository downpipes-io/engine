// An in-memory R2 binding with the conditional puts (onlyIf etagMatches / etagDoesNotMatch) the R2
// destination adapter uses, for validators that drive buildDestination(env) against DEST_R2.

import { concat } from "../../src/crypto/bytes.ts";

export function memoryBucket(): { bucket: Record<string, unknown>; store: Map<string, Uint8Array> } {
  const store = new Map<string, Uint8Array>();
  const tags = new Map<string, string>();
  let seq = 0;
  const drain = async (body: unknown): Promise<Uint8Array> => {
    if (body instanceof Uint8Array) return body;
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    if (typeof body === "string") return new TextEncoder().encode(body);
    const reader = (body as ReadableStream<Uint8Array>).getReader();
    const parts: Uint8Array[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) parts.push(value);
    }
    return concat(...parts);
  };
  const objectFor = (key: string, bytes: Uint8Array): Record<string, unknown> => ({
    key,
    size: bytes.length,
    etag: tags.get(key) ?? "e0",
    httpEtag: `"${tags.get(key) ?? "e0"}"`,
    uploaded: new Date(0),
    arrayBuffer: async () => bytes.slice().buffer,
  });
  const bucket = {
    put: async (key: string, body: unknown, opts?: { onlyIf?: { etagMatches?: string; etagDoesNotMatch?: string } }): Promise<Record<string, unknown> | null> => {
      const bytes = await drain(body);
      const cur = tags.get(key);
      if (opts?.onlyIf?.etagDoesNotMatch !== undefined && (opts.onlyIf.etagDoesNotMatch === "*" ? cur !== undefined : cur === opts.onlyIf.etagDoesNotMatch)) return null;
      if (opts?.onlyIf?.etagMatches !== undefined && cur !== opts.onlyIf.etagMatches) return null;
      store.set(key, bytes);
      tags.set(key, `e${++seq}`);
      return objectFor(key, bytes);
    },
    get: async (key: string): Promise<Record<string, unknown> | null> => {
      const v = store.get(key);
      return v ? objectFor(key, v) : null;
    },
    head: async (key: string): Promise<Record<string, unknown> | null> => {
      const v = store.get(key);
      return v ? objectFor(key, v) : null;
    },
    delete: async (keys: string | string[]): Promise<void> => {
      for (const k of Array.isArray(keys) ? keys : [keys]) {
        store.delete(k);
        tags.delete(k);
      }
    },
    list: async (opts?: { prefix?: string }) => ({ objects: [...store.entries()].filter(([k]) => k.startsWith(opts?.prefix ?? "")).map(([k, v]) => objectFor(k, v)), truncated: false, delimitedPrefixes: [] }),
  };
  return { bucket, store };
}

