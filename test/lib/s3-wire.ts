// s3-wire: a stateful, path-style S3 wire for every bucket on one endpoint, installed over globalThis.fetch,
// so a validator drives the real S3Destination (src/dest/s3.ts) against buckets it can read and seed. It
// answers ListObjectsV2 (one page), conditional PUT (If-None-Match: * and If-Match), GET, HEAD and DELETE.
// Requests to any other origin go to the real fetch. `onRequest` runs once for each request the wire answers,
// so a validator can charge a latency to its own clock.

export type WireObject = { bytes: Uint8Array; etag: string };

export class S3Wire {
  readonly buckets = new Map<string, Map<string, WireObject>>();
  private seq = 0;
  private readonly realFetch = globalThis.fetch;
  private readonly endpoint: string;
  private readonly onRequest: () => void;
  constructor(endpoint: string, onRequest: () => void = () => {}) {
    this.endpoint = endpoint;
    this.onRequest = onRequest;
  }

  install(): void {
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (u.origin !== this.endpoint) return this.realFetch(input as RequestInfo, init);
      this.onRequest();
      return this.handle(u, init ?? {});
    }) as typeof fetch;
  }

  uninstall(): void {
    globalThis.fetch = this.realFetch;
  }

  bucket(name: string): Map<string, WireObject> {
    let b = this.buckets.get(name);
    if (!b) {
      b = new Map();
      this.buckets.set(name, b);
    }
    return b;
  }

  // put stores an object directly (no request is charged), with a fresh etag, for a validator that seeds a
  // bucket from a fixture.
  put(bucket: string, key: string, bytes: Uint8Array): void {
    this.bucket(bucket).set(key, { bytes, etag: `"s3-${++this.seq}"` });
  }

  private async handle(u: URL, init: RequestInit): Promise<Response> {
    const method = (init.method ?? "GET").toUpperCase();
    const headers = new Headers(init.headers);
    const parts = u.pathname.split("/");
    const store = this.bucket(parts[1] ?? "");
    const path = parts.slice(2).map(decodeURIComponent).join("/");
    if (method === "GET" && u.searchParams.get("list-type") === "2") {
      const prefix = u.searchParams.get("prefix") ?? "";
      const keys = [...store.keys()].filter((k) => k.startsWith(prefix)).sort();
      const xml = `<ListBucketResult>${keys.map((k) => `<Contents><Key>${k}</Key></Contents>`).join("")}<IsTruncated>false</IsTruncated></ListBucketResult>`;
      return new Response(xml, { status: 200 });
    }
    if (method === "PUT") {
      const existing = store.get(path);
      if (headers.get("if-none-match") === "*" && existing) return new Response("", { status: 412 });
      const im = headers.get("if-match");
      if (im !== null && (!existing || existing.etag !== im)) return new Response("", { status: 412 });
      const body = new Uint8Array(await new Response(init.body as BodyInit).arrayBuffer());
      const etag = `"s3-${++this.seq}"`;
      store.set(path, { bytes: body, etag });
      return new Response("", { status: 200, headers: { etag } });
    }
    if (method === "GET" || method === "HEAD") {
      const r = store.get(path);
      if (!r) return new Response(method === "HEAD" ? null : "<Error><Code>NoSuchKey</Code></Error>", { status: 404 });
      return new Response(method === "HEAD" ? null : r.bytes.slice(), { status: 200, headers: { etag: r.etag, "content-length": String(r.bytes.length) } });
    }
    if (method === "DELETE") {
      store.delete(path);
      return new Response(null, { status: 204 });
    }
    return new Response("", { status: 400 });
  }
}
