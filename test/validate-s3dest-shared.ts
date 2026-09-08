// Shared fixtures for the S3 destination validator suite.
// validate-s3dest.ts was one ~1440-line file; it is now a thin orchestrator that imports and calls a
// run() from each area module. Every area module shares the fetch stub, the ok() assertion sink, the
// fixed clock/credentials and the byte builders defined here, so the split is behaviour-preserving:
// the same assertions run, in the same order, against the same fixtures.
//
// The ok() sink keeps a module-level failure count exactly as the original did. Each area module
// imports ok and calls it; the orchestrator reads getFailures() at the end to decide the exit code.
//
// fetch is stubbed (no network, no deploy): the stub captures the method/url/headers/body of each
// request and returns a scripted Response, so the canonical signed path is checked against what is
// actually put on the wire, exactly as validate-r2dest.ts does for the R2 binding path.

import { hexEncode, utf8 } from "../src/crypto/bytes.ts";
import type { SigV4Creds } from "../src/dest/sigv4.ts";

let failures = 0;
export function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
// getFailures returns the running failure count so the orchestrator can set the process exit code
// after every area has run (the count is module-level, shared across every area that calls ok()).
export function getFailures(): number {
  return failures;
}

export const ENDPOINT = "https://s3.example.com";
export const BUCKET = "archive-bucket";
// The canonical AWS documentation example credentials (not real, no account uses them).
export const CREDS: SigV4Creds = { accessKeyID: "AKIDEXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", region: "us-east-1", service: "s3" };
// A fixed clock so the amzDate (and therefore the SigV4 signature) is deterministic and the
// expected Authorization header can be recomputed independently of wall time.
export const FIXED_NOW = () => new Date("2026-06-08T12:34:56.000Z");
export const FIXED_AMZDATE = "20260608T123456Z";

// Multipart sizing shared between the multipart and edge suites. A 33 MiB declared size whose sealed
// bound clears the 32 MiB multipart threshold, so putStream takes the multipart path rather than a
// single buffered PUT. Kept just past the threshold so the part allocations stay small.
export const MiB = 1024 * 1024;
export const MULTIPART_SIZE = 33 * MiB;

export function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// A deterministic filler past the 64 KiB getRandomValues cap; the bytes are arbitrary (the
// destination hashes whatever it is given), only that they round-trip and have a known length.
export function fill(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) & 0xff;
  return b;
}

export async function sha256Hex(b: Uint8Array): Promise<string> {
  // Copy into a fresh ArrayBuffer-backed view so the argument satisfies BufferSource (a plain Uint8Array
  // may be ArrayBufferLike-backed under TS6's stricter typed-array generics).
  const src = new Uint8Array(b);
  return hexEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", src)));
}

export function streamOf(...chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const c of chunks) controller.enqueue(c);
      controller.close();
    },
  });
}

// A zero-filled stream of `total` bytes emitted in `chunk`-byte pieces, for the multipart path
// (the destination hashes whatever bytes it is given; only the lengths and the count of parts
// matter here, so a zero fill keeps the allocation cheap). Distinct from streamOf above, which
// takes explicit chunks.
export function zeroStream(total: number, chunk: number): ReadableStream<Uint8Array> {
  let sent = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent >= total) {
        controller.close();
        return;
      }
      const n = Math.min(chunk, total - sent);
      controller.enqueue(new Uint8Array(n));
      sent += n;
    },
  });
}

// A captured request: the bytes the destination handed to fetch, plus the normalised header
// view, whether the body was a streaming body (which would force chunked Transfer-Encoding
// with no Content-Length and is exactly the wire shape a buffered, length-delimited PUT must avoid), and the
// redirect option passed in the RequestInit (V15.3.2).
export interface Captured {
  method: string;
  url: string;
  headers: Record<string, string>;
  bodyWasStream: boolean;
  body: Uint8Array;
  redirect: RequestInit["redirect"] | undefined;
}

// installFetch swaps globalThis.fetch for a stub that captures each request and replies with
// the next scripted Response. It records the body as bytes AND records whether the supplied
// body object was a ReadableStream before it was drained, since "buffered, length-known" vs
// "stream, chunked" is the precise distinction the Content-Length fix turns on. Returns the
// capture log and a restore() to put the real fetch back.
export function installFetch(script: (cap: Captured) => Response): { captures: Captured[]; restore: () => void } {
  const captures: Captured[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    const method = (init?.method ?? "GET").toUpperCase();
    const headers: Record<string, string> = {};
    const h = init?.headers;
    if (h) {
      if (h instanceof Headers) for (const [k, v] of h.entries()) headers[k.toLowerCase()] = v;
      else if (Array.isArray(h)) for (const [k, v] of h) headers[k.toLowerCase()] = v;
      else for (const [k, v] of Object.entries(h)) headers[k.toLowerCase()] = String(v);
    }
    const rawBody = init?.body;
    const bodyWasStream = rawBody instanceof ReadableStream;
    let body = new Uint8Array(0);
    if (rawBody instanceof ReadableStream) {
      const parts: Uint8Array[] = [];
      const reader = rawBody.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) parts.push(value);
      }
      let n = 0;
      for (const p of parts) n += p.length;
      body = new Uint8Array(n);
      let off = 0;
      for (const p of parts) {
        body.set(p, off);
        off += p.length;
      }
    } else if (rawBody instanceof Uint8Array) {
      // Copy into a fresh ArrayBuffer-backed array: init.body is a BodyInit so its bytes may be
      // ArrayBufferLike (SharedArrayBuffer-backed), which is not assignable to Uint8Array<ArrayBuffer>.
      body = new Uint8Array(rawBody);
    } else if (rawBody instanceof ArrayBuffer) {
      body = new Uint8Array(rawBody.slice(0));
    } else if (ArrayBuffer.isView(rawBody)) {
      const v = rawBody as ArrayBufferView;
      const copy = new Uint8Array(v.byteLength);
      copy.set(new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
      body = copy;
    } else if (typeof rawBody === "string") {
      body = utf8(rawBody);
    }
    const cap: Captured = { method, url, headers, bodyWasStream, body, redirect: init?.redirect };
    captures.push(cap);
    return script(cap);
  }) as typeof fetch;
  return { captures, restore: () => { globalThis.fetch = real; } };
}

export function res(status: number, headers?: Record<string, string>): Response {
  // Spread headers only when present: ResponseInit.headers is optional and exactOptionalPropertyTypes
  // rejects an explicit undefined.
  return new Response(status === 204 || status === 404 || status === 412 ? null : "", { status, ...(headers !== undefined ? { headers } : {}) });
}
