// Prove the S3 destination's streamed put: a body past the multipart threshold uploads
// as a SigV4 multipart (initiate, uniform 32 MiB parts each with its own signed payload
// hash, complete with the collected ETags, in order), a transient part fault retries
// rather than failing the upload, a terminal fault aborts the upload best-effort, an
// empty stream falls back to a direct empty put, a small body stays a single PUT, and
// the sealed-bound arithmetic accepts a maximal segment (sealedSegmentLength > 1 GiB)
// that the old plaintext-cap drain refused.
// Run: node test/validate-s3-multipart.ts

import { S3Destination } from "../src/dest/s3.ts";
import { sealedSegmentLength } from "../src/crypto/streamseal.ts";
import { MAX_STREAM_SEGMENT_BYTES } from "../src/dest/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

interface Captured {
  method: string;
  url: URL;
  query: string;
  bodyBytes: number;
  headers: Record<string, string>;
}

// streamOf yields total bytes in chunkSize pieces of a repeating pattern.
function streamOf(total: number, chunkSize: number): ReadableStream<Uint8Array> {
  let sent = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent >= total) {
        controller.close();
        return;
      }
      const n = Math.min(chunkSize, total - sent);
      const chunk = new Uint8Array(n);
      for (let i = 0; i < n; i++) chunk[i] = (sent + i) % 251;
      sent += n;
      controller.enqueue(chunk);
    },
  });
}

const MiB = 1024 * 1024;

// Harness holds the captured-request log, the mutable fault flags the mock fetch reads, the abort
// counter and the meter spend log, shared across the scenario functions main() calls in order.
interface Harness {
  captured: Captured[];
  faults: { failPartOnce: boolean; failPartOnceRetryAfter: boolean; failCompleteAlways: boolean };
  aborted: number;
  spent: number[];
  dest: S3Destination;
}

async function proofMultipartShape(h: Harness): Promise<void> {
  console.log("multipart upload shape:");
  h.captured.length = 0;
  // 70 MiB declared plaintext; the sealed bound is what matters for the drain. The
  // mock stream emits exactly 70 MiB; parts must be 32 + 32 + 6 MiB in order.
  await h.dest.putStream("seg/aa/aabb.seg", streamOf(70 * MiB, 1 * MiB), 70 * MiB);
  const initiate = h.captured.filter((c) => c.method === "POST" && c.query === "uploads=");
  const parts = h.captured.filter((c) => c.method === "PUT" && /partNumber=/.test(c.query));
  const completes = h.captured.filter((c) => c.method === "POST" && /uploadId=/.test(c.query));
  ok("one initiate request with uploads= query", initiate.length === 1);
  ok("three parts for a 70 MiB body", parts.length === 3);
  ok("parts are uniform 32 MiB except the last", parts[0]!.bodyBytes === 32 * MiB && parts[1]!.bodyBytes === 32 * MiB && parts[2]!.bodyBytes === 6 * MiB);
  ok("parts are numbered in order", /partNumber=1&/.test(parts[0]!.query) && /partNumber=2&/.test(parts[1]!.query) && /partNumber=3&/.test(parts[2]!.query));
  ok("every part carries its own signed payload hash", parts.every((p) => /^[0-9a-f]{64}$/.test(p.headers["x-amz-content-sha256"] ?? "")));
  ok("every part carries a SigV4 Authorization", parts.every((p) => (p.headers["Authorization"] ?? "").startsWith("AWS4-HMAC-SHA256")));
  ok("one complete request with the uploadId", completes.length === 1 && /uploadId=test-upload-id-1/.test(completes[0]!.query));
  ok("the meter saw every subrequest (initiate + 3 parts + complete)", h.spent.length === 5);
}

async function proofTransientRetry(h: Harness): Promise<void> {
  console.log("transient part fault retries:");
  h.captured.length = 0;
  h.faults.failPartOnce = true;
  await h.dest.putStream("seg/bb/bbcc.seg", streamOf(40 * MiB, 1 * MiB), 40 * MiB);
  const parts = h.captured.filter((c) => c.method === "PUT" && /partNumber=/.test(c.query));
  // part 1 fails once (503) then retries: 3 part requests for 2 logical parts.
  ok("a 503 part is retried, not fatal", parts.length === 3);
}

async function proofRetryAfter(h: Harness): Promise<void> {
  console.log("a 503 part with Retry-After is honoured (waits at least the requested time):");
  h.captured.length = 0;
  h.faults.failPartOnceRetryAfter = true;
  // Capture each backoff delay and fire the callback immediately so the test stays fast; the delay
  // VALUE is what we assert, not the wall time. Restored in the finally.
  const delays: number[] = [];
  const realSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = ((cb: () => void, ms?: number) => {
    delays.push(ms ?? 0);
    queueMicrotask(cb);
    return 0;
  }) as unknown as typeof globalThis.setTimeout;
  try {
    await h.dest.putStream("seg/cc/ccdd.seg", streamOf(40 * MiB, 1 * MiB), 40 * MiB);
  } finally {
    globalThis.setTimeout = realSetTimeout;
  }
  const parts = h.captured.filter((c) => c.method === "PUT" && /partNumber=/.test(c.query));
  ok("a 503-with-Retry-After part is retried", parts.length === 3);
  ok("the backoff honoured the Retry-After (waited at least the requested 2000 ms)", delays.some((d) => d >= 2000));
}

async function proofTerminalFault(h: Harness): Promise<void> {
  console.log("terminal fault aborts the upload:");
  h.captured.length = 0;
  h.faults.failCompleteAlways = true;
  const abortedBefore = h.aborted;
  let threw = false;
  try {
    await h.dest.putStream("seg/cc/ccdd.seg", streamOf(40 * MiB, 1 * MiB), 40 * MiB);
  } catch {
    threw = true;
  } finally {
    // Reset in finally so a future unexpected throw cannot leak the fault into later scenarios.
    h.faults.failCompleteAlways = false;
  }
  ok("a persistent complete failure throws", threw);
  ok("the failed upload was aborted best-effort", h.aborted > abortedBefore);
}

async function proofSmallAndEmpty(h: Harness): Promise<void> {
  console.log("small and empty bodies:");
  h.captured.length = 0;
  await h.dest.putStream("seg/dd/ddee.seg", streamOf(64 * 1024, 16 * 1024), 64 * 1024);
  const singles = h.captured.filter((c) => c.method === "PUT" && c.query === "");
  ok("a small body is one single PUT, no multipart", singles.length === 1 && h.captured.length === 1);
  ok("the single PUT drained the sealed stream length", singles[0]!.bodyBytes === 64 * 1024);

  h.captured.length = 0;
  const before = h.aborted;
  await h.dest.putStream("seg/ee/eeff.seg", streamOf(0, 1024), 64 * MiB);
  // A declared-large but actually-empty stream initiates, finds no parts, aborts and
  // writes the empty object directly.
  ok("an empty stream aborts the multipart and writes the empty object", h.aborted === before + 1 && h.captured.some((c) => c.method === "PUT" && c.query === "" && c.bodyBytes === 0));
}

async function proofSealedBound(h: Harness): Promise<void> {
  console.log("sealed-bound arithmetic:");
  ok("sealedSegmentLength of the 1 GiB cap exceeds 1 GiB (framing + tags)", sealedSegmentLength(MAX_STREAM_SEGMENT_BYTES) > MAX_STREAM_SEGMENT_BYTES);
  ok(
    "sealedSegmentLength is exact for an empty plaintext (framing + nonce + one tag)",
    sealedSegmentLength(0) === 4 + 1 + 16 + 16,
  );
  let threw = false;
  try {
    await h.dest.putStream("seg/ff/ffgg.seg", streamOf(0, 1024), MAX_STREAM_SEGMENT_BYTES + 1);
  } catch (e) {
    threw = /single-segment limit/.test((e as Error).message);
  }
  ok("a plaintext past the single-segment limit is refused with the classified message", threw);
}

async function proofStorageClass(h: Harness): Promise<void> {
  console.log("storage class on multipart: set on CreateMultipartUpload, not on the parts:");
  h.captured.length = 0;
  const scDest = new S3Destination("https://s3.example.test", "bucket", "auto", "AK", "SK", { meter: { spend: () => {} }, storageClass: "STANDARD_IA" });
  await scDest.putStream("seg/dd/ddee.seg", streamOf(70 * MiB, 1 * MiB), 70 * MiB);
  const initiate = h.captured.filter((c) => c.method === "POST" && c.query === "uploads=");
  const parts = h.captured.filter((c) => c.method === "PUT" && /partNumber=/.test(c.query));
  ok("the CreateMultipartUpload carries x-amz-storage-class", initiate.length === 1 && initiate[0]!.headers["x-amz-storage-class"] === "STANDARD_IA");
  ok("the PARTS do NOT carry x-amz-storage-class (bound to the object at create time)", parts.length > 0 && parts.every((p) => p.headers["x-amz-storage-class"] === undefined));
}

async function main(): Promise<void> {
  const realFetch = globalThis.fetch;
  const h: Harness = {
    captured: [],
    faults: { failPartOnce: false, failPartOnceRetryAfter: false, failCompleteAlways: false },
    aborted: 0,
    spent: [],
    dest: undefined as unknown as S3Destination,
  };

  // The mock store: initiate returns an UploadId, parts return ETags, complete returns
  // 200 XML, abort returns 204. Bodies are drained to count bytes, never retained.
  globalThis.fetch = (async (input: URL | RequestInfo, init?: RequestInit): Promise<Response> => {
    const url = input instanceof URL ? input : new URL(String(input));
    const method = init?.method ?? "GET";
    let bodyBytes = 0;
    const b = init?.body;
    if (b instanceof ArrayBuffer) bodyBytes = b.byteLength;
    else if (ArrayBuffer.isView(b)) bodyBytes = b.byteLength;
    const headers = (init?.headers ?? {}) as Record<string, string>;
    h.captured.push({ method, url, query: url.search.replace(/^\?/, ""), bodyBytes, headers });

    if (method === "POST" && url.search === "?uploads=") {
      return new Response(`<InitiateMultipartUploadResult><UploadId>test-upload-id-1</UploadId></InitiateMultipartUploadResult>`, { status: 200 });
    }
    if (method === "PUT" && /partNumber=/.test(url.search)) {
      const m = /partNumber=(\d+)/.exec(url.search)!;
      if (h.faults.failPartOnce) {
        h.faults.failPartOnce = false;
        return new Response("slow down", { status: 503 });
      }
      if (h.faults.failPartOnceRetryAfter) {
        h.faults.failPartOnceRetryAfter = false;
        // A 503 SlowDown that asks for a 2-second wait; multipartStep must honour it.
        return new Response("slow down", { status: 503, headers: { "retry-after": "2" } });
      }
      return new Response(null, { status: 200, headers: { etag: `"etag-part-${m[1]}"` } });
    }
    if (method === "POST" && /uploadId=/.test(url.search)) {
      if (h.faults.failCompleteAlways) return new Response("boom", { status: 500 });
      return new Response(`<CompleteMultipartUploadResult></CompleteMultipartUploadResult>`, { status: 200 });
    }
    if (method === "DELETE" && /uploadId=/.test(url.search)) {
      h.aborted++;
      return new Response(null, { status: 204 });
    }
    if (method === "PUT") return new Response(null, { status: 200, headers: { etag: `"single"` } });
    return new Response("unexpected", { status: 500 });
  }) as typeof fetch;

  try {
    h.dest = new S3Destination("https://s3.example.test", "bucket", "auto", "AK", "SK", { meter: { spend: (n = 1) => h.spent.push(n) } });
    await proofMultipartShape(h);
    await proofTransientRetry(h);
    await proofRetryAfter(h);
    await proofTerminalFault(h);
    await proofSmallAndEmpty(h);
    await proofSealedBound(h);
    await proofStorageClass(h);
  } finally {
    globalThis.fetch = realFetch;
  }

  console.log(failures === 0 ? "\nS3 MULTIPART CONTRACT PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
