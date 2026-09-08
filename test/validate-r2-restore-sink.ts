// R2RestoreSink unit tests and oversized-segment guards.
//
// Covers:
//   1. put() round-trips bytes and applies R2 HTTP + custom metadata via r2PutOptions.
//   2. put() with no descriptor calls the binding bare (no extra options object).
//   3. putStream() round-trips a streamed body.
//   4. putStream() enforces the MAX_STREAM_SEGMENT_BYTES ceiling and throws on oversized input.
//   5. sourceType and target() report correctly.
//
// The "never hold a whole copy" claim in the RestoreSink interface is accurate for the
// STREAMED path only: putStream() passes a ReadableStream directly to the R2 binding without
// buffering the bytes in the JS layer. The non-streamed put() does hold the whole value as a
// Uint8Array; both paths are exercised here.
//
// Run: node test/validate-r2-restore-sink.ts
// In-memory doubles only. No network, no deploy, no cost.

import { R2RestoreSink } from "../src/dest/restore-sink.ts";
import type { RestorePutOptions } from "../src/dest/restore-sink.ts";
import { R2_MAX_SINGLE_PUT } from "../src/dest/types.ts";
import { utf8 } from "../src/crypto/bytes.ts";
import { eqBytes, fill, streamOf, toBytes } from "./testutil.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// Records a single put() call the mock binding received. options is optional and may be recorded as
// undefined (a put with no options), so it is widened to allow undefined under exactOptionalPropertyTypes.
interface MockPutRecord {
  key: string;
  bytes: Uint8Array;
  options?: R2PutOptions | undefined;
}

// objMeta returns the R2HTTPMetadata OBJECT form of a put's httpMetadata. R2PutOptions.httpMetadata is
// R2HTTPMetadata | Headers; the production R2RestoreSink always builds the object form, never a Headers, so
// this narrows out the Headers arm for the field reads below. If a Headers ever appeared it would read as
// undefined and the assertion would fail, which is the correct outcome.
function objMeta(options: R2PutOptions | undefined): R2HTTPMetadata | undefined {
  const meta = options?.httpMetadata;
  if (meta === undefined || meta instanceof Headers) return undefined;
  return meta;
}

// A minimal in-memory R2Bucket mock that records put() calls and serves them back via get().
class MemR2Sink {
  readonly puts: MockPutRecord[] = [];
  private store = new Map<string, Uint8Array>();

  async put(key: string, body: ReadableStream<Uint8Array> | ArrayBuffer | ArrayBufferView | string | null | Blob, options?: R2PutOptions): Promise<{ etag: string }> {
    const bytes = await toBytes(body);
    this.store.set(key, bytes);
    this.puts.push({ key, bytes, options });
    return { etag: `etag-${this.puts.length}` };
  }

  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    if (!v) return null;
    return { arrayBuffer: async () => v.slice().buffer, etag: `etag-${key.length}` };
  }

  async head(key: string): Promise<{ etag: string } | null> {
    const v = this.store.get(key);
    return v ? { etag: `etag-${key.length}` } : null;
  }

  // Not used by R2RestoreSink but required by the binding shape.
  list(): never { throw new Error("list not used by R2RestoreSink"); }
  delete(): never { throw new Error("delete not used by R2RestoreSink"); }
}

// Shorthand to grab the first put record from a mock binding.
function p(r2: MemR2Sink): MockPutRecord {
  return r2.puts[0]!;
}

async function main(): Promise<void> {
  const BUCKET = "restore-target";

  // ---- 1. Identity and target ----
  console.log("identity + target:");
  {
    const r2 = new MemR2Sink();
    const sink = new R2RestoreSink(r2 as unknown as R2Bucket, BUCKET);
    ok("sourceType is 'r2'", sink.sourceType === "r2");
    ok("target() returns the bucket name", sink.target() === BUCKET);
  }

  // ---- 2. put() bare (no descriptor) ----
  console.log("\nput() bare (no descriptor):");
  {
    const r2 = new MemR2Sink();
    const sink = new R2RestoreSink(r2 as unknown as R2Bucket, BUCKET);
    const body = utf8("hello restore");
    await sink.put("objects/a.txt", body);
    ok("put() bare: one call to the binding", r2.puts.length === 1);
    const p = r2.puts[0]!;
    ok("put() bare: key is correct", p.key === "objects/a.txt");
    ok("put() bare: bytes round-trip", eqBytes(p.bytes, body));
    // No descriptor: the binding must be called WITHOUT an options object so the binding
    // does not receive an empty R2PutOptions (which would still be a distinct argument).
    ok("put() bare: no options object passed to binding", p.options === undefined);
  }

  // ---- 3. put() with HTTP metadata ----
  console.log("\nput() with HTTP metadata:");
  {
    const r2 = new MemR2Sink();
    const sink = new R2RestoreSink(r2 as unknown as R2Bucket, BUCKET);
    const body = utf8("report content");
    const cacheExpiry = new Date("2026-12-31T23:59:59.000Z");
    const opts: RestorePutOptions = {
      r2: {
        httpMetadata: {
          contentType: "text/plain; charset=utf-8",
          cacheControl: "max-age=86400",
          cacheExpiry: cacheExpiry.toISOString(),
          contentEncoding: "gzip",
        },
      },
    };
    await sink.put("uploads/report.txt", body, opts);
    ok("put() http metadata: one call to binding", r2.puts.length === 1);
    const p = r2.puts[0]!;
    ok("put() http metadata: key correct", p.key === "uploads/report.txt");
    ok("put() http metadata: bytes round-trip", eqBytes(p.bytes, body));
    ok("put() http metadata: httpMetadata applied", !!p.options?.httpMetadata);
    ok("put() http metadata: contentType", objMeta(p.options)?.contentType === "text/plain; charset=utf-8");
    ok("put() http metadata: cacheControl", objMeta(p.options)?.cacheControl === "max-age=86400");
    ok("put() http metadata: contentEncoding", objMeta(p.options)?.contentEncoding === "gzip");
    // cacheExpiry is stored as an ISO string and must be rebuilt as a Date for the binding.
    ok("put() http metadata: cacheExpiry rebuilt as Date", objMeta(p.options)?.cacheExpiry instanceof Date);
    ok("put() http metadata: cacheExpiry value correct",
      objMeta(p.options)?.cacheExpiry instanceof Date &&
      objMeta(p.options)?.cacheExpiry?.toISOString() === cacheExpiry.toISOString());
  }

  // ---- 4. put() with custom metadata ----
  console.log("\nput() with custom metadata:");
  {
    const r2 = new MemR2Sink();
    const sink = new R2RestoreSink(r2 as unknown as R2Bucket, BUCKET);
    const body = fill(512);
    const opts: RestorePutOptions = {
      r2: {
        customMetadata: { team: "ops", origin: "ingest", version: "3" },
      },
    };
    await sink.put("data/blob.bin", body, opts);
    ok("put() custom metadata: options applied", !!p(r2).options?.customMetadata);
    ok("put() custom metadata: team", p(r2).options?.customMetadata?.["team"] === "ops");
    ok("put() custom metadata: origin", p(r2).options?.customMetadata?.["origin"] === "ingest");
    ok("put() custom metadata: version", p(r2).options?.customMetadata?.["version"] === "3");
    ok("put() custom metadata: bytes round-trip", eqBytes(p(r2).bytes, body));
  }

  // ---- 5. putStream() round-trips a small streamed body ----
  console.log("\nputStream() round-trip:");
  {
    const r2 = new MemR2Sink();
    const sink = new R2RestoreSink(r2 as unknown as R2Bucket, BUCKET);
    const body = fill(200_000);
    await sink.putStream("media/video.mp4", streamOf(body), body.length);
    ok("putStream() small: one call to binding", r2.puts.length === 1);
    ok("putStream() small: key correct", r2.puts[0]!.key === "media/video.mp4");
    ok("putStream() small: bytes round-trip", eqBytes(r2.puts[0]!.bytes, body));
    ok("putStream() small: no options (bare)", r2.puts[0]!.options === undefined);
  }

  // ---- 6. putStream() with HTTP + custom metadata ----
  console.log("\nputStream() with metadata:");
  {
    const r2 = new MemR2Sink();
    const sink = new R2RestoreSink(r2 as unknown as R2Bucket, BUCKET);
    const body = fill(1_000);
    const opts: RestorePutOptions = {
      r2: {
        httpMetadata: { contentType: "video/mp4", cacheControl: "public, max-age=31536000" },
        customMetadata: { author: "alice" },
      },
    };
    await sink.putStream("media/clip.mp4", streamOf(body), body.length, opts);
    const put = r2.puts[0]!;
    ok("putStream() with metadata: bytes round-trip", eqBytes(put.bytes, body));
    ok("putStream() with metadata: contentType applied", objMeta(put.options)?.contentType === "video/mp4");
    ok("putStream() with metadata: cacheControl applied", objMeta(put.options)?.cacheControl === "public, max-age=31536000");
    ok("putStream() with metadata: customMetadata author", put.options?.customMetadata?.["author"] === "alice");
  }

  // ---- 7. putStream() oversized guard ----
  // The guard must throw BEFORE calling the binding, so a byte too many never reaches R2.
  // We use a size one byte past the R2_MAX_SINGLE_PUT ceiling (the streaming restore lifts the
  // in-account ceiling from the 1 GiB per-segment limit to R2's single-PUT maximum).
  console.log("\nputStream() oversized guard:");
  {
    const r2 = new MemR2Sink();
    const sink = new R2RestoreSink(r2 as unknown as R2Bucket, BUCKET);
    const oversizedSize = R2_MAX_SINGLE_PUT + 1;
    // The stream body is a tiny placeholder; the guard fires on the `size` argument before
    // the binding is called, so the body bytes are irrelevant.
    const tinyBody = streamOf(new Uint8Array(8));
    let threw = false;
    let errMessage = "";
    try {
      await sink.putStream("oversized/key", tinyBody, oversizedSize);
    } catch (e) {
      threw = true;
      errMessage = (e as Error).message;
    }
    ok("putStream() oversized: throws on size > R2_MAX_SINGLE_PUT", threw);
    ok("putStream() oversized: error names the key", errMessage.includes("oversized/key"));
    // The oversized object is chained across segments on backup and IS recoverable offline; the error now
    // steers to the downpipe CLI (the in-account path cannot reassemble it in a 128 MB isolate) rather than
    // quoting a raw byte limit that reads as "unrecoverable".
    ok("putStream() oversized: error steers recovery to the offline downpipe CLI", /offline/.test(errMessage) && /downpipe CLI/.test(errMessage));
    // The binding must NOT have been called: the guard fires before any byte reaches R2.
    ok("putStream() oversized: binding was NOT called (guard fires pre-binding)", r2.puts.length === 0);
  }

  // ---- 8. putStream() at exactly the ceiling passes ----
  console.log("\nputStream() at exactly the ceiling:");
  {
    const r2 = new MemR2Sink();
    const sink = new R2RestoreSink(r2 as unknown as R2Bucket, BUCKET);
    // Body is minimal (mock does not validate that stream length matches size).
    await sink.putStream("boundary/key", streamOf(new Uint8Array(8)), R2_MAX_SINGLE_PUT);
    ok("putStream() at ceiling: does not throw", r2.puts.length === 1);
    ok("putStream() at ceiling: key correct", r2.puts[0]!.key === "boundary/key");
  }

  // ---- 9. putStream() at size 0 passes (empty restore) ----
  console.log("\nputStream() at size 0:");
  {
    const r2 = new MemR2Sink();
    const sink = new R2RestoreSink(r2 as unknown as R2Bucket, BUCKET);
    await sink.putStream("empty/key", streamOf(new Uint8Array(0)), 0);
    ok("putStream() size 0: does not throw", r2.puts.length === 1);
  }

  // ---- 10. cacheExpiry with a malformed ISO string is dropped (not written as Invalid Date) ----
  console.log("\nput() malformed cacheExpiry dropped:");
  {
    const r2 = new MemR2Sink();
    const sink = new R2RestoreSink(r2 as unknown as R2Bucket, BUCKET);
    const opts: RestorePutOptions = {
      r2: {
        httpMetadata: {
          contentType: "text/plain",
          cacheExpiry: "not-a-date",
        },
      },
    };
    await sink.put("meta/bad-expiry.txt", utf8("body"), opts);
    const put = r2.puts[0]!;
    ok("put() malformed cacheExpiry: contentType still applied", objMeta(put.options)?.contentType === "text/plain");
    // A malformed cacheExpiry must be DROPPED rather than written as an Invalid Date.
    ok("put() malformed cacheExpiry: cacheExpiry not on httpMetadata", objMeta(put.options)?.cacheExpiry === undefined);
  }

  // ---- 11. empty httpMetadata / customMetadata maps yield no options ----
  console.log("\nput() empty descriptor yields no options:");
  {
    const r2 = new MemR2Sink();
    const sink = new R2RestoreSink(r2 as unknown as R2Bucket, BUCKET);
    const opts: RestorePutOptions = {
      r2: {
        httpMetadata: {},
        customMetadata: {},
      },
    };
    await sink.put("empty/descriptor.txt", utf8("body"), opts);
    const put = r2.puts[0]!;
    // An all-empty descriptor must produce no options (the binding is called bare).
    ok("put() empty descriptor: no options passed to binding", put.options === undefined);
  }

  console.log(failures === 0
    ? "\nR2 RESTORE SINK + OVERSIZED GUARD PASS"
    : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
