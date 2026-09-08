// PUT wire-shape vectors for the S3 destination: the production PUT wire
// shape and the putStream drain-to-a-single-length-delimited-PUT path.
// Behaviour-preserving: same assertions, same order as the original main().

import { S3Destination } from "../src/dest/s3.ts";
import { signV4, encodePath } from "../src/dest/sigv4.ts";
import { utf8 } from "../src/crypto/bytes.ts";
import { MAX_STREAM_SEGMENT_BYTES } from "../src/dest/types.ts";
import {
  ok,
  ENDPOINT,
  BUCKET,
  CREDS,
  FIXED_NOW,
  FIXED_AMZDATE,
  eqBytes,
  fill,
  sha256Hex,
  streamOf,
  installFetch,
  res,
} from "./validate-s3dest-shared.ts";

// Part 1: the production PUT wire shape.
async function putWireShape(): Promise<void> {
  console.log("PUT wire shape (length-delimited, signed):");
  const { captures, restore } = installFetch(() => res(200, { etag: '"etag-1"' }));
  try {
    const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
    const key = "seg/0001";
    const body = utf8("a sealed segment body");
    await dest.put(key, body);

    ok("exactly one request was issued", captures.length === 1);
    const c = captures[0]!;
    ok("method is PUT", c.method === "PUT");
    ok("url is endpoint/bucket/encoded-key", c.url === `${ENDPOINT}/${BUCKET}/${encodePath(key)}`);

    // The crux: the body must be a buffered (length-known) body, NOT a ReadableStream. A
    // stream body emits chunked Transfer-Encoding with no Content-Length, which real S3/R2
    // reject; a buffered body is length-delimited so the runtime sends a definite
    // Content-Length. We assert the body is buffered and carries the full segment bytes.
    ok("body is buffered, not a stream (so Content-Length, not chunked)", !c.bodyWasStream);
    ok("buffered body carries the whole segment (a measurable length)", eqBytes(c.body, body));

    // A SigV4 Authorization header is present and well formed, and equals an independently
    // recomputed signature over the real body hash (UNSIGNED-PAYLOAD is NOT used on put).
    const auth = c.headers["authorization"];
    ok("Authorization header is present", typeof auth === "string" && auth.length > 0);
    ok("Authorization is an AWS4-HMAC-SHA256 SigV4 credential", !!auth && auth.startsWith("AWS4-HMAC-SHA256 Credential="));
    const payloadHash = await sha256Hex(body);
    ok("x-amz-content-sha256 binds the real body hash (not UNSIGNED-PAYLOAD)", c.headers["x-amz-content-sha256"] === payloadHash);
    ok("x-amz-date is the fixed amzDate", c.headers["x-amz-date"] === FIXED_AMZDATE);
    const u = new URL(c.url);
    const expectAuth = await signV4("PUT", u.pathname, "", { host: u.host, "x-amz-date": FIXED_AMZDATE, "x-amz-content-sha256": payloadHash }, payloadHash, FIXED_AMZDATE, CREDS);
    ok("Authorization matches an independently recomputed SigV4 signature", auth === expectAuth);
  } finally {
    restore();
  }
}

// Part 2: putStream produces the SAME length-delimited signed shape as put. The
// pre-fix code passed a ReadableStream straight to fetch (chunked, no length); the fix drains
// the bounded segment and PUTs it as one buffered, hashed body.
async function streamWireShape(): Promise<void> {
  console.log("putStream wire shape (drained to a single length-delimited PUT):");
  const { captures, restore } = installFetch(() => res(200, { etag: '"etag-s"' }));
  try {
    const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
    const key = "seg/streamed";
    // Two chunks, so a naive single-chunk assumption would be caught; the wire body must be
    // the concatenation of both.
    const part1 = fill(120_000);
    const part2 = fill(80_000);
    const whole = new Uint8Array(part1.length + part2.length);
    whole.set(part1, 0);
    whole.set(part2, part1.length);
    await dest.putStream(key, streamOf(part1, part2), whole.length);

    ok("exactly one request was issued for the stream", captures.length === 1);
    const c = captures[0]!;
    ok("streamed put uses method PUT", c.method === "PUT");
    ok("streamed put targets endpoint/bucket/key", c.url === `${ENDPOINT}/${BUCKET}/${encodePath(key)}`);
    ok("streamed put body is buffered, NOT a stream (no chunked Transfer-Encoding)", !c.bodyWasStream);
    ok("streamed put body is the full drained segment", eqBytes(c.body, whole));
    const auth = c.headers["authorization"];
    ok("streamed put carries a SigV4 Authorization header", !!auth && auth.startsWith("AWS4-HMAC-SHA256 Credential="));
    const payloadHash = await sha256Hex(whole);
    ok("streamed put binds the real drained body hash (not UNSIGNED-PAYLOAD)", c.headers["x-amz-content-sha256"] === payloadHash);
  } finally {
    restore();
  }

  // The oversized-stream guard still throws (the 1 GiB ceiling is defence in depth). We assert
  // via the declared size without allocating a gigabyte: putStream rejects before draining.
  console.log("putStream ceiling guard:");
  {
    const { captures, restore } = installFetch(() => res(200));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      let threw = false;
      try {
        await dest.putStream("seg/huge", streamOf(new Uint8Array(1)), MAX_STREAM_SEGMENT_BYTES + 1);
      } catch {
        threw = true;
      }
      ok("declared-oversize segment is rejected before any request", threw && captures.length === 0);
    } finally {
      restore();
    }
  }
}

export async function run(): Promise<void> {
  await putWireShape();
  await streamWireShape();
}
