// Multipart error and retry vectors for the S3 destination: putStream past
// the multipart threshold, exercising the destination's own bounded retry and best-effort abort through
// the public putStream surface with the fetch stub scripting each multipart step (initiate, part,
// complete, abort) by its method and query. The happy multipart shape is proven in
// validate-s3-multipart.ts; here every arm is an error or edge. Behaviour-preserving: same assertions,
// same order as the original main().

import { classifyDestError, destDownReason } from "../src/dest/classify.ts";
import { S3Destination } from "../src/dest/s3.ts";
import {
  ok,
  ENDPOINT,
  BUCKET,
  CREDS,
  FIXED_NOW,
  MiB,
  MULTIPART_SIZE,
  type Captured,
  streamOf,
  zeroStream,
  installFetch,
  res,
} from "./validate-s3dest-shared.ts";

// Part 8: the multipart error and retry paths (putStream past the multipart threshold). These are
// the destination's own bounded retry and best-effort abort, exercised through the public putStream
// surface with the fetch stub scripting each multipart step (initiate, part, complete, abort) by its
// method and query. The happy multipart shape is proven in validate-s3-multipart.ts; here every arm
// is an error or edge: a step that throttles, a step that is terminally bad, a stream that overruns,
// and the empty-stream fallback. setTimeout is shimmed locally so the backoff sleeps do not slow the
// run, and so the Retry-After delay VALUE can be asserted rather than waited on.
async function multipartErrorPaths(): Promise<void> {
  console.log("multipart error + retry paths (putStream over the threshold):");

  // A small helper that classifies a captured multipart request by its query string.
  const isInitiate = (c: Captured): boolean => c.method === "POST" && c.url.includes("uploads=");
  const isPart = (c: Captured): boolean => c.method === "PUT" && /partNumber=/.test(c.url);
  const isComplete = (c: Captured): boolean => c.method === "POST" && /uploadId=/.test(c.url) && !c.url.includes("uploads=");
  const isAbort = (c: Captured): boolean => c.method === "DELETE" && /uploadId=/.test(c.url);
  const initiateBody = `<InitiateMultipartUploadResult><UploadId>up-1</UploadId></InitiateMultipartUploadResult>`;
  const mk = (): S3Destination => new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });

  // 8a: a non-transient initiate failure (HTTP 400) is NOT retried and the upload fails. This drives
  // multipartStep's classification: throttleError builds "status 400", the transient regex does not
  // match it, so the error is rethrown on the first attempt rather than retried.
  {
    const { captures, restore } = installFetch((c) => (isInitiate(c) ? res(400) : res(200)));
    try {
      let threw = false;
      try {
        await mk().putStream("seg/mp-400", zeroStream(MULTIPART_SIZE, 4 * MiB), MULTIPART_SIZE);
      } catch {
        threw = true;
      }
      const initiates = captures.filter(isInitiate);
      ok("a non-transient (400) initiate fails the upload", threw);
      ok("a non-transient initiate is NOT retried (one initiate request only)", initiates.length === 1);
    } finally {
      restore();
    }
  }

  // 8a-worm: R2 refuses a LOCK-BEARING CreateMultipartUpload to a bucket that is not Object-Lock enabled
  // with 501 NotImplemented. The initiate is the
  // only multipart step that carries the Object-Lock headers, and every large segment reaches the store
  // through here rather than through the single-shot PUT, so this is the seal's own path.
  //
  // TWO things had to hold and neither did: multipartStep's transient regex matches "status 501", so the
  // permanent refusal was retried three times per segment; and the exhaustion wrapper builds a NEW Error,
  // which would drop the refusal stamp and take the worm-refused down-reason with it.
  {
    const r2NoLock = new Response("<Error><Code>NotImplemented</Code></Error>", { status: 501 });
    const { captures, restore } = installFetch((c) => (isInitiate(c) ? r2NoLock.clone() : res(200)));
    try {
      const wormDest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, {
        now: FIXED_NOW,
        worm: { mode: "governance", retentionDays: 30 },
      });
      let caught: unknown;
      try {
        await wormDest.putStream("seg/mp-worm-501", zeroStream(MULTIPART_SIZE, 4 * MiB), MULTIPART_SIZE);
      } catch (e) {
        caught = e;
      }
      ok("8a-worm: a WORM-armed initiate refused 501 fails the upload", caught !== undefined);
      ok("8a-worm: the refusal is NOT retried (one initiate only), not three attempts per segment", captures.filter(isInitiate).length === 1);
      ok("8a-worm: the down-reason survives the throw as worm-refused, not a store blip", destDownReason(caught) === "worm-refused");
      ok("8a-worm: and it classifies permanent, so nothing above retries it either", classifyDestError(caught) === "permanent");
    } finally {
      restore();
    }
  }

  // CONTROL for 8a-worm: the SAME 501 from a destination with NO WORM policy is unchanged. It is still a
  // transient fault and still retried the bounded number of times, so the change above added the lock case
  // rather than reclassifying 501.
  {
    const realSetTimeout = globalThis.setTimeout;
    globalThis.setTimeout = ((cb: () => void) => {
      queueMicrotask(cb);
      return 0;
    }) as unknown as typeof globalThis.setTimeout;
    const { captures, restore } = installFetch((c) => (isInitiate(c) ? new Response("<Error><Code>NotImplemented</Code></Error>", { status: 501 }) : res(200)));
    try {
      let threw = false;
      try {
        await mk().putStream("seg/mp-501-noworm", zeroStream(MULTIPART_SIZE, 4 * MiB), MULTIPART_SIZE);
      } catch {
        threw = true;
      }
      ok("8a-worm CONTROL: a 501 initiate with NO WORM policy still throws", threw);
      ok("8a-worm CONTROL: ... and is still retried the bounded number of times (3 attempts)", captures.filter(isInitiate).length === 3);
    } finally {
      restore();
      globalThis.setTimeout = realSetTimeout;
    }
  }

  // 8b: an initiate that returns 200 but carries no UploadId throws the "no UploadId" error.
  {
    const { restore } = installFetch((c) => (isInitiate(c) ? new Response("<InitiateMultipartUploadResult></InitiateMultipartUploadResult>", { status: 200 }) : res(200)));
    try {
      let msg = "";
      try {
        await mk().putStream("seg/mp-no-uploadid", zeroStream(MULTIPART_SIZE, 4 * MiB), MULTIPART_SIZE);
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("an initiate 200 with no UploadId throws a UploadId error", msg.includes("UploadId"));
    } finally {
      restore();
    }
  }

  // 8c: a persistent transient initiate (503 every time) exhausts the bounded retries and throws the
  // wrapped "<label>: <message>" error. setTimeout is shimmed so the three backoff sleeps are instant.
  {
    const realSetTimeout = globalThis.setTimeout;
    globalThis.setTimeout = ((cb: () => void) => {
      queueMicrotask(cb);
      return 0;
    }) as unknown as typeof globalThis.setTimeout;
    const { captures, restore } = installFetch((c) => (isInitiate(c) ? res(503) : res(200)));
    try {
      let threw = false;
      try {
        await mk().putStream("seg/mp-503", zeroStream(MULTIPART_SIZE, 4 * MiB), MULTIPART_SIZE);
      } catch {
        threw = true;
      }
      ok("a persistent 503 initiate throws after exhausting the bounded retries", threw);
      ok("a persistent 503 initiate was retried the bounded number of times (3 attempts)", captures.filter(isInitiate).length === 3);
    } finally {
      restore();
      globalThis.setTimeout = realSetTimeout;
    }
  }

  // 8d: a 503 part carrying an HTTP-date Retry-After is honoured (multipartStep waits at least until
  // that instant). This drives parseRetryAfterMs's HTTP-date branch (the non-numeric value path) and
  // the Retry-After-vs-jitter max in multipartStep. The shimmed setTimeout records the delay VALUE.
  {
    const realSetTimeout = globalThis.setTimeout;
    const delays: number[] = [];
    globalThis.setTimeout = ((cb: () => void, ms?: number) => {
      delays.push(ms ?? 0);
      queueMicrotask(cb);
      return 0;
    }) as unknown as typeof globalThis.setTimeout;
    // An HTTP-date six seconds in the future; parseRetryAfterMs takes the Date.parse branch (the value
    // is not a delta-seconds number) and yields a few seconds, well under the 8 s cap. toUTCString floors
    // to whole seconds, so the parsed delay is a little under six seconds, but always far above the sub-
    // 150 ms jitter, which is what the assertion distinguishes.
    const when = new Date(Date.now() + 6000).toUTCString();
    let failedOnce = false;
    const { captures, restore } = installFetch((c) => {
      if (isInitiate(c)) return new Response(initiateBody, { status: 200 });
      if (isPart(c)) {
        if (!failedOnce) {
          failedOnce = true;
          return res(503, { "retry-after": when });
        }
        return res(200, { etag: '"p-1"' });
      }
      if (isComplete(c)) return new Response("<CompleteMultipartUploadResult></CompleteMultipartUploadResult>", { status: 200 });
      return res(204);
    });
    try {
      await mk().putStream("seg/mp-httpdate", zeroStream(MULTIPART_SIZE, 4 * MiB), MULTIPART_SIZE);
      ok("a part 503 with an HTTP-date Retry-After is retried, not fatal", captures.filter(isPart).length >= 3);
      // The honoured backoff is multiple seconds (driven by the parsed HTTP-date), not the sub-150 ms
      // jitter the first retry would otherwise use; that gap is what proves the HTTP-date was parsed.
      ok("the HTTP-date Retry-After is parsed and honoured (a backoff of several seconds, not jitter)", delays.some((d) => d >= 3000));
    } finally {
      restore();
      globalThis.setTimeout = realSetTimeout;
    }
  }

  // 8d-2: a 503 part whose Retry-After is unparseable (neither a delta-seconds number nor an HTTP-date)
  // carries no server delay, so multipartStep falls back to its own jittered backoff and still retries.
  // This drives parseRetryAfterMs's final null arm (Date.parse of a garbage value is NaN).
  {
    const realSetTimeout = globalThis.setTimeout;
    globalThis.setTimeout = ((cb: () => void) => {
      queueMicrotask(cb);
      return 0;
    }) as unknown as typeof globalThis.setTimeout;
    let failedOnce = false;
    const { captures, restore } = installFetch((c) => {
      if (isInitiate(c)) return new Response(initiateBody, { status: 200 });
      if (isPart(c)) {
        if (!failedOnce) {
          failedOnce = true;
          return res(503, { "retry-after": "not-a-date-or-number" });
        }
        return res(200, { etag: '"p-1"' });
      }
      if (isComplete(c)) return new Response("<CompleteMultipartUploadResult></CompleteMultipartUploadResult>", { status: 200 });
      return res(204);
    });
    try {
      await mk().putStream("seg/mp-garbage-ra", zeroStream(MULTIPART_SIZE, 4 * MiB), MULTIPART_SIZE);
      ok("a 503 with an unparseable Retry-After still retries (falls back to jittered backoff)", captures.filter(isPart).length >= 3);
    } finally {
      restore();
      globalThis.setTimeout = realSetTimeout;
    }
  }

  // 8d-3: a part chunk that crosses the 32 MiB part boundary mid-chunk leaves a non-empty remainder
  // that is carried into the next part. Emitting one 33 MiB chunk forces a 32 MiB part to be carved
  // with a 1 MiB remainder, driving the remainder-non-empty arm of the part-carving loop.
  {
    const { captures, restore } = installFetch((c) => {
      if (isInitiate(c)) return new Response(initiateBody, { status: 200 });
      if (isPart(c)) {
        const m = /partNumber=(\d+)/.exec(c.url);
        return res(200, { etag: `"p-${m ? m[1] : "x"}"` });
      }
      if (isComplete(c)) return new Response("<CompleteMultipartUploadResult></CompleteMultipartUploadResult>", { status: 200 });
      return res(204);
    });
    try {
      // A single 33 MiB chunk: pendingBytes hits 33 MiB >= PART_SIZE, carves a 32 MiB part and keeps a
      // 1 MiB remainder; the trailing flush then sends that remainder as the final part. Two parts.
      await mk().putStream("seg/mp-remainder", streamOf(new Uint8Array(33 * MiB)), 40 * MiB);
      const parts = captures.filter(isPart);
      ok("a chunk crossing the part boundary carries the remainder into a second part", parts.length === 2);
    } finally {
      restore();
    }
  }

  // 8d-4: putStream called with NO declared size falls back to the maximum-segment sealed bound, which
  // is past the multipart threshold, so an undersized (here empty) stream still takes the multipart
  // path, aborts (no parts) and writes the empty object. This drives the size-default nullish arm.
  {
    const { captures, restore } = installFetch((c) => {
      if (isInitiate(c)) return new Response(initiateBody, { status: 200 });
      if (isAbort(c)) return res(204);
      if (c.method === "PUT") return res(200, { etag: '"single"' });
      return res(200);
    });
    try {
      await mk().putStream("seg/mp-nosize", streamOf(new Uint8Array(0)));
      ok("putStream with no declared size takes the multipart path (max sealed bound) and aborts an empty stream", captures.some(isAbort));
      ok("the no-size empty stream then writes the empty object directly", captures.some((c) => c.method === "PUT" && !/partNumber=/.test(c.url) && c.body.length === 0));
    } finally {
      restore();
    }
  }

  // 8e: a part that returns 200 with NO ETag header throws the "no ETag" error from uploadPart.
  {
    const { restore } = installFetch((c) => {
      if (isInitiate(c)) return new Response(initiateBody, { status: 200 });
      if (isPart(c)) return res(200); // 200 but no etag header
      return res(204);
    });
    try {
      let msg = "";
      try {
        await mk().putStream("seg/mp-no-etag", zeroStream(MULTIPART_SIZE, 4 * MiB), MULTIPART_SIZE);
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a part 200 with no ETag throws an ETag error", msg.includes("ETag"));
    } finally {
      restore();
    }
  }

  // 8f: a complete that returns 200 but whose body names an Error is treated as a failure (some stores
  // return a 200 with an error document). This drives completeMultipart's post-200 body check.
  {
    const { restore } = installFetch((c) => {
      if (isInitiate(c)) return new Response(initiateBody, { status: 200 });
      if (isPart(c)) return res(200, { etag: '"p-1"' });
      if (isComplete(c)) return new Response("<Error><Code>InternalError</Code></Error>", { status: 200 });
      return res(204);
    });
    try {
      let msg = "";
      try {
        await mk().putStream("seg/mp-200-error", zeroStream(MULTIPART_SIZE, 4 * MiB), MULTIPART_SIZE);
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a complete 200 with an Error body is treated as a failure", msg.includes("error"));
    } finally {
      restore();
    }
  }

  // 8g: when a step fails terminally, the upload is aborted best-effort; even if the abort ITSELF
  // fails (here the abort returns 500), the original step error is what propagates (the abort failure
  // is swallowed). This drives the inner catch around abortMultipart in putMultipart's cleanup.
  {
    const { captures, restore } = installFetch((c) => {
      if (isInitiate(c)) return new Response(initiateBody, { status: 200 });
      if (isPart(c)) return res(200, { etag: '"p-1"' });
      if (isComplete(c)) return res(400); // terminal, non-transient -> fails the upload
      if (isAbort(c)) return res(500); // the best-effort abort itself fails
      return res(204);
    });
    try {
      const dest = mk();
      let msg = "";
      try {
        await dest.putStream("seg/mp-abort-fails", zeroStream(MULTIPART_SIZE, 4 * MiB), MULTIPART_SIZE);
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a terminal complete still attempts a best-effort abort", captures.some(isAbort));
      ok("an abort that itself fails is swallowed; the original complete error propagates", msg.includes("complete"));
      // multipart-abort-stranded-parts: the swallowed abort failure is TALLIED so the seal driver can surface
      // `multipartAbortFailed` on the run row (the invisible stranded-part-storage fault becomes visible).
      ok("a swallowed abort failure is tallied on the destination (multipart-abort-stranded-parts)", dest.multipartAbortFailures() === 1);
    } finally {
      restore();
    }
  }

  // 8h: a stream that overruns its declared sealed bound mid-multipart throws the "stream exceeds its
  // bound" error (defence in depth: the planner sizes the bound, an overrun is a bug). The declared
  // size is just over the threshold but the stream emits far more bytes than that sealed bound.
  {
    const { restore } = installFetch((c) => {
      if (isInitiate(c)) return new Response(initiateBody, { status: 200 });
      if (isPart(c)) return res(200, { etag: '"p-1"' });
      if (isComplete(c)) return new Response("<CompleteMultipartUploadResult></CompleteMultipartUploadResult>", { status: 200 });
      return res(204);
    });
    try {
      let msg = "";
      try {
        // declared 33 MiB (sealed bound ~34.6 MiB), but the stream emits 96 MiB.
        await mk().putStream("seg/mp-overrun", zeroStream(96 * MiB, 8 * MiB), MULTIPART_SIZE);
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a multipart stream that overruns its sealed bound throws a bound error", msg.includes("bound"));
    } finally {
      restore();
    }
  }

  // 8i: a zero-length chunk in the stream is skipped (the loop's empty-chunk continue), and a declared-
  // large stream that turns out empty aborts the multipart and writes the empty object directly. Both
  // exercise the empty-handling arms in putMultipart that the happy path never reaches.
  {
    const { captures, restore } = installFetch((c) => {
      if (isInitiate(c)) return new Response(initiateBody, { status: 200 });
      if (isAbort(c)) return res(204);
      if (c.method === "PUT") return res(200, { etag: '"single"' });
      return res(200);
    });
    try {
      // Declared large (so the multipart path is taken) but the stream yields only an empty chunk.
      await mk().putStream("seg/mp-empty", streamOf(new Uint8Array(0)), MULTIPART_SIZE);
      ok("a declared-large but empty stream aborts the multipart", captures.some(isAbort));
      ok("an empty stream writes the empty object directly (a single zero-byte PUT)", captures.some((c) => c.method === "PUT" && !/partNumber=/.test(c.url) && c.body.length === 0));
    } finally {
      restore();
    }
  }
}

export async function run(): Promise<void> {
  await multipartErrorPaths();
}
