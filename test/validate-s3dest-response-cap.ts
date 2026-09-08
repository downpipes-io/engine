// Destination response-body read caps (V12.3.1): a destination response is now bounded when
// it is buffered regardless of whether (or what) Content-Length claims, so a malicious/compromised/
// misbehaving S3-compatible endpoint cannot OOM the Worker by omitting the header (chunked transfer-
// encoding, the common real shape) or by advertising a value that understates its real body. Covers all
// six read call sites the finding named: get(), readS3ErrorCode (via get()'s error path), listPage(),
// objectLockStatus(), put()/putConditional()'s error-body read, and initiateMultipart()/
// completeMultipart(). Behaviour is unchanged for every conforming response; only what happens when a
// response omits or understates its length changes. A literal 1 GiB overrun of get()'s own ceiling is
// deliberately NOT exercised here (that would mean allocating past 1 GiB in a routine test): the shared
// drainResponseBounded primitive's numeric-threshold enforcement is proven directly (Part 12) with a
// small injected limit, the same discipline validate-s3dest-edges.ts's drainBoundedEdges() (Part 11a)
// already uses for the raw-stream drainBounded via putStream's size param.

import { S3Destination } from "../src/dest/s3.ts";
import { drainResponseBounded } from "../src/dest/s3-stream.ts";
import { MAX_DEST_TEXT_BYTES, MAX_LIST_PAGE_BYTES } from "../src/dest/types.ts";
import { utf8 } from "../src/crypto/bytes.ts";
import { ok, ENDPOINT, BUCKET, CREDS, FIXED_NOW, MiB, MULTIPART_SIZE, type Captured, zeroStream, installFetch, res } from "./validate-s3dest-shared.ts";

const mk = (): S3Destination => new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });

// Part 12: drainResponseBounded, the primitive every one of the six call sites now shares, bounds a
// Response by its ACTUAL bytes as they stream in. It never inspects Content-Length at all (that header is
// the CALLER's business, e.g. get()'s cheap early exit in Part 13 below) -- which is exactly why a
// response that omits or understates the header gets the same ceiling as one that is honest about it.
async function drainResponseBoundedPrimitive(): Promise<void> {
  console.log("drainResponseBounded: bounds a Response by its actual bytes, never by Content-Length:");

  // 12a: no body at all (a HEAD reply, or a 204/304) drains to an empty array rather than throwing --
  // there is nothing to bound.
  {
    const out = await drainResponseBounded(new Response(null, { status: 204 }), 100, "no-body");
    ok("a null-body response drains to an empty array", out.length === 0);
  }

  // 12b: a body under the limit, with NO Content-Length header (the common real-world "chunked" shape,
  // and what a Response built from a stream carries by default -- confirmed below), drains whole.
  {
    const resp = new Response(zeroStream(200, 64), { status: 200 });
    ok("a stream body carries no content-length header by default", resp.headers.get("content-length") === null);
    const out = await drainResponseBounded(resp, 10_000, "small-no-cl");
    ok("a small body with no content-length drains whole (regression pin)", out.length === 200);
  }

  // 12c: a body that exceeds the limit throws -- the exact ML-20 gap: a store that omits Content-Length
  // was previously read via resp.arrayBuffer()/resp.text() with NO ceiling at all.
  {
    let msg = "";
    try {
      await drainResponseBounded(new Response(zeroStream(4096, 512), { status: 200 }), 1000, "no-cl-overrun");
    } catch (e) {
      msg = e instanceof Error ? e.message : String(e);
    }
    ok("a body exceeding the limit throws a bound error even with no content-length header", /bound/.test(msg));
  }
}

// Part 13: get(), the site the finding cites directly, through the public S3Destination surface.
async function getIntegration(): Promise<void> {
  console.log("get(): the response-cap fix through the public S3Destination surface:");

  // 13a: a normal small body with NO content-length header -- the common real-world shape (every
  // existing get() test elsewhere in this suite already exercises it incidentally) -- is unchanged:
  // get() still returns the real bytes and ETag.
  {
    const payload = utf8("small manifest bytes");
    const { restore } = installFetch(() => new Response(payload, { status: 200, headers: { etag: '"e1"' } }));
    try {
      const r = await mk().get("run/x/root.manifest.json");
      ok("get() with no content-length and a small body is unchanged (regression pin)", r !== null && r.etag === '"e1"' && r.body.length === payload.length);
    } finally {
      restore();
    }
  }

  // 13b: an advertised Content-Length past the cap still fails FAST, before any body is read -- the
  // pre-existing early-exit guard is untouched by this fix (kept as a cheap early exit per the fix): only
  // one request is issued and the tiny stream body behind it is never drained.
  {
    const { captures, restore } = installFetch(() => new Response(zeroStream(10, 5), { status: 200, headers: { "content-length": "5000000000", etag: '"e2"' } }));
    try {
      let msg = "";
      try {
        await mk().get("run/x/root.manifest.json");
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("an advertised Content-Length over the cap still fails fast (early exit preserved)", /Content-Length/.test(msg) && /exceeds/.test(msg));
      ok("exactly one request was issued (the fast exit did not retry)", captures.length === 1);
    } finally {
      restore();
    }
  }

  // 13c: a Content-Length that UNDERSTATES the real body (a "lying" header) gets no special trust: get()
  // returns the FULL actual bytes, not the advertised (smaller) count. The read now always flows through
  // the same bounded reader regardless of what the header claims (V12.3.1), so a lying header can no
  // longer mask an oversized body the way an unbounded resp.arrayBuffer() previously would have let it.
  {
    const real = new Uint8Array(4096);
    const { restore } = installFetch(() => new Response(real, { status: 200, headers: { "content-length": "10", etag: '"e3"' } }));
    try {
      const r = await mk().get("run/x/root.manifest.json");
      ok("a lying (understated) Content-Length is never trusted: the full actual body is still returned", r !== null && r.body.length === 4096 && r.etag === '"e3"');
    } finally {
      restore();
    }
  }

  // 13d: readS3ErrorCode's own bound (the finding's other named gap): a 403 with NO content-length and an
  // oversized error body still degrades cleanly. readS3ErrorCode's own try/catch swallows the bound-
  // exceeded read to "", so the cold-storage classifier finds no InvalidObjectState code and get() falls
  // through to the plain "status 403" -- not a hang, not an OOM.
  {
    const oversized = MAX_DEST_TEXT_BYTES + 1024;
    const { restore } = installFetch(() => new Response(zeroStream(oversized, 8 * 1024), { status: 403 }));
    try {
      let msg = "";
      try {
        await mk().get("run/x/root.manifest.json");
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a 403 with no content-length and an oversized error body still degrades to a plain status error", /status 403/.test(msg) && !msg.includes("thaw-needed"));
    } finally {
      restore();
    }
  }
}

// Part 14: listPage() pages a listing at 1000 keys regardless of bucket size, so a conforming page never
// approaches MAX_LIST_PAGE_BYTES (sized generously above the largest page this system's own key shapes
// could produce -- see types.ts); a body that does is refused rather than buffered whole.
async function listPageOverrun(): Promise<void> {
  console.log("listPage(): a page over the list cap throws rather than buffering unbounded:");
  const oversized = MAX_LIST_PAGE_BYTES + 4096;
  const { restore } = installFetch(() => new Response(zeroStream(oversized, 64 * 1024), { status: 200 }));
  try {
    let msg = "";
    try {
      await mk().list("run/");
    } catch (e) {
      msg = e instanceof Error ? e.message : String(e);
    }
    ok("a ListObjectsV2 page with no content-length over the list cap throws a bound error", /bound/.test(msg));
  } finally {
    restore();
  }
}

// Part 15: objectLockStatus() is a probe -- it never throws, so the bound composes with its existing
// catch-all (a fault, including a bound-exceeded read, is the same safe "cannot confirm" reading a
// transport error or an unparseable body already produced).
async function objectLockStatusOverrun(): Promise<void> {
  console.log("objectLockStatus(): an oversized probe body composes with the existing catch-all:");
  const oversized = MAX_DEST_TEXT_BYTES + 1024;
  const { restore } = installFetch(() => new Response(zeroStream(oversized, 8 * 1024), { status: 200 }));
  try {
    const st = await mk().objectLockStatus!();
    ok('an oversized object-lock probe body (no content-length) resolves to enabled:"unknown", not a throw/hang', st.enabled === "unknown");
  } finally {
    restore();
  }
}

// Part 16: put()/putConditional()'s error-body read (s3.ts's errorBodyOf) is swallowed to "" on any
// hiccup, exactly as the unbounded resp.text().catch(() => "") it replaces already was on a network
// fault -- a bound-exceeded read degrades the same way, so the write still fails with the normal,
// legible s3WriteFailure rather than hanging or exhausting isolate memory on the error body itself.
async function writeErrorBodyOverrun(): Promise<void> {
  console.log("put()/putConditional(): an oversized error body still fails cleanly (not a hang):");
  const oversized = MAX_DEST_TEXT_BYTES + 1024;

  {
    const { restore } = installFetch(() => new Response(zeroStream(oversized, 8 * 1024), { status: 500 }));
    try {
      let msg = "";
      try {
        await mk().put("seg/write-500", utf8("x"));
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a PUT 500 with no content-length and an oversized error body still throws a normal write failure", msg.includes("500"));
    } finally {
      restore();
    }
  }

  {
    const { restore } = installFetch(() => new Response(zeroStream(oversized, 8 * 1024), { status: 500 }));
    try {
      let msg = "";
      try {
        await mk().putConditional("seg/write-cond-500", utf8("x"), { ifNoneMatch: "*" });
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a conditional PUT 500 with no content-length and an oversized error body still throws a normal write failure", msg.includes("500"));
    } finally {
      restore();
    }
  }
}

// Part 17: initiateMultipart()/completeMultipart() have no surrounding try/catch (unlike get()'s error
// path or the probe), so a bound-exceeded read is expected to propagate directly as a genuine error --
// still a clean, legible failure, never an unbounded buffer.
async function multipartResponseOverrun(): Promise<void> {
  console.log("initiateMultipart()/completeMultipart(): an oversized 200 body throws rather than buffering unbounded:");
  const isInitiate = (c: Captured): boolean => c.method === "POST" && c.url.includes("uploads=");
  const isPart = (c: Captured): boolean => c.method === "PUT" && /partNumber=/.test(c.url);
  const isComplete = (c: Captured): boolean => c.method === "POST" && /uploadId=/.test(c.url) && !c.url.includes("uploads=");
  const oversized = MAX_DEST_TEXT_BYTES + 1024;

  // 17a: initiate returns a 200 with no content-length and an oversized body before any part is sent.
  {
    const { restore } = installFetch((c) => (isInitiate(c) ? new Response(zeroStream(oversized, 8 * 1024), { status: 200 }) : res(200)));
    try {
      let msg = "";
      try {
        await mk().putStream("seg/mp-initiate-big", zeroStream(MULTIPART_SIZE, 4 * MiB), MULTIPART_SIZE);
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("an initiate 200 with no content-length and an oversized body throws a bound error, not a buffered parse", /bound/.test(msg));
    } finally {
      restore();
    }
  }

  // 17b: initiate and the one part succeed normally; complete returns a 200 with no content-length and
  // an oversized body.
  {
    const { restore } = installFetch((c) => {
      if (isInitiate(c)) return new Response(`<InitiateMultipartUploadResult><UploadId>up-cap</UploadId></InitiateMultipartUploadResult>`, { status: 200 });
      if (isPart(c)) return res(200, { etag: '"p-1"' });
      if (isComplete(c)) return new Response(zeroStream(oversized, 8 * 1024), { status: 200 });
      return res(204);
    });
    try {
      let msg = "";
      try {
        await mk().putStream("seg/mp-complete-big", zeroStream(MULTIPART_SIZE, 4 * MiB), MULTIPART_SIZE);
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a complete 200 with no content-length and an oversized body throws a bound error, not a buffered parse", /bound/.test(msg));
    } finally {
      restore();
    }
  }
}

export async function run(): Promise<void> {
  await drainResponseBoundedPrimitive();
  await getIntegration();
  await listPageOverrun();
  await objectLockStatusOverrun();
  await writeErrorBodyOverrun();
  await multipartResponseOverrun();
}
