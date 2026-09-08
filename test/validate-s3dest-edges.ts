// Cost-meter and error-arm edge vectors for the S3 destination: the meter
// tagging reads as r2ClassB and writes as r2ClassA, the conditional-write/get/list/probe error and
// redirect arms the happy-path suites do not reach, and the drainBounded (small single-PUT path) edge
// arms. Behaviour-preserving: same assertions, same order as the original main().

import { S3Destination, S3_FETCH_TIMEOUT_MS } from "../src/dest/s3.ts";
import { utf8 } from "../src/crypto/bytes.ts";
import {
  ok,
  ENDPOINT,
  BUCKET,
  CREDS,
  FIXED_NOW,
  MULTIPART_SIZE,
  eqBytes,
  streamOf,
  zeroStream,
  installFetch,
  res,
} from "./validate-s3dest-shared.ts";

// Part 9: the cost meter tags reads (GET/HEAD = r2ClassB) and writes (PUT/POST/DELETE = r2ClassA)
// distinctly. The other validators that pass a meter only drive the write class through multipart, so
// the read-class arm of metered's op ternary needs a meter present on a GET/HEAD here.
async function meterTagging(): Promise<void> {
  console.log("meter tags reads as r2ClassB and writes as r2ClassA:");
  const ops: string[] = [];
  const meter = { spend: (_n: number, op?: string) => ops.push(op ?? "untagged") };
  const mk = (): S3Destination => new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, meter: meter as never });
  {
    const { restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      ops.length = 0;
      await mk().put("seg/m1", utf8("x"));
      ok("a PUT is metered as the write class (r2ClassA)", ops.length === 1 && ops[0] === "r2ClassA");
    } finally {
      restore();
    }
  }
  {
    const payload = utf8("bytes");
    const { restore } = installFetch(() => new Response(payload, { status: 200, headers: { etag: '"e"' } }));
    try {
      ops.length = 0;
      await mk().get("seg/m1");
      ok("a GET is metered as the read class (r2ClassB)", ops.length === 1 && ops[0] === "r2ClassB");
    } finally {
      restore();
    }
  }
  {
    const { restore } = installFetch(() => res(200));
    try {
      ops.length = 0;
      await mk().exists("seg/m1");
      ok("a HEAD is metered as the read class (r2ClassB)", ops.length === 1 && ops[0] === "r2ClassB");
    } finally {
      restore();
    }
  }
}

// Part 10: the conditional-write, get, list and probe error arms that the happy-path suites above do
// not reach: a conditional PUT that 3xx-redirects (rejected, not followed), a conditional create whose
// 200 carries no ETag (ok:true with no etag field), a get that errors on a non-404 status, a list and
// an objectLockStatus probe that 3xx-redirect, a signed DELETE that redirects, and an abort whose
// status is neither 204/404 nor ok (the empty-stream abort path propagates it).
async function conditionalGetListEdges(): Promise<void> {
  console.log("conditional/get/list/probe error + redirect arms:");
  const mk = (): S3Destination => new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });

  // 10a: a conditional PUT that returns a 3xx is rejected (redirect:"manual"; the credentialed write is
  // never re-sent to the Location target).
  {
    const { restore } = installFetch(() => res(301, { location: "https://attacker.example.com/steal" }));
    try {
      let msg = "";
      try {
        await mk().putConditional("seg/c-redir", utf8("x"), { ifNoneMatch: "*" });
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a conditional PUT that 3xx-redirects is rejected (not followed)", msg.includes("301") || msg.includes("redirect"));
    } finally {
      restore();
    }
  }

  // 10a-2: a conditional PUT that returns a non-redirect, non-412 error status (500) throws. This is
  // distinct from the 412 (ok:false) and 3xx (redirect) arms: an unexpected server error is fatal.
  {
    const { restore } = installFetch(() => res(500));
    try {
      let msg = "";
      try {
        await mk().putConditional("seg/c-500", utf8("x"), { ifNoneMatch: "*" });
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a conditional PUT on a 500 throws (not ok:false, not a redirect)", msg.includes("500"));
    } finally {
      restore();
    }
  }

  // 10b: a conditional create that succeeds (200) but returns NO ETag header yields ok:true with no
  // etag field (the etag-present ternary's absent arm).
  {
    const { restore } = installFetch(() => new Response("", { status: 200 })); // 200, no etag header
    try {
      const r = await mk().putConditional("seg/c-noetag", utf8("x"), { ifNoneMatch: "*" });
      ok("a conditional create with no ETag returns ok:true and no etag field", r.ok === true && r.etag === undefined);
    } finally {
      restore();
    }
  }

  // 10c: a get on a non-404 error status (500) throws rather than returning null (only 404 is null).
  {
    const { restore } = installFetch(() => res(500));
    try {
      let msg = "";
      try {
        await mk().get("seg/g-500");
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a get on a 500 throws (only a 404 maps to null)", msg.includes("500"));
    } finally {
      restore();
    }
  }

  // 10c-2: a get on a COLD-storage-class object (bucket-lifecycle-to-glacier): S3 answers the GET with a
  // non-2xx (403 here) carrying <Code>InvalidObjectState</Code>. get() reads the error body, classifies it,
  // and throws a DISTINCT `thaw-needed` fault (not a generic `status 403`), so a later verify/restore renders
  // the actionable cause instead of an opaque access error. This drives readS3ErrorCode + the classify branch.
  {
    const { restore } = installFetch(() => new Response("<Error><Code>InvalidObjectState</Code><Message>The operation is not valid for the object's storage class</Message></Error>", { status: 403 }));
    try {
      let msg = "";
      try {
        await mk().get("run/cold/root.manifest.json");
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a get on a cold-storage-class object is classified as thaw-needed (not a generic status error)", /thaw-needed/.test(msg) && !/status 403/.test(msg));
    } finally {
      restore();
    }
  }

  // 10c-3: a non-2xx WITHOUT an InvalidObjectState code (a plain 403) still throws the generic status error
  // (the classifier only special-cases the cold-storage code; every other fault is unchanged). This drives
  // readS3ErrorCode's "no matching code" arm.
  {
    const { restore } = installFetch(() => new Response("<Error><Code>AccessDenied</Code></Error>", { status: 403 }));
    try {
      let msg = "";
      try {
        await mk().get("seg/g-403");
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a plain 403 (no InvalidObjectState) still throws the generic status error", /status 403/.test(msg) && !/thaw-needed/.test(msg));
    } finally {
      restore();
    }
  }

  // 10d: a list that 3xx-redirects is rejected (the listing GET is credentialed too).
  {
    const { restore } = installFetch(() => res(302, { location: "https://attacker.example.com/steal" }));
    try {
      let msg = "";
      try {
        await mk().list("run/");
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a list that 3xx-redirects is rejected (not followed)", msg.includes("302") || msg.includes("redirect"));
    } finally {
      restore();
    }
  }

  // 10e: a signed DELETE that 3xx-redirects is rejected (delete goes via signedRequest, whose redirect
  // guard is the one under test here).
  {
    const { restore } = installFetch(() => res(307, { location: "https://attacker.example.com/steal" }));
    try {
      let msg = "";
      try {
        await mk().delete("seg/d-redir");
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("a signed DELETE that 3xx-redirects is rejected (not followed)", msg.includes("307") || msg.includes("redirect"));
    } finally {
      restore();
    }
  }

  // 10f: an objectLockStatus probe that 3xx-redirects degrades to enabled:"unknown" (the probe never
  // throws and never blocks a backup; a redirect is a cannot-confirm, not a green WORM claim).
  {
    const { restore } = installFetch(() => res(301, { location: "https://attacker.example.com/steal" }));
    try {
      const st = await mk().objectLockStatus!();
      ok("an objectLockStatus probe that redirects reports enabled:\"unknown\"", st.enabled === "unknown");
    } finally {
      restore();
    }
  }

  // 10g: an abort whose status is neither 204/404 nor ok (HTTP 500) throws from abortMultipart. The
  // only path that lets an abort error propagate (rather than being swallowed by the cleanup catch) is
  // the empty-stream branch, which aborts the never-completed upload and then writes the empty object.
  // Here the abort returns 500, so that error surfaces.
  {
    const initiateBody = `<InitiateMultipartUploadResult><UploadId>up-1</UploadId></InitiateMultipartUploadResult>`;
    const { restore } = installFetch((c) => {
      if (c.method === "POST" && c.url.includes("uploads=")) return new Response(initiateBody, { status: 200 });
      if (c.method === "DELETE") return res(500); // abort fails with a non-204/404, non-ok status
      return res(200);
    });
    try {
      let msg = "";
      try {
        await mk().putStream("seg/mp-empty-abort-500", streamOf(new Uint8Array(0)), MULTIPART_SIZE);
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("an abort that returns a non-204/404 error status throws from abortMultipart", msg.includes("abort") && msg.includes("500"));
    } finally {
      restore();
    }
  }
}

// Part 11: drainBounded (the small single-PUT path) edge arms. A stream that emits more bytes than the
// declared sealed bound is rejected before the body is buffered (defence in depth against an unbounded
// buffer in the isolate), and an undefined chunk yielded by the reader is skipped.
async function drainBoundedEdges(): Promise<void> {
  console.log("drainBounded (small-PUT path) edge arms:");
  const mk = (): S3Destination => new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });

  // 11a: a small declared size keeps putStream on the single-buffered-PUT path (drainBounded), but the
  // stream actually emits more than the sealed bound, so drainBounded throws before any PUT is issued.
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      let msg = "";
      try {
        // declared 1 KiB (sealed bound is tiny, well under the multipart threshold), but the stream
        // emits 256 KiB, overrunning the bound.
        await mk().putStream("seg/drain-overrun", zeroStream(256 * 1024, 64 * 1024), 1024);
      } catch (e) {
        msg = e instanceof Error ? e.message : String(e);
      }
      ok("an over-bound small stream is rejected by drainBounded with a bound error", msg.includes("bound"));
      ok("the over-bound stream issued no PUT (rejected before buffering)", captures.length === 0);
    } finally {
      restore();
    }
  }

  // 11b: an undefined chunk yielded by the reader is skipped, and the remaining real bytes drain to a
  // single PUT. A ReadableStream that enqueues undefined surfaces { value: undefined } to the reader,
  // exercising the defensive undefined-chunk continue.
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      const real = utf8("real bytes");
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(undefined as unknown as Uint8Array);
          controller.enqueue(real);
          controller.close();
        },
      });
      await mk().putStream("seg/drain-undef", stream, real.length);
      ok("an undefined chunk is skipped and the real bytes still drain to one PUT", captures.length === 1 && eqBytes(captures[0]!.body, real));
    } finally {
      restore();
    }
  }
}

// Part 12: metered's bounded AbortController timeout. A black-holed
// destination (a fetch that never resolves on its own) must abort at fetchTimeoutMs rather than hanging the
// pass forever; a request that completes comfortably inside the bound is unaffected (no spurious abort).
// fetchTimeoutMs is overridden to a tiny value here so the test proves the abort actually fires without
// waiting out the real 120s production default (S3_FETCH_TIMEOUT_MS).
async function timeoutVectors(): Promise<void> {
  console.log("metered(): a bounded AbortController timeout (item 7) aborts a black-holed endpoint rather than hanging forever");
  const real = globalThis.fetch;
  // A fetch stub that never settles on its own; the ONLY way it resolves is by rejecting when the caller's
  // AbortController fires, mirroring a real hung TCP connection that only ends via the abort signal.
  globalThis.fetch = ((_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    return new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("The operation was aborted.", "AbortError")));
    });
  }) as typeof fetch;
  try {
    const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, fetchTimeoutMs: 30 });
    const started = Date.now();
    let threw: Error | undefined;
    try {
      await dest.put("seg/timeout-test", utf8("x"));
    } catch (e) {
      threw = e as Error;
    }
    const elapsed = Date.now() - started;
    ok("a black-holed endpoint's PUT throws (never hangs) once fetchTimeoutMs elapses", threw !== undefined);
    ok("the error names the timeout (an actionable diagnosis, not a bare abort)", threw?.message.includes("timed out") === true);
    ok(`the call returns promptly, bounded by fetchTimeoutMs (took ${elapsed}ms against a 30ms budget)`, elapsed < 2000);
  } finally {
    globalThis.fetch = real;
  }

  // A request that resolves well inside the bound is unaffected: no spurious abort/timeout.
  {
    const { restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, fetchTimeoutMs: 30 });
      let threw = false;
      try {
        await dest.put("seg/fast", utf8("x"));
      } catch {
        threw = true;
      }
      ok("a request that completes well inside the bound is unaffected (no spurious timeout)", threw === false);
    } finally {
      restore();
    }
  }

  // The default (no opts.fetchTimeoutMs supplied) is the full generous production bound, not the tiny
  // per-test override -- a production destination is never accidentally left on a short fuse.
  {
    const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
    ok("with no override, the destination's timeout is the generous S3_FETCH_TIMEOUT_MS default (120s), not a short test fuse", (dest as unknown as { fetchTimeoutMs: number }).fetchTimeoutMs === S3_FETCH_TIMEOUT_MS);
  }
}

export async function run(): Promise<void> {
  await meterTagging();
  await conditionalGetListEdges();
  await drainBoundedEdges();
  await timeoutVectors();
}
