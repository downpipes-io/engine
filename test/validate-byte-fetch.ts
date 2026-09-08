// Validates the byte-capture primitive (src/sources/byte-fetch.ts): the real makeByteFetcher driven by a
// fake fetch over an in-memory blob, the captureBlob size-gating (buffer / stream / skip), and the
// INTEGRITY-CRITICAL two-pass contract: a streamed value's open() yields byte-identical bytes every time
// it is opened (the seal opens it once to address and once to seal), windowed via HTTP Range, and pinned
// to the probe ETag so a mid-capture change fails LOUDLY rather than producing a corrupt segment. No
// network: the fake fetch serves bytes from memory with Range + ETag + If-Match semantics.

import { sha384 } from "@noble/hashes/sha2.js";
import { makeByteFetcher, captureBlob, httpStreamingValue, type ByteTarget } from "../src/sources/byte-fetch.ts";
import { isCloudflareStreamUrl } from "../src/sources/stream.ts";
import { sealRecordToDest, type RecordSealDeps } from "../src/seal/record.ts";
import { MAX_SINGLE_RECORD_CONTENT_BYTES } from "../src/seal/budget.ts";
import { isIncompleteMarkerValue } from "../src/seal/marker.ts";
import { hexEncode } from "../src/crypto/bytes.ts";
import type { Destination } from "../src/dest/types.ts";

let failures = 0;
function ok(msg: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${msg}`);
  if (!cond) failures++;
}
function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
// blob of n deterministic bytes (i % 251, a prime so windows do not line up on 256 boundaries).
function blobOf(n: number): Uint8Array {
  const u = new Uint8Array(n);
  for (let i = 0; i < n; i++) u[i] = i % 251;
  return u;
}
async function collect(cs: { chunks(): AsyncIterable<Uint8Array> }): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  let total = 0;
  for await (const c of cs.chunks()) {
    parts.push(c);
    total += c.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// fakeServer holds one blob and answers fetch() with Range / ETag / If-Match semantics. `etag` is
// mutable so a test can simulate the content changing between the probe and a ranged read (a 412).
// `supportRanges=false` makes it ignore Range and always answer 200 (an Accept-Ranges-less server).
function fakeServer(blob: Uint8Array, opts?: { etag?: string; supportRanges?: boolean; contentType?: string }) {
  const state = { etag: opts?.etag ?? '"v1"', blob };
  const supportRanges = opts?.supportRanges ?? true;
  const contentType = opts?.contentType ?? "application/octet-stream";
  const fetchImpl = (async (_url: string, init?: { headers?: Record<string, string> }) => {
    const h = init?.headers ?? {};
    const range = h.range;
    const ifMatch = h["if-match"];
    if (ifMatch !== undefined && ifMatch !== state.etag) {
      return new Response(null, { status: 412 }); // pinned version changed
    }
    if (range !== undefined && supportRanges) {
      const m = /bytes=(\d+)-(\d+)/.exec(range)!;
      const start = Number(m[1]);
      const end = Number(m[2]);
      const slice = state.blob.slice(start, end + 1);
      return new Response(slice, {
        status: 206,
        headers: { "content-range": `bytes ${start}-${end}/${state.blob.length}`, "content-length": String(slice.length), etag: state.etag, "content-type": contentType },
      });
    }
    // whole body (or a range-ignoring server): 200 with the full blob. Copy into a fresh ArrayBuffer-backed
    // array so it satisfies BodyInit (a plain Uint8Array may be ArrayBufferLike-backed under TS6).
    return new Response(new Uint8Array(state.blob), { status: 200, headers: { "content-length": String(state.blob.length), etag: state.etag, "content-type": contentType } });
  }) as unknown as typeof fetch;
  return { state, fetchImpl };
}

const T: ByteTarget = { url: "/accounts/acct/images/v1/img/blob" };

console.log("-- probe: size, range support, etag from a 1-byte ranged GET --");
{
  const big = blobOf(1234);
  const { fetchImpl } = fakeServer(big, { etag: '"abc"' });
  const f = makeByteFetcher("tok", fetchImpl);
  const p = await f.probe(T);
  ok("probe size from content-range total", p.size === 1234);
  ok("probe reports range support (206)", p.acceptsRanges === true);
  ok("probe captures the etag", p.etag === '"abc"');
}

console.log("\n-- captureBlob: small blob is buffered as a value --");
{
  const small = blobOf(40);
  const { fetchImpl } = fakeServer(small);
  const f = makeByteFetcher("tok", fetchImpl);
  const cap = await captureBlob(f, T, undefined, { bufferMax: 100, window: 16 });
  ok("small blob -> buffered value", cap.value !== undefined && cap.stream === undefined && cap.skip === undefined);
  ok("buffered value bytes are exact", cap.value !== undefined && eqBytes(cap.value, small));
}

console.log("\n-- captureBlob: large range-capable blob is streamed --");
{
  const large = blobOf(1000);
  const { fetchImpl } = fakeServer(large);
  const f = makeByteFetcher("tok", fetchImpl);
  const cap = await captureBlob(f, T, undefined, { bufferMax: 100, window: 64 });
  ok("large blob -> streamed value (not buffered, not skipped)", cap.stream !== undefined && cap.value === undefined && cap.skip === undefined);
  ok("streamed value reports the size", cap.stream?.size === 1000);
  // THE INTEGRITY CONTRACT: open() twice yields byte-identical plaintext, both equal to the source.
  const pass1 = await collect(cap.stream!.open());
  const pass2 = await collect(cap.stream!.open());
  ok("pass one equals the source bytes", eqBytes(pass1, large));
  ok("pass two equals the source bytes", eqBytes(pass2, large));
  ok("the two passes are byte-identical (re-openable)", eqBytes(pass1, pass2));
  // windowing: a 1000-byte value over a 64-byte window opens in ceil(1000/64)=16 chunks.
  let chunks = 0;
  for await (const _c of cap.stream!.open().chunks()) chunks++;
  ok("windowed into ceil(size/window) chunks", chunks === Math.ceil(1000 / 64));
}

console.log("\n-- captureBlob: a large range-capable blob streams at ANY size (no ceiling; the seal chains it) --");
{
  const large = blobOf(1000);
  const { fetchImpl } = fakeServer(large);
  const f = makeByteFetcher("tok", fetchImpl);
  // Even with a tiny buffer cap, a range-capable blob streams regardless of size (the seal windows it into
  // a chained multi-segment record via openRange); it is never skipped for being "too big".
  const cap = await captureBlob(f, T, undefined, { bufferMax: 100, window: 64 });
  ok("large range-capable -> streamed (not skipped for size)", cap.stream !== undefined && cap.skip === undefined);
  const win = await collect(cap.stream!.openRange!(100, 200));
  ok("openRange(100,200) (the seal's chaining entry) returns exactly that window", eqBytes(win, large.slice(100, 300)));
}

console.log("\n-- captureBlob: large but no range support is skipped (cannot stream safely) --");
{
  const large = blobOf(1000);
  const { fetchImpl } = fakeServer(large, { supportRanges: false });
  const f = makeByteFetcher("tok", fetchImpl);
  const cap = await captureBlob(f, T, undefined, { bufferMax: 100, window: 64 });
  ok("large + no-range -> skip", cap.skip !== undefined && cap.stream === undefined);
}

// unknownSizeServer answers a plain 200 with NO Content-Length and NO range support, streaming the body as
// a ReadableStream in `chunk`-byte pieces. It is the OOM-risk case: the server never advertises a size, so
// captureBlob cannot pre-size it. `pulled` counts the bytes the body actually streamed before it was
// cancelled, so a test can assert the read ABORTED early (never drained the whole body). `hardCap` makes
// the producer throw if it is ever asked for more than hardCap bytes, so a stream-and-count that fails to
// abort blows up loudly rather than silently buffering the whole thing.
function unknownSizeServer(totalBytes: number, opts?: { chunk?: number; hardCap?: number }) {
  const chunk = opts?.chunk ?? 64;
  const hardCap = opts?.hardCap ?? totalBytes;
  const counter = { pulled: 0 };
  const fetchImpl = (async (_url: string, init?: { headers?: Record<string, string> }) => {
    const h = init?.headers ?? {};
    // The probe is a 1-byte ranged GET; this server ignores Range, so it answers 200 with no size signal,
    // which makes probe() report size = -1 and acceptsRanges = false (the unknown-size path).
    if (h.range !== undefined && /bytes=0-0/.test(h.range)) {
      return new Response(new Uint8Array([0]), { status: 200, headers: { "content-type": "application/octet-stream" } });
    }
    let pos = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (pos >= totalBytes) {
          controller.close();
          return;
        }
        const len = Math.min(chunk, totalBytes - pos);
        counter.pulled += len;
        if (counter.pulled > hardCap) {
          controller.error(new Error(`producer drained past the hard cap (${counter.pulled} > ${hardCap}): the read did NOT abort early`));
          return;
        }
        controller.enqueue(blobOf(totalBytes).slice(pos, pos + len));
        pos += len;
      },
    });
    // A plain 200 with NO content-length header: an unknown-size body.
    return new Response(body, { status: 200, headers: { "content-type": "application/octet-stream" } });
  }) as unknown as typeof fetch;
  return { counter, fetchImpl };
}

console.log("\n-- captureBlob: unknown-size body OVER the cap aborts early (no whole-body buffering, no OOM) --");
{
  // The body is 100 KiB but the server never advertises a size (200, no Content-Length, no ranges). The cap
  // is 1 KiB. A correct stream-and-count must STOP a hair past 1 KiB; the hardCap (4 KiB) makes the producer
  // throw if the read ever pulls anywhere near the whole 100 KiB, so the OLD arrayBuffer() path (which
  // buffers the whole body BEFORE the cap check) would blow the producer up instead of returning a skip.
  const total = 100 * 1024;
  const { counter, fetchImpl } = unknownSizeServer(total, { chunk: 256, hardCap: 4 * 1024 });
  const f = makeByteFetcher("tok", fetchImpl);
  const cap = await captureBlob(f, T, undefined, { bufferMax: 1024, window: 64 });
  ok("unknown-size over-cap -> skip (not captured, not buffered whole)", cap.skip !== undefined && cap.value === undefined && cap.stream === undefined);
  ok("the download aborted early (did not drain the whole 100 KiB body)", counter.pulled <= 4 * 1024);
  ok("it stopped only just past the cap (a chunk or two over 1 KiB)", counter.pulled <= 1024 + 256 * 2);
}

console.log("\n-- captureBlob: unknown-size body WITHIN the cap still captures correctly --");
{
  // Same unknown-size server (200, no size, no ranges) but the body fits under the cap: it must buffer as an
  // exact value, success behaviour unchanged.
  const total = 600;
  const want = blobOf(total);
  const { fetchImpl } = unknownSizeServer(total, { chunk: 64 });
  const f = makeByteFetcher("tok", fetchImpl);
  const cap = await captureBlob(f, T, undefined, { bufferMax: 1024, window: 64 });
  ok("unknown-size within-cap -> buffered value (captured)", cap.value !== undefined && cap.stream === undefined && cap.skip === undefined);
  ok("the buffered value bytes are exact", cap.value !== undefined && eqBytes(cap.value, want));
}

// rangeButUnknownTotalServer answers the probe with a 206 (so acceptsRanges = true) whose Content-Range
// total is "*" (so probe size = -1: a range-capable server that does NOT advertise a total). captureBlob's
// unknown-size branch must STILL fall back to wholeCapped (an unknown length cannot be windowed into a
// chain) and so still buffer-or-skip by the cap, independent of range support. The body read (no range
// header on the cap fetch) is a plain 200 streaming `totalBytes` in `chunk`-byte pieces.
function rangeButUnknownTotalServer(totalBytes: number, opts?: { chunk?: number; hardCap?: number }) {
  const chunk = opts?.chunk ?? 64;
  const hardCap = opts?.hardCap ?? totalBytes;
  const counter = { pulled: 0 };
  const fetchImpl = (async (_url: string, init?: { headers?: Record<string, string> }) => {
    const h = init?.headers ?? {};
    if (h.range !== undefined && /bytes=0-0/.test(h.range)) {
      // 206 (range support) but an unknown total ("*"): probe -> acceptsRanges true, size -1.
      return new Response(new Uint8Array([0]), {
        status: 206,
        headers: { "content-range": "bytes 0-0/*", "content-type": "application/octet-stream" },
      });
    }
    let pos = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (pos >= totalBytes) {
          controller.close();
          return;
        }
        const len = Math.min(chunk, totalBytes - pos);
        counter.pulled += len;
        if (counter.pulled > hardCap) {
          controller.error(new Error(`producer drained past the hard cap (${counter.pulled} > ${hardCap}): the read did NOT abort early`));
          return;
        }
        controller.enqueue(blobOf(totalBytes).slice(pos, pos + len));
        pos += len;
      },
    });
    return new Response(body, { status: 200, headers: { "content-type": "application/octet-stream" } });
  }) as unknown as typeof fetch;
  return { counter, fetchImpl };
}

console.log("\n-- captureBlob: unknown total BUT range-capable, body OVER the cap -> still skip (cannot chain an unknown length) --");
{
  // probe: 206 with total "*" => acceptsRanges true, size -1. The body is 100 KiB over a 1 KiB cap. The
  // unknown-size branch runs regardless of range support and aborts early, returning a skip (NOT a stream:
  // a chain needs a known length), so range capability does not let an unknown-length blob slip past the cap.
  const total = 100 * 1024;
  const { counter, fetchImpl } = rangeButUnknownTotalServer(total, { chunk: 256, hardCap: 4 * 1024 });
  const f = makeByteFetcher("tok", fetchImpl);
  const p = await f.probe(T);
  ok("probe: range-capable (206) but unknown total -> acceptsRanges true, size -1", p.acceptsRanges === true && p.size === -1);
  const cap = await captureBlob(f, T, undefined, { bufferMax: 1024, window: 64 });
  ok("range-capable + unknown total + over-cap -> skip (not streamed, not buffered whole)", cap.skip !== undefined && cap.stream === undefined && cap.value === undefined);
  ok("the download still aborted early (did not drain the whole body)", counter.pulled <= 4 * 1024);
}

console.log("\n-- ETag pin: content changing mid-capture fails LOUDLY (no silent corruption) --");
{
  const large = blobOf(1000);
  const srv = fakeServer(large, { etag: '"v1"' });
  const f = makeByteFetcher("tok", srv.fetchImpl);
  const sv = httpStreamingValue(f, T, 1000, '"v1"', undefined, 64);
  // Simulate the resource being overwritten after the value was addressed: the etag changes, so the
  // pinned (If-Match: "v1") range read now gets a 412 and the stream throws rather than yielding wrong bytes.
  srv.state.etag = '"v2"';
  let threw = false;
  try {
    await collect(sv.open());
  } catch {
    threw = true;
  }
  ok("a changed etag makes the pinned re-read throw (412), never silently wrong", threw);
}

console.log("\n-- range(): a server ignoring Range (200 not 206) is rejected, not mis-windowed --");
{
  const large = blobOf(1000);
  const { fetchImpl } = fakeServer(large, { supportRanges: false });
  const f = makeByteFetcher("tok", fetchImpl);
  let threw = false;
  try {
    await f.range(T, 0, 64, undefined);
  } catch {
    threw = true;
  }
  ok("range read that returns 200 (range ignored) throws", threw);
}

// redirectingServer simulates a host that answers every request with a 3xx to an attacker-controlled
// Location. When the caller passes redirect:"manual" it hands back the raw 3xx untouched (what doFetch now
// requires); otherwise it simulates the runtime silently auto-following the redirect (the pre-fix default)
// by answering as the "attacker" would -- a plain success carrying different bytes -- so a regression that
// drops redirect:"manual" is caught the same way it would bite in production: a SILENT capture of
// attacker-controlled content, not a thrown error. lastRedirect records the redirect option doFetch sent.
function redirectingServer() {
  const state = { lastRedirect: "unset" as unknown };
  const fetchImpl = (async (_url: string, init?: { redirect?: unknown }) => {
    state.lastRedirect = init?.redirect;
    if (init?.redirect === "manual") {
      return new Response(null, { status: 302, headers: { location: "https://attacker.example/payload" } });
    }
    return new Response(new Uint8Array([0xee]), { status: 200, headers: { "content-length": "1" } }); // "attacker" body
  }) as unknown as typeof fetch;
  return { state, fetchImpl };
}

console.log("\n-- doFetch: a redirect is refused, never silently followed, on every ByteFetcher method --");
{
  // This is the exact bypass the fix closes: a compromised/spoofed API response's URL passes the pre-fetch
  // host allow-list (e.g. stream.ts's isCloudflareStreamUrl), then that (validated) host answers with a 3xx.
  {
    const { state, fetchImpl } = redirectingServer();
    const f = makeByteFetcher("tok", fetchImpl);
    let msg = "";
    try { await f.probe(T); } catch (e) { msg = e instanceof Error ? e.message : String(e); }
    ok('probe: requests redirect:"manual"', state.lastRedirect === "manual");
    ok("probe: the redirect is refused with a clear error, not silently followed", /unexpected redirect/.test(msg));
  }
  {
    const { state, fetchImpl } = redirectingServer();
    const f = makeByteFetcher("tok", fetchImpl);
    let msg = "";
    try { await f.wholeCapped(T, 1000); } catch (e) { msg = e instanceof Error ? e.message : String(e); }
    ok('wholeCapped: requests redirect:"manual"', state.lastRedirect === "manual");
    ok("wholeCapped: the redirect is refused with a clear error, not silently followed", /unexpected redirect/.test(msg));
  }
  {
    const { state, fetchImpl } = redirectingServer();
    const f = makeByteFetcher("tok", fetchImpl);
    let msg = "";
    try { await f.range(T, 0, 10, undefined); } catch (e) { msg = e instanceof Error ? e.message : String(e); }
    ok('range: requests redirect:"manual"', state.lastRedirect === "manual");
    ok("range: the redirect is refused with a clear error, not silently followed", /unexpected redirect/.test(msg));
  }
  {
    const { state, fetchImpl } = redirectingServer();
    const f = makeByteFetcher("tok", fetchImpl);
    let msg = "";
    try {
      for await (const _c of f.streamedRange(T, 0, 10, undefined)) { /* unreachable once the redirect is refused */ }
    } catch (e) {
      msg = e instanceof Error ? e.message : String(e);
    }
    ok('streamedRange: requests redirect:"manual"', state.lastRedirect === "manual");
    ok("streamedRange: the redirect is refused with a clear error, not silently followed", /unexpected redirect/.test(msg));
  }
}

console.log("\n-- doFetch: an opaque redirect (status 0, WHATWG's redirect:\"manual\" answer to a true cross-host 3xx) is also refused --");
{
  // A real Workers fetch under redirect:"manual" against an ACTUAL cross-origin redirect returns an
  // opaque-redirect Response whose status is fixed at 0 (the Response constructor itself refuses to build a
  // status-0 instance, so this is a plain duck-typed stub matching the one field doFetch reads here: `.status`).
  const opaque = (async () => ({ status: 0 })) as unknown as typeof fetch;
  const f = makeByteFetcher("tok", opaque);
  let msg = "";
  try { await f.probe(T); } catch (e) { msg = e instanceof Error ? e.message : String(e); }
  ok("status 0 (opaque redirect) is refused, never treated as an empty success", /unexpected redirect/.test(msg));
}

// streamRedirectServer mimics Cloudflare Stream's download URL (STREAM-MP4): the download URL ALWAYS
// answers a 302 to a signed same-host URL (.../dl/default.mp4?p=..&s=..), and the signed URL serves the real
// bytes with Range/ETag semantics. It records every request's URL and whether it carried an Authorization
// header, so a test can prove the follow happened AND the Bearer token was not leaked to the redirected URL.
// `signedHost` points the Location at a chosen host (a DIFFERENT host proves the allow-list refuses it; a
// different-but-allowed host proves the cross-origin token strip). `loop` makes EVERY request a 302 (a
// redirect loop), so the depth-1 bound is exercised.
function streamRedirectServer(blob: Uint8Array, opts?: { signedHost?: string; loop?: boolean; etag?: string }) {
  const initialUrl = "https://customer-abc.cloudflarestream.com/uid/downloads/default.mp4";
  const signedHost = opts?.signedHost ?? "customer-abc.cloudflarestream.com";
  const signedUrl = `https://${signedHost}/uid/dl/default.mp4?p=PP&s=SS`;
  const etag = opts?.etag ?? '"v1"';
  const requests: Array<{ url: string; auth: boolean }> = [];
  const fetchImpl = (async (url: string, init?: { headers?: Record<string, string>; redirect?: unknown }) => {
    const h = init?.headers ?? {};
    requests.push({ url, auth: h.authorization !== undefined });
    if (url === initialUrl || opts?.loop === true) {
      // The download URL (or, in loop mode, every URL): a 302 to the signed URL. redirect:"manual" hands
      // this back untouched, which is what doFetch requires to re-validate the Location before following.
      return new Response(null, { status: 302, headers: { location: signedUrl } });
    }
    const range = h.range;
    if (range !== undefined) {
      const m = /bytes=(\d+)-(\d+)/.exec(range)!;
      const start = Number(m[1]);
      const end = Number(m[2]);
      const slice = blob.slice(start, end + 1);
      return new Response(slice, { status: 206, headers: { "content-range": `bytes ${start}-${end}/${blob.length}`, "content-length": String(slice.length), etag, "content-type": "video/mp4" } });
    }
    return new Response(new Uint8Array(blob), { status: 200, headers: { "content-length": String(blob.length), etag, "content-type": "video/mp4" } });
  }) as unknown as typeof fetch;
  return { initialUrl, signedUrl, requests, fetchImpl };
}

console.log("\n-- STREAM-MP4: a 302 to an allow-list-passing same-host Location is followed ONCE and returns the real bytes --");
{
  const mp4 = blobOf(500);
  const srv = streamRedirectServer(mp4);
  const f = makeByteFetcher("tok", srv.fetchImpl);
  // The Stream video.mp4 target: no token (auth:false), allow-list predicate = isCloudflareStreamUrl.
  const target: ByteTarget = { url: srv.initialUrl, auth: false, allowRedirect: (loc) => isCloudflareStreamUrl(loc) };
  const cap = await captureBlob(f, target, undefined, { bufferMax: 1000, window: 64 });
  ok("the redirect is followed and the real MP4 bytes are captured (not a marker)", cap.value !== undefined && eqBytes(cap.value, mp4));
  ok("the fetch actually followed to the signed same-host URL", srv.requests.some((r) => r.url === srv.signedUrl));
}

console.log("\n-- STREAM-MP4: a 302 to a DISALLOWED host is refused (SSRF preserved), never followed --");
{
  const mp4 = blobOf(500);
  const srv = streamRedirectServer(mp4, { signedHost: "attacker.example" });
  const f = makeByteFetcher("tok", srv.fetchImpl);
  const target: ByteTarget = { url: srv.initialUrl, auth: false, allowRedirect: (loc) => isCloudflareStreamUrl(loc) };
  let msg = "";
  try { await captureBlob(f, target, undefined, { bufferMax: 1000, window: 64 }); } catch (e) { msg = e instanceof Error ? e.message : String(e); }
  ok("a redirect to a non-cloudflarestream.com host throws (allow-list refuses it)", /unexpected redirect/.test(msg));
  ok("the disallowed host was NEVER fetched", !srv.requests.some((r) => r.url === srv.signedUrl));
}

console.log("\n-- STREAM-MP4: a redirect with NO predicate still throws (default unchanged = fail-safe) --");
{
  const mp4 = blobOf(500);
  const srv = streamRedirectServer(mp4);
  const f = makeByteFetcher("tok", srv.fetchImpl);
  const target: ByteTarget = { url: srv.initialUrl, auth: false }; // no allowRedirect
  let msg = "";
  try { await f.probe(target); } catch (e) { msg = e instanceof Error ? e.message : String(e); }
  ok("no predicate -> the 302 is refused exactly as before the fix", /unexpected redirect/.test(msg));
  ok("the signed URL was never fetched with no predicate", !srv.requests.some((r) => r.url === srv.signedUrl));
}

console.log("\n-- STREAM-MP4: a redirect LOOP (302 -> 302) throws (follow depth bound to 1) --");
{
  const mp4 = blobOf(500);
  const srv = streamRedirectServer(mp4, { loop: true }); // every request is a 302
  const f = makeByteFetcher("tok", srv.fetchImpl);
  const target: ByteTarget = { url: srv.initialUrl, auth: false, allowRedirect: (loc) => isCloudflareStreamUrl(loc) };
  let msg = "";
  try { await f.probe(target); } catch (e) { msg = e instanceof Error ? e.message : String(e); }
  ok("a second 3xx after one follow throws (never an unbounded redirect chain)", /unexpected redirect/.test(msg));
}

console.log("\n-- STREAM-MP4: the Bearer token is NOT forwarded across a followed cross-origin redirect --");
{
  const mp4 = blobOf(500);
  // Redirect to a DIFFERENT origin that the predicate still allows (another *.cloudflarestream.com host), with
  // a token-bearing target (auth:true): the follow must DROP the Authorization header at the new origin.
  const srv = streamRedirectServer(mp4, { signedHost: "customer-xyz.cloudflarestream.com" });
  const f = makeByteFetcher("SECRET-TOKEN", srv.fetchImpl);
  const target: ByteTarget = { url: srv.initialUrl, auth: true, allowRedirect: (loc) => isCloudflareStreamUrl(loc) };
  await f.probe(target);
  const initialReq = srv.requests.find((r) => r.url === srv.initialUrl);
  const signedReq = srv.requests.find((r) => r.url === srv.signedUrl);
  ok("the initial (allow-listed) request carried the Bearer token", initialReq?.auth === true);
  ok("the cross-origin redirected request did NOT carry the token (no leak)", signedReq !== undefined && signedReq.auth === false);
}

console.log("\n-- STREAM-MP4: a SAME-origin redirect keeps the token (the 'unless same-origin' clause) --");
{
  const mp4 = blobOf(500);
  const srv = streamRedirectServer(mp4); // signed URL is on the SAME host as the initial URL
  const f = makeByteFetcher("SECRET-TOKEN", srv.fetchImpl);
  const target: ByteTarget = { url: srv.initialUrl, auth: true, allowRedirect: (loc) => isCloudflareStreamUrl(loc) };
  await f.probe(target);
  const signedReq = srv.requests.find((r) => r.url === srv.signedUrl);
  ok("a same-origin follow retains the Authorization header", signedReq !== undefined && signedReq.auth === true);
}

console.log("\n-- end-to-end: a large streamed blob CHAINS through the real production seal (>1 GiB path) --");
{
  // Drive the actual seal/record.ts sealRecordToDest with this module's httpStreamingValue and a TINY
  // segment target, so a 1000-byte value seals as a multi-segment CHAIN (no gigabyte fixture needed). This
  // proves a value past the single-segment ceiling is captured as an ordered chain, with the whole-record
  // SHA-384 + size correct, end to end on the production path.
  const blob = blobOf(1000);
  const { fetchImpl } = fakeServer(blob, { etag: '"v1"' });
  const f = makeByteFetcher("tok", fetchImpl);
  const sv = httpStreamingValue(f, T, 1000, '"v1"', undefined, 64);
  // Minimal in-memory destination: the chained-stream seal only calls exists() + putStream(); the rest
  // are unused stubs. putStream drains the sealed body so the stream completes.
  const segKeys: string[] = [];
  const dest: Destination = {
    exists: async () => false,
    putStream: async (key: string, body: ReadableStream<Uint8Array>) => {
      segKeys.push(key);
      const reader = body.getReader();
      for (;;) { const { done } = await reader.read(); if (done) break; }
    },
    put: async () => {},
    get: async () => null,
    putConditional: async () => ({ ok: true as const, etag: '"x"' }),
    delete: async () => {},
    list: async () => [],
  };
  let nonce = 0;
  const fill = (n: number, seed: number) => { const u = new Uint8Array(n); for (let i = 0; i < n; i++) u[i] = (seed + i) & 0xff; return u; };
  const deps: RecordSealDeps = {
    cak: fill(32, 7), master: fill(32, 11), runIdBytes: fill(16, 3), dest,
    randomNonce: () => fill(16, ++nonce), randomSalt: () => fill(16, 99),
    segmentTargetBytes: 256, // 1000 bytes / 256 => a 4-segment chain
  };
  const outcome = await sealRecordToDest(deps, "r000000000000000", { sourceType: "images", name: "x/blob", stream: sv });
  ok("seal succeeded", outcome.ok === true);
  if (outcome.ok === true) {
    ok("a value past the segment target sealed as a CHAIN (>1 segment)", outcome.seal.segments.length > 1);
    ok("the chained record's whole size equals the source bytes", outcome.seal.size === 1000);
    ok("the chained record's whole-record SHA-384 matches the source bytes", outcome.seal.plaintextSha384 === hexEncode(sha384(blob)));
    ok("one dest object written per chain segment", segKeys.length === outcome.seal.segments.length);
  }
}

// hugeDeclaredServer answers the probe (the 1-byte ranged GET) with a 206 whose Content-Range total is
// `declared` -- so probe() learns a size of `declared` and acceptsRanges=true -- WITHOUT ever holding that
// many bytes. It is the over-threshold mitigation fixture: captureBlob decides purely on the DECLARED size
// from the cheap probe, before any seal cost, so a multi-GiB size can be exercised with no allocation. A
// `range` call beyond the 1-byte probe throws, because a correct captureBlob must NEVER stream an
// over-threshold object (it skips at probe); if it ever tried, this server blows up loudly.
function hugeDeclaredServer(declared: number) {
  const reached = { rangedBody: false };
  const fetchImpl = (async (_url: string, init?: { headers?: Record<string, string> }) => {
    const h = init?.headers ?? {};
    const range = h.range;
    if (range !== undefined && /bytes=0-0/.test(range)) {
      // The probe: a 1-byte ranged GET. Report the full declared total via Content-Range, range support
      // (206), and an etag, but return only the single probed byte.
      return new Response(new Uint8Array([0]), {
        status: 206,
        headers: { "content-range": `bytes 0-0/${declared}`, "content-length": "1", etag: '"huge"', "content-type": "application/octet-stream" },
      });
    }
    // Any non-probe read of an over-threshold object means captureBlob tried to STREAM it: that is exactly
    // the wedge the mitigation prevents. Fail loudly so a regression cannot pass silently.
    reached.rangedBody = true;
    throw new Error(`over-threshold object was read beyond the probe (range=${range}): captureBlob did NOT skip it`);
  }) as unknown as typeof fetch;
  return { reached, fetchImpl };
}

console.log("\n-- captureBlob: a single object OVER the single-invocation seal ceiling is SKIPPED (not streamed) -> incompleteness marker --");
{
  // A single content value whose DECLARED size exceeds MAX_SINGLE_RECORD_CONTENT_BYTES cannot be sealed in
  // one invocation (its two-pass seal is not checkpointable mid-record), so attempting it would exhaust the
  // platform subrequest cap mid-record and TERMINAL-FAIL the whole run. captureBlob must DECLINE it at probe
  // time and return a skip the adapter turns into an honest incompleteness marker, so the run COMPLETES and
  // recordsIncrement surfaces the one object. The OLD code returned a STREAM here (it streamed at any size),
  // so the seal would have attempted the multi-thousand-subrequest chain and wedged.
  const over = MAX_SINGLE_RECORD_CONTENT_BYTES + 1;
  const { reached, fetchImpl } = hugeDeclaredServer(over);
  const f = makeByteFetcher("tok", fetchImpl);
  const cap = await captureBlob(f, T, undefined, { bufferMax: 100, window: 64 });
  ok("over-threshold single object -> skip (NOT streamed, NOT buffered) so the seal is never attempted", cap.skip !== undefined && cap.stream === undefined && cap.value === undefined);
  ok("the skip never streamed the body (no wedge: the seal cost was never incurred)", reached.rangedBody === false);
  ok("the skip carries the declared size and an out-of-band recovery reason", cap.skip?.size === over && /out of band|in-band capture limit/.test(cap.skip?.reason ?? ""));
  // The adapter wraps a skip into a "_skipped" marker record (sources/images.ts, stream.ts, artifacts.ts).
  // That marker is detected by isIncompleteMarkerValue, which is what slice.ts uses to increment
  // recordsIncomplete (R1-1) so the completed run reports "N items not fully captured".
  const markerValue = new TextEncoder().encode(JSON.stringify({ _skipped: cap.skip!.reason, size: cap.skip!.size }));
  ok("the resulting _skipped marker is detected as an incompleteness sentinel (drives recordsIncomplete)", isIncompleteMarkerValue(markerValue) === true);
}

console.log("\n-- captureBlob: a single object just UNDER the ceiling still STREAMS + chains normally (no regression) --");
{
  // An object at the ceiling (<=) is still streamed and chains through the production seal exactly as before:
  // the mitigation only changes the OVER-threshold case. Drive it for real with a small blob whose declared
  // size sits at the boundary: captureBlob keys off the declared probe size, so a real small body that
  // ADVERTISES exactly the ceiling proves the boundary is inclusive (<=) and still produces a stream. The
  // window read is exercised on the real (tiny) bytes.
  const small = blobOf(1000);
  // A server that advertises the ceiling as its total but serves the tiny real body for any window read.
  const atCeiling = MAX_SINGLE_RECORD_CONTENT_BYTES;
  const fetchImpl = (async (_url: string, init?: { headers?: Record<string, string> }) => {
    const h = init?.headers ?? {};
    const range = h.range;
    if (range !== undefined && /bytes=0-0/.test(range)) {
      return new Response(new Uint8Array([0]), {
        status: 206,
        headers: { "content-range": `bytes 0-0/${atCeiling}`, "content-length": "1", etag: '"v1"', "content-type": "application/octet-stream" },
      });
    }
    const m = /bytes=(\d+)-(\d+)/.exec(range ?? "")!;
    const start = Number(m[1]);
    const end = Math.min(Number(m[2]), small.length - 1);
    const slice = small.slice(start, end + 1);
    return new Response(slice, { status: 206, headers: { "content-range": `bytes ${start}-${end}/${atCeiling}`, "content-length": String(slice.length), etag: '"v1"' } });
  }) as unknown as typeof fetch;
  const f = makeByteFetcher("tok", fetchImpl);
  const cap = await captureBlob(f, T, undefined, { bufferMax: 100, window: 64 });
  ok("at-ceiling object -> STREAMED (the boundary is inclusive, no regression to the chained path)", cap.stream !== undefined && cap.skip === undefined && cap.value === undefined);
  ok("the streamed value reports the declared size", cap.stream?.size === atCeiling);
}

console.log(failures === 0 ? "\nBYTE-FETCH PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
