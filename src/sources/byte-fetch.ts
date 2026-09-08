// Raw-bytes capture for the media source adapters (images / stream / artifacts). The cf-config CfApi
// (cf-config-core.ts) unwraps the Cloudflare JSON success/errors envelope, so it can only return parsed
// metadata, NOT a binary blob. This module fetches a resource's RAW bytes and presents them to the seal
// as one of three shapes, decided purely by size so the integrity contract is never at risk:
//
//   1. SMALL (<= BYTE_BUFFER_MAX): fetched whole into a buffered `value`. One in-memory copy, sealed
//      once. There is no re-open, so it is immune to the resource changing mid-seal. This is the safe
//      majority path (most images, captions, small layers).
//   2. LARGE + range-capable (up to the applicable record ceiling): a re-openable StreamingValue. The
//      seal opens it to address and to seal; each open re-fetches the bytes in windows via HTTP Range,
//      PINNED to the ETag captured at probe time (If-Match). If the resource changes between or during the
//      passes the pinned fetch fails LOUDLY (a 412), so the run errors rather than sealing a segment whose
//      sealed bytes disagree with its addressed hash. Loud-and-recoverable beats silent-and-corrupt. The
//      production seal (seal/record.ts) windows a value past the single-segment ceiling into a CHAINED
//      multi-segment record via openRange, so a multi-GiB blob seals as an ordered chain, never held whole;
//      with a STABLE ETAG it also seals MID-RECORD ACROSS SLICES (the seal re-hashes the already-sealed
//      prefix via openStreamedRange, pinned to that etag), so it scales up to the higher resumable ceiling.
//   3. NOT range-capable AND larger than the buffer cap: NOT captured (a chain needs ranged reads). Also,
//      a single object whose DECLARED size exceeds the applicable ceiling is NOT captured even when
//      range-capable: an ETAG-PINNED value can mid-record-resume, so its ceiling is the higher
//      MAX_SINGLE_RECORD_CONTENT_BYTES (the prefix re-hash bound); a value with NO stable etag (or when
//      sliced runs are disabled) cannot resume and so seals whole in one slice, capped at the lower
//      MAX_SINGLE_SLICE_RECORD_BYTES (the seal/budget.ts thresholds explain both derivations). captureBlob
//      returns a `skip` with a reason + the size; the adapter turns it into an honest marker record,
//      recovered out of band, never a silent drop and never a wedged run.
//
// A target is either a v4-API-relative path (Bearer-authenticated, prefixed with the API base, e.g. the
// Images blob endpoint) or an absolute URL used verbatim (e.g. a Stream download URL or an OCI blob URL).
// Everything is retry-wrapped and pacer-aware exactly like makeCfApi, so byte reads share the same
// transient-fault and rate-limit behaviour as the metadata reads. No network in the validator: ByteFetcher
// is an interface a test drives with an in-memory stub.

import type { CfPacer } from "../cf-pace.ts";
import type { ChunkSource, StreamingValue } from "../crypto/streamseal.ts";
import type { Meter } from "../meter.ts";
import { MAX_SINGLE_RECORD_CONTENT_BYTES, MAX_SINGLE_SLICE_RECORD_BYTES } from "../seal/budget.ts";
import { API_READ_RETRY, parseRetryAfter, rateLimitError, withRetry } from "../seal/retry.ts";
import { classifySourceFaultStatus, recordRetryExhausted, recordSecurityRefusal, recordThrottle } from "./source-fault-ledger.ts";

const CF_API_BASE = "https://api.cloudflare.com/client/v4";

// BYTE_BUFFER_MAX: at or below this a blob is read whole into a buffered value. Kept well within a
// Worker's ~128 MiB memory limit allowing for the seal's transient working copy of the same bytes. Above
// it a range-capable blob is STREAMED (and chained past the single-segment ceiling) up to the applicable
// record ceiling (the resumable MAX_SINGLE_RECORD_CONTENT_BYTES for an etag-pinned object, else the
// one-slice MAX_SINGLE_SLICE_RECORD_BYTES), past which it is skipped as an honest marker (a single object
// that large cannot be captured in band without wedging the run).
export const BYTE_BUFFER_MAX = 32 * 1024 * 1024; // 32 MiB
// BYTE_RANGE_WINDOW: the streamed read window held at a time (one HTTP Range request per window).
export const BYTE_RANGE_WINDOW = 8 * 1024 * 1024; // 8 MiB

// ByteTarget names a resource to fetch. `url` is either a v4-relative path beginning with "/" (the API
// base is prepended and, unless auth is explicitly false, the discovery Bearer token is attached) or an
// absolute http(s) URL used verbatim (auth defaults to false; pass headers for a registry token, say).
//
// allowRedirect is the OPTIONAL per-target redirect policy (STREAM-MP4, SSRF V15.2.1). By default a byte
// fetch REFUSES every 3xx (a byte-fetch target must not redirect: a validated host answering a 3xx could
// otherwise steer the read at an unvalidated target with no re-check). A source whose resource legitimately
// redirects to a same-allow-list host (Cloudflare Stream's download URL 302s to a signed same-host URL)
// supplies this predicate: on a 3xx doFetch resolves the Location against the current URL and, ONLY if the
// predicate returns true for that absolute URL, follows it ONCE (the follow depth is bound to 1: a second
// 3xx throws). The predicate MUST re-apply the SAME allow-list that vetted the initial URL, so a redirect to
// any other host is still refused. Absent predicate = the safe default (no follow, throw on any 3xx).
export interface ByteTarget {
  url: string;
  auth?: boolean;
  headers?: Record<string, string>;
  allowRedirect?: (location: string, fromUrl: string) => boolean;
}

// ByteProbe is what a HEAD-equivalent probe learns without downloading the body: the total size (or -1
// when the server reports none), whether ranged reads are honoured, the ETag to pin a streamed re-read
// to, and the content type (informational).
export interface ByteProbe {
  size: number;
  acceptsRanges: boolean;
  etag?: string;
  contentType?: string;
}

// WholeCapped is wholeCapped()'s result: either the whole body buffered (it fits at or below the cap) or
// a signal that the body exceeded the cap. In the over-cap case the download is ABORTED early, so the
// over-cap body is never held whole; `read` reports how many bytes were drained before the abort.
export type WholeCapped = { bytes: Uint8Array } | { overCap: true; read: number };

// ByteFetcher is the byte-capture client. probe() learns size/range-support/etag; wholeCapped() streams the
// whole body but ABORTS the moment the running total exceeds the cap (so an unknown-size body that overruns
// the Worker memory limit is never buffered whole); range() reads one window, buffered, pinned to etag so a
// mid-capture change fails loudly; streamedRange() reads an extent in ONE subrequest, streamed chunk by
// chunk in bounded memory (the mid-record-resume prefix re-hash, which must make progress in a single
// subrequest however large the prefix). It is an interface so the validator drives every adapter with an
// in-memory stub and no network.
export interface ByteFetcher {
  probe(t: ByteTarget, meter?: Meter): Promise<ByteProbe>;
  wholeCapped(t: ByteTarget, cap: number, meter?: Meter): Promise<WholeCapped>;
  range(t: ByteTarget, offset: number, length: number, etag: string | undefined, meter?: Meter): Promise<Uint8Array>;
  streamedRange(t: ByteTarget, offset: number, length: number, etag: string | undefined, meter?: Meter): AsyncIterable<Uint8Array>;
}

// MediaContentOpts is the optional byte-capture wiring the stream/images/artifacts adapters accept:
// whether the downpipe opted into capturing the resource BYTES (not just the metadata inventory), the
// fetcher to do it with, and whether the run can mid-record-resume (sliced runs enabled), which sets the
// in-band ceiling a large streamed value is held to. Absent/false includeContent leaves the adapter
// metadata-only (the safe default). resumable defaults to true (the deployed default has slicing on); it
// is set false under SLICED_RUNS_DISABLED, capping a large value at the one-slice ceiling. It lives here
// (not seal/adapters.ts) so the adapters import it without a cycle through the builder.
export interface MediaContentOpts {
  includeContent?: boolean;
  bytes?: ByteFetcher;
  resumable?: boolean;
}

// BlobCapture is captureBlob's result: exactly one of a buffered value, a streamed value, or a skip
// marker (with a human reason + the size for the record). contentType is informational when present.
export interface BlobCapture {
  value?: Uint8Array;
  stream?: StreamingValue;
  contentType?: string;
  skip?: { reason: string; size: number };
}

// resolve turns a ByteTarget into the absolute URL and the header set. A relative path (starts with "/")
// is prefixed with the API base and Bearer-authenticated unless auth is explicitly false; an absolute URL
// is used verbatim and only Bearer-authenticated when auth is explicitly true.
function resolve(token: string, t: ByteTarget): { url: string; headers: Record<string, string> } {
  const relative = t.url.startsWith("/");
  const url = relative ? `${CF_API_BASE}${t.url}` : t.url;
  const auth = t.auth ?? relative;
  const headers: Record<string, string> = { ...(t.headers ?? {}) };
  if (auth) headers.authorization = `Bearer ${token}`;
  return { url, headers };
}

// sameOrigin reports whether two absolute URLs share a scheme+host+port origin. Used to decide whether a
// followed redirect may keep the Authorization header (same origin) or must drop it (a different origin). An
// unparseable URL is treated as a DIFFERENT origin (fail safe: strip the token rather than risk leaking it).
function sameOrigin(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

// stripAuthorization returns a copy of the headers with any Authorization header removed (case-insensitive),
// so a cross-origin redirect follow never forwards the Bearer/registry token to the redirected host.
function stripAuthorization(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === "authorization") continue;
    out[k] = v;
  }
  return out;
}

// parseContentRange reads the total size out of a "bytes 0-0/12345" Content-Range header; returns -1
// when absent or unparseable (a "*" total or a missing header).
function parseContentRange(h: string | null): number {
  if (!h) return -1;
  const m = /\/(\d+)\s*$/.exec(h.trim());
  return m ? Number(m[1]) : -1;
}

// makeByteFetcher builds the real fetch-backed client: Bearer/registry auth, shared transient-fault
// retry, pacer-aware (both no-op when absent, so the off-network stub path is unchanged), and a clear
// throw on any non-ok response (never a silent empty body).
export function makeByteFetcher(token: string, fetchImpl: typeof fetch = fetch, pacer?: CfPacer): ByteFetcher {
  // G170: withRetry only ever surfaces the TERMINAL outcome, so every 429 a retry successfully swallowed is
  // invisible today and a chronically throttled account reads as perfectly healthy right up to the day the
  // retries exhaust. Recording inside the retried function counts the absorbed 429s; recording the exhaustion
  // on the way out counts the ones that finally beat us. Counts and a clamped seconds value only.
  const doFetch = (t: ByteTarget, extra: Record<string, string>, meter: Meter | undefined): Promise<Response> =>
    withRetry(async () => {
      const { url, headers } = resolve(token, t);
      // redirect:"manual" prevents the runtime from silently following a 3xx: for an absolute-URL target
      // (e.g. the Stream download URL) stream.ts's isCloudflareStreamUrl allow-list only validates the URL
      // BEFORE this fetch, so a redirect from that (validated) host could otherwise steer the read at an
      // unvalidated target with no re-check (V15.2.1). We follow a 3xx ONLY when t.allowRedirect re-passes
      // the source's own allow-list on the resolved Location, and only ONCE (depth bound 1: a second 3xx
      // throws). Everything else (no predicate, no Location, predicate rejects, opaque status 0) throws.
      let currentUrl = url;
      let currentHeaders: Record<string, string> = { ...headers, ...extra };
      for (let hop = 0; ; hop++) {
        await pacer?.take();
        meter?.spend(1, "cfApiRead");
        const resp = await fetchImpl(currentUrl, { method: "GET", headers: currentHeaders, redirect: "manual" });
        if (resp.status === 429) {
          const retryAfterMs = parseRetryAfter(resp.headers.get("retry-after"));
          // G170: count the throttle BEFORE the throw, so a 429 the retry ladder goes on to absorb is still
          // evidence. The Retry-After is the platform's own ask, carried as a clamped integer; the URL is not.
          recordThrottle(retryAfterMs === null ? undefined : Math.round(retryAfterMs / 1000));
          throw rateLimitError(`byte fetch ${t.url}: HTTP 429`, retryAfterMs);
        }
        // A 3xx, or the opaque-redirect status 0 that redirect:"manual" can surface, is not followed by
        // default: hard-fail exactly like dest/s3.ts / dest/s3-read-ops.ts / dest/sts.ts / notify/types.ts do
        // for every other externally-steerable fetch in this codebase.
        if (resp.status === 0 || (resp.status >= 300 && resp.status < 400)) {
          const location = resp.status === 0 ? null : resp.headers.get("location");
          // Follow ONLY when: this is the first hop (depth bound 1), the target supplied an allow-list
          // predicate, the redirect carried a Location, that Location resolves to an absolute URL, and the
          // predicate accepts that absolute URL (re-passing the SAME allow-list that vetted the initial URL).
          if (hop === 0 && t.allowRedirect !== undefined && location !== null) {
            let resolved: URL | undefined;
            try { resolved = new URL(location, currentUrl); } catch { resolved = undefined; }
            if (resolved !== undefined && t.allowRedirect(resolved.href, currentUrl)) {
              await resp.arrayBuffer().catch(() => undefined); // drain the redirect body so the socket is reusable
              // Same method (GET) and the same Range/headers, but the Bearer token is NOT forwarded to a
              // DIFFERENT origin (the signed ?p=&s= URL needs no auth; forwarding it would leak the token).
              currentHeaders = sameOrigin(currentUrl, resolved.href) ? currentHeaders : stripAuthorization(currentHeaders);
              currentUrl = resolved.href;
              continue;
            }
          }
          // G327: a redirect on a byte-fetch target is a SECURITY refusal, not a transport hiccup: it is an
          // attempt to steer a validated read at an unvalidated host (or, past hop 0, a second hop that the
          // depth bound refuses regardless of the predicate). Today it is anonymous (an "_refused" marker
          // count, archive-sealed), so support cannot separate a benign misconfiguration from a steering
          // attempt. The KIND is recorded; the redirect TARGET is exactly what must never be.
          recordSecurityRefusal("redirect-refused");
          throw new Error(`byte fetch ${t.url}: unexpected redirect (status ${resp.status}); a byte-fetch target must not redirect except to a Location that re-passes the source's allow-list`);
        }
        return resp;
      }
    }, API_READ_RETRY).catch((e: unknown) => {
      // G170: the retry ladder gave up. Counted separately from the absorbed 429s above, so "throttled but
      // coping" and "throttled into failure" are distinguishable on the run row. Re-thrown unchanged.
      if (classifySourceFaultStatus(e) === "429") recordRetryExhausted();
      throw e;
    });

  return {
    probe: async (t, meter) => {
      // A 1-byte ranged GET learns size (Content-Range total), range support (a 206), and the ETag,
      // without pulling the body; a server that ignores Range answers 200 (acceptsRanges = false).
      const resp = await doFetch(t, { range: "bytes=0-0" }, meter);
      if (!resp.ok) throw new Error(`byte probe ${t.url}: HTTP ${resp.status}`);
      await resp.arrayBuffer().catch(() => undefined); // drain the (1-byte) body so the socket is reusable
      const acceptsRanges = resp.status === 206;
      const size = acceptsRanges
        ? parseContentRange(resp.headers.get("content-range"))
        : Number(resp.headers.get("content-length") ?? -1);
      const etag = resp.headers.get("etag");
      const contentType = resp.headers.get("content-type");
      return {
        size: Number.isFinite(size) ? size : -1,
        acceptsRanges,
        ...(etag !== null ? { etag } : {}),
        ...(contentType !== null ? { contentType } : {}),
      };
    },
    wholeCapped: async (t, cap, meter) => {
      const resp = await doFetch(t, {}, meter);
      if (!resp.ok) throw new Error(`byte fetch ${t.url}: HTTP ${resp.status}`);
      // Stream-and-count: read the body chunk by chunk, accumulating only while the running total stays at
      // or below the cap. The MOMENT it exceeds the cap we cancel the body and return overCap, so an
      // unknown-size server streaming past the Worker memory limit never gets buffered whole (it would have
      // crashed the isolate via arrayBuffer()). A null body (no stream) is treated as an empty body.
      const body = resp.body;
      if (!body) {
        const bytes = new Uint8Array(await resp.arrayBuffer());
        return bytes.length > cap ? { overCap: true as const, read: bytes.length } : { bytes };
      }
      const reader = body.getReader();
      const parts: Uint8Array[] = [];
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;
        total += value.length;
        if (total > cap) {
          await reader.cancel().catch(() => undefined); // abort the download; do not drain the rest
          return { overCap: true as const, read: total };
        }
        parts.push(value);
      }
      const out = new Uint8Array(total);
      let off = 0;
      for (const part of parts) {
        out.set(part, off);
        off += part.length;
      }
      return { bytes: out };
    },
    range: async (t, offset, length, etag, meter) => {
      const extra: Record<string, string> = { range: `bytes=${offset}-${offset + length - 1}` };
      if (etag !== undefined) extra["if-match"] = etag; // pin the version: a change -> 412, never silent
      const resp = await doFetch(t, extra, meter);
      if (resp.status === 412) throw new Error(`byte range ${t.url}: resource changed during capture (precondition failed)`);
      if (resp.status !== 206) throw new Error(`byte range ${t.url}: expected 206, got HTTP ${resp.status} (server did not honour the range)`);
      const body = new Uint8Array(await resp.arrayBuffer());
      if (body.length !== length) throw new Error(`byte range ${t.url}: expected ${length} bytes, got ${body.length}`);
      return body;
    },
    // streamedRange reads [offset, offset+length) in ONE subrequest (a single ranged GET), yielding the
    // body chunk by chunk so an arbitrarily large extent never buffers whole. It pins the version exactly
    // like range() (If-Match -> 412 on change) and asserts the total length at the end (a short body means
    // the server lied or the object changed under the pin), so the prefix re-hash it feeds is over the
    // pinned bytes or it throws. The whole read is one subrequest (it spends the meter once, like range
    // over one window), so the mid-record resume always makes forward progress in a single subrequest.
    streamedRange: async function* (t, offset, length, etag, meter): AsyncIterable<Uint8Array> {
      const extra: Record<string, string> = { range: `bytes=${offset}-${offset + length - 1}` };
      if (etag !== undefined) extra["if-match"] = etag;
      const resp = await doFetch(t, extra, meter);
      if (resp.status === 412) throw new Error(`byte streamed-range ${t.url}: resource changed during capture (precondition failed)`);
      if (resp.status !== 206) throw new Error(`byte streamed-range ${t.url}: expected 206, got HTTP ${resp.status} (server did not honour the range)`);
      const body = resp.body;
      let seen = 0;
      if (body) {
        const reader = body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!value || value.length === 0) continue;
          seen += value.length;
          yield value;
        }
      } else {
        const whole = new Uint8Array(await resp.arrayBuffer());
        seen = whole.length;
        if (whole.length > 0) yield whole;
      }
      if (seen !== length) throw new Error(`byte streamed-range ${t.url}: expected ${length} bytes, got ${seen}`);
    },
  };
}

// httpStreamingValue presents a large remote blob to the two-pass seal as a re-openable StreamingValue.
// Each open re-fetches the bytes in BYTE_RANGE_WINDOW windows, pinned to `etag`, so the two passes see
// identical bytes or the second pass throws (412). openRange windows a sub-extent the same way (one HTTP
// Range per memory window). openStreamedRange reads a sub-extent in ONE subrequest (a single ranged GET
// streamed chunk by chunk) for the mid-record-resume prefix re-hash, which must make forward progress in a
// single subrequest however large the prefix. etag is exposed so the resume can pin a record's version
// across slices (abandon rather than resume if it changed); it is omitted when the source had no etag, and
// such a value is never mid-record-resumed.
export function httpStreamingValue(fetcher: ByteFetcher, t: ByteTarget, size: number, etag: string | undefined, meter?: Meter, window: number = BYTE_RANGE_WINDOW): StreamingValue {
  const windowed = (start: number, total: number): ChunkSource => ({
    async *chunks(): AsyncIterable<Uint8Array> {
      let off = start;
      const end = start + total;
      while (off < end) {
        const len = Math.min(window, end - off);
        yield await fetcher.range(t, off, len, etag, meter);
        off += len;
      }
    },
  });
  const streamed = (start: number, total: number): ChunkSource => ({
    chunks(): AsyncIterable<Uint8Array> {
      return fetcher.streamedRange(t, start, total, etag, meter);
    },
  });
  return {
    size,
    ...(etag !== undefined ? { etag } : {}),
    open: () => windowed(0, size),
    openRange: (offset, length) => windowed(offset, length),
    openStreamedRange: (offset, length) => streamed(offset, length),
  };
}

// ByteGates tunes the size thresholds; production uses the module defaults, tests inject tiny values so
// the buffer/stream/skip decision and the streamed window are exercised without allocating real megabytes.
// resumable says whether the RUN can mid-record-resume a large streamed value (sliced runs enabled): true
// raises the in-band ceiling for an etag-pinned, range-capable object to MAX_SINGLE_RECORD_CONTENT_BYTES;
// false (SLICED_RUNS_DISABLED, the buffered whole-run path) holds it to the one-slice
// MAX_SINGLE_SLICE_RECORD_BYTES. Default true (the deployed default has slicing on).
export interface ByteGates {
  bufferMax?: number;
  window?: number;
  resumable?: boolean;
}

// recordCeiling picks the in-band capture ceiling for a streamed value. A value can only be
// MID-RECORD-RESUMED when the run allows it (sliced runs on) AND the object is range-capable AND it has a
// STABLE ETAG (the resume re-hashes the prefix pinned to that etag; without one it would risk re-hashing
// changed bytes and corrupting the record, so it must seal whole in one slice instead). A resumable value
// gets the higher MAX_SINGLE_RECORD_CONTENT_BYTES (its prefix re-hash, not the per-slice subrequest cap, is
// the bound); everything else gets the one-slice MAX_SINGLE_SLICE_RECORD_BYTES.
function recordCeiling(p: ByteProbe, resumable: boolean): number {
  return resumable && p.acceptsRanges && p.etag !== undefined ? MAX_SINGLE_RECORD_CONTENT_BYTES : MAX_SINGLE_SLICE_RECORD_BYTES;
}

// captureBlob probes a resource then returns the size-gated seal-ready shape (see the module header). A
// blob at or below the buffer cap is buffered; a larger range-capable blob is STREAMED (the seal chains it
// past the single-segment ceiling) up to the applicable record ceiling (recordCeiling: the higher
// resumable ceiling for an etag-pinned object when the run can mid-record-resume, else the one-slice
// ceiling); a blob past that ceiling, or a larger blob with no range support, is skipped (the former would
// wedge the run, the latter cannot chain without ranged reads). It never throws for a skip (surfaced as a
// marker); it DOES throw on a transport failure, which the adapter catches as its per-item fail-open.
export async function captureBlob(fetcher: ByteFetcher, t: ByteTarget, meter?: Meter, gates?: ByteGates): Promise<BlobCapture> {
  const bufferMax = gates?.bufferMax ?? BYTE_BUFFER_MAX;
  const window = gates?.window ?? BYTE_RANGE_WINDOW;
  const resumable = gates?.resumable ?? true;
  const p = await fetcher.probe(t, meter);
  if (p.size < 0) {
    // Unknown size: the probe's Content-Range total was absent or "*". A range-capable server still cannot
    // be windowed into a chain without a known length, so for either sub-case the only safe option is to
    // download under the buffer cap. Stream-and-count with an early abort the moment the running total
    // exceeds bufferMax, rather than buffering the whole body first (an unknown-size server streaming past
    // the Worker memory limit would otherwise crash the isolate). Over-cap becomes an honest skip marker.
    const r = await fetcher.wholeCapped(t, bufferMax, meter);
    if ("overCap" in r) {
      return { skip: { reason: "content size was not advertised and the body exceeds the buffer cap; not captured", size: r.read } };
    }
    return { value: r.bytes, ...(p.contentType !== undefined ? { contentType: p.contentType } : {}) };
  }
  if (p.size <= bufferMax) {
    // Advertised at or below the cap: buffer it. Still go through the capped read so a server that lies
    // about its size (sends more than it advertised) cannot overrun the buffer cap; a within-cap body keeps
    // the existing buffered-value success behaviour unchanged.
    const r = await fetcher.wholeCapped(t, bufferMax, meter);
    if ("overCap" in r) {
      return { skip: { reason: `content advertised as ${p.size} bytes overran the buffer cap during download; not captured`, size: r.read } };
    }
    return { value: r.bytes, ...(p.contentType !== undefined ? { contentType: p.contentType } : {}) };
  }
  if (!p.acceptsRanges) {
    return { skip: { reason: `content (${p.size} bytes) exceeds the buffer cap and the server does not support range reads; not captured`, size: p.size } };
  }
  const ceiling = recordCeiling(p, resumable);
  if (p.size > ceiling) {
    // OVER-CEILING SINGLE OBJECT (the whole-run-wedge mitigation). A value past the applicable ceiling
    // cannot be captured in band: a resumable (etag-pinned) value's prefix re-hash would exceed one slice's
    // wall/CPU budget; a non-resumable (no-etag / unknown-size) value, or any value when sliced runs are
    // disabled, cannot be checkpointed mid-record at all and would spend past the platform's per-invocation
    // cap, persist no progress, and after MAX_SLICE_FAILURES TERMINAL-FAIL the whole downpipe's run. The
    // declared size is known here from the cheap probe, BEFORE any seal cost is incurred, so refuse the
    // in-band capture and emit an honest skip the adapter turns into an incompleteness marker
    // (recordsIncomplete surfaces it; the rest of the backup completes). Recover this one object out of band
    // with the downpipe CLI (no Worker limits). An object at or BELOW the ceiling still streams and chains
    // (and, when resumable, seals across slices), unchanged.
    return { skip: { reason: `content (${p.size} bytes) exceeds the ${ceiling}-byte single-invocation in-band capture limit; not captured, recover it out of band`, size: p.size } };
  }
  // Range-capable, larger than the buffer cap, and within the applicable seal ceiling: stream it.
  // The seal windows it into a chained multi-segment record (seal/record.ts) when it is past the
  // single-segment ceiling, so a multi-GiB object up to the ceiling seals as an
  // ordered chain, never held whole.
  return { stream: httpStreamingValue(fetcher, t, p.size, p.etag, meter, window), ...(p.contentType !== undefined ? { contentType: p.contentType } : {}) };
}
