// Cloudflare Stream source: snapshots the account's Stream VIDEO INVENTORY + metadata (uid, name,
// duration, thumbnails, playback ids, input, status, requireSignedURLs, allowedOrigins, created,
// modified, meta) as one record per video through the unchanged seal pipeline. Like cf-config and
// workers (and UNLIKE the binding sources KV/R2/D1/Secrets), it reads the Cloudflare REST API with
// the engine's read-only discovery token; it is account-scoped and needs no binding.
//
// SCOPE: ALWAYS the video METADATA inventory, one record per video (name = video uid), so it streams
// record-by-record and scales like the KV source. When the downpipe opts in (includeContent), ALSO the
// video BYTES and the captions:
//   - "<uid>/video.mp4": the downloadable MP4. Stream renders it ASYNCHRONOUSLY: a POST to /downloads
//     ensures the download exists and reports its status. To stay inside the seal's budgeted slice (no
//     long polling), a video that is "ready" is captured this run; one still "inprogress" leaves an
//     honest "_pending" marker (with percentComplete) and is captured on a LATER run once Stream finishes
//     rendering. Never a silent gap.
//   - "<uid>/captions/<lang>.vtt": each caption track's WebVTT text (a small buffered value).
// Metadata-only is the default (video bytes can multiply a run's size and cost).
//
// RESTORE is REPROVISION (the honesty contract, like workers): the snapshot proves the inventory +
// per-video config (and, with content, the MP4 + captions) are recoverable; the operator re-uploads
// deliberately. There is NO blind restore path for "stream" (resolveSink has no stream sink ->
// reprovision; the Go reader's ReprovisionSourceType("stream") is true). Signing KEYS (/stream/keys) are
// a separate secret resource, not captured here.
//
// FAIL-OPEN: a list the token cannot read throws loudly (a broken token is not a per-video gap); each
// per-video download/captions fetch is fail-open (a marker, never a void run). A capped list (>limit
// videos) emits an honest "_truncated" marker, never a silent drop (mirrors cf-config's truncation marker).

import { captureBlob, type MediaContentOpts } from "./byte-fetch.ts";
import type { CfApi } from "./cf-config-surfaces.ts";
import { inScope } from "./selector.ts";
import {
  classifySourceFaultReason,
  classifySourceFaultStatus,
  faultItemId,
  recordIncompleteFault,
  recordResumeTokenDefect,
  recordSecurityRefusal,
  recordShapeAnomaly,
  recordSourceFatal,
} from "./source-fault-ledger.ts";
import type { CrawlEvent, Meter, ResumableSource, Selector, SourceAdapter, SourceRecord } from "./types.ts";

// BudgetLike is the structural slice of the Meter the sliced seal actually passes (a SliceBudget): it
// exposes shouldYield() so a long INTRA-video content capture can checkpoint mid-video instead of running
// to the platform subrequest cap and wedging the run (M4). The validator's plain Meter has no shouldYield,
// so wantsYield() returns false there and the video is captured whole, exactly as it did before this fix.
interface BudgetLike {
  shouldYield(): boolean;
}

// wantsYield reports whether the meter is a budget under pressure (its shouldYield() is true). A plain
// Meter (no shouldYield) is never under pressure here, so a video's records are captured in one pass.
function wantsYield(meter: Meter | undefined): boolean {
  const b = meter as Partial<BudgetLike> | undefined;
  return typeof b?.shouldYield === "function" && b.shouldYield();
}

// Stream's list endpoint returns up to 1000 videos per call. The crawl PAGES the whole library by the
// `created` cursor (asc + start = the last page's newest created), deduping by uid so a boundary video
// shared across pages is never double-counted; it scales like KV rather than capping at one page.
export const STREAM_LIST_LIMIT = 1000;
// A hard ceiling so a buggy/looping cursor can never spin forever; 1000 pages * 1000/page = 1e6 videos,
// far above any realistic library. Past it we emit a truncation marker, never silently drop.
export const STREAM_MAX_PAGES = 1000;

// isCloudflareStreamUrl is the host allow-list for the MP4 download URL (finding engine-src-050-05, SSRF).
// The download URL is taken VERBATIM from the Stream API response and fetched without the API token, so a
// compromised or spoofed response could otherwise aim the byte capture at an attacker host (incl. cloud
// metadata or an internal service). Stream always serves the MP4 from cloudflarestream.com, so we accept
// ONLY an https URL whose hostname is exactly cloudflarestream.com or a subdomain of it (the same
// exact-or-suffix idiom isAllowedWebhookUrl uses to bar workers.dev). The dotted suffix ".cloudflarestream.com"
// (not a bare "cloudflarestream.com" substring) defeats a "cloudflarestream.com.attacker.example" spoof, and
// the URL parser lowercases the hostname so the comparison is case-insensitive.
export function isCloudflareStreamUrl(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol !== "https:") return false;
  const host = u.hostname;
  return host === "cloudflarestream.com" || host.endsWith(".cloudflarestream.com");
}

// StreamToken is the resume cursor (R2-3 + M4): the page `start` (the `created` value the current list
// page was fetched from, undefined for the very first page) plus `afterUid`, the uid of the last
// video whose records were ALL yielded. A resume re-fetches the page at `start` and, within that
// page, skips every video up to and including `afterUid` (and skips whole earlier pages by paging
// forward to `start`), so no already-yielded video is re-read. The cursor never carries value bytes.
//
// M4 (MEDIUM, can wedge a run): a single video captured WITH content emits several records (metadata,
// the MP4 bytes, each caption track), and the seal reads a large MP4's bytes TWICE (address then seal)
// in BYTE_RANGE_WINDOW windows. The only checkpoint was the coarse per-video mark AFTER all of those
// records, so one very large video's capture could exceed a single invocation's subrequest budget with
// no intra-video yield and wedge the run on that one item. So the resume cursor ALSO checkpoints WITHIN
// a video: the optional `inVideo` cursor records the uid and `afterRecord`, the record name (e.g.
// "<uid>/video.mp4") AFTER which to resume the video's record sequence. On resume the video's records
// are re-derived deterministically and every record up to and including `afterRecord` is suppressed (the
// slice already sealed it), then the rest are yielded. No value bytes are ever in the token.
interface StreamToken {
  start?: string;
  afterUid: string;
  inVideo?: { uid: string; afterRecord: string };
}

// parseStreamToken parses a persisted resume token and asserts its shape, mirroring workers.ts's
// parseWorkersToken. A corrupt token would otherwise leave afterUid undefined and silently restart
// the whole crawl, so a malformed token throws rather than masking lost progress. The optional `inVideo`
// mid-video cursor is validated only when present (an absent cursor = resume at the video boundary, the
// R2-3 behaviour); a present-but-malformed cursor throws rather than silently restart.
function parseStreamToken(token: string): StreamToken {
  // G213: closed defect class per corruption mode; the token bytes are never recorded.
  let t: StreamToken;
  try {
    t = JSON.parse(token) as StreamToken;
  } catch {
    recordResumeTokenDefect("stream", "unparseable");
    throw new Error("malformed Stream resume token (unparseable)");
  }
  if (typeof t !== "object" || t === null || typeof t.afterUid !== "string") {
    recordResumeTokenDefect("stream", "bad-shape");
    throw new Error("malformed Stream resume token");
  }
  if (t.start !== undefined && typeof t.start !== "string") {
    recordResumeTokenDefect("stream", "bad-shape");
    throw new Error("malformed Stream resume token");
  }
  if (t.inVideo !== undefined && (typeof t.inVideo.uid !== "string" || typeof t.inVideo.afterRecord !== "string")) {
    recordResumeTokenDefect("stream", "bad-cursor");
    throw new Error("malformed Stream resume token (inVideo cursor)");
  }
  return t;
}

// VideoCtx is the per-video record-emission context (M4). One video emits several records (metadata,
// the MP4 bytes, each caption track) and the seal reads a large MP4 in BYTE_RANGE_WINDOW windows TWICE,
// so a single very large video's capture can exceed one slice's budget. emit() flows every one of that
// video's records through this context so the slice can checkpoint BETWEEN those records: it suppresses
// records already yielded on a mid-video resume (`skipRecordUntil`) and emits an intra-video {mark} after
// a record when the slice budget is low (`pressure()`).
interface VideoCtx {
  start?: string; // the page `start` cursor, carried in the intra-video mark so a resume re-pages here
  uid: string; // the video uid, the intra-video cursor's `inVideo.uid`
  prevUid: string; // the uid of the video BEFORE this one (the intra-video mark's afterUid skip watermark)
  passedRecordSkip: boolean; // false while replaying a resumed video up to the watermark; true once past it
  skipRecordUntil?: string; // the record name (e.g. "<uid>/video.mp4") to resume after on a mid-video resume
  pressure: () => boolean; // true when the slice budget wants the video capture to checkpoint and yield
  // createdMs (support-pack gap G015) is the video's upload time as epoch ms, when the list reported a
  // parseable one. It is used ONLY to derive the AGE of a "_pending" (still-rendering) marker: "a video stuck
  // at percentComplete 40 for three weeks" is a real ticket, and percentComplete alone cannot tell a fresh
  // upload from a wedged render. Only the derived, clamped AGE is ever recorded; the timestamp never is.
  createdMs?: number;
}

// StreamSource is RESUMABLE: crawlFrom emits a {mark} after each fully-yielded video (its metadata
// plus, with content, its MP4 + caption records), so the sliced seal can checkpoint between videos
// and resume across invocations the way it does WorkersSource and R2Source. The mark carries the page
// `start` cursor and the video's uid, so a resumed slice re-pages to the recorded page and skips every
// video already yielded. crawl() is the whole-crawl form (it delegates to crawlFrom and drops the marks).
export class StreamSource implements SourceAdapter, ResumableSource {
  readonly sourceType = "stream" as const;
  readonly accountId: string;
  private api: CfApi;
  private content: MediaContentOpts;

  // api is injectable for the validator (an in-memory CfApi, no network). In production, construct it
  // from the discovery token via makeCfApi(token); buildAdapter does exactly that. content is the
  // optional byte-capture wiring (off by default = metadata only).
  constructor(accountId: string, api: CfApi, content?: MediaContentOpts) {
    this.accountId = accountId;
    this.api = api;
    this.content = content ?? {};
  }

  private captureBytes(): boolean {
    return this.content.includeContent === true && this.content.bytes !== undefined;
  }

  private acct(): string {
    return encodeURIComponent(this.accountId);
  }

  // listPath returns one page: oldest-first (asc) so the `start` cursor advances monotonically; start,
  // when set, is the previous page's newest `created` timestamp (inclusive, so the boundary video repeats
  // and is deduped by uid).
  private listPath(start?: string): string {
    const base = `/accounts/${this.acct()}/stream?limit=${STREAM_LIST_LIMIT}&asc=true`;
    return start !== undefined ? `${base}&start=${encodeURIComponent(start)}` : base;
  }

  // crawl() is the whole-crawl form: it delegates to crawlFrom(selector, null, meter) and drops the
  // marks, preserving the same yield-records behaviour over a full pass. The sliced seal uses crawlFrom
  // directly (it needs the marks to checkpoint between videos).
  async *crawl(selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    for await (const ev of this.crawlFrom(selector, null, meter)) {
      if (ev.kind === "record") yield ev.record;
    }
  }

  // crawlFrom is the RESUMABLE crawl. A null token starts a fresh paged crawl; a token re-pages to the
  // recorded `start` page and skips every video up to and including the recorded uid, so no already-
  // yielded video is re-read. It emits a {mark} AFTER each fully-yielded video (its metadata plus, with
  // content, its MP4 + caption records), so a slice can checkpoint between videos and span invocations.
  // This is what lets a large library with content capture back up at all: the run continues across
  // invocations instead of throwing "source too large for one slice" with no progress. The truncation
  // markers are NOT followed by a mark (they end the crawl), so a resume never lands "after" a marker.
  async *crawlFrom(selector: Selector, token: string | null, meter?: Meter): AsyncIterable<CrawlEvent> {
    const resume = token === null ? null : parseStreamToken(token);
    // The `start` cursor is INCLUSIVE on `created`, so the videos sharing the previous page's newest
    // `created` timestamp repeat at the top of the next page. We dedup ONLY that boundary by holding the
    // uids whose created equals the cursor we advanced to, rather than a full seen-Set of every uid. A
    // full Set would grow to STREAM_MAX_PAGES * STREAM_LIST_LIMIT (up to one million 32-char uids) and
    // risk OOM in the Worker's memory limit; the boundary set is bounded by one timestamp's worth of ties.
    let prevBoundary = new Set<string>();
    let start: string | undefined = resume?.start;
    // skipUntil holds the uid the resume must skip up to (inclusive) on the FIRST re-paged page; once
    // that uid is passed it is cleared so later pages yield from the top. A resume into a page that no
    // longer contains the uid (data shifted) simply yields the page in full, never re-reading a video
    // already sealed by name in an earlier slice (the seal dedups by record name across shards).
    // skipUntil holds the uid the resume must skip up to (inclusive). On a mid-video resume (`inVideo`
    // present) `afterUid` names the PREVIOUS fully-yielded video, so the same skip walks past it and lands
    // on the interrupted video; an EMPTY afterUid means there was no prior video to skip (the interrupted
    // video was the first in-scope video of the crawl), so skipUntil is undefined and the page yields from
    // the top, re-entering the interrupted video via the inVideo cursor below.
    let skipUntil: string | undefined = resume === null || resume.afterUid === "" ? undefined : resume.afterUid;
    // inVideoResume, when present, names the video whose record sequence was interrupted mid-slice and the
    // record AFTER which to resume it. It applies to the FIRST in-scope video encountered past the uid
    // watermark (which, by construction, is that video).
    const inVideoResume = resume?.inVideo;
    let captured = 0;
    // prevUid tracks the uid of the last video whose records were ALL yielded, so an intra-video {mark} can
    // name the correct uid-skip watermark (the video BEFORE the interrupted one). On a resume it begins at
    // the uid watermark; on a fresh crawl it is empty until the first video completes.
    let prevUid = skipUntil ?? "";
    for (let page = 0; page < STREAM_MAX_PAGES; page++) {
      meter?.spend(1, "cfApiRead");
      let result: unknown;
      try {
        result = await this.api.get(this.listPath(start));
      } catch (e) {
        // G144: record the CLOSED transport verdict + stage BEFORE the rewrap below discards the HTTP status.
        recordSourceFatal({ sourceType: "stream", statusClass: classifySourceFaultStatus(e), stage: "list" });
        // The LIST failing (after the api layer's own retry) is a broken/under-scoped token, not a
        // per-video gap: fail loudly with the actionable scope hint (as the Workers source does) so a run
        // never reports a "successful" empty Stream snapshot that listed nothing real.
        throw new Error(`Stream video list failed (${(e as Error).message.replace(/^Cloudflare API GET [^:]+:\s*/, "").slice(0, 160)}); the token likely lacks "Stream" read scope or is invalid`);
      }
      // G110: a list result that is not an array coerces to an EMPTY page, so a Cloudflare response-shape change
      // returns a crawl that captured NOTHING while the run reports a clean ok. Count the tolerant-parse drop.
      if (!Array.isArray(result)) recordShapeAnomaly("stream:list");
      const videos = Array.isArray(result) ? (result as Array<Record<string, unknown>>) : [];
      let fresh = 0;
      let passedSkip = skipUntil === undefined; // once true, videos on this page may yield
      for (const v of videos) {
        const uid = typeof v?.uid === "string" ? v.uid : undefined;
        if (uid === undefined) { recordShapeAnomaly("stream:list-item"); continue; } // G110: a uid-less video is silently dropped
        if (prevBoundary.has(uid)) continue; // dedup the inclusive-cursor boundary repeat
        fresh++;
        // Resume skip: on the first re-paged page, walk past every uid up to and including the recorded
        // watermark before yielding anything (the videos before it were sealed in an earlier slice).
        if (!passedSkip) {
          if (uid === skipUntil) { passedSkip = true; skipUntil = undefined; }
          continue;
        }
        if (!inScope(uid, selector)) continue;
        // A mid-video resume re-enters THIS video's record sequence skipping the already-yielded records;
        // midVideo drives the per-record replay-suppression below. It applies only to the interrupted uid.
        const midVideo = inVideoResume?.uid === uid ? inVideoResume.afterRecord : undefined;
        const createdRaw = typeof (v as { created?: unknown })?.created === "string" ? (v as { created: string }).created : undefined;
        const createdMs = createdRaw !== undefined ? Date.parse(createdRaw) : Number.NaN;
        const ctx: VideoCtx = {
          ...(start !== undefined ? { start } : {}),
          ...(Number.isFinite(createdMs) ? { createdMs } : {}),
          uid,
          prevUid,
          passedRecordSkip: midVideo === undefined,
          ...(midVideo !== undefined ? { skipRecordUntil: midVideo } : {}),
          pressure: () => wantsYield(meter),
        };
        // The metadata record, then (with content) the MP4 + caption records, all flow through emit(),
        // which suppresses already-yielded records on a mid-video resume and emits an intra-video {mark}
        // after a record whenever the slice budget is low, so one very large video can span slices.
        yield* this.emit(ctx, { sourceType: "stream", name: uid, value: new TextEncoder().encode(JSON.stringify(v)) });
        captured++;
        if (this.captureBytes()) {
          for await (const rec of this.video(uid, ctx, meter)) yield* this.emit(ctx, rec);
          for await (const rec of this.captions(uid, ctx, meter)) yield* this.emit(ctx, rec);
        }
        // Mark AFTER all of this video's records: a slice may end here and resume after this uid on this
        // page. The mark carries the page `start` so the resume re-pages to exactly this page (start is
        // omitted on the first page, where it is undefined, so the codec round-trips it as "no start").
        const mark: StreamToken = start !== undefined ? { start, afterUid: uid } : { afterUid: uid };
        yield { kind: "mark", token: JSON.stringify(mark) };
        prevUid = uid; // this video is now fully yielded; the next intra-video mark skips up to it
      }
      // A page no longer holding the resume watermark still clears it so subsequent pages yield in full.
      skipUntil = undefined;
      if (videos.length < STREAM_LIST_LIMIT) return; // a short page is the end of the library
      // Advance the cursor to the newest created in this page; stop if it cannot advance or this page
      // added nothing new (a whole page of duplicates: avoid an unbounded loop).
      const last = videos[videos.length - 1] as { created?: unknown } | undefined;
      const nextStart = typeof last?.created === "string" ? last.created : undefined;
      if (nextStart === undefined) return;
      if (fresh === 0) {
        // A FULL page (videos.length === STREAM_LIST_LIMIT) of nothing-new means a single `created`
        // timestamp bucket is wider than one page: the inclusive cursor cannot advance past it, so
        // further videos sharing that timestamp would be stranded. Stopping here is unavoidable (paging
        // by `created` alone cannot split the bucket), so emit an honest incomplete marker rather than
        // returning silently, mirroring the page-cap path below.
        // G015: WHY this library is short (the inclusive `created` cursor cannot advance past a timestamp bucket
        // wider than one page) and by HOW MUCH (videos captured so far). The stranded uids stay archive-sealed.
        recordIncompleteFault("_truncated", "cursor-stall", { id: "stream:list", pagesRead: page + 1, recordsAccumulated: captured });
        yield {
          kind: "record",
          record: {
            sourceType: "stream",
            name: "_truncated",
            value: new TextEncoder().encode(JSON.stringify({ _truncated: `Stream crawl stalled on more than ${STREAM_LIST_LIMIT} videos sharing the created timestamp ${nextStart}`, captured })),
            markerKind: "_truncated",
            markerReason: "cursor-stall",
          },
        };
        return;
      }
      // The next boundary is every uid on this page whose created equals the cursor we advance to (the
      // ties that the inclusive `start` will repeat). Recomputed per page, so it never accumulates.
      const next = new Set<string>();
      for (const v of videos) {
        const uid = typeof v?.uid === "string" ? v.uid : undefined;
        const created = typeof (v as { created?: unknown })?.created === "string" ? (v as { created: string }).created : undefined;
        if (uid !== undefined && created === nextStart) next.add(uid);
      }
      prevBoundary = next;
      start = nextStart;
    }
    // Hit the page cap without exhausting: honest truncation marker, never a silent drop.
    recordIncompleteFault("_truncated", "page-cap", { id: "stream:list", pagesRead: STREAM_MAX_PAGES, recordsAccumulated: captured }); // G015: the shortfall magnitude
    yield {
      kind: "record",
      record: {
        sourceType: "stream",
        name: "_truncated",
        value: new TextEncoder().encode(JSON.stringify({ _truncated: `Stream crawl exceeded ${STREAM_MAX_PAGES} pages`, captured })),
        markerKind: "_truncated",
        markerReason: "page-cap",
      },
    };
  }

  // emit yields ONE of a video's records through the resume-skip + intra-video checkpoint discipline (M4).
  // While replaying a resumed video (passedRecordSkip false) it SUPPRESSES the record (the slice already
  // sealed it) and only flips passedRecordSkip once the watermark record name is reached. Past the
  // watermark it yields the record, then, if the slice budget is low (pressure()), emits an intra-video
  // {mark} carrying the `inVideo` cursor so the slice can checkpoint here and the next invocation resumes
  // the video AFTER this exact record. The {mark} is NEVER emitted while replaying (a resumed slice must
  // reach new work before it can checkpoint again) nor for a record before the watermark.
  private *emit(ctx: VideoCtx, rec: SourceRecord): Generator<CrawlEvent> {
    if (!ctx.passedRecordSkip) {
      if (rec.name === ctx.skipRecordUntil) ctx.passedRecordSkip = true;
      return; // replaying up to (and including) the watermark: do not re-yield
    }
    yield { kind: "record", record: rec };
    if (ctx.pressure()) {
      // An intra-video checkpoint: the uid-skip watermark is the PREVIOUS fully-yielded video (so the
      // resume re-pages and skips up to it), and the inVideo cursor re-enters THIS video's record sequence
      // after this exact record. afterUid must name a video strictly BEFORE this one (naming this video
      // would skip it entirely); prevUid is exactly that, set by crawlFrom as it advances video to video.
      const mark: StreamToken = ctx.start !== undefined
        ? { start: ctx.start, afterUid: ctx.prevUid, inVideo: { uid: ctx.uid, afterRecord: rec.name } }
        : { afterUid: ctx.prevUid, inVideo: { uid: ctx.uid, afterRecord: rec.name } };
      yield { kind: "mark", token: JSON.stringify(mark) };
    }
  }

  // replaying reports whether emit() will SUPPRESS this record on a mid-video resume: it is true while the
  // walk has not yet crossed the content watermark (passedRecordSkip false), because every record up to AND
  // INCLUDING the watermark is suppressed (the resume is AFTER it). The byte capture (the download POST +
  // captureBlob) is then short-circuited for such a record so a resumed slice does not re-spend the
  // platform budget re-fetching bytes whose record will be discarded; a cheap placeholder still flows
  // through emit() so the watermark check advances (mirrors the artifacts blob replay short-circuit, A2).
  // Once past the watermark, replaying() is false and the real capture runs.
  private replaying(ctx: VideoCtx): boolean {
    return !ctx.passedRecordSkip;
  }

  // video captures one video's downloadable MP4 as a "<uid>/video.mp4" record. Stream renders the MP4
  // asynchronously, so a POST to /downloads ensures it exists and reports status WITHOUT blocking: a
  // "ready" download is fetched + size-gated now; an "inprogress" one leaves a "_pending" marker (with
  // percentComplete) for a later run to capture. Per-video fail-open: any error leaves an "_unavailable"
  // marker, never a void run.
  //
  // M4 replay short-circuit: on a mid-video resume, a "<uid>/video.mp4" at or before the content watermark
  // is suppressed by the caller's emit(); to avoid re-spending the platform budget on the download POST +
  // byte fetch of a record that will be discarded, yield a cheap placeholder the suppression consumes and
  // skip the network work entirely. Past the watermark the real capture runs.
  private async *video(uid: string, ctx?: VideoCtx, meter?: Meter): AsyncIterable<SourceRecord> {
    const fetcher = this.content.bytes;
    if (fetcher === undefined) return;
    if (ctx !== undefined && this.replaying(ctx)) {
      yield { sourceType: "stream", name: `${uid}/video.mp4`, value: new Uint8Array(0) };
      return;
    }
    const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
    const name = `${uid}/video.mp4`;
    try {
      meter?.spend(1, "cfApiRead");
      // POST /downloads is create-or-return: it ensures the MP4 render exists and reports its status.
      const dl = (await this.api.send("POST", `/accounts/${this.acct()}/stream/${encodeURIComponent(uid)}/downloads`)) as
        | { default?: { status?: unknown; url?: unknown; percentComplete?: unknown } }
        | null;
      const def = dl?.default ?? {};
      const status = typeof def.status === "string" ? def.status : "unknown";
      const url = typeof def.url === "string" ? def.url : undefined;
      if (status === "ready" && url !== undefined) {
        // The MP4 URL is an absolute cloudflarestream.com address served without the API token. Validate
        // the host against the allow-list BEFORE fetching (finding engine-src-050-05, SSRF): a compromised
        // or spoofed API response could otherwise point the byte capture at an attacker host. A url that is
        // not an https cloudflarestream.com address is refused with an honest marker, never fetched.
        if (!isCloudflareStreamUrl(url)) {
          let host = url;
          try { host = new URL(url).hostname; } catch { /* keep the raw url in the marker if unparseable */ }
          // G015: the reason class only (never the host, which rides in the archive-sealed marker payload).
          recordIncompleteFault("_refused", "redirect-refused", { id: await faultItemId("stream:video", uid) });
          // G327: the same refusal, additionally counted as a SECURITY event. The G015 reason above explains
          // why a record is incomplete; this says the source layer refused an off-Cloudflare download host,
          // which is what a security-relevant signal must surface without the operator opening an archive.
          // The refused host is deliberately NOT carried here (it stays sealed in the marker payload).
          recordSecurityRefusal("host-refused");
          yield { sourceType: "stream", name, value: enc({ _refused: "download url is not an https cloudflarestream.com address", host }), markerKind: "_refused", markerReason: "redirect-refused" };
          return;
        }
        // STREAM-MP4: the download URL 302-redirects to a signed same-host URL (.../dl/default.mp4?p=..&s=..)
        // that carries the real MP4 bytes; without following it the capture only ever seals the ~212-byte
        // marker page. allowRedirect re-applies isCloudflareStreamUrl to the redirect Location, so the byte
        // fetch follows a 302 to another *.cloudflarestream.com URL but refuses one to any other host (SSRF
        // preserved: the same allow-list vets the redirect target that vetted the initial URL). The fetch
        // carries no token (auth: false), so no Bearer is exposed to the signed URL.
        const cap = await captureBlob(fetcher, { url, auth: false, allowRedirect: (loc) => isCloudflareStreamUrl(loc) }, meter, { resumable: this.content.resumable ?? true });
        if (cap.skip) {
          recordIncompleteFault("_skipped", "size-cap", { id: await faultItemId("stream:video", uid) }); // G015: the buffered-capture ceiling
          yield { sourceType: "stream", name, value: enc({ _skipped: cap.skip.reason, size: cap.skip.size }), markerKind: "_skipped", markerReason: "size-cap" };
        } else if (cap.stream) {
          yield { sourceType: "stream", name, stream: cap.stream };
        } else {
          yield { sourceType: "stream", name, value: cap.value ?? new Uint8Array(0) };
        }
        return;
      }
      // Not ready: an honest marker. A subsequent run finds it "ready" (Stream caches the render) and
      // captures the bytes, so the gap is transient and never silent.
      // G015: carry the render's AGE (clamped ms since upload), the only signal that separates "uploaded a
      // minute ago, still rendering" from "stuck at percentComplete 40 for three weeks". percentComplete itself
      // stays in the archive-sealed marker payload; the pack gets the age and the reason class.
      const ageMs = ctx?.createdMs !== undefined ? Date.now() - ctx.createdMs : undefined;
      recordIncompleteFault("_pending", "render-pending", {
        id: await faultItemId("stream:video", uid),
        ...(ageMs !== undefined && ageMs > 0 ? { pendingAgeMs: ageMs } : {}),
      });
      yield { sourceType: "stream", name, value: enc({ _pending: `download ${status}`, percentComplete: def.percentComplete ?? null }), markerKind: "_pending", markerReason: "render-pending" };
    } catch (e) {
      const reason = classifySourceFaultReason(e);
      recordIncompleteFault("_unavailable", reason, { id: await faultItemId("stream:video", uid) }); // G015
      yield { sourceType: "stream", name, value: enc({ _unavailable: e instanceof Error ? e.message : String(e) }), markerKind: "_unavailable", markerReason: reason };
    }
  }

  // captions lists a video's caption tracks then captures each track's WebVTT text as a small buffered
  // "<uid>/captions/<lang>.vtt" record. The /vtt endpoint returns text (not the JSON envelope), so it is
  // read via the byte fetcher. Fail-open: a missing/un-listable track set leaves nothing, never throws.
  //
  // M4 replay short-circuit: on a mid-video resume the caption LIST is re-read (cheap, and it re-derives
  // the deterministic track order the watermark relies on), but each track at or before the content
  // watermark has its per-track byte fetch short-circuited (a placeholder the caller's emit() suppresses),
  // so a resumed slice does not re-spend the platform budget on caption bytes whose record will be
  // discarded. Past the watermark the real per-track capture runs.
  private async *captions(uid: string, ctx?: VideoCtx, meter?: Meter): AsyncIterable<SourceRecord> {
    const fetcher = this.content.bytes;
    if (fetcher === undefined) return;
    let tracks: Array<{ language?: unknown }> = [];
    try {
      meter?.spend(1, "cfApiRead");
      const list = await this.api.get(`/accounts/${this.acct()}/stream/${encodeURIComponent(uid)}/captions`);
      // G110: a non-array caption list coerces to NO TRACKS, so on a response-shape change every video's captions
      // vanish from the archive with no marker and a clean ok. Count the tolerant-parse drop.
      if (!Array.isArray(list)) recordShapeAnomaly("stream:captions-list");
      tracks = Array.isArray(list) ? (list as Array<{ language?: unknown }>) : [];
    } catch (e) {
      // WS-P3: the caption LIST read failed (after the api layer's own retry). Emit an honest per-video
      // "_unavailable" marker rather than returning silently (which would make a video whose caption
      // inventory could NOT be read look identical to a video with no captions), so the seal counts it
      // (recordsIncomplete) and the run reports "N items not fully captured" rather than a clean ok. It
      // flows through the caller's emit() like the video's other records (resume-suppressed while replaying,
      // intra-video marked), so it never breaks the checkpoint. A later run re-reads the list and captures
      // the tracks if the fault was transient. Reason is coarse + capped (no free-text past the cap).
      const listReason = classifySourceFaultReason(e); // G015: WHY the caption inventory is short
      recordIncompleteFault("_unavailable", listReason, { id: await faultItemId("stream:captions", uid) });
      yield { sourceType: "stream", name: `${uid}/captions/_unavailable`, value: new TextEncoder().encode(JSON.stringify({ _unavailable: `caption track list could not be read: ${e instanceof Error ? e.message.replace(/^Cloudflare API GET [^:]+:\s*/, "").slice(0, 200) : String(e)}` })), markerKind: "_unavailable", markerReason: listReason };
      return; // no track order to iterate; the marker is the honest record for this video's captions
    }
    for (const t of tracks) {
      const lang = typeof t?.language === "string" ? t.language : undefined;
      if (lang === undefined) continue;
      const name = `${uid}/captions/${lang}.vtt`;
      if (ctx !== undefined && this.replaying(ctx)) {
        yield { sourceType: "stream", name, value: new Uint8Array(0) };
        continue; // replaying: skip the byte fetch; the placeholder advances the watermark via emit()
      }
      try {
        const cap = await captureBlob(fetcher, { url: `/accounts/${this.acct()}/stream/${encodeURIComponent(uid)}/captions/${encodeURIComponent(lang)}/vtt` }, meter);
        if (cap.skip) {
          recordIncompleteFault("_skipped", "size-cap", { id: await faultItemId("stream:captions", uid) }); // G015
          yield { sourceType: "stream", name, value: new TextEncoder().encode(JSON.stringify({ _skipped: cap.skip.reason, size: cap.skip.size })), markerKind: "_skipped", markerReason: "size-cap" };
        } else if (cap.stream) {
          yield { sourceType: "stream", name, stream: cap.stream };
        } else {
          yield { sourceType: "stream", name, value: cap.value ?? new Uint8Array(0) };
        }
      } catch (e) {
        const trackReason = classifySourceFaultReason(e); // G015
        recordIncompleteFault("_unavailable", trackReason, { id: await faultItemId("stream:captions", uid) });
        yield { sourceType: "stream", name, value: new TextEncoder().encode(JSON.stringify({ _unavailable: e instanceof Error ? e.message : String(e) })), markerKind: "_unavailable", markerReason: trackReason };
      }
    }
  }

  async estimate(selector: Selector): Promise<{ records: number; bytes: number }> {
    // One record per in-scope video (plus, with content, roughly one MP4 + caption records each, which
    // estimate cannot count without reading); sizes are unknown without reading (bytes: -1). The video
    // count is paged the same way crawl() pages (cursor on `created`, deduped by uid), so a library over
    // STREAM_LIST_LIMIT videos is counted in full rather than capped at the first page.
    try {
      const seen = new Set<string>();
      let start: string | undefined;
      let n = 0;
      for (let page = 0; page < STREAM_MAX_PAGES; page++) {
        const result = await this.api.get(this.listPath(start));
        const videos = Array.isArray(result) ? (result as Array<{ uid?: unknown; created?: unknown }>) : [];
        let fresh = 0;
        for (const v of videos) {
          const uid = typeof v?.uid === "string" ? v.uid : undefined;
          if (uid === undefined || seen.has(uid)) continue; // dedup the inclusive-cursor boundary repeat
          seen.add(uid);
          fresh++;
          if (inScope(uid, selector)) n++;
        }
        if (videos.length < STREAM_LIST_LIMIT) break; // a short page is the end of the library
        const last = videos[videos.length - 1] as { created?: unknown } | undefined;
        const nextStart = typeof last?.created === "string" ? last.created : undefined;
        if (nextStart === undefined || fresh === 0) break;
        start = nextStart;
      }
      const perVideo = this.captureBytes() ? 2 : 1; // metadata + (at least) the video record
      return { records: n * perVideo, bytes: -1 };
    } catch {
      return { records: 0, bytes: -1 };
    }
  }
}
