// Validates the Cloudflare Stream source adapter: one record per video (name = uid, value = the
// video metadata), selector scoping by uid, the FULL paged crawl (created cursor + uid dedup across the
// inclusive page boundary), the OPT-IN byte capture (video MP4 + caption tracks, with their ready,
// pending, skipped, streamed and fail-open shapes), cursor-stall and page-cap truncation, the meter
// accounting, and the estimate fast path. No network: an in-memory CfApi stub plus an in-memory
// ByteFetcher stub drive every path.

import { StreamSource, STREAM_LIST_LIMIT, STREAM_MAX_PAGES } from "../src/sources/stream.ts";
import type { CfApi } from "../src/sources/cf-config-surfaces.ts";
import type { ByteFetcher, ByteTarget, ByteProbe } from "../src/sources/byte-fetch.ts";
import type { Meter, CfOp } from "../src/meter.ts";
import type { SourceRecord, Selector, CrawlEvent } from "../src/sources/types.ts";
import { isResumable } from "../src/sources/types.ts";

let failures = 0;
function ok(msg: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${msg}`);
  if (!cond) failures++;
}
const ALL: Selector = { include: [], exclude: [] };
const dec = (u: Uint8Array) => JSON.parse(new TextDecoder().decode(u));

// stubApi answers GET /accounts/{a}/stream with `videos`; every other GET returns null. get() is the
// only method the adapter uses.
function stubApi(videos: unknown): CfApi {
  return {
    get: async (path: string) => (path.includes("/stream") ? videos : null),
    getPage: async () => ({ result: [] }),
    send: async () => null,
  };
}
async function collect(src: StreamSource, sel: Selector = ALL): Promise<SourceRecord[]> {
  const out: SourceRecord[] = [];
  for await (const r of src.crawl(sel)) out.push(r);
  return out;
}

async function main(): Promise<void> {
console.log("-- one record per video, name = uid, value = metadata --");
const videos = [
  { uid: "v1", name: "Intro", duration: 12, requireSignedURLs: true },
  { uid: "v2", name: "Demo", duration: 99 },
  { name: "no-uid-skip" }, // no uid -> skipped (cannot key/restore it)
];
const recs = await collect(new StreamSource("acct", stubApi(videos)));
ok("emits one record per video WITH a uid (2 of 3)", recs.length === 2);
ok("record name is the video uid", recs[0]!.name === "v1" && recs[1]!.name === "v2");
ok("record sourceType is 'stream'", recs.every((r) => r.sourceType === "stream"));
ok("record value is the full video metadata", dec(recs[0]!.value!).name === "Intro" && dec(recs[0]!.value!).requireSignedURLs === true);

console.log("\n-- selector scopes by uid --");
const scoped = await collect(new StreamSource("acct", stubApi(videos)), { include: ["v2"], exclude: [] });
ok("include ['v2'] yields only v2", scoped.length === 1 && scoped[0]!.name === "v2");
const excl = await collect(new StreamSource("acct", stubApi(videos)), { include: [], exclude: ["v1"] });
ok("exclude ['v1'] drops v1", excl.length === 1 && excl[0]!.name === "v2");

console.log("\n-- FULL paged crawl by the created cursor (no 1000-video cap), deduping the boundary --");
// pagedApi serves a master list the way Stream does: asc by created, at most STREAM_LIST_LIMIT per call,
// filtered to created >= start (start INCLUSIVE, so the boundary video repeats across pages).
function pagedApi(all: Array<{ uid: string; created: string }>): CfApi {
  const sorted = [...all].sort((a, b) => (a.created < b.created ? -1 : 1));
  return {
    get: async (path: string) => {
      if (!path.includes("/stream")) return null;
      const m = /[?&]start=([^&]+)/.exec(path);
      const start = m ? decodeURIComponent(m[1]!) : undefined;
      const filtered = start !== undefined ? sorted.filter((v) => v.created >= start) : sorted;
      return filtered.slice(0, STREAM_LIST_LIMIT);
    },
    getPage: async () => ({ result: [] }),
    send: async () => null,
  };
}
// 1500 videos -> 2 pages (1000 + the inclusive-boundary repeat + the rest). Distinct created so the
// cursor advances monotonically.
const big = Array.from({ length: 1500 }, (_, i) => ({ uid: `v${i}`, created: `2026-01-01T00:${String(Math.floor(i / 60)).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}.${String(i).padStart(4, "0")}Z` }));
const all = await collect(new StreamSource("acct", pagedApi(big)));
const uids = new Set(all.map((r) => r.name));
ok("every video across both pages is captured (>1000, no cap)", all.length === 1500);
ok("no duplicate uid despite the inclusive-cursor boundary", uids.size === 1500);
ok("no _truncated marker for a fully-paged library", !all.some((r) => r.name === "_truncated"));

// estimate pages the same way crawl does: a 1500-video library is counted in full, not capped at the
// first STREAM_LIST_LIMIT (1000) page. estimate must be a genuine count, not a floor, for libraries over
// 1000 videos.
const estBig = await new StreamSource("acct", pagedApi(big)).estimate(ALL);
ok("estimate pages past the first page (counts all 1500, not capped at 1000)", estBig.records === 1500);
ok("estimate.bytes is still unknown (-1) on the paged path", estBig.bytes === -1);

console.log("\n-- empty account: no records, no marker --");
const empty = await collect(new StreamSource("acct", stubApi([])));
ok("an account with no videos yields nothing", empty.length === 0);

console.log("\n-- estimate counts in-scope videos without reading values --");
const est = await new StreamSource("acct", stubApi(videos)).estimate(ALL);
ok("estimate.records = in-scope video count (2)", est.records === 2);
ok("estimate.bytes is unknown (-1)", est.bytes === -1);

console.log("\n-- estimate is fail-open: a list the token cannot read returns zero, never throws --");
const throwingApi: CfApi = {
  get: async () => { throw new Error("403 forbidden"); },
  getPage: async () => ({ result: [] }),
  send: async () => null,
};
const estErr = await new StreamSource("acct", throwingApi).estimate(ALL);
ok("estimate.records = 0 when the list read throws", estErr.records === 0);
ok("estimate.bytes still -1 on the fail-open path", estErr.bytes === -1);

// ---------------------------------------------------------------------------
// OPT-IN byte capture: includeContent + a fetcher yields the video MP4 and the
// caption tracks alongside the metadata record. contentApi distinguishes the
// LIST (a /stream query) from the per-video captions list and answers the
// download POST per uid; contentFetcher is a configurable in-memory ByteFetcher
// that returns whichever capture shape (buffered value, empty value, skip or
// stream) the case under test needs, or throws to drive the per-item fail-open.
// ---------------------------------------------------------------------------
const stripQuery = (p: string): string => p.split("?", 1)[0]!;

// One in-scope video per uid in `uids`, plus the metadata the download/captions
// behaviour keys off. `downloads` maps a uid to the /downloads response (status,
// url, percentComplete); `captionLangs` maps a uid to its caption track list (a
// non-array value drives the not-an-array fallback); `captionsThrow` makes the
// captions LIST read throw (the fail-open-to-nothing path).
interface ContentApiSpec {
  uids: string[];
  downloads: Record<string, unknown>;
  captionLangs: Record<string, unknown>;
  captionsThrow?: Set<string>;
}
function contentApi(spec: ContentApiSpec): CfApi {
  return {
    get: async (path: string) => {
      const p = stripQuery(path);
      const capMatch = /\/stream\/([^/]+)\/captions$/.exec(p);
      if (capMatch) {
        const uid = decodeURIComponent(capMatch[1]!);
        if (spec.captionsThrow?.has(uid)) throw new Error("captions list 500");
        return spec.captionLangs[uid] ?? [];
      }
      if (/\/stream$/.test(p)) return spec.uids.map((uid) => ({ uid }));
      return null;
    },
    getPage: async () => ({ result: [] }),
    send: async (_method: string, path: string) => {
      const m = /\/stream\/([^/]+)\/downloads$/.exec(stripQuery(path));
      if (m) {
        const uid = decodeURIComponent(m[1]!);
        if (spec.downloads[uid] instanceof Error) throw spec.downloads[uid];
        return spec.downloads[uid] ?? null;
      }
      return null;
    },
  };
}

// A capture-shape description the stub turns into a captureBlob-equivalent result.
type Shape =
  | { kind: "value"; bytes: Uint8Array }
  | { kind: "empty" } // whole() returns 0 bytes -> the cap.value ?? new Uint8Array(0) fallback
  | { kind: "skip"; reason: string; size: number } // not range-capable + over the buffer cap -> a skip
  | { kind: "stream"; size: number } // range-capable + over the buffer cap -> a StreamingValue
  | { kind: "throw"; message: string }
  | { kind: "throwString"; message: string }; // probe throws a bare string -> the String(e) catch arm

// contentFetcher drives captureBlob's real size-gated branching off `shapes`,
// keyed by the EXACT target url, by tuning probe()/whole()/range() per shape. The
// adapter calls captureBlob with the module-default 32 MiB buffer cap, so the skip
// and stream shapes simply REPORT a size just over that cap (OVER_CAP); the bytes
// are never allocated because whole() is not called for either shape.
function contentFetcher(shapes: Record<string, Shape>): ByteFetcher {
  const shapeFor = (t: ByteTarget): Shape => {
    const s = shapes[t.url];
    if (s === undefined) throw new Error(`unexpected target ${t.url}`);
    return s;
  };
  return {
    probe: async (t: ByteTarget): Promise<ByteProbe> => {
      const s = shapeFor(t);
      if (s.kind === "throw") throw new Error(s.message);
      if (s.kind === "throwString") throw s.message; // a non-Error throw
      if (s.kind === "value") return { size: s.bytes.length, acceptsRanges: true, etag: '"v"' };
      if (s.kind === "empty") return { size: 0, acceptsRanges: true, etag: '"e"' };
      if (s.kind === "skip") return { size: s.size, acceptsRanges: false };
      return { size: s.size, acceptsRanges: true, etag: '"s"' };
    },
    wholeCapped: async (t: ByteTarget, cap: number) => {
      const s = shapeFor(t);
      const b = s.kind === "value" ? s.bytes : s.kind === "empty" ? new Uint8Array(0) : undefined;
      if (b === undefined) throw new Error(`wholeCapped() unexpected for ${s.kind}`);
      return b.length > cap ? { overCap: true as const, read: b.length } : { bytes: b };
    },
    range: async (t: ByteTarget, o: number, l: number): Promise<Uint8Array> => {
      const s = shapeFor(t);
      if (s.kind === "stream") return new Uint8Array(l).fill(7); // window of the streamed blob
      throw new Error(`range() unexpected for ${s.kind}`);
    },
    streamedRange: async function* (t: ByteTarget, _o: number, l: number): AsyncIterable<Uint8Array> {
      const s = shapeFor(t);
      if (s.kind === "stream") { yield new Uint8Array(l).fill(7); return; }
      throw new Error(`streamedRange() unexpected for ${s.kind}`);
    },
  };
}
// OVER_CAP is one byte past the module-default 32 MiB buffer cap, so a probe that
// reports it forces captureBlob down the skip (no range) or stream (range) branch.
const OVER_CAP = 32 * 1024 * 1024 + 1;

console.log("\n-- default (no content) yields no MP4 or caption records --");
const noContent = await collect(
  new StreamSource("acct", contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "ready", url: "https://customer-abc.cloudflarestream.com/v1.mp4" } } }, captionLangs: { v1: [{ language: "en" }] } })),
);
ok("metadata-only by default: exactly one record, the uid", noContent.length === 1 && noContent[0]!.name === "v1");
ok("no /video.mp4 record without includeContent", !noContent.some((r) => r.name.includes("/video.mp4")));
ok("no /captions/ record without includeContent", !noContent.some((r) => r.name.includes("/captions/")));

console.log("\n-- includeContent=true but no fetcher stays metadata-only (captureBytes guard) --");
const contentNoFetcher = await collect(new StreamSource("acct", contentApi({ uids: ["v1"], downloads: {}, captionLangs: {} }), { includeContent: true }));
ok("includeContent without bytes captures no MP4/captions", contentNoFetcher.length === 1 && contentNoFetcher[0]!.name === "v1");

console.log("\n-- a READY download captures the MP4 bytes; captions captured as VTT --");
const mp4 = new TextEncoder().encode("MP4-V1");
const vtt = new TextEncoder().encode("WEBVTT en");
const readyApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "ready", url: "https://customer-abc.cloudflarestream.com/v1/downloads/default.mp4" } } }, captionLangs: { v1: [{ language: "en" }] } });
const readyFetcher = contentFetcher({ "https://customer-abc.cloudflarestream.com/v1/downloads/default.mp4": { kind: "value", bytes: mp4 }, "/accounts/acct/stream/v1/captions/en/vtt": { kind: "value", bytes: vtt } });
const ready = await collect(new StreamSource("acct", readyApi, { includeContent: true, bytes: readyFetcher }));
ok("metadata record still emitted alongside the bytes", ready.some((r) => r.name === "v1"));
ok("ready video.mp4 carries the exact MP4 bytes", (() => { const r = ready.find((x) => x.name === "v1/video.mp4"); return r?.value !== undefined && new TextDecoder().decode(r.value) === "MP4-V1"; })());
ok("the caption track is captured as <uid>/captions/<lang>.vtt", (() => { const r = ready.find((x) => x.name === "v1/captions/en.vtt"); return r?.value !== undefined && new TextDecoder().decode(r.value) === "WEBVTT en"; })());

console.log("\n-- a ready download url at a non-cloudflarestream host is REFUSED (SSRF) --");
// A compromised/spoofed Stream API response points the MP4 url at an attacker host. The host allow-list
// refuses it: an honest _refused marker is emitted and captureBlob is never called against the host.
let attackerFetched = false;
const evilApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "ready", url: "https://attacker.example/evil.mp4" } } }, captionLangs: { v1: [] } });
const watchFetcher: ByteFetcher = {
  probe: async () => { attackerFetched = true; return { size: 1, acceptsRanges: true }; },
  wholeCapped: async () => { attackerFetched = true; return { bytes: new Uint8Array(0) }; },
  range: async (_t, _o, l) => { attackerFetched = true; return new Uint8Array(l); },
  streamedRange: async function* (_t, _o, l) { attackerFetched = true; yield new Uint8Array(l); },
};
const evil = await collect(new StreamSource("acct", evilApi, { includeContent: true, bytes: watchFetcher }));
ok("a non-cloudflarestream MP4 url yields a _refused video.mp4 marker", (() => { const r = evil.find((x) => x.name === "v1/video.mp4"); return r?.value !== undefined && typeof dec(r.value)._refused === "string"; })());
ok("the _refused marker reports the rejected host", (() => { const r = evil.find((x) => x.name === "v1/video.mp4"); return r?.value !== undefined && dec(r.value).host === "attacker.example"; })());
ok("captureBlob is never called against the attacker host", !attackerFetched);
ok("the video metadata record is still emitted (refusal does not void the run)", evil.some((r) => r.name === "v1"));

console.log("\n-- a url that merely CONTAINS cloudflarestream.com is still refused (no substring bypass) --");
let suffixSpoofFetched = false;
const spoofApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "ready", url: "https://cloudflarestream.com.attacker.example/evil.mp4" } } }, captionLangs: { v1: [] } });
const spoofFetcher: ByteFetcher = {
  probe: async () => { suffixSpoofFetched = true; return { size: 1, acceptsRanges: true }; },
  wholeCapped: async () => { suffixSpoofFetched = true; return { bytes: new Uint8Array(0) }; },
  range: async (_t, _o, l) => { suffixSpoofFetched = true; return new Uint8Array(l); },
  streamedRange: async function* (_t, _o, l) { suffixSpoofFetched = true; yield new Uint8Array(l); },
};
const spoof = await collect(new StreamSource("acct", spoofApi, { includeContent: true, bytes: spoofFetcher }));
ok("a host whose suffix only resembles cloudflarestream.com is refused", (() => { const r = spoof.find((x) => x.name === "v1/video.mp4"); return r?.value !== undefined && typeof dec(r.value)._refused === "string"; })());
ok("the suffix-spoof host is never fetched", !suffixSpoofFetched);

console.log("\n-- a plain http (non-https) cloudflarestream url is refused --");
let httpFetched = false;
const httpApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "ready", url: "http://videodelivery.cloudflarestream.com/v1.mp4" } } }, captionLangs: { v1: [] } });
const httpFetcher: ByteFetcher = {
  probe: async () => { httpFetched = true; return { size: 1, acceptsRanges: true }; },
  wholeCapped: async () => { httpFetched = true; return { bytes: new Uint8Array(0) }; },
  range: async (_t, _o, l) => { httpFetched = true; return new Uint8Array(l); },
  streamedRange: async function* (_t, _o, l) { httpFetched = true; yield new Uint8Array(l); },
};
const httpRun = await collect(new StreamSource("acct", httpApi, { includeContent: true, bytes: httpFetcher }));
ok("a non-https cloudflarestream url is refused", (() => { const r = httpRun.find((x) => x.name === "v1/video.mp4"); return r?.value !== undefined && typeof dec(r.value)._refused === "string"; })());
ok("the non-https url is never fetched", !httpFetched);

console.log("\n-- a bare cloudflarestream.com (apex) https url is allowed and captures --");
const apexApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "ready", url: "https://cloudflarestream.com/v1/downloads/default.mp4" } } }, captionLangs: { v1: [] } });
const apexFetcher = contentFetcher({ "https://cloudflarestream.com/v1/downloads/default.mp4": { kind: "value", bytes: mp4 } });
const apex = await collect(new StreamSource("acct", apexApi, { includeContent: true, bytes: apexFetcher }));
ok("a bare cloudflarestream.com MP4 url still captures the bytes", (() => { const r = apex.find((x) => x.name === "v1/video.mp4"); return r?.value !== undefined && new TextDecoder().decode(r.value) === "MP4-V1"; })());

console.log("\n-- the byte reads are metered as cfApiRead subrequests --");
let cfReads = 0;
const meter: Meter = { spend: (_n?: number, op?: CfOp) => { if (op === "cfApiRead") cfReads++; } };
const meteredApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "ready", url: "https://customer-abc.cloudflarestream.com/v1.mp4" } } }, captionLangs: { v1: [{ language: "en" }] } });
const meteredFetcher = contentFetcher({ "https://customer-abc.cloudflarestream.com/v1.mp4": { kind: "value", bytes: mp4 }, "/accounts/acct/stream/v1/captions/en/vtt": { kind: "value", bytes: vtt } });
for await (const _r of new StreamSource("acct", meteredApi, { includeContent: true, bytes: meteredFetcher }).crawl(ALL, meter)) { /* drain */ }
// The adapter meters its OWN cfApiRead subrequests: the list page, the per-video downloads POST,
// and the captions list (3 here). The byte reads inside captureBlob are metered by the real
// ByteFetcher, which the in-memory stub does not propagate, so only the adapter's spends are seen.
ok("byte capture spends cfApiRead for the list, the download POST and the captions list", cfReads >= 3);

console.log("\n-- a download still rendering leaves a _pending marker, not a gap --");
const pendingApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "inprogress", percentComplete: 42 } } }, captionLangs: { v1: [] } });
const pending = await collect(new StreamSource("acct", pendingApi, { includeContent: true, bytes: contentFetcher({}) }));
ok("in-progress download yields a _pending video.mp4 marker", (() => { const r = pending.find((x) => x.name === "v1/video.mp4"); return r?.value !== undefined && dec(r.value)._pending === "download inprogress"; })());
ok("the _pending marker carries percentComplete", (() => { const r = pending.find((x) => x.name === "v1/video.mp4"); return r !== undefined && dec(r.value!).percentComplete === 42; })());

console.log("\n-- an absent download default falls back to status 'unknown' with null percent --");
const unknownApi = contentApi({ uids: ["v1"], downloads: { v1: null }, captionLangs: { v1: [] } });
const unknown = await collect(new StreamSource("acct", unknownApi, { includeContent: true, bytes: contentFetcher({}) }));
ok("a null download response marks status 'unknown'", (() => { const r = unknown.find((x) => x.name === "v1/video.mp4"); return r?.value !== undefined && dec(r.value)._pending === "download unknown"; })());
ok("absent percentComplete becomes null in the marker", (() => { const r = unknown.find((x) => x.name === "v1/video.mp4"); const j = dec(r!.value!); return j.percentComplete === null; })());

console.log("\n-- a ready download with no url is treated as not-ready (pending), never a void capture --");
const noUrlApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "ready" } } }, captionLangs: { v1: [] } });
const noUrl = await collect(new StreamSource("acct", noUrlApi, { includeContent: true, bytes: contentFetcher({}) }));
ok("ready-but-urlless download falls through to a _pending marker", (() => { const r = noUrl.find((x) => x.name === "v1/video.mp4"); return r?.value !== undefined && dec(r.value)._pending === "download ready"; })());

console.log("\n-- the download POST throwing is per-video fail-open (_unavailable marker) --");
const dlThrowApi = contentApi({ uids: ["v1"], downloads: { v1: new Error("downloads 500") }, captionLangs: { v1: [] } });
const dlThrow = await collect(new StreamSource("acct", dlThrowApi, { includeContent: true, bytes: contentFetcher({}) }));
ok("a thrown download leaves an _unavailable video.mp4 marker", (() => { const r = dlThrow.find((x) => x.name === "v1/video.mp4"); return r?.value !== undefined && dec(r.value)._unavailable === "downloads 500"; })());

console.log("\n-- a non-Error thrown by the download is stringified into the marker --");
// send throws a bare string (not an Error), exercising the String(e) fallback in the catch.
const strThrowApi: CfApi = {
  get: async (path: string) => (/\/stream$/.test(stripQuery(path)) ? [{ uid: "v1" }] : []),
  getPage: async () => ({ result: [] }),
  send: async () => { throw "downloads exploded"; },
};
const strThrow = await collect(new StreamSource("acct", strThrowApi, { includeContent: true, bytes: contentFetcher({}) }));
ok("a non-Error download throw is stringified in the _unavailable marker", (() => { const r = strThrow.find((x) => x.name === "v1/video.mp4"); return r?.value !== undefined && dec(r.value)._unavailable === "downloads exploded"; })());

console.log("\n-- a ready MP4 that is too large with no range support is SKIPPED with a reason --");
const skipApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "ready", url: "https://customer-abc.cloudflarestream.com/big.mp4" } } }, captionLangs: { v1: [] } });
const skip = await collect(new StreamSource("acct", skipApi, { includeContent: true, bytes: contentFetcher({ "https://customer-abc.cloudflarestream.com/big.mp4": { kind: "skip", reason: "too big", size: OVER_CAP } }) }));
ok("an over-cap non-rangeable MP4 yields a _skipped marker with its size", (() => { const r = skip.find((x) => x.name === "v1/video.mp4"); return r?.value !== undefined && dec(r.value)._skipped !== undefined && dec(r.value).size === OVER_CAP; })());

console.log("\n-- a ready MP4 that is large but range-capable is captured as a STREAM --");
const streamApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "ready", url: "https://customer-abc.cloudflarestream.com/stream.mp4" } } }, captionLangs: { v1: [] } });
const streamed = await collect(new StreamSource("acct", streamApi, { includeContent: true, bytes: contentFetcher({ "https://customer-abc.cloudflarestream.com/stream.mp4": { kind: "stream", size: OVER_CAP } }) }));
ok("a large rangeable MP4 yields a streaming value (no buffered bytes)", (() => { const r = streamed.find((x) => x.name === "v1/video.mp4"); return r !== undefined && r.stream !== undefined && r.value === undefined && r.stream.size === OVER_CAP; })());

console.log("\n-- a ready MP4 whose body is empty still yields a (zero-length) value, never undefined --");
const emptyApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "ready", url: "https://customer-abc.cloudflarestream.com/empty.mp4" } } }, captionLangs: { v1: [] } });
const emptied = await collect(new StreamSource("acct", emptyApi, { includeContent: true, bytes: contentFetcher({ "https://customer-abc.cloudflarestream.com/empty.mp4": { kind: "empty" } }) }));
ok("an empty ready MP4 yields a zero-length value record", (() => { const r = emptied.find((x) => x.name === "v1/video.mp4"); return r?.value !== undefined && r.value.length === 0; })());

console.log("\n-- captions: a track with no language is skipped; a track with one is captured --");
const capMixApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "inprogress" } } }, captionLangs: { v1: [{ language: "en" }, { /* no language */ }, { language: "fr" }] } });
const capMix = await collect(new StreamSource("acct", capMixApi, { includeContent: true, bytes: contentFetcher({ "/accounts/acct/stream/v1/captions/en/vtt": { kind: "value", bytes: vtt }, "/accounts/acct/stream/v1/captions/fr/vtt": { kind: "value", bytes: new TextEncoder().encode("WEBVTT fr") } }) }));
ok("the languaged tracks are captured (en + fr)", capMix.some((r) => r.name === "v1/captions/en.vtt") && capMix.some((r) => r.name === "v1/captions/fr.vtt"));
ok("the language-less track yields no caption record", capMix.filter((r) => r.name.includes("/captions/")).length === 2);

console.log("\n-- captions: a non-array list response is treated as no tracks --");
const capNotArrApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "inprogress" } } }, captionLangs: { v1: { not: "an array" } } });
const capNotArr = await collect(new StreamSource("acct", capNotArrApi, { includeContent: true, bytes: contentFetcher({}) }));
ok("a non-array captions list yields no caption records", !capNotArr.some((r) => r.name.includes("/captions/")));

console.log("\n-- captions: a captions LIST that throws emits an _unavailable MARKER, run intact --");
const capListThrowApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "inprogress" } } }, captionLangs: {}, captionsThrow: new Set(["v1"]) });
const capListThrow = await collect(new StreamSource("acct", capListThrowApi, { includeContent: true, bytes: contentFetcher({}) }));
const capListMarker = capListThrow.find((r) => r.name === "v1/captions/_unavailable");
ok("a thrown captions list yields the metadata + pending marker + a v1/captions/_unavailable caption marker (visible shortfall)",
  capListThrow.some((r) => r.name === "v1") && capListMarker !== undefined && (JSON.parse(new TextDecoder().decode(capListMarker.value!)) as { _unavailable?: unknown })._unavailable !== undefined);

console.log("\n-- captions: a per-track fetch that throws leaves an _unavailable marker (fail-open) --");
const capFetchThrowApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "inprogress" } } }, captionLangs: { v1: [{ language: "en" }] } });
const capFetchThrow = await collect(new StreamSource("acct", capFetchThrowApi, { includeContent: true, bytes: contentFetcher({ "/accounts/acct/stream/v1/captions/en/vtt": { kind: "throw", message: "vtt 500" } }) }));
ok("a thrown caption fetch yields an _unavailable .vtt marker", (() => { const r = capFetchThrow.find((x) => x.name === "v1/captions/en.vtt"); return r?.value !== undefined && dec(r.value)._unavailable === "vtt 500"; })());

console.log("\n-- captions: a non-Error thrown by a track fetch is stringified into the marker --");
const capStrThrowApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "inprogress" } } }, captionLangs: { v1: [{ language: "en" }] } });
const capStrThrow = await collect(new StreamSource("acct", capStrThrowApi, { includeContent: true, bytes: contentFetcher({ "/accounts/acct/stream/v1/captions/en/vtt": { kind: "throwString", message: "vtt exploded" } }) }));
ok("a non-Error caption throw is stringified in the _unavailable marker", (() => { const r = capStrThrow.find((x) => x.name === "v1/captions/en.vtt"); return r?.value !== undefined && dec(r.value)._unavailable === "vtt exploded"; })());

console.log("\n-- captions: a too-large non-rangeable track is SKIPPED; an empty track yields a zero-length value --");
const capShapesApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "inprogress" } } }, captionLangs: { v1: [{ language: "big" }, { language: "void" }] } });
const capShapes = await collect(new StreamSource("acct", capShapesApi, { includeContent: true, bytes: contentFetcher({ "/accounts/acct/stream/v1/captions/big/vtt": { kind: "skip", reason: "too big", size: OVER_CAP }, "/accounts/acct/stream/v1/captions/void/vtt": { kind: "empty" } }) }));
ok("an over-cap non-rangeable caption yields a _skipped marker", (() => { const r = capShapes.find((x) => x.name === "v1/captions/big.vtt"); return r?.value !== undefined && dec(r.value)._skipped !== undefined; })());
ok("an empty caption track yields a zero-length value", (() => { const r = capShapes.find((x) => x.name === "v1/captions/void.vtt"); return r?.value !== undefined && r.value.length === 0; })());

console.log("\n-- captions: a large rangeable track is captured as a STREAM --");
const capStreamApi = contentApi({ uids: ["v1"], downloads: { v1: { default: { status: "inprogress" } } }, captionLangs: { v1: [{ language: "big" }] } });
const capStream = await collect(new StreamSource("acct", capStreamApi, { includeContent: true, bytes: contentFetcher({ "/accounts/acct/stream/v1/captions/big/vtt": { kind: "stream", size: OVER_CAP } }) }));
ok("a large rangeable caption yields a streaming value", (() => { const r = capStream.find((x) => x.name === "v1/captions/big.vtt"); return r !== undefined && r.stream !== undefined && r.value === undefined; })());

console.log("\n-- estimate counts roughly two records per video when content is on --");
const estContent = await new StreamSource("acct", contentApi({ uids: ["v1", "v2"], downloads: {}, captionLangs: {} }), { includeContent: true, bytes: contentFetcher({}) }).estimate(ALL);
ok("estimate.records doubles to metadata + bytes per video (2 videos -> 4)", estContent.records === 4);

console.log("\n-- estimate honours the selector, counting only in-scope videos --");
// v2 is excluded by prefix, so inScope returns false for it and only v1 counts.
const estScoped = await new StreamSource("acct", contentApi({ uids: ["v1", "v2"], downloads: {}, captionLangs: {} }), { includeContent: true, bytes: contentFetcher({}) }).estimate({ include: [], exclude: ["v2"] });
ok("estimate counts only the in-scope video, doubled for content (1 -> 2)", estScoped.records === 2);

console.log("\n-- a created-timestamp bucket wider than one page halts the crawl with an honest marker --");
// Every page returns the SAME 1000 uids sharing ONE `created` second: page 0 captures them, page 1 is
// all dups (fresh === 0) but the page is full and the cursor IS advanceable, so a single timestamp
// bucket exceeds one page. The crawl cannot page past it, so it stops with a _truncated marker rather
// than silently dropping any further videos in that bucket.
function dupPageApi(): CfApi {
  const pageVideos = Array.from({ length: STREAM_LIST_LIMIT }, (_, i) => ({ uid: `d${i}`, created: "2026-01-01T00:00:00.0000Z" }));
  return {
    get: async (path: string) => (path.includes("/stream") ? pageVideos : null),
    getPage: async () => ({ result: [] }),
    send: async () => null,
  };
}
const dupRun = await collect(new StreamSource("acct", dupPageApi()));
ok("the distinct set plus the _truncated marker are emitted", dupRun.length === STREAM_LIST_LIMIT + 1);
ok("a _truncated marker is emitted when a timestamp bucket exceeds one page", dupRun.some((r) => r.name === "_truncated"));

console.log("\n-- a full page whose last video has no created cursor halts the crawl --");
// A full page (>= limit) of fresh uids but no usable `created` on the last entry:
// nextStart is undefined so the cursor cannot advance and the crawl returns.
function noCursorApi(): CfApi {
  const pageVideos = Array.from({ length: STREAM_LIST_LIMIT }, (_, i) => ({ uid: `n${i}` })); // no created field
  return {
    get: async (path: string) => (path.includes("/stream") ? pageVideos : null),
    getPage: async () => ({ result: [] }),
    send: async () => null,
  };
}
const noCursorRun = await collect(new StreamSource("acct", noCursorApi()));
ok("an unadvanceable cursor stops the crawl after one full page", noCursorRun.length === STREAM_LIST_LIMIT);
ok("no _truncated marker when the cursor cannot advance", !noCursorRun.some((r) => r.name === "_truncated"));

console.log("\n-- exceeding the page cap emits an honest _truncated marker, never a silent drop --");
// Every page returns a FULL page of globally fresh uids with a monotonic created, so
// the crawl never exhausts and runs the whole STREAM_MAX_PAGES budget. The videos are
// all out of scope (excluded by prefix), so almost nothing is yielded until the marker
// and the run stays cheap while still iterating every page.
let pageCounter = 0;
function neverEndingApi(): CfApi {
  return {
    get: async (path: string) => {
      if (!path.includes("/stream")) return null;
      const base = pageCounter * STREAM_LIST_LIMIT;
      pageCounter++;
      return Array.from({ length: STREAM_LIST_LIMIT }, (_, i) => {
        const n = base + i;
        return { uid: `cap${n}`, created: `2026-01-01T00:00:00.${String(n).padStart(9, "0")}Z` };
      });
    },
    getPage: async () => ({ result: [] }),
    send: async () => null,
  };
}
const capped = await collect(new StreamSource("acct", neverEndingApi()), { include: ["never-matches"], exclude: [] });
ok("the crawl reads exactly STREAM_MAX_PAGES pages before truncating", pageCounter === STREAM_MAX_PAGES);
ok("the only record is the _truncated marker (everything else out of scope)", capped.length === 1 && capped[0]!.name === "_truncated");
ok("the _truncated marker names the page cap that was hit", (() => { const j = dec(capped[0]!.value!); return typeof j._truncated === "string" && j._truncated.includes(String(STREAM_MAX_PAGES)); })());

console.log("\n-- a non-array list result is treated as an empty page --");
const nonArrayList = await collect(new StreamSource("acct", stubApi({ not: "an array" })));
ok("a non-array /stream result yields no records", nonArrayList.length === 0);

console.log("\n-- estimate also treats a non-array list result as zero videos --");
const estNonArray = await new StreamSource("acct", stubApi({ not: "an array" })).estimate(ALL);
ok("estimate.records = 0 for a non-array list result", estNonArray.records === 0);

// ---------------------------------------------------------------------------
// RESUMABILITY: a library larger than one slice resumes from the cursor and
// captures the FULL set across two crawl calls, rather than restarting from the
// beginning. crawlFrom emits a {mark} after each fully-yielded video; a resume from
// that mark re-pages to the recorded page and skips every already-yielded uid.
// pagedApi serves the library the way Stream does (asc by created, <= limit/page,
// created >= start). With distinct created stamps every video is its own bucket, so
// the page boundary is exact.
// ---------------------------------------------------------------------------
console.log("\n-- crawlFrom is RESUMABLE (marks after each video, resume skips the yielded prefix) --");
{
  // A small library that still spans TWO list pages (limit lowered is not exposed, so use a >limit set).
  // Use 3 videos with distinct created on a SINGLE page (videos.length < limit ends the crawl) so the
  // page-internal resume is exercised without needing 1000+ fixtures; then a multi-page case below.
  const small = [
    { uid: "a", created: "2026-01-01T00:00:00.0001Z", name: "A" },
    { uid: "b", created: "2026-01-01T00:00:00.0002Z", name: "B" },
    { uid: "c", created: "2026-01-01T00:00:00.0003Z", name: "C" },
  ];
  function onePageApi(all: Array<{ uid: string; created: string }>): CfApi {
    const sorted = [...all].sort((x, y) => (x.created < y.created ? -1 : 1));
    return {
      get: async (path: string) => {
        if (!path.includes("/stream")) return null;
        const m = /[?&]start=([^&]+)/.exec(path);
        const start = m ? decodeURIComponent(m[1]!) : undefined;
        const filtered = start !== undefined ? sorted.filter((v) => v.created >= start) : sorted;
        return filtered.slice(0, STREAM_LIST_LIMIT);
      },
      getPage: async () => ({ result: [] }),
      send: async () => null,
    };
  }
  ok("StreamSource is resumable (implements crawlFrom)", isResumable(new StreamSource("acct", onePageApi(small))));

  // Drive crawlFrom from scratch, capturing the marks. Simulate a slice that stops after the FIRST
  // video by resuming from the first mark: the resume must yield ONLY b + c, never re-reading a.
  const evs: CrawlEvent[] = [];
  for await (const ev of new StreamSource("acct", onePageApi(small)).crawlFrom(ALL, null)) evs.push(ev);
  const marks = evs.filter((e) => e.kind === "mark") as Array<{ kind: "mark"; token: string }>;
  const fromScratch = evs.filter((e) => e.kind === "record").map((e) => (e as { record: SourceRecord }).record.name);
  ok("from scratch yields every video (a, b, c)", ["a", "b", "c"].every((n) => fromScratch.includes(n)));
  ok("a mark is emitted after each video (3)", marks.length === 3);

  const afterA = marks[0]!.token;
  const resumed: string[] = [];
  for await (const ev of new StreamSource("acct", onePageApi(small)).crawlFrom(ALL, afterA))
    if (ev.kind === "record") resumed.push(ev.record.name);
  ok("resume after the first video skips it (never re-read) and yields b + c", resumed.join(",") === "b,c");

  // The FULL set across two crawl calls (slice 1 stops at the first mark; slice 2 resumes): the union
  // must equal the whole library, with NO restart-from-the-beginning duplication.
  const sliceOne: string[] = [];
  let firstMark: string | null = null;
  for await (const ev of new StreamSource("acct", onePageApi(small)).crawlFrom(ALL, null)) {
    if (ev.kind === "record") sliceOne.push(ev.record.name);
    else if (ev.kind === "mark") { firstMark = ev.token; break; } // a real slice ends at a mark when the budget says yield
  }
  const sliceTwo: string[] = [];
  for await (const ev of new StreamSource("acct", onePageApi(small)).crawlFrom(ALL, firstMark))
    if (ev.kind === "record") sliceTwo.push(ev.record.name);
  ok("slice 1 captured the first video only (budget yielded at its mark)", sliceOne.join(",") === "a");
  ok("two slices together capture the FULL set exactly once (no restart)", [...sliceOne, ...sliceTwo].sort().join(",") === "a,b,c");

  // A library spanning TWO list pages: a resume from a mark on page 2 must NOT re-yield page 1, and the
  // union over the split must be the whole 1500-video library with no duplicate uid.
  const big2 = Array.from({ length: 1500 }, (_, i) => ({ uid: `v${String(i).padStart(4, "0")}`, created: `2026-01-01T00:${String(Math.floor(i / 60)).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}.${String(i).padStart(4, "0")}Z` }));
  // Stop slice 1 after the 1100th video's mark (well into page 2), then resume.
  let splitMark: string | null = null;
  const firstNames: string[] = [];
  let count = 0;
  for await (const ev of new StreamSource("acct", onePageApi(big2)).crawlFrom(ALL, null)) {
    if (ev.kind === "record") { firstNames.push(ev.record.name); }
    else if (ev.kind === "mark") { count++; if (count === 1100) { splitMark = ev.token; break; } }
  }
  const secondNames: string[] = [];
  for await (const ev of new StreamSource("acct", onePageApi(big2)).crawlFrom(ALL, splitMark))
    if (ev.kind === "record") secondNames.push(ev.record.name);
  const union = new Set([...firstNames, ...secondNames]);
  ok("a resume from a page-2 mark captures the full 1500-video library across the split", union.size === 1500);
  ok("no video is captured twice across the resume split (cursor, not restart)", firstNames.length + secondNames.length === 1500);
}

// ---------------------------------------------------------------------------
// INTRA-VIDEO RESUMABILITY: a single very large video captured WITH content emits several records
// (metadata, the MP4 bytes streamed in BYTE_RANGE_WINDOW windows read twice by the seal, then each
// caption track). A video large enough to exceed a single slice's budget must not wedge the run: an
// intra-video {mark} is emitted between a video's records when the slice budget is low (shouldYield), so
// the capture of one very large video spans slices and resumes. A BudgetMeter exposes shouldYield() the
// way the sliced seal's SliceBudget does; a plain Meter (no shouldYield) runs the video whole.
// ---------------------------------------------------------------------------
console.log("\n-- a single large video yields mid-item (intra-video mark) and resumes --");
{
  // One in-scope video with content: metadata + a large streamed MP4 + two caption tracks. The slice
  // budget is the only thing that decides when to checkpoint; the records are otherwise identical to the
  // per-video sequence the existing tests cover.
  const oneVideoApi = (): CfApi => contentApi({
    uids: ["big"],
    downloads: { big: { default: { status: "ready", url: "https://customer-abc.cloudflarestream.com/big/downloads/default.mp4" } } },
    captionLangs: { big: [{ language: "en" }, { language: "fr" }] },
  });
  const oneVideoFetcher = (): ByteFetcher => contentFetcher({
    "https://customer-abc.cloudflarestream.com/big/downloads/default.mp4": { kind: "stream", size: OVER_CAP }, // a large MP4 streamed in windows
    "/accounts/acct/stream/big/captions/en/vtt": { kind: "value", bytes: vtt },
    "/accounts/acct/stream/big/captions/fr/vtt": { kind: "value", bytes: new TextEncoder().encode("WEBVTT fr") },
  });
  const content = { includeContent: true, bytes: oneVideoFetcher() } as const;

  // BudgetMeter is a Meter with shouldYield() (the structural SliceBudget shape wantsYield() probes). It
  // reports "yield" once the slice has captured at least `after` records of THIS video, so the checkpoint
  // lands mid-video (after the MP4, before the captions) rather than only at the per-video boundary.
  function budgetMeter(after: number): Meter & { shouldYield(): boolean } {
    let reads = 0;
    return { spend: () => { reads++; }, shouldYield: () => reads >= after };
  }

  // BASELINE: a plain Meter has no shouldYield(), so the video is captured whole with NO intra-video
  // mark (only the per-video boundary mark).
  const wholeEvs: CrawlEvent[] = [];
  for await (const ev of new StreamSource("acct", oneVideoApi(), content).crawlFrom(ALL, null)) wholeEvs.push(ev);
  const wholeMarks = wholeEvs.filter((e) => e.kind === "mark") as Array<{ kind: "mark"; token: string }>;
  const intraVideoMarks = wholeMarks.filter((m) => JSON.parse(m.token).inVideo !== undefined);
  ok("a plain Meter (old behaviour) emits ZERO intra-video marks (only the per-video boundary mark)", intraVideoMarks.length === 0 && wholeMarks.length === 1);
  const wholeRecords = wholeEvs.filter((e) => e.kind === "record").map((e) => (e as { record: SourceRecord }).record.name);
  ok("the whole-video capture yields metadata + MP4 + both captions", wholeRecords.join(",") === "big,big/video.mp4,big/captions/en.vtt,big/captions/fr.vtt");

  // RED-BEFORE-GREEN: a budget under pressure mid-video emits an intra-video {mark} between the video's
  // records. shouldYield after 2 metered reads (the list page + the MP4 download POST) makes the first
  // checkpoint land after the MP4 record, before the captions.
  const sliceOne: string[] = [];
  let midMark: string | null = null;
  for await (const ev of new StreamSource("acct", oneVideoApi(), content).crawlFrom(ALL, null, budgetMeter(2))) {
    if (ev.kind === "record") sliceOne.push(ev.record.name);
    else if (ev.kind === "mark") { midMark = ev.token; break; } // a real slice ends at the first mark the budget produces
  }
  ok("an intra-video mark IS emitted within one large video (mid-item yield)", midMark !== null);
  const midTok = midMark !== null ? JSON.parse(midMark) : {};
  ok("the mark carries an inVideo cursor naming this uid", midTok.inVideo?.uid === "big");
  ok("the inVideo cursor resumes AFTER the MP4 record (the checkpoint point)", midTok.inVideo?.afterRecord === "big/video.mp4");
  ok("the mark's afterUid names a video BEFORE this one (empty: big is the first)", midTok.afterUid === "");
  ok("slice 1 stopped mid-video (metadata + MP4 only, no captions yet)", sliceOne.join(",") === "big,big/video.mp4");

  // RESUME from the intra-video mark: the remaining records (the two captions) are yielded; the metadata
  // and MP4 are NOT re-yielded (they were sealed in slice 1), and the video completes with its boundary
  // mark. A no-pressure budget on the resume runs to completion in one pass.
  const sliceTwo: string[] = [];
  let boundaryAfterResume: string | null = null;
  for await (const ev of new StreamSource("acct", oneVideoApi(), content).crawlFrom(ALL, midMark)) {
    if (ev.kind === "record") sliceTwo.push(ev.record.name);
    else if (ev.kind === "mark") boundaryAfterResume = ev.token;
  }
  ok("resume yields ONLY the post-watermark records (the two captions), not the metadata/MP4", sliceTwo.join(",") === "big/captions/en.vtt,big/captions/fr.vtt");
  ok("the resumed slice ends at the per-video boundary mark (video complete)", boundaryAfterResume !== null && JSON.parse(boundaryAfterResume).inVideo === undefined);
  ok("the two slices together capture the full video's records exactly once", [...sliceOne, ...sliceTwo].join(",") === "big,big/video.mp4,big/captions/en.vtt,big/captions/fr.vtt");

  // A mid-video resume must NOT re-spend the platform budget re-fetching the already-sealed MP4 bytes: the
  // replay short-circuits the download POST + byte fetch for the suppressed records. Count the MP4 fetcher
  // hits on the resume; they must be zero (only the captions are fetched live).
  let mp4Probes = 0;
  const countingFetcher: ByteFetcher = {
    probe: async (t) => { if (t.url.includes("/downloads/")) mp4Probes++; return oneVideoFetcher().probe(t); },
    wholeCapped: (t, cap) => oneVideoFetcher().wholeCapped(t, cap),
    range: (t, o, l, e) => oneVideoFetcher().range(t, o, l, e),
    streamedRange: (t, o, l, e) => oneVideoFetcher().streamedRange(t, o, l, e),
  };
  for await (const _ev of new StreamSource("acct", oneVideoApi(), { includeContent: true, bytes: countingFetcher }).crawlFrom(ALL, midMark)) { /* drain */ }
  ok("the resume does NOT re-probe/re-fetch the already-sealed MP4 bytes (replay short-circuit)", mp4Probes === 0);

  // A malformed inVideo cursor throws rather than silently restarting the crawl (mirrors
  // parseStreamToken's afterUid assertion).
  let threw = false;
  try {
    for await (const _ev of new StreamSource("acct", oneVideoApi(), content).crawlFrom(ALL, JSON.stringify({ afterUid: "", inVideo: { uid: "big" } }))) { /* drain */ }
  } catch { threw = true; }
  ok("a malformed inVideo cursor throws rather than silently restarting the crawl", threw);
}

console.log(failures === 0 ? "\nSTREAM SOURCE PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
