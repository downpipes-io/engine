// Validates the OPT-IN byte capture in the three media source adapters (images / stream / artifacts):
// with includeContent the adapter also yields the resource BYTES (extra "<id>/blob", "<uid>/video.mp4",
// "<ns>/<repo>/blob/<hash>" records), gated off by default, per-item fail-open (a marker, never a void
// run), and honest markers for an async-not-ready Stream download. No network: a stub CfApi serves the
// metadata JSON and a stub ByteFetcher (the byte-fetch contract) serves the blob bytes from memory.

import { ImagesSource } from "../src/sources/images.ts";
import { StreamSource } from "../src/sources/stream.ts";
import { ArtifactsSource } from "../src/sources/artifacts.ts";
import { validateConfig } from "../src/sched/config-validate.ts";
import type { DownpipeConfig } from "../src/sched/types.ts";
import type { CfApi, CfPage } from "../src/sources/cf-config-surfaces.ts";
import type { ByteFetcher, ByteTarget } from "../src/sources/byte-fetch.ts";
import type { SourceAdapter, SourceRecord, Selector } from "../src/sources/types.ts";

let failures = 0;
function ok(msg: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${msg}`);
  if (!cond) failures++;
}
const ALL: Selector = { include: [], exclude: [] };
const enc = (s: string) => new TextEncoder().encode(s);
const dec = (u: Uint8Array) => new TextDecoder().decode(u);
function stripQuery(p: string): string {
  return p.split("?")[0] ?? p;
}
async function collect(src: SourceAdapter, sel: Selector = ALL): Promise<SourceRecord[]> {
  const out: SourceRecord[] = [];
  for await (const r of src.crawl(sel)) out.push(r);
  return out;
}
function byName(recs: SourceRecord[], name: string): SourceRecord | undefined {
  return recs.find((r) => r.name === name);
}

// stubFetcher serves blob bytes from a map keyed by the EXACT target url. A url in `fail` throws (to
// exercise per-item fail-open); a url not in the map throws a 404. Everything is small, so captureBlob
// buffers it into `value` (the streaming path is covered by validate-byte-fetch).
function stubFetcher(map: Record<string, Uint8Array>, fail: Set<string> = new Set()): ByteFetcher {
  const get = (t: ByteTarget): Uint8Array => {
    if (fail.has(t.url)) throw new Error("403 forbidden");
    const b = map[t.url];
    if (b === undefined) throw new Error(`404 ${t.url}`);
    return b;
  };
  return {
    probe: async (t) => ({ size: get(t).length, acceptsRanges: true, etag: '"x"' }),
    wholeCapped: async (t, cap) => {
      const b = get(t);
      return b.length > cap ? { overCap: true as const, read: b.length } : { bytes: b };
    },
    range: async (t, o, l) => get(t).slice(o, o + l),
    streamedRange: async function* (t, o, l) { yield get(t).slice(o, o + l); },
  };
}

// ---------------------------------------------------------------------------
console.log("-- Images: includeContent adds a '<id>/blob' bytes record per image --");
// ---------------------------------------------------------------------------
{
  const imagesApi: CfApi = {
    get: async (path) => {
      if (path.includes("/images/v1/variants")) return { w: 1 };
      if (path.includes("/images/v2")) return { images: [{ id: "a" }, { id: "b" }], continuation_token: "" };
      return null;
    },
    getPage: async () => ({ result: [] }),
    send: async () => null,
  };
  const blobA = enc("IMAGE-A-BYTES");
  const blobB = enc("IMAGE-B-BYTES");
  const fetcher = stubFetcher({
    "/accounts/acct/images/v1/a/blob": blobA,
    "/accounts/acct/images/v1/b/blob": blobB,
  });

  const off = await collect(new ImagesSource("acct", imagesApi));
  ok("default (no content): no /blob records", !off.some((r) => r.name.endsWith("/blob")));

  const on = await collect(new ImagesSource("acct", imagesApi, { includeContent: true, bytes: fetcher }));
  ok("metadata record still present for each image", byName(on, "a") !== undefined && byName(on, "b") !== undefined);
  ok("blob record present for each image", byName(on, "a/blob") !== undefined && byName(on, "b/blob") !== undefined);
  ok("blob 'a' carries the exact bytes as a value", (() => { const r = byName(on, "a/blob"); return r?.value !== undefined && dec(r.value) === "IMAGE-A-BYTES"; })());

  // fail-open: image b's blob fetch throws -> a marker, the run is intact and a's blob still captured.
  const failer = stubFetcher({ "/accounts/acct/images/v1/a/blob": blobA }, new Set(["/accounts/acct/images/v1/b/blob"]));
  const fo = await collect(new ImagesSource("acct", imagesApi, { includeContent: true, bytes: failer }));
  ok("a's blob captured, b's blob is an _unavailable marker (fail-open)", (() => {
    const a = byName(fo, "a/blob");
    const b = byName(fo, "b/blob");
    return a?.value !== undefined && dec(a.value) === "IMAGE-A-BYTES" && b?.value !== undefined && dec(b.value).includes("_unavailable");
  })());
}

// ---------------------------------------------------------------------------
console.log("\n-- Stream: includeContent captures a ready MP4 + captions, marks a pending one --");
// ---------------------------------------------------------------------------
{
  const streamApi: CfApi = {
    get: async (path) => {
      if (/\/stream\/v1\/captions$/.test(stripQuery(path))) return [{ language: "en" }];
      if (/\/stream\/v2\/captions$/.test(stripQuery(path))) return [];
      if (/\/stream$/.test(stripQuery(path)) || path.includes("/stream?")) return [{ uid: "v1" }, { uid: "v2" }];
      return null;
    },
    getPage: async () => ({ result: [] }),
    send: async (_m, path) => {
      if (path.includes("/stream/v1/downloads")) return { default: { status: "ready", url: "https://customer.cloudflarestream.com/v1.mp4" } };
      if (path.includes("/stream/v2/downloads")) return { default: { status: "inprogress", percentComplete: 42 } };
      return null;
    },
  };
  const mp4 = enc("MP4-V1-BYTES");
  const vtt = enc("WEBVTT en");
  const fetcher = stubFetcher({
    "https://customer.cloudflarestream.com/v1.mp4": mp4,
    "/accounts/acct/stream/v1/captions/en/vtt": vtt,
  });

  const off = await collect(new StreamSource("acct", streamApi));
  ok("default (no content): no video/caption records", !off.some((r) => r.name.includes("/video.mp4") || r.name.includes("/captions/")));

  const on = await collect(new StreamSource("acct", streamApi, { includeContent: true, bytes: fetcher }));
  ok("v1 ready: video.mp4 carries the exact bytes", (() => { const r = byName(on, "v1/video.mp4"); return r?.value !== undefined && dec(r.value) === "MP4-V1-BYTES"; })());
  ok("v1 caption track captured as vtt bytes", (() => { const r = byName(on, "v1/captions/en.vtt"); return r?.value !== undefined && dec(r.value) === "WEBVTT en"; })());
  ok("v2 in-progress: video.mp4 is a _pending marker (captured on a later run)", (() => { const r = byName(on, "v2/video.mp4"); return r?.value !== undefined && dec(r.value).includes("_pending"); })());
}

// ---------------------------------------------------------------------------
console.log("\n-- Artifacts: includeContent walks log -> commit -> tree -> blobs (deduped) --");
// ---------------------------------------------------------------------------
{
  const page = (result: unknown[]): CfPage => ({ result, result_info: { page: 1, total_pages: 1 } });
  // TWO commits: c1 (tree t1 -> b1 + subtree t2 -> b2,b1-dup) and c2 (tree t3 -> b1-shared + b3-new). The
  // walk must cover BOTH commits (full history), and b1 (shared across commits) must be captured ONCE.
  const artifactsApi: CfApi = {
    get: async (path) => {
      const p = stripQuery(path);
      if (p.endsWith("/repos/r/log")) return [{ hash: "c1" }, { hash: "c2" }];
      if (p.endsWith("/repos/r/commit/c1")) return { tree: "t1" };
      if (p.endsWith("/repos/r/commit/c2")) return { tree: "t3" };
      if (p.endsWith("/repos/r/tree/t1")) return { entries: [{ type: "blob", hash: "b1", name: "f1" }, { type: "tree", hash: "t2", name: "sub" }] };
      if (p.endsWith("/repos/r/tree/t2")) return { entries: [{ type: "blob", hash: "b2", name: "f2" }, { type: "blob", hash: "b1", name: "dup" }] };
      if (p.endsWith("/repos/r/tree/t3")) return { entries: [{ type: "blob", hash: "b1", name: "f1-unchanged" }, { type: "blob", hash: "b3", name: "f3-new" }] };
      return null;
    },
    getPage: async (path) => {
      const p = stripQuery(path);
      if (p.endsWith("/artifacts/namespaces")) return page([{ name: "ns" }]);
      if (p.endsWith("/namespaces/ns/repos")) return page([{ name: "r" }]);
      return page([]);
    },
    send: async () => null,
  };
  const b1 = enc("BLOB-ONE");
  const b2 = enc("BLOB-TWO");
  const b3 = enc("BLOB-THREE");
  const fetcher = stubFetcher({
    "/accounts/acct/artifacts/namespaces/ns/repos/r/blob/b1": b1,
    "/accounts/acct/artifacts/namespaces/ns/repos/r/blob/b2": b2,
    "/accounts/acct/artifacts/namespaces/ns/repos/r/blob/b3": b3,
  });

  const off = await collect(new ArtifactsSource("acct", artifactsApi));
  ok("default (no content): just the repo inventory record", off.length === 1 && off[0]!.name === "ns/r");

  const on = await collect(new ArtifactsSource("acct", artifactsApi, { includeContent: true, bytes: fetcher }));
  ok("inventory record still present", byName(on, "ns/r") !== undefined);
  ok("log + BOTH commits + all trees captured (full history)", byName(on, "ns/r/log") !== undefined && byName(on, "ns/r/commit/c1") !== undefined && byName(on, "ns/r/commit/c2") !== undefined && byName(on, "ns/r/tree/t1") !== undefined && byName(on, "ns/r/tree/t2") !== undefined && byName(on, "ns/r/tree/t3") !== undefined);
  ok("the new blob b3 from the second commit is captured", (() => { const r = byName(on, "ns/r/blob/b3"); return r?.value !== undefined && dec(r.value) === "BLOB-THREE"; })());
  ok("blob b1 + b2 captured with exact bytes", (() => {
    const r1 = byName(on, "ns/r/blob/b1");
    const r2 = byName(on, "ns/r/blob/b2");
    return r1?.value !== undefined && dec(r1.value) === "BLOB-ONE" && r2?.value !== undefined && dec(r2.value) === "BLOB-TWO";
  })());
  ok("a blob hash reachable twice is captured only ONCE (deduped)", on.filter((r) => r.name === "ns/r/blob/b1").length === 1);
}

// ---------------------------------------------------------------------------
console.log("\n-- config-validate: includeContent gate --");
// ---------------------------------------------------------------------------
{
  const cfg = (source: Record<string, unknown>): DownpipeConfig =>
    ({ id: "dp", name: "n", cadenceSeconds: 3600, enabled: true, source } as unknown as DownpipeConfig);
  const accountId = "0123456789abcdef0123456789abcdef";
  const tryValidate = (source: Record<string, unknown>): string | null => {
    try {
      validateConfig(cfg(source));
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : String(e);
    }
  };
  ok("images source with includeContent:true validates", tryValidate({ type: "images", accountId, includeContent: true, include: [], exclude: [] }) === null);
  ok("stream source with includeContent:false validates", tryValidate({ type: "stream", accountId, includeContent: false, include: [], exclude: [] }) === null);
  // Artifact Registry is GATED (Cloudflare closed beta): validateConfig rejects the TYPE. The ArtifactsSource
  // adapter above is still exercised (dormant code, snaps back when ungated). At GA, add "artifacts" to
  // SELECTABLE_SOURCE_TYPES in config-validate.ts, which is the single place the gate lives, and restore this
  // to expect === null.
  //
  // The message is matched, not merely its presence. "it threw something" passes for any reason at all,
  // including a probe config that was invalid for an unrelated field, so it would keep passing if the gate
  // opened and the config were rejected on the next line down.
  ok("artifacts source is gated (closed beta): validateConfig rejects THE TYPE", (tryValidate({ type: "artifacts", accountId, includeContent: true, include: [], exclude: [] }) ?? "").startsWith("source.type must be"));
  ok("includeContent on a kv source is rejected", (tryValidate({ type: "kv", binding: "KV_x", includeContent: true, include: [], exclude: [] }) ?? "").includes("only valid for stream/images/artifacts"));
  ok("non-boolean includeContent is rejected", (tryValidate({ type: "images", accountId, includeContent: "yes", include: [], exclude: [] }) ?? "").includes("must be a boolean"));
  ok("absent includeContent still validates (default = metadata only)", tryValidate({ type: "images", accountId, include: [], exclude: [] }) === null);
}

console.log(failures === 0 ? "\nMEDIA-CONTENT PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
