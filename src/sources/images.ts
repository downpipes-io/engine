// Cloudflare Images source: snapshots the account's Images INVENTORY + metadata (id, filename,
// uploaded, requireSignedURLs, variants, user meta) as one record per image, PLUS the account-level
// variant DEFINITIONS as one record. Like cf-config/workers/stream (and UNLIKE the binding sources),
// it reads the Cloudflare REST API with the engine's read-only discovery token; account-scoped, no binding.
//
// SCOPE: ALWAYS the image METADATA inventory (paged in full via the v2 continuation-token list, one
// record per image, so it streams record-by-record and scales like KV) plus the variant config. When the
// downpipe opts in (includeContent), ALSO the image BINARIES: one extra "<id>/blob" record per image
// holding the original bytes from /images/v1/{id}/blob, size-gated by captureBlob (small buffered, large
// streamed, over-ceiling skipped with an honest marker). Signing KEYS (/images/v1/keys) are value-bearing
// secrets and are NOT captured. Metadata-only is the default (bytes can multiply a run's size and cost).
//
// RESTORE is REPROVISION (like workers/stream): the snapshot proves the inventory + variant config (and,
// with content, the image bytes) are recoverable; the operator re-uploads deliberately. resolveSink has
// no images sink (-> reprovision); the Go reader's ReprovisionSourceType("images") is true.
//
// FAIL-OPEN: the variant read and each per-image blob fetch are fail-open (a missing variants config or an
// un-fetchable blob never voids the run, it leaves a marker); the image list throws loudly on a broken
// token. A list that exceeds the page cap emits an honest "_truncated" marker, never a silent drop.

import { captureBlob, type MediaContentOpts } from "./byte-fetch.ts";
import type { CfApi } from "./cf-config-surfaces.ts";
import { inScope } from "./selector.ts";
import {
  classifySourceFaultReason,
  classifySourceFaultStatus,
  faultItemId,
  recordIncompleteFault,
  recordShapeAnomaly,
  recordSourceFatal,
} from "./source-fault-ledger.ts";
import type { CrawlEvent, Meter, ResumableSource, Selector, SourceAdapter, SourceRecord } from "./types.ts";

export const IMAGES_PER_PAGE = 1000;
// A hard ceiling so a buggy/looping continuation can never spin forever; 1000 pages * 1000/page = 1e6
// images, far above any realistic library. Past it we emit a truncation marker, never silently drop.
export const IMAGES_MAX_PAGES = 1000;

// ImagesToken is the resume cursor (R2-3): the v2 list `continuation_token` for the page to resume on
// plus `afterId`, the id of the last image whose records were ALL yielded. A resume re-fetches the page
// at `continuation` and skips every image up to and including `afterId`, so no already-yielded image is
// re-read; `variantsDone` records that the account-level variant config was already emitted so a resume
// never re-emits it. The cursor carries no value bytes.
interface ImagesToken {
  continuation?: string;
  afterId?: string;
  variantsDone: boolean;
}

// parseImagesToken parses a persisted resume token and asserts its shape, mirroring workers.ts's
// parseWorkersToken. A corrupt token would silently restart the whole crawl, so a malformed token throws.
function parseImagesToken(token: string): ImagesToken {
  const t = JSON.parse(token) as ImagesToken;
  if (typeof t.variantsDone !== "boolean") throw new Error("malformed Images resume token");
  if (t.continuation !== undefined && typeof t.continuation !== "string") throw new Error("malformed Images resume token");
  if (t.afterId !== undefined && typeof t.afterId !== "string") throw new Error("malformed Images resume token");
  return t;
}

// ImagesSource is RESUMABLE: crawlFrom emits a {mark} after the variant config and after each fully-
// yielded image (its metadata plus, with content, its blob), so the sliced seal can checkpoint between
// images and span invocations the way it does WorkersSource. crawl() is the whole-crawl form.
export class ImagesSource implements SourceAdapter, ResumableSource {
  readonly sourceType = "images" as const;
  readonly accountId: string;
  private api: CfApi;
  private content: MediaContentOpts;

  constructor(accountId: string, api: CfApi, content?: MediaContentOpts) {
    this.accountId = accountId;
    this.api = api;
    this.content = content ?? {};
  }

  private acct(): string {
    return encodeURIComponent(this.accountId);
  }

  // captureBytes is true only when the downpipe opted into content AND a byte fetcher is wired.
  private captureBytes(): boolean {
    return this.content.includeContent === true && this.content.bytes !== undefined;
  }

  // crawl() is the whole-crawl form: it delegates to crawlFrom(selector, null, meter) and drops the
  // marks, preserving the same yield-records behaviour over a full pass. The sliced seal uses crawlFrom
  // directly (it needs the marks to checkpoint between images).
  async *crawl(selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    for await (const ev of this.crawlFrom(selector, null, meter)) {
      if (ev.kind === "record") yield ev.record;
    }
  }

  // crawlFrom is the RESUMABLE crawl. A null token starts a fresh crawl (the variant config, then the
  // paged image inventory); a token re-fetches the recorded continuation page, skips the variant config
  // (already emitted) and skips every image up to and including the recorded id. It emits a {mark} after
  // the variant config and AFTER each fully-yielded image (its metadata plus, with content, its blob),
  // so a slice can checkpoint between images and span invocations rather than throwing "source too large
  // for one slice" with no progress. The truncation marker is NOT followed by a mark (it ends the crawl).
  async *crawlFrom(selector: Selector, token: string | null, meter?: Meter): AsyncIterable<CrawlEvent> {
    const resume = token === null ? null : parseImagesToken(token);
    const enc = (s: string) => new TextEncoder().encode(s);
    let variantsDone = resume?.variantsDone ?? false;
    // Account-level variant DEFINITIONS (durable config), one record. Per-record fail-open. Emitted only
    // on a fresh crawl (a resume already sealed it); on success the mark records variantsDone so a later
    // resume into the image pages never re-emits it.
    if (!variantsDone && inScope("_variants", selector)) {
      meter?.spend(1, "cfApiRead");
      try {
        const variants = await this.api.get(`/accounts/${this.acct()}/images/v1/variants`);
        yield { kind: "record", record: { sourceType: "images", name: "_variants", value: enc(JSON.stringify({ variants })) } };
        variantsDone = true;
        yield { kind: "mark", token: JSON.stringify({ variantsDone: true } satisfies ImagesToken) };
      } catch (e) {
        // WS-P3: the account variant-DEFINITIONS read failed. Emit an honest "_unavailable" marker in the
        // _variants slot rather than swallowing it (which would make a run whose variant config could NOT be
        // read look identical to an account with no variants), so the seal counts it (recordsIncomplete) and
        // the run reports the gap. Mark variantsDone so a RESUME of THIS run does not re-attempt it (symmetric
        // with the success path); a LATER fresh crawl retries the read. Reason coarse+capped.
        yield { kind: "record", record: { sourceType: "images", name: "_variants", value: enc(JSON.stringify({ _unavailable: `variant definitions could not be read: ${e instanceof Error ? e.message.replace(/^Cloudflare API GET [^:]+:\s*/, "").slice(0, 200) : String(e)}` })), markerKind: "_unavailable" } };
        variantsDone = true;
        yield { kind: "mark", token: JSON.stringify({ variantsDone: true } satisfies ImagesToken) };
      }
    }
    // Image inventory (metadata), paged IN FULL via the v2 continuation token; one record per image.
    let cont: string | undefined = resume?.continuation;
    // skipUntil holds the image id the resume must skip up to (inclusive) on the FIRST re-fetched page.
    let skipUntil: string | undefined = resume?.afterId;
    let captured = 0;
    for (let page = 0; page < IMAGES_MAX_PAGES; page++) {
      const q = `per_page=${IMAGES_PER_PAGE}${cont !== undefined ? `&continuation_token=${encodeURIComponent(cont)}` : ""}`;
      meter?.spend(1, "cfApiRead");
      let result: { images?: unknown[]; continuation_token?: unknown } | null;
      try {
        result = (await this.api.get(`/accounts/${this.acct()}/images/v2?${q}`)) as { images?: unknown[]; continuation_token?: unknown } | null;
      } catch (e) {
        // G144: record the CLOSED transport verdict before the rewrap below throws away the HTTP status. The
        // classic ticket ("my Images backup fails after a token rotation") is unanswerable from the run row
        // otherwise: 401 expired vs 403 under-scoped vs 5xx outage all collapse to one coarse class.
        recordSourceFatal({ sourceType: "images", statusClass: classifySourceFaultStatus(e), stage: "list" });
        // The LIST failing (after the api layer's own retry) is a broken/under-scoped token, not a
        // per-image gap: fail loudly with the actionable scope hint (as the Workers source does) so a run
        // never reports a "successful" empty Images snapshot that listed nothing real.
        throw new Error(`Images list failed (${(e as Error).message.replace(/^Cloudflare API GET [^:]+:\s*/, "").slice(0, 160)}); the token likely lacks "Images" read scope or is invalid`);
      }
      // G110: a v2 list whose `images` field is not an array coerces to an EMPTY page here, so on a Cloudflare
      // response-shape change the crawl returns with ZERO images captured and the run still reports ok. Count it.
      if (!Array.isArray(result?.images)) recordShapeAnomaly("images:list");
      const images = Array.isArray(result?.images) ? (result.images as Array<Record<string, unknown>>) : [];
      let passedSkip = skipUntil === undefined;
      for (const img of images) {
        const id = typeof img?.id === "string" ? img.id : undefined;
        if (id === undefined) { recordShapeAnomaly("images:list-item"); continue; } // G110: an id-less image is silently dropped from the archive
        // Resume skip: walk past every id up to and including the recorded watermark before yielding.
        if (!passedSkip) {
          if (id === skipUntil) { passedSkip = true; skipUntil = undefined; }
          continue;
        }
        if (!inScope(id, selector)) continue;
        yield { kind: "record", record: { sourceType: "images", name: id, value: enc(JSON.stringify(img)) } };
        captured++;
        // Optional image BYTES: one extra "<id>/blob" record, size-gated, per-image fail-open.
        if (this.captureBytes()) {
          for await (const rec of this.blob(id, enc, meter)) yield { kind: "record", record: rec };
        }
        // Mark AFTER all of this image's records: a slice may end here and resume after this id on this
        // continuation page. The mark carries the page's continuation so the resume re-fetches it (the
        // continuation is omitted on the first page, where it is undefined, and the codec treats its
        // absence as "the first page").
        const mark: ImagesToken = cont !== undefined ? { continuation: cont, afterId: id, variantsDone } : { afterId: id, variantsDone };
        yield { kind: "mark", token: JSON.stringify(mark) };
      }
      skipUntil = undefined; // later pages yield from the top
      const next = typeof result?.continuation_token === "string" && result.continuation_token !== "" ? result.continuation_token : undefined;
      if (next === undefined) return;
      cont = next;
    }
    // G015: WHY (the page cap) and the shortfall MAGNITUDE (pages read, images accumulated), so "is our library
    // fully backed up?" is answerable from the pack; the image ids stay archive-sealed.
    recordIncompleteFault("_truncated", "page-cap", { id: "images:list", pagesRead: IMAGES_MAX_PAGES, recordsAccumulated: captured });
    yield { kind: "record", record: { sourceType: "images", name: "_truncated", value: enc(JSON.stringify({ _truncated: `image list exceeded ${IMAGES_MAX_PAGES} pages`, captured })), markerKind: "_truncated", markerReason: "page-cap" } };
  }

  // blob captures one image's original bytes (GET /images/v1/{id}/blob) as a "<id>/blob" record, size-
  // gated by captureBlob (small buffered value, large streamed value, over-ceiling an honest skip marker).
  // Per-image fail-open: any transport error leaves an "_unavailable" marker rather than voiding the run.
  private async *blob(id: string, enc: (s: string) => Uint8Array, meter?: Meter): AsyncIterable<SourceRecord> {
    const fetcher = this.content.bytes;
    if (fetcher === undefined) return;
    const name = `${id}/blob`;
    try {
      const cap = await captureBlob(fetcher, { url: `/accounts/${this.acct()}/images/v1/${encodeURIComponent(id)}/blob` }, meter, { resumable: this.content.resumable ?? true });
      if (cap.skip) {
        // G015: the size ceiling, not a fault. The image id is customer-owned, so it is attributed by handle.
        recordIncompleteFault("_skipped", "size-cap", { id: await faultItemId("images:blob", id) });
        yield { sourceType: "images", name, value: enc(JSON.stringify({ _skipped: cap.skip.reason, size: cap.skip.size })), markerKind: "_skipped", markerReason: "size-cap" };
      } else if (cap.stream) {
        yield { sourceType: "images", name, stream: cap.stream };
      } else {
        yield { sourceType: "images", name, value: cap.value ?? new Uint8Array(0) };
      }
    } catch (e) {
      // G015: WHY this image's bytes are missing (auth / not-found / rate-limited / server-error), which until
      // now lived ONLY in the archive-sealed marker payload.
      const reason = classifySourceFaultReason(e);
      recordIncompleteFault("_unavailable", reason, { id: await faultItemId("images:blob", id) });
      yield { sourceType: "images", name, value: enc(JSON.stringify({ _unavailable: e instanceof Error ? e.message : String(e) })), markerKind: "_unavailable", markerReason: reason };
    }
  }

  async estimate(selector: Selector): Promise<{ records: number; bytes: number }> {
    // One record per in-scope image (first page as a rough upper bound) plus the variants record; sizes
    // are unknown without reading. A cost projection hint, not an exhaustive count.
    try {
      const result = (await this.api.get(`/accounts/${this.acct()}/images/v2?per_page=${IMAGES_PER_PAGE}`)) as { images?: unknown[] } | null;
      const images = Array.isArray(result?.images) ? (result.images as Array<{ id?: unknown }>) : [];
      const n = images.filter((i) => typeof i?.id === "string" && inScope(i.id, selector)).length;
      // With content capture each in-scope image also yields a "<id>/blob" record, so the record count
      // (roughly) doubles; byte sizes stay unknown without reading (estimate never reads values).
      const perImage = this.captureBytes() ? 2 : 1;
      return { records: n * perImage + (inScope("_variants", selector) ? 1 : 0), bytes: -1 };
    } catch {
      return { records: 0, bytes: -1 };
    }
  }
}
