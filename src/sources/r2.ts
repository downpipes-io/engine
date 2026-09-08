import { utf8 } from "../crypto/bytes.ts";
import type { ChunkSource } from "../crypto/streamseal.ts";
import { MAX_SINGLE_RECORD_CONTENT_BYTES, MAX_SINGLE_SLICE_RECORD_BYTES } from "../seal/budget.ts";
import { vanishedMarkerValue } from "../seal/marker.ts";
import { inScope } from "./selector.ts";
import { classifyLivenessFault, type LivenessProbe, SourceResourceMissingError } from "./source-errors.ts";
import { recordResumeFatal } from "./source-fault-ledger.ts";
import type { CrawlEvent, Meter, RestoreDescriptor, ResumableSource, Selector, SourceAdapter, SourceRecord } from "./types.ts";
import { hasAnyField } from "./types.ts";

// describeObject captures an R2 object's HTTP and custom metadata into a restore descriptor
// (SPEC 6.2). The HTTP metadata is normalised to a plain JSON object of strings: a binding
// returns it as R2HTTPMetadata whose cacheExpiry is a Date, which is not canonicalisable, so
// the Date is rendered to its ISO string here (and rebuilt into a Date on the restore side).
// Every field is included only when defined, so the descriptor is the omitempty shape the Go
// reader mirrors. A custom-metadata map is carried verbatim (it is already a string map).
function describeObject(obj: { httpMetadata?: R2HTTPMetadata; customMetadata?: Record<string, string> }): RestoreDescriptor | undefined {
  const d: RestoreDescriptor = {};
  const http = obj.httpMetadata;
  if (http) {
    const h: Record<string, string> = {};
    if (http.contentType !== undefined) h.contentType = http.contentType;
    if (http.contentLanguage !== undefined) h.contentLanguage = http.contentLanguage;
    if (http.contentDisposition !== undefined) h.contentDisposition = http.contentDisposition;
    if (http.contentEncoding !== undefined) h.contentEncoding = http.contentEncoding;
    if (http.cacheControl !== undefined) h.cacheControl = http.cacheControl;
    if (http.cacheExpiry !== undefined) h.cacheExpiry = http.cacheExpiry.toISOString();
    if (Object.keys(h).length > 0) d.r2HttpMetadata = h;
  }
  const custom = obj.customMetadata;
  if (custom && Object.keys(custom).length > 0) d.r2CustomMetadata = { ...custom };
  return hasAnyField(d) ? d : undefined;
}

// Above this size an R2 object is streamed (two re-opening passes, never buffered whole);
// below it the object is read whole, which is simpler and deduplicates the same way.
export const STREAM_THRESHOLD = 8 * 1024 * 1024; // 8 MiB

interface R2Token {
  after: string; // resume listing strictly after this key (R2 startAfter)
}

function parseToken(token: string): R2Token {
  // G144: the R2 resume token's two failure modes are both RUN-FATAL (JSON.parse throws; a token without a
  // string `after` throws), and neither recorded anything at all -- so a bucket crawl wedged on a corrupt
  // token failed at the same point on every tick with a run row that said only "the run failed". The stage
  // (resume) is what places it. The token is never read into the record; the throws are byte-unchanged.
  let t: R2Token;
  try {
    t = JSON.parse(token) as R2Token;
  } catch (e) {
    recordResumeFatal("r2");
    throw e;
  }
  if (typeof t.after !== "string") {
    recordResumeFatal("r2");
    throw new Error("malformed R2 resume token");
  }
  return t;
}

// R2 adapter: crawl a bucket by listing objects and yielding each in-scope object. Small
// objects are read whole; a large object is yielded as a re-openable stream so the seal
// never holds it whole (design F11). R2 list returns object sizes, so estimate() projects
// bytes from metadata without reading values.
//
// The resumable form (crawlFrom) marks after each fully-yielded page with the page's last
// key and resumes with R2's native startAfter, so a resume is exact, needs no cursor
// longevity, and re-reads no values. R2 list is lexicographically ordered.
//
// Streamed opens are pinned to the etag observed at list time (onlyIf etagMatches): the
// two-pass seal reads a large object twice (address, then seal), and an object REPLACED
// between passes would otherwise seal bytes that do not match the recorded address. With
// the pin, a changed object reads as gone (the same shape as vanished mid-crawl) and the
// writer skips the record loudly instead of archiving a record that can never verify.
//
// A large object also carries its etag and an openStreamedRange on the stream value, so the seal can
// resume it MID-RECORD ACROSS SLICES (seal/record.ts re-hashes the already-sealed prefix in ONE
// etag-pinned ranged read rather than re-fetching the whole object each slice). The etag pin makes the
// resume safe: a version change between slices fails the pinned read, so the seal abandons the partial
// (changed-mid-crawl) instead of stitching two object versions. A single object past what one run can
// safely seal in band (recordCeiling) is NOT streamed at all: it is yielded as a LOUD incompleteness
// marker (a tiny buffered JSON value; recordsIncomplete surfaces it) and the crawl CONTINUES, so one
// over-ceiling video/dataset/VM-image no longer terminal-fails the whole run with zero archive. The
// declared size is read from the list page BEFORE any value GET, so the over-ceiling object's bytes are
// never fetched; recover it out of band with the downpipe CLI (no Worker limits).
export class R2Source implements SourceAdapter, ResumableSource, LivenessProbe {
  readonly sourceType = "r2" as const;
  private r2: R2Bucket;
  private bucketName: string;
  // resumable: whether the RUN can mid-record-resume a large object across slices (sliced runs enabled).
  // An R2 object always has a stable etag and supports ranged reads, so (mirroring sources/byte-fetch.ts
  // recordCeiling) its in-band capture ceiling is decided purely by this: the higher
  // MAX_SINGLE_RECORD_CONTENT_BYTES when it can seal across slices, else the one-slice
  // MAX_SINGLE_SLICE_RECORD_BYTES. Default true (the deployed default has slicing on); the seal builder
  // sets it false under SLICED_RUNS_DISABLED (the v1 whole-run buffered path, no mid-record resume).
  private resumable: boolean;
  // streamThreshold is the buffer-vs-stream boundary (default STREAM_THRESHOLD). It is a test seam: a
  // validator lowers it to exercise the streamed/chained/resume path on a TINY object without an 8 MiB
  // fixture (mirrors sources/byte-fetch.ts ByteGates.bufferMax). Production leaves it at the default.
  private streamThreshold: number;

  constructor(r2: R2Bucket, bucketName: string, opts?: { resumable?: boolean; streamThreshold?: number }) {
    this.r2 = r2;
    this.bucketName = bucketName;
    this.resumable = opts?.resumable ?? true;
    this.streamThreshold = opts?.streamThreshold ?? STREAM_THRESHOLD;
  }

  // recordCeiling is the largest single object captured in band; a larger object is skipped with an honest
  // marker. R2 always has an etag and ranged reads, so the only variable is whether the run can resume
  // across slices: a resumable object is bounded by its prefix re-hash (MAX_SINGLE_RECORD_CONTENT_BYTES),
  // a non-resumable one by what seals whole in a single slice (MAX_SINGLE_SLICE_RECORD_BYTES). This mirrors
  // the media adapters' recordCeiling so the two large-value paths share one ceiling rule.
  private recordCeiling(): number {
    return this.resumable ? MAX_SINGLE_RECORD_CONTENT_BYTES : MAX_SINGLE_SLICE_RECORD_BYTES;
  }

  // probeLiveness (SRC-1) proves the bound bucket still EXISTS with one cheap object list (no value read)
  // before the crawl commits to it. A truthy binding pointing at a deleted bucket passes preflight's
  // presence check but throws raw on first use; this names the failure instead.
  async probeLiveness(): Promise<void> {
    if (typeof this.r2.list !== "function") {
      throw new SourceResourceMissingError("r2", this.bucketName, "misconfigured", "the bound object is not an R2 bucket (no list())");
    }
    try {
      await this.r2.list({ limit: 1 });
    } catch (e) {
      throw classifyLivenessFault("r2", this.bucketName, e);
    }
  }

  // streamObject re-opens an R2 object as a ChunkSource (a fresh GET per pass), pinned to
  // the etag observed at list time. range bounds the read for chained-segment windows.
  private streamObject(key: string, etag: string, meter?: Meter, range?: { offset: number; length: number }): ChunkSource {
    const r2 = this.r2;
    return {
      async *chunks() {
        meter?.spend(1, "r2ClassB");
        const body = await r2.get(key, {
          onlyIf: { etagMatches: etag },
          ...(range ? { range: { offset: range.offset, length: range.length } } : {}),
        });
        // null: vanished between list and read. An onlyIf get whose precondition fails
        // returns an R2Object WITHOUT a body (the etag no longer matches, i.e. the object
        // was replaced mid-crawl): treat the same way; the caller detects the short read
        // by size and skips the record.
        if (body === null || !("body" in body) || body.body === null) return;
        const reader = body.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          yield value;
        }
      },
    };
  }

  async *crawl(selector: Selector): AsyncIterable<SourceRecord> {
    for await (const ev of this.crawlFrom(selector, null)) {
      if (ev.kind === "record") yield ev.record;
    }
  }

  async *crawlFrom(selector: Selector, token: string | null, meter?: Meter): AsyncIterable<CrawlEvent> {
    const prefix = selector.include.length === 1 ? selector.include[0] : undefined;
    let startAfter: string | undefined;
    if (token !== null) startAfter = parseToken(token).after;
    const ceiling = this.recordCeiling();
    let cursor: string | undefined;
    do {
      meter?.spend(1, "r2ClassA");
      // startAfter applies to the first page of a resume; subsequent pages ride the cursor.
      // The native R2 binding omits httpMetadata/customMetadata from list() results UNLESS asked, so request
      // them here: the streamed (large-object) path reads its descriptor from the list page and would
      // otherwise lose content-type and custom metadata on every object over the threshold. The pinned
      // workers-types R2ListOptions predates the include option (the runtime supports it), so the options are
      // typed through an intersection to carry it without a stale-types error.
      const listOpts: R2ListOptions & { include?: ("httpMetadata" | "customMetadata")[] } = {
        ...(prefix !== undefined ? { prefix } : {}),
        ...(cursor !== undefined ? { cursor } : startAfter !== undefined ? { startAfter } : {}),
        limit: 1000,
        include: ["httpMetadata", "customMetadata"],
      };
      const page = await this.r2.list(listOpts);
      for (const obj of page.objects) {
        if (!inScope(obj.key, selector)) continue;
        if (obj.size > ceiling) {
          // OVER-CEILING SINGLE OBJECT (the whole-run-wedge mitigation, mirrors sources/byte-fetch.ts
          // captureBlob). A single object past the applicable ceiling cannot be captured in band: even with
          // mid-record resume its prefix re-hash would exceed one slice's wall budget, and the chained seal
          // would otherwise THROW past MAX_SINGLE_RECORD_CONTENT_BYTES and terminal-fail the WHOLE run,
          // losing every other object. The declared size is known here from the cheap list page BEFORE any
          // value GET, so emit an honest incompleteness marker (a tiny buffered JSON value; the seal counts
          // it into recordsIncomplete, which the completion and notification surface) and CONTINUE the crawl
          // (the mark below still advances past it). No r2.get is issued for this object, so its bytes are
          // never fetched; recover it out of band with the downpipe CLI (no Worker limits).
          yield {
            kind: "record",
            record: {
              sourceType: "r2",
              name: obj.key,
              bucket: this.bucketName,
              value: utf8(JSON.stringify({ _skipped: `content (${obj.size} bytes) exceeds the ${ceiling}-byte single-invocation in-band capture limit; not captured, recover it out of band`, size: obj.size })),
              markerKind: "_skipped",
              markerReason: "size-cap", // G015: WHY this object is short -- the buffered-capture ceiling, not a fault
            },
          };
        } else if (obj.size > this.streamThreshold) {
          // The list() above is issued with include:[httpMetadata,customMetadata], so the list page
          // object carries the metadata for the streamed path and a large object's HTTP and custom
          // metadata are captured without an extra read. The open is etag-pinned (see the class note);
          // openRange lets the writer seal a multi-segment chain (SPEC 6.2, 14.5) over bounded windows for
          // objects past the single-segment ceiling. etag + openStreamedRange let the seal RESUME the
          // object mid-record across slices (it re-hashes the already-sealed prefix in one etag-pinned
          // ranged read), so a multi-GiB object up to the ceiling seals across as many slices as it needs
          // rather than having to complete in one.
          const descriptor = describeObject(obj);
          yield {
            kind: "record",
            record: {
              sourceType: "r2",
              name: obj.key,
              bucket: this.bucketName,
              stream: {
                size: obj.size,
                etag: obj.etag,
                open: () => this.streamObject(obj.key, obj.etag, meter),
                openRange: (offset: number, length: number) => this.streamObject(obj.key, obj.etag, meter, { offset, length }),
                // For R2 a ranged get is already ONE operation (the binding streams the body), so the
                // single-subrequest streamed read the prefix re-hash needs is openRange's one-window form.
                openStreamedRange: (offset: number, length: number) => this.streamObject(obj.key, obj.etag, meter, { offset, length }),
              },
              ...(descriptor ? { descriptor } : {}),
            },
          };
        } else {
          meter?.spend(1, "r2ClassB");
          const body = await this.r2.get(obj.key);
          if (body === null) {
            // Vanished mid-crawl (WS-P2): the object was listed but DELETED before its value could be read.
            // Seal an honest _vanished MARKER record (see kv.ts) so the archive records WHICH object raced the
            // crawl (counted into recordsIncomplete + incompleteByMarker._vanished + recordsVanished; skipped
            // on restore), rather than a silent skip. It falls through to the shared per-record mark below,
            // so the cursor advances past it and a resume skips the vanished key (no re-yield / double-count).
            yield { kind: "record", record: { sourceType: "r2", name: obj.key, bucket: this.bucketName, value: vanishedMarkerValue(), markerKind: "_vanished", markerReason: "changed-mid-crawl" } };
          } else {
            // The GET body carries the authoritative metadata for the buffered path.
            const descriptor = describeObject(body);
            yield { kind: "record", record: { sourceType: "r2", name: obj.key, value: new Uint8Array(await body.arrayBuffer()), bucket: this.bucketName, ...(descriptor ? { descriptor } : {}) } };
          }
        }
        // A per-record mark (R2 startAfter resumes exactly after this key), so a slice
        // can checkpoint after any record without re-reading it on resume.
        yield { kind: "mark", token: JSON.stringify({ after: obj.key } satisfies R2Token) };
      }
      const lastOfPage = page.objects.length > 0 ? page.objects[page.objects.length - 1]!.key : null;
      cursor = page.truncated ? page.cursor : undefined;
      if (cursor !== undefined && lastOfPage !== null) {
        yield { kind: "mark", token: JSON.stringify({ after: lastOfPage } satisfies R2Token) };
      }
    } while (cursor);
  }

  async estimate(selector: Selector): Promise<{ records: number; bytes: number }> {
    const prefix = selector.include.length === 1 ? selector.include[0] : undefined;
    let cursor: string | undefined;
    let records = 0;
    let bytes = 0;
    do {
      const page = await this.r2.list({ ...(prefix !== undefined ? { prefix } : {}), ...(cursor !== undefined ? { cursor } : {}), limit: 1000 });
      for (const obj of page.objects) {
        if (!inScope(obj.key, selector)) continue;
        records++;
        bytes += obj.size;
      }
      cursor = page.truncated ? page.cursor : undefined;
    } while (cursor);
    return { records, bytes };
  }
}
