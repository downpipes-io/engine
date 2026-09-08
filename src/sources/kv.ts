import { vanishedMarkerValue } from "../seal/marker.ts";
import { inScope } from "./selector.ts";
import { classifyLivenessFault, type LivenessProbe, SourceResourceMissingError } from "./source-errors.ts";
import { recordIncompleteFault, recordResumeFatal, recordResumeTokenDefect } from "./source-fault-ledger.ts";
import type { CrawlEvent, KeySampler, Meter, ResumableSource, Selector, SourceAdapter, SourceRecord } from "./types.ts";
import { hasAnyField } from "./types.ts";

// Workers KV adapter: crawl a namespace by listing keys (with optional prefix) and
// fetching each in-scope value. KV has no point-in-time snapshot, so this is a crawl
// over a live namespace; a key that vanishes mid-crawl is simply skipped (SPEC 12.5).
//
// Cost note (SPEC): a high-frequency full re-read of a large namespace is the headline
// bill-shock risk. estimate() reads only list metadata, never values, so a projection
// never itself costs a read per value.
//
// The resumable form (crawlFrom) is how a namespace larger than one invocation's
// subrequest budget is backed up at all: KV list pages are 1000 keys and every value get
// is a subrequest, so a crawl past roughly a thousand keys MUST span invocations. A mark
// is emitted after each fully-yielded page carrying the next-page cursor AND the page's
// last key: resume tries the cursor first, and if KV refuses it (cursors are opaque and
// not contractually long-lived) it falls back to re-listing from the start and skipping
// every key at or before the watermark, which costs list pages only, never value reads.
// KV list is lexicographically ordered, which is what makes the watermark sound.

interface KVToken {
  cursor?: string;
  after: string; // the last key of the last fully-yielded page
}

// KVPage is the list-result shape the crawl consumes: the platform type narrows cursor
// to the incomplete case via a union, which a resume-time probe handles dynamically.
interface KVPage {
  keys: { name: string; expiration?: number }[];
  list_complete: boolean;
  cursor?: string;
}

function parseToken(token: string): KVToken {
  // G213: record the CLOSED defect class so a token-corruption wedge is legible on the run row instead of
  // collapsing into the generic "run failed" bucket. Never the token bytes.
  let t: KVToken;
  try {
    t = JSON.parse(token) as KVToken;
  } catch {
    recordResumeTokenDefect("kv", "unparseable");
    recordResumeFatal("kv");
    throw new Error("malformed KV resume token (unparseable)");
  }
  if (typeof t !== "object" || t === null) {
    recordResumeTokenDefect("kv", "bad-shape");
    recordResumeFatal("kv");
    throw new Error("malformed KV resume token");
  }
  if (typeof t.after !== "string" || (t.cursor !== undefined && typeof t.cursor !== "string")) {
    recordResumeTokenDefect("kv", "bad-cursor");
    recordResumeFatal("kv");
    throw new Error("malformed KV resume token");
  }
  return t;
}

export class KVSource implements SourceAdapter, ResumableSource, LivenessProbe, KeySampler {
  readonly sourceType = "kv" as const;
  private kv: KVNamespace;
  private namespaceId: string;

  constructor(kv: KVNamespace, namespaceId: string) {
    this.kv = kv;
    this.namespaceId = namespaceId;
  }

  // probeLiveness (SRC-1) proves the bound namespace still EXISTS with one cheap metadata list (no value
  // read) before the crawl commits to it. A truthy binding pointing at a deleted namespace passes
  // preflight's presence check but throws a raw platform error on first use; this turns that into a named
  // SourceResourceMissingError so the run fails legibly ("source resource missing"), not generically.
  async probeLiveness(): Promise<void> {
    if (typeof this.kv.list !== "function") {
      throw new SourceResourceMissingError("kv", this.namespaceId, "misconfigured", "the bound object is not a KV namespace (no list())");
    }
    try {
      await this.kv.list({ limit: 1 });
    } catch (e) {
      throw classifyLivenessFault("kv", this.namespaceId, e);
    }
  }

  // readRecord fetches one in-scope key's value and metadata as a SourceRecord, or null
  // when the key vanished mid-crawl (SPEC 12.5).
  private async readRecord(k: { name: string; expiration?: number }, meter?: Meter): Promise<SourceRecord | null> {
    // getWithMetadata captures the value AND the per-key metadata in one read, so a restore
    // reconstructs the metadata, not just the bytes (SPEC 6.2). The live KVNamespace binding
    // always provides it; a minimal double may expose only get(), so fall back to a plain
    // read (degrading to no metadata, the pre-descriptor behaviour) rather than throwing.
    let v: ArrayBuffer | null;
    let metadata: unknown = null;
    meter?.spend(1, "kvRead");
    if (typeof this.kv.getWithMetadata === "function") {
      const r = await this.kv.getWithMetadata(k.name, "arrayBuffer");
      v = r.value;
      metadata = r.metadata;
    } else {
      // G042: this fallback silently DEGRADES the capture -- the key's metadata and TTL are simply not read, and
      // the archived record is byte-identical to a key that genuinely has neither. On restore the KV keys come
      // back with their metadata and expiry dropped, and nothing in the pack ever said the read was degraded.
      // Record the degraded sub-read as a closed "envelope-absent" fault against a product-token scope (the
      // NAMESPACE is not recorded: this is a binding-capability fault, not a per-key one, so one entry per crawl
      // is the honest signal and the per-kind count carries the magnitude).
      recordIncompleteFault("_unavailable", "envelope-absent", { id: "kv:metadata" });
      v = await this.kv.get(k.name, "arrayBuffer");
    }
    if (v === null) return null; // vanished mid-crawl
    const descriptor: SourceRecord["descriptor"] = {};
    // KV metadata is returned already parsed; carry it as parsed JSON so the writer
    // canonicalises it the same way the Go reader recomputes it. Only attach a non-null,
    // non-undefined object; KV returns null when a key has no metadata.
    if (metadata !== null && metadata !== undefined) descriptor.kvMetadata = metadata;
    // Expiration is an absolute Unix epoch second; absent means the key does not expire.
    if (typeof k.expiration === "number" && k.expiration > 0) descriptor.kvExpiration = k.expiration;
    return {
      sourceType: "kv",
      name: k.name,
      value: new Uint8Array(v),
      namespace: this.namespaceId,
      ...(hasAnyField(descriptor) ? { descriptor } : {}),
    };
  }

  async *crawl(selector: Selector): AsyncIterable<SourceRecord> {
    for await (const ev of this.crawlFrom(selector, null)) {
      if (ev.kind === "record") yield ev.record;
    }
  }

  // rangeBound (Fix 2b fan-out) cuts a listed page at the range's INCLUSIVE stopAt: it returns the keys
  // that are IN range (<= stopAt) and whether the page CROSSED the boundary (it contained a key > stopAt).
  // KV lists ascending, so the FIRST key past stopAt ends the range for good: yield the in-range prefix and
  // stop the crawl. A range with no stopAt (the last partition, or a serial run) never cuts.
  private rangeBound(keys: { name: string; expiration?: number }[], stopAt: string | undefined): { keys: { name: string; expiration?: number }[]; ended: boolean } {
    if (stopAt === undefined) return { keys, ended: false };
    const cut = keys.findIndex((k) => k.name > stopAt);
    if (cut < 0) return { keys, ended: false };
    return { keys: keys.slice(0, cut), ended: true };
  }

  // crawlFrom is the resumable crawl (see the header note). A null token starts from the
  // beginning; a token from a previous mark continues after that page. The watermark
  // fallback path re-lists from the start but skips whole pages by their last key, so an
  // expired cursor costs O(pages) list calls and zero value reads.
  async *crawlFrom(selector: Selector, token: string | null, meter?: Meter): AsyncIterable<CrawlEvent> {
    // Use the first include prefix to narrow the list call when there is exactly one,
    // otherwise list all and filter, so multi-prefix selectors still work.
    const listPrefix = selector.include.length === 1 ? selector.include[0] : undefined;
    let cursor: string | undefined;
    // Fix 2b: seed the start watermark from the range's EXCLUSIVE startAfter (skip keys <= startAfter),
    // reusing the existing watermark-skip machinery for free; a resume token's `after` (always within the
    // range) overrides it below. stopAt bounds the OTHER end (rangeBound). Absent range = the whole space.
    let skipThrough: string | null = selector.range?.startAfter ?? null; // keys <= this have already been yielded / are below the range
    const stopAt = selector.range?.stopAt;

    if (token !== null) {
      const t = parseToken(token);
      skipThrough = t.after;
      if (t.cursor !== undefined) {
        // Try the saved cursor first. KV cursors are opaque; if the platform refuses it,
        // fall back to the watermark scan rather than failing the run. Only the probe list
        // call is inside the try: a fault while reading a value is a real read fault and
        // must propagate, not silently restart the listing.
        let probe: KVPage | null = null;
        try {
          meter?.spend(1, "kvList");
          probe = (await this.kv.list({ ...(listPrefix !== undefined ? { prefix: listPrefix } : {}), cursor: t.cursor })) as unknown as KVPage;
        } catch {
          probe = null; // cursor refused: watermark scan from the start
        }
        if (probe !== null) {
          const { keys: inRange, ended } = this.rangeBound(probe.keys, stopAt);
          yield* this.yieldPage(inRange, selector, skipThrough, t.cursor, meter);
          if (ended) return; // the range's stopAt boundary fell inside the resumed page: range complete
          const lastKey = probe.keys.length > 0 ? probe.keys[probe.keys.length - 1]!.name : skipThrough;
          if (probe.list_complete) return;
          yield { kind: "mark", token: JSON.stringify({ ...(probe.cursor !== undefined ? { cursor: probe.cursor } : {}), after: lastKey } satisfies KVToken) };
          cursor = probe.cursor;
          skipThrough = null; // past the watermark; normal paging from here
        }
      }
    }

    do {
      const pageInCursor = cursor; // the cursor that fetches THIS page (per-record marks resume by re-listing it)
      meter?.spend(1, "kvList");
      const page = await this.kv.list({ ...(listPrefix !== undefined ? { prefix: listPrefix } : {}), ...(cursor !== undefined ? { cursor } : {}) });
      const lastOfPage = page.keys.length > 0 ? page.keys[page.keys.length - 1]!.name : null;
      // Watermark fast-forward: a page whose last key is at or before the watermark was
      // fully yielded before the resume; skip it without reading any value.
      if (skipThrough !== null && lastOfPage !== null && lastOfPage <= skipThrough) {
        cursor = page.list_complete ? undefined : page.cursor;
        continue;
      }
      const { keys: inRange, ended } = this.rangeBound(page.keys, stopAt);
      yield* this.yieldPage(inRange, selector, skipThrough, pageInCursor, meter);
      if (skipThrough !== null && lastOfPage !== null && lastOfPage > skipThrough) skipThrough = null;
      if (ended) return; // Fix 2b: the first key past the range's stopAt ends the crawl (no further mark/page)
      cursor = page.list_complete ? undefined : page.cursor;
      if (cursor !== undefined && lastOfPage !== null) {
        yield { kind: "mark", token: JSON.stringify({ cursor, after: lastOfPage } satisfies KVToken) };
      }
    } while (cursor);
  }

  // yieldPage yields each in-scope key's record FOLLOWED by a mark naming it, so a slice
  // can checkpoint after any record: the mark's cursor re-lists the page the record came
  // from and its watermark skips everything at or before it. A record costing one value
  // read therefore never needs to be re-read on resume, whichever record a slice ends at.
  private async *yieldPage(keys: { name: string; expiration?: number }[], selector: Selector, skipThrough: string | null, pageInCursor: string | undefined, meter?: Meter): AsyncIterable<CrawlEvent> {
    for (const k of keys) {
      if (skipThrough !== null && k.name <= skipThrough) continue; // already yielded before the resume
      if (!inScope(k.name, selector)) continue;
      const rec = await this.readRecord(k, meter);
      if (rec === null) {
        // Vanished mid-crawl (WS-P2, SPEC 12.5): the key was listed but DELETED before its value could be
        // read. Seal an honest _vanished MARKER record (a tiny buffered sentinel) so the archive records
        // WHICH object raced the crawl, not just a count; the seal counts it (recordsIncomplete +
        // incompleteByMarker._vanished + recordsVanished) and the RESTORE side skips it (never writes the
        // marker JSON back as the deleted key's value). It rides the SAME trailing mark as a real record, so
        // the cursor advances past it and a resume skips the vanished key (no re-yield, no double-seal/count).
        yield { kind: "record", record: { sourceType: "kv", name: k.name, namespace: this.namespaceId, value: vanishedMarkerValue(), markerKind: "_vanished", markerReason: "changed-mid-crawl" } };
      } else {
        yield { kind: "record", record: rec };
      }
      yield { kind: "mark", token: JSON.stringify({ ...(pageInCursor !== undefined ? { cursor: pageInCursor } : {}), after: k.name } satisfies KVToken) };
    }
  }

  async estimate(selector: Selector): Promise<{ records: number; bytes: number }> {
    const listPrefix = selector.include.length === 1 ? selector.include[0] : undefined;
    // Fix 2b: honour the range bound so a per-range estimate sizes only that partition (the fan-out
    // planner uses the full-keyspace estimate to decide N, then this to sanity-check per-range balance).
    const startAfter = selector.range?.startAfter;
    const stopAt = selector.range?.stopAt;
    let cursor: string | undefined;
    let records = 0;
    do {
      const page = await this.kv.list({ ...(listPrefix !== undefined ? { prefix: listPrefix } : {}), ...(cursor !== undefined ? { cursor } : {}) });
      for (const k of page.keys) {
        if (startAfter !== undefined && k.name <= startAfter) continue; // below the range (exclusive)
        if (stopAt !== undefined && k.name > stopAt) continue; // above the range (inclusive)
        if (inScope(k.name, selector)) records++;
      }
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
    // KV list does not return value sizes, so bytes is unknown from metadata alone.
    return { records, bytes: -1 };
  }

  // sampleKeys (Fix 2b fan-out) lists in-scope keys -- metadata only, NEVER a value read -- up to `cap`, in
  // ascending order (KV list is lexicographic), and reports whether MORE keys exist beyond the cap. The
  // fan-out planner partitions this sample into N ranges. Listing is bounded by the cap, so a huge namespace
  // is not fully materialised; the trade-off is that for a namespace larger than the cap the sampled keys
  // are the FRONT of the keyspace, so the splits skew to the front (the documented skew-defer -- a future
  // even-stride or byte-space split removes it). It honours the selector range too, for a per-range re-plan.
  async sampleKeys(selector: Selector, cap: number): Promise<{ keys: string[]; more: boolean }> {
    const listPrefix = selector.include.length === 1 ? selector.include[0] : undefined;
    const startAfter = selector.range?.startAfter;
    const stopAt = selector.range?.stopAt;
    const keys: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await this.kv.list({ ...(listPrefix !== undefined ? { prefix: listPrefix } : {}), ...(cursor !== undefined ? { cursor } : {}) });
      for (const k of page.keys) {
        if (startAfter !== undefined && k.name <= startAfter) continue;
        if (stopAt !== undefined && k.name > stopAt) continue;
        if (!inScope(k.name, selector)) continue;
        if (keys.length >= cap) return { keys, more: true }; // hit the cap with more to come
        keys.push(k.name);
      }
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
    return { keys, more: false };
  }

  // inScopeNames filters one listed page to the in-scope key NAMES the planning scan counts/strides:
  // skip keys at or before the resume watermark (already seen) and keys outside the selector's include/
  // exclude. It reads no value; the planning scan is metadata only.
  private inScopeNames(keys: { name: string; expiration?: number }[], selector: Selector, skipThrough: string | null): string[] {
    const out: string[] = [];
    for (const k of keys) {
      if (skipThrough !== null && k.name <= skipThrough) continue; // already yielded before the resume
      if (!inScope(k.name, selector)) continue;
      out.push(k.name);
    }
    return out;
  }

  // listKeysFrom (Fix 2b H2) is the SLICED, keys-only planning scan (see the KeySampler doc): it yields one
  // event per fully-listed page -- the page's in-scope key NAMES, an opaque resume token, and a `last` flag
  // -- reading NO values, so the fan-out coordinator can COUNT then STRIDE a huge namespace across many
  // invocations to size BALANCED ranges. It mirrors crawlFrom's resume exactly: a null token starts from the
  // beginning (or the range's startAfter); a token tries its saved cursor first and, if KV refuses the
  // opaque cursor, falls back to re-listing from the start and skipping whole pages by the `after` watermark
  // (list pages only, never a value read). stopAt ends the scan at the first key past the range bound.
  async *listKeysFrom(selector: Selector, token: string | null, meter?: Meter): AsyncIterable<{ keys: string[]; token: string; last: boolean }> {
    const listPrefix = selector.include.length === 1 ? selector.include[0] : undefined;
    let skipThrough: string | null = selector.range?.startAfter ?? null; // keys <= this are below the range / already seen
    const stopAt = selector.range?.stopAt;
    let cursor: string | undefined;

    if (token !== null) {
      const t = parseToken(token);
      skipThrough = t.after;
      if (t.cursor !== undefined) {
        let probe: KVPage | null = null;
        try {
          meter?.spend(1, "kvList");
          probe = (await this.kv.list({ ...(listPrefix !== undefined ? { prefix: listPrefix } : {}), cursor: t.cursor })) as unknown as KVPage;
        } catch {
          probe = null; // cursor refused: fall through to the watermark scan from the start
        }
        if (probe !== null) {
          const { keys: inRange, ended } = this.rangeBound(probe.keys, stopAt);
          const lastKey = probe.keys.length > 0 ? probe.keys[probe.keys.length - 1]!.name : t.after;
          const done = ended || probe.list_complete;
          cursor = done ? undefined : probe.cursor;
          yield { keys: this.inScopeNames(inRange, selector, skipThrough), token: JSON.stringify({ ...(cursor !== undefined ? { cursor } : {}), after: lastKey } satisfies KVToken), last: cursor === undefined };
          if (cursor === undefined) return; // range bound hit or list complete inside the resumed page
          skipThrough = null; // past the watermark; normal paging from here
        }
      }
    }

    do {
      meter?.spend(1, "kvList");
      const page = (await this.kv.list({ ...(listPrefix !== undefined ? { prefix: listPrefix } : {}), ...(cursor !== undefined ? { cursor } : {}) })) as unknown as KVPage;
      const lastOfPage = page.keys.length > 0 ? page.keys[page.keys.length - 1]!.name : null;
      // Watermark fast-forward: a page fully at or before the watermark was already scanned before the
      // resume; skip it without emitting an event (a cursor-refused resume costs list pages only).
      if (skipThrough !== null && lastOfPage !== null && lastOfPage <= skipThrough) {
        cursor = page.list_complete ? undefined : page.cursor;
        continue;
      }
      const { keys: inRange, ended } = this.rangeBound(page.keys, stopAt);
      const names = this.inScopeNames(inRange, selector, skipThrough);
      if (skipThrough !== null && lastOfPage !== null && lastOfPage > skipThrough) skipThrough = null;
      const done = ended || page.list_complete;
      cursor = done ? undefined : page.cursor;
      yield { keys: names, token: JSON.stringify({ ...(cursor !== undefined ? { cursor } : {}), after: lastOfPage ?? "" } satisfies KVToken), last: cursor === undefined };
      if (cursor === undefined) return; // the stopAt bound or list-complete ends the scan
    } while (cursor);
  }
}
