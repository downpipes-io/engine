// Cloudflare configuration source: snapshots a zone's (and the account's) configuration
// surfaces, DNS, zone settings, rulesets/WAF, page rules, Access, load balancers, etc., as
// small canonical-JSON records through the unchanged seal pipeline. Unlike every other source
// (which reads a Workers binding), this one reads the Cloudflare REST API with a customer
// read-only API token (the engine's discovery token, broadened to "Read all resources").
//
// One archived record per surface: name = surface id, value = the surface's config as JSON.
// The selector scopes WHICH surfaces a downpipe covers (by surface-id prefix), not the items
// within a surface. A zone-scoped surface is skipped when no zoneId is configured (an
// account-only downpipe); account-scoped surfaces always apply.
//
// Restore is tiered and lives in the restore sink; the backup is read-only and never holds an
// edit token. See cf-config-surfaces.ts for the surface registry and the restore tiers.

import type { CfPacer } from "../cf-pace.ts";
import { log } from "../log.ts";
import type { MarkerKey } from "../seal/marker.ts";
import { CF_CONFIG_IDENTITY_ID, CF_CONFIG_SURFACES, type CfApi, CfApiError, type CfConfigSurface, CfPaginationTruncated, makeCfApi, surfaceSelected } from "./cf-config-surfaces.ts";
import {
  classifySourceFaultReason,
  classifySourceFaultStatus,
  faultItemId,
  paginationMagnitude,
  recordIncompleteFault,
  recordResumeTokenDefect,
  recordSourceFatal,
  type SourceFaultReason,
} from "./source-fault-ledger.ts";
import type { CrawlEvent, Meter, ResumableSource, Selector, SourceAdapter, SourceRecord } from "./types.ts";

// A single surface's serialised JSON must fit in memory (it is buffered, like the D1 export). The
// READ is now fully paginated (every page accumulated; see paginate() in cf-config-surfaces.ts), so
// this cap guards the buffered SIZE, not page count: 64 MiB is far above any realistic zone/account
// config; a surface whose accumulated JSON exceeds it errors loudly (marked _unavailable) rather
// than risk exhausting the Worker, with streaming the buffered output to the dest a deferred refinement.
export const CF_CONFIG_SURFACE_SIZE_LIMIT = 64 * 1024 * 1024;

// CfConfigToken is the resume cursor: the id of the last surface whose record was yielded. A resume
// re-iterates the (stable, registry-ordered) surface list and skips through to AFTER that surface, so no
// surface is re-read. Per-surface granularity (a mark after each surface) is the checkpoint unit; a single
// surface's internal pagination is bounded by the page cap + the size limit.
interface CfConfigToken {
  after: string;
}

// parseCfConfigToken classifies a corrupt cf-config resume token into the CLOSED defect vocabulary (G213)
// instead of letting a raw JSON.parse SyntaxError escape unclassified. The token bytes never leave this site.
function parseCfConfigToken(token: string): CfConfigToken {
  let t: CfConfigToken;
  try {
    t = JSON.parse(token) as CfConfigToken;
  } catch {
    recordResumeTokenDefect("cf-config", "unparseable");
    throw new Error("malformed cf-config resume token (unparseable)");
  }
  if (typeof t !== "object" || t === null || typeof t.after !== "string") {
    recordResumeTokenDefect("cf-config", "bad-shape");
    throw new Error("malformed cf-config resume token");
  }
  return t;
}

// NOT_ATTEMPTED_MARKER_REASON is the FIXED reason a not-attempted "_unavailable" marker carries (G234). It
// is deliberately a constant rather than a per-surface message: the run never issued the read, so it has no
// Cloudflare error of its own, and inventing one from the stale discovery classification would assert
// something this run did not measure. The status class the probe DID measure lives on the discovery row
// (cfConfigDiscovery.unavailableByClass), which the support pack already carries.
export const NOT_ATTEMPTED_MARKER_REASON =
  "not attempted by this run: a prior configuration discovery could not read this surface, and auto capture mode reads only the surfaces discovery found in use. This surface is missing from the snapshot because it could not be read, not because the account has nothing here.";

// notAttemptedMarkerValue builds the marker value for a surface auto mode left unread. The "_unavailable"
// key is the SAME sentinel a refused read produces, so every existing consumer already handles it:
// decodeConfigSnapshot refuses to diff it, the restore plan lists it out of band by surface name, and the
// seal counts it. The extra "notAttempted" flag is what lets a reader YEARS LATER tell the two apart from
// the archive alone, without the run record, which is not in the archive.
function notAttemptedMarkerValue(): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ _unavailable: NOT_ATTEMPTED_MARKER_REASON, notAttempted: true }));
}

export class CloudflareConfigSource implements SourceAdapter, ResumableSource {
  readonly sourceType = "cf-config" as const;
  private token: string;
  readonly accountId: string;
  private zoneId: string | undefined;
  private surfaces: CfConfigSurface[];
  private fetchImpl: typeof fetch;
  private sizeLimit: number;
  private pacer: CfPacer | undefined;

  // surfaces, fetchImpl and sizeLimit are injectable for the validator (a stubbed registry + fetch,
  // a tiny limit to exercise the size guard); do not pass them in production code. pacer is the optional
  // account-API token-bucket throttle (buildAdapter supplies it from env); absent in tests.
  constructor(
    token: string,
    accountId: string,
    zoneId?: string,
    surfaces: CfConfigSurface[] = CF_CONFIG_SURFACES,
    fetchImpl: typeof fetch = fetch,
    sizeLimit: number = CF_CONFIG_SURFACE_SIZE_LIMIT,
    pacer?: CfPacer,
  ) {
    this.token = token;
    this.accountId = accountId;
    this.zoneId = zoneId;
    this.surfaces = surfaces;
    this.fetchImpl = fetchImpl;
    this.sizeLimit = sizeLimit;
    this.pacer = pacer;
  }

  // applicable filters the registry to the surfaces this source can read: account-scoped always,
  // zone-scoped only when a zone is configured.
  private applicable(): CfConfigSurface[] {
    return this.surfaces.filter((s) => s.scope === "account" || this.zoneId !== undefined);
  }

  async *crawl(selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    for await (const ev of this.crawlFrom(selector, null, meter)) {
      if (ev.kind === "record") yield ev.record;
    }
  }

  // crawlFrom is the RESUMABLE crawl: it walks the applicable surfaces in the registry's STABLE order from
  // the resume watermark, yields one record per surface, and emits a {mark} AFTER each so a slice can
  // checkpoint between surfaces and resume without re-reading any surface. This lets a crowded config crawl
  // (the full surface registry, some heavily paginated) span invocations instead of running whole in one and dying on the
  // subrequest cap. The fail-open-per-surface and all-unavailable semantics are unchanged from crawl().
  async *crawlFrom(selector: Selector, token: string | null, meter?: Meter): AsyncIterable<CrawlEvent> {
    const api = makeCfApi(this.token, this.fetchImpl, this.pacer);
    const ids = this.zoneId !== undefined ? { accountId: this.accountId, zoneId: this.zoneId } : { accountId: this.accountId };
    // G213: this was a BARE JSON.parse. A corrupt checkpoint threw a raw SyntaxError that matched no coarse
    // error branch, so a wedged cf-config downpipe read as a plain "run failed" and support had no way to see
    // that the run was stuck on resume-state corruption (remedy: clear the resume token). Classify it.
    const after = token !== null ? parseCfConfigToken(token).after : null;
    const applicable = this.applicable();
    // SELF-IDENTIFYING RECORD: a from-scratch crawl emits the identity record FIRST (which account/zone this
    // backup is for), then marks after it, so a slice can resume past it. It is reserved (not a surface), so
    // it is excluded from the surface loop, the watermark validation and the all-failed guard below.
    if (after === null) {
      yield { kind: "record", record: { sourceType: "cf-config", name: CF_CONFIG_IDENTITY_ID, value: await this.buildIdentityValue(api) } };
      yield { kind: "mark", token: JSON.stringify({ after: CF_CONFIG_IDENTITY_ID } satisfies CfConfigToken) };
    }
    // FAIL LOUD on a stale resume watermark: if the resume token names a surface id that is no longer
    // in the (applicable) registry (a removed/renamed surface, or a token from a different scope), the
    // skip-through loop below would never clear `skipping`, the crawl would yield nothing, and the run
    // would report a "successful" snapshot that captured zero surfaces. Detect that here and throw a
    // clear error instead of returning an empty crawl. (engine-src-048-03). The identity watermark is a
    // valid resume point (it precedes the first surface), so it is exempt from this check.
    if (after !== null && after !== CF_CONFIG_IDENTITY_ID && !applicable.some((s) => s.id === after)) {
      throw new Error(
        `cf-config resume watermark "${after}" is not a known surface id in the current registry; the surface was likely removed or renamed, or the resume token is from a different scope. Re-run the crawl from scratch (clear the resume token).`,
      );
    }
    // Resuming from the identity watermark means "start at the first surface": nothing to skip through.
    let skipping = after !== null && after !== CF_CONFIG_IDENTITY_ID; // skip through to AFTER the watermark surface (already yielded)
    let attempted = 0;
    let succeeded = 0;
    // lastFault holds the most recent per-surface throw so the ALL-FAILED guard below can classify the run-
    // fatal fault (G144) from a real error rather than inventing one: every surface failing is nearly always
    // ONE cause (an expired token, a lost scope, a Cloudflare outage), and its status class is what tells the
    // operator which lever to pull. Only the closed class is ever recorded, never the error itself.
    let lastFault: unknown;
    // notAttempted (G234): the surfaces the CALLER left out of the include set because a cached probe could
    // not read them. They are not read here (that is the whole point of the cost narrowing), but each one
    // still gets an "_unavailable" marker record below, so the archive is self-describing and the seal's
    // recordsIncomplete / incompleteByMarker / incompleteIds count and NAME them on the run row.
    const notAttempted = new Set(selector.notAttempted ?? []);
    for (const surface of applicable) {
      if (skipping) {
        if (surface.id === after) skipping = false; // found the watermark; resume after it
        continue;
      }
      if (!surfaceSelected(surface.id, selector.include, selector.exclude)) {
        // A surface merely OUT OF SCOPE (an operator's tick-box, or a discovery "empty"/"gated" partition
        // that is evidence the account has nothing there) is skipped silently, as it always has been.
        // A surface the caller named in notAttempted is skipped LOUDLY: it is absent from this archive
        // because we could not read it, not because there was nothing to read.
        if (!notAttempted.has(surface.id)) continue;
        recordIncompleteFault("_unavailable", "not-attempted", { id: await faultItemId(surface.id) });
        yield {
          kind: "record",
          record: { sourceType: "cf-config", name: surface.id, value: notAttemptedMarkerValue(), markerKind: "_unavailable", markerReason: "not-attempted" },
        };
        // Mark AFTER it exactly as for a read surface, so the resume watermark stays the registry order.
        yield { kind: "mark", token: JSON.stringify({ after: surface.id } satisfies CfConfigToken) };
        continue;
      }
      attempted++;
      let read: { value: Uint8Array; ok: boolean; markerKind?: MarkerKey; markerReason?: SourceFaultReason };
      try {
        read = { value: await this.readSurfaceValue(surface, api, ids, meter), ok: true };
      } catch (e) {
        read = this.surfaceErrorValue(surface, e);
        lastFault = e;
        // G015: record WHY this surface is short, into the closed reason vocabulary, at the exact site that
        // decides to substitute a marker. The surface id is a CLOSED-registry product token (the existing
        // incompleteIds precedent), so it is carried raw and clamped; the raw CF message stays archive-sealed.
        // For a page-cap truncation also carry the shortfall MAGNITUDE (pages read / records accumulated), so
        // "is our config surface fully backed up?" is answerable from the pack alone.
        const mag = paginationMagnitude(e);
        recordIncompleteFault(read.markerKind ?? "_unavailable", read.markerReason ?? "other", {
          id: await faultItemId(surface.id),
          ...(mag !== undefined ? { pagesRead: mag.pagesRead, recordsAccumulated: mag.recordsAccumulated } : {}),
        });
      }
      if (read.ok) succeeded++;
      yield {
        kind: "record",
        record: {
          sourceType: "cf-config",
          name: surface.id,
          value: read.value,
          ...(read.markerKind !== undefined ? { markerKind: read.markerKind } : {}),
          ...(read.markerReason !== undefined ? { markerReason: read.markerReason } : {}),
        },
      };
      // Mark AFTER the surface: a slice may end here and resume after this surface id.
      yield { kind: "mark", token: JSON.stringify({ after: surface.id } satisfies CfConfigToken) };
    }
    // If this is a FROM-SCRATCH crawl (no resume) where EVERY attempted surface failed, it is not a
    // per-surface gap but a broken/expired token, a missing read scope, or the wrong account: fail loudly
    // so a run can NEVER report a "successful" snapshot that captured nothing real. A RESUME pass (after !==
    // null) covers a subset and skips this guard.
    if (after === null && attempted > 0 && succeeded === 0) {
      // G144: the run row would otherwise carry ONE coarse "run failed" class with no status and no stage, so
      // an expired token (401), a lost read scope (403), an account-plan gate and a Cloudflare outage (5xx) all
      // read identically to support. Record the closed status class + stage + the attempted/succeeded magnitude
      // BEFORE throwing. Never the CF message, path or numeric code list.
      recordSourceFatal({ sourceType: "cf-config", statusClass: classifySourceFaultStatus(lastFault), stage: "item-read", attempted, succeeded });
      throw new Error(
        'every Cloudflare config surface failed to read; the token likely lacks config read scope or is invalid, set a read-only "Read all resources" discovery token',
      );
    }
  }

  // buildIdentityValue serialises the self-identifying record ({ v, accountId, zoneId?, zoneName? }) every
  // crawl emits first, so the archive records WHICH account/zone it is a backup of (the downpipe name lives
  // only in config, never the backup). The human-readable zoneName is read from GET /zones/<id> FAIL-OPEN: a
  // failed/absent name never fails the crawl (the zoneId alone is unambiguous), it is simply omitted. Never
  // carries a token or any credential.
  private async buildIdentityValue(api: CfApi): Promise<Uint8Array> {
    let zoneName: string | undefined;
    if (this.zoneId !== undefined) {
      try {
        const zone = (await api.get(`/zones/${this.zoneId}`)) as { name?: unknown } | null;
        if (zone !== null && typeof zone.name === "string" && zone.name.length > 0) zoneName = zone.name;
      } catch {
        // fail-open: the zoneId already identifies the zone unambiguously; a human name is a bonus.
      }
    }
    const identity = {
      v: 1,
      accountId: this.accountId,
      ...(this.zoneId !== undefined ? { zoneId: this.zoneId } : {}),
      ...(zoneName !== undefined ? { zoneName } : {}),
    };
    return new TextEncoder().encode(JSON.stringify(identity));
  }

  // readSurfaceValue reads ONE surface and returns its serialised canonical JSON, throwing if the
  // accumulated JSON exceeds the buffered size limit (the caller turns the throw into an _unavailable
  // marker). Extracted from crawlFrom so the per-surface read is a single testable unit.
  private async readSurfaceValue(surface: CfConfigSurface, api: CfApi, ids: { accountId: string; zoneId?: string }, meter?: Meter): Promise<Uint8Array> {
    const data = await surface.read(api, ids, meter);
    const value = new TextEncoder().encode(JSON.stringify(data ?? null));
    if (value.byteLength > this.sizeLimit) {
      throw new Error(`serialised JSON exceeds the ${this.sizeLimit}-byte limit; paginated streaming of this surface is deferred`);
    }
    return value;
  }

  // surfaceErrorValue turns a per-surface read failure into the record value to emit. A pagination
  // truncation IS a successful partial read (ok: true) marked _truncated; any other failure is a
  // fail-open _unavailable marker (ok: false) so the snapshot stays complete and one surface's gap
  // never fails the whole config crawl. markerKind (CR-04) is the adapter's own assertion that this
  // value IS one of the two sentinels below, never left for the seal/restore paths to guess from shape.
  // markerReason (G015) rides beside markerKind: the CLOSED reason class the seal folds into the run row's
  // per-kind reason breakdown, so the pack says WHY a surface is short without ever carrying the CF error text.
  private surfaceErrorValue(surface: CfConfigSurface, e: unknown): { value: Uint8Array; ok: boolean; markerKind: MarkerKey; markerReason: SourceFaultReason } {
    if (e instanceof CfPaginationTruncated) {
      // A list surface that exceeded the pagination max-pages guard (SRC-4) is NOT "unavailable",
      // we DID read records, we just stopped before the tail. Record it as an explicit "_truncated"
      // marker (carrying how many pages/records we did read) and LOG it, so a truncation is always
      // visible and never silent, and so it reads differently from a surface we could not read at all.
      log("error", `cf-config surface ${surface.id} truncated: read ${e.pagesRead} pages (${e.accumulated} records) without exhausting the list; increase the page cap or narrow the surface`);
      return { value: new TextEncoder().encode(JSON.stringify({ _truncated: e.message, pagesRead: e.pagesRead, recordsRead: e.accumulated })), ok: true, markerKind: "_truncated", markerReason: "page-cap" };
    }
    // Fail-open PER SURFACE: an unavailable surface (a DEPRECATED endpoint like Page Rules, a scope the
    // token lacks like Logpush, a too-large surface, or a transient fault that survived retry) is
    // recorded as an explicit "_unavailable" marker rather than failing the WHOLE config snapshot.
    const reason = (e as Error).message.replace(/^Cloudflare API GET [^:]+:\s*/, "").slice(0, 200);
    // A DEFINITIVE plan-entitlement gate reads identically to a token-scope gap in the marker's OWN
    // JSON today: both are {_unavailable: reason}, and the only place the two are told apart is the
    // out-of-band markerReason (below), a run-row aggregate that never rides in the archive. That is
    // fine on the CACHED-discovery path (a gated surface is silently skipped there, never crawled at
    // all), but this is the DIRECT-ATTEMPT path -- a first run before discovery, or a stale-fallback
    // run -- where a genuinely plan-gated surface is attempted for real and lands here. Stamp the same
    // verdict CfApiError already computed (isCfPlanEntitlementError, cf-config-core.ts) onto the
    // record's own value, so a reader of the archive itself (the downpipe reader, a restore, a future
    // per-surface view) can tell "your plan does not carry this" from "we could not read this, check
    // your token scope" without the run row. Additive: the {_unavailable} shape is unchanged, and
    // nothing today reads `planGated`, so an entitlement-gated marker still decodes exactly as before
    // everywhere except the one place that now asks the question.
    const planGated = e instanceof CfApiError && e.planEntitlementGated;
    return {
      value: new TextEncoder().encode(JSON.stringify({ _unavailable: reason, ...(planGated ? { planGated: true } : {}) })),
      ok: false,
      markerKind: "_unavailable",
      markerReason: classifySourceFaultReason(e),
    };
  }

  async estimate(selector: Selector): Promise<{ records: number; bytes: number }> {
    // One record per in-scope surface, PLUS the self-identifying record every crawl emits first (counted so
    // the projection matches what a completed run actually reports). Sizes are unknown without reading (the
    // cost projection reports the record count, never reads a surface to size it).
    // G234: a notAttempted surface yields a marker RECORD too, so it counts here for the same reason -- the
    // projection has to match the run, and the markers are the run's honest account of what it missed.
    const notAttempted = new Set(selector.notAttempted ?? []);
    const records = this.applicable().filter(
      (s) => surfaceSelected(s.id, selector.include, selector.exclude) || notAttempted.has(s.id),
    ).length;
    return { records: records + 1, bytes: -1 };
  }
}
