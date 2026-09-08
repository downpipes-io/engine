// A source adapter reduces a live Cloudflare resource to an ordered stream of records
// the seal pipeline turns into an archive. Each adapter only reads and yields; it never
// seals, never holds a key, and for secrets never logs or persists plaintext.

import type { StreamingValue } from "../crypto/streamseal.ts";
import type { Meter } from "../meter.ts";
import type { MarkerKey } from "../seal/marker.ts";
import type { SourceFaultReason } from "./source-fault-ledger.ts";

// A RestoreDescriptor carries the per-source configuration a restore reconstructs BEYOND the
// value bytes (SPEC 6.2, 12.3): KV metadata and expiration, R2 HTTP and custom metadata, a
// secret's wiring, a D1 dump's body format. Without it an archive is silently value-only: a
// KV record would come back with its metadata and TTL dropped, an R2 object with its content
// type lost. Each field is optional; the writer emits a descriptor only when it has at least
// one non-empty field, and emits each field only when non-empty, so a record with nothing to
// describe adds nothing to the manifest (the omitempty contract the Go reader mirrors).
//
// The opaque metadata objects (kvMetadata, r2HttpMetadata, r2CustomMetadata) are held as the
// PARSED JSON value, not raw bytes, so the writer routes them through the same canonical-JSON
// path as the rest of the manifest and the Go reader recomputes byte-identical signed bytes.
export interface RestoreDescriptor {
  // KV: the metadata returned by getWithMetadata (already-parsed JSON), and the absolute
  // expiration as a Unix epoch second (0/absent means no expiry).
  kvMetadata?: unknown;
  kvExpiration?: number;
  // R2: the object's HTTP metadata as a plain JSON object (a Date such as cacheExpiry is
  // normalised to its ISO string on capture so it canonicalises, and back to a Date on apply),
  // and its custom metadata (a string map).
  r2HttpMetadata?: Record<string, string>;
  r2CustomMetadata?: Record<string, string>;
  // Secrets: the wiring a restore needs (the value itself is never here). The store, the
  // scope, an optional comment, and for a per-Worker secret the Worker and the binding var.
  secretsStore?: string;
  secretsScope?: string;
  secretsComment?: string;
  secretsWorker?: string;
  secretsBindingVar?: string;
  // D1: how the dump body was produced, so a restore can refuse a shape it cannot replay.
  d1Format?: string;
}

// hasAnyField reports whether a descriptor carries at least one defined field, so a source
// attaches a descriptor to a record only when there is something to describe. This is the
// engine half of the omitempty contract: a record with nothing to describe carries no
// descriptor, so the manifest line is byte-identical to one written before descriptors
// existed (the backward-compatibility guarantee the Go reader's omitempty mirrors).
export function hasAnyField(d: RestoreDescriptor): boolean {
  for (const k of Object.keys(d) as (keyof RestoreDescriptor)[]) {
    if (d[k] !== undefined) return true;
  }
  return false;
}

export interface SourceRecord {
  // "durable_object" is DECLARED but NOT yet live: it lets DurableObjectSource (a compile-only
  // stub, src/sources/durable-object.ts) typecheck against this interface. It is deliberately
  // absent from the config-validate allow-list and buildAdapter, so no run can select it; until
  // an in-tenant export shim is wired, its crawl throws rather than producing an empty backup.
  sourceType: "kv" | "r2" | "secrets" | "d1" | "cf-config" | "workers" | "stream" | "images" | "artifacts" | "durable_object";
  name: string; // the source-native name (KV key, R2 object key, secret name)
  value?: Uint8Array; // the buffered plaintext (small records)
  stream?: StreamingValue; // a re-openable large value (a big R2 object), streamed to the dest
  namespace?: string;
  bucket?: string;
  database?: string; // for d1: the native database UUID (self-identifying; the record NAME carries only the binding name)
  account?: string; // for the API sources (workers/stream/images/artifacts): the Cloudflare account this backup is OF
  descriptor?: RestoreDescriptor; // the full-fidelity restore metadata (SPEC 6.2, 12.3)
  // markerKind (CR-04): set by the adapter itself, ONLY at the exact call site that builds a synthetic
  // incompleteness sentinel in place of real bytes (never inferred elsewhere). This is an assertion of fact
  // ("I just emitted a marker, and here is which kind"), not a guess from the value's shape: a real customer
  // value can legitimately contain JSON that LOOKS like a marker (e.g. `{"_pending":false,"orderId":42}`),
  // and without this field the seal/restore paths had no way to tell the two apart other than sniffing the
  // bytes -- which a real value can collide with. The seal (slice.ts/pipeline.ts) stamps meta.incompleteMarker
  // from THIS field, and restore (restore-apply.ts/restore-plan.ts) gates the write-skip on the resulting
  // signed manifest field, so a lookalike real value with no adapter-asserted markerKind is never misclassified.
  markerKind?: MarkerKey;
  // markerReason (support-pack gap G015): the CLOSED reason class for the marker this record carries, set by
  // the adapter at the SAME call site that sets markerKind. markerKind says WHICH KIND of shortfall this is
  // ("_unavailable"); markerReason says WHY ("auth" / "entitlement" / "page-cap" / "size-cap" / "shape" /
  // "render-pending" / ...). Before this field the WHY existed ONLY inside the sentinel's JSON payload, which
  // is end-to-end encrypted at the customer's own destination (NO-CUSTODY) and therefore unreadable to
  // support: a pack could prove "surface X was _unavailable in every run" and never say whether that was a
  // 403 scope gap, a 5xx outage, a size ceiling or a page cap. The seal aggregates it exactly as it
  // aggregates markerKind into incompleteByMarker (one per-kind reason->count map), so the run row gains a
  // reason breakdown while the raw error text, URLs and object sizes stay archive-sealed.
  // Never inferred from the value's bytes: like markerKind (CR-04) it is an adapter ASSERTION.
  markerReason?: SourceFaultReason;
}

// Selector scopes a crawl by source-native key prefixes (SPEC 12.2).
export interface Selector {
  include: string[]; // a record is in scope if it matches at least one include (or include is empty = all)
  exclude: string[]; // and matches no exclude
  // range (Fix 2b fan-out) optionally narrows a LEX-ORDERED resumable crawl (KV first; R2 stretch) to one
  // contiguous HALF-OPEN key-range, so a high-cardinality source can be partitioned across N parallel
  // workers and merged into one archive. Semantics, chosen so range seams cover every boundary key EXACTLY
  // ONCE: startAfter is EXCLUSIVE (yield keys strictly > startAfter) and stopAt is INCLUSIVE (yield keys <=
  // stopAt, stop at the first key > stopAt). Worker i therefore covers (split[i-1], split[i]]: the boundary
  // key split[i] belongs to worker i (its inclusive stopAt), never worker i+1 (its exclusive startAfter).
  // Absent = the whole keyspace (a serial run), so the field is invisible to every non-fan-out crawl.
  range?: { startAfter?: string; stopAt?: string };
  // notAttempted (G234) names the record ids the CALLER deliberately left out of `include` because a
  // CACHED probe said they could not be read, so the adapter must still ACCOUNT for them: one
  // "_unavailable" marker record each, exactly as if the read had been attempted and refused, without
  // spending the read. It is the difference between a selector that narrows on evidence of ABSENCE
  // ("this account does not use the product", nothing to lose) and one that narrows on evidence of a
  // FAILED READ ("we could not see it"), which a backup product must never let disappear.
  // Today only the cf-config auto capture mode sets it (from the discovery cache's `unavailable`
  // partition); every other crawl leaves it absent and behaves exactly as before. An id here that the
  // adapter does not recognise, or that `exclude` rules out, is simply not emitted.
  notAttempted?: string[];
}

// SourceAdapter crawls one configured source. The crawl is an async iterable so a large
// source streams record by record rather than materialising a list.
export interface SourceAdapter {
  readonly sourceType: SourceRecord["sourceType"];
  // accountId, when the source knows it (the API sources: cf-config/workers/stream/images/artifacts), is the
  // Cloudflare account this source is a backup OF. The seal stamps it onto every record's `account` identity
  // annotation so the archive self-identifies its account (binding sources leave it undefined).
  readonly accountId?: string;
  // meter, when supplied, receives one spend per platform subrequest the crawl issues
  // (a D1 query, a Secrets Store get): the non-resumable crawl runs inside a budgeted
  // slice and its calls count against the same invocation cap as everything else.
  crawl(selector: Selector, meter?: Meter): AsyncIterable<SourceRecord>;
  // estimate returns an upper bound on record count and bytes from listing metadata
  // ONLY (never reading values), for the pre-run cost projection (SPEC cost note).
  estimate(selector: Selector): Promise<{ records: number; bytes: number }>;
}

// Meter (src/meter.ts) is the subrequest accounting hook the resumable crawl reports
// list pages and value reads into; re-exported here so source implementations and their
// callers share one import surface.
export type { Meter } from "../meter.ts";

// CrawlEvent is the resumable crawl's stream: records interleaved with marks. A mark is an opaque per-source
// resume token meaning "everything before this point is fully yielded; a later crawlFrom(selector, token)
// continues after it without re-reading". Marks come at page boundaries, so resuming re-lists at most nothing
// and re-reads no values. The token is engine-internal state (a cursor or a last-key watermark), carries no
// value bytes, and is safe to persist in checkpoint state.
//
// A mid-crawl VANISH (WS-P2) -- an in-scope object the LIST returned but that was GONE by the time its value
// was read (a KV key / R2 object deleted BETWEEN the list page and the value GET, a live-source race, SPEC
// 12.5) -- is NOT a separate event kind: the KV/R2 adapters seal an honest _vanished MARKER record (a tiny
// buffered sentinel, seal/marker.ts vanishedMarkerValue) in its place, so the archive records WHICH object
// raced the crawl and the seal counts it exactly like any other incompleteness marker (recordsIncomplete +
// incompleteByMarker._vanished) while ALSO bumping the distinct recordsVanished counter. The marker record
// rides the SAME trailing mark as a real record, so the cursor advances past it and a resume skips the
// vanished key (no re-yield, no double-seal/double-count). The restore side skips the marker (via the signed
// rec.incompleteMarker manifest field, itself stamped from this record's markerKind), so a deleted key is
// never re-created with sentinel bytes on restore.
export type CrawlEvent = { kind: "record"; record: SourceRecord } | { kind: "mark"; token: string };

// ResumableSource extends a source with the checkpointed crawl the sliced seal uses for
// large environments. crawl() remains the simple whole-crawl form (and the two stay
// behaviourally identical over a full pass; validate-sources pins it).
export interface ResumableSource extends SourceAdapter {
  crawlFrom(selector: Selector, token: string | null, meter?: Meter): AsyncIterable<CrawlEvent>;
}

export function isResumable(s: SourceAdapter): s is ResumableSource {
  return typeof (s as { crawlFrom?: unknown }).crawlFrom === "function";
}

// KeySampler (Fix 2b fan-out) is the optional key-only planning scan a LEX-ORDERED source exposes so the
// coordinator can pick range split points WITHOUT reading any value. sampleKeys lists keys (metadata only,
// the estimate() cost model, never a value read) up to `cap`, in ascending key order, and reports whether
// the source has MORE keys beyond the cap (so the planner can tell "small enough to fan out evenly" from
// "huge, splits skewed to the sampled front" -- the latter is the documented skew-defer). Only KV
// implements it today (fan-out is KV-first); a source without it cannot be fanned out.
export interface KeySampler {
  sampleKeys(selector: Selector, cap: number): Promise<{ keys: string[]; more: boolean }>;
  // listKeysFrom (Fix 2b H2) is the SLICED, keys-only planning scan the coordinator drives to COUNT then
  // STRIDE the WHOLE keyspace WITHOUT reading any value, so it can size BALANCED ranges over the real key
  // count instead of a front sample. It yields one event per fully-listed page (the in-scope key NAMES, an
  // opaque resume token, and a `last` flag marking the final page), and a later call with a saved token
  // resumes after that page -- mirroring crawlFrom's cursor-first / watermark-fallback discipline so the
  // scan can span many invocations. No value read, so a whole-keyspace scan costs list pages only.
  listKeysFrom(selector: Selector, token: string | null, meter?: Meter): AsyncIterable<{ keys: string[]; token: string; last: boolean }>;
}

export function hasKeySampler(s: SourceAdapter): s is SourceAdapter & KeySampler {
  return typeof (s as { sampleKeys?: unknown }).sampleKeys === "function";
}

// API_DISCOVERY_SOURCE_TYPES are the source types whose adapters read the Cloudflare REST API with the
// engine's read-only discovery token rather than a Workers binding: cf-config, workers, and the three
// media sources (stream/images/artifacts). Every buildAdapter branch for these types THROWS when the
// token is absent, so the run path's cfConfigToken MUST fetch and pass the token for EXACTLY this set.
// It lives in this leaf (re-exported from seal/adapters.ts) so the run-path resolver AND the coverage
// reporter can both test membership against ONE set without importing the seal/scheduler graph -- the
// drift that left stream/images/artifacts unable to run at all despite a configured token.
export type ApiDiscoverySourceType = "cf-config" | "workers" | "stream" | "images" | "artifacts";
export const API_DISCOVERY_SOURCE_TYPES: ReadonlySet<string> = new Set<ApiDiscoverySourceType>([
  "cf-config",
  "workers",
  "stream",
  "images",
  "artifacts",
]);

// isApiDiscoverySourceType is the type-guard form of the membership test, so callers that branch on it
// (the coverage reporter skipping non-data sources) get the residual narrowed to the binding data types,
// exactly as the hand-written OR-chain it replaced did.
export function isApiDiscoverySourceType(t: string): t is ApiDiscoverySourceType {
  return API_DISCOVERY_SOURCE_TYPES.has(t);
}
