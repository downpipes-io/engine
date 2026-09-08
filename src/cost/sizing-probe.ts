// The onboarding sizing probe: size a source (or a whole estate) BEFORE any backup has run, so the cost
// estimate shows a real number with no typing. Analytics-first by design: it reads the account's storage
// by design: it reads the account's storage analytics (KV namespace bytes/keys, R2 bucket
// bytes/objects) and never reads a value. Anything analytics cannot answer (D1, an absent id, a missing
// scope) returns "unavailable" so the caller degrades honestly rather than guessing.
//
// no-custody is inherent (this runs in the customer's own account); the probe reads only sizes and counts.
// House rules: Australian English; precise claims.

import { type CfAnalytics, type CfSize, isCfSize } from "./cf-analytics.ts";

// SizeBasis records HOW a size was obtained, so the console can show its provenance:
//   "analytics"   - from Cloudflare's storage analytics (no value reads); the accurate path.
//   "list-meta"   - from a metadata listing (exact object sizes, no value reads); a future fallback hook.
//   "unavailable" - analytics could not answer (D1, no id, no scope); the estimate must say so, not guess.
// "list-meta" is a forward-compatibility hook only; no code path produces it yet. Implement the
// produces it yet. Implement the metadata-listing fallback or drop the variant when that work is scheduled.
export type SizeBasis = "analytics" | "list-meta" | "unavailable";

export interface SizeEstimate {
  bytes: number;
  count: number;
  basis: SizeBasis;
}

// SizingSource is the minimal shape the probe needs from a SourceSpec, kept local so the probe does not
// depend on the scheduler types (the caller maps a SourceSpec onto this).
export interface SizingSource {
  type: string;
  namespaceId?: string; // kv
  bucketName?: string; // r2
}

export interface SizingDeps {
  analytics: CfAnalytics;
  accountId: string;
}

const UNAVAILABLE: SizeEstimate = { bytes: 0, count: 0, basis: "unavailable" };

function fromAnalytics(s: CfSize): SizeEstimate {
  return { bytes: s.bytes, count: s.count, basis: "analytics" };
}

// ---- sizing-probe health (G296) -------------------------------------------------------------------------
//
// The probe's outcome CLASS, per source type. The load-bearing member is measured-zero: analytics ANSWERED,
// and it answered zero -- which the console then presents to the customer as a MEASURED size ("this source is
// empty"). That is a completely different fact from an honestly unavailable one, and the two used to produce
// identical evidence (a 0 and a basis). A broken discovery token, or a Cloudflare schema drift, therefore
// showed the customer an empty account and invited them to conclude they had nothing to back up.
//
// This module is a PURE leaf (it takes its analytics client by injection and holds no env or scheduler stub),
// so it tallies isolate-locally -- the source-fault-ledger idiom -- and the ROUTE that runs the probe drains
// it and posts it. Closed source type + closed class only: never an id, a name or a GraphQL error body.
export type SizingOutcomeClass = "ok" | "measured-zero" | "analytics-auth-or-scope" | "analytics-schema-drift" | "unsupported-source-type" | "missing-identifier" | "network";
let sizingOutcomes: Array<{ sourceType: string; cls: SizingOutcomeClass }> = [];
function noteSizingOutcome(sourceType: string, cls: SizingOutcomeClass): void {
  if (sizingOutcomes.length >= 64) return; // bounded: an estate probe cannot grow this without limit
  sizingOutcomes.push({ sourceType, cls });
}

/**
 * drainSizingOutcomes returns and CLEARS the isolate-local probe tally, so the outcomes are attributable to
 * the probe that just ran and cannot leak into the next one.
 *
 * @returns one {sourceType, class} row per source the probe attempted.
 */
export function drainSizingOutcomes(): Array<{ sourceType: string; cls: SizingOutcomeClass }> {
  const out = sizingOutcomes;
  sizingOutcomes = [];
  return out;
}

// classifyAnalyticsFault maps the analytics client's closed fault to the probe's closed outcome class.
function classifyAnalyticsFault(f: "auth-or-scope" | "schema-drift" | "network"): SizingOutcomeClass {
  if (f === "auth-or-scope") return "analytics-auth-or-scope";
  if (f === "schema-drift") return "analytics-schema-drift";
  return "network";
}

// estimateSourceSize sizes ONE source, analytics-first. KV is sized by namespace, R2 by bucket; every
// other source type, and any analytics miss, returns "unavailable" (D1 sizing needs a row/db query that
// is a separate, later add; list-meta is a documented future fallback hook).
export async function estimateSourceSize(source: SizingSource, deps: SizingDeps): Promise<SizeEstimate> {
  // Every exit NOTES its closed outcome class (G296). The measured-zero arm is the one that matters: an
  // answered-with-zero size is reported to the customer as a MEASURED "this source is empty", and until now
  // it was indistinguishable from a size the engine simply could not obtain.
  if (source.type === "kv" || source.type === "r2") {
    const id = source.type === "kv" ? source.namespaceId : source.bucketName;
    if (id === undefined || id === "") {
      noteSizingOutcome(source.type, "missing-identifier");
      return UNAVAILABLE;
    }
    const s = source.type === "kv" ? await deps.analytics.kvNamespaceSize(deps.accountId, id) : await deps.analytics.r2BucketSize(deps.accountId, id);
    if (!isCfSize(s)) {
      noteSizingOutcome(source.type, classifyAnalyticsFault(s));
      return UNAVAILABLE;
    }
    noteSizingOutcome(source.type, s.bytes === 0 && s.count === 0 ? "measured-zero" : "ok");
    return fromAnalytics(s);
  }
  noteSizingOutcome(source.type, "unsupported-source-type");
  return UNAVAILABLE;
}

// EstateSize is the whole-estate sizing roll-up: the totals plus the per-source detail, so an onboarding
// cost estimate can sum the account's backup-relevant data and show which sources it could and could not
// size.
export interface EstateSize {
  totalBytes: number;
  totalCount: number;
  sizedSources: number; // how many sources analytics could size (basis !== "unavailable")
  perSource: SizeEstimate[];
}

// estimateEstateSize sizes a set of sources in sequence (analytics calls are cheap and bounded by the
// source count) and returns the totals plus per-source detail. Unavailable sources contribute zero to
// the totals and are counted out via sizedSources, so the caller can say "sized N of M sources" honestly.
export async function estimateEstateSize(sources: SizingSource[], deps: SizingDeps): Promise<EstateSize> {
  const perSource: SizeEstimate[] = [];
  for (const source of sources) perSource.push(await estimateSourceSize(source, deps));
  let totalBytes = 0;
  let totalCount = 0;
  let sizedSources = 0;
  for (const e of perSource) {
    totalBytes += e.bytes;
    totalCount += e.count;
    if (e.basis !== "unavailable") sizedSources += 1;
  }
  return { totalBytes, totalCount, sizedSources, perSource };
}
