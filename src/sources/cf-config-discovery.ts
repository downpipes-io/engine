// cf-config DISCOVERY: probe which configuration surfaces an account/zone actually uses, so a
// backup run can capture only the PRESENT set instead of hammering the Cloudflare API with one GET
// per surface (200+) every run. Discovery is a SEPARATE, occasional probe (daily via cron, or a
// manual "rediscover"); the per-run capture path reads the cached present set. This is the read-cost
// control the user asked for; it never affects the seal/restore path (capture-only).
//
// SAFETY (this is a backup product, so a surface must never SILENTLY drop):
//   - "present"     = the surface returned real data (or a partial/truncated read)  -> CAPTURE.
//   - "empty"       = the surface returned a definitive empty ([]/{}/null)           -> skip (no data to lose).
//   - "gated"       = the read returned a DEFINITIVE account-PLAN / entitlement gate -> skip (BENIGN: the
//                     account's plan does not include the product, so the backup is COMPLETE w.r.t. the
//                     account, nothing to capture, like "empty"; a diagnosis consumer ignores it).
//   - "unavailable" = the read errored with an ACTIONABLE/AMBIGUOUS fault (token-scope/permission gap,
//                     transient 5xx, 429-after-retry, network, unrecognised) -> skip, re-checked next
//                     discovery. CONSERVATIVE: anything not a DEFINITIVE plan gate stays here, so a real
//                     token-scope gap is never silently routed to the benign bucket.
//   - until a downpipe has EVER been discovered, capture falls back to ALL surfaces (fail-safe).
//   - the cache is re-probed every DISCOVERY_MAX_AGE_MS (and on manual rediscover), so anything that
//     becomes present is picked up within a day; the console shows the last-discovered time + counts.
//   - a surface ADDED to the registry after the last discovery (e.g. a coverage-sweep append) is in
//     none of the cached partitions, so effectiveCfConfigSelector fails it safe to CAPTURED until the
//     next discovery classifies it, rather than silently omitting it for up to the max age.

import type { CfConfigDiscovery, CfConfigMode } from "../sched/types.ts";
import type { CfConfigSurface } from "./cf-config-surfaces.ts";
import { CF_CONFIG_SURFACES, CfApiError, CfPaginationTruncated, makeCfApi } from "./cf-config-surfaces.ts";
import { classifySourceFaultStatus, noteCfSelectorMode, SOURCE_FAULT_STATUS_CLASSES } from "./source-fault-ledger.ts";
import type { Selector } from "./types.ts";

// CfConfigDiscovery + CfConfigMode are defined in ../sched/types.ts (the leaf types module) so the
// scheduler can persist them without importing this module; re-export them here for source-side callers.
export type { CfConfigDiscovery, CfConfigMode } from "../sched/types.ts";

// A discovered cache older than this is treated as stale: capture fail-safes back to ALL surfaces and
// a fresh discovery is scheduled. 25h (not 24h) so a once-a-day refresh never races its own deadline.
export const DISCOVERY_MAX_AGE_MS = 25 * 60 * 60 * 1000;

// isEmptyValue reports whether a surface read returned a definitive "nothing here" (the account does
// not use this product): null, an empty list, an empty object, or an empty string.
function isEmptyValue(data: unknown): boolean {
  if (data == null || data === "") return true;
  if (Array.isArray(data)) return data.length === 0;
  if (typeof data === "object") return Object.keys(data as object).length === 0;
  return false;
}

// applicableSurfaces filters the registry the way the adapter does: account-scoped always, zone-scoped
// only when a zone is configured.
function applicableSurfaces(zoneId: string | undefined, surfaces: CfConfigSurface[]): CfConfigSurface[] {
  return surfaces.filter((s) => s.scope === "account" || zoneId !== undefined);
}

// runPool runs `tasks` with a bounded concurrency so a discovery probe of 200+ surfaces completes in
// a few seconds (vs ~minutes serial) without firing all reads at once (which would itself trip the CF
// rate limit the whole feature exists to respect).
async function runPool<T>(items: T[], concurrency: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      await fn(items[i]!);
    }
  });
  await Promise.all(workers);
}

// probeCfConfig reads every applicable surface ONCE (bounded concurrency) and classifies it. It is
// fail-open per surface (a read that throws is "gated" ONLY for a definitive account-plan gate, else
// "unavailable", never a thrown probe). It returns the partitioned result for caching. It does NOT seal
// anything and is safe to run from a request/cron context that can make subrequests.
export async function probeCfConfig(
  token: string,
  accountId: string,
  zoneId: string | undefined,
  now: number,
  opts?: { surfaces?: CfConfigSurface[]; fetchImpl?: typeof fetch; concurrency?: number },
): Promise<CfConfigDiscovery> {
  const api = makeCfApi(token, opts?.fetchImpl ?? fetch);
  const ids = zoneId !== undefined ? { accountId, zoneId } : { accountId };
  const surfaces = applicableSurfaces(zoneId, opts?.surfaces ?? CF_CONFIG_SURFACES);
  const present: string[] = [];
  const empty: string[] = [];
  const gated: string[] = [];
  const unavailable: string[] = [];
  // G006: WHY each unavailable surface is unavailable, and WHICH surfaces truncated. The id lists alone
  // cannot separate a token that lost a scope (actionable, permanent) from a transient Cloudflare outage
  // (self-healing) -- "auto-mode silently skips 12 surfaces from every backup" is unanswerable without this.
  // The class is a closed enum selected from the fault; the message and the CF error-code list are discarded.
  const unavailableByClass: Record<string, number> = {};
  const truncated: string[] = [];
  await runPool(surfaces, opts?.concurrency ?? 8, async (surface) => {
    try {
      const data = await surface.read(api, ids);
      (isEmptyValue(data) ? empty : present).push(surface.id);
    } catch (e) {
      // A truncation means we DID read records (a large list) -> present (partial data). It is ALSO the
      // early warning that this surface is big enough to be at risk of a partial capture, which the bare
      // "present" classification threw away.
      if (e instanceof CfPaginationTruncated) {
        present.push(surface.id);
        truncated.push(surface.id);
      }
      // A DEFINITIVE account-plan / entitlement gate (the verdict the CfApiError carries, computed from the
      // CF error code/message at the throw site) -> gated (BENIGN). EVERYTHING else, a token-scope 403, a
      // 5xx, a 429-after-retry, a network fault, a non-CfApiError throw, falls through to `unavailable`
      // (ACTIONABLE), the conservative direction: only an unambiguous plan gate is ever routed away from it.
      else if (e instanceof CfApiError && e.planEntitlementGated) gated.push(surface.id);
      else {
        unavailable.push(surface.id);
        const cls = classifySourceFaultStatus(e);
        unavailableByClass[cls] = (unavailableByClass[cls] ?? 0) + 1;
      }
    }
  });
  present.sort();
  empty.sort();
  gated.sort();
  unavailable.sort();
  truncated.sort();
  return {
    at: now,
    present,
    empty,
    gated,
    unavailable,
    ...(Object.keys(unavailableByClass).length > 0 ? { unavailableByClass } : {}),
    ...(truncated.length > 0 ? { truncated } : {}),
  };
}

// The bounds the DO-side sanitiser enforces. Surface ids are the FIXED product vocabulary (the registry), so
// the id lists are bounded by the registry itself; the cap is defence in depth against a drifted caller.
const DISCOVERY_IDS_MAX = 256;
const DISCOVERY_ID_MAX_LEN = 64;
const DISCOVERY_COUNT_MAX = 1_000_000;
const SOURCE_FAULT_STATUS_SET: ReadonlySet<string> = new Set(SOURCE_FAULT_STATUS_CLASSES);

/**
 * sanitiseCfConfigDiscovery is the DO-side REDACTION CHOKEPOINT for a posted discovery result (G006). The DO
 * previously stored the probe's object VERBATIM onto DownpipeState (and from there into the pack), which was
 * safe only because the sole writer was the engine's own probe. Now that the record carries a class map, that
 * implicit trust is made explicit: every surface id must be a member of the CLOSED registry vocabulary, every
 * class must be a member of the closed status set, every count is clamped, and NOTHING else on the posted
 * object is read. So a drifted or hostile caller cannot land a message, a token, an account id or a free-text
 * key here, even though this record rides straight into the support pack.
 *
 * @param raw - the posted discovery object (UNTRUSTED).
 * @param surfaces - the registry (injected for the validator).
 * @returns the sanitised record, or null when the body is not a discovery result at all.
 */
export function sanitiseCfConfigDiscovery(raw: unknown, surfaces: CfConfigSurface[] = CF_CONFIG_SURFACES): CfConfigDiscovery | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const known: ReadonlySet<string> = new Set(surfaces.map((s) => s.id));
  const ids = (v: unknown): string[] => {
    if (!Array.isArray(v)) return [];
    const out: string[] = [];
    for (const x of v) {
      if (typeof x !== "string" || x.length > DISCOVERY_ID_MAX_LEN) continue;
      if (!known.has(x)) continue; // not a registry surface: DROP (never a caller-chosen string)
      out.push(x);
      if (out.length >= DISCOVERY_IDS_MAX) break;
    }
    return out;
  };
  const at = typeof r.at === "number" && Number.isFinite(r.at) && r.at > 0 ? Math.floor(r.at) : 0;
  if (at === 0) return null;
  const byClass: Record<string, number> = {};
  if (typeof r.unavailableByClass === "object" && r.unavailableByClass !== null && !Array.isArray(r.unavailableByClass)) {
    for (const [cls, n] of Object.entries(r.unavailableByClass as Record<string, unknown>)) {
      if (!SOURCE_FAULT_STATUS_SET.has(cls)) continue; // out of vocabulary: DROP
      const c = typeof n === "number" && Number.isFinite(n) && n > 0 ? Math.min(DISCOVERY_COUNT_MAX, Math.floor(n)) : 0;
      if (c > 0) byClass[cls] = c;
    }
  }
  const truncated = ids(r.truncated);
  return {
    at,
    present: ids(r.present),
    empty: ids(r.empty),
    gated: ids(r.gated),
    unavailable: ids(r.unavailable),
    ...(Object.keys(byClass).length > 0 ? { unavailableByClass: byClass } : {}),
    ...(truncated.length > 0 ? { truncated } : {}),
  };
}

// resolveCfConfigMode resolves the EFFECTIVE capture mode for a cf-config source. An explicit
// cfConfigMode wins. When ABSENT (a pre-feature downpipe, or one never set), it is derived for
// backward compatibility: a NON-EMPTY include is an operator's explicit surface selection -> MANUAL
// (so discovery never silently BROADENS what they chose); an empty include (= all) -> AUTO (so it
// gets the read-cost optimisation, capturing the surfaces in use). New downpipes set it explicitly.
export function resolveCfConfigMode(source: { cfConfigMode?: CfConfigMode; include: string[] }): CfConfigMode {
  if (source.cfConfigMode === "auto" || source.cfConfigMode === "manual") return source.cfConfigMode;
  return source.include.length > 0 ? "manual" : "auto";
}

// effectiveCfConfigSelector computes the selector a cf-config run should actually use, given the
// source's (resolved) mode + cached discovery. This is the ONLY thing the capture path needs from discovery.
//   - manual mode: the operator's explicit selection, unchanged.
//   - auto mode with a FRESH discovery: capture exactly the present set (minus any operator exclude),
//     and carry the UNAVAILABLE partition in `notAttempted` so the crawl still accounts for it (below).
//   - auto mode with NO/STALE discovery: fail-safe to ALL surfaces (empty include) so nothing is
//     missed while discovery is pending; a refresh will narrow it next time.
//
// G234 (the silent drop). "empty" and "gated" are evidence of ABSENCE: the account does not use the
// product, or its plan does not include it, so narrowing them away loses nothing and they stay out of
// the archive as they always have. "unavailable" is the opposite: the probe could NOT READ the surface
// (a token-scope gap, a deprecated endpoint, a 5xx), so the account may well hold configuration there
// that this run is not capturing. Filtering those ids out of `include` and letting the crawl skip them
// before its attempted counter would produce no record, no marker and no run-level incompleteness count:
// a backup that quietly did not capture something. They stay out of
// `include` (auto mode exists so a run is not one GET per registry surface, and re-reading a surface a
// probe just found unreadable buys nothing), and are named in `notAttempted` instead, which costs no
// Cloudflare read and makes both the archive and the run row say what was missed.
export function effectiveCfConfigSelector(
  source: { cfConfigMode?: CfConfigMode; include: string[]; exclude: string[] },
  discovery: CfConfigDiscovery | undefined,
  now: number,
  maxAgeMs: number = DISCOVERY_MAX_AGE_MS,
  surfaces: CfConfigSurface[] = CF_CONFIG_SURFACES,
): Selector {
  if (resolveCfConfigMode(source) === "manual") {
    noteCfSelectorMode("configured"); // G006: the operator's explicit selection
    return { include: source.include, exclude: source.exclude };
  }
  const fresh = discovery !== undefined && now - discovery.at <= maxAgeMs;
  if (!fresh || discovery === undefined) {
    // G006: THE COST EXPLOSION. An auto-mode downpipe whose discovery cache is missing or STALE (>25h,
    // because the discovery pass is being skipped -- see the discovery skip reasons) silently fail-safes to
    // crawling EVERY surface in the registry, every run, forever. That is correct for safety (nothing is ever silently
    // dropped) and it is also exactly why "our runs suddenly take 10x longer and trip rate limits" had no
    // recorded cause. Stamp the mode on the run row so the fallback is attributable.
    noteCfSelectorMode("stale-fallback-all");
    return { include: source.include, exclude: source.exclude }; // fail-safe (usually [] = all)
  }
  noteCfSelectorMode("auto");
  // Union the present set with any registry surface the cached discovery never classified (a surface
  // ADDED to the registry after this discovery ran, e.g. a coverage-sweep append). It is in none of the
  // present/empty/unavailable partitions, so without this it would be silently omitted for up to the
  // max age. Failing it safe to CAPTURED until the next discovery re-classifies it keeps the no-silent-
  // drop invariant whole.
  // A gated surface IS classified (the account's plan does not include it), so it counts as "known" and
  // must NOT be force-captured as a newly-registered surface; it is simply skipped (never added to the
  // include set below). `?? []` so a discovery cache persisted before this field existed still reads safely.
  const known = new Set<string>([...discovery.present, ...discovery.empty, ...(discovery.gated ?? []), ...discovery.unavailable]);
  const newlyRegistered = surfaces.map((s) => s.id).filter((id) => !known.has(id));
  const include = newlyRegistered.length === 0 ? discovery.present : [...discovery.present, ...newlyRegistered].sort();
  // The surfaces this run is NOT reading because the cached probe could not read them. An operator's
  // explicit exclude still wins (they asked for that surface to be out of scope, so a marker would be
  // noise), and anything that ended up in `include` anyway is attempted for real and needs no marker.
  const included = new Set(include);
  const notAttempted = discovery.unavailable.filter((id) => !included.has(id) && !source.exclude.includes(id));
  return { include, exclude: source.exclude, ...(notAttempted.length > 0 ? { notAttempted } : {}) };
}

// discoveryIsStale reports whether an auto-mode cf-config downpipe needs a (re)discovery: never
// discovered, or older than the max age. Used by the daily cron pass to pick which downpipes to probe.
export function discoveryIsStale(discovery: CfConfigDiscovery | undefined, now: number, maxAgeMs: number = DISCOVERY_MAX_AGE_MS): boolean {
  return discovery === undefined || now - discovery.at > maxAgeMs;
}
