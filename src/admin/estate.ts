// Estate rollup: the volume-based self-serve licensing usage figure -- how much this engine is
// actually protecting right now. It reuses the SAME DO-held facts the support bundle already reads
// (the downpipe roster's config + selector via GET /downpipes, and each downpipe's run history via
// fetchRunHistory, the identical fetch support-sections-runs.ts uses for the pack's `runs` section),
// so this is a second, independent read of records the engine already keeps, never a new probe of
// live Cloudflare state and never a call to the vendor. Two consumers: GET /admin/licence (as
// `estate`, alongside the entitlement) and the support bundle (as `volumes`), so a customer and
// support both see "what is actually protected" next to "what the licence grants".
//
// "Protected" is the MOST RECENT SUCCESSFUL run per downpipe (RunHistoryEntry.status === "ok", the
// status completeRun stamps on a clean completion; see scheduler-do-scheduling.ts). A downpipe with
// no successful run in its retained history (recently added, or currently failing) contributes zero
// bytes/records but is still counted in `downpipes`, so a struggling fleet is never silently dropped
// from the estate, only honestly zeroed.
//
// Fail-open, matching the licence itself: this NEVER gates or blocks anything (it is read-only, pure
// aggregation), and any read fault anywhere (a DO hiccup, an unreachable scheduler) resolves the WHOLE
// rollup to `null` rather than a thrown error or a partial/misleading number.

import { bumpAdminCounter } from "./diag-counters.ts";
import { doURL } from "../do-url.ts";
import { fetchRunHistory } from "./support-sections-runs.ts";

// EstateByType is the per-source-type slice of the rollup: records and bytes captured by the most
// recent successful run, summed across every downpipe of that type (kv/r2/d1/secrets/cf-config/
// workers/stream/images/artifacts). Only types actually present among the fleet's downpipes appear.
export interface EstateByType {
  records: number;
  bytes: number;
}

// EstateRollup is the whole-fleet usage figure returned by computeEstateRollup. See the field-level
// comments below for the exact definition each carries; the module comment above states the basis.
export interface EstateRollup {
  // The sum, across every downpipe, of the most recent SUCCESSFUL run's bytes (the plaintext bytes
  // that run sealed -- RunSummary.bytes / RunHistoryEntry.bytes). A downpipe with no successful run
  // contributes 0.
  totalProtectedBytes: number;
  // The count of DISTINCT Cloudflare account ids across the fleet's bound sources (source.accountId,
  // carried by cf-config and workers sources; absent for kv/r2/d1/secrets).
  accounts: number;
  // The count of DISTINCT Cloudflare zone ids across the fleet's bound sources (source.zoneId,
  // carried by a zone-scoped cf-config source).
  zones: number;
  // The TOTAL downpipe count, successful-run or not (the roster size).
  downpipes: number;
  // records/bytes summed per source type, from the same most-recent-successful-run basis as
  // totalProtectedBytes.
  byType: Record<string, EstateByType>;
  // The newest startedAt among the runs actually used above, or null when no downpipe in the fleet
  // has ever completed a successful run (the honest "no measurement yet" state).
  asOf: string | null;
}

// RollupDownpipe is the minimal shape computeEstateRollup needs from a GET /downpipes row: just the
// id and the source's type/accountId/zoneId, the same fields the support bundle already projects
// (see SupportDownpipe in support.ts). Kept local so this module does not depend on the scheduler's
// internal DownpipeConfig type across the DO-fetch boundary, mirroring the rest of support-sections-*.
type RollupDownpipe = {
  config: { id: string; source: { type: string; accountId?: string; zoneId?: string } };
};

// isRollupDownpipe is the defensive type-guard over one GET /downpipes row crossing the DO-fetch
// boundary: config must be an object, config.id a non-empty string, and config.source an object whose
// type is itself a non-empty string (never undefined/a number/an object), so a malformed row can never
// produce a bogus byType["undefined"] entry or a source.type value this module did not itself validate
// as a plain string. A row failing any check is silently dropped (never thrown), the same
// defence-in-depth posture the rest of support-sections-*.ts already applies at this exact boundary.
function isRollupDownpipe(d: unknown): d is RollupDownpipe {
  if (typeof d !== "object" || d === null) return false;
  const config = (d as { config?: unknown }).config;
  if (typeof config !== "object" || config === null) return false;
  const id = (config as { id?: unknown }).id;
  if (typeof id !== "string" || id === "") return false;
  const source = (config as { source?: unknown }).source;
  if (typeof source !== "object" || source === null) return false;
  const type = (source as { type?: unknown }).type;
  return typeof type === "string" && type !== "";
}

// RunRow is the minimal shape this module reads off fetchRunHistory's per-downpipe rows.
type RunRow = { status?: string; index?: number; startedAt?: string; recordCount?: number; bytes?: number };

// mostRecentOk picks the SUCCESSFUL (status "ok") row with the greatest monotonic index from a
// downpipe's run-history rows. Order-independent: it does not assume the rows arrive newest-first or
// oldest-first, only that `index` is monotonically increasing per run (the RunHistoryEntry contract).
// A row with a missing/non-numeric index (malformed data crossing the DO-fetch boundary) can still
// become the initial pick but is never preferred over one with a genuine index, so a single well-formed
// row always wins over a malformed one. Returns undefined when the downpipe has no "ok" row at all.
function mostRecentOk(rows: unknown[]): RunRow | undefined {
  let best: RunRow | undefined;
  let bestIndex = Number.NEGATIVE_INFINITY;
  for (const r of rows) {
    if (typeof r !== "object" || r === null) continue;
    const row = r as RunRow;
    if (row.status !== "ok") continue;
    const idx = typeof row.index === "number" && Number.isFinite(row.index) ? row.index : Number.NEGATIVE_INFINITY;
    if (best === undefined || idx > bestIndex) {
      best = row;
      bestIndex = idx;
    }
  }
  return best;
}

// computeEstateRollup reuses the exact data access the support bundle already performs: the downpipe
// roster (GET /downpipes on the scheduler DO, config + selector only, never customer data) and
// per-downpipe run history (fetchRunHistory, the same fetch support-sections-runs.ts uses for the
// pack's `runs` section). It never throws: any fault anywhere in the read or the aggregation resolves
// to `null`, so a rollup problem can never break the licence read or the support-bundle build that
// carry it. A fleet that reads cleanly but has zero downpipes still resolves to a real (all-zero)
// EstateRollup, never null -- null means the rollup itself could not be computed, not "nothing to show".
export async function computeEstateRollup(scheduler: DurableObjectStub): Promise<EstateRollup | null> {
  try {
    // The two reads are SEPARATELY guarded, because their failures produce the SAME wrong answer by
    // two different routes and support cannot act without knowing which. A faulted ROSTER read used to be
    // coerced to an empty array (`Array.isArray(raw) ? raw : []`), so the rollup aggregated over an EMPTY fleet
    // and reported ZERO protected bytes for a perfectly healthy estate -- a number the customer is BILLED and
    // AUDITED against, presented as measured fact. A faulted HISTORY read does the same by a different door.
    // Neither is a fault the rollup can honestly recover from, so each is COUNTED and the rollup returns null
    // (which makes sections.volumes read "error" rather than an affirmative, wrong zero).
    let downpipesRaw: unknown;
    try {
      downpipesRaw = (await (await scheduler.fetch(doURL("/downpipes"), { method: "GET" })).json()) as unknown;
    } catch (e) {
      void bumpAdminCounter(scheduler, "volumes-read-failed-downpipes");
      throw e; // the outer catch resolves the rollup to null, exactly as before
    }
    // A NON-ARRAY body is a DO contract fault, not an empty fleet -- and it is coerced to [] below, so the
    // rollup goes on to report ZERO protected bytes for a healthy estate as though it had measured them. The
    // COERCION is deliberately left alone (callers pin it, and a real empty rollup is the honest answer for a
    // genuinely empty fleet); what changes is that the pack now CARRIES the fact that the read did not give us
    // a fleet. A non-zero counter beside a zero-byte rollup is the whole diagnosis.
    if (!Array.isArray(downpipesRaw)) void bumpAdminCounter(scheduler, "volumes-read-failed-downpipes");
    const downpipes = (Array.isArray(downpipesRaw) ? downpipesRaw : []).filter(isRollupDownpipe);
    let runs: Awaited<ReturnType<typeof fetchRunHistory>>;
    try {
      runs = await fetchRunHistory(scheduler);
    } catch (e) {
      void bumpAdminCounter(scheduler, "volumes-read-failed-history");
      throw e; // as before: the outer catch resolves to null rather than an affirmative zero
    }

    const accounts = new Set<string>();
    const zones = new Set<string>();
    // byType is deliberately a null-prototype object (never a plain `{}`): source.type is a validated
    // non-empty string (isRollupDownpipe above) but is still an ARBITRARY string crossing the DO-fetch
    // boundary, and a plain object's inherited `__proto__` accessor means a type literally named
    // "__proto__" would otherwise skip its own init (the `in` check finds the INHERITED property) and
    // then silently repoint byType's prototype instead of aggregating -- a prototype-pollution footgun
    // for the rest of this isolate's lifetime. A null-prototype object has no such accessor: every key,
    // however named, is always a plain, isolated own property.
    const byType: Record<string, EstateByType> = Object.create(null);
    let totalProtectedBytes = 0;
    let asOf: string | null = null;
    let asOfMs = Number.NEGATIVE_INFINITY;

    for (const d of downpipes) {
      const { id, source } = d.config;
      if (typeof source.accountId === "string" && source.accountId !== "") accounts.add(source.accountId);
      if (typeof source.zoneId === "string" && source.zoneId !== "") zones.add(source.zoneId);

      const type = source.type;
      if (!(type in byType)) byType[type] = { records: 0, bytes: 0 };

      const rows = Array.isArray(runs[id]) ? runs[id]! : [];
      const latestOk = mostRecentOk(rows);
      if (latestOk === undefined) continue; // no successful run: contributes 0, still counted in `downpipes`

      const records = typeof latestOk.recordCount === "number" && Number.isFinite(latestOk.recordCount) ? latestOk.recordCount : 0;
      const bytes = typeof latestOk.bytes === "number" && Number.isFinite(latestOk.bytes) ? latestOk.bytes : 0;
      totalProtectedBytes += bytes;
      byType[type]!.records += records;
      byType[type]!.bytes += bytes;

      const at = typeof latestOk.startedAt === "string" ? Date.parse(latestOk.startedAt) : Number.NaN;
      if (Number.isFinite(at) && at > asOfMs) {
        asOfMs = at;
        asOf = latestOk.startedAt as string;
      }
    }

    return { totalProtectedBytes, accounts: accounts.size, zones: zones.size, downpipes: downpipes.length, byType, asOf };
  } catch {
    return null;
  }
}
