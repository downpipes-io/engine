// metrics.ts -- the Prometheus text-exposition /metrics scrape endpoint (monitoring integrations, the
// highest-value Tier-1 auto-parse build: ONE scrape target that Prometheus, Grafana, the Datadog agent,
// New Relic, Dynatrace, Elastic, Splunk Observability and Grafana Cloud's agentless scraper all read
// natively, zero customer setup).
//
// AUTH: a dedicated READ-ONLY bearer, reusing the EXISTING platform-issued ingest-credential mechanism
// (support-ingest.ts) rather than a parallel one: "metrics" is a third IngestScope alongside "diagnostics"/
// "audit-feed", minted and revoked through the SAME owner-gated POST /admin/support/credentials{,/delete}
// routes and stored/verified through the SAME DO ingest-credential store (GET/POST /ingest-credential*). A
// scrape target IS exactly the "platform-issued client/secret a pull connector presents" shape that module
// already generalises over, so this reuses its constant-time verification, server-side expiry, per-scope
// single-active-credential/revoke/re-mint story and the customer-visible pull trail, instead of inventing a
// second credential mechanism. /metrics is a NON-/admin route (like /support/*): a scraper must reach it
// without an interactive console session, without the CSRF/step-up gates and without the Access perimeter
// tripping it up on every unattended scrape (see [[siem-access-perimeter]]).
//
// SOURCE OF TRUTH: every value is read from the DO's EXISTING accessors -- GET /downpipes, GET /history, GET
// /replication -- the SAME three routes /admin/status, /admin/history and /admin/replication already forward
// to (router-status.ts, router-updates.ts). Nothing here recomputes freshness/RPO/replication; it derives the
// same per-downpipe facts the SLA report and the SRE alert detector already derive from the identical
// run-history ring (scheduler-do-reporting.ts's slaReportData, scheduler-do-sre-alerting.ts's reconcileAlerts).
//
// HONESTY: a downpipe with no RESOLVED run omits the last-success timestamp, the success gauge, the duration
// and the size series (never a fabricated timestamp or a fabricated "instant" duration). The attempt/success/
// failure counters ARE an honest 0 for a fresh downpipe (the standard Prometheus counter idiom: a counter
// that has never incremented reads 0, not absent) but are windowed over the RETAINED run-history ring
// (RING_CAP, currently 50 runs per downpipe: scheduler-do-limits.ts) rather than a lifetime count -- the DO
// holds no lifetime counter today, and adding one would mean touching the core trigger/completeRun run-
// lifecycle commit points, deliberately NOT done in this build (see the HELP text on each counter, and the
// build's return notes, for the trade-off). downpipe_destination_healthy is emitted only for a destination
// the DO actually tracks replication state for; a downpipe on the implicit default destination has none by
// the DO's own design (recordReplicationState: "an env-default run with no console destination id records
// nothing"), so it is honestly absent there too, never a fabricated healthy/unhealthy guess.
//
// INJECTION SAFETY: every label VALUE (downpipe id/name, destination id) is an operator-chosen string and is
// therefore treated as untrusted; escapeLabelValue applies the Prometheus text-exposition escaping (backslash
// FIRST, then double quote, then any line break) so a hostile name can never forge or break out of a metric
// line (e.g. close the quote early and inject a second, fabricated series).

import type { DestReplState } from "../sched/scheduler-do-records.ts";
import type { DownpipeConfig, RunHistoryEntry } from "../sched/types.ts";
import type { MetricsScrapeOutcome } from "./diag-records.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { doURL } from "../do-url.ts";
import { classifyIngestCredentialCheck, type IngestGrant } from "./support-ingest.ts";
import { nowIso } from "./support-shared.ts";

// MONITORING_SURFACES is the closed set of monitoring/observability PULL surfaces the engine exposes. It is
// parsed externally as a source of truth, exactly the way NOTIFY_EVENT_NAMES/ChannelKind/REPORT_KINDS are
// already parsed out of notify/types.ts and admin/reports.ts. A future monitoring surface (e.g. an OTLP
// metrics-push target) is added here so it is declared in the one place every consumer reads from.
export const MONITORING_SURFACES = ["metrics"];

// escapeLabelValue applies the Prometheus text-exposition label-value escaping: backslash MUST be escaped
// FIRST (otherwise the backslash the quote/newline escapes below introduce would itself be re-escaped), then
// the double quote that delimits the value, then any line break. \r\n and a lone \r are folded into the same
// \n two-character escape as a lone \n, so a bare carriage return cannot smuggle a line break past a
// newline-only check either. This is the sole defence between an operator-chosen downpipe name/id or
// destination id and a forged/broken metric line.
export function escapeLabelValue(v: string): string {
  return v
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\r\n|\r|\n/g, "\\n");
}

// formatValue renders a finite number the way the exposition format expects (a bare decimal; NaN/+-Inf have
// their own literals). Every value this module computes is already a bounded epoch-seconds/byte/duration/
// count, so the NaN/Inf arms are a defensive backstop, not an expected path.
function formatValue(n: number): string {
  if (Number.isNaN(n)) return "NaN";
  if (n === Number.POSITIVE_INFINITY) return "+Inf";
  if (n === Number.NEGATIVE_INFINITY) return "-Inf";
  return String(n);
}

interface MetricRow {
  labels: Record<string, string>;
  value: number;
}

function formatSample(name: string, row: MetricRow): string {
  const labelPairs = Object.entries(row.labels)
    .map(([k, v]) => `${k}="${escapeLabelValue(v)}"`)
    .join(",");
  const labelPart = labelPairs.length > 0 ? `{${labelPairs}}` : "";
  return `${name}${labelPart} ${formatValue(row.value)}`;
}

// GatheredDownpipe is the per-downpipe slice gatherMetricsState assembles from the DO's three existing
// accessors: the config identity, the run-history ring (newest-first, exactly as GET /history returns it),
// and the per-destination replication map (exactly as GET /replication returns it for that downpipe).
export interface GatheredDownpipe {
  id: string;
  name: string;
  ring: RunHistoryEntry[];
  dests: Record<string, DestReplState>;
}

// gatherMetricsState calls the SAME three DO routes /admin/status, /admin/history and /admin/replication
// already forward to (GET /downpipes, GET /history, GET /replication with no ?id, i.e. the fleet-wide byId
// shapes), and folds them into one array keyed on downpipe. It deliberately does NOT swallow a fetch/parse
// fault: an unreachable or malformed DO response propagates (the caller's outer handler turns that into a
// 500), so a genuine backend outage fails the SCRAPE itself (Prometheus's own per-target `up` goes to 0) --
// distinct and much MORE correct than a healthy-looking 200 with zero series masking a real outage as
// "nothing configured". An honestly EMPTY fleet (valid JSON, empty arrays/objects) still renders fine below.
//
// The three "coerce a bad body to empty" fallbacks below are the
// SILENT failure this endpoint has. A DO that answers 2xx with an unexpected shape (a schema drift, a partial
// read) renders a perfectly valid scrape with ZERO downpipe series while Prometheus's own `up` stays 1: every
// dashboard and every alert rule goes quiet and reads as "nothing configured". The optional `faults` out-param
// lets handleMetricsRoute record that coercion (a boolean, never the body) on the DO's metrics-health record,
// so "all our series vanished" is finally diagnosable. Passing no `faults` keeps the prior behaviour exactly.
export async function gatherMetricsState(scheduler: DurableObjectStub, faults?: { shapeFallback: boolean }): Promise<GatheredDownpipe[]> {
  const [dpResp, histResp, replResp] = await Promise.all([
    scheduler.fetch(doURL("/downpipes"), { method: "GET" }),
    scheduler.fetch(doURL("/history"), { method: "GET" }),
    scheduler.fetch(doURL("/replication"), { method: "GET" }),
  ]);
  if (!dpResp.ok || !histResp.ok || !replResp.ok) {
    // A non-2xx from the DO is a genuine backend fault, not an empty fleet: SchedulerDO.fetch converts a
    // thrown storage/dispatch error into a normally-resolved non-2xx JSON body, which the shape-coercion
    // below would otherwise read as "no downpipes/history/replication" and return as a healthy-looking 200
    // with zero series -- masking the outage. Throw instead, so the caller's outer handler fails the scrape
    // (HTTP 500, Prometheus's per-target `up` -> 0), which is the honest signal a real outage should give.
    throw new Error(`metrics: scheduler DO returned non-2xx (${dpResp.status}/${histResp.status}/${replResp.status})`);
  }
  const dpBody: unknown = await dpResp.json();
  const dpIsArray = Array.isArray(dpBody);
  const downpipes = dpIsArray ? (dpBody as Array<{ config?: DownpipeConfig }>) : [];
  const histBody = (await histResp.json()) as { byDownpipe?: Record<string, RunHistoryEntry[]> };
  const replBody = (await replResp.json()) as { byDownpipe?: Record<string, Record<string, DestReplState>> };
  const histByDownpipe = histBody.byDownpipe ?? {};
  const replByDownpipe = replBody.byDownpipe ?? {};
  // G049: the DO answered 2xx but a body was NOT the shape this renderer expects, so it was coerced to empty.
  // The downpipes body is the load-bearing one (an empty array there empties EVERY series while up == 1); a
  // missing byDownpipe map silently empties the run/replication facts for the whole fleet. Record the COERCION
  // as a boolean; the offending body is never read further, retained or forwarded.
  if (faults && (!dpIsArray || histBody.byDownpipe === undefined || replBody.byDownpipe === undefined)) faults.shapeFallback = true;
  const out: GatheredDownpipe[] = [];
  for (const ds of downpipes) {
    if (!ds.config) continue;
    out.push({
      id: ds.config.id,
      name: ds.config.name,
      ring: histByDownpipe[ds.config.id] ?? [],
      dests: replByDownpipe[ds.config.id] ?? {},
    });
  }
  return out;
}

// renderPrometheusMetrics is the pure formatter: given the gathered per-downpipe slices, it derives the
// canonical metric set and renders Prometheus text exposition (HELP + TYPE + zero or more samples per metric
// family, in that order, matching the format's canonical grouped form). Pure and side-effect-free so it is
// directly unit-testable without a DO.
//
// Per-downpipe derivation (mirrors the SAME ring-reading idiom scheduler-do-reporting.ts's slaReportData/
// rtoInputs and scheduler-do-sre-alerting.ts's reconcileAlerts already use over this identical ring, rather
// than inventing a parallel freshness computation):
//   - latestResolved: the newest NON-in-flight entry (ring is newest-first) -- the "what happened last" clock
//     for the success gauge and the duration gauge.
//   - latestOk: the newest "ok" entry (may be older than latestResolved when the most recent attempt failed)
//     -- the "last known-good" clock for the last-success timestamp and the size gauge, mirroring rtoInputs'
//     own "latest successful run" framing for archive size.
export function renderPrometheusMetrics(downpipes: GatheredDownpipe[]): string {
  const lastSuccessRows: MetricRow[] = [];
  const successRows: MetricRow[] = [];
  const attemptRows: MetricRow[] = [];
  const successTotalRows: MetricRow[] = [];
  const failureTotalRows: MetricRow[] = [];
  const durationRows: MetricRow[] = [];
  const sizeRows: MetricRow[] = [];
  const destHealthyRows: MetricRow[] = [];

  for (const dp of downpipes) {
    const labels = { downpipe_id: dp.id, downpipe_name: dp.name };
    const ring = dp.ring; // newest-first, as returned by the DO's history()

    const latestResolved = ring.find((e) => e.status !== "in-flight");
    const latestOk = ring.find((e) => e.status === "ok");

    if (latestOk !== undefined) {
      // The recovery point is when the run COMPLETED, not when it was triggered: the history row stamps
      // startedAt at trigger time, so add the run's own duration when known (mirrors point-in-time.ts's
      // completionMs) to keep this metric's "completion" contract honest. Falls back to the start time when
      // duration is unavailable (a pre-duration-reporting run), which is the closest honest value.
      const startMs = Date.parse(latestOk.startedAt);
      if (Number.isFinite(startMs)) {
        const durMs = typeof latestOk.durationMs === "number" && Number.isFinite(latestOk.durationMs) ? latestOk.durationMs : 0;
        lastSuccessRows.push({ labels, value: Math.floor((startMs + durMs) / 1000) });
      }
      if (typeof latestOk.bytes === "number" && Number.isFinite(latestOk.bytes)) sizeRows.push({ labels, value: latestOk.bytes });
    }
    if (latestResolved !== undefined) {
      successRows.push({ labels, value: latestResolved.status === "ok" ? 1 : 0 });
      if (typeof latestResolved.durationMs === "number" && Number.isFinite(latestResolved.durationMs)) {
        durationRows.push({ labels, value: latestResolved.durationMs / 1000 });
      }
    }

    // The bounded-window counters: every entry in the ring is either "in-flight" (not yet concluded, so it
    // counts toward none of the three) or a terminal outcome, exactly one of "ok" (success) or "failed"/
    // "abandoned" (failure) -- so attempts = successes + failures always holds by construction.
    let attempts = 0;
    let successes = 0;
    let failures = 0;
    for (const e of ring) {
      if (e.status === "in-flight") continue;
      attempts++;
      if (e.status === "ok") successes++;
      else failures++;
    }
    attemptRows.push({ labels, value: attempts });
    successTotalRows.push({ labels, value: successes });
    failureTotalRows.push({ labels, value: failures });

    for (const [destId, state] of Object.entries(dp.dests)) {
      destHealthyRows.push({ labels: { downpipe_id: dp.id, downpipe_name: dp.name, destination: destId }, value: state.lastOk ? 1 : 0 });
    }
  }

  const lines: string[] = [];
  const emitFamily = (name: string, help: string, type: "gauge" | "counter", rows: MetricRow[]): void => {
    lines.push(`# HELP ${name} ${help}`);
    lines.push(`# TYPE ${name} ${type}`);
    for (const row of rows) lines.push(formatSample(name, row));
  };

  emitFamily(
    "downpipe_backup_last_success_timestamp_seconds",
    "Unix timestamp in seconds of the most recent successful backup completion for this downpipe. Absent when no run has ever succeeded (never a fabricated timestamp).",
    "gauge",
    lastSuccessRows,
  );
  emitFamily(
    "downpipe_backup_success",
    "Whether the most recently completed backup run succeeded (1) or failed (0). Absent when no run has completed yet.",
    "gauge",
    successRows,
  );
  // Windowed counts over the retained run-history ring, NOT lifetime-monotonic, so they are exposed as
  // GAUGES (not _total counters): a value that shrinks as old runs age out of the ring would be read by
  // rate()/increase() as a counter reset and produce phantom spikes. The gauge type plus the non-_total name
  // keep any consumer from applying counter idioms to a windowed value.
  emitFamily(
    "downpipe_backup_recent_attempts",
    "Backup run attempts among the most recent runs retained in the run-history window (a windowed gauge over the retained ring, not a lifetime counter).",
    "gauge",
    attemptRows,
  );
  emitFamily(
    "downpipe_backup_recent_successes",
    "Successful backup runs among the most recent runs retained in the run-history window (a windowed gauge over the retained ring, not a lifetime counter).",
    "gauge",
    successTotalRows,
  );
  emitFamily(
    "downpipe_backup_recent_failures",
    "Failed backup runs among the most recent runs retained in the run-history window (a windowed gauge over the retained ring, not a lifetime counter).",
    "gauge",
    failureTotalRows,
  );
  emitFamily(
    "downpipe_backup_duration_seconds",
    "Wall-clock duration in seconds of the most recently completed backup run. Absent when the run predates duration reporting or none has completed.",
    "gauge",
    durationRows,
  );
  emitFamily(
    "downpipe_backup_size_bytes",
    "Plaintext byte size of the most recent successful backup. Absent when no run has succeeded yet.",
    "gauge",
    sizeRows,
  );
  emitFamily(
    "downpipe_destination_healthy",
    "Whether the destination's most recent seal or replication attempt for this downpipe succeeded (1) or not (0). Only emitted for a destination the engine has recorded replication state for.",
    "gauge",
    destHealthyRows,
  );

  return `${lines.join("\n")}\n`;
}

// checkMetricsBearer verifies a presented "Authorization: Bearer <clientId>.<secret>" against the stored
// "metrics"-scope ingest-credential grant: constant-time secret comparison + server-side expiry, exactly the
// handleSupportPull check. A missing/malformed header or an absent/expired/mismatched grant is a refusal; the
// caller returns 401 with no detail (the same fail-closed, no-oracle shape as the /support/* pulls).
//
// G049: it now returns the CLOSED reason alongside the verdict. The client-facing 401 is byte-identical (no
// detail, no oracle); the reason is recorded on the DO's metrics-health record only. auth-check-unavailable is
// the one that matters most: the grant could not be READ (a DO hiccup), so a perfectly valid scrape is refused
// FAIL-CLOSED and reported to the operator as "unauthorised" -- exactly the misdirection in the ticket
// ("Prometheus started getting 401s with an unexpired credential").
async function checkMetricsBearer(req: Request, scheduler: DurableObjectStub): Promise<MetricsScrapeOutcome> {
  const auth = req.headers.get("Authorization") ?? "";
  const presented = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length).trim() : "";
  if (presented === "") return "bearer-malformed";
  let grant: IngestGrant | null = null;
  try {
    const resp = await scheduler.fetch(doURL("/ingest-credential?scope=metrics"), { method: "GET" });
    if (!resp.ok) return "auth-check-unavailable";
    ({ grant } = (await resp.json()) as { grant: IngestGrant | null });
  } catch {
    return "auth-check-unavailable";
  }
  return classifyIngestCredentialCheck(presented, grant);
}

// recordScrape posts ONE scrape observation to the DO's bounded metrics-health record. Best-effort and
// fire-and-forget by contract: it must never delay or fail a scrape (a scraper that times out on our
// bookkeeping is worse than no bookkeeping). It goes through recordDiagWrite, so if THIS write is dropped the
// loss is itself counted in droppedWrites rather than vanishing -- the recorder that goes blind
// during an outage is exactly the meta-failure the audit named. Only the closed outcome enum + two booleans
// cross the wire: never the bearer, the clientId, the grant or the rendered body.
async function recordScrape(scheduler: DurableObjectStub, outcome: MetricsScrapeOutcome, opts?: { shapeFallback?: boolean; pullFailed?: boolean }): Promise<void> {
  await recordDiagWrite(scheduler, "metrics-health", () =>
    scheduler.fetch(doURL("/metrics-scrape"), {
      method: "POST",
      body: JSON.stringify({ outcome, shapeFallback: opts?.shapeFallback === true, pullFailed: opts?.pullFailed === true }),
      headers: { "content-type": "application/json" },
    }),
  );
}

// handleMetricsRoute serves GET /metrics: the Prometheus text-exposition scrape surface. It is dispatched
// from the Worker entry as a NON-/admin route (like /support/*), reached by the bearer alone -- no console
// session, no CSRF/step-up gate, no Access assertion required -- because an unattended, recurring scrape must
// work without an interactive sign-in. A failed presentation is a plain 401 (no detail, matching
// handleSupportPull's no-oracle shape); a non-GET is a 404 (the surface has no other verb). On success it
// gathers the canonical metric set from the DO's existing accessors and renders Prometheus text exposition,
// then records the pull on the grant (best-effort -- never blocks or fails the scrape response on a storage
// hiccup), giving the customer the same "when was this last read" trail every ingest credential keeps.
export async function handleMetricsRoute(req: Request, scheduler: DurableObjectStub): Promise<Response> {
  if (req.method !== "GET") return new Response("not found", { status: 404 });
  const auth = await checkMetricsBearer(req, scheduler);
  if (auth !== "ok") {
    // The refusal is UNCHANGED: a bare 401 with no detail. Only the closed reason is recorded (G049).
    //
    // bearer-malformed is DELIBERATELY not recorded: checkMetricsBearer short-circuits an absent / non-Bearer
    // header BEFORE any DO round trip (a property a validator pins, because an unauthenticated flood must not
    // cost one DO fetch per probe), and recording it would hand a scanner a free DO write on every request.
    // Every OTHER outcome has already paid the grant round trip, so one bounded counter write is proportionate.
    if (auth !== "bearer-malformed") await recordScrape(scheduler, auth);
    return new Response("unauthorised", { status: 401 });
  }
  const faults = { shapeFallback: false };
  let downpipes: GatheredDownpipe[];
  try {
    downpipes = await gatherMetricsState(scheduler, faults);
  } catch (e) {
    // gatherMetricsState throws by design on a non-2xx / unparseable DO answer, so the scrape 500s and
    // Prometheus's own `up` goes to 0 (the honest signal). That behaviour is unchanged; it is now also
    // RECORDED, so a scrape outage is visible in the pack rather than only in the customer's own Prometheus.
    // The error itself is re-thrown untouched to the entry's handler and never recorded (it carries DO status
    // text): only the closed enum is written.
    await recordScrape(scheduler, "do-read-failed");
    throw e;
  }
  const body = renderPrometheusMetrics(downpipes);
  // The pull trail write is best-effort but no longer UNCHECKED: a pull-trail write that keeps failing makes a
  // live, healthy scrape read as ABANDONED in the pack ("record-pull silently stops updating"), which sends
  // support looking for a decommissioned scraper that is in fact scraping every 15 seconds. Its failure is
  // counted on the health record (recordPullFailures) and, if THAT write is lost too, in droppedWrites.
  const pullLanded = await recordDiagWrite(scheduler, "support-pull-trail", () =>
    scheduler.fetch(doURL("/ingest-credential/record-pull"), {
      method: "POST",
      body: JSON.stringify({ scope: "metrics", at: nowIso() }),
      headers: { "content-type": "application/json" },
    }),
  );
  await recordScrape(scheduler, faults.shapeFallback ? "shape-fallback" : "ok", { shapeFallback: faults.shapeFallback, pullFailed: !pullLanded });
  return new Response(body, { headers: { "content-type": "text/plain; version=0.0.4; charset=utf-8" } });
}
