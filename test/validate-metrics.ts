// Prove the Prometheus /metrics scrape endpoint (monitoring integrations, Tier-1 auto-parse build). In-memory
// doubles only; no network, no deploy, no cost. Run:
//   node test/validate-metrics.ts
//
// Coverage:
//  escapeLabelValue: backslash/quote/newline(+CR) escaping, in the correct order (backslash first).
//  renderPrometheusMetrics (pure): every canonical metric name carries HELP+TYPE; a hostile downpipe name
//    cannot forge or break out of a metric line (proven structurally: exactly one real sample line per
//    metric, no injected line); the honest-zero/absent behaviour for a no-run / in-flight-only downpipe
//    (timestamp/success/duration/size series OMITTED, counters an honest 0); latest-ok vs latest-resolved can
//    legitimately differ (a downpipe whose newest run failed but an earlier one succeeded); per-destination
//    health gauges.
//  gatherMetricsState + handleMetricsRoute (DO routes): seeded via fetchDO against a REAL SchedulerDO (no
//    globalThis.fetch stub), mirroring validate-reports.ts's testDORoutes -- POST /downpipes, a directly-
//    seeded hist: ring (the ring is internal, exactly as testDORoutes seeds it), and POST /replication/record
//    (the real DO route) for destination health. The read-only "metrics" bearer gates access: absent/wrong/
//    expired bearer -> 401; the minted bearer -> 200 with the expected content-type and body.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";
import { mintIngestCredential } from "../src/admin/support-ingest.ts";
import { escapeLabelValue, renderPrometheusMetrics, gatherMetricsState, handleMetricsRoute, MONITORING_SURFACES, type GatheredDownpipe } from "../src/admin/metrics.ts";
import type { RunHistoryEntry } from "../src/sched/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: new SchedulerDO(state) };
}

const OWNER_CALLER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
const OWNER_HEADER = encodeCaller(OWNER_CALLER);

function fetchDO(dobj: SchedulerDO, method: string, path: string, body?: unknown, header?: string): Promise<Response> {
  const url = `https://scheduler.internal${path}`;
  const headers: Record<string, string> = {
    ...(body !== undefined ? { "content-type": "application/json" } : {}),
    ...(header !== undefined ? { "x-downpipe-caller": header } : {}),
  };
  const init: RequestInit = { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
  return dobj.fetch(new Request(url, init));
}

// asStub adapts a real SchedulerDO test double to the DurableObjectStub shape gatherMetricsState/
// handleMetricsRoute expect (the production signature, matching schedulerStub(env)'s return type). The real
// platform bridges a stub's TWO-ARGUMENT fetch(url, init) call into the ONE-ARGUMENT Request the DO class's
// own fetch(req) handler expects; SchedulerDO.fetch (like every DO class) only implements the latter, so this
// wrapper does the SAME bridging fetchDO's Request-construction does, just on the production call shape
// (scheduler.fetch(doURL(path), init)) rather than the test helper's.
function asStub(dobj: SchedulerDO): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(input instanceof Request ? input : new Request(input as string, init)),
  } as unknown as DurableObjectStub;
}

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse("2026-07-05T12:00:00.000Z");

function iso(ms: number): string {
  return new Date(ms).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

// ---- escapeLabelValue -----------------------------------------------------------------------
function testEscapeLabelValue(): void {
  ok("escape: plain ASCII passes through unchanged", escapeLabelValue("Primary S3") === "Primary S3");
  ok("escape: backslash doubles", escapeLabelValue("C:\\backups") === "C:\\\\backups");
  ok("escape: double quote is backslash-escaped", escapeLabelValue('say "hi"') === 'say \\"hi\\"');
  ok("escape: newline becomes a literal \\n two-char escape", escapeLabelValue("line1\nline2") === "line1\\nline2");
  ok("escape: bare CR also becomes \\n (no raw line break survives)", escapeLabelValue("line1\rline2") === "line1\\nline2");
  ok("escape: CRLF collapses to one \\n, not two", escapeLabelValue("line1\r\nline2") === "line1\\nline2");
  // Order matters: backslash MUST be escaped first, or the backslash the quote/newline escapes introduce
  // would itself be re-escaped. A backslash immediately followed by a quote proves the order is correct.
  ok("escape: backslash-then-quote escapes cleanly (order-sensitive)", escapeLabelValue('a\\"b') === 'a\\\\\\"b');
  // A composite hostile value carrying all three special characters at once.
  const hostile = 'evil\\"} 1\nfake_metric{x="1';
  const escaped = escapeLabelValue(hostile);
  ok("escape: no raw quote survives in a composite hostile value", !/[^\\]"/.test(escaped) && !escaped.startsWith('"'));
  ok("escape: no raw newline survives in a composite hostile value", !escaped.includes("\n"));
}

// ---- renderPrometheusMetrics (pure) ----------------------------------------------------------
const CANONICAL_METRICS: Array<{ name: string; type: "gauge" | "counter" }> = [
  { name: "downpipe_backup_last_success_timestamp_seconds", type: "gauge" },
  { name: "downpipe_backup_success", type: "gauge" },
  { name: "downpipe_backup_recent_attempts", type: "gauge" },
  { name: "downpipe_backup_recent_successes", type: "gauge" },
  { name: "downpipe_backup_recent_failures", type: "gauge" },
  { name: "downpipe_backup_duration_seconds", type: "gauge" },
  { name: "downpipe_backup_size_bytes", type: "gauge" },
  { name: "downpipe_destination_healthy", type: "gauge" },
];

function testCanonicalHelpType(): void {
  const text = renderPrometheusMetrics([]);
  for (const m of CANONICAL_METRICS) {
    const helpCount = text.split("\n").filter((l) => l.startsWith(`# HELP ${m.name} `)).length;
    ok(`canonical: ${m.name} carries exactly one # HELP line`, helpCount === 1);
    ok(`canonical: ${m.name} carries a # TYPE line declaring ${m.type}`, text.includes(`# TYPE ${m.name} ${m.type}`));
  }
  // Even with zero downpipes the metric catalogue is still advertised (HELP/TYPE), just with no samples --
  // the standard exporter idiom -- and the body ends with a trailing newline (the exposition format
  // requirement). No sample line (anything that is not blank and not a #-comment) should be present.
  const sampleLines = text.split("\n").filter((l) => l !== "" && !l.startsWith("#"));
  ok("canonical: an empty fleet renders HELP/TYPE only, no sample lines", sampleLines.length === 0);
  ok("canonical: the body ends with a trailing newline", text.endsWith("\n"));
}

function testHostileNameInjectionSafety(): void {
  const hostile = 'Evil"} 1\nfake_metric{pwned="true';
  const ring: RunHistoryEntry[] = [{ runId: "r1", index: 1, startedAt: iso(NOW - DAY), status: "ok", bytes: 123 }];
  const dp: GatheredDownpipe = { id: "dp-evil", name: hostile, ring, dests: {} };
  const text = renderPrometheusMetrics([dp]);
  const lines = text.split("\n");
  ok("injection: exactly one real downpipe_backup_success sample line (no line injected)", lines.filter((l) => l.startsWith("downpipe_backup_success{")).length === 1);
  ok("injection: exactly one real downpipe_backup_last_success_timestamp_seconds sample line", lines.filter((l) => l.startsWith("downpipe_backup_last_success_timestamp_seconds{")).length === 1);
  ok("injection: no injected fake_metric line was created", !lines.some((l) => l.startsWith("fake_metric")));
  ok("injection: the hostile name appears only in its escaped form", text.includes(`downpipe_name="${escapeLabelValue(hostile)}"`));
  ok("injection: the raw hostile name (with a real newline) is not present verbatim", !text.includes(hostile));
}

function testHonestZeroOrAbsent(): void {
  // A fresh downpipe with NO runs at all: the timestamp/success/duration/size series must be ABSENT (never
  // a fabricated timestamp or an implied "ran instantly"); the bounded-window counters are an honest 0.
  const fresh: GatheredDownpipe = { id: "fresh", name: "Fresh", ring: [], dests: {} };
  // An in-flight-only downpipe (a run has started but never resolved): same absence, since latestResolved
  // finds nothing to report and no run has concluded to count in the attempt/success/failure totals.
  const inflightOnly: GatheredDownpipe = { id: "inflight", name: "InFlight", ring: [{ runId: "r0", index: 1, startedAt: iso(NOW), status: "in-flight" }], dests: {} };
  const text = renderPrometheusMetrics([fresh, inflightOnly]);
  const lines = text.split("\n");
  const sampleLine = (metric: string, id: string): string | undefined => lines.find((l) => l.startsWith(`${metric}{downpipe_id="${id}"`));

  for (const dp of [fresh, inflightOnly]) {
    ok(`honest: ${dp.id} omits downpipe_backup_last_success_timestamp_seconds (never a fabricated timestamp)`, sampleLine("downpipe_backup_last_success_timestamp_seconds", dp.id) === undefined);
    ok(`honest: ${dp.id} omits downpipe_backup_success (no resolved run yet)`, sampleLine("downpipe_backup_success", dp.id) === undefined);
    ok(`honest: ${dp.id} omits downpipe_backup_duration_seconds`, sampleLine("downpipe_backup_duration_seconds", dp.id) === undefined);
    ok(`honest: ${dp.id} omits downpipe_backup_size_bytes`, sampleLine("downpipe_backup_size_bytes", dp.id) === undefined);
    // The counters ARE an honest zero (the standard Prometheus counter idiom), not omitted.
    ok(`honest: ${dp.id} emits downpipe_backup_recent_attempts 0`, sampleLine("downpipe_backup_recent_attempts", dp.id)?.endsWith(" 0") === true);
    ok(`honest: ${dp.id} emits downpipe_backup_recent_successes 0`, sampleLine("downpipe_backup_recent_successes", dp.id)?.endsWith(" 0") === true);
    ok(`honest: ${dp.id} emits downpipe_backup_recent_failures 0`, sampleLine("downpipe_backup_recent_failures", dp.id)?.endsWith(" 0") === true);
  }
}

function testLatestOkVsLatestResolvedDiffer(): void {
  // newest-first ring: the LATEST run failed, but an earlier one succeeded. downpipe_backup_success must
  // reflect the latest (failed=0); the last-success timestamp + size must reflect the earlier OK run, not
  // the failed one and not an even-older ok run (the NEWEST ok, mirroring rtoInputs' own framing).
  const ring: RunHistoryEntry[] = [
    { runId: "r3", index: 3, startedAt: iso(NOW - DAY), status: "failed", error: "destination unreachable" },
    { runId: "r2", index: 2, startedAt: iso(NOW - 2 * DAY), status: "ok", bytes: 500, durationMs: 4000 },
    { runId: "r1", index: 1, startedAt: iso(NOW - 3 * DAY), status: "ok", bytes: 400, durationMs: 3000 },
  ];
  const dp: GatheredDownpipe = { id: "dp1", name: "Primary", ring, dests: {} };
  const text = renderPrometheusMetrics([dp]);
  ok("latest-ok: last-success timestamp is the EARLIER ok run (r2), not r1 or the failed r3", text.includes(`downpipe_backup_last_success_timestamp_seconds{downpipe_id="dp1",downpipe_name="Primary"} ${Math.floor((NOW - 2 * DAY + 4000) / 1000)}`));
  ok("latest-ok: size reflects the same r2 run's bytes (500), not r1's 400", text.includes(`downpipe_backup_size_bytes{downpipe_id="dp1",downpipe_name="Primary"} 500`));
  ok("latest-resolved: success gauge reflects the LATEST run (r3, failed) -> 0", text.includes('downpipe_backup_success{downpipe_id="dp1",downpipe_name="Primary"} 0'));
  ok("latest-resolved: r3 (the latest, failed) carries no durationMs, so duration is honestly absent (not r2's stale 4s)", !text.includes('downpipe_backup_duration_seconds{downpipe_id="dp1"'));
  ok("counters: attempt=3, success=2, failure=1", text.includes('downpipe_backup_recent_attempts{downpipe_id="dp1",downpipe_name="Primary"} 3') && text.includes('downpipe_backup_recent_successes{downpipe_id="dp1",downpipe_name="Primary"} 2') && text.includes('downpipe_backup_recent_failures{downpipe_id="dp1",downpipe_name="Primary"} 1'));
}

function testAbandonedCountsAsFailure(): void {
  const ring: RunHistoryEntry[] = [{ runId: "r1", index: 1, startedAt: iso(NOW), status: "abandoned", error: "abandoned (run lease expired)" }];
  const dp: GatheredDownpipe = { id: "dp2", name: "Reclaimed", ring, dests: {} };
  const text = renderPrometheusMetrics([dp]);
  ok("abandoned: counts toward recent-attempts and recent-failures, not recent-successes", text.includes('downpipe_backup_recent_attempts{downpipe_id="dp2",downpipe_name="Reclaimed"} 1') && text.includes('downpipe_backup_recent_failures{downpipe_id="dp2",downpipe_name="Reclaimed"} 1') && text.includes('downpipe_backup_recent_successes{downpipe_id="dp2",downpipe_name="Reclaimed"} 0'));
  ok("abandoned: downpipe_backup_success reads 0 (an abandoned run is not a success)", text.includes('downpipe_backup_success{downpipe_id="dp2",downpipe_name="Reclaimed"} 0'));
}

function testDestinationHealthy(): void {
  const dp: GatheredDownpipe = {
    id: "dp3",
    name: "Fanout",
    ring: [],
    dests: {
      "dest-a": { holdsRunId: "r9", holdsIndex: 9, lastOk: true, lastAttemptAt: NOW },
      "dest-b": { holdsRunId: "r7", holdsIndex: 7, lastOk: false, lastAttemptAt: NOW, reason: "unreachable" },
    },
  };
  const text = renderPrometheusMetrics([dp]);
  ok("dest-healthy: a healthy destination reads 1", text.includes('downpipe_destination_healthy{downpipe_id="dp3",downpipe_name="Fanout",destination="dest-a"} 1'));
  ok("dest-healthy: an unhealthy destination reads 0", text.includes('downpipe_destination_healthy{downpipe_id="dp3",downpipe_name="Fanout",destination="dest-b"} 0'));
  // A downpipe with NO replication state at all (the implicit-default-destination case; the DO records
  // nothing there by design) must emit no destination_healthy series -- honestly absent, never fabricated.
  const noRepl: GatheredDownpipe = { id: "dp4", name: "DefaultOnly", ring: [], dests: {} };
  const text2 = renderPrometheusMetrics([noRepl]);
  ok("dest-healthy: a downpipe with no tracked replication state emits no series for it", !text2.includes('downpipe_destination_healthy{downpipe_id="dp4"'));
}

// ---- DO routes (mirrors validate-reports.ts's testDORoutes: fetchDO against a REAL SchedulerDO, no
// globalThis.fetch stub) ------------------------------------------------------------------------
async function testGatherMetricsState(): Promise<void> {
  const { stub, storage } = makeScheduler();
  await fetchDO(stub, "POST", "/downpipes", { id: "dp1", name: "Primary", cadenceSeconds: 86400, enabled: true, source: { type: "kv", binding: "KV_dp1", include: [], exclude: [] } }, OWNER_HEADER);
  await fetchDO(stub, "POST", "/downpipes", { id: "dp2", name: "Secondary", cadenceSeconds: 3600, enabled: true, source: { type: "r2", binding: "R2_dp2", include: [], exclude: [] } }, OWNER_HEADER);
  // Seed dp1's run-history ring directly (internal storage key, exactly as testDORoutes seeds it) with two
  // ok runs and a trailing failure (newest-last, as stored; the DO's history() route reverses it).
  storage.rawPut("hist:dp1", [
    { runId: "r1", index: 1, startedAt: iso(NOW - 3 * DAY), status: "ok", bytes: 1000, durationMs: 5000 },
    { runId: "r2", index: 2, startedAt: iso(NOW - 2 * DAY), status: "ok", bytes: 2000, durationMs: 6000 },
    { runId: "r3", index: 3, startedAt: iso(NOW - DAY), status: "failed" },
  ]);
  // dp2 has never run (no hist: key at all).
  // Record replication state for dp1 through the REAL DO route (not a raw storage seed): one destination
  // proven healthy at run 2.
  await fetchDO(stub, "POST", "/replication/record", { id: "dp1", destinationId: "s3-primary", ok: true, runId: "r2", index: 2 });

  const gathered = await gatherMetricsState(asStub(stub));
  ok("gather: returns one entry per configured downpipe", gathered.length === 2);
  const dp1 = gathered.find((d) => d.id === "dp1");
  const dp2 = gathered.find((d) => d.id === "dp2");
  ok("gather: dp1 carries its name + the newest-first ring from GET /history", dp1?.name === "Primary" && dp1?.ring.length === 3 && dp1?.ring[0]?.runId === "r3");
  ok("gather: dp1 carries its replication map from GET /replication", dp1?.dests["s3-primary"]?.lastOk === true);
  ok("gather: dp2 (never run) has an empty ring and an empty replication map, not a throw", dp2?.ring.length === 0 && Object.keys(dp2?.dests ?? { x: 1 }).length === 0);

  const text = renderPrometheusMetrics(gathered);
  ok("gather+render: dp1's last success is r2 (the newest ok run, not r1)", text.includes(`downpipe_backup_last_success_timestamp_seconds{downpipe_id="dp1",downpipe_name="Primary"} ${Math.floor((Date.parse(iso(NOW - 2 * DAY)) + 6000) / 1000)}`));
  ok("gather+render: dp1's destination is healthy per the recorded replication state", text.includes('downpipe_destination_healthy{downpipe_id="dp1",downpipe_name="Primary",destination="s3-primary"} 1'));
  ok("gather+render: dp2 (never run) omits the timestamp/success series but has honest-zero counters", !text.includes('downpipe_backup_success{downpipe_id="dp2"') && text.includes('downpipe_backup_recent_attempts{downpipe_id="dp2",downpipe_name="Secondary"} 0'));
}

// ---- handleMetricsRoute: content-type + auth gating -------------------------------------------
async function testHandleMetricsRouteAuthGating(): Promise<void> {
  const { stub } = makeScheduler();
  await fetchDO(stub, "POST", "/downpipes", { id: "dp1", name: "Primary", cadenceSeconds: 86400, enabled: true, source: { type: "kv", binding: "KV_dp1", include: [], exclude: [] } }, OWNER_HEADER);

  const metricsUrl = "https://engine.internal/metrics";
  {
    const resp = await handleMetricsRoute(new Request(metricsUrl), asStub(stub));
    ok("auth: no Authorization header -> 401", resp.status === 401);
  }
  {
    const resp = await handleMetricsRoute(new Request(metricsUrl, { headers: { authorization: "Bearer dpc_nope.dps_wrong" } }), asStub(stub));
    ok("auth: an unrecognised bearer -> 401 (no grant exists yet)", resp.status === 401);
  }
  {
    const resp = await handleMetricsRoute(new Request(metricsUrl, { method: "POST" }), asStub(stub));
    ok("auth: POST /metrics -> 404 (GET-only surface)", resp.status === 404);
  }

  // Mint a "metrics" scope credential (the third IngestScope) and store it via the SAME DO route the
  // diagnostics/audit-feed scopes use, then present its bearer.
  const minted = await mintIngestCredential("metrics", "owner@example.com.au", undefined);
  await fetchDO(stub, "POST", "/ingest-credential/set", { scope: "metrics", grant: minted.grant }, OWNER_HEADER);
  const bearer = `${minted.clientId}.${minted.secret}`;
  {
    const resp = await handleMetricsRoute(new Request(metricsUrl, { headers: { authorization: `Bearer ${bearer}` } }), asStub(stub));
    ok("auth: the minted metrics bearer -> 200", resp.status === 200);
    ok("content-type: text/plain; version=0.0.4; charset=utf-8", resp.headers.get("content-type") === "text/plain; version=0.0.4; charset=utf-8");
    const text = await resp.text();
    ok("body: carries the HELP/TYPE preamble for the canonical metric set", CANONICAL_METRICS.every((m) => text.includes(`# TYPE ${m.name} ${m.type}`)));
    ok("body: carries dp1's series", text.includes('downpipe_id="dp1"'));
  }
  {
    // A wrong secret against the RIGHT clientId must still fail (constant-time compare, not a clientId-only check).
    const resp = await handleMetricsRoute(new Request(metricsUrl, { headers: { authorization: `Bearer ${minted.clientId}.dps_totallywrong` } }), asStub(stub));
    ok("auth: right clientId + wrong secret -> 401", resp.status === 401);
  }

  // A pull is recorded on the grant (best-effort, fire-and-forget from handleMetricsRoute); by the time this
  // next await resolves, the microtask has had its chance to land.
  const after = await fetchDO(stub, "GET", "/ingest-credential?scope=metrics");
  const { grant } = (await after.json()) as { grant: { pulls?: Array<{ at: string }> } | null };
  ok("pull trail: the successful scrape is recorded on the grant", (grant?.pulls?.length ?? 0) >= 1);

  // An EXPIRED grant must be refused even with the right secret (server-side expiry, not just presence).
  const expired = await mintIngestCredential("metrics", "owner@example.com.au", 60);
  expired.grant.expiresAt = new Date(NOW - DAY).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
  await fetchDO(stub, "POST", "/ingest-credential/set", { scope: "metrics", grant: expired.grant }, OWNER_HEADER);
  {
    const resp = await handleMetricsRoute(new Request(metricsUrl, { headers: { authorization: `Bearer ${expired.clientId}.${expired.secret}` } }), asStub(stub));
    ok("auth: an expired metrics grant -> 401 even with the correct secret", resp.status === 401);
  }
}

// ---- the coverage-map hook (MONITORING_SURFACES) -----------------------------------------------
function testMonitoringSurfacesExported(): void {
  ok("coverage: MONITORING_SURFACES names the metrics surface (parsed externally by a coverage-map script)", Array.isArray(MONITORING_SURFACES) && MONITORING_SURFACES.includes("metrics"));
}

async function main(): Promise<void> {
  console.log("escapeLabelValue:");
  testEscapeLabelValue();
  console.log("renderPrometheusMetrics (pure):");
  testCanonicalHelpType();
  testHostileNameInjectionSafety();
  testHonestZeroOrAbsent();
  testLatestOkVsLatestResolvedDiffer();
  testAbandonedCountsAsFailure();
  testDestinationHealthy();
  console.log("gatherMetricsState (DO routes):");
  await testGatherMetricsState();
  console.log("handleMetricsRoute (auth gating + content-type):");
  await testHandleMetricsRouteAuthGating();
  console.log("chaos coverage-map hook:");
  testMonitoringSurfacesExported();

  console.log(failures === 0 ? "\nMETRICS VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
