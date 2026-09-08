// Validates the OTLP/HTTP metrics push feature's PURE + drain-internal logic: the OTLP ResourceMetrics JSON builder (envelope correctness, the canonical metric names, injection
// safety, the batch cap, the no-custody field allow-list), the bespoke egress-secure sender (send-time SSRF
// re-screen, the header carries the secret and the body NEVER does), the sealed-secret round-trip + 4-way
// AAD domain separation (an OTLP push ciphertext must not decrypt under the destination/SIEM-header/SIEM-s3
// AADs, and vice versa), the DO's KEEP-SECRET + straggler-guard + bounded trail, the metrics-snapshot READ
// (otlpMetricsSnapshot's derivation off the run-history/replication state, deliberately NOT recomputing any
// staleness/freshness judgement), and the full cron drain pass end to end (runOtlpPushPass) against a fake
// scheduler + a mocked fetch. No network. Run:
//   node test/validate-otlp-push.ts

import {
  buildOtlpResourceMetrics,
  buildOtlpResourceMetricsChunks,
  OTLP_PUSH_CHUNK_DOWNPIPES,
  OTLP_PUSH_DOWNPIPE_CAP,
  OTLP_METRIC_LAST_SUCCESS,
  OTLP_METRIC_SUCCESS,
  OTLP_METRIC_RECENT_ATTEMPTS,
  OTLP_METRIC_RECENT_SUCCESSES,
  OTLP_METRIC_RECENT_FAILURES,
  OTLP_METRIC_DURATION,
  OTLP_METRIC_SIZE_BYTES,
  OTLP_METRIC_DEST_HEALTHY,
  OTLP_METRIC_ENABLED,
  type OtlpDownpipeMetrics,
} from "../src/cron/otlp-push-shape.ts";
import { runOtlpPushPass, fetchOtlpPushConfig, deliverResolvedOtlpPush, type ResolvedOtlpPushConfig } from "../src/cron/otlp-push-pass.ts";
import { deliverOtlpPush } from "../src/notify/otlp-push-sender.ts";
import { runTimestampSeconds, runSizeBytes } from "../src/sched/scheduler-do-otlp-push.ts";
import {
  wrapConfigSecret,
  unwrapConfigSecret,
  resolveConfigSecret,
  maybeWrapConfigSecret,
  OTLP_PUSH_SECRET_AAD,
  PUSH_SECRET_AAD,
  PUSH_S3_SECRET_AAD,
  type WrappedSecret,
} from "../src/admin/config-secret.ts";
import type { DestReplState, RunHistoryEntry } from "../src/sched/scheduler-do-base.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}
async function throwsAsync(label: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
    ok(label, false);
  } catch {
    ok(label, true);
  }
}

// ---- fixtures -------------------------------------------------------------------------------------------
function fakeDownpipeMetrics(id: string, overrides: Partial<OtlpDownpipeMetrics> = {}): OtlpDownpipeMetrics {
  return {
    id,
    name: `Downpipe ${id}`,
    enabled: true,
    lastSuccessTimestampSeconds: 1_700_000_000,
    backupSuccess: 1,
    attemptsTotal: 5,
    successTotal: 4,
    failureTotal: 1,
    durationSeconds: 12.5,
    sizeBytes: 4096,
    destinations: [{ id: "dest-1", healthy: true }],
    ...overrides,
  };
}

function fakeRunHistoryEntry(index: number, overrides: Partial<RunHistoryEntry> = {}): RunHistoryEntry {
  return {
    runId: `run-${index}`,
    index,
    startedAt: new Date(1_700_000_000_000 + index * 60_000).toISOString(),
    status: "ok",
    ...overrides,
  };
}

import { MockStorage } from "./mock-storage.ts";

const OWNER_CALLER = { method: "token" as const, email: null, subject: null, groups: [] };

// otlpJsonKeyAllowList is the CLOSED set of JSON object keys the OTLP ResourceMetrics body may EVER contain
// (the OTLP schema's own field names plus our label names), for the no-custody structural check below: a
// crafted downpipe name or a future careless edit could otherwise smuggle an extra field into the payload
// (a customer id, a secret, a free-form note) without any single assertion catching it.
const OTLP_JSON_KEY_ALLOWLIST = new Set([
  "resourceMetrics",
  "resource",
  "attributes",
  "key",
  "value",
  "stringValue",
  "scopeMetrics",
  "scope",
  "name",
  "version",
  "metrics",
  "description",
  "unit",
  "gauge",
  "dataPoints",
  "timeUnixNano",
  "asDouble",
]);

function collectKeys(v: unknown, out: Set<string>): void {
  if (Array.isArray(v)) {
    for (const e of v) collectKeys(e, out);
  } else if (v !== null && typeof v === "object") {
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      out.add(k);
      collectKeys(val, out);
    }
  }
}

async function main(): Promise<void> {
  console.log("shape: OTLP ResourceMetrics envelope correctness");
  {
    // dp-b models a downpipe with NO run data yet: the optional run fields are ABSENT (not explicit
    // undefined, which exactOptionalPropertyTypes forbids on a Partial), so the shaper omits their series.
    const dpB = fakeDownpipeMetrics("dp-b", { destinations: [] });
    delete dpB.lastSuccessTimestampSeconds;
    delete dpB.backupSuccess;
    delete dpB.durationSeconds;
    delete dpB.sizeBytes;
    const dps = [fakeDownpipeMetrics("dp-a", { destinations: [{ id: "dest-1", healthy: true }, { id: "dest-2", healthy: false }] }), dpB];
    const nowMs = 1_720_000_000_000;
    const shaped = buildOtlpResourceMetrics(dps, nowMs);
    ok("content-type is application/json", shaped.contentType === "application/json");
    const doc = JSON.parse(shaped.body) as {
      resourceMetrics: Array<{
        resource: { attributes: Array<{ key: string; value: { stringValue: string } }> };
        scopeMetrics: Array<{ scope: { name: string; version: string }; metrics: Array<{ name: string; description: string; unit: string; gauge: { dataPoints: Array<{ attributes: Array<{ key: string; value: { stringValue: string } }>; timeUnixNano: string; asDouble: number }> } }> }>;
      }>;
    };
    ok("exactly one ResourceMetrics entry", doc.resourceMetrics.length === 1);
    const rm = doc.resourceMetrics[0]!;
    const resourceAttrs = new Map(rm.resource.attributes.map((a) => [a.key, a.value.stringValue]));
    ok("resource carries service.name/service.version", resourceAttrs.get("service.name") === "downpipes-engine" && typeof resourceAttrs.get("service.version") === "string");
    ok("exactly one ScopeMetrics entry", rm.scopeMetrics.length === 1);
    const sm = rm.scopeMetrics[0]!;
    ok("scope names the OTLP push instrumentation", sm.scope.name === "downpipes.otlp-push" && typeof sm.scope.version === "string");
    const byName = new Map(sm.metrics.map((m) => [m.name, m]));
    const expectedNames = [
      OTLP_METRIC_LAST_SUCCESS,
      OTLP_METRIC_SUCCESS,
      OTLP_METRIC_RECENT_ATTEMPTS,
      OTLP_METRIC_RECENT_SUCCESSES,
      OTLP_METRIC_RECENT_FAILURES,
      OTLP_METRIC_DURATION,
      OTLP_METRIC_SIZE_BYTES,
      OTLP_METRIC_DEST_HEALTHY,
      OTLP_METRIC_ENABLED,
    ];
    ok("every canonical metric name is present", expectedNames.every((n) => byName.has(n)));
    ok("metric names match the exact canonical set (Velero/restic/pgBackRest/Kasten-converged)", OTLP_METRIC_LAST_SUCCESS === "downpipe_backup_last_success_timestamp_seconds" && OTLP_METRIC_SUCCESS === "downpipe_backup_success" && OTLP_METRIC_DEST_HEALTHY === "downpipe_destination_healthy");
    // F4: the windowed counts are honest GAUGE names WITHOUT a _total suffix (a _total name invites rate()/
    // increase(), which breaks with a phantom reset when the run-history ring evicts a run). Match the sibling
    // /metrics endpoint (mon-metrics).
    ok("F4: the windowed counts are named recent_* (NOT _total, which would invite rate() over a non-monotonic gauge)", OTLP_METRIC_RECENT_ATTEMPTS === "downpipe_backup_recent_attempts" && OTLP_METRIC_RECENT_SUCCESSES === "downpipe_backup_recent_successes" && OTLP_METRIC_RECENT_FAILURES === "downpipe_backup_recent_failures");
    ok("F4: no metric carries a _total suffix (they are windowed gauges, not lifetime counters)", [...byName.keys()].every((n) => !n.endsWith("_total")));
    ok("F4: the recent_* HELP text states they are windowed gauges, NOT lifetime counters", /windowed gauge/i.test(byName.get(OTLP_METRIC_RECENT_ATTEMPTS)!.description) && /NOT a lifetime counter/i.test(byName.get(OTLP_METRIC_RECENT_ATTEMPTS)!.description));
    for (const m of byName.values()) {
      ok(`${m.name}: every metric is a gauge (windowed counts are honestly non-monotonic, see otlp-push-shape.ts)`, "gauge" in m && Array.isArray(m.gauge.dataPoints));
      ok(`${m.name}: carries a unit and a description`, typeof m.unit === "string" && m.unit.length > 0 && typeof m.description === "string" && m.description.length > 0);
    }
    // dp-a has 2 destinations, dp-b has 0 -> downpipe_destination_healthy carries exactly 2 data points.
    ok("downpipe_destination_healthy has one data point per configured destination", byName.get(OTLP_METRIC_DEST_HEALTHY)!.gauge.dataPoints.length === 2);
    ok("downpipe_backup_recent_attempts has one data point per downpipe (always present, even at 0)", byName.get(OTLP_METRIC_RECENT_ATTEMPTS)!.gauge.dataPoints.length === 2);
    // F4a: downpipe_enabled is present for EVERY downpipe (both dp-a enabled + dp-b enabled here).
    ok("F4a: downpipe_enabled is present for every downpipe (a decommissioned job is distinguishable from a live one)", byName.get(OTLP_METRIC_ENABLED)!.gauge.dataPoints.length === 2 && byName.get(OTLP_METRIC_ENABLED)!.gauge.dataPoints.every((p) => p.asDouble === 1));
    // dp-b omitted lastSuccessTimestampSeconds/backupSuccess/durationSeconds/sizeBytes -> only dp-a contributes.
    ok("downpipe_backup_last_success_timestamp_seconds omits a downpipe with no recorded success", byName.get(OTLP_METRIC_LAST_SUCCESS)!.gauge.dataPoints.length === 1);
    ok("downpipe_backup_success omits a downpipe with no resolved run", byName.get(OTLP_METRIC_SUCCESS)!.gauge.dataPoints.length === 1);
    ok("downpipe_backup_duration_seconds omits a downpipe with no resolved run", byName.get(OTLP_METRIC_DURATION)!.gauge.dataPoints.length === 1);
    ok("downpipe_backup_size_bytes omits a downpipe with no recorded size", byName.get(OTLP_METRIC_SIZE_BYTES)!.gauge.dataPoints.length === 1);

    const dpADataPoint = byName.get(OTLP_METRIC_RECENT_ATTEMPTS)!.gauge.dataPoints.find((p) => p.attributes.some((a) => a.value.stringValue === "dp-a"))!;
    const dpALabels = new Map(dpADataPoint.attributes.map((a) => [a.key, a.value.stringValue]));
    ok("labelled by downpipe_id + downpipe_name", dpALabels.get("downpipe_id") === "dp-a" && dpALabels.get("downpipe_name") === "Downpipe dp-a");
    const destPoint = byName.get(OTLP_METRIC_DEST_HEALTHY)!.gauge.dataPoints.find((p) => p.attributes.some((a) => a.value.stringValue === "dest-2"))!;
    const destLabels = new Map(destPoint.attributes.map((a) => [a.key, a.value.stringValue]));
    ok("downpipe_destination_healthy is ALSO labelled by destination_id", destLabels.get("downpipe_id") === "dp-a" && destLabels.get("destination_id") === "dest-2");
    ok("dest-2 (healthy:false) reports asDouble 0", destPoint.asDouble === 0);
    const dest1Point = byName.get(OTLP_METRIC_DEST_HEALTHY)!.gauge.dataPoints.find((p) => p.attributes.some((a) => a.value.stringValue === "dest-1"))!;
    ok("dest-1 (healthy:true) reports asDouble 1", dest1Point.asDouble === 1);

    ok("timeUnixNano is a STRING (uint64 proto-JSON mapping, never a float that would lose precision)", typeof dpADataPoint.timeUnixNano === "string");
    ok("timeUnixNano is exactly nowMs * 1e6 in nanoseconds, computed via BigInt (no float precision loss)", dpADataPoint.timeUnixNano === `${BigInt(nowMs) * 1_000_000n}`);
    ok("asDouble carries the numeric value (attemptsTotal 5)", dpADataPoint.asDouble === 5);

    // F3 accounting: a non-truncated snapshot reports the ACTUAL shaped count and no truncation.
    ok("F3: a within-cap snapshot reports downpipeCount === the input length and truncated:false", shaped.downpipeCount === 2 && shaped.truncated === false && shaped.droppedCount === 0);
  }

  console.log("\nshape: downpipe_enabled reflects a paused/decommissioned downpipe as 0 (F4a)");
  {
    type Pt = { attributes: Array<{ key: string; value: { stringValue: string } }>; asDouble: number };
    type Doc = { resourceMetrics: Array<{ scopeMetrics: Array<{ metrics: Array<{ name: string; gauge: { dataPoints: Pt[] } }> }> }> };
    const shaped = buildOtlpResourceMetrics([fakeDownpipeMetrics("live", { enabled: true }), fakeDownpipeMetrics("paused", { enabled: false })], Date.now());
    const metrics = (JSON.parse(shaped.body) as Doc).resourceMetrics[0]!.scopeMetrics[0]!.metrics;
    const enabledPts = metrics.find((m) => m.name === OTLP_METRIC_ENABLED)!.gauge.dataPoints;
    const byDp = new Map(enabledPts.map((p) => [p.attributes.find((a) => a.key === "downpipe_id")!.value.stringValue, p.asDouble]));
    ok("F4a: a live downpipe reports downpipe_enabled 1, a paused one reports 0", byDp.get("live") === 1 && byDp.get("paused") === 0);
  }

  console.log("\nshape: an all-empty snapshot omits every metric (no metric ships with zero data points)");
  {
    const shaped = buildOtlpResourceMetrics([], Date.now());
    const doc = JSON.parse(shaped.body) as { resourceMetrics: Array<{ scopeMetrics: Array<{ metrics: unknown[] }> }> };
    ok("zero downpipes -> zero metrics (every series would be empty)", doc.resourceMetrics[0]!.scopeMetrics[0]!.metrics.length === 0);
    ok("still exactly one ResourceMetrics/ScopeMetrics envelope even with nothing to report", doc.resourceMetrics.length === 1 && doc.resourceMetrics[0]!.scopeMetrics.length === 1);
    ok("F3: an empty snapshot reports downpipeCount 0, truncated false", shaped.downpipeCount === 0 && shaped.truncated === false && shaped.droppedCount === 0);
  }

  console.log("\nshape: batch cap covers the known 2500-fleet scale (ENG-SCALE-08) and TRUNCATES HONESTLY beyond it (F3)");
  {
    // F3: the cap sits well above the engine's known large-fleet scale (validate-fleet-scale.ts's 2500), so a
    // realistic fleet is NEVER silently truncated.
    ok("F3: OTLP_PUSH_DOWNPIPE_CAP covers the known 2500-fleet scale with margin (ENG-SCALE-08)", OTLP_PUSH_DOWNPIPE_CAP >= 5000);
    const overCap = OTLP_PUSH_DOWNPIPE_CAP + 25;
    const many = Array.from({ length: overCap }, (_, i) => fakeDownpipeMetrics(`dp-${i}`));
    const shaped = buildOtlpResourceMetrics(many, Date.now());
    const doc = JSON.parse(shaped.body) as { resourceMetrics: Array<{ scopeMetrics: Array<{ metrics: Array<{ name: string; gauge: { dataPoints: unknown[] } }> }> }> };
    const attemptMetric = doc.resourceMetrics[0]!.scopeMetrics[0]!.metrics.find((m) => m.name === OTLP_METRIC_RECENT_ATTEMPTS)!;
    ok("caps at OTLP_PUSH_DOWNPIPE_CAP even when handed more downpipes", attemptMetric.gauge.dataPoints.length === OTLP_PUSH_DOWNPIPE_CAP);
    // F3: the OVER-CAP case surfaces the truncation explicitly (never a silent drop) -- the shaped count is the
    // cap, truncated is true, and the dropped count is exact.
    ok("F3: an over-cap snapshot reports downpipeCount === cap (the ACTUAL shaped count, never the pre-cap input length)", shaped.downpipeCount === OTLP_PUSH_DOWNPIPE_CAP);
    ok("F3: an over-cap snapshot flags truncated:true with the exact dropped count (never a silent partial)", shaped.truncated === true && shaped.droppedCount === 25);
    // A realistic worst-case byte-size sanity check: a FULL 2500-fleet with generous label sizes still
    // serialises well under a typical OTLP collector's request-size budget (a wide margin, not the cap).
    const fleet2500 = Array.from({ length: 2500 }, (_, i) =>
      fakeDownpipeMetrics(`dp-${"x".repeat(40)}-${i}`, { name: "N".repeat(60), destinations: [{ id: "dest-1", healthy: true }, { id: "dest-2", healthy: false }] }),
    );
    const fleetBody = buildOtlpResourceMetrics(fleet2500, Date.now()).body;
    ok(`F3: a full 2500-fleet snapshot serialises under 10 MB (got ${fleetBody.length} bytes) -- a single POST covers the known scale`, fleetBody.length < 10_000_000);
  }

  console.log("\nshape: buildOtlpResourceMetricsChunks (item 4) -- a large fleet splits into conservative, independently-sized chunks, never one oversized body");
  {
    // At the engine's known large-fleet scale (2500, ENG-SCALE-08) with generous label sizes, EVERY chunk
    // must stay well clear of a vendor's OTLP/HTTP request-size cap (New Relic's ~1 MB, the tightest target).
    const fleet2500 = Array.from({ length: 2500 }, (_, i) =>
      fakeDownpipeMetrics(`dp-${"x".repeat(40)}-${i}`, { name: "N".repeat(60), destinations: [{ id: "dest-1", healthy: true }, { id: "dest-2", healthy: false }] }),
    );
    const chunks = buildOtlpResourceMetricsChunks(fleet2500, Date.now());
    const expectedChunks = Math.ceil(2500 / OTLP_PUSH_CHUNK_DOWNPIPES);
    ok(`2500 downpipes split into ceil(2500/${OTLP_PUSH_CHUNK_DOWNPIPES}) = ${expectedChunks} chunks`, chunks.length === expectedChunks);
    ok("every chunk but (possibly) the last carries exactly OTLP_PUSH_CHUNK_DOWNPIPES downpipes", chunks.slice(0, -1).every((c) => c.downpipeCount === OTLP_PUSH_CHUNK_DOWNPIPES));
    ok("the downpipe counts across every chunk sum to the total (none dropped, none duplicated)", chunks.reduce((n, c) => n + c.downpipeCount, 0) === 2500);
    ok(`every chunk's body stays under 1 MB (New Relic's cap; largest was ${Math.max(...chunks.map((c) => c.body.length))} bytes)`, chunks.every((c) => c.body.length < 1_000_000));
    ok("every chunk is independently valid JSON with exactly its own downpipes' data points", chunks.every((c) => {
      const doc = JSON.parse(c.body) as { resourceMetrics: Array<{ scopeMetrics: Array<{ metrics: Array<{ name: string; gauge: { dataPoints: unknown[] } }> }> }> };
      const attempts = doc.resourceMetrics[0]!.scopeMetrics[0]!.metrics.find((m) => m.name === OTLP_METRIC_RECENT_ATTEMPTS);
      return attempts !== undefined && attempts.gauge.dataPoints.length === c.downpipeCount;
    }));
    ok("no chunk is flagged truncated (2500 is well under the cap)", chunks.every((c) => c.truncated === false && c.droppedCount === 0));

    // Over-cap: the whole-snapshot truncation accounting is carried on EVERY chunk (never just the first
    // or a separate summary), so any one chunk's result already tells the reader the snapshot was truncated.
    const overCap = OTLP_PUSH_DOWNPIPE_CAP + 40;
    const overChunks = buildOtlpResourceMetricsChunks(Array.from({ length: overCap }, (_, i) => fakeDownpipeMetrics(`dp-${i}`)), Date.now());
    ok("over-cap: every chunk (not just the first) is flagged truncated:true with the exact dropped count", overChunks.every((c) => c.truncated === true && c.droppedCount === 40));
    ok("over-cap: the downpipe counts across every chunk sum to the CAP, never the pre-cap length", overChunks.reduce((n, c) => n + c.downpipeCount, 0) === OTLP_PUSH_DOWNPIPE_CAP);

    // A tiny fleet (well under one chunk) is still exactly one chunk, unchanged from the pre-chunking shape.
    const small = buildOtlpResourceMetricsChunks([fakeDownpipeMetrics("dp-a"), fakeDownpipeMetrics("dp-b")], Date.now());
    ok("a small fleet (under one chunk) yields exactly one chunk", small.length === 1 && small[0]?.downpipeCount === 2);

    // Zero downpipes still yields exactly one (empty) chunk, mirroring buildOtlpResourceMetrics's own
    // always-post-a-heartbeat-body behaviour rather than sending nothing.
    const empty = buildOtlpResourceMetricsChunks([], Date.now());
    ok("zero downpipes still yields exactly one empty chunk (a heartbeat body, never zero requests)", empty.length === 1 && empty[0]?.downpipeCount === 0);
  }

  console.log("\nINJECTION SAFETY: a crafted downpipe/destination name cannot break the JSON structure or forge an extra field");
  {
    const evilName = 'attacker","extra":{"pwned":true},"x":"\\ninjected\r\nCEF:0|forged"';
    const evil = fakeDownpipeMetrics("dp-evil", { name: evilName, destinations: [{ id: 'd"};{"pwn":1', healthy: true }] });
    const shaped = buildOtlpResourceMetrics([evil], Date.now());
    // JSON.parse succeeding at all proves the crafted value never broke out of its string slot.
    let parsed: unknown;
    let parseOk = true;
    try {
      parsed = JSON.parse(shaped.body);
    } catch {
      parseOk = false;
    }
    ok("a crafted name/id round-trips as valid JSON (never breaks the structure)", parseOk);
    const doc = parsed as { resourceMetrics: Array<{ scopeMetrics: Array<{ metrics: Array<{ name: string; gauge: { dataPoints: Array<{ attributes: Array<{ key: string; value: { stringValue: string } }> }> } }> }> }> };
    const metrics = doc.resourceMetrics[0]!.scopeMetrics[0]!.metrics;
    ok("no extra metric was forged (exactly the metrics this one downpipe's data actually populates)", metrics.every((m) => m.gauge.dataPoints.length === 1 || m.name === OTLP_METRIC_DEST_HEALTHY));
    const attemptPoint = metrics.find((m) => m.name === OTLP_METRIC_RECENT_ATTEMPTS)!.gauge.dataPoints[0]!;
    const nameLabel = attemptPoint.attributes.find((a) => a.key === "downpipe_name")!.value.stringValue;
    ok("the crafted name round-trips EXACTLY (JSON structurally escapes it, never truncated or split)", nameLabel === evilName);
  }

  console.log("\nno-custody envelope: the OTLP body carries ONLY the OTLP schema fields + our label names, never a stray field");
  {
    const dps = [fakeDownpipeMetrics("dp-a"), fakeDownpipeMetrics("dp-b", { destinations: [{ id: "dest-9", healthy: false }] })];
    const shaped = buildOtlpResourceMetrics(dps, Date.now());
    const keys = new Set<string>();
    collectKeys(JSON.parse(shaped.body), keys);
    const unexpected = [...keys].filter((k) => !OTLP_JSON_KEY_ALLOWLIST.has(k));
    ok(`no key outside the closed OTLP-schema allow-list appears (found: ${unexpected.join(", ") || "none"})`, unexpected.length === 0);
  }

  console.log("\nrunTimestampSeconds / runSizeBytes: pure per-run derivation helpers (no freshness/staleness judgement)");
  {
    const withDuration = fakeRunHistoryEntry(1, { durationMs: 30_000 });
    ok("runTimestampSeconds anchors on startedAt + durationMs when duration is known", runTimestampSeconds(withDuration) === (Date.parse(withDuration.startedAt) + 30_000) / 1000);
    const noDuration = fakeRunHistoryEntry(2);
    ok("runTimestampSeconds falls back to startedAt alone when durationMs is absent", runTimestampSeconds(noDuration) === Date.parse(noDuration.startedAt) / 1000);
    const malformed = { startedAt: "not-a-date" };
    ok("runTimestampSeconds falls back to Date.now() on a malformed ts (never NaN)", Number.isFinite(runTimestampSeconds(malformed)));

    ok("runSizeBytes is undefined for an undefined entry (no resolved run yet)", runSizeBytes(undefined) === undefined);
    ok("runSizeBytes PREFERS archiveBytesWritten (the stored bytes) over bytes (the plaintext size)", runSizeBytes({ archiveBytesWritten: 111, bytes: 222 }) === 111);
    ok("runSizeBytes falls back to bytes when archiveBytesWritten is absent (an older row)", runSizeBytes({ bytes: 222 }) === 222);
    ok("runSizeBytes is undefined when neither field was ever recorded (a legacy row)", runSizeBytes({}) === undefined);
  }

  console.log("\ndeliverOtlpPush: the auth header carries the secret; the body NEVER does (non-negotiable invariant)");
  {
    const SECRET = "dd-api-key-DO-NOT-LEAK-9f3a7c21";
    const body = buildOtlpResourceMetrics([fakeDownpipeMetrics("dp-a")], Date.now()).body;
    const realFetch = globalThis.fetch;
    const captures: Array<{ headers: Record<string, string>; body: string }> = [];
    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      captures.push({ headers: { ...(init?.headers as Record<string, string>) }, body: String(init?.body ?? "") });
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    try {
      const r = await deliverOtlpPush("https://otlp.example.com/v1/metrics", body, "Authorization", SECRET);
      ok("deliverOtlpPush reports ok:true + the status on a 200", r.ok === true && r.status === 200);
      const last = captures[captures.length - 1];
      ok("the configured auth header carries the secret", last?.headers.Authorization === SECRET);
      ok("the request BODY never contains the secret", last?.body.includes(SECRET) !== true);
      ok("content-type is ALWAYS application/json (OTLP/HTTP JSON, no per-format branching)", last?.headers["content-type"] === "application/json");

      // A non-default header name (Datadog's DD-API-KEY, New Relic's Api-Key) carries the secret under
      // that exact name.
      captures.length = 0;
      await deliverOtlpPush("https://api.datadoghq.com/api/v2/otlp/v1/metrics", body, "DD-API-KEY", SECRET);
      const ddLast = captures[captures.length - 1];
      ok("a non-default header name (DD-API-KEY) carries the secret under that exact name", ddLast?.headers["DD-API-KEY"] === SECRET);
      ok("the body still never contains the secret under a custom header name", ddLast?.body.includes(SECRET) !== true);
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  console.log("\ndeliverOtlpPush: send-time SSRF re-screen (defence in depth)");
  {
    const r1 = await deliverOtlpPush("https://169.254.169.254/latest/meta-data/", "{}", "Authorization", "s");
    ok("an internal-literal (cloud metadata) target is refused before any fetch, never throws", r1.ok === false && r1.code === "internal-sink-blocked");
    const r2 = await deliverOtlpPush("https://127.0.0.1/x", "{}", "Authorization", "s");
    ok("a loopback target is refused", r2.ok === false && r2.code === "internal-sink-blocked");
    const r3 = await deliverOtlpPush("not a url", "{}", "Authorization", "s");
    ok("an unparseable url is refused (url-invalid), never throws", r3.ok === false && r3.code === "url-invalid");
  }

  console.log("\nsealed-secret round-trip + 4-WAY AAD domain separation (dest / SIEM-header / SIEM-s3 / OTLP-push ciphertexts never cross-open)");
  {
    const KEY = crypto.getRandomValues(new Uint8Array(32));
    const SECRET = "otlp-bearer-token-abcdef0123456789";
    const wrapped = await wrapConfigSecret(KEY, SECRET, OTLP_PUSH_SECRET_AAD);
    ok("wrap+unwrap round-trips under the OTLP push AAD", (await unwrapConfigSecret(KEY, wrapped, OTLP_PUSH_SECRET_AAD)) === SECRET);
    await throwsAsync("an OTLP push ciphertext does NOT decrypt under the DEST (default) AAD", async () => unwrapConfigSecret(KEY, wrapped));
    await throwsAsync("an OTLP push ciphertext does NOT decrypt under the SIEM push-header AAD", async () => unwrapConfigSecret(KEY, wrapped, PUSH_SECRET_AAD));
    await throwsAsync("an OTLP push ciphertext does NOT decrypt under the SIEM push-s3 AAD", async () => unwrapConfigSecret(KEY, wrapped, PUSH_S3_SECRET_AAD));

    const wrapped2 = await maybeWrapConfigSecret(KEY, SECRET, OTLP_PUSH_SECRET_AAD);
    ok("maybeWrapConfigSecret(otlpAad) with a key produces an envelope", typeof wrapped2 !== "string");
    ok("resolveConfigSecret(otlpAad) resolves it back to plaintext", (await resolveConfigSecret(KEY, wrapped2, OTLP_PUSH_SECRET_AAD)) === SECRET);
    await throwsAsync("resolveConfigSecret with the WRONG (default/dest) aad fails to open an OTLP push envelope", async () => resolveConfigSecret(KEY, wrapped2 as WrappedSecret));

    // The reverse direction: a SIEM-domain ciphertext must not open under the OTLP AAD either.
    const destWrapped = await wrapConfigSecret(KEY, SECRET);
    const siemHeaderWrapped = await wrapConfigSecret(KEY, SECRET, PUSH_SECRET_AAD);
    const siemS3Wrapped = await wrapConfigSecret(KEY, SECRET, PUSH_S3_SECRET_AAD);
    await throwsAsync("a DEST ciphertext does NOT open under the OTLP push AAD", async () => unwrapConfigSecret(KEY, destWrapped, OTLP_PUSH_SECRET_AAD));
    await throwsAsync("a SIEM push-header ciphertext does NOT open under the OTLP push AAD", async () => unwrapConfigSecret(KEY, siemHeaderWrapped, OTLP_PUSH_SECRET_AAD));
    await throwsAsync("a SIEM push-s3 ciphertext does NOT open under the OTLP push AAD", async () => unwrapConfigSecret(KEY, siemS3Wrapped, OTLP_PUSH_SECRET_AAD));

    // Existing 2-arg call sites (every destination credential call) are unaffected: additive, not a behaviour change.
    ok("a 2-arg wrap (no aad argument) still uses CONFIG_SECRET_AAD (back-compat, unchanged)", (await unwrapConfigSecret(KEY, destWrapped)) === SECRET);
    ok("maybeWrapConfigSecret with NO key still floors to plaintext (unchanged back-compat path)", (await maybeWrapConfigSecret(undefined, SECRET, OTLP_PUSH_SECRET_AAD)) === SECRET);
  }

  console.log("\nDO: setOtlpPushDestination validation + getOtlpPushView redaction");
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    await throwsAsync("a non-https endpoint is rejected", async () =>
      dobj.setOtlpPushDestination({ endpoint: "http://otlp.example.com/v1/metrics", authHeaderValue: "s", enabled: true }, OWNER_CALLER),
    );
    await throwsAsync("a FIRST set with no authHeaderValue is rejected (needs a secret to create)", async () =>
      dobj.setOtlpPushDestination({ endpoint: "https://otlp.example.com/v1/metrics", enabled: true }, OWNER_CALLER),
    );
    ok("nothing was stored by either rejected create", (await dobj.getOtlpPushRecordRaw()) === null);

    const view = await dobj.setOtlpPushDestination({ endpoint: "https://otlp.example.com/v1/metrics", authHeaderValue: "bearer-secret-xyz", enabled: true }, OWNER_CALLER);
    ok("a valid create succeeds and defaults authHeaderName to Authorization", view.present === true && view.authHeaderName === "Authorization" && view.endpoint === "https://otlp.example.com/v1/metrics" && view.enabled === true);
    const rec = (await dobj.getOtlpPushRecordRaw())!;
    ok("the stored record carries a fresh generation id (crypto.randomUUID)", typeof rec.gen === "string" && rec.gen.length > 0);
    ok("getOtlpPushView NEVER carries the secret, its ciphertext OR the gen", !JSON.stringify(view).includes("bearer-secret-xyz") && !("authHeaderValue" in view) && !("gen" in view));

    const auditEvents = (await dobj.readAudit(new URLSearchParams())).events;
    ok("otlp-push-destination-set was recorded under its OWN action name (distinct from the SIEM push)", auditEvents.some((e) => e.action === "otlp-push-destination-set"));
  }

  console.log("\nDO: KEEP-SECRET update semantics (the write-only-secret-field UX)");
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    await dobj.setOtlpPushDestination({ endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "DD-API-KEY", authHeaderValue: "kept-secret-1", enabled: true }, OWNER_CALLER);
    const rec1 = (await dobj.getOtlpPushRecordRaw())!;
    ok("the create stored the secret verbatim (DO holds no wrap key -> plaintext floor)", rec1.authHeaderValue === "kept-secret-1");

    await dobj.setOtlpPushDestination({ endpoint: "https://otlp2.example.com/v1/metrics", authHeaderName: "DD-API-KEY", enabled: false }, OWNER_CALLER);
    const rec2 = (await dobj.getOtlpPushRecordRaw())!;
    ok("KEEP-SECRET: the auth header value is preserved across a set that omits it", rec2.authHeaderValue === "kept-secret-1");
    ok("KEEP-SECRET: the non-secret fields WERE updated (endpoint/enabled)", rec2.endpoint === "https://otlp2.example.com/v1/metrics" && rec2.enabled === false);
    ok("the gen changed on the keep-secret replace (a fresh generation on every set)", rec2.gen !== rec1.gen);

    // An explicit empty-string authHeaderValue is treated the same as absent (keep).
    await dobj.setOtlpPushDestination({ endpoint: "https://otlp2.example.com/v1/metrics", authHeaderName: "DD-API-KEY", authHeaderValue: "", enabled: true }, OWNER_CALLER);
    ok("KEEP-SECRET: an explicit EMPTY authHeaderValue also keeps the existing secret", (await dobj.getOtlpPushRecordRaw())!.authHeaderValue === "kept-secret-1");

    // A later set WITH a new secret replaces it (rotation is re-enter).
    await dobj.setOtlpPushDestination({ endpoint: "https://otlp2.example.com/v1/metrics", authHeaderName: "DD-API-KEY", authHeaderValue: "new-secret-2", enabled: true }, OWNER_CALLER);
    ok("a set WITH a new secret replaces the kept one", (await dobj.getOtlpPushRecordRaw())!.authHeaderValue === "new-secret-2");

    // "Still delivers": the kept secret resolves through the drain's read path to the original value.
    const rec3 = (await dobj.getOtlpPushRecordRaw())!;
    const resolved = await fetchOtlpPushConfig({ fetch: async () => new Response(JSON.stringify({ record: rec3 }), { status: 200 }) } as unknown as Parameters<typeof fetchOtlpPushConfig>[0], undefined);
    ok("fetchOtlpPushConfig resolves the stored secret for the sender", resolved?.authHeaderValue === "new-secret-2");
  }

  console.log("\nDO: FORBIDDEN AUTH HEADER NAME (content-type and runtime-controlled headers rejected)");
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    for (const name of ["content-type", "Content-Type", "host", "content-length", "connection"]) {
      await throwsAsync(`setOtlpPushDestination rejects the forbidden auth header name "${name}"`, async () =>
        dobj.setOtlpPushDestination({ endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: name, authHeaderValue: "s", enabled: true }, OWNER_CALLER),
      );
    }
    ok("nothing was stored by any forbidden-header rejection", (await dobj.getOtlpPushRecordRaw()) === null);
    await dobj.setOtlpPushDestination({ endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Api-Key", authHeaderValue: "s", enabled: true }, OWNER_CALLER);
    ok("a legitimate custom header name (Api-Key, New Relic's convention) is accepted", (await dobj.getOtlpPushRecordRaw())!.authHeaderName === "Api-Key");
  }

  console.log("\nDO: clearOtlpPushDestination wipes config + trail; only an Owner may set/clear");
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    await dobj.setOtlpPushDestination({ endpoint: "https://otlp.example.com/v1/metrics", authHeaderValue: "s", enabled: true }, OWNER_CALLER);
    ok("clearOtlpPushDestination succeeds for an owner", (await dobj.clearOtlpPushDestination(OWNER_CALLER)).ok === true);
    ok("clear wipes the config (getOtlpPushView reports present:false)", (await dobj.getOtlpPushView()).present === false);
    const auditCleared = (await dobj.readAudit(new URLSearchParams())).events;
    ok("otlp-push-destination-cleared was recorded", auditCleared.some((e) => e.action === "otlp-push-destination-cleared"));

    const NON_OWNER = { method: "access" as const, email: "viewer@example.com", subject: "sub-viewer", groups: [] };
    await throwsAsync("a non-owner cannot set the OTLP push destination", async () =>
      dobj.setOtlpPushDestination({ endpoint: "https://otlp.example.com/v1/metrics", authHeaderValue: "s", enabled: true }, NON_OWNER),
    );
  }

  console.log("\nDO: recordOtlpPushOutcome -- bounded trail, failureCount audit, STRAGGLER guard");
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    await dobj.setOtlpPushDestination({ endpoint: "https://otlp.example.com/v1/metrics", authHeaderValue: "s", enabled: true }, OWNER_CALLER);
    const genA = (await dobj.getOtlpPushRecordRaw())!.gen;

    await dobj.recordOtlpPushOutcome({ ok: true, httpStatus: 200, downpipeCount: 5, gen: genA });
    let trail = await dobj.getOtlpPushTrail();
    ok("a successful outcome lands on the trail", trail.length === 1 && trail[0]!.ok === true && trail[0]!.downpipeCount === 5);

    await dobj.recordOtlpPushOutcome({ ok: false, httpStatus: 503, reason: "http-5xx", downpipeCount: 5, gen: genA });
    trail = await dobj.getOtlpPushTrail();
    ok("a failure ALSO lands on the trail (no cursor to hold; this feature only ever has a trail)", trail.length === 2 && trail[1]!.ok === false && trail[1]!.reason === "http-5xx");
    const audit1 = (await dobj.readAudit(new URLSearchParams())).events;
    const failure1 = audit1.find((e) => e.action === "otlp-push-delivery-failure");
    ok("an otlp-push-delivery-failure audit event was recorded under its OWN action name", failure1 !== undefined);
    ok(
      "its target is the CLOSED, REUSED push-destination shape: op + failureCount only, no free-form field",
      failure1?.target.kind === "push-destination" && (failure1.target as { op?: string }).op === "delivery-failure" && (failure1.target as { failureCount?: number }).failureCount === 1,
    );

    for (let i = 0; i < 60; i++) await dobj.recordOtlpPushOutcome({ ok: true, httpStatus: 200, downpipeCount: 1, gen: genA });
    ok("the trail never exceeds its 50-entry cap", (await dobj.getOtlpPushTrail()).length === 50);

    // STRAGGLER (i): after a plain CLEAR, an in-flight outcome for the old gen is a total no-op.
    await dobj.clearOtlpPushDestination(OWNER_CALLER);
    await dobj.recordOtlpPushOutcome({ ok: true, httpStatus: 200, downpipeCount: 9, gen: genA });
    ok("a straggler after a clear writes NO trail entry (no live destination to describe)", (await dobj.getOtlpPushTrail()).length === 0);

    // STRAGGLER (ii): a NEW destination configured after the clear has its OWN gen; A's straggler cannot land on it.
    await dobj.setOtlpPushDestination({ endpoint: "https://otlp-b.example.com/v1/metrics", authHeaderValue: "s2", enabled: true }, OWNER_CALLER);
    const genB = (await dobj.getOtlpPushRecordRaw())!.gen;
    ok("B's gen differs from A's", genB !== genA);
    await dobj.recordOtlpPushOutcome({ ok: true, httpStatus: 200, downpipeCount: 9, gen: genA });
    ok("A's straggler CANNOT land on B's trail (gen mismatch -> no-op)", (await dobj.getOtlpPushTrail()).length === 0);
    await dobj.recordOtlpPushOutcome({ ok: true, httpStatus: 200, downpipeCount: 3, gen: genB });
    ok("a live (matching-gen) outcome for B records normally", (await dobj.getOtlpPushTrail()).length === 1);

    // STRAGGLER (iii): an in-place REPLACE mints a new gen; a pre-replace straggler is dropped.
    await dobj.setOtlpPushDestination({ endpoint: "https://otlp-b.example.com/v1/metrics", enabled: false }, OWNER_CALLER);
    const genB2 = (await dobj.getOtlpPushRecordRaw())!.gen;
    ok("the in-place replace minted a new gen", genB2 !== genB);
    ok("an in-place replace KEEPS the trail (not a fresh create)", (await dobj.getOtlpPushTrail()).length === 1);
    await dobj.recordOtlpPushOutcome({ ok: true, httpStatus: 200, downpipeCount: 4, gen: genB });
    ok("a straggler from before the in-place replace is dropped (stale gen): trail length unchanged", (await dobj.getOtlpPushTrail()).length === 1);
  }

  console.log("\nDO: otlpMetricsSnapshot -- the MINIMAL read of existing run/replication state (no recomputed freshness)");
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    const storage = (dobj as unknown as { state: { storage: MockStorage } }).state.storage;

    // dp-a: a failed run then an ok run (5s duration, 12345 archive bytes), two configured destinations, one
    // proven healthy and one not.
    await storage.put("dp:dp-a", {
      config: { id: "dp-a", name: "Downpipe A", cadenceSeconds: 3600, enabled: true, destinationIds: ["dest-1", "dest-2"], source: {} },
      nextRunAt: 0,
      lastRunId: null,
      inFlight: false,
    } as unknown as DownpipeState);
    await storage.put("hist:dp-a", [
      fakeRunHistoryEntry(1, { status: "failed" }),
      fakeRunHistoryEntry(2, { status: "ok", durationMs: 5000, archiveBytesWritten: 12345 }),
    ] satisfies RunHistoryEntry[]);
    await storage.put("repl:dp-a", { "dest-1": { holdsRunId: "run-2", holdsIndex: 2, lastOk: true, lastAttemptAt: 1 }, "dest-2": { holdsRunId: null, holdsIndex: -1, lastOk: false, lastAttemptAt: 1, reason: "unreachable" } } satisfies Record<string, DestReplState>);

    // dp-b: brand new, never run, no destinations proven yet.
    await storage.put("dp:dp-b", { config: { id: "dp-b", name: "Downpipe B", cadenceSeconds: 3600, enabled: true, destinationId: "dest-3", source: {} }, nextRunAt: 0, lastRunId: null, inFlight: false } as unknown as DownpipeState);

    // dp-c: only an in-flight run so far (never resolved), AND deliberately DISABLED (paused/decommissioned)
    // so the snapshot's enabled flag is exercised in both polarities (F4a).
    await storage.put("dp:dp-c", { config: { id: "dp-c", name: "Downpipe C", cadenceSeconds: 3600, enabled: false, source: {} }, nextRunAt: 0, lastRunId: "run-3", inFlight: true } as unknown as DownpipeState);
    await storage.put("hist:dp-c", [fakeRunHistoryEntry(3, { status: "in-flight" })] satisfies RunHistoryEntry[]);

    // dp-d: newest run ABANDONED (a crashed run reclaimed by the lease) after an earlier genuine success --
    // backupSuccess must read 0 (the newest RESOLVED run failed-like) while last_success still reports the
    // OLDER ok run's timestamp (these are deliberately DIFFERENT questions).
    await storage.put("dp:dp-d", { config: { id: "dp-d", name: "Downpipe D", cadenceSeconds: 3600, enabled: true, source: {} }, nextRunAt: 0, lastRunId: null, inFlight: false } as unknown as DownpipeState);
    await storage.put("hist:dp-d", [
      fakeRunHistoryEntry(4, { status: "ok", durationMs: 1000 }),
      fakeRunHistoryEntry(5, { status: "abandoned" }),
    ] satisfies RunHistoryEntry[]);

    const snap = await dobj.otlpMetricsSnapshot();
    const byId = new Map(snap.downpipes.map((d) => [d.id, d]));
    ok("the snapshot reports all 4 seeded downpipes", snap.downpipes.length === 4);

    const a = byId.get("dp-a")!;
    ok("dp-a: attempts/success/failure counts match the ring (1 failed + 1 ok)", a.attemptsTotal === 2 && a.successTotal === 1 && a.failureTotal === 1);
    ok("F4a: dp-a (config enabled) surfaces enabled:true in the snapshot", a.enabled === true);
    ok("dp-a: backupSuccess reflects the newest RESOLVED run (ok)", a.backupSuccess === 1);
    ok("dp-a: durationSeconds/sizeBytes come from the newest resolved run", a.durationSeconds === 5 && a.sizeBytes === 12345);
    ok("dp-a: lastSuccessTimestampSeconds is set (a run did succeed)", typeof a.lastSuccessTimestampSeconds === "number");
    const aDestById = new Map(a.destinations.map((d) => [d.id, d.healthy]));
    ok("dp-a: BOTH configured destinations are reported (proven healthy AND proven unhealthy)", aDestById.get("dest-1") === true && aDestById.get("dest-2") === false);

    const b = byId.get("dp-b")!;
    ok("dp-b: a brand-new downpipe reports zero counts, never a false success/failure", b.attemptsTotal === 0 && b.successTotal === 0 && b.failureTotal === 0);
    ok("dp-b: lastSuccessTimestampSeconds/backupSuccess/durationSeconds/sizeBytes are ALL absent (no data, not a misleading default)", b.lastSuccessTimestampSeconds === undefined && b.backupSuccess === undefined && b.durationSeconds === undefined && b.sizeBytes === undefined);
    ok("dp-b: an UNPROVEN destination (no repl: row yet) is OMITTED, not asserted unhealthy", b.destinations.length === 0);

    const c = byId.get("dp-c")!;
    ok("dp-c: an in-flight-only history counts as ONE attempt but no success/failure yet", c.attemptsTotal === 1 && c.successTotal === 0 && c.failureTotal === 0);
    ok("dp-c: no RESOLVED run yet -> backupSuccess/lastSuccessTimestampSeconds are absent (never falsely 0/1)", c.backupSuccess === undefined && c.lastSuccessTimestampSeconds === undefined);
    ok("F4a: dp-c (config disabled) surfaces enabled:false in the snapshot (a paused job is distinguishable)", c.enabled === false);

    const d = byId.get("dp-d")!;
    ok("dp-d: an abandoned newest run counts as a FAILURE (the same mapping reconcileAlerts applies)", d.failureTotal === 1 && d.successTotal === 1);
    ok("dp-d: backupSuccess is 0 (the newest RESOLVED run is the abandoned one, not the earlier ok one)", d.backupSuccess === 0);
    ok("dp-d: lastSuccessTimestampSeconds STILL reports the earlier ok run (last success != last resolved)", typeof d.lastSuccessTimestampSeconds === "number");
  }

  console.log("\nrunOtlpPushPass: full drain integration (opt-in gate; NO cursor -- every enabled tick re-pushes; fail-open; false-green on a genuine fault)");
  {
    interface FakeState {
      record: { endpoint: string; authHeaderName: string; authHeaderValue: unknown; enabled: boolean; gen: string } | null;
      downpipes: OtlpDownpipeMetrics[];
      recorded: Array<{ ok: boolean; httpStatus?: number; reason?: string; downpipeCount: number; truncated?: boolean; gen?: string }>;
    }
    type Sched = Parameters<typeof runOtlpPushPass>[1];
    function fakeScheduler(state: FakeState, opts?: { throwPath?: string }): Sched {
      return {
        fetch: async (input: string | URL, init?: RequestInit): Promise<Response> => {
          const url = new URL(typeof input === "string" ? input : input.toString());
          if (opts?.throwPath && url.pathname === opts.throwPath) throw new Error(`simulated DO ${url.pathname} unavailable`);
          const json = (v: unknown): Response => new Response(JSON.stringify(v), { status: 200 });
          if (url.pathname === "/otlp-push-config") return json({ record: state.record });
          if (url.pathname === "/otlp-metrics-snapshot") return json({ downpipes: state.downpipes });
          if (url.pathname === "/otlp-push-record") {
            state.recorded.push(JSON.parse(String(init?.body ?? "{}")) as FakeState["recorded"][number]);
            return json({ ok: true });
          }
          throw new Error(`unexpected DO fetch in test: ${url.pathname}`);
        },
      } as unknown as Sched;
    }
    const env = { CONFIG_WRAP_KEY: undefined } as unknown as Env;
    const realFetch = globalThis.fetch;

    {
      // loadConfigWrapKey runs inside the pass's own try, so a malformed CONFIG_WRAP_KEY throws loudly but
      // that throw must land on THIS pass's false-green path (return false), never escape runOtlpPushPass
      // uncaught -- and it must throw BEFORE any DO round-trip (a scheduler that throws on ANY fetch proves
      // the DO is never reached).
      const badKeyEnv = { CONFIG_WRAP_KEY: "not-valid-base64url-of-32-bytes" } as unknown as Env;
      const uncalledScheduler = { fetch: async (): Promise<Response> => { throw new Error("the DO must never be reached when CONFIG_WRAP_KEY is malformed"); } } as unknown as Sched;
      ok("a malformed CONFIG_WRAP_KEY returns false (the false-green signal), never a throw out of the pass", (await runOtlpPushPass(badKeyEnv, uncalledScheduler)) === false);
    }
    {
      const state: FakeState = { record: null, downpipes: [], recorded: [] };
      ok("opt-in: no destination configured -> true (silent no-op)", (await runOtlpPushPass(env, fakeScheduler(state))) === true);
      ok("no outcome recorded when unconfigured", state.recorded.length === 0);
    }
    {
      const state: FakeState = { record: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: false, gen: "gen-disabled" }, downpipes: [fakeDownpipeMetrics("dp-a")], recorded: [] };
      ok("opt-in: configured but DISABLED -> true (silent no-op)", (await runOtlpPushPass(env, fakeScheduler(state))) === true);
      ok("no outcome recorded when disabled, even though downpipes exist", state.recorded.length === 0);
    }
    {
      const state: FakeState = {
        record: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true, gen: "gen-ok" },
        downpipes: [fakeDownpipeMetrics("dp-a"), fakeDownpipeMetrics("dp-b")],
        recorded: [],
      };
      const captures: Array<{ headers: Record<string, string>; body: string }> = [];
      globalThis.fetch = (async (_url, init) => {
        captures.push({ headers: { ...(init?.headers as Record<string, string>) }, body: String(init?.body ?? "") });
        return new Response("ok", { status: 200 });
      }) as typeof fetch;
      try {
        ok("a successful push completes (true)", (await runOtlpPushPass(env, fakeScheduler(state))) === true);
      } finally {
        globalThis.fetch = realFetch;
      }
      ok("a request was actually captured", captures.length === 1);
      ok("the outbound request carried the secret in the configured header", captures[0]?.headers.Authorization === "sekret-value");
      ok("the outbound body never contains the secret", captures[0]?.body.includes("sekret-value") !== true);
      ok("the outbound body carries the canonical metric names", captures[0]?.body.includes(OTLP_METRIC_RECENT_ATTEMPTS) === true);
      ok("a 2xx recorded ok:true and the downpipe count (the ACTUAL shaped count)", state.recorded[0]?.ok === true && state.recorded[0]?.downpipeCount === 2 && state.recorded[0]?.truncated === undefined);
      ok("the recorded outcome carries the config's gen (the straggler guard threaded through the drain)", state.recorded[0]?.gen === "gen-ok");

      // NO CURSOR: unlike the SIEM push, an UNCHANGED snapshot on the next tick still pushes again.
      state.recorded = [];
      captures.length = 0;
      globalThis.fetch = (async (_url, init) => {
        captures.push({ headers: { ...(init?.headers as Record<string, string>) }, body: String(init?.body ?? "") });
        return new Response("ok", { status: 200 });
      }) as typeof fetch;
      try {
        ok("a SECOND tick with the SAME (unchanged) snapshot still pushes again (no cursor to short-circuit it)", (await runOtlpPushPass(env, fakeScheduler(state))) === true);
      } finally {
        globalThis.fetch = realFetch;
      }
      ok("the second tick made its own request and recorded its own outcome", captures.length === 1 && state.recorded.length === 1);
    }
    {
      // F3 (the trail-misreport fix, end to end): an OVER-CAP fleet must record the ACTUAL shaped count (the
      // cap), NOT the pre-cap snapshot length, and must flag truncated:true. Without the fix a 5000+cap fleet's
      // trail would read downpipeCount = the full length, ok:true, while only the cap was actually sent.
      // The cap is delivered as several chunked requests, each recorded as its OWN outcome, so the
      // assertions sum across state.recorded rather than expecting one entry for the whole cap.
      const overCap = OTLP_PUSH_DOWNPIPE_CAP + 40;
      const state: FakeState = {
        record: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true, gen: "gen-trunc" },
        downpipes: Array.from({ length: overCap }, (_, i) => fakeDownpipeMetrics(`dp-${i}`)),
        recorded: [],
      };
      let requestCount = 0;
      globalThis.fetch = (async () => {
        requestCount++;
        return new Response("ok", { status: 200 });
      }) as typeof fetch;
      try {
        ok("an over-cap fleet still completes the pass (true)", (await runOtlpPushPass(env, fakeScheduler(state))) === true);
      } finally {
        globalThis.fetch = realFetch;
      }
      const expectedChunks = Math.ceil(OTLP_PUSH_DOWNPIPE_CAP / OTLP_PUSH_CHUNK_DOWNPIPES);
      ok(`F4: the cap is chunked into ${expectedChunks} requests, each recorded as its own outcome`, requestCount === expectedChunks && state.recorded.length === expectedChunks);
      ok("F4: no single recorded chunk ever exceeds OTLP_PUSH_CHUNK_DOWNPIPES", state.recorded.every((r) => r.downpipeCount <= OTLP_PUSH_CHUNK_DOWNPIPES));
      ok("F3: the recorded downpipe counts SUM to the ACTUAL shaped total (=cap), NEVER the pre-cap snapshot length", state.recorded.reduce((n, r) => n + r.downpipeCount, 0) === OTLP_PUSH_DOWNPIPE_CAP);
      ok("F3: EVERY chunk flags truncated:true on an over-cap push (a large fleet is a LOUD signal, never silent)", state.recorded.every((r) => r.truncated === true));
    }
    {
      // At a large but WITHIN-cap fleet (the engine's known 2500 scale): still several
      // chunked requests (never one oversized body), each an independent ok:true outcome, none truncated.
      const state: FakeState = {
        record: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true, gen: "gen-fleet2500" },
        downpipes: Array.from({ length: 2500 }, (_, i) => fakeDownpipeMetrics(`dp-${i}`)),
        recorded: [],
      };
      const bodies: string[] = [];
      globalThis.fetch = (async (_url, init) => {
        bodies.push(String(init?.body ?? ""));
        return new Response("ok", { status: 200 });
      }) as typeof fetch;
      try {
        ok("a 2500-downpipe fleet still completes the pass (true)", (await runOtlpPushPass(env, fakeScheduler(state))) === true);
      } finally {
        globalThis.fetch = realFetch;
      }
      const expectedChunks = Math.ceil(2500 / OTLP_PUSH_CHUNK_DOWNPIPES);
      ok(`2500 downpipes -> ${expectedChunks} chunked POSTs, never one oversized body`, bodies.length === expectedChunks && state.recorded.length === expectedChunks);
      ok("every chunk body stays under 1 MB (New Relic's cap)", bodies.every((b) => b.length < 1_000_000));
      ok("every chunk records ok:true, none flagged truncated (2500 is under the cap)", state.recorded.every((r) => r.ok === true && r.truncated === undefined));
      ok("the recorded downpipe counts sum to the full 2500", state.recorded.reduce((n, r) => n + r.downpipeCount, 0) === 2500);
    }
    {
      // A collector that rejects ONLY the second chunk: per-chunk independence means the OTHER
      // chunks still deliver and record ok:true -- one bad chunk does not fail the whole tick's accounting.
      const state: FakeState = {
        record: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true, gen: "gen-partial" },
        downpipes: Array.from({ length: OTLP_PUSH_CHUNK_DOWNPIPES * 3 }, (_, i) => fakeDownpipeMetrics(`dp-${i}`)),
        recorded: [],
      };
      let n = 0;
      globalThis.fetch = (async () => {
        n++;
        return n === 2 ? new Response("nope", { status: 503 }) : new Response("ok", { status: 200 });
      }) as typeof fetch;
      try {
        ok("a partial rejection (chunk 2 of 3) still completes the pass (true)", (await runOtlpPushPass(env, fakeScheduler(state))) === true);
      } finally {
        globalThis.fetch = realFetch;
      }
      ok("all 3 chunks were sent (the rejection of one does not stop the others)", state.recorded.length === 3);
      ok("chunks 1 and 3 recorded ok:true; chunk 2 recorded ok:false with a coarse reason", state.recorded[0]?.ok === true && state.recorded[1]?.ok === false && state.recorded[1]?.reason === "http-5xx" && state.recorded[2]?.ok === true);
    }
    {
      // A failing collector: the pass still COMPLETES (true); the outcome is recorded as a failure. Proves
      // the pass-level contract: a customer-endpoint rejection is not a pass fault (fail-open).
      const state: FakeState = {
        record: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true, gen: "gen-reject" },
        downpipes: [fakeDownpipeMetrics("dp-a")],
        recorded: [],
      };
      globalThis.fetch = (async () => new Response("nope", { status: 503 })) as typeof fetch;
      try {
        ok("a rejected delivery still completes the pass (true) -- fail-open", (await runOtlpPushPass(env, fakeScheduler(state))) === true);
      } finally {
        globalThis.fetch = realFetch;
      }
      ok("the failure is recorded with ok:false + a coarse reason (never a raw body)", state.recorded[0]?.ok === false && state.recorded[0]?.reason === "http-5xx");
    }
    {
      // A genuine DO round-trip fault (the config is unreadable) is a PASS fault: false, the false-green
      // signal drive() folds into passErrors.
      const state: FakeState = { record: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true, gen: "gen-fault" }, downpipes: [], recorded: [] };
      ok("a DO round-trip fault (config unreadable) returns false (the false-green signal)", (await runOtlpPushPass(env, fakeScheduler(state, { throwPath: "/otlp-push-config" }))) === false);
    }
    {
      // A genuine DO round-trip fault reading the metrics snapshot is ALSO a pass fault.
      const state: FakeState = { record: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true, gen: "gen-fault2" }, downpipes: [], recorded: [] };
      ok("a DO round-trip fault (metrics snapshot unreadable) returns false", (await runOtlpPushPass(env, fakeScheduler(state, { throwPath: "/otlp-metrics-snapshot" }))) === false);
    }
    {
      // DRAIN TAIL TRY/CATCH: a contract-violating throw from the shape/deliver tail must NOT escape the pass
      // and must NOT silently skip the tick: it records a FAILURE (ok:false) and returns false (the
      // false-green signal). Forced with a genuinely malformed downpipe (destinations is not iterable), the
      // same "real cross-version contract violation" discipline the sibling SIEM-push validator uses.
      const state: FakeState = {
        record: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true, gen: "gen-tail" },
        downpipes: [{ ...fakeDownpipeMetrics("dp-a"), destinations: null as unknown as [] }],
        recorded: [],
      };
      const passResult = await runOtlpPushPass(env, fakeScheduler(state));
      ok("a shape/deliver tail throw returns false (never escapes the pass, never skips silently)", passResult === false);
      ok("the tail throw recorded a FAILURE outcome (ok:false)", state.recorded.length === 1 && state.recorded[0]?.ok === false && state.recorded[0]?.reason === "shape-or-deliver-fault");
    }
  }

  console.log("\ndeliverResolvedOtlpPush: the standalone builder+send path (mirrors deliverResolvedPush)");
  {
    const cfg: ResolvedOtlpPushConfig = { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "sekret-value", enabled: true, gen: "g" };
    const realFetch = globalThis.fetch;
    const captures: Array<{ body: string }> = [];
    globalThis.fetch = (async (_url, init) => {
      captures.push({ body: String(init?.body ?? "") });
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    try {
      const r = await deliverResolvedOtlpPush(cfg, [fakeDownpipeMetrics("dp-a")], Date.now());
      ok("reports ok:true + status on a 200", r.ok === true && r.status === 200);
      ok("the shaped OTLP body was actually sent", captures[0]?.body.includes("resourceMetrics") === true);
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  console.log(failures === 0 ? "\nOTLP PUSH (engine-internal) VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
