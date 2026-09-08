// Pure OTLP/HTTP JSON builder for the OTLP metrics push drain (cron/otlp-push-pass.ts) and, eventually, a
// test-send route: given the canonical backup-health metric snapshot,
// render one OTLP ResourceMetrics JSON body (the "OTLP/HTTP over plain fetch() with a JSON body" shape that
// is proven feasible in Workers -- no protobuf, no Node net). No I/O; a straight data transform, so the
// validator drives it without a network call or a Durable Object.
//
// CANONICAL METRIC SET (converged across Velero/restic/pgBackRest/Kasten): last-success
// timestamp, a 0/1 success flag, recent attempt/success/failure counts, run duration, archive size, per-
// destination health, and an enabled flag, labelled by downpipe (+ destination for the health series). Every
// metric here is an OTLP GAUGE. The three WINDOWED-COUNT metrics are named without a "_total" suffix on
// purpose (downpipe_backup_recent_attempts / _recent_successes / _recent_failures, matching the sibling
// Prometheus /metrics endpoint on mon-metrics): a real Velero/restic exporter can expose a true monotonic
// counter because its process holds an in-memory tally across its whole lifetime, but this engine's Worker is
// stateless per-invocation and the DO retains only a BOUNDED run-history ring (RING_CAP entries), so these
// counts are windowed over the retained runs and CAN SHRINK as old runs age out of the ring. A "_total" name
// invites rate()/increase(), which reads a windowed value's ring-eviction dip as a phantom counter reset and
// misfires; the honest "recent_*" gauge name (TYPE gauge, HELP = "count over the retained run-history
// window", NOT a lifetime counter) is what a consumer should read as a level, not a rate. See
// scheduler-do-otlp-push.ts's otlpMetricsSnapshot for the windowed-count derivation this builder consumes.
//
// INJECTION SAFETY: every label value (a downpipe id/name, a destination id) rides inside a JSON
// `stringValue` field. JSON.stringify structurally escapes quotes/backslashes/control characters, so a
// crafted downpipe name can never break out of its string slot, forge an extra metric/dataPoint, or corrupt
// the surrounding JSON structure -- the same structural-safety argument cron/siem-push-shape.ts's GELF
// shaper makes.

import { ENGINE_VERSION } from "../format/version.ts";
import type { OtlpDestinationHealth, OtlpDownpipeMetrics } from "../sched/scheduler-do-base.ts";

export type { OtlpDestinationHealth, OtlpDownpipeMetrics };

// OTLP_PUSH_DOWNPIPE_CAP bounds the per-tick snapshot to a finite number of downpipes (defence in depth,
// mirroring SIEM_PUSH_BATCH_CAP). It is set WELL ABOVE the known large-fleet scale (the engine's own scale
// regression exercises a 2500-downpipe account), so the cap sits at 2x that (5000) to cover it with margin
// and never silently drop a downpipe at any realistic fleet size.
// A snapshot beyond the cap does NOT drop rows silently: buildOtlpResourceMetrics reports truncated:true and
// the dropped count, the drain records both on the delivery trail (so a fleet growing past the cap is a
// LOUD, visible signal to raise it or move to a batched transport, never an invisible partial). A full 2500-
// fleet snapshot serialises to a few MB (well under a typical OTLP collector's request-size limit); a fleet
// large enough to approach the single-POST size budget is the point to split the payload into several POSTs
// (a known scale follow-up, not yet built),
// which is why the cap is a hard ceiling with an explicit truncation signal rather than an unbounded body
// that would 413 opaquely.
export const OTLP_PUSH_DOWNPIPE_CAP = 5000;

// ShapedOtlpPush carries the wire body PLUS the honest accounting the drain records on the delivery trail:
// downpipeCount is the ACTUAL number of downpipes shaped into this body (post-cap), NEVER the pre-cap input
// length, so a trail entry can never claim it pushed more than it did; truncated + droppedCount surface an
// over-cap snapshot explicitly (see OTLP_PUSH_DOWNPIPE_CAP).
export interface ShapedOtlpPush {
  body: string;
  contentType: string;
  downpipeCount: number;
  truncated: boolean;
  droppedCount: number;
}

// The canonical metric names, exported so the drain, a future test-send route and the validator share one
// spelling rather than several hand-literal copies drifting apart. The recent-* three are windowed GAUGES
// (no "_total" suffix; see the file header for why), matching the Prometheus /metrics endpoint on mon-metrics.
export const OTLP_METRIC_LAST_SUCCESS = "downpipe_backup_last_success_timestamp_seconds";
export const OTLP_METRIC_SUCCESS = "downpipe_backup_success";
export const OTLP_METRIC_RECENT_ATTEMPTS = "downpipe_backup_recent_attempts";
export const OTLP_METRIC_RECENT_SUCCESSES = "downpipe_backup_recent_successes";
export const OTLP_METRIC_RECENT_FAILURES = "downpipe_backup_recent_failures";
export const OTLP_METRIC_DURATION = "downpipe_backup_duration_seconds";
export const OTLP_METRIC_SIZE_BYTES = "downpipe_backup_size_bytes";
export const OTLP_METRIC_DEST_HEALTHY = "downpipe_destination_healthy";
export const OTLP_METRIC_ENABLED = "downpipe_enabled";

interface OtlpKeyValue {
  key: string;
  value: { stringValue: string };
}

interface OtlpNumberDataPoint {
  attributes: OtlpKeyValue[];
  timeUnixNano: string;
  asDouble: number;
}

interface OtlpGaugeMetric {
  name: string;
  description: string;
  unit: string;
  gauge: { dataPoints: OtlpNumberDataPoint[] };
}

function attr(key: string, value: string): OtlpKeyValue {
  return { key, value: { stringValue: value } };
}

// nanosOf converts an epoch-MILLIS number to the OTLP timeUnixNano STRING (uint64 in the proto, so the JSON
// mapping is a decimal string, not a JS number: ms * 1e6 already exceeds Number.MAX_SAFE_INTEGER today, so
// this multiplies as BigInt, never a float, to avoid silently truncating/rounding the timestamp).
function nanosOf(epochMs: number): string {
  return `${BigInt(Math.floor(epochMs)) * 1_000_000n}`;
}

function point(nowNs: string, value: number, labels: OtlpKeyValue[]): OtlpNumberDataPoint {
  return { attributes: labels, timeUnixNano: nowNs, asDouble: value };
}

function destLabels(dp: OtlpDownpipeMetrics, d: OtlpDestinationHealth): OtlpKeyValue[] {
  return [attr("downpipe_id", dp.id), attr("downpipe_name", dp.name), attr("destination_id", d.id)];
}

// buildOneOtlpBody renders the OTLP JSON body for EXACTLY the downpipes handed to it (already capped/sliced
// by the caller): one Resource (the engine itself), one InstrumentationScope, and the canonical metrics,
// each carrying one data point per downpipe (or per downpipe+destination for downpipe_destination_healthy).
// A metric with zero data points (e.g. no downpipe has any destination health recorded yet) is OMITTED from
// the metrics array entirely, mirroring how a real exporter skips an empty series rather than shipping a
// metric with no data. Shared by buildOtlpResourceMetrics (the whole-cap single body) and
// buildOtlpResourceMetricsChunks (one body per chunk, item 4), so the wire shape for a given set of
// downpipes is byte-identical either way.
function buildOneOtlpBody(downpipes: OtlpDownpipeMetrics[], nowMs: number): { body: string; contentType: string } {
  const nowNs = nanosOf(nowMs);

  const lastSuccess: OtlpNumberDataPoint[] = [];
  const success: OtlpNumberDataPoint[] = [];
  const recentAttempts: OtlpNumberDataPoint[] = [];
  const recentSuccesses: OtlpNumberDataPoint[] = [];
  const recentFailures: OtlpNumberDataPoint[] = [];
  const duration: OtlpNumberDataPoint[] = [];
  const sizeBytes: OtlpNumberDataPoint[] = [];
  const destHealthy: OtlpNumberDataPoint[] = [];
  const enabled: OtlpNumberDataPoint[] = [];

  for (const dp of downpipes) {
    const dpLabels = [attr("downpipe_id", dp.id), attr("downpipe_name", dp.name)];
    if (dp.lastSuccessTimestampSeconds !== undefined) lastSuccess.push(point(nowNs, dp.lastSuccessTimestampSeconds, dpLabels));
    if (dp.backupSuccess !== undefined) success.push(point(nowNs, dp.backupSuccess, dpLabels));
    recentAttempts.push(point(nowNs, dp.attemptsTotal, dpLabels));
    recentSuccesses.push(point(nowNs, dp.successTotal, dpLabels));
    recentFailures.push(point(nowNs, dp.failureTotal, dpLabels));
    if (dp.durationSeconds !== undefined) duration.push(point(nowNs, dp.durationSeconds, dpLabels));
    if (dp.sizeBytes !== undefined) sizeBytes.push(point(nowNs, dp.sizeBytes, dpLabels));
    // downpipe_enabled distinguishes a live green job from a DECOMMISSIONED one whose last-known success
    // would otherwise read as an eternally-fresh backup: a consumer gates its staleness alert on enabled==1.
    enabled.push(point(nowNs, dp.enabled ? 1 : 0, dpLabels));
    for (const d of dp.destinations) {
      destHealthy.push(point(nowNs, d.healthy ? 1 : 0, destLabels(dp, d)));
    }
  }

  const metric = (name: string, description: string, unit: string, dataPoints: OtlpNumberDataPoint[]): OtlpGaugeMetric => ({
    name,
    description,
    unit,
    gauge: { dataPoints },
  });

  const metrics: OtlpGaugeMetric[] = [
    metric(OTLP_METRIC_LAST_SUCCESS, "Unix time of the last successful backup", "s", lastSuccess),
    metric(OTLP_METRIC_SUCCESS, "Whether the most recent backup attempt succeeded (1) or not (0)", "1", success),
    metric(OTLP_METRIC_RECENT_ATTEMPTS, "Backup attempts over the retained run-history window (a windowed gauge, NOT a lifetime counter)", "1", recentAttempts),
    metric(OTLP_METRIC_RECENT_SUCCESSES, "Successful backups over the retained run-history window (a windowed gauge, NOT a lifetime counter)", "1", recentSuccesses),
    metric(OTLP_METRIC_RECENT_FAILURES, "Failed backups over the retained run-history window (a windowed gauge, NOT a lifetime counter)", "1", recentFailures),
    metric(OTLP_METRIC_DURATION, "Wall-clock duration of the most recent resolved backup run", "s", duration),
    metric(OTLP_METRIC_SIZE_BYTES, "Archive bytes written by the most recent resolved backup run", "By", sizeBytes),
    metric(OTLP_METRIC_DEST_HEALTHY, "Whether a configured destination's last seal/replicate attempt succeeded (1) or not (0)", "1", destHealthy),
    metric(OTLP_METRIC_ENABLED, "Whether the downpipe is enabled (1) or paused/decommissioned (0)", "1", enabled),
  ].filter((m) => m.gauge.dataPoints.length > 0);

  const body = JSON.stringify({
    resourceMetrics: [
      {
        resource: {
          attributes: [attr("service.name", "downpipes-engine"), attr("service.version", ENGINE_VERSION)],
        },
        scopeMetrics: [
          {
            scope: { name: "downpipes.otlp-push", version: ENGINE_VERSION },
            metrics,
          },
        ],
      },
    ],
  });
  return { body, contentType: "application/json" };
}

// buildOtlpResourceMetrics renders the FULL OTLP JSON body for one push tick in a SINGLE ResourceMetrics
// envelope: every (post-cap) downpipe's data points in one body. It returns the ACTUAL shaped downpipe
// count + the truncation accounting alongside the body (see ShapedOtlpPush). Kept as the whole-snapshot
// builder for callers that want one body regardless of size (deliverResolvedOtlpPush, and this file's own
// validator); the cron drain itself sends buildOtlpResourceMetricsChunks's per-chunk bodies instead (item 4:
// a single 2500+-downpipe body can exceed a vendor's 1 MB OTLP/HTTP request-size cap).
export function buildOtlpResourceMetrics(downpipes: OtlpDownpipeMetrics[], nowMs: number): ShapedOtlpPush {
  const capped = downpipes.slice(0, OTLP_PUSH_DOWNPIPE_CAP);
  const droppedCount = downpipes.length - capped.length;
  const { body, contentType } = buildOneOtlpBody(capped, nowMs);
  return { body, contentType, downpipeCount: capped.length, truncated: droppedCount > 0, droppedCount };
}

// OTLP_PUSH_CHUNK_DOWNPIPES bounds each CHUNK to a conservative downpipe count so no single POST body can
// ever approach a vendor's request-size cap: New Relic's OTLP/HTTP intake
// caps a request at ~1 MB, tighter than Dynatrace's 4 MB. Each downpipe's data point is duplicated across
// every populated metric (its id/name labels are NOT shared/interned in the JSON, so an 8-metric downpipe
// carries its labels 8+ times), which measures out to ~2.9 KB/downpipe in the validator's deliberately
// pathological fixture (long ULID-shaped ids, 60-char names, two destinations each). 300 downpipes per
// chunk keeps even that worst case under ~900 KB, comfortably inside the <=800 KB target with margin for
// the fixed resource/scope wrapper, and a REALISTIC fleet (short ids/names) sits far below it. A
// conservative COUNT cap (mirroring SIEM_PUSH_BATCH_CAP's reasoning) is used over measuring serialised
// bytes per chunk, so a chunk is never built twice just to size it.
export const OTLP_PUSH_CHUNK_DOWNPIPES = 300;

// buildOtlpResourceMetricsChunks splits the (post-cap) snapshot into OTLP_PUSH_CHUNK_DOWNPIPES-sized
// chunks, each rendered as its OWN complete, independently-POSTable OTLP ResourceMetrics body (item 4): the
// drain sends and records EACH chunk's outcome separately, so one oversized tick can never fail (or silently
// truncate) the WHOLE push the way a single >1 MB body would. truncated/droppedCount reflect the SAME
// whole-snapshot over-OTLP_PUSH_DOWNPIPE_CAP accounting on EVERY chunk (never a per-chunk truncation
// concept), so a caller reading any one chunk's result already knows whether the snapshot itself was
// truncated, with no need to consult the others. A snapshot with zero (post-cap) downpipes still yields
// exactly ONE (empty-metrics) chunk, matching buildOtlpResourceMetrics's existing behaviour of always
// posting a body (a heartbeat) even when every metric array is empty.
export function buildOtlpResourceMetricsChunks(downpipes: OtlpDownpipeMetrics[], nowMs: number): ShapedOtlpPush[] {
  const capped = downpipes.slice(0, OTLP_PUSH_DOWNPIPE_CAP);
  const droppedCount = downpipes.length - capped.length;
  const truncated = droppedCount > 0;
  const groups: OtlpDownpipeMetrics[][] = [];
  for (let i = 0; i < capped.length; i += OTLP_PUSH_CHUNK_DOWNPIPES) groups.push(capped.slice(i, i + OTLP_PUSH_CHUNK_DOWNPIPES));
  if (groups.length === 0) groups.push([]);
  return groups.map((g) => {
    const { body, contentType } = buildOneOtlpBody(g, nowMs);
    return { body, contentType, downpipeCount: g.length, truncated, droppedCount };
  });
}
