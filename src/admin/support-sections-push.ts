// Support-pack section gatherers: the SIEM audit-log PUSH and OTLP metrics PUSH delivery trails. Both push
// drains record a bounded delivery trail on their scheduler-DO records (the same trail the console's admin
// push view reads); these gatherers project that EXISTING, already-coarse trail into the pack so "our SIEM
// feed / OTLP metrics stopped arriving" is diagnosable from the bundle, redaction-safe: presence + transport
// + the cursor lag + the last delivery attempts as {at, ok, httpStatus, reason-class, batch counts}. They
// NEVER carry the endpoint URL, auth header name, token, S3 location or syslog host that the admin view
// exposes for the console.

import { PUSH_PASS_FAIL_CODES, PUSH_SINK_FAIL_CODES } from "../cron/siem-push-pass.ts";
import { doURL } from "../do-url.ts";
import { OTLP_PARTIAL_BODY_CLASSES } from "../notify/otlp-push-sender.ts";
import { HEC_BODY_CLASSES } from "../notify/siem-push-sender.ts";
import { SYSLOG_FAIL_CODES } from "../notify/siem-syslog-sender.ts";
import { DELIVERY_FAIL_CODES } from "../notify.ts";
import { PUSH_FORMAT_SET, PUSH_SINK_SET } from "../sched/scheduler-do-limits.ts";
import { clampInt, clampTs } from "./support-shared.ts";

// PUSH_FORMAT_SET / PUSH_SINK_SET are the closed vocabularies the SIEM push view reports (defence in depth:
// anything outside the set is dropped rather than propagated into the pack). They are IMPORTED from the
// engine's one authority (sched/scheduler-do-limits.ts PUSH_FORMATS / PUSH_SINKS) rather than re-typed here,
// because a hand-typed copy drifts from the engine's real vocabulary (the eight PushFormat members and
// "http" | "s3" | "syslog-tls") the moment either side changes: a dropped value is not a visible failure
// here, since the key is simply ABSENT from the section, reading exactly like an engine that never reported
// it. For a Splunk destination that would mean the support bundle carries nothing anywhere in it naming
// Splunk, while the operator's console says Splunk HEC. Deriving both sets from the one authority means a
// ninth format reaches the pack with no second edit in this file.

// PUSH_REASON_SET is the CLOSED union of every reason a push-trail row can carry. A free-text `reason` would
// be a redaction hole the moment a recording site interpolated anything, and a bot-hostile surface (no closed
// set to key rules off), so every recording site coarsens to an enum member and the pack GATES on the union
// of those vocabularies, dropping a non-member:
//   - PUSH_PASS_FAIL_CODES : the PRE-delivery drain faults (a rotated CONFIG_WRAP_KEY, an unreadable config or
//                            cursor, an unresolvable secret), distinct from a silent `return false` that would
//                            leave an empty trail indistinguishable from a drain that was never enabled.
//   - PUSH_SINK_FAIL_CODES : the S3 / syslog target faults.
//   - DELIVERY_FAIL_CODES  : the shared HTTP/network delivery vocabulary (including the network-dns /
//                            network-tls / network-reset split and http-gone = a DEPROVISIONED sink).
//   - SYSLOG_FAIL_CODES    : the syslog-over-TLS split (sockets-unsupported = an ENGINE fault, tls-untrusted =
//                            the receiver's cert, connect-refused = a firewall, + the timeout PHASE).
//   - OTLP_PARTIAL_BODY_CLASSES : set on an ok:true OTLP push whose 200 partial_success body could not be read
//                            (absent / oversized / unparseable), rather than swallowed into a fake clean
//                            delivery.
//   - HEC_BODY_CLASSES     : the splunk-hec response envelope, whose status lives in the BODY. Either HEC
//                            POSITIVELY refused the batch (hec-declined-*, which holds the cursor rather than
//                            advancing past events Splunk threw away) or its answer could not be read
//                            (hec-body-*, an ok:true caveat: accepted is a weaker claim than it looks).
const PUSH_REASON_SET: ReadonlySet<string> = new Set<string>([
  ...PUSH_PASS_FAIL_CODES,
  ...PUSH_SINK_FAIL_CODES,
  ...DELIVERY_FAIL_CODES,
  ...SYSLOG_FAIL_CODES,
  ...OTLP_PARTIAL_BODY_CLASSES,
  ...HEC_BODY_CLASSES,
]);

// UNKNOWN_REASON is the closed PLACEHOLDER a non-member reason collapses to. Silently DROPPING an
// out-of-vocabulary value is itself a silent-evidence bug: a recording site that grows a new code the pack's
// allowlist has not learned yet would vanish from the trail, and the row would read as a failure with no cause
// at all -- indistinguishable from a healthy one to a bot keying off `reason`. Emitting a fixed placeholder
// keeps the redaction guarantee absolute (the raw value never rides) while making the DRIFT itself visible, and
// the per-section unknownReasonCount says how often it happened.
const UNKNOWN_REASON = "unknown-code";

// projectReason gates a stored trail reason against the CLOSED union (PUSH_REASON_SET). A member rides
// verbatim; any other non-empty value collapses to the UNKNOWN_REASON placeholder -- never the raw string, so a
// site that ever interpolated a host, token or response body cannot leak through this seam.
function projectReason(v: unknown): string | undefined {
  if (typeof v !== "string" || v === "") return undefined;
  return PUSH_REASON_SET.has(v) ? v : UNKNOWN_REASON;
}

// countUnknownReasons tallies the trail rows whose reason fell OUTSIDE the closed vocabulary, so a drifted
// recording site is a visible count rather than a silently thinner trail.
function countUnknownReasons(trail: Array<{ reason?: unknown }>): number {
  return trail.reduce((n, a) => (projectReason(a.reason) === UNKNOWN_REASON ? n + 1 : n), 0);
}

// CAUSE_DIGEST_SHAPE gates the trail's Workers-Logs JOIN KEY: the engine's own 12-hex one-way digest
// of the raw fault behind the coarse reason. A closed vocabulary says what CLASS of fault it was; the digest
// says WHICH ONE, and it is byte-identical to the `[cause <hex>]` in the engine's own redacted log line -- so
// support (who sees only the pack) and the customer (who sees only their Workers Logs) can prove they are
// looking at the same failure. Anything that is not bare 12-hex did not come from the engine and is DROPPED,
// so the field can never become a free-text seam.
const CAUSE_DIGEST_SHAPE = /^[0-9a-f]{12}$/;
function projectCauseDigest(v: unknown): string | undefined {
  return typeof v === "string" && CAUSE_DIGEST_SHAPE.test(v) ? v : undefined;
}

// projectAttempt maps ONE stored delivery attempt to its redaction-safe pack shape. Every field is a coarse
// enum / clamped int / boolean by contract (the trail "never a response body"): the httpStatus is clamped to
// 0..999, the reason is gated on the CLOSED vocabulary (a non-member collapses to the unknown-code placeholder,
// never the raw text), the batch counts and seq bounds are non-negative clamped ints. Absent fields stay absent
// (canonicalJSON rejects an explicit undefined).
function projectAttempt(a: { at?: unknown; ok?: unknown; httpStatus?: unknown; reason?: unknown; count?: unknown; fromSeq?: unknown; toSeq?: unknown; failedIndex?: unknown; causeDigest?: unknown }): Record<string, unknown> {
  const reason = projectReason(a.reason);
  return {
    ...(clampTs(a.at) !== undefined ? { at: clampTs(a.at) } : {}),
    ok: a.ok === true,
    ...(typeof a.httpStatus === "number" && Number.isFinite(a.httpStatus) ? { httpStatus: Math.max(0, Math.min(999, Math.floor(a.httpStatus))) } : {}),
    ...(reason !== undefined ? { reason } : {}),
    ...(clampInt(a.count) !== undefined ? { count: clampInt(a.count) } : {}),
    ...(clampInt(a.fromSeq, Number.MAX_SAFE_INTEGER) !== undefined ? { fromSeq: clampInt(a.fromSeq, Number.MAX_SAFE_INTEGER) } : {}),
    ...(clampInt(a.toSeq, Number.MAX_SAFE_INTEGER) !== undefined ? { toSeq: clampInt(a.toSeq, Number.MAX_SAFE_INTEGER) } : {}),
    // failedIndex: on a syslog-shape-failed row, the zero-based POSITION of the poison audit event that
    // broke the batch -- a bounded integer only, never the event's content.
    ...(clampInt(a.failedIndex) !== undefined ? { failedIndex: clampInt(a.failedIndex) } : {}),
    // causeDigest: the join key to the customer's own Workers Logs line for this same fault.
    ...(projectCauseDigest(a.causeDigest) !== undefined ? { causeDigest: projectCauseDigest(a.causeDigest) } : {}),
  };
}


// consecutiveTrailingFailures counts the run of ok:false attempts at the END of the trail (the trail is oldest
// -> newest), the "how long has this been failing" signal a diagnoser reads first.
function consecutiveTrailingFailures(trail: Array<{ ok?: unknown }>): number {
  let n = 0;
  for (let i = trail.length - 1; i >= 0; i--) {
    if (trail[i]?.ok === true) break;
    n++;
  }
  return n;
}

// fetchSiemPush projects the SIEM audit-log push drain's delivery state (GET /push). Redaction-safe: presence,
// the closed format + sink enums, enabled, the cursor lag (headSeq - lastPushedSeq, both non-sensitive audit
// chain positions), the trailing-failure streak, and the last 20 attempts. NEVER the endpoint/host/token/S3
// location. A fetch/parse fault PROPAGATES to section() (recorded "error"); a not-configured drain reads
// "empty" (configured:false with no trail).
export async function fetchSiemPush(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/push"), { method: "GET" });
    const j = (await r.json()) as {
      present?: unknown; format?: unknown; enabled?: unknown; sink?: unknown; lastPushedSeq?: unknown; headSeq?: unknown;
      trail?: Array<{ at?: unknown; ok?: unknown; httpStatus?: unknown; reason?: unknown; count?: unknown; fromSeq?: unknown; toSeq?: unknown; failedIndex?: unknown; causeDigest?: unknown }>;
    };
    const configured = j.present === true;
    const trailRaw = Array.isArray(j.trail) ? j.trail : [];
    const windowed = trailRaw.slice(-20);
    const trail = windowed.map(projectAttempt);
    const unknownReasonCount = countUnknownReasons(windowed);
    const lastPushedSeq = clampInt(j.lastPushedSeq, Number.MAX_SAFE_INTEGER);
    const headSeq = clampInt(j.headSeq, Number.MAX_SAFE_INTEGER);
    const lag = lastPushedSeq !== undefined && headSeq !== undefined ? Math.max(0, headSeq - lastPushedSeq) : undefined;
    if (!configured && trail.length === 0) return { configured: false };
    return {
      configured,
      ...(typeof j.format === "string" && PUSH_FORMAT_SET.has(j.format) ? { format: j.format } : {}),
      ...(typeof j.sink === "string" && PUSH_SINK_SET.has(j.sink) ? { sink: j.sink } : {}),
      ...(typeof j.enabled === "boolean" ? { enabled: j.enabled } : {}),
      ...(lag !== undefined ? { lag } : {}),
      ...(trail.length > 0 ? { consecutiveFailures: consecutiveTrailingFailures(trailRaw), trail } : {}),
      // unknownReasonCount: trail rows whose reason fell outside the closed vocabulary. Non-zero means a
      // recording site has drifted ahead of the pack's allowlist -- evidence the pack would otherwise have lost.
      ...(unknownReasonCount > 0 ? { unknownReasonCount } : {}),
    };
  }
}

// fetchOtlpPush projects the OTLP metrics push drain's delivery state (GET /otlp-push). Redaction-safe:
// presence + enabled + the last 20 attempts, each additionally carrying the OTLP-specific loud signals
// (downpipeCount actually shaped, truncated over-cap, rejectedDataPoints on a 200-partial_success). NEVER the
// endpoint/host/token. A fault PROPAGATES to section(); a not-configured drain reads "empty".
export async function fetchOtlpPush(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/otlp-push"), { method: "GET" });
    const j = (await r.json()) as {
      present?: unknown; enabled?: unknown;
      trail?: Array<{ at?: unknown; ok?: unknown; httpStatus?: unknown; reason?: unknown; downpipeCount?: unknown; truncated?: unknown; droppedCount?: unknown; rejectedDataPoints?: unknown; causeDigest?: unknown }>;
    };
    const configured = j.present === true;
    const trailRaw = Array.isArray(j.trail) ? j.trail : [];
    const windowed = trailRaw.slice(-20);
    const trail = windowed.map((a) => {
      const reason = projectReason(a.reason);
      return {
        ...(clampTs(a.at) !== undefined ? { at: clampTs(a.at) } : {}),
        ok: a.ok === true,
        ...(typeof a.httpStatus === "number" && Number.isFinite(a.httpStatus) ? { httpStatus: Math.max(0, Math.min(999, Math.floor(a.httpStatus))) } : {}),
        // The reason rides on ok:TRUE rows too: an OTLP 200 partial_success body the drain could not read
        // (absent / oversized / unparseable) would otherwise be swallowed into a fake clean delivery, so "the
        // collector silently stopped receiving metrics" would read as a healthy push. Closed-gated like every
        // other.
        ...(reason !== undefined ? { reason } : {}),
        ...(clampInt(a.downpipeCount) !== undefined ? { downpipeCount: clampInt(a.downpipeCount) } : {}),
        ...(a.truncated === true ? { truncated: true } : {}),
        // droppedCount: truncated:true says the batch was over the 5000-point cap, but not by HOW MUCH --
        // so "how many of our downpipes are missing from the dashboards?" is otherwise unanswerable once the
        // fleet outgrows the cap. The shaper already counts the points it drops; the pack carries it.
        // A clamped non-negative int (a count of dropped data points), never a downpipe id or a metric name.
        ...(clampInt(a.droppedCount, 1_000_000_000) !== undefined && (clampInt(a.droppedCount, 1_000_000_000) ?? 0) > 0 ? { droppedCount: clampInt(a.droppedCount, 1_000_000_000) } : {}),
        ...(clampInt(a.rejectedDataPoints) !== undefined && (clampInt(a.rejectedDataPoints) ?? 0) > 0 ? { rejectedDataPoints: clampInt(a.rejectedDataPoints) } : {}),
        // causeDigest: the join key to the customer's own Workers Logs line for this same fault.
        ...(projectCauseDigest(a.causeDigest) !== undefined ? { causeDigest: projectCauseDigest(a.causeDigest) } : {}),
      };
    });
    const unknownReasonCount = countUnknownReasons(windowed);
    if (!configured && trail.length === 0) return { configured: false };
    return {
      configured,
      ...(typeof j.enabled === "boolean" ? { enabled: j.enabled } : {}),
      ...(trail.length > 0 ? { consecutiveFailures: consecutiveTrailingFailures(trailRaw), trail } : {}),
      ...(unknownReasonCount > 0 ? { unknownReasonCount } : {}),
    };
  }
}
