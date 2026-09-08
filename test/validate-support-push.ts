// Prove the support pack's SIEM-push and OTLP-push sections carry the delivery trail redaction-safely.
//
// Both push drains record a bounded
// delivery trail on their scheduler-DO records, but no support-pack section collected it, so "our SIEM feed
// stopped" / "OTLP metrics stopped arriving" was undiagnosable from the bundle. The new siemPush/otlpPush
// sections project the EXISTING coarse trail. This test drives the real gatherers through a DO double and
// asserts: (1) the trail rides with coarse http status + reason + counts; (2) the cursor lag is derived;
// (3) the consecutive-failure streak is counted; (4) the endpoint URL / host / token NEVER appear (the DO
// view exposes them for the console, the pack must not); (5) a fetch fault reads section "error", a
// not-configured drain reads "empty".
//
// Run:  node test/validate-support-push.ts
// In-memory doubles only; no network, no deploy, no cost.

import { fetchSiemPush, fetchOtlpPush } from "../src/admin/support-sections-push.ts";
// The ENGINE'S authority for the two closed vocabularies, imported so section 8 below is driven by the real
// list rather than by a list transcribed into this test (which is the defect it exists for, one layer up).
import { PUSH_FORMATS, PUSH_SINKS } from "../src/sched/scheduler-do-limits.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A DO double serving a chosen /push and /otlp-push view (the same shape getSiemPushView/getOtlpPushView
// return), including the fields the pack MUST strip (endpoint, authHeaderName, syslog host).
function pushScheduler(siem: unknown, otlp: unknown): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/push") return new Response(JSON.stringify(siem));
      if (url.pathname === "/otlp-push") return new Response(JSON.stringify(otlp));
      return new Response("{}");
    },
  } as unknown as DurableObjectStub;
}
function throwingScheduler(path: string): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === path) throw new Error("push DO unavailable");
      return new Response("{}");
    },
  } as unknown as DurableObjectStub;
}

async function main(): Promise<void> {
  console.log("validate-support-push\n");

  const SECRET_URL = "https://siem.example.com/ingest?token=SECRET";
  const siemView = {
    present: true,
    endpoint: SECRET_URL, // MUST be stripped
    authHeaderName: "Authorization", // MUST be stripped
    format: "cef",
    enabled: true,
    sink: "http",
    lastPushedSeq: 40,
    headSeq: 55,
    setBy: "owner@example.com", // MUST be stripped
    trail: [
      { at: "2026-07-11T00:00:00Z", ok: true, httpStatus: 200, count: 10, fromSeq: 1, toSeq: 10 },
      // "http-5xx" is what the engine ACTUALLY emits for a 503 (classifyHttpDeliveryStatus). The pack GATES
      // the trail reason on the closed vocabulary, so a fictional code would be coarsened to the unknown-code
      // placeholder -- the fixture has to speak the real vocabulary to test the real path.
      { at: "2026-07-11T01:00:00Z", ok: false, httpStatus: 503, reason: "http-5xx", count: 5, fromSeq: 11, toSeq: 15 },
      { at: "2026-07-11T02:00:00Z", ok: false, httpStatus: 503, reason: "http-5xx", count: 5, fromSeq: 16, toSeq: 20 },
    ],
  };
  const otlpView = {
    present: true,
    endpoint: SECRET_URL, // MUST be stripped
    enabled: true,
    trail: [
      { at: "2026-07-11T00:00:00Z", ok: true, httpStatus: 200, downpipeCount: 12 },
      { at: "2026-07-11T01:00:00Z", ok: true, httpStatus: 200, downpipeCount: 200, truncated: true, rejectedDataPoints: 7 },
    ],
  };

  const sched = pushScheduler(siemView, otlpView);
  const siem = (await fetchSiemPush(sched)) as Record<string, unknown>;
  const otlp = (await fetchOtlpPush(sched)) as Record<string, unknown>;

  // 1. Trail + coarse fields present.
  ok("siemPush.configured is true and the format/sink/enabled ride", siem.configured === true && siem.format === "cef" && siem.sink === "http" && siem.enabled === true);
  // The second attempt is pulled into a const and asserted PRESENT before its fields are read: under
  // noUncheckedIndexedAccess a missing element would otherwise read as undefined, and `undefined.httpStatus`
  // is a throw rather than a FAIL line. The explicit !== undefined keeps a short trail an honest failure.
  const siemTrailRows = (siem.trail ?? []) as Array<{ httpStatus?: number; reason?: string }>;
  const siemAttempt2 = siemTrailRows[1];
  ok("siemPush.trail carries the last attempts with http status + reason + counts", Array.isArray(siem.trail) && siemTrailRows.length === 3 && siemAttempt2 !== undefined && siemAttempt2.httpStatus === 503 && siemAttempt2.reason === "http-5xx");
  // 2. Cursor lag derived (headSeq - lastPushedSeq).
  ok("siemPush.lag is the derived cursor lag (headSeq - lastPushedSeq)", siem.lag === 15);
  // 3. Consecutive trailing failures counted.
  ok("siemPush.consecutiveFailures counts the trailing failure streak", siem.consecutiveFailures === 2);
  // 4. Redaction: the endpoint URL / token / auth header / setBy NEVER appear anywhere in the section.
  const siemStr = JSON.stringify(siem);
  ok("siemPush NEVER carries the endpoint URL, token, auth header name or setBy (redaction)", !siemStr.includes("siem.example.com") && !siemStr.includes("SECRET") && !siemStr.includes("Authorization") && !siemStr.includes("owner@example.com"));

  // OTLP: loud signals ride (truncated over-cap, rejectedDataPoints partial-success), endpoint stripped.
  // Same index-access discipline as the SIEM trail above: the second attempt is asserted present, then read.
  const otlpTrailRows = (otlp.trail ?? []) as Array<{ truncated?: boolean; rejectedDataPoints?: number }>;
  const otlpAttempt2 = otlpTrailRows[1];
  ok("otlpPush.trail carries downpipeCount + truncated + rejectedDataPoints (the loud partial-loss signals)", Array.isArray(otlp.trail) && otlpAttempt2 !== undefined && otlpAttempt2.truncated === true && otlpAttempt2.rejectedDataPoints === 7);
  ok("otlpPush NEVER carries the endpoint URL or token (redaction)", !JSON.stringify(otlp).includes("siem.example.com") && !JSON.stringify(otlp).includes("SECRET"));

  // 5a. Not-configured drain reads a minimal configured:false (section() will mark it "empty").
  const empty = (await fetchSiemPush(pushScheduler({ present: false, trail: [] }, { present: false, trail: [] }))) as Record<string, unknown>;
  ok("a not-configured SIEM push drain returns { configured:false } with no trail (honest absence)", empty.configured === false && empty.trail === undefined);

  // 5b. A fetch fault PROPAGATES (the gatherer does not swallow it), so section() records "error".
  let threw = false;
  try {
    await fetchSiemPush(throwingScheduler("/push"));
  } catch {
    threw = true;
  }
  ok("a /push fetch fault propagates out of fetchSiemPush (so section() records 'error', not a clean empty)", threw);

  // 6. CLOSED-REASON GATE + the unknown-code placeholder.
  // The trail's `reason` is coarsened by every recording site to a closed enum member, and the pack gates on
  // the union of those vocabularies. Two properties are load-bearing:
  //   (a) REDACTION -- a reason carrying a live-looking secret, a customer host or raw error text must NEVER
  //       reach the pack, no matter what the DO hands back. It collapses to the fixed placeholder.
  //   (b) NON-SILENCE -- the drift is COUNTED rather than silently dropped, because a recording site that grows
  //       a code the allowlist has not learned yet would otherwise vanish from the trail, leaving a failure row
  //       with no cause at all -- indistinguishable from a healthy one to a bot keying off `reason`.
  const POISON = "https://evil.example.com/hook?token=SECRET-abc123 ECONNREFUSED at Object.<anonymous>";
  const drifted = (await fetchSiemPush(pushScheduler({
    present: true, format: "cef", enabled: true, sink: "http", lastPushedSeq: 1, headSeq: 1,
    trail: [
      { at: "2026-07-11T03:00:00Z", ok: false, httpStatus: 500, reason: POISON, count: 1, fromSeq: 1, toSeq: 1 },
      { at: "2026-07-11T04:00:00Z", ok: false, httpStatus: 0, reason: "wrap-key-invalid", count: 0 },
    ],
  }, { present: false, trail: [] }))) as Record<string, unknown>;
  const dRows = drifted.trail as Array<{ reason?: string }>;
  ok("an out-of-vocabulary trail reason collapses to the 'unknown-code' placeholder (never the raw string)", dRows[0]?.reason === "unknown-code");
  ok("a poison reason (secret + customer host + raw error text) NEVER reaches the pack", !JSON.stringify(drifted).includes("SECRET-abc123") && !JSON.stringify(drifted).includes("evil.example.com") && !JSON.stringify(drifted).includes("ECONNREFUSED"));
  ok("unknownReasonCount counts the drifted rows (the drop is visible, not silent)", drifted.unknownReasonCount === 1);
  // A PRE-DELIVERY pass fault code (the rotated-CONFIG_WRAP_KEY stop) is a real vocabulary member and rides.
  ok("a closed PUSH_PASS_FAIL_CODES member (wrap-key-invalid) rides the trail verbatim", dRows[1]?.reason === "wrap-key-invalid");

  // 7. The OTLP partial-success body class rides on an ok:TRUE row: a 200 whose partial_success body the
  // drain could not read must not be swallowed into a fake clean delivery ("the collector silently stopped").
  const otlpPartial = (await fetchOtlpPush(pushScheduler({ present: false, trail: [] }, {
    present: true, enabled: true,
    trail: [{ at: "2026-07-11T05:00:00Z", ok: true, httpStatus: 200, reason: "otlp-partial-body-unparseable", downpipeCount: 3 }],
  }))) as Record<string, unknown>;
  ok("otlpPush carries the partial-success body class on an ok:true row (a fake clean delivery is now named)", (otlpPartial.trail as Array<{ ok?: boolean; reason?: string }>)[0]?.reason === "otlp-partial-body-unparseable");

  // 8. THE PACK'S FORMAT AND SINK VOCABULARIES ARE THE ENGINE'S, NOT A COPY OF THEM.
  //
  // If the pack gated the format/sink through its own hand-written set instead of the engine's authority, a
  // format or sink outside that copy would drop silently: the key would simply be ABSENT, reading exactly
  // like an older engine that never reported it, so a customer's push destination could vanish from every
  // bundle with no visible failure.
  //
  // The loop below is driven by the ENGINE'S OWN authority, not by a list written here. That is the point: a
  // ninth PushFormat added to scheduler-do-limits.ts is covered by this test with no second edit, in this file
  // or in support-sections-push.ts. The floor under the loop stops it passing vacuously if the import ever
  // resolves to an empty list.
  ok(`the format authority is non-empty and the sink authority is non-empty (${PUSH_FORMATS.length} formats, ${PUSH_SINKS.length} sinks)`, PUSH_FORMATS.length >= 8 && PUSH_SINKS.length >= 3);
  const droppedFormats: string[] = [];
  for (const format of PUSH_FORMATS) {
    const projected = (await fetchSiemPush(pushScheduler({ present: true, format, enabled: true, sink: "http", lastPushedSeq: 1, headSeq: 1, trail: [] }, { present: false, trail: [] }))) as Record<string, unknown>;
    if (projected.format !== format) droppedFormats.push(format);
  }
  ok(`every engine PushFormat rides into the pack (dropped: ${droppedFormats.length === 0 ? "none" : droppedFormats.join(", ")})`, droppedFormats.length === 0);
  const droppedSinks: string[] = [];
  for (const sink of PUSH_SINKS) {
    // A syslog-tls destination carries cef (the only formats that sink can deliver), so the fixture is a
    // deliverable pair rather than a shape the config boundaries would refuse.
    const format = sink === "syslog-tls" ? "cef" : "ndjson";
    const projected = (await fetchSiemPush(pushScheduler({ present: true, format, enabled: true, sink, lastPushedSeq: 1, headSeq: 1, trail: [] }, { present: false, trail: [] }))) as Record<string, unknown>;
    if (projected.sink !== sink) droppedSinks.push(sink);
  }
  ok(`every engine PushSink rides into the pack (dropped: ${droppedSinks.length === 0 ? "none" : droppedSinks.join(", ")})`, droppedSinks.length === 0);
  // Splunk by name, because that is the bundle the defect was found on: a Splunk destination's pack section
  // must contain the string a diagnoser would search for.
  const splunkSection = (await fetchSiemPush(pushScheduler({ present: true, format: "splunk-hec", enabled: true, sink: "http", lastPushedSeq: 7, headSeq: 9, trail: [] }, { present: false, trail: [] }))) as Record<string, unknown>;
  ok("a Splunk HEC destination's pack section names Splunk (format: splunk-hec), never an absent format", splunkSection.format === "splunk-hec" && JSON.stringify(splunkSection).includes("splunk"));
  // The gate is still a GATE: a value outside the engine's authority is dropped rather than propagated.
  const bogus = (await fetchSiemPush(pushScheduler({ present: true, format: "ecs", enabled: true, sink: "syslog", lastPushedSeq: 1, headSeq: 1, trail: [] }, { present: false, trail: [] }))) as Record<string, unknown>;
  ok("a format and a sink outside the engine's authority are still DROPPED (the projection gates, it does not echo)", bogus.format === undefined && bogus.sink === undefined);

  console.log(failures === 0 ? "\nALL SUPPORT-PUSH VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
