// Pins OTLP/HTTP partial_success handling on the metrics push sender.
//
// WHAT THIS PINS: the OTLP/HTTP spec says a collector that accepts only PART of the exported data MUST
// answer HTTP 200 with an ExportMetricsServiceResponse whose `partialSuccess { rejectedDataPoints,
// errorMessage }` is populated. Before this fix deliverOtlpPush did `void resp.body?.cancel()` on a 200 and
// returned a clean success, so a partial rejection (a cardinality/quota drop of some datapoints) was
// recorded as a fully-delivered push: the customer's dashboards silently miss those points. This validator
// asserts the sender READS the 200 body, surfaces rejectedDataPoints, and that the drain records it on the
// delivery trail (loud signal, mirroring the existing `truncated` flag) rather than a silent full success.
//
// Run: node test/validate-destsim-otlp-partial.ts

import { deliverOtlpPush } from "../src/notify/otlp-push-sender.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

// A PUBLIC-looking endpoint so the sender's send-time SSRF screen (screenSinkHost) passes and we reach the
// stubbed fetch; loopback would be refused before the request (deliverOtlpPush has no internal-sink override
// by design). We never open a socket: fetch is stubbed to return a hand-built OTLP response.
const PUBLIC_OTLP_URL = "https://otlp.example-collector.test/v1/metrics";

async function withStubbedFetch(
  responder: (input: RequestInfo | URL, init?: RequestInit) => Response,
  body: () => Promise<void>,
): Promise<void> {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => responder(input, init)) as typeof fetch;
  try {
    await body();
  } finally {
    globalThis.fetch = realFetch;
  }
}

async function main(): Promise<void> {
  // 1. A 200 carrying partial_success -> the sender must surface the rejected-datapoint count.
  await withStubbedFetch(
    () =>
      new Response(JSON.stringify({ partialSuccess: { rejectedDataPoints: 7, errorMessage: "cardinality quota exceeded" } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    async () => {
      const r = await deliverOtlpPush(PUBLIC_OTLP_URL, "{}", "Authorization", "Bearer x");
      ok("partial_success 200: sender returns ok:true (the request WAS accepted)", r.ok === true);
      ok("partial_success 200: sender surfaces rejectedDataPoints=7 (never silently dropped)", r.rejectedDataPoints === 7);
    },
  );

  // 1b. proto3 JSON serialises an int64 as a decimal STRING; the reader accepts that spelling too.
  await withStubbedFetch(
    () => new Response(JSON.stringify({ partialSuccess: { rejectedDataPoints: "42" } }), { status: 200, headers: { "content-type": "application/json" } }),
    async () => {
      const r = await deliverOtlpPush(PUBLIC_OTLP_URL, "{}", "Authorization", "Bearer x");
      ok('partial_success 200 with a STRING rejectedDataPoints ("42"): parsed to 42 (proto3 int64 JSON mapping)', r.ok === true && r.rejectedDataPoints === 42);
    },
  );

  // 2. A clean 200 (no partialSuccess, or rejectedDataPoints 0) -> no rejection surfaced.
  await withStubbedFetch(
    () => new Response(JSON.stringify({ partialSuccess: { rejectedDataPoints: 0 } }), { status: 200, headers: { "content-type": "application/json" } }),
    async () => {
      const r = await deliverOtlpPush(PUBLIC_OTLP_URL, "{}", "Authorization", "Bearer x");
      ok("clean 200 (rejected 0): ok:true", r.ok === true);
      ok("clean 200 (rejected 0): no rejectedDataPoints surfaced", r.rejectedDataPoints === undefined || r.rejectedDataPoints === 0);
    },
  );

  // 3. An empty 200 body -> no rejection, no throw (a collector that returns 200 with no body is fine).
  await withStubbedFetch(
    () => new Response("", { status: 200 }),
    async () => {
      const r = await deliverOtlpPush(PUBLIC_OTLP_URL, "{}", "Authorization", "Bearer x");
      ok("empty 200 body: ok:true, no rejection, no throw", r.ok === true && (r.rejectedDataPoints === undefined || r.rejectedDataPoints === 0));
    },
  );

  // 4. A malformed 200 body -> the sender must not throw; treat as delivered with no parseable rejection.
  await withStubbedFetch(
    () => new Response("<html>not json</html>", { status: 200, headers: { "content-type": "text/html" } }),
    async () => {
      const r = await deliverOtlpPush(PUBLIC_OTLP_URL, "{}", "Authorization", "Bearer x");
      ok("malformed 200 body: ok:true, no rejection surfaced, no throw", r.ok === true && r.rejectedDataPoints === undefined);
    },
  );

  // 5. An oversized 200 body (> the 16 KiB read cap) is not parsed: a collector that answers 200 with a huge
  //    or streaming body is not sending us OTLP, so the bounded read skips it (delivered, no rejection).
  await withStubbedFetch(
    () => new Response(`{"partialSuccess":{"rejectedDataPoints":9},"pad":"${"x".repeat(20000)}"}`, { status: 200, headers: { "content-type": "application/json" } }),
    async () => {
      const r = await deliverOtlpPush(PUBLIC_OTLP_URL, "{}", "Authorization", "Bearer x");
      ok("oversized 200 body (>16 KiB): ok:true, not parsed for partial (bounded read skips it)", r.ok === true && r.rejectedDataPoints === undefined);
    },
  );

  // 6. A non-2xx is unchanged: still a delivery failure with a classified code, no partial parsing.
  await withStubbedFetch(
    () => new Response("rate limited", { status: 429 }),
    async () => {
      const r = await deliverOtlpPush(PUBLIC_OTLP_URL, "{}", "Authorization", "Bearer x");
      ok("429: ok:false, code http-rate-limited (unchanged)", r.ok === false && r.code === "http-rate-limited");
    },
  );

  // 6. The drain's outcome recorder persists rejectedDataPoints on the trail (loud signal on the redacted
  //    admin view), not a silent success. Drive the real DO end to end.
  {
    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    const OWNER_CALLER = { method: "token" as const, email: null, subject: null, groups: [] };
    await dobj.setOtlpPushDestination(
      { endpoint: PUBLIC_OTLP_URL, authHeaderName: "Authorization", authHeaderValue: "Bearer x", enabled: true },
      OWNER_CALLER,
    );
    const rec = await dobj.getOtlpPushRecordRaw();
    const gen = rec?.gen ?? "";
    await dobj.recordOtlpPushOutcome({ ok: true, httpStatus: 200, downpipeCount: 3, rejectedDataPoints: 7, gen });
    const view = await dobj.getOtlpPushView();
    const last = view.trail[view.trail.length - 1];
    ok("DO trail records the push as ok:true (the request was accepted)", last?.ok === true);
    ok("DO trail carries rejectedDataPoints=7 (visible partial loss, not a silent success)", last?.rejectedDataPoints === 7);
  }

  console.log(failures === 0 ? "\nDESTSIM OTLP PARTIAL_SUCCESS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
