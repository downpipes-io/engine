// The bespoke egress-secure sender for the OTLP/HTTP metrics push destination (mon-otlp, PLAN.md
// M2), used by the cron drain (cron/otlp-push-pass.ts). It copies deliverSiemPush's exact send hygiene
// (siem-push-sender.ts / notify/types.ts) -- AbortController + WEBHOOK_TIMEOUT_MS, redirect:"manual",
// non-throwing, void resp.body?.cancel(), and the send-time SSRF re-screen via screenSinkHost -- but is its
// OWN small file (not a reuse of deliverSiemPush) so the SIEM push and OTLP push egress concerns stay
// cleanly separated, the same discipline PUSH_SECRET_AAD / PUSH_S3_SECRET_AAD / OTLP_PUSH_SECRET_AAD keep
// for the secrets themselves. Unlike deliverSiemPush there is no url-token option and no per-format
// content-type: OTLP/HTTP JSON is always POSTed as application/json, and no OTLP collector this build
// targets uses a path-token intake, so neither complexity is carried over.

import { classifyHttpDeliveryStatus, classifyNetworkFailure, type DeliveryFailCode, screenSinkHost, WEBHOOK_TIMEOUT_MS } from "./types.ts";

// OtlpPartialBodyClass is the CLOSED class of what the collector's 200 body actually WAS when the sender went
// looking for partial_success (gap G032). The class rides on the result's `code` (and thence the push
// trail's `reason`) so the pack can tell a collector that CONFIRMED a clean accept from one whose answer we
// could not read at all:
//   - otlp-partial-body-absent: the 200 carried no body / zero bytes (nothing to confirm against).
//   - otlp-partial-body-oversized: the body exceeded OTLP_RESP_MAX_BYTES, so it was never parsed.
//   - otlp-partial-body-unparseable: the body was not proto3-JSON we could read (or the field was malformed).
// A body that parsed cleanly sets NO code (the ok class), so a healthy drain's trail stays quiet. Never the
// collector's errorMessage, host or token -- a closed enum only.
export type OtlpPartialBodyClass = "otlp-partial-body-absent" | "otlp-partial-body-oversized" | "otlp-partial-body-unparseable";

// OTLP_PARTIAL_BODY_CLASSES is the runtime allow-list of the closed vocabulary (defence in depth).
export const OTLP_PARTIAL_BODY_CLASSES: ReadonlySet<string> = new Set<OtlpPartialBodyClass>([
  "otlp-partial-body-absent", "otlp-partial-body-oversized", "otlp-partial-body-unparseable",
]);

export interface OtlpPushSendResult {
  ok: boolean;
  status?: number;
  // On a FAILURE this is the closed DeliveryFailCode. On a SUCCESS (ok:true) it may instead carry the closed
  // OtlpPartialBodyClass (gap G032): the collector accepted the push, but its partial_success body could not be
  // read, so "delivered clean" is a weaker claim than it looks. Both vocabularies are closed enums, and the
  // drain folds this field into the push trail's `reason` either way.
  code?: DeliveryFailCode | OtlpPartialBodyClass;
  // rejectedDataPoints is the count from an OTLP/HTTP partial_success response: a collector that accepts only
  // PART of the exported data answers HTTP 200 with an ExportMetricsServiceResponse carrying
  // partialSuccess.rejectedDataPoints (> 0). The request WAS accepted (ok stays true), but this many points
  // were dropped server-side; surfacing it lets the drain record a LOUD partial-loss signal on the trail
  // (mirroring `truncated`) instead of reading the 200 as a fully-delivered push (destsim finding F1,
  // HARDENING.md item 15). Absent/0 when the collector accepted everything.
  rejectedDataPoints?: number;
}

// OTLP_RESP_MAX_BYTES bounds how much of a 200 response body the sender reads to look for partial_success. An
// ExportMetricsServiceResponse is tiny (a count + a short message); a collector that answers 200 with a large
// or streaming body is not sending us OTLP, so we cap the read and treat an unparseable body as "no partial
// info" (a clean delivery) rather than holding the connection open or throwing.
const OTLP_RESP_MAX_BYTES = 16 * 1024;

// readOtlpRejectedDataPoints parses an OTLP/HTTP JSON success body for partialSuccess.rejectedDataPoints. It
// NEVER throws: any read/parse/shape problem returns undefined (treated as a clean delivery), because a
// missing or malformed body on a 200 is not itself a delivery failure. The proto3 JSON mapping serialises an
// int64 field as either a JSON number or a decimal string, so both spellings are accepted.
async function readOtlpRejectedDataPoints(resp: Response): Promise<{ rejectedDataPoints?: number; bodyClass?: OtlpPartialBodyClass }> {
  try {
    if (resp.body === null) return { bodyClass: "otlp-partial-body-absent" };
    const buf = await resp.arrayBuffer();
    if (buf.byteLength === 0) return { bodyClass: "otlp-partial-body-absent" };
    if (buf.byteLength > OTLP_RESP_MAX_BYTES) return { bodyClass: "otlp-partial-body-oversized" };
    const doc = JSON.parse(new TextDecoder().decode(buf)) as { partialSuccess?: { rejectedDataPoints?: unknown } };
    const raw = doc.partialSuccess?.rejectedDataPoints;
    // A partialSuccess that is present but whose count is NOT a readable proto3 int64 (a NaN, an object, a
    // non-numeric string) is UNPARSEABLE, not "zero rejected": coercing it to 0 is exactly the silent
    // clean-read this gap is about. An ABSENT partialSuccess (the healthy case) parses to the ok class.
    if (raw !== undefined && raw !== null) {
      const n = typeof raw === "number" ? raw : typeof raw === "string" ? Number(raw) : Number.NaN;
      if (!Number.isFinite(n) || n < 0) return { bodyClass: "otlp-partial-body-unparseable" };
      const clamped = Math.min(Math.floor(n), Number.MAX_SAFE_INTEGER);
      return clamped > 0 ? { rejectedDataPoints: clamped } : {};
    }
    return {};
  } catch {
    return { bodyClass: "otlp-partial-body-unparseable" };
  }
}

// deliverOtlpPush POSTs an already-built OTLP ResourceMetrics JSON body to the collector's endpoint, with
// the ONE configured auth header (a bearer token, or a vendor API-key header such as Datadog's DD-API-KEY
// or New Relic's Api-Key) and content-type application/json. There is no per-destination internal-sink
// override: isAllowedWebhookUrl has already SSRF-refused an internal target before an OTLP push destination
// can ever be stored, so the send-time re-screen below only ever needs to catch a bypass of that boundary
// (a future migration, a hand-edited storage value), never a legitimate opt-in. It NEVER throws.
export async function deliverOtlpPush(url: string, body: string, authHeaderName: string, authHeaderValue: string): Promise<OtlpPushSendResult> {
  // Re-screen the host at SEND time (defence in depth, the same discipline deliverSiemPush and
  // deliverPayload apply): a stored endpoint can never be posted to an internal target even if a future
  // migration or a hand-edited storage value bypassed the config-time isAllowedWebhookUrl check.
  const sinkScreen = screenSinkHost(url);
  if (sinkScreen === "url-invalid") return { ok: false, code: "url-invalid" };
  if (sinkScreen === "internal-literal") return { ok: false, code: "internal-sink-blocked" };
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, WEBHOOK_TIMEOUT_MS);
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", [authHeaderName]: authHeaderValue },
      body,
      signal: controller.signal,
      redirect: "manual",
    });
    const ok = resp.ok;
    const status = resp.status;
    if (ok) {
      // A 200 can carry an OTLP partial_success: read the (bounded) body to detect server-side datapoint
      // rejection instead of blindly cancelling it as a clean delivery (finding F1). readOtlpRejectedDataPoints
      // consumes the body, so the connection is released either way.
      // The body CLASS rides alongside the count (gap G032): an oversized/unparseable/absent body means we
      // could not confirm a clean accept, which must never read as a confirmed-clean push.
      const partial = await readOtlpRejectedDataPoints(resp);
      return {
        ok,
        status,
        ...(partial.rejectedDataPoints !== undefined ? { rejectedDataPoints: partial.rejectedDataPoints } : {}),
        ...(partial.bodyClass !== undefined ? { code: partial.bodyClass } : {}),
      };
    }
    // Release the underlying connection; an unconsumed body holds the TCP connection open until exit.
    void resp.body?.cancel();
    return { ok, status, code: classifyHttpDeliveryStatus(status) };
  } catch (e) {
    // A thrown fetch is a timeout (we aborted at the send timeout) or a transport failure, coarsened to its
    // CLOSED sub-cause (dns / tls / reset / other, gap G248) at this site; the exception text never leaves.
    return { ok: false, code: timedOut ? "timeout" : classifyNetworkFailure(e) };
  } finally {
    clearTimeout(timer);
  }
}
