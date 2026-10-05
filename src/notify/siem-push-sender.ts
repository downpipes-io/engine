// The egress-secure sender for the SIEM push destination, shared by the cron drain
// (cron/siem-push-pass.ts) and the admin test-send route (admin/router-push.ts). It copies
// deliverPayload's send hygiene (types.ts) -- AbortController + WEBHOOK_TIMEOUT_MS,
// redirect:"manual", non-throwing, and the send-time SSRF re-screen via
// screenSinkHost -- but deliverPayload hardcodes content-type:application/json and has no custom-header
// parameter, so it cannot carry the one configured SIEM auth header (an HEC token, a Datadog key, a
// bearer) a push destination needs. This bespoke sender is reused identically by both call
// sites, so no outbound fetch to a customer-controlled push endpoint can ever bypass the re-screen.

import { classifyTransportFault } from "./transport-probe.ts";
import { classifyHttpDeliveryStatus, type DeliveryFailCode, screenResolvedIfHostname, screenSinkHost, WEBHOOK_TIMEOUT_MS } from "./types.ts";

// HecBodyClass is the closed class of what a Splunk HEC response body actually was when the sender read
// it, and of what it declared. It exists because HEC's own status code lives in the BODY, not in the HTTP
// status: the documented envelope is {"text":"...","code":N}, and code 0 is the only value that means the
// batch was taken. Reading only the HTTP status is not enough:
//   - a 2xx whose body declares a NON-ZERO code must not read as a clean delivery, or the cursor would
//     advance PAST audit events HEC had positively refused. Those events would never be re-sent: silent,
//     permanent audit-log loss. The fix is to read the body and believe what it says.
//   - a non-2xx must not discard the payload that names WHICH refusal it was. Collapsing every HEC 400 to
//     http-bad-request would leave "the feed stopped" reaching support with no way to tell a refused index
//     from a refused channel from a shape HEC would not parse. Different causes need different fixes, so
//     each gets its own code.
//
// The read classes (what the answer WAS):
//   - hec-body-absent: no body / zero bytes, so HEC's own code could not be read at all.
//   - hec-body-oversized: past HEC_RESP_MAX_BYTES, so it was never parsed.
//   - hec-body-unparseable: not the JSON envelope HEC documents, or a `code` that is not a finite number.
// The declined classes (what the answer SAID). Grouped by the operator action, never by the raw number:
//   - hec-declined-index: the index is the problem (a name the token may not write, or one that is gone).
//   - hec-declined-token: the token is the problem (missing, disabled, wrong, or the wrong auth scheme).
//   - hec-declined-format: HEC refused the BODY as data. Ours to fix, not the customer's.
//   - hec-declined-channel: the request channel / ack configuration was refused (see also the ack design).
//   - hec-declined-busy: the indexer queue is full. Real backpressure, and the retry is the right answer.
//   - hec-declined-other: any other non-zero code, including one Splunk adds in future.
// A body that parses and declares code 0 sets no class, so a healthy drain's trail stays quiet. Never
// HEC's `text`, the endpoint or the token: a closed enum only.
export type HecBodyClass =
  | "hec-body-absent"
  | "hec-body-oversized"
  | "hec-body-unparseable"
  | "hec-declined-index"
  | "hec-declined-token"
  | "hec-declined-format"
  | "hec-declined-channel"
  | "hec-declined-busy"
  | "hec-declined-other";

// HEC_BODY_CLASSES is the runtime allow-list of the closed vocabulary (defence in depth: only a member
// reaches the trail / the pack), mirroring DELIVERY_FAIL_CODES and OTLP_PARTIAL_BODY_CLASSES.
export const HEC_BODY_CLASSES: ReadonlySet<string> = new Set<HecBodyClass>([
  "hec-body-absent", "hec-body-oversized", "hec-body-unparseable",
  "hec-declined-index", "hec-declined-token", "hec-declined-format", "hec-declined-channel", "hec-declined-busy", "hec-declined-other",
]);

// HEC_DECLINED_CLASSES is the subset that is a POSITIVE refusal by HEC (it read the request and said no), as
// opposed to a body we merely could not read. Only this subset may turn a 2xx into a failure, so an
// unreadable answer can never manufacture one.
const HEC_DECLINED_CLASSES: ReadonlySet<HecBodyClass> = new Set<HecBodyClass>([
  "hec-declined-index", "hec-declined-token", "hec-declined-format", "hec-declined-channel", "hec-declined-busy", "hec-declined-other",
]);

// HEC_RESP_MAX_BYTES bounds how much of a response body the sender reads to find HEC's declared code. The
// documented envelope is a short string plus an integer; an endpoint answering with more than 16 KiB is not
// answering in HEC's shape, so the read stops there and the body is classed oversized rather than parsed.
// Unlike the OTLP sender (which buffers the whole body and only THEN checks its length, so its cap gates the
// parse and not the read), this streams with the cap enforced on the bytes actually taken off the socket, the
// same discipline fetchOidcGuarded uses -- a customer-controlled endpoint must not be able to make the drain
// buffer an unbounded body.
const HEC_RESP_MAX_BYTES = 16 * 1024;

// classifyHecCode groups HEC's documented non-zero status codes by the operator action they imply. The number
// itself never leaves this function; only the enum member does. An unrecognised non-zero code (a value Splunk
// adds later) falls to hec-declined-other, so a future code can never fall OUT of the vocabulary and read as
// a success.
function classifyHecCode(code: number): HecBodyClass {
  if (code === 7) return "hec-declined-index"; // incorrect index
  if (code === 1 || code === 2 || code === 3 || code === 4 || code === 16) return "hec-declined-token"; // disabled / required / invalid authorization / invalid token / query-string auth off
  if (code === 5 || code === 6 || code === 12 || code === 13) return "hec-declined-format"; // no data / invalid data format / event field required / event field blank
  if (code === 10 || code === 11 || code === 14) return "hec-declined-channel"; // data channel missing / invalid / ack disabled
  if (code === 9) return "hec-declined-busy"; // server is busy (the indexer queue is full)
  return "hec-declined-other";
}

// readHecBodyClass streams a BOUNDED prefix of the response body and classifies HEC's declared code. It NEVER
// throws and it never branches on the response's content-type: destsim's wrong-content-type fault exists
// precisely because a real endpoint can serve its own ack under a content-type nobody expects, so the shape of
// the CONTENT is the only thing worth reading. It always consumes or cancels the body, so the connection is
// released on every path.
async function readHecBodyClass(resp: Response): Promise<HecBodyClass | undefined> {
  const reader = resp.body?.getReader();
  if (reader === undefined) return "hec-body-absent";
  try {
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > HEC_RESP_MAX_BYTES) {
        // Stop taking bytes the moment the cap is passed; the cap bounds the READ, not just the parse.
        await reader.cancel();
        return "hec-body-oversized";
      }
      chunks.push(value);
    }
    if (total === 0) return "hec-body-absent";
    const buf = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      buf.set(c, off);
      off += c.byteLength;
    }
    const doc = JSON.parse(new TextDecoder().decode(buf)) as { code?: unknown };
    const raw = doc?.code;
    // An ABSENT code is unparseable, not zero. HEC always states its code, so a JSON body without one is not
    // HEC answering, and coercing that silence to "accepted" is exactly the clean-read this fixes. Likewise a
    // code that is present but not a finite number: never coerce it to 0.
    if (typeof raw !== "number" || !Number.isFinite(raw)) return "hec-body-unparseable";
    if (raw === 0) return undefined; // the healthy answer: parsed, and it said accepted
    return classifyHecCode(raw);
  } catch {
    // A parse failure, or a socket dropped mid-body. Either way we did not learn HEC's code.
    return "hec-body-unparseable";
  }
}

export interface SiemPushSendResult {
  ok: boolean;
  status?: number;
  // On a FAILURE this is the closed DeliveryFailCode. It may instead carry the closed HecBodyClass (the
  // splunk-hec format only): on an ok:true send that means HEC accepted the batch but its own answer could not
  // be read, so "delivered" is a weaker claim than it looks; on an ok:false send whose HTTP status was a 2xx it
  // means HEC POSITIVELY refused the batch and the cursor must hold. Both vocabularies are closed enums, and
  // the drain folds this field into the push trail's `reason` either way.
  code?: DeliveryFailCode | HecBodyClass;
}

// deliverSiemPush POSTs an already-shaped body to the push destination's endpoint, with the ONE configured
// auth header and the format's content-type. There is no per-destination internal-sink override (unlike a
// notify webhook channel's allowInternalSink): isAllowedWebhookUrl has already SSRF-refused an internal
// target before a push destination can ever be stored, so allowInternal is always false here, matching
// the endpoint's own config-time posture. It NEVER throws.
//
// URL-TOKEN (opts.omitAuthHeader): when the auth secret rides IN the url (the Devo-style path-token intake,
// spliced by the caller BEFORE this call), the auth header MUST NOT also be sent. The caller passes
// omitAuthHeader:true, so only the content-type header goes on the wire. The final url (which carries the
// secret) is NEVER logged here (this function logs nothing) and never rides the result (only a status/code
// does), so the token cannot leak through the sender. The send-time SSRF re-screen still runs on that final
// url (screenSinkHost reads only the hostname).
// HEC ENVELOPE (opts.hecEnvelope): the caller sets this ONLY for the splunk-hec format, because it is the one
// sink whose response contract this engine knows: {"text":"...","code":N}, code 0 alone meaning accepted. With
// it set, the response body is READ (bounded) and classified instead of cancelled unread. Without it the body
// is cancelled exactly as before, so every other sink's result is byte-identical -- deliberately, since a
// generic sink's `code` field (if it has one at all) means whatever that vendor decided, and reading a 200 from
// an endpoint whose contract we do not know as anything other than a 200 would invent failures.
export async function deliverSiemPush(
  url: string,
  body: string,
  contentType: string,
  authHeaderName: string,
  authHeaderValue: string,
  opts?: { omitAuthHeader?: boolean; hecEnvelope?: boolean },
): Promise<SiemPushSendResult> {
  // Re-screen the host at SEND time (defence in depth, the same discipline deliverPayload applies): a
  // stored endpoint can never be posted to an internal target even if a future migration or a hand-edited
  // storage value bypassed the config-time isAllowedWebhookUrl check.
  const sinkScreen = screenSinkHost(url);
  if (sinkScreen === "url-invalid") return { ok: false, code: "url-invalid" };
  if (sinkScreen === "internal-literal") return { ok: false, code: "internal-sink-blocked" };
  // And what the name RESOLVES to: a name repointed at internal space after it was stored is
  // refused here, not delivered to with the customer's SIEM credential attached.
  if ((await screenResolvedIfHostname(url, sinkScreen, false)).refused) return { ok: false, code: "internal-sink-resolved" };
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, WEBHOOK_TIMEOUT_MS);
  // Omit the auth header when the secret is carried in the url instead (URL-TOKEN); otherwise send the ONE
  // configured header carrying it.
  const headers: Record<string, string> = opts?.omitAuthHeader === true ? { "content-type": contentType } : { "content-type": contentType, [authHeaderName]: authHeaderValue };
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
      redirect: "manual",
    });
    const ok = resp.ok;
    const status = resp.status;
    // ACCEPTANCE IS NOT DELIVERY.
    //
    // `ok` here is nothing more than a 2xx. For splunk-hec that 2xx carries {"text":"...","code":N}, and only
    // code 0 means HEC PARSED and QUEUED the request. The block below reads that code, so a 2xx whose body
    // declares a non-zero code does not pass as a delivery; what HEC itself refuses is caught here.
    //
    // WHAT IS STILL NOT COVERED: even a code 0 is acceptance, not
    // indexing: events behind it can be dropped downstream by an index-time nullQueue transform, a blocked
    // indexing queue or a full disk, none of which HEC can know about at ingest and none of which appear in
    // this response. The caller treats ok:true as delivered and advances the push cursor past the batch, so
    // in those cases the audit events are still never re-sent. The product's "at-least-once delivery"
    // property is therefore at-least-once to HEC ACCEPTANCE, not to the index.
    //
    // Splunk's only mechanism for the stronger claim is indexer acknowledgement: send an
    // X-Splunk-Request-Channel GUID plus ?channel=, then poll /services/collector/ack until the ackId turns
    // true. That is not implemented here, and it cannot be bolted on inside this function -- it needs a second
    // round trip and somewhere durable to hold the pending ackId across ticks. Until then this REMAINING limit
    // is a KNOWN and DELIBERATE one, not an oversight, and it must not be described to a customer as proof of
    // delivery.
    if (opts?.hecEnvelope === true) {
      // readHecBodyClass consumes or cancels the body itself, so the connection is released on every path.
      const bodyClass = await readHecBodyClass(resp);
      if (bodyClass !== undefined && HEC_DECLINED_CLASSES.has(bodyClass)) {
        // HEC POSITIVELY refused this batch. On a non-2xx that only sharpens the reason (the HTTP status
        // already failed the send). On a 2xx it FLIPS the verdict, which is the point: ok:false leaves the
        // cursor where it was, so the same events are re-exported and re-sent next tick instead of being
        // skipped forever. This matches the at-least-once behaviour a persistent HEC 400 already gets: a 2xx
        // whose body declares a refusal holds the cursor exactly as a non-2xx does.
        return { ok: false, status, code: bodyClass };
      }
      // Either HEC declared code 0 (a clean accept: no code rides, byte-identical to today's happy path) or we
      // could not read its answer. An unreadable answer must NEVER manufacture a failure, so ok is untouched;
      // it rides as a caveat on the trail instead, exactly as the OTLP sender's body classes do.
      if (ok) return { ok, status, ...(bodyClass !== undefined ? { code: bodyClass } : {}) };
      // A non-2xx keeps its HTTP classification. A read CLASS must not displace it: "the body was empty" is a
      // strictly weaker fact than "the sink answered 401", and the trail carries one reason.
      return { ok, status, code: classifyHttpDeliveryStatus(status) };
    }
    // Release the underlying connection; an unconsumed body holds the TCP connection open until exit.
    void resp.body?.cancel();
    if (ok) return { ok, status };
    return { ok, status, code: classifyHttpDeliveryStatus(status) };
  } catch (e) {
    // A thrown fetch is a timeout (we aborted at the send timeout) or a transport failure, coarsened to its
    // closed sub-cause (dns / tls / reset / other) at this site -- "the SIEM feed flaps with network-error"
    // is three different fixes (their DNS, their TLS chain, their firewall). The exception text is classified
    // and discarded here; only the enum member ever reaches the push trail.
    //
    // classifyTransportFault, not classifyNetworkFailure: the text classifier alone cannot see a certificate
    // fault on the Workers runtime, because workerd hands JavaScript `internal error; reference = <id>` and
    // logs the real cause where the operator will not read it. classifyTransportFault runs that same text
    // classifier first and only falls back to a structural observation (transport-probe.ts) on the residual,
    // so a fault the text already names costs nothing extra.
    return { ok: false, code: timedOut ? "timeout" : await classifyTransportFault(e, url) };
  } finally {
    clearTimeout(timer);
  }
}
