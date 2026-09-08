// test/destsim/server.ts -- a REAL local node:http (and node:tls) destination emulator: not a stub, an
// actual socket-listening server on 127.0.0.1 that a validator points the real engine senders at (via
// channel.url / channel.allowInternalSink:true for the HTTP senders, or the
// __setSyslogConnectForTest(makeRealSyslogConnect()) injection point for the syslog-TLS sender), so the
// wire bytes are proven over an actual accept()/read()/write() socket, never merely constructed in memory.
//
// startEmulator(opts) covers every HTTP-delivered format: the eight SIEM push formats (raw-json / ndjson /
// json-array / splunk-hec / datadog / cef / leef / gelf), OTLP/HTTP, and the six notify-channel JSON shapes
// (webhook / slack / teams / pagerduty / servicenow / jsm). Every accepted request is run through the
// matching STRICT parser (test/destsim/parsers.ts) before being folded into `ledger` -- a real destination
// that "accepts" garbage is worse than no destination at all, so a body that fails strict parsing is
// answered 400, never a rubber-stamped 200. Prometheus is PULLED (GET /metrics), not pushed, so it has no
// place in this push-oriented server; parsePrometheusText is exercised directly against
// renderPrometheusMetrics's output instead (see test/validate-destsim-formats.ts).
//
// startSyslogEmulator() is the TLS sibling for the syslog-over-TLS sink (RFC 5424 records, RFC 6587
// octet-counting, notify/siem-syslog-sender.ts): a node:tls.createServer bound to 127.0.0.1:0 using a
// THROWAWAY self-signed cert (test/vectors/destsim-throwaway-tls-cert.ts -- lives under test/vectors/, not
// alongside its consumer here, because the repo's pre-commit hook only exempts committed PEM private-key
// blocks under that path; see that file's header for the full rationale), paired with makeRealSyslogConnect(), a
// SyslogConnectFn-shaped adapter that opens a REAL node:tls client connection and satisfies the sender's
// exact socket contract (opened / writable.getWriter().write()/.close() / close()) so the sender can be
// driven through its own __setSyslogConnectForTest() injection point against genuine TLS bytes.
//
// LEDGER / DEDUPE IDENTITY: every parsed record is folded into `ledger` (a Map) keyed by the vendor's own
// dedupe identity -- an audit event's `seq:hash` pair for the eleven audit/metrics formats, or the
// PagerDuty dedup_key / ServiceNow message_key / JSM alias for the three incident-channel formats -- so a
// caller can assert at-least-once delivery (the key exists), no-loss (every expected key is present) or
// bounded-dupes (deliveryCount stays under a bound) purely from the DESTINATION's own point of view, exactly
// as a real vendor's correlation engine would see it.
//
// FAULT INJECTION: setFault(f) installs one fault program, applied per request per its pacing (afterN /
// prob, both seeded-deterministic; a bare fault with neither pacing knob applies to every request). "flap"
// carries its own everyN. Every kind is documented on EmulatorFaultKind below.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createNetServer, type AddressInfo, type Socket } from "node:net";
import { TLSSocket, connect as tlsConnect } from "node:tls";
import {
  parseCef,
  parseLeef,
  parseGelf,
  parseSplunkHec,
  parseDatadog,
  parseNdjson,
  parseJsonArray,
  parseRawJson,
  parseOtlpJson,
  parseWebhookPayload,
  parseSlackPayload,
  parseTeamsCard,
  parsePagerDutyPayload,
  parseServiceNowPayload,
  parseJsmCreatePayload,
  parseSyslogFrames,
} from "./parsers.ts";
import { THROWAWAY_TLS_CERT_PEM, THROWAWAY_TLS_KEY_PEM } from "../vectors/destsim-throwaway-tls-cert.ts";

// ============================================================================================================
// Shared types
// ============================================================================================================

export type EmulatorFormat = "raw-json" | "ndjson" | "json-array" | "splunk-hec" | "datadog" | "cef" | "leef" | "gelf" | "otlp" | "webhook" | "slack" | "teams" | "pagerduty" | "servicenow" | "jsm";

export type EmulatorFaultKind =
  | { kind: "ok" }
  // status: the destination rejects/errors the request outright (no parse, no ledger entry).
  | { kind: "status"; code: number; retryAfter?: number; body?: string }
  // malformed-200: the request IS accepted and ledgered (the engine's bytes were fine), but the
  // destination's ACK body is deliberately garbage -- proves a sender that reads the response body (JSM's
  // requestId extraction) degrades gracefully rather than throwing.
  | { kind: "malformed-200" }
  // wrong-content-type: accepted and ledgered, but the ack is served under an unexpected Content-Type
  // (senders in this engine never branch on the response's content-type; this proves that is really true).
  | { kind: "wrong-content-type" }
  // partial-success: OTLP-only. A 200 carrying the documented OTLP/HTTP partialSuccess envelope.
  | { kind: "partial-success"; rejected: number; message: string }
  // jsm-202-then-fail: JSM-only. The create/close 202s with a requestId as usual, but the SUBSEQUENT poll
  // of that requestId reports success:false (the "accepted, then actually failed" async outcome).
  | { kind: "jsm-202-then-fail" }
  // drop-mid-body: the destination starts writing its response, then destroys the socket after N bytes.
  | { kind: "drop-mid-body"; afterBytes: number }
  // stall: the destination never responds within `ms` (this emulator eventually answers well past `ms` so
  // a long test run cannot accumulate unbounded open sockets; a caller proving a client-side timeout should
  // race its own shorter abort against this).
  | { kind: "stall"; ms: number }
  // flap: fails (503) every Nth request; every other request is a clean, ledgered "ok".
  | { kind: "flap"; everyN: number };

export interface FaultPacing {
  // afterN: the fault applies only from the Nth request (1-based) onward; earlier requests are "ok".
  afterN?: number;
  // prob: the fault applies with this probability (0..1) per request, via a seeded deterministic PRNG (NOT
  // Math.random) so a test asserting a specific outcome sequence is reproducible across runs.
  prob?: number;
  seed?: number;
}

export type EmulatorFault = EmulatorFaultKind & FaultPacing;

export interface EmulatorRequestRecord {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: Buffer;
  at: number;
}

export interface LedgerEntry {
  key: string;
  firstSeenAt: number;
  deliveryCount: number;
  sample: unknown;
}

export interface EmulatorHandle {
  url: string;
  port: number;
  ledger: Map<string, LedgerEntry>;
  requests: EmulatorRequestRecord[];
  setFault(f: EmulatorFault): void;
  close(): Promise<void>;
}

// ============================================================================================================
// Deterministic pacing
// ============================================================================================================

// seededRandom is a small, deterministic (mulberry32-style) hash-to-float PRNG: the SAME seed+index always
// yields the SAME float in [0,1), so a `prob`-paced fault is reproducible across runs (no wall-clock/random
// dependence), per the suite-wide determinism requirement.
function seededRandom(seed: number): number {
  let t = (seed + 0x6d2b79f5) | 0;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}

function basePathFor(format: EmulatorFormat): string {
  switch (format) {
    case "jsm":
      return "/v2/alerts";
    case "servicenow":
      return "/api/now/table/em_event";
    case "pagerduty":
      return "/v2/enqueue";
    case "splunk-hec":
      // HEC's real ingest path (Splunk does not serve "/ingest"), so a destination configured with the
      // wrong path is genuinely rejected rather than silently accepted. Observed on a real Splunk Cloud
      // stack, port 8088.
      return "/services/collector/event";
    case "otlp":
      return "/v1/metrics";
    case "webhook":
      return "/webhook";
    case "slack":
      return "/slack/webhook";
    case "teams":
      return "/teams/webhook";
    default:
      return "/ingest";
  }
}

// ============================================================================================================
// Splunk HEC: the OBSERVED contract
// ============================================================================================================
//
// Every status/body pair below was captured against a real Splunk Cloud stack, POSTing to
// its :8088 /services/collector/event listener. Without this contract, a destination configured with
// `Authorization: Bearer <token>` (which real HEC REFUSES) would pass the whole suite green with no auth
// check ever applied.
//
// The two auth failures are DIFFERENT diagnoses and HEC distinguishes them by status:
//   401 code 3 "Invalid authorization" -- the Authorization header's SCHEME is wrong (Bearer, a bare token,
//              or the wrong case). This is OUR bug: no customer credential can fix it.
//   403 code 4 "Invalid token"        -- the scheme was right, the token is not known to the stack. This is
//              the CUSTOMER's credential to fix, and retrying will never help.
// The scheme is a literal, case-sensitive "Splunk": `splunk`, `SPLUNK` and `SPlunk` were all observed to fail
// with 401 code 3, so this is a byte comparison and not a case-insensitive one.
const HEC_SUCCESS_BODY = JSON.stringify({ text: "Success", code: 0 });
const HEC_ERR_TOKEN_REQUIRED = JSON.stringify({ text: "Token is required", code: 2 });
const HEC_ERR_INVALID_AUTHORIZATION = JSON.stringify({ text: "Invalid authorization", code: 3 });
const HEC_ERR_INVALID_TOKEN = JSON.stringify({ text: "Invalid token", code: 4 });
const HEC_HEALTHY_BODY = JSON.stringify({ text: "HEC is healthy", code: 17 });
// Observed: a GET on the event endpoint answers HTTP 405 while its BODY says code 404. The two deliberately
// disagree, which is why anything reading the body's `code` as though it mirrored the HTTP status mislabels
// this case. Encoded here so a reader of our code cannot "tidy" the mismatch away.
const HEC_ERR_NOT_FOUND_BODY = JSON.stringify({ text: "The requested URL was not found on this server.", code: 404 });

// The paths a real HEC listener serves. Anything else 404s, which is what makes a wrong configured path a
// test FAILURE rather than a silent pass.
const HEC_COLLECTOR_PATHS: ReadonlySet<string> = new Set(["/services/collector", "/services/collector/event", "/services/collector/raw", "/services/collector/ack"]);
const HEC_HEALTH_PATHS: ReadonlySet<string> = new Set(["/services/collector/health", "/services/collector/health/1.0"]);

export type HecAuthVerdict = { ok: true; token: string } | { ok: false; status: number; body: string };

// classifyHecAuth is the observed auth ladder, exported so a test can assert every rung without a socket.
// `expected` undefined means "any non-empty token is accepted once the scheme is right" -- the scheme check
// is the part that catches a Bearer/bare/wrong-case header, and it applies unconditionally.
export function classifyHecAuth(authHeader: string | undefined, queryToken: string | undefined, expected: string | undefined): HecAuthVerdict {
  // Query-string auth was observed ENABLED on the probed stack: ?token=<unknown> reached token validation and
  // returned code 4, not code 16 ("Query string authorization is not enabled"). It is a real second channel.
  if (authHeader === undefined || authHeader === "") {
    if (queryToken !== undefined && queryToken !== "") {
      if (expected !== undefined && queryToken !== expected) return { ok: false, status: 403, body: HEC_ERR_INVALID_TOKEN };
      return { ok: true, token: queryToken };
    }
    return { ok: false, status: 401, body: HEC_ERR_TOKEN_REQUIRED };
  }
  // The scheme must be the literal "Splunk" followed by a space. A case-insensitive compare here would
  // re-open exactly the trap this exists to catch.
  if (!authHeader.startsWith("Splunk ")) return { ok: false, status: 401, body: HEC_ERR_INVALID_AUTHORIZATION };
  const token = authHeader.slice("Splunk ".length).trim();
  if (token === "") return { ok: false, status: 401, body: HEC_ERR_INVALID_AUTHORIZATION };
  if (expected !== undefined && token !== expected) return { ok: false, status: 403, body: HEC_ERR_INVALID_TOKEN };
  return { ok: true, token };
}

function ackBodyFor(format: EmulatorFormat): string {
  // NOTE ON WHAT THIS BODY MEANS. {"text":"Success","code":0} is HEC saying it PARSED and QUEUED the request,
  // not that the events are indexed or searchable. Splunk's only mechanism for the stronger claim is indexer
  // acknowledgement (an X-Splunk-Request-Channel GUID plus a poll of /services/collector/ack), which the
  // engine does not implement, so a 200 here is acceptance and nothing more. deliverSiemPush treats it as
  // delivered and the push cursor advances past the batch permanently -- see the claim note in
  // src/notify/siem-push-sender.ts.
  if (format === "splunk-hec") return HEC_SUCCESS_BODY;
  if (format === "otlp") return "{}";
  return JSON.stringify({ ok: true });
}

// extractLedgerKey prefers the vendor's OWN dedupe identity (PagerDuty dedup_key / ServiceNow message_key /
// JSM alias / an audit event's seq:hash). webhook/slack/teams are FIRE-ONLY (contract section 2.2: no
// trigger/resolve state machine, so the real adapters carry no dedup field at all) -- for those, the
// content itself IS the only honest identity a real vendor-side dedup window could key on, so this falls
// back to the exact JSON of the parsed event: a byte-identical retry collapses to one entry (bounded-dupes)
// while any distinct content is its own entry (no-loss), without inventing a field the wire format never
// carries.
// bigIntSafeStringify mirrors JSON.stringify but never throws on a bigint field (plain JSON.stringify
// throws "Do not know how to serialize a BigInt" -- OTLP data points carry timeUnixNano as a bigint, see
// parseOtlpJson): every bigint is rendered as its decimal string, which is lossless and exactly what the
// wire form (OTLP's own timeUnixNano string) already was before parseOtlpJson converted it.
function bigIntSafeStringify(v: unknown): string {
  return JSON.stringify(v, (_k, val) => (typeof val === "bigint" ? val.toString() : val));
}

function extractLedgerKey(ev: unknown): string {
  if (typeof ev !== "object" || ev === null) return bigIntSafeStringify(ev);
  const r = ev as Record<string, unknown>;
  if (typeof r.dedup_key === "string") return r.dedup_key;
  if (typeof r.message_key === "string") return r.message_key;
  if (typeof r.alias === "string") return r.alias;
  if (typeof r.seq === "number" && typeof r.hash === "string") return `${r.seq}:${r.hash}`;
  return bigIntSafeStringify(r);
}

function parseByEmulatorFormat(format: EmulatorFormat, body: Buffer, contentType: string | undefined): unknown[] {
  const opts = contentType !== undefined ? { contentType } : undefined;
  switch (format) {
    case "raw-json":
      return parseRawJson(body, opts).events;
    case "ndjson":
      return parseNdjson(body, opts).events;
    case "json-array":
      return parseJsonArray(body, opts).events;
    case "splunk-hec":
      return parseSplunkHec(body, opts).events;
    case "datadog":
      return parseDatadog(body, opts).events;
    case "cef":
      return parseCef(body, opts).events;
    case "leef":
      return parseLeef(body, opts).events;
    case "gelf":
      return parseGelf(body, opts).events;
    case "otlp":
      return parseOtlpJson(body, opts).events;
    case "webhook":
      return parseWebhookPayload(body, opts).events;
    case "slack":
      return parseSlackPayload(body, opts).events;
    case "teams":
      return parseTeamsCard(body, opts).events;
    case "pagerduty":
      return parsePagerDutyPayload(body, opts).events;
    case "servicenow":
      return parseServiceNowPayload(body, opts).events;
    case "jsm":
      throw new Error("jsm is routed separately (respondJsm handles create/close/poll before this dispatcher is reached)");
  }
}

function safeJsonParse(body: Buffer): unknown {
  try {
    return JSON.parse(body.toString("utf8"));
  } catch {
    return undefined;
  }
}

// ============================================================================================================
// startEmulator: the HTTP destination emulator
// ============================================================================================================

export interface EmulatorOptions {
  format: EmulatorFormat;
  // splunk-hec only: the exact token the emulator will accept after the "Splunk " scheme. When omitted, any
  // non-empty token passes once the SCHEME is right -- the scheme check is never optional, so a Bearer / bare
  // / wrong-case header fails whether or not a caller pins a token.
  hecToken?: string;
}

export async function startEmulator(opts: EmulatorOptions): Promise<EmulatorHandle> {
  const requests: EmulatorRequestRecord[] = [];
  const ledger = new Map<string, LedgerEntry>();
  let fault: EmulatorFault = { kind: "ok" };
  let counter = 0;
  // jsmRequestIdToAlias tracks the JSM async-accepted (202) create/close so the poll endpoint
  // (GET .../requests/{id}) can answer against the SAME episode, mirroring jsm.ts's own create-then-poll
  // sequencing (deliver() polls immediately after a 202, within the same logical call).
  const jsmRequestIdToAlias = new Map<string, string>();

  function recordLedger(key: string, sample: unknown): void {
    const existing = ledger.get(key);
    if (existing) {
      existing.deliveryCount++;
      return;
    }
    ledger.set(key, { key, firstSeenAt: Date.now(), deliveryCount: 1, sample });
  }

  // shouldApplyFault reports whether the CURRENTLY configured fault applies to THIS request, honouring
  // afterN/prob pacing (both compose) and flap's own everyN. counter is 1-based (the first request is #1).
  function shouldApplyFault(): boolean {
    counter++;
    if (fault.kind === "ok") return false;
    let applies = true;
    if (fault.afterN !== undefined && counter < fault.afterN) applies = false;
    if (applies && fault.prob !== undefined) applies = seededRandom((fault.seed ?? 1) * 2654435761 + counter) < fault.prob;
    if (fault.kind === "flap") applies = applies && counter % fault.everyN === 0;
    return applies;
  }

  function respondGeneric(format: EmulatorFormat, body: Buffer, headers: Record<string, string>, activeFault: EmulatorFault, res: ServerResponse): void {
    let parsedEvents: unknown[];
    try {
      parsedEvents = parseByEmulatorFormat(format, body, headers["content-type"]);
    } catch (e) {
      res.writeHead(400, { "content-type": "text/plain" });
      res.end(`destsim emulator: strict parse rejected the request body: ${e instanceof Error ? e.message : String(e)}`);
      return;
    }
    for (const ev of parsedEvents) recordLedger(extractLedgerKey(ev), ev);
    if (activeFault.kind === "malformed-200") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{not-valid-json");
      return;
    }
    if (activeFault.kind === "wrong-content-type") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html>destsim emulator: unexpected content-type on the destination's own ack</html>");
      return;
    }
    if (activeFault.kind === "partial-success" && format === "otlp") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ partialSuccess: { rejectedDataPoints: activeFault.rejected, errorMessage: activeFault.message } }));
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(ackBodyFor(format));
  }

  function respondServiceNow(body: Buffer, activeFault: EmulatorFault, res: ServerResponse): void {
    let events: ReturnType<typeof parseServiceNowPayload>["events"];
    try {
      events = parseServiceNowPayload(body).events;
    } catch (e) {
      res.writeHead(400, { "content-type": "text/plain" });
      res.end(`destsim emulator: strict parse rejected the ServiceNow body: ${e instanceof Error ? e.message : String(e)}`);
      return;
    }
    for (const ev of events) recordLedger(ev.message_key, ev);
    if (activeFault.kind === "malformed-200") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{not-valid");
      return;
    }
    res.writeHead(201, { "content-type": "application/json" });
    res.end(JSON.stringify({ result: "success" }));
  }

  // respondSplunkHec enforces the OBSERVED HEC contract (path, method, then auth) BEFORE the body is parsed,
  // which is the order the real listener uses: malformed JSON with a bad token was observed to answer the
  // TOKEN error (403 code 4), never a parse error. A test that sends rubbish with a bad token therefore proves
  // nothing about body validation, and this ordering is what keeps that honest here too.
  function respondSplunkHec(method: string, url: string, headers: Record<string, string>, body: Buffer, activeFault: EmulatorFault, res: ServerResponse): void {
    const parsedUrl = new URL(url, "http://127.0.0.1");
    const path = parsedUrl.pathname;

    const sendHec = (status: number, payload: string): void => {
      res.writeHead(status, { "content-type": "application/json; charset=UTF-8" });
      res.end(payload);
    };

    // The health endpoint answers 200 with NO auth at all (observed). It is the one HEC surface reachable
    // without a token, so it is the only honest pre-flight reachability probe.
    if (HEC_HEALTH_PATHS.has(path)) {
      if (method !== "GET") {
        sendHec(405, HEC_ERR_NOT_FOUND_BODY);
        return;
      }
      sendHec(200, HEC_HEALTHY_BODY);
      return;
    }
    // A path the listener does not serve is a 404, so a misconfigured collector path FAILS here instead of
    // being rubber-stamped.
    if (!HEC_COLLECTOR_PATHS.has(path)) {
      sendHec(404, HEC_ERR_NOT_FOUND_BODY);
      return;
    }
    // Observed: GET on the event endpoint is HTTP 405 with a body whose `code` says 404. Both halves are
    // reproduced deliberately; they disagree in the real thing.
    if (method !== "POST") {
      sendHec(405, HEC_ERR_NOT_FOUND_BODY);
      return;
    }
    const verdict = classifyHecAuth(headers.authorization, parsedUrl.searchParams.get("token") ?? undefined, opts.hecToken);
    if (!verdict.ok) {
      sendHec(verdict.status, verdict.body);
      return;
    }
    // Authenticated and on a real collector path: now the body is parsed and the batch ack'd, exactly as
    // respondGeneric does for every other format (so the ledger/fault behaviour stays shared, not forked).
    respondGeneric("splunk-hec", body, headers, activeFault, res);
  }

  function respondJsm(method: string, url: string, body: Buffer, activeFault: EmulatorFault, res: ServerResponse): void {
    const parsedUrl = new URL(url, "http://127.0.0.1");
    const base = basePathFor("jsm");
    const path = parsedUrl.pathname;

    if (method === "GET" && path.startsWith(`${base}/requests/`)) {
      const requestId = decodeURIComponent(path.slice(`${base}/requests/`.length));
      const alias = jsmRequestIdToAlias.get(requestId);
      const success = alias !== undefined && activeFault.kind !== "jsm-202-then-fail";
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ requestId, data: { success } }));
      return;
    }

    if (method === "POST" && path !== base && path.endsWith("/close")) {
      const alias = decodeURIComponent(path.slice(base.length + 1, path.length - "/close".length));
      recordLedger(alias, { op: "close", alias, body: safeJsonParse(body) });
      const requestId = `req-close-${alias}-${counter}`;
      jsmRequestIdToAlias.set(requestId, alias);
      res.writeHead(202, { "content-type": "application/json" });
      res.end(JSON.stringify({ result: "request accepted", requestId }));
      return;
    }

    if (method === "POST" && path === base) {
      let events: ReturnType<typeof parseJsmCreatePayload>["events"];
      try {
        events = parseJsmCreatePayload(body).events;
      } catch (e) {
        res.writeHead(400, { "content-type": "text/plain" });
        res.end(`destsim emulator: strict parse rejected the JSM create body: ${e instanceof Error ? e.message : String(e)}`);
        return;
      }
      const created = events[0];
      if (created === undefined) {
        res.writeHead(500, { "content-type": "text/plain" });
        res.end("destsim emulator: JSM create body carried no event");
        return;
      }
      recordLedger(created.alias, { op: "create", ...created });
      const requestId = `req-${created.alias}-${counter}`;
      jsmRequestIdToAlias.set(requestId, created.alias);
      res.writeHead(202, { "content-type": "application/json" });
      res.end(JSON.stringify({ result: "request accepted", took: 0.01, requestId }));
      return;
    }

    res.writeHead(404, { "content-type": "text/plain" });
    res.end("destsim emulator: unrecognised JSM route");
  }

  function respond(method: string, url: string, headers: Record<string, string>, body: Buffer, res: ServerResponse): void {
    const applyFault = shouldApplyFault();
    const activeFault: EmulatorFault = applyFault ? fault : { kind: "ok" };

    if (activeFault.kind === "stall") {
      const timer = setTimeout(() => {
        if (!res.writableEnded) {
          res.writeHead(200, { "content-type": "application/json" });
          res.end("{}");
        }
      }, activeFault.ms);
      // Never block process exit on a stalled response the test itself is about to tear down.
      timer.unref();
      return;
    }
    if (activeFault.kind === "drop-mid-body") {
      const full = JSON.stringify({ ok: true, note: "about to be dropped mid-body by the destsim emulator" });
      const partial = full.slice(0, Math.max(0, activeFault.afterBytes));
      res.writeHead(200, { "content-type": "application/json" });
      res.write(partial);
      res.socket?.destroy();
      return;
    }
    if (activeFault.kind === "status") {
      const h: Record<string, string> = { "content-type": "text/plain" };
      if (activeFault.retryAfter !== undefined) h["retry-after"] = String(activeFault.retryAfter);
      res.writeHead(activeFault.code, h);
      res.end(activeFault.body ?? `destsim emulator: injected status ${activeFault.code}`);
      return;
    }
    if (activeFault.kind === "flap") {
      // shouldApplyFault already decided THIS request is the failing Nth one; the failure itself is a
      // plain 503 (no parse, no ledger entry), the same shape as a real destination throttling/erroring.
      res.writeHead(503, { "content-type": "text/plain" });
      res.end("destsim emulator: flap fault (periodic failure)");
      return;
    }

    if (opts.format === "jsm") {
      respondJsm(method, url, body, activeFault, res);
      return;
    }
    if (opts.format === "servicenow") {
      respondServiceNow(body, activeFault, res);
      return;
    }
    if (opts.format === "splunk-hec") {
      respondSplunkHec(method, url, headers, body, activeFault, res);
      return;
    }
    respondGeneric(opts.format, body, headers, activeFault, res);
  }

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    let aborted = false;
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("error", () => {
      aborted = true;
    });
    req.on("end", () => {
      if (aborted) return;
      const body = Buffer.concat(chunks);
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers[k] = v;
      const method = req.method ?? "GET";
      const url = req.url ?? "/";
      requests.push({ method, url, headers, body, at: Date.now() });
      try {
        respond(method, url, headers, body, res);
      } catch (e) {
        // A fault in the emulator's OWN handling code (a bug in this test harness) must not hang the
        // socket or crash the process; surface it loudly as a 500 so a failing assertion is diagnosable.
        if (!res.headersSent) res.writeHead(500, { "content-type": "text/plain" });
        res.end(`destsim emulator internal error: ${e instanceof Error ? e.message : String(e)}`);
      }
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${addr.port}${basePathFor(opts.format)}`,
    port: addr.port,
    ledger,
    requests,
    setFault: (f: EmulatorFault): void => {
      fault = f;
    },
    close: (): Promise<void> => closeServerOrThrow(server, "http emulator", () => server.closeAllConnections()),
  };
}

// ============================================================================================================
// startSyslogEmulator: the TLS destination emulator for the syslog-over-TLS sink
// ============================================================================================================

export interface SyslogRequestRecord {
  pri: number;
  format: "cef" | "leef";
  record: string;
  at: number;
}

export type SyslogEmulatorFault = { kind: "ok" } | { kind: "connect-drop" } | { kind: "mid-frame-drop"; afterBytes: number } | { kind: "stall"; ms: number };

export interface SyslogEmulatorHandle {
  host: string;
  port: number;
  ledger: Map<string, LedgerEntry>;
  requests: SyslogRequestRecord[];
  setFault(f: SyslogEmulatorFault): void;
  // waitForLedgerSize polls (bounded by timeoutMs) until the ledger reaches AT LEAST n entries, so a caller
  // driving a REAL socket does not race the async gap between "the client's write+close promise resolved"
  // and "the server's 'end' handler finished parsing and ledgering the bytes" (two genuinely different
  // events on two different sockets, ordered only by the network, never by the same microtask queue).
  // Resolves true once satisfied, false on timeout (never throws, never hangs past the bound).
  waitForLedgerSize(n: number, timeoutMs?: number): Promise<boolean>;
  close(): Promise<void>;
}

export async function startSyslogEmulator(): Promise<SyslogEmulatorHandle> {
  const requests: SyslogRequestRecord[] = [];
  const ledger = new Map<string, LedgerEntry>();
  let fault: SyslogEmulatorFault = { kind: "ok" };

  // A PLAIN net.Server, not tls.createServer: tls.Server starts the TLS handshake automatically the
  // instant a raw connection arrives, so there is no JS-level hook early enough to genuinely withhold a
  // ServerHello (a paused/backpressured raw socket does not stop the internal TLS engine from having
  // already begun consuming buffered bytes). Accepting the RAW connection ourselves and constructing the
  // server-side TLSSocket (new tls.TLSSocket(socket, {isServer:true,...})) OURSELVES, only when ready, is
  // the one technique that reliably delays the handshake: with no TLSSocket wrapping it yet, the raw
  // socket's ClientHello sits unread in the kernel receive buffer, so the client's `opened` promise
  // (siem-syslog-sender.ts awaits socket.opened, which resolves on a completed handshake) genuinely cannot
  // resolve until we choose to wrap it (or the client gives up on its own timeout). connect-drop destroys
  // the raw socket before any TLSSocket is ever constructed, so the handshake never even starts.
  function acceptConnection(socket: Socket): void {
    const tlsSocket = new TLSSocket(socket, { isServer: true, cert: THROWAWAY_TLS_CERT_PEM, key: THROWAWAY_TLS_KEY_PEM });
    tlsSocket.on("error", () => {
      // A client that gave up (its own timeout fired) before or during our handshake is an EXPECTED
      // outcome under the stall fault, not a harness bug; nothing to ledger for an abandoned handshake.
    });
    const midFrameDrop = fault.kind === "mid-frame-drop" ? fault.afterBytes : undefined;
    const chunks: Buffer[] = [];
    let total = 0;
    tlsSocket.on("data", (c: Buffer) => {
      if (midFrameDrop !== undefined && total + c.length > midFrameDrop) {
        const allowed = Math.max(0, midFrameDrop - total);
        chunks.push(c.subarray(0, allowed));
        tlsSocket.destroy();
        return;
      }
      chunks.push(c);
      total += c.length;
    });
    tlsSocket.on("end", () => {
      const buf = Buffer.concat(chunks);
      if (buf.length === 0) return;
      try {
        const { events } = parseSyslogFrames(buf);
        for (const frame of events) {
          requests.push({ pri: frame.pri, format: frame.format, record: frame.msg, at: Date.now() });
          const key = `${frame.decoded.seq}:${frame.decoded.hash}`;
          const existing = ledger.get(key);
          if (existing) existing.deliveryCount++;
          else ledger.set(key, { key, firstSeenAt: Date.now(), deliveryCount: 1, sample: frame });
        }
      } catch {
        // A framing/parse fault on a partial buffer is EXPECTED under mid-frame-drop (the truncation is
        // deliberate); there is nothing to ledger for an unparseable buffer.
      }
    });
  }

  // Every accepted raw socket is tracked so close() can destroy it. Without this, the stall fault
  // parks a socket behind an unref()'d timer and never wraps or destroys it, so net.Server.close()'s
  // completion callback (which waits for all connections to end) never fires, the promise wrapping it
  // never settles, and the caller's `await em.close()` never returns. Nothing ref'd is then holding the
  // event loop open, so Node drains it and the process exits 0 with the verdict line unprinted -- a false
  // green with no assertion able to fail. The pending timers are tracked for the same reason.
  const openSockets = new Set<Socket>();
  const pendingStallTimers = new Set<ReturnType<typeof setTimeout>>();
  const server = createNetServer((rawSocket) => {
    openSockets.add(rawSocket);
    rawSocket.on("close", () => openSockets.delete(rawSocket));
    if (fault.kind === "connect-drop") {
      rawSocket.destroy();
      return;
    }
    if (fault.kind === "stall") {
      const timer = setTimeout(() => {
        pendingStallTimers.delete(timer);
        acceptConnection(rawSocket);
      }, fault.ms);
      timer.unref();
      pendingStallTimers.add(timer);
      return;
    }
    acceptConnection(rawSocket);
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return {
    host: "127.0.0.1",
    port: addr.port,
    ledger,
    requests,
    setFault: (f: SyslogEmulatorFault): void => {
      fault = f;
    },
    waitForLedgerSize: async (n: number, timeoutMs = 2000): Promise<boolean> => {
      const start = Date.now();
      while (ledger.size < n) {
        if (Date.now() - start > timeoutMs) return false;
        await new Promise<void>((resolve) => setTimeout(resolve, 5));
      }
      return true;
    },
    close: (): Promise<void> =>
      closeServerOrThrow(server, "syslog emulator", () => {
        for (const timer of pendingStallTimers) clearTimeout(timer);
        pendingStallTimers.clear();
        for (const socket of openSockets) socket.destroy();
        openSockets.clear();
      }),
  };
}

/**
 * closeServerOrThrow settles, always. It releases whatever the caller is still holding (open sockets,
 * pending timers), closes the listener, and REJECTS if the close has not completed inside the bound.
 *
 * The bound is the point. A close() that never settles is not a hang in this codebase, it is a silent
 * exit 0: the awaiting validator is suspended forever, nothing ref'd keeps the event loop alive, Node
 * drains it, and the process exits 0 having never printed its verdict. Rejecting turns that into a
 * thrown error the caller's own catch reports, which is loud. Resolving on timeout instead would
 * restore the false green in a quieter form.
 */
async function closeServerOrThrow(
  server: { close(cb?: () => void): unknown },
  what: string,
  release: () => void,
  timeoutMs = 5000,
): Promise<void> {
  release();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const closed = new Promise<void>((resolve) => server.close(() => resolve()));
  const timedOut = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`destsim ${what}: close() did not complete within ${timeoutMs}ms; a connection is still open`)), timeoutMs);
  });
  try {
    await Promise.race([closed, timedOut]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

// ============================================================================================================
// makeRealSyslogConnect: a real node:tls client adapter matching siem-syslog-sender.ts's SyslogConnectFn
// ============================================================================================================

interface RealSyslogWriter {
  write(chunk: Uint8Array): Promise<void>;
  close(): Promise<void>;
}
interface RealSyslogSocket {
  readonly opened: Promise<unknown>;
  readonly writable: { getWriter(): RealSyslogWriter };
  close(): Promise<void>;
}
// The structural shape of siem-syslog-sender.ts's (unexported) SyslogConnectFn. TypeScript's structural
// typing lets a value of this LOCALLY-DECLARED type satisfy __setSyslogConnectForTest's parameter without
// importing the private type -- the same technique test/validate-siem-syslog.ts's own MockConnect uses.
type RealSyslogConnectFn = (address: { hostname: string; port: number }, options: { secureTransport: "on"; allowHalfOpen: false }) => RealSyslogSocket;

/** makeRealSyslogConnect returns a SyslogConnectFn-shaped adapter that opens a GENUINE node:tls client
 * connection (rejectUnauthorized:false -- the throwaway cert is self-signed and this suite is proving wire
 * FRAMING, not certificate trust) and satisfies the sender's exact socket contract: `opened` resolves on a
 * completed TLS handshake (rejects on a connect/handshake failure), `writable.getWriter().write()` resolves
 * once the chunk is flushed to the kernel socket buffer (rejects on a write error), `.close()` on either the
 * writer or the socket itself ends/destroys the real connection. Pass the result to
 * __setSyslogConnectForTest so deliverSiemSyslog is driven through its own real injection point against
 * genuine TLS bytes, not a re-implementation of the sender's logic. */
export function makeRealSyslogConnect(): RealSyslogConnectFn {
  return (address) => {
    const socket = tlsConnect({ host: address.hostname, port: address.port, rejectUnauthorized: false });
    const opened = new Promise<unknown>((resolve, reject) => {
      socket.once("secureConnect", () => resolve({}));
      socket.once("error", (e) => reject(e));
    });
    return {
      opened,
      writable: {
        getWriter: () => ({
          write: (chunk: Uint8Array): Promise<void> =>
            new Promise((resolve, reject) => {
              socket.write(Buffer.from(chunk), (err) => (err ? reject(err) : resolve()));
            }),
          close: (): Promise<void> =>
            new Promise((resolve) => {
              socket.end(() => resolve());
            }),
        }),
      },
      close: (): Promise<void> =>
        new Promise((resolve) => {
          if (socket.destroyed) {
            resolve();
            return;
          }
          socket.destroy();
          resolve();
        }),
    };
  };
}
