// Validates the SUPPORT-PACK fault evidence the notify/push egress layer records. Without it, a real, distinct
// fault coarsens into a code that names the WRONG owner (or no owner at all):
//
//   a rotated CONFIG_WRAP_KEY would make every jsm/servicenow send read `no-transport` -- byte-identical to a
//   channel with no url configured -- so support would tell customers to re-enter fields that were never wrong.
//   Every transport fault reading `network-error` and every non-{400,401,403,429} 4xx reading `http-4xx` hides
//   "DNS gone" vs "your TLS cert expired" vs "your firewall reset us", and a DEPROVISIONED sink (410) vs
//   a wrong path (404), needing customer-side logs to tell apart.
//   A JSM 202 whose status poll POSITIVELY reports the create FAILED must not record identically to one that
//   simply could not be confirmed: both would otherwise read `delivered:true, unconfirmed:true`.
//   An OTLP collector's partial_success body that is empty / oversized / unparseable must not be swallowed and
//   the push recorded as a fully-clean delivery.
//   The syslog-TLS sink must not collapse "our runtime has no sockets", "your receiver cert is untrusted" and
//   "nothing accepted the connection" into one `syslog-connect-failed`, drop the timeout's phase, or leave a
//   poison event with no index.
//
// EVERY new field asserted here is a CLOSED ENUM MEMBER or a BOUNDED INT. The second half of each block is the
// REDACTION proof: a customer value / secret / raw exception text is planted at the fault site, and the whole
// recorded result is serialised and asserted not to contain it. No network. Run:
//   node test/validate-notify-fault-evidence.ts

import { deliver as jsmDeliver } from "../src/notify/channels/jsm.ts";
import { deliver as servicenowDeliver } from "../src/notify/channels/servicenow.ts";
import { deliverOtlpPush, OTLP_PARTIAL_BODY_CLASSES } from "../src/notify/otlp-push-sender.ts";
import { deliverSiemSyslog, SYSLOG_FAIL_CODES, __setSyslogConnectForTest } from "../src/notify/siem-syslog-sender.ts";
import { deliverPayload, classifyNetworkFailure, classifyHttpDeliveryStatus, DELIVERY_FAIL_CODES, ACK_OUTCOMES } from "../src/notify/types.ts";
import type { NotifyChannel, NotifyEmission } from "../src/notify/types.ts";
import { deliverEmission } from "../src/notify-routing.ts";
import { wrapConfigSecret, JSM_SECRET_AAD, SERVICENOW_SECRET_AAD } from "../src/admin/config-secret.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import type { PushCursorMeta } from "../src/cron/siem-push-shape.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// The planted customer/secret/raw-error material. If ANY of it appears in a recorded result the redaction
// contract is broken (these are exactly the strings a real fault carries: a hostname, a token, a stack).
const SECRET_TOKEN = "genie-SECRET-TOKEN-must-never-ride";
const CUSTOMER_HOST = "siem.internal.customer-corp.example";
const RAW_ERROR = `connect ECONNREFUSED ${CUSTOMER_HOST}:6514 (token=${SECRET_TOKEN})`;
function leaks(recorded: unknown): boolean {
  const s = JSON.stringify(recorded ?? null);
  return s.includes(SECRET_TOKEN) || s.includes(CUSTOMER_HOST) || s.includes("ECONNREFUSED") || s.includes(RAW_ERROR);
}

const EMISSION: NotifyEmission = {
  event: "backup-failure",
  severity: "critical",
  downpipeId: "dp1",
  downpipeName: "nightly-d1",
  detail: "nightly-d1 backup failed",
  at: "2026-07-10T00:00:00.000Z",
};

const META: PushCursorMeta = { afterSeq: 0, nextAfterSeq: 1, headSeq: 1, headHash: "h" };
function fakeEvent(seq: number): AuditEvent {
  return {
    seq,
    ts: new Date(1_700_000_000_000 + seq * 1000).toISOString(),
    actorSubject: "https://acct.cloudflareaccess.com|sub",
    actorEmail: "owner@example.com",
    actorMethod: "access",
    sourceIp: "203.0.113.7",
    action: "dest-config-set",
    outcome: "success",
    target: { kind: "access-policy" },
    prevHash: `sha384:${"a".repeat(96)}`,
    hash: `sha384:${"b".repeat(96)}`,
  } as AuditEvent;
}

async function main(): Promise<void> {
  const realFetch = globalThis.fetch;

  // ---- an undecryptable sealed credential is its OWN code, never no-transport -------------------
  console.log("\na rotated/absent CONFIG_WRAP_KEY -> deliveryCode credential-undecryptable (not no-transport)");
  {
    const KEY = crypto.getRandomValues(new Uint8Array(32));
    const WRONG = crypto.getRandomValues(new Uint8Array(32));
    const env = { CONFIG_WRAP_KEY: b64urlEncode(WRONG) } as unknown as Env;
    let fetched = false;
    globalThis.fetch = (async () => {
      fetched = true;
      return new Response("never", { status: 200 });
    }) as typeof fetch;
    try {
      const jsmChannel: NotifyChannel = {
        id: "c1", kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts",
        apiKey: await wrapConfigSecret(KEY, SECRET_TOKEN, JSM_SECRET_AAD), enabled: true, createdAt: "2026-01-01T00:00:00.000Z",
      };
      const rj = await jsmDeliver(env, jsmChannel, EMISSION);
      ok("jsm: an undecryptable sealed apiKey -> ok:false, code:credential-undecryptable", rj.ok === false && rj.code === "credential-undecryptable");
      ok("jsm: the code is a member of the CLOSED DELIVERY_FAIL_CODES allow-list (so the DO/pack will carry it)", rj.code !== undefined && DELIVERY_FAIL_CODES.has(rj.code));
      ok("jsm: it is NOT the misleading no-transport class an undecryptable credential could otherwise read as", rj.code !== "no-transport");
      ok("jsm: no send was attempted with an unusable credential", fetched === false);
      ok("REDACTION: the sealed envelope / plaintext token never rides the recorded result", !leaks(rj));

      const snChannel: NotifyChannel = {
        id: "c2", kind: "servicenow", name: "SN", url: "https://dev123.service-now.com/api/now/table/em_event",
        username: "integration", apiKey: await wrapConfigSecret(KEY, SECRET_TOKEN, SERVICENOW_SECRET_AAD), enabled: true, createdAt: "2026-01-01T00:00:00.000Z",
      };
      const rs = await servicenowDeliver(env, snChannel, EMISSION);
      ok("servicenow: an undecryptable sealed apiKey -> ok:false, code:credential-undecryptable", rs.ok === false && rs.code === "credential-undecryptable");
      ok("REDACTION: the servicenow Basic password never rides the recorded result", !leaks(rs));

      // The DeliveryRecord the DO's /notify/record persists (notify-routing.deliverEmission) carries the code.
      const records = await deliverEmission(env, EMISSION, [jsmChannel, snChannel]);
      ok("the persisted DeliveryRecord[] carries credential-undecryptable for BOTH channels (this is what reaches the history ring)",
        records.length === 2 && records.every((r) => r.delivered === false && r.code === "credential-undecryptable"));
      ok("REDACTION: the whole DeliveryRecord[] is free of the token, the host and the raw error", !leaks(records));
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  // ---- closed network sub-cause + the deprovisioned-sink (410) split ----------------------------
  console.log("\nnetwork-error split into a CLOSED {dns,tls,reset,other} sub-cause; 410 split out of http-4xx");
  {
    ok("classifyNetworkFailure: an unresolved name -> network-dns", classifyNetworkFailure(new Error("getaddrinfo ENOTFOUND alerts.example.com")) === "network-dns");
    ok("classifyNetworkFailure: a certificate/TLS fault -> network-tls", classifyNetworkFailure(new Error("unable to verify the first certificate")) === "network-tls");
    ok("classifyNetworkFailure: a refused/reset connection -> network-reset", classifyNetworkFailure(new Error(RAW_ERROR)) === "network-reset");
    ok("classifyNetworkFailure: an unrecognised transport fault falls to the residual network-error", classifyNetworkFailure(new Error("something odd happened")) === "network-error");
    ok("classifyNetworkFailure: every returned member is in the CLOSED allow-list",
      ["network-dns", "network-tls", "network-reset", "network-error"].every((c) => DELIVERY_FAIL_CODES.has(c)));
    ok("REDACTION: classifyNetworkFailure returns ONLY the enum member, never the message it read", !leaks(classifyNetworkFailure(new Error(RAW_ERROR))));

    ok("classifyHttpDeliveryStatus: 410 -> http-gone (a DEPROVISIONED sink: recreate the integration)", classifyHttpDeliveryStatus(410) === "http-gone");
    ok("classifyHttpDeliveryStatus: 404 stays in the residual http-4xx (a wrong path on a LIVE sink)", classifyHttpDeliveryStatus(404) === "http-4xx");
    ok("classifyHttpDeliveryStatus: http-gone is in the CLOSED allow-list", DELIVERY_FAIL_CODES.has("http-gone"));

    // THE MISATTRIBUTION CLASS. A status the DELIVERING RUNTIME synthesised about its own refusal is not the
    // destination answering: `fetch` resolves with it, so the throw path that classifies transport faults
    // correctly never runs, and http-5xx then tells an operator their SIEM returned a server error and sends
    // them to the wrong team. Two members are measured, and each measurement fixed the party as well as the
    // layer, so this block asserts BOTH the members and the non-members.
    //
    // 525/526: the DESTINATION'S CERTIFICATE is refused. A self-signed, expired or wrong-host certificate
    // produces 526, while a valid chain produces the destination's own 405, so the certificate is the only
    // variable that moves the status.
    ok("classifyHttpDeliveryStatus: 526 -> network-tls (the destination's CERTIFICATE was refused, not its server)", classifyHttpDeliveryStatus(526) === "network-tls");
    ok("classifyHttpDeliveryStatus: 525 -> network-tls (a TLS handshake failure is the same layer)", classifyHttpDeliveryStatus(525) === "network-tls");
    // 530: the hostname DOES NOT RESOLVE. A `.invalid` endpoint (a TLD RFC 6761 reserves as never-resolvable)
    // has no destination that could have answered anything, so the status is the runtime's own. An unresolvable
    // host is usually the operator's own typo in the endpoint they typed, and http-5xx would bill that typo to
    // the vendor ("the endpoint itself is erroring. This is at the vendor's end"). network-dns is the code the
    // THROW path already gives the identical fault, so the two paths agree on one fault rather than naming
    // opposite parties for it.
    ok("classifyHttpDeliveryStatus: 530 -> network-dns (the hostname never resolved, so nothing at the vendor answered)", classifyHttpDeliveryStatus(530) === "network-dns");
    ok("classifyHttpDeliveryStatus: the status path and the THROW path agree on an unresolvable host",
      classifyHttpDeliveryStatus(530) === classifyNetworkFailure(new Error("getaddrinfo ENOTFOUND alerts.example.invalid")));
    // GUARD 1, the sweep guard: a genuine server error must still be http-5xx. Sweeping the whole 5xx range
    // into a network-* code would pass every assertion above while making a real SIEM outage read as a
    // certificate or DNS problem at the customer's end, which is worse than not classifying it at all.
    // 502/504 are here because a proxy in front of a healthy destination is the case most easily confused
    // with the runtime synthesising a status about its own refusal.
    ok("classifyHttpDeliveryStatus: a GENUINE server error stays http-5xx",
      classifyHttpDeliveryStatus(500) === "http-5xx" && classifyHttpDeliveryStatus(502) === "http-5xx"
      && classifyHttpDeliveryStatus(503) === "http-5xx" && classifyHttpDeliveryStatus(504) === "http-5xx");
    // GUARD 2, the band guard: the REST of the Cloudflare-origin band is deliberately NOT in the class and
    // must stay http-5xx. This runtime throws on a refused connection rather than synthesising one (measured;
    // classifyNetworkFailure's "connection lost" matcher exists for exactly that observation), and each of
    // these presupposes a connection to a proxy that then could not answer for something behind it, so the
    // vendor's end is not refuted by the status. Moving one is a decision that needs its own measurement, and
    // this assertion is what forces that decision to be made deliberately rather than by widening a range.
    ok("classifyHttpDeliveryStatus: 520-524 and 527 stay http-5xx (not measured as this runtime's own refusal)",
      [520, 521, 522, 523, 524, 527].every((s) => classifyHttpDeliveryStatus(s) === "http-5xx"));
    ok("classifyHttpDeliveryStatus: both codes reached this way are in the CLOSED allow-list", DELIVERY_FAIL_CODES.has("network-tls") && DELIVERY_FAIL_CODES.has("network-dns"));

    // The fault path itself: deliverPayload's catch must classify and DISCARD the exception.
    globalThis.fetch = (async () => {
      throw new Error(RAW_ERROR);
    }) as typeof fetch;
    try {
      const r = await deliverPayload("https://hooks.example.com/x", { a: 1 });
      ok("deliverPayload: a thrown fetch is recorded as the closed sub-cause network-reset", r.ok === false && r.code === "network-reset");
      ok("REDACTION: the raw exception text (host + token) never reaches the recorded delivery result", !leaks(r));
    } finally {
      globalThis.fetch = realFetch;
    }
    globalThis.fetch = (async () => new Response("gone", { status: 410 })) as typeof fetch;
    try {
      const r = await deliverPayload("https://hooks.example.com/x", { a: 1 });
      ok("deliverPayload: a 410 from a deprovisioned webhook is recorded as http-gone", r.ok === false && r.code === "http-gone");
    } finally {
      globalThis.fetch = realFetch;
    }
    // THE DELIVERY SITE, not just the pure classifier: a RESOLVED 530 must reach the recorded result as
    // network-dns. The runtime resolves rather than throws here, so the catch arm that would name the fault
    // correctly is never entered and the resolved-status arm is the only thing an operator ever sees.
    globalThis.fetch = (async () => new Response("", { status: 530 })) as typeof fetch;
    try {
      const r = await deliverPayload("https://alerts.example.invalid/x", { a: 1 });
      ok("deliverPayload: a synthesised 530 is recorded as network-dns, not as the vendor's server error", r.ok === false && r.code === "network-dns");
      ok("deliverPayload: ok stays FALSE either way, so the re-code changes the report and not delivery", r.ok === false);
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  // ---- a POSITIVELY-failed async create is not "could not confirm" ------------------------------
  console.log("\nJSM 202 -> a CLOSED ackOutcome splits async-create-failed from confirmation-unavailable");
  {
    const channel: NotifyChannel = { id: "c1", kind: "jsm", name: "Ops", url: "https://api.opsgenie.com/v2/alerts", apiKey: "k", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };
    const env = {} as unknown as Env;
    // The provider says: accepted (202, requestId), then the poll POSITIVELY reports the create FAILED.
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      if (method === "POST") return new Response(JSON.stringify({ requestId: "req-1" }), { status: 202 });
      return new Response(JSON.stringify({ data: { success: false, status: `alert rejected for ${CUSTOMER_HOST}` } }), { status: 200 });
    }) as typeof fetch;
    try {
      const r = await jsmDeliver(env, channel, EMISSION);
      ok("a poll that POSITIVELY confirms FAILURE records ackOutcome:async-create-failed (the page never existed)", r.ackOutcome === "async-create-failed");
      ok("ok/unconfirmed are UNCHANGED (an idempotent-by-alias async create is never retry-stormed by a flipped ok)", r.ok === true && r.unconfirmed === true);
      ok("REDACTION: the JSM ack body (its status text) never rides the recorded result", !leaks(r));
      const records = await deliverEmission(env, EMISSION, [channel]);
      ok("the persisted DeliveryRecord carries ackOutcome:async-create-failed", records[0]?.ackOutcome === "async-create-failed");
      ok("every ackOutcome emitted is a member of the CLOSED ACK_OUTCOMES allow-list", records[0]?.ackOutcome !== undefined && ACK_OUTCOMES.has(records[0].ackOutcome));
    } finally {
      globalThis.fetch = realFetch;
    }
    // The poll itself is refused: we could not confirm -- a DIFFERENT, non-actionable class.
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      if (method === "POST") return new Response(JSON.stringify({ requestId: "req-2" }), { status: 202 });
      return new Response("nope", { status: 503 });
    }) as typeof fetch;
    try {
      const r = await jsmDeliver(env, channel, EMISSION);
      ok("a poll that could not answer records ackOutcome:confirmation-unavailable (NOT a failed create)", r.ok === true && r.unconfirmed === true && r.ackOutcome === "confirmation-unavailable");
    } finally {
      globalThis.fetch = realFetch;
    }
    // A positively-confirmed success carries no caveat at all.
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      if (method === "POST") return new Response(JSON.stringify({ requestId: "req-3" }), { status: 202 });
      return new Response(JSON.stringify({ data: { success: true } }), { status: 200 });
    }) as typeof fetch;
    try {
      const r = await jsmDeliver(env, channel, EMISSION);
      ok("a poll-confirmed success records ackOutcome:confirmed with no unconfirmed caveat", r.ok === true && r.unconfirmed === undefined && r.ackOutcome === "confirmed");
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  // ---- an unreadable OTLP partial_success body is never a confirmed-clean push ------------------
  console.log("\nthe OTLP 200 partial_success BODY class rides the push trail (absent / oversized / unparseable)");
  {
    const URL_OTLP = "https://otlp.example.com/v1/metrics";
    const cases: Array<{ label: string; body: string; expect: string | undefined }> = [
      { label: "an empty 200 body (the collector confirmed nothing)", body: "", expect: "otlp-partial-body-absent" },
      { label: "a non-JSON 200 body", body: "not json at all", expect: "otlp-partial-body-unparseable" },
      { label: "a 200 whose rejectedDataPoints is NOT a proto3 int64 (never coerced to a clean 0)", body: JSON.stringify({ partialSuccess: { rejectedDataPoints: {}, errorMessage: `cardinality quota exceeded on ${CUSTOMER_HOST} (${SECRET_TOKEN})` } }), expect: "otlp-partial-body-unparseable" },
      { label: `an oversized 200 body (>16 KiB, never parsed)`, body: `{"partialSuccess":{"rejectedDataPoints":9},"pad":"${"x".repeat(20000)}"}`, expect: "otlp-partial-body-oversized" },
      { label: "a genuinely clean 200 (an empty ExportMetricsServiceResponse)", body: "{}", expect: undefined },
    ];
    for (const c of cases) {
      globalThis.fetch = (async () => new Response(c.body, { status: 200, headers: { "content-type": "application/json" } })) as typeof fetch;
      try {
        const r = await deliverOtlpPush(URL_OTLP, "{}", "Authorization", `Bearer ${SECRET_TOKEN}`);
        ok(`${c.label} -> ok:true, code:${c.expect ?? "(none)"}`, r.ok === true && r.code === c.expect);
        if (c.expect !== undefined) ok(`  the class is a member of the CLOSED OTLP_PARTIAL_BODY_CLASSES allow-list`, OTLP_PARTIAL_BODY_CLASSES.has(c.expect));
        ok(`  REDACTION: the collector's errorMessage / our bearer token never ride the result`, !leaks(r));
      } finally {
        globalThis.fetch = realFetch;
      }
    }
    // A REAL partial loss still surfaces its clamped count (the pre-existing loud signal is not regressed).
    globalThis.fetch = (async () => new Response(JSON.stringify({ partialSuccess: { rejectedDataPoints: "7", errorMessage: SECRET_TOKEN } }), { status: 200 })) as typeof fetch;
    try {
      const r = await deliverOtlpPush(URL_OTLP, "{}", "Authorization", "Bearer x");
      ok("a real partial_success still reports rejectedDataPoints:7 as a bounded int, with no body-class caveat", r.ok === true && r.rejectedDataPoints === 7 && r.code === undefined);
      ok("REDACTION: the collector's errorMessage is never carried alongside the count", !leaks(r));
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  // ---- the syslog sink's causes are split, the timeout carries its phase, the poison event is indexed
  console.log("\nsyslog-TLS outcomes are cause-split (sockets / tls-trust / connect) and phase-tagged");
  {
    // A synchronous connect() throw carrying the customer's host + a token in its message.
    __setSyslogConnectForTest(() => {
      throw new Error(RAW_ERROR);
    });
    const rConnect = await deliverSiemSyslog(CUSTOMER_HOST, 6514, "cef", [fakeEvent(1)], META);
    ok("connect() throws (a firewall / closed 6514) -> syslog-connect-refused", rConnect.ok === false && rConnect.code === "syslog-connect-refused");
    ok("REDACTION: the receiver host and the raw connect error never ride the recorded result", !leaks(rConnect));

    // The TLS handshake rejects (socket.opened): an untrusted / self-signed receiver certificate.
    __setSyslogConnectForTest(() => ({
      opened: Promise.reject(new Error(`self-signed certificate for CN=${CUSTOMER_HOST}`)),
      writable: { getWriter: () => ({ write: async () => {}, close: async () => {} }) },
      close: async () => {},
    }));
    const rTls = await deliverSiemSyslog(CUSTOMER_HOST, 6514, "cef", [fakeEvent(1)], META);
    ok("the TLS handshake rejects (an untrusted receiver cert) -> syslog-tls-untrusted (distinct from connect-failed)", rTls.ok === false && rTls.code === "syslog-tls-untrusted");
    ok("REDACTION: the certificate subject / host never rides the recorded result", !leaks(rTls));

    // A black-holed handshake: the hard timeout must name the PHASE it stalled in.
    __setSyslogConnectForTest(() => ({
      opened: new Promise(() => {}),
      writable: { getWriter: () => ({ write: async () => {}, close: async () => {} }) },
      close: () => new Promise(() => {}),
    }));
    const rTimeout = await deliverSiemSyslog(CUSTOMER_HOST, 6514, "cef", [fakeEvent(1)], META, { timeoutMs: 20 });
    ok("a black-holed handshake -> syslog-timeout-handshake (the phase is named, not dropped)", rTimeout.ok === false && rTimeout.code === "syslog-timeout-handshake");

    // A poison event: shaping throws, and the batch is blocked forever with no pointer to WHICH event.
    __setSyslogConnectForTest(() => ({
      opened: Promise.resolve(),
      writable: { getWriter: () => ({ write: async () => {}, close: async () => {} }) },
      close: async () => {},
    }));
    const poison = fakeEvent(2);
    Object.defineProperty(poison, "action", {
      get() {
        throw new Error(`poison event for ${CUSTOMER_HOST} (${SECRET_TOKEN})`);
      },
    });
    const rShape = await deliverSiemSyslog(CUSTOMER_HOST, 6514, "cef", [fakeEvent(1), poison, fakeEvent(3)], META);
    ok("a poison event -> syslog-shape-failed with the offending event's BOUNDED index (1), never 'forever, unknown'", rShape.ok === false && rShape.code === "syslog-shape-failed" && rShape.failedIndex === 1);
    ok("the index is a bounded non-negative int, never a field value", Number.isInteger(rShape.failedIndex) && (rShape.failedIndex ?? -1) >= 0);
    ok("REDACTION: the poison event's own content never rides the recorded result", !leaks(rShape));

    ok("every syslog code emitted here is a member of the CLOSED SYSLOG_FAIL_CODES allow-list",
      [rConnect.code, rTls.code, rTimeout.code, rShape.code].every((c) => c !== undefined && SYSLOG_FAIL_CODES.has(c)));
    __setSyslogConnectForTest(null);
  }

  console.log(`\n${failures === 0 ? "PASS" : `FAIL (${failures})`}`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
