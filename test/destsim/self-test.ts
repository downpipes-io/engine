// test/destsim/self-test.ts -- proves the EMULATOR ITSELF is trustworthy. A fake destination that silently
// accepts garbage (or silently loses good data) is worse than no destination at all: it would let a real
// engine bug sail through test/validate-destsim-formats.ts's round-trip assertions unnoticed. This module is
// the library; test/validate-destsim-selftest.ts is the thin chain-entry that supplies the house
// ok()/failures bookkeeping and calls runSelfTests(ok).
//
// Two independent proofs:
//   1. PARSER FIXTURES: small, HAND-WRITTEN (not shaper-generated) known-good and known-bad bodies for every
//      parser in test/destsim/parsers.ts, asserting accept/reject. Deliberately independent of
//      src/cron/siem-push-shape.ts et al: if the parser and the shaper shared a subtle wrong assumption,
//      round-tripping shaper output through the SAME parser could not catch it, but a hand-written fixture
//      built from the vendor documentation directly can.
//   2. LIVE EMULATOR BEHAVIOUR: start the real http/tls emulator (test/destsim/server.ts) and drive it with
//      real fetch()/TLS calls (no engine code in this half either): good bodies ledger and ack 200, bad
//      bodies are rejected 400 with NOTHING ledgered, every fault kind behaves as documented, and the
//      ledger's dedupe identity (seq:hash / dedup_key / message_key / alias) collapses a repeated delivery
//      to one entry with deliveryCount>1 (bounded-dupes) while distinct events each get their own entry
//      (no-loss).

import { Buffer } from "node:buffer";
import {
  parseCef,
  parseLeef,
  parseSyslogFrames,
  parseSplunkHec,
  parseDatadog,
  parseGelf,
  parseNdjson,
  parseJsonArray,
  parseRawJson,
  parseOtlpJson,
  parsePrometheusText,
  parseWebhookPayload,
  parseSlackPayload,
  parseTeamsCard,
  parsePagerDutyPayload,
  parseServiceNowPayload,
  parseJsmCreatePayload,
  parseJsmClosePayload,
  DestsimParseError,
} from "./parsers.ts";
import { startEmulator, startSyslogEmulator, makeRealSyslogConnect } from "./server.ts";
import { deliverSiemSyslog, __setSyslogConnectForTest } from "../../src/notify/siem-syslog-sender.ts";
import type { PushCursorMeta } from "../../src/cron/siem-push-shape.ts";
import type { AuditEvent } from "../../src/admin/audit-types.ts";

export type OkFn = (label: string, cond: boolean) => void;

// ---- shared minimal fixtures ------------------------------------------------------------------------------

const HASH_A = `sha384:${"a".repeat(96)}`;
const HASH_B = `sha384:${"b".repeat(96)}`;

// JSON_HEADERS: fetch() sets NO content-type for a plain string body other than the Fetch spec's own
// text/plain default, so every JSON-format live-emulator call below must set this EXPLICITLY -- the
// emulator's strict content-type check (parsers.ts's assertContentType) will otherwise (correctly) reject
// the request as a wrong-content-type, which is the parser doing its job, not a bug.
const JSON_HEADERS = { "content-type": "application/json" };

function minimalAuditEvent(overrides?: Record<string, unknown>): Record<string, unknown> {
  return {
    seq: 101,
    ts: "2024-01-01T00:00:00.000Z",
    actorSubject: "https://acct.example.com|sub-owner",
    actorEmail: "owner@example.com",
    actorMethod: "access",
    sourceIp: "203.0.113.7",
    action: "dest-config-set",
    outcome: "success",
    target: { kind: "access-policy" },
    prevHash: HASH_A,
    hash: HASH_B,
    ...overrides,
  };
}

function realAuditEvent(overrides?: Partial<AuditEvent>): AuditEvent {
  return {
    seq: 101,
    ts: "2024-01-01T00:00:00.000Z",
    actorSubject: "https://acct.example.com|sub-owner",
    actorEmail: "owner@example.com",
    actorMethod: "access",
    sourceIp: "203.0.113.7",
    action: "dest-config-set",
    outcome: "success",
    target: { kind: "access-policy" },
    prevHash: HASH_A,
    hash: HASH_B,
    ...overrides,
  };
}

function throws(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch (e) {
    return e instanceof DestsimParseError;
  }
}

// ---- section 1: parser fixtures (hand-written, independent of the shapers) --------------------------------

function testCefFixtures(ok: OkFn): void {
  const good = `CEF:0|Maelstrom AI|Downpipes|0.1.9|dest-config-set|Dest config set|3|rt=1700000000000 suser=owner@example.com src=203.0.113.7 act=dest-config-set outcome=success cs2Label=actorMethod cs2=access cs3Label=targetKind cs3=access-policy cs6Label=prevHash cs6=${HASH_A} cn1Label=seq cn1=101 flexString1Label=hash flexString1=${HASH_B}`;
  const parsed = parseCef(good).events[0];
  ok("CEF fixture: a hand-written well-formed line is accepted", parsed !== undefined);
  ok("CEF fixture: decoded fields round-trip", parsed?.actorEmail === "owner@example.com" && parsed?.action === "dest-config-set" && parsed?.seq === 101 && parsed?.hash === HASH_B);

  ok("CEF fixture: wrong vendor is rejected", throws(() => parseCef(good.replace("Maelstrom AI", "Evil Corp"))));
  ok("CEF fixture: out-of-range severity is rejected", throws(() => parseCef(good.replace("|3|", "|99|"))));
  ok("CEF fixture: an unknown extension key is rejected", throws(() => parseCef(`${good} bogusKey=x`)));
  ok("CEF fixture: a missing mandatory key (act) is rejected", throws(() => parseCef(good.replace("act=dest-config-set ", ""))));
  ok("CEF fixture: wrong content-type opt is rejected", throws(() => parseCef(good, { contentType: "application/json" })));
  ok("CEF fixture: empty input is rejected", throws(() => parseCef("")));
}

function testLeefFixtures(ok: OkFn): void {
  const good = `LEEF:2.0|Maelstrom AI|Downpipes|0.1.9|dest-config-set|^|devTime=1700000000000^cat=access-policy^sev=3^usrName=owner@example.com^src=203.0.113.7^action=dest-config-set^outcome=success^authMethod=access^targetKind=access-policy^seq=101^prevHash=${HASH_A}^eventHash=${HASH_B}`;
  const parsed = parseLeef(good).events[0];
  ok("LEEF fixture: a hand-written well-formed line is accepted", parsed !== undefined);
  ok("LEEF fixture: decoded fields round-trip", parsed?.actorEmail === "owner@example.com" && parsed?.action === "dest-config-set" && parsed?.seq === 101);

  ok("LEEF fixture: wrong delimiter declaration is rejected", throws(() => parseLeef(good.replace("|^|", "|~|"))));
  ok("LEEF fixture: cat/targetKind mismatch is rejected", throws(() => parseLeef(good.replace("cat=access-policy", "cat=downpipe"))));
  ok("LEEF fixture: an un-sanitised '|' surviving in a value is rejected", throws(() => parseLeef(`${good.slice(0, -1)}X|Y`)));
  ok("LEEF fixture: a value carrying a raw '=' (sanitisation failed) is rejected", throws(() => parseLeef(good.replace("outcome=success", "outcome=suc=cess"))));
  ok("LEEF fixture: empty input is rejected", throws(() => parseLeef("")));
}

function testSyslogFixtures(ok: OkFn): void {
  const enc = new TextEncoder();
  const record = `<110>1 2024-01-01T00:00:00.000Z downpipes downpipe-engine - audit - CEF:0|Maelstrom AI|Downpipes|0.1.9|dest-config-set|Dest config set|3|rt=1700000000000 act=dest-config-set outcome=success cs2Label=actorMethod cs2=access cs3Label=targetKind cs3=access-policy cs6Label=prevHash cs6=${HASH_A} cn1Label=seq cn1=101 flexString1Label=hash flexString1=${HASH_B}`;
  const recordBytes = enc.encode(record);
  const goodFrame = Buffer.concat([Buffer.from(`${recordBytes.length} `, "ascii"), Buffer.from(recordBytes)]);

  const parsed = parseSyslogFrames(goodFrame).events[0];
  ok("syslog fixture: a correctly octet-counted frame is accepted", parsed !== undefined);
  ok("syslog fixture: PRI decomposes to facility 13 / severity 6 (110)", parsed?.facility === 13 && parsed?.severity === 6 && parsed?.pri === 110);
  ok("syslog fixture: the trailing CEF line decodes via parseCef", parsed?.decoded.action === "dest-config-set");

  const wrongLen = Buffer.concat([Buffer.from(`${recordBytes.length + 5} `, "ascii"), Buffer.from(recordBytes)]);
  ok("syslog fixture: a length prefix that overruns the buffer is rejected", throws(() => parseSyslogFrames(wrongLen)));
  const shortLen = Buffer.concat([Buffer.from(`${recordBytes.length - 5} `, "ascii"), Buffer.from(recordBytes)]);
  ok("syslog fixture: a length prefix shorter than the real record desynchronises framing and is rejected", throws(() => parseSyslogFrames(shortLen)));
  const badPri = Buffer.from(record.replace("<110>", "<999>"), "utf8");
  const badPriFrame = Buffer.concat([Buffer.from(`${badPri.length} `, "ascii"), badPri]);
  ok("syslog fixture: an out-of-range PRI is rejected", throws(() => parseSyslogFrames(badPriFrame)));
}

function testSplunkHecFixtures(ok: OkFn): void {
  const good = JSON.stringify({ time: 1700000000, source: "downpipes", sourcetype: "downpipe:audit", event: minimalAuditEvent() });
  ok("splunk-hec fixture: a well-formed HEC line is accepted", parseSplunkHec(good).events.length === 1);
  ok("splunk-hec fixture: wrong source is rejected", throws(() => parseSplunkHec(JSON.stringify({ time: 1700000000, source: "not-downpipes", sourcetype: "downpipe:audit", event: minimalAuditEvent() }))));
  ok("splunk-hec fixture: an extra top-level key is rejected", throws(() => parseSplunkHec(JSON.stringify({ time: 1700000000, source: "downpipes", sourcetype: "downpipe:audit", event: minimalAuditEvent(), extra: 1 }))));
  ok("splunk-hec fixture: a non-integer time is rejected", throws(() => parseSplunkHec(JSON.stringify({ time: 1.5, source: "downpipes", sourcetype: "downpipe:audit", event: minimalAuditEvent() }))));
}

function testDatadogFixtures(ok: OkFn): void {
  const base = minimalAuditEvent();
  const good = JSON.stringify([{ ddsource: "downpipes", service: "downpipe-engine", message: "dest-config-set success", status: "info", ...base }]);
  ok("datadog fixture: a well-formed array element is accepted", parseDatadog(good).events.length === 1);
  const badStatus = JSON.stringify([{ ddsource: "downpipes", service: "downpipe-engine", message: "dest-config-set success", status: "error", ...base }]);
  ok("datadog fixture: status not matching the outcome-derived mapping is rejected", throws(() => parseDatadog(badStatus)));
  const notArray = JSON.stringify({ ddsource: "downpipes", service: "downpipe-engine", message: "x", status: "info", ...base });
  ok("datadog fixture: a bare object (not an array) is rejected", throws(() => parseDatadog(notArray)));
}

function testGelfFixtures(ok: OkFn): void {
  const good = JSON.stringify({
    version: "1.1",
    host: "downpipes",
    short_message: "dest-config-set success",
    timestamp: 1700000000,
    level: 6,
    _seq: 101,
    _actorEmail: "owner@example.com",
    _actorSubject: "sub",
    _actorMethod: "access",
    _sourceIp: "203.0.113.7",
    _action: "dest-config-set",
    _outcome: "success",
    _targetKind: "access-policy",
    _prevHash: HASH_A,
    _hash: HASH_B,
  });
  ok("GELF fixture: a well-formed object is accepted", parseGelf(good).events.length === 1);
  ok("GELF fixture: the reserved _id key is rejected", throws(() => parseGelf(good.replace("{", '{"_id":"x",'))));
  ok("GELF fixture: a non-underscore custom key is rejected", throws(() => parseGelf(good.replace("{", '{"bogus":"x",'))));
  ok("GELF fixture: an invalid level is rejected", throws(() => parseGelf(good.replace('"level":6', '"level":5'))));
}

function testNdjsonJsonArrayRawJsonFixtures(ok: OkFn): void {
  const e1 = minimalAuditEvent();
  const e2 = minimalAuditEvent({ seq: 102 });
  ok("ndjson fixture: two well-formed lines are accepted", parseNdjson(`${JSON.stringify(e1)}\n${JSON.stringify(e2)}`).events.length === 2);
  ok("ndjson fixture: an unknown action is rejected", throws(() => parseNdjson(JSON.stringify(minimalAuditEvent({ action: "not-a-real-action" })))));

  ok("json-array fixture: a well-formed array is accepted", parseJsonArray(JSON.stringify([e1, e2])).events.length === 2);
  ok("json-array fixture: an extra unknown field on an event is rejected", throws(() => parseJsonArray(JSON.stringify([{ ...e1, bogus: 1 }]))));

  const feed = { kind: "downpipe-audit-feed", v: 1, afterSeq: 100, nextAfterSeq: 102, headSeq: 102, headHash: "h", count: 2, events: [e1, e2] };
  ok("raw-json fixture: a well-formed feed envelope is accepted", parseRawJson(JSON.stringify(feed)).events.length === 2);
  ok("raw-json fixture: a count/events.length mismatch is rejected", throws(() => parseRawJson(JSON.stringify({ ...feed, count: 5 }))));
  ok("raw-json fixture: wrong kind is rejected", throws(() => parseRawJson(JSON.stringify({ ...feed, kind: "something-else" }))));
}

// otlpFixtureObject builds the OTLP body as a plain JS object (not a hand-written JSON string), so the
// "corrupted copy" variants below mutate the OBJECT before stringifying -- immune to whitespace/formatting
// drift between how a human writes a JSON literal and how JSON.stringify actually renders it.
function otlpFixtureObject(): { resourceMetrics: unknown[] } {
  return {
    resourceMetrics: [
      {
        resource: { attributes: [{ key: "service.name", value: { stringValue: "downpipes-engine" } }, { key: "service.version", value: { stringValue: "0.1.9" } }] },
        scopeMetrics: [
          {
            scope: { name: "downpipes.otlp-push", version: "0.1.9" },
            metrics: [
              {
                name: "downpipe_enabled",
                description: "Whether the downpipe is enabled",
                unit: "1",
                gauge: { dataPoints: [{ attributes: [{ key: "downpipe_id", value: { stringValue: "dp1" } }], timeUnixNano: "1700000000000000000", asDouble: 1 }] },
              },
            ],
          },
        ],
      },
    ],
  };
}

function testOtlpFixtures(ok: OkFn): void {
  const good = JSON.stringify(otlpFixtureObject());
  const parsed = parseOtlpJson(good);
  ok("OTLP fixture: a well-formed body is accepted", parsed.events.length === 1);
  ok("OTLP fixture: timeUnixNano parses as BigInt", parsed.events[0]?.timeUnixNano === 1700000000000000000n);

  const badMetricNameObj = otlpFixtureObject() as { resourceMetrics: Array<{ scopeMetrics: Array<{ metrics: Array<{ name: string }> }> }> };
  badMetricNameObj.resourceMetrics[0]!.scopeMetrics[0]!.metrics[0]!.name = "downpipe_not_a_real_metric";
  ok("OTLP fixture: an unknown metric name is rejected", throws(() => parseOtlpJson(JSON.stringify(badMetricNameObj))));

  const numericNanoObj = otlpFixtureObject() as { resourceMetrics: Array<{ scopeMetrics: Array<{ metrics: Array<{ gauge: { dataPoints: Array<{ timeUnixNano: unknown }> } }> }> }> };
  numericNanoObj.resourceMetrics[0]!.scopeMetrics[0]!.metrics[0]!.gauge.dataPoints[0]!.timeUnixNano = 1700000000000000000;
  ok("OTLP fixture: a numeric (not string) timeUnixNano is rejected", throws(() => parseOtlpJson(JSON.stringify(numericNanoObj))));

  const missingServiceVersionObj = otlpFixtureObject() as { resourceMetrics: Array<{ resource: { attributes: unknown[] } }> };
  missingServiceVersionObj.resourceMetrics[0]!.resource.attributes = [{ key: "service.name", value: { stringValue: "downpipes-engine" } }];
  ok("OTLP fixture: a missing service.version attribute is rejected", throws(() => parseOtlpJson(JSON.stringify(missingServiceVersionObj))));
}

function testPrometheusFixtures(ok: OkFn): void {
  const good = ["# HELP downpipe_backup_success Whether the most recently completed backup run succeeded.", "# TYPE downpipe_backup_success gauge", 'downpipe_backup_success{downpipe_id="dp1",downpipe_name="Prod"} 1', ""].join("\n");
  const parsed = parsePrometheusText(good);
  ok("Prometheus fixture: a well-formed family is accepted", parsed.events.length === 1 && parsed.events[0]?.value === 1);

  const noType = ["# HELP downpipe_backup_success x", 'downpipe_backup_success{downpipe_id="dp1"} 1', ""].join("\n");
  ok("Prometheus fixture: a sample with no preceding TYPE is rejected", throws(() => parsePrometheusText(noType)));

  const dupType = ["# TYPE downpipe_backup_success gauge", "# TYPE downpipe_backup_success gauge", 'downpipe_backup_success{downpipe_id="dp1"} 1', ""].join("\n");
  ok("Prometheus fixture: a duplicate TYPE line is rejected", throws(() => parsePrometheusText(dupType)));

  const unescapedQuote = ["# TYPE downpipe_backup_success gauge", 'downpipe_backup_success{downpipe_name="ab"cd"} 1', ""].join("\n");
  ok("Prometheus fixture: an unescaped quote inside a label value is rejected", throws(() => parsePrometheusText(unescapedQuote)));

  const noTrailingNewline = ["# TYPE downpipe_backup_success gauge", 'downpipe_backup_success{downpipe_id="dp1"} 1'].join("\n");
  ok("Prometheus fixture: a body with no trailing newline is rejected", throws(() => parsePrometheusText(noTrailingNewline)));
}

function testChannelFixtures(ok: OkFn): void {
  const webhookGood = JSON.stringify({ kind: "downpipe-event-v1", at: "2024-01-01T00:00:00.000Z", event: "backup-failure", severity: "critical", downpipe: { id: "dp1", name: "Prod" }, detail: "Prod: last run failed" });
  ok("webhook fixture: a well-formed v1 body is accepted", parseWebhookPayload(webhookGood).events.length === 1);
  ok("webhook fixture: an unknown severity is rejected", throws(() => parseWebhookPayload(webhookGood.replace('"critical"', '"apocalyptic"'))));
  ok("webhook fixture: wrong kind is rejected", throws(() => parseWebhookPayload(webhookGood.replace("downpipe-event-v1", "downpipe-event-v2"))));

  const slackGood = JSON.stringify({ text: "backup-failure", blocks: [{ type: "section", text: { type: "mrkdwn", text: "*backup-failure* (critical)" } }] });
  ok("slack fixture: a well-formed body is accepted", parseSlackPayload(slackGood).events.length === 1);
  ok("slack fixture: a wrong block type is rejected", throws(() => parseSlackPayload(slackGood.replace('"section"', '"header"'))));

  const teamsGood = JSON.stringify({ "@type": "MessageCard", "@context": "http://schema.org/extensions", themeColor: "D93F3F", summary: "x", title: "y", text: "z" });
  ok("teams fixture: a well-formed card is accepted", parseTeamsCard(teamsGood).events.length === 1);
  ok("teams fixture: a malformed themeColor is rejected", throws(() => parseTeamsCard(teamsGood.replace("D93F3F", "not-a-hex-colour"))));

  const pdGood = JSON.stringify({ routing_key: "R123", event_action: "trigger", dedup_key: "downpipe:dp1:backup-failure", payload: { summary: "x", severity: "critical", source: "Prod", component: "backup-failure" } });
  ok("pagerduty fixture: a well-formed envelope is accepted", parsePagerDutyPayload(pdGood).events.length === 1);
  ok("pagerduty fixture: an unknown event_action is rejected", throws(() => parsePagerDutyPayload(pdGood.replace('"trigger"', '"snooze"'))));
  ok("pagerduty fixture: an over-cap summary is rejected", throws(() => parsePagerDutyPayload(pdGood.replace('"summary":"x"', `"summary":"${"x".repeat(1025)}"`))));

  const snGood = JSON.stringify({ source: "downpipes", node: "Prod", resource: "backup-failure", metric_name: "downpipe.backup-failure", severity: 1, description: "x", message_key: "downpipe:dp1:backup-failure" });
  ok("servicenow fixture: a well-formed flat body is accepted", parseServiceNowPayload(snGood).events.length === 1);
  const snJsonV2Good = JSON.stringify({ records: [JSON.parse(snGood)] });
  ok("servicenow fixture: the em/jsonv2 {records:[...]} wrapper is accepted", parseServiceNowPayload(snJsonV2Good).events.length === 1);
  ok("servicenow fixture: metric_name not matching downpipe.<resource> is rejected", throws(() => parseServiceNowPayload(snGood.replace("downpipe.backup-failure", "downpipe.something-else"))));
  ok("servicenow fixture: an out-of-range severity is rejected", throws(() => parseServiceNowPayload(snGood.replace('"severity":1', '"severity":9'))));

  const jsmCreateGood = JSON.stringify({ message: "Prod backup-failure", alias: "downpipe:dp1:backup-failure", description: "Prod: last run failed", priority: "P1", source: "Prod" });
  ok("jsm-create fixture: a well-formed create body is accepted", parseJsmCreatePayload(jsmCreateGood).events.length === 1);
  ok("jsm-create fixture: an unknown priority is rejected", throws(() => parseJsmCreatePayload(jsmCreateGood.replace('"P1"', '"P0"'))));
  ok("jsm-create fixture: an over-cap message is rejected", throws(() => parseJsmCreatePayload(jsmCreateGood.replace('"message":"Prod backup-failure"', `"message":"${"x".repeat(131)}"`))));

  const jsmCloseGood = JSON.stringify({ source: "Prod" });
  ok("jsm-close fixture: a well-formed close body is accepted", parseJsmClosePayload(jsmCloseGood).events.length === 1);
  ok("jsm-close fixture: an extra field is rejected", throws(() => parseJsmClosePayload(JSON.stringify({ source: "Prod", extra: 1 }))));
}

// ---- section 2: live HTTP emulator behaviour ---------------------------------------------------------------

async function testEmulatorAcceptsGoodRejectsBad(ok: OkFn): Promise<void> {
  const em = await startEmulator({ format: "cef" });
  try {
    const good = `CEF:0|Maelstrom AI|Downpipes|0.1.9|dest-config-set|Dest config set|3|rt=1700000000000 act=dest-config-set outcome=success cs2Label=actorMethod cs2=access cs3Label=targetKind cs3=access-policy cs6Label=prevHash cs6=${HASH_A} cn1Label=seq cn1=555 flexString1Label=hash flexString1=${HASH_B}`;
    const r1 = await fetch(em.url, { method: "POST", headers: { "content-type": "text/plain; charset=utf-8" }, body: good });
    ok("live emulator (cef): a well-formed body is ack'd 200", r1.status === 200);
    ok("live emulator (cef): the good body is recorded on the ledger", em.ledger.has(`555:${HASH_B}`));

    const bad = good.replace("Maelstrom AI", "Evil Corp");
    const r2 = await fetch(em.url, { method: "POST", headers: { "content-type": "text/plain; charset=utf-8" }, body: bad });
    ok("live emulator (cef): a corrupted body is rejected 400 (never rubber-stamped)", r2.status === 400);
    ok("live emulator: every request is recorded regardless of parse outcome", em.requests.length === 2);
    ok("live emulator: the ledger has exactly ONE entry (the rejected body never ledgered)", em.ledger.size === 1);
  } finally {
    await em.close();
  }
}

// HEC_TEST_TOKEN is an obviously-synthetic stand-in. A real HEC token is a GUID and must never appear in a
// fixture; the emulator only ever compares it to what the test itself sends.
const HEC_TEST_TOKEN = "00000000-0000-4000-8000-000000000000";
const HEC_AUTH_HEADERS = { "content-type": "application/json", authorization: `Splunk ${HEC_TEST_TOKEN}` };

async function testEmulatorLedgerDedupe(ok: OkFn): Promise<void> {
  const em = await startEmulator({ format: "splunk-hec", hecToken: HEC_TEST_TOKEN });
  try {
    const line = (seq: number): string => JSON.stringify({ time: 1700000000, source: "downpipes", sourcetype: "downpipe:audit", event: minimalAuditEvent({ seq }) });
    await fetch(em.url, { method: "POST", headers: HEC_AUTH_HEADERS, body: line(1) });
    await fetch(em.url, { method: "POST", headers: HEC_AUTH_HEADERS, body: line(1) }); // a retried delivery of the SAME event
    await fetch(em.url, { method: "POST", headers: HEC_AUTH_HEADERS, body: line(2) });
    ok("live emulator: no-loss -- two distinct events each get a ledger entry", em.ledger.has(`1:${HASH_B}`) && em.ledger.has(`2:${HASH_B}`));
    ok("live emulator: bounded-dupes -- a retried identical event collapses to ONE ledger entry", em.ledger.size === 2);
    ok("live emulator: the dupe's deliveryCount reflects both attempts", em.ledger.get(`1:${HASH_B}`)?.deliveryCount === 2);
  } finally {
    await em.close();
  }
}

// testSplunkHecObservedContract pins the emulator to the contract observed from a real Splunk Cloud stack
// (port 8088, /services/collector/event). Without this, the emulator would apply no auth check and serve
// any path with 200 {"text":"Success","code":0}, so a destination configured with `Authorization: Bearer
// <token>` -- which real HEC REFUSES -- would pass the entire suite green. Every row below is a status/body
// pair actually observed.
async function testSplunkHecObservedContract(ok: OkFn): Promise<void> {
  const em = await startEmulator({ format: "splunk-hec", hecToken: HEC_TEST_TOKEN });
  const body = JSON.stringify({ time: 1700000000, source: "downpipes", sourcetype: "downpipe:audit", event: minimalAuditEvent({ seq: 7 }) });
  // post sends `body` with the given Authorization value (omitted entirely when undefined) and returns the
  // status plus the parsed ack, so each assertion can check BOTH halves the way a real client would.
  const post = async (auth: string | undefined, path?: string): Promise<{ status: number; text: string }> => {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (auth !== undefined) headers.authorization = auth;
    const target = path === undefined ? em.url : `${new URL(em.url).origin}${path}`;
    const r = await fetch(target, { method: "POST", headers, body });
    return { status: r.status, text: await r.text() };
  };
  try {
    ok("hec observed: the emulator's ingest path is /services/collector/event (not an invented one)", new URL(em.url).pathname === "/services/collector/event");

    const good = await post(`Splunk ${HEC_TEST_TOKEN}`);
    ok('hec observed: "Splunk <token>" is accepted 200 {"text":"Success","code":0}', good.status === 200 && good.text === JSON.stringify({ text: "Success", code: 0 }));
    ok("hec observed: an accepted event IS ledgered", em.ledger.has(`7:${HASH_B}`));

    // THE TRAP. Bearer is the reflex for every other vendor and HEC refuses it. A wrong SCHEME is 401 code 3,
    // which is a DIFFERENT diagnosis from a wrong token (403 code 4): one is our bug, the other the
    // customer's credential.
    const bearer = await post(`Bearer ${HEC_TEST_TOKEN}`);
    ok('hec observed: "Bearer <token>" is REFUSED 401 {"text":"Invalid authorization","code":3}', bearer.status === 401 && bearer.text === JSON.stringify({ text: "Invalid authorization", code: 3 }));

    const missing = await post(undefined);
    ok('hec observed: no Authorization header is 401 {"text":"Token is required","code":2}', missing.status === 401 && missing.text === JSON.stringify({ text: "Token is required", code: 2 }));

    const bare = await post(HEC_TEST_TOKEN);
    ok('hec observed: a bare token with no scheme is 401 code 3 (not 403)', bare.status === 401 && bare.text === JSON.stringify({ text: "Invalid authorization", code: 3 }));

    // The scheme is a literal, case-SENSITIVE "Splunk": all three spellings were observed to fail.
    for (const spelling of ["splunk", "SPLUNK", "SPlunk"]) {
      const r = await post(`${spelling} ${HEC_TEST_TOKEN}`);
      ok(`hec observed: scheme "${spelling}" is REFUSED 401 code 3 (the comparison is case-sensitive)`, r.status === 401 && r.text === JSON.stringify({ text: "Invalid authorization", code: 3 }));
    }

    const wrongToken = await post("Splunk 11111111-2222-4333-8444-555555555555");
    ok('hec observed: a right scheme with an unknown token is 403 {"text":"Invalid token","code":4}', wrongToken.status === 403 && wrongToken.text === JSON.stringify({ text: "Invalid token", code: 4 }));

    // Auth is evaluated BEFORE the body is parsed, so rubbish plus a bad token returns the TOKEN error. A
    // 403 therefore never rules out a second, body-level problem waiting behind it.
    const rubbish = await fetch(em.url, { method: "POST", headers: { "content-type": "application/json", authorization: "Splunk 11111111-2222-4333-8444-555555555555" }, body: "{not json at all" });
    ok("hec observed: auth is checked BEFORE the body (malformed JSON + bad token yields the token error, not a parse error)", rubbish.status === 403 && (await rubbish.text()) === JSON.stringify({ text: "Invalid token", code: 4 }));

    // A path the listener does not serve 404s, which is what makes a misconfigured collector path a FAILURE
    // rather than a silent pass.
    const wrongPath = await post(`Splunk ${HEC_TEST_TOKEN}`, "/ingest");
    ok("hec observed: the OLD emulator path /ingest now 404s (Splunk does not serve it)", wrongPath.status === 404);

    // Observed oddity kept deliberately: HTTP 405, body code 404. They disagree.
    const getEvent = await fetch(em.url, { method: "GET" });
    const getEventText = await getEvent.text();
    ok("hec observed: GET on the event endpoint is HTTP 405 while its BODY says code 404 (they disagree)", getEvent.status === 405 && JSON.parse(getEventText).code === 404);

    // The health endpoint is the one HEC surface reachable with NO token, so it is the only honest
    // reachability pre-flight.
    const health = await fetch(`${new URL(em.url).origin}/services/collector/health`, { method: "GET" });
    ok('hec observed: GET /services/collector/health needs NO auth and answers 200 {"text":"HEC is healthy","code":17}', health.status === 200 && (await health.text()) === JSON.stringify({ text: "HEC is healthy", code: 17 }));

    ok("hec observed: only the ONE authenticated event was ledgered (no refused request was rubber-stamped)", em.ledger.size === 1);
  } finally {
    await em.close();
  }
}

// testSplunkHecBatching pins the newline-delimited batch: HEC accepts concatenated JSON objects in one body,
// which is what shapeSplunkHec relies on, and the emulator must ledger EVERY member rather than only the first.
async function testSplunkHecBatching(ok: OkFn): Promise<void> {
  const em = await startEmulator({ format: "splunk-hec", hecToken: HEC_TEST_TOKEN });
  try {
    const line = (seq: number): string => JSON.stringify({ time: 1700000000, source: "downpipes", sourcetype: "downpipe:audit", event: minimalAuditEvent({ seq }) });
    const r = await fetch(em.url, { method: "POST", headers: HEC_AUTH_HEADERS, body: [line(11), line(12), line(13)].join("\n") });
    ok("hec batch: three newline-delimited events in ONE request are accepted 200", r.status === 200);
    ok("hec batch: every member of the batch is ledgered, not just the first", em.ledger.has(`11:${HASH_B}`) && em.ledger.has(`12:${HASH_B}`) && em.ledger.has(`13:${HASH_B}`));
    ok("hec batch: exactly three ledger entries", em.ledger.size === 3);
  } finally {
    await em.close();
  }
}

async function testEmulatorFaultStatus(ok: OkFn): Promise<void> {
  const em = await startEmulator({ format: "webhook" });
  try {
    em.setFault({ kind: "status", code: 503, retryAfter: 30, body: "come back later" });
    const res = await fetch(em.url, { method: "POST", body: JSON.stringify({ kind: "downpipe-event-v1", at: "2024-01-01T00:00:00.000Z", event: "backup-failure", severity: "critical", detail: "x" }) });
    ok("fault(status): the configured status code is returned", res.status === 503);
    ok("fault(status): retry-after rides the header", res.headers.get("retry-after") === "30");
    ok("fault(status): the configured body rides verbatim", (await res.text()) === "come back later");
    ok("fault(status): a rejected-by-fault request is NOT ledgered", em.ledger.size === 0);
  } finally {
    await em.close();
  }
}

async function testEmulatorFaultMalformed200AndWrongContentType(ok: OkFn): Promise<void> {
  const em = await startEmulator({ format: "webhook" });
  try {
    const body = JSON.stringify({ kind: "downpipe-event-v1", at: "2024-01-01T00:00:00.000Z", event: "backup-failure", severity: "critical", detail: "x" });
    em.setFault({ kind: "malformed-200" });
    const r1 = await fetch(em.url, { method: "POST", headers: JSON_HEADERS, body });
    ok("fault(malformed-200): still a 200 (the ENGINE's bytes were fine)", r1.status === 200);
    let bodyIsInvalidJson = false;
    try {
      JSON.parse(await r1.text());
    } catch {
      bodyIsInvalidJson = true;
    }
    ok("fault(malformed-200): the ack BODY is deliberately garbage", bodyIsInvalidJson);
    ok("fault(malformed-200): the request is STILL ledgered (the destination accepted it, only its ack is bad)", em.ledger.size === 1);

    em.setFault({ kind: "wrong-content-type" });
    const r2 = await fetch(em.url, { method: "POST", headers: JSON_HEADERS, body });
    ok("fault(wrong-content-type): still 200", r2.status === 200);
    ok('fault(wrong-content-type): the ack Content-Type is unexpected ("text/html")', r2.headers.get("content-type")?.includes("text/html") === true);
  } finally {
    await em.close();
  }
}

async function testEmulatorFaultPartialSuccessOtlp(ok: OkFn): Promise<void> {
  const em = await startEmulator({ format: "otlp" });
  try {
    em.setFault({ kind: "partial-success", rejected: 3, message: "3 data points rejected: out of range" });
    const body = JSON.stringify(otlpFixtureObject());
    const res = await fetch(em.url, { method: "POST", headers: JSON_HEADERS, body });
    ok("fault(partial-success): OTLP's own 200 partial-success convention", res.status === 200);
    const parsed = (await res.json()) as { partialSuccess?: { rejectedDataPoints: number; errorMessage: string } };
    ok("fault(partial-success): the documented partialSuccess envelope rides the ack", parsed.partialSuccess?.rejectedDataPoints === 3 && parsed.partialSuccess?.errorMessage.includes("out of range") === true);
  } finally {
    await em.close();
  }
}

async function testEmulatorFaultDropMidBodyAndStall(ok: OkFn): Promise<void> {
  const body = JSON.stringify({ kind: "downpipe-event-v1", at: "2024-01-01T00:00:00.000Z", event: "backup-failure", severity: "critical", detail: "x" });

  const em1 = await startEmulator({ format: "webhook" });
  try {
    em1.setFault({ kind: "drop-mid-body", afterBytes: 5 });
    let bodyReadErrored = false;
    try {
      const res = await fetch(em1.url, { method: "POST", body });
      await res.text();
    } catch {
      bodyReadErrored = true;
    }
    ok("fault(drop-mid-body): the client observes a network error reading the truncated response", bodyReadErrored);
  } finally {
    await em1.close();
  }

  const em2 = await startEmulator({ format: "webhook" });
  try {
    em2.setFault({ kind: "stall", ms: 60_000 });
    let aborted = false;
    try {
      await fetch(em2.url, { method: "POST", body, signal: AbortSignal.timeout(200) });
    } catch {
      aborted = true;
    }
    ok("fault(stall): a client with a short timeout observes no response in time", aborted);
  } finally {
    await em2.close();
  }
}

async function testEmulatorFaultFlapAndAfterN(ok: OkFn): Promise<void> {
  // flap: exactly every 3rd request fails (503-class); the rest succeed and ledger.
  const emFlap = await startEmulator({ format: "webhook" });
  try {
    const body = JSON.stringify({ kind: "downpipe-event-v1", at: "2024-01-01T00:00:00.000Z", event: "backup-failure", severity: "critical", detail: "x" });
    emFlap.setFault({ kind: "flap", everyN: 3 });
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      const res = await fetch(emFlap.url, { method: "POST", headers: JSON_HEADERS, body });
      statuses.push(res.status);
    }
    ok("fault(flap): every 3rd request fails, the rest succeed (200,200,503,200,200,503)", statuses.join(",") === "200,200,503,200,200,503");
  } finally {
    await emFlap.close();
  }

  // afterN pacing: a status fault only takes effect from the Nth request onward.
  const emAfter = await startEmulator({ format: "webhook" });
  try {
    const body = JSON.stringify({ kind: "downpipe-event-v1", at: "2024-01-01T00:00:00.000Z", event: "backup-failure", severity: "critical", detail: "x" });
    emAfter.setFault({ kind: "status", code: 500, afterN: 3 });
    const statuses: number[] = [];
    for (let i = 0; i < 4; i++) {
      const res = await fetch(emAfter.url, { method: "POST", headers: JSON_HEADERS, body });
      statuses.push(res.status);
    }
    ok("fault pacing(afterN=3): the first two requests are unaffected, the fault bites from #3 onward (200,200,500,500)", statuses.join(",") === "200,200,500,500");
  } finally {
    await emAfter.close();
  }
}

async function testEmulatorJsmCreateCloseAndPoll(ok: OkFn): Promise<void> {
  const em = await startEmulator({ format: "jsm" });
  try {
    const create = JSON.stringify({ message: "Prod backup-failure", alias: "downpipe:dp1:backup-failure", description: "Prod: last run failed", priority: "P1", source: "Prod" });
    const r1 = await fetch(em.url, { method: "POST", headers: { "content-type": "application/json" }, body: create });
    ok("jsm live: create responds 202 (async-accepted, the real Alert API convention)", r1.status === 202);
    const createBody = (await r1.json()) as { requestId?: string };
    ok("jsm live: create's ack carries a requestId", typeof createBody.requestId === "string" && createBody.requestId.length > 0);
    ok("jsm live: the create is ledgered under its alias", em.ledger.has("downpipe:dp1:backup-failure"));

    const pollUrl = `${em.url}/requests/${encodeURIComponent(createBody.requestId ?? "")}`;
    const r2 = await fetch(pollUrl);
    const pollBody = (await r2.json()) as { data?: { success?: boolean } };
    ok("jsm live: a normal (non-faulted) poll reports success:true", pollBody.data?.success === true);

    const closeUrl = `${em.url}/${encodeURIComponent("downpipe:dp1:backup-failure")}/close?identifierType=alias`;
    const r3 = await fetch(closeUrl, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ source: "Prod" }) });
    ok("jsm live: close also responds 202", r3.status === 202);
    ok("jsm live: the close re-uses the SAME alias ledger key (dedup_key parity with the create)", em.ledger.get("downpipe:dp1:backup-failure")?.deliveryCount === 2);
  } finally {
    await em.close();
  }

  // jsm-202-then-fail: the create still 202s, but the poll now reports success:false.
  const em2 = await startEmulator({ format: "jsm" });
  try {
    em2.setFault({ kind: "jsm-202-then-fail" });
    const create = JSON.stringify({ message: "x", alias: "downpipe:dp2:backup-failure", description: "x", priority: "P1", source: "Prod" });
    const r1 = await fetch(em2.url, { method: "POST", headers: { "content-type": "application/json" }, body: create });
    ok("fault(jsm-202-then-fail): create still 202s", r1.status === 202);
    const { requestId } = (await r1.json()) as { requestId?: string };
    const r2 = await fetch(`${em2.url}/requests/${encodeURIComponent(requestId ?? "")}`);
    const pollBody = (await r2.json()) as { data?: { success?: boolean } };
    ok("fault(jsm-202-then-fail): the SUBSEQUENT poll reports success:false", pollBody.data?.success === false);
  } finally {
    await em2.close();
  }
}

async function testEmulatorServiceNow(ok: OkFn): Promise<void> {
  const em = await startEmulator({ format: "servicenow" });
  try {
    const good = JSON.stringify({ source: "downpipes", node: "Prod", resource: "backup-failure", metric_name: "downpipe.backup-failure", severity: 1, description: "x", message_key: "downpipe:dp1:backup-failure" });
    const r1 = await fetch(em.url, { method: "POST", headers: { "content-type": "application/json" }, body: good });
    ok("servicenow live: a well-formed em_event is accepted 201", r1.status === 201);
    ok("servicenow live: ledgered under message_key", em.ledger.has("downpipe:dp1:backup-failure"));

    const bad = good.replace('"severity":1', '"severity":9');
    const r2 = await fetch(em.url, { method: "POST", headers: { "content-type": "application/json" }, body: bad });
    ok("servicenow live: an out-of-range severity is rejected 400", r2.status === 400);
  } finally {
    await em.close();
  }
}

// ---- section 3: live syslog-TLS emulator behaviour -----------------------------------------------------

async function testSyslogEmulatorRealTls(ok: OkFn): Promise<void> {
  const em = await startSyslogEmulator();
  const meta: PushCursorMeta = { afterSeq: 0, nextAfterSeq: 1, headSeq: 1, headHash: "h" };
  try {
    __setSyslogConnectForTest(makeRealSyslogConnect());
    const events = [realAuditEvent({ seq: 777 })];
    const r = await deliverSiemSyslog(em.host, em.port, "cef", events, meta);
    ok("syslog live TLS: deliverSiemSyslog reports ok:true over a REAL TLS handshake", r.ok === true);
    // The client's write+close promise resolving is a DIFFERENT event than the server having finished
    // parsing (two sockets, ordered only by the network); wait for the server side to actually land it.
    const landed = await em.waitForLedgerSize(1);
    ok("syslog live TLS: the event is ledgered by seq:hash", landed && em.ledger.has(`777:${HASH_B}`));
    ok("syslog live TLS: the raw request is captured with the correct PRI (success -> 110)", em.requests[0]?.pri === 110);
  } finally {
    __setSyslogConnectForTest(null);
    await em.close();
  }
}

async function testSyslogEmulatorFaults(ok: OkFn): Promise<void> {
  const meta: PushCursorMeta = { afterSeq: 0, nextAfterSeq: 1, headSeq: 1, headHash: "h" };

  const em1 = await startSyslogEmulator();
  try {
    em1.setFault({ kind: "connect-drop" });
    __setSyslogConnectForTest(makeRealSyslogConnect());
    const r = await deliverSiemSyslog(em1.host, em1.port, "cef", [realAuditEvent({ seq: 1 })], meta);
    ok("syslog fault(connect-drop): the sender observes a non-throwing ok:false", r.ok === false);
  } finally {
    __setSyslogConnectForTest(null);
    await em1.close();
  }

  const em2 = await startSyslogEmulator();
  try {
    em2.setFault({ kind: "stall", ms: 60_000 });
    __setSyslogConnectForTest(makeRealSyslogConnect());
    const started = Date.now();
    const r = await deliverSiemSyslog(em2.host, em2.port, "cef", [realAuditEvent({ seq: 2 })], meta, { timeoutMs: 200 });
    const elapsed = Date.now() - started;
    // gap G138: the syslog timeout is no longer the flat "timeout" code -- it now carries its PHASE
    // (handshake / write / flush), because WHERE a stalled receiver black-holes the send is the whole
    // diagnosis: a handshake stall is a firewall or an untrusted TLS cert, a write/flush stall is a receiver
    // that accepted the connection and then stopped reading. A real stall can be caught at any of the three
    // depending on how much the emulator buffered before it went quiet, so accept any phase-tagged member of
    // the closed SYSLOG_FAIL_CODES timeout family (and, deliberately, nothing outside it).
    const timeoutPhases = ["syslog-timeout-handshake", "syslog-timeout-write", "syslog-timeout-flush"];
    ok("syslog fault(stall): the sender's own hard timeout fires rather than hanging forever", r.ok === false && typeof r.code === "string" && timeoutPhases.includes(r.code));
    ok(`syslog fault(stall): resolves promptly against the sender's timeout budget (took ${elapsed}ms)`, elapsed < 5000);
  } finally {
    __setSyslogConnectForTest(null);
    await em2.close();
  }
}

// ---- entry point -------------------------------------------------------------------------------------------

/** runSelfTests drives every fixture/live-emulator assertion through the supplied `ok` callback (the house
 * ok()/failures bookkeeping lives in the caller, test/validate-destsim-selftest.ts). */
export async function runSelfTests(ok: OkFn): Promise<void> {
  testCefFixtures(ok);
  testLeefFixtures(ok);
  testSyslogFixtures(ok);
  testSplunkHecFixtures(ok);
  testDatadogFixtures(ok);
  testGelfFixtures(ok);
  testNdjsonJsonArrayRawJsonFixtures(ok);
  testOtlpFixtures(ok);
  testPrometheusFixtures(ok);
  testChannelFixtures(ok);

  await testEmulatorAcceptsGoodRejectsBad(ok);
  await testEmulatorLedgerDedupe(ok);
  await testSplunkHecObservedContract(ok);
  await testSplunkHecBatching(ok);
  await testEmulatorFaultStatus(ok);
  await testEmulatorFaultMalformed200AndWrongContentType(ok);
  await testEmulatorFaultPartialSuccessOtlp(ok);
  await testEmulatorFaultDropMidBodyAndStall(ok);
  await testEmulatorFaultFlapAndAfterN(ok);
  await testEmulatorJsmCreateCloseAndPoll(ok);
  await testEmulatorServiceNow(ok);

  await testSyslogEmulatorRealTls(ok);
  await testSyslogEmulatorFaults(ok);
}
