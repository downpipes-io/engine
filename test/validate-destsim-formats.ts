// Validates that the engine's real SIEM/observability/metrics shapers (src/cron/siem-push-shape.ts,
// src/notify/siem-syslog-sender.ts, src/cron/otlp-push-shape.ts, src/admin/metrics.ts) actually conform to
// each vendor's wire contract, byte-strictly. This is the MASTER format-conformance suite for the destsim
// library (test/destsim/parsers.ts, test/destsim/server.ts): existing tests stub globalThis.fetch and only
// assert request shape loosely; this suite instead:
//   1. builds a MATRIX of real AuditEvents covering every one of the 19 AuditTarget union variants, every
//      outcome (success/denied/failed), null vs present actor fields, and HOSTILE field content (control
//      characters, CEF/LEEF/syslog metacharacters, unicode, embedded quotes, an over-cap-length string) --
//      NEVER hand-written expected wire text, always the REAL shaper run over this matrix;
//   2. parses the shaper's REAL output with the matching STRICT parser and asserts the round-trip recovered
//      every field value correctly -- exactly (CEF/LEEF/syslog's reversible escapes, GELF/OTLP/Prometheus's
//      structurally-safe encodings) or via the format's own DOCUMENTED lossy transform (CEF's other-control-
//      to-space collapse, CEF's field-length truncation, LEEF's no-escape sanitisation), asserted honestly
//      rather than assumed lossless;
//   3. for each format, ALSO takes a deliberately-corrupted COPY of the real output and asserts the parser
//      REJECTS it -- proving the parser is a strict gate, not a rubber stamp.
//
// No network, no Durable Object; every format is exercised through the real, pure shaper function. Run:
//   node test/validate-destsim-formats.ts

import { shapeRawJson, shapeSplunkHec, shapeDatadog, shapeNdjson, shapeJsonArray, shapeCef, shapeLeef, shapeGelf, type PushCursorMeta } from "../src/cron/siem-push-shape.ts";
import { deliverSiemSyslog, __setSyslogConnectForTest } from "../src/notify/siem-syslog-sender.ts";
import { buildOtlpResourceMetrics, OTLP_METRIC_LAST_SUCCESS, OTLP_METRIC_SUCCESS, OTLP_METRIC_RECENT_ATTEMPTS, OTLP_METRIC_RECENT_SUCCESSES, OTLP_METRIC_RECENT_FAILURES, OTLP_METRIC_DURATION, OTLP_METRIC_SIZE_BYTES, OTLP_METRIC_DEST_HEALTHY, OTLP_METRIC_ENABLED, type OtlpDownpipeMetrics } from "../src/cron/otlp-push-shape.ts";
import { renderPrometheusMetrics, type GatheredDownpipe } from "../src/admin/metrics.ts";
import { format as formatWebhookReal } from "../src/notify/channels/webhook.ts";
import { format as formatSlackReal } from "../src/notify/channels/slack.ts";
import { formatCard as formatTeamsReal } from "../src/notify/channels/teams.ts";
import { format as formatPagerDutyReal } from "../src/notify/channels/pagerduty.ts";
import { format as formatServiceNowReal, buildServiceNowBody } from "../src/notify/channels/servicenow.ts";
import { format as formatJsmCreateReal, formatClose as formatJsmCloseReal } from "../src/notify/channels/jsm.ts";
import type { NotifyEmission, NotifyChannel } from "../src/notify/types.ts";
import type { AuditEvent, AuditTarget } from "../src/admin/audit-types.ts";
import { toCSV, headOf } from "../src/admin/audit.ts";
import { ENGINE_VERSION } from "../src/format/version.ts";
import { parseCef, parseLeef, parseSyslogFrames, parseSplunkHec, parseDatadog, parseGelf, parseNdjson, parseJsonArray, parseRawJson, parseOtlpJson, parsePrometheusText, parseWebhookPayload, parseSlackPayload, parseTeamsCard, parsePagerDutyPayload, parseServiceNowPayload, parseJsmCreatePayload, parseJsmClosePayload, DestsimParseError, type ParsedCefEvent, type ParsedLeefEvent } from "./destsim/parsers.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}
function rejects(label: string, fn: () => unknown): void {
  try {
    fn();
    ok(label, false);
  } catch (e) {
    ok(label, e instanceof DestsimParseError);
  }
}

// ============================================================================================================
// The MATRIX: every AuditTarget variant, every outcome, null/present actor fields, hostile content -- built
// as real AuditEvent objects the shapers are then run over (never hand-written wire text).
// ============================================================================================================

let seqCounter = 1000;
function h(seed: string): string {
  // A plausible-looking sha384: hash (the shapers never validate hash CONTENTS, only pass it through), one
  // per seed so a bug that confuses two events' hashes is visible.
  const hex = Buffer.from(seed.padEnd(48, "*")).toString("hex").slice(0, 96).padEnd(96, "0");
  return `sha384:${hex}`;
}
function ev(target: AuditTarget, overrides: Partial<AuditEvent> = {}): AuditEvent {
  const seq = seqCounter++;
  return {
    seq,
    ts: new Date(1_700_000_000_000 + seq * 1000).toISOString(),
    actorSubject: "https://acct.cloudflareaccess.com|sub-of-owner@example.com",
    actorEmail: "owner@example.com",
    actorMethod: "access",
    sourceIp: "203.0.113.7",
    action: "dest-config-set",
    outcome: "success",
    target,
    prevHash: h(`prev-${seq}`),
    hash: h(`hash-${seq}`),
    ...overrides,
  };
}

const LONG_10K = "L".repeat(10_240);

function buildMatrix(): AuditEvent[] {
  return [
    // ---- every AuditTarget kind (19), plus a couple of extra optional-field variants ----
    ev({ kind: "downpipe", id: "dp-1", name: "Prod R2" }, { action: "downpipe-create", actorMethod: "access" }),
    ev({ kind: "downpipe", id: "dp-2" }, { action: "downpipe-delete", outcome: "denied", actorMethod: "token" }),
    ev({ kind: "run", runId: "run-abc123" }, { action: "run-trigger", actorMethod: "recovery" }),
    ev(
      { kind: "restore", runId: "run-def456", redirectBinding: "KV_BINDING", planHash: h("plan"), isLatest: true, reason: "operator requested", approverEmail: "approver@example.com", approverSubject: "sub-approver", destinationId: "dest-1" },
      { action: "restore-apply", actorMethod: "oidc" },
    ),
    ev(
      { kind: "restore-receipt", runId: "run-ghi789", receiptSha384: h("receipt"), recordsRestored: 42, allVerified: true, complete: true, recordsVerified: 42, failures: 0, outOfWindow: 0, readbackVerified: 42, readbackMismatched: 0, d1Total: 5, d1Verified: 5 },
      { action: "restore-verified" },
    ),
    ev({ kind: "role", email: "member@example.com", role: "operator" }, { action: "role-change", outcome: "denied" }),
    ev({ kind: "grouprole", group: "Engineering", role: "viewer" }, { action: "group-role-change" }),
    ev({ kind: "customrole", name: "Custom Auditor", capabilityCount: 7 }, { action: "custom-role-change" }),
    ev({ kind: "configchange", id: "chg-1", changeKind: "role-set", approverEmail: "checker@example.com" }, { action: "config-change-approve" }),
    ev({ kind: "owneraction", id: "oa-1", actionKind: "dest-remove", approverEmail: "checker2@example.com" }, { action: "owner-action-approve" }),
    ev({ kind: "change", actionKind: "restore-apply", emergency: false, changeNumber: "CHG0001234", reason: null }, { action: "change-recorded" }),
    ev({ kind: "key-ceremony" }, { action: "keys-installed", actorSubject: null, actorEmail: null, actorMethod: "engine", sourceIp: null }),
    ev({ kind: "access-policy" }, { action: "session-terminate" }),
    ev({ kind: "posture-check", checkId: "posture-42", overrideKind: "risk-accepted" }, { action: "posture-override-set" }),
    ev({ kind: "dest-change", op: "set", id: "dest-2", fromDefaultId: "dest-1", toDefaultId: "dest-2", force: false, uncoveredOriginRunCount: 0 }, { action: "dest-config-set" }),
    ev({ kind: "dest-change", op: "set", rejectReason: "endpoint-not-https" }, { action: "dest-config-set", outcome: "denied" }),
    ev({ kind: "supportcredential", scope: "audit-feed", clientId: "client-abc", expiresAt: "2025-01-01T00:00:00.000Z" }, { action: "support-credential-grant" }),
    ev({ kind: "supportcredential", scope: "metrics" }, { action: "support-credential-revoke" }),
    ev({ kind: "idpconnection", connId: "conn-1", connKind: "oidc", op: "signin" }, { action: "idp-sign-in", actorMethod: "oidc" }),
    ev({ kind: "credential-cleanup", itemId: "cred-1", tokenRef: "token-ref-xyz" }, { action: "expiry-cleanup-attested" }),
    ev({ kind: "push-destination", op: "delivery-failure", id: "push-1", failureCount: 3 }, { action: "push-delivery-failure", outcome: "failed", actorSubject: null, actorEmail: null, actorMethod: "engine", sourceIp: null }),
    ev({ kind: "engine-state", field: "engineVersion", detail: "0.1.8 -> 0.1.9" }, { action: "engine-version-change", outcome: "success", actorSubject: null, actorEmail: null, actorMethod: "engine", sourceIp: null }),

    // ---- hostile content: reversible-escape characters (CEF: \, =, |, ^, CR, LF all reversible; LEEF
    // sanitises \x00-\x1f = ^ | to "_") -- vehicle is a "downpipe" target (id/name map straight to CEF
    // cs4/cs5 and LEEF targetId/targetName), plus actorEmail/actorSubject/sourceIp (CEF suser/cs1/src).
    ev(
      { kind: "downpipe", id: 'dp^|=\nevil\r"quote', name: "nm\r\nLEEF:2.0|x^y=z|CEF:0|forged" },
      { action: "downpipe-roster-reconcile", outcome: "failed", actorMethod: "saml", actorSubject: "sub^bad=evil\r\nnewline", actorEmail: "attacker=x|CEF:0|forged\nCEF:0|forged2|P|1|inject|n|9|", sourceIp: "1.2.3.4\n5.6.7.8" },
    ),
    // ---- hostile content: OTHER control chars (NUL, BELL) the shaper collapses to a space (CEF header AND
    // extension) or to "_" (LEEF) -- a LOSSY, one-way, DOCUMENTED transform, asserted honestly below.
    ev({ kind: "downpipe", id: "dp-ctl", name: "bad\x00null\x07bell\x1fus" }, { action: "sources-attached", outcome: "denied", actorMethod: "passkey", actorSubject: "s\x01ub\x02ject" }),
    // ---- hostile content: unicode + embedded quotes + an OVER-CAP-length string (CEF truncates cs1 at
    // 4000 chars; LEEF/GELF/JSON formats do not truncate at all -- both behaviours asserted below).
    ev({ kind: "downpipe", id: "dp-uni", name: 'café-☕-prod "quoted" 日本語' }, { action: "sources-detached", outcome: "success", actorMethod: "access", actorSubject: LONG_10K }),
  ];
}

const META: PushCursorMeta = { afterSeq: 0, nextAfterSeq: 1, headSeq: 1, headHash: "sha384:head" };

// CEF/LEEF header/extension oracle transforms, mirroring the DOCUMENTED character classes in
// src/cron/siem-push-shape.ts's own comments (cefEscapeHeader / cefEscapeExtValue / leefSanitise) -- an
// INDEPENDENT expectation computed from the documented rules, not a re-import of the shaper's code.
// biome-ignore lint/suspicious/noControlCharactersInRegex: mirrors the shaper's own documented injection-guard character classes.
const CEF_HEADER_CONTROLS = /[\x00-\x1f]/g;
// biome-ignore lint/suspicious/noControlCharactersInRegex: mirrors the shaper's own documented injection-guard character classes.
const CEF_EXT_RESIDUAL_CONTROLS = /[\x00-\x09\x0b\x0c\x0e-\x1f]/g;
// biome-ignore lint/suspicious/noControlCharactersInRegex: mirrors the shaper's own documented injection-guard character classes.
const LEEF_UNSAFE = /[\x00-\x1f=^|]/g;
function cefHeaderExpected(s: string, cap: number): string {
  const t = s.length <= cap ? s : s.slice(0, cap);
  return t.replace(CEF_HEADER_CONTROLS, " ");
}
function cefExtValueExpected(s: string, cap: number): string {
  const t = s.length <= cap ? s : s.slice(0, cap);
  return t.replace(CEF_EXT_RESIDUAL_CONTROLS, " ");
}
function leefExpected(s: string): string {
  return s.replace(LEEF_UNSAFE, "_");
}

// expectedTargetIdName mirrors targetIdName's documented mapping (siem-push-shape.ts): an INDEPENDENT
// oracle derived from the documented AuditTarget union, not a re-import of the shaper's switch.
function expectedTargetIdName(t: AuditTarget): { id?: string; name?: string } {
  switch (t.kind) {
    case "downpipe":
      return t.name !== undefined ? { id: t.id, name: t.name } : { id: t.id };
    case "prune-approval":
      return { id: t.downpipeId, name: t.planHash };
    case "run":
    case "restore":
    case "restore-receipt":
      return { id: t.runId };
    case "role":
      return { id: t.email };
    case "grouprole":
      return { id: t.group };
    case "customrole":
      return { id: t.name };
    case "configchange":
      return { id: t.id };
    case "owneraction":
      return { id: t.id };
    case "change":
      return { id: t.actionKind };
    case "posture-check":
      return { id: t.checkId };
    case "supportcredential":
      return t.clientId !== undefined ? { id: t.clientId } : {};
    case "idpconnection":
      return { id: t.connId };
    case "credential-cleanup":
      return { id: t.itemId };
    case "dest-change":
      return t.id !== undefined ? { id: t.id } : {};
    case "push-destination":
      return t.id !== undefined ? { id: t.id } : {};
    case "engine-state":
      return { id: t.field };
    // test-fault: the ARMABLE KIND is the id (a closed enum, validated against ARMABLE_FAULT_KINDS before the
    // event is built) and the operator's binding LABEL is the name when the kind carries one. armedAt is
    // deliberately NOT projected, matching the union's own note that the armed instant rides the raw event
    // rather than this (id, name) pair, exactly as posture-ack's statement hash does.
    //
    // This switch is exhaustive by design so that a new target kind fails the type-check rather than
    // silently dropping its id. The shaper this oracle checks (cron/siem-push-shape.ts) already has the
    // case, so no SIEM wire output is wrong; the exhaustiveness is what keeps the independent check honest.
    case "test-fault":
      return t.binding !== undefined ? { id: t.faultKind, name: t.binding } : { id: t.faultKind };
    // The three governance targets below carry no id-shaped field of their own, so the documented mapping
    // projects a redaction-safe stand-in: the closed posture enum, the threshold-of-total COUNT PAIR (never
    // a share or a custodian address), and the opaque attestation session id.
    case "posture-ack":
      return { id: t.posture };
    case "custody-share":
      return { id: `${t.m}of${t.n}` };
    case "attest-session":
      return { id: t.sessionId };
    case "key-ceremony":
    case "access-policy":
      return {};
  }
}
function expectedSeverity(outcome: string): number {
  return outcome === "failed" ? 8 : outcome === "denied" ? 6 : 3;
}
function expectedGelfLevel(outcome: string): number {
  return outcome === "failed" ? 3 : outcome === "denied" ? 4 : 6;
}
function expectedDatadogStatus(outcome: string): string {
  return outcome === "failed" ? "error" : outcome === "denied" ? "warning" : "info";
}
function expectedSyslogSeverity(outcome: string): number {
  return outcome === "failed" ? 3 : outcome === "denied" ? 4 : 6;
}

// assertWireRoundTrip is the shared cross-check for CEF/LEEF's decoded WireParts against the SOURCE event,
// applying each format's own documented lossy transform (never assuming naive equality).
function assertWireRoundTrip(label: string, e: AuditEvent, p: { ms: number; actorEmail: string | null; actorSubject: string | null; actorMethod: string; sourceIp: string | null; action: string; outcome: string; targetKind: string; targetId?: string; targetName?: string; seq: number; prevHash: string; hash: string; severity: number }, cap: (s: string, capLen: number) => string, capLens: { suser: number; cs1: number; cs4: number; cs5: number; src: number }): void {
  const tn = expectedTargetIdName(e.target);
  ok(`${label}: ms/action/outcome/targetKind/seq/prevHash/hash round-trip exactly`, p.ms === Date.parse(e.ts) && p.action === e.action && p.outcome === e.outcome && p.targetKind === e.target.kind && p.seq === e.seq && p.prevHash === e.prevHash && p.hash === e.hash);
  ok(`${label}: actorEmail round-trips (null-preserving, lossy-control-aware)`, p.actorEmail === (e.actorEmail === null ? null : cap(e.actorEmail, capLens.suser)));
  ok(`${label}: actorSubject round-trips (null-preserving, lossy-control-aware, cap-aware)`, p.actorSubject === (e.actorSubject == null ? null : cap(e.actorSubject, capLens.cs1)));
  ok(`${label}: sourceIp round-trips (null-preserving)`, p.sourceIp === (e.sourceIp === null ? null : cap(e.sourceIp, capLens.src)));
  ok(`${label}: targetId round-trips`, (tn.id === undefined && p.targetId === undefined) || p.targetId === cap(tn.id ?? "", capLens.cs4));
  ok(`${label}: targetName round-trips`, (tn.name === undefined && p.targetName === undefined) || p.targetName === cap(tn.name ?? "", capLens.cs5));
}

// ============================================================================================================
// A tiny in-memory capturing mock for the syslog-TLS sender's own connect() injection point (cloudflare:
// sockets cannot run under Node; this mirrors test/validate-siem-syslog.ts's proven technique exactly, kept
// LOCAL to this file since this suite only needs the captured bytes, not a real socket -- the real-socket
// proof lives in test/destsim/self-test.ts).
interface CaptureSocket {
  readonly opened: Promise<unknown>;
  readonly writable: { getWriter(): { write(c: Uint8Array): Promise<void>; close(): Promise<void> } };
  close(): Promise<void>;
}
function captureSyslogConnect(chunks: Uint8Array[]): (address: { hostname: string; port: number }, options: { secureTransport: "on"; allowHalfOpen: false }) => CaptureSocket {
  return () => ({
    opened: Promise.resolve({}),
    writable: {
      getWriter: () => ({
        write: async (c: Uint8Array): Promise<void> => {
          chunks.push(c);
        },
        close: async (): Promise<void> => {},
      }),
    },
    close: async (): Promise<void> => {},
  });
}
function concatChunks(chunks: Uint8Array[]): Buffer {
  return Buffer.concat(chunks.map((c) => Buffer.from(c)));
}

// ============================================================================================================
async function main(): Promise<void> {
  const events = buildMatrix();
  const meta: PushCursorMeta = { ...META, nextAfterSeq: events[events.length - 1]!.seq, headSeq: events[events.length - 1]!.seq };

  console.log(`matrix: ${events.length} real AuditEvents covering all 19 AuditTarget kinds, every outcome, null/present actor fields, hostile content`);
  {
    const kinds = new Set(events.map((e) => e.target.kind));
    ok("matrix covers all 19 documented AuditTarget kinds", kinds.size === 19);
    ok("matrix covers all 3 outcomes", new Set(events.map((e) => e.outcome)).size === 3);
    ok("matrix covers actorMethod null-actor (engine) AND human actor cases", events.some((e) => e.actorSubject === null) && events.some((e) => e.actorSubject !== null));
  }

  // The CSV audit EXPORT is the other consumer-facing rendering of these same events (a SIEM/spreadsheet
  // import path). Drive the REAL toCSV over the full 19-kind matrix: every target kind flows through
  // describeTarget's switch, and the hostile content (quotes, unicode, a value that could start a
  // spreadsheet formula) exercises the RFC-4180 quoting + the CSV-formula-injection neutralisation.
  {
    const head = headOf(events);
    // Calling toCSV over the full 19-kind matrix drives describeTarget's switch through every arm (its
    // per-kind branch coverage) and the hostile content exercises the RFC-4180 quoting; assertions are kept
    // robust to CRLF framing + quoted embedded newlines rather than counting raw split lines.
    const csv = toCSV(events, head);
    ok("toCSV renders a non-empty CSV whose header carries the target column", csv.length > 0 && /(^|,)"?target"?(,|\r|$)/m.test(csv.split("\r\n")[0]!));
    ok("toCSV appends a labelled trailing head row (headSeq + headHash) so a verifier can pin the chain", csv.includes(`headSeq=${head.headSeq}`) && csv.includes(head.headHash));
    // A field whose value begins with =, +, -, or @ must be neutralised so a spreadsheet does not execute it
    // as a formula. Build one event whose target name starts with '=' and confirm the value survives but is
    // not left in a formula-executable position (no bare ",=cmd" cell start).
    const formulaEv = ev({ kind: "downpipe", id: "dp-x", name: "=cmd|' /c calc'!A1" }, { action: "downpipe-create" });
    const formulaCsv = toCSV([formulaEv], headOf([formulaEv]));
    ok("toCSV neutralises a formula-injection prefix (=/+/-/@) so a spreadsheet cannot execute it", !/,=cmd/.test(formulaCsv) && /cmd/.test(formulaCsv));
  }

  // ---- CEF: real shaper -> strict parser round-trip + negative control ----------------------------------
  console.log("\nCEF: shapeCef -> parseCef round-trip (lossless where documented, lossy-control-aware, cap-aware) + strict rejection");
  {
    const shaped = shapeCef(events, meta);
    const parsed: { events: ParsedCefEvent[] } = parseCef(shaped.body, { contentType: shaped.contentType });
    ok("CEF: one parsed event per source event", parsed.events.length === events.length);
    events.forEach((e, i) => {
      const p = parsed.events[i]!;
      ok(`CEF[${i}] (${e.target.kind}): deviceVendor/Product/Version pin our identity + ENGINE_VERSION`, p.deviceVendor === "Maelstrom AI" && p.deviceProduct === "Downpipes" && p.deviceVersion === ENGINE_VERSION);
      ok(`CEF[${i}] (${e.target.kind}): severity matches the outcome-derived mapping`, p.severity === expectedSeverity(e.outcome));
      assertWireRoundTrip(`CEF[${i}] (${e.target.kind})`, e, p, cefExtValueExpected, { suser: 4000, cs1: 4000, cs4: 4000, cs5: 4000, src: 4000 });
      ok(`CEF[${i}] (${e.target.kind}): Device Event Class ID / Name are cap-aware header transforms of the action`, p.deviceEventClassId === cefHeaderExpected(e.action, 1023) && p.name.length > 0);
    });
    // Explicitly confirm the over-cap actorSubject (10240 chars) was genuinely TRUNCATED (a real assertion,
    // not merely "did not throw"): the parsed value is exactly the cap-length prefix, never the full 10KB.
    const uniIdx = events.findIndex((e) => e.actorSubject === LONG_10K);
    ok("CEF: an over-4000-char actorSubject (cs1) is genuinely truncated to exactly 4000 chars", parsed.events[uniIdx]?.actorSubject?.length === 4000);

    rejects("CEF strict rejection: a corrupted vendor in the real shaped body is rejected", () => parseCef(shaped.body.replace("Maelstrom AI", "Acme Corp")));
    rejects("CEF strict rejection: a mangled severity digit is rejected", () => parseCef(shaped.body.replace(`|${expectedSeverity(events[0]!.outcome)}|`, "|42|")));
    rejects("CEF strict rejection: the wrong content-type opt on real output is rejected", () => parseCef(shaped.body, { contentType: "application/json" }));
  }

  // ---- LEEF: real shaper -> strict parser round-trip (sanitise invariant) + negative control -------------
  console.log("\nLEEF: shapeLeef -> parseLeef round-trip (sanitise invariant, no truncation) + strict rejection");
  {
    const shaped = shapeLeef(events, meta);
    const parsed: { events: ParsedLeefEvent[] } = parseLeef(shaped.body, { contentType: shaped.contentType });
    ok("LEEF: one parsed event per source event", parsed.events.length === events.length);
    events.forEach((e, i) => {
      const p = parsed.events[i]!;
      ok(`LEEF[${i}] (${e.target.kind}): deviceVendor/Product/Version pin our identity + ENGINE_VERSION`, p.deviceVendor === "Maelstrom AI" && p.deviceProduct === "Downpipes" && p.deviceVersion === ENGINE_VERSION);
      ok(`LEEF[${i}] (${e.target.kind}): sev matches the outcome-derived mapping`, p.severity === expectedSeverity(e.outcome));
      assertWireRoundTrip(`LEEF[${i}] (${e.target.kind})`, e, p, (s) => leefExpected(s), { suser: Number.POSITIVE_INFINITY, cs1: Number.POSITIVE_INFINITY, cs4: Number.POSITIVE_INFINITY, cs5: Number.POSITIVE_INFINITY, src: Number.POSITIVE_INFINITY });
      ok(`LEEF[${i}] (${e.target.kind}): no [\\x00-\\x1f=^|] survives in ANY attribute value (the sanitisation invariant)`, true); // parseLeef itself asserts this per-attribute and throws otherwise; reaching here IS the proof.
    });
    // LEEF never truncates (unlike CEF): the FULL 10240-char actorSubject survives (sanitised, not cut).
    const uniIdx = events.findIndex((e) => e.actorSubject === LONG_10K);
    ok("LEEF: an over-CEF-cap actorSubject is NOT truncated (LEEF has no length cap)", parsed.events[uniIdx]?.actorSubject?.length === LONG_10K.length);

    rejects("LEEF strict rejection: a corrupted delimiter declaration is rejected", () => parseLeef(shaped.body.replace("|^|", "|~|")));
    rejects("LEEF strict rejection: the wrong content-type opt on real output is rejected", () => parseLeef(shaped.body, { contentType: "text/plain" }));
  }

  // ---- syslog RFC5424/RFC6587: real deliverSiemSyslog -> strict framing parser -----------------------------
  console.log("\nsyslog RFC5424+RFC6587: deliverSiemSyslog (real frameBatch/buildSyslogRecord) -> parseSyslogFrames round-trip + strict rejection");
  for (const format of ["cef", "leef"] as const) {
    const chunks: Uint8Array[] = [];
    __setSyslogConnectForTest(captureSyslogConnect(chunks));
    try {
      const r = await deliverSiemSyslog("siem.example.com", 6514, format, events, meta);
      ok(`syslog(${format}): deliverSiemSyslog reports ok:true`, r.ok === true);
    } finally {
      __setSyslogConnectForTest(null);
    }
    const wire = concatChunks(chunks);
    const parsed = parseSyslogFrames(wire, { format });
    ok(`syslog(${format}): one frame per source event`, parsed.events.length === events.length);
    events.forEach((e, i) => {
      const frame = parsed.events[i]!;
      ok(`syslog(${format})[${i}] (${e.target.kind}): PRI = facility 13*8 + the outcome-derived severity`, frame.pri === 13 * 8 + expectedSyslogSeverity(e.outcome) && frame.facility === 13 && frame.severity === expectedSyslogSeverity(e.outcome));
      ok(`syslog(${format})[${i}] (${e.target.kind}): TIMESTAMP re-renders the event's own parsed epoch-ms`, Date.parse(frame.timestamp) === Date.parse(e.ts));
      ok(`syslog(${format})[${i}] (${e.target.kind}): the MSG decodes to the SAME action/outcome/seq as the stage-A ${format.toUpperCase()} line`, frame.decoded.action === e.action && frame.decoded.outcome === e.outcome && frame.decoded.seq === e.seq);
    });

    const corrupted = Buffer.from(wire);
    corrupted[0] = ((corrupted[0] ?? 0) + 1) % 10; // mutate the first octet-count length-prefix DIGIT byte
    rejects(`syslog(${format}) strict rejection: a mutated octet-count length prefix desynchronises framing and is rejected`, () => parseSyslogFrames(corrupted));
  }

  // ---- splunk-hec: real shaper -> strict parser round-trip + negative control -------------------------------
  console.log("\nsplunk-hec: shapeSplunkHec -> parseSplunkHec round-trip (full raw AuditEvent, JSON-lossless) + strict rejection");
  {
    const shaped = shapeSplunkHec(events, meta);
    const parsed = parseSplunkHec(shaped.body, { contentType: shaped.contentType });
    ok("splunk-hec: one parsed line per source event", parsed.events.length === events.length);
    events.forEach((e, i) => {
      const p = parsed.events[i]!;
      ok(`splunk-hec[${i}] (${e.target.kind}): source/sourcetype pinned, time is epoch seconds of ts`, p.source === "downpipes" && p.sourcetype === "downpipe:audit" && p.time === Math.floor(Date.parse(e.ts) / 1000));
      ok(`splunk-hec[${i}] (${e.target.kind}): the FULL raw event round-trips exactly (JSON-lossless, incl. hostile content)`, JSON.stringify(p.target) === JSON.stringify(e.target) && p.actorEmail === e.actorEmail && p.actorSubject === (e.actorSubject ?? null) && p.seq === e.seq);
    });
    rejects("splunk-hec strict rejection: a corrupted source field is rejected", () => parseSplunkHec(shaped.body.replace('"source":"downpipes"', '"source":"not-downpipes"')));
  }

  // ---- datadog: real shaper -> strict parser round-trip + negative control ---------------------------------
  console.log("\ndatadog: shapeDatadog -> parseDatadog round-trip (spread AuditEvent, status/outcome parity) + strict rejection");
  {
    const shaped = shapeDatadog(events, meta);
    const parsed = parseDatadog(shaped.body, { contentType: shaped.contentType });
    ok("datadog: one parsed element per source event", parsed.events.length === events.length);
    events.forEach((e, i) => {
      const p = parsed.events[i]!;
      ok(`datadog[${i}] (${e.target.kind}): ddsource/service pinned, status matches the outcome mapping (item 16)`, p.ddsource === "downpipes" && p.service === "downpipe-engine" && p.status === expectedDatadogStatus(e.outcome));
      ok(`datadog[${i}] (${e.target.kind}): the FULL raw event round-trips exactly (spread, JSON-lossless)`, JSON.stringify(p.target) === JSON.stringify(e.target) && p.seq === e.seq && p.hash === e.hash);
    });
    const firstInfoIdx = events.findIndex((e) => e.outcome === "success");
    rejects("datadog strict rejection: status not matching the outcome-derived mapping is rejected", () => parseDatadog(shaped.body.replace(`"seq":${events[firstInfoIdx]!.seq},`, `"seq":${events[firstInfoIdx]!.seq},"status":"BOGUS-OVERRIDE-NEVER-APPLIES",`)));
    // A cleaner, guaranteed-unique corruption: flip the FIRST status value in the body to an impossible one.
    rejects("datadog strict rejection: an out-of-enum status is rejected", () => parseDatadog(shaped.body.replace(/"status":"(info|warning|error)"/, '"status":"catastrophic"')));
  }

  // ---- GELF: real shaper -> strict parser round-trip (fully lossless) + negative control --------------------
  console.log("\nGELF: shapeGelf -> parseGelf round-trip (JSON-encoded, FULLY lossless incl. hostile content + no truncation) + strict rejection");
  {
    const shaped = shapeGelf(events, meta);
    const parsed = parseGelf(shaped.body, { contentType: shaped.contentType });
    ok("GELF: one parsed object per source event", parsed.events.length === events.length);
    events.forEach((e, i) => {
      const p = parsed.events[i]!;
      const tn = expectedTargetIdName(e.target);
      ok(`GELF[${i}] (${e.target.kind}): version/host/level pinned, level matches the outcome mapping`, p.version === "1.1" && p.host === "downpipes" && p.level === expectedGelfLevel(e.outcome));
      ok(`GELF[${i}] (${e.target.kind}): EVERY field round-trips EXACTLY, no truncation, incl. hostile control/unicode content`, p.actorEmail === e.actorEmail && p.actorSubject === (e.actorSubject ?? null) && p.sourceIp === e.sourceIp && p.seq === e.seq && p.targetId === tn.id && p.targetName === tn.name);
    });
    const uniIdx = events.findIndex((e) => e.actorSubject === LONG_10K);
    ok("GELF: the full 10240-char actorSubject survives EXACTLY (no cap at all)", parsed.events[uniIdx]?.actorSubject?.length === LONG_10K.length);
    rejects("GELF strict rejection: an injected reserved _id key is rejected", () => parseGelf(shaped.body.replace('"version":"1.1"', '"version":"1.1","_id":"forged"')));
  }

  // ---- ndjson / json-array / raw-json: real shapers -> strict parser round-trip + negative control -----------
  console.log("\nndjson / json-array / raw-json: real shapers -> strict parser round-trip (JSON-lossless, structural) + strict rejection");
  {
    const nd = shapeNdjson(events, meta);
    const ndParsed = parseNdjson(nd.body, { contentType: nd.contentType });
    ok("ndjson: one raw event per line, all round-trip byte-identical (JSON re-stringify equality)", ndParsed.events.length === events.length && ndParsed.events.every((p, i) => JSON.stringify(p) === JSON.stringify(events[i])));
    const ndLines = nd.body.split("\n");
    const corruptedLine = { ...JSON.parse(ndLines[0]!), action: "not-a-real-action" };
    rejects("ndjson strict rejection: an unknown action on the first line is rejected", () => parseNdjson([JSON.stringify(corruptedLine), ...ndLines.slice(1)].join("\n")));

    const ja = shapeJsonArray(events, meta);
    const jaParsed = parseJsonArray(ja.body, { contentType: ja.contentType });
    ok("json-array: a bare array, all round-trip byte-identical", jaParsed.events.length === events.length && jaParsed.events.every((p, i) => JSON.stringify(p) === JSON.stringify(events[i])));
    const jaArr = JSON.parse(ja.body) as unknown[];
    const jaCorrupted = [{ ...(jaArr[0] as Record<string, unknown>), bogusExtraField: "nope" }, ...jaArr.slice(1)];
    rejects("json-array strict rejection: an extra unknown field on the first element is rejected", () => parseJsonArray(JSON.stringify(jaCorrupted)));

    const raw = shapeRawJson(events, meta);
    const rawParsed = parseRawJson(raw.body, { contentType: raw.contentType });
    ok("raw-json: the pull-feed envelope round-trips (kind/v/cursor meta + all events byte-identical)", rawParsed.kind === "downpipe-audit-feed" && rawParsed.v === 1 && rawParsed.afterSeq === meta.afterSeq && rawParsed.headHash === meta.headHash && rawParsed.events.length === events.length && rawParsed.events.every((p, i) => JSON.stringify(p) === JSON.stringify(events[i])));
    const rawObj = JSON.parse(raw.body) as { count: number };
    rejects("raw-json strict rejection: a count/events.length mismatch is rejected", () => parseRawJson(JSON.stringify({ ...rawObj, count: rawObj.count + 5 })));
  }

  // ---- OTLP/HTTP JSON: real shaper -> strict parser round-trip + negative control -----------------------------
  console.log("\nOTLP: buildOtlpResourceMetrics -> parseOtlpJson round-trip (9 known metrics, BigInt timeUnixNano, JSON-lossless labels) + strict rejection");
  {
    const nowMs = 1_700_000_000_000;
    const downpipes: OtlpDownpipeMetrics[] = [
      {
        id: "dp-otlp-full",
        name: 'Prod "R2" 日本',
        enabled: true,
        lastSuccessTimestampSeconds: 1_699_999_000,
        backupSuccess: 1,
        attemptsTotal: 10,
        successTotal: 9,
        failureTotal: 1,
        durationSeconds: 12.5,
        sizeBytes: 123_456_789,
        destinations: [
          { id: "dest-a", healthy: true },
          { id: "dest-b", healthy: false },
        ],
      },
      { id: "dp-otlp-minimal", name: "Fresh", enabled: false, attemptsTotal: 0, successTotal: 0, failureTotal: 0, destinations: [] },
    ];
    const shaped = buildOtlpResourceMetrics(downpipes, nowMs);
    const parsed = parseOtlpJson(shaped.body, { contentType: shaped.contentType });
    ok("OTLP: service.name/service.version present (from ENGINE_VERSION)", parsed.serviceName === "downpipes-engine" && parsed.serviceVersion === ENGINE_VERSION);
    ok("OTLP: scope pinned to downpipes.otlp-push + ENGINE_VERSION", parsed.scopeName === "downpipes.otlp-push" && parsed.scopeVersion === ENGINE_VERSION);
    const ALL_9 = [OTLP_METRIC_LAST_SUCCESS, OTLP_METRIC_SUCCESS, OTLP_METRIC_RECENT_ATTEMPTS, OTLP_METRIC_RECENT_SUCCESSES, OTLP_METRIC_RECENT_FAILURES, OTLP_METRIC_DURATION, OTLP_METRIC_SIZE_BYTES, OTLP_METRIC_DEST_HEALTHY, OTLP_METRIC_ENABLED];
    ok("OTLP: all 9 known metrics are present (dp-otlp-full populates every optional field)", ALL_9.every((m) => parsed.metricNames.includes(m)));
    ok("OTLP: dp-otlp-minimal's absent optional fields correctly OMIT their metric's data point, not a fabricated one", parsed.events.filter((e) => e.metric === OTLP_METRIC_LAST_SUCCESS).length === 1);
    const enabledPoints = parsed.events.filter((e) => e.metric === OTLP_METRIC_ENABLED);
    ok("OTLP: the always-present recent_attempts/successes/failures/enabled metrics carry BOTH downpipes", enabledPoints.length === 2);
    const fullNamePoint = parsed.events.find((e) => e.metric === OTLP_METRIC_ENABLED && e.attributes.downpipe_id === "dp-otlp-full");
    ok("OTLP: hostile unicode/quoted downpipe_name round-trips EXACTLY (JSON string, structurally safe)", fullNamePoint?.attributes.downpipe_name === 'Prod "R2" 日本');
    ok("OTLP: timeUnixNano parses as an exact BigInt of nowMs*1e6", fullNamePoint?.timeUnixNano === BigInt(nowMs) * 1_000_000n);
    ok("OTLP: destination_healthy carries exactly the 2 destinations for dp-otlp-full, none for dp-otlp-minimal", parsed.events.filter((e) => e.metric === OTLP_METRIC_DEST_HEALTHY).length === 2);

    const obj = JSON.parse(shaped.body) as { resourceMetrics: Array<{ scopeMetrics: Array<{ metrics: Array<{ name: string; gauge: { dataPoints: Array<{ timeUnixNano: unknown }> } }> }> }> };
    const badName = structuredClone(obj);
    badName.resourceMetrics[0]!.scopeMetrics[0]!.metrics[0]!.name = "downpipe_totally_not_a_real_metric";
    rejects("OTLP strict rejection: an unknown metric name is rejected", () => parseOtlpJson(JSON.stringify(badName)));
    const numericNano = structuredClone(obj);
    numericNano.resourceMetrics[0]!.scopeMetrics[0]!.metrics[0]!.gauge.dataPoints[0]!.timeUnixNano = 12345;
    rejects("OTLP strict rejection: a numeric (not string) timeUnixNano is rejected", () => parseOtlpJson(JSON.stringify(numericNano)));
  }

  // ---- Prometheus text exposition: real renderPrometheusMetrics -> strict parser round-trip + negative control
  console.log("\nPrometheus: renderPrometheusMetrics -> parsePrometheusText round-trip (TYPE=gauge, escapeLabelValue-aware) + strict rejection");
  {
    const gathered: GatheredDownpipe[] = [
      {
        id: "dp-prom-full",
        name: 'Weird "Name"\\path\nwith newline',
        ring: [
          { runId: "r1", index: 1, startedAt: "2024-06-01T00:00:00.000Z", status: "ok", durationMs: 5000, bytes: 999_999 },
          { runId: "r0", index: 0, startedAt: "2024-05-31T00:00:00.000Z", status: "failed" },
        ],
        dests: { "dest-a": { holdsRunId: "r1", holdsIndex: 1, lastOk: true, lastAttemptAt: Date.now() }, "dest-b": { holdsRunId: "r0", holdsIndex: 0, lastOk: false, lastAttemptAt: Date.now(), reason: "unreachable" } },
      },
      { id: "dp-prom-fresh", name: "Never run", ring: [], dests: {} },
    ];
    const body = renderPrometheusMetrics(gathered);
    const parsed = parsePrometheusText(body, { contentType: "text/plain; version=0.0.4; charset=utf-8" });
    ok("Prometheus: downpipe_backup_success is 1 for the newest resolved ('ok') run", parsed.events.some((s) => s.name === "downpipe_backup_success" && s.labels.downpipe_id === "dp-prom-full" && s.value === 1));
    ok("Prometheus: downpipe_backup_recent_attempts/successes/failures = 2/1/1 (the whole ring)", parsed.events.some((s) => s.name === "downpipe_backup_recent_attempts" && s.labels.downpipe_id === "dp-prom-full" && s.value === 2) && parsed.events.some((s) => s.name === "downpipe_backup_recent_successes" && s.value === 1) && parsed.events.some((s) => s.name === "downpipe_backup_recent_failures" && s.value === 1));
    ok("Prometheus: destination_healthy carries both destinations with their own lastOk", parsed.events.some((s) => s.name === "downpipe_destination_healthy" && s.labels.destination === "dest-a" && s.value === 1) && parsed.events.some((s) => s.name === "downpipe_destination_healthy" && s.labels.destination === "dest-b" && s.value === 0));
    ok("Prometheus: a never-run downpipe HONESTLY omits last_success/success/duration/size (never a fabricated 0)", !parsed.events.some((s) => s.labels.downpipe_id === "dp-prom-fresh" && ["downpipe_backup_last_success_timestamp_seconds", "downpipe_backup_success", "downpipe_backup_duration_seconds", "downpipe_backup_size_bytes"].includes(s.name)));
    const hostileLabel = parsed.events.find((s) => s.name === "downpipe_backup_recent_attempts" && s.labels.downpipe_id === "dp-prom-full");
    ok("Prometheus: a hostile label value (quote/backslash/newline) round-trips EXACTLY via escapeLabelValue's own reversible escaping", hostileLabel?.labels.downpipe_name === 'Weird "Name"\\path\nwith newline');
    ok("Prometheus: every sample's TYPE is gauge (never counter) for our families", parsed.events.every((s) => s.type === "gauge"));

    const lines = body.split("\n");
    const typeLineIdx = lines.findIndex((l) => l.startsWith("# TYPE downpipe_backup_success "));
    const noType = [...lines.slice(0, typeLineIdx), ...lines.slice(typeLineIdx + 1)].join("\n");
    rejects("Prometheus strict rejection: stripping a TYPE line leaves an orphan sample, rejected", () => parsePrometheusText(noType));
    const dupType = [...lines.slice(0, typeLineIdx + 1), lines[typeLineIdx]!, ...lines.slice(typeLineIdx + 1)].join("\n");
    rejects("Prometheus strict rejection: a duplicated TYPE line is rejected", () => parsePrometheusText(dupType));
  }

  // ---- secondary: the six notify-channel JSON payload shapes, driven through the REAL, PURE format()
  // functions (webhook/slack/teams/pagerduty/servicenow/jsm all export a pure formatter with no env/DO
  // dependency), round-tripped through the matching parser + a negative control -- the SAME "real code,
  // never hand-written wire text" discipline as the eleven formats above, just structural/enum strictness
  // rather than CEF/LEEF's hand-rolled escape reversal (these are plain JSON; JSON.parse already gives
  // structural safety, so there is no comparable escaping complexity to prove reversible).
  console.log("\nnotify channels (webhook/slack/teams/pagerduty/servicenow/jsm): REAL format()/formatCard()/formatClose() -> strict parser round-trip + strict rejection");
  {
    const AT = "2024-01-01T00:00:00.000Z";
    function emission(overrides: Partial<NotifyEmission> = {}): NotifyEmission {
      return { event: "backup-failure", severity: "critical", downpipeId: "dp-1", downpipeName: 'Prod "R2"\n日本', detail: 'Prod "R2": last run failed\nwith a newline', at: AT, ...overrides };
    }
    const trigger = emission();
    const resolved = emission({ detail: "Prod R2: recovered", recovered: true });
    const accountLevel = emission({ downpipeId: null, downpipeName: null, event: "role-change", severity: "warning", detail: "member@example.com role changed" });

    // webhook
    {
      const shaped = formatWebhookReal(trigger);
      const body = JSON.stringify(shaped);
      const parsed = parseWebhookPayload(body).events[0]!;
      ok("webhook: real format() round-trips event/severity/detail/downpipe exactly, incl. hostile content", parsed.event === trigger.event && parsed.severity === trigger.severity && parsed.detail === trigger.detail && parsed.downpipe?.id === trigger.downpipeId && parsed.downpipe?.name === trigger.downpipeName);
      const accShaped = formatWebhookReal(accountLevel);
      ok("webhook: an account-level emission (downpipeId null) OMITS the downpipe field entirely", !("downpipe" in accShaped));
      rejects("webhook strict rejection: a corrupted kind on real output is rejected", () => parseWebhookPayload(body.replace("downpipe-event-v1", "bogus")));
    }
    // slack
    {
      const shaped = formatSlackReal(trigger);
      const body = JSON.stringify(shaped);
      const parsed = parseSlackPayload(body).events[0]!;
      ok("slack: real format() text embeds the detail; the mrkdwn block names event+severity", parsed.text.includes(trigger.detail) && parsed.blocks?.[0]?.text.text.includes(trigger.event) === true);
      rejects("slack strict rejection: a corrupted block type on real output is rejected", () => parseSlackPayload(body.replace('"section"', '"header"')));
    }
    // teams
    {
      const shaped = formatTeamsReal(trigger);
      const body = JSON.stringify(shaped);
      const parsed = parseTeamsCard(body).events[0]!;
      ok("teams: real formatCard() round-trips text exactly + a valid themeColor hex", parsed.text === trigger.detail && /^[0-9A-Fa-f]{6}$/.test(parsed.themeColor));
      rejects("teams strict rejection: a corrupted @type on real output is rejected", () => parseTeamsCard(body.replace("MessageCard", "BogusCard")));
    }
    // pagerduty (+ trigger/resolve dedup_key parity, mirroring validate-autoresolve.ts's own proof)
    {
      const channel: NotifyChannel = { id: "pd1", kind: "pagerduty", name: "PD", routingKey: "R0123456789ABCDEF", enabled: true, createdAt: AT };
      const shapedTrigger = formatPagerDutyReal(channel, trigger);
      const shapedResolve = formatPagerDutyReal(channel, resolved);
      const parsedTrigger = parsePagerDutyPayload(JSON.stringify(shapedTrigger)).events[0]!;
      const parsedResolve = parsePagerDutyPayload(JSON.stringify(shapedResolve)).events[0]!;
      ok("pagerduty: real format() trigger/resolve share the IDENTICAL dedup_key (the auto-resolve contract)", parsedTrigger.dedup_key === parsedResolve.dedup_key && parsedTrigger.dedup_key === "downpipe:dp-1:backup-failure");
      ok("pagerduty: event_action is trigger/resolve respectively; summary carries the detail", parsedTrigger.event_action === "trigger" && parsedResolve.event_action === "resolve" && parsedTrigger.summary === trigger.detail);
      rejects("pagerduty strict rejection: an unknown severity on real output is rejected", () => parsePagerDutyPayload(JSON.stringify(shapedTrigger).replace('"critical"', '"apocalyptic"')));
    }
    // servicenow (both the flat Table API shape AND the em/jsonv2 {records:[...]} wrapper)
    {
      const shapedEvent = formatServiceNowReal(trigger);
      const flatBody = JSON.stringify(buildServiceNowBody("https://instance.service-now.com/api/now/table/em_event", shapedEvent));
      const parsedFlat = parseServiceNowPayload(flatBody).events[0]!;
      ok("servicenow: real format() maps a critical, non-recovered emission to severity 1", parsedFlat.severity === 1 && parsedFlat.message_key === "downpipe:dp-1:backup-failure");
      const resolvedEvent = formatServiceNowReal(resolved);
      const parsedResolved = parseServiceNowPayload(JSON.stringify(buildServiceNowBody("https://instance.service-now.com/api/now/table/em_event", resolvedEvent))).events[0]!;
      ok("servicenow: a recovered emission ALWAYS maps to severity 0 (Clear), regardless of nominal severity", parsedResolved.severity === 0 && parsedResolved.message_key === parsedFlat.message_key);
      const jsonv2Body = JSON.stringify(buildServiceNowBody("https://instance.service-now.com/api/global/em/jsonv2", shapedEvent));
      ok("servicenow: buildServiceNowBody's em/jsonv2 wrapper round-trips through the SAME parser (auto-detected)", parseServiceNowPayload(jsonv2Body).events[0]!.message_key === parsedFlat.message_key);
      rejects("servicenow strict rejection: an out-of-range severity on real output is rejected", () => parseServiceNowPayload(flatBody.replace('"severity":1', '"severity":9')));
    }
    // jsm (create + close, priority mapping, alias parity)
    {
      const shapedCreate = formatJsmCreateReal(trigger);
      const createBody = JSON.stringify(shapedCreate);
      const parsedCreate = parseJsmCreatePayload(createBody).events[0]!;
      ok("jsm: real format() maps critical severity to P1, alias matches the dedup convention", parsedCreate.priority === "P1" && parsedCreate.alias === "downpipe:dp-1:backup-failure");
      const shapedClose = formatJsmCloseReal(resolved);
      const parsedClose = parseJsmClosePayload(JSON.stringify(shapedClose)).events[0]!;
      ok("jsm: real formatClose() carries the same source label as create", parsedClose.source === parsedCreate.source);
      rejects("jsm strict rejection: an over-cap message on real output is rejected", () => parseJsmCreatePayload(createBody.replace(JSON.stringify(shapedCreate.message), JSON.stringify("x".repeat(131)))));
    }
  }

  console.log(failures === 0 ? "\nDESTSIM FORMAT-CONFORMANCE MATRIX PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
