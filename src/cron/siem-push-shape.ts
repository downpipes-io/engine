// Pure format shapers for the SIEM push drain (cron/siem-push-pass.ts) and the admin test-send route
// (admin/router-push.ts): given a batch of audit events + cursor metadata, render the wire body per the
// configured PushFormat. No I/O; each function is a straight data transform, so the validator drives every
// configured PushFormat. The envelopes are the wire shapes documented for each vendor: raw-json is the
// pull feed's own body, POSTed instead of GET-returned; ndjson is one raw audit event object per line (the
// split-friendly default); json-array is a bare [event, ...] array; splunk-hec is one HEC event object per
// audit event, newline-concatenated; datadog is a JSON array of flattened log objects; cef and leef are one
// ArcSight-CEF / IBM-LEEF line per event (INJECTION-SAFE per the escaping rules below); gelf is one Graylog
// GELF object per line.
//
// INJECTION SAFETY (the #1 adversarial target). CEF/LEEF/GELF and the eventual
// syslog framing must be UNABLE to let a crafted audit field value (an actorEmail from an IdP claim, an
// operator-chosen target id) break the header/extension grammar, forge an extra event, or inject a
// newline/CR that would start a new record. CEF ESCAPES (backslash, `=`, and CR/LF to the literal two-char
// `\r`/`\n`); LEEF has no escape mechanism, so it SANITISES (any `^`, `=`, `|` or control char in a value
// becomes `_`, so a value can never carry the active delimiter or a record boundary); GELF is JSON-encoded
// (structurally safe) and keeps every custom key `_`-prefixed. The audit fields are a closed set (emails,
// ids, hashes, ips, enums), but each shaper still defends unconditionally and the validator asserts a
// crafted value cannot escape its slot.

import { GENESIS_PREV_HASH } from "../admin/audit.ts";
import type { AuditEvent, AuditTarget } from "../admin/audit.ts";
import { ENGINE_VERSION } from "../format/version.ts";
import type { PushFormat } from "../sched/scheduler-do-base.ts";
import { noteSiemShapingFallback } from "./cron-fault-ledger.ts";

// SIEM_PUSH_BATCH_CAP bounds the per-tick drain batch WELL under Datadog's tightest limit (1000 events /
// 5 MB per request, the tightest of the three targets). Audit events are small, bounded, redaction-safe
// records (the largest free-text fields -- a restore reason, a change-management reason/number -- are
// capped at REASON_MAX_LEN=1000 chars in scheduler-do-records.ts), so 500 events serialises to well under
// a megabyte in the worst realistic case, leaving a wide safety margin under the 5 MB cap without needing
// a dynamic byte-size trim. A destination with a backlog beyond this drains it over successive ticks (the
// cursor only advances to the last DELIVERED event), never in one oversized request. Each shaper enforces
// this cap itself (not only the caller), so the invariant holds regardless of what the drain requested.
export const SIEM_PUSH_BATCH_CAP = 500;

// capBatch slices a batch to SIEM_PUSH_BATCH_CAP and COUNTS the truncation (G084). Every shaper goes through
// it, so the fallback can never fire silently in one format and be counted in another.
//
// This is the LATENT DATA-LOSS path the gap names: the drain and the shapers have SEPARATE limits, and the
// push cursor advances to the last event the DRAIN saw. If the drain limit ever exceeds this cap, the batch
// TAIL is shaped away, the cursor advances PAST it, and the delivery trail claims a full, successful
// delivery -- silent, permanent audit-log loss with no counter anywhere. runSiemPushPass asserts the two
// constants agree (assertSiemBatchCapSound) and derives its cursor from the CAPPED set, so the path is
// closed; this counter is the standing evidence if a future edit ever re-opens it.
function capBatch(events: AuditEvent[]): AuditEvent[] {
  if (events.length <= SIEM_PUSH_BATCH_CAP) return events;
  noteSiemShapingFallback("batch-cap-truncated", events.length - SIEM_PUSH_BATCH_CAP);
  return events.slice(0, SIEM_PUSH_BATCH_CAP);
}


export interface ShapedPush {
  body: string;
  contentType: string;
}

export interface PushCursorMeta {
  afterSeq: number;
  nextAfterSeq: number;
  headSeq: number;
  headHash: string;
}

// shapeRawJson mirrors the pull feed's own body shape (admin/support-ingest.ts handleSupportPull), so a
// customer can point either mechanism (pull or push) at the same parser.
export function shapeRawJson(events: AuditEvent[], meta: PushCursorMeta): ShapedPush {
  const capped = capBatch(events);
  const body = JSON.stringify({
    kind: "downpipe-audit-feed",
    v: 1,
    afterSeq: meta.afterSeq,
    nextAfterSeq: meta.nextAfterSeq,
    headSeq: meta.headSeq,
    headHash: meta.headHash,
    count: capped.length,
    events: capped,
  });
  return { body, contentType: "application/json" };
}

// shapeSplunkHec renders one HEC event object per audit event, newline-concatenated (Splunk's HEC accepts
// concatenated JSON objects in one request body). time is epoch SECONDS (HEC's convention); a malformed ts
// (should be impossible, the DO always stamps a valid RFC-3339 string) falls back to the current time
// rather than emitting NaN.
export function shapeSplunkHec(events: AuditEvent[], _meta: PushCursorMeta): ShapedPush {
  const capped = capBatch(events);
  const lines = capped.map((e) => {
    const parsed = Date.parse(e.ts);
    // G084: a malformed ts silently becomes "now", so the SIEM's own event ordering is wrong and nothing
    // anywhere says so. Count the substitution (a count; never the event, the ts or the actor).
    if (!Number.isFinite(parsed)) noteSiemShapingFallback("timestamp-substituted");
    const time = Number.isFinite(parsed) ? Math.floor(parsed / 1000) : Math.floor(Date.now() / 1000);
    return JSON.stringify({ time, source: "downpipes", sourcetype: "downpipe:audit", event: e });
  });
  return { body: lines.join("\n"), contentType: "application/json" };
}

// datadogStatus maps an audit outcome onto Datadog's log `status` attribute, the field Datadog's severity
// facet/monitors read (item 16, HARDENING.md): without it, Datadog defaults every log to "info",
// so a failed or denied audit event reads as a success in the severity facet. failed -> error (the
// strongest signal), denied -> warning, success/anything else -> info -- the SAME info/warning/error triad
// outcomeSeverity/gelfLevel/syslogSeverity already use, kept consistent across every format.
function datadogStatus(outcome: string): string {
  if (outcome === "failed") return "error";
  if (outcome === "denied") return "warning";
  return "info";
}

// shapeDatadog renders a JSON array of Datadog log objects: the audit event flattened alongside a
// human-readable message plus ddsource/service/status, batched under Datadog's cap. status rides BEFORE the
// `...e` spread; AuditEvent carries no field of that name, so the outcome-derived value is never shadowed.
export function shapeDatadog(events: AuditEvent[], _meta: PushCursorMeta): ShapedPush {
  const capped = capBatch(events);
  const body = JSON.stringify(
    capped.map((e) => ({
      ddsource: "downpipes",
      service: "downpipe-engine",
      message: `${e.action} ${e.outcome}`,
      status: datadogStatus(e.outcome),
      ...e,
    })),
  );
  return { body, contentType: "application/json" };
}

// shapeNdjson renders one RAW audit event object per line (JSON.stringify(event) joined by "\n"), the
// split-friendly default. Nearly every generic HTTP intake splits an application/x-ndjson body into N
// events. No wrapper, no cursor meta: the raw event (with its stable seq + hash the SIEM dedups on) is the
// line. JSON.stringify is structurally injection-safe (a crafted field value is escaped), so a value can
// never inject a newline that would split one event into two.
export function shapeNdjson(events: AuditEvent[], _meta: PushCursorMeta): ShapedPush {
  const capped = capBatch(events);
  const body = capped.map((e) => JSON.stringify(e)).join("\n");
  return { body, contentType: "application/x-ndjson" };
}

// shapeJsonArray renders a bare [event, event, ...] array of the raw audit events, for array-splitting
// intakes (Elastic, Panther). Content-type application/json.
export function shapeJsonArray(events: AuditEvent[], _meta: PushCursorMeta): ShapedPush {
  const capped = capBatch(events);
  return { body: JSON.stringify(capped), contentType: "application/json" };
}

// CEF_LEEF_VENDOR / CEF_LEEF_PRODUCT are the fixed Device Vendor / Device Product header fields (never
// operator input, so they cannot inject); the Device Version is the running ENGINE_VERSION.
const CEF_LEEF_VENDOR = "Maelstrom AI";
const CEF_LEEF_PRODUCT = "Downpipes";

// WireParts is the normalised, redaction-safe projection of an AuditEvent the CEF/LEEF/GELF shapers map
// onto their wire slots: the epoch-ms timestamp, the scalar actor/action/outcome fields, and the target
// decomposed into a kind plus an optional id/name (targetIdName). Every value here is already redaction-safe
// (an id, an email actor-key, a hash, an ip, a closed enum); the shapers escape/sanitise each one regardless.
interface WireParts {
  ms: number;
  actorEmail: string | null;
  actorSubject: string | null;
  actorMethod: string;
  sourceIp: string | null;
  action: string;
  outcome: string;
  targetKind: string;
  targetId?: string;
  targetName?: string;
  seq: number;
  prevHash: string;
  hash: string;
}

// targetIdName extracts a redaction-safe (id, name) from the closed AuditTarget union for the CEF cs4/cs5,
// the LEEF targetId/targetName, and the GELF _targetId/_targetName slots. It reads ONLY the union's own safe
// fields (a downpipe id/name, a run id, a role email actor-key, an opaque action/connection id), so it can
// never surface a secret; the switch is exhaustive, so a future target kind fails the type-check here and
// must be mapped deliberately rather than silently dropping its id.
function targetIdName(t: AuditTarget): { id?: string; name?: string } {
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
    // The armable kind is the id (a closed enum), the binding label the name. The armed instant is not
    // projected here: it rides the raw event, exactly like the posture-ack statement hash below.
    case "test-fault":
      return t.binding !== undefined ? { id: t.faultKind, name: t.binding } : { id: t.faultKind };
    case "posture-ack":
      // The posture chosen is a closed enum, redaction-safe as the id slot; the statement hash and
      // principal type ride the raw event, not this (id, name) projection.
      return { id: t.posture };
    case "custody-share":
      // The threshold-of-total is a redaction-safe count pair; never a share or address.
      return { id: `${t.m}of${t.n}` };
    case "attest-session":
      // The opaque session id is the redaction-safe id slot; the run/sample counts ride the raw event.
      return { id: t.sessionId };
    case "key-ceremony":
    case "access-policy":
      return {};
  }
}

// wireParts normalises one event. A malformed ts (should be impossible; the DO stamps a valid RFC-3339
// string) falls back to the current time rather than emitting a NaN timestamp.
function wireParts(e: AuditEvent): WireParts {
  const parsed = Date.parse(e.ts);
  // G084: the same silent timestamp substitution on the CEF/LEEF/GELF wire path.
  if (!Number.isFinite(parsed)) noteSiemShapingFallback("timestamp-substituted");
  const ms = Number.isFinite(parsed) ? parsed : Date.now();
  const tn = targetIdName(e.target);
  return {
    ms,
    actorEmail: e.actorEmail,
    actorSubject: e.actorSubject ?? null,
    actorMethod: e.actorMethod,
    sourceIp: e.sourceIp,
    action: e.action,
    outcome: e.outcome,
    targetKind: e.target.kind,
    ...(tn.id !== undefined ? { targetId: tn.id } : {}),
    ...(tn.name !== undefined ? { targetName: tn.name } : {}),
    seq: e.seq,
    prevHash: e.prevHash,
    hash: e.hash,
  };
}

// outcomeSeverity maps an audit outcome onto the CEF/LEEF integer severity (0-10): a success/info is low, a
// denied is mid, a failed is high. Kept deliberately simple and documented.
function outcomeSeverity(outcome: string): number {
  if (outcome === "failed") return 8;
  if (outcome === "denied") return 6;
  return 3;
}

// gelfLevel maps an audit outcome onto a GELF/syslog level: 6 info (success), 4 warning (denied), 3 error
// (failed).
function gelfLevel(outcome: string): number {
  if (outcome === "failed") return 3;
  if (outcome === "denied") return 4;
  return 6;
}

// humaniseAction renders a CEF `Name` phrase from the closed-enum action (replace the id separators with
// spaces, sentence-case). The action is a closed enum (never operator input), so it cannot inject; the CEF
// header escape still runs over the result.
function humaniseAction(action: string): string {
  const s = action.replace(/[-_.]/g, " ").trim();
  return s.length === 0 ? action : s.charAt(0).toUpperCase() + s.slice(1);
}

// trunc bounds a header/extension value to a CEF length cap (truncate-and-drop the tail; our real values are
// short, so this rarely bites, but a pathological id cannot blow a field's documented ceiling).
function trunc(s: string, n: number): string {
  if (s.length <= n) return s;
  // G084: a truncated field is invisible today -- and a truncated HASH field silently fails the customer's
  // own chain-verification script, which reads as "your audit log is tampered". Count it (a count only).
  noteSiemShapingFallback("field-truncated");
  return s.slice(0, n);
}

// cefEscapeHeader escapes a CEF HEADER field: backslash -> `\\` and pipe -> `\|` (the field delimiter). `=`
// needs no escaping in a header. Any raw control char (a record-boundary risk) collapses to a space, so a
// header field can never carry a newline. Applied to every header field uniformly.
// biome-ignore lint/suspicious/noControlCharactersInRegex: stripping raw C0 control characters is the deliberate CEF header injection guard (a newline in a header field must never start a new record).
const CEF_HEADER_CONTROLS = /[\x00-\x1f]/g;
function cefEscapeHeader(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(CEF_HEADER_CONTROLS, " ");
}

// cefEscapeExtValue escapes a CEF EXTENSION value (the k=v section): backslash -> `\\` FIRST (so the
// backslashes the later rules add are not re-escaped), then `=` -> `\=` (the key/value delimiter), then a
// CR/LF to the LITERAL two-char `\r` / `\n` (NEVER a raw control char: this is the injection guard that
// stops a value starting a new syslog record). Any other C0 control char collapses to a space. Pipes need no
// escaping in an extension value.
// biome-ignore lint/suspicious/noControlCharactersInRegex: escaping/stripping the C0 control characters is the deliberate CEF extension injection guard (a raw CR/LF in a value must never start a new record).
const CEF_EXT_RESIDUAL_CONTROLS = /[\x00-\x09\x0b\x0c\x0e-\x1f]/g;
function cefEscapeExtValue(s: string): string {
  return s
    .replace(/\\/g, "\\\\")
    .replace(/=/g, "\\=")
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n")
    .replace(CEF_EXT_RESIDUAL_CONTROLS, " ");
}

// leefSanitise is the LEEF injection guard: LEEF 2.0 has NO escape mechanism (confirmed in the IBM spec), so
// the shaper AVOIDS the dangerous characters entirely by replacing any active delimiter (`^`), key/value
// separator (`=`), header delimiter (`|`) or control char in a VALUE with `_`. A crafted value therefore
// cannot carry the delimiter, split a key=value pair, or inject a record boundary.
// biome-ignore lint/suspicious/noControlCharactersInRegex: replacing the C0 control characters is the deliberate LEEF injection guard (LEEF has no escape mechanism, so a raw CR/LF or delimiter in a value must be removed).
const LEEF_UNSAFE = /[\x00-\x1f=^|]/g;
function leefSanitise(s: string): string {
  return s.replace(LEEF_UNSAFE, "_");
}

// shapeCef renders one ArcSight CEF line per event. The 7 header fields are all
// mandatory: version 0, our vendor/product, the engine version, the audit action as BOTH the Device Event
// Class ID (a stable signature) and the extension `act`, a human Name phrase, and the outcome-derived
// severity. The extension maps the scalar fields to the CEF dictionary (src/suser/rt/act/outcome) and the
// non-standard fields to the labelled custom slots (cs1..cs6 + cn1 + flexString1). Lines join on "\n"; a
// value can never contain a raw "\n" (cefEscapeExtValue converts it), so the body splits to exactly one
// event per line.
export function shapeCef(events: AuditEvent[], _meta: PushCursorMeta): ShapedPush {
  const capped = capBatch(events);
  const lines = capped.map((e) => {
    const p = wireParts(e);
    const ext: string[] = [];
    const put = (k: string, v: string): void => {
      ext.push(`${k}=${cefEscapeExtValue(v)}`);
    };
    put("rt", String(p.ms));
    if (p.actorEmail !== null) put("suser", p.actorEmail);
    if (p.sourceIp !== null) put("src", p.sourceIp);
    put("act", p.action);
    put("outcome", p.outcome);
    if (p.actorSubject !== null) {
      put("cs1Label", "actorSubject");
      put("cs1", trunc(p.actorSubject, 4000));
    }
    put("cs2Label", "actorMethod");
    put("cs2", trunc(p.actorMethod, 4000));
    put("cs3Label", "targetKind");
    put("cs3", trunc(p.targetKind, 4000));
    if (p.targetId !== undefined) {
      put("cs4Label", "targetId");
      put("cs4", trunc(p.targetId, 4000));
    }
    if (p.targetName !== undefined) {
      put("cs5Label", "targetName");
      put("cs5", trunc(p.targetName, 4000));
    }
    put("cs6Label", "prevHash");
    put("cs6", trunc(p.prevHash, 4000));
    put("cn1Label", "seq");
    put("cn1", String(p.seq));
    put("flexString1Label", "hash");
    put("flexString1", trunc(p.hash, 1023));
    const header =
      `CEF:0|${cefEscapeHeader(trunc(CEF_LEEF_VENDOR, 63))}|${cefEscapeHeader(trunc(CEF_LEEF_PRODUCT, 63))}` +
      `|${cefEscapeHeader(trunc(ENGINE_VERSION, 31))}|${cefEscapeHeader(trunc(p.action, 1023))}` +
      `|${cefEscapeHeader(trunc(humaniseAction(p.action), 512))}|${outcomeSeverity(p.outcome)}|`;
    return header + ext.join(" ");
  });
  return { body: lines.join("\n"), contentType: "text/plain; charset=utf-8" };
}

// shapeLeef renders one IBM LEEF 2.0 line per event. The 6 header fields include
// the explicit delimiter field `^` (declared literally, then used to separate the attributes). EventID is
// the audit action. The reserved keys devTime/cat/sev/src/usrName carry the timestamp/category/severity/ip/
// user; the rest are plain (non-reserved) keys. Every value is leefSanitise-d (LEEF has no escaping), so a
// crafted value cannot carry the `^` delimiter, an `=`, or a record boundary. Lines join on "\n".
export function shapeLeef(events: AuditEvent[], _meta: PushCursorMeta): ShapedPush {
  const capped = capBatch(events);
  const lines = capped.map((e) => {
    const p = wireParts(e);
    const attrs: string[] = [];
    const put = (k: string, v: string): void => {
      attrs.push(`${k}=${leefSanitise(v)}`);
    };
    put("devTime", String(p.ms));
    put("cat", p.targetKind);
    put("sev", String(outcomeSeverity(p.outcome)));
    if (p.actorEmail !== null) put("usrName", p.actorEmail);
    if (p.sourceIp !== null) put("src", p.sourceIp);
    put("action", p.action);
    put("outcome", p.outcome);
    if (p.actorSubject !== null) put("authSubject", p.actorSubject);
    put("authMethod", p.actorMethod);
    put("targetKind", p.targetKind);
    if (p.targetId !== undefined) put("targetId", p.targetId);
    if (p.targetName !== undefined) put("targetName", p.targetName);
    put("seq", String(p.seq));
    put("prevHash", p.prevHash);
    put("eventHash", p.hash);
    // The header EventID is the audit action (a closed enum). leefSanitise defends it anyway; the vendor/
    // product/version are our own literals; the 6th field is the literal delimiter `^`.
    const header = `LEEF:2.0|${CEF_LEEF_VENDOR}|${CEF_LEEF_PRODUCT}|${ENGINE_VERSION}|${leefSanitise(p.action)}|^|`;
    return header + attrs.join("^");
  });
  return { body: lines.join("\n"), contentType: "text/plain; charset=utf-8" };
}

// shapeGelf renders one Graylog GELF (1.1) object per line, for the GELF HTTP input. version/host/
// short_message are mandatory; timestamp is epoch SECONDS (a float); every custom field is `_`-prefixed and
// FLAT (target.* is flattened to _targetKind/_targetId/_targetName, never a nested object). GELF is
// JSON-encoded, so it is structurally injection-safe (a crafted value is JSON-escaped); the reserved `_id`
// key is deliberately never emitted. NDJSON (one object per line) to the GELF HTTP input.
export function shapeGelf(events: AuditEvent[], _meta: PushCursorMeta): ShapedPush {
  const capped = capBatch(events);
  const lines = capped.map((e) => {
    const p = wireParts(e);
    const obj: Record<string, unknown> = {
      version: "1.1",
      host: "downpipes",
      short_message: `${p.action} ${p.outcome}`,
      timestamp: p.ms / 1000,
      level: gelfLevel(p.outcome),
      _seq: p.seq,
      _actorEmail: p.actorEmail,
      _actorSubject: p.actorSubject,
      _actorMethod: p.actorMethod,
      _sourceIp: p.sourceIp,
      _action: p.action,
      _outcome: p.outcome,
      _targetKind: p.targetKind,
      ...(p.targetId !== undefined ? { _targetId: p.targetId } : {}),
      ...(p.targetName !== undefined ? { _targetName: p.targetName } : {}),
      _prevHash: p.prevHash,
      _hash: p.hash,
    };
    return JSON.stringify(obj);
  });
  return { body: lines.join("\n"), contentType: "application/json" };
}

// shapeForFormat dispatches to the configured shaper. Exhaustive over PushFormat (the switch returns in every
// arm, so adding a PushFormat member without a matching shaper fails the type-check here), so an unrecognised
// value at the type level cannot silently fall back to the wrong envelope.
export function shapeForFormat(format: PushFormat, events: AuditEvent[], meta: PushCursorMeta): ShapedPush {
  switch (format) {
    case "raw-json":
      return shapeRawJson(events, meta);
    case "ndjson":
      return shapeNdjson(events, meta);
    case "json-array":
      return shapeJsonArray(events, meta);
    case "splunk-hec":
      return shapeSplunkHec(events, meta);
    case "datadog":
      return shapeDatadog(events, meta);
    case "cef":
      return shapeCef(events, meta);
    case "leef":
      return shapeLeef(events, meta);
    case "gelf":
      return shapeGelf(events, meta);
  }
}

// objectExtensionForFormat names the file extension an S3-drop object carries, derived from the WIRE SHAPE
// the matching shaper produces rather than from the format's name. It exists because the drop sink writes a
// file rather than a request body: an http receiver is told the shape by the Content-Type header, whereas a
// bucket consumer has only the key, and S3Destination.put (the archive client this path deliberately reuses)
// signs no Content-Type at all. An extension that named the wrong shape would be the same defect as a body
// that carried the wrong shape, one step further downstream.
//
// The mapping is deliberately many-to-one and the ambiguity is honest: raw-json, json-array and datadog are
// each ONE JSON document, so `.json` is true of all three; ndjson, splunk-hec and gelf are each newline-joined
// JSON objects, so `.ndjson` is true of all three. Nothing here claims an extension identifies WHICH format
// was chosen, only that it never misdescribes how to read the bytes. cef and leef are neither, and take their
// own names. Exhaustive over PushFormat, so a new format cannot inherit a stale extension by falling through.
export function objectExtensionForFormat(format: PushFormat): string {
  switch (format) {
    case "raw-json":
    case "json-array":
    case "datadog":
      return "json";
    case "ndjson":
    case "splunk-hec":
    case "gelf":
      return "ndjson";
    case "cef":
      return "cef";
    case "leef":
      return "leef";
  }
}

// buildSyntheticPushEvent is a single, clearly-synthetic AuditEvent for the test-send route (POST
// /admin/push/test): it proves the format/header/endpoint wiring end to end without reading a single real
// event off the chain. Its seq/prevHash/hash are placeholders (this object is never appended to, or
// verified against, the real chain); the detail string is deliberately unambiguous so a human scanning raw
// SIEM data never mistakes it for a real engine event.
//
// A PLACEHOLDER STILL HAS TO BE WELL FORMED: the hash placeholders must be the full 96 hex characters wide
// (a real SIEM receiver may check the digest shape even on an obviously-synthetic event), so
// GENESIS_PREV_HASH -- the audit chain's own zero placeholder, built from SHA384_HEX_LEN -- is reused here
// rather than a hand-typed literal, so the width is always derived, never typed.
export function buildSyntheticPushEvent(): AuditEvent {
  return {
    seq: 0,
    ts: new Date().toISOString(),
    actorSubject: null,
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "engine-secret-present",
    outcome: "success",
    target: { kind: "engine-state", field: "secret-present", detail: "downpipe-siem-push-test-event: this is a synthetic test event, not a real engine action" },
    prevHash: GENESIS_PREV_HASH,
    hash: GENESIS_PREV_HASH,
  };
}
