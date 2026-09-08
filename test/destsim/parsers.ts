// test/destsim/parsers.ts -- the SHARED strict wire-format parser library behind the destination-emulator
// suite (test/validate-destsim-formats.ts, test/validate-destsim-selftest.ts, test/destsim/server.ts).
//
// PURPOSE: existing tests stub globalThis.fetch with an always-happy response and only assert the outbound
// request SHAPE loosely (a field is present, a substring appears). That proves the engine CALLS fetch with
// something plausible; it does not prove the bytes on the wire actually conform to the vendor's documented
// format. Every parseX function here is the opposite of a rubber stamp: it parses EVERY byte of a shaped
// body against the wire contract src/cron/siem-push-shape.ts, src/notify/siem-syslog-sender.ts,
// src/cron/otlp-push-shape.ts, src/admin/metrics.ts and src/notify/channels/*.ts document, and THROWS a
// DestsimParseError describing exactly what deviated (an unknown field, a wrong type, a missing escape, a
// malformed frame) rather than silently accepting or best-effort-guessing. A parser that cannot reject a
// corrupted copy is not proof of anything; test/validate-destsim-formats.ts exercises both directions for
// every format: accept the REAL shaper output, reject a deliberately corrupted copy.
//
// SCOPE: the eleven audit/metrics wire formats the engine pushes to a SIEM/observability destination --
// CEF, LEEF, syslog RFC 5424 + RFC 6587 framing, Splunk HEC, Datadog, GELF, ndjson, json-array, raw-json,
// OTLP/HTTP JSON and Prometheus text exposition -- are parsed BYTE-STRICT, including reversing the CEF/LEEF
// escaping to recover the original field value losslessly (CEF) or asserting the documented sanitisation
// invariant holds (LEEF, which has no escape mechanism and is therefore lossy by design). A second,
// lighter-weight section covers the six notify-channel JSON payload shapes (webhook/slack/teams/pagerduty/
// servicenow/jsm): these are plain JSON (JSON.parse already gives structural safety), so "strict" there
// means exact key-set + enum + cap validation rather than hand-rolled escape reversal.
//
// Pure and dependency-free: no I/O, no npm package, every function a straight synchronous transform of the
// bytes handed to it (or a throw). The only external imports are READ-ONLY references into src/ for the
// closed vocabularies a real parser must hold in lock-step with the engine (AUDIT_ACTIONS, the 9 OTLP metric
// names) so this library cannot silently drift from what the shapers actually emit.
//
// Every parseX(raw, opts?) accepts opts.contentType: when supplied, it is asserted to EXACTLY equal the
// format's documented content-type (a wrong content-type passed in is a rejection, matching a real intake
// that inspects Content-Type before parsing).

import { AUDIT_ACTIONS, type AuditEvent, type AuditTarget, SHA384_HEX_LEN } from "../../src/admin/audit-types.ts";
import {
  OTLP_METRIC_LAST_SUCCESS,
  OTLP_METRIC_SUCCESS,
  OTLP_METRIC_RECENT_ATTEMPTS,
  OTLP_METRIC_RECENT_SUCCESSES,
  OTLP_METRIC_RECENT_FAILURES,
  OTLP_METRIC_DURATION,
  OTLP_METRIC_SIZE_BYTES,
  OTLP_METRIC_DEST_HEALTHY,
  OTLP_METRIC_ENABLED,
} from "../../src/cron/otlp-push-shape.ts";

// ============================================================================================================
// Shared primitives
// ============================================================================================================

/** Thrown by every parseX on ANY deviation from the documented wire contract. Always carries a descriptive,
 * human-readable message naming exactly what was expected and what was found. */
export class DestsimParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DestsimParseError";
  }
}

function fail(message: string): never {
  throw new DestsimParseError(message);
}

function toText(raw: string | Buffer): string {
  return typeof raw === "string" ? raw : raw.toString("utf8");
}

function toBuffer(raw: string | Buffer): Buffer {
  return typeof raw === "string" ? Buffer.from(raw, "utf8") : raw;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function assertContentType(opts: { contentType?: string } | undefined, expected: string, label: string): void {
  if (opts?.contentType !== undefined && opts.contentType !== expected) {
    fail(`${label}: wrong content-type, expected ${JSON.stringify(expected)}, got ${JSON.stringify(opts.contentType)}`);
  }
}

function assertObjectKeys(obj: Record<string, unknown>, required: readonly string[], optional: readonly string[], where: string): void {
  const allowed = new Set<string>([...required, ...optional]);
  for (const k of Object.keys(obj)) if (!allowed.has(k)) fail(`${where}: unexpected key ${JSON.stringify(k)}`);
  for (const k of required) if (!(k in obj)) fail(`${where}: missing required key ${JSON.stringify(k)}`);
}

function str(obj: Record<string, unknown>, key: string, where: string): string {
  const v = obj[key];
  if (typeof v !== "string") fail(`${where}: "${key}" must be a string, got ${JSON.stringify(v)}`);
  return v;
}
function strOrNull(obj: Record<string, unknown>, key: string, where: string): string | null {
  const v = obj[key];
  if (v === null) return null;
  if (typeof v !== "string") fail(`${where}: "${key}" must be a string or null, got ${JSON.stringify(v)}`);
  return v;
}
function num(obj: Record<string, unknown>, key: string, where: string): number {
  const v = obj[key];
  if (typeof v !== "number" || !Number.isFinite(v)) fail(`${where}: "${key}" must be a finite number, got ${JSON.stringify(v)}`);
  return v;
}
function bool(obj: Record<string, unknown>, key: string, where: string): boolean {
  const v = obj[key];
  if (typeof v !== "boolean") fail(`${where}: "${key}" must be a boolean, got ${JSON.stringify(v)}`);
  return v;
}

function parseJsonObject(text: string, label: string): Record<string, unknown> {
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch (e) {
    fail(`${label}: invalid JSON (${(e as Error).message})`);
  }
  if (!isPlainObject(obj)) fail(`${label}: top-level value must be a JSON object`);
  return obj;
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: detecting a raw C0 control byte on the wire is the entire point of this strict-parser check.
const RAW_CONTROL_RE = /[\x00-\x1f]/;
function assertNoRawControlChars(s: string, where: string): void {
  const m = RAW_CONTROL_RE.exec(s);
  if (m) fail(`${where}: raw control character 0x${m[0]!.charCodeAt(0).toString(16).padStart(2, "0")} found on the wire (must be escaped or stripped, never raw)`);
}

/** assertKnownSubsequence asserts every element of `order` is a member of `canonical` AND appears in the
 * same relative order as `canonical` (never out of order), the shared "documented key set/order" check CEF
 * and LEEF both need. */
function assertKnownSubsequence(order: string[], canonical: string[], where: string): void {
  let ci = 0;
  for (const key of order) {
    const idx = canonical.indexOf(key, ci);
    if (idx === -1) {
      if (!canonical.includes(key)) fail(`${where}: unknown key ${JSON.stringify(key)} (not in the documented set)`);
      fail(`${where}: key ${JSON.stringify(key)} appears out of the documented order`);
    }
    ci = idx + 1;
  }
}

// The accepting shape for the audit chain's prevHash/hash on the wire. The width is DERIVED from
// SHA384_HEX_LEN, the same constant the producer's placeholder is built from, so the emulator and the
// product cannot disagree about it: a hard-coded width could otherwise mismatch the placeholder length
// and reject a payload a real destination would accept.
const HASH_RE = new RegExp(`^sha384:[0-9a-f]{${SHA384_HEX_LEN}}$`);

/** The flattened wire projection CEF/LEEF/GELF all encode (src/cron/siem-push-shape.ts's WireParts),
 * decoded/exposed by parseCef/parseLeef/parseGelf. */
export interface ParsedWireEvent {
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
  severity: number;
}

// ============================================================================================================
// CEF (ArcSight Common Event Format)
// ============================================================================================================

const CEF_VENDOR = "Maelstrom AI";
const CEF_PRODUCT = "Downpipes";
const CEF_EXTENSION_ORDER = ["rt", "suser", "src", "act", "outcome", "cs1Label", "cs1", "cs2Label", "cs2", "cs3Label", "cs3", "cs4Label", "cs4", "cs5Label", "cs5", "cs6Label", "cs6", "cn1Label", "cn1", "flexString1Label", "flexString1"];

export interface ParsedCefEvent extends ParsedWireEvent {
  deviceVendor: string;
  deviceProduct: string;
  deviceVersion: string;
  deviceEventClassId: string;
  name: string;
}

type CefHeaderFields = [string, string, string, string, string, string, string];

/** splitCefHeaderAndExtension finds the FIRST 7 unescaped "|" delimiters (the mandatory CEF header fields)
 * and returns everything after the 7th verbatim as the extension -- deliberately NOT splitting the whole
 * line on "|", since an extension VALUE may legitimately carry an unescaped pipe (cefEscapeExtValue never
 * escapes "|", only header fields do). Escape-aware (a "\|" inside a header field is not a delimiter). */
function splitCefHeaderAndExtension(line: string): { fields: CefHeaderFields; extension: string } {
  const fields: string[] = [];
  let cur = "";
  let escaped = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (escaped) {
      cur += c;
      escaped = false;
      continue;
    }
    if (c === "\\") {
      escaped = true;
      cur += c;
      continue;
    }
    if (c === "|") {
      fields.push(cur);
      cur = "";
      if (fields.length === 7) return { fields: fields as CefHeaderFields, extension: line.slice(i + 1) };
      continue;
    }
    cur += c;
  }
  fail(`CEF header: expected 7 pipe-delimited header fields followed by an extension, found only ${fields.length} unescaped "|" delimiters before the line ended`);
}

/** decodeCefHeaderField reverses cefEscapeHeader: "\\"->"\\", "\|"->"|"; a raw control byte must never
 * appear (the shaper always maps a residual control char to a space at encode time). */
function decodeCefHeaderField(rawField: string, where: string): string {
  let out = "";
  let i = 0;
  while (i < rawField.length) {
    const c = rawField[i]!;
    if (c === "\\") {
      const n = rawField[i + 1];
      if (n === "\\") {
        out += "\\";
        i += 2;
        continue;
      }
      if (n === "|") {
        out += "|";
        i += 2;
        continue;
      }
      fail(`${where}: invalid CEF header escape sequence "\\${n ?? ""}"`);
    }
    out += c;
    i++;
  }
  return out;
}

/** decodeCefExtValue reverses cefEscapeExtValue: "\\"->"\\" (checked first), "\="->"=", "\r"->CR, "\n"->LF.
 * Lossless for every character cefEscapeExtValue treats reversibly; any OTHER control byte the shaper
 * collapsed to a literal space at encode time stays a space here (that step is deliberately lossy by
 * design, so there is nothing to reverse). */
function decodeCefExtValue(rawValue: string, where: string): string {
  let out = "";
  let i = 0;
  while (i < rawValue.length) {
    const c = rawValue[i]!;
    if (c === "\\") {
      const n = rawValue[i + 1];
      if (n === "\\") {
        out += "\\";
        i += 2;
        continue;
      }
      if (n === "=") {
        out += "=";
        i += 2;
        continue;
      }
      if (n === "r") {
        out += "\r";
        i += 2;
        continue;
      }
      if (n === "n") {
        out += "\n";
        i += 2;
        continue;
      }
      fail(`${where}: invalid CEF extension escape sequence "\\${n ?? ""}"`);
    }
    out += c;
    i++;
  }
  return out;
}

interface CefKv {
  key: string;
  rawValue: string;
}

/** tokenizeCefExtension finds every UNESCAPED "=" (cefEscapeExtValue guarantees a value can never contain a
 * raw "="), so every unescaped "=" found IS a genuine key/value delimiter -- no dictionary lookahead or
 * ambiguity is needed. Each key is the run of key-chars immediately before its "="; each value runs to the
 * single separating space before the next key (or end of string for the last pair). */
function tokenizeCefExtension(ext: string): CefKv[] {
  const eqPositions: number[] = [];
  let escaped = false;
  for (let i = 0; i < ext.length; i++) {
    const c = ext[i]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (c === "\\") {
      escaped = true;
      continue;
    }
    if (c === "=") eqPositions.push(i);
  }
  if (escaped) fail("CEF extension: trailing unescaped backslash");
  if (eqPositions.length === 0) fail('CEF extension: no key=value pairs found (no unescaped "=")');

  const keyStarts = eqPositions.map((eq) => {
    let ks = eq;
    while (ks > 0 && ext[ks - 1] !== " ") ks--;
    return ks;
  });
  keyStarts.forEach((keyStart, idx) => {
    const eq = eqPositions[idx]!;
    const key = ext.slice(keyStart, eq);
    if (!/^[A-Za-z][A-Za-z0-9]*$/.test(key)) fail(`CEF extension: malformed key ${JSON.stringify(key)} immediately before "="`);
    if (idx === 0 && keyStart !== 0) fail(`CEF extension: unexpected leading content ${JSON.stringify(ext.slice(0, keyStart))} before the first key`);
    if (idx > 0 && keyStart === 0) fail(`CEF extension: key ${JSON.stringify(key)} is missing its separating space from the previous value`);
  });

  return keyStarts.map((keyStart, idx) => {
    const eq = eqPositions[idx]!;
    const key = ext.slice(keyStart, eq);
    const nextKeyStart = idx + 1 < keyStarts.length ? keyStarts[idx + 1]! : undefined;
    const valueEnd = nextKeyStart === undefined ? ext.length : nextKeyStart - 1;
    if (nextKeyStart !== undefined && ext[nextKeyStart - 1] !== " ") fail(`CEF extension: expected a single separating space before the next key at position ${nextKeyStart}`);
    if (valueEnd < eq + 1) fail(`CEF extension: empty or negative-length value span for key ${JSON.stringify(key)}`);
    return { key, rawValue: ext.slice(eq + 1, valueEnd) };
  });
}

function parseCefLine(line: string, idx: number): ParsedCefEvent {
  const where = `CEF line ${idx}`;
  assertNoRawControlChars(line, where);
  if (!line.startsWith("CEF:0|")) fail(`${where}: does not start with the mandatory "CEF:0|" prefix`);
  const { fields, extension } = splitCefHeaderAndExtension(line);
  const [cefVersion, vendorRaw, productRaw, versionRaw, classIdRaw, nameRaw, severityRaw] = fields;
  if (cefVersion !== "CEF:0") fail(`${where}: expected header field 0 to be "CEF:0", got ${JSON.stringify(cefVersion)}`);
  const deviceVendor = decodeCefHeaderField(vendorRaw, `${where} vendor`);
  const deviceProduct = decodeCefHeaderField(productRaw, `${where} product`);
  const deviceVersion = decodeCefHeaderField(versionRaw, `${where} device version`);
  const deviceEventClassId = decodeCefHeaderField(classIdRaw, `${where} device event class id`);
  const name = decodeCefHeaderField(nameRaw, `${where} name`);
  if (deviceVendor !== CEF_VENDOR) fail(`${where}: Device Vendor must be ${JSON.stringify(CEF_VENDOR)}, got ${JSON.stringify(deviceVendor)}`);
  if (deviceProduct !== CEF_PRODUCT) fail(`${where}: Device Product must be ${JSON.stringify(CEF_PRODUCT)}, got ${JSON.stringify(deviceProduct)}`);
  const severity = Number(severityRaw);
  if (!Number.isInteger(severity) || severity < 0 || severity > 10) fail(`${where}: Severity must be an integer 0-10, got ${JSON.stringify(severityRaw)}`);

  const pairs = tokenizeCefExtension(extension);
  const seen = new Map<string, string>();
  for (const { key, rawValue } of pairs) {
    if (seen.has(key)) fail(`${where}: duplicate extension key ${JSON.stringify(key)}`);
    seen.set(key, decodeCefExtValue(rawValue, `${where} extension key ${key}`));
  }
  assertKnownSubsequence([...seen.keys()], CEF_EXTENSION_ORDER, `${where} extension key order`);

  const need = (k: string): string => {
    const v = seen.get(k);
    if (v === undefined) fail(`${where}: missing mandatory extension key "${k}"`);
    return v;
  };
  const optLabel = (labelKey: string, valueKey: string, expectedLabel: string): string | undefined => {
    const hasLabel = seen.has(labelKey);
    const hasValue = seen.has(valueKey);
    if (hasLabel !== hasValue) fail(`${where}: "${labelKey}" and "${valueKey}" must appear together`);
    if (!hasLabel) return undefined;
    const label = seen.get(labelKey)!;
    if (label !== expectedLabel) fail(`${where}: "${labelKey}" must be ${JSON.stringify(expectedLabel)}, got ${JSON.stringify(label)}`);
    return seen.get(valueKey)!;
  };

  const rt = need("rt");
  const ms = Number(rt);
  if (!Number.isFinite(ms)) fail(`${where}: rt (timestamp) is not numeric: ${JSON.stringify(rt)}`);
  const actorEmail = seen.get("suser") ?? null;
  const sourceIp = seen.get("src") ?? null;
  const action = need("act");
  const outcome = need("outcome");
  const actorSubject = optLabel("cs1Label", "cs1", "actorSubject") ?? null;
  const actorMethod = optLabel("cs2Label", "cs2", "actorMethod");
  if (actorMethod === undefined) fail(`${where}: missing mandatory cs2Label/cs2 (actorMethod)`);
  const targetKind = optLabel("cs3Label", "cs3", "targetKind");
  if (targetKind === undefined) fail(`${where}: missing mandatory cs3Label/cs3 (targetKind)`);
  const targetId = optLabel("cs4Label", "cs4", "targetId");
  const targetName = optLabel("cs5Label", "cs5", "targetName");
  const prevHash = optLabel("cs6Label", "cs6", "prevHash");
  if (prevHash === undefined) fail(`${where}: missing mandatory cs6Label/cs6 (prevHash)`);
  const cn1 = optLabel("cn1Label", "cn1", "seq");
  if (cn1 === undefined) fail(`${where}: missing mandatory cn1Label/cn1 (seq)`);
  const seq = Number(cn1);
  if (!Number.isInteger(seq)) fail(`${where}: seq (cn1) is not an integer: ${JSON.stringify(cn1)}`);
  const hash = optLabel("flexString1Label", "flexString1", "hash");
  if (hash === undefined) fail(`${where}: missing mandatory flexString1Label/flexString1 (hash)`);
  if (deviceEventClassId !== action) fail(`${where}: Device Event Class ID (${JSON.stringify(deviceEventClassId)}) must equal act (${JSON.stringify(action)})`);
  if (!HASH_RE.test(prevHash)) fail(`${where}: cs6 (prevHash) is not a valid sha384: hash: ${JSON.stringify(prevHash)}`);
  if (!HASH_RE.test(hash)) fail(`${where}: flexString1 (hash) is not a valid sha384: hash: ${JSON.stringify(hash)}`);

  return {
    deviceVendor,
    deviceProduct,
    deviceVersion,
    deviceEventClassId,
    name,
    ms,
    actorEmail,
    actorSubject,
    actorMethod,
    sourceIp,
    action,
    outcome,
    targetKind,
    ...(targetId !== undefined ? { targetId } : {}),
    ...(targetName !== undefined ? { targetName } : {}),
    seq,
    prevHash,
    hash,
    severity,
  };
}

/** parseCef parses one-or-more "\n"-joined ArcSight CEF lines (shapeCef's exact output shape). Throws on
 * any deviation: a missing/malformed header field, an unknown vendor/product, an out-of-range severity, an
 * unknown/duplicate/out-of-order extension key, a broken escape sequence, or a raw control byte. */
export function parseCef(raw: string | Buffer, opts?: { contentType?: string }): { events: ParsedCefEvent[] } {
  assertContentType(opts, "text/plain; charset=utf-8", "CEF");
  const text = toText(raw);
  if (text.length === 0) fail("CEF: empty input");
  const events = text.split("\n").map((line, idx) => parseCefLine(line, idx));
  return { events };
}

// ============================================================================================================
// LEEF (IBM Log Event Extended Format) 2.0
// ============================================================================================================

const LEEF_ATTR_ORDER = ["devTime", "cat", "sev", "usrName", "src", "action", "outcome", "authSubject", "authMethod", "targetKind", "targetId", "targetName", "seq", "prevHash", "eventHash"];
const LEEF_UNSAFE_RE = /[\x00-\x1f=^|]/;

export interface ParsedLeefEvent extends ParsedWireEvent {
  deviceVendor: string;
  deviceProduct: string;
  deviceVersion: string;
  eventId: string;
}

function parseLeefLine(line: string, idx: number): ParsedLeefEvent {
  const where = `LEEF line ${idx}`;
  assertNoRawControlChars(line, where);
  // leefSanitise strips |, ^, = and every control byte from EVERY value (header EventID included), so a
  // plain split on "|" (no escape-awareness needed, unlike CEF) is safe and exhaustive: any surviving "|"
  // beyond the fixed 6 header delimiters means sanitisation failed somewhere upstream.
  const parts = line.split("|");
  if (parts.length !== 7) fail(`${where}: expected exactly 7 "|"-delimited header fields, found ${parts.length} (an un-sanitised "|" likely leaked into a value)`);
  const [versionTag, deviceVendor, deviceProduct, deviceVersion, eventId, delim, attrsBlob] = parts as [string, string, string, string, string, string, string];
  if (versionTag !== "LEEF:2.0") fail(`${where}: expected header field 0 to be "LEEF:2.0", got ${JSON.stringify(versionTag)}`);
  if (deviceVendor !== CEF_VENDOR) fail(`${where}: Vendor must be ${JSON.stringify(CEF_VENDOR)}, got ${JSON.stringify(deviceVendor)}`);
  if (deviceProduct !== CEF_PRODUCT) fail(`${where}: Product must be ${JSON.stringify(CEF_PRODUCT)}, got ${JSON.stringify(deviceProduct)}`);
  if (delim !== "^") fail(`${where}: the 6th header field must be the literal delimiter "^", got ${JSON.stringify(delim)}`);

  const tokens = attrsBlob.length === 0 ? [] : attrsBlob.split("^");
  const seen = new Map<string, string>();
  for (const tok of tokens) {
    const eq = tok.indexOf("=");
    if (eq === -1) fail(`${where}: attribute token ${JSON.stringify(tok)} has no "="`);
    if (tok.indexOf("=", eq + 1) !== -1) fail(`${where}: attribute token ${JSON.stringify(tok)} has more than one "=" (leefSanitise should have stripped it from the value)`);
    const key = tok.slice(0, eq);
    const value = tok.slice(eq + 1);
    if (!/^[A-Za-z][A-Za-z0-9]*$/.test(key)) fail(`${where}: malformed attribute key ${JSON.stringify(key)}`);
    if (seen.has(key)) fail(`${where}: duplicate attribute key ${JSON.stringify(key)}`);
    if (LEEF_UNSAFE_RE.test(value)) fail(`${where}: attribute "${key}" carries an un-sanitised character (leefSanitise must strip [\\x00-\\x1f=^|]); got ${JSON.stringify(value)}`);
    seen.set(key, value);
  }
  assertKnownSubsequence([...seen.keys()], LEEF_ATTR_ORDER, `${where} attribute order`);

  const need = (k: string): string => {
    const v = seen.get(k);
    if (v === undefined) fail(`${where}: missing mandatory attribute "${k}"`);
    return v;
  };
  const devTime = need("devTime");
  const ms = Number(devTime);
  if (!Number.isFinite(ms)) fail(`${where}: devTime is not numeric: ${JSON.stringify(devTime)}`);
  const cat = need("cat");
  const sev = need("sev");
  const severity = Number(sev);
  if (!Number.isInteger(severity) || severity < 0 || severity > 10) fail(`${where}: sev must be an integer 0-10, got ${JSON.stringify(sev)}`);
  const actorEmail = seen.get("usrName") ?? null;
  const sourceIp = seen.get("src") ?? null;
  const action = need("action");
  const outcome = need("outcome");
  const actorSubject = seen.get("authSubject") ?? null;
  const actorMethod = need("authMethod");
  const targetKind = need("targetKind");
  if (targetKind !== cat) fail(`${where}: "cat" (${JSON.stringify(cat)}) and "targetKind" (${JSON.stringify(targetKind)}) must match`);
  const targetId = seen.get("targetId");
  const targetName = seen.get("targetName");
  const seqStr = need("seq");
  const seq = Number(seqStr);
  if (!Number.isInteger(seq)) fail(`${where}: seq is not an integer: ${JSON.stringify(seqStr)}`);
  const prevHash = need("prevHash");
  const hash = need("eventHash");
  if (eventId !== action) fail(`${where}: header EventID (${JSON.stringify(eventId)}) must equal the "action" attribute (${JSON.stringify(action)})`);
  if (!HASH_RE.test(prevHash)) fail(`${where}: prevHash is not a valid sha384: hash: ${JSON.stringify(prevHash)}`);
  if (!HASH_RE.test(hash)) fail(`${where}: eventHash is not a valid sha384: hash: ${JSON.stringify(hash)}`);

  return {
    deviceVendor,
    deviceProduct,
    deviceVersion,
    eventId,
    ms,
    actorEmail,
    actorSubject,
    actorMethod,
    sourceIp,
    action,
    outcome,
    targetKind,
    ...(targetId !== undefined ? { targetId } : {}),
    ...(targetName !== undefined ? { targetName } : {}),
    seq,
    prevHash,
    hash,
    severity,
  };
}

/** parseLeef parses one-or-more "\n"-joined IBM LEEF 2.0 lines (shapeLeef's exact output shape). Because
 * LEEF has NO escape mechanism (values are SANITISED, not escaped), decoding is lossy by design for any
 * [\x00-\x1f=^|] byte in the original value; this parser exposes the sanitised value as-is and separately
 * asserts the sanitisation invariant holds (no such byte survives), rather than attempting to "recover" a
 * value LEEF's own wire format cannot carry. */
export function parseLeef(raw: string | Buffer, opts?: { contentType?: string }): { events: ParsedLeefEvent[] } {
  assertContentType(opts, "text/plain; charset=utf-8", "LEEF");
  const text = toText(raw);
  if (text.length === 0) fail("LEEF: empty input");
  const events = text.split("\n").map((line, idx) => parseLeefLine(line, idx));
  return { events };
}

// ============================================================================================================
// syslog RFC 5424 (record shape) + RFC 6587 (octet-counting framing over TCP/TLS)
// ============================================================================================================

export interface ParsedSyslogFrame {
  byteLength: number;
  pri: number;
  facility: number;
  severity: number;
  timestamp: string;
  host: string;
  appName: string;
  procId: string;
  msgId: string;
  structuredData: string;
  msg: string;
  format: "cef" | "leef";
  decoded: ParsedCefEvent | ParsedLeefEvent;
}

const RFC5424_RE = /^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (\S+) ([\s\S]+)$/;

function parseOneSyslogRecord(record: string, byteLength: number, idx: number, opts?: { format?: "cef" | "leef" }): ParsedSyslogFrame {
  const where = `syslog record ${idx}`;
  if (/[\r\n]/.test(record)) fail(`${where}: contains a raw CR/LF (must never appear inside a single octet-counted record)`);
  const m = RFC5424_RE.exec(record);
  if (!m) fail(`${where}: does not match the RFC 5424 "<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG" shape: ${JSON.stringify(record.slice(0, 160))}`);
  const [, priStr, timestamp, host, appName, procId, msgId, structuredData, msg] = m as unknown as [string, string, string, string, string, string, string, string, string];
  const pri = Number(priStr);
  if (!Number.isInteger(pri) || pri < 0 || pri > 191) fail(`${where}: PRI ${priStr} out of the valid 0-191 range`);
  const facility = Math.floor(pri / 8);
  const severity = pri % 8;
  if (facility !== 13) fail(`${where}: expected facility 13 (log audit), got ${facility}`);
  if (host !== "downpipes") fail(`${where}: unexpected HOSTNAME ${JSON.stringify(host)}`);
  if (appName !== "downpipe-engine") fail(`${where}: unexpected APP-NAME ${JSON.stringify(appName)}`);
  if (procId !== "-") fail(`${where}: unexpected PROCID ${JSON.stringify(procId)} (expected NILVALUE "-")`);
  if (msgId !== "audit") fail(`${where}: unexpected MSGID ${JSON.stringify(msgId)}`);
  if (structuredData !== "-") fail(`${where}: unexpected STRUCTURED-DATA ${JSON.stringify(structuredData)} (expected NILVALUE "-")`);
  if (!Number.isFinite(Date.parse(timestamp))) fail(`${where}: TIMESTAMP ${JSON.stringify(timestamp)} is not a valid RFC 3339 timestamp`);
  const format: "cef" | "leef" = opts?.format ?? (msg.startsWith("LEEF:") ? "leef" : "cef");
  const decoded = format === "leef" ? parseLeef(msg).events[0] : parseCef(msg).events[0];
  if (decoded === undefined) fail(`${where}: the MSG did not decode to exactly one ${format.toUpperCase()} event`);
  return { byteLength, pri, facility, severity, timestamp, host, appName, procId, msgId, structuredData, msg, format, decoded };
}

/** parseSyslogFrames parses an RFC 6587 octet-counted byte stream (`<len> <record>` repeated with no
 * separator; len is the record's UTF-8 BYTE length, per frameBatch in siem-syslog-sender.ts), asserts each
 * declared length matches the record's actual UTF-8 byte length exactly, parses the RFC 5424 envelope,
 * recomputes PRI = facility*8 + severity, and hands the trailing CEF/LEEF line to parseCef/parseLeef. */
export function parseSyslogFrames(raw: string | Buffer, opts?: { format?: "cef" | "leef" }): { events: ParsedSyslogFrame[] } {
  const bytes = toBuffer(raw);
  const frames: ParsedSyslogFrame[] = [];
  let i = 0;
  let idx = 0;
  while (i < bytes.length) {
    let j = i;
    while (j < bytes.length && bytes[j] !== 0x20) {
      const b = bytes[j]!;
      if (b < 0x30 || b > 0x39) fail(`syslog framing: non-digit byte 0x${b.toString(16)} in the octet-count length prefix starting at offset ${i}`);
      j++;
    }
    if (j >= bytes.length) fail(`syslog framing: no space found after the length prefix starting at offset ${i} (framing desynchronised or truncated)`);
    if (j === i) fail(`syslog framing: empty length prefix at offset ${i}`);
    const lenStr = bytes.subarray(i, j).toString("ascii");
    const len = Number(lenStr);
    if (!Number.isInteger(len) || len < 0) fail(`syslog framing: invalid length prefix "${lenStr}" at offset ${i}`);
    const start = j + 1;
    const end = start + len;
    if (end > bytes.length) fail(`syslog framing: declared length ${len} at offset ${i} overruns the remaining buffer (have ${bytes.length - start} bytes left)`);
    const recordBytes = bytes.subarray(start, end);
    const record = recordBytes.toString("utf8");
    const actualByteLen = Buffer.byteLength(record, "utf8");
    if (actualByteLen !== len) fail(`syslog framing: declared length ${len} at offset ${i} does not match the record's actual UTF-8 byte length ${actualByteLen}`);
    frames.push(parseOneSyslogRecord(record, len, idx, opts));
    i = end;
    idx++;
  }
  if (frames.length === 0) fail("syslog framing: no frames found (empty input)");
  return { events: frames };
}

// ============================================================================================================
// Audit event structural validator (shared by ndjson / json-array / raw-json / splunk-hec / datadog)
// ============================================================================================================

const AUDIT_ACTION_SET: ReadonlySet<string> = new Set(AUDIT_ACTIONS);
const AUTH_METHODS: ReadonlySet<string> = new Set(["access", "passkey", "oidc", "saml", "token", "recovery", "engine"]);
const OUTCOMES: ReadonlySet<string> = new Set(["success", "denied", "failed"]);
const ROLES: ReadonlySet<string> = new Set(["viewer", "operator", "restore-operator", "approver", "access-admin", "owner"]);

function assertAuditTarget(v: unknown, where: string): AuditTarget {
  if (!isPlainObject(v)) fail(`${where}: target must be an object`);
  const kind = v.kind;
  if (typeof kind !== "string") fail(`${where}: target.kind must be a string`);
  const w = `${where}.target(${kind})`;
  switch (kind) {
    case "downpipe": {
      assertObjectKeys(v, ["kind", "id"], ["name"], w);
      str(v, "id", w);
      if (v.name !== undefined) str(v, "name", w);
      return v as AuditTarget;
    }
    case "run": {
      assertObjectKeys(v, ["kind", "runId"], [], w);
      str(v, "runId", w);
      return v as AuditTarget;
    }
    case "restore": {
      assertObjectKeys(v, ["kind", "runId", "redirectBinding", "planHash", "isLatest"], ["reason", "approverEmail", "approverSubject", "destinationId"], w);
      str(v, "runId", w);
      strOrNull(v, "redirectBinding", w);
      str(v, "planHash", w);
      bool(v, "isLatest", w);
      if (v.reason !== undefined) str(v, "reason", w);
      if (v.approverEmail !== undefined) str(v, "approverEmail", w);
      if (v.approverSubject !== undefined) str(v, "approverSubject", w);
      if (v.destinationId !== undefined) str(v, "destinationId", w);
      return v as AuditTarget;
    }
    case "restore-receipt": {
      assertObjectKeys(v, ["kind", "runId", "receiptSha384", "recordsRestored", "allVerified"], ["complete", "recordsVerified", "failures", "outOfWindow", "readbackVerified", "readbackMismatched", "d1Total", "d1Verified"], w);
      str(v, "runId", w);
      str(v, "receiptSha384", w);
      num(v, "recordsRestored", w);
      bool(v, "allVerified", w);
      if (v.complete !== undefined) bool(v, "complete", w);
      for (const k of ["recordsVerified", "failures", "outOfWindow", "readbackVerified", "readbackMismatched", "d1Total", "d1Verified"] as const) {
        if (v[k] !== undefined) num(v, k, w);
      }
      return v as AuditTarget;
    }
    case "role": {
      assertObjectKeys(v, ["kind", "email", "role"], [], w);
      str(v, "email", w);
      const role = str(v, "role", w);
      if (!ROLES.has(role)) fail(`${w}: unknown role ${JSON.stringify(role)}`);
      return v as AuditTarget;
    }
    case "grouprole": {
      assertObjectKeys(v, ["kind", "group", "role"], [], w);
      str(v, "group", w);
      const role = str(v, "role", w);
      if (!ROLES.has(role)) fail(`${w}: unknown role ${JSON.stringify(role)}`);
      return v as AuditTarget;
    }
    case "customrole": {
      assertObjectKeys(v, ["kind", "name", "capabilityCount"], [], w);
      str(v, "name", w);
      num(v, "capabilityCount", w);
      return v as AuditTarget;
    }
    case "configchange": {
      assertObjectKeys(v, ["kind", "id", "changeKind"], ["approverEmail"], w);
      str(v, "id", w);
      str(v, "changeKind", w);
      if (v.approverEmail !== undefined) str(v, "approverEmail", w);
      return v as AuditTarget;
    }
    case "owneraction": {
      assertObjectKeys(v, ["kind", "id", "actionKind"], ["approverEmail"], w);
      str(v, "id", w);
      str(v, "actionKind", w);
      if (v.approverEmail !== undefined) str(v, "approverEmail", w);
      return v as AuditTarget;
    }
    case "change": {
      assertObjectKeys(v, ["kind", "actionKind", "emergency", "changeNumber", "reason"], [], w);
      str(v, "actionKind", w);
      bool(v, "emergency", w);
      strOrNull(v, "changeNumber", w);
      strOrNull(v, "reason", w);
      return v as AuditTarget;
    }
    case "key-ceremony":
    case "access-policy": {
      assertObjectKeys(v, ["kind"], [], w);
      return v as AuditTarget;
    }
    case "posture-check": {
      assertObjectKeys(v, ["kind", "checkId", "overrideKind"], [], w);
      str(v, "checkId", w);
      strOrNull(v, "overrideKind", w);
      return v as AuditTarget;
    }
    case "dest-change": {
      assertObjectKeys(v, ["kind", "op"], ["id", "fromDefaultId", "toDefaultId", "force", "uncoveredOriginRunCount", "rejectReason"], w);
      const op = str(v, "op", w);
      if (!["set", "clear", "default", "remove"].includes(op)) fail(`${w}: unknown op ${JSON.stringify(op)}`);
      if (v.id !== undefined) str(v, "id", w);
      if (v.fromDefaultId !== undefined) str(v, "fromDefaultId", w);
      if (v.toDefaultId !== undefined) str(v, "toDefaultId", w);
      if (v.force !== undefined) bool(v, "force", w);
      if (v.uncoveredOriginRunCount !== undefined) num(v, "uncoveredOriginRunCount", w);
      if (v.rejectReason !== undefined) {
        const r = str(v, "rejectReason", w);
        if (!["endpoint-not-https", "missing-fields", "invalid-config"].includes(r)) fail(`${w}: unknown rejectReason ${JSON.stringify(r)}`);
      }
      return v as AuditTarget;
    }
    case "supportcredential": {
      assertObjectKeys(v, ["kind", "scope"], ["clientId", "expiresAt"], w);
      const scope = str(v, "scope", w);
      if (!["diagnostics", "audit-feed", "metrics"].includes(scope)) fail(`${w}: unknown scope ${JSON.stringify(scope)}`);
      if (v.clientId !== undefined) str(v, "clientId", w);
      if (v.expiresAt !== undefined) str(v, "expiresAt", w);
      return v as AuditTarget;
    }
    case "idpconnection": {
      assertObjectKeys(v, ["kind", "connId", "connKind", "op"], [], w);
      str(v, "connId", w);
      const connKind = str(v, "connKind", w);
      if (!["oidc", "oauth2", "saml"].includes(connKind)) fail(`${w}: unknown connKind ${JSON.stringify(connKind)}`);
      const op = str(v, "op", w);
      if (!["create", "update", "delete", "enable", "disable", "signin", "test"].includes(op)) fail(`${w}: unknown op ${JSON.stringify(op)}`);
      return v as AuditTarget;
    }
    case "credential-cleanup": {
      assertObjectKeys(v, ["kind", "itemId"], ["tokenRef"], w);
      str(v, "itemId", w);
      if (v.tokenRef !== undefined) str(v, "tokenRef", w);
      return v as AuditTarget;
    }
    case "push-destination": {
      assertObjectKeys(v, ["kind", "op"], ["id", "rejectReason", "failureCount"], w);
      const op = str(v, "op", w);
      if (!["set", "clear", "test", "delivery-failure"].includes(op)) fail(`${w}: unknown op ${JSON.stringify(op)}`);
      if (v.id !== undefined) str(v, "id", w);
      if (v.rejectReason !== undefined) {
        const r = str(v, "rejectReason", w);
        if (!["endpoint-invalid", "format-invalid", "missing-fields"].includes(r)) fail(`${w}: unknown rejectReason ${JSON.stringify(r)}`);
      }
      if (v.failureCount !== undefined) num(v, "failureCount", w);
      return v as AuditTarget;
    }
    case "engine-state": {
      assertObjectKeys(v, ["kind", "field", "detail"], [], w);
      const field = str(v, "field", w);
      if (!["secret-present", "engineVersion"].includes(field)) fail(`${w}: unknown field ${JSON.stringify(field)}`);
      str(v, "detail", w);
      return v as AuditTarget;
    }
    default:
      fail(`${where}: unknown target.kind ${JSON.stringify(kind)}`);
  }
}

/** assertAuditEvent structurally validates a raw JSON value against the closed AuditEvent shape
 * (src/admin/audit-types.ts): every field present with the correct type, action drawn from the live
 * AUDIT_ACTIONS set, outcome/actorMethod from their closed enums, prevHash/hash valid sha384: strings, and
 * target validated against all 19 AuditTarget union variants. Used by ndjson/json-array/raw-json (the raw
 * event IS the wire payload) and by splunk-hec/datadog (the raw event is nested/spread into a wrapper). */
function assertAuditEvent(v: unknown, where: string): AuditEvent {
  if (!isPlainObject(v)) fail(`${where}: audit event must be an object`);
  assertObjectKeys(v, ["seq", "ts", "actorEmail", "actorMethod", "sourceIp", "action", "outcome", "target", "prevHash", "hash"], ["actorSubject", "advisory"], where);
  const seq = num(v, "seq", where);
  if (!Number.isInteger(seq) || seq < 0) fail(`${where}: seq must be a non-negative integer, got ${seq}`);
  const ts = str(v, "ts", where);
  if (!Number.isFinite(Date.parse(ts))) fail(`${where}: ts ${JSON.stringify(ts)} is not a valid timestamp`);
  if (v.actorSubject !== undefined) strOrNull(v, "actorSubject", where);
  strOrNull(v, "actorEmail", where);
  const actorMethod = str(v, "actorMethod", where);
  if (!AUTH_METHODS.has(actorMethod)) fail(`${where}: unknown actorMethod ${JSON.stringify(actorMethod)}`);
  strOrNull(v, "sourceIp", where);
  const action = str(v, "action", where);
  if (!AUDIT_ACTION_SET.has(action)) fail(`${where}: unknown action ${JSON.stringify(action)} (not in AUDIT_ACTIONS)`);
  const outcome = str(v, "outcome", where);
  if (!OUTCOMES.has(outcome)) fail(`${where}: unknown outcome ${JSON.stringify(outcome)}`);
  assertAuditTarget(v.target, where);
  const prevHash = str(v, "prevHash", where);
  if (!HASH_RE.test(prevHash)) fail(`${where}: prevHash ${JSON.stringify(prevHash)} is not a valid sha384: hash`);
  const hash = str(v, "hash", where);
  if (!HASH_RE.test(hash)) fail(`${where}: hash ${JSON.stringify(hash)} is not a valid sha384: hash`);
  if (v.advisory !== undefined) {
    if (!isPlainObject(v.advisory)) fail(`${where}: advisory must be an object`);
    assertObjectKeys(v.advisory, [], ["acr", "amr", "authTime"], `${where}.advisory`);
    if (v.advisory.acr !== undefined) str(v.advisory, "acr", `${where}.advisory`);
    if (v.advisory.amr !== undefined) {
      if (!Array.isArray(v.advisory.amr) || !v.advisory.amr.every((x) => typeof x === "string")) fail(`${where}.advisory: amr must be a string array`);
    }
    if (v.advisory.authTime !== undefined) num(v.advisory, "authTime", `${where}.advisory`);
  }
  return v as unknown as AuditEvent;
}

// ============================================================================================================
// ndjson / json-array / raw-json (the plain audit-feed envelopes)
// ============================================================================================================

/** parseNdjson parses one raw AuditEvent JSON object per "\n"-joined line (shapeNdjson's exact shape). */
export function parseNdjson(raw: string | Buffer, opts?: { contentType?: string }): { events: AuditEvent[] } {
  assertContentType(opts, "application/x-ndjson", "ndjson");
  const text = toText(raw);
  if (text.length === 0) fail("ndjson: empty input");
  const events = text.split("\n").map((line, idx) => {
    let obj: unknown;
    try {
      obj = JSON.parse(line);
    } catch (e) {
      fail(`ndjson line ${idx}: invalid JSON (${(e as Error).message})`);
    }
    return assertAuditEvent(obj, `ndjson line ${idx}`);
  });
  return { events };
}

/** parseJsonArray parses a bare `[event, ...]` JSON array of raw AuditEvents (shapeJsonArray's exact shape). */
export function parseJsonArray(raw: string | Buffer, opts?: { contentType?: string }): { events: AuditEvent[] } {
  assertContentType(opts, "application/json", "json-array");
  const text = toText(raw);
  let arr: unknown;
  try {
    arr = JSON.parse(text);
  } catch (e) {
    fail(`json-array: invalid JSON (${(e as Error).message})`);
  }
  if (!Array.isArray(arr)) fail("json-array: top-level value must be a JSON array");
  const events = arr.map((item, idx) => assertAuditEvent(item, `json-array[${idx}]`));
  return { events };
}

export interface ParsedRawJsonFeed {
  events: AuditEvent[];
  kind: string;
  v: number;
  afterSeq: number;
  nextAfterSeq: number;
  headSeq: number;
  headHash: string;
  count: number;
}

/** parseRawJson parses the pull-feed-shaped push envelope (shapeRawJson's exact shape): EXACTLY
 * {kind,v,afterSeq,nextAfterSeq,headSeq,headHash,count,events}, no missing or extra top-level key. */
export function parseRawJson(raw: string | Buffer, opts?: { contentType?: string }): ParsedRawJsonFeed {
  assertContentType(opts, "application/json", "raw-json");
  const obj = parseJsonObject(toText(raw), "raw-json");
  assertObjectKeys(obj, ["kind", "v", "afterSeq", "nextAfterSeq", "headSeq", "headHash", "count", "events"], [], "raw-json");
  const kind = str(obj, "kind", "raw-json");
  if (kind !== "downpipe-audit-feed") fail(`raw-json: kind must be "downpipe-audit-feed", got ${JSON.stringify(kind)}`);
  const v = num(obj, "v", "raw-json");
  if (v !== 1) fail(`raw-json: v must be 1, got ${v}`);
  const afterSeq = num(obj, "afterSeq", "raw-json");
  const nextAfterSeq = num(obj, "nextAfterSeq", "raw-json");
  const headSeq = num(obj, "headSeq", "raw-json");
  const headHash = str(obj, "headHash", "raw-json");
  const count = num(obj, "count", "raw-json");
  if (!Array.isArray(obj.events)) fail("raw-json: events must be an array");
  if (obj.events.length !== count) fail(`raw-json: count (${count}) does not match events.length (${obj.events.length})`);
  const events = obj.events.map((item, idx) => assertAuditEvent(item, `raw-json.events[${idx}]`));
  return { events, kind, v, afterSeq, nextAfterSeq, headSeq, headHash, count };
}

// ============================================================================================================
// Splunk HEC
// ============================================================================================================

export interface ParsedHecLine extends AuditEvent {
  time: number;
  source: string;
  sourcetype: string;
}

/** parseSplunkHec parses newline-concatenated HEC event objects (shapeSplunkHec's exact shape): each line
 * EXACTLY {time:epoch-seconds, source, sourcetype, event}, no missing or extra top-level key.
 *
 * SCOPE: this is a conformance check on OUR OWN envelope, deliberately STRICTER than real HEC. A real listener
 * also accepts `index`, `host` and `fields` beside these four and tolerates trailing whitespace between
 * objects, so a body this rejects is not necessarily a body Splunk would reject. Read a failure here as "the
 * engine's shaper changed", never as "Splunk would refuse this".
 *
 * Worth knowing while reading it: shapeSplunkHec sends NO `index` key, so every event lands in whatever
 * default index the HEC token carries. A token pointed at a deleted or renamed index still answers
 * {"text":"Success","code":0} and silently drops the events, and the push cursor advances regardless -- see
 * the acceptance-versus-delivery note in src/notify/siem-push-sender.ts. */
export function parseSplunkHec(raw: string | Buffer, opts?: { contentType?: string }): { events: ParsedHecLine[] } {
  assertContentType(opts, "application/json", "splunk-hec");
  const text = toText(raw);
  if (text.length === 0) fail("splunk-hec: empty input");
  const events = text.split("\n").map((line, idx) => {
    const where = `splunk-hec line ${idx}`;
    let obj: unknown;
    try {
      obj = JSON.parse(line);
    } catch (e) {
      fail(`${where}: invalid JSON (${(e as Error).message})`);
    }
    if (!isPlainObject(obj)) fail(`${where}: not a JSON object`);
    assertObjectKeys(obj, ["time", "source", "sourcetype", "event"], [], where);
    const time = num(obj, "time", where);
    if (!Number.isInteger(time)) fail(`${where}: time must be an integer (epoch seconds), got ${time}`);
    const source = str(obj, "source", where);
    if (source !== "downpipes") fail(`${where}: source must be "downpipes", got ${JSON.stringify(source)}`);
    const sourcetype = str(obj, "sourcetype", where);
    if (sourcetype !== "downpipe:audit") fail(`${where}: sourcetype must be "downpipe:audit", got ${JSON.stringify(sourcetype)}`);
    const event = assertAuditEvent(obj.event, `${where}.event`);
    return { ...event, time, source, sourcetype };
  });
  return { events };
}

// ============================================================================================================
// Datadog
// ============================================================================================================

export interface ParsedDatadogLog extends AuditEvent {
  ddsource: string;
  service: string;
  message: string;
  status: string;
}

/** parseDatadog parses a bare JSON array of Datadog log objects (shapeDatadog's exact shape): each element
 * carries ddsource/service/message/status PLUS the spread raw AuditEvent fields, status asserted to match
 * the outcome-derived mapping (failed->error, denied->warning, else info). */
export function parseDatadog(raw: string | Buffer, opts?: { contentType?: string }): { events: ParsedDatadogLog[] } {
  assertContentType(opts, "application/json", "datadog");
  const text = toText(raw);
  let arr: unknown;
  try {
    arr = JSON.parse(text);
  } catch (e) {
    fail(`datadog: invalid JSON (${(e as Error).message})`);
  }
  if (!Array.isArray(arr)) fail("datadog: top-level value must be a JSON array");
  const events = arr.map((item, idx) => {
    const where = `datadog[${idx}]`;
    if (!isPlainObject(item)) fail(`${where}: not a JSON object`);
    const ddsource = str(item, "ddsource", where);
    if (ddsource !== "downpipes") fail(`${where}: ddsource must be "downpipes", got ${JSON.stringify(ddsource)}`);
    const service = str(item, "service", where);
    if (service !== "downpipe-engine") fail(`${where}: service must be "downpipe-engine", got ${JSON.stringify(service)}`);
    const message = str(item, "message", where);
    const status = str(item, "status", where);
    if (!["error", "warning", "info"].includes(status)) fail(`${where}: status must be one of error/warning/info, got ${JSON.stringify(status)}`);
    const { ddsource: _a, service: _b, message: _c, status: _d, ...rest } = item;
    const event = assertAuditEvent(rest, where);
    const expectedMessage = `${event.action} ${event.outcome}`;
    if (message !== expectedMessage) fail(`${where}: message ${JSON.stringify(message)} does not match "<action> <outcome>" (${JSON.stringify(expectedMessage)})`);
    const expectedStatus = event.outcome === "failed" ? "error" : event.outcome === "denied" ? "warning" : "info";
    if (status !== expectedStatus) fail(`${where}: status ${JSON.stringify(status)} does not match the outcome-derived value ${JSON.stringify(expectedStatus)}`);
    return { ...event, ddsource, service, message, status };
  });
  return { events };
}

// ============================================================================================================
// GELF (Graylog Extended Log Format) 1.1
// ============================================================================================================

export interface ParsedGelfEvent {
  version: "1.1";
  host: string;
  short_message: string;
  timestamp: number;
  level: number;
  seq: number;
  actorEmail: string | null;
  actorSubject: string | null;
  actorMethod: string;
  sourceIp: string | null;
  action: string;
  outcome: string;
  targetKind: string;
  targetId?: string;
  targetName?: string;
  prevHash: string;
  hash: string;
}

const GELF_RESERVED_TOP = new Set(["version", "host", "short_message", "full_message", "timestamp", "level", "facility", "line", "file"]);
const GELF_KNOWN_UNDERSCORE = new Set(["_seq", "_actorEmail", "_actorSubject", "_actorMethod", "_sourceIp", "_action", "_outcome", "_targetKind", "_targetId", "_targetName", "_prevHash", "_hash"]);

function parseGelfLine(line: string, idx: number): ParsedGelfEvent {
  const where = `GELF line ${idx}`;
  let obj: unknown;
  try {
    obj = JSON.parse(line);
  } catch (e) {
    fail(`${where}: invalid JSON (${(e as Error).message})`);
  }
  if (!isPlainObject(obj)) fail(`${where}: top-level value is not a JSON object`);
  if (obj.version !== "1.1") fail(`${where}: version must be "1.1", got ${JSON.stringify(obj.version)}`);
  const host = str(obj, "host", where);
  const short_message = str(obj, "short_message", where);
  const timestamp = num(obj, "timestamp", where);
  const level = num(obj, "level", where);
  if (![3, 4, 6].includes(level)) fail(`${where}: level must be one of 3/4/6, got ${level}`);
  if ("_id" in obj) fail(`${where}: "_id" is GELF-reserved and must never be emitted`);
  for (const key of Object.keys(obj)) {
    if (GELF_RESERVED_TOP.has(key)) continue;
    if (!key.startsWith("_")) fail(`${where}: custom field ${JSON.stringify(key)} must start with "_"`);
    if (!GELF_KNOWN_UNDERSCORE.has(key)) fail(`${where}: unknown custom field ${JSON.stringify(key)}`);
  }
  const seq = num(obj, "_seq", where);
  if (!Number.isInteger(seq)) fail(`${where}: _seq must be an integer, got ${seq}`);
  const actorEmail = strOrNull(obj, "_actorEmail", where);
  const actorSubject = strOrNull(obj, "_actorSubject", where);
  const actorMethod = str(obj, "_actorMethod", where);
  const sourceIp = strOrNull(obj, "_sourceIp", where);
  const action = str(obj, "_action", where);
  const outcome = str(obj, "_outcome", where);
  const targetKind = str(obj, "_targetKind", where);
  const targetId = "_targetId" in obj ? str(obj, "_targetId", where) : undefined;
  const targetName = "_targetName" in obj ? str(obj, "_targetName", where) : undefined;
  const prevHash = str(obj, "_prevHash", where);
  const hash = str(obj, "_hash", where);
  if (!HASH_RE.test(prevHash)) fail(`${where}: _prevHash is not a valid sha384: hash: ${JSON.stringify(prevHash)}`);
  if (!HASH_RE.test(hash)) fail(`${where}: _hash is not a valid sha384: hash: ${JSON.stringify(hash)}`);
  const expectedShortMessage = `${action} ${outcome}`;
  if (short_message !== expectedShortMessage) fail(`${where}: short_message ${JSON.stringify(short_message)} does not match "<action> <outcome>" (${JSON.stringify(expectedShortMessage)})`);
  return {
    version: "1.1",
    host,
    short_message,
    timestamp,
    level,
    seq,
    actorEmail,
    actorSubject,
    actorMethod,
    sourceIp,
    action,
    outcome,
    targetKind,
    ...(targetId !== undefined ? { targetId } : {}),
    ...(targetName !== undefined ? { targetName } : {}),
    prevHash,
    hash,
  };
}

/** parseGelf parses newline-joined GELF 1.1 objects (shapeGelf's exact shape): version/host/short_message
 * mandatory, timestamp a number (epoch seconds), level in {3,4,6}, every custom field "_"-prefixed and
 * drawn from the closed set, "_id" never present (GELF-reserved). JSON-encoded, so fully lossless -- the
 * strongest round-trip proof of the eleven formats. */
export function parseGelf(raw: string | Buffer, opts?: { contentType?: string }): { events: ParsedGelfEvent[] } {
  assertContentType(opts, "application/json", "GELF");
  const text = toText(raw);
  if (text.length === 0) fail("GELF: empty input");
  const events = text.split("\n").map((line, idx) => parseGelfLine(line, idx));
  return { events };
}

// ============================================================================================================
// OTLP/HTTP JSON (ExportMetricsServiceRequest)
// ============================================================================================================

const KNOWN_OTLP_METRICS: ReadonlySet<string> = new Set([
  OTLP_METRIC_LAST_SUCCESS,
  OTLP_METRIC_SUCCESS,
  OTLP_METRIC_RECENT_ATTEMPTS,
  OTLP_METRIC_RECENT_SUCCESSES,
  OTLP_METRIC_RECENT_FAILURES,
  OTLP_METRIC_DURATION,
  OTLP_METRIC_SIZE_BYTES,
  OTLP_METRIC_DEST_HEALTHY,
  OTLP_METRIC_ENABLED,
]);

export interface ParsedOtlpDataPoint {
  metric: string;
  unit: string;
  description: string;
  attributes: Record<string, string>;
  timeUnixNano: bigint;
  asDouble: number;
}

export interface ParsedOtlpBody {
  events: ParsedOtlpDataPoint[];
  serviceName: string;
  serviceVersion: string;
  scopeName: string;
  scopeVersion: string;
  metricNames: string[];
}

function parseOtlpAttributes(v: unknown, where: string): Record<string, string> {
  if (!Array.isArray(v)) fail(`${where}: must be an array`);
  const out: Record<string, string> = {};
  v.forEach((kv, idx) => {
    const kvWhere = `${where}[${idx}]`;
    if (!isPlainObject(kv)) fail(`${kvWhere}: not an object`);
    assertObjectKeys(kv, ["key", "value"], [], kvWhere);
    const key = str(kv, "key", kvWhere);
    const value = kv.value;
    if (!isPlainObject(value)) fail(`${kvWhere}.value: must be an object`);
    assertObjectKeys(value, ["stringValue"], [], `${kvWhere}.value`);
    out[key] = str(value, "stringValue", `${kvWhere}.value`);
  });
  return out;
}

function parseBigIntStrict(s: string, where: string): bigint {
  if (!/^-?\d+$/.test(s)) fail(`${where}: ${JSON.stringify(s)} is not a plain decimal integer string`);
  return BigInt(s);
}

/** parseOtlpJson parses one OTLP/HTTP JSON ExportMetricsServiceRequest body (buildOneOtlpBody's exact
 * shape): exactly one resourceMetrics[0].resource (service.name/service.version present), exactly one
 * scopeMetrics[0].scope (name "downpipes.otlp-push"), and metrics[] each a gauge with a NON-EMPTY
 * dataPoints[] (an empty-series metric must be omitted entirely) whose name is one of the 9 known OTLP
 * metric names, each dataPoint carrying timeUnixNano as a decimal STRING (parsed as BigInt, never a
 * silently-truncated float) and asDouble a finite number. */
export function parseOtlpJson(raw: string | Buffer, opts?: { contentType?: string }): ParsedOtlpBody {
  assertContentType(opts, "application/json", "OTLP");
  const obj = parseJsonObject(toText(raw), "OTLP");
  assertObjectKeys(obj, ["resourceMetrics"], [], "OTLP");
  if (!Array.isArray(obj.resourceMetrics) || obj.resourceMetrics.length !== 1) fail(`OTLP: resourceMetrics must be a single-element array, got length ${Array.isArray(obj.resourceMetrics) ? obj.resourceMetrics.length : "n/a"}`);
  const rm = obj.resourceMetrics[0];
  if (!isPlainObject(rm)) fail("OTLP: resourceMetrics[0] must be an object");
  assertObjectKeys(rm, ["resource", "scopeMetrics"], [], "OTLP.resourceMetrics[0]");
  const resource = rm.resource;
  if (!isPlainObject(resource)) fail("OTLP: resource must be an object");
  assertObjectKeys(resource, ["attributes"], [], "OTLP.resource");
  const resAttrs = parseOtlpAttributes(resource.attributes, "OTLP.resource.attributes");
  if (JSON.stringify(Object.keys(resAttrs).sort()) !== JSON.stringify(["service.name", "service.version"])) {
    fail(`OTLP: resource.attributes must be exactly {service.name, service.version}, got ${JSON.stringify(Object.keys(resAttrs))}`);
  }
  const serviceName = resAttrs["service.name"]!;
  const serviceVersion = resAttrs["service.version"]!;
  if (serviceName.length === 0) fail("OTLP: resource.attributes.service.name must not be empty");
  if (serviceVersion.length === 0) fail("OTLP: resource.attributes.service.version must not be empty");

  if (!Array.isArray(rm.scopeMetrics) || rm.scopeMetrics.length !== 1) fail("OTLP: scopeMetrics must be a single-element array");
  const sm = rm.scopeMetrics[0];
  if (!isPlainObject(sm)) fail("OTLP: scopeMetrics[0] must be an object");
  assertObjectKeys(sm, ["scope", "metrics"], [], "OTLP.scopeMetrics[0]");
  const scope = sm.scope;
  if (!isPlainObject(scope)) fail("OTLP: scope must be an object");
  assertObjectKeys(scope, ["name", "version"], [], "OTLP.scope");
  const scopeName = str(scope, "name", "OTLP.scope");
  const scopeVersion = str(scope, "version", "OTLP.scope");
  if (scopeName !== "downpipes.otlp-push") fail(`OTLP: scope.name must be "downpipes.otlp-push", got ${JSON.stringify(scopeName)}`);

  if (!Array.isArray(sm.metrics)) fail("OTLP: metrics must be an array");
  const metricNames: string[] = [];
  const events: ParsedOtlpDataPoint[] = [];
  sm.metrics.forEach((metric, mIdx) => {
    const where = `OTLP.metrics[${mIdx}]`;
    if (!isPlainObject(metric)) fail(`${where}: not an object`);
    assertObjectKeys(metric, ["name", "description", "unit", "gauge"], [], where);
    const name = str(metric, "name", where);
    if (!KNOWN_OTLP_METRICS.has(name)) fail(`${where}: unknown metric name ${JSON.stringify(name)}`);
    if (metricNames.includes(name)) fail(`${where}: duplicate metric name ${JSON.stringify(name)}`);
    metricNames.push(name);
    const description = str(metric, "description", where);
    const unit = str(metric, "unit", where);
    const gauge = metric.gauge;
    if (!isPlainObject(gauge)) fail(`${where}: gauge must be an object`);
    assertObjectKeys(gauge, ["dataPoints"], [], `${where}.gauge`);
    if (!Array.isArray(gauge.dataPoints) || gauge.dataPoints.length === 0) fail(`${where}: gauge.dataPoints must be a non-empty array (an empty-series metric must be omitted entirely)`);
    gauge.dataPoints.forEach((dp, dIdx) => {
      const dWhere = `${where}.dataPoints[${dIdx}]`;
      if (!isPlainObject(dp)) fail(`${dWhere}: not an object`);
      assertObjectKeys(dp, ["attributes", "timeUnixNano", "asDouble"], [], dWhere);
      const attributes = parseOtlpAttributes(dp.attributes, `${dWhere}.attributes`);
      const timeUnixNanoRaw = dp.timeUnixNano;
      if (typeof timeUnixNanoRaw !== "string") fail(`${dWhere}: timeUnixNano must be a string, got ${JSON.stringify(timeUnixNanoRaw)}`);
      const timeUnixNano = parseBigIntStrict(timeUnixNanoRaw, `${dWhere}.timeUnixNano`);
      if (timeUnixNano < 0n) fail(`${dWhere}: timeUnixNano must be non-negative, got ${timeUnixNanoRaw}`);
      const asDouble = num(dp, "asDouble", dWhere);
      events.push({ metric: name, unit, description, attributes, timeUnixNano, asDouble });
    });
  });
  return { events, serviceName, serviceVersion, scopeName, scopeVersion, metricNames };
}

// ============================================================================================================
// Prometheus text exposition (renderPrometheusMetrics's exact output)
// ============================================================================================================

export interface ParsedPrometheusSample {
  name: string;
  labels: Record<string, string>;
  value: number;
  type: string;
}

const PROM_FAMILIES = ["downpipe_backup_last_success_timestamp_seconds", "downpipe_backup_success", "downpipe_backup_recent_attempts", "downpipe_backup_recent_successes", "downpipe_backup_recent_failures", "downpipe_backup_duration_seconds", "downpipe_backup_size_bytes", "downpipe_destination_healthy"];

function parsePrometheusSampleLine(line: string, i: number): { name: string; labels: Record<string, string>; value: number } {
  const nameMatch = /^[a-zA-Z_:][a-zA-Z0-9_:]*/.exec(line);
  if (!nameMatch) fail(`Prometheus line ${i}: sample line does not start with a valid metric name: ${JSON.stringify(line)}`);
  const name = nameMatch[0];
  let pos = name.length;
  const labels: Record<string, string> = {};
  if (line[pos] === "{") {
    pos++;
    if (line[pos] === "}") fail(`Prometheus line ${i}: empty label set "{}" (omit the braces instead)`);
    for (;;) {
      const keyMatch = /^[a-zA-Z_][a-zA-Z0-9_]*/.exec(line.slice(pos));
      if (!keyMatch) fail(`Prometheus line ${i}: expected a label name at position ${pos}`);
      const key = keyMatch[0];
      pos += key.length;
      if (line[pos] !== "=") fail(`Prometheus line ${i}: expected "=" after label name ${JSON.stringify(key)}`);
      pos++;
      if (line[pos] !== '"') fail(`Prometheus line ${i}: expected opening quote for label ${JSON.stringify(key)}`);
      pos++;
      let value = "";
      let closed = false;
      while (pos < line.length) {
        const c = line[pos]!;
        if (c === "\\") {
          const n = line[pos + 1];
          if (n === "\\") {
            value += "\\";
            pos += 2;
            continue;
          }
          if (n === '"') {
            value += '"';
            pos += 2;
            continue;
          }
          if (n === "n") {
            value += "\n";
            pos += 2;
            continue;
          }
          fail(`Prometheus line ${i}: invalid escape sequence "\\${n ?? ""}" in label ${JSON.stringify(key)}`);
        }
        if (c === '"') {
          closed = true;
          pos++;
          break;
        }
        if (RAW_CONTROL_RE.test(c)) fail(`Prometheus line ${i}: raw unescaped control character in label ${JSON.stringify(key)} (must be escaped, e.g. "\\n")`);
        value += c;
        pos++;
      }
      if (!closed) fail(`Prometheus line ${i}: unterminated label value for ${JSON.stringify(key)}`);
      if (key in labels) fail(`Prometheus line ${i}: duplicate label ${JSON.stringify(key)}`);
      labels[key] = value;
      if (line[pos] === ",") {
        pos++;
        continue;
      }
      if (line[pos] === "}") {
        pos++;
        break;
      }
      fail(`Prometheus line ${i}: expected "," or "}" after label value for ${JSON.stringify(key)}, got ${JSON.stringify(line[pos] ?? "<eof>")}`);
    }
  }
  if (line[pos] !== " ") fail(`Prometheus line ${i}: expected a single space before the value at position ${pos}`);
  pos++;
  const valueStr = line.slice(pos);
  const special = valueStr === "NaN" || valueStr === "+Inf" || valueStr === "-Inf";
  const value = valueStr === "NaN" ? NaN : valueStr === "+Inf" ? Infinity : valueStr === "-Inf" ? -Infinity : Number(valueStr);
  if (!special && (!/^-?\d+(\.\d+)?(e[+-]?\d+)?$/i.test(valueStr) || !Number.isFinite(value))) fail(`Prometheus line ${i}: invalid sample value ${JSON.stringify(valueStr)}`);
  return { name, labels, value };
}

/** parsePrometheusText parses Prometheus text exposition (renderPrometheusMetrics's exact output): every
 * sample's metric must have a preceding (non-duplicate) "# TYPE" line declaring "gauge", label values are
 * decoded per escapeLabelValue's rules (backslash/quote/CRLF), and any other malformed line is rejected. */
export function parsePrometheusText(raw: string | Buffer, opts?: { contentType?: string }): { events: ParsedPrometheusSample[] } {
  assertContentType(opts, "text/plain; version=0.0.4; charset=utf-8", "Prometheus");
  const text = toText(raw);
  if (!text.endsWith("\n")) fail("Prometheus: body must end with a trailing newline");
  const rawLines = text.split("\n");
  if (rawLines[rawLines.length - 1] !== "") fail("Prometheus: unexpected content after the final newline");
  const lines = rawLines.slice(0, -1);

  const typeOf = new Map<string, string>();
  const helpSeen = new Set<string>();
  const events: ParsedPrometheusSample[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.length === 0) fail(`Prometheus line ${i}: blank line not permitted`);
    if (line.startsWith("# HELP ")) {
      const rest = line.slice("# HELP ".length);
      const sp = rest.indexOf(" ");
      const name = sp === -1 ? rest : rest.slice(0, sp);
      if (!PROM_FAMILIES.includes(name)) fail(`Prometheus line ${i}: HELP for unknown metric family ${JSON.stringify(name)}`);
      if (helpSeen.has(name)) fail(`Prometheus line ${i}: duplicate HELP for ${JSON.stringify(name)}`);
      helpSeen.add(name);
      continue;
    }
    if (line.startsWith("# TYPE ")) {
      const rest = line.slice("# TYPE ".length);
      const sp = rest.indexOf(" ");
      if (sp === -1) fail(`Prometheus line ${i}: malformed TYPE line`);
      const name = rest.slice(0, sp);
      const type = rest.slice(sp + 1);
      if (!PROM_FAMILIES.includes(name)) fail(`Prometheus line ${i}: TYPE for unknown metric family ${JSON.stringify(name)}`);
      if (typeOf.has(name)) fail(`Prometheus line ${i}: duplicate TYPE line for ${JSON.stringify(name)}`);
      if (type !== "gauge") fail(`Prometheus line ${i}: TYPE for ${JSON.stringify(name)} must be "gauge", got ${JSON.stringify(type)}`);
      typeOf.set(name, type);
      continue;
    }
    if (line.startsWith("#")) fail(`Prometheus line ${i}: unrecognised comment line ${JSON.stringify(line)}`);
    const sample = parsePrometheusSampleLine(line, i);
    if (!typeOf.has(sample.name)) fail(`Prometheus line ${i}: sample for ${JSON.stringify(sample.name)} has no preceding TYPE line`);
    events.push({ ...sample, type: typeOf.get(sample.name)! });
  }
  return { events };
}

// ============================================================================================================
// Secondary section: notify-channel JSON payload shapes (webhook / slack / teams / pagerduty / servicenow /
// jsm). Plain JSON, so "strict" here is exact key-set + enum + cap validation (JSON.parse already gives
// structural safety; there is no hand-rolled escaping to reverse the way CEF/LEEF need).
// ============================================================================================================

export interface ParsedWebhookPayload {
  kind: "downpipe-event-v1";
  at: string;
  event: string;
  severity: string;
  downpipe?: { id: string; name: string | null };
  detail: string;
}

/** parseWebhookPayload validates the generic webhook v1 body (webhook.ts's WebhookPayloadV1). */
export function parseWebhookPayload(raw: string | Buffer, opts?: { contentType?: string }): { events: ParsedWebhookPayload[] } {
  assertContentType(opts, "application/json", "webhook");
  const obj = parseJsonObject(toText(raw), "webhook");
  assertObjectKeys(obj, ["kind", "at", "event", "severity", "detail"], ["downpipe"], "webhook");
  const kind = str(obj, "kind", "webhook");
  if (kind !== "downpipe-event-v1") fail(`webhook: kind must be "downpipe-event-v1", got ${JSON.stringify(kind)}`);
  const at = str(obj, "at", "webhook");
  if (!Number.isFinite(Date.parse(at))) fail(`webhook: at ${JSON.stringify(at)} is not a valid timestamp`);
  const event = str(obj, "event", "webhook");
  const severity = str(obj, "severity", "webhook");
  if (!["info", "warning", "critical"].includes(severity)) fail(`webhook: unknown severity ${JSON.stringify(severity)}`);
  const detail = str(obj, "detail", "webhook");
  let downpipe: { id: string; name: string | null } | undefined;
  if (obj.downpipe !== undefined) {
    const dp = obj.downpipe;
    if (!isPlainObject(dp)) fail("webhook: downpipe must be an object");
    assertObjectKeys(dp, ["id", "name"], [], "webhook.downpipe");
    downpipe = { id: str(dp, "id", "webhook.downpipe"), name: strOrNull(dp, "name", "webhook.downpipe") };
  }
  return { events: [{ kind: "downpipe-event-v1", at, event, severity, detail, ...(downpipe !== undefined ? { downpipe } : {}) }] };
}

export interface ParsedSlackPayload {
  text: string;
  blocks?: Array<{ type: "section"; text: { type: "mrkdwn"; text: string } }>;
}

/** parseSlackPayload validates the Slack incoming-webhook body (slack.ts's SlackPayload). */
export function parseSlackPayload(raw: string | Buffer, opts?: { contentType?: string }): { events: ParsedSlackPayload[] } {
  assertContentType(opts, "application/json", "slack");
  const obj = parseJsonObject(toText(raw), "slack");
  assertObjectKeys(obj, ["text"], ["blocks"], "slack");
  const text = str(obj, "text", "slack");
  let blocks: ParsedSlackPayload["blocks"];
  if (obj.blocks !== undefined) {
    if (!Array.isArray(obj.blocks)) fail("slack: blocks must be an array");
    blocks = obj.blocks.map((b, idx) => {
      const w = `slack.blocks[${idx}]`;
      if (!isPlainObject(b)) fail(`${w}: not an object`);
      assertObjectKeys(b, ["type", "text"], [], w);
      if (b.type !== "section") fail(`${w}: type must be "section"`);
      const bt = b.text;
      if (!isPlainObject(bt)) fail(`${w}.text: must be an object`);
      assertObjectKeys(bt, ["type", "text"], [], `${w}.text`);
      if (bt.type !== "mrkdwn") fail(`${w}.text: type must be "mrkdwn"`);
      return { type: "section" as const, text: { type: "mrkdwn" as const, text: str(bt, "text", `${w}.text`) } };
    });
  }
  return { events: [{ text, ...(blocks !== undefined ? { blocks } : {}) }] };
}

export interface ParsedTeamsCard {
  "@type": "MessageCard";
  "@context": "http://schema.org/extensions";
  themeColor: string;
  summary: string;
  title: string;
  text: string;
}

/** parseTeamsCard validates the Teams connector MessageCard body (teams.ts's TeamsCard). */
export function parseTeamsCard(raw: string | Buffer, opts?: { contentType?: string }): { events: ParsedTeamsCard[] } {
  assertContentType(opts, "application/json", "teams");
  const obj = parseJsonObject(toText(raw), "teams");
  assertObjectKeys(obj, ["@type", "@context", "themeColor", "summary", "title", "text"], [], "teams");
  if (obj["@type"] !== "MessageCard") fail('teams: "@type" must be "MessageCard"');
  if (obj["@context"] !== "http://schema.org/extensions") fail('teams: "@context" must be "http://schema.org/extensions"');
  const themeColor = str(obj, "themeColor", "teams");
  if (!/^[0-9A-Fa-f]{6}$/.test(themeColor)) fail(`teams: themeColor must be a 6-digit hex string, got ${JSON.stringify(themeColor)}`);
  return { events: [{ "@type": "MessageCard", "@context": "http://schema.org/extensions", themeColor, summary: str(obj, "summary", "teams"), title: str(obj, "title", "teams"), text: str(obj, "text", "teams") }] };
}

export interface ParsedPagerDutyEvent {
  routing_key: string;
  event_action: "trigger" | "resolve";
  dedup_key?: string;
  summary: string;
  severity: string;
  source: string;
  component?: string;
}

/** parsePagerDutyPayload validates the PagerDuty Events API v2 envelope (pagerduty.ts's PagerDutyPayload). */
export function parsePagerDutyPayload(raw: string | Buffer, opts?: { contentType?: string }): { events: ParsedPagerDutyEvent[] } {
  assertContentType(opts, "application/json", "pagerduty");
  const obj = parseJsonObject(toText(raw), "pagerduty");
  assertObjectKeys(obj, ["routing_key", "event_action", "payload"], ["dedup_key"], "pagerduty");
  const routing_key = str(obj, "routing_key", "pagerduty");
  const event_action = str(obj, "event_action", "pagerduty");
  if (event_action !== "trigger" && event_action !== "resolve") fail(`pagerduty: event_action must be trigger/resolve, got ${JSON.stringify(event_action)}`);
  const dedup_key = obj.dedup_key !== undefined ? str(obj, "dedup_key", "pagerduty") : undefined;
  const payload = obj.payload;
  if (!isPlainObject(payload)) fail("pagerduty: payload must be an object");
  assertObjectKeys(payload, ["summary", "severity", "source"], ["component"], "pagerduty.payload");
  const summary = str(payload, "summary", "pagerduty.payload");
  if (summary.length > 1024) fail(`pagerduty: payload.summary exceeds the 1024-char cap (${summary.length})`);
  const severity = str(payload, "severity", "pagerduty.payload");
  if (!["info", "warning", "critical"].includes(severity)) fail(`pagerduty: unknown severity ${JSON.stringify(severity)}`);
  const source = str(payload, "source", "pagerduty.payload");
  const component = payload.component !== undefined ? str(payload, "component", "pagerduty.payload") : undefined;
  return { events: [{ routing_key, event_action, ...(dedup_key !== undefined ? { dedup_key } : {}), summary, severity, source, ...(component !== undefined ? { component } : {}) }] };
}

export interface ParsedServiceNowEvent {
  source: string;
  node: string;
  resource: string;
  metric_name: string;
  severity: 0 | 1 | 2 | 3 | 4 | 5;
  description: string;
  message_key: string;
}

/** parseServiceNowPayload validates a ServiceNow em_event body: either the flat Table API shape
 * (servicenow.ts's ServiceNowEventPayload) or the {records:[...]} em/jsonv2 wrapper (buildServiceNowBody's
 * two documented intakes), auto-detected by the top-level shape exactly as buildServiceNowBody itself picks
 * by URL path. */
export function parseServiceNowPayload(raw: string | Buffer, opts?: { contentType?: string }): { events: ParsedServiceNowEvent[] } {
  assertContentType(opts, "application/json", "servicenow");
  const text = toText(raw);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    fail(`servicenow: invalid JSON (${(e as Error).message})`);
  }
  let list: unknown[];
  if (isPlainObject(parsed) && Array.isArray(parsed.records)) {
    assertObjectKeys(parsed, ["records"], [], "servicenow(jsonv2)");
    list = parsed.records;
  } else {
    list = [parsed];
  }
  const events = list.map((item, idx) => {
    const where = `servicenow[${idx}]`;
    if (!isPlainObject(item)) fail(`${where}: not an object`);
    assertObjectKeys(item, ["source", "node", "resource", "metric_name", "severity", "description", "message_key"], [], where);
    const source = str(item, "source", where);
    if (source !== "downpipes") fail(`${where}: source must be "downpipes", got ${JSON.stringify(source)}`);
    const node = str(item, "node", where);
    const resource = str(item, "resource", where);
    const metric_name = str(item, "metric_name", where);
    if (metric_name !== `downpipe.${resource}`) fail(`${where}: metric_name must be "downpipe.${resource}", got ${JSON.stringify(metric_name)}`);
    const severity = num(item, "severity", where);
    if (![0, 1, 2, 3, 4, 5].includes(severity)) fail(`${where}: severity must be 0-5, got ${severity}`);
    const description = str(item, "description", where);
    const message_key = str(item, "message_key", where);
    return { source, node, resource, metric_name, severity: severity as 0 | 1 | 2 | 3 | 4 | 5, description, message_key };
  });
  return { events };
}

export interface ParsedJsmCreate {
  message: string;
  alias: string;
  description: string;
  priority: "P1" | "P2" | "P3" | "P4" | "P5";
  source: string;
}
export interface ParsedJsmClose {
  source: string;
}

/** parseJsmCreatePayload validates the JSM/Opsgenie Alert API create body (jsm.ts's JsmCreatePayload). */
export function parseJsmCreatePayload(raw: string | Buffer, opts?: { contentType?: string }): { events: ParsedJsmCreate[] } {
  assertContentType(opts, "application/json", "jsm-create");
  const obj = parseJsonObject(toText(raw), "jsm-create");
  assertObjectKeys(obj, ["message", "alias", "description", "priority", "source"], [], "jsm-create");
  const message = str(obj, "message", "jsm-create");
  if (message.length > 130) fail(`jsm-create: message exceeds the 130-char cap (${message.length})`);
  const alias = str(obj, "alias", "jsm-create");
  const description = str(obj, "description", "jsm-create");
  const priority = str(obj, "priority", "jsm-create");
  if (!["P1", "P2", "P3", "P4", "P5"].includes(priority)) fail(`jsm-create: unknown priority ${JSON.stringify(priority)}`);
  const source = str(obj, "source", "jsm-create");
  if (source.length > 100) fail(`jsm-create: source exceeds the 100-char cap (${source.length})`);
  return { events: [{ message, alias, description, priority: priority as ParsedJsmCreate["priority"], source }] };
}

/** parseJsmClosePayload validates the JSM/Opsgenie Alert API close-by-alias body (jsm.ts's JsmClosePayload). */
export function parseJsmClosePayload(raw: string | Buffer, opts?: { contentType?: string }): { events: ParsedJsmClose[] } {
  assertContentType(opts, "application/json", "jsm-close");
  const obj = parseJsonObject(toText(raw), "jsm-close");
  assertObjectKeys(obj, ["source"], [], "jsm-close");
  return { events: [{ source: str(obj, "source", "jsm-close") }] };
}
