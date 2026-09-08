// test/validate-destination-format-coverage.ts -- the DESTINATION-FORMAT DENOMINATOR and the census that
// grades every member of it by DRIVING the engine's real delivery path, never by reading an adapter.
//
// WHY THIS EXISTS. Prior coverage reporting used percentages over four denominators. The destination surface
// has none, so no percentage can fall on it, and the one figure in circulation ("destsim emulates 15
// formats") is a count of the TEST HARNESS's capability rather than of anything the product promises. This
// file replaces that with a denominator DERIVED, at runtime, from the engine's own authorities:
//
//   PUSH_FORMATS x PUSH_SINKS, minus the pairs pushSinkFormatError refuses  (sched/scheduler-do-limits.ts)
//
// so it FALLS the moment a format is added, a sink is added, or the cross-field rule changes, and it cannot
// be hand-maintained into a lie. Nothing here re-types the vocabularies; every list is imported.
//
// WHAT "PROVEN" MEANS HERE, and it is deliberately a high bar. A destination that accepted a write is not a
// destination that was read back. Every pair is graded into exactly one of four verdicts:
//
//   ROUND-TRIP     the REAL engine delivery entry point (cron/siem-push-pass.ts deliverResolvedPush, the
//                  single sink dispatch shared by the cron drain and the admin test-send) delivered over a
//                  REAL socket to a REAL listening destination, which STRICT-PARSED the bytes back into
//                  audit events under the parser for the CONFIGURED format, and every event's identity
//                  (seq:hash) came back. Write and read-back, both, on the wire.
//   SUBSTITUTED    delivery succeeded and the destination parsed the bytes, but ONLY under a parser for a
//                  DIFFERENT format than the operator configured. The receiver got plausible bytes under
// the wrong label. This is the class the syslog-tls sink was refused for.
//   REJECTED       the destination refused the bytes (a strict parse failure), or delivery reported not-ok.
//   NOT-DRIVEN     nothing drove the pair at all.
//
// THE THREE DESTINATIONS ARE REAL SERVERS, not fetch stubs.
//   http        test/destsim/server.ts startEmulator: a node:http server on 127.0.0.1 that strict-parses
//               every accepted body and answers 400 on anything it cannot parse. The engine's push sender
//               (notify/siem-push-sender.ts) has NO internal-sink override -- unlike a notify webhook
//               channel it deliberately cannot be pointed at a loopback literal -- so the endpoint stays a
//               public hostname and ONE fetch relay swaps the ORIGIN to the emulator, preserving method,
//               headers, body and status. Everything else on the path is the shipped code: the shaper, the
//               content-type, the auth header, the redirect:"manual" guard, the status classification.
//   s3          startS3DropEmulator below: a node:http server speaking enough S3 to accept the drain's
//               SigV4-signed PUT and hold the object. NO relay and NO stub at all -- S3Destination permits
//               an http://127.0.0.1 endpoint (dest/s3-addressing.ts requireHttpsEndpoint's loopback
//               allowance), so the drain signs and sends to it directly. The stored object is then read
//               back off the emulator and strict-parsed. destsim had no S3 emulator; the s3 sink is a
//               third of the delivery surface and nothing had ever read one of its objects back.
//   syslog-tls  test/destsim/server.ts startSyslogEmulator + makeRealSyslogConnect: genuine TLS bytes.
//
// TWO SECTIONS BESIDES THE CENSUS, because a denominator that names only what it counts hides its own edges.
//   WHERE THE SOURCES DISAGREE  derives the product's vocabulary and destsim's emulation capability from
//                               each side separately and NAMES the disagreements rather than reconciling
//                               them into one number. The figure for this surface has moved 39 -> 15 -> 18,
//                               and all three are right because each counts a different axis.
//   CONFIG BOUNDARY             asks what the engine will STORE, not what it delivers, because a pair the
//                               engine stores is a pair a customer's estate can be sitting on whatever the
//                               console's own form would have let them pick.
//
// INSTRUMENT CONTROL, and there are three, each two-sided, each run BEFORE the number it guards.
//   the grader          the SAME grader on the SAME pair must answer ROUND-TRIP against an unmodified
//                       destination and REJECTED against a corrupted one, on http and on s3. A grader that
//                       cannot say no has not said yes.
//   the config boundary storing every deliverable pair, AND a pair outside the denominator refused by the identical call,
//                       so the count is not also true of a boundary that stores anything.
//   the union extractor driven on a synthetic declaration whose answer is known, and on a text with no
//                       declaration, where it must THROW rather than return [] -- an empty list would print
//                       as a count of zero and read like a measurement.
//
// Run: node test/validate-destination-format-coverage.ts

import { Buffer } from "node:buffer";
import { readdirSync, readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AuditEvent } from "../src/admin/audit-types.ts";
import { deliverResolvedPush, type ResolvedPushConfig } from "../src/cron/siem-push-pass.ts";
import { objectExtensionForFormat, type PushCursorMeta, shapeForFormat } from "../src/cron/siem-push-shape.ts";
import { __setSyslogConnectForTest } from "../src/notify/siem-syslog-sender.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { PUSH_FORMATS, PUSH_SINKS, type PushFormat, type PushSink, pushSinkFormatError } from "../src/sched/scheduler-do-limits.ts";
import { isChannelKindLocal } from "../src/sched/scheduler-helpers.ts";
import { DestsimParseError, parseCef, parseDatadog, parseGelf, parseJsonArray, parseLeef, parseNdjson, parseRawJson, parseSplunkHec, } from "./destsim/parsers.ts";
import { type EmulatorFormat, makeRealSyslogConnect, startEmulator, startSyslogEmulator } from "./destsim/server.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// ============================================================================================================
// The DERIVED denominator
// ============================================================================================================

export interface Pair {
  format: PushFormat;
  sink: PushSink;
}

/** deliverablePairs derives the denominator from the engine's own authorities: every (format, sink)
 * combination the engine will accept and store, which is the closed set of things an operator can configure a
 * destination to be. It is computed, never listed: adding a format, a sink or a cross-field rule moves it. */
export function deliverablePairs(): Pair[] {
  const out: Pair[] = [];
  for (const sink of PUSH_SINKS) {
    for (const format of PUSH_FORMATS) {
      if (pushSinkFormatError(format, sink) === null) out.push({ format, sink });
    }
  }
  return out;
}

/** allPairs is the UNFILTERED product, the denominator's denominator. Subtracting deliverablePairs from it
 * names which pairs the cross-field rule refuses, so the census can say what LEFT the deliverable set rather
 * than only how many remain: a fraction whose denominator shrinks is not comparable with one whose numerator
 * grew, and this is what keeps the two apart. */
export function allPairs(): Pair[] {
  const out: Pair[] = [];
  for (const sink of PUSH_SINKS) {
    for (const format of PUSH_FORMATS) out.push({ format, sink });
  }
  return out;
}

const HERE = dirname(fileURLToPath(import.meta.url));

/** emulatorFormatMembers reads destsim's OWN EmulatorFormat union out of its source, rather than re-typing
 * it here. That is deliberate: the claim "destsim emulates 15 formats" IS this union's cardinality, so
 * the only way to say whether that figure still holds is to count the union itself, and the count then moves
 * when the union does. A type cannot be counted at runtime; its declaration can. */
export function parseUnionMembers(text: string, typeName: string): string[] {
  const m = text.match(new RegExp(`export type ${typeName} = ([^;]+);`));
  if (!m) throw new Error(`${typeName} declaration not found; this census cannot count what it cannot read`);
  return m[1]!
    .split("|")
    .map((s) => s.trim().replace(/^"|"$/g, ""))
    .filter(Boolean);
}

function emulatorFormatMembers(): string[] {
  return parseUnionMembers(readFileSync(join(HERE, "destsim", "server.ts"), "utf8"), "EmulatorFormat");
}

/** notifyChannelKinds derives the notification-destination kinds the product ships from the FILESYSTEM (one
 * adapter per kind under src/notify/channels/) screened through the engine's own runtime membership
 * predicate. Two independent authorities have to agree before a kind is counted, so an adapter with no kind
 * and a kind with no adapter both show up rather than cancelling out. */
function notifyChannelKinds(): string[] {
  return readdirSync(join(HERE, "..", "src", "notify", "channels"))
    .filter((f) => f.endsWith(".ts"))
    .map((f) => f.replace(/\.ts$/, ""))
    .filter((k) => isChannelKindLocal(k));
}

export type Verdict = "ROUND-TRIP" | "SUBSTITUTED" | "REJECTED" | "NOT-DRIVEN";

export interface Graded extends Pair {
  verdict: Verdict;
  detail: string;
}

// ============================================================================================================
// The audit events every pair is driven with
// ============================================================================================================

const HASH = (seed: string): string => `sha384:${Buffer.from(seed.padEnd(48, "*")).toString("hex").slice(0, 96).padEnd(96, "0")}`;

function ev(seq: number): AuditEvent {
  return {
    seq,
    ts: new Date(1_700_000_000_000 + seq * 1000).toISOString(),
    actorSubject: "https://acct.cloudflareaccess.com|sub-of-owner@example.com",
    actorEmail: "owner@example.com",
    actorMethod: "access",
    sourceIp: "203.0.113.7",
    action: "dest-config-set",
    outcome: "success",
    target: { kind: "downpipe", id: `dp-${seq}`, name: `downpipe ${seq}` },
    prevHash: HASH(`prev-${seq}`),
    hash: HASH(`hash-${seq}`),
  } as AuditEvent;
}

const EVENTS: AuditEvent[] = [ev(101), ev(102), ev(103)];
const META: PushCursorMeta = { afterSeq: 100, nextAfterSeq: 103, headSeq: 103, headHash: HASH("head") };
const EXPECTED_KEYS: string[] = EVENTS.map((e) => `${e.seq}:${e.hash}`);

// The owner identity every config-boundary call is made as, matching validate-siem-push.ts's own.
const OWNER_CALLER = { method: "token" as const, email: null, subject: null, groups: [] };

// ============================================================================================================
// The parser dispatch, keyed on the CONFIGURED format (not on what happened to arrive)
// ============================================================================================================

/** parseAs strict-parses raw under the parser for exactly `format`, returning the recovered ledger
 * identities (seq:hash) or throwing DestsimParseError. This is the whole point of grading SUBSTITUTED
 * separately: the question is never "did something parse" but "did the format the operator chose parse". */
function parseAs(format: PushFormat, raw: Buffer | string, contentType?: string): string[] {
  const opts = contentType !== undefined ? { contentType } : undefined;
  const idOf = (e: { seq: number; hash: string }): string => `${e.seq}:${e.hash}`;
  switch (format) {
    case "raw-json":
      return parseRawJson(raw, opts).events.map(idOf);
    case "ndjson":
      return parseNdjson(raw, opts).events.map(idOf);
    case "json-array":
      return parseJsonArray(raw, opts).events.map(idOf);
    case "splunk-hec":
      return parseSplunkHec(raw, opts).events.map(idOf);
    case "datadog":
      return parseDatadog(raw, opts).events.map(idOf);
    case "gelf":
      return parseGelf(raw, opts).events.map(idOf);
    case "cef":
      return parseCef(raw, opts).events.map(idOf);
    case "leef":
      return parseLeef(raw, opts).events.map(idOf);
  }
}

/** whicheverParses names the format whose parser DOES accept these bytes, for the SUBSTITUTED detail line.
 * It answers "what did the receiver actually get", which is the fact an operator needs and which no counter,
 * trail row or audit event records today. */
function whicheverParses(raw: Buffer | string, contentType?: string): PushFormat | null {
  for (const f of PUSH_FORMATS) {
    try {
      if (parseAs(f, raw, contentType).length > 0) return f;
    } catch {
      // not this one
    }
  }
  return null;
}

function sameIdentities(got: string[]): boolean {
  if (got.length !== EXPECTED_KEYS.length) return false;
  const g = [...got].sort();
  const w = [...EXPECTED_KEYS].sort();
  return g.every((v, i) => v === w[i]);
}

// ============================================================================================================
// The S3-drop destination emulator (new: destsim had none)
// ============================================================================================================

export interface S3DropObject {
  key: string;
  body: Buffer;
  contentType: string | undefined;
  authorization: string | undefined;
}

export interface S3DropHandle {
  endpoint: string;
  objects: S3DropObject[];
  /** corruptBodies, when set, mutates the stored bytes before they are held, so the grader can be shown a
   * destination whose object does NOT parse. Used only by the instrument control. */
  corruptBodies: boolean;
  close(): Promise<void>;
}

/** startS3DropEmulator is a REAL node:http server on 127.0.0.1 speaking the sliver of S3 the audit drain
 * uses: a single-shot PUT of one object. It answers 200 with an ETag (what S3Destination.put requires) and
 * holds the exact bytes, so the object can be READ BACK and strict-parsed -- the half of the promise a fetch
 * stub asserting on init.body can never reach. It deliberately does NOT verify the SigV4 signature: proving
 * the signature is dest/sigv4.ts's own suite's job, and a destination that rejected an unsigned request
 * would make this file fail for a reason that is not about formats. It DOES record the Authorization header
 * so a caller can assert one was present. */
export async function startS3DropEmulator(): Promise<S3DropHandle> {
  const objects: S3DropObject[] = [];
  const handle: Partial<S3DropHandle> & { objects: S3DropObject[] } = { objects, corruptBodies: false };
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      if (req.method !== "PUT") {
        res.writeHead(405, { "content-type": "text/plain" });
        res.end("s3-drop emulator: only PUT is implemented");
        return;
      }
      let body = Buffer.concat(chunks);
      if (handle.corruptBodies === true) body = Buffer.from(`${body.toString("utf8")}\n{"seq":"not-a-number"}`, "utf8");
      objects.push({
        key: req.url ?? "",
        body,
        contentType: req.headers["content-type"],
        authorization: req.headers.authorization,
      });
      res.writeHead(200, { etag: '"deadbeef"', "content-type": "application/xml" });
      res.end("");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  handle.endpoint = `http://127.0.0.1:${addr.port}`;
  handle.close = (): Promise<void> =>
    new Promise<void>((resolve, reject) => {
      server.closeAllConnections();
      server.close((e) => (e ? reject(e) : resolve()));
    });
  return handle as S3DropHandle;
}

// ============================================================================================================
// The http relay: the ONE substitution on the http path, and it is a transport hop, not a stub
// ============================================================================================================

/** installOriginRelay replaces globalThis.fetch with a relay that rewrites the ORIGIN of any request to
 * `publicOrigin` onto `localOrigin` and performs the request for real. Method, headers, body, status and
 * response body are the genuine ones; only the host the packet goes to changes.
 *
 * WHY IT IS NEEDED AND WHY IT IS HONEST. deliverSiemPush re-screens the sink host at SEND time and returns
 * internal-sink-blocked for 127.0.0.1, by design and with no per-destination override (the notify webhook
 * channel's allowInternalSink has no counterpart here). So the engine's real push sender CANNOT be pointed
 * at a loopback emulator, and every existing test of it therefore stubs fetch and asserts on the request it
 * was handed. This relay keeps the whole engine path -- shaper, content-type, auth header, redirect guard,
 * timeout, status classification -- and moves only the packet, so the destination on the far end is a real
 * server that really parses. `corrupt` mutates the body on the wire for the instrument control. */
function installOriginRelay(publicOrigin: string, localOrigin: string, state: { corrupt: boolean }): () => void {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    if (`${url.protocol}//${url.host}` !== publicOrigin) return realFetch(input as RequestInfo, init);
    const local = new URL(url.pathname + url.search, localOrigin);
    let body = init?.body;
    if (state.corrupt && typeof body === "string") body = `${body}CORRUPT`;
    return realFetch(local.toString(), { ...init, body } as RequestInit);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = realFetch;
  };
}

// ============================================================================================================
// The three drivers, one per sink
// ============================================================================================================

const PUBLIC_ORIGIN = "https://siem.example.invalid";

async function driveHttp(format: PushFormat, corrupt: boolean): Promise<Graded> {
  const emu = await startEmulator({ format: format as EmulatorFormat });
  const local = new URL(emu.url);
  const restore = installOriginRelay(PUBLIC_ORIGIN, `${local.protocol}//${local.host}`, { corrupt });
  try {
    const cfg: ResolvedPushConfig = {
      endpoint: `${PUBLIC_ORIGIN}${local.pathname}`,
      format,
      authHeaderName: "Authorization",
      // splunk-hec carries the literal, case-sensitive "Splunk " scheme a real HEC listener requires; every
      // other format keeps the bare token, because the scheme is vendor-specific and only HEC pins one.
      //
      // A bare token sent for splunk-hec is REFUSED by a real HEC listener (403 code 4), so this fixture must
      // send the literal "Splunk " scheme for that format to avoid a false ROUND-TRIP grade that a live
      // customer configuration would not achieve.
      authHeaderValue: format === "splunk-hec" ? "Splunk push-secret-DO-NOT-LEAK" : "push-secret-DO-NOT-LEAK",
      enabled: true,
      gen: "g",
      sink: "http",
      authInUrl: false,
    };
    const r = await deliverResolvedPush(cfg, EVENTS, META);
    if (!r.ok) return { format, sink: "http", verdict: "REJECTED", detail: `delivery not ok (${r.reason ?? r.status ?? "no reason"}); the destination's strict parser refused the bytes or the send failed` };
    const keys = [...emu.ledger.keys()];
    if (!sameIdentities(keys)) return { format, sink: "http", verdict: "REJECTED", detail: `the destination ledgered ${keys.length} of ${EXPECTED_KEYS.length} event identities` };
    // The emulator parsed under the parser for THIS format (parseByEmulatorFormat keys on the format the
    // emulator was started with), so an accepted body is by construction an accepted body IN THIS FORMAT.
    return { format, sink: "http", verdict: "ROUND-TRIP", detail: `${EXPECTED_KEYS.length} of ${EXPECTED_KEYS.length} identities recovered by the ${format} parser at the destination` };
  } finally {
    restore();
    await emu.close();
  }
}

async function driveS3(format: PushFormat, corrupt: boolean): Promise<Graded> {
  const s3 = await startS3DropEmulator();
  s3.corruptBodies = corrupt;
  try {
    const cfg: ResolvedPushConfig = {
      endpoint: "",
      format,
      authHeaderName: "Authorization",
      authHeaderValue: "",
      enabled: true,
      gen: "g",
      sink: "s3",
      authInUrl: false,
      s3: { endpoint: s3.endpoint, bucket: "audit-bucket", region: "auto", accessKeyId: "AKIAEXAMPLEKEYID", secretAccessKey: "s3-secret-DO-NOT-LEAK", prefix: "downpipes-audit" },
    };
    const r = await deliverResolvedPush(cfg, EVENTS, META);
    if (!r.ok) return { format, sink: "s3", verdict: "REJECTED", detail: `delivery not ok (${r.reason ?? "no reason"})` };
    if (s3.objects.length !== 1) return { format, sink: "s3", verdict: "REJECTED", detail: `${s3.objects.length} objects landed, expected exactly 1` };
    const obj = s3.objects[0]!;
    // READ BACK: the object the destination is holding, parsed under the CONFIGURED format's parser.
    try {
      const keys = parseAs(format, obj.body);
      if (!sameIdentities(keys)) return { format, sink: "s3", verdict: "REJECTED", detail: `the stored object parsed as ${format} but yielded ${keys.length} of ${EXPECTED_KEYS.length} identities` };
      return { format, sink: "s3", verdict: "ROUND-TRIP", detail: `object ${obj.key.split("/").pop()} read back off the destination and parsed as ${format}, ${keys.length} of ${EXPECTED_KEYS.length} identities recovered` };
    } catch (e) {
      if (!(e instanceof DestsimParseError)) throw e;
      const actual = whicheverParses(obj.body);
      if (actual === null) return { format, sink: "s3", verdict: "REJECTED", detail: `the stored object parses as NO engine format: ${e.message}` };
      return { format, sink: "s3", verdict: "SUBSTITUTED", detail: `configured ${format}, but the object the destination is holding parses only as ${actual} (key ends .${obj.key.split(".").pop()})` };
    }
  } finally {
    await s3.close();
  }
}

async function driveSyslog(format: PushFormat, corrupt: boolean): Promise<Graded> {
  const emu = await startSyslogEmulator();
  __setSyslogConnectForTest(makeRealSyslogConnect());
  try {
    const cfg: ResolvedPushConfig = {
      endpoint: "",
      format,
      authHeaderName: "Authorization",
      authHeaderValue: "",
      enabled: true,
      gen: "g",
      sink: "syslog-tls",
      authInUrl: false,
      syslog: { host: emu.host, port: emu.port },
    };
    if (corrupt) emu.setFault({ kind: "connect-drop" });
    const r = await deliverResolvedPush(cfg, EVENTS, META);
    if (!r.ok) return { format, sink: "syslog-tls", verdict: "REJECTED", detail: `delivery not ok (${r.reason ?? "no reason"})` };
    await emu.waitForLedgerSize(EVENTS.length, 5000);
    const keys = [...emu.ledger.keys()];
    if (!sameIdentities(keys)) return { format, sink: "syslog-tls", verdict: "REJECTED", detail: `the destination ledgered ${keys.length} of ${EXPECTED_KEYS.length} event identities` };
    // The destination AUTO-DETECTS each frame's MSG format (parseSyslogFrames with no format hint) and
    // records what it actually received, so a silent CEF-for-everything substitution -- where every non-LEEF
    // format falls into the CEF arm -- grades SUBSTITUTED here rather
    // than passing on a ledger that never looked at the wire shape.
    const wrong = emu.requests.filter((q) => q.format !== format);
    if (wrong.length > 0) return { format, sink: "syslog-tls", verdict: "SUBSTITUTED", detail: `configured ${format}, but ${wrong.length} of ${emu.requests.length} frames arrived as ${wrong[0]!.format}` };
    return { format, sink: "syslog-tls", verdict: "ROUND-TRIP", detail: `${keys.length} of ${EXPECTED_KEYS.length} identities recovered from ${emu.requests.length} RFC 5424 frames over real TLS, each independently detected as ${format}` };
  } finally {
    // null, not undefined: the hook's own signature is SyslogConnectFn | null, and the test tsconfig is the
    // one that says so. `npx tsc -p tsconfig.json` passes on undefined; `npm run typecheck` does not, because
    // it runs tsconfig.test.json as its second half. A targeted typecheck is not the repo's typecheck.
    __setSyslogConnectForTest(null);
    await emu.close();
  }
}

async function drive(pair: Pair, corrupt = false): Promise<Graded> {
  if (pair.sink === "http") return driveHttp(pair.format, corrupt);
  if (pair.sink === "s3") return driveS3(pair.format, corrupt);
  return driveSyslog(pair.format, corrupt);
}

// ============================================================================================================
// The instrument control: prove the grader can say NO before believing any yes
// ============================================================================================================

async function runInstrumentControl(): Promise<void> {
  console.log("\nINSTRUMENT CONTROL: the identical grader, driven twice, must answer differently");
  const positive = await drive({ format: "ndjson", sink: "http" }, false);
  ok(`positive control: ndjson over http against an unmodified destination grades ROUND-TRIP (got ${positive.verdict})`, positive.verdict === "ROUND-TRIP");
  const negative = await drive({ format: "ndjson", sink: "http" }, true);
  ok(`negative control: the SAME pair with a corrupted body on the wire grades REJECTED (got ${negative.verdict})`, negative.verdict === "REJECTED");

  const s3pos = await drive({ format: "ndjson", sink: "s3" }, false);
  ok(`positive control: ndjson over the s3 drop grades ROUND-TRIP (got ${s3pos.verdict})`, s3pos.verdict === "ROUND-TRIP");
  const s3neg = await drive({ format: "ndjson", sink: "s3" }, true);
  ok(`negative control: the SAME pair with the stored object corrupted grades REJECTED (got ${s3neg.verdict})`, s3neg.verdict === "REJECTED");
}

// ============================================================================================================
// main
// ============================================================================================================

async function main(): Promise<void> {
  console.log("DESTINATION-FORMAT DENOMINATOR: derived from PUSH_FORMATS x PUSH_SINKS minus pushSinkFormatError\n");
  const pairs = deliverablePairs();
  console.log(`  PUSH_FORMATS (${PUSH_FORMATS.length}): ${PUSH_FORMATS.join(", ")}`);
  console.log(`  PUSH_SINKS   (${PUSH_SINKS.length}): ${PUSH_SINKS.join(", ")}`);
  console.log(`  DENOMINATOR  (${pairs.length} deliverable pairs)\n`);
  ok("the denominator is non-empty and smaller than the unfiltered product (the cross-field rule bites)", pairs.length > 0 && pairs.length < PUSH_FORMATS.length * PUSH_SINKS.length);

  // ----------------------------------------------------------------------------------------------------
  // WHERE THE TWO SOURCES DISAGREE, derived from each side rather than narrated.
  //
  // A figure that keeps moving is usually measuring something different each time. This one has moved
  // twice: "39 vendors emulated", corrected to "destsim emulates 15 formats", and now 18 here. The 15 and
  // the 18 are BOTH right and they are NOT the same axis, which is the whole finding:
  //
  //   15 = |EmulatorFormat|, a FORMAT-NAME list on ONE transport (http), spanning THREE product surfaces
  //        (the audit push, the metrics push, the notification channels).
  //   18 = the deliverable (format, sink) pairs of ONE product surface (the audit push) across ALL THREE
  //        of its transports.
  //
  // Their intersection is the 8 audit-push formats over http, and each side holds things the other does
  // not. Subtracting one from the other would be meaningless, so the assertions below name the
  // disagreements instead of reconciling them into a single number.
  // ----------------------------------------------------------------------------------------------------
  console.log("\nWHERE THE SOURCES DISAGREE: the product's vocabulary and destsim's emulation capability");
  // CONTROL ON THE MEASURING TOOL, before any count it produces is believed. The union extractor is read
  // off source text, which is the fragile half of this section, so it is driven twice on known inputs: a
  // synthetic declaration whose answer is known, and a text with no declaration at all, which must throw
  // rather than quietly return an empty list. An extractor that answers [] for a missing declaration would
  // report "destsim emulates 0 formats" as though it were a measurement.
  {
    const synthetic = 'export type EmulatorFormat = "alpha" | "beta" | "gamma";\n';
    const got = parseUnionMembers(synthetic, "EmulatorFormat");
    ok("extractor positive control: a synthetic 3-member declaration reads back as exactly those 3", got.join(",") === "alpha,beta,gamma");
    let threw = false;
    try {
      parseUnionMembers("nothing to see here", "EmulatorFormat");
    } catch {
      threw = true;
    }
    ok("extractor negative control: a text with no declaration THROWS rather than returning an empty list that would read as a count of zero", threw);
  }
  const emulator = emulatorFormatMembers();
  const notifyKinds = notifyChannelKinds();
  const pushSet = new Set<string>(PUSH_FORMATS);
  const emulatedPush = emulator.filter((f) => pushSet.has(f));
  const emulatedNotify = notifyKinds.filter((k) => emulator.includes(k));
  const unemulatedNotify = notifyKinds.filter((k) => !emulator.includes(k));
  const emulatorNonPush = emulator.filter((f) => !pushSet.has(f));
  console.log(`  product, audit push:       ${PUSH_FORMATS.length} formats x ${PUSH_SINKS.length} sinks = ${pairs.length} deliverable pairs`);
  console.log(`  product, notify channels:  ${notifyKinds.length} kinds (${notifyKinds.join(", ")})`);
  console.log(`  destsim, EmulatorFormat:   ${emulator.length} members (${emulator.join(", ")})`);
  console.log(`  overlap:                   ${emulatedPush.length} audit-push formats, all on http only`);
  console.log(`  destsim members that are NOT audit-push formats: ${emulatorNonPush.length} (${emulatorNonPush.join(", ")})`);
  console.log(`  notify kinds destsim cannot emulate:             ${unemulatedNotify.length} (${unemulatedNotify.join(", ") || "none"})`);

  ok(`destsim emulates every one of the ${PUSH_FORMATS.length} audit-push formats, so the two sides agree on the FORMAT axis`, emulatedPush.length === PUSH_FORMATS.length);
  ok(`destsim's ${emulator.length}-member list is not an audit-push list: ${emulatorNonPush.length} of its members belong to other product surfaces (the metrics push and the notification channels)`, emulatorNonPush.length > 0);
  // The non-http share is COUNTED, not inferred from PUSH_FORMATS.length. It used to be written as
  // `pairs.length - PUSH_FORMATS.length`, which silently assumed every format is deliverable over http; the
  // moment cef and leef were refused away from syslog-tls that identity broke and the check went red on an
  // arithmetic shortcut rather than on anything about destsim. The claim only ever concerned the SINK axis.
  const nonHttpPairs = pairs.filter((p) => p.sink !== "http");
  const httpPairs = pairs.filter((p) => p.sink === "http");
  ok(
    `destsim's list names no SINK at all, so it cannot speak to ${nonHttpPairs.length} of the ${pairs.length} deliverable pairs (every s3-drop and syslog-tls pair)`,
    nonHttpPairs.length > 0 && nonHttpPairs.length + httpPairs.length === pairs.length && nonHttpPairs.every((p) => p.sink !== "http"),
  );
  ok(`the ${unemulatedNotify.length} notify kind(s) with no destsim emulator are named rather than absorbed: ${unemulatedNotify.join(", ") || "none"}`, unemulatedNotify.length === notifyKinds.length - emulatedNotify.length);
  ok("email is the notification destination destsim cannot emulate, because it is the one channel whose payload is not an HTTP JSON body", unemulatedNotify.includes("email"));

  await runInstrumentControl();

  console.log("\nCENSUS: every deliverable pair, driven through deliverResolvedPush against a real destination");
  const graded: Graded[] = [];
  for (const pair of pairs) {
    let g: Graded;
    try {
      g = await drive(pair);
    } catch (e) {
      g = { ...pair, verdict: "NOT-DRIVEN", detail: `the driver threw: ${e instanceof Error ? e.message : String(e)}` };
    }
    graded.push(g);
    console.log(`  ${g.verdict.padEnd(11)} ${`${g.format} over ${g.sink}`.padEnd(28)} ${g.detail}`);
  }

  const roundTrip = graded.filter((g) => g.verdict === "ROUND-TRIP");
  const substituted = graded.filter((g) => g.verdict === "SUBSTITUTED");
  const rejected = graded.filter((g) => g.verdict === "REJECTED");
  const notDriven = graded.filter((g) => g.verdict === "NOT-DRIVEN");

  console.log(`\nTODAY'S FRACTION: ${roundTrip.length} of ${pairs.length} deliverable (format, sink) pairs round-trip`);
  console.log(`  SUBSTITUTED ${substituted.length}   REJECTED ${rejected.length}   NOT-DRIVEN ${notDriven.length}`);
  for (const g of substituted) console.log(`  SUBSTITUTED: ${g.format} over ${g.sink} -- ${g.detail}`);

  // A PARSER-INDEPENDENT proof of what the s3 sink stores, so the verdicts above cannot be an artefact of the
  // parser dispatch. This block is the one that FOUND the substitution: it used to assert that the object a
  // splunk-hec destination is holding and the object an ndjson destination is holding were the SAME BYTES, and
  // it passed, because putSiemBatchToS3 called shapeNdjson unconditionally. It now asserts the opposite, and
  // asserts it AGAINST THE BYTES rather than against a structure: each stored object must equal, character for
  // character, what shapeForFormat produces for the format that was configured. A check that only asked
  // whether the object parsed, or whether the eight differed from one another, would pass against eight
  // wrong-but-distinct bodies; only the byte comparison pins which body belongs to which format.
  console.log("\nS3-DROP BYTES, proven without a parser: the object stored is the one the configured format shapes");
  {
    const bodies = new Map<PushFormat, string>();
    const keys = new Map<PushFormat, string>();
    for (const format of PUSH_FORMATS) {
      const s3 = await startS3DropEmulator();
      try {
        const cfg: ResolvedPushConfig = {
          endpoint: "",
          format,
          authHeaderName: "Authorization",
          authHeaderValue: "",
          enabled: true,
          gen: "g",
          sink: "s3",
          authInUrl: false,
          s3: { endpoint: s3.endpoint, bucket: "audit-bucket", region: "auto", accessKeyId: "AKIAEXAMPLEKEYID", secretAccessKey: "s3-secret-DO-NOT-LEAK", prefix: "downpipes-audit" },
        };
        await deliverResolvedPush(cfg, EVENTS, META);
        bodies.set(format, s3.objects[0]!.body.toString("utf8"));
        keys.set(format, s3.objects[0]!.key);
      } finally {
        await s3.close();
      }
    }
    // THE BYTE ASSERTION. shapeForFormat is the same call the http sink makes, and http round-trips 8 of 8, so
    // equality with it is equality with bytes a real SIEM has been shown to accept.
    const wrongBytes = PUSH_FORMATS.filter((f) => bodies.get(f) !== shapeForFormat(f, EVENTS, META).body);
    ok(
      `every one of the ${PUSH_FORMATS.length} formats stores the EXACT bytes its own shaper produces on the s3 sink${wrongBytes.length > 0 ? ` (wrong: ${wrongBytes.join(", ")})` : ""}`,
      wrongBytes.length === 0,
    );
    // The counter-fact the old assertion recorded, now stated as a refusal. Distinctness is WEAKER than the
    // byte equality above and cannot replace it, but it is what fails loudest if the format stops being
    // threaded through at all, and it names the collapse in the exact words the defect was reported in.
    const reference = bodies.get("ndjson")!;
    const identicalToNdjson = PUSH_FORMATS.filter((f) => bodies.get(f) === reference);
    ok(
      `no format other than ndjson stores an object byte-identical to the ndjson one, so the format field selects the bytes rather than nothing (identical to ndjson: ${identicalToNdjson.join(", ")})`,
      identicalToNdjson.length === 1 && identicalToNdjson[0] === "ndjson",
    );
    // The key is the only thing a bucket consumer sees before it opens the object, and S3Destination.put signs
    // no Content-Type, so an extension naming the wrong shape would be the same lie one step downstream.
    const wrongExt = PUSH_FORMATS.filter((f) => !keys.get(f)!.endsWith(`.${objectExtensionForFormat(f)}`));
    ok(`every stored object's key carries its own format's extension${wrongExt.length > 0 ? ` (wrong: ${wrongExt.join(", ")})` : ""}`, wrongExt.length === 0);
  }

  // THE CONFIG BOUNDARY, driven rather than reasoned about. The census above asks what a pair DELIVERS; this
  // asks what the engine will STORE, because a pair the engine stores is a pair a customer's estate can be
  // sitting on, whatever the console's own form would have let them pick.
  console.log("\nCONFIG BOUNDARY: which of the denominator the scheduler DO will actually store");
  {
    const stored: Pair[] = [];
    // The DO writes its audit chain to console.log; silence it for this block so 18 chain rows do not bury
    // the verdict lines. Restored in the finally, and nothing else is suppressed.
    const realLog = console.log;
    console.log = (): void => {};
    try {
      for (const pair of pairs) {
        const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
        const target =
          pair.sink === "s3"
            ? { s3Target: { endpoint: "https://s3.example.com", bucket: "audit", region: "auto", accessKeyId: "AKIAEXAMPLEKEYID", secretAccessKey: "s3-secret" } }
            : pair.sink === "syslog-tls"
              ? { syslog: { host: "siem.example.com", port: 6514 } }
              : { endpoint: "https://siem.example.com/ingest", authHeaderName: "Authorization", authHeaderValue: "header-secret" };
        try {
          const view = await dobj.setSiemPushDestination({ format: pair.format, sink: pair.sink, enabled: true, ...target }, OWNER_CALLER);
          // Stored means the DO READ IT BACK as the pair that was asked for, not merely that nothing threw.
          if (view.present === true && view.format === pair.format && (view.sink ?? "http") === pair.sink) stored.push(pair);
        } catch {
          // A refused pair is a pair the config boundary will not store; that is the fact being counted.
        }
      }
    } finally {
      console.log = realLog;
    }
    // NEGATIVE CONTROL for this section, through the identical call: a pair the cross-field rule REFUSES
    // (splunk-hec over syslog-tls, the defect) must NOT be stored. Without it, "every pair stored"
    // is equally consistent with a boundary that stores anything at all.
    let refusedStored = false;
    const control = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    console.log = (): void => {};
    try {
      const view = await control.setSiemPushDestination({ format: "splunk-hec", sink: "syslog-tls", enabled: true, syslog: { host: "siem.example.com", port: 6514 } }, OWNER_CALLER);
      refusedStored = view.present === true && view.format === "splunk-hec";
    } catch {
      refusedStored = false;
    } finally {
      console.log = realLog;
    }
    ok("negative control: splunk-hec over syslog-tls, a pair OUTSIDE the denominator, is refused by the same call that stored every deliverable pair", refusedStored === false);
    console.log(`  the DO stores ${stored.length} of the ${pairs.length} deliverable pairs`);
    ok(`every deliverable pair is also a STORABLE pair (${stored.length} of ${pairs.length}); a pair the delivery path handles but the config boundary refuses would be dead vocabulary`, stored.length === pairs.length);
    // THE FOUR PAIRS THE SCREEN REFUSED AND THE API DID NOT, driven through the API's own boundary. The
    // console's validatePushFormatSink has refused cef/leef over http and over s3 and the
    // docs state the rule, while pushSinkFormatError implemented only the other direction of it, so the engine
    // stored all four. It now refuses them, and this asserts the refusal from the outside rather than trusting
    // the edit: each is offered to setSiemPushDestination exactly as the other pairs were.
    const shouldRefuse: Pair[] = [
      { format: "cef", sink: "http" },
      { format: "cef", sink: "s3" },
      { format: "leef", sink: "http" },
      { format: "leef", sink: "s3" },
    ];
    const wronglyStored: string[] = [];
    console.log = (): void => {};
    try {
      for (const pair of shouldRefuse) {
        const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
        const target =
          pair.sink === "s3"
            ? { s3Target: { endpoint: "https://s3.example.com", bucket: "audit", region: "auto", accessKeyId: "AKIAEXAMPLEKEYID", secretAccessKey: "s3-secret" } }
            : { endpoint: "https://siem.example.com/ingest", authHeaderName: "Authorization", authHeaderValue: "header-secret" };
        try {
          const view = await dobj.setSiemPushDestination({ format: pair.format, sink: pair.sink, enabled: true, ...target }, OWNER_CALLER);
          if (view.present === true && view.format === pair.format) wronglyStored.push(`${pair.format}+${pair.sink}`);
        } catch {
          // refused, which is the point
        }
      }
    } finally {
      console.log = realLog;
    }
    ok(
      `cef and leef over http or s3 are REFUSED by the API, not only by the console form${wronglyStored.length > 0 ? ` (still stored: ${wronglyStored.join(", ")})` : ""}`,
      wronglyStored.length === 0,
    );
    // AND THE FOUR LEFT THE DENOMINATOR, which is the fact that must never be allowed to flatter the
    // round-trip fraction. The denominator was 18 and is now 14, so a reader comparing today's count with the
    // row's "11 of 18" is comparing two different denominators unless the census says so out loud. TWO of the
    // four were genuinely broken and are the defect this pass fixed (cef+s3 and leef+s3, written as NDJSON);
    // the OTHER TWO delivered correct CEF and LEEF bytes over http and were removed on the rule, not on a
    // fault. A fraction that improves because pairs were removed is not the same result as one that improves
    // because bytes were fixed, and the pre-refusal run recorded 18 of 18 on the full 18 for exactly that
    // reason.
    //
    // 14 is also the two-sided convergence: the console's validatePushFormatSink accepts 14 of the same 24,
    // and it was 14 against the engine's 18 that made this a disagreement rather than a preference.
    const removed = allPairs().filter((p) => !pairs.some((q) => q.format === p.format && q.sink === p.sink));
    const removedNames = removed.map((p) => `${p.format}+${p.sink}`).sort();
    const expectedRemoved = ["cef+http", "cef+s3", "gelf+syslog-tls", "json-array+syslog-tls", "leef+http", "leef+s3", "ndjson+syslog-tls", "raw-json+syslog-tls", "splunk-hec+syslog-tls"].sort();
    ok(`the deliverable set is now 14 of the 24 unfiltered pairs, the same 14 the console accepts (denominator: ${pairs.length})`, pairs.length === 14);
    ok(
      `the 10 refused pairs are exactly the 6 non-CEF/LEEF over syslog-tls plus the 4 CEF/LEEF away from it (refused: ${removedNames.length})`,
      removedNames.length === 10 && expectedRemoved.every((n) => removedNames.includes(n)) && removedNames.includes("datadog+syslog-tls"),
    );
  }

  ok("every deliverable pair reached a verdict (none NOT-DRIVEN)", notDriven.length === 0);
  ok("no deliverable pair is REJECTED by its own destination (a stored, valid configuration that cannot deliver)", rejected.length === 0);
  // THE FRACTION GATES. Until this line the census PRINTED 11 of 18 and exited 0, which is the shape the whole
  // finding is about: an instrument that grades and then declines to refuse leaves the defect on main with a
  // green tick beside it. A SUBSTITUTED pair is customer data written in a format the customer did not choose,
  // so it is a failure, not an observation.
  ok(`every deliverable pair ROUND-TRIPS (${roundTrip.length} of ${pairs.length}); a SUBSTITUTED pair is customer data stored in a format the customer did not choose`, substituted.length === 0);

  console.log(failures === 0 ? "\nDESTINATION-FORMAT DENOMINATOR PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
