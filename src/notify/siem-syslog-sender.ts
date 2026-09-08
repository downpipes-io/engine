// The syslog-over-TLS delivery sink for the SIEM audit-log push destination (design/siem-top20/
// FORMATS-AND-TRANSPORT.md "syslog-TLS sink"). It is the enterprise auto-parse path: QRadar, Microsoft
// Sentinel's built-in DSM and LogRhythm auto-parse CEF/LEEF only over real syslog transport (an RFC 5424
// record over TCP/TLS, port 6514), never a plain HTTPS POST. For each audit event this shapes a CEF or LEEF
// line (reusing the stage-A shapers, so the wire bytes match the http sink exactly), wraps it as one RFC 5424
// record, frames it per RFC 6587 octet-counting, writes the whole batch over ONE implicit-TLS socket, and
// closes. It is NON-THROWING and returns an ok/failure result shaped like the http sender's SiemPushSendResult
// so the drain's recordOutcome path is unchanged; the cursor advances only when the batch is written+flushed.
//
// WHY connect() IS A GUARDED DYNAMIC IMPORT, NOT A TOP-LEVEL `import { connect } from "cloudflare:sockets"`.
// The "cloudflare:sockets" module exists only inside workerd; plain Node (which runs every `node test/
// validate-*.ts` gate script) cannot resolve the specifier. cron/siem-push-pass.ts imports this sender, and
// several Node validators import siem-push-pass.ts, so a top-level static import of "cloudflare:sockets" would
// throw ERR_MODULE_NOT_FOUND at MODULE-LOAD time and turn the whole gate red. FORMATS-AND-TRANSPORT.md's own
// test plan ("the socket cannot run under plain node; validators mock connect()") is only satisfiable if this
// module LOADS under Node, which it can only do without a top-level socket import. So connect() is resolved
// LAZILY at first use via a dynamic import (evaluated only in workerd, where it succeeds), and a test override
// lets the validator inject a mock connect() so the real dynamic import is never reached under Node.

import type { AuditEvent } from "../admin/audit.ts";
import { type PushCursorMeta, SIEM_PUSH_BATCH_CAP, shapeCef, shapeLeef } from "../cron/siem-push-shape.ts";
import { type PushFormat, SYSLOG_TLS_FORMAT_SET, type SYSLOG_TLS_FORMATS } from "../sched/scheduler-do-base.ts";
import { WEBHOOK_TIMEOUT_MS } from "./types.ts";

// SiemSyslogSendResult mirrors the http sender's SiemPushSendResult (notify/siem-push-sender.ts) minus the
// HTTP status (a syslog write has none): ok, plus a coarse failure code on a non-delivery. It carries no
// body, no host, and no secret (the syslog sink holds none), so the drain folds it into a PushDeliveryResult
// exactly as it folds the http sender's result.
export interface SiemSyslogSendResult {
  ok: boolean;
  code?: SyslogFailCode;
  // failedIndex (gap G138) is the BOUNDED, zero-based index of the event whose shaping threw, on a
  // syslog-shape-failed result ONLY. A poison event otherwise blocks the whole batch FOREVER with no pointer
  // to which one it is (the cursor holds, the same batch is re-shaped every tick, and the pack shows only the
  // fixed code). An integer 0..SIEM_PUSH_BATCH_CAP-1 is a position in a batch, never a field value, an actor
  // or an id, so it is redaction-safe by construction. The event's CONTENT is never carried.
  failedIndex?: number;
}

// SyslogFailCode is the CLOSED failure vocabulary of the syslog-TLS sink (gap G138). Three different owners
// each get their own member rather than collapsing onto one string: `syslog-sockets-unsupported` is "our
// runtime has no sockets" (an ENGINE fault: the cloudflare:sockets import failed), `syslog-tls-untrusted` is
// "your receiver's certificate is not trusted" (a CUSTOMER TLS fault: the TLS handshake rejected on
// socket.opened), and `syslog-connect-refused` is "nothing is listening / your firewall dropped us" (a
// CUSTOMER NETWORK fault: connect() threw); the timeout members carry the phase they stalled in.
export type SyslogFailCode =
  | "syslog-sockets-unsupported" // the cloudflare:sockets import failed: the RUNTIME has no TCP sockets (our fault, not theirs)
  | "syslog-tls-untrusted" // socket.opened rejected: the implicit-TLS handshake failed (a self-signed / untrusted / expired receiver cert)
  | "syslog-connect-refused" // connect() threw: nothing accepted the TCP connection (a firewall, a closed port, an unroutable host)
  | "syslog-write-failed" // the socket opened and TLS completed, but the batch write/flush failed mid-stream
  | "syslog-timeout-handshake" // the hard timeout fired while still connecting / completing the TLS handshake
  | "syslog-timeout-write" // the hard timeout fired while writing the framed batch
  | "syslog-timeout-flush" // the hard timeout fired while flushing/closing the write side (bytes may be partially delivered)
  | "syslog-shape-failed" // a (contract-violating) shaper throw on one event: the batch cannot be framed (see failedIndex)
  | "syslog-format-unsupported" // the configured format is not a syslog MSG shape: nothing was sent (see SyslogFormat)
  | "syslog-socket-cap"; // the per-isolate concurrent-socket cap refused the slot

// SYSLOG_FAIL_CODES is the runtime allow-list of the closed vocabulary (defence in depth: the drain folds this
// code into the push trail's `reason`, so only a member may ever reach the pack).
export const SYSLOG_FAIL_CODES: ReadonlySet<string> = new Set<SyslogFailCode>([
  "syslog-sockets-unsupported", "syslog-tls-untrusted", "syslog-connect-refused", "syslog-write-failed",
  "syslog-timeout-handshake", "syslog-timeout-write", "syslog-timeout-flush", "syslog-shape-failed",
  "syslog-format-unsupported", "syslog-socket-cap",
]);

// SyslogFormat is the NARROWED format type everything below the entry point takes: an RFC 5424 record's MSG is
// a CEF or a LEEF line and there is no third shape it can be. It is derived from the engine's own
// SYSLOG_TLS_FORMATS authority (sched/scheduler-do-limits.ts), the same list both config boundaries screen
// against, so the sender and the validators cannot come to hold different ideas of what syslog can carry.
//
// WHY THE TYPE, AND NOT A RUNTIME GUARD FURTHER DOWN. A runtime guard here (`format === "leef" ?
// shapeLeef(...) : shapeCef(...)`) would let every other PushFormat fall into the CEF arm and be DELIVERED AS
// CEF with nothing recording the substitution -- a destination configured splunk-hec over syslog-tls could
// pass both config validators and then ship ArcSight CEF to a Splunk HEC parser. Narrowing the parameter
// makes that fallback a compile error: a new PushFormat member cannot reach this file at all unless someone
// deliberately adds it to SYSLOG_TLS_FORMATS and writes its shaper arm.
export type SyslogFormat = (typeof SYSLOG_TLS_FORMATS)[number];

// isSyslogFormat narrows a configured PushFormat to the two the sink can carry, reading the SAME runtime set
// the router and the DO screen a submission against.
function isSyslogFormat(format: PushFormat): format is SyslogFormat {
  return SYSLOG_TLS_FORMAT_SET.has(format);
}

// The minimal structural surface of a cloudflare:sockets Socket this sender uses. Declaring only what we touch
// (opened / writable / close) keeps the production cast and the test mock small, and decouples the sender from
// the exact workers-types Socket shape.
interface SyslogWriter {
  write(chunk: Uint8Array): Promise<void>;
  close(): Promise<void>;
}
interface SyslogSocket {
  readonly opened: Promise<unknown>;
  readonly writable: { getWriter(): SyslogWriter };
  close(): Promise<void>;
}
// SyslogConnectFn is the connect() subset we depend on: implicit TLS (secureTransport "on") to a host:port,
// half-open disabled so closing the write side tears the whole connection down.
type SyslogConnectFn = (address: { hostname: string; port: number }, options: { secureTransport: "on"; allowHalfOpen: false }) => SyslogSocket;

// connectOverride lets the validator inject a mock connect() (cloudflare:sockets cannot run under Node). It is
// null in production, so resolveConnect() falls through to the real, lazily-imported connect().
let connectOverride: SyslogConnectFn | null = null;

// __setSyslogConnectForTest installs (or clears, with null) the mock connect() the validator drives. Test-only;
// production never calls it, so connectOverride stays null and the real socket path runs.
export function __setSyslogConnectForTest(fn: SyslogConnectFn | null): void {
  connectOverride = fn;
}

// resolveConnect returns the injected mock when set, otherwise lazily imports the real connect() from
// cloudflare:sockets. The dynamic import is evaluated ONLY here, at first real use in workerd; under Node with
// an injected mock it is never reached (so the specifier is never resolved by Node).
async function resolveConnect(): Promise<SyslogConnectFn> {
  if (connectOverride !== null) return connectOverride;
  const mod = await import("cloudflare:sockets");
  return mod.connect as unknown as SyslogConnectFn;
}

// SYSLOG_FACILITY 13 is "log audit" (RFC 5424 table 1), the correct facility for an audit event; the PRI is
// facility*8 + the per-event severity. HOSTNAME/APP-NAME are our fixed identifiers (FORMATS-AND-TRANSPORT.md).
// PROCID is NILVALUE ("-", we have no OS process id); MSGID "audit" names the message class for SIEM filters.
const SYSLOG_FACILITY = 13;
const SYSLOG_HOSTNAME = "downpipes";
const SYSLOG_APPNAME = "downpipe-engine";
const SYSLOG_MSGID = "audit";

// MAX_CONCURRENT_SOCKETS caps concurrently-open outbound sockets per isolate (FORMATS-AND-TRANSPORT.md: cap 6).
// The drain opens exactly one socket per tick (one push destination, one batch), so this is a defensive valve,
// not a hot path: a 7th concurrent attempt is refused (ok:false) rather than opening an unbounded fan of
// sockets. The slot is reserved SYNCHRONOUSLY at the check (no await between the read and the increment), so
// concurrent synchronous callers cannot all slip past a stale count.
const MAX_CONCURRENT_SOCKETS = 6;
let openSocketCount = 0;

// syslogSeverity maps an audit outcome onto the RFC 5424 severity (0-7): a failure is 3 (error), a deny is 4
// (warning), a success/info is 6 (info). This is the SAME info/warning/error scale the GELF level uses; it is
// the syslog PRI's severity half (distinct from the 0-10 CEF/LEEF severity the MSG line already carries).
function syslogSeverity(outcome: string): number {
  if (outcome === "failed") return 3;
  if (outcome === "denied") return 4;
  return 6;
}

// buildSyslogRecord wraps one CEF/LEEF line as an RFC 5424 record: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID
// MSGID STRUCTURED-DATA MSG`, with STRUCTURED-DATA NILVALUE ("-") and MSG the shaped line. The MSG is produced
// by the stage-A shaper (LEEF for the leef format, CEF for everything else, since only CEF/LEEF ride the
// enterprise auto-parse path), so the injection guard is inherited: the shaper has already escaped/neutralised
// any CR/LF, `=`, `^` or `|` in a crafted field, so the MSG carries no raw record boundary. TIMESTAMP is
// re-rendered from the event's parsed epoch-ms via Date#toISOString (a canonical, space-free, control-free
// RFC 3339 string RFC 5424 accepts directly); a malformed ts falls back to now, never a NaN timestamp.
function buildSyslogRecord(format: SyslogFormat, e: AuditEvent, meta: PushCursorMeta): string {
  const msg = format === "leef" ? shapeLeef([e], meta).body : shapeCef([e], meta).body;
  const parsed = Date.parse(e.ts);
  const ms = Number.isFinite(parsed) ? parsed : Date.now();
  const timestamp = new Date(ms).toISOString();
  const pri = SYSLOG_FACILITY * 8 + syslogSeverity(e.outcome);
  return `<${pri}>1 ${timestamp} ${SYSLOG_HOSTNAME} ${SYSLOG_APPNAME} - ${SYSLOG_MSGID} - ${msg}`;
}

// frameBatch renders the whole batch to wire bytes: for each event, one RFC 5424 record framed per RFC 6587
// octet-counting as `<octet-length> <record>`, where octet-length is the record's UTF-8 BYTE length (never its
// character length, so a multibyte value cannot desynchronise the receiver's framing). Records are
// concatenated with no separator (octet-counting needs none, and the IESG discourages the newline-trailer
// form). Octet-counting is itself an injection guard: the receiver reads EXACTLY octet-length bytes, so a
// newline or a forged `<len> ...` sequence embedded in a field is consumed as record content, never a new
// frame. Pure (no I/O), so the validator drives it without a socket.
function frameBatch(format: SyslogFormat, events: AuditEvent[], meta: PushCursorMeta): Uint8Array {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (const e of events) {
    const recordBytes = enc.encode(buildSyslogRecord(format, e, meta));
    const prefix = enc.encode(`${recordBytes.length} `);
    parts.push(prefix, recordBytes);
    total += prefix.length + recordBytes.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

// findShapeFailureIndex re-shapes the batch ONE EVENT AT A TIME to find the first event whose shaping throws,
// and returns its bounded, zero-based index (undefined if the per-event walk finds none, i.e. the fault was in
// the concatenation itself). Pure (no I/O), bounded by the batch cap, and it returns ONLY a position: the
// offending event's action, actor, target and values are never read, never returned and never logged.
function findShapeFailureIndex(format: SyslogFormat, events: AuditEvent[], meta: PushCursorMeta): number | undefined {
  for (let i = 0; i < events.length; i++) {
    try {
      frameBatch(format, [events[i]!], meta);
    } catch {
      return i;
    }
  }
  return undefined;
}

// safeClose tears a socket down best-effort. A close after the writer already closed the (half-open-disabled)
// connection may reject; that is swallowed so teardown never turns a successful write into a failure.
async function safeClose(socket: SyslogSocket): Promise<void> {
  try {
    await socket.close();
  } catch {
    // best-effort: the connection is already going away.
  }
}

// deliverSiemSyslog shapes the batch to CEF/LEEF, frames it per RFC 6587, and writes it over ONE implicit-TLS
// socket, then closes. It NEVER throws: a shaping fault, a refused concurrency slot, a connect/handshake
// failure, a write failure or a timeout all return ok:false with a coarse code (the cursor then holds and the
// batch retries next tick, exactly like an http non-2xx). ok:true is returned only after writer.close()
// resolves, i.e. the batch was written AND flushed, so the drain advances the cursor only on a real delivery.
// opts.timeoutMs overrides the hard bound (default WEBHOOK_TIMEOUT_MS); only a validator supplies it, to
// drive the timeout path in milliseconds rather than waiting out the real 5s production bound.
export async function deliverSiemSyslog(host: string, port: number, format: PushFormat, events: AuditEvent[], meta: PushCursorMeta, opts?: { timeoutMs?: number }): Promise<SiemSyslogSendResult> {
  const capped = events.slice(0, SIEM_PUSH_BATCH_CAP);
  if (capped.length === 0) return { ok: true };

  // Refuse a format this sink cannot carry BEFORE any bytes are built and before any socket is opened, and say
  // so in the closed vocabulary. Both config boundaries already refuse the combination (pushSinkFormatError),
  // so reaching this line means a record stored before that rule existed, or a caller bypassing them; either
  // way the honest outcome is a named non-delivery the trail can show, never a silent substitution of CEF.
  if (!isSyslogFormat(format)) return { ok: false, code: "syslog-format-unsupported" };

  // Build the wire bytes BEFORE touching the network: shaping is pure over redaction-safe fields, and a
  // (contract-violating) shape fault must not leave a socket dangling.
  let payload: Uint8Array;
  try {
    payload = frameBatch(format, capped, meta);
  } catch {
    // A poison event blocks the WHOLE batch every tick until it is found. Re-shape event-by-event to name its
    // bounded INDEX (gap G138) so support can point at it remotely instead of "syslog-shape-failed, forever".
    // The isolation walk is pure and bounded by the batch cap, and only ever yields an integer position; the
    // offending event's fields are never read out of it.
    const failedIndex = findShapeFailureIndex(format, capped, meta);
    return { ok: false, code: "syslog-shape-failed", ...(failedIndex !== undefined ? { failedIndex } : {}) };
  }

  // Reserve a concurrency slot synchronously (the check and the increment share no await), so the cap holds
  // even under concurrent synchronous callers.
  if (openSocketCount >= MAX_CONCURRENT_SOCKETS) return { ok: false, code: "syslog-socket-cap" };
  openSocketCount++;
  try {
    let connectFn: SyslogConnectFn;
    try {
      connectFn = await resolveConnect();
    } catch {
      // The cloudflare:sockets import itself failed: the RUNTIME cannot open a TCP socket at all. That is an
      // ENGINE-side fault, not a customer firewall or certificate -- it must never read as "connect failed".
      return { ok: false, code: "syslog-sockets-unsupported" };
    }
    let socket: SyslogSocket;
    try {
      socket = connectFn({ hostname: host, port }, { secureTransport: "on", allowHalfOpen: false });
    } catch {
      // connect() threw synchronously: nothing accepted the connection (a firewall, a closed 6514, an
      // unroutable host). Distinct from a TLS-trust failure, which surfaces on socket.opened below.
      return { ok: false, code: "syslog-connect-refused" };
    }
    // HARD TIMEOUT (item 8, HARDENING.md): the bound must hold regardless of runtime behaviour,
    // so it cannot depend on socket.close() rejecting an in-flight opened/write/close await -- a black-holed
    // 6514 may never reject any of those even after close() is called (that depends on the runtime actually
    // tearing the connection down promptly, which a genuinely stuck TCP peer need not do). So the write
    // sequence below is raced against a timer that RESOLVES its own timeout outcome directly: whichever
    // settles first wins, and the loser's eventual settlement (if any) is simply ignored (the write sequence
    // never rejects -- it catches everything itself -- so there is nothing to leave unhandled).
    // phase is the IN-SCOPE stage of the socket sequence. It names WHICH stage a hard timeout stalled in
    // (gap G138), and it splits a TLS-trust rejection (handshake) from a mid-stream write failure.
    let phase: "handshake" | "write" | "flush" = "handshake";
    const writeSequence = (async (): Promise<SiemSyslogSendResult> => {
      try {
        await socket.opened;
        phase = "write";
        const writer = socket.writable.getWriter();
        await writer.write(payload);
        // close() flushes any buffered bytes and closes the write side; with allowHalfOpen:false that tears
        // the whole connection down. Its resolution is the "written+flushed successfully" signal the drain
        // gates on.
        phase = "flush";
        await writer.close();
        return { ok: true };
      } catch {
        // socket.opened rejecting IS the implicit-TLS handshake failing: an untrusted / self-signed / expired
        // receiver certificate, the single most common "our QRadar feed never came up" cause.
        return { ok: false, code: phase === "handshake" ? "syslog-tls-untrusted" : "syslog-write-failed" };
      }
    })();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeoutSequence = new Promise<SiemSyslogSendResult>((resolve) => {
      timer = setTimeout(() => resolve({ ok: false, code: phase === "handshake" ? "syslog-timeout-handshake" : phase === "write" ? "syslog-timeout-write" : "syslog-timeout-flush" }), opts?.timeoutMs ?? WEBHOOK_TIMEOUT_MS);
    });
    try {
      return await Promise.race([writeSequence, timeoutSequence]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      // Best-effort, FIRE-AND-FORGET teardown: never awaited here, so a close() that itself never
      // resolves (the same black-holed-runtime possibility the race above defends against) cannot
      // reintroduce the hang this fix removes. safeClose swallows its own rejection either way.
      void safeClose(socket);
    }
  } finally {
    openSocketCount--;
  }
}
