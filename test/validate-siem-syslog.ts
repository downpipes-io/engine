// Validates the syslog-over-TLS delivery sink (notify/siem-syslog-sender.ts). cloudflare:sockets cannot
// run under Node, so the sender exposes
// a test hook (__setSyslogConnectForTest) that injects a MOCK connect(); this validator drives that mock and
// asserts the EXACT bytes framed:
//   - the RFC 6587 octet-counting length prefix equals the record's UTF-8 BYTE length (never char length);
//   - each record is a well-formed RFC 5424 record `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG`;
//   - the MSG is EXACTLY the stage-A CEF/LEEF line for that event (the wire matches the http sink byte-for-byte);
//   - THE INJECTION GUARD: a crafted field carrying a newline/CR, the LEEF delimiter, or a forged `<len> ...`
//     framing sequence CANNOT split a frame or inject a second record (N events -> exactly N frames);
//   - no secret rides the syslog wire (the sink carries none; a stray http auth value is never read);
//   - every failure path (a refused concurrency slot, a connect/handshake failure, a write failure, a timeout)
//     returns ok:false with a coarse code, never a throw (so the drain's cursor holds and retries).
// No network, no Durable Object. Run:
//   node test/validate-siem-syslog.ts

import { deliverSiemSyslog, __setSyslogConnectForTest, type SiemSyslogSendResult } from "../src/notify/siem-syslog-sender.ts";
import { shapeCef, shapeLeef, SIEM_PUSH_BATCH_CAP, type PushCursorMeta } from "../src/cron/siem-push-shape.ts";
import { deliverResolvedPush, type ResolvedPushConfig } from "../src/cron/siem-push-pass.ts";
// The engine's own format authority + the syslog subset, so the format-identity block below iterates the real
// union rather than a list transcribed into this test.
import { PUSH_FORMATS, SYSLOG_TLS_FORMAT_SET, SYSLOG_TLS_FORMATS } from "../src/sched/scheduler-do-limits.ts";
import type { AuditEvent } from "../src/admin/audit.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// ---- fixtures ------------------------------------------------------------------------------------------
function fakeEvent(seq: number, overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    seq,
    ts: new Date(1_700_000_000_000 + seq * 1000).toISOString(),
    actorSubject: "https://acct.cloudflareaccess.com|sub-of-owner@example.com",
    actorEmail: "owner@example.com",
    actorMethod: "access",
    sourceIp: "203.0.113.7",
    action: "dest-config-set",
    outcome: "success",
    target: { kind: "access-policy" },
    prevHash: `sha384:${"a".repeat(96)}`,
    hash: `sha384:${"b".repeat(96)}`,
    ...overrides,
  };
}

const META: PushCursorMeta = { afterSeq: 0, nextAfterSeq: 3, headSeq: 3, headHash: "h" };

// ---- a capturing mock connect() (the socket cannot run under Node) --------------------------------------
interface MockCapture {
  address?: { hostname: string; port: number };
  options?: { secureTransport: string; allowHalfOpen: boolean };
  chunks: Uint8Array[];
  opens: number;
  writerClosed: boolean;
  socketClosed: boolean;
}
function freshCapture(): MockCapture {
  return { chunks: [], opens: 0, writerClosed: false, socketClosed: false };
}

// The mock connect signature must match the sender's SyslogConnectFn subset (address, options) -> a socket-like
// object with opened / writable.getWriter() / close(). opts pick a failure mode (a handshake reject, a write
// throw, a synchronous connect throw); the default is a clean open + capture + flush.
type MockConnect = (address: { hostname: string; port: number }, options: { secureTransport: "on"; allowHalfOpen: false }) => {
  readonly opened: Promise<unknown>;
  readonly writable: { getWriter(): { write(c: Uint8Array): Promise<void>; close(): Promise<void> } };
  close(): Promise<void>;
};
function mockConnect(cap: MockCapture, opts?: { failOpen?: boolean; failWrite?: boolean; throwConnect?: boolean; hang?: boolean }): MockConnect {
  return (address, options) => {
    if (opts?.throwConnect === true) throw new Error("connect refused");
    cap.address = address;
    cap.options = options;
    cap.opens++;
    // hang: a genuinely black-holed connection -- `opened` NEVER settles (neither resolves nor rejects),
    // simulating a runtime that does not reject an in-flight await even after the sender calls close() on
    // it. The hard timeout must not depend on that rejection ever happening.
    if (opts?.hang === true) {
      return {
        opened: new Promise<unknown>(() => {}),
        writable: { getWriter: () => ({ write: async (): Promise<void> => {}, close: async (): Promise<void> => {} }) },
        // The socket's own close() ALSO never settles, proving the timeout result does not wait on it
        // (deliverSiemSyslog's teardown is fire-and-forget, never awaited into the returned outcome).
        close: (): Promise<void> => new Promise(() => {}),
      };
    }
    // Defer the reject to a microtask so the sender's `await socket.opened` handler is attached first (no
    // spurious unhandled-rejection). A clean open resolves with a SocketInfo-like value.
    const opened = opts?.failOpen === true ? Promise.resolve().then((): unknown => { throw new Error("tls handshake failed"); }) : Promise.resolve({});
    return {
      opened,
      writable: {
        getWriter: () => ({
          write: async (c: Uint8Array): Promise<void> => {
            if (opts?.failWrite === true) throw new Error("socket write failed");
            cap.chunks.push(c);
          },
          close: async (): Promise<void> => {
            cap.writerClosed = true;
          },
        }),
      },
      close: async (): Promise<void> => {
        cap.socketClosed = true;
      },
    };
  };
}

// ---- the RFC 6587 RECEIVER: read the length prefix, then EXACTLY that many bytes, repeat -----------------
// This is the discriminating parser: it follows ONLY the length prefixes the sender wrote, so a forged
// `<len> ...` sequence or a raw newline embedded in a field is consumed as record CONTENT, never a boundary.
// A miscount (prefix != actual bytes) desynchronises the next read and throws, so a clean N-frame parse is
// itself proof every prefix is exact and the buffer is fully consumed.
function parseOctetFrames(bytes: Uint8Array): Array<{ len: number; record: string }> {
  const dec = new TextDecoder();
  const frames: Array<{ len: number; record: string }> = [];
  let i = 0;
  while (i < bytes.length) {
    let j = i;
    while (j < bytes.length && bytes[j] !== 0x20) j++; // ASCII digits up to the SP
    if (j >= bytes.length) throw new Error("octet frame: no space after the length prefix");
    const lenStr = dec.decode(bytes.slice(i, j));
    if (!/^[0-9]+$/.test(lenStr)) throw new Error(`octet frame: non-numeric length prefix ${JSON.stringify(lenStr)} (framing desynchronised)`);
    const len = Number(lenStr);
    const start = j + 1;
    const end = start + len;
    if (end > bytes.length) throw new Error("octet frame: the declared length overruns the buffer");
    frames.push({ len, record: dec.decode(bytes.slice(start, end)) });
    i = end;
  }
  return frames;
}

function concatChunks(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}
const utf8Len = (s: string): number => new TextEncoder().encode(s).length;

// RFC 5424 record shape: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`. The first six
// post-version fields are space-free (\S+); MSG is the remainder (a CEF/LEEF line carries spaces). The header
// fields are our FIXED identifiers, never event-derived, so this reliably splits header from MSG for any MSG.
const RFC5424 = /^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (.+)$/;
// expectedSev mirrors the sender's syslogSeverity (failed 3 / denied 4 / else 6); PRI = facility 13*8 + sev.
const expectedSev = (outcome: string): number => (outcome === "failed" ? 3 : outcome === "denied" ? 4 : 6);
const PRI_BASE = 13 * 8;

// assertRecord checks one framed record against its source event for a given format (cef|leef): the length
// prefix equals the record's byte length, the record is well-formed RFC 5424 with our fixed header fields and
// the correct PRI, and the MSG is EXACTLY the stage-A shaper's line for that event.
function assertRecord(label: string, frame: { len: number; record: string }, e: AuditEvent, format: "cef" | "leef"): void {
  ok(`${label}: the RFC 6587 length prefix equals the record's UTF-8 byte length`, frame.len === utf8Len(frame.record));
  ok(`${label}: the framed record carries NO raw CR/LF (the record boundary cannot be inside it)`, !/[\r\n]/.test(frame.record));
  const m = RFC5424.exec(frame.record);
  ok(`${label}: the record is a well-formed RFC 5424 record`, m !== null);
  if (!m) return;
  const [, pri, ts, host, app, procid, msgid, sd, msg] = m as unknown as [string, string, string, string, string, string, string, string, string];
  ok(`${label}: HOSTNAME/APP-NAME/PROCID/MSGID/STRUCTURED-DATA are the fixed identifiers`, host === "downpipes" && app === "downpipe-engine" && procid === "-" && msgid === "audit" && sd === "-");
  ok(`${label}: PRI = facility 13*8 + the outcome-derived severity`, Number(pri) === PRI_BASE + expectedSev(e.outcome));
  ok(`${label}: TIMESTAMP is a valid RFC 3339 timestamp`, Number.isFinite(Date.parse(ts)));
  const expectedMsg = format === "leef" ? shapeLeef([e], META).body : shapeCef([e], META).body;
  ok(`${label}: the MSG is EXACTLY the stage-A ${format.toUpperCase()} line for this event`, msg === expectedMsg);
}

async function main(): Promise<void> {
  try {
    console.log("CEF over syslog-tls: batch framing (implicit TLS on 6514; one RFC 5424 record per event, octet-counted)");
    {
      const events = [fakeEvent(101, { outcome: "success" }), fakeEvent(102, { outcome: "failed" }), fakeEvent(103, { outcome: "denied" })];
      const cap = freshCapture();
      __setSyslogConnectForTest(mockConnect(cap));
      const r = await deliverSiemSyslog("siem.example.com", 6514, "cef", events, META);
      ok("cef delivery reports ok:true after the batch is written+flushed", r.ok === true && r.code === undefined);
      ok("exactly one socket opened, the writer closed (flush) and the socket closed", cap.opens === 1 && cap.writerClosed === true && cap.socketClosed === true);
      ok("implicit TLS (secureTransport on, half-open off) to host:6514", cap.options?.secureTransport === "on" && cap.options?.allowHalfOpen === false && cap.address?.hostname === "siem.example.com" && cap.address?.port === 6514);
      ok("the whole batch is written in ONE socket write", cap.chunks.length === 1);
      const wire = concatChunks(cap.chunks);
      ok("the wire carries NO raw CR/LF anywhere (octet-counting adds none; the shaper escaped the MSG)", !/[\r\n]/.test(new TextDecoder().decode(wire)));
      const frames = parseOctetFrames(wire);
      ok("one RFC 6587 frame per event (3 events -> exactly 3 frames), buffer fully consumed", frames.length === 3);
      frames.forEach((f, i) => assertRecord(`cef frame ${i}`, f, events[i]!, "cef"));
      // The three outcomes map to the three distinct syslog severities in the PRI (110 info / 107 error / 108 warn).
      const pris = frames.map((f) => Number(RFC5424.exec(f.record)![1]));
      ok("distinct outcomes yield distinct PRIs (success 110 / failed 107 / denied 108)", pris[0] === 110 && pris[1] === 107 && pris[2] === 108);
    }

    console.log("\nLEEF over syslog-tls: the MSG is the IBM LEEF 2.0 line, framed identically");
    {
      const events = [fakeEvent(201), fakeEvent(202)];
      const cap = freshCapture();
      __setSyslogConnectForTest(mockConnect(cap));
      const r = await deliverSiemSyslog("siem.example.com", 6514, "leef", events, META);
      ok("leef delivery reports ok:true", r.ok === true);
      const frames = parseOctetFrames(concatChunks(cap.chunks));
      ok("one frame per event (2 -> 2)", frames.length === 2);
      frames.forEach((f, i) => assertRecord(`leef frame ${i}`, f, events[i]!, "leef"));
      const firstMsg = (RFC5424.exec(frames[0]!.record) as unknown as [string, string, string, string, string, string, string, string, string])[8];
      ok("the LEEF MSG declares LEEF:2.0 with the '^' delimiter", firstMsg.startsWith("LEEF:2.0|Maelstrom AI|Downpipes|") && firstMsg.includes("|^|"));
    }

    console.log("\noctet-counting counts BYTES, not characters: a multibyte value cannot desynchronise framing");
    {
      // A multibyte target name (e is 2 bytes, the coffee glyph 3 bytes) makes the record's byte length exceed
      // its character length; the length prefix must be the BYTE count or the receiver's framing would break.
      const e = fakeEvent(301, { target: { kind: "downpipe", id: "dp_multibyte", name: "cafeé-☕-prod" } });
      const cap = freshCapture();
      __setSyslogConnectForTest(mockConnect(cap));
      await deliverSiemSyslog("h", 6514, "cef", [e], META);
      const frames = parseOctetFrames(concatChunks(cap.chunks));
      ok("the multibyte batch frames cleanly into exactly one record", frames.length === 1);
      ok("the length prefix equals the UTF-8 BYTE length (strictly greater than the character length here)", frames[0]!.len === utf8Len(frames[0]!.record) && frames[0]!.len > frames[0]!.record.length);
      assertRecord("multibyte cef frame", frames[0]!, e, "cef");
    }

    console.log("\nbatch cap: a batch beyond SIEM_PUSH_BATCH_CAP is capped to exactly that many frames");
    {
      const many = Array.from({ length: SIEM_PUSH_BATCH_CAP + 25 }, (_, i) => fakeEvent(i + 1));
      const cap = freshCapture();
      __setSyslogConnectForTest(mockConnect(cap));
      await deliverSiemSyslog("h", 6514, "cef", many, META);
      const frames = parseOctetFrames(concatChunks(cap.chunks));
      ok("the sender caps the batch at SIEM_PUSH_BATCH_CAP frames even when handed more", frames.length === SIEM_PUSH_BATCH_CAP);
    }

    console.log("\nINJECTION GUARD (the #1 adversarial target): a crafted field cannot split a frame or inject a record");
    {
      // The crafted values carry raw CR/LF (the record-boundary vector), the CEF/LEEF delimiters (| = ^), a
      // FORGED RFC 5424 record header, and a FORGED RFC 6587 length prefix ("11 <13>1 ..." / "999 injected").
      // If any of these could split a frame, the receiver would see MORE than two frames.
      const evil = fakeEvent(1, {
        actorEmail: "attacker=x|\n11 <13>1 2020-01-01T00:00:00Z downpipes downpipe-engine - audit - CEF:0|forged|P|1|inject|n|9|",
        actorSubject: "sub^bad=evil\r\n999 injected",
        sourceIp: "1.2.3.4\n5.6.7.8",
        target: { kind: "downpipe", id: "dp^|=\nevil", name: "nm\r\nLEEF:2.0|x^y=z" },
      });
      const benign = fakeEvent(2);

      // CEF: two events -> EXACTLY two frames; each frame's prefix is exact; no raw CR/LF on the wire; the
      // crafted MSG is exactly the shaper's escaped line (its newline is the literal two-char form, not a break).
      {
        const cap = freshCapture();
        __setSyslogConnectForTest(mockConnect(cap));
        await deliverSiemSyslog("h", 6514, "cef", [evil, benign], META);
        const wire = concatChunks(cap.chunks);
        ok("CEF: the crafted CR/LF + forged framing NEVER add a record (2 events -> exactly 2 frames)", parseOctetFrames(wire).length === 2);
        ok("CEF: the entire wire has NO raw CR/LF (the injection guard holds end-to-end)", !/[\r\n]/.test(new TextDecoder().decode(wire)));
        const frames = parseOctetFrames(wire);
        assertRecord("CEF evil frame", frames[0]!, evil, "cef");
        assertRecord("CEF benign frame", frames[1]!, benign, "cef");
      }

      // LEEF: same guarantee (the shaper neutralises the '^'/'='/CR/LF to '_'; the framing counts bytes).
      {
        const cap = freshCapture();
        __setSyslogConnectForTest(mockConnect(cap));
        await deliverSiemSyslog("h", 6514, "leef", [evil, benign], META);
        const wire = concatChunks(cap.chunks);
        ok("LEEF: the crafted delimiter/CR/LF + forged framing NEVER add a record (2 events -> exactly 2 frames)", parseOctetFrames(wire).length === 2);
        ok("LEEF: the entire wire has NO raw CR/LF", !/[\r\n]/.test(new TextDecoder().decode(wire)));
        const frames = parseOctetFrames(wire);
        assertRecord("LEEF evil frame", frames[0]!, evil, "leef");
        assertRecord("LEEF benign frame", frames[1]!, benign, "leef");
      }
    }

    console.log("\nno secret on the wire: the syslog sink carries none, and a stray http auth value is never read");
    {
      // A syslog-tls config with a (nonsensical) http auth value set: the syslog path must ignore it entirely.
      const cfg: ResolvedPushConfig = {
        endpoint: "",
        format: "cef",
        authHeaderName: "Authorization",
        authHeaderValue: "SHOULD-NOT-APPEAR-secret-xyz",
        enabled: true,
        gen: "g",
        sink: "syslog-tls",
        authInUrl: false,
        syslog: { host: "siem.example.com", port: 6514 },
      };
      const cap = freshCapture();
      __setSyslogConnectForTest(mockConnect(cap));
      const r = await deliverResolvedPush(cfg, [fakeEvent(1)], { afterSeq: 0, nextAfterSeq: 1, headSeq: 1, headHash: "h" });
      ok("syslog-tls delivers ok:true through deliverResolvedPush (the drain's real sink dispatch)", r.ok === true);
      const wire = new TextDecoder().decode(concatChunks(cap.chunks));
      ok("no secret rides the syslog wire (a stray http auth header value is never read by the syslog sink)", !wire.includes("SHOULD-NOT-APPEAR-secret-xyz"));
    }

    console.log("\nfailure classes (non-throwing; the cursor holds and the batch retries): connect, handshake, write");
    {
      const capA = freshCapture();
      __setSyslogConnectForTest(mockConnect(capA, { throwConnect: true }));
      const rConnect = await deliverSiemSyslog("h", 6514, "cef", [fakeEvent(1)], META);
      ok("a synchronous connect throw is ok:false 'syslog-connect-refused' (distinct from a TLS-trust failure), never a throw", rConnect.ok === false && rConnect.code === "syslog-connect-refused");

      const capB = freshCapture();
      __setSyslogConnectForTest(mockConnect(capB, { failOpen: true }));
      const rOpen = await deliverSiemSyslog("h", 6514, "cef", [fakeEvent(1)], META);
      ok("a TLS handshake failure (opened rejects) is ok:false 'syslog-tls-untrusted' (an untrusted receiver cert is named, not collapsed into connect-failed), never a throw", rOpen.ok === false && rOpen.code === "syslog-tls-untrusted");
      ok("the socket is still torn down after a handshake failure (best-effort close ran)", capB.socketClosed === true);

      const capC = freshCapture();
      __setSyslogConnectForTest(mockConnect(capC, { failWrite: true }));
      const rWrite = await deliverSiemSyslog("h", 6514, "cef", [fakeEvent(1)], META);
      ok("a socket write failure is ok:false 'syslog-write-failed', never a throw", rWrite.ok === false && rWrite.code === "syslog-write-failed");
    }

    console.log("\nHARD TIMEOUT: a genuinely black-holed connection resolves ok:false 'timeout' WITHOUT depending on close() ever settling");
    {
      // opened NEVER settles and the socket's own close() ALSO never settles (see mockConnect's hang mode):
      // if the bound depended on close() rejecting the in-flight await (the pre-fix behaviour), this call
      // would hang forever. opts.timeoutMs is a tiny override so the test proves the race resolves promptly
      // rather than waiting out the real 5s WEBHOOK_TIMEOUT_MS production bound.
      const capHang = freshCapture();
      __setSyslogConnectForTest(mockConnect(capHang, { hang: true }));
      const started = Date.now();
      const rHang = await deliverSiemSyslog("h", 6514, "cef", [fakeEvent(1)], META, { timeoutMs: 30 });
      const elapsed = Date.now() - started;
      ok("a black-holed connect/write is ok:false 'syslog-timeout-handshake' (the timeout carries its phase), never a hang and never a throw", rHang.ok === false && rHang.code === "syslog-timeout-handshake");
      ok(`the call resolves promptly, bounded by opts.timeoutMs (took ${elapsed}ms against a 30ms budget)`, elapsed < 2000);

      // The SAME hang, but now stalled at the WRITE phase (opened resolves fine, write() never settles):
      // the hard timeout must hold at every phase, not just connect.
      let releaseWrite: () => void = () => {};
      const writeGate = new Promise<void>((res) => { releaseWrite = res; });
      const hangAtWrite: MockConnect = () => ({
        opened: Promise.resolve({}),
        writable: { getWriter: () => ({ write: (): Promise<void> => writeGate, close: async (): Promise<void> => {} }) },
        close: (): Promise<void> => new Promise(() => {}),
      });
      __setSyslogConnectForTest(hangAtWrite);
      const startedWrite = Date.now();
      const rHangWrite = await deliverSiemSyslog("h", 6514, "cef", [fakeEvent(1)], META, { timeoutMs: 30 });
      const elapsedWrite = Date.now() - startedWrite;
      ok("a black-holed WRITE (opened fine, write() never settles) is ALSO a timeout, phase-tagged 'syslog-timeout-write'", rHangWrite.ok === false && rHangWrite.code === "syslog-timeout-write");
      ok(`the write-phase hang also resolves promptly (took ${elapsedWrite}ms against a 30ms budget)`, elapsedWrite < 2000);
      releaseWrite(); // let the gated write settle so it does not leak into a later test as an unhandled promise
    }

    console.log("\nconcurrency cap: the 7th concurrent socket is refused (a defensive valve, not a leak)");
    {
      // A gated mock whose opened resolves only when the test releases it, so six deliveries hold their slots.
      let releaseGate: () => void = () => {};
      const gate = new Promise<void>((res) => {
        releaseGate = res;
      });
      const gatedConnect: MockConnect = () => ({
        opened: gate.then(() => ({})),
        writable: { getWriter: () => ({ write: async (): Promise<void> => {}, close: async (): Promise<void> => {} }) },
        close: async (): Promise<void> => {},
      });
      __setSyslogConnectForTest(gatedConnect);
      const inflight: Promise<SiemSyslogSendResult>[] = [];
      for (let i = 0; i < 6; i++) inflight.push(deliverSiemSyslog("h", 6514, "cef", [fakeEvent(i + 1)], META));
      const seventh = await deliverSiemSyslog("h", 6514, "cef", [fakeEvent(99)], META);
      ok("the 7th concurrent socket is refused by the 6-socket cap (ok:false 'syslog-socket-cap'), never a throw", seventh.ok === false && seventh.code === "syslog-socket-cap");
      releaseGate();
      const settled = await Promise.all(inflight);
      ok("all six in-flight deliveries complete once released (the cap is transient)", settled.every((s) => s.ok === true));
      // The slots are freed: a fresh delivery is admitted again.
      const cap = freshCapture();
      __setSyslogConnectForTest(mockConnect(cap));
      const after = await deliverSiemSyslog("h", 6514, "cef", [fakeEvent(1)], META);
      ok("after the in-flight batch drains, a new delivery is admitted again (slots freed, counter balanced)", after.ok === true);
    }

    console.log("\nempty batch: nothing to send is a clean no-op that opens no socket");
    {
      const cap = freshCapture();
      __setSyslogConnectForTest(mockConnect(cap));
      const r = await deliverSiemSyslog("h", 6514, "cef", [], META);
      ok("an empty batch is ok:true and opens no socket", r.ok === true && cap.opens === 0);
    }

    // ---- THE FORMAT ON THE WIRE IS THE FORMAT THAT WAS CONFIGURED -------------------------------------
    // A destination configured for a format this sink cannot carry must be refused outright, never silently
    // delivered under a substituted format (e.g. shipping CEF bytes while reporting a different format was
    // sent). These assertions check the IDENTITY of the bytes and the absence of any write, not merely
    // whether a send happened.
    //
    // The loop is driven by the engine's own PUSH_FORMATS authority minus SYSLOG_TLS_FORMATS, so a ninth
    // format added to the union is covered here with no edit to this file. The floor under it stops it passing
    // vacuously if that subtraction ever empties.
    console.log("\nformat identity: a format this sink cannot carry is REFUSED, never silently shipped as CEF");
    {
      const notSyslog = PUSH_FORMATS.filter((f) => !SYSLOG_TLS_FORMAT_SET.has(f));
      ok(`there are formats outside the syslog set to check (${notSyslog.length} of ${PUSH_FORMATS.length})`, notSyslog.length >= 6);
      const cefBody = shapeCef([fakeEvent(301)], META).body;
      for (const format of notSyslog) {
        const cap = freshCapture();
        __setSyslogConnectForTest(mockConnect(cap));
        const r = await deliverSiemSyslog("siem.example.com", 6514, format, [fakeEvent(301)], META);
        ok(`${format} over syslog-tls is ok:false 'syslog-format-unsupported', never a delivery`, r.ok === false && r.code === "syslog-format-unsupported");
        ok(`${format} over syslog-tls opens NO socket and writes NO bytes`, cap.opens === 0 && cap.chunks.length === 0);
        // The identity assertion the old behaviour would have failed: nothing resembling a CEF line reached the
        // wire under a format that is not CEF.
        const wire = new TextDecoder().decode(concatChunks(cap.chunks));
        ok(`${format} over syslog-tls puts NO CEF line on the wire (the format is not substituted)`, !wire.includes("CEF:") && wire !== cefBody);
      }
      // The two formats the sink CAN carry still deliver, and each delivers its OWN line, so the refusal above
      // is a discrimination rather than a blanket block.
      for (const format of SYSLOG_TLS_FORMATS) {
        const cap = freshCapture();
        __setSyslogConnectForTest(mockConnect(cap));
        const r = await deliverSiemSyslog("siem.example.com", 6514, format, [fakeEvent(302)], META);
        const frames = parseOctetFrames(concatChunks(cap.chunks));
        ok(`${format} over syslog-tls still delivers, one frame`, r.ok === true && frames.length === 1);
        assertRecord(`${format} identity frame`, frames[0]!, fakeEvent(302), format);
      }
    }
  } finally {
    __setSyslogConnectForTest(null);
  }

  console.log(failures === 0 ? "\nSIEM SYSLOG-TLS SINK VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
