// validate-egress-host-screen: the internal-host (SSRF) screen on the engine's OWN outbound egress classes,
// graded at the boundary that actually carries the bytes rather than at the boundary that stores the config.
//
// WHY THIS FILE EXISTS. Two egress classes were found unscreened during the ASVS section 4 pass on
// , and neither was disclosed anywhere:
//
//   THE SYSLOG-TLS SIEM SINK had no internal-host screen on ANY boundary. admin/router-push.ts took
//   syslog.host with a non-empty check and nothing else; sched/scheduler-do-siem-push.ts's
//   buildPushSyslogTarget said in a comment that the host was deliberately not refused because "no delivery
//   happens from this stage anyway", and that clause was stale, because notify/siem-syslog-sender.ts calls
//   connect({ hostname: host, port }, { secureTransport: "on" }). A stored host of 169.254.169.254 therefore
//   had a real TLS connection attempted against it, carrying the estate's audit stream.
//
//   THE ARCHIVE DESTINATION ENDPOINT was screened in exactly one place, admin/router-destinations.ts, which
//   screens what an operator SUBMITS. sched/scheduler-do-dest-config.ts's buildDestRecord checked the shape
//   and the https scheme only, so any path into the DO that is not that router stored an endpoint nothing had
//   classified, and dest/s3.ts's fetch chokepoint did no host classification at all. Separately,
//   dest/s3-addressing.ts's requireHttpsEndpoint accepted http://localhost, http://127.0.0.1 and
//   http://[::1] from ANY caller, dest/factory.ts included, so a DEST_ENDPOINT of http://localhost:9000
//   built a live archive destination in a deployed worker and signed the SigV4 credential onto cleartext.
//
// WHAT IS GRADED HERE, and each one is graded where the bytes leave, not only where the value is stored:
//   - deliverSiemSyslog refuses an internal host BEFORE it opens a socket (the mock connect counts opens);
//   - the DO's own push-config build refuses an internal syslog host, so a record cannot be stored;
//   - S3Destination refuses at its single fetch chokepoint, with NO request issued and no meter spend;
//   - the DO's buildDestRecord refuses an internal destination endpoint however the submission arrived;
//   - requireHttpsEndpoint's loopback allowance is reachable only through the explicit test seam;
//   - the obfuscated IPv4 spellings (decimal, hex, IPv4-mapped IPv6) are screened, because the URL parser
//     canonicalises them before the classifier sees them and the wire screen reads the parsed host.
//
// EVERY REFUSAL HAS A DISCRIMINATING CONTROL beside it: a public host must still deliver, still build and
// still fetch. Without those the whole file would pass against a build that refused every egress.
//
// No network. The only doubles are DO storage (MockStorage), a mock syslog connect (cloudflare:sockets
// cannot run under Node) and the s3 suite's fetch stub. Run:
//   node test/validate-egress-host-screen.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { deliverSiemSyslog, SYSLOG_FAIL_CODES, __setSyslogConnectForTest } from "../src/notify/siem-syslog-sender.ts";
import { deliverResolvedPush, type ResolvedPushConfig } from "../src/cron/siem-push-pass.ts";
import { classifyPushRejectReason } from "../src/sched/scheduler-do-siem-push.ts";
import { requireHttpsEndpoint } from "../src/dest/s3-addressing.ts";
import { S3Destination } from "../src/dest/s3.ts";
import { canonicaliseBareHost, isInternalSinkHost } from "../src/notify/types.ts";
import { utf8 } from "../src/crypto/bytes.ts";
import type { PushCursorMeta } from "../src/cron/siem-push-shape.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import type { AuthMethod } from "../src/admin/identity.ts";
import { installFetch, res } from "./validate-s3dest-shared.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// ---- fixtures -------------------------------------------------------------------------------------------

// INTERNAL_HOSTS are the bare hostnames the syslog sink takes (it is given a host, never a URL). The list
// spans the classifier's arms rather than repeating one: link-local cloud metadata, RFC1918, loopback,
// the loopback NAME, IPv6 loopback and IPv6 unique-local.
// The last five are OBFUSCATED SPELLINGS of the first two, and they are here because the screen shipped
// without covering them. isInternalSinkHost documents its own precondition: the URL parser has already
// collapsed decimal, hex, octal and short-form IPv4 to a dotted quad before it runs. The syslog host
// never goes through a URL parser, so that precondition was violated on all three syslog boundaries.
// MEASURED before canonicaliseBareHost existed: isInternalSinkHost("2852039166") returned false and the
// sender opened a socket to it. 2852039166 IS 169.254.169.254, the cloud-metadata address; 2130706433,
// 0x7f000001, 127.1 and 017700000001 are all 127.0.0.1, and dns.lookup resolves every one of them that
// way. A screen with a documented hole reads as covered, which is worse than no screen at all.
const INTERNAL_HOSTS = [
  "169.254.169.254", "10.0.0.5", "127.0.0.1", "localhost", "[::1]", "[fd00::1]",
  "2852039166", "2130706433", "0x7f000001", "127.1", "017700000001",
];

// INTERNAL_ENDPOINTS are https URLs whose host is internal. The last three are the OBFUSCATED IPv4
// spellings: the WHATWG URL parser canonicalises 2130706433 and 0x7f000001 to 127.0.0.1 and collapses the
// IPv4-mapped form, so the screen sees the canonical host. They are here to prove the screen reads the
// PARSED host and not the string an operator typed.
const INTERNAL_ENDPOINTS = [
  "https://169.254.169.254",
  "https://10.0.0.5",
  "https://127.0.0.1:9000",
  "https://[fd00::1]",
  "https://2130706433",
  "https://0x7f000001",
  "https://[::ffff:169.254.169.254]",
];

const PUBLIC_HOST = "siem.example.com";
const PUBLIC_ENDPOINT = "https://s3.example.com";
const META: PushCursorMeta = { afterSeq: 0, nextAfterSeq: 1, headSeq: 1, headHash: "h" };

function fakeEvent(seq: number): AuditEvent {
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
  };
}

// A mock connect() that COUNTS opens and accepts every write. The count is the load-bearing assertion: a
// screen that refuses after connecting has already put a packet on the wire, which is the whole defect.
interface ConnectCount {
  opens: number;
}
function countingConnect(c: ConnectCount): Parameters<typeof __setSyslogConnectForTest>[0] {
  return () => {
    c.opens++;
    return {
      opened: Promise.resolve(),
      writable: { getWriter: () => ({ write: async () => {}, close: async () => {} }) },
      close: async () => {},
    };
  };
}

type Caller = { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null };
// A bare-token caller short-circuits roleForCaller to owner (the break-glass owner the DO trusts).
const OWNER: Caller = { method: "token", email: null, subject: null, groups: [] };

function makeDO(): SchedulerDO {
  return new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
}

async function rejects(fn: () => Promise<unknown>): Promise<string | null> {
  try {
    await fn();
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

function threw(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
}

// ---- 1. the classifier the whole file leans on --------------------------------------------------------
// A FLOOR, not a test of the classifier itself (test/validate-notify-routing.ts owns that): if these were
// false, every refusal below would be measuring the wrong thing and would still print ok.
function classifierFloor(): void {
  console.log("\nthe shared classifier answers as this file assumes:");
  // Canonicalised first, because that is what the three syslog boundaries do and the classifier's own
  // contract requires it. Asserting the raw spelling here would assert the OPPOSITE of the production
  // path and would go red on exactly the obfuscated hosts the fix exists to catch.
  const misread = INTERNAL_HOSTS.filter((h) => !isInternalSinkHost(canonicaliseBareHost(h)));
  ok(`every host this file calls internal IS internal once canonicalised${misread.length > 0 ? ` (misread: ${misread.join(", ")})` : ""}`, misread.length === 0);
  // And the hole that made canonicaliseBareHost necessary stays measured: these five are internal
  // addresses that the classifier alone, without canonicalisation, reads as public.
  const obfuscated = ["2852039166", "2130706433", "0x7f000001", "127.1", "017700000001"];
  const rawMisses = obfuscated.filter((h) => isInternalSinkHost(h) === false);
  ok(`the classifier alone still misreads all ${obfuscated.length} obfuscated spellings, so canonicalising is load-bearing (${rawMisses.length})`, rawMisses.length === obfuscated.length);
  ok("the public control host is NOT internal", isInternalSinkHost(PUBLIC_HOST) === false);
  const parsedInternal = INTERNAL_ENDPOINTS.filter((u) => isInternalSinkHost(new URL(u).hostname));
  ok(`all ${INTERNAL_ENDPOINTS.length} internal endpoints classify internal once parsed (${parsedInternal.length})`, parsedInternal.length === INTERNAL_ENDPOINTS.length);
}

// ---- 2. the syslog-TLS sink refuses at send time, before the socket ------------------------------------
async function syslogSendTime(): Promise<void> {
  console.log("\nsyslog-tls sink, send time (notify/siem-syslog-sender.ts):");
  try {
    for (const host of INTERNAL_HOSTS) {
      const c: ConnectCount = { opens: 0 };
      __setSyslogConnectForTest(countingConnect(c));
      const r = await deliverSiemSyslog(host, 6514, "cef", [fakeEvent(1)], META);
      ok(`${host} is refused with the closed code, never a delivery`, r.ok === false && r.code === "syslog-internal-sink-blocked");
      // THE ASSERTION THE OLD BEHAVIOUR FAILED: no socket was opened at all. Before this screen existed the
      // sender connected first and only the receiver decided what happened next.
      ok(`${host} opens NO socket (opens=${c.opens})`, c.opens === 0);
    }
    ok("the new code is a member of the CLOSED SYSLOG_FAIL_CODES allow-list", SYSLOG_FAIL_CODES.has("syslog-internal-sink-blocked"));

    // DISCRIMINATION: a public host still delivers over the same mock, so the block above is not "the sink
    // stopped working".
    {
      const c: ConnectCount = { opens: 0 };
      __setSyslogConnectForTest(countingConnect(c));
      const r = await deliverSiemSyslog(PUBLIC_HOST, 6514, "cef", [fakeEvent(2)], META);
      ok("CONTROL: a public syslog host still delivers over one socket", r.ok === true && c.opens === 1);
    }
    // THE SEAM: the emulator-driven validators pass allowInternalSink, and only they do. Without this the
    // destination-format census could not drive a real node:tls receiver on 127.0.0.1.
    {
      const c: ConnectCount = { opens: 0 };
      __setSyslogConnectForTest(countingConnect(c));
      const r = await deliverSiemSyslog("127.0.0.1", 6514, "cef", [fakeEvent(3)], META, { allowInternalSink: true });
      ok("the allowInternalSink seam still reaches a loopback receiver", r.ok === true && c.opens === 1);
    }
    // And the seam is opt-in per call: the drain's dispatch (deliverResolvedPush) passes nothing, so the
    // same config refuses through the path production actually uses.
    {
      const c: ConnectCount = { opens: 0 };
      __setSyslogConnectForTest(countingConnect(c));
      const cfg: ResolvedPushConfig = {
        endpoint: "",
        format: "cef",
        authHeaderName: "Authorization",
        authHeaderValue: "",
        enabled: true,
        gen: "g",
        sink: "syslog-tls",
        authInUrl: false,
        syslog: { host: "169.254.169.254", port: 6514 },
      };
      const r = await deliverResolvedPush(cfg, [fakeEvent(4)], META);
      ok("the drain's own dispatch refuses an internal syslog host and opens no socket", r.ok === false && r.reason === "syslog-internal-sink-blocked" && c.opens === 0);
    }
  } finally {
    __setSyslogConnectForTest(null);
  }
}

// ---- 3. the syslog host cannot be STORED either --------------------------------------------------------
async function syslogStoreTime(): Promise<void> {
  console.log("\nsyslog-tls sink, config boundary (sched/scheduler-do-siem-push.ts):");
  for (const host of ["169.254.169.254", "10.0.0.5", "localhost"]) {
    const dobj = makeDO();
    const msg = await rejects(() => dobj.setSiemPushDestination({ format: "cef", sink: "syslog-tls", enabled: true, syslog: { host, port: 6514 } }, OWNER));
    ok(`the DO refuses to store a syslog host of ${host}`, msg !== null && /private\/loopback\/link-local/.test(msg));
    // The refusal must file under an HONEST audit class. Worded without the word "endpoint" it classified as
    // missing-fields, which says a complete submission was incomplete.
    ok(`the ${host} refusal files as endpoint-invalid, not missing-fields`, classifyPushRejectReason(new Error(msg ?? "")) === "endpoint-invalid");
  }
  {
    const dobj = makeDO();
    const view = await dobj.setSiemPushDestination({ format: "cef", sink: "syslog-tls", enabled: true, syslog: { host: PUBLIC_HOST, port: 6514 } }, OWNER);
    ok("CONTROL: a public syslog host still stores", view !== null && view !== undefined);
  }
}

// ---- 4. the archive destination endpoint, at the wire ---------------------------------------------------
async function destinationWireScreen(): Promise<void> {
  console.log("\narchive destination, at the fetch chokepoint (dest/s3.ts metered()):");
  for (const endpoint of INTERNAL_ENDPOINTS) {
    const spent: number[] = [];
    const { captures, restore } = installFetch(() => res(200, { etag: '"x"' }));
    try {
      const dest = new S3Destination(endpoint, "archive-bucket", "us-east-1", "AKIDEXAMPLE", "secret-key", { meter: { spend: (n = 1) => spent.push(n) } });
      const msg = await rejects(() => dest.put("seg/0001", utf8("archive bytes")));
      ok(`${endpoint}: put() is refused`, msg !== null && /internal\/private\/loopback\/link-local/.test(msg));
      // THE ASSERTION THE OLD BEHAVIOUR FAILED: the SigV4-signed request was never issued. A screen that
      // fires after fetch has already handed the destination credential to whatever answered.
      ok(`${endpoint}: NO request was issued (${captures.length})`, captures.length === 0);
      ok(`${endpoint}: the refusal is not billed as a subrequest (${spent.length})`, spent.length === 0);
      const anomalies = dest.destFaults().anomalies ?? {};
      ok(`${endpoint}: the refusal is recorded as endpoint-internal-refused`, anomalies["endpoint-internal-refused"] === 1);
      // Redaction: the fault ring holds the class and the count, never the caller-chosen host.
      ok(`${endpoint}: the refused HOST never enters the fault ring`, !JSON.stringify(dest.destFaults()).includes(new URL(endpoint).hostname));
    } finally {
      restore();
    }
  }
  // DISCRIMINATION: a public endpoint still reaches the wire through the same chokepoint.
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"x"' }));
    try {
      const dest = new S3Destination(PUBLIC_ENDPOINT, "archive-bucket", "us-east-1", "AKIDEXAMPLE", "secret-key", {});
      await dest.put("seg/0001", utf8("archive bytes"));
      ok("CONTROL: a public endpoint still issues its request", captures.length === 1);
    } finally {
      restore();
    }
  }
  // THE SEAM, again opt-in per instance: the census's loopback S3 emulator.
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"x"' }));
    try {
      const dest = new S3Destination("http://127.0.0.1:9000", "archive-bucket", "us-east-1", "AKIDEXAMPLE", "secret-key", { allowInternalEndpoint: true });
      await dest.put("seg/0001", utf8("archive bytes"));
      ok("the allowInternalEndpoint seam still reaches a loopback emulator", captures.length === 1);
    } finally {
      restore();
    }
  }
}

// ---- 5. the archive destination endpoint, at the DO's store boundary -----------------------------------
function destinationStoreScreen(): void {
  console.log("\narchive destination, config boundary (sched/scheduler-do-dest-config.ts buildDestRecord):");
  const dobj = makeDO();
  const config = (endpoint: string): Record<string, unknown> => ({
    endpoint,
    bucket: "archive-x",
    region: "auto",
    accessKeyId: "AKIAEXAMPLE",
    secretAccessKey: "super-secret-value",
  });
  for (const endpoint of INTERNAL_ENDPOINTS) {
    ok(`buildDestRecord refuses ${endpoint} however the submission arrived`, threw(() => dobj.buildDestRecord(config(endpoint), "d1", "label", null)));
  }
  ok("CONTROL: a public https endpoint still builds a record", !threw(() => dobj.buildDestRecord(config("https://acct.r2.cloudflarestorage.com"), "d1", "label", null)));
}

// ---- 6. the loopback allowance is a seam, not a configuration -------------------------------------------
function loopbackSeam(): void {
  console.log("\nrequireHttpsEndpoint's loopback allowance (dest/s3-addressing.ts):");
  for (const endpoint of ["http://localhost:9000", "http://127.0.0.1:9000", "http://[::1]:9000"]) {
    ok(`${endpoint} is refused with no seam (it used to be accepted from any caller)`, threw(() => requireHttpsEndpoint(endpoint)));
    ok(`${endpoint} is accepted WITH the seam`, !threw(() => requireHttpsEndpoint(endpoint, { allowInternalEndpoint: true })));
  }
  ok("CONTROL: an https endpoint needs no seam", !threw(() => requireHttpsEndpoint(PUBLIC_ENDPOINT)));
  ok("the seam does not open cleartext to a public host", threw(() => requireHttpsEndpoint("http://s3.example.com", { allowInternalEndpoint: true })));
}

async function main(): Promise<void> {
  classifierFloor();
  await syslogSendTime();
  await syslogStoreTime();
  await destinationWireScreen();
  destinationStoreScreen();
  loopbackSeam();

  console.log(failures === 0 ? "\nEGRESS HOST SCREEN VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
