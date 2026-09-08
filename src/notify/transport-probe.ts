// Names a CERTIFICATE fault on a failed HTTPS delivery by OBSERVATION rather than by error text, because on
// the runtime the engine actually ships on the error text does not exist.
//
// THE PROBLEM. classifyNetworkFailure (notify/types.ts) reads a thrown fetch's message and code to split a
// transport failure into dns / tls / reset. That works under Node's undici, where the cause chain carries
// "self-signed certificate in certificate chain". It does not work on workerd: a certificate refusal is handed
// to JavaScript as `Error: internal error; reference = <id>` and the real cause
// (kj/compat/tls.c++: "TLS peer's certificate is not trusted; reason = self signed certificate in certificate
// chain") goes only to the runtime log, which an in-account operator does not read. An unresolvable name
// arrives in that same opaque shape. So on Workers every one of those faults collapsed into network-error, and
// "my Splunk feed does not deliver" came with no route to the cause.
//
// This is a real scenario: a self-signed or otherwise untrusted certificate on a customer's ingest endpoint
// makes strict TLS refuse before any HTTP is exchanged, so a push destination pointed at that endpoint cannot
// deliver at all, and the only thing the operator was told was "network-error".
//
// THE OBSERVATION. The syslog-TLS sink already answers this question without reading any text, and answers it
// on workerd: connect() throwing means nothing accepted the connection, whereas socket.opened rejecting means
// the TLS handshake itself failed (siem-syslog-sender.ts, code syslog-tls-untrusted). The same two facts are
// available for an HTTPS sink. Open a PLAIN TCP connection to the sink's host and port, then open a TLS one:
//   - plain opens AND TLS is refused  -> the host is reachable, the port is listening, and the TLS layer is
//     what rejected us. That is a certificate/handshake fault, positively determined.
//   - anything else                   -> no claim is made, and the text classifier's verdict stands.
//
// THIS IS NOT A WAY TO SKIP VERIFICATION. The probe never carries the payload, never carries the auth header,
// and writes no bytes at all: it opens, observes, closes. Delivery still runs over the ordinary verified
// fetch, and a sink with an untrusted chain still fails. The only thing that changes is that the operator is
// told which thing is broken.
//
// COST AND BOUNDS. It runs only on a delivery that ALREADY failed, only when the text classifier landed on
// the residual, and only for an https sink, so a healthy destination never probes. At most two short-lived
// sockets, each bounded by PROBE_TIMEOUT_MS, both closed unconditionally.

import { classifyNetworkFailure, type DeliveryFailCode, screenSinkHost } from "./types.ts";

// PROBE_TIMEOUT_MS bounds each of the two observations. It is deliberately shorter than the send timeout
// (WEBHOOK_TIMEOUT_MS, 5s): the send has already spent its budget and failed, and a diagnosis that doubles
// the tick's worst case is not worth having. A probe that does not settle in time makes no claim.
const PROBE_TIMEOUT_MS = 2500;

// The minimal structural surface of a cloudflare:sockets Socket this probe uses. It touches `opened` and
// `close()` only, because it never writes: declaring just those keeps the production cast and the test mock
// small, and makes it evident from the type that no payload can travel over a probe socket.
interface ProbeSocket {
  readonly opened: Promise<unknown>;
  close(): Promise<void>;
}

// ProbeConnectFn is the connect() subset depended on: a host:port with TLS either on or off. `off` is the
// reachability observation, `on` is the trust observation, and the pair is the whole diagnosis.
export type ProbeConnectFn = (address: { hostname: string; port: number }, options: { secureTransport: "on" | "off"; allowHalfOpen: false }) => ProbeSocket;

// connectOverride lets a Node validator inject a mock connect(): "cloudflare:sockets" exists only inside
// workerd, and every `node test/*.ts` validator would fail to load this module on a top-level import of it.
// It is null in production, so resolveConnect() falls through to the real, lazily-imported connect(). This is
// the same guarded-dynamic-import discipline siem-syslog-sender.ts uses, for the same reason.
let connectOverride: ProbeConnectFn | null = null;

// __setTransportProbeConnectForTest installs (or clears, with null) the mock connect() a validator drives.
// Test-only; production never calls it, so connectOverride stays null and the real socket path runs.
export function __setTransportProbeConnectForTest(fn: ProbeConnectFn | null): void {
  connectOverride = fn;
}

// resolveConnect returns the injected mock when set, otherwise lazily imports the real connect(). The dynamic
// import is evaluated ONLY here, at first real use in workerd; under Node with a mock installed it is never
// reached, so this module loads and the probe is exercisable off-runtime.
async function resolveConnect(): Promise<ProbeConnectFn> {
  if (connectOverride !== null) return connectOverride;
  const mod = await import("cloudflare:sockets");
  return mod.connect as unknown as ProbeConnectFn;
}

// opens reports whether a connection of the given kind reached the OPEN state inside the bound. It never
// throws and never leaks a socket: a connect() that throws synchronously, an `opened` that rejects, and a
// timeout are all simply "did not open", and close() is best-effort and swallowed either way.
async function opens(connect: ProbeConnectFn, hostname: string, port: number, secureTransport: "on" | "off"): Promise<boolean> {
  let socket: ProbeSocket;
  try {
    socket = connect({ hostname, port }, { secureTransport, allowHalfOpen: false });
  } catch {
    return false;
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const timeout = new Promise<false>((resolve) => {
      timer = setTimeout(() => resolve(false), PROBE_TIMEOUT_MS);
    });
    return await Promise.race([socket.opened.then(() => true, () => false), timeout]);
  } catch {
    return false;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    // Fire-and-forget teardown, never awaited: a close() that itself never settles cannot reintroduce a hang.
    void Promise.resolve(socket.close()).catch(() => {});
  }
}

// probeCertificateFault makes the ONE positive determination this module exists for: it returns true only
// when a plain TCP connection to the sink's host and port OPENS and a TLS connection to the same host and port
// does NOT. Anything else returns false and no claim is made.
//
// It is deliberately one-sided. A plain connection that also fails could be a refused port, a firewall drop or
// an unresolvable name, and the socket layer cannot tell those apart, so naming one of them would be a guess
// dressed as a diagnosis. Only the asymmetry is evidence.
async function probeCertificateFault(hostname: string, port: number): Promise<boolean> {
  let connect: ProbeConnectFn;
  try {
    connect = await resolveConnect();
  } catch {
    // No socket support in this runtime (plain Node with no mock installed). Nothing observed, nothing claimed.
    return false;
  }
  if (!(await opens(connect, hostname, port, "off"))) return false;
  return !(await opens(connect, hostname, port, "on"));
}

// classifyTransportFault is the classifier the egress senders call in place of classifyNetworkFailure when
// they hold the sink url. It runs the pure text classifier first and returns its verdict unchanged whenever
// that verdict is a NAMED cause, so nothing the text classifier already gets right is disturbed and no extra
// egress happens on a fault that is already understood.
//
// Only the residual network-error is probed, and only for an https sink whose host the send-time screen still
// passes (the same screenSinkHost the sender ran before the fetch: an internal or unparseable target is never
// probed, so this cannot become an SSRF or port-scan primitive on a host the sender itself would refuse).
export async function classifyTransportFault(err: unknown, url: string): Promise<Extract<DeliveryFailCode, "network-dns" | "network-tls" | "network-reset" | "network-error">> {
  const named = classifyNetworkFailure(err);
  if (named !== "network-error") return named;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return named;
  }
  if (parsed.protocol !== "https:") return named;
  const screen = screenSinkHost(url);
  if (screen !== "hostname" && screen !== "public-literal") return named;
  const port = parsed.port === "" ? 443 : Number(parsed.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return named;
  return (await probeCertificateFault(parsed.hostname, port)) ? "network-tls" : named;
}
