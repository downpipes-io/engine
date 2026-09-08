// Validates that a CERTIFICATE fault on an HTTPS push destination is named as one, and that naming it has not
// blinded the ordinary transport failures beside it.
//
// THE DEFECT. A Splunk Cloud stack serves its HEC ingest port (8088) with Splunk's stock self-signed
// certificate (CN=SplunkServerDefaultCert, issuer CN=SplunkCommonCA) while 443 carries a proper CA-issued
// wildcard. Strict TLS refuses port 8088 before any HTTP is exchanged, so a Downpipes Splunk push destination
// pointed at that stack cannot deliver at all. The engine reported it as network-error: a generic failure with
// no route to the actual cause. Two independent reasons, both measured, both covered here:
//
//   1. Under undici (Node's fetch: every `node test/*.ts` validator and the destsim harness) the thrown object
//      is `TypeError: fetch failed` and the certificate detail is only in `err.cause`
//      (`SELF_SIGNED_CERT_IN_CHAIN` / "self-signed certificate in certificate chain"). classifyNetworkFailure
//      read `${err.name} ${err.message}` alone, so it read "TypeError fetch failed" and matched nothing.
//   2. On workerd, the runtime the engine ships on, there is no text to read at all: the same refusal arrives
//      as `Error: internal error; reference = <id>` and the real cause goes only to the runtime log. So the
//      certificate fault is ALSO determined structurally, by observing that a plain TCP connection to the
//      sink's host and port opens while a TLS one to the same host and port does not.
//
// Both error shapes in this suite are the ones actually observed against that stack, not invented ones.
//
// The suite is two-sided throughout. Every assertion that a fault IS named has a partner asserting that a
// fault that is NOT a certificate problem is still classified as before, and that the probe refuses to guess
// when the observation is ambiguous. A classifier that answered "tls" more often would pass the first half and
// fail the second.
//
// No network: connect() is injected. Run: node test/validate-transport-tls-classification.ts

import { readFileSync } from "node:fs";
import { __setTransportProbeConnectForTest, classifyTransportFault, type ProbeConnectFn } from "../src/notify/transport-probe.ts";
import { classifyNetworkFailure, DELIVERY_FAIL_CODES } from "../src/notify/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// ------------------------------------------------------------------------------------------------------------
// The observed error shapes.
// ------------------------------------------------------------------------------------------------------------

// The LIVE undici shape for the stack's HEC port under strict TLS, reproduced exactly: a bare
// `TypeError: fetch failed` whose cause carries the OpenSSL verdict and its stable code.
function undiciCertRefusal(message: string, code: string): unknown {
  const cause = new Error(message) as Error & { code?: string };
  cause.code = code;
  return new TypeError("fetch failed", { cause });
}
// The workerd shape: no cause, no code, an opaque reference id. The detail exists only in the runtime log.
function workerdOpaque(): unknown {
  return new Error("internal error; reference = 05mekvdrlp4qg1vjqf86q6cb");
}

const HTTPS_HEC = "https://prd-p-ngpjb.splunkcloud.com:8088/services/collector/event";

// installConnect wires a mock connect() whose open/refuse decision is keyed on the TLS flag, so a case can say
// "plain opens, TLS is refused" without any network. It records what the probe asked for.
interface ProbeLog {
  asked: Array<{ hostname: string; port: number; secureTransport: "on" | "off" }>;
  closed: number;
}
function installConnect(decide: (secureTransport: "on" | "off") => "open" | "refuse" | "hang"): ProbeLog {
  const log: ProbeLog = { asked: [], closed: 0 };
  const connect: ProbeConnectFn = (address, options) => {
    log.asked.push({ hostname: address.hostname, port: address.port, secureTransport: options.secureTransport });
    const verdict = decide(options.secureTransport);
    if (verdict === "refuse") {
      return {
        opened: Promise.reject(new Error("proxy request failed, cannot connect to the specified address")),
        close: async () => {
          log.closed++;
        },
      };
    }
    return {
      opened: verdict === "hang" ? new Promise(() => {}) : Promise.resolve(undefined),
      close: async () => {
        log.closed++;
      },
    };
  };
  __setTransportProbeConnectForTest(connect);
  return log;
}

// ------------------------------------------------------------------------------------------------------------

console.log("1. the text classifier reads the whole cause chain, so undici's certificate refusal is named");
ok("the LIVE shape (TypeError: fetch failed / cause SELF_SIGNED_CERT_IN_CHAIN) -> network-tls",
  classifyNetworkFailure(undiciCertRefusal("self-signed certificate in certificate chain", "SELF_SIGNED_CERT_IN_CHAIN")) === "network-tls");
ok("the code alone is enough, so a reworded undici message cannot regress it -> network-tls",
  classifyNetworkFailure(undiciCertRefusal("fetch failed", "SELF_SIGNED_CERT_IN_CHAIN")) === "network-tls");
// THE FLOOR on the loop below: an empty list would assert nothing and still print PASS.
const OPENSSL_CERT_CODES = ["CERT_HAS_EXPIRED", "DEPTH_ZERO_SELF_SIGNED_CERT", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "ERR_TLS_CERT_ALTNAME_INVALID"];
ok(`the OpenSSL code list is populated (got ${OPENSSL_CERT_CODES.length})`, OPENSSL_CERT_CODES.length >= 4);
for (const code of OPENSSL_CERT_CODES) {
  ok(`OpenSSL code ${code} in the cause -> network-tls`, classifyNetworkFailure(undiciCertRefusal("fetch failed", code)) === "network-tls");
}
ok("an AggregateError's members are read too -> network-tls",
  classifyNetworkFailure(new AggregateError([new Error("boom"), undiciCertRefusal("self signed certificate", "SELF_SIGNED_CERT_IN_CHAIN")], "fetch failed")) === "network-tls");
ok("a hostname mismatch is a CERTIFICATE fault, not a DNS one, even though it quotes DNS: altnames",
  classifyNetworkFailure(undiciCertRefusal(`Hostname/IP does not match certificate's altnames: Host: a.example.com. is not in the cert's altnames: DNS:*.b.example.com`, "ERR_TLS_CERT_ALTNAME_INVALID")) === "network-tls");

console.log("2. the general case is NOT blinded");
ok("an unresolvable name in the cause chain is still network-dns",
  classifyNetworkFailure(new TypeError("fetch failed", { cause: Object.assign(new Error("getaddrinfo ENOTFOUND alerts.example.com"), { code: "ENOTFOUND" }) })) === "network-dns");
ok("a refused connection in the cause chain is still network-reset",
  classifyNetworkFailure(new TypeError("fetch failed", { cause: Object.assign(new Error("connect ECONNREFUSED 203.0.113.7:443"), { code: "ECONNREFUSED" }) })) === "network-reset");
ok("the pre-existing top-level spellings still classify (an unresolved name)", classifyNetworkFailure(new Error("getaddrinfo ENOTFOUND alerts.example.com")) === "network-dns");
ok("the pre-existing top-level spellings still classify (a certificate fault)", classifyNetworkFailure(new Error("unable to verify the first certificate")) === "network-tls");
ok("the pre-existing top-level spellings still classify (a reset)", classifyNetworkFailure(new Error("read ECONNRESET")) === "network-reset");
ok("workerd's own wording for a lost or refused connection is now named: network-reset",
  classifyNetworkFailure(new Error("Network connection lost.")) === "network-reset");
ok("an unrecognised transport fault still falls to the residual network-error", classifyNetworkFailure(new Error("something odd happened")) === "network-error");
ok("workerd's OPAQUE internal error is honestly left in the residual by the TEXT classifier", classifyNetworkFailure(workerdOpaque()) === "network-error");
ok("a null/undefined/number throw does not crash the classifier and lands in the residual",
  classifyNetworkFailure(null) === "network-error" && classifyNetworkFailure(undefined) === "network-error" && classifyNetworkFailure(7) === "network-error");
ok("a CYCLIC cause chain terminates", (() => {
  const a = new Error("outer") as Error & { cause?: unknown };
  const b = new Error("inner") as Error & { cause?: unknown };
  a.cause = b;
  b.cause = a;
  return classifyNetworkFailure(a) === "network-error";
})());
ok("every code the classifier can return is in the CLOSED allow-list",
  ["network-tls", "network-dns", "network-reset", "network-error"].every((c) => DELIVERY_FAIL_CODES.has(c)));
ok("REDACTION: the verdict is the enum member only, never any of the text it read",
  !/splunk|certificate|SELF_SIGNED|reference/i.test(classifyNetworkFailure(undiciCertRefusal("self-signed certificate in certificate chain", "SELF_SIGNED_CERT_IN_CHAIN"))));

console.log("3. the structural probe names the certificate fault workerd will not describe");
{
  // The measured stack behaviour: 8088 plain opens, 8088 TLS is refused.
  const log = installConnect((tls) => (tls === "on" ? "refuse" : "open"));
  const verdict = await classifyTransportFault(workerdOpaque(), HTTPS_HEC);
  ok("plain opens and TLS is refused -> network-tls, from an error that carried no text at all", verdict === "network-tls");
  ok("the probe asked about the SINK's own host and port, not a default", log.asked.every((a) => a.hostname === "prd-p-ngpjb.splunkcloud.com" && a.port === 8088));
  ok("the probe made exactly the two observations, plain then TLS", log.asked.length === 2 && log.asked[0]?.secureTransport === "off" && log.asked[1]?.secureTransport === "on");
  ok("both probe sockets were closed", log.closed === 2);
}
{
  // The measured 443 behaviour: a sound chain opens both ways, so nothing is claimed.
  const log = installConnect(() => "open");
  ok("plain AND TLS both open -> no claim, the residual stands", (await classifyTransportFault(workerdOpaque(), "https://prd-p-ngpjb.splunkcloud.com/services/collector/event")) === "network-error");
  ok("a sound chain still costs both observations and closes both", log.asked.length === 2 && log.closed === 2);
}
{
  // The measured closed-port behaviour: neither opens. The socket layer cannot tell a firewall from a bad name,
  // so the probe refuses to guess rather than blaming the certificate.
  const log = installConnect(() => "refuse");
  ok("nothing opens -> the probe does NOT claim a certificate fault", (await classifyTransportFault(workerdOpaque(), "https://prd-p-ngpjb.splunkcloud.com:9998/x")) === "network-error");
  ok("a plain connection that failed stops the probe before it opens a TLS one", log.asked.length === 1 && log.asked[0]?.secureTransport === "off");
}
{
  const log = installConnect((tls) => (tls === "on" ? "hang" : "open"));
  const started = Date.now();
  ok("a TLS connection that never settles is bounded, and refusing to open counts as refused -> network-tls",
    (await classifyTransportFault(workerdOpaque(), HTTPS_HEC)) === "network-tls");
  ok("the bound is well under the 5s send timeout", Date.now() - started < 4500);
  ok("the hung socket was still closed", log.closed === 2);
}

console.log("4. the probe is only reached where it belongs");
{
  const log = installConnect((tls) => (tls === "on" ? "refuse" : "open"));
  ok("a fault the TEXT already named is returned unchanged, with NO probe egress",
    (await classifyTransportFault(undiciCertRefusal("getaddrinfo ENOTFOUND x.example.com", "ENOTFOUND"), HTTPS_HEC)) === "network-dns" && log.asked.length === 0);
}
{
  const log = installConnect((tls) => (tls === "on" ? "refuse" : "open"));
  ok("an http:// sink is never probed (there is no certificate to be wrong)",
    (await classifyTransportFault(workerdOpaque(), "http://sink.example.com:8088/x")) === "network-error" && log.asked.length === 0);
}
{
  const log = installConnect((tls) => (tls === "on" ? "refuse" : "open"));
  ok("an INTERNAL sink is never probed, so this cannot become an egress the sender itself would refuse",
    (await classifyTransportFault(workerdOpaque(), "https://127.0.0.1:8088/x")) === "network-error" && log.asked.length === 0);
}
{
  const log = installConnect((tls) => (tls === "on" ? "refuse" : "open"));
  ok("an unparseable url is never probed", (await classifyTransportFault(workerdOpaque(), "not a url")) === "network-error" && log.asked.length === 0);
}
{
  // No connect() at all: plain Node with nothing injected. The dynamic import fails and the probe stays silent.
  __setTransportProbeConnectForTest(null);
  ok("a runtime with no sockets makes no claim rather than throwing", (await classifyTransportFault(workerdOpaque(), HTTPS_HEC)) === "network-error");
}

console.log("5. the probe cannot carry the payload or the credential");
const probeSrc = readFileSync(new URL("../src/notify/transport-probe.ts", import.meta.url), "utf8");
ok("src/notify/transport-probe.ts is readable and non-trivial", probeSrc.length > 1000);
ok("the probe's socket type exposes no writer, so no payload can travel over it", !/\bwritable\b|getWriter|\bwrite\(/.test(probeSrc));
ok("the probe never sees an auth header or a body", !/authHeader|body|token/i.test(probeSrc.replace(/^\s*\/\/.*$/gm, "")));
const senderSrc = readFileSync(new URL("../src/notify/siem-push-sender.ts", import.meta.url), "utf8");
ok("the push sender routes its transport faults through classifyTransportFault", /classifyTransportFault\(e, url\)/.test(senderSrc));
ok("the push sender still verifies certificates: no fetch option disabling it exists anywhere in the module",
  !/rejectUnauthorized|insecure|skipVerify|NODE_TLS_REJECT/i.test(senderSrc + probeSrc));

console.log(failures === 0 ? "\nTRANSPORT TLS CLASSIFICATION PASS" : `\nTRANSPORT TLS CLASSIFICATION FAIL (${failures})`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
