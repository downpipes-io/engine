// Validates the destsim EMULATOR ITSELF (test/destsim/server.ts, test/destsim/parsers.ts): a fake
// destination that lies -- silently accepting a corrupted body, silently losing a good one, or
// mis-describing a fault -- is worse than no emulator at all, because it would let a real engine bug sail
// through test/validate-destsim-formats.ts's round-trip assertions unnoticed. This is the house-shape
// chain-entry wrapper; the actual fixtures and live-emulator drives live in test/destsim/self-test.ts
// (runSelfTests), kept separate so it can be imported without pulling in a process.exit(1) side effect.
//
// Covers, independent of the real engine shapers (hand-written fixtures only):
//   - every parser in test/destsim/parsers.ts accepts a small known-good fixture and rejects a
//     deliberately-corrupted one (CEF, LEEF, syslog RFC 5424/6587 framing, Splunk HEC, Datadog, GELF,
//     ndjson, json-array, raw-json, OTLP, Prometheus, plus the six notify-channel JSON shapes);
//   - the live http emulator (test/destsim/server.ts's startEmulator) actually parses+ledgers a good body,
//     400s a bad one without ledgering it, and every documented fault kind (status / malformed-200 /
//     wrong-content-type / partial-success / jsm-202-then-fail / drop-mid-body / stall / flap / afterN
//     pacing) behaves exactly as documented, driven with real fetch() over a real loopback socket;
//   - the ledger's dedupe identity collapses a retried delivery to one entry (bounded-dupes) while two
//     distinct events each get their own (no-loss);
//   - the live syslog-TLS emulator (startSyslogEmulator) is driven through deliverSiemSyslog's own
//     __setSyslogConnectForTest injection point via a REAL node:tls client (makeRealSyslogConnect), proving
//     the sender's exact socket contract over genuine TLS bytes, including its connect-drop/stall faults.
//
// Run: node test/validate-destsim-selftest.ts

import { runSelfTests, type OkFn } from "./destsim/self-test.ts";

let failures = 0;
const ok: OkFn = (label, cond) => {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
};

async function main(): Promise<void> {
  console.log("destsim emulator self-test: parser fixtures + live http/tls emulator behaviour");
  await runSelfTests(ok);

  console.log(failures === 0 ? "\nDESTSIM SELF-TEST PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
