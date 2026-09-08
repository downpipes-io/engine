// Pins config-time validation of the SIEM/OTLP push AUTH HEADER VALUE.
//
// WHAT THIS PINS: the operator-supplied auth header VALUE (a bearer token / API key) was accepted as any
// string with no length cap and no control-character screen, while the header NAME was strictly validated.
// A value carrying a CR/LF (header-injection shaped) or a pathological length passed config-time and
// surfaced only later as an opaque send-time network-error (undici rejects the header), stranding the
// destination with no clear cause. This validator asserts a control-char or over-long value is REJECTED at
// config time (a clear error), while legitimate token shapes -- including those with spaces like
// "Basic <b64>", "Splunk <token>", "GenieKey <token>" -- are accepted unchanged.
//
// Run: node test/validate-destsim-pushauth.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { isValidPushHeaderValue, PUSH_HEADER_VALUE_MAX_LEN } from "../src/sched/scheduler-do-limits.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

const OWNER_CALLER = { method: "token" as const, email: null, subject: null, groups: [] };

async function rejects(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}

async function main(): Promise<void> {
  // 1. The pure helper: control chars rejected, printable+space accepted, length capped.
  ok("helper: plain bearer token accepted", isValidPushHeaderValue("Bearer abc.def.ghi-123_XYZ"));
  ok('helper: "Basic <b64>" (contains a space) accepted', isValidPushHeaderValue("Basic dXNlcjpwYXNzd29yZA=="));
  ok('helper: "Splunk <token>" (space) accepted', isValidPushHeaderValue("Splunk 11111111-2222-3333-4444-555555555555"));
  ok("helper: CRLF rejected (header injection)", !isValidPushHeaderValue("tok\r\nX-Injected: 1"));
  ok("helper: bare LF rejected", !isValidPushHeaderValue("tok\nevil"));
  ok("helper: bare CR rejected", !isValidPushHeaderValue("tok\revil"));
  ok("helper: NUL rejected", !isValidPushHeaderValue("tok\u0000"));
  ok("helper: DEL (0x7f) rejected", !isValidPushHeaderValue("tok"));
  ok("helper: TAB rejected (no legit auth token carries one)", !isValidPushHeaderValue("tok\tval"));
  ok("helper: empty string is NOT valid (empty is handled as keep-secret upstream, not a value)", !isValidPushHeaderValue(""));
  ok(`helper: value at the ${PUSH_HEADER_VALUE_MAX_LEN} cap accepted`, isValidPushHeaderValue("a".repeat(PUSH_HEADER_VALUE_MAX_LEN)));
  ok("helper: value one over the cap rejected", !isValidPushHeaderValue("a".repeat(PUSH_HEADER_VALUE_MAX_LEN + 1)));

  // 2. DO enforcement (the plaintext no-wrap-key floor): a CRLF value is rejected at set time, not stored.
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    const crlfRejected = await rejects(() =>
      dobj.setSiemPushDestination(
        { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "tok\r\nX-Injected: 1", enabled: true },
        OWNER_CALLER,
      ),
    );
    ok("DO siem-push: CRLF auth value REJECTED at set time", crlfRejected);

    const longRejected = await rejects(() =>
      dobj.setSiemPushDestination(
        { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "a".repeat(PUSH_HEADER_VALUE_MAX_LEN + 100), enabled: true },
        OWNER_CALLER,
      ),
    );
    ok("DO siem-push: over-cap auth value REJECTED at set time", longRejected);

    // A legitimate space-bearing value is accepted and stored.
    const view = await dobj.setSiemPushDestination(
      { endpoint: "https://siem.example.com/ingest", format: "splunk-hec", authHeaderName: "Authorization", authHeaderValue: "Splunk 11111111-2222-3333-4444-555555555555", enabled: true },
      OWNER_CALLER,
    );
    ok("DO siem-push: legitimate 'Splunk <token>' value accepted + stored", view.present === true && view.enabled === true);
  }

  // 3. DO enforcement for the OTLP push destination too.
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    const crlfRejected = await rejects(() =>
      dobj.setOtlpPushDestination(
        { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "DD-API-KEY", authHeaderValue: "key\r\nInject: 1", enabled: true },
        OWNER_CALLER,
      ),
    );
    ok("DO otlp-push: CRLF auth value REJECTED at set time", crlfRejected);

    const view = await dobj.setOtlpPushDestination(
      { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "DD-API-KEY", authHeaderValue: "dd-0123456789abcdef0123456789abcdef", enabled: true },
      OWNER_CALLER,
    );
    ok("DO otlp-push: legitimate API key accepted + stored", view.present === true);
  }

  console.log(failures === 0 ? "\nDESTSIM PUSH AUTH-VALUE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
