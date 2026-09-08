// Detection-layer vectors for the validate-notify suite (TC-N-01..TC-N-04), split out of
// validate-notify.ts. Covers isAllowedWebhookUrl, classify,
// shouldAlert and buildAlert (the no-custody surface).
//
// TC-N-05 (emitAlerts / postWebhook fail-open) went with the legacy single-webhook policy in P3.2b.
// Its two properties survive on the path that replaced it and are proven there: deliverPayload never
// throws (validate-notify-fault-evidence.ts, where a thrown fetch and a 410 both come back as a closed
// sub-cause) and it RE-SCREENS the sink host at send time against the metadata, RFC1918 and carrier-NAT
// ranges WITHOUT issuing the POST (validate-notify-routing.ts TC-N-11b, which carries TC-N-05's
// globalThis.fetch spy across so the no-POST half is proven, not inferred from a result shape).

import {
  isAllowedWebhookUrl,
  classify,
  shouldAlert,
  buildAlert,
  type MinRun,
} from "../src/notify.ts";
import { ok, makeDI, NOW, ONE_HOUR_AGO, STALE_THRESHOLD_MS, staleStart, freshStart } from "./validate-notify-shared.ts";

// ---- TC-N-01: isAllowedWebhookUrl -----------------------------------------------------------
// Split into focused sub-tests: scheme/shape acceptance, userinfo
// rejection, private-range default-deny, and the explicit per-channel override.

// schemes and shape: https accepted, http/workers.dev/oversized/non-string/empty/unparseable rejected.
async function testAllowedWebhookUrlSchemes(): Promise<void> {
  {
    const r = isAllowedWebhookUrl("https://hooks.example.com/alert");
    ok("isAllowedWebhookUrl: valid https url is ok", r.ok === true);
  }
  {
    const r = isAllowedWebhookUrl("http://hooks.example.com/alert");
    ok("isAllowedWebhookUrl: http rejected", r.ok === false);
    if (!r.ok) ok("isAllowedWebhookUrl: http reason mentions https", r.reason.includes("https"));
  }
  {
    const r = isAllowedWebhookUrl("https://my-worker.workers.dev/notify");
    ok("isAllowedWebhookUrl: workers.dev rejected", r.ok === false);
    if (!r.ok) ok("isAllowedWebhookUrl: workers.dev reason is present", r.reason.length > 0);
  }
  {
    const r = isAllowedWebhookUrl("https://sub.my-worker.workers.dev/alert");
    ok("isAllowedWebhookUrl: workers.dev subdomain rejected", r.ok === false);
  }
  {
    const long = "https://example.com/" + "a".repeat(2048);
    const r = isAllowedWebhookUrl(long);
    ok("isAllowedWebhookUrl: oversized url rejected", r.ok === false);
    if (!r.ok) ok("isAllowedWebhookUrl: length cap reason present", r.reason.includes("long"));
  }
  ok("isAllowedWebhookUrl: non-string rejected", isAllowedWebhookUrl(42).ok === false);
  ok("isAllowedWebhookUrl: whitespace-only rejected", isAllowedWebhookUrl("   ").ok === false);
  ok("isAllowedWebhookUrl: unparseable url rejected", isAllowedWebhookUrl("not a url at all").ok === false);
}

// userinfo: any embedded credentials are rejected; a path-token url (no userinfo) passes.
async function testAllowedWebhookUrlUserinfo(): Promise<void> {
  {
    const r = isAllowedWebhookUrl("https://user@hooks.example.com/alert");
    ok("isAllowedWebhookUrl: userinfo (username only) rejected", r.ok === false);
    if (!r.ok) ok("isAllowedWebhookUrl: userinfo reason mentions userinfo", r.reason.includes("userinfo"));
  }
  {
    const r = isAllowedWebhookUrl("https://user:pass@hooks.example.com/alert");
    ok("isAllowedWebhookUrl: userinfo (user:pass) rejected", r.ok === false);
    if (!r.ok) ok("isAllowedWebhookUrl: userinfo user:pass reason present", r.reason.length > 0);
  }
  {
    const r = isAllowedWebhookUrl("https://hooks.slack.com/services/T000/B000/xxxxxxxxxxxx");
    ok("isAllowedWebhookUrl: path-token url (no userinfo) is ok", r.ok === true);
  }
}

// private ranges (SSRF default-deny): metadata, RFC1918, loopback, link-local,
// IPv6 loopback/ULA/link-local, localhost names and obfuscated IPv4 spellings are all denied; a public
// IP literal and an ordinary public host are allowed.
async function testAllowedWebhookUrlPrivateRanges(): Promise<void> {
  {
    const r = isAllowedWebhookUrl("https://169.254.169.254/latest/meta-data/");
    ok("isAllowedWebhookUrl: 169.254.169.254 cloud-metadata IP rejected by default", r.ok === false);
    if (!r.ok) ok("isAllowedWebhookUrl: metadata reject reason mentions private/metadata", /private|metadata|loopback|link-local/i.test(r.reason));
  }
  ok("isAllowedWebhookUrl: RFC1918 10/8 literal rejected by default", isAllowedWebhookUrl("https://10.0.0.5/ingest").ok === false);
  ok("isAllowedWebhookUrl: 127.0.0.1 loopback rejected by default", isAllowedWebhookUrl("https://127.0.0.1/h").ok === false);
  ok("isAllowedWebhookUrl: 172.16/12 rejected by default", isAllowedWebhookUrl("https://172.16.5.9/h").ok === false);
  ok("isAllowedWebhookUrl: 172.31/12 (top of range) rejected by default", isAllowedWebhookUrl("https://172.31.255.255/h").ok === false);
  ok("isAllowedWebhookUrl: 172.15 (BELOW range) is public -> allowed", isAllowedWebhookUrl("https://172.15.0.1/h").ok === true);
  ok("isAllowedWebhookUrl: 172.32 (ABOVE range) is public -> allowed", isAllowedWebhookUrl("https://172.32.0.1/h").ok === true);
  ok("isAllowedWebhookUrl: 192.168/16 rejected by default", isAllowedWebhookUrl("https://192.168.1.1/h").ok === false);
  ok("isAllowedWebhookUrl: localhost name rejected by default", isAllowedWebhookUrl("https://localhost/h").ok === false);
  ok("isAllowedWebhookUrl: *.localhost name rejected by default", isAllowedWebhookUrl("https://foo.localhost/h").ok === false);
  ok("isAllowedWebhookUrl: trailing-dot localhost. rejected by default", isAllowedWebhookUrl("https://localhost./h").ok === false);
  ok("isAllowedWebhookUrl: ::1 IPv6 loopback rejected by default", isAllowedWebhookUrl("https://[::1]/h").ok === false);
  ok("isAllowedWebhookUrl: fe80 link-local IPv6 rejected by default", isAllowedWebhookUrl("https://[fe80::1]/h").ok === false);
  ok("isAllowedWebhookUrl: fc00::/7 unique-local IPv6 rejected by default", isAllowedWebhookUrl("https://[fd00::1]/h").ok === false);
  ok("isAllowedWebhookUrl: ::ffff:10.0.0.1 IPv4-mapped IPv6 rejected by default", isAllowedWebhookUrl("https://[::ffff:10.0.0.1]/h").ok === false);
  // Obfuscated IPv4 spellings collapse to the canonical quad via the URL parser and are still caught.
  ok("isAllowedWebhookUrl: decimal-IP spelling of 127.0.0.1 rejected by default", isAllowedWebhookUrl("https://2130706433/h").ok === false);
  ok("isAllowedWebhookUrl: hex-IP spelling of 127.0.0.1 rejected by default", isAllowedWebhookUrl("https://0x7f000001/h").ok === false);
  // A PUBLIC IP literal is NOT internal and is allowed by default (the deny-list is private-only).
  ok("isAllowedWebhookUrl: public IP literal allowed by default", isAllowedWebhookUrl("https://203.0.113.10/h").ok === true);
  ok("isAllowedWebhookUrl: ordinary public host still allowed", isAllowedWebhookUrl("https://siem.example.com/ingest").ok === true);
}

// override: the same internal targets are allowed only with the explicit per-channel override.
async function testAllowedWebhookUrlOverride(): Promise<void> {
  const meta = isAllowedWebhookUrl("https://169.254.169.254/x", { allowInternalSink: true });
  ok("isAllowedWebhookUrl: metadata IP allowed WITH allowInternalSink override", meta.ok === true);
  const rfc = isAllowedWebhookUrl("https://10.0.0.5/ingest", { allowInternalSink: true });
  ok("isAllowedWebhookUrl: RFC1918 allowed WITH allowInternalSink override", rfc.ok === true);
  const lo = isAllowedWebhookUrl("https://127.0.0.1/h", { allowInternalSink: true });
  ok("isAllowedWebhookUrl: loopback allowed WITH allowInternalSink override", lo.ok === true);
}

// ---- TC-N-02: classify -----------------------------------------------------------------
// Split into the no-alert/failed-precedence group and the
// staleness-window group.

// no-alert and failed precedence: disabled/empty/in-flight return null; a failed resolved run wins
// over a prior ok run and is not hidden by a later in-flight row.
async function testClassifyPrecedence(): Promise<void> {
  {
    const di = makeDI({
      enabled: false,
      history: [{ runId: "r1", startedAt: staleStart(), status: "failed" }],
    });
    ok("classify: disabled -> null (never alert)", classify(di, NOW) === null);
  }
  {
    const di = makeDI({ history: [] });
    ok("classify: empty history -> null (pending)", classify(di, NOW) === null);
  }
  {
    const di = makeDI({ history: [{ runId: "r1", startedAt: freshStart(), status: "in-flight" }] });
    ok("classify: in-flight only -> null", classify(di, NOW) === null);
  }
  {
    const di = makeDI({ history: [{ runId: "r1", startedAt: freshStart(), status: "failed" }] });
    ok("classify: last resolved failed -> 'failed'", classify(di, NOW) === "failed");
  }
  {
    const di = makeDI({
      history: [
        { runId: "r0", startedAt: staleStart(), status: "ok" },
        { runId: "r1", startedAt: freshStart(), status: "failed" },
      ],
    });
    ok("classify: failed after ok -> 'failed' (not stale)", classify(di, NOW) === "failed");
  }
  {
    const di = makeDI({
      history: [
        { runId: "r1", startedAt: freshStart(), status: "failed" },
        { runId: "r2", startedAt: freshStart(), status: "in-flight" },
      ],
    });
    ok("classify: in-flight after failed -> still 'failed'", classify(di, NOW) === "failed");
  }
}

// staleness window: a fresh ok run is healthy; an old ok run is stale; the boundary and an
// unparseable timestamp are conservative (null); a failed run after a stale ok run still wins.
async function testClassifyStaleness(): Promise<void> {
  {
    const di = makeDI({ history: [{ runId: "r1", startedAt: freshStart(), status: "ok" }] });
    ok("classify: fresh ok -> null", classify(di, NOW) === null);
  }
  {
    const di = makeDI({ history: [{ runId: "r1", startedAt: staleStart(), status: "ok" }] });
    ok("classify: stale ok -> 'stale'", classify(di, NOW) === "stale");
  }
  {
    const justFreshStart = new Date(NOW - STALE_THRESHOLD_MS + 5000).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
    const di = makeDI({ history: [{ runId: "r1", startedAt: justFreshStart, status: "ok" }] });
    ok("classify: just-inside stale window -> null (not stale)", classify(di, NOW) === null);
  }
  {
    const di = makeDI({ history: [{ runId: "r1", startedAt: "not-a-date", status: "ok" }] });
    ok("classify: unparseable startedAt on ok run -> null (no false positive)", classify(di, NOW) === null);
  }
  {
    const di = makeDI({
      history: [
        { runId: "r1", startedAt: staleStart(), status: "ok" },
        { runId: "r2", startedAt: freshStart(), status: "failed" },
      ],
    });
    // The last resolved run is failed, so "failed" wins regardless of staleness.
    ok("classify: failed after stale ok -> 'failed'", classify(di, NOW) === "failed");
  }
}

// ---- TC-N-03: shouldAlert (transition + cooldown gate) ------------------------------------

async function testShouldAlert(): Promise<void> {
  // no alert when classify returns null
  {
    const di = makeDI({ history: [{ runId: "r1", startedAt: freshStart(), status: "ok" }] });
    ok("shouldAlert: healthy -> null", shouldAlert(di, NOW) === null);
  }
  // first alert (no prior record) -> fires immediately
  {
    const di = makeDI({ history: [{ runId: "r1", startedAt: freshStart(), status: "failed" }] });
    ok("shouldAlert: first alert (no prior) -> 'failed'", shouldAlert(di, NOW) === "failed");
  }
  // same state within cooldown -> suppressed
  {
    const di = makeDI({
      history: [{ runId: "r1", startedAt: freshStart(), status: "failed" }],
      lastAlertedState: "failed",
      lastAlertedAt: NOW - 100, // 100ms ago, well within cooldown
    });
    ok("shouldAlert: same state within cooldown -> null (suppressed)", shouldAlert(di, NOW) === null);
  }
  // same state but cooldown elapsed -> re-nudge fires
  {
    const di = makeDI({
      history: [{ runId: "r1", startedAt: freshStart(), status: "failed" }],
      lastAlertedState: "failed",
      lastAlertedAt: ONE_HOUR_AGO - 1, // just over one cooldown window
    });
    ok("shouldAlert: same state, cooldown elapsed -> re-nudge fires", shouldAlert(di, NOW) === "failed");
  }
  // state transition (stale -> failed) -> always fires regardless of cooldown
  {
    const di = makeDI({
      history: [{ runId: "r1", startedAt: freshStart(), status: "failed" }],
      lastAlertedState: "stale",
      lastAlertedAt: NOW - 100, // within cooldown but state changed
    });
    ok("shouldAlert: state transition (stale->failed) always fires", shouldAlert(di, NOW) === "failed");
  }
  // state transition (failed -> stale would not happen since failed takes precedence; but
  // test a fresh stale after a stale->cleared recovery, i.e. lastAlertedState differs)
  {
    const di = makeDI({
      history: [{ runId: "r1", startedAt: staleStart(), status: "ok" }],
      lastAlertedState: "failed",
      lastAlertedAt: NOW - 100,
    });
    ok("shouldAlert: stale with prior 'failed' (transition) -> 'stale'", shouldAlert(di, NOW) === "stale");
  }
  // missing lastAlertedAt with same state -> treated as elapsed (alerts)
  {
    const di = makeDI({
      history: [{ runId: "r1", startedAt: freshStart(), status: "failed" }],
      lastAlertedState: "failed",
      // lastAlertedAt absent
    });
    ok("shouldAlert: same state, missing lastAlertedAt -> treated as elapsed (fires)", shouldAlert(di, NOW) === "failed");
  }
}

// ---- TC-N-04: buildAlert (no-custody surface assertion) ----------------------------------

async function testBuildAlert(): Promise<void> {
  const history: MinRun[] = [
    { runId: "run-id-abc", startedAt: freshStart(), status: "ok" },
  ];
  const config = { id: "pipe-x", name: "Pipe X" };
  const alert = buildAlert(config, history, "failed");

  ok("buildAlert: id is present", alert.id === "pipe-x");
  ok("buildAlert: name is present", alert.name === "Pipe X");
  ok("buildAlert: state is present", alert.state === "failed");
  ok("buildAlert: lastRunAt is present when run exists", typeof alert.lastRunAt === "string");
  ok("buildAlert: lastRunId is present when run exists", typeof alert.lastRunId === "string");

  // NO-CUSTODY: the alert must not carry any field beyond id/name/state/lastRunAt/lastRunId.
  // Assert by exhaustively checking there are no extra keys (secrets, values, selectors, bytes, etc).
  const allowedKeys = new Set(["id", "name", "state", "lastRunAt", "lastRunId"]);
  const actualKeys = Object.keys(alert);
  const extraKeys = actualKeys.filter((k) => !allowedKeys.has(k));
  ok("buildAlert: no extra keys (no-custody surface: id/name/state/freshness only)", extraKeys.length === 0);

  // With no resolved run: lastRunAt/lastRunId must be absent (exactOptionalPropertyTypes-safe).
  const alertNoRun = buildAlert(config, [{ runId: "r1", startedAt: freshStart(), status: "in-flight" }], "stale");
  ok("buildAlert: lastRunAt absent when no resolved run (in-flight only)", !("lastRunAt" in alertNoRun));
  ok("buildAlert: lastRunId absent when no resolved run (in-flight only)", !("lastRunId" in alertNoRun));

  // Empty history: optional fields absent.
  const alertEmpty = buildAlert(config, [], "stale");
  ok("buildAlert: lastRunAt absent with empty history", !("lastRunAt" in alertEmpty));
  ok("buildAlert: lastRunId absent with empty history", !("lastRunId" in alertEmpty));
}

// runDetection runs the detection-layer groups in their original order.
export async function runDetection(): Promise<void> {
  console.log("isAllowedWebhookUrl");
  await testAllowedWebhookUrlSchemes();
  await testAllowedWebhookUrlUserinfo();
  await testAllowedWebhookUrlPrivateRanges();
  await testAllowedWebhookUrlOverride();

  console.log("classify");
  await testClassifyPrecedence();
  await testClassifyStaleness();

  console.log("shouldAlert");
  await testShouldAlert();

  console.log("buildAlert (no-custody surface)");
  await testBuildAlert();

}
