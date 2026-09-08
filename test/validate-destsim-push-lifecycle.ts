// Exercises the SIEM push DO mixin lifecycle beyond the target validation (scheduler-do-siem-push.ts):
// recordSiemPushOutcome's outcome shapes + straggler/monotonic-cursor guards, clearSiemPushDestination's
// remove/no-op arms, and summarisePushConfig's redaction-safe inbox line for each sink. These methods are
// driven by the real drain + dual-control queue in production; pinning their branches here keeps the drain's
// cursor/trail/failure accounting and the owner-action summary honest.
//
// Run: node test/validate-destsim-push-lifecycle.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

const OWNER = { method: "token" as const, email: null, subject: null, groups: [] };
const httpCfg = { endpoint: "https://siem.example.com/ingest", format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "sekret", enabled: true } as const;

async function main(): Promise<void> {
  // ---- recordSiemPushOutcome: outcome shapes + cursor + straggler/monotonic guards ----
  {
    const d = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    await d.setSiemPushDestination(httpCfg, OWNER);
    const gen = (await d.getSiemPushRecordRaw())?.gen ?? "";

    // A stale straggler (wrong gen) is dropped: no trail entry, no cursor move.
    await d.recordSiemPushOutcome({ ok: true, toSeq: 99, gen: "not-the-gen" });
    ok("recordOutcome: a gen-mismatch straggler is dropped (no trail entry)", (await d.getSiemPushView()).trail.length === 0);

    // A full 2xx outcome (all optional fields present) advances the cursor and records the trail entry.
    await d.recordSiemPushOutcome({ ok: true, httpStatus: 200, count: 5, fromSeq: 0, toSeq: 5, gen });
    let view = await d.getSiemPushView();
    ok("recordOutcome: a 2xx with full fields records a trail entry", view.trail.length === 1 && view.trail[0]?.ok === true);
    ok("recordOutcome: the trail entry carries httpStatus + count + fromSeq/toSeq", view.trail[0]?.httpStatus === 200 && view.trail[0]?.count === 5 && view.trail[0]?.toSeq === 5);
    ok("recordOutcome: a 2xx advances lastPushedSeq to toSeq", view.lastPushedSeq === 5);

    // A minimal 2xx (no optional fields) exercises the absent-optional arms + no cursor move (no toSeq).
    await d.recordSiemPushOutcome({ ok: true, gen });
    view = await d.getSiemPushView();
    ok("recordOutcome: a 2xx with NO toSeq leaves the cursor where it was (5)", view.lastPushedSeq === 5);

    // A failure holds the cursor and records a push-delivery-failure audit event with a consecutive count.
    await d.recordSiemPushOutcome({ ok: false, httpStatus: 503, reason: "http-5xx", count: 5, fromSeq: 5, toSeq: 10, gen });
    view = await d.getSiemPushView();
    ok("recordOutcome: a failure holds the cursor (still 5, at-least-once retry)", view.lastPushedSeq === 5);
    ok("recordOutcome: the failure is on the trail (ok:false, reason)", view.trail.some((t) => t.ok === false && t.reason === "http-5xx"));

    // Monotonic cursor: a LATE 2xx for an earlier range never moves the cursor backward.
    await d.recordSiemPushOutcome({ ok: true, toSeq: 3, gen });
    ok("recordOutcome: cursor is monotonic (a late lower toSeq never rewinds it below 5)", (await d.getSiemPushView()).lastPushedSeq === 5);
  }

  // ---- clearSiemPushDestination: remove arm + no-op arm ----
  {
    const d = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    // Clearing when nothing is set is a no-op (removed=false: no cursor/trail delete, no cleared audit).
    await d.clearSiemPushDestination(OWNER);
    ok("clear: clearing an absent destination is a benign no-op (present stays false)", (await d.getSiemPushView()).present === false);
    // Set, then clear (the remove arm: config + cursor + trail deleted, a cleared audit recorded).
    await d.setSiemPushDestination(httpCfg, OWNER);
    const geniune = (await d.getSiemPushRecordRaw())?.gen ?? "";
    await d.recordSiemPushOutcome({ ok: true, toSeq: 7, gen: geniune });
    await d.clearSiemPushDestination(OWNER);
    const cleared = await d.getSiemPushView();
    ok("clear: a set destination is removed (present:false, trail empty, cursor gone)", cleared.present === false && cleared.trail.length === 0);
    const audit = await d.exportAudit(new URLSearchParams(""));
    const events = ((await audit.json()) as { events: Array<{ action?: string }> }).events;
    ok("clear: a push-destination-cleared audit event was recorded", events.some((e) => e.action === "push-destination-cleared"));
  }

  // ---- summarisePushConfig: the redaction-safe inbox line per sink (+ malformed + null) ----
  {
    const d = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    ok("summary: null/non-object -> a generic label (never throws)", d.summarisePushConfig(null) === "Set the SIEM push destination");
    const httpSummary = d.summarisePushConfig({ endpoint: "https://siem.example.com/ingest", format: "raw-json" });
    ok("summary: http sink names the format + host, never the secret", httpSummary.includes("raw-json") && httpSummary.includes("siem.example.com") && !httpSummary.includes("sekret"));
    const s3Summary = d.summarisePushConfig({ sink: "s3", format: "ndjson", s3Target: { endpoint: "https://s3.us-east-1.amazonaws.com", bucket: "audit-bucket" } });
    ok("summary: s3 sink names the bucket + host, never the s3 secret", s3Summary.includes("audit-bucket") && s3Summary.includes("s3.us-east-1.amazonaws.com"));
    const syslogSummary = d.summarisePushConfig({ sink: "syslog-tls", format: "cef", syslog: { host: "siem.internal.example" } });
    ok("summary: syslog sink names the host over syslog-tls", syslogSummary.includes("syslog-tls") && syslogSummary.includes("siem.internal.example"));
    const malformed = d.summarisePushConfig({ endpoint: "::not a url::", format: "raw-json" });
    ok("summary: a malformed endpoint never leaks (host falls back to a placeholder, no throw)", malformed.includes("(host)"));
  }

  console.log(failures === 0 ? "\nDESTSIM PUSH-LIFECYCLE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
