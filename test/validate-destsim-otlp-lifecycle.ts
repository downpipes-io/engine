// Exercises the OTLP push DO mixin lifecycle (scheduler-do-otlp-push.ts): recordOtlpPushOutcome's outcome
// shapes + straggler guard, clearOtlpPushDestination's remove/no-op arms, and getOtlpPushView, mirroring the
// SIEM push lifecycle test. These methods are driven by the real OTLP drain in production; pinning their
// branches keeps the drain's trail + failure accounting honest.
//
// Run: node test/validate-destsim-otlp-lifecycle.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

const OWNER = { method: "token" as const, email: null, subject: null, groups: [] };
const cfg = { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "DD-API-KEY", authHeaderValue: "dd-secret", enabled: true } as const;

async function main(): Promise<void> {
  // ---- recordOtlpPushOutcome: outcome shapes + straggler guard ----
  {
    const d = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    await d.setOtlpPushDestination(cfg, OWNER);
    const gen = (await d.getOtlpPushRecordRaw())?.gen ?? "";

    await d.recordOtlpPushOutcome({ ok: true, downpipeCount: 3, gen: "stale-gen" });
    ok("otlp recordOutcome: a gen-mismatch straggler is dropped (no trail entry)", (await d.getOtlpPushView()).trail.length === 0);

    await d.recordOtlpPushOutcome({ ok: true, httpStatus: 200, downpipeCount: 300, truncated: true, gen });
    let view = await d.getOtlpPushView();
    ok("otlp recordOutcome: a 2xx records a trail entry with downpipeCount + truncated flag", view.trail.length === 1 && view.trail[0]?.downpipeCount === 300 && view.trail[0]?.truncated === true);

    await d.recordOtlpPushOutcome({ ok: false, httpStatus: 413, reason: "http-4xx", downpipeCount: 600, gen });
    view = await d.getOtlpPushView();
    ok("otlp recordOutcome: a failure is on the trail (ok:false, reason)", view.trail.some((t) => t.ok === false && t.reason === "http-4xx"));

    // partial_success: a 2xx that carries rejectedDataPoints is recorded as a loud partial-loss signal.
    await d.recordOtlpPushOutcome({ ok: true, httpStatus: 200, downpipeCount: 10, rejectedDataPoints: 4, gen });
    view = await d.getOtlpPushView();
    ok("otlp recordOutcome: a partial_success (rejectedDataPoints) is recorded on the trail (F1)", view.trail.some((t) => t.rejectedDataPoints === 4));
  }

  // ---- clearOtlpPushDestination: remove arm + no-op arm ----
  {
    const d = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    await d.clearOtlpPushDestination(OWNER);
    ok("otlp clear: clearing an absent destination is a benign no-op (present:false)", (await d.getOtlpPushView()).present === false);
    await d.setOtlpPushDestination(cfg, OWNER);
    const gen = (await d.getOtlpPushRecordRaw())?.gen ?? "";
    await d.recordOtlpPushOutcome({ ok: true, downpipeCount: 2, gen });
    await d.clearOtlpPushDestination(OWNER);
    const cleared = await d.getOtlpPushView();
    ok("otlp clear: a set destination is removed (present:false, trail empty)", cleared.present === false && cleared.trail.length === 0);
    const audit = await d.exportAudit(new URLSearchParams(""));
    const events = ((await audit.json()) as { events: Array<{ action?: string }> }).events;
    ok("otlp clear: an otlp-push-destination-cleared audit event was recorded", events.some((e) => e.action === "otlp-push-destination-cleared"));
  }

  // ---- getOtlpPushView redaction: the sealed key never appears ----
  {
    const d = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    const view = await d.setOtlpPushDestination(cfg, OWNER);
    ok("otlp view: present with the endpoint + authHeaderName, NEVER the key value", view.present === true && view.authHeaderName === "DD-API-KEY" && !JSON.stringify(view).includes("dd-secret"));
  }

  console.log(failures === 0 ? "\nDESTSIM OTLP-LIFECYCLE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
