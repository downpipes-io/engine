// Covers the Worker side of the auto-resolve recovery retry: runAlertPass delivers each recovery
// emission and REPORTS the outcome back to the DO via POST /recovery-delivered -- a delivered resolve clears
// its owed-resolve marker, a FAILED one writes/keeps one so reconcileAlerts retries. This drives the REAL
// runAlertPass (src/cron/alert-passes.ts) with a scheduler stub returning recoveries and a stubbed global
// fetch that makes the channel delivery succeed or fail, then asserts the reported delivered/failed split.
//
// The DO side is pinned by validate-destsim-autoresolve-retry.ts; this pins the Worker feedback that
// drives it. Run: node test/validate-destsim-recovery-pass.ts

import { runAlertPass } from "../src/cron/alert-passes.ts";
import { makeSchedulerStub, makeEnv } from "./validate-worker-helpers.ts";
import type { NotifyChannel, NotifyEmission, NotifyEvent } from "../src/notify/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

const CHANNEL: NotifyChannel = { id: "ch-1", kind: "webhook", name: "ops", url: "https://hooks.example.com/f4", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" };

function recovery(id: string, event: NotifyEvent): NotifyEmission {
  return { event, severity: event === "backup-failure" ? "critical" : "warning", downpipeId: id, downpipeName: `Pipe ${id}`, detail: `${id} recovered`, at: "2026-07-07T00:00:00.000Z", recovered: true };
}

// Drive runAlertPass with the given recoveries and a channel-delivery outcome; capture the /recovery-delivered
// report. deliver=true -> the stubbed channel POST returns 200 (delivered); false -> it throws (not delivered).
async function drive(recoveries: NotifyEmission[], deliver: boolean): Promise<{ report: { deliveredIds?: string[]; failed?: Array<{ id: string; state: string }> } | null; passOk: boolean }> {
  let report: { deliveredIds?: string[]; failed?: Array<{ id: string; state: string }> } | null = null;
  const stub = makeSchedulerStub(async (url: string, init?: RequestInit) => {
    const path = new URL(url).pathname;
    let body: unknown;
    if (typeof init?.body === "string") { try { body = JSON.parse(init.body); } catch { body = init.body; } }
    if (path === "/reconcile-alerts") return new Response(JSON.stringify({ alerts: [], pendingTransitionIds: [], successes: [], recoveries, pendingRecoveryIds: recoveries.map((r) => r.downpipeId) }), { headers: { "content-type": "application/json" } });
    if (path === "/notify/resolve") return new Response(JSON.stringify({ now: [CHANNEL], digestedCount: 0, emission: body }), { headers: { "content-type": "application/json" } });
    if (path === "/notify/record") return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    if (path === "/recovery-delivered") { report = body as typeof report; return new Response(JSON.stringify({ cleared: 0, owed: 0 }), { headers: { "content-type": "application/json" } }); }
    if (path === "/notify/health-bump") return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
  });
  const env = makeEnv(stub);
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    // The only global fetch here is the channel's webhook POST; the DO routes go through the stub.
    if (deliver) return new Response(JSON.stringify({ ok: true }), { status: 200 });
    throw new Error("simulated channel delivery failure");
  }) as typeof fetch;
  let passOk = false;
  try {
    passOk = await runAlertPass(env, stub);
  } finally {
    globalThis.fetch = realFetch;
  }
  return { report, passOk };
}

async function main(): Promise<void> {
  // A. Two recoveries, both DELIVER -> reported as deliveredIds, no failures.
  {
    const { report, passOk } = await drive([recovery("dp-a", "backup-failure"), recovery("dp-b", "backup-stale")], true);
    ok("deliver-ok: runAlertPass completes (true)", passOk === true);
    ok("deliver-ok: /recovery-delivered was called", report !== null);
    ok("deliver-ok: both ids reported as delivered", (report?.deliveredIds ?? []).sort().join(",") === "dp-a,dp-b");
    ok("deliver-ok: no failures reported", (report?.failed ?? []).length === 0);
  }

  // B. Two recoveries, both FAIL delivery -> reported as failed with the correct state mapping.
  {
    const { report } = await drive([recovery("dp-a", "backup-failure"), recovery("dp-b", "backup-stale")], false);
    ok("deliver-fail: /recovery-delivered was called", report !== null);
    ok("deliver-fail: no ids reported as delivered", (report?.deliveredIds ?? []).length === 0);
    const failed = report?.failed ?? [];
    ok("deliver-fail: both reported as failed", failed.length === 2);
    ok("deliver-fail: backup-failure -> state 'failed'", failed.find((f) => f.id === "dp-a")?.state === "failed");
    ok("deliver-fail: backup-stale -> state 'stale'", failed.find((f) => f.id === "dp-b")?.state === "stale");
  }

  // C. No recoveries -> no /recovery-delivered POST (the guard skips the report).
  {
    const { report, passOk } = await drive([], true);
    ok("no-recoveries: runAlertPass completes (true)", passOk === true);
    ok("no-recoveries: /recovery-delivered is NOT called (nothing owed)", report === null);
  }

  console.log(failures === 0 ? "\nDESTSIM RECOVERY-PASS (worker) PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
