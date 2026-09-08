// Prove the DELIVERY-FEEDBACK fault evidence: the notify pipeline's
// three feedback confirms -- POST /alerts-delivered, POST /recovery-delivered, POST /replication-alerts-delivered
// -- now RECORD their own failure in the DO's notifyHealth aggregate (the pack's notifyHealth.feedbackFails),
// so the two silent symptoms have a durable cause:
//
//   "we never got a second warning while the pipe stayed broken"  -> the OPTIMISTIC cooldown stayed written
//                                                                    because the confirm that would have cleared
//                                                                    it was lost
//   "PagerDuty never auto-closed after recovery"                  -> the owed-resolve marker for a FAILED resolve
//                                                                    was never written, so nothing retried it
//
// TWO DEFECTS PINNED HERE (both were live before this change):
//   1. NON-2XX WAS SILENTLY SUCCESS. The passes caught a THROW only, so a DO that ANSWERS (a 404 from a route
//      chain skewed by a partial deploy, a 400, a 500 under load) returned a Response, `await` resolved, and a
//      LOST confirm was treated as a landed one. Cases B/C/E/G below fail on the pre-change code.
//   2. TWO OF THE THREE STREAMS COUNTED NOTHING. Only /alerts-delivered bumped the counter; the recovery and
//      replication confirms went to Workers Logs, which the pack cannot collect. Cases D/E/F/G below fail on
//      the pre-change code.
//   Plus: the counter's OWN bump was `.catch(() => {})` -- the write most likely to be lost in the very fault
//   window it exists to prove. It is now checked and retried once (cases I/J).
//
// REDACTION (binding, no-custody): a CUSTOMER SENTINEL is planted at the fault site -- inside the thrown error
// message AND inside the non-2xx response body of the failing confirm -- and case K asserts it reaches NO body
// the engine posts to the DO. The only thing that rides is a bump of one CLOSED field name: {"field":
// "feedbackFails"} and nothing else (asserted key-by-key, not by substring).
//
// Run: node test/validate-notify-feedback-evidence.ts

import { runAlertPass, runReplicationAlertPass } from "../src/cron/alert-passes.ts";
import { makeSchedulerStub, makeEnv } from "./validate-worker-helpers.ts";
import type { DownpipeAlert } from "../src/notify.ts";
import type { NotifyEmission, NotifyEvent } from "../src/notify/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

// The customer sentinel. It exists ONLY inside the fault (the thrown message, the refusal body). If it ever
// appears in a body the engine posts to the DO, a raw error message has leaked into a durable record.
const SENTINEL = "SENTINEL-CUSTOMER-SECRET-a1b2c3-https://acme.internal/hooks?token=hunter2";

// A failure mode for one DO route: throw (a transport fault) or answer with this HTTP status (a DO that
// ANSWERS and refuses -- the case the pre-change code read as success).
type FailMode = "throw" | number;

interface Drive {
  posts: Array<{ path: string; body: string }>;
  passOk: boolean;
}

// Drive one alert pass against a scheduler stub. `fail` maps a DO route to its failure mode; `healthBump` is
// the per-ATTEMPT outcome list for /notify/health-bump (so the bump's own retry can be exercised).
async function drive(opts: {
  pass: "alert" | "replication";
  alerts?: DownpipeAlert[];
  pendingTransitionIds?: string[];
  recoveries?: NotifyEmission[];
  emissions?: NotifyEmission[];
  fail?: Record<string, FailMode>;
  healthBump?: FailMode[];
}): Promise<Drive> {
  const posts: Array<{ path: string; body: string }> = [];
  let bumpAttempt = 0;
  const stub = makeSchedulerStub(async (url: string, init?: RequestInit) => {
    const path = new URL(url).pathname;
    const body = typeof init?.body === "string" ? init.body : "";
    if (init?.method === "POST") posts.push({ path, body });

    // The health-bump: its own per-attempt outcome (default 200).
    if (path === "/notify/health-bump") {
      const mode = opts.healthBump?.[bumpAttempt++] ?? 200;
      if (mode === "throw") throw new Error(`health-bump transport fault: ${SENTINEL}`);
      return new Response(JSON.stringify({ ok: mode === 200 }), { status: mode, headers: { "content-type": "application/json" } });
    }

    // The route under test may be configured to fail. The fault carries the SENTINEL in BOTH channels a
    // classifier could be tempted to read: the thrown message and the refusal body.
    const mode = opts.fail?.[path];
    if (mode !== undefined) {
      if (mode === "throw") throw new Error(`DO transport fault reaching ${path}: ${SENTINEL}`);
      return new Response(`{"ok":false,"reason":"${SENTINEL}"}`, { status: mode, headers: { "content-type": "application/json" } });
    }

    if (path === "/reconcile-alerts") {
      return Response.json({ alerts: opts.alerts ?? [], pendingTransitionIds: opts.pendingTransitionIds ?? [], successes: [], recoveries: opts.recoveries ?? [] });
    }
    if (path === "/reconcile-replication-alerts") {
      return Response.json({ emissions: opts.emissions ?? [], pendingTransitionIds: opts.pendingTransitionIds ?? [], recoveries: [] });
    }
    // resolveDelivery returns NO channels, so routeNotification reports "delivered to nothing" without any
    // outbound channel I/O at all: every alert is a failed transition and every recovery is a failed resolve,
    // which is exactly the state whose confirm we are testing.
    if (path === "/notify/resolve") return Response.json({ now: [], digestedCount: 0, emission: null });
    return Response.json({ ok: true });
  });
  const env = makeEnv(stub);
  const passOk = opts.pass === "alert" ? await runAlertPass(env, stub) : await runReplicationAlertPass(env, stub);
  return { posts, passOk };
}

const bumps = (d: Drive): Array<{ path: string; body: string }> => d.posts.filter((p) => p.path === "/notify/health-bump");

// The closed-vocabulary assertion: a bump body carries EXACTLY one key, `field`, whose value is the one closed
// member. Checked key-by-key (not by substring), so a body that ALSO smuggled a message would fail here.
function bumpBodiesAreClosed(d: Drive): boolean {
  return bumps(d).every((p) => {
    const parsed = JSON.parse(p.body) as Record<string, unknown>;
    return Object.keys(parsed).length === 1 && parsed.field === "feedbackFails";
  });
}

const alert = (id: string, state: "failed" | "stale"): DownpipeAlert => ({ id, name: `Pipe ${id}`, state } as DownpipeAlert);
const recovery = (id: string, event: NotifyEvent): NotifyEmission => ({ event, severity: event === "backup-failure" ? "critical" : "warning", downpipeId: id, downpipeName: `Pipe ${id}`, detail: `${id} recovered`, at: "2026-07-10T00:00:00.000Z", recovered: true });
const emission = (id: string): NotifyEmission => ({ event: "replication-degraded", severity: "warning", downpipeId: id, downpipeName: `Pipe ${id}`, detail: `${id} degraded`, at: "2026-07-10T00:00:00.000Z" });

const ALERTS = [alert("dp-a", "failed")];
const PENDING = ["dp-a"];

async function main(): Promise<void> {
  const all: Drive[] = [];

  // ---- the alerts stream (stuck cooldown: "no second warning while the pipe stayed broken") -------------
  console.log("\n# /alerts-delivered: a lost confirm keeps the OPTIMISTIC cooldown written");
  {
    // A. THROW -- the one case the pre-change code already counted (regression guard).
    const d = await drive({ pass: "alert", alerts: ALERTS, pendingTransitionIds: PENDING, fail: { "/alerts-delivered": "throw" } });
    all.push(d);
    ok("A alerts-delivered THROWS: one feedbackFails bump recorded", bumps(d).length === 1);
    ok("A alerts-delivered THROWS: the pass still completes (fail-open, never a crashed cron)", d.passOk === true);
  }
  {
    // B. 500 -- the DO ANSWERED and refused. Pre-change: resp was never checked, so this was SILENT success.
    const d = await drive({ pass: "alert", alerts: ALERTS, pendingTransitionIds: PENDING, fail: { "/alerts-delivered": 500 } });
    all.push(d);
    ok("B alerts-delivered 500 (DO answered, refused): one feedbackFails bump recorded", bumps(d).length === 1);
    ok("B alerts-delivered 500: the pass still completes", d.passOk === true);
  }
  {
    // C. 404 -- a route chain skewed by a partial deploy: the confirm route is simply not there any more.
    const d = await drive({ pass: "alert", alerts: ALERTS, pendingTransitionIds: PENDING, fail: { "/alerts-delivered": 404 } });
    all.push(d);
    ok("C alerts-delivered 404 (route skew after a partial deploy): one feedbackFails bump recorded", bumps(d).length === 1);
  }

  // ---- the recovery stream ("PagerDuty never auto-closed after recovery") -------------------------------
  console.log("\n# /recovery-delivered: a lost confirm strands the open incident (no counter existed AT ALL)");
  {
    // D. THROW. Pre-change: logged only, counted nowhere.
    const d = await drive({ pass: "alert", recoveries: [recovery("dp-r", "backup-failure")], fail: { "/recovery-delivered": "throw" } });
    all.push(d);
    ok("D recovery-delivered THROWS: one feedbackFails bump recorded", bumps(d).length === 1);
    ok("D recovery-delivered THROWS: the pass still completes", d.passOk === true);
  }
  {
    // E. 500. Pre-change: silent success AND counted nowhere (both defects at once).
    const d = await drive({ pass: "alert", recoveries: [recovery("dp-r", "backup-stale")], fail: { "/recovery-delivered": 500 } });
    all.push(d);
    ok("E recovery-delivered 500: one feedbackFails bump recorded", bumps(d).length === 1);
  }

  // ---- the replication stream (a degraded fan-out silently cooled) --------------------------------------
  console.log("\n# /replication-alerts-delivered: a lost confirm keeps the repl cooldown written (no counter existed AT ALL)");
  {
    // F. THROW.
    const d = await drive({ pass: "replication", emissions: [emission("dp-x")], pendingTransitionIds: ["dp-x"], fail: { "/replication-alerts-delivered": "throw" } });
    all.push(d);
    ok("F replication-alerts-delivered THROWS: one feedbackFails bump recorded", bumps(d).length === 1);
    ok("F replication-alerts-delivered THROWS: the pass still completes", d.passOk === true);
  }
  {
    // G. 500.
    const d = await drive({ pass: "replication", emissions: [emission("dp-x")], pendingTransitionIds: ["dp-x"], fail: { "/replication-alerts-delivered": 500 } });
    all.push(d);
    ok("G replication-alerts-delivered 500: one feedbackFails bump recorded", bumps(d).length === 1);
  }

  // ---- the healthy steady state: silence must stay silent -----------------------------------------------
  console.log("\n# the healthy path records NOTHING (a counter that fires when nothing is wrong is worse than none)");
  {
    // H. Every confirm lands: ZERO bumps, on both passes.
    const a = await drive({ pass: "alert", alerts: ALERTS, pendingTransitionIds: PENDING, recoveries: [recovery("dp-r", "backup-failure")] });
    const r = await drive({ pass: "replication", emissions: [emission("dp-x")], pendingTransitionIds: ["dp-x"] });
    all.push(a, r);
    ok("H alert pass, every confirm lands: ZERO feedbackFails bumps", bumps(a).length === 0);
    ok("H replication pass, every confirm lands: ZERO feedbackFails bumps", bumps(r).length === 0);
    ok("H alert pass: the confirm was still POSTed (the loop is closed, not skipped)", a.posts.some((p) => p.path === "/alerts-delivered") && a.posts.some((p) => p.path === "/recovery-delivered"));
    ok("H replication pass: the confirm was still POSTed", r.posts.some((p) => p.path === "/replication-alerts-delivered"));
  }

  // ---- the counter's OWN write (the diagnostic that used to be the first thing lost) --------------------
  console.log("\n# the bump itself is CHECKED and retried once (it was `.catch(() => {})`)");
  {
    // I. The first bump attempt is refused (500), the retry lands: exactly two attempts, and the record lands.
    const d = await drive({ pass: "alert", alerts: ALERTS, pendingTransitionIds: PENDING, fail: { "/alerts-delivered": "throw" }, healthBump: [500, 200] });
    all.push(d);
    ok("I bump refused then retried: exactly 2 health-bump attempts (the retry landed the record)", bumps(d).length === 2);
    ok("I bump refused then retried: the pass still completes", d.passOk === true);
  }
  {
    // J. The bump fails on BOTH attempts (the DO is gone). It must not retry for ever, and must NEVER break
    // the pass that observed the fault: the irreducible floor is a log line and a pack that under-counts by one.
    const d = await drive({ pass: "alert", alerts: ALERTS, pendingTransitionIds: PENDING, fail: { "/alerts-delivered": "throw" }, healthBump: ["throw", "throw"] });
    all.push(d);
    ok("J bump lost on both attempts: bounded at 2 attempts (no unbounded retry in a cron tick)", bumps(d).length === 2);
    ok("J bump lost on both attempts: the alert pass STILL completes (a bookkeeping write never breaks it)", d.passOk === true);
  }

  // ---- REDACTION: the sentinel planted in the fault reaches no record -----------------------------------
  console.log("\n# redaction: the customer sentinel planted in the fault reaches NO posted body");
  {
    let leaked: string | null = null;
    for (const d of all) {
      for (const p of d.posts) {
        if (p.body.includes(SENTINEL) || p.body.includes("hunter2") || p.body.includes("acme.internal")) leaked = `${p.path}: ${p.body.slice(0, 120)}`;
      }
    }
    ok("K the sentinel (planted in the thrown message AND the refusal body) reaches no posted body", leaked === null);
    if (leaked !== null) console.log(`       leaked into -> ${leaked}`);
    ok("K every health-bump body is EXACTLY {\"field\":\"feedbackFails\"} (one closed key, checked key-by-key)", all.every(bumpBodiesAreClosed));
    // Defence in depth: no HTTP status, no route path and no error text of any kind rides the record either.
    const bumpBodies = all.flatMap((d) => bumps(d).map((p) => p.body));
    ok("K no bump body carries a status, a path, a message or a stack", bumpBodies.every((b) => !/500|404|status|error|Error|stack|delivered|http/i.test(b)));
    ok("K bumps were actually exercised (the redaction assertions are not vacuous)", bumpBodies.length >= 9);
  }

  console.log(failures === 0 ? "\nNOTIFY FEEDBACK EVIDENCE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
