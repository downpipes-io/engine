// validate-autoresolve.ts -- the TRANSITION DETECTOR / auto-resolve suite (mon-autoresolve, M3 of the
// monitoring integrations build). PagerDuty's channel adapter has always been able to format a `resolve`
// event with a stable dedup_key (see notify/channels/pagerduty.ts); nothing emitted `recovered:true` for
// the four alertable conditions (backup-failure, backup-stale, replication-degraded, run-at-risk-eviction),
// so a recovered backup never closed the incident. reconcileAlerts/reconcileReplicationAlerts
// (sched/scheduler-do-sre-alerting.ts) now emit a recovery on the FALLING EDGE of the same AlertCooldown /
// ReplAlertCooldown they already tracked; this suite proves it end to end against the REAL engine code
// (the real SchedulerDO, the real notify-routing + channel-adapter modules), not a re-implementation:
//
//  - PagerDuty formats a `resolve` with the IDENTICAL dedup_key the matching `trigger` used (both the pure
//    format() and the real deliver() + a captures[] fetch stub, since PAGERDUTY_EVENTS_URL is a fixed
//    provider endpoint that cannot be redirected to a local capture server).
//  - webhook's REAL deliver() is proven against a REAL local `node:http` capture server (allowInternalSink,
//    the documented on-prem-sink escape hatch), so the recovery is shown actually leaving the process over
//    a real socket, not merely constructed in memory.
//  - slack/teams/email render the recovery sensibly via the detail text alone (they carry no distinct
//    "recovered" field; they are fire-only, no close semantics, exactly as the brief accepts).
//  - the DO-level falling edge: fires recovered:true exactly once per healthy episode, never fires without
//    a prior firing cooldown, and stays cooldown-bounded across a fail/recover/relapse/recover flap (no
//    storm on either side).
//
// Run: node test/validate-autoresolve.ts

import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { type NotifyChannel, type NotifyEmission } from "../src/notify.ts";
import * as pagerdutyChannel from "../src/notify/channels/pagerduty.ts";
import { format as formatPagerDuty, PAGERDUTY_EVENTS_URL } from "../src/notify/channels/pagerduty.ts";
import * as webhookChannel from "../src/notify/channels/webhook.ts";
import { format as formatSlack } from "../src/notify/channels/slack.ts";
import { formatCard as formatTeamsCard } from "../src/notify/channels/teams.ts";
import { format as formatEmail } from "../src/notify/channels/email.ts";
import { ok, getFailures, makeScheduler, stubFetch, ownerFetch, makeConfig, freshStart } from "./validate-notify-shared.ts";
import { REPL_ALERT_COOLDOWN_PREFIX } from "../src/sched/scheduler-do-records.ts";

const AT = "2026-07-05T00:00:00.000Z";
function pdChannel(routingKey = "R0123456789ABCDEF"): NotifyChannel {
  return { id: "pd1", kind: "pagerduty", name: "PD", routingKey, enabled: true, createdAt: AT };
}

// ---- 1: PagerDuty dedup_key parity (pure format(), no I/O) ---------------------------------------
// The recipe the whole feature rests on: a recovery reuses the SAME event + downpipeId as the trigger it
// closes, so pagerdutyDedupKey (a pure function of downpipeId + event) is byte-identical for both.

function testPagerDutyDedupKeyParity(): void {
  const cases: Array<{ event: NotifyEmission["event"]; severity: NotifyEmission["severity"]; recoveredDetail: string }> = [
    { event: "backup-failure", severity: "critical", recoveredDetail: "Prod KV: the last run succeeded; the previous failure has cleared" },
    { event: "backup-stale", severity: "warning", recoveredDetail: "Prod KV: a recent run succeeded; the staleness has cleared" },
    { event: "replication-degraded", severity: "warning", recoveredDetail: "Fan-out: replication recovered; 3 of 3 copies proven, every destination reachable" },
    { event: "run-at-risk-eviction", severity: "critical", recoveredDetail: "Fan-out: the at-risk run is no longer exposed to eviction; 1 of 2 copies proven, every destination reachable" },
  ];
  for (const c of cases) {
    const channel = pdChannel();
    const trigger: NotifyEmission = { event: c.event, severity: c.severity, downpipeId: "dp-1", downpipeName: "Prod KV", detail: `Prod KV ${c.event}`, at: AT };
    const resolve: NotifyEmission = { ...trigger, detail: c.recoveredDetail, recovered: true };
    const t = formatPagerDuty(channel, trigger);
    const r = formatPagerDuty(channel, resolve);
    ok(`pagerduty(${c.event}): trigger event_action is "trigger"`, t.event_action === "trigger");
    ok(`pagerduty(${c.event}): resolve event_action is "resolve"`, r.event_action === "resolve");
    ok(`pagerduty(${c.event}): trigger and resolve share the IDENTICAL dedup_key`, t.dedup_key === r.dedup_key && t.dedup_key === `downpipe:dp-1:${c.event}`);
    ok(`pagerduty(${c.event}): resolve summary is the recovery detail, not the trigger's`, r.payload.summary === c.recoveredDetail);
  }
  // Account-level event (downpipeId null): dedup_key keys on the event alone, same parity property.
  const channel = pdChannel();
  const trigger: NotifyEmission = { event: "canary-dead", severity: "critical", downpipeId: null, downpipeName: "Canary", detail: "Canary dead", at: AT };
  const resolve: NotifyEmission = { ...trigger, event: "canary-dead", detail: "Canary alive again", recovered: true };
  ok("pagerduty(account-level): trigger/resolve dedup_key parity (account:<event>)", formatPagerDuty(channel, trigger).dedup_key === formatPagerDuty(channel, resolve).dedup_key && formatPagerDuty(channel, trigger).dedup_key === "account:canary-dead");
}

// ---- 2: PagerDuty REAL deliver() via a captures[] fetch stub --------------------------------------
// PAGERDUTY_EVENTS_URL is a FIXED provider endpoint (not a customer url), so it cannot be redirected to a
// local capture server; the established technique for proving a real adapter call in this suite (see
// validate-s3-multipart.ts) is a temporary globalThis.fetch stub that records the exact url/body. This
// exercises the REAL deliver()/format() code path, a real JSON serialise + parse round trip, and a real
// (if stubbed) network call, not a re-implementation of the adapter's logic.

async function testPagerDutyRealAdapterFetchStub(): Promise<void> {
  const realFetch = globalThis.fetch;
  const captures: Array<{ url: string; body: { event_action: string; dedup_key?: string; routing_key: string; payload: { summary: string } } }> = [];
  globalThis.fetch = (async (input: URL | RequestInfo, init?: RequestInit): Promise<Response> => {
    const url = input instanceof URL ? input.toString() : String(input);
    const body = JSON.parse(String(init?.body ?? "{}"));
    captures.push({ url, body });
    return new Response(JSON.stringify({ status: "success" }), { status: 202 });
  }) as typeof fetch;
  try {
    const channel = pdChannel("R0123456789ABCDEF");
    const trigger: NotifyEmission = { event: "replication-degraded", severity: "warning", downpipeId: "dp-r1", downpipeName: "Fan-out", detail: "Fan-out: 2 of 3 copies proven; the lagging copy is not reachable, check the destination", at: AT };
    const resolve: NotifyEmission = { ...trigger, detail: "Fan-out: replication recovered; 3 of 3 copies proven, every destination reachable", at: "2026-07-05T00:05:00.000Z", recovered: true };
    const r1 = await pagerdutyChannel.deliver(channel, trigger);
    const r2 = await pagerdutyChannel.deliver(channel, resolve);
    ok("pd-real-adapter: trigger delivered ok via the REAL deliver()", r1.ok === true);
    ok("pd-real-adapter: resolve delivered ok via the REAL deliver()", r2.ok === true);
    ok("pd-real-adapter: exactly 2 real fetch calls, both to the FIXED Events API endpoint", captures.length === 2 && captures.every((c) => c.url === PAGERDUTY_EVENTS_URL));
    ok("pd-real-adapter: trigger body event_action is trigger", captures[0]?.body.event_action === "trigger");
    ok("pd-real-adapter: resolve body event_action is resolve", captures[1]?.body.event_action === "resolve");
    ok("pd-real-adapter: trigger and resolve carry the IDENTICAL dedup_key", captures[0]?.body.dedup_key === captures[1]?.body.dedup_key && captures[0]?.body.dedup_key === "downpipe:dp-r1:replication-degraded");
    ok("pd-real-adapter: routing_key rides unaltered on both calls", captures[0]?.body.routing_key === "R0123456789ABCDEF" && captures[1]?.body.routing_key === "R0123456789ABCDEF");
  } finally {
    globalThis.fetch = realFetch;
  }
}

// ---- 3: the other channels render a recovery sensibly (detail-text-only, no distinct field) ------
// webhook/slack/teams/email have no trigger/resolve state machine (they are fire-only): a recovery is
// legible ONLY through the emission's own detail text (already worded "recovered"/"cleared" at the call
// site in scheduler-do-sre-alerting.ts), never a special payload field. This is by design (the brief calls
// it "fine and honest"); the assertions below confirm it is true of the actual formatters, not assumed.

function testOtherChannelsRenderRecoverySensibly(): void {
  const resolve: NotifyEmission = { event: "backup-stale", severity: "warning", downpipeId: "dp-s1", downpipeName: "Prod R2", detail: "Prod R2: a recent run succeeded; the staleness has cleared", at: AT, recovered: true };

  const webhookPayload = webhookChannel.format(resolve);
  ok("webhook: recovery body carries the cleared detail", webhookPayload.detail === resolve.detail);
  ok("webhook: recovery body carries NO distinct recovered field (fire-only)", !("recovered" in (webhookPayload as object)));

  const slackMsg = formatSlack(resolve);
  ok("slack: recovery text contains the cleared detail", slackMsg.text.includes("staleness has cleared"));
  ok("slack: recovery text carries no secret/url", !/https?:\/\//.test(slackMsg.text));
  ok("slack: recovery payload carries no distinct recovered field", !("recovered" in (slackMsg as object)));

  const card = formatTeamsCard(resolve);
  ok("teams: recovery card text is the cleared detail verbatim", card.text === resolve.detail);
  ok("teams: recovery card theme is the severity colour (warning), not a special recovered colour", card.themeColor === "E8A317");
  ok("teams: recovery card carries no distinct recovered field", !("recovered" in (card as object)));

  const email = formatEmail(["ops@example.com"], resolve);
  ok("email: recovery subject names the event + severity", email.subject.includes("backup-stale") && email.subject.includes("warning"));
  ok("email: recovery body contains the cleared detail", email.text.includes("staleness has cleared"));
  ok("email: recovery body carries no url/secret", !/https?:|secret|key=/i.test(email.text));
}

// ---- 4: webhook REAL deliver() to a REAL local http.Server capture sink --------------------------
// Not a mock of the business logic: a genuine node:http server bound to 127.0.0.1, and the REAL
// deliverPayload()-backed webhook deliver() POSTs to it over an actual socket. allowInternalSink:true is
// the documented per-channel SSRF override (the on-prem-sink escape hatch); a local capture server is
// exactly that class of target, so this is the same trust boundary a real operator would opt into.

async function startCaptureServer(): Promise<{ url: string; captured: Array<Record<string, unknown>>; close: () => Promise<void> }> {
  const captured: Array<Record<string, unknown>> = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
      } catch {
        body = {};
      }
      captured.push(body);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/capture`,
    captured,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function testWebhookRealLocalCaptureDelivery(): Promise<void> {
  const cap = await startCaptureServer();
  try {
    const channel: NotifyChannel = { id: "wh1", kind: "webhook", name: "local-capture", url: cap.url, allowInternalSink: true, enabled: true, createdAt: AT };
    const trigger: NotifyEmission = { event: "backup-failure", severity: "critical", downpipeId: "dp-x", downpipeName: "Prod KV", detail: "Prod KV last run failed", at: AT };
    const resolve: NotifyEmission = { ...trigger, detail: "Prod KV: the last run succeeded; the previous failure has cleared", at: "2026-07-05T00:05:00.000Z", recovered: true };
    const r1 = await webhookChannel.deliver(channel, trigger);
    const r2 = await webhookChannel.deliver(channel, resolve);
    ok("real-local-delivery: trigger POST delivered ok over a real socket", r1.ok === true);
    ok("real-local-delivery: resolve POST delivered ok over a real socket", r2.ok === true);
    ok("real-local-delivery: exactly 2 POSTs actually received by the real local server", cap.captured.length === 2);
    ok("real-local-delivery: the real server saw the trigger's event/detail", cap.captured[0]?.event === "backup-failure" && cap.captured[0]?.detail === trigger.detail);
    ok("real-local-delivery: the real server saw the resolve's cleared detail", (cap.captured[1]?.detail as string | undefined)?.includes("cleared") === true);
  } finally {
    await cap.close();
  }
}

// ---- 5: the DO-level falling edge -- exactly once, no fire without prior state, cooldown-bounded --
// Drives the REAL SchedulerDO through a fail -> (suppressed re-nudge) -> recover -> (silent once
// healthy) -> relapse -> recover again cycle, proving: (a) a recovery fires exactly once per healthy
// episode; (b) it never fires without a prior firing cooldown (the very first tick, before any failure,
// emits nothing); (c) the cycle is cooldown-bounded, not a storm -- a persistently-broken downpipe is
// suppressed exactly as before (unaffected by this change) and a fully-recovered downpipe stays silent on
// every subsequent unchanged tick (no repeat recovery spam).

async function testFlapCycleCooldownBounded(): Promise<void> {
  const { stub, storage } = makeScheduler();
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-flap"));
  await ownerFetch(stub, "POST", "/notify/channels", { kind: "webhook", name: "Alerts", url: "https://hooks.example.com/flap" });

  type Recon = { alerts: Array<{ id: string; state: string }>; recoveries?: Array<{ event: string; downpipeId: string | null; recovered?: boolean }> };
  const reconcile = async (): Promise<Recon> => (await (await stubFetch(stub, "POST", "/reconcile-alerts")).json()) as Recon;

  // Tick 0: a brand-new downpipe with no history at all is "pending", not alertable -- no alert, no
  // recovery (nothing to recover FROM: proves the falling edge cannot fire without a prior firing state).
  const t0 = await reconcile();
  ok("flap t0: a never-run downpipe alerts nothing", t0.alerts.length === 0);
  ok("flap t0: a never-run downpipe recovers nothing (no prior state to fall from)", (t0.recoveries ?? []).length === 0);

  // Tick 1: it fails for the first time -- a transition, fires the trigger, no recovery.
  await storage.put("hist:dp-flap", [{ runId: "f1", index: 1, startedAt: new Date().toISOString(), status: "failed" }]);
  const t1 = await reconcile();
  ok("flap t1: first failure alerts (transition)", t1.alerts.length === 1 && t1.alerts[0]?.state === "failed");
  ok("flap t1: first failure emits no recovery", (t1.recoveries ?? []).length === 0);

  // Tick 2: still failed, SAME state, WITHIN the cooldown window -- suppressed (unaffected pre-existing
  // storm guard), and still no recovery (still broken).
  const t2 = await reconcile();
  ok("flap t2: same-state re-nudge within cooldown is suppressed (no storm)", t2.alerts.length === 0);
  ok("flap t2: still broken -> no recovery", (t2.recoveries ?? []).length === 0);

  // Tick 3: recovers -- no alert, EXACTLY one recovery (recovered:true, backup-failure, this downpipe).
  await storage.put("hist:dp-flap", [
    { runId: "f1", index: 1, startedAt: new Date(Date.now() - 120_000).toISOString(), status: "failed" },
    { runId: "ok1", index: 2, startedAt: freshStart(), status: "ok" },
  ]);
  const t3 = await reconcile();
  ok("flap t3: recovered -> no alert", t3.alerts.length === 0);
  ok("flap t3: recovered -> exactly ONE recovery", (t3.recoveries ?? []).length === 1);
  ok("flap t3: the recovery is backup-failure recovered:true for dp-flap", t3.recoveries?.[0]?.event === "backup-failure" && t3.recoveries?.[0]?.recovered === true && t3.recoveries?.[0]?.downpipeId === "dp-flap");

  // Tick 4: unchanged, still healthy -- silent (no repeat recovery storm for an unchanged healthy state).
  const t4 = await reconcile();
  ok("flap t4: unchanged healthy state emits no alert", t4.alerts.length === 0);
  ok("flap t4: unchanged healthy state emits NO repeat recovery (no storm)", (t4.recoveries ?? []).length === 0);

  // Tick 5: relapses (fails again) -- the cooldown was cleared on recovery, so this is a FRESH transition
  // (fires immediately, not suppressed), proving the falling edge correctly re-arms the rising edge too.
  await storage.put("hist:dp-flap", [
    { runId: "f1", index: 1, startedAt: new Date(Date.now() - 240_000).toISOString(), status: "failed" },
    { runId: "ok1", index: 2, startedAt: new Date(Date.now() - 180_000).toISOString(), status: "ok" },
    { runId: "f2", index: 3, startedAt: new Date().toISOString(), status: "failed" },
  ]);
  const t5 = await reconcile();
  ok("flap t5: relapse re-alerts immediately (re-armed by the recovery, not suppressed by a stale cooldown)", t5.alerts.length === 1 && t5.alerts[0]?.state === "failed");
  ok("flap t5: relapse emits no recovery (it just broke again)", (t5.recoveries ?? []).length === 0);

  // Tick 6: recovers a second time -- exactly one recovery again (the cycle repeats cleanly, no drift).
  await storage.put("hist:dp-flap", [
    { runId: "f2", index: 3, startedAt: new Date(Date.now() - 120_000).toISOString(), status: "failed" },
    { runId: "ok2", index: 4, startedAt: freshStart(), status: "ok" },
  ]);
  const t6 = await reconcile();
  ok("flap t6: second recovery -> no alert", t6.alerts.length === 0);
  ok("flap t6: second recovery -> exactly ONE recovery again (clean repeat, no drift)", (t6.recoveries ?? []).length === 1);
}

// ---- 6: reconcileReplicationAlerts edge clears must ALSO resolve a held incident, not strand it ----
// Two edge branches clear the replication cooldown WITHOUT the main falling edge: (a) a fan-out edited
// back to a single destination (configuredCopies < 2), and (b) no ok run to assess (latestOk undefined).
// If a prior degraded/at-risk trigger opened a PagerDuty incident, clearing the cooldown in these branches
// MUST still emit a recovery (recovered:true, SAME event so the dedup_key matches), or that incident is
// stranded open forever. Each test also asserts the negative: with NO held cooldown, the branch emits
// nothing (a downpipe that was never alerted must not manufacture a spurious resolve).

type ReplRecon = { emissions: unknown[]; recoveries?: Array<{ event: string; severity: string; downpipeId: string | null; detail: string; recovered?: boolean }> };
const iso = (ms: number): string => new Date(ms).toISOString();

async function testConfigShrinkResolvesHeldIncident(): Promise<void> {
  const { stub, storage } = makeScheduler();
  await storage.put("notify-channel:ch-detect", { id: "ch-detect", kind: "webhook", name: "Sink", url: "https://sink.example.com/hook", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });

  // A downpipe now configured for a SINGLE destination, but holding a degraded cooldown from when it was a
  // fan-out (an OPEN PagerDuty incident). The clear must resolve it.
  const id = "dp-repl-shrink";
  await storage.put(`dp:${id}`, { config: makeConfig(id, { destinationIds: ["dest-A"] }), nextRunAt: Date.now() + 3_600_000, lastRunId: "r1", inFlight: false });
  await storage.put(`${REPL_ALERT_COOLDOWN_PREFIX}${id}`, { state: "replication-degraded", at: Date.now(), severity: "warning" });

  // A second, single-destination downpipe with NO held cooldown -> must emit nothing (negative case).
  const idNeg = "dp-repl-shrink-neverfired";
  await storage.put(`dp:${idNeg}`, { config: makeConfig(idNeg, { destinationIds: ["dest-Z"] }), nextRunAt: Date.now() + 3_600_000, lastRunId: "r1", inFlight: false });

  const b = (await (await stubFetch(stub, "POST", "/reconcile-replication-alerts")).json()) as ReplRecon;
  const recs = b.recoveries ?? [];
  const rec = recs.find((r) => r.downpipeId === id);
  ok("config-shrink: a held cooldown emits exactly one recovery on the clear", recs.filter((r) => r.downpipeId === id).length === 1);
  ok("config-shrink: recovery carries recovered:true", rec?.recovered === true);
  ok("config-shrink: recovery event mirrors the cooldown state (dedup_key matches the trigger)", rec?.event === "replication-degraded");
  ok("config-shrink: recovery reuses the persisted severity (warning)", rec?.severity === "warning");
  ok("config-shrink: recovery detail is honest (no longer applies) and secret-free", /single destination/.test(rec?.detail ?? "") && /no longer applies/.test(rec?.detail ?? "") && !/https?:\/\//.test(rec?.detail ?? ""));
  ok("config-shrink: the held cooldown is cleared after the resolve", storage.rawGet(`${REPL_ALERT_COOLDOWN_PREFIX}${id}`) === undefined);
  ok("config-shrink: a single-destination pipe with NO prior cooldown emits no recovery (no spurious resolve)", recs.find((r) => r.downpipeId === idNeg) === undefined);
}

async function testNoOkRunResolvesHeldIncident(): Promise<void> {
  const { stub, storage } = makeScheduler();
  await storage.put("notify-channel:ch-detect", { id: "ch-detect", kind: "webhook", name: "Sink", url: "https://sink.example.com/hook", enabled: true, createdAt: "2026-01-01T00:00:00.000Z" });

  // A fan-out downpipe with NO ok run in the ring (only a failed run) but holding an ESCALATED at-risk
  // cooldown (critical). The clear must resolve the incident AND carry the escalated severity through.
  const id = "dp-repl-nook";
  await storage.put(`dp:${id}`, { config: makeConfig(id, { destinationIds: ["dest-A", "dest-B"] }), nextRunAt: Date.now() + 3_600_000, lastRunId: "f1", inFlight: false });
  await storage.put(`hist:${id}`, [{ runId: "f1", index: 1, startedAt: iso(Date.now()), status: "failed", destinationId: "dest-A" }]);
  await storage.put(`${REPL_ALERT_COOLDOWN_PREFIX}${id}`, { state: "run-at-risk-eviction", at: Date.now(), severity: "critical" });

  // A fan-out with no ok run and NO held cooldown -> nothing to resolve (negative case).
  const idNeg = "dp-repl-nook-neverfired";
  await storage.put(`dp:${idNeg}`, { config: makeConfig(idNeg, { destinationIds: ["dest-A", "dest-B"] }), nextRunAt: Date.now() + 3_600_000, lastRunId: "f1", inFlight: false });
  await storage.put(`hist:${idNeg}`, [{ runId: "fz", index: 1, startedAt: iso(Date.now()), status: "failed", destinationId: "dest-A" }]);

  const b = (await (await stubFetch(stub, "POST", "/reconcile-replication-alerts")).json()) as ReplRecon;
  const recs = b.recoveries ?? [];
  const rec = recs.find((r) => r.downpipeId === id);
  ok("no-ok-run: a held cooldown emits exactly one recovery on the clear", recs.filter((r) => r.downpipeId === id).length === 1);
  ok("no-ok-run: recovery carries recovered:true", rec?.recovered === true);
  ok("no-ok-run: recovery event mirrors the cooldown state (dedup_key matches the trigger)", rec?.event === "run-at-risk-eviction");
  ok("no-ok-run: recovery reuses the persisted ESCALATED severity (critical), not a recomputed base", rec?.severity === "critical");
  ok("no-ok-run: recovery detail is honest (no assessable run, cleared) and secret-free", /no recent successful run/.test(rec?.detail ?? "") && /cleared/.test(rec?.detail ?? "") && !/https?:\/\//.test(rec?.detail ?? ""));
  ok("no-ok-run: the held cooldown is cleared after the resolve", storage.rawGet(`${REPL_ALERT_COOLDOWN_PREFIX}${id}`) === undefined);
  ok("no-ok-run: a no-ok-run pipe with NO prior cooldown emits no recovery (no spurious resolve)", recs.find((r) => r.downpipeId === idNeg) === undefined);
}

// ---- Main ----------------------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("pagerduty dedup_key parity (pure format)");
  testPagerDutyDedupKeyParity();

  console.log("pagerduty real deliver() via a captures[] fetch stub");
  await testPagerDutyRealAdapterFetchStub();

  console.log("other channels (webhook/slack/teams/email) render a recovery sensibly");
  testOtherChannelsRenderRecoverySensibly();

  console.log("webhook real deliver() to a real local http.Server capture sink");
  await testWebhookRealLocalCaptureDelivery();

  console.log("DO-level falling edge: exactly once, no fire without prior state, cooldown-bounded flap cycle");
  await testFlapCycleCooldownBounded();

  console.log("replication config-shrink clear resolves a held incident (never strands it open)");
  await testConfigShrinkResolvesHeldIncident();

  console.log("replication no-ok-run clear resolves a held incident (carries the escalated severity)");
  await testNoOkRunResolvesHeldIncident();

  const failures = getFailures();
  console.log(failures === 0 ? "\nAUTORESOLVE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
