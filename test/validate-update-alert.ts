// One-shot "new version available" alert. The cron (src/index.ts runUpdateAlertIfNew) pulls + verifies
// the signed channel and, on a NEWER recommended version, fires exactly ONE notification per version. The
// dedupe is server-side + atomic in the scheduler DO (claimUpdateAlert): it alerts only when the recommended
// version differs from the last-alerted one and records it inside a single read-modify-write, so a steady
// "update available" state never re-fires and a genuinely NEW version alerts once. This drives the REAL
// SchedulerDO /update-alert-claim route (no network, no deploy) to prove idempotency, plus the severity. Run:
//   node test/validate-update-alert.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { severityOf, isNotifyEvent } from "../src/notify.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeDO(): { stub: { fetch: (url: string, init?: RequestInit) => Promise<Response> }; storage: MockStorage } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  return {
    stub: { fetch: (url: string, init?: RequestInit) => dobj.fetch(new Request(url, init)) },
    storage,
  };
}

async function claim(stub: { fetch: (url: string, init?: RequestInit) => Promise<Response> }, recommendedVersion: unknown): Promise<boolean> {
  const r = await stub.fetch("https://do/update-alert-claim", { method: "POST", body: JSON.stringify({ recommendedVersion }), headers: { "content-type": "application/json" } });
  return ((await r.json()) as { shouldAlert: boolean }).shouldAlert;
}

async function claimRollback(stub: { fetch: (url: string, init?: RequestInit) => Promise<Response> }, recommendedVersion: unknown, toVersion = "v-new", canaryVerdict = "ailing"): Promise<boolean> {
  const r = await stub.fetch("https://do/update-rollback-needed-claim", { method: "POST", body: JSON.stringify({ recommendedVersion, toVersion, canaryVerdict }), headers: { "content-type": "application/json" } });
  return ((await r.json()) as { shouldAlert: boolean }).shouldAlert;
}

async function setPending(stub: { fetch: (url: string, init?: RequestInit) => Promise<Response> }, recommendedVersion: string, promotedAt = Date.now()): Promise<void> {
  await stub.fetch("https://do/update-pending", { method: "POST", body: JSON.stringify({ fromVersion: "v-old", toVersion: "v-new", recommendedVersion, promotedAt, promotedBy: "a@b.c" }), headers: { "content-type": "application/json" } });
}

async function main(): Promise<void> {
  // ---- the event is wired (severity + admitted by the public guard) ----
  ok("severityOf(update-available) === warning", severityOf("update-available") === "warning");
  ok("isNotifyEvent admits update-available (selectable in a rule)", isNotifyEvent("update-available") === true);

  // ---- once-per-version idempotency ----
  {
    const { stub } = makeDO();
    ok("first claim for 0.2.0 => alert", (await claim(stub, "0.2.0")) === true);
    ok("second claim for the SAME 0.2.0 => no alert (deduped, never spammed)", (await claim(stub, "0.2.0")) === false);
    ok("third claim for the same version still no alert", (await claim(stub, "0.2.0")) === false);
    // A genuinely NEW version alerts once, then dedupes again.
    ok("a NEW version 0.3.0 => alert once", (await claim(stub, "0.3.0")) === true);
    ok("repeat 0.3.0 => no alert", (await claim(stub, "0.3.0")) === false);
  }

  // ---- a blank / missing / non-string version never claims (no spurious alert) ----
  {
    const { stub } = makeDO();
    ok("blank version => no alert", (await claim(stub, "")) === false);
    ok("whitespace version => no alert", (await claim(stub, "   ")) === false);
    ok("missing version => no alert", (await claim(stub, undefined)) === false);
    ok("non-string version => no alert", (await claim(stub, 123)) === false);
    // ...and a real version still alerts after the no-ops (the no-ops recorded nothing).
    ok("real version after no-ops still alerts", (await claim(stub, "1.0.0")) === true);
  }

  // ---- the claim records the version (so the dedupe survives a re-read) without disturbing pending/last ----
  {
    const { stub, storage } = makeDO();
    // Seed a pending + last record, then claim; pending/last must be preserved, lastAlertedVersion added.
    await stub.fetch("https://do/update-pending", { method: "POST", body: JSON.stringify({ fromVersion: "v-old", toVersion: "v-new", recommendedVersion: "0.2.0", promotedAt: Date.now(), promotedBy: "a@b.c" }), headers: { "content-type": "application/json" } });
    await claim(stub, "0.2.0");
    const rec = storage.rawGet<{ pending: unknown; last: unknown; lastAlertedVersion?: string }>("updateLifecycle")!;
    ok("claim records lastAlertedVersion", rec.lastAlertedVersion === "0.2.0");
    ok("claim preserves the pending record (does not clobber the lifecycle)", rec.pending !== null && (rec.pending as { toVersion?: string }).toVersion === "v-new");
  }

  // ---- the canary cron's "rollback needed" escalation for a promoted-but-unsettled bad version ----------
  // The two-phase apply promotes live then the console settles; if settle never runs and the hourly canary
  // finds the now-live new version unhealthy, the cron claims a ONE-SHOT CRITICAL "rollback needed" alert
  // (the engine holds NO deploy token, so it escalates to a one-click rollback rather than deploying). The
  // claim is deduped + bound to an unsettled pending, and any settle CLEARS the flag.
  ok("severityOf(update-rollback-needed) === critical (page now)", severityOf("update-rollback-needed") === "critical");
  // Like canary-dead, this is a SYSTEM-fired critical, not a user-selectable rule event: it is delivered by
  // "all"-events / critical-severity rules (and the DO's own parseEmission guard, exercised by the claim test
  // below), NOT chosen from the rule event list, so isNotifyEvent returns false, in parity with canary-dead.
  ok("update-rollback-needed is a system critical (not rule-selectable), like canary-dead", isNotifyEvent("update-rollback-needed") === isNotifyEvent("canary-dead"));
  {
    const { stub, storage } = makeDO();
    // No pending -> no escalation (the version is already settled; nothing to roll back).
    ok("rollback-claim with NO pending => no alert", (await claimRollback(stub, "0.2.0")) === false);
    // With an unsettled pending, the FIRST observation pages; repeats are deduped (page once, not hourly).
    await setPending(stub, "0.2.0");
    ok("first rollback-claim for an unsettled pending => alert", (await claimRollback(stub, "0.2.0")) === true);
    ok("second rollback-claim for the SAME version => no alert (deduped)", (await claimRollback(stub, "0.2.0")) === false);
    const rec = storage.rawGet<{ pending: unknown; rollbackNeeded?: { recommendedVersion: string } }>("updateLifecycle")!;
    ok("the rollbackNeeded flag is recorded (the console surfaces the urgent prompt)", rec.rollbackNeeded?.recommendedVersion === "0.2.0");
  }
  {
    // Settling RESOLVES the pending, so the rollback-needed flag is cleared (the urgent prompt goes away).
    const { stub, storage } = makeDO();
    await setPending(stub, "0.2.0");
    await claimRollback(stub, "0.2.0");
    await stub.fetch("https://do/update-settled", { method: "POST", body: JSON.stringify({ outcome: "rolled-back", recommendedVersion: "0.2.0", fromVersion: "v-old", toVersion: "v-new", at: Date.now(), by: "a@b.c" }), headers: { "content-type": "application/json" } });
    const rec = storage.rawGet<{ pending: unknown; rollbackNeeded?: unknown }>("updateLifecycle")!;
    ok("settling clears pending AND the rollbackNeeded flag", rec.pending === null && (rec.rollbackNeeded ?? null) === null);
  }
  {
    // claimUpdateAlert must PRESERVE an existing rollbackNeeded flag (it rebuilds the record).
    const { stub, storage } = makeDO();
    await setPending(stub, "0.2.0");
    await claimRollback(stub, "0.2.0");
    await claim(stub, "0.2.0"); // the W3 update-available claim, which rebuilds the lifecycle record
    const rec = storage.rawGet<{ rollbackNeeded?: { recommendedVersion: string }; lastAlertedVersion?: string }>("updateLifecycle")!;
    ok("the update-available claim preserves the rollbackNeeded flag", rec.rollbackNeeded?.recommendedVersion === "0.2.0" && rec.lastAlertedVersion === "0.2.0");
  }

  console.log(failures === 0 ? "\nUPDATE-ALERT VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
