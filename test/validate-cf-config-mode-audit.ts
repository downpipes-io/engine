// validate-cf-config-mode-audit: a cf-config capture-mode change must reach the audit trail and config history.
//
// POST /admin/downpipes/cf-config/mode decides what the next cf-config run captures. It wrote no audit row, and
// the config snapshot had no mode field, so no history version was written and an approver under dual control
// saw an empty diff.
//
// Driven through the production handleAdmin router and a real SchedulerDO (validate-config-change-control-
// harness.ts). It proves:
//  - gate off: an inline mode change writes a downpipe-create success row that names the downpipe;
//  - gate off: it writes a config-history version whose diff names the capture-mode change;
//  - gate on: the queued change carries a diff line that names the capture-mode change (not an empty diff);
//  - a refused mode change (unknown downpipe) writes a failed row;
//  - a kv downpipe's snapshot carries no mode field, so versions of other sources are unchanged.
//
// Run: node test/validate-cf-config-mode-audit.ts

import { buildContext, OWNER } from "./validate-config-change-control-harness.ts";
import { snapshotConfig } from "../src/admin/config-snapshot.ts";
import type { DownpipeConfig } from "../src/sched/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const { ctx, realFetch } = await buildContext();
const { call, ok } = ctx;
const DP = "cfmode-audit-dp";

try {
  // Seed a cf-config downpipe directly (its account scope is not under test here).
  await ctx.sched.storage.put(`dp:${DP}`, {
    config: { id: DP, name: "CF config", cadenceSeconds: 3600, enabled: true, source: { type: "cf-config", accountId: "acc-1", cfConfigMode: "auto", include: [], exclude: [] } },
    nextRunAt: Date.now() + 3600_000,
    lastRunId: null,
    inFlight: false,
  });
  // A first versioned mutation, so the mode change below has a head version to diff against.
  const kvUpsert = await call(OWNER, "POST", "/admin/downpipes", ctx.dp("cfmodekv", "kv dp"));
  ok("setup: a kv downpipe upsert applies (200)", kvUpsert.status === 200);
  const headBefore = (await ctx.configHistory()).headId;
  // The audit rows appended after a given head seq (the feed's order is not assumed).
  const rowsAfter = async (seq: number) => (await ctx.readLog()).events.filter((e) => e.seq > seq);
  const rowsBefore = (await ctx.readLog()).headSeq;

  // GATE OFF: an inline mode change.
  const off = await call(OWNER, "POST", "/admin/downpipes/cf-config/mode", { id: DP, mode: "manual" });
  ok("gate off: the mode change applies inline (200)", off.status === 200);
  const rows = await rowsAfter(rowsBefore);
  console.log(`  new audit rows: ${JSON.stringify(rows.map((e) => `${e.action}:${e.outcome}`))}`);
  const row = rows.find((e) => e.action === "downpipe-create" && e.outcome === "success");
  ok("gate off: the mode change writes a downpipe-create success row", row !== undefined);
  ok("gate off: the row names the downpipe and the caller", row !== undefined && JSON.stringify(row.target) === JSON.stringify({ kind: "downpipe", id: DP }) && row.actorEmail === OWNER);

  const hist = await ctx.configHistory();
  ok("gate off: the mode change writes a config-history version", hist.headId > headBefore);
  const diff = await ctx.configDiff(headBefore, hist.headId);
  console.log(`  history diff: ${JSON.stringify(diff.changes?.map((c) => c.text) ?? [])}`);
  ok("gate off: the version diff names the capture-mode change", (diff.changes ?? []).some((c) => c.area === "downpipe" && c.text.includes("capture mode auto -> manual")));

  // A refused mode change: the DO throws on an unknown downpipe (400).
  const failedBefore = (await ctx.readLog()).headSeq;
  const unknown = await call(OWNER, "POST", "/admin/downpipes/cf-config/mode", { id: "no-such-dp", mode: "auto" });
  ok("an unknown downpipe is refused (400)", unknown.status === 400);
  const failedRows = await rowsAfter(failedBefore);
  ok("the refused mode change writes a downpipe-create failed row", failedRows.some((e) => e.action === "downpipe-create" && e.outcome === "failed"));

  // GATE ON: the change is queued. The approver must see what changes.
  await ctx.setGate(OWNER, true);
  const on = await call(OWNER, "POST", "/admin/downpipes/cf-config/mode", { id: DP, mode: "auto" });
  ok("gate on: the mode change is queued (202)", on.status === 202);
  const id = ((await on.json()) as { id?: string }).id ?? "";
  const pending = (await ctx.pendingChanges(OWNER)).find((c) => c.id === id);
  console.log(`  pending diff: ${JSON.stringify(pending?.diff.map((l) => l.text) ?? null)}`);
  ok("gate on: the queued change's diff names the capture-mode change", (pending?.diff ?? []).some((l) => l.text.includes("capture mode manual -> auto")));

  // A non-cf-config downpipe's snapshot carries no mode field, even when a stray value is stored.
  const kv = { ...ctx.dp("snap-kv", "kv"), source: { type: "kv", binding: "KV_x", include: [], exclude: [], cfConfigMode: "manual" } } as unknown as DownpipeConfig;
  const snap = snapshotConfig({ downpipes: [kv], roles: [], groupRoles: [], customRoles: [], notifyChannels: [], notifyRules: [], riskAccepts: [], expiryItems: [], coverage: null });
  ok("a kv downpipe's snapshot carries no cfConfigMode field", snap.downpipes[0] !== undefined && !("cfConfigMode" in snap.downpipes[0].source));
} finally {
  globalThis.fetch = realFetch;
}

const failures = ctx.getFailures();
console.log(failures === 0 ? "\nVALIDATE-CF-CONFIG-MODE-AUDIT VECTORS PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
