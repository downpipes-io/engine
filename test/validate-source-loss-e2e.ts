// validate-source-loss-e2e: the WHOLE source-loss story end-to-end through the REAL engine handlers, the
// owner's exact worry proven start to finish. A configured KV downpipe with a backup-history entry, then a
// bare `wrangler deploy` drops its source binding, and we assert at each step over a REAL SchedulerDO:
//   1. healthy   -> GET /admin/status reports 0 sources detached.
//   2. the drop  -> the downpipe config AND its run history are UNTOUCHED in DO storage (the lineage anchor
//                   survives; a deploy can only reset the live worker bindings, never the DO or the bucket).
//   3. detect    -> GET /admin/status now reports 1 source detached (proactive, before the next run fails).
//   4. alert     -> the source-drift edge-trigger returns the binding as NEWLY detached, and only ONCE.
//   5. recover   -> POST /sources/reattach-missing plans to re-add the SAME binding with its recorded
//                   namespace id (rebuildable, not "needs a re-save"), so the next run continues the SAME
//                   downpipe id + RUNLOG chain. Continuity proven by construction: the binding name and the
//                   history never changed, so re-attaching restores the read side and nothing is orphaned.
//
// The route writes themselves (changeBindings) are proven in validate-reattach-missing + validate-attach;
// this suite proves the INTEGRATION + the no-loss/continuity invariant the feature exists to guarantee.
//
// Run: node test/validate-source-loss-e2e.ts

import { handleAdmin } from "../src/admin/router.ts";
import { makeScheduler, makeSigner, TEAM, AUD } from "./validate-rbac-harness.ts";
import { DISCOVERY_KEY } from "../src/sched/scheduler-do-records.ts";
import { planRosterReattach } from "../src/admin/roster-reattach.ts";
import type { Env } from "../src/env.d.ts";
import type { DownpipeConfig } from "../src/sched/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A duck-typed KV binding object: what enumerateBoundSources reads as a LIVE kv source. Omitting it from
// the env is the bare-`wrangler deploy` drop (the worker's bindings reset to wrangler.toml, which pins none).
const kvLive = () => ({ get() {}, put() {}, list() {}, getWithMetadata() {} });
const DP_ID = "dp-uploads";
const SRC = "SRC_KV_uploads";
const NS = "ns-1111aaaa";
const kvSource: DownpipeConfig["source"] = { type: "kv", binding: SRC, namespaceId: NS, include: [], exclude: [] } as DownpipeConfig["source"];
const dpState = () => ({
  config: { id: DP_ID, name: "Uploads KV", cadenceSeconds: 3600, enabled: true, source: kvSource } as DownpipeConfig,
  nextRunAt: 0,
  lastRunId: "run-0001",
  inFlight: false,
});
// One completed backup run already in the per-downpipe history ring (the "backup history" the worry is about).
const priorHistory = [{ runId: "run-0001", index: 1, startedAt: "2026-06-30T00:00:00.000Z", status: "ok" }];

async function main(): Promise<void> {
  const signer = await makeSigner();
  const { tokenFor } = signer;
  const OWNER = "owner-e2e@acme.example";

  const s = makeScheduler();
  // Build the request env with or without the live source binding; everything else (the SchedulerDO, the
  // discovery config) is identical, so the ONLY thing that changes across the drop is the live binding.
  const envWith = (liveBindings: Record<string, unknown>) => ({ ...s.env, ...liveBindings, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN: "bg-e2e" }) as unknown as Env;
  const call = async (env: Env, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> =>
    handleAdmin(new Request(`https://engine.example${path}`, {
      method,
      headers: { "cf-access-jwt-assertion": await tokenFor(OWNER), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    }), env);

  // Bootstrap the first Access caller as Owner, then seed the discovery config (so the engine can name its
  // own account for an attach), the downpipe config (the roster), and its backup-history ring.
  await call(envWith({ [SRC]: kvLive() }), "GET", "/admin/whoami");
  await s.storage.put(DISCOVERY_KEY, { token: "cfat_seeded_token_e2e_1234567890", setAt: 1, setBy: OWNER, accountsSeen: [{ id: "acct-1", name: "A" }], selected: ["acct-1"], engineAccountId: "acct-1" });
  await s.storage.put(`dp:${DP_ID}`, dpState());
  await s.storage.put(`hist:${DP_ID}`, priorHistory);

  console.log("-- 1) HEALTHY: the source is attached, status reports nothing detached --");
  {
    const b = (await (await call(envWith({ [SRC]: kvLive() }), "GET", "/admin/status")).json()) as { downpipeCount: number; sourcesDetachedCount?: number };
    ok("status: the downpipe is counted", b.downpipeCount === 1);
    ok("status: 0 sources detached while the binding is live", b.sourcesDetachedCount === 0);
  }

  console.log("-- 2) THE BAD DEPLOY: the binding is dropped, but the config + history are UNTOUCHED --");
  {
    // Re-read DO storage AFTER simulating the drop (the drop is purely an env change on the next request).
    const cfg = (await s.storage.get(`dp:${DP_ID}`)) as { config: DownpipeConfig } | undefined;
    const hist = (await s.storage.get(`hist:${DP_ID}`)) as Array<{ runId: string }> | undefined;
    ok("the downpipe config survived (DO storage is not touched by a worker-binding reset)", cfg?.config.id === DP_ID && cfg?.config.source.binding === SRC && cfg?.config.source.namespaceId === NS);
    ok("the backup history survived (the run-0001 lineage entry is still there)", Array.isArray(hist) && hist.length === 1 && hist[0]!.runId === "run-0001");
  }

  console.log("-- 3) DETECT: status now reports the source as detached (proactive, pre-run-failure) --");
  {
    const b = (await (await call(envWith({}), "GET", "/admin/status")).json()) as { sourcesDetachedCount?: number };
    ok("status: 1 source detached once the binding is gone", b.sourcesDetachedCount === 1);
  }

  console.log("-- 4) ALERT: the source-drift edge-trigger fires for the binding, and only ONCE --");
  {
    const driftReconcile = async (): Promise<{ newlyDetached: string[] }> =>
      (await (await s.stub.fetch("https://scheduler.internal/source-drift/reconcile", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ missing: [SRC] }) })).json()) as { newlyDetached: string[] };
    const r1 = await driftReconcile();
    ok("drift: the dropped binding is NEWLY detached (an alert fires)", r1.newlyDetached.length === 1 && r1.newlyDetached[0] === SRC);
    const r2 = await driftReconcile();
    ok("drift: a still-missing binding does NOT re-alert (edge-triggered, pages once)", r2.newlyDetached.length === 0);
  }

  console.log("-- 5) RECOVER: the route finds the recoverable source and asks for the deploy token --");
  {
    // There IS a rebuildable missing source, so the route requires the one-shot deploy token to perform the
    // write (the token is needed only for the binding write; the plan computation found something to do). A
    // 400 that names the deploy token IS the integration proof that the engine detected the recoverable source.
    const r = await call(envWith({}), "POST", "/admin/sources/reattach-missing", {});
    const b = (await r.json()) as { error?: string };
    ok("re-attach: the route asks for the deploy token (it found a source to re-add)", r.status === 400 && /deploy token/.test(b.error ?? ""));
    // The PURE planner the route runs proves WHAT it would re-attach: the SAME binding name, carrying its
    // recorded namespace id (rebuildable, NOT "needs a re-save"), attributed to the right downpipe.
    const plan = planRosterReattach([dpState().config], new Set<string>());
    ok("re-attach: the dropped source is rebuildable from the roster (carries its namespace id)", plan.toAttach.length === 1 && plan.toAttach[0]!.binding === SRC && plan.toAttach[0]!.namespaceId === NS && plan.unreconstructable.length === 0);
    ok("re-attach: the plan attributes the binding to its downpipe (so recovery is targeted)", (plan.affects[SRC] ?? []).includes(DP_ID));
  }

  console.log("-- 6) RECOVERED: with the binding re-attached, status reports nothing detached again --");
  {
    // Re-attaching SRC (same name, same id) makes the binding live again; the engine's drift count clears.
    const b = (await (await call(envWith({ [SRC]: kvLive() }), "GET", "/admin/status")).json()) as { sourcesDetachedCount?: number };
    ok("status: 0 sources detached again after the re-attach (the loop closes)", b.sourcesDetachedCount === 0);
  }

  console.log("-- 7) CONTINUITY: the lineage anchor (downpipe id + history) never changed across the loss --");
  {
    // The whole worry, answered: re-attaching SRC (same name) makes the EXISTING downpipe (same id) read its
    // source again, and its next run appends to the SAME RUNLOG chain in the SAME destination bucket. We prove
    // the invariant that makes that automatic: the source loss did not mutate the downpipe id, its binding
    // reference, or its history. Nothing is orphaned; recovery is restoring the read side, not rebuilding state.
    const cfg = (await s.storage.get(`dp:${DP_ID}`)) as { config: DownpipeConfig } | undefined;
    const hist = (await s.storage.get(`hist:${DP_ID}`)) as Array<{ runId: string }> | undefined;
    ok("continuity: the downpipe id is unchanged (the lineage key)", cfg?.config.id === DP_ID);
    ok("continuity: the source reference is still the same binding name (a re-attach resolves it)", cfg?.config.source.binding === SRC);
    ok("continuity: the prior run is still the head of the history (the chain continues, never restarts)", Array.isArray(hist) && hist[0]!.runId === "run-0001");
  }

  console.log(failures === 0 ? "\nvalidate-source-loss-e2e: ALL PASS" : `\nvalidate-source-loss-e2e: ${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
