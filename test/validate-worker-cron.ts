// Cron orchestration cases of the validate-worker suite (split out of test/validate-worker.ts):
// scheduled() handler resilience to a scheduler outage, the seal HAPPY PATH reconciliation sequence,
// the per-run isolation negative controls, the guarded error-path /complete, and the post-run
// alert/expiry/restore-test/digest passes (stocked and error-injected fail-open). No network, no deploy.

import worker from "../src/index.ts";
import type { DigestBatch, DigestSummary, NotifyChannel } from "../src/notify.ts";
import { ok, makeEnv, makeSchedulerStub, makeCronScheduler, runScheduled, dueState, type RecordedCall } from "./validate-worker-helpers.ts";

export async function run(): Promise<void> {
  // -----------------------------------------------------------------------------------------
  // 9. scheduled() handler: drive() throws (scheduler.fetch rejects) -> scheduled() does NOT
  //    rethrow or reject its own waitUntil promise.  The cron must not crash.
  //    We simulate this by giving the scheduler a fetch that always rejects.
  // -----------------------------------------------------------------------------------------
  {
    const throwingStub = makeSchedulerStub(async (_url: string) => {
      throw new Error("simulated scheduler unavailable");
    });
    const env = makeEnv(throwingStub);

    // ExecutionContext.waitUntil receives a Promise; we capture it so we can await it and
    // assert it RESOLVES (does not reject). A rejection here would be an unhandled crash in
    // the cron invocation.
    let capturedPromise: Promise<void> | undefined;
    const ctx = {
      waitUntil: (p: Promise<unknown>) => {
        capturedPromise = p as Promise<void>;
      },
    } as unknown as ExecutionContext;

    // The ScheduledController shape only needs its type; scheduled() does not read it.
    const event = {} as unknown as ScheduledController;

    // scheduled() should return without throwing.
    let scheduledThrew = false;
    try {
      await worker.scheduled(event, env, ctx);
    } catch {
      scheduledThrew = true;
    }
    ok("scheduled() does not throw when drive() rejects", !scheduledThrew);
    ok("scheduled() called ctx.waitUntil", capturedPromise !== undefined);

    // The waitUntil promise (drive()) must RESOLVE (not reject) even when every scheduler
    // fetch throws. drive() catches the per-downpipe errors and logs them; the /tick fetch
    // itself throwing escapes drive() and would reject the waitUntil promise, which counts
    // as a crash in the cron. We await and assert resolution.
    let waitUntilRejected = false;
    if (capturedPromise !== undefined) {
      try {
        await capturedPromise;
      } catch {
        waitUntilRejected = true;
      }
    }
    // A scheduler outage must degrade to a skipped tick, NEVER crash the cron invocation.
    // drive() in src/index.ts guards its /tick+/due preamble in a try/catch that logs and returns
    // early, so the waitUntil promise resolves even when the scheduler DO is unavailable (the
    // durable DO alarms remain the real per-downpipe timers, and the next */15 tick retries).
    ok("scheduled() waitUntil resolves on a scheduler outage (no cron crash)", !waitUntilRejected);
  }

  // -----------------------------------------------------------------------------------------
  // CRON ORCHESTRATION SEAL HAPPY PATH.
  //
  // Drive the REAL worker.scheduled(event, env, ctx) with a mock scheduler that returns ONE due
  // downpipe from /due, and assert the documented reconciliation sequence the cron driver performs:
  //   scheduled() -> ctx.waitUntil(drive()) -> POST /tick -> GET /due -> [per due downpipe]
  //     runDownpipe -> POST /trigger (allocates runId/index) -> sealRun -> POST /complete.
  //
  // The test env deliberately lacks the seal prerequisites (SIGNER_PRIVATE / BREAK_GLASS_PUBLIC /
  // a destination). The sliced seal (seal/runstate.ts) catches the key-load failure INSIDE its own
  // try and reconciles the run with the failure completion AT THE ALLOCATED INDEX:
  // POST /complete { id, runId: "", index: <allocated>, status: "failed", error: <coarse> }. The
  // empty runId leaves lastRunId untouched (the prevRunId chain stays intact); the REAL index
  // resolves the in-flight history row to failed and clears the lease immediately. (The pre-sliced
  // driver let this failure escape to drive()'s index-less catch, whose index-0 completion matched
  // no row, so a misconfigured engine stranded the lease until the 30-minute reclaim; resolving the
  // real row is the corrected contract.) The point of THIS test is the wiring/control flow: each due
  // run is driven to a TERMINAL /complete rather than being left stranded in flight, and the failure
  // NEVER escapes ctx.waitUntil as a crashed cron invocation.
  //
  // Negative controls (so this is not a vacuous "it ran" assertion):
  //  - /trigger MUST be called for the due downpipe (the run was genuinely allocated; the driver
  //    did not skip straight to /complete);
  //  - the call ORDER is /tick before /due before /trigger (the reconciliation preamble precedes the
  //    run, not the other way round);
  //  - the terminal /complete carries runId === "" (the failure completion), NOT a success: a seal
  //    that silently "succeeded" with no keys would be a serious correctness bug, so we assert the
  //    completion is the empty-runId failure shape and that NO success-shaped completion was posted;
  //  - the captured drive() promise RESOLVES (the seal failure was swallowed, not rethrown).
  // -----------------------------------------------------------------------------------------
  {
    const trigger = { runId: "01CRONHAPPYCRONHAPPYCRON", index: 4, prevRunId: "01PREVPREVPREVPREVPREVPR" };
    // Source binds to an ABSENT non-reserved binding; this is irrelevant on this path because the
    // seal throws earlier (no SIGNER_PRIVATE), but it keeps the due state realistic.
    const { stub, calls } = makeCronScheduler([dueState("dp-cron", "KV_SOURCE_ABSENT")], trigger);
    // No SIGNER_PRIVATE / BREAK_GLASS_PUBLIC / DEST_* in env: the seal cannot proceed, by design.
    const env = makeEnv(stub);

    // Silence the expected console.error lines the driver emits for the deliberate seal failure, so
    // the test output stays readable; restore immediately after. (We do not assert on them here; the
    // behaviour under test is the /complete reconciliation, asserted via the recorded calls.)
    const origError = console.error;
    console.error = () => {};
    let res: Awaited<ReturnType<typeof runScheduled>>;
    try {
      res = await runScheduled(env, worker);
    } finally {
      console.error = origError;
    }

    ok("cron: scheduled() does not throw synchronously", !res.scheduledThrew);
    ok("cron: scheduled() handed drive() to ctx.waitUntil", res.waitUntilCaptured);
    ok("cron: drive() promise RESOLVES (seal failure swallowed, no cron crash)", !res.waitUntilRejected);

    const paths = calls.map((c) => c.path);
    // The reconciliation preamble: /tick then /due, in that order, each exactly once.
    ok("cron: POST /tick was called", paths.includes("/tick"));
    ok("cron: GET /due was called", paths.includes("/due"));
    ok("cron: /tick is called before /due", paths.indexOf("/tick") < paths.indexOf("/due") && paths.indexOf("/tick") !== -1);
    // The due downpipe was genuinely allocated a run (NEGATIVE CONTROL: not skipped to /complete).
    ok("cron: /trigger was called for the due downpipe", paths.includes("/trigger"));
    const triggerCall = calls.find((c) => c.path === "/trigger");
    ok(
      "cron: /trigger carried the due downpipe id",
      !!triggerCall && (triggerCall.body as { id?: string } | undefined)?.id === "dp-cron",
    );
    // ORDER: /due (which yields the due list) precedes /trigger (which acts on it).
    ok("cron: /due is called before /trigger", paths.indexOf("/due") < paths.indexOf("/trigger") && paths.indexOf("/due") !== -1);

    // The run is reconciled to a TERMINAL /complete (not stranded in flight).
    const completeCalls = calls.filter((c) => c.path === "/complete");
    ok("cron: a terminal /complete was posted (the run is reconciled, not left in flight)", completeCalls.length === 1);
    const completeBody = completeCalls[0]?.body as { id?: string; runId?: string; index?: number; status?: string } | undefined;
    ok("cron: /complete targets the due downpipe id", completeBody?.id === "dp-cron");
    // The documented empty-runId FAILURE completion: runId "" keeps lastRunId where it is. The
    // sliced seal resolves the run AT ITS ALLOCATED INDEX with status "failed", so the in-flight
    // history row is terminally resolved and the lease clears immediately (no 30-minute reclaim
    // wait for a misconfigured engine).
    ok("cron: terminal /complete is the empty-runId failure completion (runId === '')", completeBody?.runId === "");
    ok("cron: terminal /complete resolves the ALLOCATED index with status failed", completeBody?.index === 4 && completeBody?.status === "failed");
    // NEGATIVE CONTROL: a keyless seal must NOT report success. There must be no completion that
    // carries status:"ok" or a non-empty runId (which would mean lastRunId was wrongly advanced).
    const sawSuccessCompletion = completeCalls.some((c) => {
      const b = c.body as { status?: string; runId?: string } | undefined;
      return b?.status === "ok" || (typeof b?.runId === "string" && b.runId.length > 0);
    });
    ok("cron: NO success-shaped completion was posted (a keyless seal cannot silently succeed)", !sawSuccessCompletion);
    // After reconciling the run, the driver runs its alerting preamble exactly once (proving control
    // flow reached the end of drive() rather than aborting mid-loop). The no-destination reconcile
    // returns an empty batch, so routing is a no-op and no /alerts-delivered feedback call is made.
    ok("cron: /reconcile-alerts ran once after the run loop", paths.filter((p) => p === "/reconcile-alerts").length === 1);
    ok("cron: no /alerts-delivered feedback call (no transition alerts this tick)", !paths.includes("/alerts-delivered"));
    // 3-2-1 replication health: the driver runs the replication reconcile exactly once after the
    // failure-alert stream. The no-replica stub returns an empty batch with no pending transitions, so
    // emitting is a no-op and NO two-phase /replication-alerts-delivered feedback call is made.
    ok("cron: /reconcile-replication-alerts ran once after the alert stream (3-2-1)", paths.filter((p) => p === "/reconcile-replication-alerts").length === 1);
    ok("cron: no /replication-alerts-delivered feedback call (no replication transitions this tick)", !paths.includes("/replication-alerts-delivered"));
    // Contract sections 4 + 5: after the alert stream the driver runs the expiry transition pass and
    // the scheduled-restore-test due-check, each exactly once. With no items/no due tests this tick
    // they return empty and no further round-trip (no notification, no drill) follows.
    ok("cron: /expiry/reconcile ran once after the alert stream (section 4)", paths.filter((p) => p === "/expiry/reconcile").length === 1);
    ok("cron: /restore-tests-due ran once after the alert stream (section 5)", paths.filter((p) => p === "/restore-tests-due").length === 1);
    ok("cron: no scheduled-test round-trip when none are due (no /restore-test-complete, no /drill-evidence)", !paths.includes("/restore-test-complete") && !paths.includes("/drill-evidence"));
    // Contract section 2 (digest flush): after the alert/expiry/restore-test passes the driver runs the
    // digest flush exactly once. With no window elapsed this tick the DO returns an empty batch list, so
    // the flush delivers nothing and posts NO /notify/digest-sent and fetches NO /notify/channel.
    ok("cron: /notify/digest-due ran once after the restore-test pass (section 2)", paths.filter((p) => p === "/notify/digest-due").length === 1);
    ok("cron: no digest delivery round-trip when nothing is due (no /notify/digest-sent, no /notify/channel)", !paths.includes("/notify/digest-sent") && !paths.includes("/notify/channel"));
    // ASVS V14.2.7 (retention prune) + 3-2-1 replication: TWO passes read the downpipe list once each —
    // the retention prune (to find retention-configured downpipes) and the replication pass (to find
    // fan-out downpipes). The test downpipe has neither retention nor replicas, so BOTH return after
    // their read with NO planner/apply or replication round-trip (no /runlog-lock/*, no /audit), no deletion.
    ok("cron: /downpipes read once each by the prune + replication + source-drift passes (V14.2.7 + 3-2-1 + drift)", paths.filter((p) => p === "/downpipes").length === 3);
    ok("cron: no retention apply round-trip when no downpipe has retention (no /runlog-lock, no /audit)", !paths.includes("/runlog-lock/acquire") && !paths.includes("/audit"));
    // NEGATIVE CONTROL on the stub: no UNEXPECTED DO route was hit (every recorded path is one of the
    // routes the cron reconciliation is documented to touch). A new round-trip would fail this.
    const expectedPaths = new Set(["/tick", "/due", "/dest-config", "/trigger", "/complete", "/reconcile-alerts", "/reconcile-replication-alerts", "/expiry/reconcile", "/restore-tests-due", "/canary/due", "/notify/digest-due", "/downpipes", "/cf-config/discovery-due",
      // control-plane auto-reconcile pass (chaos/heal-cp-autoreconcile): a per-tick health read + periodic signed export, gated on SIGNER_PRIVATE.
      "/control-plane/recovery-status", "/control-plane/export-state", "/control-plane/export", "/control-plane/export-recorded", "/control-plane/resume-apply", "/control-plane/stage", "/control-plane/recovery-required", "/control-plane/recovery-refused",
      // CPR needs-new-logging: the deterministic per-tick deploy-identity observation, the health pass's
      // amnesia-probe class, the export-pass health, and the notify-pipeline drop counter (on a fail-open path).
      "/control-plane/deploy-observe", "/control-plane/amnesia-probe", "/control-plane/export-health", "/notify/health-bump",
      // fleet-drill pass (chaos/heal-scale).
      "/fleet-drill/next",
      // proactive source-drift pass: the per-tick missing-source edge-trigger.
      "/source-drift/reconcile",
      // scheduled security-centre evaluation: the cheap per-tick due check (the full posture compute +
      // WORM probe only runs when the 6-hour interval has lapsed; see src/cron/posture-pass.ts).
      "/posture/evaluation-due", "/posture",
      // per-tick OUTCOME record (scheduler-liveness new-logging): the end-of-invocation false-green detector.
      "/tick-outcome",
      // Single-flight tick lease: drive() acquires it at the top of the tick and releases it at the end,
      // so two overlapping */15 cron ticks do not both run the pass sequence (a duplicate seal is already
      // coalesced by the per-run in-flight lease; this guards the one non-idempotent tail, the digest flush).
      "/tick-lease/acquire", "/tick-lease/release",
      // SIEM audit-log push destination (SIEM-PUSH-DESIGN.md): the drain's per-tick config read
      // (always made, opt-in no-op when unconfigured); this stub answers null, so no further push round-trip.
      "/push-config",
      // OTLP/HTTP metrics push (mon-otlp M2): the drain's per-tick config read (always made, opt-in no-op
      // when unconfigured), plus the metrics snapshot + outcome record it makes only once a destination is set.
      "/otlp-push-config", "/otlp-metrics-snapshot", "/otlp-push-record",
      // The support-pack DIAGNOSTIC recorder family (support-pack gap audit). These are the
      // best-effort, never-throwing writes that record WHY a pass faulted, so the pack stops going quietly
      // empty during the very incident it exists to explain. They are deliberately IN this allowlist rather
      // than exempted from it: a diagnostic write is a real round-trip with a real subrequest cost, and it
      // must stay a NAMED, reviewed member of the cron's DO surface, not an invisible one.
      //
      // /diag/dropped-writes is the meta-recorder: it lands the count of diagnostic writes that were THEMSELVES
      // dropped, and it is piggy-backed on the next write that succeeds -- so it appears here exactly when an
      // earlier diagnostic write failed against this stub, which is the behaviour it exists to have.
      //
      // /diag/admin-counters is the cron drain's ALARM BELL: the rich, structured evidence for each fault
      // rides the cron-health delta above, and the ONE headline fact of each -- a critical page consumed
      // and never delivered, a restore test that did not run, a push-trail write that was lost -- is also
      // raised as a closed admin-counter name, because the pack already carries that aggregate in full. It
      // is raised ONLY on a tick that recorded such a fault (a healthy tick posts nothing here and costs no
      // subrequest), which is why it is a named member of this reviewed surface rather than an
      // unconditional per-tick write.
      "/diag/cron-health", "/diag/admin-counters", "/diag/dropped-writes", "/diag/run-faults", "/diag/integrity-faults", "/diag/dest-probe-faults", "/diag/dispatch-fault"]);
    ok("cron: only the documented DO routes were called (no stray round-trip)", paths.every((p) => expectedPaths.has(p)));
  }

  // -----------------------------------------------------------------------------------------
  // 11. CRON RECONCILES EVERY DUE RUN: when /due returns TWO downpipes and the FIRST one's seal
  //     fails, the driver must STILL trigger AND reconcile the SECOND (the per-downpipe try/catch
  //     in drive() isolates a failure to its own run). This is the negative control proving drive()
  //     does not abort the loop on the first failure and strand the rest of the batch.
  // -----------------------------------------------------------------------------------------
  {
    const trigger = { runId: "01TWORUNTWORUNTWORUNTWOR", index: 1, prevRunId: null };
    const { stub, calls } = makeCronScheduler(
      [dueState("dp-one", "KV_A_ABSENT"), dueState("dp-two", "KV_B_ABSENT")],
      trigger,
    );
    const env = makeEnv(stub); // again no keys: BOTH seals fail and BOTH must be reconciled

    const origError = console.error;
    console.error = () => {};
    let res: Awaited<ReturnType<typeof runScheduled>>;
    try {
      res = await runScheduled(env, worker);
    } finally {
      console.error = origError;
    }

    ok("cron(2): drive() promise resolves with two failing runs", !res.waitUntilRejected);
    const triggered = calls.filter((c) => c.path === "/trigger").map((c) => (c.body as { id?: string }).id);
    ok("cron(2): BOTH due downpipes were triggered", triggered.includes("dp-one") && triggered.includes("dp-two"));
    const completedIds = calls.filter((c) => c.path === "/complete").map((c) => (c.body as { id?: string }).id);
    ok("cron(2): BOTH due downpipes were reconciled to /complete", completedIds.includes("dp-one") && completedIds.includes("dp-two"));
    ok("cron(2): exactly two terminal completions (one per due run, none stranded)", completedIds.length === 2);
    // Every completion is the empty-runId failure shape (no keys -> both fail at key-load).
    const allEmptyRunId = calls
      .filter((c) => c.path === "/complete")
      .every((c) => (c.body as { runId?: string }).runId === "");
    ok("cron(2): every completion is the empty-runId failure completion (no false success)", allEmptyRunId);
  }

  // -----------------------------------------------------------------------------------------
  // The per-downpipe run-loop catch posts a best-effort /complete to clear the lock. That completion
  //     is GUARDED in its own try/catch so a DO blip DURING error handling cannot reject drive() (which
  //     would crash the cron and strand the rest of the due batch). We drive the REAL scheduled() with a
  //     scheduler whose /complete ALWAYS throws while the run itself also fails (no SIGNER_PRIVATE), and
  //     assert the captured drive() promise still RESOLVES.
  //
  // NEGATIVE CONTROL: with TWO due downpipes whose /complete both throw, BOTH must still be attempted
  // (the guard isolates the completion failure to its own iteration, so the loop does not abort after
  // the first).
  // -----------------------------------------------------------------------------------------
  {
    // A scheduler that drives the run loop but THROWS on every /complete (the error-path lock clear).
    const calls: RecordedCall[] = [];
    const due = [dueState("dp-a", "KV_A_ABSENT"), dueState("dp-b", "KV_B_ABSENT")];
    const stub = makeSchedulerStub(async (url: string, init?: RequestInit) => {
      const path = new URL(url).pathname;
      let body: unknown = undefined;
      if (typeof init?.body === "string") { try { body = JSON.parse(init.body); } catch { body = init.body; } }
      calls.push({ path, body });
      if (path === "/tick") return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
      if (path === "/due") return new Response(JSON.stringify({ due }), { headers: { "content-type": "application/json" } });
      if (path === "/dest-config") return new Response(JSON.stringify({ config: null }), { headers: { "content-type": "application/json" } });
      if (path === "/trigger") return new Response(JSON.stringify({ runId: "01R11R11R11R11R11R11R11R1", index: 1, prevRunId: null }), { headers: { "content-type": "application/json" } });
      // The error-path lock clear ALWAYS throws (simulated DO blip during error handling).
      if (path === "/complete") throw new Error("simulated DO blip during /complete");
      // The post-run preamble (alerts/expiry/restore/digest) must still complete without crashing.
      if (path === "/reconcile-alerts") return new Response(JSON.stringify({ alerts: [], pendingTransitionIds: [] }), { headers: { "content-type": "application/json" } });
      // The 3-2-1 replication alert stream, the canary-due read and the cf-config discovery-due read are
      // real post-run round-trips; they MUST be stubbed with the same empty shapes makeCronScheduler uses so
      // a future drive() change that makes one of them required is not silently absorbed as a 500 here.
      if (path === "/reconcile-replication-alerts") return new Response(JSON.stringify({ emissions: [], pendingTransitionIds: [] }), { headers: { "content-type": "application/json" } });
      if (path === "/expiry/reconcile") return new Response(JSON.stringify({ emissions: [] }), { headers: { "content-type": "application/json" } });
      if (path === "/restore-tests-due") return new Response(JSON.stringify({ due: [] }), { headers: { "content-type": "application/json" } });
      if (path === "/canary/due") return new Response(JSON.stringify({ due: false }), { headers: { "content-type": "application/json" } });
      if (path === "/notify/digest-due") return new Response(JSON.stringify({ batches: [] }), { headers: { "content-type": "application/json" } });
      if (path === "/cf-config/discovery-due") return new Response(JSON.stringify({ due: [] }), { headers: { "content-type": "application/json" } });
      // The retention prune pass reads the downpipe list; none have retention here, so it returns
      // after this read (no apply, no deletion). Returning [] keeps the pass a clean no-op.
      if (path === "/downpipes") return new Response(JSON.stringify([]), { headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ unexpected: path }), { status: 500, headers: { "content-type": "application/json" } });
    });
    const env = makeEnv(stub); // no keys: both seals fail, so both reach the guarded /complete

    const origError = console.error;
    console.error = () => {};
    let res: Awaited<ReturnType<typeof runScheduled>>;
    try {
      res = await runScheduled(env, worker);
    } finally {
      console.error = origError;
    }

    ok("scheduled() does not throw synchronously", !res.scheduledThrew);
    ok("drive() RESOLVES even though every error-path /complete throws (no cron crash)", !res.waitUntilRejected);
    // NEGATIVE CONTROL: BOTH due runs were triggered AND both reached the (throwing) /complete, proving
    // the guard isolated the first completion failure and the loop did not abort.
    const triggered = calls.filter((c) => c.path === "/trigger").map((c) => (c.body as { id?: string }).id);
    ok("both due downpipes were triggered (loop not aborted by the first /complete throw)", triggered.includes("dp-a") && triggered.includes("dp-b"));
    const completed = calls.filter((c) => c.path === "/complete").map((c) => (c.body as { id?: string }).id);
    ok("both due downpipes reached the guarded /complete attempt", completed.includes("dp-a") && completed.includes("dp-b"));
    // The flush still ran after the loop (control flow reached the end of drive() despite the throws).
    ok("the post-run digest flush still ran (drive reached its tail)", calls.some((c) => c.path === "/notify/digest-due"));
  }

  // -----------------------------------------------------------------------------------------
  // 15. DRIVE POST-RUN PASSES (STOCKED): the alert / expiry / scheduled-restore-test / digest loop
  //     BODIES must execute when the DO returns non-empty work, not just the empty-batch fast paths the
  //     happy-path test covers. We drive the REAL scheduled() with a scheduler that returns: two alerts
  //     (a failed + a stale, both flagged as transitions), one expiry emission, one restore-test-due
  //     downpipe (env has NO OPERATIONAL_PRIVATE, so runScheduledRestoreTest takes the break-glass-only
  //     INFO path: recency + drill-evidence + an info emission, never a false pass), and one digest batch
  //     delivered to an enabled channel. /due is empty so the heavy seal loop (covered by the happy-path
  //     test) is not re-run. globalThis.fetch is stubbed so a webhook delivery does not touch the network.
  // -----------------------------------------------------------------------------------------
  {
    const calls: RecordedCall[] = [];
    const ALERT_FAILED = { id: "dp-failed", name: "Failed pipe", state: "failed" as const };
    const ALERT_STALE = { id: "dp-stale", name: "Stale pipe", state: "stale" as const };
    // An enabled webhook channel the alert/expiry routing AND the digest flush deliver to (so the
    // deliverEmission / deliverToChannel paths run; the webhook POST is the stubbed global fetch).
    const CHANNEL: NotifyChannel = {
      id: "ch-1", kind: "webhook", name: "ops", url: "https://hooks.example.com/abc", enabled: true, createdAt: "2026-01-01T00:00:00.000Z",
    };
    const DIGEST_SUMMARY: DigestSummary = {
      total: 2, byEvent: { "backup-success": 2 }, downpipeNames: ["Primary", "Secondary"],
      accountLevelCount: 0, fromAt: "2026-06-09T00:00:00.000Z", toAt: "2026-06-10T00:00:00.000Z",
    };
    // The cron only reads channelId / summary / seqs from a batch; the extra DigestBatch fields are set
    // for an honest, fully-typed literal (no loose cast).
    const DIGEST_BATCH_OK: DigestBatch = { channelId: "ch-1", channelKind: "webhook", period: "daily", summary: DIGEST_SUMMARY, detail: "Digest: 2 updates", seqs: [1, 2] };
    const DIGEST_BATCH_BADCH: DigestBatch = { channelId: "ch-missing", channelKind: "webhook", period: "daily", summary: DIGEST_SUMMARY, detail: "Digest: 2 updates", seqs: [3] };

    const stub = makeSchedulerStub(async (url: string, init?: RequestInit) => {
      const u = new URL(url);
      const path = u.pathname;
      let body: unknown = undefined;
      if (typeof init?.body === "string") { try { body = JSON.parse(init.body); } catch { body = init.body; } }
      calls.push({ path, body });
      if (path === "/tick") return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
      if (path === "/due") return new Response(JSON.stringify({ due: [] }), { headers: { "content-type": "application/json" } });
      if (path === "/dest-config") return new Response(JSON.stringify({ config: null }), { headers: { "content-type": "application/json" } });
      // Two alerts, both transitions, so both the event-mapping arms and the transition-feedback arms run.
      if (path === "/reconcile-alerts") {
        return new Response(JSON.stringify({ alerts: [ALERT_FAILED, ALERT_STALE], pendingTransitionIds: [ALERT_FAILED.id, ALERT_STALE.id] }), { headers: { "content-type": "application/json" } });
      }
      // routeNotification resolves to the enabled channel, so deliverEmission/deliverToChannel run and the
      // records.some(delivered) feedback path executes (the webhook POST is the stubbed global fetch).
      if (path === "/notify/resolve") {
        return new Response(JSON.stringify({ now: [CHANNEL], digestedCount: 0, emission: body }), { headers: { "content-type": "application/json" } });
      }
      if (path === "/notify/record") return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
      if (path === "/alerts-delivered") return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
      // One expiry emission, so the expiry loop body + routeNotification run.
      if (path === "/expiry/reconcile") {
        return new Response(JSON.stringify({ emissions: [{ id: "cred-1", detail: "BREAK_GLASS_PUBLIC expires in 14 days" }] }), { headers: { "content-type": "application/json" } });
      }
      // One restore-test-due downpipe; env has no OPERATIONAL_PRIVATE so the break-glass INFO path runs.
      if (path === "/restore-tests-due") {
        return new Response(JSON.stringify({ due: [dueState("dp-rt", "KV_RT")] }), { headers: { "content-type": "application/json" } });
      }
      if (path === "/restore-test-complete") return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
      if (path === "/drill-evidence") return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
      // Two digest batches: one to the enabled channel (delivery + record + clear), one whose channel
      // fetch throws (the per-batch catch path; those seqs are NOT cleared).
      if (path === "/notify/digest-due") {
        return new Response(JSON.stringify({ batches: [DIGEST_BATCH_OK, DIGEST_BATCH_BADCH] }), { headers: { "content-type": "application/json" } });
      }
      if (path === "/notify/channel") {
        const id = u.searchParams.get("id");
        if (id === "ch-1") return new Response(JSON.stringify({ channel: CHANNEL }), { headers: { "content-type": "application/json" } });
        // ch-missing: a malformed body so `await chResp.json()` throws -> the per-batch catch runs.
        return new Response("not json", { headers: { "content-type": "application/json" } });
      }
      if (path === "/notify/digest-sent") return new Response(JSON.stringify({ cleared: (body as { ids?: number[] }).ids?.length ?? 0 }), { headers: { "content-type": "application/json" } });
      // The 3-2-1 replication alert stream, the canary-due read and the cf-config discovery-due read are real
      // post-run round-trips with no work due here; stub them with the empty shapes makeCronScheduler uses so
      // a future required round-trip is not silently absorbed as a 500.
      if (path === "/reconcile-replication-alerts") return new Response(JSON.stringify({ emissions: [], pendingTransitionIds: [] }), { headers: { "content-type": "application/json" } });
      if (path === "/canary/due") return new Response(JSON.stringify({ due: false }), { headers: { "content-type": "application/json" } });
      if (path === "/cf-config/discovery-due") return new Response(JSON.stringify({ due: [] }), { headers: { "content-type": "application/json" } });
      // The retention prune pass reads the downpipe list; none have retention here, so it is a no-op
      // after this read (env also has no OPERATIONAL_PRIVATE, the break-glass-only deferral). Returning
      // [] keeps the pass clean (no apply, no deletion round-trip).
      if (path === "/downpipes") return new Response(JSON.stringify([]), { headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ unexpected: path }), { status: 500, headers: { "content-type": "application/json" } });
    });
    const env = makeEnv(stub); // deliberately NO OPERATIONAL_PRIVATE -> restore test takes the break-glass path

    const origFetch = globalThis.fetch;
    const origError = console.error;
    let webhookHits = 0;
    globalThis.fetch = (async () => { webhookHits++; return new Response("", { status: 200 }); }) as typeof fetch;
    console.error = () => {};
    let res: Awaited<ReturnType<typeof runScheduled>>;
    try {
      res = await runScheduled(env, worker);
    } finally {
      globalThis.fetch = origFetch;
      console.error = origError;
    }
    const paths = calls.map((c) => c.path);
    ok("15: scheduled() does not throw and drive() resolves with stocked post-run work", !res.scheduledThrew && !res.waitUntilRejected);
    // Alert loop body ran for BOTH alerts (two /notify/resolve, one per emission), and the transition
    // feedback was posted.
    ok("15: the alert loop resolved channels for both alerts", calls.filter((c) => c.path === "/notify/resolve").length >= 2);
    ok("15: the transition-delivery feedback was posted (/alerts-delivered)", paths.includes("/alerts-delivered"));
    // The webhook delivery actually ran (deliverEmission -> deliverToChannel -> the stubbed POST).
    ok("15: at least one channel delivery POST was attempted (deliverEmission path ran)", webhookHits >= 1);
    // Expiry loop body ran.
    ok("15: the expiry reconcile + routing ran", paths.includes("/expiry/reconcile"));
    // Restore-test loop body ran: the break-glass path records recency + evidence (no false pass).
    ok("15: the scheduled restore-test loop ran (recency recorded)", paths.includes("/restore-test-complete"));
    ok("15: the scheduled restore-test recorded a drill-evidence entry", paths.includes("/drill-evidence"));
    const rtEvidence = calls.find((c) => c.path === "/drill-evidence");
    ok("15: the break-glass restore test recorded OFFLINE-REHEARSAL evidence (not a false pass)", (rtEvidence?.body as { kind?: string })?.kind === "offline-rehearsal");
    // Digest flush delivered the good batch and cleared exactly its seqs; the bad-channel batch's seqs
    // were NOT cleared (the per-batch catch path left them pending).
    const cleared = (calls.find((c) => c.path === "/notify/digest-sent")?.body as { ids?: number[] })?.ids ?? [];
    ok("15: the digest flush cleared the delivered batch's seqs only", cleared.includes(1) && cleared.includes(2) && !cleared.includes(3));
  }

  // -----------------------------------------------------------------------------------------
  // 16. DRIVE POST-RUN FAIL-OPEN (ERROR-INJECTED): every best-effort sub-step's catch arm must degrade,
  //     never crash the cron. We drive scheduled() with a scheduler whose /alerts-delivered, the
  //     restore-test recency record (/restore-test-complete), the drill-evidence write (/drill-evidence),
  //     and the digest channel fetch all THROW, with one alert transition, one restore-test-due downpipe,
  //     and one digest batch. drive() must still RESOLVE and every loop must complete.
  // -----------------------------------------------------------------------------------------
  {
    const calls: RecordedCall[] = [];
    const stub = makeSchedulerStub(async (url: string, init?: RequestInit) => {
      const u = new URL(url);
      const path = u.pathname;
      let body: unknown = undefined;
      if (typeof init?.body === "string") { try { body = JSON.parse(init.body); } catch { body = init.body; } }
      calls.push({ path, body });
      if (path === "/tick") return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
      if (path === "/due") return new Response(JSON.stringify({ due: [] }), { headers: { "content-type": "application/json" } });
      if (path === "/dest-config") return new Response(JSON.stringify({ config: null }), { headers: { "content-type": "application/json" } });
      if (path === "/reconcile-alerts") {
        return new Response(JSON.stringify({ alerts: [{ id: "dp-x", name: "X", state: "failed" }], pendingTransitionIds: ["dp-x"] }), { headers: { "content-type": "application/json" } });
      }
      // No channels resolve, so routeNotification returns false early (the alert is a failed transition
      // whose delivery is empty -> failedTransitionIds), exercising the no-channel arm.
      if (path === "/notify/resolve") return new Response(JSON.stringify({ now: [], digestedCount: 0, emission: null }), { headers: { "content-type": "application/json" } });
      // The transition feedback POST THROWS -> the fire-and-forget .catch arm runs (non-critical).
      if (path === "/alerts-delivered") throw new Error("simulated /alerts-delivered blip");
      // The 3-2-1 replication alert stream, the canary-due read and the cf-config discovery-due read are real
      // post-run round-trips; stub them with the empty shapes makeCronScheduler uses (this test injects faults
      // elsewhere) so they are explicit, not silently absorbed 500s.
      if (path === "/reconcile-replication-alerts") return new Response(JSON.stringify({ emissions: [], pendingTransitionIds: [] }), { headers: { "content-type": "application/json" } });
      if (path === "/canary/due") return new Response(JSON.stringify({ due: false }), { headers: { "content-type": "application/json" } });
      if (path === "/cf-config/discovery-due") return new Response(JSON.stringify({ due: [] }), { headers: { "content-type": "application/json" } });
      if (path === "/expiry/reconcile") return new Response(JSON.stringify({ emissions: [] }), { headers: { "content-type": "application/json" } });
      if (path === "/restore-tests-due") return new Response(JSON.stringify({ due: [dueState("dp-rt2", "KV_RT2")] }), { headers: { "content-type": "application/json" } });
      // Both best-effort restore-test record writes THROW -> recordRestoreTestOutcome's two catch arms run.
      if (path === "/restore-test-complete") throw new Error("simulated recency blip");
      if (path === "/drill-evidence") throw new Error("simulated evidence blip");
      // A single digest batch whose channel fetch THROWS -> the flush per-batch catch arm runs.
      if (path === "/notify/digest-due") return new Response(JSON.stringify({ batches: [{ channelId: "ch-z", channelKind: "webhook", period: "daily", summary: { total: 1, byEvent: {}, downpipeNames: [], accountLevelCount: 0, fromAt: "", toAt: "" }, detail: "Digest: 1 update", seqs: [9] }] }), { headers: { "content-type": "application/json" } });
      if (path === "/notify/channel") throw new Error("simulated channel fetch blip");
      if (path === "/notify/digest-sent") return new Response(JSON.stringify({ cleared: 0 }), { headers: { "content-type": "application/json" } });
      // The retention prune pass reads the downpipe list; to also exercise its FAIL-OPEN arm here, the
      // list read THROWS, and drive() must still resolve (the pass is wrapped, like every other tail
      // pass). The assertion below confirms the cron survives every injected fault including this one.
      if (path === "/downpipes") throw new Error("simulated /downpipes blip");
      return new Response(JSON.stringify({ unexpected: path }), { status: 500, headers: { "content-type": "application/json" } });
    });
    const env = makeEnv(stub);
    const origError = console.error;
    console.error = () => {};
    let res: Awaited<ReturnType<typeof runScheduled>>;
    try {
      res = await runScheduled(env, worker);
    } finally {
      console.error = origError;
    }
    ok("16: drive() RESOLVES even when every best-effort sub-step throws (full fail-open)", !res.scheduledThrew && !res.waitUntilRejected);
    const paths = calls.map((c) => c.path);
    // Every loop was still reached despite the injected throws.
    ok("16: the alert loop still attempted the (throwing) delivery feedback", paths.includes("/alerts-delivered"));
    ok("16: the restore-test loop still attempted the (throwing) recency + evidence writes", paths.includes("/restore-test-complete") && paths.includes("/drill-evidence"));
    ok("16: the digest flush still attempted the (throwing) channel fetch", paths.includes("/notify/channel"));
    // The bad-channel batch's seqs were NOT cleared (catch path), so no digest-sent with that seq.
    const cleared16 = (calls.find((c) => c.path === "/notify/digest-sent")?.body as { ids?: number[] })?.ids ?? [];
    ok("16: the thrown-channel digest batch left its seq pending (not cleared)", !cleared16.includes(9));
  }
}
