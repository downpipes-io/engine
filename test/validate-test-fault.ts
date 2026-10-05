// Prove the HARNESS-ONLY engine test-fault-hook (the owner-gated /admin/test-fault/* surface that lets the
// self-update fault-provocation journeys provoke engine-INTERNAL faults):
//   node test/validate-test-fault.ts
//
// The safety property that matters: a real deployment never sets HARNESS_TEST_FAULTS, so the whole surface
// does not exist there (every /admin/test-fault/* path 404s BEFORE any auth), and the consumption side is
// separately gated so no fault can fire. This drives the REAL router + REAL Durable Object (all mixins, not a
// shim) and the REAL consume helpers + gate/driver wrappers. In-memory doubles only; no network, no deploy.

import { handleAdmin } from "../src/admin/router.ts";
import { classifyDestError } from "../src/dest/classify.ts";
import { consumeArmedFault, consumeControlPlaneRecoveryFault, consumeDestHeaderFault, consumeDropSourceBindingFault, consumeHourlyCanaryFault, consumeSettleFault, deployFailingDriver, forcedDeadGate, HARNESS_CONTROL_PLANE_FAULT_REASON, headerFaultingDestination, maybeHeaderFaultDestination, testFaultsEnabled } from "../src/admin/test-faults.ts";
import type { DeployDriver, HealthGate } from "../src/admin/update-types.ts";
import type { Destination } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ADMIN = "harness-admin-secret-xyz-1234567890";

import { MockStorage } from "./mock-storage.ts";

function makeDO(): { storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(u, init));
    },
  } as unknown as DurableObjectStub;
  return { storage, stub };
}

function envWith(opts: { faults: boolean; stub: DurableObjectStub }): Env {
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => opts.stub,
  } as unknown as DurableObjectNamespace;
  return {
    SCHEDULER: namespace,
    ADMIN_TOKEN: ADMIN,
    CONSOLE_ORIGIN: "https://harness.downpipes.io",
    ...(opts.faults ? { HARNESS_TEST_FAULTS: "1" } : {}),
  } as unknown as Env;
}

const DO = "https://scheduler.internal";
async function doJson(stub: DurableObjectStub, method: string, path: string, body?: unknown): Promise<any> {
  const r = await stub.fetch(`${DO}${path}`, { method, ...(body !== undefined ? { headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : {}) });
  return r.json();
}

// ---- 1. The DO store directly: arm -> read -> consume (single-shot) -> cleared, plus per-seam selectivity ----
async function testDOStore(): Promise<void> {
  const { stub } = makeDO();
  // Unknown kind arms NOTHING (defence in depth, the Worker validates too).
  ok("DO: an unknown kind arms nothing", (await doJson(stub, "POST", "/test-fault/arm", { kind: "bogus" })).armed === false);
  ok("DO: status after a rejected arm is null", (await doJson(stub, "GET", "/test-fault/status")).armed === null);

  // Each of the six kinds: arm -> status shows it -> consume (by its seam's kinds) fires ONCE -> cleared.
  for (const kind of ["canary-dead", "rollback-deploy-fail", "hourly-canary-unhealthy", "drop-source-binding", "dest-header-corrupt", "control-plane-recovery-required"]) {
    ok(`DO: arm ${kind} -> armed:true`, (await doJson(stub, "POST", "/test-fault/arm", { kind })).armed === true);
    ok(`DO: status shows ${kind} armed`, (await doJson(stub, "GET", "/test-fault/status")).armed?.kind === kind);
    const first = await doJson(stub, "POST", "/test-fault/consume", { kinds: [kind] });
    ok(`DO: consume ${kind} fires once`, first.fault?.kind === kind);
    ok(`DO: ${kind} self-cleared after firing`, (await doJson(stub, "GET", "/test-fault/status")).armed === null);
    const second = await doJson(stub, "POST", "/test-fault/consume", { kinds: [kind] });
    ok(`DO: ${kind} is single-shot (a second consume is null)`, second.fault === null);
  }

  // SELECTIVITY: a settle's verdict seam consumes only {canary-dead,rollback-deploy-fail}, so a
  // drop-source-binding armed for the SAME settle survives for the binding-diff seam to consume.
  ok("DO: arm drop-source-binding{binding} -> armed", (await doJson(stub, "POST", "/test-fault/arm", { kind: "drop-source-binding", binding: "KV_ACCOUNTS" })).armed === true);
  const verdictSeam = await doJson(stub, "POST", "/test-fault/consume", { kinds: ["canary-dead", "rollback-deploy-fail"] });
  ok("DO: the verdict seam leaves a drop-source-binding fault armed", verdictSeam.fault === null);
  ok("DO: the binding fault still armed after the verdict seam", (await doJson(stub, "GET", "/test-fault/status")).armed?.kind === "drop-source-binding");
  const bindingSeam = await doJson(stub, "POST", "/test-fault/consume", { kinds: ["drop-source-binding"] });
  ok("DO: the binding seam consumes it WITH the named binding", bindingSeam.fault?.kind === "drop-source-binding" && bindingSeam.fault?.binding === "KV_ACCOUNTS");

  // disarm clears an armed fault (best-effort cleanup).
  await doJson(stub, "POST", "/test-fault/arm", { kind: "canary-dead" });
  ok("DO: disarm returns disarmed:true", (await doJson(stub, "POST", "/test-fault/disarm")).disarmed === true);
  ok("DO: status is null after disarm", (await doJson(stub, "GET", "/test-fault/status")).armed === null);
}

// ---- 2. The router: HARD GATE (no flag -> 404 before auth), auth gate, Owner happy path ----
const rf = (host: string, path: string, method: string, headers?: Record<string, string>, body?: unknown): Request =>
  new Request(`${host}/admin/test-fault/${path}`, { method, ...(headers ? { headers } : {}), ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });

async function testRouterHardGate(): Promise<void> {
  // No HARNESS_TEST_FAULTS: EVERY /admin/test-fault/* path 404s, even WITH a valid ADMIN_TOKEN bearer, BEFORE
  // any auth (a production engine has no fault surface at all).
  const { stub } = makeDO();
  const env = envWith({ faults: false, stub });
  for (const [method, path] of [["GET", "status"], ["POST", "arm"], ["POST", "disarm"], ["POST", "canary-tick"], ["POST", "control-plane-clear"]] as const) {
    const r = await handleAdmin(rf("https://harness.downpipes.io", path, method, { Authorization: `Bearer ${ADMIN}` }, method === "POST" ? { kind: "canary-dead" } : undefined), env);
    ok(`router: no flag -> ${method} ${path} 404s (no surface in production)`, r.status === 404);
  }
  // No flag + NO auth also 404s (the 404 is BEFORE auth, so it is not a 401).
  const noAuth = await handleAdmin(rf("https://harness.downpipes.io", "status", "GET"), env);
  ok("router: no flag + no auth -> 404 (gate is before auth, never a 401)", noAuth.status === 404);
}

async function testRouterAuthGate(): Promise<void> {
  const { stub } = makeDO();
  const env = envWith({ faults: true, stub });
  // Flag on but NO credential -> 401 (the route now exists, but the admin auth gate refuses).
  ok("router: flag on + no auth -> 401", (await handleAdmin(rf("https://harness.downpipes.io", "status", "GET"), env)).status === 401);
  // Flag on + WRONG bearer -> 401.
  ok("router: flag on + wrong bearer -> 401", (await handleAdmin(rf("https://harness.downpipes.io", "status", "GET", { Authorization: "Bearer not-the-admin-token" }), env)).status === 401);
}

async function testRouterOwnerHappyPath(): Promise<void> {
  const { stub } = makeDO();
  const env = envWith({ faults: true, stub });
  const auth = { Authorization: `Bearer ${ADMIN}` };
  // The probe the harness reads: GET status -> {harnessFaultHook:true, controlPlaneFaultHook:true, armed:null}.
  const status = await handleAdmin(rf("https://harness.downpipes.io", "status", "GET", auth), env);
  ok("router: Owner GET /status -> 200", status.status === 200);
  const sBody = (await status.json()) as { harnessFaultHook?: boolean; controlPlaneFaultHook?: boolean; armed?: unknown };
  ok("router: status reports harnessFaultHook:true", sBody.harnessFaultHook === true);
  // This is the exact field lib/verbs-recovery-transitions.ts's probeControlPlaneFaultHook reads, so an
  // undefined value here would leave that probe unable to see the hook at all.
  ok("router: status reports controlPlaneFaultHook:true", sBody.controlPlaneFaultHook === true);
  ok("router: status starts armed:null", sBody.armed === null);

  // Arm each of the six kinds over the router; status reflects it; then disarm clears it.
  for (const kind of ["canary-dead", "rollback-deploy-fail", "hourly-canary-unhealthy", "drop-source-binding", "dest-header-corrupt", "control-plane-recovery-required"]) {
    const arm = await handleAdmin(rf("https://harness.downpipes.io", "arm", "POST", { ...auth, "content-type": "application/json" }, { kind, ...(kind === "drop-source-binding" ? { binding: "R2_ARCHIVE" } : {}) }), env);
    const armBody = (await arm.json()) as { armed?: boolean };
    ok(`router: Owner arms ${kind} -> {armed:true}`, arm.status === 200 && armBody.armed === true);
    const st = (await (await handleAdmin(rf("https://harness.downpipes.io", "status", "GET", auth), env)).json()) as { armed?: { kind?: string } };
    ok(`router: status reflects ${kind} armed`, st.armed?.kind === kind);
    const dis = await handleAdmin(rf("https://harness.downpipes.io", "disarm", "POST", auth), env);
    ok(`router: disarm ${kind} -> {disarmed:true}`, ((await dis.json()) as { disarmed?: boolean }).disarmed === true);
  }
  // An unknown kind is refused with 400 (the closed set is enforced at the Worker too).
  const bad = await handleAdmin(rf("https://harness.downpipes.io", "arm", "POST", { ...auth, "content-type": "application/json" }, { kind: "wipe-everything" }), env);
  ok("router: Owner arms an unknown kind -> 400", bad.status === 400);
}

// ---- 3. The consume helpers: OFF unless the flag is set (byte-identical production), and the wrappers ----
async function testConsumeHelpersGatedOff(): Promise<void> {
  const { stub } = makeDO();
  // Arm every kind in the DO, then prove that with the flag OFF the helpers do NOT consume (and do not even
  // touch the DO): the consumption side is gated independently of the arming side.
  await doJson(stub, "POST", "/test-fault/arm", { kind: "canary-dead" });
  let fetches = 0;
  const countingStub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      fetches++;
      const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return stub.fetch(u, init);
    },
  } as unknown as DurableObjectStub;
  const offEnv = { } as unknown as Env; // no HARNESS_TEST_FAULTS
  ok("helpers: testFaultsEnabled false without the flag", testFaultsEnabled(offEnv) === false);
  ok("helpers: consumeSettleFault is null with the flag off", (await consumeSettleFault(offEnv, countingStub)) === null);
  ok("helpers: consumeDropSourceBindingFault is null with the flag off", (await consumeDropSourceBindingFault(offEnv, countingStub)) === null);
  ok("helpers: consumeHourlyCanaryFault is false with the flag off", (await consumeHourlyCanaryFault(offEnv, countingStub)) === false);
  ok("helpers: consumeDestHeaderFault is false with the flag off", (await consumeDestHeaderFault(offEnv, countingStub)) === false);
  ok("helpers: consumeControlPlaneRecoveryFault is false with the flag off", (await consumeControlPlaneRecoveryFault(offEnv, countingStub)) === false);
  ok("helpers: NO Durable Object round-trip happened with the flag off", fetches === 0);
  // The armed fault is UNTOUCHED (still armed): the flag-off path never reached the store.
  ok("helpers: the armed fault is untouched with the flag off", (await doJson(stub, "GET", "/test-fault/status")).armed?.kind === "canary-dead");
}

async function testConsumeHelpersFire(): Promise<void> {
  const { stub } = makeDO();
  const onEnv = { HARNESS_TEST_FAULTS: "1" } as unknown as Env;
  ok("helpers: testFaultsEnabled true with the flag", testFaultsEnabled(onEnv) === true);
  // canary-dead fires through the settle helper and clears.
  await doJson(stub, "POST", "/test-fault/arm", { kind: "canary-dead" });
  ok("helpers: consumeSettleFault returns canary-dead when armed", (await consumeSettleFault(onEnv, stub)) === "canary-dead");
  ok("helpers: consumeSettleFault is single-shot (null next time)", (await consumeSettleFault(onEnv, stub)) === null);
  // rollback-deploy-fail fires through the settle helper.
  await doJson(stub, "POST", "/test-fault/arm", { kind: "rollback-deploy-fail" });
  ok("helpers: consumeSettleFault returns rollback-deploy-fail when armed", (await consumeSettleFault(onEnv, stub)) === "rollback-deploy-fail");
  // drop-source-binding returns the named binding through its own helper (and the settle helper ignores it).
  await doJson(stub, "POST", "/test-fault/arm", { kind: "drop-source-binding", binding: "D1_LEDGER" });
  ok("helpers: consumeSettleFault ignores a drop-source-binding fault", (await consumeSettleFault(onEnv, stub)) === null);
  ok("helpers: consumeDropSourceBindingFault returns the named binding", (await consumeDropSourceBindingFault(onEnv, stub)) === "D1_LEDGER");
  // hourly-canary-unhealthy fires through the cron helper.
  await doJson(stub, "POST", "/test-fault/arm", { kind: "hourly-canary-unhealthy" });
  ok("helpers: consumeHourlyCanaryFault true when armed", (await consumeHourlyCanaryFault(onEnv, stub)) === true);
  ok("helpers: consumeHourlyCanaryFault single-shot (false next time)", (await consumeHourlyCanaryFault(onEnv, stub)) === false);
  // dest-header-corrupt fires through the seal-write helper (and the settle helper ignores it, so the two
  // seams never cross-consume).
  await doJson(stub, "POST", "/test-fault/arm", { kind: "dest-header-corrupt" });
  ok("helpers: consumeSettleFault ignores a dest-header-corrupt fault", (await consumeSettleFault(onEnv, stub)) === null);
  ok("helpers: consumeDestHeaderFault true when armed", (await consumeDestHeaderFault(onEnv, stub)) === true);
  ok("helpers: consumeDestHeaderFault single-shot (false next time)", (await consumeDestHeaderFault(onEnv, stub)) === false);
  // control-plane-recovery-required fires through its own helper (and the settle helper ignores it, so the
  // update-fault seams and the control-plane seam never cross-consume each other's kind).
  await doJson(stub, "POST", "/test-fault/arm", { kind: "control-plane-recovery-required" });
  ok("helpers: consumeSettleFault ignores a control-plane-recovery-required fault", (await consumeSettleFault(onEnv, stub)) === null);
  ok("helpers: consumeControlPlaneRecoveryFault true when armed", (await consumeControlPlaneRecoveryFault(onEnv, stub)) === true);
  ok("helpers: consumeControlPlaneRecoveryFault single-shot (false next time)", (await consumeControlPlaneRecoveryFault(onEnv, stub)) === false);
}

// ---- 3b. POST-SWAP TOLERANCE: the consume RETRIES through the isolate-reset window --
// A settle/cron consume runs on the JUST-PROMOTED isolate, whose code swap resets every Durable Object, so a
// SINGLE un-retried consume round-trip in that window reads back null and an armed fault never injects (a
// fault-injection MISS, not a product defect). consumeArmedFault mirrors the settle canary's bounded retry
// (update-gate.ts probeSettleVerdict): it retries ONLY an UNAVAILABLE round-trip (thrown / non-ok, the reset
// window) and returns a CLEAN answer (a fault, or a definitive empty) at once, so the normal no-fault path
// never spins. sleep is injected here so the vectors never wait for real.

// flakyConsumeStub wraps a real DO stub so the first `failFirst` /test-fault/consume round-trips are UNAVAILABLE
// (a thrown fetch or a 503, the two shapes the reset window takes), then it delegates to the real DO. Every
// other path (arm/status) always delegates, so the fault can be armed and read back normally.
function flakyConsumeStub(real: DurableObjectStub, opts: { failFirst: number; mode: "throw" | "503" }): { stub: DurableObjectStub; consumeCalls: () => number } {
  let calls = 0;
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (u.includes("/test-fault/consume")) {
        calls++;
        if (calls <= opts.failFirst) {
          return opts.mode === "throw"
            ? Promise.reject(new Error("Durable Object reset because its code was updated (simulated post-swap window)"))
            : Promise.resolve(new Response("service unavailable", { status: 503 }));
        }
      }
      return real.fetch(u, init);
    },
  } as unknown as DurableObjectStub;
  return { stub, consumeCalls: () => calls };
}

async function testPostSwapConsumeRetry(): Promise<void> {
  const schedule = [1, 1, 1] as const; // a fixed 3-slot budget; sleep is injected, so these are never real waits.

  // (a) HEALTHY DO + fault armed: fires on the FIRST read, and NEVER sleeps (the fault path is not slowed).
  {
    const { stub } = makeDO();
    await doJson(stub, "POST", "/test-fault/arm", { kind: "canary-dead" });
    const slept: number[] = [];
    const got = await consumeArmedFault(stub, ["canary-dead"], { backoffMs: schedule, sleep: async (ms) => { slept.push(ms); } });
    ok("retry: a healthy DO fires the armed fault on the first read", got?.kind === "canary-dead");
    ok("retry: the healthy fault path never slept (no over-poll)", slept.length === 0);
  }

  // (b) HEALTHY DO + NOTHING armed: returns null on the FIRST read, NEVER sleeps. This is the NORMAL no-fault
  //     settle/cron path -- byte-identical in behaviour to before the fix (no spin, no added latency).
  {
    const { stub } = makeDO();
    const slept: number[] = [];
    const got = await consumeArmedFault(stub, ["canary-dead", "rollback-deploy-fail"], { backoffMs: schedule, sleep: async (ms) => { slept.push(ms); } });
    ok("retry: an empty store returns null on the first read (the normal no-fault path)", got === null);
    ok("retry: the empty/normal path never slept", slept.length === 0);
  }

  // (c) THE WINDOW: the consume round-trip is UNAVAILABLE for the first two reads, then clears. The retry must
  //     ride through and STILL fire the armed fault -- the exact fault-injection miss this closes. Both shapes.
  for (const mode of ["throw", "503"] as const) {
    const { stub: real } = makeDO();
    await doJson(real, "POST", "/test-fault/arm", { kind: "rollback-deploy-fail" });
    const { stub, consumeCalls } = flakyConsumeStub(real, { failFirst: 2, mode });
    const slept: number[] = [];
    const got = await consumeArmedFault(stub, ["canary-dead", "rollback-deploy-fail"], { backoffMs: schedule, sleep: async (ms) => { slept.push(ms); } });
    ok(`retry (${mode}): the armed fault fires once the post-swap window clears`, got?.kind === "rollback-deploy-fail");
    ok(`retry (${mode}): it retried exactly through the unavailable window`, slept.length === 2 && consumeCalls() === 3);
  }

  // (d) BOUNDED + FAIL-SAFE: a DO that NEVER clears exhausts the budget (three sleeps, four reads) then returns
  //     null. It must never hang; a fault that could not be read leaves the harness net-zero read-back as the
  //     authority (the same fail-safe the pre-fix single read already had, now after a bounded retry).
  {
    const { stub: real } = makeDO();
    await doJson(real, "POST", "/test-fault/arm", { kind: "canary-dead" });
    const { stub, consumeCalls } = flakyConsumeStub(real, { failFirst: 99, mode: "throw" });
    const slept: number[] = [];
    const got = await consumeArmedFault(stub, ["canary-dead"], { backoffMs: schedule, sleep: async (ms) => { slept.push(ms); } });
    ok("retry: an unavailable DO that never clears fails safe to null (never hangs)", got === null);
    ok("retry: the retry budget is bounded (one read + N backoff reads, no more)", slept.length === schedule.length && consumeCalls() === schedule.length + 1);
  }

  // (e) SELECTIVITY holds under the retry: with a drop-source-binding armed, the verdict seam's kinds read
  //     CLEAN-empty and return null AT ONCE (no retry), leaving the binding fault for its own seam (077's one
  //     settle carrying both a verdict fault and a binding fault still works).
  {
    const { stub } = makeDO();
    await doJson(stub, "POST", "/test-fault/arm", { kind: "drop-source-binding", binding: "KV_ACCOUNTS" });
    const slept: number[] = [];
    const verdict = await consumeArmedFault(stub, ["canary-dead", "rollback-deploy-fail"], { backoffMs: schedule, sleep: async (ms) => { slept.push(ms); } });
    ok("retry: the verdict seam reads clean-empty past a non-matching armed fault (no retry)", verdict === null && slept.length === 0);
    ok("retry: the drop-source-binding fault survives for its own seam", (await doJson(stub, "GET", "/test-fault/status")).armed?.kind === "drop-source-binding");
  }
}

async function testWrappers(): Promise<void> {
  // forcedDeadGate: the flight is DEAD; baseline and selfCheck delegate to the real gate.
  const realGate: HealthGate = {
    baseline: async () => "alive",
    flyNow: async () => "alive",
    selfCheck: async () => true,
    flyNowMeasured: async () => ({ status: "alive", measured: true }),
  };
  const dead = forcedDeadGate(realGate);
  ok("wrapper: forcedDeadGate flyNow -> dead", (await dead.flyNow()) === "dead");
  ok("wrapper: forcedDeadGate flyNowMeasured -> dead + measured", JSON.stringify(await dead.flyNowMeasured!()) === JSON.stringify({ status: "dead", measured: true }));
  ok("wrapper: forcedDeadGate baseline delegates (alive)", (await dead.baseline()) === "alive");
  ok("wrapper: forcedDeadGate selfCheck delegates (true)", (await dead.selfCheck()) === true);

  // deployFailingDriver: deployVersion THROWS; every read method passes through.
  let uploaded = "";
  const realDriver: DeployDriver = {
    currentLiveVersionId: async () => "0.1.9",
    deployVersion: async () => {
      uploaded = "REAL-DEPLOY-RAN";
    },
    uploadVersion: async () => "v-new",
  };
  const failing = deployFailingDriver(realDriver);
  ok("wrapper: deployFailingDriver passes currentLiveVersionId through", (await failing.currentLiveVersionId()) === "0.1.9");
  ok("wrapper: deployFailingDriver passes uploadVersion through", (await failing.uploadVersion(new Uint8Array(), { version: "x" })) === "v-new");
  let threw = false;
  try {
    await failing.deployVersion("0.1.9");
  } catch {
    threw = true;
  }
  ok("wrapper: deployFailingDriver deployVersion THROWS", threw);
  ok("wrapper: the real deploy never ran (the throw preceded it)", uploaded === "");
}

// ---- 4. The dest-header seam: the destination WRITE wrapper + the gated consume-and-wrap ----
async function testDestHeaderWrapper(): Promise<void> {
  // A recording Destination double: every method notes the call so we can prove the wrapper NEVER reached the
  // real write and DID delegate every read.
  const calls: string[] = [];
  const realDest: Destination = {
    get: async (k: string) => { calls.push(`get ${k}`); return { body: new Uint8Array([1]), etag: "e-real" }; },
    put: async (k: string) => { calls.push(`put ${k}`); },
    putStream: async (k: string) => { calls.push(`putStream ${k}`); },
    putConditional: async (k: string) => { calls.push(`putConditional ${k}`); return { ok: true, etag: "e-real" }; },
    exists: async (k: string) => { calls.push(`exists ${k}`); return true; },
    delete: async (k: string) => { calls.push(`delete ${k}`); },
    list: async (p: string) => { calls.push(`list ${p}`); return ["a"]; },
  };

  const faulted = headerFaultingDestination(realDest);
  // put / putStream THROW, and the throw PRECEDES the real write, so no bytes ever reach the store.
  let putErr: unknown;
  try { await faulted.put("seg/0001", new Uint8Array()); } catch (e) { putErr = e; }
  ok("dest-header: headerFaultingDestination put THROWS", putErr instanceof Error);
  // THE SEAM REFUTER: the thrown header fault carries no status/network vocabulary, so classifyDestError reads
  // it PERMANENT -- withRetry fails it on the first attempt and the inline-throttle routing never park-and-
  // resumes it, so the run fails terminally rather than healing on a later slice.
  ok("dest-header: the header fault classifies PERMANENT (fails loud on attempt 1, never a throttle park)", classifyDestError(putErr) === "permanent");
  let streamErr: unknown;
  try { await faulted.putStream("seg/0002", undefined as unknown as ReadableStream<Uint8Array>, 1); } catch (e) { streamErr = e; }
  ok("dest-header: headerFaultingDestination putStream THROWS", streamErr instanceof Error);
  ok("dest-header: the real archive write NEVER ran (the header fault preceded it)", !calls.some((c) => c.startsWith("put ") || c.startsWith("putStream ")));

  // Every non-write method DELEGATES to the real destination unchanged (a wrapped seal still reads/lists/
  // conditional-writes/deletes exactly as before, so only the archive WRITE is faulted).
  ok("dest-header: get delegates to the real destination", (await faulted.get("k"))?.etag === "e-real" && calls.includes("get k"));
  ok("dest-header: exists delegates", (await faulted.exists("k")) === true && calls.includes("exists k"));
  ok("dest-header: putConditional delegates (the RUNLOG write is NOT faulted)", (await faulted.putConditional("k", new Uint8Array(), {})).ok === true && calls.includes("putConditional k"));
  ok("dest-header: list delegates", JSON.stringify(await faulted.list("p")) === JSON.stringify(["a"]) && calls.includes("list p"));

  // maybeHeaderFaultDestination: flag OFF -> the destination is returned UNCHANGED (same reference), and no DO
  // is ever consulted (byte-identical production). A write on it succeeds (not faulted).
  const offEnv = {} as unknown as Env;
  const passthrough = await maybeHeaderFaultDestination(offEnv, realDest);
  ok("dest-header: flag OFF returns the destination unchanged (no wrap, no consume)", passthrough === realDest);

  // Flag ON + a dest-header-corrupt fault armed -> the returned destination is WRAPPED (its write throws), and
  // the fault is single-shot: a second build (fault consumed) returns the destination unchanged.
  const { stub } = makeDO();
  const onEnv = envWith({ faults: true, stub });
  await doJson(stub, "POST", "/test-fault/arm", { kind: "dest-header-corrupt" });
  const wrapped = await maybeHeaderFaultDestination(onEnv, realDest);
  ok("dest-header: flag ON + armed returns a WRAPPED destination", wrapped !== realDest);
  let wrappedThrew = false;
  try { await wrapped.put("seg/0003", new Uint8Array()); } catch { wrappedThrew = true; }
  ok("dest-header: the wrapped destination's write THROWS", wrappedThrew);
  const secondBuild = await maybeHeaderFaultDestination(onEnv, realDest);
  ok("dest-header: single-shot -- the next seal build is UNWRAPPED (fault self-cleared)", secondBuild === realDest);

  // Flag ON + NOTHING armed -> unchanged (the normal harness-estate seal path is not faulted).
  const cleanBuild = await maybeHeaderFaultDestination(onEnv, realDest);
  ok("dest-header: flag ON + nothing armed returns the destination unchanged", cleanBuild === realDest);
}

// ---- 5. THE CONTROL-PLANE fault: the REAL router + REAL DO, GET /admin/control-plane/status --
// consume seam plus the harness-only control-plane-clear release. probeControlPlaneFaultHook needs this hook
// to be reachable rather than unavailable: the vectors below PLANT the arm and DEMAND the real latch,
// mirroring section 4's plant-and-demand shape for dest-header-corrupt.
async function testControlPlaneRecoveryFault(): Promise<void> {
  const { stub } = makeDO();
  const env = envWith({ faults: true, stub });
  const auth = { Authorization: `Bearer ${ADMIN}` };
  const cpStatus = (): Request => new Request("https://harness.downpipes.io/admin/control-plane/status", { method: "GET", headers: auth });

  // Healthy baseline: nothing armed, the real plane reads recoveryRequired:false.
  const baseline = (await (await handleAdmin(cpStatus(), env)).json()) as { recoveryRequired?: boolean };
  ok("control-plane fault: a healthy plane reads recoveryRequired:false before anything is armed", baseline.recoveryRequired === false);

  // Arm control-plane-recovery-required over the router, then read the status route: the fault fires ONCE at
  // the read seam and calls the REAL setControlPlaneRecoveryRequired (the same DO method the cron health pass
  // uses on a genuine wipe), so this read carries the genuine latched plane, never a spoofed response.
  const arm = await handleAdmin(rf("https://harness.downpipes.io", "arm", "POST", { ...auth, "content-type": "application/json" }, { kind: "control-plane-recovery-required" }), env);
  ok("control-plane fault: arm control-plane-recovery-required -> {armed:true}", arm.status === 200 && ((await arm.json()) as { armed?: boolean }).armed === true);

  const first = (await (await handleAdmin(cpStatus(), env)).json()) as { recoveryRequired?: boolean; reason?: string | null };
  ok("control-plane fault: the FIRST read after arming latches recoveryRequired:true", first.recoveryRequired === true);
  ok("control-plane fault: the reason names the harness fault (redaction-safe)", first.reason === HARNESS_CONTROL_PLANE_FAULT_REASON);

  // The INJECTION is single-shot (the armed record is consumed, not re-armed), but the REAL latch it set
  // persists -- exactly as a genuine wipe's latch persists -- so a second read, with nothing re-armed, still
  // sees it: the seam changed real state, it did not spoof one response.
  ok("control-plane fault: single-shot -- the fault record is consumed, not left armed", (await doJson(stub, "GET", "/test-fault/status")).armed === null);
  const second = (await (await handleAdmin(cpStatus(), env)).json()) as { recoveryRequired?: boolean };
  ok("control-plane fault: a SECOND read (nothing re-armed) still sees the persisted real latch", second.recoveryRequired === true);

  // The harness-only clear releases the REAL latch (unreachable in production; proven by the hard-gate test),
  // and the plane reads healthy again -- net-zero, the way the dormant harness leg's own header describes it.
  const clear = await handleAdmin(rf("https://harness.downpipes.io", "control-plane-clear", "POST", auth), env);
  ok("control-plane fault: POST /test-fault/control-plane-clear -> {cleared:true}", clear.status === 200 && ((await clear.json()) as { cleared?: boolean }).cleared === true);
  const after = (await (await handleAdmin(cpStatus(), env)).json()) as { recoveryRequired?: boolean };
  ok("control-plane fault: after the clear the plane reads recoveryRequired:false again", after.recoveryRequired === false);

  // FLAG OFF: arm directly in the DO store (bypassing the gated router), then prove the status-READ seam
  // never consumes it and never touches the real latch -- byte-identical production behaviour, exactly like
  // testConsumeHelpersGatedOff proves for the update-fault family.
  const { stub: offStub } = makeDO();
  await doJson(offStub, "POST", "/test-fault/arm", { kind: "control-plane-recovery-required" });
  const offEnv = envWith({ faults: false, stub: offStub });
  const offRead = (await (await handleAdmin(cpStatus(), offEnv)).json()) as { recoveryRequired?: boolean };
  ok("control-plane fault: flag OFF -- the status read never consumes the armed fault (recoveryRequired stays false)", offRead.recoveryRequired === false);
  ok("control-plane fault: flag OFF -- the fault is left armed, untouched (the seam never even checked)", (await doJson(offStub, "GET", "/test-fault/status")).armed?.kind === "control-plane-recovery-required");
}

async function main(): Promise<void> {
  await testDOStore();
  await testRouterHardGate();
  await testRouterAuthGate();
  await testRouterOwnerHappyPath();
  await testConsumeHelpersGatedOff();
  await testConsumeHelpersFire();
  await testPostSwapConsumeRetry();
  await testWrappers();
  await testDestHeaderWrapper();
  await testControlPlaneRecoveryFault();

  console.log(failures === 0 ? "\nTEST-FAULT-HOOK VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
