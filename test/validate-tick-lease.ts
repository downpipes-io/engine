// Prove the cron driver's SINGLE-FLIGHT tick lease end to end with in-memory doubles only. No
// network, no deploy, no cost. Run:
//   node test/validate-tick-lease.ts
//
// Why this exists: the scheduled() handler runs drive() with no lock, so two OVERLAPPING
// */15 cron ticks (a slow tick still in flight when the platform fires the next one, possibly in a separate
// isolate) could both run the pass sequence. The per-run in-flight lease inside trigger() already COALESCES a
// duplicate SEAL (the scary part is not reachable), and the alert/expiry/replication/source-drift/canary/
// update-alert tail passes each dedupe atomically in the DO -- but the digest flush does NOT (digestDue only
// READS; the paired digestSent clears AFTER out-of-band delivery), so an overlap could deliver the same digest
// twice. The fix is a DO-level single-flight lease drive() takes at the top of a tick and releases at the end.
//
// PART A (the DO lease primitive, exercised through the REAL routes POST /tick-lease/acquire + /release, the
// same the cron driver calls): mirrors validate-runlog-lock.ts's negative-control discipline.
//   - acquire on a free lease returns acquired:true + a fresh token, and persists it with a future expiry;
//   - a SECOND acquire while the lease is live is REFUSED (acquired:false, no token leaked) -- the property
//     that makes two overlapping ticks single-flight;
//   - release with the correct token frees it, and a re-acquire mints a DIFFERENT token (a genuine re-grant);
//   - a LEASE-EXPIRED lease is reclaimable WITHOUT a release (the crash backstop: an evicted tick self-heals);
//   - a STALE/WRONG or missing token does NOT free another tick's lease (a superseded slow tick cannot free
//     the newer tick's lease), and the classic suspended-writer hazard is covered.
//
// PART B (the end-to-end guard, driving the REAL worker.scheduled() -> drive()):
//   - GRANT+RELEASE: a tick that acquires the lease runs the full pass sequence AND releases the lease at the
//     end (so the next */15 tick runs immediately);
//   - SKIP: a tick that finds the lease HELD (acquired:false) does NO work at all -- no /due, no /trigger, no
//     /notify/digest-due -- so an overlapping tick cannot double-dispatch or double-flush a digest;
//   - FAIL-OPEN: a DO blip on the acquire (the fetch throws) does NOT stop the tick -- drive() proceeds
//     without the guard (no worse than before the lease existed) and never crashes the cron.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import worker from "../src/index.ts";
import { dueState, makeCronScheduler, makeEnv, makeSchedulerStub, runScheduled, type RecordedCall } from "./validate-worker-helpers.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- PART A: the DO lease primitive through the real routes -------------------------------
const LEASE_KEY = "tickLease";
interface StoredLease {
  token: string;
  expiresAt: number;
}
type AcquireResult = { acquired: boolean; token?: string };

function makeScheduler(): { storage: MockStorage; dobj: SchedulerDO } {
  const storage = new MockStorage();
  return { storage, dobj: new SchedulerDO({ storage } as unknown as DurableObjectState) };
}

function doFetch(dobj: SchedulerDO, path: string, body?: unknown): Promise<Response> {
  const init: RequestInit = {
    method: "POST",
    headers: body !== undefined ? { "content-type": "application/json" } : {},
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  };
  return dobj.fetch(new Request(`https://scheduler.internal${path}`, init));
}

async function acquire(dobj: SchedulerDO): Promise<{ status: number; body: AcquireResult }> {
  const r = await doFetch(dobj, "/tick-lease/acquire");
  return { status: r.status, body: (await r.json()) as AcquireResult };
}

async function release(dobj: SchedulerDO, token: unknown): Promise<{ status: number; body: { ok?: true } }> {
  const r = await doFetch(dobj, "/tick-lease/release", token === undefined ? {} : { token });
  return { status: r.status, body: (await r.json()) as { ok?: true } };
}

// Age the stored lease into the past so the next acquire treats the holder as crashed and reclaims it
// (the same direct-storage backdating validate-runlog-lock.ts uses). Returns the prior token.
function expireLease(storage: MockStorage): string {
  const cur = storage.rawGet<StoredLease>(LEASE_KEY);
  if (!cur) throw new Error("test bug: expected a stored lease to expire");
  const prior = cur.token;
  cur.expiresAt = Date.now() - 1000; // strictly < now, so not "live"
  storage.rawPut(LEASE_KEY, cur);
  return prior;
}

async function testAcquireOnFree(): Promise<void> {
  const { dobj, storage } = makeScheduler();
  const a = await acquire(dobj);
  ok("A/acquire: 200 response", a.status === 200);
  ok("A/acquire: acquired is true on a free lease", a.body.acquired === true);
  ok("A/acquire: returns a non-empty token", typeof a.body.token === "string" && (a.body.token as string).length > 0);
  const stored = storage.rawGet<StoredLease>(LEASE_KEY);
  ok("A/acquire: lease persisted in storage", stored !== undefined);
  ok("A/acquire: stored token matches the returned token", stored?.token === a.body.token);
  ok("A/acquire: stored lease expires in the future", typeof stored?.expiresAt === "number" && stored!.expiresAt > Date.now());
}

// The defining single-flight property: while one tick holds the lease, a second (overlapping) tick's acquire
// is refused, so it does no work. This is exactly what stops two overlapping */15 ticks running the passes.
async function testContentionIsSingleFlight(): Promise<void> {
  const { dobj } = makeScheduler();
  const first = await acquire(dobj);
  ok("A/contention: first acquire succeeds", first.body.acquired === true && typeof first.body.token === "string");
  const second = await acquire(dobj);
  ok("A/contention: a second acquire while held is REFUSED (single-flight)", second.body.acquired === false);
  ok("A/contention: the refused acquire carries no token", second.body.token === undefined);
  const third = await acquire(dobj);
  ok("A/contention: a third acquire while held is still refused (the live lease is not self-consumed)", third.body.acquired === false);
}

async function testReleaseThenReAcquire(): Promise<void> {
  const { dobj, storage } = makeScheduler();
  const first = await acquire(dobj);
  const token = first.body.token as string;
  ok("A/release: acquired before release", first.body.acquired === true && typeof token === "string");
  const rel = await release(dobj, token);
  ok("A/release: 200 { ok: true }", rel.status === 200 && rel.body.ok === true);
  ok("A/release: lease removed from storage", !storage.has(LEASE_KEY));
  const reAcq = await acquire(dobj);
  ok("A/release: re-acquire after release succeeds", reAcq.body.acquired === true);
  ok("A/release: re-acquire mints a NEW token (a genuine re-grant, not the freed one)", typeof reAcq.body.token === "string" && reAcq.body.token !== token);
}

// The crash backstop: a tick whose isolate was evicted before it released never frees the lease. TICK_LEASE_MS
// bounds that -- once elapsed, the next tick reclaims. Both sides of the boundary in one flow.
async function testExpiredLeaseReclaim(): Promise<void> {
  const { dobj, storage } = makeScheduler();
  const held = await acquire(dobj);
  const heldToken = held.body.token as string;
  ok("A/reclaim: initial acquire holds the lease", held.body.acquired === true && typeof heldToken === "string");
  const refusedWhileFresh = await acquire(dobj);
  ok("A/reclaim: a fresh lease refuses a second acquire", refusedWhileFresh.body.acquired === false);
  const prior = expireLease(storage);
  ok("A/reclaim: backdated the held token's lease", prior === heldToken);
  const reclaimed = await acquire(dobj);
  ok("A/reclaim: an expired lease is reclaimable by a new acquire (crash self-heals)", reclaimed.body.acquired === true);
  ok("A/reclaim: the reclaimed token differs from the abandoned one", typeof reclaimed.body.token === "string" && reclaimed.body.token !== heldToken);
  const refusedAfterReclaim = await acquire(dobj);
  ok("A/reclaim: the reclaimed lease again refuses a second acquire", refusedAfterReclaim.body.acquired === false);
}

// Only the CURRENT holder's token frees the lease. A wrong or missing token is a harmless no-op, and a
// superseded slow tick (whose lease expired and was reclaimed) must not free the newer tick's lease.
async function testWrongTokenAndSuspendedTick(): Promise<void> {
  const { dobj, storage } = makeScheduler();
  const holder = await acquire(dobj);
  const holderToken = holder.body.token as string;
  ok("A/wrong-token: holder acquires the lease", holder.body.acquired === true && typeof holderToken === "string");
  const wrong = await release(dobj, "not-the-real-token");
  ok("A/wrong-token: wrong-token release still returns { ok: true } (no-op, never an error)", wrong.body.ok === true);
  ok("A/wrong-token: holder's lease survives a wrong-token release", storage.rawGet<StoredLease>(LEASE_KEY)?.token === holderToken);
  const missing = await release(dobj, undefined);
  ok("A/wrong-token: missing-token release is a no-op too", missing.body.ok === true && storage.rawGet<StoredLease>(LEASE_KEY)?.token === holderToken);
  ok("A/wrong-token: the lease is still held (a fresh acquire is refused)", (await acquire(dobj)).body.acquired === false);

  // Suspended-tick hazard: A holds, its lease expires, B reclaims (a new token), then A wakes and releases
  // with its STALE token -- must NOT free B's lease, or two ticks could run at once.
  expireLease(storage);
  const b = await acquire(dobj);
  const tokenB = b.body.token as string;
  ok("A/suspended: B reclaims after the holder's lease expires", b.body.acquired === true && tokenB !== holderToken);
  const staleRelease = await release(dobj, holderToken);
  ok("A/suspended: the stale release returns { ok: true } (no-op)", staleRelease.body.ok === true);
  ok("A/suspended: B's lease survives the stale release", storage.rawGet<StoredLease>(LEASE_KEY)?.token === tokenB);
  ok("A/suspended: B still holds it (a concurrent acquire is refused)", (await acquire(dobj)).body.acquired === false);
}

// ---- PART B: the end-to-end guard through worker.scheduled() -> drive() --------------------

// A stateful lease stub: it records every path, and its /tick-lease/acquire answer is parameterised so a test
// can simulate a FREE lease (acquired:true), a HELD lease held by an overlapping tick (acquired:false), or a
// DO blip (throw). Every other route the cron reaches is answered minimally so a proceeding tick resolves.
function makeLeaseStub(acquireMode: "grant" | "held" | "throw"): { stub: DurableObjectStub; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const j = (o: unknown) => new Response(JSON.stringify(o), { headers: { "content-type": "application/json" } });
  const stub = makeSchedulerStub(async (url: string, init?: RequestInit) => {
    const path = new URL(url).pathname;
    let body: unknown;
    if (typeof init?.body === "string") {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    }
    calls.push({ path, body });
    if (path === "/tick-lease/acquire") {
      if (acquireMode === "throw") throw new Error("DO unreachable acquiring the lease (test)");
      return j(acquireMode === "grant" ? { acquired: true, token: "b-token" } : { acquired: false });
    }
    if (path === "/tick-lease/release") return j({ ok: true });
    // The minimal tick surface a PROCEEDING drive reaches (grant/throw modes). Empty everywhere so the whole
    // drive() promise resolves network-free; a SKIP (held) drive must reach none of these.
    if (path === "/tick") return j({ ok: true });
    if (path === "/due") return j({ due: [] });
    if (path === "/reconcile-alerts") return j({ alerts: [], pendingTransitionIds: [] });
    if (path === "/reconcile-replication-alerts") return j({ emissions: [], pendingTransitionIds: [] });
    if (path === "/source-drift/reconcile") return j({ newlyDetached: [] });
    if (path === "/expiry/reconcile") return j({ emissions: [] });
    if (path === "/restore-tests-due") return j({ due: [] });
    if (path === "/notify/digest-due") return j({ batches: [] });
    if (path === "/downpipes") return j([]);
    if (path === "/canary/due") return j({ due: false });
    if (path === "/cf-config/discovery-due") return j({ due: [] });
    if (path === "/push-config") return j({ record: null });
    if (path === "/otlp-push-config") return j({ record: null });
    if (path === "/posture/evaluation-due") return j({ due: false });
    // Everything else (control-plane pass, tick-outcome, diag recorders): a benign no-op ack.
    return j({ ok: true });
  });
  return { stub, calls };
}

// GRANT+RELEASE: a tick that gets the lease runs the full pass sequence AND releases the lease at the end.
async function testDriveGrantAndRelease(): Promise<void> {
  const trigger = { runId: "01TICKLEASEGRANTGRANTGRA", index: 1, prevRunId: null };
  const { stub, calls } = makeCronScheduler([dueState("dp-lease", "KV_SOURCE_ABSENT")], trigger);
  const env = makeEnv(stub);
  const origError = console.error;
  console.error = () => {};
  let res: Awaited<ReturnType<typeof runScheduled>>;
  try {
    res = await runScheduled(env, worker);
  } finally {
    console.error = origError;
  }
  const paths = calls.map((c) => c.path);
  ok("B/grant: drive() promise RESOLVES (no cron crash)", !res.waitUntilRejected);
  ok("B/grant: acquired the single-flight tick lease", paths.includes("/tick-lease/acquire"));
  ok("B/grant: RELEASED the lease at the end (the next */15 tick runs immediately)", paths.includes("/tick-lease/release"));
  // The lease genuinely wrapped a real tick: the reconcile + dispatch + digest passes all ran under it.
  ok("B/grant: the tick ran under the lease (/due, /trigger, /notify/digest-due all fired)", paths.includes("/due") && paths.includes("/trigger") && paths.includes("/notify/digest-due"));
  // ORDER: acquire is the FIRST call and release is the LAST (the lease wraps the whole tick).
  ok("B/grant: acquire is the FIRST DO call", paths[0] === "/tick-lease/acquire");
  ok("B/grant: release is the LAST DO call", paths[paths.length - 1] === "/tick-lease/release");
}

// SKIP: a tick that finds the lease HELD by an overlapping tick does NO work at all. This is the C3-07 fix:
// the overlapping tick cannot double-dispatch a downpipe or double-flush a digest.
async function testDriveSkipsWhenHeld(): Promise<void> {
  const { stub, calls } = makeLeaseStub("held");
  const env = makeEnv(stub);
  const res = await runScheduled(env, worker);
  const paths = calls.map((c) => c.path);
  ok("B/skip: drive() promise RESOLVES (no cron crash)", !res.waitUntilRejected);
  ok("B/skip: the acquire WAS attempted", paths.includes("/tick-lease/acquire"));
  ok("B/skip: ONLY the acquire was called (the tick did no work)", paths.length === 1 && paths[0] === "/tick-lease/acquire");
  // The load-bearing negative controls: a held lease means NONE of the pass surface ran.
  ok("B/skip: NO /tick (no reconciliation)", !paths.includes("/tick"));
  ok("B/skip: NO /due (no dispatch decision)", !paths.includes("/due"));
  ok("B/skip: NO /trigger (no run allocated -> cannot double-dispatch)", !paths.includes("/trigger"));
  ok("B/skip: NO /notify/digest-due (no digest flush -> cannot double-send a digest)", !paths.includes("/notify/digest-due"));
  ok("B/skip: NO /tick-lease/release (nothing was acquired, so nothing is released)", !paths.includes("/tick-lease/release"));
}

// FAIL-OPEN: a DO blip on the acquire (the fetch throws) must NOT stop the tick. drive() proceeds without the
// guard (no worse than before the lease existed) and never crashes the cron; with no token, it releases nothing.
async function testDriveFailsOpenOnAcquireThrow(): Promise<void> {
  const { stub, calls } = makeLeaseStub("throw");
  const env = makeEnv(stub);
  const origError = console.error;
  console.error = () => {};
  let res: Awaited<ReturnType<typeof runScheduled>>;
  try {
    res = await runScheduled(env, worker);
  } finally {
    console.error = origError;
  }
  const paths = calls.map((c) => c.path);
  ok("B/fail-open: drive() promise RESOLVES (the acquire throw did not crash the cron)", !res.waitUntilRejected);
  ok("B/fail-open: the acquire was attempted (and threw)", paths.includes("/tick-lease/acquire"));
  ok("B/fail-open: the tick PROCEEDED without the guard (/tick + /due ran)", paths.includes("/tick") && paths.includes("/due"));
  ok("B/fail-open: NO /tick-lease/release (no token was acquired, so nothing is released)", !paths.includes("/tick-lease/release"));
}

async function main(): Promise<void> {
  console.log("-- PART A: the DO tick-lease primitive (through the real routes) --");
  await testAcquireOnFree();
  await testContentionIsSingleFlight();
  await testReleaseThenReAcquire();
  await testExpiredLeaseReclaim();
  await testWrongTokenAndSuspendedTick();
  console.log("-- PART B: the end-to-end guard (worker.scheduled() -> drive()) --");
  await testDriveGrantAndRelease();
  await testDriveSkipsWhenHeld();
  await testDriveFailsOpenOnAcquireThrow();

  console.log(failures === 0 ? "\nTICK-LEASE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
