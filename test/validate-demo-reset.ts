// Prove the DEMO-ONLY reset (POST /admin/demo/reset): it wipes the scheduler Durable Object back to
// first-run, is HARD-GATED behind DEMO_MODE (404 in production, BEFORE any auth or DO round-trip), and
// accepts ONLY the ADMIN_TOKEN break-glass bearer. In-memory doubles only; no network, no deploy.
//   node test/validate-demo-reset.ts
//
// The safety property that matters: a real deployment never sets DEMO_MODE, so the reset route does not
// exist there (404), so it can never wipe a production engine. This proves that, plus the happy path and
// the auth gate, against the REAL router + DO code (not a shim).

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { buildStatus } from "../src/admin/status.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ADMIN = "demo-admin-secret-xyz-1234567890";

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

function envWith(opts: { demo: boolean; stub: DurableObjectStub }): Env {
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => opts.stub,
  } as unknown as DurableObjectNamespace;
  return {
    SCHEDULER: namespace,
    ADMIN_TOKEN: ADMIN,
    CONSOLE_ORIGIN: "https://demo.downpipes.io",
    ...(opts.demo ? { DEMO_MODE: "true" } : {}),
  } as unknown as Env;
}

function seed(storage: MockStorage): Promise<void[]> {
  // A representative spread: identity, a downpipe, the credential registry, the audit chain, a destination.
  return Promise.all([
    storage.put("role:owner@x", { role: "owner" }),
    storage.put("dp:abc", { id: "abc" }),
    storage.put("expiry:idp-cert-1", { id: "idp-cert-1" }),
    storage.put("audit:0000000001", { seq: 1 }),
    storage.put("DESTINATIONS_KEY", { list: [] }),
  ]);
}

const reset = (host: string, headers?: Record<string, string>): Request =>
  new Request(`${host}/admin/demo/reset`, { method: "POST", ...(headers ? { headers } : {}) });

// A minimal in-memory R2 bucket binding: the demo-reset bucket-clear path only needs delete(). It is
// pre-seeded with the surviving signed RUNLOG (+ .sig) that a pre-reset run left behind, so the test can
// prove the reset drops them (RUNLOG-1: otherwise post-reset runs reuse indices against this log).
class MockR2Bucket {
  store = new Map<string, Uint8Array>();
  async delete(key: string | string[]): Promise<void> {
    const keys = Array.isArray(key) ? key : [key];
    for (const k of keys) this.store.delete(k);
  }
  has(key: string): boolean {
    return this.store.has(key);
  }
}

// ---- buildStatus surfaces demoMode (so the console shows the reset button ONLY on the demo engine) ----
function testBuildStatus(): void {
  ok("status: demoMode true when DEMO_MODE set", buildStatus({ DEMO_MODE: "true" } as unknown as Env, 0).demoMode === true);
  ok("status: demoMode false when DEMO_MODE unset", buildStatus({} as unknown as Env, 0).demoMode === false);
}

// ---- FAIL-CLOSED at the DO. An UNMARKED instance refuses the reset, wipes nothing ----
// The router checks DEMO_MODE upstream, but the DO cannot read env; a reset that reaches the DO WITHOUT
// the DEMO_MODE-gated /demo/mark (a misrouted or forged call against a non-demo instance) must be refused
// (403) and wipe NOTHING. The OLD code wiped unconditionally; this in-DO marker guard is the new defence.
async function testHardGateNoDemo(): Promise<void> {
  const { storage, stub } = makeDO();
  await seed(storage);
  ok("M1: storage seeded (5 keys)", storage.size() === 5);
  const refused = await stub.fetch("https://scheduler.internal/demo/reset", { method: "POST" });
  ok("M1: an UNMARKED DO refuses the reset (403)", refused.status === 403);
  const refusedBody = (await refused.json()) as { ok?: boolean };
  ok("M1: the refusal reports ok:false", refusedBody.ok === false);
  ok("M1: an UNMARKED DO wipes NOTHING (storage untouched)", storage.size() === 5);
}

// ---- the DO route directly: a MARKED instance wipes ALL storage + reports the cleared count ----
async function testDOReset(): Promise<void> {
  {
    const { storage, stub } = makeDO();
    await seed(storage);
    ok("DO: storage seeded (5 keys)", storage.size() === 5);
    // mark THIS DO as a demo instance first (the router does this on a DEMO_MODE-gated
    // path). Now the reset is permitted. The mark adds one key, so the seeded set is 6 before the reset.
    await stub.fetch("https://scheduler.internal/demo/mark", { method: "POST" });
    ok("DO: marked as a demo instance (6 keys: 5 seeded + the marker)", storage.size() === 6);
    const r = await stub.fetch("https://scheduler.internal/demo/reset", { method: "POST" });
    const body = (await r.json()) as { ok: boolean; cleared: number };
    ok("DO reset: 200 ok", r.status === 200 && body.ok === true);
    ok("DO reset: cleared count == all keys (5 seeded + the marker)", body.cleared === 6);
    // The wipe clears every key, then re-writes TWO markers: demoFreshFirstRun (so the guided setup
    // restarts at the ceremony) and the demoModeMarker (so a legitimate demo DO stays markable, and a
    // subsequent reset is not refused).
    ok("DO reset: only the two markers remain", storage.size() === 2);
    ok("DO reset: fresh-first-run marker is set", (await storage.get("demoFreshFirstRun")) === true);
    ok("DO reset: demo-mode marker survives the wipe", (await storage.get("demoModeMarker")) === true);
    const fr = await (await stub.fetch("https://scheduler.internal/demo/first-run", { method: "GET" })).json() as { forceFirstRun?: boolean };
    ok("DO: GET /demo/first-run reports forceFirstRun true after a reset", fr.forceFirstRun === true);
    // A SECOND reset on the now-marked DO is permitted (the marker survived the first wipe).
    const r2 = await stub.fetch("https://scheduler.internal/demo/reset", { method: "POST" });
    ok("DO: a second reset on the still-marked DO is permitted (200)", r2.status === 200);
    // The key ceremony clears the fresh-first-run marker (so keysReady reflects the freshly-installed keys).
    await stub.fetch("https://scheduler.internal/demo/first-run/clear", { method: "POST" });
    const fr2 = await (await stub.fetch("https://scheduler.internal/demo/first-run", { method: "GET" })).json() as { forceFirstRun?: boolean };
    ok("DO: /demo/first-run/clear drops the fresh-first-run marker (forceFirstRun false)", fr2.forceFirstRun === false);
    // The demo-mode marker is NOT cleared by the ceremony (it is the instance's demo identity), so it remains.
    ok("DO: only the demo-mode marker remains after the ceremony clear", storage.size() === 1 && (await storage.get("demoModeMarker")) === true);
  }
}

// ---- HARD GATE: no DEMO_MODE -> 404 BEFORE any auth (production has NO reset surface) ----
async function testRouterHardGate(): Promise<void> {
  const { storage, stub } = makeDO();
  await seed(storage);
  // Even WITH a valid ADMIN_TOKEN bearer, an engine WITHOUT DEMO_MODE 404s the route entirely.
  const r = await handleAdmin(reset("https://demo.downpipes.io", { Authorization: `Bearer ${ADMIN}` }), envWith({ demo: false, stub }));
  ok("router: no DEMO_MODE -> 404 (no reset surface in production)", r.status === 404);
  ok("router: no DEMO_MODE -> storage UNTOUCHED", storage.size() === 5);
}

// ---- DEMO_MODE on, NO credential -> 401 (the route exists but is gated) ----
async function testUnauthenticated(): Promise<void> {
  const { storage, stub } = makeDO();
  await seed(storage);
  const r = await handleAdmin(reset("https://demo.downpipes.io"), envWith({ demo: true, stub }));
  ok("router: DEMO_MODE on + no auth -> 401", r.status === 401);
  ok("router: unauthenticated reset -> storage UNTOUCHED", storage.size() === 5);
}

// ---- DEMO_MODE on, WRONG bearer -> 401 (constant-time ADMIN_TOKEN mismatch) ----
async function testWrongBearer(): Promise<void> {
  const { storage, stub } = makeDO();
  await seed(storage);
  const r = await handleAdmin(reset("https://demo.downpipes.io", { Authorization: "Bearer not-the-admin-token" }), envWith({ demo: true, stub }));
  ok("router: DEMO_MODE on + wrong bearer -> 401", r.status === 401);
  ok("router: wrong-bearer reset -> storage UNTOUCHED", storage.size() === 5);
}

// ---- HAPPY PATH: DEMO_MODE on + ADMIN_TOKEN bearer -> 200 + DO wiped to first-run ----
async function testHappyPath(): Promise<void> {
  const { storage, stub } = makeDO();
  await seed(storage);
  await storage.put("passkey:cred1", { id: "cred1" });
  const r = await handleAdmin(reset("https://demo.downpipes.io", { Authorization: `Bearer ${ADMIN}` }), envWith({ demo: true, stub }));
  ok("router: DEMO_MODE on + ADMIN_TOKEN -> 200", r.status === 200);
  const body = (await r.json()) as { ok?: boolean; reset?: boolean };
  ok("router: reports reset:true", body.ok === true && body.reset === true);
  // the router marks the DO as a demo instance before forwarding the reset (a
  // DEMO_MODE-gated path), so the reset is permitted, and the wipe leaves TWO markers behind: the
  // fresh-first-run marker (wizard back to step 1) and the surviving demo-mode marker (the demo identity).
  // The wipe must leave NO demo/account state behind: the two markers and nothing else.
  //
  // The one admissible companion is a `diag:` key (the support-pack diagnostic recorders). Those are written
  // by the RESET ITSELF, AFTER the wipe -- the reset builds a destination to clear the surviving RUNLOG, and a
  // build that has no destination configured records its own closed outcome class. So a `diag:` key here is not
  // demo state that SURVIVED the wipe; it is a fresh observation OF the wipe, carrying only counts and closed
  // enums (never a downpipe, a key, a credential or a customer value). The assertion therefore pins the two
  // markers exactly and allows nothing else that is not diagnostic.
  const surviving = [...(await storage.list<unknown>()).keys()];
  const nonDiag = surviving.filter((k) => !k.startsWith("diag:"));
  ok(
    "router: DO wiped to first-run (only the two markers remain, plus any diagnostic record the reset itself wrote)",
    nonDiag.length === 2 && (await storage.get("demoFreshFirstRun")) === true && (await storage.get("demoModeMarker")) === true,
  );
}

// ---- RUNLOG-1: the reset CLEARS the surviving destination RUNLOG so post-reset runs cannot reuse
// indices against it (the deterministic demo-reset chain fork). With a default R2 destination bound, the
// reset deletes _RECOVERY/RUNLOG (+ .sig) and reports runlogCleared:true. ----
async function testDestinationRunlogCleared(): Promise<void> {
  const { storage, stub } = makeDO();
  await seed(storage);
  const r2 = new MockR2Bucket();
  r2.store.set("_RECOVERY/RUNLOG", new Uint8Array([1, 2, 3]));
  r2.store.set("_RECOVERY/RUNLOG.sig", new Uint8Array([4, 5, 6]));
  const env = { ...envWith({ demo: true, stub }), DEST_R2: r2 } as unknown as Env;
  const r = await handleAdmin(reset("https://demo.downpipes.io", { Authorization: `Bearer ${ADMIN}` }), env);
  ok("router: reset with a default R2 destination -> 200", r.status === 200);
  const body = (await r.json()) as { ok?: boolean; runlogCleared?: boolean };
  ok("router: reset reports runlogCleared:true", body.ok === true && body.runlogCleared === true);
  ok("router: the surviving destination RUNLOG was deleted", !r2.has("_RECOVERY/RUNLOG"));
  ok("router: the surviving destination RUNLOG.sig was deleted", !r2.has("_RECOVERY/RUNLOG.sig"));
}

// ---- With NO default destination configured the reset still succeeds (the DO wipe is the primary
// effect) but honestly reports runlogCleared:false, so the operator is told to empty the bucket. ----
async function testNoDestinationRunlogNotCleared(): Promise<void> {
  const { storage, stub } = makeDO();
  await seed(storage);
  const r = await handleAdmin(reset("https://demo.downpipes.io", { Authorization: `Bearer ${ADMIN}` }), envWith({ demo: true, stub }));
  ok("router: reset with no default destination -> 200", r.status === 200);
  const body = (await r.json()) as { runlogCleared?: boolean; note?: string };
  ok("router: reset reports runlogCleared:false (nothing to clear)", body.runlogCleared === false);
  ok("router: the note warns to empty the bucket before the first post-reset run", /empty the destination bucket/.test(body.note ?? ""));
}

async function main(): Promise<void> {
  testBuildStatus();
  await testHardGateNoDemo();
  await testDOReset();
  await testRouterHardGate();
  await testUnauthenticated();
  await testWrongBearer();
  await testHappyPath();
  await testDestinationRunlogCleared();
  await testNoDestinationRunlogNotCleared();

  console.log(failures === 0 ? "\nDEMO-RESET VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
