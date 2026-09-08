// The attended-verification cadence check must be CLEARABLE by the one action that is meant to clear it.
//
// WHY THIS EXISTS, and it is the sharpest risk the cadence feature carries. The check fails when a downpipe
// with a completed run has no full proven attended verification inside the stated interval. The only way a
// customer clears it is to run one. That clearing depends on a chain of four links:
//
//   1. recordAttendedVerification stamps ds.restoreProven with method "attended-blind-test", and ONLY for a
//      full (sampleRate >= 100), proven, passing session with a real runId
//   2. the DO projects that state into PostureDownpipeInput as restoreProvenAt + restoreProvenMethod
//   3. evaluateAttendedCadence credits exactly that method string, and nothing looser
//   4. buildAttendedCadence turns the credit into a passing check
//
// Every one of those is tested in isolation somewhere. NONE of them tested the CHAIN. If any link drifted,
// the check would keep failing after a customer did the one thing it asks for, and the product would be
// telling an operator to perform an act that cannot satisfy it. posture-checks.ts already names that exact
// failure in its own words for the scheduled drill, "the check they can never pass", which is what the
// durable keyed credit was built to fix. A new check that reintroduces it would be worse than no check.
//
// So this drives the REAL DO route (/attest-record, the same one validate-attest-session.ts uses), reads the
// REAL stored state back, projects it the way the DO does, and runs the REAL check. No hand-built proof
// object, because a hand-built one would prove this file's idea of the stamp rather than the engine's.
//
import { buildAttendedCadence, buildRestoreTestRecency } from "../src/admin/posture-checks.ts";
import type { PostureDownpipeInput, PostureInput } from "../src/admin/posture-types.ts";
import { CALLER_HEADER, type Caller, encodeCaller } from "../src/admin/identity.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeState } from "../src/sched/types.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const DAY = 86_400_000;
const RUN_ID = "01JATTENDLOOP00000000000";
const owner: Caller = { method: "access", email: "owner@acme.example", subject: "acc|subj-A", role: "owner", groups: [] };

function makeScheduler(): { storage: MockStorage; scheduler: DurableObjectStub } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const scheduler = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  return { storage, scheduler };
}

/** The DO's own state-to-posture projection (scheduler-do-observability.ts), reproduced for the two fields
 *  this chain turns on. Reproduced rather than imported because the projection is inline in a DO method; the
 *  assertion below on the stored state is what keeps this honest about what the DO actually wrote. */
function project(ds: DownpipeState): PostureDownpipeInput {
  return {
    id: ds.config.id,
    name: ds.config.name,
    ...(ds.lastRunId !== null && ds.lastRunId !== undefined ? { lastRunId: ds.lastRunId } : {}),
    ...(ds.restoreProven !== undefined ? { restoreProvenAt: ds.restoreProven.at, restoreProvenMethod: ds.restoreProven.method } : {}),
  };
}

// The evaluation instant is passed in rather than fixed, because the DO stamps the proof with its OWN clock
// and this test must be judged relative to that. A fixed far-future constant here silently made every real
// stamp look 171 days old, so the first run of this file reported the chain broken when it was the fixture
// that was wrong. Deriving "now" from what the DO actually wrote keeps the test deterministic AND honest
// about the engine's own timestamp.
/** The same projection, plus the recency fields buildRestoreTestRecency reads (the deferral discriminator is
 *  what makes crediting a durable proof SAFE, so it must travel). */
function projectRecency(ds: DownpipeState): PostureDownpipeInput {
  return {
    ...project(ds),
    ...(ds.lastRestoreTestAt !== undefined ? { lastRestoreTestAt: ds.lastRestoreTestAt } : {}),
    ...(ds.lastRestoreTestOk !== undefined ? { lastRestoreTestOk: ds.lastRestoreTestOk } : {}),
    ...(ds.lastRestoreTestDeferred !== undefined ? { lastRestoreTestDeferred: ds.lastRestoreTestDeferred } : {}),
  };
}

function checkFor(dps: PostureDownpipeInput[], now: number): ReturnType<typeof buildAttendedCadence> {
  const input = { status: {}, operationalPrivatePresent: false, attendedCadenceDays: 30, downpipes: dps } as unknown as PostureInput;
  return buildAttendedCadence(input, now);
}

async function main(): Promise<void> {
  const { storage, scheduler } = makeScheduler();
  const headers = { [CALLER_HEADER]: encodeCaller(owner), "content-type": "application/json" };
  const stamp = async (body: unknown): Promise<Response> =>
    scheduler.fetch("https://scheduler.internal/attest-record", { method: "POST", headers, body: JSON.stringify(body) });

  const seed = async (id: string): Promise<void> => {
    await storage.put(`dp:${id}`, {
      config: { id, name: `dp-${id}`, enabled: true, source: { type: "kv", binding: "SRC" }, schedule: { cadenceSeconds: 3600 } },
      lastRunId: RUN_ID,
      nextRunAt: 0,
      inFlight: false,
    } as unknown as DownpipeState);
  };
  const read = async (id: string): Promise<DownpipeState> => (await storage.get<DownpipeState>(`dp:${id}`)) as DownpipeState;

  console.log("\n-- the cadence check can be cleared by an attended verification --\n");

  // ---- the starting state ----------------------------------------------------------------------------------
  await seed("a");
  const seededAt = Date.now();
  const before = checkFor([project(await read("a"))], seededAt);
  ok("a downpipe with a run and no proof FAILS the cadence check", before?.auto === "fail");
  ok("and it is reported as never verified, not as lapsed", before?.detail.includes("never attended-verified") === true);

  // ---- the one action the check asks for -------------------------------------------------------------------
  const resp = await stamp({ downpipeId: "a", runId: RUN_ID, ok: true, sampleRate: 100, provenSession: true });
  ok("the attended-verification stamp is accepted by the DO", resp.ok);

  const after = await read("a");
  // Asserted against the STORED state, so the projection below cannot quietly invent a proof the DO did not
  // write. This is the link that would break silently if the method string were ever renamed.
  ok("the DO stored a restoreProven stamp", after.restoreProven !== undefined);
  ok('with method "attended-blind-test", which is the exact string the cadence credits', after.restoreProven?.method === "attended-blind-test");

  // One day after the DO stamped it, which is inside the 30-day interval by construction.
  const provenAt = after.restoreProven?.at ?? 0;
  const cleared = checkFor([project(after)], provenAt + DAY);
  ok("and the cadence check now PASSES, so the act the check asks for actually clears it", cleared?.auto === "pass");

  // ---- the shapes that must NOT clear it -------------------------------------------------------------------
  // Each of these is a real path through the same route, and each must leave the check failing. If any of
  // them cleared it, a customer could satisfy a full-proof obligation with something weaker.
  await seed("sub");
  await stamp({ downpipeId: "sub", runId: RUN_ID, ok: true, sampleRate: 50, provenSession: true });
  ok("a 50% sample does not clear it (it stamps recency, never a full proof)", checkFor([project(await read("sub"))], Date.now())?.auto === "fail");

  await seed("unproven");
  await stamp({ downpipeId: "unproven", runId: RUN_ID, ok: true, sampleRate: 100, provenSession: false });
  ok("a full sample on an UNPROVEN session does not clear it", checkFor([project(await read("unproven"))], Date.now())?.auto === "fail");

  await seed("failed");
  await stamp({ downpipeId: "failed", runId: RUN_ID, ok: false, sampleRate: 100, provenSession: true, reason: "integrity" });
  ok("a FAILING attended run does not clear it", checkFor([project(await read("failed"))], Date.now())?.auto === "fail");

  // ---- and the proof ages out ------------------------------------------------------------------------------
  // A cleared check must not stay cleared forever, or the cadence would be a one-time formality rather than a
  // rhythm. The stamp is written at the DO's own clock, so this ages the STORED proof rather than the input.
  // Evaluated 400 days AFTER the DO's own stamp, rather than by rewriting the stamp, so what ages is the
  // passage of time and not the evidence.
  ok(
    "a proof older than the interval fails again, so the cadence is a rhythm and not a one-time formality",
    checkFor([project(after)], provenAt + 400 * DAY)?.auto === "fail",
  );

  // ---- the SAME chain for restore-test-recency, which is CRITICAL ------------------------------------------
  // posture-checks.ts's durable keyed credit exists because a break-glass-only estate's cron DEFERS every
  // restore-test tick, which clobbers lastRestoreTestOk back to false forever: "the check they can never
  // pass". A full attended proof SURVIVES that deferral, because completeRestoreTest never touches
  // restoreProven, and the credit reads it.
  //
  // That credit is tested against a HAND-BUILT input, which proves the check's logic and not that the engine
  // produces the shape it credits. Same gap the cadence had, at CRITICAL severity rather than medium: if the
  // stamp drifted, every break-glass-only estate would fail a critical check forever with no way to clear it,
  // silently reinstating the exact defect the credit was built to remove.
  //
  // THE ORDER MATTERS AND IS THE POINT. The attended verification happens FIRST, then the cron keeps
  // deferring on every later tick. Running them the other way round proves nothing: the stamp writes the
  // recency fields too, so a just-stamped downpipe passes on the ORDINARY path and never reaches the credit.
  // The first draft of this block had them reversed and passed for that reason, which would have been a test
  // that looked like it covered the credit and did not.
  await seed("bg");
  await stamp({ downpipeId: "bg", runId: RUN_ID, ok: true, sampleRate: 100, provenSession: true });
  const proven = await read("bg");
  const provenBgAt = proven.restoreProven?.at ?? 0;
  ok("the attended verification stamps a durable proof on the break-glass estate", proven.restoreProven?.method === "attended-blind-test");

  // Now the cron defers, as it will on every tick in this posture.
  await scheduler.fetch("https://scheduler.internal/restore-test-complete", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ id: "bg", ok: false, deferred: "posture" }),
  });
  const deferred = await read("bg");
  ok("the cron's deferral is recorded as a DEFERRAL, not a failure", deferred.lastRestoreTestDeferred === "posture" && deferred.lastRestoreTestOk === false);
  ok("and the deferral does NOT erase the durable proof", deferred.restoreProven?.method === "attended-blind-test");

  const recencyOf = (ds: DownpipeState, now: number) => {
    const input = { status: {}, operationalPrivatePresent: false, downpipes: [projectRecency(ds)] } as unknown as PostureInput;
    return buildRestoreTestRecency(input, now);
  };
  const recency = recencyOf(deferred, provenBgAt + DAY);
  ok("the credit RESCUES the critical check through the deferral, which is the whole reason it exists", recency?.auto === "pass");
  ok("and the detail names the attended verification, so the pass is not mistaken for a scheduled drill", (recency?.detail ?? "").includes("attended verification"));

  console.log(`\n${failures === 0 ? "ATTENDED-CADENCE-LOOP PASS" : `ATTENDED-CADENCE-LOOP: ${failures} FAILED`}\n`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
