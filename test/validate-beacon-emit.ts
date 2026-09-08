// Prove the OPT-IN vendor beacon emitter (cron/beacon-emit.ts): OFF by default (no phone-home), CONTENT-FREE
// when on (only the closed aggregate scalars; no per-downpipe field), and FAIL-OPEN (a DO read fault never
// throws out of the pass). In-memory doubles only; no network, no deploy.
//
//   node test/validate-beacon-emit.ts

import { beaconConfigured } from "../src/cron/beacon-config.ts";
import { runBeaconEmitPass } from "../src/cron/beacon-emit.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

const AGG = { downpipeCount: 3, healthy: 2, stalled: 1, runlogMaxIndex: 42 };
type Sched = Parameters<typeof runBeaconEmitPass>[1];
// The DO POST /beacon-state records the last attempt outcome (beacon-post-lost). The double captures every
// such post so the test can prove the emitter records ok/status on success, failure, and the fail-open path.
let beaconStatePosts: Array<{ ok?: boolean; status?: number }> = [];
function fakeScheduler(opts?: { throwOnFetch?: boolean }): Sched {
  return {
    fetch: async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url;
      // /beacon-state is the outcome-recording POST; capture it and never throw (it must stay reachable even
      // when the aggregate read is faulted, so the fail-open path can still record a failed attempt).
      if (url.endsWith("/beacon-state")) {
        beaconStatePosts.push(JSON.parse(String(init?.body ?? "{}")) as { ok?: boolean; status?: number });
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
      if (opts?.throwOnFetch) throw new Error("DO unavailable");
      return new Response(JSON.stringify(AGG), { status: 200 });
    },
  } as unknown as Sched;
}

let posted: { url: string; auth: string; body: Record<string, unknown> } | null = null;
function resetPosted(): void {
  // Reset via a helper, not a direct `posted = null` in main(). The object is assigned
  // inside the fetch closure that runBeaconEmitPass invokes opaquely, so a direct
  // null-assignment in main would wrongly narrow `posted` to `never` at the asserts below.
  posted = null;
}
function captureFetch(status = 200): void {
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    posted = {
      url: typeof url === "string" ? url : url instanceof URL ? url.href : (url as Request).url,
      auth: String((init?.headers as Record<string, string>)?.authorization ?? ""),
      body: JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>,
    };
    return new Response("ok", { status });
  }) as typeof fetch;
}

async function main(): Promise<void> {
  console.log("opt-in gate (no phone-home by default):");
  resetPosted(); captureFetch();
  await runBeaconEmitPass({} as Env, fakeScheduler());
  ok("OFF when BEACON_URL/INGEST_KEY/CF_ACCOUNT_ID are unset", posted === null);
  resetPosted(); captureFetch();
  await runBeaconEmitPass({ BEACON_URL: "https://cp.example", CF_ACCOUNT_ID: "acct-1" } as Env, fakeScheduler());
  ok("OFF when the ingest key is missing (partial config)", posted === null);

  console.log("\nON: a content-free aggregate beacon:");
  resetPosted(); captureFetch(); beaconStatePosts = [];
  await runBeaconEmitPass(
    { BEACON_URL: "https://cp.example", BEACON_INGEST_KEY: "ik", CF_ACCOUNT_ID: "acct-1", CF_VERSION_METADATA: { id: "cf-v9", tag: "" } } as unknown as Env,
    fakeScheduler(),
  );
  ok("posts to {BEACON_URL}/beacon", posted !== null && posted.url === "https://cp.example/beacon");
  ok("sends the ingest bearer", posted?.auth === "Bearer ik");
  ok("carries account tag + engine version + cfVersionId", posted?.body.accountTag === "acct-1" && typeof posted?.body.engineVersion === "string" && posted?.body.cfVersionId === "cf-v9");
  ok("carries the aggregate counts from the DO", posted?.body.downpipeCount === 3 && posted?.body.healthy === 2 && posted?.body.stalled === 1 && posted?.body.runlogMaxIndex === 42);

  console.log("\nattempt-outcome recording (beacon-post-lost):");
  // A successful (2xx) POST records ok:true + the status, so the support pack can show the beacon is reaching
  // the vendor.
  ok("records a successful attempt (ok:true, status:200)", beaconStatePosts.length === 1 && beaconStatePosts[0]?.ok === true && beaconStatePosts[0]?.status === 200);
  // A non-2xx POST (the receiver disabled ingestion / tightened the shape) records ok:false + the status, so
  // a beacon that is configured but NOT being accepted is visible rather than silently lost.
  resetPosted(); captureFetch(422); beaconStatePosts = [];
  await runBeaconEmitPass({ BEACON_URL: "https://cp.example", BEACON_INGEST_KEY: "ik", CF_ACCOUNT_ID: "acct-1" } as Env, fakeScheduler());
  ok("records a rejected attempt (ok:false, status:422)", beaconStatePosts.length === 1 && beaconStatePosts[0]?.ok === false && beaconStatePosts[0]?.status === 422);

  console.log("\ncontent-free / no-custody envelope:");
  const allowed = new Set(["kind", "accountTag", "engineVersion", "cfVersionId", "downpipeCount", "healthy", "stalled", "runlogMaxIndex", "emittedAt", "signature"]);
  const keysOk = posted ? Object.keys(posted.body).every((k) => allowed.has(k)) : false;
  const noNested = posted ? Object.values(posted.body).every((v) => typeof v !== "object" || v === null) : false;
  ok("only allowlisted scalar keys (no per-downpipe field)", keysOk);
  ok("no nested object/array (cannot carry a per-downpipe series)", noNested);

  console.log("\nfail-open:");
  resetPosted(); captureFetch(); beaconStatePosts = [];
  let threw = false;
  try {
    await runBeaconEmitPass({ BEACON_URL: "https://cp.example", BEACON_INGEST_KEY: "ik", CF_ACCOUNT_ID: "acct-1" } as Env, fakeScheduler({ throwOnFetch: true }));
  } catch {
    threw = true;
  }
  ok("a DO read fault does not throw out of the pass (advisory, fail-open)", threw === false);
  // Even on the faulted path the attempt is recorded as a FAILURE (ok:false), so a beacon that is silently
  // not reaching the vendor because of a local DO fault is still visible in the pack.
  ok("records a failed attempt (ok:false) on the fail-open path", beaconStatePosts.length === 1 && beaconStatePosts[0]?.ok === false);

  // The posture screen's beacon-off check and the emitter's opt-in gate must be the SAME predicate. They
  // were not: router-posture.ts computed beaconEnabled from BEACON_URL and BEACON_INGEST_KEY alone, so an
  // estate with those two set and no CF_ACCOUNT_ID was told "the vendor beacon is enabled; the engine
  // reports usage to the vendor" while this emitter returned without sending a byte. That is a false
  // accusation against our own product on the no-custody claim, which is the direction a wrong reading
  // must never run. Both sides now call beaconConfigured, and these assertions pin the predicate to the
  // emitter's OBSERVED behaviour rather than to itself: for each env, whether beaconConfigured says on
  // must equal whether a POST actually happened.
  console.log("\nthe posture predicate agrees with the emitter, env by env:");
  const envs: { label: string; env: Partial<Env> }[] = [
    { label: "all three set", env: { BEACON_URL: "https://cp.example", BEACON_INGEST_KEY: "ik", CF_ACCOUNT_ID: "acct-1" } },
    { label: "CF_ACCOUNT_ID unset (the reported case)", env: { BEACON_URL: "https://cp.example", BEACON_INGEST_KEY: "ik" } },
    { label: "CF_ACCOUNT_ID empty", env: { BEACON_URL: "https://cp.example", BEACON_INGEST_KEY: "ik", CF_ACCOUNT_ID: "" } },
    { label: "BEACON_URL unset", env: { BEACON_INGEST_KEY: "ik", CF_ACCOUNT_ID: "acct-1" } },
    { label: "BEACON_INGEST_KEY unset", env: { BEACON_URL: "https://cp.example", CF_ACCOUNT_ID: "acct-1" } },
    { label: "nothing set", env: {} },
    // A whitespace-only value was the third reading of these vars: cron-fault-ledger's noteBeaconEnv has
    // always trimmed, while the emitter's gate tested !== "", so the operator was told the URL was absent
    // while the emitter treated it as configured and attempted a POST to it.
    { label: "BEACON_URL whitespace only", env: { BEACON_URL: "   ", BEACON_INGEST_KEY: "ik", CF_ACCOUNT_ID: "acct-1" } },
    { label: "CF_ACCOUNT_ID whitespace only", env: { BEACON_URL: "https://cp.example", BEACON_INGEST_KEY: "ik", CF_ACCOUNT_ID: "  " } },
  ];
  for (const { label, env } of envs) {
    resetPosted(); captureFetch(); beaconStatePosts = [];
    await runBeaconEmitPass(env as Env, fakeScheduler({}));
    const emitted = posted !== null;
    const predicate = beaconConfigured(env);
    ok(`${label}: the posture predicate (${predicate}) matches whether the emitter sent (${emitted})`, predicate === emitted);
  }
  // A control, so a green above cannot be two functions agreeing on "never": the all-three case must
  // actually have emitted.
  resetPosted(); captureFetch(); beaconStatePosts = [];
  await runBeaconEmitPass({ BEACON_URL: "https://cp.example", BEACON_INGEST_KEY: "ik", CF_ACCOUNT_ID: "acct-1" } as Env, fakeScheduler({}));
  ok("CONTROL: the fully-configured env really does emit (the agreement above is not vacuous)", posted !== null && beaconConfigured({ BEACON_URL: "https://cp.example", BEACON_INGEST_KEY: "ik", CF_ACCOUNT_ID: "acct-1" }) === true);

  // THE AGREEMENT LOOP ABOVE IS NOT ENOUGH ON ITS OWN, and the control that showed it was run rather than
  // reasoned: cutting CF_ACCOUNT_ID back out of beaconConfigured left the loop at ZERO failures, because
  // both sides read the same predicate and moved together. Agreement can be bought by making both wrong.
  // These two assertions are the substantive half. They do not consult the predicate at all: they state
  // what a beacon IS. accountTag is the beacon's key and the control plane cannot attribute a beacon
  // without it, so an emission with no account tag is not a beacon, and the env that cannot produce one
  // must not emit. With CF_ACCOUNT_ID removed from the predicate these fail, which is what makes the
  // requirement pinned rather than merely mirrored.
  console.log("\nwhat a beacon IS, independent of the predicate:");
  resetPosted(); captureFetch(); beaconStatePosts = [];
  await runBeaconEmitPass({ BEACON_URL: "https://cp.example", BEACON_INGEST_KEY: "ik" } as Env, fakeScheduler({}));
  ok("no CF_ACCOUNT_ID => nothing is sent (an unattributable beacon is not sent at all)", posted === null);
  resetPosted(); captureFetch(); beaconStatePosts = [];
  await runBeaconEmitPass({ BEACON_URL: "https://cp.example", BEACON_INGEST_KEY: "ik", CF_ACCOUNT_ID: "acct-1" } as Env, fakeScheduler({}));
  ok("every beacon that IS sent carries a non-empty accountTag", posted !== null && typeof posted.body.accountTag === "string" && (posted.body.accountTag as string).trim() !== "");

  console.log(failures === 0 ? "\nBEACON EMITTER PASS" : `\n${failures} ASSERTION(S) FAILED`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

await main();
