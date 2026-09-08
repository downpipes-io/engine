// Prove the 0.1.5 UX update-judgment machinery: the critical-only selfCheck
// allowlist (update-gate.ts) and the hourly canary's background confirmation arm (notify-passes.ts
// confirmUpdateIfSettled). Driven with a fake scheduler stub (just enough of DurableObjectStub.fetch to
// answer the routes runPreflight/confirmUpdateIfSettled reach) and a stubbed globalThis.fetch for the one
// real network call (Access JWKS) a non-critical preflight failure needs. No Cloudflare account, no real
// deploy, no network beyond the stub. Run:
//   node test/validate-update-gate.ts

import { makeHealthGate, CRITICAL_PREFLIGHT_CHECK_IDS } from "../src/admin/update-gate.ts";
import { confirmUpdateIfSettled } from "../src/cron/notify-passes.ts";
import { decideKeep } from "../src/admin/update-types.ts";
import { ENGINE_VERSION } from "../src/format/version.ts";
import type { CanaryCheckResult } from "../src/canary/types.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// makeFakeScheduler answers exactly the routes runPreflight's probes reach in this suite (tick-info,
// dest-config, downpipes), so every OTHER preflight item reads its honest "unconfigured" default (never
// "failed") without dragging in a real SchedulerDO. dieOnTick makes the Durable-Objects round-trip itself
// fail (the CRITICAL brick-class item); everything else is a clean, empty, non-failing answer.
function makeFakeScheduler(opts: { dieOnTick?: boolean; lastTickAt?: number | null } = {}): DurableObjectStub {
  return {
    fetch: async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const path = new URL(url).pathname;
      if (path === "/tick-info") {
        if (opts.dieOnTick) throw new Error("the scheduler Durable Object did not respond (test)");
        return new Response(JSON.stringify({ lastTickAt: opts.lastTickAt ?? Date.now() }), { headers: { "content-type": "application/json" } });
      }
      if (path === "/dest-config") return new Response(JSON.stringify({ config: null }), { headers: { "content-type": "application/json" } });
      if (path === "/downpipes") return new Response(JSON.stringify([]), { headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({}), { headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
}

const RECOMMENDED = "0.9.9-selfcheck-test";

async function testCriticalAllowlist(): Promise<void> {
  // CRITICAL_PREFLIGHT_CHECK_IDS (design §3): the narrow allowlist itself. "durable-objects" is the DO
  // bind/round-trip brick-class check the design names explicitly; nothing else qualifies (destination/
  // source-bindings/source-liveness/signer/recipients/access/email/sliced-runs/licence/api-discovery-token
  // are all install chores, per the explicit examples in the task and the design's own wording).
  ok("the critical allowlist contains exactly durable-objects", CRITICAL_PREFLIGHT_CHECK_IDS.size === 1 && CRITICAL_PREFLIGHT_CHECK_IDS.has("durable-objects"));
  ok("the allowlist explicitly excludes every named install-chore id", !CRITICAL_PREFLIGHT_CHECK_IDS.has("destination") && !CRITICAL_PREFLIGHT_CHECK_IDS.has("source-bindings") && !CRITICAL_PREFLIGHT_CHECK_IDS.has("source-liveness") && !CRITICAL_PREFLIGHT_CHECK_IDS.has("licence") && !CRITICAL_PREFLIGHT_CHECK_IDS.has("access-zero-trust") && !CRITICAL_PREFLIGHT_CHECK_IDS.has("email-sending") && !CRITICAL_PREFLIGHT_CHECK_IDS.has("sliced-runs") && !CRITICAL_PREFLIGHT_CHECK_IDS.has("signer") && !CRITICAL_PREFLIGHT_CHECK_IDS.has("recipients") && !CRITICAL_PREFLIGHT_CHECK_IDS.has("api-source-discovery-token"));
}

async function testSelfCheck(): Promise<void> {
  // ---- version identity: the FIRST proof, checked before preflight even runs ----
  {
    const scheduler = makeFakeScheduler({ dieOnTick: true }); // would fail preflight too, proving the short-circuit
    const gate = makeHealthGate({} as Env, scheduler, "9.9.9-not-running");
    ok("a version mismatch fails selfCheck without ever needing a clean preflight", (await gate.selfCheck()) === false);
  }
  // ---- the CRITICAL failure: the Durable-Objects round-trip itself fails -> selfCheck FAILS ----
  {
    const scheduler = makeFakeScheduler({ dieOnTick: true });
    const gate = makeHealthGate({} as Env, scheduler, ENGINE_VERSION);
    ok("a critical (durable-objects) preflight failure -> selfCheck FALSE (the brick class gates)", (await gate.selfCheck()) === false);
  }
  // ---- the HAPPY PATH: version matches, DO round-trips clean, nothing else configured (so every other
  // item reads its honest "unconfigured" default, never "failed") -> selfCheck TRUE ----
  {
    const scheduler = makeFakeScheduler();
    const gate = makeHealthGate({} as Env, scheduler, ENGINE_VERSION);
    ok("version matches + a clean DO round-trip + nothing else configured -> selfCheck TRUE", (await gate.selfCheck()) === true);
  }
  // ---- the CORE PROOF: a NON-CRITICAL failure (Access/Zero-Trust JWKS fetch fails -> "access-zero-trust"
  // reads status:"failed", required:false) must NOT fail selfCheck: counting every failed item regardless
  // of criticality or required-ness would roll back a perfectly healthy build over an install chore. ----
  {
    const scheduler = makeFakeScheduler();
    const env = { CF_ACCESS_TEAM_DOMAIN: "gate-test", CF_ACCESS_AUD: "gate-aud" } as unknown as Env;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url === "https://gate-test.cloudflareaccess.com/cdn-cgi/access/certs") {
        return new Response("service unavailable", { status: 503 });
      }
      return new Response(JSON.stringify({ error: "unexpected fetch in test", url }), { status: 404 });
    }) as typeof fetch;
    try {
      const gate = makeHealthGate(env, scheduler, ENGINE_VERSION);
      ok("a NON-CRITICAL failure (access-zero-trust, required:false) does NOT fail selfCheck", (await gate.selfCheck()) === true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
  // ---- a THROWN preflight (the scheduler itself unreachable for every call) is the defensive catch-all:
  // selfCheck reads it as false, never throws out. ----
  {
    const scheduler = { fetch: async () => { throw new Error("scheduler wholly unreachable (test)"); } } as unknown as DurableObjectStub;
    const gate = makeHealthGate({} as Env, scheduler, ENGINE_VERSION);
    ok("a wholly unreachable scheduler -> selfCheck false (fail-safe, never throws)", (await gate.selfCheck()) === false);
  }
}

// ---- confirmUpdateIfSettled (the hourly canary's background confirmation) ----------------------------
// makeConfirmScheduler records every /update-confirm POST (body) so a test can assert whether the clear
// was attempted, and answers /update-status with the given `last` record.
function makeConfirmScheduler(last: unknown, confirmCalls: Array<{ recommendedVersion?: unknown }>): DurableObjectStub {
  return {
    fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const path = new URL(url).pathname;
      if (path === "/update-status") {
        return new Response(JSON.stringify({ last }), { headers: { "content-type": "application/json" } });
      }
      if (path === "/update-confirm") {
        confirmCalls.push(JSON.parse(String(init?.body ?? "{}")));
        return new Response(JSON.stringify({ cleared: true }), { headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify({}), { headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
}

const aliveResult: CanaryCheckResult = { status: "alive", durationMs: 5, destinationId: null, aspects: [], byteDelta: 0, deadReason: null };
const deadResult: CanaryCheckResult = { status: "dead", durationMs: 5, destinationId: null, aspects: [], byteDelta: 3, deadReason: "a byte strayed (test)" };
const ailingResult: CanaryCheckResult = { status: "ailing", durationMs: 5, destinationId: null, aspects: [], byteDelta: null, deadReason: null };

async function testConfirmUpdateIfSettled(): Promise<void> {
  // cron-alive clears it: an ALIVE aggregate + a matching applied+pending record -> the clear IS attempted.
  {
    const calls: Array<{ recommendedVersion?: unknown }> = [];
    const scheduler = makeConfirmScheduler({ outcome: "applied", confirmationPending: true, recommendedVersion: ENGINE_VERSION }, calls);
    await confirmUpdateIfSettled(scheduler, [aliveResult]);
    ok("[cron-alive] an alive verdict on a matching pending-confirmation record clears it", calls.length === 1 && calls[0]?.recommendedVersion === ENGINE_VERSION);
  }
  // cron-dead leaves it + never deploys anything: this function's only side effect is the confirm POST, so
  // "does not deploy anything" is proven by construction (it has no deploy call at all) plus "not even the
  // confirm POST fires" on a dead verdict.
  {
    const calls: Array<{ recommendedVersion?: unknown }> = [];
    const scheduler = makeConfirmScheduler({ outcome: "applied", confirmationPending: true, recommendedVersion: ENGINE_VERSION }, calls);
    await confirmUpdateIfSettled(scheduler, [deadResult]);
    ok("[cron-dead] a dead verdict never attempts the confirm (leaves confirmationPending as-is)", calls.length === 0);
  }
  // Neither ailing nor a mixed alive+dead aggregate (worst-of) clears it.
  {
    const calls: Array<{ recommendedVersion?: unknown }> = [];
    const scheduler = makeConfirmScheduler({ outcome: "applied", confirmationPending: true, recommendedVersion: ENGINE_VERSION }, calls);
    await confirmUpdateIfSettled(scheduler, [ailingResult]);
    ok("[cron-ailing] an ailing verdict never attempts the confirm", calls.length === 0);
  }
  {
    const calls: Array<{ recommendedVersion?: unknown }> = [];
    const scheduler = makeConfirmScheduler({ outcome: "applied", confirmationPending: true, recommendedVersion: ENGINE_VERSION }, calls);
    await confirmUpdateIfSettled(scheduler, [aliveResult, deadResult]);
    ok("[cron-mixed] an aggregate that is not wholly alive (one destination dead) never confirms", calls.length === 0);
  }
  // A version MISMATCH (the recorded keep is for a different version than the one now confirmed alive,
  // e.g. a later apply superseded it) never confirms -- the tokenless, semver-shaped guard.
  {
    const calls: Array<{ recommendedVersion?: unknown }> = [];
    const scheduler = makeConfirmScheduler({ outcome: "applied", confirmationPending: true, recommendedVersion: "0.0.1-superseded" }, calls);
    await confirmUpdateIfSettled(scheduler, [aliveResult]);
    ok("[cron-alive] a recommendedVersion mismatch never confirms (never the wrong record)", calls.length === 0);
  }
  // No confirmationPending at all (a canary-confirmed keep, or already cleared) -> nothing to do, no call.
  {
    const calls: Array<{ recommendedVersion?: unknown }> = [];
    const scheduler = makeConfirmScheduler({ outcome: "applied", recommendedVersion: ENGINE_VERSION }, calls);
    await confirmUpdateIfSettled(scheduler, [aliveResult]);
    ok("[cron-alive] no confirmationPending flag at all -> nothing to confirm, no call", calls.length === 0);
  }
  // A rolled-back outcome (never applied) -> never confirmed even if somehow flagged.
  {
    const calls: Array<{ recommendedVersion?: unknown }> = [];
    const scheduler = makeConfirmScheduler({ outcome: "rolled-back", confirmationPending: true, recommendedVersion: ENGINE_VERSION }, calls);
    await confirmUpdateIfSettled(scheduler, [aliveResult]);
    ok("[cron-alive] a rolled-back outcome is never confirmable", calls.length === 0);
  }
  // No pending/settled record at all (null last) -> fully quiet, no throw.
  {
    const calls: Array<{ recommendedVersion?: unknown }> = [];
    const scheduler = makeConfirmScheduler(null, calls);
    await confirmUpdateIfSettled(scheduler, [aliveResult]);
    ok("[cron-alive] no last record at all -> quiet no-op, never throws", calls.length === 0);
  }
  // Fully fail-open: a scheduler that throws on every call degrades to "no confirmation this tick", never
  // an escaped exception (the cron driver's own guard is belt-and-braces; this function must not need it).
  {
    const scheduler = { fetch: async () => { throw new Error("scheduler unreachable (test)"); } } as unknown as DurableObjectStub;
    let threw = false;
    try {
      await confirmUpdateIfSettled(scheduler, [aliveResult]);
    } catch {
      threw = true;
    }
    ok("[fail-open] an unreachable scheduler never throws out of confirmUpdateIfSettled", threw === false);
  }
  // No results at all (an empty flight, e.g. no destinations) -> aggregateLiveness reads "pending", never
  // alive, so no confirm is attempted.
  {
    const calls: Array<{ recommendedVersion?: unknown }> = [];
    const scheduler = makeConfirmScheduler({ outcome: "applied", confirmationPending: true, recommendedVersion: ENGINE_VERSION }, calls);
    await confirmUpdateIfSettled(scheduler, []);
    ok("[cron] an empty result set (nothing flown) never confirms", calls.length === 0);
  }
}

// A break-glass-only estate could never roll back a bad self-update. Its canary returned "ailing" on
// every flight, forever, because the engine held no in-account key to read its own cell back, so
// decideKeep only ever saw ailing and only ever took the optimistic keep branch. "dead" was structurally
// unreachable for that entire population.
//
// Since verify-at-seal and the canary began reading back from the run's own per-run master, that posture
// flies a real canary, so all three verdicts are now reachable there. That is a safety GAIN and it is a
// live change to the self-update decision, which is why it is pinned rather than left implied.
function testBreakGlassOnlyCanNowRollBack(): void {
  // The verdict that used to be unreachable in this posture. A bad update on a break-glass-only estate
  // was KEPT, because the canary could not say otherwise.
  const dead = decideKeep("alive", "dead", true);
  ok("a dead canary rolls back, which a break-glass-only estate could never reach before", dead.keep === false);
  ok("and the reason names the canary rather than the posture", /canary is dead/.test(dead.reason));

  // The positive confirmation that posture also never got: it now settles on evidence rather than on
  // "the hourly canary will confirm it later".
  const alive = decideKeep("alive", "alive", true);
  ok("an alive canary keeps on evidence, not on deferred confirmation", alive.keep === true && /sings/.test(alive.reason));

  // Unchanged, and deliberately so: a flight that could not complete is still an optimistic keep. The
  // point of the change is that this is no longer the ONLY branch a break-glass-only estate can reach.
  const ailing = decideKeep("alive", "ailing", true);
  ok("an incomplete flight still keeps, with confirmation pending", ailing.keep === true);
  ok("a self-check failure alongside an incomplete flight still keeps", decideKeep("alive", "ailing", false).keep === true);
}

async function main(): Promise<void> {
  await testCriticalAllowlist();
  await testSelfCheck();
  await testConfirmUpdateIfSettled();
  testBreakGlassOnlyCanNowRollBack();
  console.log(failures === 0 ? "\nUPDATE-GATE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
