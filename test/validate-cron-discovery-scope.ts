// validate-cron-discovery-scope: the last line of defence against the CRON half of the cross-account
// confused-deputy guard (ASVS V4, HI-11) being deleted without a single validator noticing.
//
// THE FAILURE THIS FILE STOPS. src/cron/discovery-pass.ts:55 is the fourth and last call site of
// accountInDiscoveryScope. Its own comment states why it exists: `selected` can narrow AFTER a downpipe was
// created, so the periodic refresh must not keep silently servicing a since-deselected Cloudflare account
// with the Owner's account-wide discovery token. Remove it and the pass keeps probing an account the Owner
// has revoked, on a */15 cron, with no request, no operator and no recorded cause.
//
// WHY A DEDICATED VALIDATOR. accountInDiscoveryScope has four call sites; the other three (the write-time
// gate, the rediscover re-check and the run-path token chokepoint) are covered by
// test/validate-source-account-scope.ts, which never reaches the cron pass. Without this file, deleting the
// cron guard would be invisible to the rest of the suite. Neutering line 55 turns this file red.
//
// WHAT IT DRIVES. The REAL runDiscoveryPass, with all three of its injectable arguments stubbed: a scheduler
// whose fetch answers on the DO path and RECORDS every path and body it is handed, a budget held well above
// DISCOVERY_PROBE_RESERVE so the budget bail can never pre-empt the guard, and a globalThis.fetch that
// refuses offline so a probe past the guard can never touch the network. The POST to /cf-config/discovery is
// the probe RESULT sink, so a POST recorded in an out-of-scope case IS the confused-deputy firing.
//
// Run: node test/validate-cron-discovery-scope.ts

import { drainCronFaultLedger, resetCronFaultLedger } from "../src/cron/cron-fault-ledger.ts";
import { runDiscoveryPass } from "../src/cron/discovery-pass.ts";
import type { schedulerStub } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import type { DownpipeConfig, DownpipeState } from "../src/sched/types.ts";
import type { budgetFromEnv } from "../src/seal/budget.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// Cloudflare account ids are 32-char hex. A is selected, B is seen but deselected, C was never seen at all.
const ACCT_A = "a".repeat(32);
const ACCT_B = "b".repeat(32);
const ACCT_C = "c".repeat(32);

// DISCOVERY_PROBE_RESERVE is 250; the stub budget sits far above it so the budget bail (which returns before
// the scope guard is ever reached) can never be mistaken for the guard firing.
const BUDGET_REMAINING = 10_000;

/** DiscoveryCfgStub is the /sources/discovery-config body's `config`, or null for the env/IaC-only case. */
type DiscoveryCfgStub = { token: string; accountsSeen: Array<{ id: string }>; selected: string[] } | null;

/** CaseOutcome is everything one pass observably did: the ledger reasons, the DO traffic and the spend. */
interface CaseOutcome {
  skips: Partial<Record<string, number>>;
  posts: string[];
  gets: string[];
  spends: number[];
  probeFetches: number;
  returned: boolean;
}

// The offline fetch refusal. A validator must never touch the network, and this is what keeps the positive
// control offline. It answers 403 with an EMPTY Cloudflare errors array on purpose: cf-config-core then
// builds the thrown message as the bare "HTTP 403", which dest/classify.ts reads as an embedded status and
// classifies AUTH, so withRetry fails it on attempt one. A message carrying any of the network vocabulary
// instead takes the transient arm, and API_READ_RETRY's six attempts with backoff, on every account
// surface, would hang the run past two minutes.
//
// Counting the calls is also the strongest positive-control signal there is: an outbound fetch is attempted
// at all only if execution got PAST the scope guard.
let probeFetches = 0;
const realFetch = globalThis.fetch;
globalThis.fetch = ((): Promise<Response> => {
  probeFetches++;
  return Promise.resolve(new Response(JSON.stringify({ success: false, errors: [] }), { status: 403 }));
}) as typeof fetch;

/**
 * runCase drives the real runDiscoveryPass once against a stubbed scheduler, budget and env.
 *
 * @param accountId - the accountId the due downpipe's cf-config source names.
 * @param cfg - the discovery config the DO hands back (null = the env/IaC-only deployment).
 * @returns what the pass observably did.
 */
async function runCase(accountId: string, cfg: DiscoveryCfgStub): Promise<CaseOutcome> {
  resetCronFaultLedger();
  probeFetches = 0;
  const posts: string[] = [];
  const gets: string[] = [];
  const spends: number[] = [];

  const state: DownpipeState = {
    config: { id: "dp-discovery-scope", name: "dp-discovery-scope", cadenceSeconds: 3600, enabled: true, source: { type: "cf-config", accountId, include: [], exclude: [] } } as DownpipeConfig,
    nextRunAt: 0,
    lastRunId: null,
    inFlight: false,
  };

  // The scheduler is used ONLY as scheduler.fetch(doURL(path), init), so a plain object with a fetch that
  // keys on the pathname is a complete stand-in. Every call is recorded before it is answered.
  const scheduler = {
    fetch: (url: string, init?: { method?: string; body?: string }): Promise<{ json: () => Promise<unknown> }> => {
      const path = new URL(url).pathname;
      if ((init?.method ?? "GET") === "POST") {
        posts.push(path);
        return Promise.resolve({ json: (): Promise<unknown> => Promise.resolve({ ok: true }) });
      }
      gets.push(path);
      if (path === "/cf-config/discovery-due") return Promise.resolve({ json: (): Promise<unknown> => Promise.resolve({ due: [state] }) });
      if (path === "/sources/discovery-config") return Promise.resolve({ json: (): Promise<unknown> => Promise.resolve({ config: cfg }) });
      return Promise.resolve({ json: (): Promise<unknown> => Promise.resolve({}) });
    },
  } as unknown as ReturnType<typeof schedulerStub>;

  const budget = {
    remaining: (): number => BUDGET_REMAINING,
    spend: (n: number): void => {
      spends.push(n);
    },
  } as unknown as ReturnType<typeof budgetFromEnv>;

  // The env token is the documented fallback for a deployment with no console-set discovery config; it is
  // what carries case (4) past the no-token bail so the null-config branch can be reached at all.
  const env = { DISCOVERY_API_TOKEN: "env-fallback-token-for-the-validator" } as unknown as Env;

  const returned = await runDiscoveryPass(env, scheduler, budget);
  const drained = drainCronFaultLedger();
  return { skips: drained.discoverySkips ?? {}, posts, gets, spends, probeFetches, returned };
}

async function main(): Promise<void> {
  const CFG_SEEN_AND_SELECTED: DiscoveryCfgStub = { token: "cfat_cron_scope_token_1234567890", accountsSeen: [{ id: ACCT_A }, { id: ACCT_B }], selected: [ACCT_A] };

  // ===========================================================================================
  // (1) OUT OF SCOPE: the token still SEES account B, and the Owner has narrowed `selected` to A.
  //     This is the exact TOCTOU the guard's comment names: the downpipe was legal when created.
  // ===========================================================================================
  {
    const r = await runCase(ACCT_B, CFG_SEEN_AND_SELECTED);
    console.log("(1) seen but deselected");
    ok("out-of-scope: the pass read both DO routes and got as far as the guard", r.gets.includes("/cf-config/discovery-due") && r.gets.includes("/sources/discovery-config"));
    ok("out-of-scope: NO probe result was posted to /cf-config/discovery", !r.posts.includes("/cf-config/discovery"));
    ok("out-of-scope: the probe reserve was never spent", r.spends.length === 0);
    ok("out-of-scope: no outbound Cloudflare fetch was attempted at all", r.probeFetches === 0);
    ok('out-of-scope: the ledger records the skip as "out-of-scope"', r.skips["out-of-scope"] === 1);
    ok("out-of-scope: the skip is a deferral, not a pass fault (returns true)", r.returned === true);
  }

  // ===========================================================================================
  // (2) NEVER SEEN AT ALL: account C is in neither accountsSeen nor selected. Same expectations:
  //     an account the discovery token never verified must never be probed by the cron.
  // ===========================================================================================
  {
    const r = await runCase(ACCT_C, CFG_SEEN_AND_SELECTED);
    console.log("(2) never in accountsSeen");
    ok("never-seen: NO probe result was posted to /cf-config/discovery", !r.posts.includes("/cf-config/discovery"));
    ok("never-seen: the probe reserve was never spent", r.spends.length === 0);
    ok("never-seen: no outbound Cloudflare fetch was attempted at all", r.probeFetches === 0);
    ok('never-seen: the ledger records the skip as "out-of-scope"', r.skips["out-of-scope"] === 1);
    ok("never-seen: the skip is a deferral, not a pass fault (returns true)", r.returned === true);
  }

  // ===========================================================================================
  // (3) POSITIVE CONTROL, IN SCOPE: account A IS selected, so the guard must NOT fire. Execution
  //     reaching budget.spend and an outbound probe fetch is the proof it got PAST the guard.
  //     globalThis.fetch refuses offline, so the probe classifies every surface as unreadable; that
  //     outcome is irrelevant here, the point is only that the guard let it through.
  // ===========================================================================================
  {
    const r = await runCase(ACCT_A, CFG_SEEN_AND_SELECTED);
    console.log("(3) selected (positive control)");
    ok("in-scope: the guard did NOT fire (no out-of-scope skip recorded)", r.skips["out-of-scope"] === undefined);
    ok("in-scope: the probe reserve WAS spent, which is the first statement past the guard", r.spends.length === 1 && r.spends[0] === 250);
    ok("in-scope: execution reached the outbound probe", r.probeFetches > 0);
    ok("in-scope: the pass either posted its result or recorded probe-failed, never a scope skip", r.posts.includes("/cf-config/discovery") || r.skips["probe-failed"] === 1);
  }

  // ===========================================================================================
  // (4) NULL CONFIG (the env-only / IaC deployment): there is no Owner-curated list to check
  //     against, so the guard is a documented no-op. It must NOT read as out-of-scope, which
  //     would silently stop discovery refreshing on every IaC deployment in the fleet.
  // ===========================================================================================
  {
    const r = await runCase(ACCT_C, null);
    console.log("(4) null discovery config (env/IaC only)");
    ok("null-config: the guard does not fire (no out-of-scope skip recorded)", r.skips["out-of-scope"] === undefined);
    ok("null-config: the pass proceeded to spend the probe reserve", r.spends.length === 1 && r.spends[0] === 250);
    ok("null-config: it did not bail for a missing token either", r.skips["no-token"] === undefined);
  }

  globalThis.fetch = realFetch;
  console.log(failures === 0 ? "\nvalidate-cron-discovery-scope: ALL PASS" : `\nvalidate-cron-discovery-scope: ${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

void main();
