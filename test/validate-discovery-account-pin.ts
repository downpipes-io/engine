// resolveDiscoveryAccounts must always ask the live Cloudflare /accounts API which accounts a
// token can reach. It used to short-circuit and return a single FABRICATED account record built from
// env.CF_ACCOUNT_ID whenever that var was set, without ever calling cfApi(token) or GET /accounts --
// so a token whose real reach differs from the pinned id (wrong account, expired, or merely
// shape-valid garbage) was accepted with a confident "1 account visible" answer, and the
// zero-account onboarding warning (the one built specifically to catch that) could never fire.
//
// resolveEngineAccountId is untouched by the fix: it returns env.CF_ACCOUNT_ID directly one level
// above its own call into resolveDiscoveryAccounts, so it never reaches the pinned branch either way
// (asserted below).

import { resolveDiscoveryAccounts, resolveEngineAccountId } from "../src/admin/router-sources-discovery.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(msg: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${msg}`);
  if (!cond) failures++;
}

const realFetch = globalThis.fetch;

// A token that genuinely reaches TWO accounts, neither of which is the pinned env account -- the
// "wrong account" / "reissued for a different estate" case the bug hides.
function stubMultiAccountFetch(): { calls: string[] } {
  const calls: string[] = [];
  globalThis.fetch = (async (input: unknown): Promise<Response> => {
    calls.push(String(input));
    return new Response(JSON.stringify({ result: [{ id: "acct-real-1", name: "Real One" }, { id: "acct-real-2", name: "Real Two" }] }), { status: 200 });
  }) as typeof fetch;
  return { calls };
}

function stubUnreachableFetch(): { calls: string[] } {
  const calls: string[] = [];
  globalThis.fetch = (async (input: unknown): Promise<Response> => {
    calls.push(String(input));
    return new Response("unauthorized", { status: 401 });
  }) as typeof fetch;
  return { calls };
}

const baseEnv = { CF_ACCOUNT_ID: "acct-pinned" } as unknown as Env;

console.log("-- resolveDiscoveryAccounts must consult the live API, never trust the pin alone --");
{
  const { calls } = stubMultiAccountFetch();
  const resolved = await resolveDiscoveryAccounts("some-token-value", baseEnv);
  ok("calls the Cloudflare API at least once (not skipped by the pin)", calls.length > 0);
  ok("returns the token's REAL account list, not a fabricated single pinned record", resolved.accounts.length === 2);
  ok("does not silently substitute the pinned id for the token's own accounts", !(resolved.accounts.length === 1 && resolved.accounts[0]!.id === "acct-pinned"));
  globalThis.fetch = realFetch;
}

console.log("\n-- an unreachable/wrong-account token must NOT be reported as '1 account visible' --");
{
  stubUnreachableFetch();
  const resolved = await resolveDiscoveryAccounts("garbage-shaped-token-xxxxxxxxxxxxxxxx", baseEnv);
  ok("reports zero accounts (so the onboarding warning can fire)", resolved.accounts.length === 0);
  ok("carries an error explaining why", resolved.errors.length > 0);
  globalThis.fetch = realFetch;
}

console.log("\n-- resolveEngineAccountId is unaffected: it returns CF_ACCOUNT_ID one level above the pinned branch --");
{
  const { calls } = stubMultiAccountFetch();
  const accountId = await resolveEngineAccountId(baseEnv, null);
  ok("still resolves the pinned engine account directly", accountId === "acct-pinned");
  ok("never calls the Cloudflare API to do so (short-circuits one level up, at env.CF_ACCOUNT_ID)", calls.length === 0);
  globalThis.fetch = realFetch;
}

if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall discovery account-pin checks passed");
