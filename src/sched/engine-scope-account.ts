// engine-scope-account.ts -- the engine's own Cloudflare account, as the discovery scope guard names it.
//
// With no console-set discovery config (an env-only discovery token), the only account a downpipe source may
// name is the engine's own: CF_ACCOUNT_ID when it is set, else the account the engine has proved it runs in
// (the scheduler's verified engine account). Null means neither is known, and the guard then refuses every
// account. An error reply carries no account id and so reads as null; a read that throws propagates. A fault
// therefore never reads as "no restriction".

import { doURL } from "../do-url.ts";

interface SchedulerFetcher {
  fetch(input: string, init?: RequestInit): Promise<Response>;
}

export async function engineScopeAccount(env: { CF_ACCOUNT_ID?: unknown }, scheduler: SchedulerFetcher): Promise<string | null> {
  const fromEnv = typeof env.CF_ACCOUNT_ID === "string" ? env.CF_ACCOUNT_ID.trim() : "";
  if (fromEnv !== "") return fromEnv;
  const resp = await scheduler.fetch(doURL("/sources/engine-account-verified"), { method: "GET" });
  const verified = (await resp.json()) as { accountId?: unknown } | null;
  return typeof verified?.accountId === "string" && verified.accountId !== "" ? verified.accountId : null;
}

// recordEnvEngineAccount records CF_ACCOUNT_ID, when the deploy sets it, as the engine's verified account. The
// scheduler cannot see env, and its scope check (accountInDiscoveryScope) runs inside it, so the Worker hands
// the value over before a downpipe is added and before a configuration replay after a storage wipe. CF_ACCOUNT_ID
// wins over any stored account, here and in engineScopeAccount, so the Worker's check and the scheduler's check
// name the same account: a value that differs from the stored one replaces it, and an equal value changes
// nothing, so this is safe to call on every mutating request and every tick. Nothing is sent when CF_ACCOUNT_ID
// is unset.
export async function recordEnvEngineAccount(env: { CF_ACCOUNT_ID?: unknown }, scheduler: SchedulerFetcher): Promise<void> {
  const fromEnv = typeof env.CF_ACCOUNT_ID === "string" ? env.CF_ACCOUNT_ID.trim() : "";
  if (fromEnv === "") return;
  await scheduler.fetch(doURL("/sources/engine-account-verified"), { method: "POST", body: JSON.stringify({ accountId: fromEnv, via: "deploy-var" }), headers: { "content-type": "application/json" } });
}
