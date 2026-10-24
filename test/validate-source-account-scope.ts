// validate-source-account-scope: proves the cross-account confused-deputy guard (ASVS V4) closes end to
// end. A cf-config/workers/stream/images/artifacts source's accountId is checked not only for shape
// (config-validate.ts) but against the discovery config's `selected` / `accountsSeen` set -- otherwise a
// downpipe.write-only caller (operator/approver, or any composable custom role, since keys.ceremony can
// never enter one) could point a source at an account the Owner's own read-only discovery token can see
// but never selected, then use rediscover/trigger to probe or seal it.
//
// Covers, at each of the three layers the guard spans:
//  (1) PRIMARY write-time gate (scheduler-do.ts addDownpipe, via config-validate.ts's
//      accountInDiscoveryScope): a multi-account config rejects an out-of-scope or wholly-unseen
//      accountId at POST /admin/downpipes and accepts one that IS selected.
//  (2) DEFENSIVE re-check (router-discovery.ts POST /downpipes/cf-config/rediscover): the TOCTOU where a
//      downpipe created while its account was in scope keeps working until the Owner narrows `selected`,
//      at which point rediscover refuses instead of probing.
//  (3) An env-only (IaC) deployment with no console-set discovery config allows only the engine's own
//      account, and a single-account token (auto-selected, the common case) still works unchanged.
//  (4) The pure accountInDiscoveryScope predicate directly (unit-level), and the run path's actual
//      data-capture chokepoint, seal/runstate-helpers.ts's cfConfigToken, which THROWS (fails the run
//      loud) rather than silently sealing an out-of-scope account.
//
// Run: node test/validate-source-account-scope.ts

import { handleAdmin } from "../src/admin/router.ts";
import { makeScheduler, makeSigner, TEAM, AUD } from "./validate-rbac-harness.ts";
import { DISCOVERY_KEY } from "../src/sched/scheduler-do-records.ts";
import { accountInDiscoveryScope } from "../src/sched/config-validate.ts";
import { cfConfigToken } from "../src/seal/runstate-helpers.ts";
import type { Env } from "../src/env.d.ts";
import type { DownpipeConfig, DownpipeState } from "../src/sched/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// Cloudflare account ids are 32-char hex; three distinct accounts under test.
const ACCT_A = "a".repeat(32);
const ACCT_B = "b".repeat(32);
const ACCT_C = "c".repeat(32);

async function main(): Promise<void> {
  const signer = await makeSigner();
  const { tokenFor } = signer;
  const OWNER = "owner-scope@acme.example";

  // mk builds a fresh owner-bootstrapped scheduler with an Access-authenticated caller. discoveryCfg, when
  // given, is seeded directly into DO storage (the DISCOVERY_KEY record a real setDiscoveryToken/
  // setDiscoveryAccounts call would have produced); omitted means no console-set config at all (the
  // env-only/IaC deployment regression case).
  const mk = async (discoveryCfg?: Record<string, unknown>) => {
    const s = makeScheduler();
    const accEnv = { ...s.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN: "bg-scope" } as unknown as Env;
    const call = async (email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> =>
      handleAdmin(new Request(`https://engine.example${path}`, {
        method,
        headers: { "cf-access-jwt-assertion": await tokenFor(email), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      }), accEnv);
    await call(OWNER, "GET", "/admin/whoami"); // bootstrap the first Access caller as Owner
    if (discoveryCfg) await s.storage.put(DISCOVERY_KEY, discoveryCfg);
    return { call, s, accEnv };
  };
  const cfConfigSource = (accountId: string): DownpipeConfig["source"] => ({ type: "cf-config", accountId, include: [], exclude: [] } as DownpipeConfig["source"]);
  const createBody = (id: string, accountId: string) => ({ id, name: id, cadenceSeconds: 3600, enabled: true, source: cfConfigSource(accountId) });

  // ===========================================================================================
  // (1) PRIMARY write-time gate: a multi-account config with selected=[A], accountsSeen=[A,B].
  // ===========================================================================================
  {
    const { call } = await mk({ token: "cfat_scope_token_1234567890", setAt: 1, setBy: OWNER, accountsSeen: [{ id: ACCT_A, name: "A" }, { id: ACCT_B, name: "B" }], selected: [ACCT_A], engineAccountId: ACCT_A });

    const rB = await call(OWNER, "POST", "/admin/downpipes", createBody("dp-b", ACCT_B));
    const bB = (await rB.json()) as { error?: string };
    ok("create: an accountId the token SAW but the Owner never selected is rejected (400)", rB.status === 400);
    ok("create: the rejection names the discovery-scope reason", /discovery-selected/.test(bB.error ?? ""));

    const rC = await call(OWNER, "POST", "/admin/downpipes", createBody("dp-c", ACCT_C));
    ok("create: an accountId the token never saw AT ALL is rejected (400)", rC.status === 400);

    const rA = await call(OWNER, "POST", "/admin/downpipes", createBody("dp-a", ACCT_A));
    ok("create: the Owner-selected accountId is accepted (200)", rA.status === 200);

    // A secrets source reads its wiring metadata (scopes, comment, the Workers that bind it) with the same
    // discovery token, so its optional accountId gets the same shape check and the same scope check.
    const secretsBody = (id: string, accountId: string) => ({ id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "secrets", accountId, secrets: [{ name: "API_KEY", binding: "SRC_SEC_api_key", storeId: "0123456789abcdef0123456789abcdef" }], include: [], exclude: [] } });
    const sB = await call(OWNER, "POST", "/admin/downpipes", secretsBody("dp-sec-b", ACCT_B));
    const sBody = (await sB.json()) as { error?: string };
    ok("create: a secrets source whose accountId is seen but not selected is rejected (400, discovery scope)", sB.status === 400 && /discovery-selected/.test(sBody.error ?? ""));
    const sBad = await call(OWNER, "POST", "/admin/downpipes", secretsBody("dp-sec-bad", "not-an-account!"));
    const sBadBody = (await sBad.json()) as { error?: string };
    ok("create: a secrets source with a malformed accountId is rejected (400, shape)", sBad.status === 400 && /secrets accountId must be a Cloudflare account id/.test(sBadBody.error ?? ""));
    const sA = await call(OWNER, "POST", "/admin/downpipes", secretsBody("dp-sec-a", ACCT_A));
    ok("create: a secrets source whose accountId is selected is accepted (200)", sA.status === 200);
  }

  // ===========================================================================================
  // (2) DEFENSIVE re-check (TOCTOU): a downpipe created while its account is in scope must stop
  //     working the moment the Owner narrows `selected` to no longer include it.
  // ===========================================================================================
  {
    const { call } = await mk({ token: "cfat_scope_token_1234567890", setAt: 1, setBy: OWNER, accountsSeen: [{ id: ACCT_A, name: "A" }, { id: ACCT_B, name: "B" }], selected: [ACCT_A, ACCT_B], engineAccountId: ACCT_A });

    // B is in scope at creation time -> accepted.
    const created = await call(OWNER, "POST", "/admin/downpipes", createBody("dp-toctou", ACCT_B));
    ok("toctou: created while B is in the browsed set (200)", created.status === 200);

    // The Owner narrows the browsed set to A only -- B is still `accountsSeen` (the token still sees it)
    // but no longer `selected`.
    const narrowed = await call(OWNER, "POST", "/admin/sources/discovery-accounts", { selected: [ACCT_A], engineAccountId: ACCT_A });
    ok("toctou: the Owner can narrow the browsed set to A only (200)", narrowed.status === 200);

    // rediscover on the now-out-of-scope downpipe must refuse, NEVER reach probeCfConfig (which would
    // otherwise make a real Cloudflare API call).
    const redisc = await call(OWNER, "POST", "/admin/downpipes/cf-config/rediscover", { id: "dp-toctou" });
    const rb = (await redisc.json()) as { ok: boolean; error?: string; discovery?: unknown };
    ok("toctou: rediscover on the deselected account returns ok:false (200 status, refusal body)", redisc.status === 200 && rb.ok === false);
    ok("toctou: the refusal names the no-longer-in-scope reason and never returns a discovery partition", /no longer in the discovery scope/.test(rb.error ?? "") && rb.discovery === undefined);
  }

  // ===========================================================================================
  // (3a) An env-only (IaC) deployment -- no console-set discovery config at all -- allows only the engine's
  //      own account: a foreign account is refused (the lower-role confused deputy), the verified engine
  //      account is accepted.
  // ===========================================================================================
  {
    const { call, accEnv, s } = await mk(undefined);
    (accEnv as unknown as { DISCOVERY_API_TOKEN: string }).DISCOVERY_API_TOKEN = "env-fallback-token-1234567890";
    const foreign = await call(OWNER, "POST", "/admin/downpipes", createBody("dp-env-foreign", ACCT_C));
    ok("env-only discovery, engine account unknown: a foreign accountId is refused (400)", foreign.status === 400);
    await s.storage.put("engineAccountVerified", { accountId: ACCT_A, verifiedAt: 1, via: "attach" });
    const stillForeign = await call(OWNER, "POST", "/admin/downpipes", createBody("dp-env-foreign2", ACCT_C));
    ok("env-only discovery, engine account known: a foreign accountId is still refused (400)", stillForeign.status === 400);
    const own = await call(OWNER, "POST", "/admin/downpipes", createBody("dp-env-own", ACCT_A));
    ok("negative control: env-only discovery accepts the verified engine account (200)", own.status === 200);
  }

  // ===========================================================================================
  // (3b) REGRESSION: a single-account token (auto-selected on connect, the common case) still works.
  // ===========================================================================================
  {
    const { call } = await mk({ token: "cfat_scope_token_1234567890", setAt: 1, setBy: OWNER, accountsSeen: [{ id: ACCT_A, name: "A" }], selected: [ACCT_A], engineAccountId: ACCT_A });
    const r = await call(OWNER, "POST", "/admin/downpipes", createBody("dp-single", ACCT_A));
    ok("regression: a single-account (auto-selected) token still accepts its one account (200)", r.status === 200);
  }

  // ===========================================================================================
  // (4a) The pure predicate directly (unit-level): every branch of accountInDiscoveryScope.
  // ===========================================================================================
  {
    ok("predicate: a null config with the engine account known allows only that account", accountInDiscoveryScope(ACCT_C, null, ACCT_C) && !accountInDiscoveryScope(ACCT_A, null, ACCT_C));
    ok("predicate: a null config with an unknown engine account allows no account", !accountInDiscoveryScope(ACCT_C, null, null));
    ok("predicate: in accountsSeen, selected EMPTY (fresh multi-account token, no choice made yet) -> in scope", accountInDiscoveryScope(ACCT_B, { accountsSeen: [{ id: ACCT_A }, { id: ACCT_B }], selected: [] }, null));
    ok("predicate: in accountsSeen AND in a non-empty selected -> in scope", accountInDiscoveryScope(ACCT_A, { accountsSeen: [{ id: ACCT_A }, { id: ACCT_B }], selected: [ACCT_A] }, null));
    ok("predicate: in accountsSeen but selected is non-empty and excludes it -> OUT of scope", !accountInDiscoveryScope(ACCT_B, { accountsSeen: [{ id: ACCT_A }, { id: ACCT_B }], selected: [ACCT_A] }, null));
    ok("predicate: never in accountsSeen at all -> OUT of scope even with an empty selected", !accountInDiscoveryScope(ACCT_C, { accountsSeen: [{ id: ACCT_A }], selected: [] }, null));
    // AN EMPTY accountsSeen IS A CONFIG, NOT AN ABSENT ONE, and it is the vector every case above was
    // missing: all five use a non-empty accountsSeen, so widening the null-config no-op to
    // `cfg === null || cfg.accountsSeen.length === 0` passed the whole file. That is the shape of a
    // plausible "treat an empty config like no config" tidy-up, and it is reachable: a saved discovery
    // config whose token authenticates but lists zero accounts has exactly this shape (see
    // router-sources-discovery.ts, where a token that can list nothing yields accounts: []). Under the
    // widened rule that config waves through ANY account id the shared token can reach, which is the
    // confused deputy this predicate exists to stop.
    ok("predicate: a config that saw ZERO accounts is still a config -> OUT of scope, not a no-op", !accountInDiscoveryScope(ACCT_C, { accountsSeen: [], selected: [] }, null));
    ok("predicate: a zero-account config does not wave through a selected id either", !accountInDiscoveryScope(ACCT_A, { accountsSeen: [], selected: [ACCT_A] }, null));
  }

  // ===========================================================================================
  // (4b) The run path's actual data-capture chokepoint: seal/runstate-helpers.ts's cfConfigToken must
  //      THROW for an out-of-scope accountId (a recorded, alertable failed run) rather than resolve the
  //      token and let buildAdapter silently seal the wrong account.
  // ===========================================================================================
  {
    const { s, accEnv } = await mk({ token: "cfat_scope_token_1234567890", setAt: 1, setBy: OWNER, accountsSeen: [{ id: ACCT_A, name: "A" }, { id: ACCT_B, name: "B" }], selected: [ACCT_A], engineAccountId: ACCT_A });
    const stateOf = (id: string, accountId: string): DownpipeState => ({
      config: { id, name: id, cadenceSeconds: 3600, enabled: true, source: cfConfigSource(accountId) } as DownpipeConfig,
      nextRunAt: 0,
      lastRunId: null,
      inFlight: false,
    });

    let threwB = false;
    try {
      await cfConfigToken(s.stub, stateOf("run-b", ACCT_B), accEnv);
    } catch {
      threwB = true;
    }
    ok("run path: cfConfigToken THROWS for an out-of-scope accountId (fails the run loud, never seals)", threwB);

    let threwA = false;
    let tokenA: string | undefined;
    try {
      tokenA = await cfConfigToken(s.stub, stateOf("run-a", ACCT_A), accEnv);
    } catch {
      threwA = true;
    }
    ok("run path: cfConfigToken resolves normally (returns the token) for an in-scope accountId", !threwA && tokenA === "cfat_scope_token_1234567890");

    // A binding source (kv) is untouched: no accountId check applies and no token is resolved.
    const kvState: DownpipeState = { config: { id: "run-kv", name: "run-kv", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_x", include: [], exclude: [] } } as DownpipeConfig, nextRunAt: 0, lastRunId: null, inFlight: false };
    const kvToken = await cfConfigToken(s.stub, kvState, accEnv);
    ok("run path: a binding source (kv) is unaffected -- cfConfigToken returns undefined, no DO round trip needed", kvToken === undefined);
  }

  signer.restoreFetch();
  console.log(failures === 0 ? "\nvalidate-source-account-scope: ALL PASS" : `\nvalidate-source-account-scope: ${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
