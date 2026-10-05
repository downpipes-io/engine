// Pins that a Secrets Store secret's archive record says WHERE the secret was: its scopes and comment from the
// Secrets Store, and every Worker that binds it (script + binding name), read with the read-only discovery token.
// Before this, buildAdapter set only name/get/bindingVar/store, so descriptor.secretsScope/secretsWorker/
// secretsComment existed in the type but no run ever populated them, and the archive could not say which of
// the customer's Workers used a secret.
//
// It also pins the degradation contract. The metadata is additive: a missing token, an under-scoped token, an
// unreadable script or a slice budget too small for the Workers pass must never fail the run, and the Worker
// list is never a partial guess. Each such run still seals every value, records the wiring as "unknown", and
// records why as an incompleteness fact (never as an API shape anomaly).
//
// And it pins the account-scope guard (ASVS V4): every account the reader touches must be in the Owner's
// discovery scope, and "captured" needs the secret's name in the store and the engine's own binding in the list.
// Run: node test/validate-secrets-wiring.ts

import { buildRecordLine } from "../src/format/writer-record.ts";
import type { DownpipeState } from "../src/sched/types.ts";
import { validateConfig } from "../src/sched/config-validate.ts";
import { buildAdapter } from "../src/seal/adapters.ts";
import { FINALISE_RESERVE, SliceBudget } from "../src/seal/budget.ts";
import { cfConfigToken } from "../src/seal/runstate-helpers.ts";
import { SECRETS_WIRING_RESERVE_PER_SECRET } from "../src/sources/secrets-wiring.ts";
import { readSourceFaultLedger, resetSourceFaultLedger, type SourceFaultLedger } from "../src/sources/source-fault-ledger.ts";
import type { SourceRecord } from "../src/sources/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { healthStub, makeEnv, makeSchedulerStub } from "./validate-worker-helpers.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

const STORE = "0123456789abcdef0123456789abcdef";
const ACCT = "acct-owner";

// incompleteIds lists every "secrets:wiring/..." id the ledger holds, under any marker kind.
function wiringIds(l: SourceFaultLedger): string[] {
  return Object.values(l.incompleteIds).flat().filter((id): id is string => typeof id === "string" && id.startsWith("secrets:wiring/"));
}

function secretsState(accountId?: string): DownpipeState {
  return {
    config: {
      id: "dp-secrets",
      name: "secrets",
      cadenceSeconds: 3600,
      enabled: true,
      source: { type: "secrets", ...(accountId !== undefined ? { accountId } : {}), secrets: [{ name: "API_KEY", binding: "SRC_SEC_api_key", storeId: STORE }, { name: "DB_URL", binding: "SRC_SEC_db_url", storeId: STORE }], include: [], exclude: [] },
    },
    nextRunAt: 0,
    lastRunId: null,
    inFlight: false,
  } as unknown as DownpipeState;
}

interface FakeAccount {
  secrets?: Array<Record<string, unknown>>;
  secretsStatus?: number;
  scripts?: string[];
  settings?: Record<string, { status?: number; bindings?: unknown[] }>;
}

// fakeCloudflare stubs globalThis.fetch with an in-memory Cloudflare API. It records every path so the test
// can prove no value ever rides a request.
function fakeCloudflare(accounts: Record<string, FakeAccount>, listedAccounts: string[]): { paths: string[]; restore: () => void } {
  const paths: string[] = [];
  const real = globalThis.fetch;
  const json = (status: number, body: unknown): Response => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const cfEnvelope = (result: unknown) => ({ success: true, errors: [], result, result_info: { page: 1, total_pages: 1 } });
  const fail = (status: number) => json(status, { success: false, errors: [{ message: `HTTP ${status}` }], result: null });
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
    const p = u.pathname.replace(/^\/client\/v4/, "");
    paths.push(p + u.search);
    if (p === "/accounts") return json(200, cfEnvelope(listedAccounts.map((id) => ({ id }))));
    let m = p.match(/^\/accounts\/([^/]+)\/secrets_store\/stores\/([^/]+)\/secrets$/);
    if (m) {
      const a = accounts[decodeURIComponent(m[1]!)];
      if (a === undefined || a.secrets === undefined || decodeURIComponent(m[2]!) !== STORE) return fail(404);
      if (a.secretsStatus !== undefined) return fail(a.secretsStatus);
      return json(200, cfEnvelope(a.secrets));
    }
    m = p.match(/^\/accounts\/([^/]+)\/workers\/scripts$/);
    if (m) {
      const a = accounts[decodeURIComponent(m[1]!)];
      if (a?.scripts === undefined) return fail(403);
      return json(200, cfEnvelope(a.scripts.map((id) => ({ id }))));
    }
    m = p.match(/^\/accounts\/([^/]+)\/workers\/scripts\/([^/]+)\/settings$/);
    if (m) {
      const s = accounts[decodeURIComponent(m[1]!)]?.settings?.[decodeURIComponent(m[2]!)];
      if (s === undefined) return fail(404);
      if (s.status !== undefined) return fail(s.status);
      return json(200, cfEnvelope({ bindings: s.bindings ?? [] }));
    }
    return fail(404);
  }) as typeof fetch;
  return { paths, restore: () => { globalThis.fetch = real; } };
}

const VALUES: Record<string, string> = { SRC_SEC_api_key: "sk-live-never-in-a-request", SRC_SEC_db_url: "postgres://never-in-a-request" };
// scopeStub answers the scheduler DO's discovery-config read. undefined = no stored config (an env-only
// token); "throw" = the DO cannot be read.
function scopeStub(cfg?: { accountsSeen: Array<{ id: string }>; selected: string[] } | "throw") {
  if (cfg === undefined) return healthStub();
  return makeSchedulerStub(async (url) => {
    if (cfg === "throw") throw new Error("DO unreachable");
    if (url.endsWith("/sources/discovery-config")) return new Response(JSON.stringify({ config: { token: "do-token", ...cfg } }), { status: 200 });
    return new Response("{}", { status: 200 });
  });
}
function secretEnv(extra: Record<string, unknown> = {}, scope?: Parameters<typeof scopeStub>[0]) {
  return makeEnv(scopeStub(scope), { SRC_SEC_api_key: { get: async () => VALUES["SRC_SEC_api_key"] }, SRC_SEC_db_url: { get: async () => VALUES["SRC_SEC_db_url"] }, ...extra } as never);
}

async function crawl(state: DownpipeState, token: string | undefined, env = secretEnv(), budget?: SliceBudget): Promise<SourceRecord[]> {
  const recs: SourceRecord[] = [];
  for await (const r of buildAdapter(env, state, token).crawl({ include: [], exclude: [] }, budget)) recs.push(r);
  return recs;
}

// crawlLikeASlice drives the crawl the way seal/slice.ts crawlNonResumable does: once one record is sealed,
// a budget that says yield fails the whole run ("source too large for one slice").
async function crawlLikeASlice(state: DownpipeState, env: ReturnType<typeof secretEnv>, budget: SliceBudget): Promise<{ recs: SourceRecord[]; failed: boolean }> {
  const recs: SourceRecord[] = [];
  for await (const r of buildAdapter(env, state, "discovery-token").crawl({ include: [], exclude: [] }, budget)) {
    if (recs.length > 0 && budget.shouldYield()) return { recs, failed: true };
    recs.push(r);
  }
  return { recs, failed: false };
}

const OWNER: FakeAccount = {
  secrets: [
    { id: "s1", name: "API_KEY", scopes: ["workers", "ai_gateway"], comment: "prod API key", status: "active" },
    { id: "s2", name: "DB_URL", scopes: ["workers"], status: "active" },
  ],
  scripts: ["web", "api", "downpipes-engine"],
  settings: {
    api: { bindings: [{ type: "secrets_store_secret", name: "KEY", store_id: STORE, secret_name: "API_KEY" }, { type: "kv_namespace", name: "CACHE", namespace_id: "n1" }] },
    web: { bindings: [{ type: "secrets_store_secret", name: "UPSTREAM_KEY", store_id: STORE, secret_name: "API_KEY" }, { type: "secrets_store_secret", name: "OTHER", store_id: "another-store", secret_name: "DB_URL" }] },
    "downpipes-engine": { bindings: [{ type: "secrets_store_secret", name: "SRC_SEC_api_key", store_id: STORE, secret_name: "API_KEY" }, { type: "secrets_store_secret", name: "SRC_SEC_db_url", store_id: STORE, secret_name: "DB_URL" }] },
  },
};

async function capturedCase(): Promise<void> {
  console.log("\nwiring captured (token + accountId, every script readable):");
  const cf = fakeCloudflare({ [ACCT]: OWNER }, [ACCT]);
  try {
    const recs = await crawl(secretsState(ACCT), "discovery-token");
    const api = recs.find((r) => r.name === "API_KEY");
    const db = recs.find((r) => r.name === "DB_URL");
    ok("both secrets are sealed with their values", recs.length === 2 && new TextDecoder().decode(api?.value) === VALUES["SRC_SEC_api_key"]);
    ok("API_KEY records its scopes from the Secrets Store (sorted)", JSON.stringify(api?.descriptor?.secretsScopes) === JSON.stringify(["ai_gateway", "workers"]));
    ok("API_KEY records its comment", api?.descriptor?.secretsComment === "prod API key");
    ok(
      "API_KEY records every Worker that binds it, with the binding name, sorted by script",
      JSON.stringify(api?.descriptor?.secretsWorkers) === JSON.stringify([{ script: "api", binding: "KEY" }, { script: "downpipes-engine", binding: "SRC_SEC_api_key" }, { script: "web", binding: "UPSTREAM_KEY" }]),
    );
    ok("API_KEY wiring is captured (the Worker list is complete)", api?.descriptor?.secretsWiring === "captured");
    ok("a binding to the same secret NAME in ANOTHER store is not counted", !(JSON.stringify(db?.descriptor?.secretsWorkers) ?? "").includes("OTHER"));
    ok("DB_URL has no comment and is bound only by the engine", db?.descriptor?.secretsComment === undefined && JSON.stringify(db?.descriptor?.secretsWorkers) === JSON.stringify([{ script: "downpipes-engine", binding: "SRC_SEC_db_url" }]));
    ok("the store and the engine binding are still recorded", api?.descriptor?.secretsStore === STORE && api?.descriptor?.secretsBindingVar === "SRC_SEC_api_key");
    ok("the Secrets Store is read once per store, not once per secret", cf.paths.filter((p) => p.includes("/secrets_store/")).length === 1);
    ok("no request path carries a secret value", !cf.paths.some((p) => Object.values(VALUES).some((v) => p.includes(encodeURIComponent(v)) || p.includes(v))));
    ok("no descriptor field carries a secret value", !recs.some((r) => Object.values(VALUES).some((v) => (JSON.stringify(r.descriptor) ?? "").includes(v))));

    // The manifest line carries the new members under the omitempty contract.
    const line = (await buildRecordLine(new Uint8Array(32), "rid-1", { sourceType: "secrets", name: "API_KEY", descriptor: api!.descriptor! }, { segments: [], plaintextSha384: "00".repeat(48), size: 1 })).line as { secrets?: Record<string, unknown> };
    ok(
      "the record line's secrets descriptor carries store, scopes, comment, workers, wiring and bindingVar",
      JSON.stringify(Object.keys(line.secrets ?? {}).sort()) === JSON.stringify(["bindingVar", "comment", "scopes", "store", "wiring", "workers"]),
    );
  } finally {
    cf.restore();
  }
}

async function accountDiscoveryCase(): Promise<void> {
  console.log("\nno accountId and no CF_ACCOUNT_ID: the reader probes the in-scope accounts of the discovery config:");
  const cf = fakeCloudflare({ "acct-other": { scripts: [] }, [ACCT]: OWNER }, ["acct-other", ACCT]);
  try {
    const recs = await crawl(secretsState(), "discovery-token", secretEnv({}, { accountsSeen: [{ id: "acct-other" }, { id: ACCT }], selected: [] }));
    const api = recs.find((r) => r.name === "API_KEY");
    ok("the store is found in the in-scope account that returns it (acct-other 404s)", api?.descriptor?.secretsWiring === "captured" && api.descriptor.secretsScopes?.length === 2);
    ok("the Workers of the non-owning account are never read", !cf.paths.some((p) => p.startsWith("/accounts/acct-other/workers")));
    ok("the accounts the token can see are never listed", !cf.paths.some((p) => p.startsWith("/accounts?")));
  } finally {
    cf.restore();
  }
  console.log("\nCF_ACCOUNT_ID names the account, so no probe is needed:");
  const cf2 = fakeCloudflare({ [ACCT]: OWNER }, []);
  try {
    const recs = await crawl(secretsState(), "discovery-token", secretEnv({ CF_ACCOUNT_ID: ACCT }));
    ok("CF_ACCOUNT_ID is used as the account", recs[0]?.descriptor?.secretsWiring === "captured" && !cf2.paths.some((p) => p.startsWith("/accounts?")));
  } finally {
    cf2.restore();
  }
  console.log("\nan env-only token with no account named: nothing is listed, the wiring is unknown:");
  resetSourceFaultLedger();
  const cf3 = fakeCloudflare({ [ACCT]: OWNER }, [ACCT]);
  try {
    const recs = await crawl(secretsState(), "discovery-token");
    ok("no account: every value sealed, wiring unknown, no Cloudflare request at all", recs.length === 2 && recs.every((r) => r.descriptor?.secretsWiring === "unknown") && cf3.paths.length === 0);
    ok("no account: recorded as secrets:wiring/no-account", wiringIds(readSourceFaultLedger()).includes("secrets:wiring/no-account"));
  } finally {
    cf3.restore();
  }
}

async function accountScopeCases(): Promise<void> {
  console.log("\naccount scope (ASVS V4): an account outside the Owner's discovery scope is never read:");
  // The downpipe names ACCT, which the token can reach, but the Owner selected only someone-else.
  resetSourceFaultLedger();
  let cf = fakeCloudflare({ [ACCT]: OWNER }, [ACCT]);
  try {
    const recs = await crawl(secretsState(ACCT), "discovery-token", secretEnv({}, { accountsSeen: [{ id: ACCT }, { id: "someone-else" }], selected: ["someone-else"] }));
    ok("out-of-scope accountId: both values sealed, wiring unknown, no scopes or comment", recs.length === 2 && recs.every((r) => r.descriptor?.secretsWiring === "unknown" && r.descriptor.secretsScopes === undefined && r.descriptor.secretsComment === undefined));
    ok("out-of-scope accountId: no request reaches that account", !cf.paths.some((p) => p.startsWith(`/accounts/${ACCT}/`)));
    ok("out-of-scope accountId: recorded as a refusal, secrets:wiring/account-scope", (readSourceFaultLedger().incompleteIds._refused ?? []).includes("secrets:wiring/account-scope"));
  } finally {
    cf.restore();
  }
  // Negative control: the same crawl with ACCT selected captures, so the refusal above is the scope, not the stub.
  cf = fakeCloudflare({ [ACCT]: OWNER }, [ACCT]);
  try {
    const recs = await crawl(secretsState(ACCT), "discovery-token", secretEnv({}, { accountsSeen: [{ id: ACCT }, { id: "someone-else" }], selected: [ACCT] }));
    ok("negative control: with ACCT selected the same crawl captures", recs.every((r) => r.descriptor?.secretsWiring === "captured"));
  } finally {
    cf.restore();
  }
  // No accountId: the probe pool is the SELECTED accounts only, never a seen-but-deselected one.
  cf = fakeCloudflare({ [ACCT]: OWNER }, [ACCT]);
  try {
    const recs = await crawl(secretsState(), "discovery-token", secretEnv({}, { accountsSeen: [{ id: ACCT }, { id: "someone-else" }], selected: ["someone-else"] }));
    ok("no accountId: a seen but deselected account is not probed", recs.every((r) => r.descriptor?.secretsWiring === "unknown") && !cf.paths.some((p) => p.startsWith(`/accounts/${ACCT}/`)));
  } finally {
    cf.restore();
  }
  // The discovery config cannot be read: fail closed.
  resetSourceFaultLedger();
  cf = fakeCloudflare({ [ACCT]: OWNER }, [ACCT]);
  try {
    const recs = await crawl(secretsState(ACCT), "discovery-token", secretEnv({}, "throw"));
    ok("unreadable scope: both values sealed, wiring unknown, no Cloudflare request", recs.length === 2 && recs.every((r) => r.descriptor?.secretsWiring === "unknown") && cf.paths.length === 0);
    ok("unreadable scope: recorded as secrets:wiring/scope-unreadable", wiringIds(readSourceFaultLedger()).includes("secrets:wiring/scope-unreadable"));
  } finally {
    cf.restore();
  }
  // The save path shape-checks a secrets accountId like the API sources do.
  const cfg = (accountId: string) => ({ ...secretsState(accountId).config }) as never;
  let threw = false;
  try {
    validateConfig(cfg("not-an-account!"));
  } catch {
    threw = true;
  }
  ok("validateConfig refuses a malformed secrets accountId", threw);
  threw = false;
  try {
    validateConfig(cfg("0123456789abcdef0123456789abcdef"));
  } catch {
    threw = true;
  }
  ok("validateConfig accepts a hex secrets accountId", !threw);
}

async function provenanceCases(): Promise<void> {
  console.log("\n\"captured\" needs the secret's name in the store and the engine's own binding in the list:");
  // DB_URL is missing from the store list (a mistyped name, or a deleted secret).
  resetSourceFaultLedger();
  let cf = fakeCloudflare({ [ACCT]: { ...OWNER, secrets: [OWNER.secrets![0]!] } }, [ACCT]);
  try {
    const recs = await crawl(secretsState(ACCT), "discovery-token");
    const db = recs.find((r) => r.name === "DB_URL");
    ok("name not in the store: wiring unknown, no scopes, no Workers", db?.descriptor?.secretsWiring === "unknown" && db.descriptor.secretsScopes === undefined && db.descriptor.secretsWorkers === undefined);
    ok("name not in the store: recorded as secrets:wiring/name-miss/<handle>", wiringIds(readSourceFaultLedger()).some((id) => id.startsWith("secrets:wiring/name-miss/h:")));
    ok("name not in the store: the other secret still captures", recs.find((r) => r.name === "API_KEY")?.descriptor?.secretsWiring === "captured");
  } finally {
    cf.restore();
  }
  // The engine's own binding for API_KEY is absent from every script: the store id or name is not what it binds.
  resetSourceFaultLedger();
  const engineOnlyDb = { bindings: [{ type: "secrets_store_secret", name: "SRC_SEC_db_url", store_id: STORE, secret_name: "DB_URL" }] };
  cf = fakeCloudflare({ [ACCT]: { ...OWNER, settings: { ...OWNER.settings, "downpipes-engine": engineOnlyDb } } }, [ACCT]);
  try {
    const recs = await crawl(secretsState(ACCT), "discovery-token");
    const api = recs.find((r) => r.name === "API_KEY");
    ok("engine binding absent: wiring unknown and none of the metadata is recorded", api?.descriptor?.secretsWiring === "unknown" && api.descriptor.secretsWorkers === undefined && api.descriptor.secretsScopes === undefined && api.descriptor.secretsComment === undefined);
    ok("engine binding absent: recorded as secrets:wiring/self-miss/<handle>", wiringIds(readSourceFaultLedger()).some((id) => id.startsWith("secrets:wiring/self-miss/h:")));
  } finally {
    cf.restore();
  }
  // The API documents scopes and bindings as optional. Absent fields are no shape anomaly.
  resetSourceFaultLedger();
  cf = fakeCloudflare({ [ACCT]: { ...OWNER, secrets: OWNER.secrets!.map(({ scopes: _s, ...rest }) => rest), settings: { ...OWNER.settings, web: {} } } }, [ACCT]);
  try {
    const recs = await crawl(secretsState(ACCT), "discovery-token");
    ok("absent scopes and bindings: still captured, no scopes invented", recs.every((r) => r.descriptor?.secretsWiring === "captured" && r.descriptor.secretsScopes === undefined));
    ok("absent scopes and bindings: no shape anomaly", readSourceFaultLedger().shapeAnomalies === 0);
  } finally {
    cf.restore();
  }
}

async function budgetCases(): Promise<void> {
  console.log("\nslice budget: the Workers pass never costs the run (the crawl is not resumable):");
  // 80 scripts at the default pace (3 reads a second) need about 26 s. The slice wall is 4 s, so an unbounded
  // pass would still be reading when the first record arrived, and the slice would fail the run.
  resetSourceFaultLedger();
  const many = Array.from({ length: 80 }, (_, i) => `w${i}`);
  const settings: FakeAccount["settings"] = { ...OWNER.settings };
  for (const w of many) settings[w] = { bindings: [] };
  let cf = fakeCloudflare({ [ACCT]: { ...OWNER, scripts: [...OWNER.scripts!, ...many], settings } }, [ACCT]);
  try {
    const t0 = Date.now();
    const { recs, failed } = await crawlLikeASlice(secretsState(ACCT), secretEnv(), new SliceBudget({ wallMs: 4000 }));
    const ms = Date.now() - t0;
    ok(`wall budget: the run seals both values and never trips the slice's yield (${ms} ms)`, !failed && recs.length === 2 && recs.every((r) => r.value !== undefined));
    ok("wall budget: the crawl ends inside the slice wall", ms < 4000);
    ok("wall budget: wiring unknown, recorded as secrets:wiring/budget", recs.every((r) => r.descriptor?.secretsWiring === "unknown") && wiringIds(readSourceFaultLedger()).includes("secrets:wiring/budget"));
    ok("wall budget: not an API shape anomaly", readSourceFaultLedger().shapeAnomalies === 0);
  } finally {
    cf.restore();
  }
  // Subrequests: a slice of 120 cannot pay for 83 settings reads beside the value reads and finalisation, so
  // no settings read is spent at all.
  resetSourceFaultLedger();
  cf = fakeCloudflare({ [ACCT]: { ...OWNER, scripts: [...OWNER.scripts!, ...many], settings } }, [ACCT]);
  try {
    const budget = new SliceBudget({ subrequests: 120 });
    const { recs, failed } = await crawlLikeASlice(secretsState(ACCT), secretEnv(), budget);
    ok("subrequest budget: the run seals both values and never trips the slice's yield", !failed && recs.length === 2);
    ok("subrequest budget: no settings read is spent on a pass that cannot finish", !cf.paths.some((p) => p.endsWith("/settings")));
    ok("subrequest budget: wiring unknown, recorded as secrets:wiring/budget", recs.every((r) => r.descriptor?.secretsWiring === "unknown") && wiringIds(readSourceFaultLedger()).includes("secrets:wiring/budget"));
    ok("subrequest budget: finalisation still has its reserve", budget.canFinalise());
  } finally {
    cf.restore();
  }
  // The RateLimitDO asks: with the DistributedPacer bound, every paced read also asks the limiter, and the
  // meter never sees the ask. Ten in-scope accounts, the store in the last one: ten probes before the Workers
  // pass. The real spend (metered plus asks) must still leave the value seal and finalisation their share.
  resetSourceFaultLedger();
  const tenAccounts = Array.from({ length: 9 }, (_, i) => `acct-${i}`).concat([ACCT]);
  const fakeAccounts: Record<string, FakeAccount> = { [ACCT]: { ...OWNER, scripts: [...OWNER.scripts!, ...many], settings } };
  cf = fakeCloudflare(fakeAccounts, []);
  try {
    // The limiter refuses each first ask and grants the second: two asks a read, as at the default pace.
    let asks = 0;
    const limiter = { idFromName: () => ({}), get: () => ({ fetch: async () => { asks++; return new Response(JSON.stringify({ granted: asks % 2 === 0, waitMs: 0 }), { status: 200 }); } }) };
    const budget = new SliceBudget({ subrequests: 310, wallMs: 120_000 });
    const env = secretEnv({ RATELIMIT_DO: limiter }, { accountsSeen: tenAccounts.map((id) => ({ id })), selected: [] });
    const { recs, failed } = await crawlLikeASlice(secretsState(), env, budget);
    const real = budget.subrequestsSpent + asks;
    const sealShare = FINALISE_RESERVE + recs.length * (SECRETS_WIRING_RESERVE_PER_SECRET - 1);
    ok(`limiter asks: both values sealed, never a yield (metered ${budget.subrequestsSpent} + asks ${asks} = ${real} of ${310})`, !failed && recs.length === 2);
    ok(`limiter asks: the real spend leaves the seal and finalisation their ${sealShare}`, real + sealShare <= 310);
  } finally {
    cf.restore();
  }
  // Negative control: the same account under the default slice budget and a fast pace captures.
  cf = fakeCloudflare({ [ACCT]: { ...OWNER } }, [ACCT]);
  try {
    const { recs, failed } = await crawlLikeASlice(secretsState(ACCT), secretEnv(), new SliceBudget());
    ok("negative control: a small account under the default budget captures", !failed && recs.every((r) => r.descriptor?.secretsWiring === "captured"));
  } finally {
    cf.restore();
  }
}

async function degradedCases(): Promise<void> {
  console.log("\ndegradation: never a failed run, never a partial Worker list:");
  // 1. No discovery token at all.
  resetSourceFaultLedger();
  let recs = await crawl(secretsState(ACCT), undefined);
  ok("no token: every value is still sealed", recs.length === 2 && recs.every((r) => r.value !== undefined && r.value.byteLength > 0));
  ok("no token: wiring is unknown and no scopes are invented", recs.every((r) => r.descriptor?.secretsWiring === "unknown" && r.descriptor.secretsScopes === undefined && r.descriptor.secretsWorkers === undefined));
  ok("no token: recorded as secrets:wiring/no-token, and not as an API shape anomaly", wiringIds(readSourceFaultLedger()).includes("secrets:wiring/no-token") && readSourceFaultLedger().shapeAnomalies === 0);

  // 2. One script's settings are unreadable: the list would be partial, so it is unknown.
  resetSourceFaultLedger();
  let cf = fakeCloudflare({ [ACCT]: { ...OWNER, settings: { ...OWNER.settings, web: { status: 403 } } } }, [ACCT]);
  try {
    recs = await crawl(secretsState(ACCT), "discovery-token");
    const api = recs.find((r) => r.name === "API_KEY");
    ok("one unreadable script: wiring is unknown, never a short list", api?.descriptor?.secretsWiring === "unknown" && api.descriptor.secretsWorkers === undefined);
    ok("one unreadable script: scopes and comment still come from the Secrets Store", api?.descriptor?.secretsComment === "prod API key" && api.descriptor.secretsScopes !== undefined);
    const l = readSourceFaultLedger();
    ok("one unreadable script: recorded as secrets:wiring/settings/<handle> with reason auth", wiringIds(l).some((id) => id.startsWith("secrets:wiring/settings/h:")) && (l.incompleteReasons._unavailable?.auth ?? 0) >= 1);
    ok("one unreadable script: the script name never enters the ledger", !JSON.stringify(l).includes('"web"') && !JSON.stringify(l).includes("/web"));
  } finally {
    cf.restore();
  }

  // 3. The token cannot read the Secrets Store at all (403), nor the Workers scripts list.
  resetSourceFaultLedger();
  cf = fakeCloudflare({ [ACCT]: { secrets: [], secretsStatus: 403 } }, [ACCT]);
  try {
    recs = await crawl(secretsState(ACCT), "discovery-token");
    ok("under-scoped token: both values sealed, wiring unknown, no scopes", recs.length === 2 && recs.every((r) => r.descriptor?.secretsWiring === "unknown" && r.descriptor.secretsScopes === undefined));
    ok("under-scoped token: recorded as secrets:wiring/store, not as a shape anomaly", wiringIds(readSourceFaultLedger()).includes("secrets:wiring/store") && readSourceFaultLedger().shapeAnomalies === 0);
  } finally {
    cf.restore();
  }

  resetSourceFaultLedger();
}

async function tokenResolutionCase(): Promise<void> {
  console.log("\nthe run path hands the secrets source the discovery token, best-effort:");
  const scheduler = makeSchedulerStub(async (url) => {
    if (url.endsWith("/sources/discovery-config")) return new Response(JSON.stringify({ config: { token: "do-token", accountsSeen: [{ id: "someone-else" }], selected: ["someone-else"] } }), { status: 200 });
    return new Response("{}", { status: 200 });
  });
  const env = makeEnv(scheduler);
  const tok = await cfConfigToken(scheduler, secretsState(ACCT), env);
  // The token is returned even though ACCT is outside this config's scope: a secrets run must not fail on
  // metadata. The reader applies the scope instead (accountScopeCases), so the account is never read.
  ok("cfConfigToken returns the discovery token for a secrets downpipe, without failing the run", tok === "do-token");
  const broken = makeSchedulerStub(async () => {
    throw new Error("DO unreachable");
  });
  let threw = false;
  let none: string | undefined = "unset";
  try {
    none = await cfConfigToken(broken, secretsState(ACCT), makeEnv(broken));
  } catch {
    threw = true;
  }
  ok("a DO fault never fails a secrets run: the token is simply absent", !threw && none === undefined);
}

async function main(): Promise<void> {
  await capturedCase();
  await accountDiscoveryCase();
  await accountScopeCases();
  await provenanceCases();
  await degradedCases();
  await budgetCases();
  await tokenResolutionCase();
  console.log(failures === 0 ? "\nSECRETS WIRING PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
