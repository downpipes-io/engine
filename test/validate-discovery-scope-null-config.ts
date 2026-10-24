// validate-discovery-scope-null-config: with no Owner discovery config (an env-only discovery token), a
// downpipe source may name only the engine's own Cloudflare account. The env token reaches every account it
// was issued for, so a member who holds only downpipe.write could otherwise name any of them and have the
// engine read and seal it. The engine's own account is CF_ACCOUNT_ID, else the account the scheduler has
// verified; when neither is known, no account is in scope. A foreign account then needs an Owner discovery
// config. Covers the predicate, the account resolver and the run path's token resolution (cfConfigToken).
//
// NEGATIVE CONTROLS: the engine's own account is accepted, and a stored discovery config behaves as before.
// It also covers: the engine account recorded from CF_ACCOUNT_ID (so an env-only estate that never attached
// can add a source, and a configuration replay after a storage wipe keeps its sources), ids compared in
// lowercase, a zoneId that must belong to the source's account (at save and at run), and the source
// listing limited to the same scope.
//
// Run: node test/validate-discovery-scope-null-config.ts

import { handleAdmin } from "../src/admin/router.ts";
import { accountInDiscoveryScope } from "../src/sched/config-validate.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import type { DownpipeConfig, DownpipeState } from "../src/sched/types.ts";
import { cfConfigToken } from "../src/seal/runstate-helpers.ts";
import { controlPlaneArtefactKey } from "../src/admin/control-plane.ts";
import { engineScopeAccount, recordEnvEngineAccount } from "../src/sched/engine-scope-account.ts";
import { DISCOVERY_KEY } from "../src/sched/scheduler-do-records.ts";
import { classifyConfigReject } from "../src/sched/sched-fault-admin-ledger.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

const OWN = "a".repeat(32);
const FOREIGN = "f".repeat(32);

function stubScheduler(opts: { config: unknown; verified: unknown }): DurableObjectStub {
  return {
    fetch: async (input: RequestInfo | URL): Promise<Response> => {
      const path = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url).pathname;
      if (path === "/sources/discovery-config") return new Response(JSON.stringify({ config: opts.config }));
      if (path === "/sources/engine-account-verified") return new Response(JSON.stringify(opts.verified));
      return new Response("{}");
    },
  } as unknown as DurableObjectStub;
}

function stateFor(accountId: string, zoneId?: string): DownpipeState {
  return {
    config: { id: "dp", name: "dp", cadenceSeconds: 3600, enabled: true, source: { type: "cf-config", accountId, ...(zoneId !== undefined ? { zoneId } : {}), include: [], exclude: [] } } as DownpipeConfig,
    nextRunAt: 0,
    lastRunId: null,
    inFlight: false,
  };
}

async function tokenOutcome(scheduler: DurableObjectStub, env: Record<string, unknown>, accountId: string, zoneId?: string): Promise<"token" | "refused" | "error"> {
  try {
    return (await cfConfigToken(scheduler, stateFor(accountId, zoneId), env as unknown as Env)) === undefined ? "refused" : "token";
  } catch (e) {
    return /not one of the discovery-selected|outside the discovery scope|not a zone of the source/.test((e as Error).message) ? "refused" : "error";
  }
}

async function main(): Promise<void> {
  console.log("\nthe predicate\n");
  ok("a null config with a known engine account: a foreign account is out of scope", accountInDiscoveryScope(FOREIGN, null, OWN) === false);
  ok("negative control: a null config with a known engine account: the engine's own account is in scope", accountInDiscoveryScope(OWN, null, OWN) === true);
  ok("a null config with an unknown engine account: no account is in scope", accountInDiscoveryScope(OWN, null, null) === false);
  ok("negative control: a stored config is judged on its own lists, whatever the engine account", accountInDiscoveryScope(FOREIGN, { accountsSeen: [{ id: FOREIGN }], selected: [] }, null) === true);

  console.log("\nthe engine account resolver\n");
  let resolver: ((env: Record<string, unknown>, scheduler: DurableObjectStub) => Promise<string | null>) | null = null;
  try {
    resolver = (await import("../src/sched/engine-scope-account.ts")).engineScopeAccount;
  } catch {
    resolver = null;
  }
  ok("the resolver module exists", resolver !== null);
  if (resolver !== null) {
    ok("CF_ACCOUNT_ID names the engine account", (await resolver({ CF_ACCOUNT_ID: OWN }, stubScheduler({ config: null, verified: null }))) === OWN);
    ok("without CF_ACCOUNT_ID the verified engine account is used", (await resolver({}, stubScheduler({ config: null, verified: { accountId: OWN, verifiedAt: 1, via: "attach" } }))) === OWN);
    ok("with neither, the engine account is unknown (null)", (await resolver({}, stubScheduler({ config: null, verified: null }))) === null);
  }

  console.log("\nthe run path (cfConfigToken)\n");
  const withToken = { config: null as unknown };
  const cfgNull = stubScheduler({ config: withToken.config, verified: null });
  ok("env-only token, CF_ACCOUNT_ID set: a foreign account is refused", (await tokenOutcome(cfgNull, { DISCOVERY_API_TOKEN: "env-token-0123456789", CF_ACCOUNT_ID: OWN }, FOREIGN)) === "refused");
  ok("env-only token, no engine account known: every account is refused", (await tokenOutcome(cfgNull, { DISCOVERY_API_TOKEN: "env-token-0123456789" }, OWN)) === "refused");
  ok("negative control: env-only token, the engine's own account is not refused", (await tokenOutcome(cfgNull, { DISCOVERY_API_TOKEN: "env-token-0123456789", CF_ACCOUNT_ID: OWN }, OWN)) === "token");

  const OWN_UPPER = OWN.toUpperCase();
  console.log("\nids compare in lowercase\n");
  ok("an uppercase engine account matches the lowercase source account", accountInDiscoveryScope(OWN, null, OWN_UPPER) === true);
  ok("an uppercase source account matches the lowercase engine account", accountInDiscoveryScope(OWN_UPPER, null, OWN) === true);
  ok("a stored config matches ids in either case", accountInDiscoveryScope(OWN_UPPER, { accountsSeen: [{ id: OWN }], selected: [OWN] }, null) === true);

  // ---- the engine account recorded from CF_ACCOUNT_ID, and the configuration replay after a wipe ----
  console.log("\nCF_ACCOUNT_ID reaches the scheduler (env-only estate, never attached)\n");
  const owner = { method: "access" as const, email: null, subject: null, role: "owner" as const, groups: [] as string[] };
  const dpConfig = (accountId: string, zoneId?: string): never =>
    ({ id: "dp-scope", name: "dp-scope", cadenceSeconds: 3600, enabled: true, source: { type: "cf-config", accountId, ...(zoneId !== undefined ? { zoneId } : {}), include: [], exclude: [] } }) as never;
  const makeDo = (): { dobj: SchedulerDO; stub: DurableObjectStub } => {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url, init)) } as unknown as DurableObjectStub;
    return { dobj, stub };
  };
  // applyResumeDownpipes belongs to the control-plane mixin and is not on the SchedulerDO surface type.
  const replay = (dobj: SchedulerDO, exp: { downpipes: unknown[] }): Promise<number> =>
    (dobj as unknown as { applyResumeDownpipes(e: unknown, tolerant: boolean): Promise<number> }).applyResumeDownpipes(exp, true);
  let recordEnv: ((env: Record<string, unknown>, scheduler: DurableObjectStub) => Promise<void>) | null = null;
  try {
    recordEnv = (await import("../src/sched/engine-scope-account.ts")).recordEnvEngineAccount;
  } catch {
    recordEnv = null;
  }
  ok("the env-record helper exists", recordEnv !== null && typeof recordEnv === "function");
  if (recordEnv !== null) {
    {
      const w = makeDo();
      let before = "added";
      try {
        await w.dobj.addDownpipe(dpConfig(OWN), owner);
      } catch {
        before = "refused";
      }
      ok("control: before the account is recorded, an env-only scheduler refuses the source", before === "refused");
      await recordEnv({ CF_ACCOUNT_ID: OWN_UPPER }, w.stub);
      let own = "refused";
      try {
        await w.dobj.addDownpipe(dpConfig(OWN), owner);
        own = "added";
      } catch {
        own = "refused";
      }
      ok("after CF_ACCOUNT_ID is recorded (uppercase in env), the engine's own account is added", own === "added");
      let foreign = "added";
      try {
        await w.dobj.addDownpipe({ ...(dpConfig(FOREIGN) as object), id: "dp-foreign" } as never, owner);
      } catch {
        foreign = "refused";
      }
      ok("after CF_ACCOUNT_ID is recorded, a foreign account is still refused", foreign === "refused");
    }
    {
      // A storage wipe empties the scheduler; the tick records CF_ACCOUNT_ID again, then the replay runs.
      const wiped = makeDo();
      const skippedWithoutRecord = await replay(wiped.dobj, { downpipes: [dpConfig(OWN)] });
      ok("control: a replay into a wiped scheduler before the account is recorded drops the source", skippedWithoutRecord === 0);
      const wiped2 = makeDo();
      await recordEnv({ CF_ACCOUNT_ID: OWN }, wiped2.stub);
      const kept = await replay(wiped2.dobj, { downpipes: [dpConfig(OWN)] });
      ok("a replay into a wiped scheduler keeps the engine-account source once the account is recorded", kept === 1);
    }
    {
      const w = makeDo();
      const calls: string[] = [];
      const spy = {
        fetch: (input: string, init?: RequestInit): Promise<Response> => {
          calls.push(`${init?.method ?? "GET"} ${new URL(input).pathname}`);
          return w.stub.fetch(input, init);
        },
      } as unknown as DurableObjectStub;
      await recordEnv({}, spy);
      ok("negative control: with CF_ACCOUNT_ID unset nothing is sent to the scheduler", calls.length === 0);
    }
  }
  {
    const src = (await import("node:fs")).readFileSync(new URL("../src/cron/drive.ts", import.meta.url), "utf8");
    ok("structural: the cron tick records CF_ACCOUNT_ID before the scheduled replay runs", src.indexOf("recordEnvEngineAccount(env, scheduler)") !== -1 && src.indexOf("recordEnvEngineAccount(env, scheduler)") < src.indexOf("runScheduledTick(env, scheduler)"));
  }

  // ---- round 3: resume order, the stored account following CF_ACCOUNT_ID, and the env-only refusal text ----
  console.log("\nresume applies the discovery config before the downpipes\n");
  {
    // An estate whose Owner selected a foreign account and has an API source on it.
    const aStorage = new MockStorage();
    const aDo = new SchedulerDO({ storage: aStorage } as unknown as DurableObjectState);
    await aStorage.put(DISCOVERY_KEY, { token: "", setAt: 1, setBy: null, accountsSeen: [{ id: FOREIGN, name: "foreign" }], selected: [FOREIGN], engineAccountId: null });
    await aDo.addDownpipe({ ...(dpConfig(FOREIGN) as object), id: "dp-foreign-selected" } as never, owner);
    const exp = await aDo.buildControlPlaneExport();
    const tokenCaller = { method: "token" as const, email: null, subject: null, groups: [] as string[] };
    const hasForeign = async (d: SchedulerDO): Promise<boolean> => (await d.listDownpipes()).some((s) => s.config.id === "dp-foreign-selected");
    const staged = (): never => ({ export: exp, signature: "", sourceKey: controlPlaneArtefactKey(exp.configVersion, exp.exportedAt), version: exp.configVersion, stagedAt: new Date().toISOString(), resumeApplied: false }) as never;

    {
      const w = makeDo();
      await w.dobj.setControlPlaneRecoveryRequired("config empty but bucket has runs");
      await w.dobj.stageControlPlaneRecovery(staged());
      const r = await w.dobj.applyControlPlaneResumeSlice();
      ok("the staged auto-heal resume keeps an API source on the account the Owner selected", r.ok === true && (r as { downpipes: number }).downpipes === 1 && (await hasForeign(w.dobj)));
    }
    {
      const w = makeDo();
      await w.dobj.setControlPlaneRecoveryRequired("config empty but bucket has runs");
      await w.dobj.stageControlPlaneRecovery(staged());
      await w.dobj.applyControlPlaneResumeSlice();
      ok("the staged auto-heal resume counts no skipped downpipe", (await w.dobj.listDownpipes()).length === 1);
    }
    {
      const w = makeDo();
      await w.dobj.setControlPlaneRecoveryRequired("config empty but bucket has runs");
      await w.dobj.stageControlPlaneRecovery(staged());
      const confirmed = await w.dobj.applyControlPlaneAuthoritySlice(tokenCaller).then(() => true, () => false);
      ok("the break-glass confirm keeps an API source on the account the Owner selected", confirmed && (await hasForeign(w.dobj)));
    }
    {
      const w = makeDo();
      const r = await w.dobj.reconcileControlPlane(exp, tokenCaller).catch(() => null);
      ok("the manual reconcile keeps an API source on the account the Owner selected", r !== null && r.downpipes === 1 && (await hasForeign(w.dobj)));
    }
    {
      const w = makeDo();
      const r = await w.dobj.importControlPlaneDefinition(exp, false, owner).catch(() => null);
      ok("the estate import keeps an API source on the account the Owner selected", r !== null && r.downpipes === 1 && (await hasForeign(w.dobj)));
    }
    {
      const w = makeDo();
      const kept = await replay(w.dobj, { downpipes: [(await aDo.listDownpipes())[0]!.config] });
      ok("control: a downpipe replayed alone, with no discovery config applied, is dropped", kept === 0);
    }
    {
      const src = (await import("node:fs")).readFileSync(new URL("../src/sched/scheduler-do-control-plane.ts", import.meta.url), "utf8");
      const calls = [...src.matchAll(/this\.applyResume(Discovery|Downpipes)\(/g)].map((m) => m[1]!);
      let ordered = calls.length === 8;
      for (let i = 0; i + 1 < calls.length && ordered; i += 2) ordered = calls[i] === "Discovery" && calls[i + 1] === "Downpipes";
      ok("structural: all four apply sites call applyResumeDiscovery directly before applyResumeDownpipes", ordered);
    }
  }

  console.log("\nthe stored engine account follows CF_ACCOUNT_ID\n");
  {
    const SECOND = "b".repeat(32);
    const w = makeDo();
    const mustAdd = async (accountId: string, id: string): Promise<boolean> => {
      try {
        await w.dobj.addDownpipe({ ...(dpConfig(accountId) as object), id } as never, owner);
        return true;
      } catch {
        return false;
      }
    };
    await recordEnvEngineAccount({ CF_ACCOUNT_ID: OWN }, w.stub);
    ok("first value recorded: its account is added", await mustAdd(OWN, "dp-a"));
    const auditBefore = (await w.dobj.listAuditEntries()).filter((e) => e.action === "engine-account-verified").length;
    await recordEnvEngineAccount({ CF_ACCOUNT_ID: OWN.toUpperCase() }, w.stub);
    ok("the same value in another letter case changes nothing and writes no audit row", (await w.dobj.listAuditEntries()).filter((e) => e.action === "engine-account-verified").length === auditBefore);
    await recordEnvEngineAccount({ CF_ACCOUNT_ID: SECOND }, w.stub);
    ok("CF_ACCOUNT_ID changed: the scheduler now names the new account", (await w.dobj.getVerifiedEngineAccount())?.accountId === SECOND);
    ok("CF_ACCOUNT_ID changed: a source on the new account is added", await mustAdd(SECOND, "dp-b"));
    ok("CF_ACCOUNT_ID changed: a source on the previous account is refused", !(await mustAdd(OWN, "dp-c")));
    ok("the scheduler and the Worker resolver name the same account", (await engineScopeAccount({ CF_ACCOUNT_ID: SECOND }, w.stub)) === (await w.dobj.getVerifiedEngineAccount())?.accountId);
    ok("a change writes one more audit row", (await w.dobj.listAuditEntries()).filter((e) => e.action === "engine-account-verified").length === auditBefore + 1);
    const attach = await w.dobj.recordVerifiedEngineAccount({ accountId: OWN, via: "attach" });
    ok("negative control: an attach record never overwrites the stored account", attach.accountId === SECOND && (await w.dobj.getVerifiedEngineAccount())?.accountId === SECOND);
    const applied = await w.dobj.recordVerifiedEngineAccount({ accountId: OWN, via: "update-apply" });
    ok("negative control: an update-apply record never overwrites the stored account", applied.accountId === SECOND);
  }

  console.log("\nthe env-only refusal names the real remedy\n");
  {
    const w = makeDo();
    await recordEnvEngineAccount({ CF_ACCOUNT_ID: OWN }, w.stub);
    let envOnlyMsg = "";
    try {
      await w.dobj.addDownpipe({ ...(dpConfig(FOREIGN) as object), id: "dp-env-foreign" } as never, owner);
    } catch (e) {
      envOnlyMsg = (e as Error).message;
    }
    ok("env-only save: the refusal does not tell the caller to select the account under Sources first", envOnlyMsg !== "" && !/select it under Sources first/.test(envOnlyMsg));
    ok("env-only save: the refusal names CF_ACCOUNT_ID and the Owner discovery token", /CF_ACCOUNT_ID/.test(envOnlyMsg) && /Owner discovery token under Sources/.test(envOnlyMsg));
    const c = new MockStorage();
    const cDo = new SchedulerDO({ storage: c } as unknown as DurableObjectState);
    await c.put(DISCOVERY_KEY, { token: "", setAt: 1, setBy: null, accountsSeen: [{ id: OWN, name: "own" }], selected: [OWN], engineAccountId: null });
    let cfgMsg = "";
    try {
      await cDo.addDownpipe({ ...(dpConfig(FOREIGN) as object), id: "dp-cfg-foreign" } as never, owner);
    } catch (e) {
      cfgMsg = (e as Error).message;
    }
    ok("negative control: with a stored config the refusal still says to select the account under Sources", /select it under Sources first/.test(cfgMsg));
    ok("the refusal still classifies as a discovery-scope refusal", classifyConfigReject(new Error(envOnlyMsg)) === "discovery-scope");
    let runMsg = "";
    try {
      await cfConfigToken(stubScheduler({ config: null, verified: null }), stateFor(FOREIGN), { DISCOVERY_API_TOKEN: "env-token-0123456789", CF_ACCOUNT_ID: OWN } as unknown as Env);
    } catch (e) {
      runMsg = (e as Error).message;
    }
    ok("run path: the env-only refusal names CF_ACCOUNT_ID and does not send the caller to re-select under Sources", /CF_ACCOUNT_ID/.test(runMsg) && !/re-select it under Sources/.test(runMsg));
  }

  // ---- through the admin router: save, zone, listing ----
  console.log("\nthe admin router\n");
  const ZONE_OWN = "1".repeat(32);
  const ZONE_FOREIGN = "2".repeat(32);
  const ZONE_DENIED = "3".repeat(32);
  const ZONE_THROWS = "4".repeat(32);
  const realFetch = globalThis.fetch;
  const zoneCalls: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const json = (v: unknown, status = 200): Response => new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
    const zone = /\/zones\/([0-9a-f]+)$/.exec(url);
    if (zone) {
      zoneCalls.push(zone[1]!);
      if (zone[1] === ZONE_THROWS) throw new TypeError("fetch failed");
      if (zone[1] === ZONE_OWN) return json({ success: true, result: { id: ZONE_OWN, account: { id: OWN } } });
      if (zone[1] === ZONE_FOREIGN) return json({ success: true, result: { id: ZONE_FOREIGN, account: { id: FOREIGN } } });
      return json({ success: false, errors: [] }, 403);
    }
    if (/\/accounts\?/.test(url)) return json({ success: true, result: [{ id: OWN, name: "own" }, { id: FOREIGN, name: "foreign" }] });
    return json({ success: true, result: [] });
  }) as typeof fetch;
  try {
    const BEARER = "scope-null-config-bearer-0123456789";
    const stack = (extra: Record<string, unknown>): Env => {
      const { stub } = makeDo();
      const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
      return { SCHEDULER: namespace, ADMIN_TOKEN: BEARER, ...extra } as unknown as Env;
    };
    const call = async (env: Env, method: "GET" | "POST", path: string, body?: unknown): Promise<{ status: number; json: Record<string, unknown> }> => {
      const resp = await handleAdmin(
        new Request(`https://engine.scope.example${path}`, { method, headers: { authorization: `Bearer ${BEARER}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }),
        env,
      );
      return { status: resp.status, json: (await resp.json().catch(() => ({}))) as Record<string, unknown> };
    };
    const createBody = (accountId: string, zoneId?: string): Record<string, unknown> => dpConfig(accountId, zoneId) as unknown as Record<string, unknown>;
    const envOnly = { DISCOVERY_API_TOKEN: "env-token-0123456789", CF_ACCOUNT_ID: OWN };

    const own = await call(stack(envOnly), "POST", "/admin/downpipes", createBody(OWN));
    ok(`router: an env-only estate with CF_ACCOUNT_ID, never attached, adds a source naming its own account (status ${own.status})`, own.status === 200);
    const foreign = await call(stack(envOnly), "POST", "/admin/downpipes", createBody(FOREIGN));
    ok(`router: the same estate refuses a foreign account (status ${foreign.status})`, foreign.status === 400);

    const zOwn = await call(stack(envOnly), "POST", "/admin/downpipes", createBody(OWN, ZONE_OWN));
    ok(`router: negative control, a zone of the source's account is saved (status ${zOwn.status})`, zOwn.status === 200);
    const zForeign = await call(stack(envOnly), "POST", "/admin/downpipes", createBody(OWN, ZONE_FOREIGN));
    ok(`router: a zone of another account is refused at save (status ${zForeign.status})`, zForeign.status === 400);
    const zDenied = await call(stack(envOnly), "POST", "/admin/downpipes", createBody(OWN, ZONE_DENIED));
    ok(`router: a zone the token cannot read is refused at save (status ${zDenied.status})`, zDenied.status === 400);
    {
      // A network fault in the zone lookup rejects the request before the save is forwarded. Whatever the
      // Worker's outer handler then answers, the source must not be stored.
      const held = makeDo();
      const heldEnv = { SCHEDULER: { idFromName: () => ({}) as unknown as DurableObjectId, get: () => held.stub } as unknown as DurableObjectNamespace, ADMIN_TOKEN: BEARER, ...envOnly } as unknown as Env;
      let outcome: number | "threw" = "threw";
      try {
        outcome = (await call(heldEnv, "POST", "/admin/downpipes", createBody(OWN, ZONE_THROWS))).status;
      } catch {
        outcome = "threw";
      }
      ok(`router: a zone lookup that throws is not answered as a save (${outcome})`, outcome !== 200);
      ok("router: a zone lookup that throws stores no source", (await held.dobj.listDownpipes()).length === 0);
    }
    const bulk = await call(stack(envOnly), "POST", "/admin/downpipes/bulk", { downpipes: [createBody(OWN, ZONE_FOREIGN)] });
    ok(`router: a bulk save naming a zone of another account is refused (status ${bulk.status})`, bulk.status === 400);

    const runEnv = { ...envOnly } as unknown as Record<string, unknown>;
    ok("run path: a zone of another account is refused", (await tokenOutcome(stubScheduler({ config: null, verified: null }), runEnv, OWN, ZONE_FOREIGN)) === "refused");
    ok("run path: negative control, a zone of the source's account passes", (await tokenOutcome(stubScheduler({ config: null, verified: null }), runEnv, OWN, ZONE_OWN)) === "token");
    ok("run path: a zone lookup that throws ends in an error, never a token", (await tokenOutcome(stubScheduler({ config: null, verified: null }), runEnv, OWN, ZONE_THROWS)) === "error");
    const lookupsBefore = zoneCalls.length;
    await tokenOutcome(stubScheduler({ config: null, verified: null }), runEnv, OWN);
    ok("run path: a source with no zone makes no zone lookup", zoneCalls.length === lookupsBefore);
    ok("run path: negative control, the zone cases above did make lookups", lookupsBefore > 0);

    const listed = async (extra: Record<string, unknown>): Promise<string[]> => {
      const r = await call(stack(extra), "GET", "/admin/sources/discover");
      return ((r.json.accounts as Array<{ accountId: string }> | undefined) ?? []).map((a) => a.accountId);
    };
    ok("listing: with CF_ACCOUNT_ID and no config, only the engine's own account is listed", JSON.stringify(await listed(envOnly)) === JSON.stringify([OWN]));
    ok("listing: with several reachable accounts and no known engine account, none is listed", (await listed({ DISCOVERY_API_TOKEN: "env-token-0123456789" })).length === 0);
  } finally {
    globalThis.fetch = realFetch;
  }


  console.log(failures === 0 ? "\nDISCOVERY SCOPE NULL CONFIG PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
