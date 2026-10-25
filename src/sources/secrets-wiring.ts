// Secrets Store wiring reader (SPEC 12.3). The secrets source reads each VALUE through the engine's own
// binding. That binding says nothing about how the secret is set up in the account: which products may
// use it (its scopes), the operator's comment on it, and which Workers bind it. Without those three, an
// archive cannot say where a secret was, and a rebuild after an incident has to guess the wiring.
//
// This module reads that metadata once per crawl with the engine's read-only discovery token:
//   - scopes and comment: from the Secrets Store secrets list of the secret's own store
//     (GET /accounts/{a}/secrets_store/stores/{store}/secrets), matched by name. The list returns the
//     metadata of every secret in the store; only the entries whose names match a configured secret are kept.
//   - the Workers that bind it: from each script's settings (GET /accounts/{a}/workers/scripts/{s}/settings),
//     every binding of type secrets_store_secret whose store_id and secret_name match. The settings of a
//     script hold all its bindings, plain-text values included, in isolate memory for the read; only the
//     matched secrets_store_secret references are kept.
//
// It never reads a secret value. The Secrets Store list returns metadata only, and a Worker's settings return
// a secrets_store_secret binding as a reference (store_id + secret_name), never the value.
//
// ACCOUNT SCOPE (ASVS V4, the same guard as the API sources). The token reaches every account it was granted,
// and the downpipe's accountId and storeId are operator-writable. So every account this reader touches must
// pass accountInDiscoveryScope against the Owner's discovery config, read fresh at crawl time. Without a
// configured account, the candidates come from that config (selected, else seen), never from a raw
// /accounts listing. An account outside the scope is refused and the wiring is "unknown".
//
// BUDGET. The secrets crawl is not resumable: a slice that yields after its first record fails the whole run
// (seal/slice.ts crawlNonResumable). The Workers pass is one paced GET per script, so it is bounded by the
// slice budget the crawl is given. Before each read it checks that the subrequests the value reads, their
// seal writes and finalisation need are still free, and that at least SECRETS_WIRING_WALL_KEEP of the wall
// time left at its start remains. On a shortfall it stops and records the wiring as "unknown".
//
// FAIL-SOFT, NEVER A GUESS. This metadata is additive. A token that is absent, under-scoped or rejected
// must never fail the run, because the value capture (the part that matters in a disaster) does not need
// it. So every failure degrades: the secret keeps its value and store, and its wiring is recorded as
// "unknown". A partial Workers read is also "unknown", never a short list: a list that silently omits a
// Worker would tell the operator that nothing else binds the secret. "captured" also needs two proofs about
// the secret itself: its name is in the store list, and the complete list holds the engine's own binding.
//
// EVIDENCE. An expected state (no token, a refused read, the budget, a name the store does not hold) is an
// incompleteness fact, recorded with recordIncompleteFault under a closed reason and a "secrets:wiring/..."
// id. recordShapeAnomaly is kept for a real parse drop: a response the reader did not recognise.

import type { Meter } from "../meter.ts";
import { accountInDiscoveryScope, type DiscoveryScopeConfig } from "../sched/config-validate.ts";
import { FINALISE_RESERVE, SliceBudget } from "../seal/budget.ts";
import type { CfApi, CfPage } from "./cf-config-core.ts";
import { paginate, paginateAdaptive } from "./cf-config-core.ts";
import { classifySourceFaultReason, faultItemId, recordIncompleteFault, recordShapeAnomaly, type SourceFaultReason } from "./source-fault-ledger.ts";
import type { SecretWorkerBinding } from "./types.ts";

// SECRETS_WIRING_MAX_ACCOUNTS bounds how many in-scope accounts the reader probes to find the account that
// holds a store, when neither the downpipe config nor CF_ACCOUNT_ID names it. A store id is unique, so only
// the owning account returns it. This is a match, not a guess.
export const SECRETS_WIRING_MAX_ACCOUNTS = 10;

// SECRETS_STORE_PER_PAGE is the Secrets Store list's documented per_page ceiling (100). Asking for more makes
// Cloudflare refuse the page, so the reader asks for exactly this.
export const SECRETS_STORE_PER_PAGE = 100;

// SECRETS_WIRING_SUBREQUESTS_PER_READ is what one paced API read can cost against the platform cap: the GET
// itself, plus up to two RateLimitDO asks when the DistributedPacer is bound (at the default 3 reads a
// second it asks about twice per read). The meter sees only the GET. So the budget check charges all three
// for each read still to come, and counts the asks the reads already made (Limit.unseen).
export const SECRETS_WIRING_SUBREQUESTS_PER_READ = 3;

// SECRETS_WIRING_RESERVE_PER_SECRET is what each secret still needs after the wiring pass: the value read,
// the segment exists-check and put the seal makes for its record, and one retry of the put.
export const SECRETS_WIRING_RESERVE_PER_SECRET = 4;

// SECRETS_WIRING_WALL_KEEP is the share of the wall time left at the start of the wiring pass that the pass
// must leave for the value reads and the seal. The pass stops once less than this share remains.
export const SECRETS_WIRING_WALL_KEEP = 0.5;

// SecretsWiringApi is the read surface the reader needs: a JSON GET (settings) and a paged list GET.
// makeWorkersCfApi satisfies it; the validator drives it with an in-memory stub.
export interface SecretsWiringApi {
  get(path: string): Promise<unknown>;
  getPage(path: string): Promise<CfPage>;
}

// SecretsWiringContext is what buildAdapter hands the secrets source when a discovery token exists:
//   - api: the read-only API client;
//   - accountIds: the configured accounts, in order of trust (the downpipe's own accountId, then
//     CF_ACCOUNT_ID). Empty means "probe the in-scope accounts of the discovery config";
//   - scope: reads the Owner's discovery config (null for an env-only token). It throws when the config
//     cannot be read, and the reader then refuses to touch any account.
export interface SecretsWiringContext {
  api: SecretsWiringApi;
  accountIds: string[];
  scope: () => Promise<DiscoveryScopeConfig | null>;
  // engineAccount names the engine's own account for an env-only token (no discovery config). Absent or
  // null means no account is in scope without a config. It throws when the account cannot be read, and the
  // reader then refuses to touch any account.
  engineAccount?: () => Promise<string | null>;
}

// WiringBudget is the part of the slice budget (seal/budget.ts SliceBudget) the reader checks. The crawl
// hands the slice budget itself, or a fresh default budget on the buffered path, which has none.
export interface WiringBudget extends Meter {
  remaining(): number;
  wallRemainingMs(): number;
}

// isWiringBudget reports whether a meter is a budget the reader can check (a SliceBudget is).
export function isWiringBudget(m: Meter | undefined): m is WiringBudget {
  const b = m as Partial<WiringBudget> | undefined;
  return typeof b?.remaining === "function" && typeof b.wallRemainingMs === "function";
}

// wiringBudget returns the budget the wiring read checks. A sliced run hands the crawl its SliceBudget,
// which is used as is. The buffered path hands no meter, and a test may hand a plain meter: the read then
// runs under a fresh default budget that also forwards each spend to that meter.
export function wiringBudget(meter?: Meter): WiringBudget {
  if (isWiringBudget(meter)) return meter;
  const local = new SliceBudget();
  return {
    spend: (n, op) => {
      local.spend(n, op);
      meter?.spend(n, op);
    },
    remaining: () => local.remaining(),
    wallRemainingMs: () => local.wallRemainingMs(),
  };
}

// SecretWiring is the metadata one secret's record carries. `wiring` is "captured" only when the reader
// read EVERY script's settings in the store's account, so `workers` is the complete list. It always holds
// the engine's own binding, because "captured" requires it.
export interface SecretWiring {
  scopes?: string[];
  comment?: string;
  workers?: SecretWorkerBinding[];
  wiring: "captured" | "unknown";
}

// SecretRef is one configured secret: its name in the store, its store id, and the binding variable the
// engine reads it through (the engine's own binding must appear in a captured Workers list).
export interface SecretRef {
  name: string;
  store?: string;
  bindingVar?: string;
}

// wiringKey is the map key for one secret: its store and its name (a name is unique inside a store).
export function wiringKey(store: string | undefined, name: string): string {
  return `${store ?? ""}\u0000${name}`;
}

const UNKNOWN: SecretWiring = { wiring: "unknown" };

// wiringUnknown records why a secret's wiring (or all of it) is unknown. The id is a closed product token;
// a customer name (a script, a secret) rides only as a one-way handle (faultItemId).
async function wiringUnknown(kind: "_unavailable" | "_refused" | "_truncated", reason: SourceFaultReason, scope: string, item?: string): Promise<void> {
  recordIncompleteFault(kind, reason, { id: await faultItemId(`secrets:wiring/${scope}`, item) });
}

function readOnly(api: SecretsWiringApi): CfApi {
  return { get: (p) => api.get(p), getPage: (p) => api.getPage(p), send: () => Promise.reject(new Error("the secrets wiring reader is read-only")) };
}

// Limit checks the budget before each read. It is built once per crawl from the budget and the reserve the
// value reads and finalisation need. `unseen` counts the pacer asks that reads already made and the meter
// did not record, so the check never takes the metered remainder at its word.
class Limit {
  private readonly budget: WiringBudget;
  private readonly reserve: number;
  private readonly wallFloorMs: number;
  private unseen = 0;
  constructor(budget: WiringBudget, reserve: number) {
    this.budget = budget;
    this.reserve = reserve;
    this.wallFloorMs = budget.wallRemainingMs() * SECRETS_WIRING_WALL_KEEP;
  }
  allows(reads: number): boolean {
    const free = this.budget.remaining() - this.unseen - reads * SECRETS_WIRING_SUBREQUESTS_PER_READ;
    return free >= this.reserve && this.budget.wallRemainingMs() > this.wallFloorMs;
  }
  // charge records one paced read about to be made: the meter sees its GET, never its pacer asks.
  charge(): void {
    this.unseen += SECRETS_WIRING_SUBREQUESTS_PER_READ - 1;
  }
}

interface StoreMeta {
  scopes?: string[];
  comment?: string;
}

// readStoreSecrets lists one store's secrets in one account, keyed by name. It throws on any failure
// (a 404 from the wrong account included), so the caller can try the next candidate account.
async function readStoreSecrets(api: SecretsWiringApi, accountId: string, storeId: string, meter: Meter): Promise<Map<string, StoreMeta>> {
  const path = `/accounts/${encodeURIComponent(accountId)}/secrets_store/stores/${encodeURIComponent(storeId)}/secrets`;
  const items = await paginateAdaptive(readOnly(api), path, meter, SECRETS_STORE_PER_PAGE);
  const out = new Map<string, StoreMeta>();
  for (const it of items) {
    const o = it as { name?: unknown; scopes?: unknown; comment?: unknown } | null;
    if (typeof o?.name !== "string") {
      recordShapeAnomaly("secrets:metadata-item");
      continue;
    }
    const meta: StoreMeta = {};
    // scopes is optional in the API's list response, so an absent field is no anomaly. A present field
    // that is not a list of strings is a shape the reader does not recognise.
    if (Array.isArray(o.scopes) && o.scopes.every((s) => typeof s === "string")) meta.scopes = [...(o.scopes as string[])].sort();
    else if (o.scopes !== undefined && o.scopes !== null) recordShapeAnomaly("secrets:metadata-scopes");
    if (typeof o.comment === "string" && o.comment !== "") meta.comment = o.comment;
    out.set(o.name, meta);
  }
  return out;
}

// candidateAccounts returns the in-scope accounts to probe for a store, or [] when there is none. The
// configured ids come first; a configured id outside the scope is refused, never replaced by another
// account. With no configured id, the candidates are the discovery config's selected (else seen) accounts.
async function candidateAccounts(ctx: SecretsWiringContext, meter: Meter): Promise<string[]> {
  let cfg: DiscoveryScopeConfig | null;
  let engineAccount: string | null = null;
  try { // nosemgrep: incident-catch-returns-empty -- wiringUnknown records the unknown state before the empty return
    meter.spend(1); // the discovery-config read is a DO subrequest
    cfg = await ctx.scope();
    if (cfg === null && ctx.engineAccount !== undefined) engineAccount = await ctx.engineAccount();
    if (cfg !== null && (!Array.isArray(cfg.accountsSeen) || !Array.isArray(cfg.selected))) throw new Error("discovery config shape");
  } catch { // site-fault-waiver: src/sources/secrets-wiring.ts:candidateAccounts:catch:1 -- wiringUnknown records the unknown state before the empty return
    // Without the scope, no account can be proven in scope. Fail closed.
    await wiringUnknown("_unavailable", "other", "scope-unreadable");
    return [];
  }
  const configured = [...new Set(ctx.accountIds.filter((a) => a !== ""))];
  if (configured.length > 0) {
    const allowed = configured.filter((a) => accountInDiscoveryScope(a, cfg, engineAccount));
    if (allowed.length < configured.length) await wiringUnknown("_refused", "auth", "account-scope");
    return allowed;
  }
  if (cfg === null) {
    // An env-only token has no discovery config to list accounts from, and the reader never lists the
    // accounts the token can see. It needs CF_ACCOUNT_ID or the downpipe's accountId.
    await wiringUnknown("_unavailable", "other", "no-account");
    return [];
  }
  const pool = cfg.selected.length > 0 ? cfg.selected : cfg.accountsSeen.map((a) => a.id);
  return [...new Set(pool.filter((a) => typeof a === "string" && a !== "" && accountInDiscoveryScope(a, cfg, null)))].slice(0, SECRETS_WIRING_MAX_ACCOUNTS);
}

// readWorkerBindings reads every script's settings in one account and returns, per (store, name), the
// Workers that bind that secret. It returns null when the list is not complete: the scripts list failed,
// the budget cannot cover every settings read, or one script's settings could not be read.
async function readWorkerBindings(api: SecretsWiringApi, accountId: string, meter: Meter, limit: Limit): Promise<Map<string, SecretWorkerBinding[]> | null> {
  const acct = encodeURIComponent(accountId);
  if (!limit.allows(1)) {
    await wiringUnknown("_truncated", "page-cap", "budget");
    return null;
  }
  let scripts: string[];
  try { // nosemgrep: incident-catch-returns-empty -- wiringUnknown records the unknown state before the empty return
    limit.charge();
    const list = await paginate(readOnly(api), `/accounts/${acct}/workers/scripts`, meter);
    scripts = [];
    for (const s of list) {
      const id = (s as { id?: unknown } | null)?.id;
      if (typeof id === "string" && id !== "") scripts.push(id);
      else {
        // A script the reader cannot name is a script whose settings it cannot read: the list would be short.
        recordShapeAnomaly("secrets:wiring-script-item");
        return null;
      }
    }
  } catch (e) { // site-fault-waiver: src/sources/secrets-wiring.ts:readWorkerBindings:catch:1 -- wiringUnknown records the unknown state before the empty return
    await wiringUnknown("_unavailable", classifySourceFaultReason(e), "scripts");
    return null;
  }
  // Refuse up front when the whole pass cannot fit, so a large account spends nothing on a list it cannot
  // finish. The per-read check below still guards the wall clock.
  if (!limit.allows(scripts.length)) {
    await wiringUnknown("_truncated", "page-cap", "budget");
    return null;
  }
  const out = new Map<string, SecretWorkerBinding[]>();
  for (const script of scripts) {
    if (!limit.allows(1)) {
      await wiringUnknown("_truncated", "page-cap", "budget");
      return null;
    }
    let raw: unknown;
    try { // nosemgrep: incident-catch-returns-empty -- wiringUnknown records the unknown state before the empty return
      meter.spend(1, "cfApiRead");
      limit.charge();
      raw = await api.get(`/accounts/${acct}/workers/scripts/${encodeURIComponent(script)}/settings`);
    } catch (e) { // site-fault-waiver: src/sources/secrets-wiring.ts:readWorkerBindings:catch:2 -- wiringUnknown records the unknown state before the empty return
      await wiringUnknown("_unavailable", classifySourceFaultReason(e), "settings", script);
      return null;
    }
    // bindings is optional in the API's settings response: a script with no bindings may omit it. A present
    // value that is not a list is a shape the reader does not recognise, so the list would not be complete.
    const bindings = (raw as { bindings?: unknown } | null)?.bindings ?? [];
    if (!Array.isArray(bindings)) {
      recordShapeAnomaly("secrets:wiring-settings-shape");
      return null;
    }
    for (const b of bindings) {
      const o = b as { type?: unknown; name?: unknown; store_id?: unknown; secret_name?: unknown } | null;
      if (o?.type !== "secrets_store_secret") continue;
      if (typeof o.name !== "string" || typeof o.store_id !== "string" || typeof o.secret_name !== "string") {
        recordShapeAnomaly("secrets:wiring-binding-shape");
        return null;
      }
      const k = wiringKey(o.store_id, o.secret_name);
      const arr = out.get(k) ?? [];
      arr.push({ script, binding: o.name });
      out.set(k, arr);
    }
  }
  return out;
}

// locateStores finds the in-scope account that holds each store and reads that store's metadata.
async function locateStores(ctx: SecretsWiringContext, stores: string[], accounts: string[], meter: Meter, limit: Limit) {
  const storeAccount = new Map<string, string>();
  const storeMeta = new Map<string, Map<string, StoreMeta>>();
  for (const store of stores) {
    let last: unknown;
    for (const acct of accounts) {
      if (!limit.allows(1)) {
        last = undefined;
        break;
      }
      try {
        limit.charge();
        storeMeta.set(store, await readStoreSecrets(ctx.api, acct, store, meter));
        storeAccount.set(store, acct);
        break;
      } catch (e) {
        // Not this account, or the token cannot read the Secrets Store here. Try the next one.
        last = e;
      }
    }
    if (!storeAccount.has(store)) {
      if (last === undefined) await wiringUnknown("_truncated", "page-cap", "budget");
      else await wiringUnknown("_unavailable", classifySourceFaultReason(last), "store");
    }
  }
  return { storeAccount, storeMeta };
}

function sortWorkers(list: SecretWorkerBinding[]): SecretWorkerBinding[] {
  // Sorted so the same account state always seals the same descriptor bytes.
  return [...list].sort((a, b) => (a.script === b.script ? (a.binding < b.binding ? -1 : a.binding > b.binding ? 1 : 0) : a.script < b.script ? -1 : 1));
}

// readSecretsWiring returns the wiring for each secret, keyed by wiringKey(store, name). Every secret in
// `secrets` gets an entry: "unknown" wherever the reader could not be complete. It never throws.
export async function readSecretsWiring(ctx: SecretsWiringContext | undefined, secrets: SecretRef[], budget: WiringBudget): Promise<Map<string, SecretWiring>> {
  const out = new Map<string, SecretWiring>();
  for (const s of secrets) out.set(wiringKey(s.store, s.name), UNKNOWN);
  if (secrets.length === 0) return out;
  if (ctx === undefined) {
    // No discovery token: the metadata cannot be read. Counted once per crawl, never a failed run.
    await wiringUnknown("_unavailable", "auth", "no-token");
    return out;
  }
  // A secret saved without a storeId cannot be looked up; it stays "unknown".
  if (secrets.some((s) => s.store === undefined)) await wiringUnknown("_unavailable", "other", "no-store");
  const stores = [...new Set(secrets.map((s) => s.store).filter((s): s is string => s !== undefined))];
  if (stores.length === 0) return out;

  const limit = new Limit(budget, FINALISE_RESERVE + secrets.length * SECRETS_WIRING_RESERVE_PER_SECRET);
  const accounts = await candidateAccounts(ctx, budget);
  if (accounts.length === 0) return out;
  const { storeAccount, storeMeta } = await locateStores(ctx, stores, accounts, budget, limit);

  // One Workers settings pass per account that holds a store (usually exactly one: the engine's own).
  const bindingsByAccount = new Map<string, Map<string, SecretWorkerBinding[]> | null>();
  for (const acct of new Set(storeAccount.values())) bindingsByAccount.set(acct, await readWorkerBindings(ctx.api, acct, budget, limit));

  for (const s of secrets) {
    if (s.store === undefined) continue;
    const acct = storeAccount.get(s.store);
    if (acct === undefined) continue;
    const meta = storeMeta.get(s.store)?.get(s.name);
    if (meta === undefined) {
      // The store list does not hold this name: a mistyped name or a deleted secret. Nothing about it can
      // be proven, so it records no scopes, no comment and no Workers.
      await wiringUnknown("_unavailable", "not-found", "name-miss", s.name);
      continue;
    }
    const w: SecretWiring = { wiring: "unknown" };
    if (meta.scopes !== undefined) w.scopes = meta.scopes;
    if (meta.comment !== undefined) w.comment = meta.comment;
    const bindings = bindingsByAccount.get(acct);
    if (bindings !== null && bindings !== undefined) {
      const list = bindings.get(wiringKey(s.store, s.name)) ?? [];
      // The engine reads this secret through its own binding, so a complete list must hold that binding. A
      // list without it proves the store id or name is not what the engine binds. The scopes and comment
      // then describe another secret than the sealed value, so none of the metadata is recorded.
      if (s.bindingVar === undefined || !list.some((b) => b.binding === s.bindingVar)) {
        await wiringUnknown("_unavailable", "not-found", "self-miss", s.name);
        continue;
      }
      w.wiring = "captured";
      w.workers = sortWorkers(list);
    }
    out.set(wiringKey(s.store, s.name), w);
  }
  return out;
}
