// router-sources-discovery.ts -- the account-wide source discovery slice of the router-sources spoke: the
// discovery-account/config types, the credentialed Cloudflare-API caller, the discovery-account and
// engine-account resolvers, the paginating lister, and the per-account product lister.
import { DISCOVERY_SECRET_AAD, loadConfigWrapKey, resolveConfigSecret, type WrappedSecret } from "./config-secret.ts";
import type { Env } from "../env.d.ts";


// ---- account-wide source discovery (console-set token; multi-account) -------------------------
// With a READ-ONLY Cloudflare API token the CUSTOMER pastes into the console (stored by the
// scheduler DO, runtime, no CLI, no redeploy; the vendor never sees it, the same custody class
// as the S3 destination credentials; DISCOVERY_API_TOKEN stays as the env/IaC fallback), the
// discover route lists each browsed account's KV namespaces, R2 buckets, D1 databases and Secrets
// Store secrets via the Cloudflare API, everything that EXISTS, not only what is bound.
// MULTI-ACCOUNT: an enterprise token may see many accounts; the operator chooses which to browse
// and which one is the ENGINE's own (bindings can only attach within the engine's account; other
// accounts are honest visibility, back them up by deploying an engine there). Best-effort and
// FAIL-OPEN PER PRODUCT per account: a missing scope degrades one listing to a coarse error
// string ("r2: HTTP 403"), never the route. Metadata only; the token is never returned.

// MAX_DISCOVERY_ACCOUNTS bounds how many accounts one discover request scans (each account costs
// up to ~6 subrequests; 8 accounts stays comfortably inside the Workers subrequest budget). An
// operator browsing more selects in batches.
export const MAX_DISCOVERY_ACCOUNTS = 8;


// DiscoveryConfigView mirrors the DO's stored record shape for the router's internal read.
export interface DiscoveryConfigView {
  // Mirrors DiscoveryConfig.token: an envelope when encrypted at rest, a string on the back-compat
  // floor. Every consumer resolves it through resolveConfigSecret with DISCOVERY_SECRET_AAD.
  token: string | WrappedSecret;
  accountsSeen: Array<{ id: string; name: string }>;
  selected: string[];
  engineAccountId: string | null;
  // The token-authenticated source types explicitly added on the Sources screen (cf-config / workers
  // / stream / images / artifacts); the discover route echoes them so the wizard offers only added types.
  enabledSources?: string[];
}


export interface AccountListing {
  kv: Array<{ id: string; name: string }>;
  r2: Array<{ name: string }>;
  d1: Array<{ id: string; name: string }>;
  secrets: Array<{ storeId: string; name: string }>;
  zones: Array<{ id: string; name: string }>; // Cloudflare zones, the cf-config source's selectable units
  errors: string[];
}


export function cfApi(token: string): (path: string) => Promise<unknown> {
  return async (path: string): Promise<unknown> => {
    const r = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
      headers: { authorization: `Bearer ${token}` },
      // V15.3.2: never follow a redirect on a CREDENTIALED call. A 3xx off api.cloudflare.com would replay
      // the Bearer token to the redirect target; redirect:"manual" surfaces the 3xx as a non-ok response
      // (r.ok === false) so it is treated as a failure rather than chased.
      redirect: "manual",
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  };
}


// resolveDiscoveryAccounts lists the accounts a token can see (used to VERIFY a pasted token, to
// power multi-account browsing, and as one leg of the env-fallback auto-resolution). It ALWAYS asks
// the live Cloudflare API -- it used to short-circuit and return a single fabricated account
// record built from env.CF_ACCOUNT_ID whenever that var was set, without ever consulting the token,
// so a wrong-account or garbage-shaped token was accepted with a confident "1 account visible"
// answer and multi-account browsing was permanently inert on any estate that pins CF_ACCOUNT_ID. The
// caller that legitimately wants a no-API-call pin (resolveEngineAccountId, directly below) already
// short-circuits on env.CF_ACCOUNT_ID one level above its own call into this function, so it never
// reached this branch either; removing it changes no caller's behaviour except the two verify/browse
// routes it was silently wrong for.
export async function resolveDiscoveryAccounts(token: string, _env: Env): Promise<{ accounts: Array<{ id: string; name: string }>; errors: string[] }> {
  const api = cfApi(token);
  const accounts: Array<{ id: string; name: string }> = [];
  const errors: string[] = [];
  try {
    const j = (await api(`/accounts?per_page=${MAX_ACCOUNTS_PAGE}`)) as { result?: Array<{ id?: unknown; name?: unknown }> };
    for (const a of j.result ?? []) {
      if (typeof a.id === "string" && a.id !== "") {
        accounts.push({ id: a.id, name: typeof a.name === "string" && a.name !== "" ? a.name : a.id });
      }
    }
    if (accounts.length === 0) errors.push("accounts: the token cannot list any account");
  } catch (e) {
    errors.push(`accounts: ${(e as Error).message}`);
  }
  return { accounts, errors };
}


// resolveEngineAccountId names the engine's OWN Cloudflare account for the no-CLI key install and the
// source-attach (both PUT to the engine's own worker). Order: the explicitly marked account, then the
// CF_ACCOUNT_ID deploy var, then -- the fresh self-host case neither covers -- a read-only discovery token
// that sees EXACTLY ONE account (that account is then unambiguously the engine's own). More than one visible
// account stays ambiguous and returns null, so the caller shows the honest in-console "pick it under Sources"
// prompt rather than dead-ending the first hour on a wrangler command (the no-customer-CLI rule).
export async function resolveEngineAccountId(env: Env, cfg: DiscoveryConfigView | null): Promise<string | null> {
  if (cfg?.engineAccountId) return cfg.engineAccountId;
  const envAccount = typeof env.CF_ACCOUNT_ID === "string" && env.CF_ACCOUNT_ID.trim() !== "" ? env.CF_ACCOUNT_ID.trim() : null;
  if (envAccount !== null) return envAccount;
  const envToken = typeof env.DISCOVERY_API_TOKEN === "string" ? env.DISCOVERY_API_TOKEN.trim() : "";
  // The stored token is sealed under DISCOVERY_SECRET_AAD when a wrap key is configured. This resolver
  // is best-effort by design (it feeds an honest in-console prompt, never an error), so an envelope the
  // key cannot open falls through to null exactly like a token that cannot list accounts.
  let token: string | null;
  try {
    token = cfg?.token !== undefined
      ? await resolveConfigSecret(loadConfigWrapKey(env.CONFIG_WRAP_KEY), cfg.token, DISCOVERY_SECRET_AAD)
      : (envToken !== "" ? envToken : null);
  } catch {
    token = envToken !== "" ? envToken : null;
  }
  if (token === null || token === "") return null;
  try {
    const resolved = await resolveDiscoveryAccounts(token, env);
    if (resolved.accounts.length === 1) return resolved.accounts[0]!.id;
  } catch {
    // best-effort: a token that cannot list accounts falls through to the honest in-console prompt.
  }
  return null;
}


// listPaged follows Cloudflare list pagination up to `cap` items, so the source picker is not silently
// capped at one 100-item page (discover-listing-silent-truncation). It handles BOTH paging models: a
// cursor (R2 buckets, r2-wrong-pagination-model) and page-based result_info (KV, D1, zones, secret stores).
// `pick` extracts one page's result array (R2 nests it under result.buckets; the rest are result directly).
// Bounded: stops at `cap` or when the pages/cursor are exhausted.
export async function listPaged<T>(api: (path: string) => Promise<unknown>, basePath: string, pick: (body: unknown) => T[], cap: number): Promise<T[]> {
  const per = 100;
  const items: T[] = [];
  let page = 1;
  let cursor: string | undefined;
  let useCursor = false;
  const maxPages = Math.ceil(cap / per) + 2; // bounded; +2 so the cap, not the loop, is the limit
  for (let i = 0; i < maxPages; i++) {
    const sep = basePath.includes("?") ? "&" : "?";
    const path = useCursor && cursor !== undefined
      ? `${basePath}${sep}per_page=${per}&cursor=${encodeURIComponent(cursor)}`
      : `${basePath}${sep}per_page=${per}&page=${page}`;
    const body = (await api(path)) as { result_info?: { total_pages?: number; cursor?: string; cursors?: { after?: string } } };
    const batch = pick(body);
    for (const it of batch) {
      items.push(it);
      if (items.length >= cap) return items; // cap reached (the documented bound)
    }
    const next = body.result_info?.cursor ?? body.result_info?.cursors?.after;
    if (typeof next === "string" && next !== "") { useCursor = true; cursor = next; continue; } // cursor style
    if (useCursor) return items; // cursor style and the cursor is now empty: exhausted
    const totalPages = typeof body.result_info?.total_pages === "number" ? body.result_info.total_pages : undefined;
    if (totalPages !== undefined ? page >= totalPages : batch.length < per) return items; // page style exhausted
    page++;
  }
  return items;
}

// Per-product list bounds shared by the listAccountProducts helpers.
// DISCOVERY_LIST_CAP is EXPORTED because the cap is itself a diagnostic fact (G008): a listing that returns
// exactly this many resources was TRUNCATED, and the discover route classifies that as its own outcome rather
// than letting a capped listing read as a complete one. A form that shows 500 of 900 buckets is a form the
// customer will build an incomplete backup estate against.
export const DISCOVERY_LIST_CAP = 500; // bound the response; an account with more lists the first 500 per product
const LIST_CAP = DISCOVERY_LIST_CAP;
const STORE_CAP = 50; // secret STORES to walk (each store's secrets are then paginated to LIST_CAP total)
// MAX_ACCOUNTS_PAGE bounds the first page of CF accounts a token can see during discovery.
const MAX_ACCOUNTS_PAGE = 50;

type CfApiCall = (path: string) => Promise<unknown>;

async function listKv(api: CfApiCall, accountId: string, errors: string[]): Promise<AccountListing["kv"]> {
  const out: AccountListing["kv"] = [];
  try {
    const items = await listPaged<{ id?: unknown; title?: unknown }>(api, `/accounts/${encodeURIComponent(accountId)}/storage/kv/namespaces`, (b) => (b as { result?: Array<{ id?: unknown; title?: unknown }> }).result ?? [], LIST_CAP);
    for (const n of items) if (typeof n.id === "string" && typeof n.title === "string") out.push({ id: n.id, name: n.title });
  } catch (e) {
    errors.push(`kv: ${(e as Error).message}`);
  }
  return out;
}

async function listR2(api: CfApiCall, accountId: string, errors: string[]): Promise<AccountListing["r2"]> {
  const out: AccountListing["r2"] = [];
  try {
    const items = await listPaged<{ name?: unknown }>(api, `/accounts/${encodeURIComponent(accountId)}/r2/buckets`, (b) => (b as { result?: { buckets?: Array<{ name?: unknown }> } }).result?.buckets ?? [], LIST_CAP);
    for (const b of items) if (typeof b.name === "string") out.push({ name: b.name });
  } catch (e) {
    errors.push(`r2: ${(e as Error).message}`);
  }
  return out;
}

async function listD1(api: CfApiCall, accountId: string, errors: string[]): Promise<AccountListing["d1"]> {
  const out: AccountListing["d1"] = [];
  try {
    const items = await listPaged<{ uuid?: unknown; name?: unknown }>(api, `/accounts/${encodeURIComponent(accountId)}/d1/database`, (b) => (b as { result?: Array<{ uuid?: unknown; name?: unknown }> }).result ?? [], LIST_CAP);
    for (const d of items) if (typeof d.uuid === "string" && typeof d.name === "string") out.push({ id: d.uuid, name: d.name });
  } catch (e) {
    errors.push(`d1: ${(e as Error).message}`);
  }
  return out;
}

async function listSecretsStores(api: CfApiCall, accountId: string, errors: string[]): Promise<AccountListing["secrets"]> {
  const out: AccountListing["secrets"] = [];
  try {
    const stores = await listPaged<{ id?: unknown }>(api, `/accounts/${encodeURIComponent(accountId)}/secrets_store/stores`, (b) => (b as { result?: Array<{ id?: unknown }> }).result ?? [], STORE_CAP);
    for (const st of stores) {
      if (typeof st.id !== "string") continue;
      if (out.length >= LIST_CAP) break;
      const secs = await listPaged<{ name?: unknown }>(api, `/accounts/${encodeURIComponent(accountId)}/secrets_store/stores/${encodeURIComponent(st.id)}/secrets`, (b) => (b as { result?: Array<{ name?: unknown }> }).result ?? [], LIST_CAP - out.length);
      for (const s of secs) if (typeof s.name === "string") out.push({ storeId: st.id, name: s.name });
    }
  } catch (e) {
    errors.push(`secrets-store: ${(e as Error).message}`);
  }
  return out;
}

async function listZones(api: CfApiCall, accountId: string, errors: string[]): Promise<AccountListing["zones"]> {
  const out: AccountListing["zones"] = [];
  try {
    // Zones in this account, the selectable unit for a cf-config (zone-settings) source.
    const items = await listPaged<{ id?: unknown; name?: unknown }>(api, `/zones?account.id=${encodeURIComponent(accountId)}`, (b) => (b as { result?: Array<{ id?: unknown; name?: unknown }> }).result ?? [], LIST_CAP);
    for (const z of items) if (typeof z.id === "string" && typeof z.name === "string") out.push({ id: z.id, name: z.name });
  } catch (e) {
    errors.push(`zones: ${(e as Error).message}`);
  }
  return out;
}

// listAccountProducts lists ONE account's products for the source picker, fail-open per product. Each list
// is PAGINATED to LIST_CAP (was single-page, silently capping at 100). It is a short orchestrator over the
// per-product list helpers; each helper pushes its own errors into the shared errors array.
export async function listAccountProducts(token: string, accountId: string): Promise<AccountListing> {
  const api = cfApi(token);
  const errors: string[] = [];
  const [kv, r2, d1, secrets, zones] = await Promise.all([
    listKv(api, accountId, errors),
    listR2(api, accountId, errors),
    listD1(api, accountId, errors),
    listSecretsStores(api, accountId, errors),
    listZones(api, accountId, errors),
  ]);
  kv.sort((a, b) => a.name.localeCompare(b.name));
  r2.sort((a, b) => a.name.localeCompare(b.name));
  d1.sort((a, b) => a.name.localeCompare(b.name));
  secrets.sort((a, b) => a.name.localeCompare(b.name));
  zones.sort((a, b) => a.name.localeCompare(b.name));
  return { kv, r2, d1, secrets, zones, errors };
}
