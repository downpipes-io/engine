// router-discovery.ts -- the source-discovery, cf-config rediscover/mode, account-discovery configuration
// and in-product source-attach routes. The downpipe.read / keys.ceremony gate runs on each route.


import { accountInDiscoveryScope } from "../sched/config-validate.ts";
import { DISCOVERY_SECRET_AAD, loadConfigWrapKey, maybeWrapConfigSecret, resolveConfigSecret } from "./config-secret.ts";
import type { DownpipeState } from "../sched/scheduler-do.ts";
import { probeCfConfig } from "../sources/cf-config-discovery.ts";
import { cfConfigCatalogue } from "../sources/cf-config-surfaces.ts";
import { type AttachSource, changeBindings } from "./attach.ts";
import { bindingAlarmOf } from "./attach-plan.ts";
import { recordBindingAlarm } from "./diag-admin.ts";
import { bumpAdminCounter, recordAttachHealth, recordDiscoveryHealth, recordDiscoveryTokenSet } from "./diag-counters.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { type AttachFaultClass as AttachFault, type AttachOp, type AttachPlanShape, attachRefusalClassOf, attachRefusalOf, classifyAttachError, classifyDiscoveryError, classifyDiscoveryListing, classifyTokenSetFailure, type DiscoveryAccountTally, type DiscoveryObservation, type DiscoveryOutcome, type DiscoveryProduct, worstDiscoveryOutcome } from "./discovery-health.ts";
import { planRosterReattach } from "./roster-reattach.ts";
import { callerHeaders, gate, jsonError, jsonResponse, observeAttachAfterSelfDeploy, ownerActionGate, ownerActionQueuedResponse, rateLimited, recordAuditAfterSelfDeploy, recordVerifiedEngineAccountAfterSelfDeploy, validateDeployToken } from "./router-core.ts";
import { doURL, type RouterCtx, recordAuthSignalEdge } from "./router-helpers.ts";
import { type AccountListing, DISCOVERY_LIST_CAP, type DiscoveryConfigView, enumerateBoundSources, listAccountProducts, MAX_DISCOVERY_ACCOUNTS, resolveDiscoveryAccounts, resolveEngineAccountId } from "./router-sources.ts";

// PRODUCT_LISTS maps each closed discovery product to the AccountListing field it is listed into, so the
// per-product verdict is derived from the listing's SHAPE (its length against the page cap) rather than from
// anything in it. The listing itself -- bucket names, namespace ids, database names, secret names, zones --
// never leaves this function: only the count and the closed verdict do.
const PRODUCT_LISTS: ReadonlyArray<{ product: DiscoveryProduct; key: keyof AccountListing }> = [
  { product: "kv", key: "kv" },
  { product: "r2", key: "r2" },
  { product: "d1", key: "d1" },
  { product: "secrets", key: "secrets" },
  { product: "zones", key: "zones" },
];

// classifyDiscoveryOutcomes (G008) reduces every account's listing to ONE closed per-product verdict, folding
// several accounts to the WORST (a token that reads account A's buckets and not account B's is degraded, and
// the record must say so rather than take whichever account was scanned last). It is the reason a silently
// degraded setup form stops being indistinguishable from an empty account: an EMPTY listing that came back
// clean reads "empty"; the same empty array behind a 403 reads "denied"; a full page reads "truncated".
// It ALSO counts the accounts (G286). The fold above is lossy in the one direction the gap's second ticket
// clause turns on: "half our accounts show no resources". Folded to the worst, ten accounts denied on D1 and ONE
// of ten denied on D1 are the same record -- products.d1 = "denied", accountsScanned = 10 -- because nothing
// counted accounts. So each account's per-product verdict is tallied into three exhaustive classes BEFORE the
// fold, and the tallies ride beside it. They are counts of accounts; no account id or name is built here.
function classifyDiscoveryOutcomes(listings: readonly AccountListing[]): {
  products: Partial<Record<DiscoveryProduct, DiscoveryOutcome>>;
  accountsByProduct: Partial<Record<DiscoveryProduct, DiscoveryAccountTally>>;
  accountsDegraded: number;
} {
  const products: Partial<Record<DiscoveryProduct, DiscoveryOutcome>> = {};
  const tallies = new Map<DiscoveryProduct, { withData: number; empty: number; degraded: number }>();
  let accountsDegraded = 0;
  const note = (p: DiscoveryProduct, o: DiscoveryOutcome): void => {
    const prior = products[p];
    products[p] = prior === undefined ? o : worstDiscoveryOutcome(prior, o);
  };
  const bump = (p: DiscoveryProduct, k: "withData" | "empty" | "degraded"): void => {
    const row = tallies.get(p) ?? { withData: 0, empty: 0, degraded: 0 };
    row[k] += 1;
    tallies.set(p, row);
  };

  for (const listing of listings) {
    // This account's own per-product verdict, folded across its listing and its error strings, so an account
    // whose D1 listing came back empty BEHIND A 403 is counted as degraded, not as empty.
    const perAccount = new Map<DiscoveryProduct, DiscoveryOutcome>();
    const noteAccount = (p: DiscoveryProduct, o: DiscoveryOutcome): void => {
      const prior = perAccount.get(p);
      perAccount.set(p, prior === undefined ? o : worstDiscoveryOutcome(prior, o));
    };
    for (const { product, key } of PRODUCT_LISTS) {
      const rows = listing[key];
      noteAccount(product, classifyDiscoveryListing(Array.isArray(rows) ? rows.length : 0, DISCOVERY_LIST_CAP));
    }
    // The fail-open error strings the listers pushed. classifyDiscoveryError reads each ONLY to select the
    // closed (product, outcome) pair and returns the enums; the string never travels.
    for (const err of listing.errors ?? []) {
      const { product, outcome } = classifyDiscoveryError(err);
      if (product !== null) noteAccount(product, outcome);
    }
    let thisAccountDegraded = false;
    for (const [product, outcome] of perAccount) {
      note(product, outcome);
      const isDegraded = outcome !== "ok" && outcome !== "empty";
      bump(product, isDegraded ? "degraded" : outcome === "empty" ? "empty" : "withData");
      if (isDegraded) thisAccountDegraded = true;
    }
    if (thisAccountDegraded) accountsDegraded += 1;
  }

  // G286, THE SECOND DEFECT: an empty account must not MASK a populated one. SEVERITY ranks empty(1) above
  // ok(0), so ONE genuinely empty spare account folded nine populated accounts to lastOutcome.r2 = "empty" --
  // the pack asserting "no R2 anywhere" while the wizard was showing the customer their buckets. That is a FALSE
  // row, not a missing one, and it is worse. `empty` is now only reported for a product NO account had data for;
  // if any account listed rows, the product is not empty and the per-account tally says how many were.
  const accountsByProduct: Partial<Record<DiscoveryProduct, DiscoveryAccountTally>> = {};
  for (const [product, row] of tallies) {
    accountsByProduct[product] = { withData: row.withData, empty: row.empty, degraded: row.degraded };
    if (products[product] === "empty" && row.withData > 0) products[product] = "ok";
  }
  return { products, accountsByProduct, accountsDegraded };
}

// boundSourceCount reduces the engine's OWN bound-source listing to a single COUNT for the G008 record. The
// binding NAMES are operator labels and stay in the response; only how many there are rides into the record --
// zero bound sources beside an absent discovery token is the completely blank setup form.
function boundSourceCount(bound: { kv: string[]; r2: string[]; d1: string[]; secrets: string[] }): number {
  return bound.kv.length + bound.r2.length + bound.d1.length + bound.secrets.length;
}

// resolveAttachAccount resolves the engine's OWN account id + script name for the self-attach write: the
// discovery config's engineAccountId (the marked account), the CF_ACCOUNT_ID deploy var, else a single-
// account discovery token (resolveEngineAccountId). Without an account the engine cannot name itself, so
// it returns the honest 400 Response the caller returns verbatim; otherwise { accountId, scriptName }.
async function resolveAttachAccount(ctx: RouterCtx): Promise<{ accountId: string; scriptName: string } | Response> {
  const { env, scheduler } = ctx;
  const cfgResp = await scheduler.fetch(doURL("/sources/discovery-config"), { method: "GET" });
  const cfg = ((await cfgResp.json()) as { config?: DiscoveryConfigView | null }).config ?? null;
  const accountId = await resolveEngineAccountId(env, cfg);
  if (accountId === null) {
    return jsonError("the engine's own account is not set; add a read-only discovery token or pick the account under Sources before attaching (no command line needed)", 400);
  }
  const scriptName = typeof env.WORKER_NAME === "string" && env.WORKER_NAME.trim() !== "" ? env.WORKER_NAME.trim() : "downpipe-engine";
  return { accountId, scriptName };
}

// observeAttachSideEffects records the best-effort, post-changeBindings bookkeeping the attach needs: the
// audit rows (attach/detach), the credential-lifecycle row for the spent ephemeral token, and (LICENCE-
// BINDING-ON-CLAIM follow-up,) the engine's own account id, PROVEN by changeBindings' own read
// of /accounts/{accountId}/workers/scripts/{scriptName} before it wrote anything. changeBindings has
// already written AND post-verified the change, and that write redeployed the engine (briefly resetting
// the audit DO), so every append uses the self-redeploy retry and is best-effort: a dropped row is never
// worse than the manual baseline (fail-open) and must not fail an attach that already landed. The token
// VALUE is never passed, only its PUBLIC id, expiry, a permission summary and the attached names. Returns
// auditDeferred (true when any audit append could not land), which the route echoes to the console.
async function observeAttachSideEffects(ctx: RouterCtx, accountId: string, result: Awaited<ReturnType<typeof changeBindings>>): Promise<boolean> {
  const { env, caller, sourceIp } = ctx;
  const { added, removed, tokenId, expiresOn, permissionSummary } = result;
  let auditDeferred = false;
  if (added.length > 0 && !(await recordAuditAfterSelfDeploy(env, caller, sourceIp, "sources-attached", { kind: "access-policy" }))) auditDeferred = true;
  if (removed.length > 0 && !(await recordAuditAfterSelfDeploy(env, caller, sourceIp, "sources-detached", { kind: "access-policy" }))) auditDeferred = true;
  // Best-effort, never gates auditDeferred: a dropped write here only means GET /admin/status keeps
  // reporting cfAccountId absent until the next attach or apply succeeds, never a user-facing failure of
  // an attach that already landed. recordVerifiedEngineAccount itself never overwrites once set.
  await recordVerifiedEngineAccountAfterSelfDeploy(env, accountId, "attach");
  if (added.length > 0) {
    await observeAttachAfterSelfDeploy(env, {
      ...(tokenId !== undefined ? { tokenId } : {}),
      ...(expiresOn !== undefined ? { expiresOn } : {}),
      permissionSummary,
      sourcesAttached: added,
    });
  }
  return auditDeferred;
}

// handleDiscovery dispatches the discovery + cf-config + attach group. Returns the route's Response, or null
// when no case here matched (the hub falls to the next spoke).
// fireInBackground: see router-identity.ts's identical helper. The
// records below are the LAST action before their route returns, with no awaited work left to give the
// detached promise a scheduling window, so under real workerd the write is abandoned with the request
// context. runtime is undefined only for a direct call with no fetch runtime (a unit test), which falls
// back to the old bare void unchanged.
function fireInBackground(runtime: RouterCtx["runtime"], task: Promise<unknown>): void {
  if (runtime?.waitUntil) runtime.waitUntil(task);
  else void task;
}


export async function handleDiscovery(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, scheduler, caller, sub, runtime } = ctx;
  switch (`${req.method} ${sub}`) {
    // ---- source discovery (the operator's "what can this engine back up?" listing) ----------------
    // GET /sources/discover enumerates the engine's OWN env bindings and classifies the backup-able
    // ones by duck-typing (KV namespace / R2 bucket / D1 database / Secrets Store), excluding the
    // engine's reserved bindings and plain vars. It lists BINDING NAMES ONLY, no values, no keys,
    // no data, so the console can offer a select-from-what-exists picker instead of manual naming.
    // HONEST BOUNDARY: a Worker sees only what is BOUND to it; resources in the account that are not
    // attached to the engine do not appear (attaching them is the wrangler.toml step the Add-a-source
    // screen documents). No Cloudflare API token is read or held (no-custody). downpipe.read gated.
    case "GET /sources/discover": {
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      const bound = enumerateBoundSources(env);
      // The ACCOUNT-WIDE tier: the console-stored token (DO config; set in the UI, no CLI, no
      // redeploy) wins; the DISCOVERY_API_TOKEN env secret remains the IaC fallback. Multi-account:
      // the operator's selected accounts are scanned (capped to bound subrequests); each account
      // lists fail-open per product. engineAccountId marks where binding stanzas can attach (the
      // env fallback presumes its single resolved account IS the engine's, matching v2 behaviour).
      // Presence-safe: a DO hiccup reading the discovery config (e.g. the demo-reset wipe window) must not
      // 500 the whole discover endpoint; fall back to null so the env-token IaC fallback or an honest
      // tokenPresent:false answers instead, the same fail-open posture resolveEngineAccount already uses.
      let cfg: DiscoveryConfigView | null = null;
      try {
        const cfgResp = await scheduler.fetch(doURL("/sources/discovery-config"), { method: "GET" });
        cfg = ((await cfgResp.json()) as { config?: DiscoveryConfigView | null }).config ?? null;
      } catch {
        // leave cfg null: the env token (if set) or tokenPresent:false answers, never a 500.
        // G051: tokenPresent:false is a LIE when the token is merely UNREADABLE. "Discovery says no token but
        // we set one" is this branch, and nothing in the pack could tell the two apart.
        void bumpAdminCounter(scheduler, "degraded-read-discovery-config");
      }
      const envToken = typeof env.DISCOVERY_API_TOKEN === "string" ? env.DISCOVERY_API_TOKEN.trim() : "";
      const stored = cfg?.token;
      const token = stored !== undefined
        ? await resolveConfigSecret(loadConfigWrapKey(env.CONFIG_WRAP_KEY), stored, DISCOVERY_SECRET_AAD)
        : (envToken !== "" ? envToken : null);
      if (token === null) {
        // G008: NO TOKEN. The account-wide tier was never even attempted, so the form shows only the engine's
        // own bindings and the console cannot say why the rest is missing. Recorded as an observation with no
        // product verdicts at all (nothing was listed), which is exactly what noTokenObservations counts.
        await recordDiscoveryHealth(scheduler, { products: {}, tokenPresent: false, engineAccountKnown: cfg?.engineAccountId != null, accountsScanned: 0, accountsCapped: false, boundSources: boundSourceCount(bound) });
        return jsonResponse({ bound, tokenPresent: false });
      }
      const nameOf = new Map<string, string>((cfg?.accountsSeen ?? []).map((a) => [a.id, a.name]));
      let engineAccountId: string | null = cfg?.engineAccountId ?? null;
      let scan: string[] = (cfg?.selected ?? []).slice(0, MAX_DISCOVERY_ACCOUNTS);
      const accountErrors: string[] = [];
      if (scan.length === 0) {
        const resolved = await resolveDiscoveryAccounts(token, env);
        accountErrors.push(...resolved.errors);
        scan = resolved.accounts.map((a) => a.id).slice(0, MAX_DISCOVERY_ACCOUNTS);
        for (const a of resolved.accounts) if (!nameOf.has(a.id)) nameOf.set(a.id, a.name);
        if (engineAccountId === null && scan.length === 1) engineAccountId = scan[0]!;
      }
      const accounts = await Promise.all(
        scan.map(async (accountId) => {
          const listing = await listAccountProducts(token, accountId);
          return { accountId, accountName: nameOf.get(accountId) ?? accountId, ...listing };
        }),
      );
      // G008: RECORD WHAT THE FORM ACTUALLY SAW. This route is fail-open per product: every listing above can
      // come back empty because the account holds nothing, because the token cannot see it, or because the
      // page cap cut it off, and the 200 it returns looks identical in all three cases. The customer then
      // builds their whole backup estate against whichever of the three it was. The observation carries the
      // CLASSIFIED verdicts only (closed enums + counts + booleans); the listing, the account ids, the account
      // names and the token stay here. Awaited (like the cf-config discovery post below) so the write is
      // CHECKED -- a dropped one is itself counted in droppedWrites rather than vanishing.
      const accountsOutcome = accountErrors.length > 0
        ? accountErrors.map((e) => classifyDiscoveryError(e).outcome).reduce(worstDiscoveryOutcome)
        : classifyDiscoveryListing(scan.length, MAX_DISCOVERY_ACCOUNTS);
      const perProduct = classifyDiscoveryOutcomes(accounts);
      const observation: DiscoveryObservation = {
        products: { accounts: accountsOutcome, ...perProduct.products },
        // G286: the per-account tallies ride BESIDE the folded verdict, so "every account is blacked out on D1"
        // and "one of ten accounts is" stop being the same row.
        accountsByProduct: perProduct.accountsByProduct,
        accountsDegraded: perProduct.accountsDegraded,
        tokenPresent: true,
        // engineAccountKnown false is the state in which NO source can ever be attached (the engine cannot name
        // its own account), and today it is silently absent from the discover payload rather than explained.
        engineAccountKnown: engineAccountId !== null,
        accountsScanned: scan.length,
        accountsCapped: scan.length >= MAX_DISCOVERY_ACCOUNTS,
        boundSources: boundSourceCount(bound),
      };
      await recordDiscoveryHealth(scheduler, observation);
      // workersSupported advertises the Workers-scripts source the console gates its add row on
      // (exactly as cfConfigSurfaces gates cf-config). The adapter is compiled into the engine, so
      // support is unconditional; the row is account-scoped, offered per discovered account.
      // addedSources echoes the token-authenticated source types the operator has explicitly ADDED on
      // the Sources screen, so the create-downpipe wizard offers only added types. It is returned ONLY
      // when a CONSOLE-set discovery config exists (cfg !== null): with the env-token IaC fallback there
      // is no config to add into, so the field is omitted and the console keeps the legacy "all supported"
      // behaviour (an absent field = ungated; a present array = gated, even when empty).
      return jsonResponse({ bound, tokenPresent: true, engineAccountId, accounts, accountErrors, cfConfigSurfaces: cfConfigCatalogue(), workersSupported: true, streamSupported: true, imagesSupported: true, artifactsSupported: false /* artifacts gated (closed beta): re-set true to advertise it as a selectable source */, ...(cfg !== null ? { addedSources: cfg.enabledSources ?? [] } : {}) });
    }

    // POST /downpipes/cf-config/rediscover probes which cf-config surfaces a downpipe's account/zone
    // actually uses (one GET per surface, bounded concurrency) and caches the PRESENT set on the
    // downpipe, so subsequent auto-mode runs capture only those instead of every surface in the registry, every run.
    // Runs in the worker (which can make the subrequests), reads the read-only discovery token, persists
    // via the DO. downpipe.write gated + rate-limited (it makes real CF API calls). Returns the partition.
    case "POST /downpipes/cf-config/rediscover": {
      const denied = gate(caller, "downpipe.write");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = (await req.json()) as { id?: string };
      if (typeof body.id !== "string" || body.id === "") return jsonResponse({ ok: false, error: "id required" });
      // This validates one id by scanning the full downpipe list (O(n) deserialise per call). It is
      // acceptable at realistic downpipe counts; a single-record GET on the DO would make it O(1) and is
      // the optimisation to take if an account ever holds hundreds of downpipes.
      const all = (await (await scheduler.fetch(doURL("/downpipes"), { method: "GET" })).json()) as DownpipeState[];
      const dp = all.find((d) => d.config.id === body.id);
      if (!dp) return jsonResponse({ ok: false, error: "unknown downpipe" });
      if (dp.config.source.type !== "cf-config") return jsonResponse({ ok: false, error: "not a cf-config downpipe" });
      if (typeof dp.config.source.accountId !== "string" || dp.config.source.accountId === "") return jsonResponse({ ok: false, error: "downpipe has no accountId" });
      const cfg = ((await (await scheduler.fetch(doURL("/sources/discovery-config"), { method: "GET" })).json()) as { config?: DiscoveryConfigView | null }).config ?? null;
      // Cross-account confused-deputy re-check (ASVS V4, HI-11): addDownpipe enforced this at create
      // time, but the Owner's `selected` set can narrow AFTER this downpipe was created (no retroactive
      // re-validation of existing downpipes), and this probe is a real per-surface presence oracle over
      // whatever account the stored config names -- so it re-checks the SAME scope boundary rather than
      // trusting the stored accountId forever.
      if (!accountInDiscoveryScope(dp.config.source.accountId, cfg)) {
        return jsonResponse({ ok: false, error: "this downpipe's account is no longer in the discovery scope; ask the owner to re-select it under Sources" });
      }
      const envToken = typeof env.DISCOVERY_API_TOKEN === "string" ? env.DISCOVERY_API_TOKEN.trim() : "";
      const stored = cfg?.token;
      const token = stored !== undefined
        ? await resolveConfigSecret(loadConfigWrapKey(env.CONFIG_WRAP_KEY), stored, DISCOVERY_SECRET_AAD)
        : (envToken !== "" ? envToken : null);
      if (token === null) return jsonResponse({ ok: false, error: "no discovery token set; set the read-only discovery token first" });
      const discovery = await probeCfConfig(token, dp.config.source.accountId, dp.config.source.zoneId, Date.now());
      // G100: CHECKED. The probe result is returned to the console either way, but a persist that is DROPPED
      // leaves the stored cf-config discovery stale, so the pack (and the capture plan built off it) reasons
      // about surfaces that may no longer exist -- while the operator, who saw a green probe, has no reason
      // to suspect it. The response is unchanged; only the LOSS is now counted.
      await recordDiagWrite(scheduler, "discovery-refresh", () =>
        scheduler.fetch(doURL("/cf-config/discovery"), { method: "POST", body: JSON.stringify({ id: body.id, discovery }), headers: callerHeaders(caller) }),
      );
      return jsonResponse({ ok: true, discovery });
    }

    // POST /downpipes/cf-config/mode sets a cf-config downpipe's capture mode (auto = capture the
    // discovered present set; manual = capture the operator's surface selection). downpipe.write gated
    // + rate-limited.
    case "POST /downpipes/cf-config/mode": {
      const denied = gate(caller, "downpipe.write");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = (await req.json()) as { id?: string; mode?: string };
      if (typeof body.id !== "string" || (body.mode !== "auto" && body.mode !== "manual")) return jsonResponse({ ok: false, error: "id and mode (auto|manual) required" });
      return scheduler.fetch(doURL("/cf-config/mode"), { method: "POST", body: JSON.stringify({ id: body.id, mode: body.mode }), headers: callerHeaders(caller) });
    }

    // ---- account-discovery configuration (console-set; owner-exclusive; no CLI, no redeploy) ------
    // POST /sources/discovery-token verifies the pasted READ-ONLY token LIVE against the Cloudflare
    // API (so a typo or a scope-less token is refused with the platform's status, never stored),
    // then hands the token + the verified account list to the DO, which re-checks owner, stores and
    // audits (never the value). token:null clears. The response is presence + accounts, so the
    // console can open the account chooser immediately for a multi-account token.
    case "POST /sources/discovery-token": {
      const denied = gate(caller, "keys.ceremony"); // owner-exclusive, like the break-glass retire
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = (await req.json()) as { token?: unknown };
      if (body.token === null) {
        return scheduler.fetch(doURL("/sources/discovery-token"), {
          method: "POST",
          body: JSON.stringify({ token: null }),
          headers: callerHeaders(caller),
        });
      }
      const token = typeof body.token === "string" ? body.token.trim() : "";
      // G129: EVERY EXIT FROM THIS ROUTE NOW SAYS WHICH ONE IT WAS. "Verify and save always fails" is the most
      // common onboarding ticket and FIVE faults wear that one sentence; this route answered a flat 400 for all
      // of them, so the console's own row collapsed to {discovery-connect, sources, refused} and a typo'd token,
      // a scope-less token, an expired token, a Cloudflare outage and a verify that never got an answer all
      // COALESCED into it. The console cannot subdivide a 400. THIS ROUTE MADE THE CLOUDFLARE CALL AND SAW THE
      // STATUS, so the class is a fact here and an inference anywhere else.
      //
      // The HTTP answers below are UNCHANGED, message for message: only the closed counter is new, and the
      // classifier reads the engine's own `HTTP <status>` literal solely to SELECT a member (the Cloudflare
      // message body, the token and the account ids are read, discarded, and cannot leave).
      if (!validateDeployToken(token)) {
        fireInBackground(runtime, recordDiscoveryTokenSet(scheduler, { outcome: "refused", failClass: classifyTokenSetFailure([], true), accountsSeen: 0 }));
        return new Response(JSON.stringify({ error: "that does not look like a Cloudflare API token (paste the token value itself)" }), { status: 400, headers: { "content-type": "application/json" } });
      }
      const resolved = await resolveDiscoveryAccounts(token, env);
      if (resolved.accounts.length === 0) {
        // The refusal the whole gap turns on. A token Cloudflare answered 403 for (valid credential, missing
        // Account Settings read) and one it answered 401 for (not a credential at all) both land here, and their
        // remedies are OPPOSITE: re-mint with the scope, versus paste the token value. So do a 200 that listed
        // cleanly and saw no account (a valid token whose scope admits nothing), a 5xx, and a verify that never
        // got an answer. The engine refuses a zero-account token, so `verified-zero-accounts` was never a state
        // the console could observe: this row is where that fact actually lives.
        fireInBackground(runtime, recordDiscoveryTokenSet(scheduler, { outcome: "refused", failClass: classifyTokenSetFailure(resolved.errors, false), accountsSeen: 0 }));
        const why = resolved.errors.join("; ") || "the token cannot list any account";
        return new Response(JSON.stringify({ error: `token verification failed: ${why}. Create a READ-ONLY token, the "Read all resources" template is simplest and also covers Cloudflare configuration backup (zones, DNS, WAF/rulesets); at minimum it needs Account Settings read plus Workers KV Storage, Workers R2 Storage, D1 and Secrets Store read.` }), { status: 400, headers: { "content-type": "application/json" } });
      }
      // The token verified. Recorded too, and NOT as noise: the pack must be able to say "this token last
      // verified cleanly and saw N accounts", because the operator's next sentence is "then why is my source
      // list empty?" -- and that is the discover half (G008), a different record with a different remedy.
      fireInBackground(runtime, recordDiscoveryTokenSet(scheduler, { outcome: "ok", accountsSeen: resolved.accounts.length }));
      // Seal the token BEFORE it crosses into the DO. This is the single write ingress for the
      // account-wide discovery credential, the mirror of maybeWrapConfigSecret at the destination-store
      // routes, and it is what stops a Durable Object storage read yielding a live estate-wide token.
      // With no CONFIG_WRAP_KEY configured this returns the plaintext unchanged (the back-compat floor),
      // so an estate that has not set a wrap key behaves exactly as before.
      const sealed = await maybeWrapConfigSecret(loadConfigWrapKey(env.CONFIG_WRAP_KEY), token, DISCOVERY_SECRET_AAD);
      return scheduler.fetch(doURL("/sources/discovery-token"), {
        method: "POST",
        body: JSON.stringify({ token: sealed, accountsSeen: resolved.accounts }),
        headers: callerHeaders(caller),
      });
    }
    case "POST /sources/discovery-accounts": {
      const denied = gate(caller, "keys.ceremony"); // owner-exclusive
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/sources/discovery-accounts"), {
        method: "POST",
        body: await req.text(),
        headers: callerHeaders(caller),
      });
    }
    case "GET /sources/discovery-status": {
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/sources/discovery-status"), { method: "GET" });
    }

    // POST /sources/enable records WHICH token-authenticated source types (cf-config / workers / stream /
    // images / artifacts) are ADDED as available to protect, so the create-downpipe wizard offers only
    // added types. Owner-exclusive (like discovery-accounts) + rate-limited; the DO re-checks the owner,
    // filters to the known types and stores the full desired set. Additive and reversible (it only changes
    // what the wizard offers, never a binding or a running downpipe), so it is not dual-control gated.
    case "POST /sources/enable": {
      const denied = gate(caller, "keys.ceremony"); // owner-exclusive
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/sources/enable"), {
        method: "POST",
        body: await req.text(),
        headers: callerHeaders(caller),
      });
    }

    // ---- in-product source attach (one-shot deploy token; never stored) ----------------------------
    // POST /sources/attach: the engine adds the requested source bindings TO ITSELF via the
    // Cloudflare script-settings API, using the deploy token in the request body for exactly one
    // read-modify-write. The token is NEVER persisted (no DO write, no env write) and never logged;
    // the audit records the binding names only. Owner-exclusive (deploy-grade) + rate-limited. The
    // new bindings take effect from the next invocation, which the console's wait-poll detects.
    case "POST /sources/attach": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = (await req.json()) as { token?: unknown; sources?: unknown; remove?: unknown };
      const tok = typeof body.token === "string" ? body.token.trim() : "";
      const sources = Array.isArray(body.sources) ? (body.sources as AttachSource[]) : [];
      const remove = Array.isArray(body.remove) ? (body.remove as unknown[]).filter((x): x is string => typeof x === "string") : [];
      if (sources.length + remove.length === 0 || sources.length + remove.length > 50) {
        return jsonError("choose between 1 and 50 sources to attach or detach", 400);
      }
      // G180: WHICH OPERATION THIS IS, and it can only be decided here. An attach and a detach are the SAME POST
      // to this one route, told apart only by which of the two typed lists the console filled in, so every refused
      // Detach used to be recorded as a refused Attach. The ticket names all three actions ("Attach now / Detach /
      // Re-attach all refuses with an error") and two of them were the same row. Their failures are not
      // interchangeable: a refused attach means a source was never protected, and a refused DETACH means a source
      // the operator believes is gone is STILL BOUND and still being read. A change that both adds and removes is
      // an `attach`, because the addition is the half that expands the protected set and deploys.
      //
      // Only the two list LENGTHS are consulted. No binding name is read here, and there is no field for one.
      const op: AttachOp = sources.length === 0 && remove.length > 0 ? "detach" : "attach";
      // OPT-IN DUAL CONTROL (router-executed): rewriting the engine's OWN bindings (which changes the backup
      // scope and runs a self-redeploy with a one-shot deploy token) takes a second owner's approval, bound to
      // the requested source binding SPECS + the removes, NEVER the deploy token. First call (gate ON, no
      // armed approval): record a pending approval + 202 WITHOUT requiring the token; a second owner approves;
      // the owner re-submits with the token and the gate consumes the armed approval here, so the token runs
      // once on the approved attach. The token requirement therefore runs only AFTER the gate says proceed.
      {
        const g = await ownerActionGate(
          scheduler,
          caller,
          "sources-attach",
          { sources, remove },
          `Attach ${sources.length} source(s) / detach ${remove.length} (rewrites the engine's bindings)`,
        );
        if (g.kind === "error") return g.response;
        if (g.kind === "queued") return ownerActionQueuedResponse(g.id);
      }
      if (!validateDeployToken(tok)) {
        // G131: every refusal on this route used to be a RESPONSE and nothing else. A token that is not
        // token-shaped means the write never left the engine, which is a completely different ticket from a
        // token Cloudflare rejected -- and both read as "attach failed" to the customer.
        await recordAttachHealth(scheduler, { op, fault: "token-invalid" });
        return jsonError("paste the deploy token itself (it is used once and never stored)", 400);
      }
      const account = await resolveAttachAccount(ctx);
      if (account instanceof Response) {
        // The engine cannot name its OWN Cloudflare account, so it cannot address the script-settings write.
        // No source can EVER be attached in this state, and it left no durable trace at all.
        await recordAttachHealth(scheduler, { op, fault: "account-unknown" });
        return account;
      }
      // G244: the window-check BLIND SPOT. Cloudflare's token-verify endpoint could not be reached, so the
      // attach proceeded without proving the token's usable window. It is not a refusal (see attach.ts), and it
      // is recorded whatever the attach then does: if the attach later dies on a generic auth error, this row is
      // what says "and nobody was able to check whether the token had even started yet".
      const noteWindowUnchecked = (): void => {
        void recordAttachHealth(scheduler, { op: "attach", fault: "other", refusal: { stage: "window-check-unavailable", cause: "window-unreadable" } });
      };
      try {
        const result = await changeBindings(tok, account.accountId, account.scriptName, sources, remove, fetch, noteWindowUnchecked);
        const auditDeferred = await observeAttachSideEffects(ctx, account.accountId, result);
        // A SUCCESS is recorded too: it is what clears a failing streak, and "the attach worked on the third
        // try" is a different story from "it has never worked".
        await recordAttachHealth(scheduler, { op, attached: result.added.length });
        return jsonResponse({ attached: result.added, detached: result.removed, auditDeferred });
      } catch (e) {
        // G099: a POST-WRITE SAFETY ALARM went ONLY into this HTTP response. The alarm that named a dropped
        // binding -- or proved a concurrent writer's lost update -- died with the operator's browser tab, while
        // the pack kept two healthy-looking sources-attached rows and a source that had quietly stopped backing
        // up. Persist the closed kind + the binding labels; the refusal itself is unchanged.
        // G131: the alarm is narrow BY DESIGN (it fires only on a tagged post-write safety fault), so an
        // ORDINARY failure -- a 403 on the token, a Cloudflare 5xx, a network reset -- recorded NOTHING. The
        // attach record carries the classified cause of EVERY failure, with the tagged alarm outranking the
        // message-derived class (the write LANDED and the verify disagrees with it, which is the worst one).
        const alarm = await recordBindingAlarmFrom(scheduler, e);
        // G244: a TAGGED refusal carries the rich evidence (which stage, which cause, which capability is
        // missing) alongside the coarse class the pack already had. An UNTAGGED throw -- a Cloudflare fault, a
        // transport error -- carries none, and classifyAttachError already names those. Never the message.
        const refusal = attachRefusalOf(e);
        await recordAttachHealth(scheduler, { op, fault: classifyAttachError(e, alarm), ...(refusal !== null ? { refusal } : {}) });
        return jsonError((e as Error).message.slice(0, 300), 400);
      }
    }

    // POST /sources/reattach-missing: HEAL after a bare `wrangler deploy` (or any cause) dropped console-
    // attached source bindings. The downpipe configs (the roster) and ALL backup history survive a deploy;
    // only the live bindings are gone. This recomputes the missing set from the roster vs the engine's live
    // env bindings and re-adds exactly those, with their ORIGINAL names + recorded native ids, so each
    // downpipe reads its source again and its NEXT run continues the SAME lineage (no new downpipe, no
    // orphaned history). It restores the already-approved roster (expands scope by ZERO), so unlike POST
    // /sources/attach it is NOT dual-control gated: a heal-to-known-good recovery must be fast (the whole
    // point, a bad deploy is not the end of the world). Owner-grade (keys.ceremony) + rate-limited; the
    // deploy token rides in the body for one read-modify-write and is never stored or logged. When nothing
    // is missing it returns the plan WITHOUT needing a token, so the console can show "all attached".
    case "POST /sources/reattach-missing": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = (await req.json()) as { token?: unknown };
      const tok = typeof body.token === "string" ? body.token.trim() : "";
      const states = (await (await scheduler.fetch(doURL("/downpipes"), { method: "GET" })).json()) as DownpipeState[];
      const bound = enumerateBoundSources(env);
      const liveNames = new Set<string>([...bound.kv, ...bound.r2, ...bound.d1, ...bound.secrets]);
      const plan = planRosterReattach(states.map((s) => s.config), liveNames);
      // G131: the plan's OWN SHAPE, recorded on every re-attach whatever its outcome. The two counts that
      // matter are the ones the plan never told anyone about: `conflictingClaims` (a binding name two
      // downpipes claim as DIFFERENT Cloudflare resources -- blocked out of the heal entirely, so those
      // downpipes stay broken and the heal still reports success), and `malformedSources` (a binding-backed
      // source with no binding name at all -- presented in NONE of the plan's lists, which is "downpipe X was
      // silently omitted from the heal plan" exactly). Counts and engine-minted ids only.
      const planShape: AttachPlanShape = {
        toAttach: plan.toAttach.length,
        alreadyAttached: plan.alreadyAttached.length,
        unreconstructable: plan.unreconstructable.length,
        conflictingClaims: plan.conflicting.length,
        malformedSources: plan.malformed.length,
      };
      const noteReattach = async (fault?: AttachFault, e?: unknown): Promise<void> => {
        // G244: the re-attach runs the SAME pipeline, so it can be refused by the same guards -- and its
        // refusals matter MORE (a failed re-attach means protected sources STAY dropped and backups are
        // failing right now). The tag rides here too.
        const refusal = e === undefined ? null : attachRefusalOf(e);
        await recordAttachHealth(scheduler, { op: "reattach" as AttachOp, ...(fault !== undefined ? { fault } : {}), plan: planShape, ...(refusal !== null ? { refusal } : {}) });
      };
      const noteReattachWindowUnchecked = (): void => {
        void recordAttachHealth(scheduler, { op: "reattach" as AttachOp, fault: "other", plan: planShape, refusal: { stage: "window-check-unavailable", cause: "window-unreadable" } });
      };
      // G314: a CONFLICTING claim is two downpipes naming the SAME binding as DIFFERENT Cloudflare resources.
      // The heal refuses to guess (correctly: guessing would point a downpipe at someone else's data), so those
      // sources stay UNPROTECTED. Never a binding name: a count, under a closed signal name.
      //
      // THE SIGNAL IS RECORDED HERE, BEFORE THE BRANCH SPLITS, AND THAT IS THE FIX. It used to sit inside the
      // `toAttach.length === 0` arm, which is the one arm where the situation was ALREADY legible (that arm
      // records noteReattach("plan-refused")). planRosterReattach deletes only the CONTESTED binding names from
      // toAttach, so the ordinary shape -- three rebuildable sources plus one contested binding -- has
      // toAttach.length > 0 AND conflicting.length > 0, falls through to the write below, and answers 200 with
      // an attached[] list. That is precisely the state the signal's own vocabulary describes ("the affected
      // sources stay unprotected while the heal REPORTS SUCCESS"), and it was the one state that recorded
      // nothing. A heal that attaches three of four and silently leaves the fourth contested now has a row.
      if (plan.conflicting.length > 0) void recordAuthSignalEdge(scheduler, "binding-claim-conflict");
      // Nothing rebuildable is missing: report the plan (already-attached + any unreconstructable legacy
      // sources + any conflicting bindings) with NO binding write, so no token is required. The console
      // renders the all-clear / re-save / conflict-block state from this alone.
      if (plan.toAttach.length === 0) {
        // Nothing to WRITE is not the same as nothing WRONG: a plan that is empty only because every missing
        // binding is conflicting or malformed is a heal that can never run, and it used to answer 200 with an
        // all-clear-shaped body. Recorded as plan-refused so the pack can tell the two apart.
        await noteReattach(plan.conflicting.length > 0 || plan.malformed.length > 0 ? "plan-refused" : undefined);
        return jsonResponse({ attached: [], alreadyAttached: plan.alreadyAttached, unreconstructable: plan.unreconstructable, conflicting: plan.conflicting, affects: plan.affects, malformed: plan.malformed });
      }
      if (!validateDeployToken(tok)) {
        await noteReattach("token-invalid");
        return jsonError("paste the deploy token itself (it is used once and never stored) to re-attach the missing source bindings", 400);
      }
      const account = await resolveAttachAccount(ctx);
      if (account instanceof Response) {
        await noteReattach("account-unknown");
        return account;
      }
      try {
        // changeBindings re-reads the live bindings, PROVES the additions drop nothing, writes, and
        // post-verifies (verifyAfter) -- the SAME safety harness the attach path uses. Removing nothing.
        // plan.toAttach never includes a conflicting binding (see planRosterReattach), so a conflict can
        // never be attached here even though this branch requires a token.
        const result = await changeBindings(tok, account.accountId, account.scriptName, plan.toAttach, [], fetch, noteReattachWindowUnchecked);
        const auditDeferred = await observeAttachSideEffects(ctx, account.accountId, result);
        await noteReattach();
        return jsonResponse({ attached: result.added, alreadyAttached: plan.alreadyAttached, unreconstructable: plan.unreconstructable, conflicting: plan.conflicting, affects: plan.affects, malformed: plan.malformed, auditDeferred });
      } catch (e) {
        // G099: the re-attach path runs the SAME post-write safety harness, so it can raise the same alarms.
        const alarm = await recordBindingAlarmFrom(scheduler, e);
        // "reattach-missing keeps failing after the deploy wiped bindings" is the most consequential failure with
        // the heal for it broken, and it recorded nothing whatsoever. The classified cause lands here.
        await noteReattach(classifyAttachError(e, alarm), e);
        return jsonError((e as Error).message.slice(0, 300), 400);
      }
    }
    default:
      return null;
  }
}

// recordBindingAlarmFrom (G099) persists a TAGGED post-write binding-safety alarm into the DO's bounded ring.
// An untagged throw (an ordinary Cloudflare / token / plan refusal) records nothing, so only genuine
// post-write alarms ride. Best-effort and never throwing: the operator's refusal is already decided.
// Returns TRUE when the throw WAS a tagged post-write alarm, so the attach record (G131) can class it as
// "binding-alarm" -- the one class that means the write went through and the engine's bindings are now not
// what was intended, the most consequential failure mode, actually happening mid-heal.
async function recordBindingAlarmFrom(scheduler: DurableObjectStub, e: unknown): Promise<boolean> {
  const tag = bindingAlarmOf(e);
  if (tag === null) {
    // G099/G180: THE VERIFY THAT NEVER RAN. verifyAfter's alarms all mean "the post-write check ran and
    // DISAGREED". This is the other half: the PATCH landed and the re-read that was supposed to prove it did
    // not come back, so the change is neither proven safe nor proven unsafe -- it is simply unproven, in the
    // worst-outcome domain, with the safety harness blind. `postwrite-reread-failed` was declared for exactly
    // that and had no producer, so the bindingAlarms ring -- the ONE place a support engineer looks to ask "did
    // a settings write break this engine's bindings" -- read clean for it.
    //
    // It records ALONGSIDE the attach-health `verify-unread` class rather than replacing it, and returns FALSE
    // so classifyAttachError still files the attach as verify-unread: the two records answer different
    // questions (which attach failed, and how, versus what happened to the bindings), and collapsing this into
    // `binding-alarm` would claim the read-back disagreed when the truth is that it never answered. No binding
    // name is known here -- that is the whole point of the fault -- so the names list is honestly empty.
    if (attachRefusalClassOf(e) === "verify-unread") await recordBindingAlarm(scheduler, "postwrite-reread-failed", []);
    return false;
  }
  await recordBindingAlarm(scheduler, tag.kind, tag.names);
  return true;
}
