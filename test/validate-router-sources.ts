// Unit-prove the router-sources SPOKE (src/admin/router-sources.ts), a god-module split that
// holds source discovery, the engine-account resolvers, the signed-artefact fetcher, the run-destination
// fallback wrapper, the Cloudflare-API account/product listers, the best-effort role-invite email, and
// the dynamic-route matchers + the denied-role guard. The full router validators reach these only through
// routing, so the error/else/guard arms (a bad URL, a thrown send, an empty id, a list that pages, an
// account that 403s) stay unexercised. Here each export is driven DIRECTLY against in-memory doubles:
//   - a path-routing mock scheduler stub (DurableObjectStub) that answers /sources/discovery-config,
//     /downpipes, /downpipes/dests-for-run and /dest-config from a per-test script;
//   - a global fetch stub for the credentialed Cloudflare API (cfApi / resolveDiscoveryAccounts /
//     listAccountProducts / listPaged) and the signed-artefact fetch (fetchArtefactBytes);
//   - a recording / throwing EMAIL binding for sendRoleInvite.
// No network, no deploy, no real Cloudflare: every assertion drives a real code path and checks a real
// outcome. House rules: Australian English; precise claims.
//
// Run:
//   node test/validate-router-sources.ts

import {
  enumerateBoundSources,
  resolveEngineAccount,
  handleEstateSize,
  fetchArtefactBytes,
  resolveRunDestCandidates,
  withRunDestFallback,
  parseRoleEntry,
  sendRoleInvite,
  INVITE_SUBJECT,
  MAX_DISCOVERY_ACCOUNTS,
  cfApi,
  resolveDiscoveryAccounts,
  resolveEngineAccountId,
  listAccountProducts,
  matchConfigChangeAction,
  matchOwnerActionAction,
  isRoleString,
  type RoleInvite,
  type DiscoveryConfigView,
} from "../src/admin/router-sources.ts";
import { REASON_OBJECT_MISSING, REASON_DESTINATION_ACCESS, REASON_RECOVERY_CHECK, isReplicaFallbackReason } from "../src/restore-reasons.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- doubles -----------------------------------------------------------------------------------

// scriptedStub builds a DurableObjectStub whose fetch routes by URL path to a per-test responder. A
// responder may return a Response, OR throw (to drive the resolvers' fail-open catch arms). An unmatched
// path returns a 404, the honest "the DO has nothing here" answer the resolvers treat as a miss.
type Responder = (method: string, path: string, search: URLSearchParams) => Response | Promise<Response>;
function scriptedStub(routes: Record<string, Responder>): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const raw = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      const u = new URL(raw);
      const method = (init?.method ?? "GET").toUpperCase();
      const r = routes[u.pathname];
      if (r === undefined) return Promise.resolve(new Response("not found", { status: 404 }));
      return Promise.resolve(r(method, u.pathname, u.searchParams));
    },
  } as unknown as DurableObjectStub;
}
const json = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

// withFetch swaps the global fetch for the duration of fn (the credentialed Cloudflare API and the
// signed-artefact fetch both go through globalThis.fetch). It always restores the original.
async function withFetch<T>(stub: typeof fetch, fn: () => Promise<T>): Promise<T> {
  const orig = globalThis.fetch;
  globalThis.fetch = stub;
  try {
    return await fn();
  } finally {
    globalThis.fetch = orig;
  }
}

// recordingEmail is the in-memory CfEmailSend double: it records every message send() is handed.
function recordingEmail(): { binding: { send(m: unknown): Promise<{ messageId: string }> }; sent: Array<Record<string, unknown>> } {
  const sent: Array<Record<string, unknown>> = [];
  return {
    sent,
    binding: {
      async send(m: unknown): Promise<{ messageId: string }> {
        sent.push(m as Record<string, unknown>);
        return { messageId: "rec-1" };
      },
    },
  };
}

async function main(): Promise<void> {
  // ---- 1. enumerateBoundSources: classify env bindings by duck-type ------------------------------
  // Each tier is recognised by its method shape; reserved bindings and plain string vars/secrets are
  // excluded; a DO/email/service binding is skipped before any storage tier matches.
  {
    const noop = () => undefined;
    const r2 = { get: noop, put: noop, list: noop, head: noop, createMultipartUpload: noop };
    const kv = { get: noop, put: noop, list: noop, getWithMetadata: noop };
    const d1 = { prepare: noop, batch: noop, exec: noop };
    const secrets = { get: noop }; // get only, no put/prepare -> Secrets Store
    const doBinding = { idFromName: noop, get: noop }; // idFromName -> Durable Object namespace, skipped
    const emailBinding = { send: noop }; // send -> email binding, skipped
    const serviceBinding = { fetch: noop }; // fetch without get -> service binding, skipped
    const env = {
      SCHEDULER: doBinding, // RESERVED_BINDINGS -> skipped even though it duck-types as a DO
      MY_R2: r2,
      MY_KV: kv,
      MY_D1: d1,
      MY_SECRETS: secrets,
      MY_DO: doBinding,
      MY_EMAIL: emailBinding,
      MY_SVC: serviceBinding,
      A_STRING_VAR: "plain", // a string var is never auto-offered
      A_NULL: null, // null is skipped at the null/non-object guard
      A_NUMBER: 7, // a non-object is skipped
    } as unknown as Env;
    const out = enumerateBoundSources(env);
    ok("enumerateBoundSources classes R2 by its method shape", out.r2.length === 1 && out.r2[0] === "MY_R2");
    ok("enumerateBoundSources classes KV (getWithMetadata, no multipart)", out.kv.length === 1 && out.kv[0] === "MY_KV");
    ok("enumerateBoundSources classes D1 (prepare/batch/exec)", out.d1.length === 1 && out.d1[0] === "MY_D1");
    ok("enumerateBoundSources classes a Secrets Store (get only)", out.secrets.length === 1 && out.secrets[0] === "MY_SECRETS");
    ok("enumerateBoundSources skips a DO binding (idFromName)", !out.kv.includes("MY_DO") && !out.r2.includes("MY_DO") && !out.d1.includes("MY_DO") && !out.secrets.includes("MY_DO"));
    ok("enumerateBoundSources skips an email binding (send)", !out.secrets.includes("MY_EMAIL"));
    ok("enumerateBoundSources skips a service binding (fetch without get)", !out.secrets.includes("MY_SVC"));
    ok("enumerateBoundSources excludes the reserved SCHEDULER binding", !out.d1.includes("SCHEDULER") && !out.kv.includes("SCHEDULER"));
    ok("enumerateBoundSources never offers a plain string var", !out.secrets.includes("A_STRING_VAR"));

    // Two of the same tier sort lexically (the .sort() arms).
    const envSort = { B_KV: kv, A_KV: kv } as unknown as Env;
    const sorted = enumerateBoundSources(envSort);
    ok("enumerateBoundSources sorts each tier (A before B)", sorted.kv.length === 2 && sorted.kv[0] === "A_KV" && sorted.kv[1] === "B_KV");

    // A deploy-declared secrets_store_secret binding the Workers runtime exposes as a
    // NON-ENUMERABLE own property (the binding answers direct env[name]
    // access exactly like the enumerable case above, but Object.keys/Object.entries never lists it,
    // because those only walk OWN ENUMERABLE properties). buildAdapter (src/seal/adapters.ts:116) reads
    // secrets by direct `env[guard(sec.binding)]` access, so the run path backs this binding up fine; only
    // the enumerator that feeds the Sources screen and boundSourceCount misses it.
    const hiddenSecret = { get: noop };
    const envHidden: Record<string, unknown> = { MY_KV: kv };
    Object.defineProperty(envHidden, "MY_HIDDEN_SECRET", { value: hiddenSecret, enumerable: false, configurable: true });
    ok("setup: the hidden binding is invisible to Object.keys (proves the runtime shape)", !Object.keys(envHidden).includes("MY_HIDDEN_SECRET"));
    const directRead = envHidden.MY_HIDDEN_SECRET as { get: typeof noop } | undefined;
    ok("setup: the hidden binding still answers direct property access, exactly like the run path's env[binding] read", directRead?.get === noop);
    const outHidden = enumerateBoundSources(envHidden as unknown as Env);
    ok("enumerateBoundSources surfaces a non-enumerable Secrets Store binding", outHidden.secrets.includes("MY_HIDDEN_SECRET"));

    // An earlier attempted fix assumed the live binding's VALUE was typeof "function", widened the
    // value-type guard to accept it, and that premise turned out to be false: the real live binding is
    // typeof "object", not "function". That widening is REVERTED here (see the function's own header for
    // the full reasoning), so a typeof-"function" binding double is once again excluded before the
    // duck-type ladder runs.
    const callableSecret: Record<string, unknown> = (() => undefined) as unknown as Record<string, unknown>;
    (callableSecret as unknown as { get: typeof noop }).get = noop;
    ok("setup: the callable binding double is typeof \"function\" (the earlier, now-superseded fixture shape)", typeof callableSecret === "function");
    const envCallable = { MY_KV: kv, MY_CALLABLE_SECRET: callableSecret } as unknown as Env;
    const outCallable = enumerateBoundSources(envCallable);
    ok("enumerateBoundSources: the earlier widening is REVERTED -- a typeof-\"function\" value is excluded again, not surfaced as a secret", !outCallable.secrets.includes("MY_CALLABLE_SECRET"));
    ok("enumerateBoundSources still enumerates the object-typed KV binding alongside it", outCallable.kv.includes("MY_KV"));

    // The real live shape: a Secrets Store binding that answers typeof "function" for ALL TWELVE
    // method names this ladder checks (a generic, property-name-agnostic capability stub -- its own
    // Object.getOwnPropertyNames is empty), while every other live binding on the same account (KV, R2, D1,
    // three Durable Object bindings) matches exactly one coherent capability group and no other. This
    // fixture reproduces that shape directly, not a guess: a plain object (typeof "object", so it
    // reaches the ladder without needing the reverted widening above) whose get/put/list/head/
    // createMultipartUpload/getWithMetadata/prepare/batch/exec/idFromName/send all answer typeof
    // "function" at once.
    const genericStub: Record<string, unknown> = {};
    for (const m of ["get", "put", "list", "head", "createMultipartUpload", "getWithMetadata", "prepare", "batch", "exec", "idFromName", "send"]) genericStub[m] = noop;
    ok("setup: the generic-stub double is typeof \"object\" (the real live shape, not the earlier typeof \"function\" guess)", typeof genericStub === "object");
    const envStub = { MY_KV: kv, MY_GENERIC_STUB_SECRET: genericStub } as unknown as Env;
    const outStub = enumerateBoundSources(envStub);
    ok("enumerateBoundSources surfaces the generic-capability-stub Secrets Store binding as a secret", outStub.secrets.includes("MY_GENERIC_STUB_SECRET"));
    ok("enumerateBoundSources does NOT also file the stub under r2/kv/d1", !outStub.r2.includes("MY_GENERIC_STUB_SECRET") && !outStub.kv.includes("MY_GENERIC_STUB_SECRET") && !outStub.d1.includes("MY_GENERIC_STUB_SECRET"));
    ok("enumerateBoundSources still enumerates the real KV binding alongside the stub", outStub.kv.includes("MY_KV"));

    // The multi-group threshold (>= 3) has real headroom, not a coincidence of the one shape observed
    // live: a double that genuinely overlaps exactly TWO groups (KV's get/put/list/getWithMetadata AND
    // D1's prepare/batch/exec at once, a shape no real binding on the measured estate exhibited but which
    // this threshold must still not misclassify) stays on the normal ladder and is filed under its first
    // matching branch, not swept into secrets.
    const twoGroupOverlap: Record<string, unknown> = { get: noop, put: noop, list: noop, getWithMetadata: noop, prepare: noop, batch: noop, exec: noop };
    const envTwoGroup = { MY_TWO_GROUP: twoGroupOverlap } as unknown as Env;
    const outTwoGroup = enumerateBoundSources(envTwoGroup);
    ok("enumerateBoundSources: a double matching exactly two groups (below the >= 3 threshold) is NOT swept into secrets", !outTwoGroup.secrets.includes("MY_TWO_GROUP"));
    ok("enumerateBoundSources: it is classified under its first matching branch (KV) instead", outTwoGroup.kv.includes("MY_TWO_GROUP"));

    // The skip classes (DO / email / service) are unaffected for a binding that genuinely matches only its
    // own single group, exactly as before this fix.
    ok("enumerateBoundSources still skips a genuine DO binding (idFromName, one group only)", !out.secrets.includes("MY_DO") && !out.kv.includes("MY_DO"));
    ok("enumerateBoundSources still skips a genuine service binding (fetch, no get, one group only)", !out.secrets.includes("MY_SVC"));
  }

  // ---- 2. resolveEngineAccount: DO config wins, else env var, else null --------------------------
  {
    // The DO returns a config with a marked engineAccountId -> that wins, the env var is not consulted.
    const stubWithCfg = scriptedStub({ "/sources/discovery-config": () => json({ config: { engineAccountId: "acct-from-do" } }) });
    const aFromDo = await resolveEngineAccount({ CF_ACCOUNT_ID: "acct-from-env" } as unknown as Env, stubWithCfg);
    ok("resolveEngineAccount returns the DO config engineAccountId", aFromDo === "acct-from-do");

    // The DO has no engineAccountId -> fall through to the CF_ACCOUNT_ID env var (trimmed).
    const stubNoEngine = scriptedStub({ "/sources/discovery-config": () => json({ config: { engineAccountId: null } }) });
    const aFromEnv = await resolveEngineAccount({ CF_ACCOUNT_ID: "  acct-from-env  " } as unknown as Env, stubNoEngine);
    ok("resolveEngineAccount falls back to a trimmed CF_ACCOUNT_ID", aFromEnv === "acct-from-env");

    // The DO read THROWS -> the catch arm falls through to the env var.
    const stubThrows = scriptedStub({ "/sources/discovery-config": () => { throw new Error("DO down"); } });
    const aOnThrow = await resolveEngineAccount({ CF_ACCOUNT_ID: "acct-on-throw" } as unknown as Env, stubThrows);
    ok("resolveEngineAccount swallows a DO fault and uses the env var", aOnThrow === "acct-on-throw");

    // Neither the DO config nor a usable env var -> null (a blank env var trims to empty -> null).
    const aNone = await resolveEngineAccount({ CF_ACCOUNT_ID: "   " } as unknown as Env, stubNoEngine);
    ok("resolveEngineAccount returns null with no config and a blank env var", aNone === null);
  }

  // ---- 3. handleEstateSize: honest empty estate vs a real (analytics) estimate -------------------
  {
    // No account AND no token -> the early honest available:false estate (no analytics call).
    const stubNoCfg = scriptedStub({ "/sources/discovery-config": () => json({ config: null }) });
    const respNone = await handleEstateSize({} as unknown as Env, stubNoCfg);
    const bodyNone = (await respNone.json()) as { available: boolean; sourceCount: number };
    ok("handleEstateSize returns available:false when account+token are unknown", respNone.status === 200 && bodyNone.available === false && bodyNone.sourceCount === 0);

    // Account + token resolvable (both via env): the analytics path runs over the configured downpipes.
    // The DO's /downpipes lists one KV downpipe; cf-analytics calls go through global fetch, which we stub
    // to return a sized KV namespace so the estimate is non-empty and available:true.
    const stubWithDownpipes = scriptedStub({
      "/sources/discovery-config": () => json({ config: null }), // force the env-var fallback for account + token
      "/downpipes": () => json([
        { config: { source: { type: "kv", namespaceId: "ns-1" } } },
        { config: { source: { type: "r2", bucketName: "bkt-1" } } },
        { config: { source: { type: "d1" } } }, // d1 carries neither id -> exercises the no-id mapping arm
      ]),
    });
    const env = { CF_ACCOUNT_ID: "acct-1", DISCOVERY_API_TOKEN: "tok-ro" } as unknown as Env;
    // The cf-analytics KV size query is a GraphQL POST to api.cloudflare.com; any 2xx with a sized result
    // makes estimateSourceSize report "analytics". We answer every analytics call with one sized row so at
    // least one source is sized (available:true) without asserting the exact byte maths (that is cf-analytics'
    // own validator). Anything we cannot shape returns an empty result and degrades to "unavailable".
    const analyticsStub: typeof fetch = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url.includes("api.cloudflare.com")) {
        return json({ data: { viewer: { accounts: [{ kvOperationsAdaptiveGroups: [{ sum: { requests: 0 } }], kvStorageAdaptiveGroups: [{ max: { byteCount: 1024, keyCount: 4 } }], r2StorageAdaptiveGroups: [{ max: { payloadSize: 2048, metadataSize: 0, objectCount: 2 } }] }] } } });
      }
      return json({});
    };
    const respEstate = await withFetch(analyticsStub, () => handleEstateSize(env, stubWithDownpipes));
    const bodyEstate = (await respEstate.json()) as { available: boolean; sourceCount: number; perSource: unknown[] };
    ok("handleEstateSize reports available:true once account+token resolve", respEstate.status === 200 && bodyEstate.available === true);
    ok("handleEstateSize counts every configured source", bodyEstate.sourceCount === 3 && bodyEstate.perSource.length === 3);

    // The /downpipes read THROWS -> the inner catch yields an empty downpipe list (zero sources) but still
    // available:true (account+token were resolvable), proving the inner try/catch, not the outer one.
    const stubDownpipesThrow = scriptedStub({
      "/sources/discovery-config": () => json({ config: null }),
      "/downpipes": () => { throw new Error("list down"); },
    });
    const respInner = await withFetch(analyticsStub, () => handleEstateSize(env, stubDownpipesThrow));
    const bodyInner = (await respInner.json()) as { available: boolean; sourceCount: number };
    ok("handleEstateSize degrades a failed downpipe list to zero sources, still available", respInner.status === 200 && bodyInner.available === true && bodyInner.sourceCount === 0);

    // TOKEN VIA THE DO CONFIG: the discovery-config carries both a marked engineAccountId AND a token, so
    // resolveEngineAccount and resolveDiscoveryToken both resolve from the DO (not the env), exercising the
    // token-present arm of resolveDiscoveryToken. The analytics path then runs and reports available:true.
    const stubCfgToken = scriptedStub({
      "/sources/discovery-config": () => json({ config: { engineAccountId: "acct-do", token: "tok-do" } }),
      "/downpipes": () => json([{ config: { source: { type: "kv", namespaceId: "ns-1" } } }]),
    });
    const respCfgToken = await withFetch(analyticsStub, () => handleEstateSize({} as unknown as Env, stubCfgToken));
    const bodyCfgToken = (await respCfgToken.json()) as { available: boolean; sourceCount: number };
    ok("handleEstateSize resolves the token from the DO config and sizes the estate", respCfgToken.status === 200 && bodyCfgToken.available === true && bodyCfgToken.sourceCount === 1);

    // The discovery-config read THROWS for BOTH resolvers (account + token), so each falls through its
    // catch to the env var; with both env vars set the analytics path still runs (available:true). This
    // drives the resolveDiscoveryToken catch arm specifically.
    const stubCfgThrow = scriptedStub({
      "/sources/discovery-config": () => { throw new Error("config read down"); },
      "/downpipes": () => json([{ config: { source: { type: "kv", namespaceId: "ns-1" } } }]),
    });
    const respCfgThrow = await withFetch(analyticsStub, () => handleEstateSize(env, stubCfgThrow));
    const bodyCfgThrow = (await respCfgThrow.json()) as { available: boolean };
    ok("handleEstateSize falls back to the env token when the DO config read throws", respCfgThrow.status === 200 && bodyCfgThrow.available === true);

    // The OUTER catch: the /downpipes read succeeds (so the inner catch does not fire) but a row is
    // missing its `config`, so the sources `.map` throws a TypeError reading `d.config.source`. That throw
    // is outside the inner try, so it reaches the OUTER catch, which returns the honest empty available:false
    // estate rather than 500ing.
    const stubMalformedRow = scriptedStub({
      "/sources/discovery-config": () => json({ config: null }),
      "/downpipes": () => json([{ notConfig: true }]), // no `config` -> d.config.source throws in the map
    });
    const respOuter = await withFetch(analyticsStub, () => handleEstateSize(env, stubMalformedRow));
    const bodyOuter = (await respOuter.json()) as { available: boolean };
    ok("handleEstateSize outer catch returns an honest empty estate on a malformed downpipe row", respOuter.status === 200 && bodyOuter.available === false);
  }

  // ---- 4. fetchArtefactBytes: https-only, bounded, fail-null -------------------------------------
  {
    ok("fetchArtefactBytes returns null on an unparseable URL", (await fetchArtefactBytes("::::not a url")) === null);
    ok("fetchArtefactBytes refuses a non-https URL", (await fetchArtefactBytes("http://example.com/bundle")) === null);

    const okBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const okFetch: typeof fetch = async () => new Response(okBytes, { status: 200 });
    const got = await withFetch(okFetch, () => fetchArtefactBytes("https://example.com/bundle"));
    ok("fetchArtefactBytes returns the bytes on a clean 2xx https fetch", got !== null && got.length === 5 && got[0] === 1);

    const notOkFetch: typeof fetch = async () => new Response("nope", { status: 404 });
    ok("fetchArtefactBytes returns null on a non-2xx response", (await withFetch(notOkFetch, () => fetchArtefactBytes("https://example.com/x"))) === null);

    const emptyFetch: typeof fetch = async () => new Response(new Uint8Array(0), { status: 200 });
    ok("fetchArtefactBytes returns null on an empty body", (await withFetch(emptyFetch, () => fetchArtefactBytes("https://example.com/x"))) === null);

    // Over the 30 MiB cap -> null (the size bound). 30 MiB + 1 byte.
    const oversize = new Uint8Array(30 * 1024 * 1024 + 1);
    const bigFetch: typeof fetch = async () => new Response(oversize, { status: 200 });
    ok("fetchArtefactBytes returns null over the 30 MiB cap", (await withFetch(bigFetch, () => fetchArtefactBytes("https://example.com/big"))) === null);

    const throwFetch: typeof fetch = async () => { throw new Error("network"); };
    ok("fetchArtefactBytes swallows a thrown fetch and returns null", (await withFetch(throwFetch, () => fetchArtefactBytes("https://example.com/x"))) === null);
  }

  // ---- 5. resolveRunDestCandidates: explicit | DO list | default --------------------------------
  {
    const anyStub = scriptedStub({});
    ok("resolveRunDestCandidates returns [explicit] when an override is given", JSON.stringify(await resolveRunDestCandidates(anyStub, "run-1", "dest-X")) === JSON.stringify(["dest-X"]));
    ok("resolveRunDestCandidates returns [undefined] for an empty runId", JSON.stringify(await resolveRunDestCandidates(anyStub, "")) === JSON.stringify([undefined]));

    const stubList = scriptedStub({ "/downpipes/dests-for-run": () => json({ destinationIds: ["primary", "replica"] }) });
    ok("resolveRunDestCandidates returns the DO destination list (primary then replica)", JSON.stringify(await resolveRunDestCandidates(stubList, "run-1")) === JSON.stringify(["primary", "replica"]));

    // The DO returns ok but an EMPTY list -> fall through to the default [undefined].
    const stubEmpty = scriptedStub({ "/downpipes/dests-for-run": () => json({ destinationIds: [] }) });
    ok("resolveRunDestCandidates falls back to the default on an empty DO list", JSON.stringify(await resolveRunDestCandidates(stubEmpty, "run-1")) === JSON.stringify([undefined]));

    // The DO returns a NON-ok status -> the default.
    const stubNotOk = scriptedStub({ "/downpipes/dests-for-run": () => json({}, 500) });
    ok("resolveRunDestCandidates falls back to the default on a non-ok DO response", JSON.stringify(await resolveRunDestCandidates(stubNotOk, "run-1")) === JSON.stringify([undefined]));

    // The DO read THROWS -> the catch arm -> the default.
    const stubThrow = scriptedStub({ "/downpipes/dests-for-run": () => { throw new Error("boom"); } });
    ok("resolveRunDestCandidates falls back to the default when the DO read throws", JSON.stringify(await resolveRunDestCandidates(stubThrow, "run-1")) === JSON.stringify([undefined]));
  }

  // ---- 6. withRunDestFallback: try each destination until one is not "object missing" -------------
  // fetchDestConfig (called inside the wrapper) reads /dest-config?id=... from the stub; we answer with a
  // COMPLETE stored destination so it returns a non-null config without throwing, then the op decides.
  {
    const completeDest = { endpoint: "https://s3.example", bucket: "b", region: "us-east-1", accessKeyId: "AK", secretAccessKey: "SK" };
    const destStub = scriptedStub({
      "/downpipes/dests-for-run": () => json({ destinationIds: ["primary", "replica"] }),
      "/dest-config": () => json({ config: completeDest }),
    });

    // The PRIMARY succeeds first -> the replica is never tried (one op invocation).
    let calls = 0;
    const firstOk = await withRunDestFallback(destStub, "run-1", undefined, async () => { calls++; return { ok: true }; });
    ok("withRunDestFallback returns the first success without trying the replica", firstOk.ok === true && calls === 1);

    // The PRIMARY is "object missing" -> the wrapper retries the replica, which succeeds (the 3-2-1 payoff).
    let attempt = 0;
    const failedOver = await withRunDestFallback(destStub, "run-1", undefined, async () => {
      attempt++;
      return attempt === 1 ? { ok: false, reason: "object missing" } : { ok: true };
    });
    ok("withRunDestFallback falls over to the replica on object-missing and then succeeds", failedOver.ok === true && attempt === 2);

    // A NON-object-missing failure returns immediately (no fallback masks a real fault: integrity/access).
    let stops = 0;
    const hardFail = await withRunDestFallback(destStub, "run-1", undefined, async () => { stops++; return { ok: false, reason: "integrity" }; });
    ok("withRunDestFallback returns a non-object-missing failure immediately (no masking)", hardFail.ok === false && stops === 1);

    // EVERY candidate is object-missing -> the wrapper returns the LAST result (still a failure), having
    // exhausted both destinations.
    let allMiss = 0;
    const exhausted = await withRunDestFallback(destStub, "run-1", undefined, async () => { allMiss++; return { ok: false, reason: "object missing" }; });
    ok("withRunDestFallback returns the last result after exhausting all candidates", (exhausted as { reason?: string }).reason === "object missing" && allMiss === 2);

    // A3: AVAILABILITY failures beyond a bare 404 must ALSO fall over to a replica. The most common real
    // DR failures on the primary are a 403 (revoked/rotated credentials) or a 5xx (provider outage), both
    // classified as REASON_DESTINATION_ACCESS, and a network/transport fault, classified as
    // REASON_RECOVERY_CHECK. RED-BEFORE-GREEN: the OLD wrapper fell back ONLY on "object missing", so for
    // each of these the primary failure would have surfaced outright and the healthy replica never read.
    for (const availReason of [REASON_DESTINATION_ACCESS, REASON_RECOVERY_CHECK]) {
      let tries = 0;
      const recovered = await withRunDestFallback(destStub, "run-1", undefined, async () => {
        tries++;
        return tries === 1 ? { ok: false, reason: availReason } : { ok: true };
      });
      ok(`withRunDestFallback falls over to a healthy replica when the primary fails with "${availReason}" and then succeeds`, recovered.ok === true && tries === 2);
    }

    // A3 INTEGRITY GUARD: a TAMPER / verification failure on the primary is a real corruption signal, NOT a
    // missing object. It must surface IMMEDIATELY and NEVER silently fall back to a replica (which could mask
    // the corruption). The exact classifier literal is "integrity check failed".
    let tamperTries = 0;
    const tampered = await withRunDestFallback(destStub, "run-1", undefined, async () => { tamperTries++; return { ok: false, reason: "integrity check failed" }; });
    ok("withRunDestFallback surfaces an integrity/verification failure immediately and does NOT fall back to a replica", tampered.ok === false && (tampered as { reason?: string }).reason === "integrity check failed" && tamperTries === 1);

    // A freshness fault (the anti-rollback verifier) is likewise not an availability fault: it surfaces.
    let freshTries = 0;
    const fresh = await withRunDestFallback(destStub, "run-1", undefined, async () => { freshTries++; return { ok: false, reason: "freshness check failed" }; });
    ok("withRunDestFallback surfaces a freshness failure immediately (no replica fallback)", fresh.ok === false && freshTries === 1);
  }

  // ---- 6b. isReplicaFallbackReason: the availability-vs-integrity split is the single source of truth ----
  {
    ok("isReplicaFallbackReason is TRUE for object missing (404)", isReplicaFallbackReason(REASON_OBJECT_MISSING) === true);
    ok("isReplicaFallbackReason is TRUE for destination access error (403/5xx)", isReplicaFallbackReason(REASON_DESTINATION_ACCESS) === true);
    ok("isReplicaFallbackReason is TRUE for recovery check failed (network/transport)", isReplicaFallbackReason(REASON_RECOVERY_CHECK) === true);
    ok("isReplicaFallbackReason is FALSE for an integrity/verification failure (no masking corruption)", isReplicaFallbackReason("integrity check failed") === false);
    ok("isReplicaFallbackReason is FALSE for a freshness failure", isReplicaFallbackReason("freshness check failed") === false);
    ok("isReplicaFallbackReason is FALSE for engine-not-configured", isReplicaFallbackReason("engine not fully configured") === false);
    ok("isReplicaFallbackReason is FALSE for a record-scope miss", isReplicaFallbackReason("record not found in run") === false);
    ok("isReplicaFallbackReason is FALSE for an undefined reason", isReplicaFallbackReason(undefined) === false);
  }

  // ---- 7. parseRoleEntry: narrow the DO body or null on any surprise -----------------------------
  {
    ok("parseRoleEntry returns null on invalid JSON", parseRoleEntry("{not json") === null);
    ok("parseRoleEntry returns null for a JSON null", parseRoleEntry("null") === null);
    ok("parseRoleEntry returns null for a non-object (a JSON array)", parseRoleEntry("[1,2]") === null);
    ok("parseRoleEntry returns null when email is missing", parseRoleEntry(JSON.stringify({ role: "viewer" })) === null);
    ok("parseRoleEntry returns null when email is empty", parseRoleEntry(JSON.stringify({ email: "", role: "viewer" })) === null);
    ok("parseRoleEntry returns null when role is not a string", parseRoleEntry(JSON.stringify({ email: "a@b.co", role: 7 })) === null);

    const plain = parseRoleEntry(JSON.stringify({ email: "a@b.co", role: "operator" }));
    ok("parseRoleEntry narrows a minimal entry (no customRole, no token)", plain !== null && plain.email === "a@b.co" && plain.role === "operator" && plain.customRole === undefined && plain.inviteToken === undefined);

    // A non-string / empty customRole is dropped; a present one is carried.
    const droppedCustom = parseRoleEntry(JSON.stringify({ email: "a@b.co", role: "viewer", customRole: "" }));
    ok("parseRoleEntry drops an empty customRole", droppedCustom !== null && droppedCustom.customRole === undefined);
    const withCustom = parseRoleEntry(JSON.stringify({ email: "a@b.co", role: "viewer", customRole: "Auditors" }));
    ok("parseRoleEntry carries a non-empty customRole", withCustom !== null && withCustom.customRole === "Auditors");

    // An empty inviteToken is dropped; a present one is carried.
    const droppedTok = parseRoleEntry(JSON.stringify({ email: "a@b.co", role: "viewer", inviteToken: "" }));
    ok("parseRoleEntry drops an empty inviteToken", droppedTok !== null && droppedTok.inviteToken === undefined);
    const withTok = parseRoleEntry(JSON.stringify({ email: "a@b.co", role: "viewer", inviteToken: "tok-123" }));
    ok("parseRoleEntry carries a non-empty inviteToken", withTok !== null && withTok.inviteToken === "tok-123");
  }

  // ---- 8. sendRoleInvite: off-unless-configured, validated, fail-open -----------------------------
  {
    const recipient: RoleInvite = { email: "grantee@customer.example", role: "operator" };

    // OFF: no EMAIL binding at all.
    ok("sendRoleInvite is off (no EMAIL binding)", (await sendRoleInvite({} as unknown as Env, recipient)).reason === "invite-not-configured");
    // OFF: an EMAIL binding whose send is not a function.
    ok("sendRoleInvite is off when EMAIL has no send()", (await sendRoleInvite({ EMAIL: {} } as unknown as Env, recipient)).reason === "invite-not-configured");

    const rec = recordingEmail();
    // OFF: a bound EMAIL but no INVITE_EMAIL_FROM (the invite is a separate opt-in from EMAIL_FROM).
    ok("sendRoleInvite is off without INVITE_EMAIL_FROM", (await sendRoleInvite({ EMAIL: rec.binding } as unknown as Env, recipient)).reason === "invite-from-not-configured");
    // OFF: an INVITE_EMAIL_FROM that is only whitespace.
    ok("sendRoleInvite is off when INVITE_EMAIL_FROM is blank", (await sendRoleInvite({ EMAIL: rec.binding, INVITE_EMAIL_FROM: "   " } as unknown as Env, recipient)).reason === "invite-from-not-configured");
    // INVALID sender (a workers.dev address fails the custom-domain rule).
    ok("sendRoleInvite rejects an invalid sender address", (await sendRoleInvite({ EMAIL: rec.binding, INVITE_EMAIL_FROM: "noreply@maelstrom.workers.dev" } as unknown as Env, recipient)).reason === "invite-from-invalid");
    // INVALID recipient (the grantee is not a custom-domain address).
    const badRecipient: RoleInvite = { email: "user@localhost", role: "viewer" };
    ok("sendRoleInvite rejects an invalid recipient address", (await sendRoleInvite({ EMAIL: rec.binding, INVITE_EMAIL_FROM: "alerts@maelstrom.au" } as unknown as Env, badRecipient)).reason === "invite-recipient-invalid");

    // SENT, plain sign-in pointer: configured, valid sender + recipient, no inviteToken, no CONSOLE_ORIGIN
    // -> the generic-origin "Sign in at your Downpipes console." body.
    const r1 = recordingEmail();
    const sentPlain = await sendRoleInvite({ EMAIL: r1.binding, INVITE_EMAIL_FROM: "alerts@maelstrom.au" } as unknown as Env, recipient);
    ok("sendRoleInvite sends a plain invite when configured", sentPlain.sent === true && r1.sent.length === 1);
    ok("sendRoleInvite uses the fixed redaction-safe subject", r1.sent[0]!.subject === INVITE_SUBJECT);
    ok("sendRoleInvite names the built-in role and the generic origin (no CONSOLE_ORIGIN)", typeof r1.sent[0]!.text === "string" && (r1.sent[0]!.text as string).includes("operator role") && (r1.sent[0]!.text as string).includes("your Downpipes console"));
    ok("sendRoleInvite addresses the validated single recipient", r1.sent[0]!.to === "grantee@customer.example" && r1.sent[0]!.from === "alerts@maelstrom.au");
    const h1 = (r1.sent[0]!.html ?? "") as string;
    ok("sendRoleInvite html is the branded card with no vendor sign-off", typeof r1.sent[0]!.html === "string" && h1.includes("<!doctype html>") && h1.includes(">downpipes</div>") && !/O'Connor|Maelstrom/.test(h1));
    ok("sendRoleInvite html names the role and, with no origin URL, shows no button", h1.includes("operator role") && !h1.includes('dp-btn" bgcolor'));

    // The custom-role label wins over the built-in role when a customRole is present.
    const r2 = recordingEmail();
    await sendRoleInvite({ EMAIL: r2.binding, INVITE_EMAIL_FROM: "alerts@maelstrom.au" } as unknown as Env, { email: "grantee@customer.example", role: "viewer", customRole: "Auditors" });
    ok("sendRoleInvite names the custom-role label over the built-in role", (r2.sent[0]!.text as string).includes("Auditors role") && !(r2.sent[0]!.text as string).includes("viewer role"));

    // REGISTER LINK: CONSOLE_ORIGIN set AND an inviteToken present -> the register-link body.
    const r3 = recordingEmail();
    await sendRoleInvite({ EMAIL: r3.binding, INVITE_EMAIL_FROM: "alerts@maelstrom.au", CONSOLE_ORIGIN: "https://console.customer.example" } as unknown as Env, { email: "grantee@customer.example", role: "operator", inviteToken: "abc 123" });
    const linkText = r3.sent[0]!.text as string;
    ok("sendRoleInvite includes a register link when origin+token are present", linkText.includes("https://console.customer.example/#/register?invite=abc%20123") && linkText.includes("Set up your passkey"));
    const h3 = (r3.sent[0]!.html ?? "") as string;
    ok("sendRoleInvite html carries the register link in a CTA button", h3.includes("register?invite=abc%20123") && h3.includes('dp-btn" bgcolor'));

    // CONSOLE_ORIGIN set but NO token -> the sign-in pointer at the real origin (the originSet && token === undefined arm).
    const r4 = recordingEmail();
    await sendRoleInvite({ EMAIL: r4.binding, INVITE_EMAIL_FROM: "alerts@maelstrom.au", CONSOLE_ORIGIN: "https://console.customer.example" } as unknown as Env, recipient);
    ok("sendRoleInvite uses the configured origin without a token (no register link)", (r4.sent[0]!.text as string).includes("Sign in at https://console.customer.example.") && !(r4.sent[0]!.text as string).includes("/#/register"));

    // FAIL-OPEN: a throwing send is swallowed and returns the coarse reason, never throwing.
    const thrower = { send: async () => { throw new Error("relay refused"); } };
    const failed = await sendRoleInvite({ EMAIL: thrower, INVITE_EMAIL_FROM: "alerts@maelstrom.au" } as unknown as Env, recipient);
    ok("sendRoleInvite swallows a thrown send (fail-open) with a coarse reason", failed.sent === false && failed.reason === "invite-send-failed");
  }

  // ---- 9. cfApi: credentialed, redirect:manual, throws on non-ok --------------------------------
  {
    // A 2xx returns the parsed JSON; the Bearer token is on the request and redirect is manual.
    let seenAuth = "";
    let seenRedirect: RequestRedirect | undefined;
    const apiOk: typeof fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      seenAuth = (init?.headers as Record<string, string>)?.authorization ?? "";
      seenRedirect = init?.redirect;
      return json({ ok: true, url });
    };
    const body = await withFetch(apiOk, () => cfApi("tok-secret")("/accounts"));
    ok("cfApi returns the parsed JSON on a 2xx", (body as { ok: boolean }).ok === true);
    ok("cfApi sends the Bearer token", seenAuth === "Bearer tok-secret");
    ok("cfApi never follows a redirect (redirect:manual)", seenRedirect === "manual");

    // A non-ok response throws `HTTP <status>` (a 3xx surfaces as non-ok under redirect:manual too).
    const apiBad: typeof fetch = async () => new Response("denied", { status: 403 });
    let threw = "";
    try {
      await withFetch(apiBad, () => cfApi("t")("/accounts"));
    } catch (e) {
      threw = (e as Error).message;
    }
    ok("cfApi throws HTTP <status> on a non-ok response", threw === "HTTP 403");
  }

  // ---- 10. resolveDiscoveryAccounts: always asks the live API | list | empty | error -------------
  {
    // CF_ACCOUNT_ID set no longer short-circuits the API call -- resolveDiscoveryAccounts must
    // always consult the token's real reach, even when a pin is configured, so a wrong-account or
    // garbage-shaped token is never reported as "1 account visible".
    const withPinFetch: typeof fetch = async () => json({ result: [{ id: "acct-real", name: "Real" }] });
    const withPin = await withFetch(withPinFetch, () => resolveDiscoveryAccounts("tok", { CF_ACCOUNT_ID: "  acct-pinned  " } as unknown as Env));
    ok("resolveDiscoveryAccounts still calls the API when CF_ACCOUNT_ID is set", withPin.accounts.length === 1 && withPin.accounts[0]!.id === "acct-real");
    ok("resolveDiscoveryAccounts does not fabricate the pinned id as an account", !withPin.accounts.some((a) => a.id === "acct-pinned"));

    // No pin -> list via the API; an account with no name falls back to its id as the name.
    const listFetch: typeof fetch = async () => json({ result: [{ id: "a1", name: "Acme" }, { id: "a2" }, { id: "", name: "skip-blank-id" }, { name: "skip-no-id" }] });
    const listed = await withFetch(listFetch, () => resolveDiscoveryAccounts("tok", {} as unknown as Env));
    ok("resolveDiscoveryAccounts lists accounts and keeps only string non-empty ids", listed.accounts.length === 2 && listed.accounts[0]!.id === "a1");
    ok("resolveDiscoveryAccounts falls back to the id as the name when name is missing", listed.accounts[1]!.id === "a2" && listed.accounts[1]!.name === "a2");

    // The token sees ZERO accounts -> the honest "cannot list any account" error.
    const emptyFetch: typeof fetch = async () => json({ result: [] });
    const empty = await withFetch(emptyFetch, () => resolveDiscoveryAccounts("tok", {} as unknown as Env));
    ok("resolveDiscoveryAccounts reports the no-account error on an empty list", empty.accounts.length === 0 && empty.errors.some((e) => e.includes("cannot list any account")));

    // A missing result field (undefined) exercises the `?? []` nullish fallback (no throw, zero accounts).
    const noResultFetch: typeof fetch = async () => json({});
    const noResult = await withFetch(noResultFetch, () => resolveDiscoveryAccounts("tok", {} as unknown as Env));
    ok("resolveDiscoveryAccounts treats a missing result as zero accounts", noResult.accounts.length === 0 && noResult.errors.length === 1);

    // The API THROWS (cfApi's HTTP throw) -> the catch arm records `accounts: <message>`.
    const apiThrow: typeof fetch = async () => new Response("x", { status: 500 });
    const errored = await withFetch(apiThrow, () => resolveDiscoveryAccounts("tok", {} as unknown as Env));
    ok("resolveDiscoveryAccounts records an account-list error on an API failure", errored.accounts.length === 0 && errored.errors.some((e) => e.startsWith("accounts: ")));
  }

  // ---- 11. resolveEngineAccountId: marked | env | single-visible | ambiguous | none --------------
  {
    // The marked engineAccountId wins.
    const marked = await resolveEngineAccountId({} as unknown as Env, { engineAccountId: "marked-acct" } as DiscoveryConfigView);
    ok("resolveEngineAccountId returns the marked engineAccountId", marked === "marked-acct");

    // No mark, but CF_ACCOUNT_ID is set -> the env var (trimmed).
    const fromEnv = await resolveEngineAccountId({ CF_ACCOUNT_ID: " env-acct " } as unknown as Env, { engineAccountId: null } as unknown as DiscoveryConfigView);
    ok("resolveEngineAccountId falls back to a trimmed CF_ACCOUNT_ID", fromEnv === "env-acct");

    // No mark, no env var, and NO token anywhere -> null (the honest in-console prompt case).
    const noToken = await resolveEngineAccountId({} as unknown as Env, null);
    ok("resolveEngineAccountId returns null with no mark, env or token", noToken === null);

    // A discovery token that sees EXACTLY ONE account -> that account is unambiguously the engine's own.
    const oneFetch: typeof fetch = async () => json({ result: [{ id: "only-acct", name: "Solo" }] });
    const single = await withFetch(oneFetch, () => resolveEngineAccountId({} as unknown as Env, { token: "tok" } as DiscoveryConfigView));
    ok("resolveEngineAccountId resolves the single visible account from the config token", single === "only-acct");

    // The token comes from the ENV (DISCOVERY_API_TOKEN) when the config has none, and resolves one account.
    const singleEnv = await withFetch(oneFetch, () => resolveEngineAccountId({ DISCOVERY_API_TOKEN: "env-tok" } as unknown as Env, null));
    ok("resolveEngineAccountId uses DISCOVERY_API_TOKEN when the config has no token", singleEnv === "only-acct");

    // MORE than one visible account -> ambiguous -> null (do not guess).
    const twoFetch: typeof fetch = async () => json({ result: [{ id: "a1", name: "One" }, { id: "a2", name: "Two" }] });
    const ambiguous = await withFetch(twoFetch, () => resolveEngineAccountId({} as unknown as Env, { token: "tok" } as DiscoveryConfigView));
    ok("resolveEngineAccountId stays null when more than one account is visible", ambiguous === null);

    // resolveDiscoveryAccounts returns zero accounts on an API failure -> length !== 1 -> the resolver
    // returns null. A blank CF_ACCOUNT_ID forces the API path; the API rejecting hard makes
    // resolveDiscoveryAccounts record an error and return zero accounts (it does NOT throw, because the
    // fetch failure is caught inside resolveDiscoveryAccounts' own try). So this exercises the empty-list
    // arm, not the resolver's catch.
    const hardThrow: typeof fetch = async () => { throw new Error("dns"); };
    const onThrow = await withFetch(hardThrow, () => resolveEngineAccountId({} as unknown as Env, { token: "tok" } as DiscoveryConfigView));
    ok("resolveEngineAccountId returns null when account resolution fails", onThrow === null);

    // A non-string CF_ACCOUNT_ID (a number here) fails resolveEngineAccountId's own
    // `typeof env.CF_ACCOUNT_ID === "string"` guard, so envAccount stays null and execution falls
    // through to the token-based resolution rather than crashing on a malformed env var.
    // resolveDiscoveryAccounts no longer reads env.CF_ACCOUNT_ID at all (the removed pinned
    // short-circuit was its only reader), so a bad env shape here can no longer make it throw --
    // this now proves the type guard alone routes around it, stubbed so it never touches a real
    // network.
    const badEnvFetch: typeof fetch = async () => json({ result: [{ id: "only-acct-2", name: "Solo2" }] });
    const resolverFallthrough = await withFetch(badEnvFetch, () => resolveEngineAccountId({ CF_ACCOUNT_ID: 12345 } as unknown as Env, { token: "tok" } as DiscoveryConfigView));
    ok("resolveEngineAccountId falls through a non-string CF_ACCOUNT_ID to token resolution", resolverFallthrough === "only-acct-2");
  }

  // ---- 12. listAccountProducts: per-product fail-open + pagination -------------------------------
  {
    // A single page per product (each list under its cap) with a couple of malformed rows that the type
    // guards drop, proving the typeof filters. zones, kv, r2, d1 and secret stores are all populated.
    const oneStorePage = (path: string): unknown => {
      if (path.includes("/storage/kv/namespaces")) return { result: [{ id: "kv1", title: "alpha" }, { id: "kv2", title: "beta" }, { id: 7, title: "drop-bad-id" }], result_info: { total_pages: 1 } };
      if (path.includes("/r2/buckets")) return { result: { buckets: [{ name: "zulu" }, { name: "alpha" }, { notname: "drop" }] }, result_info: { total_pages: 1 } };
      if (path.includes("/d1/database")) return { result: [{ uuid: "d1", name: "db-b" }, { uuid: "d2", name: "db-a" }], result_info: { total_pages: 1 } };
      if (path.includes("/secrets_store/stores/")) return { result: [{ name: "S_TOKEN" }, { notname: 1 }], result_info: { total_pages: 1 } };
      if (path.includes("/secrets_store/stores")) return { result: [{ id: "store-1" }, { notid: 1 }], result_info: { total_pages: 1 } };
      if (path.includes("/zones")) return { result: [{ id: "z1", name: "two.example" }, { id: "z2", name: "one.example" }], result_info: { total_pages: 1 } };
      return { result: [], result_info: { total_pages: 1 } };
    };
    const okFetch: typeof fetch = async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return json(oneStorePage(url));
    };
    const listing = await withFetch(okFetch, () => listAccountProducts("tok", "acct-1"));
    ok("listAccountProducts lists KV and drops a non-string id", listing.kv.length === 2 && listing.kv.every((n) => typeof n.id === "string"));
    ok("listAccountProducts lists R2 buckets and sorts them (alpha before zulu)", listing.r2.length === 2 && listing.r2[0]!.name === "alpha" && listing.r2[1]!.name === "zulu");
    ok("listAccountProducts lists D1 and sorts by name (db-a before db-b)", listing.d1.length === 2 && listing.d1[0]!.name === "db-a");
    ok("listAccountProducts walks a secret store and records its secrets with the storeId", listing.secrets.length === 1 && listing.secrets[0]!.storeId === "store-1" && listing.secrets[0]!.name === "S_TOKEN");
    ok("listAccountProducts lists zones and sorts them (one before two)", listing.zones.length === 2 && listing.zones[0]!.name === "one.example");
    ok("listAccountProducts reports no errors when every product lists cleanly", listing.errors.length === 0);

    // Per-product FAIL-OPEN: each list endpoint 403s independently -> a coarse `<product>: HTTP 403` error
    // string per product, never a thrown route. Every list is empty but the call still resolves.
    const allDeny: typeof fetch = async () => new Response("denied", { status: 403 });
    const denied = await withFetch(allDeny, () => listAccountProducts("tok", "acct-1"));
    ok("listAccountProducts is fail-open: an error string per product, no throw", denied.kv.length === 0 && denied.r2.length === 0 && denied.d1.length === 0 && denied.zones.length === 0);
    ok("listAccountProducts records the kv error string", denied.errors.some((e) => e.startsWith("kv: ")));
    ok("listAccountProducts records the r2 error string", denied.errors.some((e) => e.startsWith("r2: ")));
    ok("listAccountProducts records the d1 error string", denied.errors.some((e) => e.startsWith("d1: ")));
    ok("listAccountProducts records the secrets-store error string", denied.errors.some((e) => e.startsWith("secrets-store: ")));
    ok("listAccountProducts records the zones error string", denied.errors.some((e) => e.startsWith("zones: ")));
  }

  // ---- 12b. listPaged paging models (driven through listAccountProducts) -------------------------
  {
    // CURSOR style (R2): first page returns a cursor, second page returns an empty cursor (exhausted).
    // The page-style products return a single page so they do not interfere.
    let r2Calls = 0;
    const cursorFetch: typeof fetch = async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url.includes("/r2/buckets")) {
        r2Calls++;
        if (!url.includes("cursor=")) return json({ result: { buckets: [{ name: "b1" }] }, result_info: { cursors: { after: "CUR2" } } });
        return json({ result: { buckets: [{ name: "b2" }] }, result_info: { cursors: { after: "" } } }); // empty cursor -> exhausted
      }
      return json({ result: [], result_info: { total_pages: 1 } });
    };
    const paged = await withFetch(cursorFetch, () => listAccountProducts("tok", "acct-1"));
    ok("listPaged follows an R2 cursor across two pages then stops on an empty cursor", paged.r2.length === 2 && r2Calls === 2 && paged.r2.some((b) => b.name === "b1") && paged.r2.some((b) => b.name === "b2"));

    // PAGE style with total_pages: KV reports total_pages:2 and returns one item per page; the loop stops
    // once page >= total_pages (the page-style-exhausted arm via the total_pages branch).
    let kvCalls = 0;
    const pageFetch: typeof fetch = async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url.includes("/storage/kv/namespaces")) {
        kvCalls++;
        const page = new URL(url).searchParams.get("page");
        return json({ result: [{ id: `kv-${page}`, title: `ns-${page}` }], result_info: { total_pages: 2 } });
      }
      return json({ result: [], result_info: { total_pages: 1 } });
    };
    const pagedKv = await withFetch(pageFetch, () => listAccountProducts("tok", "acct-1"));
    ok("listPaged follows page-based result_info across two pages then stops at total_pages", pagedKv.kv.length === 2 && kvCalls === 2);

    // PAGE style WITHOUT total_pages: a full page (100 items) is followed; a short page (< per) stops.
    // d1 returns a full first page then a short second page (the batch.length < per exhausted arm).
    let d1Calls = 0;
    const noTotalFetch: typeof fetch = async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url.includes("/d1/database")) {
        d1Calls++;
        const page = Number(new URL(url).searchParams.get("page") ?? "1");
        if (page === 1) return json({ result: Array.from({ length: 100 }, (_v, i) => ({ uuid: `u${i}`, name: `db${String(i).padStart(3, "0")}` })) }); // full page, no result_info
        return json({ result: [{ uuid: "u-last", name: "db-last" }] }); // short page -> exhausted
      }
      return json({ result: [], result_info: { total_pages: 1 } });
    };
    const pagedD1 = await withFetch(noTotalFetch, () => listAccountProducts("tok", "acct-1"));
    ok("listPaged follows a full page then stops on a short page with no total_pages", pagedD1.d1.length === 101 && d1Calls === 2);

    // CURSOR via the FLAT result_info.cursor field (the other arm of `cursor ?? cursors.after`): R2 returns
    // result_info.cursor directly on the first page, then an empty one. The R2 pick still reads result.buckets.
    let flatR2 = 0;
    const flatCursorFetch: typeof fetch = async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url.includes("/r2/buckets")) {
        flatR2++;
        if (!url.includes("cursor=")) return json({ result: { buckets: [{ name: "fb1" }] }, result_info: { cursor: "FLAT2" } });
        return json({ result: { buckets: [{ name: "fb2" }] }, result_info: { cursor: "" } });
      }
      return json({ result: [], result_info: { total_pages: 1 } });
    };
    const flatPaged = await withFetch(flatCursorFetch, () => listAccountProducts("tok", "acct-1"));
    ok("listPaged follows the flat result_info.cursor field across pages", flatPaged.r2.length === 2 && flatR2 === 2);

    // PICK NULLISH FALLBACK: every product returns a 200 with NO `result` field, so each `pick` hits its
    // `?? []` arm and yields zero rows without erroring (no error string is recorded, unlike a 403). The
    // secrets path returns one store (so the per-store secrets pick runs) but that store's secrets body has
    // no `result` either, exercising both the stores pick and the per-store secrets `?? []`.
    const noResultBodies: typeof fetch = async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url.includes("/secrets_store/stores/")) return json({ result_info: { total_pages: 1 } }); // a store's secrets: no result
      if (url.includes("/secrets_store/stores")) return json({ result: [{ id: "store-1" }], result_info: { total_pages: 1 } }); // one store so the inner pick runs
      return json({ result_info: { total_pages: 1 } }); // kv / r2 / d1 / zones: no result at all
    };
    const blank = await withFetch(noResultBodies, () => listAccountProducts("tok", "acct-1"));
    ok("listPaged pick falls back to [] when a body has no result (kv/r2/d1/zones empty)", blank.kv.length === 0 && blank.r2.length === 0 && blank.d1.length === 0 && blank.zones.length === 0);
    ok("listPaged secrets pick falls back to [] when a store has no secrets result", blank.secrets.length === 0);
    ok("a no-result body is not an error (no error strings recorded)", blank.errors.length === 0);

    // The STORES pick `?? []` fallback specifically: the stores listing body itself has no `result`, so
    // zero stores are walked and the per-store secrets fetch never runs. The other products list cleanly so
    // only the secrets path is affected.
    const noStoresResult: typeof fetch = async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url.includes("/secrets_store/stores")) return json({ result_info: { total_pages: 1 } }); // no result -> the stores pick falls back to []
      return json({ result: [], result_info: { total_pages: 1 } });
    };
    const noStores = await withFetch(noStoresResult, () => listAccountProducts("tok", "acct-1"));
    ok("listPaged stores pick falls back to [] when the stores body has no result", noStores.secrets.length === 0 && !noStores.errors.some((e) => e.startsWith("secrets-store: ")));

    // LOOP-BOUND EXHAUSTION (the `return items` after the for loop): a cursor that NEVER empties and never
    // reaches CAP makes the loop run to its maxPages bound (ceil(500/100)+2 = 7) and then return what it has.
    // R2 returns one bucket per page with a fresh, always-present cursor, so the bound (not a cursor/cap) stops it.
    let unbounded = 0;
    const neverEmptyCursor: typeof fetch = async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url.includes("/r2/buckets")) {
        unbounded++;
        return json({ result: { buckets: [{ name: `u${unbounded}` }] }, result_info: { cursors: { after: `CUR${unbounded}` } } });
      }
      return json({ result: [], result_info: { total_pages: 1 } });
    };
    const bounded = await withFetch(neverEmptyCursor, () => listAccountProducts("tok", "acct-1"));
    ok("listPaged stops at its maxPages bound when a cursor never empties", bounded.r2.length === 7 && unbounded === 7);

    // CAP TRUNCATION (the `if (items.length >= cap) return items` mid-batch early return): a single R2 page
    // returns MORE than the CAP (500) buckets, so listPaged returns exactly CAP and the documented bound,
    // not the page, is the limit.
    const overCapFetch: typeof fetch = async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url.includes("/r2/buckets")) return json({ result: { buckets: Array.from({ length: 600 }, (_v, i) => ({ name: `cap${String(i).padStart(4, "0")}` })) }, result_info: { total_pages: 1 } });
      return json({ result: [], result_info: { total_pages: 1 } });
    };
    const capped = await withFetch(overCapFetch, () => listAccountProducts("tok", "acct-1"));
    ok("listPaged truncates a single over-cap page to the 500 bound", capped.r2.length === 500);

    // SECRETS CAP (the `if (out.secrets.length >= CAP) break` store-walk bound): one store holds more than
    // CAP secrets, so the per-account secrets roll-up stops at CAP across the walk.
    const overCapSecrets: typeof fetch = async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url.includes("/secrets_store/stores/")) return json({ result: Array.from({ length: 600 }, (_v, i) => ({ name: `SEC${String(i).padStart(4, "0")}` })), result_info: { total_pages: 1 } });
      if (url.includes("/secrets_store/stores")) return json({ result: [{ id: "store-1" }, { id: "store-2" }], result_info: { total_pages: 1 } });
      return json({ result: [], result_info: { total_pages: 1 } });
    };
    const cappedSecrets = await withFetch(overCapSecrets, () => listAccountProducts("tok", "acct-1"));
    ok("listAccountProducts caps the secrets roll-up at 500 across the store walk", cappedSecrets.secrets.length === 500);
  }

  // ---- 13. matchConfigChangeAction + matchOwnerActionAction: parse | reject -----------------------
  {
    ok("matchConfigChangeAction rejects a non-POST method", matchConfigChangeAction("GET", "/config/changes/abc/approve") === null);
    ok("matchConfigChangeAction rejects a path that is not the change route", matchConfigChangeAction("POST", "/something/else") === null);
    const approve = matchConfigChangeAction("POST", "/config/changes/01ABCXYZ/approve");
    ok("matchConfigChangeAction parses approve + the id", approve !== null && approve.id === "01ABCXYZ" && approve.action === "approve");
    const reject = matchConfigChangeAction("POST", "/config/changes/01ABCXYZ/reject");
    ok("matchConfigChangeAction parses reject + the id", reject !== null && reject.action === "reject");
    const decoded = matchConfigChangeAction("POST", "/config/changes/a%20b/approve");
    ok("matchConfigChangeAction percent-decodes the id segment", decoded !== null && decoded.id === "a b");
    // A malformed percent-escape makes decodeURIComponent throw -> the catch arm returns null.
    ok("matchConfigChangeAction returns null on an undecodable id (decode throws)", matchConfigChangeAction("POST", "/config/changes/%E0%A4%A/approve") === null);
    // An id that decodes to empty would be a zero-length id; the regex [^/]+ requires at least one char, so
    // a literal empty segment never matches the route in the first place (proving the regex guard).
    ok("matchConfigChangeAction rejects an empty id segment (no route match)", matchConfigChangeAction("POST", "/config/changes//approve") === null);
    // The action segment is anchored to exactly approve|reject; an unknown action verb does not match.
    ok("matchConfigChangeAction rejects an unknown action verb", matchConfigChangeAction("POST", "/config/changes/01ABCXYZ/cancel") === null);
    // The regex is end-anchored ($): a trailing segment after the action must NOT match (no /approve/extra
    // fall-through that would let an unintended handler run).
    ok("matchConfigChangeAction rejects a trailing segment after the action", matchConfigChangeAction("POST", "/config/changes/01ABCXYZ/approve/extra") === null);
    // An empty path (the root) is not the change route.
    ok("matchConfigChangeAction returns null on an empty path", matchConfigChangeAction("POST", "") === null);

    ok("matchOwnerActionAction rejects a non-POST method", matchOwnerActionAction("PUT", "/owner-actions/abc/approve") === null);
    ok("matchOwnerActionAction rejects an unrelated path", matchOwnerActionAction("POST", "/config/changes/abc/approve") === null);
    const oApprove = matchOwnerActionAction("POST", "/owner-actions/OA-1/approve");
    ok("matchOwnerActionAction parses approve + the id", oApprove !== null && oApprove.id === "OA-1" && oApprove.action === "approve");
    const oReject = matchOwnerActionAction("POST", "/owner-actions/OA-2/reject");
    ok("matchOwnerActionAction parses reject + the id", oReject !== null && oReject.action === "reject");
    ok("matchOwnerActionAction percent-decodes the id segment", matchOwnerActionAction("POST", "/owner-actions/x%2Fy/approve")?.id === "x/y");
    ok("matchOwnerActionAction returns null on an undecodable id (decode throws)", matchOwnerActionAction("POST", "/owner-actions/%E0%A4%A/approve") === null);
    ok("matchOwnerActionAction rejects an unknown action verb", matchOwnerActionAction("POST", "/owner-actions/OA-3/cancel") === null);
    ok("matchOwnerActionAction rejects a trailing segment after the action", matchOwnerActionAction("POST", "/owner-actions/OA-3/approve/extra") === null);
    ok("matchOwnerActionAction returns null on an empty path", matchOwnerActionAction("POST", "") === null);
  }

  // ---- 14. isRoleString: the closed six-role union, including the two narrow roles ----------------
  {
    for (const role of ["viewer", "operator", "restore-operator", "approver", "access-admin", "owner"]) {
      ok(`isRoleString accepts the built-in role ${role}`, isRoleString(role) === true);
    }
    ok("isRoleString rejects an unknown role string", isRoleString("superuser") === false);
    ok("isRoleString rejects a non-string", isRoleString(42) === false);
    ok("isRoleString rejects null", isRoleString(null) === false);
  }

  // ---- 15. exported constants --------------------------------------------------------------------
  {
    ok("MAX_DISCOVERY_ACCOUNTS is the documented subrequest-safe bound (8)", MAX_DISCOVERY_ACCOUNTS === 8);
    ok("INVITE_SUBJECT names no person or role (redaction-safe)", typeof INVITE_SUBJECT === "string" && !INVITE_SUBJECT.includes("operator") && INVITE_SUBJECT.length > 0);
  }

  console.log("");
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.log(`ROUTER-SOURCES SPOKE: ${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("ROUTER-SOURCES SPOKE UNIT VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
