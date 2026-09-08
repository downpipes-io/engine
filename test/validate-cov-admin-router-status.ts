// validate-cov-admin-router-status: branch-coverage proof for src/admin/router-status.ts, the post-auth
// status / preflight / supportability spoke (the onboarding-readiness status read with its presence-safe
// DO round-trips, the entitlement preflight probe, the supportability view + sealed support-bundle
// download, and the owner-only ingest-credential mint + revoke with their dual-control gate). Every
// assertion drives the REAL handleAdmin over a REAL SchedulerDO on in-memory storage and checks a real
// outcome (an HTTP status, a returned body field, a stored or audited effect). The only network is the
// stubbed Cloudflare Access JWKS; everything else is the real router + real DO.
//
// The presence-safe status branches (a DO read that throws, or returns an absent / wrong-typed / non-finite
// field) cannot be produced by a healthy DO, so a handful of status reads are driven with a controlled DO
// reply (a thrown fetch, or a synthetic JSON value) exactly as the sibling router-identity coverage test
// drives its hard-to-reach DEFENSIVE arms. The router-status code under test is always the real one; only
// the DO's reply (an input to the router's own parsing/guard logic) is shaped, and each assertion checks
// what the REAL router computed from it (the count, the masking, the honest omission).
//
// Run: node test/validate-cov-admin-router-status.ts

import { handleAdmin } from "../src/admin/router.ts";
import { handleStatus } from "../src/admin/router-status.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { DEMO_FRESH_FIRST_RUN_KEY } from "../src/sched/scheduler-do-records.ts";
import type { Env } from "../src/env.d.ts";
import type { Caller } from "../src/admin/identity.ts";
import type { RouterCtx } from "../src/admin/router-helpers.ts";
import type { StoredDestination, DestinationCollection } from "../src/sched/scheduler-do-base.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

interface Stack {
  dobj: SchedulerDO;
  storage: MockStorage;
  stub: DurableObjectStub;
  env: Pick<Env, "SCHEDULER">;
}

// makeStack builds a real SchedulerDO over MockStorage plus the namespace handleAdmin's schedulerStub()
// resolves. opts.throwPaths makes the stub THROW for those DO pathnames (driving GET /status's presence-safe
// catch arms); opts.replies returns a synthetic JSON value for a DO pathname (driving the field-parsing
// guard arms: an absent / wrong-typed / non-finite field a healthy DO never returns). Every other path runs
// against the real DO, so the router's own logic is exercised end to end.
function makeStack(opts?: { throwPaths?: Set<string>; replies?: Record<string, unknown> }): Stack {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const syntheticReply = (value: unknown): Response =>
    ({
      ok: true,
      status: 200,
      json: async () => value,
      text: async () => JSON.stringify(value),
      headers: new Headers({ "content-type": "application/json" }),
    }) as unknown as Response;
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const p = new URL(url).pathname;
      if (opts?.throwPaths?.has(p)) throw new Error(`simulated DO ${p} unavailable`);
      if (opts?.replies && Object.prototype.hasOwnProperty.call(opts.replies, p)) return Promise.resolve(syntheticReply(opts.replies[p]));
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { dobj, storage, stub, env: { SCHEDULER: namespace } };
}

// ---- Forged Access JWT (real RS256 verification against a controlled, stubbed JWKS) ----
const TEAM = "cov-status-team";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "cov-status-aud";
const KID = "cov-status-kid";
const ADMIN_TOKEN = "cov-status-break-glass-token-1234567890";
function jwtPart(o: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(o)));
}

function mkEnv(stack: Stack, extra: Record<string, unknown> = {}): Env {
  return { ...stack.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ...extra } as unknown as Env;
}

interface CallOpts {
  jwt?: string;
  bearer?: string;
  body?: unknown;
  raw?: string;
}
async function call(env: Env, method: "GET" | "POST", path: string, opts: CallOpts = {}): Promise<Response> {
  const headers: Record<string, string> = {};
  if (opts.jwt !== undefined) headers["cf-access-jwt-assertion"] = opts.jwt;
  if (opts.bearer !== undefined) headers["authorization"] = `Bearer ${opts.bearer}`;
  const hasBody = opts.body !== undefined || opts.raw !== undefined;
  if (hasBody) headers["content-type"] = "application/json";
  const init: RequestInit = { method, headers };
  if (opts.raw !== undefined) init.body = opts.raw;
  else if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
  return handleAdmin(new Request(`https://engine.cov.example${path}`, init), env);
}

// A stored destination record the DO's redaction-safe getDestStatus reflects (present + endpointHost),
// so GET /status's console-destination precedence + the R2-endpoint label are driven from real DO state.
function seedDest(id: string, endpoint: string): StoredDestination {
  return {
    id,
    label: `dest ${id}`,
    endpoint,
    bucket: `bucket-${id}`,
    region: "auto",
    accessKeyId: "AKIAEXAMPLE",
    secretAccessKey: "super-secret-key-value",
    setAt: 1_700_000_000_000,
    setBy: "owner@example.com",
    verifiedAt: 1_700_000_000_000,
    deleteProbe: "ok",
  } as StoredDestination;
}

// seedDeployDest mirrors ensureDeployDestSeeded's synthetic source:"deploy" record (scheduler-do-dest-
// config.ts): present:true, but every DestinationConfig field is the blank placeholder that record is
// stored with (no real credential, no real endpoint to derive a kind from).
function seedDeployDest(id: string): StoredDestination {
  return {
    id,
    label: "Deploy-time destination",
    source: "deploy",
    endpoint: "",
    bucket: "",
    region: "",
    accessKeyId: "",
    secretAccessKey: "",
    setAt: 1_700_000_000_000,
    setBy: "owner@example.com",
    verifiedAt: 1_700_000_000_000,
    deleteProbe: "other",
  } as StoredDestination;
}

async function main(): Promise<void> {
  // ---- install the Access JWKS fetch stub (the only network) ----
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pub = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pub.n, e: pub.e }] };
  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  async function tokenFor(email: string): Promise<string> {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  }
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${ISS}/cdn-cgi/access/certs`) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    throw new Error(`unexpected network fetch in test: ${url}`);
  }) as typeof fetch;

  try {
    // =====================================================================================
    // GET /status (A): fully real DO, Access owner, DEMO_MODE off. The present + well-typed arms of every
    // DO-read guard, the email-bearing recovery read, the empty downpipe list, and the false demo arm.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { SIGNER_PRIVATE: "signer-seed", BREAK_GLASS_PUBLIC: "bg-public" });
      // Bootstrap the first Access caller as Owner (this also latches bootstrapConsumed true).
      ok("status(A): owner bootstrap", ((await (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor("owner-a@cov.example") })).json()) as { role?: string }).role === "owner");
      const r = await call(env, "GET", "/admin/status", { jwt: await tokenFor("owner-a@cov.example") });
      ok("status(A): 200", r.status === 200);
      const b = (await r.json()) as Record<string, unknown>;
      ok("status(A): downpipeCount 0 (real empty list, Array.isArray true arm)", b.downpipeCount === 0);
      ok("status(A): sourcesDetachedCount 0 (roster read ok, empty roster -> nothing detached, present-and-zero)", b.sourcesDetachedCount === 0);
      ok("status(A): restorabilityProven 0 (reduce over the empty list)", b.restorabilityProven === 0);
      ok("status(A): expiryWarnings is a number (typeof+finite true arm)", b.expiryWarnings === 0);
      ok("status(A): cleanupPending is a number (typeof+finite true arm)", b.cleanupPending === 0);
      ok("status(A): bootstrapConsumed true (boolean guard true arm)", b.bootstrapConsumed === true);
      ok("status(A): breakGlassTokenRetired false (boolean guard true arm)", b.breakGlassTokenRetired === false);
      ok("status(A): recoveryCodesRemaining 0 (email-bearing caller, number guard true arm)", b.recoveryCodesRemaining === 0);
      ok("status(A): demoMode false (envFlagEnabled false arm, demo first-run not read)", b.demoMode === false);
      ok("status(A): signerConfigured true (SIGNER set, not demo-masked)", b.signerConfigured === true);
      ok("status(A): destConfigured false (no env dest, console dest absent)", b.destConfigured === false);
    }

    // =====================================================================================
    // GET /status (B): bare-token break-glass owner. The caller.email === null arm skips the recovery read.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const r = await call(env, "GET", "/admin/status", { bearer: ADMIN_TOKEN });
      ok("status(B): 200 (bare-token owner)", r.status === 200);
      const b = (await r.json()) as Record<string, unknown>;
      ok("status(B): recoveryCodesRemaining absent (caller.email === null arm)", b.recoveryCodesRemaining === undefined);
      ok("status(B): adminTokenConfigured true (ADMIN_TOKEN present)", b.adminTokenConfigured === true);
    }

    // =====================================================================================
    // GET /status (C): DEMO_MODE on with a real fresh-first-run marker + a real R2 console destination, and
    // a synthetic /downpipes reply driving all four reduce arms. The demoFreshFirstRun present-arm + masking,
    // the dest endpointHost string-present arm, and the restorabilityProven count.
    // =====================================================================================
    {
      // Synthetic /downpipes: [restoreProven truthy, restoreProven falsy, null element, non-object element]
      // exercises d&&typeof-object guard + the restoreProven ternary both ways (only the first counts).
      const s = makeStack({ replies: { "/downpipes": [{ restoreProven: { at: 1, how: "blind" } }, { restoreProven: null }, null, 7] } });
      // Real DO state: a fresh-first-run marker (so /demo/first-run returns forceFirstRun:true) + an R2 default
      // destination (so /dest-status returns present:true + an r2.cloudflarestorage.com endpointHost).
      s.storage.rawPut(DEMO_FRESH_FIRST_RUN_KEY, true);
      await s.dobj.saveDestinations({ list: [seedDest("d1", "https://acct.r2.cloudflarestorage.com")], defaultId: "d1" } as DestinationCollection);
      const env = mkEnv(s, { DEMO_MODE: "true", SIGNER_PRIVATE: "signer-seed" });
      ok("status(C): owner bootstrap", ((await (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor("owner-c@cov.example") })).json()) as { role?: string }).role === "owner");
      const r = await call(env, "GET", "/admin/status", { jwt: await tokenFor("owner-c@cov.example") });
      ok("status(C): 200", r.status === 200);
      const b = (await r.json()) as Record<string, unknown>;
      ok("status(C): downpipeCount 4 (synthetic array length)", b.downpipeCount === 4);
      ok("status(C): restorabilityProven 1 (only the truthy-restoreProven element counted)", b.restorabilityProven === 1);
      ok("status(C): demoMode true (envFlagEnabled true arm)", b.demoMode === true);
      ok("status(C): signerConfigured false (demoFreshFirstRun present-arm masks the key booleans)", b.signerConfigured === false);
      ok("status(C): destKind r2 (console dest present + R2 endpointHost string arm)", b.destKind === "r2");
      ok("status(C): destConfigured true (console-set destination wins)", b.destConfigured === true);
      ok("status(C): recoveryCodesRemaining 0 (real DO, email-bearing caller)", b.recoveryCodesRemaining === 0);
    }

    // =====================================================================================
    // GET /status (C2): the synthetic source:"deploy" destination
    // (ensureDeployDestSeeded) is present:true with a BLANK endpointHost -- present:true used to mean
    // "a console destination is set" unconditionally, so this read regressed to consoleDestSet:true and
    // resolveDestKind's providerForEndpoint("") guessed a specific, WRONG kind ("s3") for what is
    // actually the env's own R2 binding. router-status.ts now excludes source:"deploy" from
    // consoleDestSet, so this must read the TRUE env kind (r2, from DEST_R2) and destConfigured from the
    // env fact, exactly as an estate with no console destination at all always has.
    // =====================================================================================
    {
      const s = makeStack();
      await s.dobj.saveDestinations({ list: [seedDeployDest("deploy")], defaultId: "deploy" } as DestinationCollection);
      const env = mkEnv(s, { DEST_R2: {} });
      const r = await call(env, "GET", "/admin/status", { jwt: await tokenFor("owner-c2@cov.example") });
      ok("status(C2): 200", r.status === 200);
      const b = (await r.json()) as Record<string, unknown>;
      ok('status(C2): destKind "r2" (env DEST_R2 binding), never the blank-endpoint guess "s3"', b.destKind === "r2");
      ok("status(C2): destConfigured true (the env binding, not a fabricated console credential)", b.destConfigured === true);
    }

    // =====================================================================================
    // GET /status (D): every status DO read THROWS. The presence-safe catch arm of each read leaves the field
    // honestly absent and the status read still answers 200. DEMO_MODE on (so demo first-run is attempted too).
    // =====================================================================================
    {
      const throwPaths = new Set(["/downpipes", "/expiry/warnings", "/policy/break-glass-disposal", "/recovery/remaining", "/dest-status", "/demo/first-run", "/audit-status"]);
      const s = makeStack({ throwPaths });
      const env = mkEnv(s, { DEMO_MODE: "true" });
      // Bootstrap via a non-thrown path (whoami is not in throwPaths), then the status read with all reads down.
      ok("status(D): owner bootstrap", ((await (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor("owner-d@cov.example") })).json()) as { role?: string }).role === "owner");
      const r = await call(env, "GET", "/admin/status", { jwt: await tokenFor("owner-d@cov.example") });
      ok("status(D): 200 (presence-safe, every DO read down)", r.status === 200);
      const b = (await r.json()) as Record<string, unknown>;
      ok("status(D): downpipeCount 0 (downpipes catch -> empty)", b.downpipeCount === 0);
      ok("status(D): sourcesDetachedCount absent (roster read failed -> honestly absent, never a false all-clear)", b.sourcesDetachedCount === undefined);
      ok("status(D): restorabilityProven 0", b.restorabilityProven === 0);
      ok("status(D): expiryWarnings absent (expiry catch arm)", b.expiryWarnings === undefined);
      ok("status(D): cleanupPending absent (expiry catch arm)", b.cleanupPending === undefined);
      ok("status(D): bootstrapConsumed absent (break-glass catch arm)", b.bootstrapConsumed === undefined);
      ok("status(D): breakGlassTokenRetired absent (break-glass catch arm)", b.breakGlassTokenRetired === undefined);
      ok("status(D): recoveryCodesRemaining absent (recovery catch arm)", b.recoveryCodesRemaining === undefined);
      ok("status(D): demoMode true (envFlagEnabled true; demo first-run catch arm ran)", b.demoMode === true);
    }

    // =====================================================================================
    // GET /status (E): every status read returns an ABSENT / WRONG-TYPED field (a non-array downpipes, a
    // string where a number/boolean is expected), and demo first-run returns forceFirstRun:false. Drives the
    // Array.isArray false arm, every typeof guard false arm, and the demoFreshFirstRun !== undefined false arm.
    // =====================================================================================
    {
      const replies = {
        "/downpipes": {}, // not an array -> Array.isArray false arm -> empty list
        "/expiry/warnings": { expiryWarnings: "x", cleanupPending: "y" }, // typeof number false (both)
        "/policy/break-glass-disposal": { bootstrapConsumed: "x", breakGlassTokenRetired: 0 }, // typeof boolean false (both)
        "/recovery/remaining": { remaining: "x" }, // typeof number false
        "/dest-status": { present: "x", endpointHost: 123 }, // present boolean false + endpointHost string false
        "/demo/first-run": { forceFirstRun: false }, // forceFirstRun === true false arm
      };
      const s = makeStack({ replies });
      const env = mkEnv(s, { DEMO_MODE: "true", SIGNER_PRIVATE: "signer-seed" });
      ok("status(E): owner bootstrap", ((await (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor("owner-e@cov.example") })).json()) as { role?: string }).role === "owner");
      const r = await call(env, "GET", "/admin/status", { jwt: await tokenFor("owner-e@cov.example") });
      ok("status(E): 200", r.status === 200);
      const b = (await r.json()) as Record<string, unknown>;
      ok("status(E): downpipeCount 0 (non-array -> Array.isArray false arm)", b.downpipeCount === 0);
      ok("status(E): expiryWarnings absent (typeof number false arm)", b.expiryWarnings === undefined);
      ok("status(E): cleanupPending absent (typeof number false arm)", b.cleanupPending === undefined);
      ok("status(E): bootstrapConsumed absent (typeof boolean false arm)", b.bootstrapConsumed === undefined);
      ok("status(E): breakGlassTokenRetired absent (typeof boolean false arm)", b.breakGlassTokenRetired === undefined);
      ok("status(E): recoveryCodesRemaining absent (typeof number false arm)", b.recoveryCodesRemaining === undefined);
      ok("status(E): signerConfigured true (forceFirstRun false -> not masked, SIGNER set)", b.signerConfigured === true);
    }

    // =====================================================================================
    // GET /status (E2): expiry + recovery reads return NON-FINITE numbers. The Number.isFinite false arm of
    // each numeric guard (typeof number true, but NaN/Infinity is honestly omitted, never fabricated).
    // =====================================================================================
    {
      const replies = { "/expiry/warnings": { expiryWarnings: NaN, cleanupPending: Infinity }, "/recovery/remaining": { remaining: NaN } };
      const s = makeStack({ replies });
      const env = mkEnv(s, {});
      ok("status(E2): owner bootstrap", ((await (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor("owner-e2@cov.example") })).json()) as { role?: string }).role === "owner");
      const r = await call(env, "GET", "/admin/status", { jwt: await tokenFor("owner-e2@cov.example") });
      ok("status(E2): 200", r.status === 200);
      const b = (await r.json()) as Record<string, unknown>;
      ok("status(E2): expiryWarnings absent (Number.isFinite false arm)", b.expiryWarnings === undefined);
      ok("status(E2): cleanupPending absent (Number.isFinite false arm)", b.cleanupPending === undefined);
      ok("status(E2): recoveryCodesRemaining absent (Number.isFinite false arm)", b.recoveryCodesRemaining === undefined);
    }

    // =====================================================================================
    // GET /preflight: the entitlement probe returns a structured 200 report (any authenticated role).
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const r = await call(env, "GET", "/admin/preflight", { bearer: ADMIN_TOKEN });
      ok("preflight: 200", r.status === 200);
      const b = (await r.json()) as { items?: unknown; summary?: { required?: unknown } };
      ok("preflight: carries the probed items array", Array.isArray(b.items) && (b.items as unknown[]).length > 0);
      ok("preflight: carries the summary rollup", typeof b.summary === "object" && b.summary !== null && typeof b.summary.required === "number");
    }

    // =====================================================================================
    // GET /support: the supportability view. Both the unconfigured (no vendor key / no signer) and the
    // configured arms, plus a real stored grant flowing through redactGrant.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const r = await call(env, "GET", "/admin/support", { bearer: ADMIN_TOKEN });
      ok("support(unconfigured): 200", r.status === 200);
      const b = (await r.json()) as { vendorSealConfigured?: boolean; signerConfigured?: boolean; accessPerimeter?: boolean; diagnostics?: unknown; auditFeed?: unknown };
      ok("support(unconfigured): vendorSealConfigured false (no VENDOR_SUPPORT_PUBLIC)", b.vendorSealConfigured === false);
      ok("support(unconfigured): signerConfigured false (no SIGNER_PRIVATE)", b.signerConfigured === false);
      ok("support(unconfigured): accessPerimeter false (no cf-access-jwt-assertion on the read)", b.accessPerimeter === false);
      ok("support(unconfigured): both grants null (none minted)", b.diagnostics === null && b.auditFeed === null);
    }
    {
      const s = makeStack();
      // CF_ACCESS_* is deliberately UNSET here (mkEnv sets it by default): the perimeter-only topology,
      // where Access fronts the hostname and injects its assertion while engine auth stays
      // bare-token/passkey (the demo deployment's exact shape).
      const env = mkEnv(s, { ADMIN_TOKEN, VENDOR_SUPPORT_PUBLIC: "vendor-pub", SIGNER_PRIVATE: "signer-seed", CF_ACCESS_TEAM_DOMAIN: undefined, CF_ACCESS_AUD: undefined });
      // Mint a diagnostics credential (dual control off) so the support view reflects a real redacted grant.
      const mint = await call(env, "POST", "/admin/support/credentials", { bearer: ADMIN_TOKEN, body: { scope: "diagnostics" } });
      ok("support(configured): a diagnostics credential mints 200", mint.status === 200);
      // The read carries the edge-injected assertion: it must play no part in auth here AND must
      // surface as accessPerimeter, the flag the mint UI warns from.
      const r = await call(env, "GET", "/admin/support", { bearer: ADMIN_TOKEN, jwt: "edge-injected-not-verified-here" });
      ok("support(configured): 200", r.status === 200);
      const b = (await r.json()) as { vendorSealConfigured?: boolean; signerConfigured?: boolean; accessPerimeter?: boolean; diagnostics?: { clientId?: string } | null };
      ok("support(configured): vendorSealConfigured true", b.vendorSealConfigured === true);
      ok("support(configured): signerConfigured true", b.signerConfigured === true);
      ok("support(configured): accessPerimeter true (assertion present in perimeter-only mode)", b.accessPerimeter === true);
      ok("support(configured): the minted diagnostics grant is shown redacted (clientId, no secret)", typeof b.diagnostics?.clientId === "string" && b.diagnostics.clientId.startsWith("dpc_"));
    }

    // =====================================================================================
    // GET /support/bundle: the sealed/signed support-bundle download (here the signed form, no vendor key).
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN, SIGNER_PRIVATE: b64urlEncode(crypto.getRandomValues(new Uint8Array(64))) });
      const r = await call(env, "GET", "/admin/support/bundle", { bearer: ADMIN_TOKEN });
      ok("support/bundle: 200", r.status === 200);
      const b = (await r.json()) as { kind?: string; signature?: string };
      ok("support/bundle: returns the signed bundle form (no vendor key configured)", b.kind === "downpipe-support-bundle-signed" && typeof b.signature === "string" && b.signature.length > 0);
    }

    // =====================================================================================
    // GET /support and GET /support/bundle are rate-limited like the mutating routes
    // (both fan out multiple scheduler DO round-trips per call -- /bundle on the order of 25, plus a
    // fresh PQ seal -- so the GET-is-exempt default router.ts documents does not hold for these two).
    // Mirrors the POST /support/credentials 429 arm above: seed the shared bare-token bucket at the
    // cap, then prove BOTH GET cases refuse rather than running their DO fan-out.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      s.storage.rawPut("ratelimit:token", { windowStart: Date.now(), count: 120 });
      const rs = await call(env, "GET", "/admin/support", { bearer: ADMIN_TOKEN });
      ok("support(owner, over cap): 429", rs.status === 429);
      const rb = await call(env, "GET", "/admin/support/bundle", { bearer: ADMIN_TOKEN });
      ok("support/bundle(owner, over cap): 429", rb.status === 429);
    }

    // =====================================================================================
    // GET /preflight is rate-limited too (runPreflight's up-to-11-probe fan-out scales with the tenant's own
    // configured downpipe/source count, the same anti-automation concern as GET /support/bundle above, and
    // preflight deliberately keeps no capability gate, since onboarding/support must work for a caller who
    // legitimately lacks downpipe.read). Same seed as the arm above, proving BOTH GET /preflight and GET
    // /support/bundle refuse over cap.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      s.storage.rawPut("ratelimit:token", { windowStart: Date.now(), count: 120 });
      const rp = await call(env, "GET", "/admin/preflight", { bearer: ADMIN_TOKEN });
      ok("preflight(owner, over cap): 429", rp.status === 429);
      const rb2 = await call(env, "GET", "/admin/support/bundle", { bearer: ADMIN_TOKEN });
      ok("support/bundle(owner, over cap, again): 429", rb2.status === 429);
    }
    // A caller under the cap still gets the real 200 from both routes: the limiter fails OPEN for
    // normal use (a DO hiccup admits the request) and only refuses a caller genuinely over the cap,
    // never the reverse.
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      s.storage.rawPut("ratelimit:token", { windowStart: Date.now(), count: 3 });
      const rp = await call(env, "GET", "/admin/preflight", { bearer: ADMIN_TOKEN });
      ok("preflight(owner, under cap): 200", rp.status === 200);
      const rb3 = await call(env, "GET", "/admin/support/bundle", { bearer: ADMIN_TOKEN });
      ok("support/bundle(owner, under cap): 200", rb3.status === 200);
    }

    // =====================================================================================
    // GET /support and GET /support/bundle gate on posture.read. Every caller reachable
    // through the real handleAdmin path (built-in or custom-role) resolves posture.read today (the six
    // built-in ROLE_CAPABILITIES sets all hold it, and resolveAuthority folds the viewer floor into
    // every custom-role caller), so there is no live scenario that drives a real 403 here. This drives
    // handleStatus directly with a hand-built RouterCtx/Caller instead (the same technique the sibling
    // router-identity coverage test uses for its custom-role whoami arms) to prove the gate itself: a
    // caller whose resolved capability set genuinely lacks posture.read is refused before either route
    // ever touches the scheduler, and a caller who holds it still gets the real response.
    // =====================================================================================
    {
      // The stub THROWS if reached at all, so a 403 here also proves the gate runs before any DO round trip.
      const noDOStub = { fetch: () => { throw new Error("must not reach the scheduler: the capability gate should have refused first"); } } as unknown as DurableObjectStub;
      const narrowCaller: Caller = {
        method: "access",
        email: "contractor@cov.example",
        subject: "access:sub-of-contractor",
        role: "viewer",
        groups: [],
        capabilities: new Set(["run.trigger"]) as ReadonlySet<string> as NonNullable<Caller["capabilities"]>,
      };
      const baseCtx = {
        env: {},
        scheduler: noDOStub,
        caller: narrowCaller,
        sourceIp: null,
        runtime: undefined,
        verdict: { ok: true, method: "access", email: narrowCaller.email, subject: narrowCaller.subject },
        isOnlyOwner: false,
        roleSource: "custom",
        customRole: undefined,
      };
      const supportDenied = (await handleStatus({ ...baseCtx, req: new Request("https://engine.cov.example/admin/support", { method: "GET" }), url: new URL("https://engine.cov.example/admin/support"), sub: "/support" } as unknown as RouterCtx))!;
      ok("support(no posture.read): 403", supportDenied.status === 403);
      const sdBody = (await supportDenied.json()) as { error?: string; required?: string; have?: string };
      ok("support(no posture.read): forbidden body names required posture.read + the viewer floor", sdBody.error === "forbidden" && sdBody.required === "posture.read" && sdBody.have === "viewer");

      const bundleDenied = (await handleStatus({ ...baseCtx, req: new Request("https://engine.cov.example/admin/support/bundle", { method: "GET" }), url: new URL("https://engine.cov.example/admin/support/bundle"), sub: "/support/bundle" } as unknown as RouterCtx))!;
      ok("support/bundle(no posture.read): 403", bundleDenied.status === 403);
      const bdBody = (await bundleDenied.json()) as { error?: string; required?: string };
      ok("support/bundle(no posture.read): forbidden body names required posture.read", bdBody.error === "forbidden" && bdBody.required === "posture.read");
    }
    {
      // A caller who DOES hold posture.read (a legitimately composed custom role) still gets the real
      // response: the gate is scoped to the missing capability, not a blanket new restriction.
      const s = makeStack();
      const env = mkEnv(s);
      const readerCaller: Caller = {
        method: "access",
        email: "reader@cov.example",
        subject: "access:sub-of-reader",
        role: "viewer",
        groups: [],
        capabilities: new Set(["posture.read"]) as ReadonlySet<string> as NonNullable<Caller["capabilities"]>,
      };
      const ctx = {
        req: new Request("https://engine.cov.example/admin/support", { method: "GET" }),
        env,
        url: new URL("https://engine.cov.example/admin/support"),
        scheduler: s.stub,
        caller: readerCaller,
        sub: "/support",
        sourceIp: null,
        runtime: undefined,
        verdict: { ok: true, method: "access", email: readerCaller.email, subject: readerCaller.subject },
        isOnlyOwner: false,
        roleSource: "custom",
        customRole: undefined,
      } as unknown as RouterCtx;
      const r = (await handleStatus(ctx))!;
      ok("support(with posture.read): 200 (gate scoped, not a blanket refusal)", r.status === 200);
    }

    // =====================================================================================
    // POST /support/credentials (mint): the validation, owner gate, and dual-control-off proceed arms.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      // dual control OFF: a diagnostics mint with NO ttl proceeds (ttlSeconds undefined arms).
      const m1 = await call(env, "POST", "/admin/support/credentials", { bearer: ADMIN_TOKEN, body: { scope: "diagnostics" } });
      ok("mint(off): diagnostics with no ttl -> 200", m1.status === 200);
      const m1b = (await m1.json()) as { scope?: string; clientId?: string; secret?: string; bearer?: string };
      ok("mint(off): the secret is shown once (dps_), with a dpc_ clientId and a composite bearer", m1b.scope === "diagnostics" && (m1b.secret ?? "").startsWith("dps_") && (m1b.clientId ?? "").startsWith("dpc_") && m1b.bearer === `${m1b.clientId}.${m1b.secret}`);
      // dual control OFF: an audit-feed mint WITH a numeric ttl proceeds (ttlSeconds number arms + audit-feed scope arm).
      const m2 = await call(env, "POST", "/admin/support/credentials", { bearer: ADMIN_TOKEN, body: { scope: "audit-feed", ttlSeconds: 100 } });
      ok("mint(off): audit-feed with a numeric ttl -> 200", m2.status === 200 && ((await m2.json()) as { scope?: string }).scope === "audit-feed");
      // a malformed scope is a plain 400 with no entry (scope === null arm).
      const m3 = await call(env, "POST", "/admin/support/credentials", { bearer: ADMIN_TOKEN, body: { scope: "bogus" } });
      ok("mint: a malformed scope -> 400", m3.status === 400 && /scope must be/.test(((await m3.json()) as { error?: string }).error ?? ""));
    }

    // =====================================================================================
    // POST /support/credentials + /delete: the NON-OWNER refusal arm (403 + the recorded denied audit event).
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s);
      const OWNER = "sup-owner@cov.example";
      const VIEWER = "sup-viewer@cov.example";
      ok("deny setup: owner bootstrap", ((await (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor(OWNER) })).json()) as { role?: string }).role === "owner");
      const dm = await call(env, "POST", "/admin/support/credentials", { jwt: await tokenFor(VIEWER), body: { scope: "diagnostics" } });
      ok("mint(non-owner): 403", dm.status === 403);
      const dmb = (await dm.json()) as { required?: string; have?: string };
      ok("mint(non-owner): forbidden body names required owner + the viewer's role", dmb.required === "owner" && dmb.have === "viewer");
      const dd = await call(env, "POST", "/admin/support/credentials/delete", { jwt: await tokenFor(VIEWER), body: { scope: "audit-feed" } });
      ok("delete(non-owner): 403", dd.status === 403);
      const ddb = (await dd.json()) as { required?: string; have?: string };
      ok("delete(non-owner): forbidden body names required owner + the viewer's role", ddb.required === "owner" && ddb.have === "viewer");
      // The refused attempts recorded denied audit events (the real effect of the deny arms).
      const audit = (await (await call(env, "GET", "/admin/audit?limit=200", { jwt: await tokenFor(OWNER) })).json()) as { events?: Array<{ action?: string; outcome?: string; target?: { scope?: string } }> };
      const ev = audit.events ?? [];
      ok("deny audit: a support-credential-grant denied event was recorded", ev.some((e) => e.action === "support-credential-grant" && e.outcome === "denied" && e.target?.scope === "diagnostics"));
      ok("deny audit: a support-credential-revoke denied event was recorded", ev.some((e) => e.action === "support-credential-revoke" && e.outcome === "denied" && e.target?.scope === "audit-feed"));
    }

    // =====================================================================================
    // POST /support/credentials + /delete: the rate-limit 429 arm (seed the per-caller bucket at the cap).
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      s.storage.rawPut("ratelimit:token", { windowStart: Date.now(), count: 120 });
      const rm = await call(env, "POST", "/admin/support/credentials", { bearer: ADMIN_TOKEN, body: { scope: "diagnostics" } });
      ok("mint(owner, over cap): 429", rm.status === 429);
      const rd = await call(env, "POST", "/admin/support/credentials/delete", { bearer: ADMIN_TOKEN, body: { scope: "diagnostics" } });
      ok("delete(owner, over cap): 429", rd.status === 429);
    }

    // =====================================================================================
    // POST /support/credentials (mint): the dual-control ERROR arm. With the gate ON, the bare-token
    // break-glass owner cannot propose an owner action (no attributable identity), so the DO gate-check
    // refuses and the route surfaces that refusal verbatim (g.kind === "error").
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      // An Access owner arms the opt-in dual-control gate (arming is immediate).
      ok("gate-arm setup: owner bootstrap", ((await (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor("err-owner@cov.example") })).json()) as { role?: string }).role === "owner");
      // A second Owner so dual control can be armed (the two-Owner enable floor); granted inline while there is
      // one Owner and the gate is off.
      await call(env, "POST", "/admin/roles", { jwt: await tokenFor("err-owner@cov.example"), body: { email: "err-owner2@cov.example", role: "owner" } });
      const arm = await call(env, "POST", "/admin/config/approval-policy", { jwt: await tokenFor("err-owner@cov.example"), body: { requireConfigApproval: true } });
      ok("gate-arm: requireConfigApproval ON -> 200", arm.status === 200);
      // The bare-token owner passes the role gate + rate-limit but the gate-check refuses an unattributable maker.
      const em = await call(env, "POST", "/admin/support/credentials", { bearer: ADMIN_TOKEN, body: { scope: "diagnostics" } });
      ok("mint(gate on, bare token): the DO gate-check refusal is surfaced -> 400", em.status === 400);
      const emb = (await em.json()) as { error?: string; secret?: unknown };
      ok("mint(gate on, bare token): the refusal explains an attributable identity is required, no secret minted", /attributable/i.test(emb.error ?? "") && emb.secret === undefined);
    }

    // =====================================================================================
    // POST /support/credentials (mint): the dual-control QUEUED arm and the ARMED -> consume -> proceed arm.
    // Owner1 proposes (202), Owner2 approves (arms), Owner1 re-submits the SAME action (consumes -> mints).
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s);
      const O1 = "dc-owner1@cov.example";
      const O2 = "dc-owner2@cov.example";
      ok("dc setup: owner1 bootstrap", ((await (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor(O1) })).json()) as { role?: string }).role === "owner");
      // Grant a SECOND owner (inline while there is one owner and the gate is off).
      const grant = await call(env, "POST", "/admin/roles", { jwt: await tokenFor(O1), body: { email: O2, role: "owner" } });
      ok("dc setup: owner2 granted -> 200", grant.status === 200);
      // Arm the gate, then propose the mint.
      const arm = await call(env, "POST", "/admin/config/approval-policy", { jwt: await tokenFor(O1), body: { requireConfigApproval: true } });
      ok("dc setup: requireConfigApproval ON -> 200", arm.status === 200);
      const proposal = await call(env, "POST", "/admin/support/credentials", { jwt: await tokenFor(O1), body: { scope: "diagnostics", ttlSeconds: 3600 } });
      ok("mint(gate on, owner1 proposes): 202 queued", proposal.status === 202);
      const pb = (await proposal.json()) as { ownerActionQueued?: boolean; id?: string; status?: string };
      ok("mint(queued): the 202 carries ownerActionQueued + a pending id", pb.ownerActionQueued === true && typeof pb.id === "string" && pb.id.length > 0 && pb.status === "pending");
      // Owner2 approves -> the router-executed mint action is ARMED.
      const approve = await call(env, "POST", `/admin/owner-actions/${pb.id}/approve`, { jwt: await tokenFor(O2) });
      ok("mint(approve by owner2): 200", approve.status === 200);
      // Owner1 re-submits the SAME action -> the armed approval is consumed and the mint runs once.
      const resub = await call(env, "POST", "/admin/support/credentials", { jwt: await tokenFor(O1), body: { scope: "diagnostics", ttlSeconds: 3600 } });
      ok("mint(re-submit, armed -> proceed): 200", resub.status === 200);
      const rb = (await resub.json()) as { scope?: string; secret?: string; clientId?: string };
      ok("mint(re-submit): the secret is minted once on the approved execution", rb.scope === "diagnostics" && (rb.secret ?? "").startsWith("dps_") && (rb.clientId ?? "").startsWith("dpc_"));
    }

    // =====================================================================================
    // POST /support/credentials/delete: the owner happy arm (revoke 200) and the malformed-scope 400 arm.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      // Mint then revoke a diagnostics credential as the bare-token owner (dual control off).
      ok("revoke setup: a diagnostics credential mints", (await call(env, "POST", "/admin/support/credentials", { bearer: ADMIN_TOKEN, body: { scope: "diagnostics" } })).status === 200);
      const del = await call(env, "POST", "/admin/support/credentials/delete", { bearer: ADMIN_TOKEN, body: { scope: "diagnostics" } });
      ok("delete(owner): 200", del.status === 200);
      const delb = (await del.json()) as { ok?: boolean; scope?: string };
      ok("delete(owner): ok + the cleared scope is echoed", delb.ok === true && delb.scope === "diagnostics");
      // The grant is now gone from the supportability view.
      const view = (await (await call(env, "GET", "/admin/support", { bearer: ADMIN_TOKEN })).json()) as { diagnostics?: unknown };
      ok("delete(owner): the diagnostics grant is gone from the support view", view.diagnostics === null);
      // a malformed scope on delete is a plain 400 (scope === null arm).
      const delBad = await call(env, "POST", "/admin/support/credentials/delete", { bearer: ADMIN_TOKEN, body: { scope: "nope" } });
      ok("delete: a malformed scope -> 400", delBad.status === 400 && /scope must be/.test(((await delBad.json()) as { error?: string }).error ?? ""));
    }

    // =====================================================================================
    // The default fall-through: a method+path this spoke does not own returns null (the hub 404s).
    // =====================================================================================
    {
      const s = makeStack();
      const r = await call(mkEnv(s, { ADMIN_TOKEN }), "GET", "/admin/status-not-a-route", { bearer: ADMIN_TOKEN });
      ok("default: an unowned status-spoke path falls through to 404", r.status === 404);
    }
  } finally {
    globalThis.fetch = realFetch;
  }

  console.log(failures === 0 ? "\nROUTER-STATUS COVERAGE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
