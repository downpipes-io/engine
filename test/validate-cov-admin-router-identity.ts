// validate-cov-admin-router-identity: branch-coverage proof for src/admin/router-identity.ts, the post-auth
// identity + IdP-connection-management spoke (the DEMO_MODE reset, whoami, the role-table read, the
// control-plane recovery restore/apply-staged break-glass routes, and the native-IdP connection management
// surface). Every assertion drives the REAL handleAdmin (and, for the whoami field-echo arms, the REAL
// exported handleIdentity spoke) over a REAL SchedulerDO on in-memory storage, and checks a real outcome
// (an HTTP status, a returned body field, a stored or audited effect). The only network is the stubbed
// Cloudflare Access JWKS; control-plane signing/verifying is real Web Crypto.
//
// Run: node test/validate-cov-admin-router-identity.ts

import { handleAdmin } from "../src/admin/router.ts";
import { handleControlPlaneRecoveryAck } from "../src/admin/router-control-plane-recovery-ack.ts";
import { handleIdentity } from "../src/admin/router-identity.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import {
  signControlPlaneExport,
  controlPlaneArtefactKey,
  assertNoPlaintextSecretInExport,
  type ControlPlaneExport,
  type StagedControlPlane,
} from "../src/admin/control-plane.ts";
import { openSealedControlPlaneExport, sealControlPlaneExport, signSealedControlPlaneExport, type SealedControlPlaneExport } from "../src/admin/control-plane-seal.ts";
import { loadIdentity } from "../src/keys-env.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { x25519PublicFromScalar } from "../src/crypto/x25519.ts";
import { makeConfig } from "./validate-scheduler-shared.ts";
import { fetchRecoveryStatus } from "../src/admin/support-sections-recovery.ts";
import type { Env } from "../src/env.d.ts";
import { roleSubjectKey, type Caller } from "../src/admin/identity.ts";
import type { RouterCtx } from "../src/admin/router-helpers.ts";
import type { StoredDestination, DestinationCollection } from "../src/sched/scheduler-do-base.ts";
import { isDeepStrictEqual } from "node:util";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

// A minimal R2 bucket binding: the demo-reset RUNLOG clear only needs delete(); has() lets the test prove it.
class MockR2Bucket {
  store = new Map<string, Uint8Array>();
  async delete(key: string | string[]): Promise<void> {
    for (const k of Array.isArray(key) ? key : [key]) this.store.delete(k);
  }
  has(key: string): boolean {
    return this.store.has(key);
  }
}

interface Stack {
  dobj: SchedulerDO;
  storage: MockStorage;
  stub: DurableObjectStub;
  env: Pick<Env, "SCHEDULER">;
}

// makeStack builds a real SchedulerDO over MockStorage plus the namespace handleAdmin's schedulerStub()
// resolves. opts.failMark makes the stub THROW on the /demo/mark forward only (to drive the router's
// fail-open mark catch -> the DO's fail-closed unmarked-reset 403). opts.override returns a canned
// Response for a specific DO path (else null to forward to the real DO): this drives the router's
// DEFENSIVE reply-mapping arms (a non-ok / no-cleared reset reply, a 403 from the reconcile/apply-staged
// forward that the route's own hardcoded token caller cannot otherwise provoke) the way the wiring suite's
// fakeEnv does. Every other route still runs against the real DO.
function makeStack(opts?: { failMark?: boolean; override?: (url: string) => Response | null }): Stack {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (opts?.failMark && url.endsWith("/demo/mark")) throw new Error("simulated /demo/mark unavailable");
      if (opts?.override) {
        const canned = opts.override(url);
        if (canned !== null) return Promise.resolve(canned);
      }
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
const TEAM = "cov-team";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "cov-test-aud";
const KID = "cov-kid";
const CONSOLE_ORIGIN = "https://console.cov.example";
const ADMIN_TOKEN = "cov-admin-break-glass-token-1234567890";
function jwtPart(o: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(o)));
}

// SIGNER_PRIVATE: a real 64-byte hybrid signer seed (ed25519 seed(32) || ML-DSA-87 seed(32)).
const SIGNER_PRIVATE = b64urlEncode(crypto.getRandomValues(new Uint8Array(64)));

function mkEnv(stack: Stack, extra: Record<string, unknown> = {}): Env {
  return { ...stack.env, CONSOLE_ORIGIN, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ...extra } as unknown as Env;
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

function seedDest(id: string, secret: StoredDestination["secretAccessKey"]): StoredDestination {
  return {
    id,
    label: `dest ${id}`,
    endpoint: "https://s3.example.com",
    bucket: `bucket-${id}`,
    region: "auto",
    accessKeyId: "AKIAEXAMPLE",
    secretAccessKey: secret,
    setAt: 1_700_000_000_000,
    setBy: "owner@example.com",
    verifiedAt: 1_700_000_000_000,
    deleteProbe: "ok",
  } as StoredDestination;
}

function stagedFrom(e: ControlPlaneExport, signature: string): StagedControlPlane {
  return {
    export: e,
    signature,
    sourceKey: controlPlaneArtefactKey(e.configVersion, e.exportedAt),
    version: e.configVersion,
    stagedAt: "2026-06-29T00:00:00.000Z",
    resumeApplied: false,
  };
}

// An export-shaped object that PASSES isControlPlaneExport but smuggles a plaintext secret, so the
// no-custody structural assertion throws (the defence-in-depth 400 on import).
function leakyExport(): ControlPlaneExport {
  return {
    v: 1,
    exportedAt: "2026-06-29T00:00:00.000Z",
    configVersion: 0,
    configContentHash: "leak-hash",
    engineAccountId: null,
    priorAuditHead: { headSeq: 0, headHash: "h" },
    downpipes: [],
    destinations: [{ id: "x", secretAccessKey: "PLAINTEXT-LEAK" }],
    defaultDestinationId: null,
    roles: [],
    groupRoles: [],
    customRoles: [],
    discovery: null,
    orgPolicy: { requireConfigApproval: false },
    reestablish: [],
  } as unknown as ControlPlaneExport;
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
    // ---- Build ONE real signed control-plane export from a seeded source DO (reused everywhere) ----
    const A = makeStack();
    await A.dobj.addDownpipe(makeConfig("dp-cov"));
    await A.dobj.saveDestinations({ list: [seedDest("d1", "plaintext-secret-no-wrap")], defaultId: "d1" } as DestinationCollection);
    await A.dobj.whoami("owner@example.com", "subj-owner", "access", null);
    const signer = await loadSigner(SIGNER_PRIVATE);
    const exp = await A.dobj.buildControlPlaneExport();
    const sig = await signControlPlaneExport(signer, exp);
    const wrongSig = (sig.startsWith("A") ? "B" : "A") + sig.slice(1); // valid b64url, wrong signature bytes

    // =====================================================================================
    // WHOAMI: the identity echo, both arms of every conditional spread.
    // =====================================================================================
    {
      // Access owner (bootstrap): subject PRESENT + sessionExpiresAt PRESENT; identityProvider/connId/
      // customRole/capabilities ABSENT (a built-in Access role).
      const w = makeStack();
      const env = mkEnv(w);
      const r = await call(env, "GET", "/admin/whoami", { jwt: await tokenFor("owner-w@cov.example") });
      ok("whoami(access): 200", r.status === 200);
      const b = (await r.json()) as Record<string, unknown>;
      ok("whoami(access): method access + role owner (bootstrap)", b.method === "access" && b.role === "owner");
      ok("whoami(access): subject present (caller.subject !== null arm)", typeof b.subject === "string");
      ok("whoami(access): sessionExpiresAt present (verdict.exp arm)", typeof b.sessionExpiresAt === "number");
      ok("whoami(access): identityProvider absent + connId absent", b.identityProvider === undefined && b.connId === undefined);
      ok("whoami(access): customRole absent + capabilities absent", b.customRole === undefined && b.capabilities === undefined);
    }
    {
      // Bare-token break-glass: subject ABSENT (null) + sessionExpiresAt ABSENT (token verdict has no exp).
      const w = makeStack();
      const env = mkEnv(w, { ADMIN_TOKEN });
      const r = await call(env, "GET", "/admin/whoami", { bearer: ADMIN_TOKEN });
      ok("whoami(token): 200", r.status === 200);
      const b = (await r.json()) as Record<string, unknown>;
      ok("whoami(token): method token + role owner", b.method === "token" && b.role === "owner");
      ok("whoami(token): subject absent (caller.subject === null arm)", b.subject === undefined);
      ok("whoami(token): sessionExpiresAt absent (no verdict.exp arm)", b.sessionExpiresAt === undefined);
    }
    {
      // The PRESENT arms of identityProvider/connId/customRole/capabilities via the REAL exported spoke with a
      // synthesised native-IdP + custom-role caller. handleIdentity is the unit under test; the body is its
      // real output, so asserting the echoed fields is asserting real behaviour.
      const w = makeStack();
      const caller: Caller = {
        method: "oidc" as Caller["method"],
        email: "auditor@cov.example",
        subject: "oidc:conn9|https://idp.cov.example/x|sub9",
        role: "viewer",
        groups: ["analysts"],
        identityProvider: "https://idp.cov.example/x",
        connId: "conn9",
        capabilities: new Set(["downpipe.read", "reports.read"]) as ReadonlySet<string> as NonNullable<Caller["capabilities"]>,
      };
      const verdict = { ok: true, method: "oidc", email: caller.email, subject: caller.subject, exp: 1_900_000_000, groups: caller.groups, identityProvider: caller.identityProvider, connId: caller.connId };
      const ctx = {
        req: new Request("https://engine.cov.example/admin/whoami", { method: "GET" }),
        env: mkEnv(w),
        url: new URL("https://engine.cov.example/admin/whoami"),
        scheduler: w.stub,
        caller,
        sub: "/whoami",
        sourceIp: null,
        runtime: undefined,
        verdict,
        isOnlyOwner: false,
        roleSource: "custom",
        customRole: { name: "auditor", label: "Auditor", capabilities: ["downpipe.read", "reports.read"] },
      } as unknown as RouterCtx;
      const r = (await handleIdentity(ctx))!;
      ok("whoami(oidc/custom): 200", r.status === 200);
      const b = (await r.json()) as Record<string, unknown>;
      ok("whoami(oidc/custom): identityProvider present arm", b.identityProvider === "https://idp.cov.example/x");
      ok("whoami(oidc/custom): connId present arm", b.connId === "conn9");
      ok("whoami(oidc/custom): customRole present arm", typeof b.customRole === "object" && (b.customRole as { name?: string }).name === "auditor");
      ok("whoami(oidc/custom): capabilities present arm (Set spread to array)", Array.isArray(b.capabilities) && (b.capabilities as string[]).includes("downpipe.read"));
    }

    // =====================================================================================
    // GET /roles + GET /control-plane/status (the straight DO-forward reads).
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const r = await call(env, "GET", "/admin/roles", { bearer: ADMIN_TOKEN });
      ok("GET /roles: 200 forwards to the DO role table", r.status === 200);
      const b = (await r.json()) as unknown;
      ok("GET /roles: returns the role-entry array", Array.isArray(b));

      const st = await call(env, "GET", "/admin/control-plane/status", { bearer: ADMIN_TOKEN });
      ok("GET /control-plane/status: 200 forwards to recovery-status", st.status === 200);
      const sb = (await st.json()) as { recoveryRequired?: unknown; configEmpty?: unknown };
      ok("GET /control-plane/status: carries recoveryRequired + configEmpty", sb.recoveryRequired !== undefined && sb.configEmpty !== undefined);
    }

    // =====================================================================================
    // IdP connection MANAGEMENT, owner via the bare-token break-glass (gate-pass + forward).
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const oidcProposal = {
        id: "entra", kind: "oidc", label: "Entra", presetId: "entra", enabled: true,
        issuer: "https://login.microsoftonline.com/TENANTID/v2.0", clientId: "client-abc",
        secretRef: { mode: "do-plaintext" }, scopes: ["openid", "email", "profile"],
        idTokenSigAlgs: ["RS256"], pkce: "required", clientAuth: "client_secret_post", requireNonce: true,
      };

      const pres = await call(env, "GET", "/admin/idp/presets", { bearer: ADMIN_TOKEN });
      ok("idp/presets (owner): 200", pres.status === 200);
      ok("idp/presets (owner): carries a presets catalogue", Array.isArray(((await pres.json()) as { presets?: unknown[] }).presets));

      const list0 = await call(env, "GET", "/admin/idp/connections", { bearer: ADMIN_TOKEN });
      ok("idp/connections list (owner): 200", list0.status === 200);

      const cr = await call(env, "POST", "/admin/idp/connections", { bearer: ADMIN_TOKEN, body: { proposal: oidcProposal, secret: "super-secret-value" } });
      ok("idp/connections create (owner): 200", cr.status === 200);
      const crb = (await cr.json()) as { ok?: boolean; conn?: { id?: string } };
      ok("idp/connections create (owner): ok + the connection is returned", crb.ok === true && crb.conn?.id === "entra");
      ok("idp/connections create (owner): secret stored write-only (idpsecret:<id>)", s.storage.rawGet("idpsecret:entra") === "super-secret-value");

      const list1 = (await (await call(env, "GET", "/admin/idp/connections", { bearer: ADMIN_TOKEN })).json()) as { connections?: Array<{ id?: string; enabled?: boolean }> };
      ok("idp/connections list (owner): the created connection appears", (list1.connections ?? []).some((c) => c.id === "entra" && c.enabled === true));

      const en = await call(env, "POST", "/admin/idp/connections/enabled", { bearer: ADMIN_TOKEN, body: { connId: "entra", enabled: false } });
      ok("idp/connections/enabled (owner): 200", en.status === 200);
      const list2 = (await (await call(env, "GET", "/admin/idp/connections", { bearer: ADMIN_TOKEN })).json()) as { connections?: Array<{ id?: string; enabled?: boolean }> };
      ok("idp/connections/enabled (owner): the disable took effect", (list2.connections ?? []).some((c) => c.id === "entra" && c.enabled === false));

      // cert rollover on an OIDC connection is a clean DO refusal (cert rollover is SAML-only): the route
      // forwarded (gate passed, body parsed) and returns the DO's honest ok:false reason.
      const ce = await call(env, "POST", "/admin/idp/connections/cert", { bearer: ADMIN_TOKEN, body: { connId: "entra", addCerts: ["x"] } });
      ok("idp/connections/cert (owner): 200 (forwarded to the DO)", ce.status === 200);
      const ceb = (await ce.json()) as { ok?: boolean; reason?: string };
      ok("idp/connections/cert (owner): DO refuses a cert rollover on a non-SAML connection", ceb.ok === false && /SAML/i.test(ceb.reason ?? ""));

      const del = await call(env, "POST", "/admin/idp/connections/delete", { bearer: ADMIN_TOKEN, body: { connId: "entra" } });
      ok("idp/connections/delete (owner): 200", del.status === 200);
      const list3 = (await (await call(env, "GET", "/admin/idp/connections", { bearer: ADMIN_TOKEN })).json()) as { connections?: Array<{ id?: string }> };
      ok("idp/connections/delete (owner): the connection is gone", !(list3.connections ?? []).some((c) => c.id === "entra"));

      // The malformed-body 400 arm of each route that parses AFTER the gate + rate-limit pre-check.
      const dBad = await call(env, "POST", "/admin/idp/connections/delete", { bearer: ADMIN_TOKEN, raw: "not json{" });
      ok("idp/connections/delete: malformed body -> 400", dBad.status === 400);
      const eBad = await call(env, "POST", "/admin/idp/connections/enabled", { bearer: ADMIN_TOKEN, raw: "not json{" });
      ok("idp/connections/enabled: malformed body -> 400", eBad.status === 400);
      const cBad = await call(env, "POST", "/admin/idp/connections/cert", { bearer: ADMIN_TOKEN, raw: "not json{" });
      ok("idp/connections/cert: malformed body -> 400", cBad.status === 400);
      // The two routes whose parse runs FIRST (before the gate).
      const cnBad = await call(env, "POST", "/admin/idp/connections", { bearer: ADMIN_TOKEN, raw: "not json{" });
      ok("idp/connections create: malformed body -> 400", cnBad.status === 400);
      const tBad = await call(env, "POST", "/admin/idp/test", { bearer: ADMIN_TOKEN, raw: "not json{" });
      ok("idp/test: malformed body -> 400", tBad.status === 400);
    }

    // =====================================================================================
    // IdP /test, owner (gate-pass): the read-only probe returns a structured 200 result.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      // An internal-host issuer is SSRF-refused inside the probe -> NO outbound fetch, a structured ok:false.
      const r = await call(env, "POST", "/admin/idp/test", { bearer: ADMIN_TOKEN, body: { proposal: { kind: "oidc", issuer: "https://169.254.169.254/oidc" } } });
      ok("idp/test (owner, object proposal): 200 structured result", r.status === 200);
      const rb = (await r.json()) as { ok?: boolean; checks?: Array<{ name?: string; status?: string }> };
      ok("idp/test (owner): ok:false with the SSRF issuer check failing", rb.ok === false && (rb.checks ?? []).some((c) => /issuer/i.test(c.name ?? "") && c.status === "fail"));
      // proposal as an ARRAY -> the !Array.isArray arm falls to {} -> unknown-kind structured fail.
      const rArr = await call(env, "POST", "/admin/idp/test", { bearer: ADMIN_TOKEN, body: { proposal: [1, 2, 3] } });
      ok("idp/test (owner, array proposal): 200 ok:false (array coerced to {})", rArr.status === 200 && ((await rArr.json()) as { ok?: boolean }).ok === false);
      // proposal NOT an object -> the typeof arm falls to {} -> unknown-kind structured fail.
      const rStr = await call(env, "POST", "/admin/idp/test", { bearer: ADMIN_TOKEN, body: { proposal: "nope" } });
      ok("idp/test (owner, non-object proposal): 200 ok:false (non-object coerced to {})", rStr.status === 200 && ((await rStr.json()) as { ok?: boolean }).ok === false);
    }

    // =====================================================================================
    // IdP /test-saved: the SAME read-only probe over a connection that is ALREADY STORED
    // (re-verification after an IdP-side change without retyping the config).
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      // Malformed body -> 400 (parse runs first, like /idp/test).
      const bad = await call(env, "POST", "/admin/idp/test-saved", { bearer: ADMIN_TOKEN, raw: "not json{" });
      ok("idp/test-saved: malformed body -> 400", bad.status === 400);
      // A connId that fails the slug shape -> 400 once the caller may probe (the gate saw "unknown").
      const shp = await call(env, "POST", "/admin/idp/test-saved", { bearer: ADMIN_TOKEN, body: { connId: "NOT A SLUG!" } });
      ok("idp/test-saved: malformed connId -> 400", shp.status === 400);
      // An unknown id is a structured failed CHECK, never a 500, so the console renders every outcome
      // through the one test-result surface.
      const unk = await call(env, "POST", "/admin/idp/test-saved", { bearer: ADMIN_TOKEN, body: { connId: "nope" } });
      ok("idp/test-saved: unknown connId -> 200", unk.status === 200);
      const unkB = (await unk.json()) as { ok?: boolean; checks?: Array<{ name?: string; status?: string }> };
      ok(
        "idp/test-saved: unknown connId -> ok:false with the connection-exists check failing",
        unkB.ok === false && (unkB.checks ?? []).some((c) => /connection/i.test(c.name ?? "") && c.status === "fail"),
      );
      // A STORED connection: create one, then probe it BY ID. The probe's outbound fetch is stubbed so
      // the validator stays offline-deterministic; reaching the stub proves the stored redacted record
      // (issuer and endpoints, no secret) drove the probe, and the connection-exists check is absent.
      const savedProposal = {
        id: "entra", kind: "oidc", label: "Entra", presetId: "entra", enabled: true,
        issuer: "https://login.microsoftonline.com/TENANTID/v2.0", clientId: "client-abc",
        secretRef: { mode: "do-plaintext" }, scopes: ["openid", "email", "profile"],
        idTokenSigAlgs: ["RS256"], pkce: "required", clientAuth: "client_secret_post", requireNonce: true,
      };
      const cr = await call(env, "POST", "/admin/idp/connections", { bearer: ADMIN_TOKEN, body: { proposal: savedProposal, secret: "super-secret-value" } });
      ok("idp/test-saved: seed connection created", cr.status === 200 && ((await cr.json()) as { ok?: boolean }).ok === true);
      const realFetch = globalThis.fetch;
      let probeFetches = 0;
      globalThis.fetch = (async () => {
        probeFetches += 1;
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      }) as typeof fetch;
      try {
        const sv = await call(env, "POST", "/admin/idp/test-saved", { bearer: ADMIN_TOKEN, body: { connId: "entra" } });
        ok("idp/test-saved (owner, stored connection): 200 structured result", sv.status === 200);
        const svB = (await sv.json()) as { ok?: boolean; checks?: Array<{ name?: string; status?: string }> };
        ok("idp/test-saved (owner, stored connection): a checks array is returned", Array.isArray(svB.checks));
        ok(
          "idp/test-saved (owner, stored connection): the lookup succeeded (no connection-exists failure)",
          !(svB.checks ?? []).some((c) => /connection exists/i.test(c.name ?? "") && c.status === "fail"),
        );
        ok("idp/test-saved (owner, stored connection): the probe fetched over the stored config", probeFetches > 0);
      } finally {
        globalThis.fetch = realFetch;
      }
    }

    // =====================================================================================
    // IdP routes, NON-OWNER Access viewer (gate-denied), incl. the denied-audit connId/connKind arms.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s);
      const OWNER = "idp-owner@cov.example";
      const VIEWER = "idp-viewer@cov.example";
      // First Access caller bootstraps as Owner; a second Access caller defaults to viewer (no keys.ceremony).
      ok("denied setup: owner bootstrap", ((await (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor(OWNER) })).json()) as { role?: string }).role === "owner");

      const dPres = await call(env, "GET", "/admin/idp/presets", { jwt: await tokenFor(VIEWER) });
      ok("idp/presets (viewer): 403", dPres.status === 403);
      const dList = await call(env, "GET", "/admin/idp/connections", { jwt: await tokenFor(VIEWER) });
      ok("idp/connections list (viewer): 403", dList.status === 403);
      const dDel = await call(env, "POST", "/admin/idp/connections/delete", { jwt: await tokenFor(VIEWER), body: { connId: "x" } });
      ok("idp/connections/delete (viewer): 403", dDel.status === 403);
      const dEn = await call(env, "POST", "/admin/idp/connections/enabled", { jwt: await tokenFor(VIEWER), body: { connId: "x", enabled: true } });
      ok("idp/connections/enabled (viewer): 403", dEn.status === 403);
      const dCert = await call(env, "POST", "/admin/idp/connections/cert", { jwt: await tokenFor(VIEWER), body: { connId: "x" } });
      ok("idp/connections/cert (viewer): 403", dCert.status === 403);

      // create denied: connId from a well-formed slug (regex pass) / a bad slug (regex fail) / no proposal.
      ok("idp/connections create (viewer, valid slug): 403", (await call(env, "POST", "/admin/idp/connections", { jwt: await tokenFor(VIEWER), body: { proposal: { id: "deny-slug" } } })).status === 403);
      ok("idp/connections create (viewer, bad slug): 403", (await call(env, "POST", "/admin/idp/connections", { jwt: await tokenFor(VIEWER), body: { proposal: { id: "BAD SLUG!" } } })).status === 403);
      ok("idp/connections create (viewer, no proposal): 403", (await call(env, "POST", "/admin/idp/connections", { jwt: await tokenFor(VIEWER), body: {} })).status === 403);

      // test denied: connKind saml / oauth2 / oidc-default, with the connId slug + unknown arms.
      ok("idp/test (viewer, saml + slug): 403", (await call(env, "POST", "/admin/idp/test", { jwt: await tokenFor(VIEWER), body: { proposal: { id: "test-slug", kind: "saml" } } })).status === 403);
      ok("idp/test (viewer, oauth2 + no id): 403", (await call(env, "POST", "/admin/idp/test", { jwt: await tokenFor(VIEWER), body: { proposal: { kind: "oauth2" } } })).status === 403);
      ok("idp/test (viewer, no proposal): 403", (await call(env, "POST", "/admin/idp/test", { jwt: await tokenFor(VIEWER), body: {} })).status === 403);

      // The denied attempts recorded the audit events (the real effect of the denied arms).
      const audit = (await (await call(env, "GET", "/admin/audit?limit=100", { jwt: await tokenFor(OWNER) })).json()) as { events?: Array<{ action?: string; outcome?: string; target?: { connId?: string; connKind?: string; op?: string } }> };
      const ev = audit.events ?? [];
      const find = (op: string, connId: string, connKind?: string): boolean =>
        ev.some((e) => e.action === "idp-connection-change" && e.outcome === "denied" && e.target?.op === op && e.target?.connId === connId && (connKind === undefined || e.target?.connKind === connKind));
      ok("denied audit: create with the well-formed slug connId", find("create", "deny-slug"));
      ok("denied audit: create with the bad slug coerced to 'unknown'", find("create", "unknown"));
      ok("denied audit: test slug connId + connKind saml", find("test", "test-slug", "saml"));
      ok("denied audit: test connKind oauth2 (no id -> unknown)", find("test", "unknown", "oauth2"));
      ok("denied audit: test connKind defaults to oidc", find("test", "unknown", "oidc"));
    }

    // =====================================================================================
    // Rate-limit 429: the `if (limited) return limited` TRUE arm for every mutating IdP route.
    // Seed the per-caller "token" bucket at the cap inside the live window so each POST is refused.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      s.storage.rawPut("ratelimit:token", { windowStart: Date.now(), count: 120 });
      const cn = await call(env, "POST", "/admin/idp/connections", { bearer: ADMIN_TOKEN, body: { proposal: { id: "rl" } } });
      ok("rate-limit: idp/connections create -> 429", cn.status === 429);
      ok("rate-limit: idp/connections/delete -> 429", (await call(env, "POST", "/admin/idp/connections/delete", { bearer: ADMIN_TOKEN, body: { connId: "x" } })).status === 429);
      ok("rate-limit: idp/connections/enabled -> 429", (await call(env, "POST", "/admin/idp/connections/enabled", { bearer: ADMIN_TOKEN, body: { connId: "x", enabled: true } })).status === 429);
      ok("rate-limit: idp/connections/cert -> 429", (await call(env, "POST", "/admin/idp/connections/cert", { bearer: ADMIN_TOKEN, body: { connId: "x" } })).status === 429);
      ok("rate-limit: idp/test -> 429", (await call(env, "POST", "/admin/idp/test", { bearer: ADMIN_TOKEN, body: { proposal: { kind: "oidc" } } })).status === 429);
    }

    // =====================================================================================
    // DEMO-ONLY reset (POST /admin/demo/reset), DEMO_MODE on.
    // =====================================================================================
    {
      // The bearer gate, all three || sub-conditions. authorise passes via a valid Access caller; the case
      // re-checks the ADMIN_TOKEN bearer directly, so a valid session + a missing/wrong bearer is the 401.
      const g = makeStack();
      const jwt = await tokenFor("demo-caller@cov.example");
      // (a) ADMIN_TOKEN absent (typeof !== "string").
      ok("demo/reset: env without ADMIN_TOKEN -> 401", (await call(mkEnv(g, { DEMO_MODE: "true" }), "POST", "/admin/demo/reset", { jwt, bearer: "anything" })).status === 401);
      // (b) ADMIN_TOKEN === "" (length 0).
      ok("demo/reset: empty ADMIN_TOKEN -> 401", (await call(mkEnv(g, { DEMO_MODE: "true", ADMIN_TOKEN: "" }), "POST", "/admin/demo/reset", { jwt, bearer: "anything" })).status === 401);
      // (c) ADMIN_TOKEN set, wrong bearer (constant-time mismatch).
      ok("demo/reset: wrong bearer -> 401", (await call(mkEnv(g, { DEMO_MODE: "true", ADMIN_TOKEN }), "POST", "/admin/demo/reset", { jwt, bearer: "not-the-token" })).status === 401);
      // (d) NO Authorization header at all (the `?? ""` empty-bearer arm) -> still 401.
      ok("demo/reset: no Authorization header -> 401", (await call(mkEnv(g, { DEMO_MODE: "true", ADMIN_TOKEN }), "POST", "/admin/demo/reset", { jwt })).status === 401);
      // regression: a BYTE-CORRECT bearer must still be refused once the token is disabled or the DO
      // retire-latch is set (requireLiveBreakGlassToken) -- a raw tokenEqual pass alone must never be enough.
      ok("demo/reset: ADMIN_TOKEN_DISABLED + correct bearer -> 401", (await call(mkEnv(g, { DEMO_MODE: "true", ADMIN_TOKEN, ADMIN_TOKEN_DISABLED: "true" }), "POST", "/admin/demo/reset", { jwt, bearer: ADMIN_TOKEN })).status === 401);
      const gRetired = makeStack();
      await gRetired.dobj.writeOrgPolicy({ breakGlassTokenRetired: true });
      ok("demo/reset: DO-retired latch + correct bearer -> 401", (await call(mkEnv(gRetired, { DEMO_MODE: "true", ADMIN_TOKEN }), "POST", "/admin/demo/reset", { jwt, bearer: ADMIN_TOKEN })).status === 401);
    }
    {
      // The DEFENSIVE reply-mapping arms: a DO reset reply that is NOT ok -> 500, and an ok reply that omits
      // `cleared` -> the `out.cleared ?? null` null arm in the 200 body. The DO is forwarded for /demo/mark;
      // only the /demo/reset reply is the controlled double.
      const g500 = makeStack({ override: (url) => (url.endsWith("/demo/reset") ? new Response(JSON.stringify({ ok: false }), { status: 500, headers: { "content-type": "application/json" } }) : null) });
      const r500 = await call(mkEnv(g500, { DEMO_MODE: "true", ADMIN_TOKEN }), "POST", "/admin/demo/reset", { bearer: ADMIN_TOKEN });
      ok("demo/reset: a not-ok DO reset reply -> 500", r500.status === 500 && /demo reset failed/.test(((await r500.json()) as { error?: string }).error ?? ""));
      const gNoCleared = makeStack({ override: (url) => (url.endsWith("/demo/reset") ? new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } }) : null) });
      const rNC = await call(mkEnv(gNoCleared, { DEMO_MODE: "true", ADMIN_TOKEN }), "POST", "/admin/demo/reset", { bearer: ADMIN_TOKEN });
      ok("demo/reset: an ok reply without `cleared` -> 200 with cleared null", rNC.status === 200 && ((await rNC.json()) as { cleared?: unknown }).cleared === null);
    }
    {
      // HAPPY PATH, no default destination configured -> runlogCleared false + the warn note.
      const g = makeStack();
      const r = await call(mkEnv(g, { DEMO_MODE: "true", ADMIN_TOKEN }), "POST", "/admin/demo/reset", { bearer: ADMIN_TOKEN });
      ok("demo/reset (no dest): 200", r.status === 200);
      const b = (await r.json()) as { ok?: boolean; reset?: boolean; runlogCleared?: boolean; note?: string; cleared?: unknown };
      ok("demo/reset (no dest): ok + reset:true", b.ok === true && b.reset === true);
      ok("demo/reset (no dest): runlogCleared false (clearDestinationRunlog catch arm)", b.runlogCleared === false);
      ok("demo/reset (no dest): cleared is a number (out.cleared ?? null left arm)", typeof b.cleared === "number");
      ok("demo/reset (no dest): the note warns to empty the bucket", /empty the destination bucket/.test(b.note ?? ""));
    }
    {
      // HAPPY PATH WITH a default R2 destination -> the surviving signed RUNLOG (+ .sig) are deleted.
      const g = makeStack();
      const r2 = new MockR2Bucket();
      r2.store.set("_RECOVERY/RUNLOG", new Uint8Array([1, 2, 3]));
      r2.store.set("_RECOVERY/RUNLOG.sig", new Uint8Array([4, 5, 6]));
      const r = await call(mkEnv(g, { DEMO_MODE: "true", ADMIN_TOKEN, DEST_R2: r2 }), "POST", "/admin/demo/reset", { bearer: ADMIN_TOKEN });
      ok("demo/reset (R2 dest): 200", r.status === 200);
      const b = (await r.json()) as { runlogCleared?: boolean; note?: string };
      ok("demo/reset (R2 dest): runlogCleared true (clearDestinationRunlog success arm)", b.runlogCleared === true);
      ok("demo/reset (R2 dest): the RUNLOG + .sig were deleted from the bucket", !r2.has("_RECOVERY/RUNLOG") && !r2.has("_RECOVERY/RUNLOG.sig"));
      ok("demo/reset (R2 dest): the note reports the cleared RUNLOG", /RUNLOG cleared/.test(b.note ?? ""));
    }
    {
      // The DO refuses an UNMARKED reset: the router's /demo/mark forward throws (fail-open catch), so the DO
      // sees no marker and returns 403, which the route surfaces as a 403.
      const g = makeStack({ failMark: true });
      const r = await call(mkEnv(g, { DEMO_MODE: "true", ADMIN_TOKEN }), "POST", "/admin/demo/reset", { bearer: ADMIN_TOKEN });
      ok("demo/reset (mark throws -> unmarked DO): 403", r.status === 403);
      ok("demo/reset (unmarked DO): the refusal explains it is not marked as a demo", /not marked as a demo/.test(((await r.json()) as { error?: string }).error ?? ""));
    }

    // =====================================================================================
    // POST /control-plane/restore (the break-glass reconcile).
    // =====================================================================================
    {
      // The bearer gate, all three sub-conditions (authorise via Access; the case re-checks the bearer).
      const g = makeStack();
      const jwt = await tokenFor("cp-caller@cov.example");
      ok("restore: env without ADMIN_TOKEN -> 401", (await call(mkEnv(g, {}), "POST", "/admin/control-plane/restore", { jwt, bearer: "x", body: {} })).status === 401);
      ok("restore: empty ADMIN_TOKEN -> 401", (await call(mkEnv(g, { ADMIN_TOKEN: "" }), "POST", "/admin/control-plane/restore", { jwt, bearer: "x", body: {} })).status === 401);
      ok("restore: wrong bearer -> 401", (await call(mkEnv(g, { ADMIN_TOKEN }), "POST", "/admin/control-plane/restore", { jwt, bearer: "wrong", body: {} })).status === 401);
      ok("restore: no Authorization header -> 401", (await call(mkEnv(g, { ADMIN_TOKEN }), "POST", "/admin/control-plane/restore", { jwt, body: {} })).status === 401);
      // regression: a BYTE-CORRECT bearer must still be refused once the token is disabled or the DO
      // retire-latch is set (requireLiveBreakGlassToken) -- this is the permanent-re-escalation gap: a
      // "retired" ADMIN_TOKEN plus any historically-valid signed export must never rebuild the control plane.
      ok("restore: ADMIN_TOKEN_DISABLED + correct bearer -> 401", (await call(mkEnv(g, { ADMIN_TOKEN, ADMIN_TOKEN_DISABLED: "true" }), "POST", "/admin/control-plane/restore", { jwt, bearer: ADMIN_TOKEN, body: {} })).status === 401);
      const gRetired = makeStack();
      await gRetired.dobj.writeOrgPolicy({ breakGlassTokenRetired: true });
      ok("restore: DO-retired latch + correct bearer -> 401", (await call(mkEnv(gRetired, { ADMIN_TOKEN }), "POST", "/admin/control-plane/restore", { jwt, bearer: ADMIN_TOKEN, body: {} })).status === 401);
    }
    {
      const g = makeStack();
      const base = mkEnv(g, { ADMIN_TOKEN, SIGNER_PRIVATE });
      // malformed JSON body.
      ok("restore: malformed body -> 400", (await call(base, "POST", "/admin/control-plane/restore", { bearer: ADMIN_TOKEN, raw: "not json{" })).status === 400);
      // not a control-plane export artefact.
      ok("restore: export fails the shape gate -> 400", (await call(base, "POST", "/admin/control-plane/restore", { bearer: ADMIN_TOKEN, body: { export: {}, signature: "x" } })).status === 400);
      // signature missing (typeof !== string) and empty (length 0).
      ok("restore: signature undefined -> 400", (await call(base, "POST", "/admin/control-plane/restore", { bearer: ADMIN_TOKEN, body: { export: exp } })).status === 400);
      ok("restore: signature empty -> 400", (await call(base, "POST", "/admin/control-plane/restore", { bearer: ADMIN_TOKEN, body: { export: exp, signature: "" } })).status === 400);
      // no-custody violation (a plaintext secret smuggled into an otherwise shape-valid export).
      const ncv = await call(base, "POST", "/admin/control-plane/restore", { bearer: ADMIN_TOKEN, body: { export: leakyExport(), signature: "x" } });
      ok("restore: a plaintext secret is refused (no-custody) -> 400", ncv.status === 400 && /refused/.test(((await ncv.json()) as { error?: string }).error ?? ""));
      // SIGNER_PRIVATE not configured (typeof !== string) and empty (length 0).
      ok("restore: SIGNER_PRIVATE absent -> 500", (await call(mkEnv(g, { ADMIN_TOKEN }), "POST", "/admin/control-plane/restore", { bearer: ADMIN_TOKEN, body: { export: exp, signature: sig } })).status === 500);
      ok("restore: SIGNER_PRIVATE empty -> 500", (await call(mkEnv(g, { ADMIN_TOKEN, SIGNER_PRIVATE: "" }), "POST", "/admin/control-plane/restore", { bearer: ADMIN_TOKEN, body: { export: exp, signature: sig } })).status === 500);
      // signature verify returns false (wrong signature) and the verify path THROWS (signer load fails).
      // wrongSig flips the FIRST base64url character, which damages the Ed25519 half of the signature and
      // leaves the ML-DSA half intact. Both halves cover the SAME export bytes, so the post-quantum half still
      // verifies -- which PROVES the export was not altered, and puts the damage in the operator's own artefact.
      // The refusal is unchanged (400); what changed is that it no longer tells this customer their disaster-
      // recovery export was tampered with. A tamper breaks BOTH halves and still lands on the tamper sentence.
      const vf = await call(base, "POST", "/admin/control-plane/restore", { bearer: ADMIN_TOKEN, body: { export: exp, signature: wrongSig } });
      const vfBody = ((await vf.json()) as { error?: string; refusalClass?: string }) ?? {};
      ok("restore: a DAMAGED classical signature half does not verify -> 400", vf.status === 400 && /did not verify/.test(vfBody.error ?? ""));
      ok("restore: ...and it is NOT reported as tamper -- the post-quantum half proves the export INTACT", /INTACT/.test(vfBody.error ?? "") && /not tampering/.test(vfBody.error ?? "") && vfBody.refusalClass === "classical-half-damaged");
      // a signer-load fault is STILL caught and STILL refuses with a 400 -- but it is no longer reported
      // as "the signature did not verify". This test pinned the exact conflation the gap exists to end: the
      // engine's OWN signer key would not load, so the signature was never CHECKED AT ALL, and telling the
      // operator their recovery artefact does not verify sends them hunting a tamper that never happened. The
      // refusal is unchanged (400); only the claim about WHY is now true.
      const vc = await call(mkEnv(g, { ADMIN_TOKEN, SIGNER_PRIVATE: "tooshort" }), "POST", "/admin/control-plane/restore", { bearer: ADMIN_TOKEN, body: { export: exp, signature: sig } });
      const vcErr = ((await vc.json()) as { error?: string }).error ?? "";
      ok("restore: a signer-load fault is caught -> 400", vc.status === 400);
      ok("restore: it says the KEY is damaged, NOT that the signature did not verify (a broken key is not a tamper)", /KEY is damaged/.test(vcErr) && !/did not verify/.test(vcErr));
    }
    {
      // HAPPY PATH + reconcile-refused, all against one fresh empty target DO. There is no force overwrite:
      // a non-empty plane is always refused, and a stray force field in the body is ignored.
      const R = makeStack();
      const env = mkEnv(R, { ADMIN_TOKEN, SIGNER_PRIVATE });
      const happy = await call(env, "POST", "/admin/control-plane/restore", { bearer: ADMIN_TOKEN, body: { export: exp, signature: sig } });
      ok("restore happy: 200", happy.status === 200);
      const hb = (await happy.json()) as { ok?: boolean; downpipes?: number; destinations?: number; roles?: number };
      ok("restore happy: the wiped plane is rebuilt (downpipe + destination + role)", hb.ok === true && hb.downpipes === 1 && hb.destinations === 1 && (hb.roles ?? 0) >= 1);
      // a second restore is refused (the plane is now non-empty) -> the DO 400 surfaces as 400.
      const again = await call(env, "POST", "/admin/control-plane/restore", { bearer: ADMIN_TOKEN, body: { export: exp, signature: sig } });
      ok("restore refused: a non-empty plane -> 400", again.status === 400 && /reconcile refused/.test(((await again.json()) as { error?: string }).error ?? ""));
      // there is no force overwrite: a stray force:true in the body is IGNORED; the non-empty plane stays refused.
      const stillRefused = await call(env, "POST", "/admin/control-plane/restore", { bearer: ADMIN_TOKEN, body: { export: exp, signature: sig, force: true } });
      ok("restore: a force field is ignored; a non-empty plane stays refused -> 400", stillRefused.status === 400 && /reconcile refused/.test(((await stillRefused.json()) as { error?: string }).error ?? ""));
    }
    {
      // The DEFENSIVE 403-mapping arm: a 403 from the reconcile forward is propagated as 403 (the route's own
      // token caller cannot provoke the DO's non-token 403, so the reconcile reply is the controlled double;
      // the signature still verifies for real before the forward).
      const g = makeStack({ override: (url) => (url.endsWith("/control-plane/reconcile") ? new Response(JSON.stringify({ error: "forbidden" }), { status: 403, headers: { "content-type": "application/json" } }) : null) });
      const r = await call(mkEnv(g, { ADMIN_TOKEN, SIGNER_PRIVATE }), "POST", "/admin/control-plane/restore", { bearer: ADMIN_TOKEN, body: { export: exp, signature: sig } });
      ok("restore: a 403 from the DO reconcile is propagated as 403", r.status === 403 && /reconcile refused/.test(((await r.json()) as { error?: string }).error ?? ""));
    }

    // =====================================================================================
    // POST /control-plane/restore-sealed -- the break-glass SEALED reconcile, for the estate whose
    // engine holds no CONFIG_RECIPIENT_PRIVATE (so the cron auto-heal cannot open its own sealed export
    // either). The operator's OWN break-glass identity.key opens the SAME sealed capsule (a second,
    // independent recipient); the unseal runs in the "browser" here (openSealedControlPlaneExport, called
    // directly, exactly as keydecap.ts would) and ONLY the recovered PLAINTEXT + the still-sealed wrapper +
    // its signature ride over the wire -- the private identity is never a field on the request.
    // =====================================================================================
    {
      // A real break-glass identity: X25519 scalar(32) || ML-KEM seed(64), round-tripped through the same
      // 96-byte labelled encoding the offline downpipe reader's identity.key uses (loadIdentity/parseIdentity).
      const bgScalar = crypto.getRandomValues(new Uint8Array(32));
      const bgSeed = crypto.getRandomValues(new Uint8Array(64));
      const bgPriv = loadIdentity(b64urlEncode(new Uint8Array([...bgScalar, ...bgSeed])));
      const bgPub = { x25519: x25519PublicFromScalar(bgScalar), mlkemEk: mlkemKeygen(bgSeed).encapKey };
      const rsNonceFor = (): Uint8Array => crypto.getRandomValues(new Uint8Array(16));
      const sealed = await sealControlPlaneExport(exp, [{ role: "break-glass", pub: bgPub }], rsNonceFor);
      const sealedSig = await signSealedControlPlaneExport(signer, sealed);
      // THE BROWSER STEP: unseal locally with the identity private. This is the ONLY place bgPriv is ever
      // used in this test -- it never appears in a request body below, which is the structural proof that
      // this route never receives it.
      const recovered = await openSealedControlPlaneExport(sealed, bgPriv);
      ok("restore-sealed: the browser-side unseal recovers the ORIGINAL export (deep-equal; key order differs after the canonical-JSON round trip)", isDeepStrictEqual(recovered, exp));

      // The bearer gate, same three sub-conditions as /restore and /apply-staged.
      const g = makeStack();
      const jwt = await tokenFor("rs-caller@cov.example");
      ok("restore-sealed: env without ADMIN_TOKEN -> 401", (await call(mkEnv(g, {}), "POST", "/admin/control-plane/restore-sealed", { jwt, bearer: "x", body: {} })).status === 401);
      ok("restore-sealed: wrong bearer -> 401", (await call(mkEnv(g, { ADMIN_TOKEN }), "POST", "/admin/control-plane/restore-sealed", { jwt, bearer: "wrong" })).status === 401);
      ok("restore-sealed: ADMIN_TOKEN_DISABLED + correct bearer -> 401", (await call(mkEnv(g, { ADMIN_TOKEN, ADMIN_TOKEN_DISABLED: "true" }), "POST", "/admin/control-plane/restore-sealed", { jwt, bearer: ADMIN_TOKEN })).status === 401);

      const base = mkEnv(g, { ADMIN_TOKEN, SIGNER_PRIVATE });
      // Malformed / shape / missing-field refusals -- each its own closed class, never coalesced.
      ok("restore-sealed: malformed body -> 400", (await call(base, "POST", "/admin/control-plane/restore-sealed", { bearer: ADMIN_TOKEN, raw: "not json{" })).status === 400);
      const notSealed = await call(base, "POST", "/admin/control-plane/restore-sealed", { bearer: ADMIN_TOKEN, body: { sealed: { v: 1 }, sealedSignature: sealedSig, export: recovered } });
      ok("restore-sealed: a non-sealed-shape body -> 400 shape", notSealed.status === 400 && ((await notSealed.json()) as { refusalClass?: string }).refusalClass === "shape");
      const noSig = await call(base, "POST", "/admin/control-plane/restore-sealed", { bearer: ADMIN_TOKEN, body: { sealed, export: recovered } });
      ok("restore-sealed: a missing sealedSignature -> 400 malformed", noSig.status === 400 && ((await noSig.json()) as { refusalClass?: string }).refusalClass === "malformed");
      const emptySig = await call(base, "POST", "/admin/control-plane/restore-sealed", { bearer: ADMIN_TOKEN, body: { sealed, sealedSignature: "", export: recovered } });
      ok("restore-sealed: an empty sealedSignature -> 400 malformed", emptySig.status === 400 && ((await emptySig.json()) as { refusalClass?: string }).refusalClass === "malformed");
      const badExp = await call(base, "POST", "/admin/control-plane/restore-sealed", { bearer: ADMIN_TOKEN, body: { sealed, sealedSignature: sealedSig, export: { not: "an export" } } });
      ok("restore-sealed: a non-export plaintext -> 400 shape", badExp.status === 400 && ((await badExp.json()) as { refusalClass?: string }).refusalClass === "shape");
      // no-custody: a shape-valid but secret-leaking plaintext is refused even though the sealed wrapper
      // it is paired with here is unrelated (the no-custody check runs on the plaintext alone, first).
      const ncv = await call(base, "POST", "/admin/control-plane/restore-sealed", { bearer: ADMIN_TOKEN, body: { sealed, sealedSignature: sealedSig, export: leakyExport() } });
      ok("restore-sealed: a plaintext secret is refused (no-custody) -> 400", ncv.status === 400 && /refused/.test(((await ncv.json()) as { error?: string }).error ?? ""));
      // SIGNER_PRIVATE absent -> 500 (this route verifies the SEALED wrapper against the engine's OWN
      // signer, same as plaintext /restore -- it never accepts an operator-supplied verifier).
      ok("restore-sealed: SIGNER_PRIVATE absent -> 500", (await call(mkEnv(g, { ADMIN_TOKEN }), "POST", "/admin/control-plane/restore-sealed", { bearer: ADMIN_TOKEN, body: { sealed, sealedSignature: sealedSig, export: recovered } })).status === 500);

      // A WRONG engine signer (a different key entirely) fails the sealed-wrapper verify --'s tamper
      // class, same discrimination the plaintext route and import-sealed already prove.
      const otherSigner = await loadSigner(b64urlEncode(crypto.getRandomValues(new Uint8Array(64))));
      const otherSealedSig = await signSealedControlPlaneExport(otherSigner, sealed);
      const wrongSignerCall = await call(base, "POST", "/admin/control-plane/restore-sealed", { bearer: ADMIN_TOKEN, body: { sealed, sealedSignature: otherSealedSig, export: recovered } });
      ok("restore-sealed: a sealed signature from a DIFFERENT signer -> 400", wrongSignerCall.status === 400);
      ok("restore-sealed: ...classed as tamper (signature), the only class a genuinely wrong key/altered artefact reaches", ((await wrongSignerCall.json()) as { refusalClass?: string }).refusalClass === "signature");

      // A plaintext not matching the SIGNED bodyHash -> its own class, never no-custody or a bare shape (both
      // artefacts are individually well-formed; they just do not correspond to one another).
      const mismatchExp = { ...recovered, downpipes: [...recovered.downpipes, { ...(recovered.downpipes[0] as object), id: "dp-injected-rs" }] } as typeof recovered;
      const mismatch = await call(base, "POST", "/admin/control-plane/restore-sealed", { bearer: ADMIN_TOKEN, body: { sealed, sealedSignature: sealedSig, export: mismatchExp } });
      ok("restore-sealed: a plaintext not matching the signed bodyHash -> 400", mismatch.status === 400 && ((await mismatch.json()) as { refusalClass?: string }).refusalClass === "sealed-body-mismatch");

      // A sealed artefact predating bodyHash -> refused honestly rather than trusting the plaintext.
      const unhashedSealed = { ...sealed };
      delete (unhashedSealed as { bodyHash?: string }).bodyHash;
      const unhashedSig = await signSealedControlPlaneExport(signer, unhashedSealed as SealedControlPlaneExport);
      const unhashed = await call(base, "POST", "/admin/control-plane/restore-sealed", { bearer: ADMIN_TOKEN, body: { sealed: unhashedSealed, sealedSignature: unhashedSig, export: recovered } });
      ok("restore-sealed: an artefact without bodyHash refuses honestly rather than trusting the plaintext", unhashed.status === 400 && ((await unhashed.json()) as { refusalClass?: string }).refusalClass === "sealed-unhashed");

      // ---- HAPPY PATH + AUTHORITY POSTURE PROOFS, against one fresh empty target DO ----
      const R = makeStack();
      const rEnv = mkEnv(R, { ADMIN_TOKEN, SIGNER_PRIVATE });
      const happyReqBody = { sealed, sealedSignature: sealedSig, export: recovered };
      const happy = await call(rEnv, "POST", "/admin/control-plane/restore-sealed", { bearer: ADMIN_TOKEN, body: happyReqBody });
      ok("restore-sealed happy: 200", happy.status === 200);
      const hb = (await happy.json()) as { ok?: boolean; downpipes?: number; destinations?: number; roles?: number };
      ok("restore-sealed happy: the wiped plane is rebuilt (downpipe + destination + role)", hb.ok === true && hb.downpipes === 1 && hb.destinations === 1 && (hb.roles ?? 0) >= 1);
      // AUTHORITY POSTURE, proved both ways: this route DOES restore authority (unlike import-sealed, which
      // by design never returns a `roles` field at all) -- and ONLY through the break-glass gate above, never
      // through the sealed-shape/bodyHash proof alone. The restored Owner resolves for real.
      const restoredWho = await R.dobj.whoami("owner@example.com", "subj-owner", "access", null);
      ok("restore-sealed happy: the restored Owner resolves to Owner (authority genuinely restored)", restoredWho.role === "owner");
      // NO KEY MATERIAL TRAVELLED: neither the request body nor the response carries the break-glass private
      // (the scalar or the seed, in any encoding this test can construct) or the identity's own b64url form.
      const bgPrivB64 = b64urlEncode(new Uint8Array([...bgScalar, ...bgSeed]));
      const wireText = JSON.stringify(happyReqBody) + JSON.stringify(hb);
      ok("restore-sealed happy: the wire carries no break-glass private material (scalar, seed, or the identity.key encoding)", !wireText.includes(bgPrivB64) && !wireText.includes(b64urlEncode(bgScalar)) && !wireText.includes(b64urlEncode(bgSeed)));
      // A second restore-sealed is refused (the plane is now non-empty) -- never overwrites a live estate,
      // exactly the guard the plaintext route already relies on (same DO reconcile, no new DO code).
      const again = await call(rEnv, "POST", "/admin/control-plane/restore-sealed", { bearer: ADMIN_TOKEN, body: happyReqBody });
      ok("restore-sealed refused: a non-empty plane -> 400", again.status === 400 && /reconcile refused/.test(((await again.json()) as { error?: string }).error ?? ""));

      // The DEFENSIVE 403-mapping arm: a 403 from the reconcile forward is propagated as 403.
      const g403 = makeStack({ override: (url) => (url.endsWith("/control-plane/reconcile") ? new Response(JSON.stringify({ error: "forbidden" }), { status: 403, headers: { "content-type": "application/json" } }) : null) });
      const r403 = await call(mkEnv(g403, { ADMIN_TOKEN, SIGNER_PRIVATE }), "POST", "/admin/control-plane/restore-sealed", { bearer: ADMIN_TOKEN, body: happyReqBody });
      ok("restore-sealed: a 403 from the DO reconcile is propagated as 403", r403.status === 403 && /reconcile refused/.test(((await r403.json()) as { error?: string }).error ?? ""));

      // DISCRIMINATION: reconcile-sealed's refusal rows are their OWN surface, never conflated with the
      // plaintext reconcile or the cross-environment estate-import-sealed (three structurally different
      // routes; a shared counter here would hide which one an operator actually hit).
      const refusalRows = async (stack: Stack): Promise<Record<string, number>> => {
        const rr = await stack.stub.fetch(new Request("https://do/recovery-refusals"));
        const body = (await rr.json()) as { refusals?: { bySurfaceClass?: Record<string, number> } };
        return body.refusals?.bySurfaceClass ?? {};
      };
      const rows = await refusalRows(g);
      ok("restore-sealed: refusals are recorded under their OWN surface (reconcile-sealed)", Object.keys(rows).some((k) => k.startsWith("reconcile-sealed|")));
      ok("restore-sealed: ...never under the plaintext reconcile surface", !Object.keys(rows).some((k) => k.startsWith("reconcile|")));
      ok("restore-sealed: ...never under estate-import-sealed (a different route, different trust model)", !Object.keys(rows).some((k) => k.startsWith("estate-import-sealed|")));
    }

    // =====================================================================================
    // POST /control-plane/apply-staged (the auto-heal break-glass confirm).
    // =====================================================================================
    {
      // The bearer gate, all three sub-conditions.
      const g = makeStack();
      const jwt = await tokenFor("as-caller@cov.example");
      ok("apply-staged: env without ADMIN_TOKEN -> 401", (await call(mkEnv(g, {}), "POST", "/admin/control-plane/apply-staged", { jwt, bearer: "x" })).status === 401);
      ok("apply-staged: empty ADMIN_TOKEN -> 401", (await call(mkEnv(g, { ADMIN_TOKEN: "" }), "POST", "/admin/control-plane/apply-staged", { jwt, bearer: "x" })).status === 401);
      ok("apply-staged: wrong bearer -> 401", (await call(mkEnv(g, { ADMIN_TOKEN }), "POST", "/admin/control-plane/apply-staged", { jwt, bearer: "wrong" })).status === 401);
      ok("apply-staged: no Authorization header -> 401", (await call(mkEnv(g, { ADMIN_TOKEN }), "POST", "/admin/control-plane/apply-staged", { jwt })).status === 401);
      // regression: a BYTE-CORRECT bearer must still be refused once the token is disabled or the DO
      // retire-latch is set (requireLiveBreakGlassToken).
      ok("apply-staged: ADMIN_TOKEN_DISABLED + correct bearer -> 401", (await call(mkEnv(g, { ADMIN_TOKEN, ADMIN_TOKEN_DISABLED: "true" }), "POST", "/admin/control-plane/apply-staged", { jwt, bearer: ADMIN_TOKEN })).status === 401);
      const gRetired = makeStack();
      await gRetired.dobj.writeOrgPolicy({ breakGlassTokenRetired: true });
      ok("apply-staged: DO-retired latch + correct bearer -> 401", (await call(mkEnv(gRetired, { ADMIN_TOKEN }), "POST", "/admin/control-plane/apply-staged", { jwt, bearer: ADMIN_TOKEN })).status === 401);
    }
    {
      // nothing staged -> 409.
      const g = makeStack();
      const r = await call(mkEnv(g, { ADMIN_TOKEN, SIGNER_PRIVATE }), "POST", "/admin/control-plane/apply-staged", { bearer: ADMIN_TOKEN });
      ok("apply-staged: nothing staged -> 409", r.status === 409 && /nothing is staged/.test(((await r.json()) as { error?: string }).error ?? ""));
    }
    {
      // a staged record whose export fails the shape gate -> 409 malformed.
      const g = makeStack();
      g.dobj.stageControlPlaneRecovery({ export: {} as unknown as ControlPlaneExport, signature: "x", sourceKey: "k", version: 1, stagedAt: "2026-06-29T00:00:00.000Z", resumeApplied: false });
      const r = await call(mkEnv(g, { ADMIN_TOKEN, SIGNER_PRIVATE }), "POST", "/admin/control-plane/apply-staged", { bearer: ADMIN_TOKEN });
      ok("apply-staged: a malformed staged export -> 409", r.status === 409 && /malformed/.test(((await r.json()) as { error?: string }).error ?? ""));
    }
    {
      // a staged export carrying a plaintext secret -> the no-custody 400.
      const g = makeStack();
      g.dobj.stageControlPlaneRecovery(stagedFrom(leakyExport(), "x"));
      const r = await call(mkEnv(g, { ADMIN_TOKEN, SIGNER_PRIVATE }), "POST", "/admin/control-plane/apply-staged", { bearer: ADMIN_TOKEN });
      ok("apply-staged: a plaintext secret in the staged export -> 400", r.status === 400 && /refused/.test(((await r.json()) as { error?: string }).error ?? ""));
    }
    {
      // SIGNER_PRIVATE not configured -> 500.
      const g = makeStack();
      g.dobj.stageControlPlaneRecovery(stagedFrom(exp, sig));
      const r = await call(mkEnv(g, { ADMIN_TOKEN }), "POST", "/admin/control-plane/apply-staged", { bearer: ADMIN_TOKEN });
      ok("apply-staged: SIGNER_PRIVATE absent -> 500", r.status === 500 && /SIGNER_PRIVATE is not configured/.test(((await r.json()) as { error?: string }).error ?? ""));
    }
    {
      // staged signature does not verify (wrong sig) -> 400, and the signer-load fault catch -> 400.
      const g = makeStack();
      g.dobj.stageControlPlaneRecovery(stagedFrom(exp, wrongSig));
      const r = await call(mkEnv(g, { ADMIN_TOKEN, SIGNER_PRIVATE }), "POST", "/admin/control-plane/apply-staged", { bearer: ADMIN_TOKEN });
      // as above -- the ML-DSA half of the staged artefact's signature still verifies, so the staged EXPORT
      // is provably intact and the damage is in the classical half of the signature or the engine's signer key.
      ok("apply-staged: a wrong staged signature -> 400", r.status === 400 && /did not verify/.test(((await r.json()) as { error?: string }).error ?? ""));

      const g2 = makeStack();
      g2.dobj.stageControlPlaneRecovery(stagedFrom(exp, sig));
      // G202 (as above, on the staged-confirm path): a signer key that will not load means the staged artefact
      // was never checked. Refused identically (400); the reason no longer accuses the artefact.
      const r2 = await call(mkEnv(g2, { ADMIN_TOKEN, SIGNER_PRIVATE: "tooshort" }), "POST", "/admin/control-plane/apply-staged", { bearer: ADMIN_TOKEN });
      const r2Err = ((await r2.json()) as { error?: string }).error ?? "";
      ok("apply-staged: a signer-load fault is caught -> 400", r2.status === 400);
      ok("apply-staged: it says the KEY is damaged, NOT that the signature did not verify", /KEY is damaged/.test(r2Err) && !/did not verify/.test(r2Err));
    }
    {
      // HAPPY PATH: latch set + a valid staged export + an empty role table -> authority restored, 200.
      const g = makeStack();
      await g.dobj.setControlPlaneRecoveryRequired("config empty but bucket has runs");
      g.dobj.stageControlPlaneRecovery(stagedFrom(exp, sig));
      const r = await call(mkEnv(g, { ADMIN_TOKEN, SIGNER_PRIVATE }), "POST", "/admin/control-plane/apply-staged", { bearer: ADMIN_TOKEN });
      ok("apply-staged happy: 200", r.status === 200);
      const b = (await r.json()) as { ok?: boolean; roles?: number };
      ok("apply-staged happy: RBAC restored (roles >= 1)", b.ok === true && (b.roles ?? 0) >= 1);
      // the restored Owner now resolves to Owner with no re-bootstrap.
      const who = await g.dobj.whoami("owner@example.com", "subj-owner", "access", null);
      ok("apply-staged happy: the restored Owner resolves to Owner", who.role === "owner");
    }
    {
      // the DO refuses the authority restore over a NON-EMPTY role table (the clobber guard) -> the route's
      // not-ok arm surfaces a 400.
      const g = makeStack();
      await g.dobj.whoami("real-owner@cov.example", "subj-real", "access", null); // a pre-existing Owner
      await g.dobj.setControlPlaneRecoveryRequired("amnesia-like state with a non-empty table");
      g.dobj.stageControlPlaneRecovery(stagedFrom(exp, sig));
      const r = await call(mkEnv(g, { ADMIN_TOKEN, SIGNER_PRIVATE }), "POST", "/admin/control-plane/apply-staged", { bearer: ADMIN_TOKEN });
      ok("apply-staged clobber-guard: a non-empty role table -> 400", r.status === 400 && /recovery confirm refused/.test(((await r.json()) as { error?: string }).error ?? ""));
    }
    {
      // The DEFENSIVE 403-mapping arm: a 403 from the apply-staged forward is propagated as 403. The staged
      // record is read from the REAL DO and the signature verifies for real; only the apply-staged forward is
      // the controlled double (the route's own token caller cannot otherwise provoke the DO's non-token 403).
      const g = makeStack({ override: (url) => (url.endsWith("/control-plane/apply-staged") ? new Response(JSON.stringify({ error: "forbidden" }), { status: 403, headers: { "content-type": "application/json" } }) : null) });
      g.dobj.stageControlPlaneRecovery(stagedFrom(exp, sig));
      const r = await call(mkEnv(g, { ADMIN_TOKEN, SIGNER_PRIVATE }), "POST", "/admin/control-plane/apply-staged", { bearer: ADMIN_TOKEN });
      ok("apply-staged: a 403 from the DO apply-staged is propagated as 403", r.status === 403 && /recovery confirm refused/.test(((await r.json()) as { error?: string }).error ?? ""));
    }

    // =====================================================================================
    // GET /control-plane/export-download: build the current export + sign it for the operator to download.
    // Gated on access.policy (owner/access-admin); the DO builds, the Worker signs; no plaintext secret rides.
    // =====================================================================================
    {
      const s = makeStack();
      const mkCtx = (env: Env, caller: Caller): RouterCtx =>
        ({
          req: new Request("https://engine.cov.example/admin/control-plane/export-download", { method: "GET" }),
          env,
          url: new URL("https://engine.cov.example/admin/control-plane/export-download"),
          scheduler: s.stub,
          caller,
          sub: "/control-plane/export-download",
          sourceIp: null,
          runtime: undefined,
          verdict: { ok: true, method: caller.method, email: caller.email, subject: caller.subject, exp: 1_900_000_000, groups: caller.groups },
          isOnlyOwner: false,
          roleSource: "builtin",
          customRole: undefined,
        }) as unknown as RouterCtx;
      const ownerCaller: Caller = {
        method: "access" as Caller["method"],
        email: "owner-dl@cov.example",
        subject: "subj-dl",
        role: "owner",
        groups: [],
        capabilities: new Set(["access.policy", "downpipe.read"]) as ReadonlySet<string> as NonNullable<Caller["capabilities"]>,
      };
      const rOwner = (await handleIdentity(mkCtx(mkEnv(s, { SIGNER_PRIVATE }), ownerCaller)))!;
      ok("export-download: an access.policy owner gets 200", rOwner.status === 200);
      const dl = (await rOwner.json()) as { export?: unknown; signature?: unknown };
      ok(
        "export-download: returns a built export + a non-empty detached signature",
        typeof dl.export === "object" && dl.export !== null && typeof dl.signature === "string" && (dl.signature as string).length > 0,
      );
      // A caller WITHOUT access.policy (e.g. a viewer) is refused with a 403.
      const viewerCaller: Caller = {
        ...ownerCaller,
        email: "viewer-dl@cov.example",
        role: "viewer",
        capabilities: new Set(["downpipe.read"]) as ReadonlySet<string> as NonNullable<Caller["capabilities"]>,
      };
      const rViewer = (await handleIdentity(mkCtx(mkEnv(s, { SIGNER_PRIVATE }), viewerCaller)))!;
      ok("export-download: a caller without access.policy is refused (403)", rViewer.status === 403);
      // With no SIGNER_PRIVATE configured the export cannot be signed => 500 (never an unsigned artefact).
      const rNoSigner = (await handleIdentity(mkCtx(mkEnv(s), ownerCaller)))!;
      ok("export-download: without SIGNER_PRIVATE it fails 500 (never an unsigned export)", rNoSigner.status === 500);
    }

    // =====================================================================================
    // POST /control-plane/acknowledge-recovery (CP-RECOVERY-LATCH-NO-CLEAR-PATH-AFTER-ORGANIC-RESUME):
    // the narrow latch-clear for a plane that organically un-emptied under an active latch. Gated on
    // access.policy (never the bare break-glass token); the DO independently refuses over an empty role table.
    // Lives in its own spoke (router-control-plane-recovery-ack.ts, handleControlPlaneRecoveryAck), reached
    // here via the SAME harness as handleIdentity's own tests -- not grown into handleIdentity itself, which
    // sits at the file's line-budget ceiling.
    // =====================================================================================
    {
      const s = makeStack();
      const mkCtx = (env: Env, caller: Caller): RouterCtx =>
        ({
          req: new Request("https://engine.cov.example/admin/control-plane/acknowledge-recovery", { method: "POST" }),
          env,
          url: new URL("https://engine.cov.example/admin/control-plane/acknowledge-recovery"),
          scheduler: s.stub,
          caller,
          sub: "/control-plane/acknowledge-recovery",
          sourceIp: null,
          runtime: undefined,
          verdict: { ok: true, method: caller.method, email: caller.email, subject: caller.subject, exp: 1_900_000_000, groups: caller.groups },
          isOnlyOwner: false,
          roleSource: "builtin",
          customRole: undefined,
        }) as unknown as RouterCtx;
      const ownerCaller: Caller = {
        method: "access" as Caller["method"],
        email: "owner-ack@cov.example",
        subject: "subj-ack",
        role: "owner",
        groups: [],
        capabilities: new Set(["access.policy", "downpipe.read"]) as ReadonlySet<string> as NonNullable<Caller["capabilities"]>,
      };
      // A caller WITHOUT access.policy (a viewer) is refused with a 403 -- checked FIRST, before the plane is
      // latched, so the gate denial is the only thing under test (never masked by a later DO-side refusal).
      const viewerCaller: Caller = { ...ownerCaller, email: "viewer-ack@cov.example", role: "viewer", capabilities: new Set(["downpipe.read"]) as ReadonlySet<string> as NonNullable<Caller["capabilities"]> };
      const rViewer = (await handleControlPlaneRecoveryAck(mkCtx(mkEnv(s), viewerCaller)))!;
      ok("acknowledge-recovery: a caller without access.policy is refused (403)", rViewer.status === 403);
      // Nothing latched yet: an access.policy owner is refused because there is nothing to acknowledge (the
      // DO's plain Error surfaces as 400, exactly like every other control-plane recovery refusal).
      const rNothing = (await handleControlPlaneRecoveryAck(mkCtx(mkEnv(s), ownerCaller)))!;
      ok("acknowledge-recovery: nothing latched -> 400 (nothing to acknowledge)", rNothing.status === 400);
      // Latch the plane (simulating a genuine amnesia detection), but leave the role table EMPTY: the DO
      // refuses (never trades the visible latch for a silent deadlock), surfaced here as 400.
      await s.dobj.setControlPlaneRecoveryRequired("amnesia");
      const rEmptyRoles = (await handleControlPlaneRecoveryAck(mkCtx(mkEnv(s), ownerCaller)))!;
      ok("acknowledge-recovery: latched but the role table is EMPTY -> 400 (deadlock guard)", rEmptyRoles.status === 400);
      ok("acknowledge-recovery: the empty-role-table refusal leaves the latch set", (await s.dobj.getControlPlaneRecoveryRequired()).required === true);
      // Seed a real Owner role entry DIRECTLY (not via whoami's bootstrap, which the latch itself blocks --
      // whoami's recoveryRequired check runs BEFORE the bootstrap branch, so a latched, empty-table caller
      // never bootstraps). This is exactly the row's own "organically un-emptied" shape: the break-glass
      // token is exempt from the recoveryRequired degrade, so a role-grant made through it while latched
      // (e.g. POST /roles) lands here the same way, without ever touching whoami's bootstrap path.
      s.storage.rawPut(roleSubjectKey(ownerCaller.subject as string), {
        subject: ownerCaller.subject, email: ownerCaller.email, role: "owner", grantedBy: "token-fallback", grantedAt: "2026-07-23T00:00:00.000Z",
      });
      const rOk = (await handleControlPlaneRecoveryAck(mkCtx(mkEnv(s), ownerCaller)))!;
      ok("acknowledge-recovery: latched + a real owner on record -> 200", rOk.status === 200);
      const ackBody = (await rOk.json()) as { ok?: unknown; acknowledged?: unknown };
      ok("acknowledge-recovery: returns ok/acknowledged", ackBody.ok === true && ackBody.acknowledged === true);
      ok("acknowledge-recovery: clears the latch", (await s.dobj.getControlPlaneRecoveryRequired()).required === false);
      const ackAudit = await s.dobj.listAuditEntries();
      ok(
        "acknowledge-recovery: writes a control-plane-recovery-acknowledged audit event",
        ackAudit.some((e) => e.action === "control-plane-recovery-acknowledged" && e.outcome === "success"),
      );
      // The bare break-glass token is refused (an owner already exists to ask): gate(caller, "access.policy")
      // sees a token caller's synthesised capabilities and denies it exactly like any non-owner caller would.
      await s.dobj.setControlPlaneRecoveryRequired("a second latch, to prove the token path is refused too");
      const rToken = await call(mkEnv(s, { ADMIN_TOKEN }), "POST", "/admin/control-plane/acknowledge-recovery", { bearer: ADMIN_TOKEN });
      ok("acknowledge-recovery: the bare break-glass token is refused", rToken.status === 403);
    }

    // =====================================================================================
    // buildControlPlaneExport carries the IdP connection INVENTORY (a non-secret descriptor), never the
    // client secret, and the export still passes the no-custody assertion.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const oidcProposal = {
        id: "okta-idp", kind: "oidc", label: "Okta", presetId: "okta", enabled: true,
        issuer: "https://example.okta.com", clientId: "client-xyz",
        secretRef: { mode: "do-plaintext" }, scopes: ["openid", "email", "profile"],
        idTokenSigAlgs: ["RS256"], pkce: "required", clientAuth: "client_secret_post", requireNonce: true,
      };
      const CLIENT_SECRET = "the-confidential-client-secret-value";
      const cr = await call(env, "POST", "/admin/idp/connections", { bearer: ADMIN_TOKEN, body: { proposal: oidcProposal, secret: CLIENT_SECRET } });
      ok("idp-export: the connection is created", cr.status === 200);
      const exp = await s.dobj.buildControlPlaneExport();
      const idp = (exp.idpConnections ?? []).find((c) => c.id === "okta-idp");
      ok(
        "idp-export: the export carries the IdP connection DESCRIPTOR (kind/identity/clientId)",
        idp !== undefined && idp.kind === "oidc" && idp.identity === "https://example.okta.com" && idp.clientId === "client-xyz" && idp.enabled === true,
      );
      ok("idp-export: the descriptor marks the confidential secret for re-establishment", idp?.secretReestablish === true);
      ok("idp-export: the descriptor carries NO client-secret field", idp !== undefined && !("clientSecret" in idp) && !("secret" in idp) && !("secretRef" in idp));
      // The whole export (with the IdP descriptor) still passes the no-custody assertion, and its serialised
      // bytes never contain the client secret (which stays write-only under idpsecret:<id>, marked reestablish).
      let noCustodyOk = true;
      try {
        assertNoPlaintextSecretInExport(exp);
      } catch {
        noCustodyOk = false;
      }
      ok("idp-export: the export with the IdP descriptor passes the no-custody assertion", noCustodyOk);
      ok("idp-export: the serialised export never contains the client secret value", !JSON.stringify(exp).includes(CLIENT_SECRET));
      ok("idp-export: 'idp-secrets' stays on the reestablish list (the secret is re-entered, not restored)", (exp.reestablish ?? []).includes("idp-secrets"));
    }

    // =====================================================================================
    // buildControlPlaneExport carries the NOTIFY channel inventory (non-secret), with the webhook URL redacted
    // to host + presence -- the token never leaves, and the export still passes the no-custody assertion.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const WEBHOOK_TOKEN = "SECRET-WEBHOOK-TOKEN-abc123";
      const WEBHOOK_URL = `https://hooks.example.com/services/T00/B00/${WEBHOOK_TOKEN}`;
      const cc = await call(env, "POST", "/admin/notify/channels", { bearer: ADMIN_TOKEN, body: { kind: "webhook", name: "SIEM webhook", url: WEBHOOK_URL } });
      ok("notify-export: the channel is created", cc.status === 200);
      const exp = await s.dobj.buildControlPlaneExport();
      const ch = (exp.notifyChannels ?? []).find((c) => c.name === "SIEM webhook");
      ok(
        "notify-export: the export carries the channel DESCRIPTOR with the host (not the URL)",
        ch !== undefined && ch.kind === "webhook" && ch.urlConfigured === true && ch.urlHost === "hooks.example.com",
      );
      ok("notify-export: the descriptor marks the URL secret for re-establishment", ch?.secretReestablish === true);
      ok("notify-export: the descriptor carries NO raw url / routingKey field", ch !== undefined && !("url" in ch) && !("routingKey" in ch));
      ok("notify-export: the serialised export never contains the webhook token", !JSON.stringify(exp).includes(WEBHOOK_TOKEN));
      let ncOk = true;
      try {
        assertNoPlaintextSecretInExport(exp);
      } catch {
        ncOk = false;
      }
      ok("notify-export: the export with the notify inventory passes the no-custody assertion", ncOk);
      ok("notify-export: 'notify-routing-secrets' stays on the reestablish list", (exp.reestablish ?? []).includes("notify-routing-secrets"));
    }

    // =====================================================================================
    // POST /control-plane/import: the cross-environment estate import. Verified against the operator's kit
    // signer.pub (tamper-evidence), gated on access.policy, grants no authority; a wrong key / viewer is refused.
    // =====================================================================================
    {
      // Build a signed export from a populated SOURCE engine.
      const src = makeStack();
      await src.dobj.whoami("src-owner@cov.example", "subj-src", "access", null);
      await src.dobj.addDownpipe(makeConfig("dp-import"), { method: "access", email: "src-owner@cov.example", subject: "subj-src", role: "owner", groups: [] });
      const exp = await src.dobj.buildControlPlaneExport();
      const signer = await loadSigner(SIGNER_PRIVATE);
      const sig = await signControlPlaneExport(signer, exp);
      const v = verifierFrom(signer);
      const signerPublic = b64urlEncode(new Uint8Array([...v.ed, ...v.mldsa]));

      // A fresh TARGET engine, Owner bootstrapped: the Owner imports the estate verified against the kit pub.
      const tgt = makeStack();
      const tgtEnv = mkEnv(tgt, { ADMIN_TOKEN });
      await call(tgtEnv, "GET", "/admin/whoami", { jwt: await tokenFor("import-owner@cov.example") }); // bootstrap the Owner
      const imp = await call(tgtEnv, "POST", "/admin/control-plane/import", { jwt: await tokenFor("import-owner@cov.example"), body: { export: exp, signature: sig, signerPublic } });
      ok("import route: an Owner import verified against the kit signer.pub is 200", imp.status === 200);
      const ib = (await imp.json()) as { ok?: boolean; downpipes?: number; downpipesDisabled?: boolean; authorityImported?: boolean };
      ok("import route: the definition applied, downpipes DISABLED (cross-account: null ids), NO authority", ib.ok === true && (ib.downpipes ?? 0) >= 1 && ib.downpipesDisabled === true && ib.authorityImported === false);
      ok("import route: the imported downpipe is present but disabled", (await tgt.dobj.listDownpipes()).some((s) => s.config.id === "dp-import" && s.config.enabled === false));

      // A WRONG signer.pub -> 400 (the signature does not verify against it).
      const otherSigner = await loadSigner(b64urlEncode(crypto.getRandomValues(new Uint8Array(64))));
      const ov = verifierFrom(otherSigner);
      const wrongPub = b64urlEncode(new Uint8Array([...ov.ed, ...ov.mldsa]));
      const tgt2 = makeStack();
      const tgt2Env = mkEnv(tgt2, { ADMIN_TOKEN });
      await call(tgt2Env, "GET", "/admin/whoami", { jwt: await tokenFor("import-owner2@cov.example") });
      const wrong = await call(tgt2Env, "POST", "/admin/control-plane/import", { jwt: await tokenFor("import-owner2@cov.example"), body: { export: exp, signature: sig, signerPublic: wrongPub } });
      ok("import route: a wrong signer.pub -> 400 (does not verify, no import)", wrong.status === 400);

      // A VIEWER (no access.policy) is refused 403 (the import is Owner-gated). Bootstrap an Owner first so the
      // second caller resolves to viewer.
      const tgt3 = makeStack();
      const tgt3Env = mkEnv(tgt3, { ADMIN_TOKEN });
      await call(tgt3Env, "GET", "/admin/whoami", { jwt: await tokenFor("owner3@cov.example") }); // bootstrap the Owner
      const viewerImp = await call(tgt3Env, "POST", "/admin/control-plane/import", { jwt: await tokenFor("viewer3@cov.example"), body: { export: exp, signature: sig, signerPublic } });
      ok("import route: a viewer (no access.policy) is refused 403", viewerImp.status === 403);

    // =====================================================================================
    // THE DISCRIMINATION TEST on the estate import, the one route whose verifier is OPERATOR-SUPPLIED
    // out of a recovery kit. A proxy crypto verdict based on the SIGNATURE STRING's length alone cannot see the key at all, so a
    // right-length CORRUPT signer.pub must not be filed as `signature` -- byte-identical to a genuinely ALTERED
    // export ("someone has tampered with your recovery artefact"). Four states, four remedies, four different rows.
    // =====================================================================================
    {
      const refusalRows = async (stack: Stack): Promise<Record<string, number>> => {
        const r = await stack.stub.fetch(new Request("https://do/recovery-refusals"));
        const body = (await r.json()) as { refusals?: { bySurfaceClass?: Record<string, number> } };
        return body.refusals?.bySurfaceClass ?? {};
      };
      // A fresh Owner-bootstrapped target per state, so each row is read in isolation.
      const target = async (who: string): Promise<{ stack: Stack; env: Env; jwt: string }> => {
        const stack = makeStack();
        const env = mkEnv(stack, { ADMIN_TOKEN });
        const jwt = await tokenFor(who);
        await call(env, "GET", "/admin/whoami", { jwt });
        return { stack, env, jwt };
      };

      // STATE 1: THE KIT KEY IS CORRUPT. The right length (so parseVerifier admits it), and one byte of the
      // ML-DSA half -- 2592 of the key's 2624 bytes -- has rotted. The export is INTACT. Remedy: take another
      // copy of the key. This is the state that used to be reported as tamper.
      const corruptMldsa = Uint8Array.from(v.mldsa);
      corruptMldsa[5] = corruptMldsa[5]! ^ 0xff;
      const corruptKitPub = b64urlEncode(new Uint8Array([...v.ed, ...corruptMldsa]));
      const t1 = await target("kit-corrupt@cov.example");
      const r1 = await call(t1.env, "POST", "/admin/control-plane/import", { jwt: t1.jwt, body: { export: exp, signature: sig, signerPublic: corruptKitPub } });
      const rows1 = await refusalRows(t1.stack);
      const e1 = ((await r1.json()) as { error?: string }).error ?? "";

      // STATE 2: THE EXPORT WAS ALTERED. The kit key is the correct one. Remedy: this IS the tamper verdict.
      const alteredExp = { ...exp, downpipes: [...exp.downpipes, { ...(exp.downpipes[0] as object), id: "dp-injected" }] } as typeof exp;
      const t2 = await target("kit-tamper@cov.example");
      const r2 = await call(t2.env, "POST", "/admin/control-plane/import", { jwt: t2.jwt, body: { export: alteredExp, signature: sig, signerPublic } });
      const rows2 = await refusalRows(t2.stack);

      // STATE 3: THE .sig FILE IS DAMAGED. Truncated / half-written. Remedy: re-copy the signature.
      const t3 = await target("kit-sig@cov.example");
      const r3 = await call(t3.env, "POST", "/admin/control-plane/import", { jwt: t3.jwt, body: { export: exp, signature: sig.slice(0, 40), signerPublic } });
      const rows3 = await refusalRows(t3.stack);

      // STATE 4: THE KIT KEY WILL NOT PARSE AT ALL (the wrong length: a mangled kit file). Remedy: re-copy the key.
      const t4 = await target("kit-unparseable@cov.example");
      const r4 = await call(t4.env, "POST", "/admin/control-plane/import", { jwt: t4.jwt, body: { export: exp, signature: sig, signerPublic: b64urlEncode(new Uint8Array(64)) } });
      const rows4 = await refusalRows(t4.stack);

      ok("every one of the four states still refuses the import (400)", [r1, r2, r3, r4].every((r) => r.status === 400));
      ok("STATE 1 (a CORRUPT kit key, right length): recorded as the PQ-half mismatch, NOT as a signature/tamper", rows1["estate-import|signature-pq"] === 1 && rows1["estate-import|signature"] === undefined);
      ok("...and the operator is told the export is INTACT and their KEY is at fault, not that their artefact was altered", /is INTACT/.test(e1) && /is damaged/.test(e1) && /not tampering/.test(e1) && !/was modified/.test(e1));
      ok("STATE 2 (an ALTERED export, correct key): recorded as `signature` -- tamper lives HERE and only here", rows2["estate-import|signature"] === 1);
      ok("STATE 3 (a TRUNCATED .sig): recorded as verify-threw -- the signature FILE is damaged", rows3["estate-import|verify-threw"] === 1);
      ok("STATE 4 (an UNPARSEABLE kit key): recorded as verifier-invalid", rows4["estate-import|verifier-invalid"] === 1);
      const keys = [rows1, rows2, rows3, rows4].map((r) => Object.keys(r).join(","));
      ok("DISCRIMINATION: the four states produce FOUR DIFFERENT ROWS (they used to produce ONE)", new Set(keys).size === 4);
      ok("...and NOT ONE of the three key/signature-file faults is filed as tamper", [rows1, rows3, rows4].every((r) => r["estate-import|signature"] === undefined));
    }

    // =====================================================================================
    // POST /control-plane/import-sealed. The browser-unseal counterpart of import: this engine holds no
    // key that opens the sealed body (a fresh estate's CONFIG_RECIPIENT_PRIVATE was never a recipient of the
    // OLD export), so it verifies the SEALED WRAPPER's own signature (never the plaintext's -- none is written
    // for a sealed generation; S5 purges the plaintext siblings) and cross-checks the browser-recovered
    // plaintext against the signed bodyHash, then falls through to the SAME DO import the plaintext route uses.
    // Same access.policy gate, same no-authority / cross-account semantics.
    // =====================================================================================
    {
      const sealSrc = makeStack();
      await sealSrc.dobj.whoami("seal-src-owner@cov.example", "subj-seal-src", "access", null);
      await sealSrc.dobj.addDownpipe(makeConfig("dp-import-sealed"), { method: "access", email: "seal-src-owner@cov.example", subject: "subj-seal-src", role: "owner", groups: [] });
      const sealExp = await sealSrc.dobj.buildControlPlaneExport();
      const sealSigner = await loadSigner(SIGNER_PRIVATE);
      const sealVerifier = verifierFrom(sealSigner);
      const sealSignerPublic = b64urlEncode(new Uint8Array([...sealVerifier.ed, ...sealVerifier.mldsa]));

      // A break-glass recipient's PUBLIC half is all sealing needs. The private half is never generated for
      // this test on purpose: the route under test must never need it, which is the whole point of it.
      const bgSeed = crypto.getRandomValues(new Uint8Array(64));
      const bgScalar = crypto.getRandomValues(new Uint8Array(32));
      const bgPub = { x25519: x25519PublicFromScalar(bgScalar), mlkemEk: mlkemKeygen(bgSeed).encapKey };
      const sealNonceFor = (): Uint8Array => crypto.getRandomValues(new Uint8Array(16));
      const sealed = await sealControlPlaneExport(sealExp, [{ role: "break-glass", pub: bgPub }], sealNonceFor);
      const sealedSig = await signSealedControlPlaneExport(sealSigner, sealed);

      const sealTgt = makeStack();
      const sealTgtEnv = mkEnv(sealTgt, { ADMIN_TOKEN });
      await call(sealTgtEnv, "GET", "/admin/whoami", { jwt: await tokenFor("import-sealed-owner@cov.example") });
      const impSealed = await call(sealTgtEnv, "POST", "/admin/control-plane/import-sealed", {
        jwt: await tokenFor("import-sealed-owner@cov.example"),
        body: { sealed, sealedSignature: sealedSig, signerPublic: sealSignerPublic, export: sealExp },
      });
      ok("import-sealed route: a bodyHash-matched, sealed-signature-verified import is 200", impSealed.status === 200);
      const isb = (await impSealed.json()) as { ok?: boolean; downpipes?: number; downpipesDisabled?: boolean; authorityImported?: boolean };
      ok(
        "import-sealed route: the definition applied, downpipes DISABLED (cross-account: null ids), NO authority",
        isb.ok === true && (isb.downpipes ?? 0) >= 1 && isb.downpipesDisabled === true && isb.authorityImported === false,
      );
      ok("import-sealed route: the imported downpipe is present but disabled", (await sealTgt.dobj.listDownpipes()).some((s) => s.config.id === "dp-import-sealed" && s.config.enabled === false));

      // A plaintext that does not match the SIGNED bodyHash -> refused, its own class (never `no-custody`,
      // never a bare `shape`: the artefact and the plaintext are each individually well-formed, they just do
      // not correspond to one another).
      const sealTgt2 = makeStack();
      const sealTgt2Env = mkEnv(sealTgt2, { ADMIN_TOKEN });
      await call(sealTgt2Env, "GET", "/admin/whoami", { jwt: await tokenFor("import-sealed-mismatch@cov.example") });
      const mismatchExp = { ...sealExp, downpipes: [...sealExp.downpipes, { ...(sealExp.downpipes[0] as object), id: "dp-injected-sealed" }] } as typeof sealExp;
      const mismatch = await call(sealTgt2Env, "POST", "/admin/control-plane/import-sealed", {
        jwt: await tokenFor("import-sealed-mismatch@cov.example"),
        body: { sealed, sealedSignature: sealedSig, signerPublic: sealSignerPublic, export: mismatchExp },
      });
      ok("import-sealed route: a plaintext not matching the signed bodyHash is refused 400", mismatch.status === 400);
      const mismatchBody = (await mismatch.json()) as { refusalClass?: string };
      ok("import-sealed route: ...classed sealed-body-mismatch, never tamper", mismatchBody.refusalClass === "sealed-body-mismatch");

      // A sealed artefact predating bodyHash (an older engine's export) is refused HONESTLY rather than the
      // plaintext being trusted unverified.
      const sealTgt3 = makeStack();
      const sealTgt3Env = mkEnv(sealTgt3, { ADMIN_TOKEN });
      await call(sealTgt3Env, "GET", "/admin/whoami", { jwt: await tokenFor("import-sealed-unhashed@cov.example") });
      const unhashedSealed = { ...sealed };
      delete (unhashedSealed as { bodyHash?: string }).bodyHash;
      const unhashedSig = await signSealedControlPlaneExport(sealSigner, unhashedSealed as SealedControlPlaneExport);
      const unhashed = await call(sealTgt3Env, "POST", "/admin/control-plane/import-sealed", {
        jwt: await tokenFor("import-sealed-unhashed@cov.example"),
        body: { sealed: unhashedSealed, sealedSignature: unhashedSig, signerPublic: sealSignerPublic, export: sealExp },
      });
      ok("import-sealed route: an artefact without bodyHash refuses honestly rather than trusting the plaintext", unhashed.status === 400);
      const unhashedBody = (await unhashed.json()) as { refusalClass?: string };
      ok("import-sealed route: ...classed sealed-unhashed", unhashedBody.refusalClass === "sealed-unhashed");

      // A wrong signer.pub against the SEALED wrapper's own signature -> the same G202 five-world verdict.
      const sealTgt4 = makeStack();
      const sealTgt4Env = mkEnv(sealTgt4, { ADMIN_TOKEN });
      await call(sealTgt4Env, "GET", "/admin/whoami", { jwt: await tokenFor("import-sealed-wrongpub@cov.example") });
      const otherSealSigner = await loadSigner(b64urlEncode(crypto.getRandomValues(new Uint8Array(64))));
      const otherSealVerifier = verifierFrom(otherSealSigner);
      const wrongSealPub = b64urlEncode(new Uint8Array([...otherSealVerifier.ed, ...otherSealVerifier.mldsa]));
      const wrongPubImp = await call(sealTgt4Env, "POST", "/admin/control-plane/import-sealed", {
        jwt: await tokenFor("import-sealed-wrongpub@cov.example"),
        body: { sealed, sealedSignature: sealedSig, signerPublic: wrongSealPub, export: sealExp },
      });
      ok("import-sealed route: a wrong signer.pub against the sealed wrapper is refused 400", wrongPubImp.status === 400);

      // A viewer (no access.policy) is refused 403, exactly as the plaintext route.
      const sealTgt5 = makeStack();
      const sealTgt5Env = mkEnv(sealTgt5, { ADMIN_TOKEN });
      await call(sealTgt5Env, "GET", "/admin/whoami", { jwt: await tokenFor("import-sealed-owner5@cov.example") }); // bootstrap the Owner
      const viewerSealed = await call(sealTgt5Env, "POST", "/admin/control-plane/import-sealed", {
        jwt: await tokenFor("import-sealed-viewer5@cov.example"),
        body: { sealed, sealedSignature: sealedSig, signerPublic: sealSignerPublic, export: sealExp },
      });
      ok("import-sealed route: a viewer (no access.policy) is refused 403", viewerSealed.status === 403);

      // Malformed bodies: a non-sealed shape, an absent signature, an absent signer.pub, a non-export payload.
      const sealTgt6 = makeStack();
      const sealTgt6Env = mkEnv(sealTgt6, { ADMIN_TOKEN });
      await call(sealTgt6Env, "GET", "/admin/whoami", { jwt: await tokenFor("import-sealed-malformed@cov.example") });
      const jwtM = await tokenFor("import-sealed-malformed@cov.example");
      const notSealed = await call(sealTgt6Env, "POST", "/admin/control-plane/import-sealed", { jwt: jwtM, body: { sealed: { v: 1 }, sealedSignature: sealedSig, signerPublic: sealSignerPublic, export: sealExp } });
      ok("import-sealed route: a non-sealed-shape body is refused 400 shape", notSealed.status === 400 && ((await notSealed.json()) as { refusalClass?: string }).refusalClass === "shape");
      const noSig = await call(sealTgt6Env, "POST", "/admin/control-plane/import-sealed", { jwt: jwtM, body: { sealed, signerPublic: sealSignerPublic, export: sealExp } });
      ok("import-sealed route: a missing signature is refused 400 malformed", noSig.status === 400 && ((await noSig.json()) as { refusalClass?: string }).refusalClass === "malformed");
      const noPub = await call(sealTgt6Env, "POST", "/admin/control-plane/import-sealed", { jwt: jwtM, body: { sealed, sealedSignature: sealedSig, export: sealExp } });
      ok("import-sealed route: a missing signer.pub is refused 400 malformed", noPub.status === 400 && ((await noPub.json()) as { refusalClass?: string }).refusalClass === "malformed");
      const badExp = await call(sealTgt6Env, "POST", "/admin/control-plane/import-sealed", { jwt: jwtM, body: { sealed, sealedSignature: sealedSig, signerPublic: sealSignerPublic, export: { not: "an export" } } });
      ok("import-sealed route: a non-export plaintext is refused 400 shape", badExp.status === 400 && ((await badExp.json()) as { refusalClass?: string }).refusalClass === "shape");
    }

    // =====================================================================================
    // THE DISCRIMINATION TEST on the import OUTCOME. Both states below disable every downpipe, write
    // one reconcile bridge, and leave the estate on the operator's screen with nothing running. The remedies
    // are opposite: re-point every source, or set the account id and re-import (re-pointing sources fixes
    // NOTHING in the second world). The outcome rode only on the one-shot HTTP response, which is long gone
    // by the time a support pack is built, so the pack could not tell them apart. Now it can.
    // =====================================================================================
    {
      const packRow = async (stack: Stack): Promise<Record<string, unknown> | undefined> => {
        const rec = await fetchRecoveryStatus(stack.stub);
        return rec.lastImport as Record<string, unknown> | undefined;
      };
      // STATE A: a GENUINE cross-account import. Both sides NAME an account and the accounts differ.
      const expOld = { ...exp, engineAccountId: "acct-old" } as typeof exp;
      const sigOld = await signControlPlaneExport(signer, expOld);
      const a = makeStack();
      const aEnv = mkEnv(a, { ADMIN_TOKEN, CF_ACCOUNT_ID: "acct-new" });
      await call(aEnv, "GET", "/admin/whoami", { jwt: await tokenFor("imp-cross@cov.example") });
      const ra = await call(aEnv, "POST", "/admin/control-plane/import", { jwt: await tokenFor("imp-cross@cov.example"), body: { export: expOld, signature: sigOld, signerPublic } });
      const rowA = await packRow(a);

      // STATE B: accountIdAbsent. Neither side can name an account, sameControlPlaneAccount fails SAFE on the
      // null, crossAccount comes back TRUE anyway, and every downpipe lands disabled just the same.
      const b = makeStack();
      const bEnv = mkEnv(b, { ADMIN_TOKEN }); // no CF_ACCOUNT_ID
      await call(bEnv, "GET", "/admin/whoami", { jwt: await tokenFor("imp-absent@cov.example") });
      const rb = await call(bEnv, "POST", "/admin/control-plane/import", { jwt: await tokenFor("imp-absent@cov.example"), body: { export: exp, signature: sig, signerPublic } });
      const rowB = await packRow(b);

      ok("both imports SUCCEED (200) and both disable every downpipe -- that is the whole problem", ra.status === 200 && rb.status === 200 && rowA?.downpipesDisabled === true && rowB?.downpipesDisabled === true);
      ok("THE PACK NOW CARRIES THE IMPORT OUTCOME (it rode only on a one-shot HTTP response before)", rowA !== undefined && rowB !== undefined);
      ok("STATE A: a GENUINE cross-account import -- crossAccount true, accountIdAbsent FALSE. Re-point every source", rowA?.crossAccount === true && rowA?.accountIdAbsent === false);
      ok("STATE B: a PRE-ACCOUNT-DISCOVERY export -- accountIdAbsent TRUE. There is nothing to re-point", rowB?.accountIdAbsent === true && rowB?.crossAccount === true);
      ok("DISCRIMINATION: the two rows DIFFER on accountIdAbsent (they were byte-identical in every artefact)", rowA?.accountIdAbsent !== rowB?.accountIdAbsent);
      ok("NOISE: an engine that was never rebuilt from a kit carries NO lastImport row at all", (await packRow(makeStack())) === undefined);
      const scanned = JSON.stringify([rowA, rowB]);
      ok("REDACTION: the row is booleans, counts and a timestamp -- no account id ever rides", !scanned.includes("acct-old") && !scanned.includes("acct-new"));
    }
    }

    // =====================================================================================
    // The default fall-through: a method+path this spoke does not own returns null (the hub 404s).
    // =====================================================================================
    {
      const s = makeStack();
      const r = await call(mkEnv(s, { ADMIN_TOKEN }), "GET", "/admin/whoami-not-a-route", { bearer: ADMIN_TOKEN });
      ok("default: an unowned identity path falls through to 404", r.status === 404);
    }
  } finally {
    globalThis.fetch = realFetch;
  }

  console.log(failures === 0 ? "\nROUTER-IDENTITY COVERAGE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
