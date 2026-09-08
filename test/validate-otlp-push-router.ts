// Validates the OTLP/HTTP metrics push destination's ADMIN ROUTER surface:
// GET /admin/otlp-push is redacted (no secret/ciphertext, ever); POST /admin/otlp-push enforces the owner
// gate, is step-up listed, WRAPS the secret under OTLP_PUSH_SECRET_AAD BEFORE forwarding (so the DO never
// stores plaintext when a wrap key is set), and DUAL-CONTROL queues a pending approval once a second owner
// exists (with the QUEUED listing never carrying the secret either); POST /admin/otlp-push/delete clears
// without a second approval; and every mutation lands the correct redaction-safe audit event. Drives the REAL
// handleAdmin over a REAL SchedulerDO on in-memory storage, mirroring validate-siem-push-router.ts's harness.
// The engine-internal shaper/sender/DO logic is validated separately in test/validate-otlp-push.ts. The only
// network is the stubbed Cloudflare Access JWKS. Run:
//   node test/validate-otlp-push-router.ts

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { isWrappedSecret } from "../src/admin/config-secret.ts";
import { STEPUP_SUBS } from "../src/admin/router-core.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

interface Stack {
  dobj: SchedulerDO;
  storage: MockStorage;
  stub: DurableObjectStub;
  env: Pick<Env, "SCHEDULER">;
}

function makeStack(): Stack {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(input instanceof Request ? input : input.toString(), init)) } as unknown as DurableObjectStub;
  const namespace = { idFromName: (_n: string) => ({}) as unknown as DurableObjectId, get: (_id: DurableObjectId) => stub } as unknown as DurableObjectNamespace;
  return { dobj, storage, stub, env: { SCHEDULER: namespace } };
}

// ---- Forged Access JWT (real RS256 verification against a controlled, stubbed JWKS) ----------------------
const TEAM = "cov-otlp-team";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "cov-otlp-aud";
const KID = "cov-otlp-kid";
const ADMIN_TOKEN = "cov-otlp-break-glass-token-1234567890";
// A real base64url-of-32-bytes AES-256 wrap key, so the router's loadConfigWrapKey + maybeWrapConfigSecret
// path actually SEALS the secret (proving the DO never stores plaintext when a key is configured).
const CONFIG_WRAP_KEY = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));

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
}
async function call(env: Env, method: "GET" | "POST", path: string, opts: CallOpts = {}): Promise<{ status: number; json: Record<string, unknown> }> {
  const headers: Record<string, string> = {};
  if (opts.jwt !== undefined) headers["cf-access-jwt-assertion"] = opts.jwt;
  if (opts.bearer !== undefined) headers.authorization = `Bearer ${opts.bearer}`;
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  const init: RequestInit = { method, headers };
  if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
  const resp = await handleAdmin(new Request(`https://engine.cov.example${path}`, init), env);
  let json: Record<string, unknown> = {};
  try {
    json = (await resp.json()) as Record<string, unknown>;
  } catch {
    /* a non-JSON body (e.g. a plaintext 401) leaves json {} */
  }
  return { status: resp.status, json };
}

async function main(): Promise<void> {
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
    return new Response("ok", { status: 200 });
  }) as typeof fetch;

  const SECRET = "otlp-bearer-token-DO-NOT-LEAK-1a2b3c";

  try {
    // =====================================================================================
    // Structural: the two mutating routes are step-up listed and each reaches a REAL dispatch case (not the
    // 404 default) when driven with a step-up-EXEMPT bare-token caller.
    // =====================================================================================
    {
      ok("STEPUP_SUBS includes /otlp-push", STEPUP_SUBS.has("/otlp-push"));
      ok("STEPUP_SUBS includes /otlp-push/delete", STEPUP_SUBS.has("/otlp-push/delete"));
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      for (const sub of ["/otlp-push", "/otlp-push/delete"]) {
        const r = await call(env, "POST", `/admin${sub}`, { bearer: ADMIN_TOKEN, body: {} });
        ok(`a bare-token (step-up-exempt) caller reaches a real dispatch case on POST ${sub} (not 404)`, r.status !== 404);
      }
    }

    // =====================================================================================
    // GET /admin/otlp-push, unconfigured: present:false, an empty trail, no secret field of any kind.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const r = await call(env, "GET", "/admin/otlp-push", { bearer: ADMIN_TOKEN });
      ok("GET /admin/otlp-push (unconfigured): 200", r.status === 200);
      ok("present:false, an empty trail array", r.json.present === false && Array.isArray(r.json.trail) && (r.json.trail as unknown[]).length === 0);
      ok("no secret-shaped field anywhere in the unconfigured view", !("authHeaderValue" in r.json) && !JSON.stringify(r.json).toLowerCase().includes("ciphertext"));
    }

    // =====================================================================================
    // Owner gate: a non-owner (viewer) is refused 403 on every mutating route.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s);
      const OWNER = "otlp-owner@cov.example";
      const VIEWER = "otlp-viewer@cov.example";
      ok("owner bootstrap", (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor(OWNER) })).json.role === "owner");
      const setDenied = await call(env, "POST", "/admin/otlp-push", { jwt: await tokenFor(VIEWER), body: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "s", enabled: true } });
      ok("POST /admin/otlp-push (non-owner): 403", setDenied.status === 403 && setDenied.json.required === "keys.ceremony");
      const delDenied = await call(env, "POST", "/admin/otlp-push/delete", { jwt: await tokenFor(VIEWER) });
      ok("POST /admin/otlp-push/delete (non-owner): 403", delDenied.status === 403);
    }

    // =====================================================================================
    // Validation: the router refuses BEFORE it ever reaches the DO (never queued as a pending approval).
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN });
      const bad1 = await call(env, "POST", "/admin/otlp-push", { bearer: ADMIN_TOKEN, body: { endpoint: "http://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "s", enabled: true } });
      ok("a non-https endpoint is refused 400", bad1.status === 400 && typeof bad1.json.error === "string");
      const bad2 = await call(env, "POST", "/admin/otlp-push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://169.254.169.254/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "s", enabled: true } });
      ok("an internal-sink (cloud metadata) endpoint is refused 400 (SSRF default-deny at set time)", bad2.status === 400);
      // KEEP-SECRET: the router ALLOWS an empty authHeaderValue (it means "keep"); a FIRST create with no
      // secret is refused by the DO instead (nothing to keep), still surfacing as a 400.
      const bad3 = await call(env, "POST", "/admin/otlp-push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "", enabled: true } });
      ok("a FIRST create with an empty auth header value is refused 400 (at the DO: nothing to keep)", bad3.status === 400);
      const bad4 = await call(env, "POST", "/admin/otlp-push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: "s" } });
      ok("a missing enabled flag is refused 400", bad4.status === 400);
      // The router screens the auth header VALUE at config time (control chars / over-length) BEFORE
      // sealing, matching router-push. A CR/LF-bearing key is a clear 400, not an opaque send-time failure.
      const badVal = await call(env, "POST", "/admin/otlp-push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "DD-API-KEY", authHeaderValue: "key\r\nInject: 1", enabled: true } });
      ok("a CR/LF auth header value is refused 400 at the router", badVal.status === 400 && /control character|length cap/i.test(String(badVal.json.error)));
      const badLong = await call(env, "POST", "/admin/otlp-push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "DD-API-KEY", authHeaderValue: "a".repeat(9000), enabled: true } });
      ok("an over-length auth header value is refused 400 at the router", badLong.status === 400);
      // FORBIDDEN HEADER NAME: content-type would collide with the content-type the sender sets, so it is
      // refused 400 at the router (a runtime-controlled header like host/connection is refused too).
      const badHdr = await call(env, "POST", "/admin/otlp-push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "content-type", authHeaderValue: "s", enabled: true } });
      ok("a content-type auth header name is refused 400", badHdr.status === 400 && /content-type|runtime-controlled/i.test(String(badHdr.json.error)));
      const badHdr2 = await call(env, "POST", "/admin/otlp-push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Host", authHeaderValue: "s", enabled: true } });
      ok("a runtime-controlled header name (Host) is refused 400", badHdr2.status === 400);
      // None of the above reached the DO's dual-control queue (no pending owner action was ever recorded).
      const inbox = await call(env, "GET", "/admin/owner-actions", { bearer: ADMIN_TOKEN });
      ok("no pending owner action was queued by any rejected submission", Array.isArray(inbox.json) && (inbox.json as unknown[]).length === 0);
    }

    // =====================================================================================
    // WRAP-BEFORE-FORWARD (the CRITICAL structural fix): with CONFIG_WRAP_KEY set, POST /admin/otlp-push seals
    // the secret at the ROUTER before forwarding, so the DO STORES ONLY CIPHERTEXT -- never the plaintext. And
    // no response (the 200 body, the redacted GET) ever carries the secret or the ciphertext.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN, CONFIG_WRAP_KEY });
      const set = await call(env, "POST", "/admin/otlp-push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: SECRET, enabled: true } });
      ok("POST /admin/otlp-push (owner, gate off, wrap key set): 200 (applied inline)", set.status === 200);
      ok("the 200 body is the redacted view: no secret, no ciphertext", !("authHeaderValue" in set.json) && !JSON.stringify(set.json).includes(SECRET) && !JSON.stringify(set.json).toLowerCase().includes("ciphertext"));
      ok("the 200 body reflects the non-secret fields", set.json.present === true && set.json.endpoint === "https://otlp.example.com/v1/metrics" && set.json.authHeaderName === "Authorization" && set.json.enabled === true);

      // THE PROOF: read the DO's RAW at-rest record. The router wrapped BEFORE forwarding, so authHeaderValue
      // is a WrappedSecret envelope (v/iv/ct), NEVER the plaintext string.
      const rec = await s.dobj.getOtlpPushRecordRaw();
      ok("WRAP-BEFORE-FORWARD: the DO stored a WrappedSecret envelope, NOT the plaintext (the router sealed it first)", rec !== null && isWrappedSecret(rec.authHeaderValue));
      ok("WRAP-BEFORE-FORWARD: the at-rest record NEVER contains the plaintext secret", rec !== null && !JSON.stringify(rec.authHeaderValue).includes(SECRET));

      const get = await call(env, "GET", "/admin/otlp-push", { bearer: ADMIN_TOKEN });
      ok("GET /admin/otlp-push reflects the same redacted state, still no secret", get.json.present === true && get.json.endpoint === "https://otlp.example.com/v1/metrics" && !JSON.stringify(get.json).includes(SECRET));

      const audit = await call(env, "GET", "/admin/audit?limit=200", { bearer: ADMIN_TOKEN });
      const events = (audit.json.events as Array<{ action?: string; target?: Record<string, unknown> }>) ?? [];
      ok("an otlp-push-destination-set audit event was recorded, closed target only", events.some((e) => e.action === "otlp-push-destination-set" && e.target?.kind === "push-destination" && e.target?.op === "set"));
      ok("the audit chain never carries the secret or the endpoint URL in the push target", !JSON.stringify(events.find((e) => e.action === "otlp-push-destination-set")?.target).includes(SECRET));

      // POST /admin/otlp-push/delete: owner, not dual-control gated.
      const del = await call(env, "POST", "/admin/otlp-push/delete", { bearer: ADMIN_TOKEN });
      ok("POST /admin/otlp-push/delete (owner): 200 { ok: true }", del.status === 200 && del.json.ok === true);
      const getAfterDel = await call(env, "GET", "/admin/otlp-push", { bearer: ADMIN_TOKEN });
      ok("GET /admin/otlp-push after delete: present:false", getAfterDel.json.present === false);
      const auditAfterDel = await call(env, "GET", "/admin/audit?limit=200", { bearer: ADMIN_TOKEN });
      ok("an otlp-push-destination-cleared audit event was recorded", ((auditAfterDel.json.events as Array<{ action?: string }>) ?? []).some((e) => e.action === "otlp-push-destination-cleared"));
    }

    // =====================================================================================
    // KEEP-SECRET (the write-only-secret-field UX, end to end through the router + DO, with a wrap key): create
    // with a secret, then set again WITHOUT one to toggle enabled + edit the endpoint -> the sealed secret is
    // kept (and STILL a valid envelope), the non-secret fields update. A first-ever set with no secret is refused.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { ADMIN_TOKEN, CONFIG_WRAP_KEY });
      const firstNoSecret = await call(env, "POST", "/admin/otlp-push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", enabled: true } });
      ok("KEEP-SECRET: a FIRST set with no authHeaderValue is refused 400 (needs a secret to create)", firstNoSecret.status === 400);
      ok("KEEP-SECRET: nothing was stored by the rejected first create", (await call(env, "GET", "/admin/otlp-push", { bearer: ADMIN_TOKEN })).json.present === false);

      const create = await call(env, "POST", "/admin/otlp-push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: SECRET, enabled: true } });
      ok("KEEP-SECRET: create WITH a secret -> 200", create.status === 200 && create.json.present === true);
      const rec1 = await s.dobj.getOtlpPushRecordRaw();
      const sealed1 = rec1 !== null && isWrappedSecret(rec1.authHeaderValue) ? JSON.stringify(rec1.authHeaderValue) : "";

      const edit = await call(env, "POST", "/admin/otlp-push", { bearer: ADMIN_TOKEN, body: { endpoint: "https://otlp2.example.com/v1/metrics", authHeaderName: "DD-API-KEY", enabled: false } });
      ok("KEEP-SECRET: a later set WITHOUT authHeaderValue -> 200 (the console can toggle/edit)", edit.status === 200);
      const view = await call(env, "GET", "/admin/otlp-push", { bearer: ADMIN_TOKEN });
      ok("KEEP-SECRET: the secretless edit updated the non-secret fields", view.json.endpoint === "https://otlp2.example.com/v1/metrics" && view.json.authHeaderName === "DD-API-KEY" && view.json.enabled === false);
      const rec2 = await s.dobj.getOtlpPushRecordRaw();
      ok("KEEP-SECRET: the sealed secret is PRESERVED across a set that omits it (still the same envelope, still ciphertext)", rec2 !== null && isWrappedSecret(rec2.authHeaderValue) && JSON.stringify(rec2.authHeaderValue) === sealed1);
      ok("KEEP-SECRET: still no plaintext at rest after the keep-secret edit", rec2 !== null && !JSON.stringify(rec2.authHeaderValue).includes(SECRET));
    }

    // =====================================================================================
    // DUAL CONTROL (two owners, the opt-in gate ON): owner1 proposes -> 202 queued; the QUEUED listing
    // (GET /admin/owner-actions) NEVER carries the secret (redactOwnerActionParamsForListing strips the flat
    // authHeaderValue); owner2 (a DISTINCT identity) approves -> the DO-executed otlp-push-dest-set runs
    // immediately (maker != checker); GET /admin/otlp-push then reflects the new destination, still no secret.
    // =====================================================================================
    {
      const s = makeStack();
      const env = mkEnv(s, { CONFIG_WRAP_KEY });
      const O1 = "otlp-dc-owner1@cov.example";
      const O2 = "otlp-dc-owner2@cov.example";
      ok("owner1 bootstrap", (await call(env, "GET", "/admin/whoami", { jwt: await tokenFor(O1) })).json.role === "owner");
      const grant = await call(env, "POST", "/admin/roles", { jwt: await tokenFor(O1), body: { email: O2, role: "owner" } });
      ok("owner2 granted (inline, gate still off)", grant.status === 200);
      const arm = await call(env, "POST", "/admin/config/approval-policy", { jwt: await tokenFor(O1), body: { requireConfigApproval: true } });
      ok("dual control armed", arm.status === 200);

      const proposal = await call(env, "POST", "/admin/otlp-push", { jwt: await tokenFor(O1), body: { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: SECRET, enabled: true } });
      ok("DUAL CONTROL: owner1 proposes -> 202 queued (gate on, second owner exists -> auto-gated high-blast op)", proposal.status === 202 && proposal.json.ownerActionQueued === true);
      const pendingId = proposal.json.id as string;
      ok("DUAL CONTROL: nothing is live yet (the egress is NOT repointed inline)", (await call(env, "GET", "/admin/otlp-push", { jwt: await tokenFor(O1) })).json.present === false);

      const inbox = await call(env, "GET", "/admin/owner-actions", { jwt: await tokenFor(O2) });
      const pending = (inbox.json as unknown as Array<{ id: string; kind: string; params: Record<string, unknown> }>).find((a) => a.id === pendingId);
      ok("the pending action is visible to owner2 (kind otlp-push-dest-set)", pending !== undefined && pending.kind === "otlp-push-dest-set");
      ok("the QUEUED listing carries the non-secret fields (endpoint/header name)", pending?.params.endpoint === "https://otlp.example.com/v1/metrics" && pending?.params.authHeaderName === "Authorization");
      ok("DUAL CONTROL: the QUEUED listing NEVER carries the secret (redactOwnerActionParamsForListing strips authHeaderValue)", !("authHeaderValue" in (pending?.params ?? {})) && !JSON.stringify(pending?.params ?? {}).includes(SECRET));

      // Self-approval is refused (maker != checker), at the DO (defence in depth).
      const selfApprove = await call(env, "POST", `/admin/owner-actions/${pendingId}/approve`, { jwt: await tokenFor(O1) });
      ok("DUAL CONTROL: owner1 cannot approve their own proposal", selfApprove.status !== 200);

      const approve = await call(env, "POST", `/admin/owner-actions/${pendingId}/approve`, { jwt: await tokenFor(O2) });
      ok("DUAL CONTROL: owner2 (distinct identity) approves -> 200, executed", approve.status === 200 && approve.json.status === "executed");

      const get = await call(env, "GET", "/admin/otlp-push", { jwt: await tokenFor(O1) });
      ok("the approved config is now live (GET reflects it)", get.json.present === true && get.json.endpoint === "https://otlp.example.com/v1/metrics" && get.json.authHeaderName === "Authorization");
      ok("still no secret in the live GET after the dual-control execute", !JSON.stringify(get.json).includes(SECRET));
      // And at rest it is still sealed (the approved execution replayed the wrapped secret the router sealed).
      const rec = await s.dobj.getOtlpPushRecordRaw();
      ok("DUAL CONTROL: the executed config stores a WrappedSecret envelope, never plaintext", rec !== null && isWrappedSecret(rec.authHeaderValue) && !JSON.stringify(rec.authHeaderValue).includes(SECRET));
    }

    // =====================================================================================
    // The default fall-through: a method+path this spoke does not own returns null (the hub 404s).
    // =====================================================================================
    {
      const s = makeStack();
      const r = await call(mkEnv(s, { ADMIN_TOKEN }), "GET", "/admin/otlp-push-not-a-route", { bearer: ADMIN_TOKEN });
      ok("default: an unowned otlp-push-spoke path falls through to 404", r.status === 404);
    }
  } finally {
    globalThis.fetch = realFetch;
  }

  console.log(failures === 0 ? "\nOTLP PUSH ROUTER VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
