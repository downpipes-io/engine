// Shared harness for the D4 audit-log validator (split out of validate-audit.ts for size,
// finding engine-test-001-01). This module holds the in-memory DO doubles, the scheduler
// builder, the forged-but-correctly-signed RS256 Access JWT plumbing, the secret-marker
// constants and the per-run context (one live SchedulerDO + its audit chain). The PROOF blocks
// live in sibling modules (-events / -records / -chain / -redaction / -rollover); validate-audit.ts
// is the thin orchestrator that builds ONE shared context and CALLS each group in the original
// order, so the full suite still runs against the same state with the same assertions.

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { encodeCaller, CALLER_HEADER, type Caller } from "../src/admin/identity.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import type { Env } from "../src/env.d.ts";

// Re-export the caller helpers the PROOF groups drive the DO with directly.
export { encodeCaller, CALLER_HEADER, type Caller };

import { MockStorage } from "./mock-storage.ts";
export { MockStorage };

export interface Scheduler {
  env: Pick<Env, "SCHEDULER">;
  storage: MockStorage;
  stub: DurableObjectStub;
}

export function makeScheduler(): Scheduler {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace }, storage, stub };
}

// ---- Forged Access JWT (real RS256 verification, controlled JWKS) ------------------------
export const TEAM = "acme-corp";
export const ISS = `https://${TEAM}.cloudflareaccess.com`;
export const AUD = "audit-test-aud";
export const KID = "audit-kid-1";

export function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

// SECRET_MARKERS are distinctive byte-strings that MUST NEVER appear in the serialised audit log.
// They stand in for real secret material: a signer private key, a break-glass private, an
// operational private, a destination credential, and a private-half fingerprint. The redaction
// proof drives privileged actions whose REQUESTS reference only safe names, then asserts none of
// these markers (and none of the engine's reserved secret binding NAMES that imply a value) leaked.
export const SECRET_MARKERS = [
  "SIGNER_PRIVATE_VALUE_zzz",
  "BREAK_GLASS_PRIVATE_zzz",
  "OPERATIONAL_PRIVATE_zzz",
  "DEST_SECRET_ACCESS_KEY_zzz",
  "dpr1:deadbeefdeadbeef", // a private-half-style fingerprint
];

export const OWNER = "owner@acme.example";
export const OPERATOR = "operator@acme.example";
export const VIEWER = "viewer@acme.example";
export const APPROVER = "approver@acme.example";

export interface Ctx {
  ok(label: string, cond: boolean): void;
  getFailures(): number;
  sched: Scheduler;
  accessEnv(): Env;
  tokenFor(email: string): Promise<string>;
  subjectOf(email: string): string;
  call(email: string, method: "GET" | "POST", path: string, body?: unknown, headers?: Record<string, string>): Promise<Response>;
  readLog(query?: string): Promise<{ events: AuditEvent[]; headSeq: number; headHash: string }>;
}

// buildContext builds a fresh live DO + the JWKS-stubbed fetch + every request helper, exactly as
// the original main() did inline. The caller is responsible for restoring globalThis.fetch (see
// realFetch). It also bootstraps the OWNER and seeds the role table for the matrix.
export async function buildContext(): Promise<{ ctx: Ctx; realFetch: typeof fetch }> {
  let failures = 0;
  function ok(label: string, cond: boolean): void {
    console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
    if (!cond) failures++;
  }

  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pubJwk.n, e: pubJwk.e }] };

  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${ISS}/cdn-cgi/access/certs`) {
      return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    }
    throw new Error(`unexpected network fetch in test: ${url}`);
  }) as typeof fetch;

  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  // The audit actor now records the STABLE subject (iss+"|"+sub) alongside the display email, and the role
  // table keys on the subject, so the forged token must carry a sub. A stable per-email sub means each
  // distinct email is a distinct subject (the normal case).
  async function tokenFor(email: string): Promise<string> {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  }
  const subjectOf = (email: string): string => `${ISS}|sub-of-${email}`;

  const sched = makeScheduler();
  const accessEnv = (): Env =>
    ({
      ...sched.env,
      CF_ACCESS_TEAM_DOMAIN: TEAM,
      CF_ACCESS_AUD: AUD,
    }) as unknown as Env;

  async function call(email: string, method: "GET" | "POST", path: string, body?: unknown, headers?: Record<string, string>): Promise<Response> {
    const assertion = await tokenFor(email);
    const init: RequestInit = {
      method,
      headers: { "cf-access-jwt-assertion": assertion, ...(headers ?? {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), accessEnv());
  }

  // Read the whole audit log via the API (newest-first paged; we ask for a large page).
  async function readLog(query = ""): Promise<{ events: AuditEvent[]; headSeq: number; headHash: string }> {
    const r = await call(OWNER, "GET", "/admin/audit?limit=500" + (query ? "&" + query : ""));
    return (await r.json()) as { events: AuditEvent[]; headSeq: number; headHash: string };
  }

  // Bootstrap OWNER (first Access caller -> Owner) and seed the role table for the matrix.
  await call(OWNER, "GET", "/admin/whoami");
  await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
  await call(OWNER, "POST", "/admin/roles", { email: VIEWER, role: "viewer" });
  await call(OWNER, "POST", "/admin/roles", { email: APPROVER, role: "approver" });

  const ctx: Ctx = { ok, getFailures: () => failures, sched, accessEnv, tokenFor, subjectOf, call, readLog };
  return { ctx, realFetch };
}
