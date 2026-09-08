// Shared harness for the config change-control validator (split out of validate-config-change-control.ts
// for size). This module holds the in-memory DO storage doubles, the scheduler
// builders, the forged Access-JWT plumbing, and the per-run CONTEXT object (all the request helpers +
// fixtures + the ok/failures accumulator) that each extracted PROOF group consumes. The behaviour is
// byte-identical to the original inline definitions: same storage semantics, same helpers, same fixtures.

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { type AuditEvent } from "../src/admin/audit.ts";
import { type PendingConfigChange } from "../src/admin/change-control.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import type { DownpipeState, DownpipeConfig } from "../src/sched/scheduler-do.ts";
import type { RoleEntry } from "../src/admin/identity.ts";

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

// ---- Paging storage that HONOURS startAfter + limit -------------------------
// The platform caps a single storage.list() at a page limit (PLATFORM_LIST_PAGE keys) and HONOURS
// limit + startAfter (exclusive lower bound), exactly as validate-fleet-scale's PagingStorage does. A
// caller that wants the whole keyspace MUST loop with startAfter until a short page comes back, which is
// what listAllByPrefix does. dryRunConfigMutation captures its checkpoint and enumerates the rollback
// over the WHOLE keyspace; a BARE list() returns at most one page, so on a keyspace larger than the page
// it would snapshot only page 1 and then fail to roll back a write whose key sorts beyond the page, so a
// mere PROPOSAL would leave a side effect (the would-be downpipe persisting). The fix pages the scan, so
// the checkpoint + rollback are complete regardless of tenant scale.
export const PLATFORM_LIST_PAGE = 1000; // the platform's default/maximum keys-per-list page (matches DO_LIST_PAGE)
export class PagingStorage {
  private map = new Map<string, unknown>();
  private alarm: number | null = null;
  async get<T>(key: string): Promise<T | undefined> {
    const v = this.map.get(key);
    return v === undefined ? undefined : (JSON.parse(JSON.stringify(v)) as T);
  }
  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, JSON.parse(JSON.stringify(value)));
  }
  async delete(key: string): Promise<boolean> {
    return this.map.delete(key);
  }
  async list<T>(opts?: { prefix?: string; start?: string; startAfter?: string; limit?: number }): Promise<Map<string, T>> {
    const prefix = opts?.prefix ?? "";
    let keys = [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
    if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > (opts.startAfter as string));
    if (opts?.start !== undefined) keys = keys.filter((k) => k >= (opts.start as string));
    const cap = Math.min(opts?.limit ?? PLATFORM_LIST_PAGE, PLATFORM_LIST_PAGE);
    const page = keys.slice(0, cap);
    const out = new Map<string, T>();
    for (const k of page) out.set(k, this.map.get(k) as T);
    return out;
  }
  async getAlarm(): Promise<number | null> {
    return this.alarm;
  }
  async setAlarm(t: number): Promise<void> {
    this.alarm = t;
  }
  async deleteAlarm(): Promise<void> {
    this.alarm = null;
  }
  rawPut<T>(key: string, value: T): void {
    this.map.set(key, JSON.parse(JSON.stringify(value)));
  }
  keysWithPrefix(prefix: string): string[] {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix));
  }
}

export interface PagedScheduler {
  env: Pick<Env, "SCHEDULER">;
  storage: PagingStorage;
}

export function makePagedScheduler(): PagedScheduler {
  const storage = new PagingStorage();
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
  return { env: { SCHEDULER: namespace }, storage };
}

// ---- Forged Access JWT (real RS256 verification, controlled JWKS), from validate-dualcontrol ----
export const TEAM = "maelstrom";
export const ISS = `https://${TEAM}.cloudflareaccess.com`;
export const AUD = "change-control-test-aud";
export const KID = "change-control-kid-1";

export function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

// The fixture emails used across every PROOF group. They are typed as string (not literals) so the
// maker != checker assertions stay genuine runtime comparisons (a literal type would let TypeScript prove
// proposedBy !== approvedBy statically and flag TS2367).
export const OWNER = "owner@acme.example";
export const OPERATOR: string = "operator@acme.example"; // holds downpipe.write/delete, NOT roles.write/access.policy
export const OPERATOR2: string = "operator2@acme.example"; // a second operator, the distinct checker for downpipe changes
export const VIEWER = "viewer@acme.example"; // holds downpipe.read only (no write caps)
export const ACCESS_ADMIN = "accessadmin@acme.example"; // holds roles.write/access.policy, NOT downpipe.write
export const ACCESS_ADMIN2 = "accessadmin2@acme.example"; // a second access-admin, the distinct checker for people changes
export const OWNER2: string = "owner2@acme.example"; // a SECOND Owner, so dual control can be armed (the two-Owner enable floor)

// The per-run context every extracted PROOF group consumes. It bundles the request helpers (call, readLog,
// list*, etc.), the gate toggle, the fixtures, and the ok/failures accumulator, so each group runs against
// the SAME live DO + audit chain in order, exactly as the original single main() did.
export interface Ctx {
  ok(label: string, cond: boolean): void;
  getFailures(): number;
  sched: Scheduler;
  ADMIN_TOKEN: string;
  accessEnv(): Env;
  tokenFor(email: string): Promise<string>;
  call(email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response>;
  readLog(query?: string): Promise<{ events: AuditEvent[]; headSeq: number; headHash: string }>;
  listDownpipes(): Promise<DownpipeState[]>;
  listRoles(): Promise<RoleEntry[]>;
  pendingChanges(asEmail: string): Promise<PendingConfigChange[]>;
  setGate(asEmail: string, on: boolean): Promise<Response>;
  pendingKeyCount(): number;
  listChannels(): Promise<Array<{ id: string; name: string }>>;
  listExpiry(): Promise<Array<{ id: string }>>;
  configHistory(): Promise<{ versions: Array<{ id: number; author: string | null; summary: string }>; headId: number }>;
  configDiff(from: number, to: number): Promise<{ found: boolean; changes?: Array<{ kind: string; area: string; text: string }> }>;
  dp(id: string, name: string, cadence?: number): DownpipeConfig;
}

// Shared mutable state threaded between the dependent groups (e.g. PROOF 3 queues a downpipe whose id PROOF
// 5/6/7 then approve). Kept tiny + explicit so the data flow between groups is visible at the call site.
export interface Shared {
  queuedDownpipeId: string;
}

// buildContext builds a fresh live DO + the JWKS-stubbed fetch + every request helper, exactly as the
// original main() did inline. The caller is responsible for restoring globalThis.fetch (see realFetch).
export async function buildContext(): Promise<{ ctx: Ctx; realFetch: typeof fetch }> {
  let failures = 0;
  function ok(label: string, cond: boolean): void {
    console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
    if (!cond) failures++;
  }

  // The Access JWKS, served by a stubbed global fetch.
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pubJwk.n, e: pubJwk.e }] };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${ISS}/cdn-cgi/access/certs`) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    throw new Error(`unexpected network fetch in test: ${url}`);
  }) as typeof fetch;

  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  async function tokenFor(email: string): Promise<string> {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  }

  const sched = makeScheduler();
  // ADMIN_TOKEN is set so the test can DISARM the dual-control gate via the bare-token break-glass owner
  // (immediate, no second owner) — the off switch is now ASYMMETRIC: an attributable owner's disarm is gated
  // behind a second owner (FOLD 1), but the break-glass owner can always disarm directly (the lockout escape).
  // Setting ADMIN_TOKEN does NOT affect the Access-JWT callers (they authenticate via cf-access-jwt-assertion).
  const ADMIN_TOKEN = "config-change-break-glass-token";
  const accessEnv = (): Env => ({ ...sched.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN }) as unknown as Env;

  async function call(email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
    const assertion = await tokenFor(email);
    const init: RequestInit = {
      method,
      headers: { "cf-access-jwt-assertion": assertion, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), accessEnv());
  }
  async function readLog(query = ""): Promise<{ events: AuditEvent[]; headSeq: number; headHash: string }> {
    const r = await call(OWNER, "GET", "/admin/audit?limit=1000" + (query ? "&" + query : ""));
    return (await r.json()) as { events: AuditEvent[]; headSeq: number; headHash: string };
  }
  async function listDownpipes(): Promise<DownpipeState[]> {
    return (await (await call(OWNER, "GET", "/admin/downpipes")).json()) as DownpipeState[];
  }
  async function listRoles(): Promise<RoleEntry[]> {
    return (await (await call(OWNER, "GET", "/admin/roles")).json()) as RoleEntry[];
  }
  async function pendingChanges(asEmail: string): Promise<PendingConfigChange[]> {
    return (await (await call(asEmail, "GET", "/admin/config/changes")).json()) as PendingConfigChange[];
  }
  // setGate arms/disarms the dual-control gate. ARM (true) is immediate via the attributable owner. DISARM
  // (false) is now asymmetric for an attributable owner (gated behind a second owner), so this helper disarms
  // via the BARE-TOKEN break-glass owner, which is immediate (the lockout escape) — these tests only need the
  // gate reset, not the asymmetric-disarm semantics (those are proven in the owner-action validator).
  async function setGate(asEmail: string, on: boolean): Promise<Response> {
    if (on) return call(asEmail, "POST", "/admin/config/approval-policy", { requireConfigApproval: true });
    const init: RequestInit = { method: "POST", headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" }, body: JSON.stringify({ requireConfigApproval: false }) };
    return handleAdmin(new Request("https://engine.example/admin/config/approval-policy", init), accessEnv());
  }
  function pendingKeyCount(): number {
    return sched.storage.keysWithPrefix("configchange:").length;
  }
  async function listChannels(): Promise<Array<{ id: string; name: string }>> {
    return (await (await call(OWNER, "GET", "/admin/notify/channels")).json()) as Array<{ id: string; name: string }>;
  }
  async function listExpiry(): Promise<Array<{ id: string }>> {
    return (await (await call(OWNER, "GET", "/admin/expiry")).json()) as Array<{ id: string }>;
  }
  async function configHistory(): Promise<{ versions: Array<{ id: number; author: string | null; summary: string }>; headId: number }> {
    return (await (await call(OWNER, "GET", "/admin/config/history")).json()) as { versions: Array<{ id: number; author: string | null; summary: string }>; headId: number };
  }
  async function configDiff(from: number, to: number): Promise<{ found: boolean; changes?: Array<{ kind: string; area: string; text: string }> }> {
    return (await (await call(OWNER, "GET", `/admin/config/diff?from=${from}&to=${to}`)).json()) as { found: boolean; changes?: Array<{ kind: string; area: string; text: string }> };
  }

  function dp(id: string, name: string, cadence = 3600): DownpipeConfig {
    return { id, name, cadenceSeconds: cadence, enabled: true, source: { type: "kv", binding: `KV_${id}`, include: [], exclude: [] } } as DownpipeConfig;
  }

  // Bootstrap OWNER (first Access caller) and seed the role table. A SECOND Owner is seeded too, so the
  // dual-control gate can be ARMED (enabling it needs at least two Owners; the invariant guard refuses a lone
  // Owner arming it). Granted while the estate has one Owner and the gate is off, so it applies inline.
  await call(OWNER, "GET", "/admin/whoami");
  await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
  await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
  await call(OWNER, "POST", "/admin/roles", { email: OPERATOR2, role: "operator" });
  await call(OWNER, "POST", "/admin/roles", { email: VIEWER, role: "viewer" });
  await call(OWNER, "POST", "/admin/roles", { email: ACCESS_ADMIN, role: "access-admin" });
  await call(OWNER, "POST", "/admin/roles", { email: ACCESS_ADMIN2, role: "access-admin" });

  const ctx: Ctx = {
    ok,
    getFailures: () => failures,
    sched,
    ADMIN_TOKEN,
    accessEnv,
    tokenFor,
    call,
    readLog,
    listDownpipes,
    listRoles,
    pendingChanges,
    setGate,
    pendingKeyCount,
    listChannels,
    listExpiry,
    configHistory,
    configDiff,
    dp,
  };
  return { ctx, realFetch };
}
