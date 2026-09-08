// Shared harness for the validate-rbac suite. The RBAC proofs were
// split out of test/validate-rbac.ts into sibling modules; this module holds the in-memory doubles,
// the forged-Access-JWT minting and the per-run context so every extracted group runs against the
// SAME production code path and shared state the single-file suite used. Behaviour is unchanged: the
// orchestrator builds one context here and passes it to each group in the original order.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";

// ---- Pass/fail accounting (shared so every group reports through the one counter) -------------
export interface Counter {
  failures: number;
}

export function makeOk(counter: Counter): (label: string, cond: boolean) => void {
  return (label: string, cond: boolean): void => {
    console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
    if (!cond) counter.failures++;
  };
}

// ---- In-memory DO storage (the subset SchedulerDO uses) ---------------------------------
// get/put/delete and a prefix list, plus a no-op setAlarm. Backed by a Map so the role table,
// the bootstrap write and the last-Owner read-modify-write all operate on real persisted state.
export class MockStorage {
  private map = new Map<string, unknown>();
  async get<T>(key: string): Promise<T | undefined>;
  async get<T>(keys: string[]): Promise<Map<string, T>>;
  async get<T>(key: string | string[]): Promise<T | undefined | Map<string, T>> {
    // Batch-get (an array of keys -> Map) the way the real DO storage does, so the config-change dry-run's
    // batched ring reads work against this mock (an approver-minting role-set now runs through the dry-run).
    if (Array.isArray(key)) {
      const out = new Map<string, T>();
      for (const k of key) {
        const v = this.map.get(k);
        if (v !== undefined) out.set(k, v as T);
      }
      return out;
    }
    return this.map.get(key) as T | undefined;
  }
  async put<T>(key: string, value: T): Promise<void> {
    // Structured-clone the value the way the DO platform would, so a stored object is not a live
    // reference a later mutation could corrupt (the role entries are plain JSON).
    this.map.set(key, JSON.parse(JSON.stringify(value)));
  }
  async delete(key: string): Promise<boolean> {
    return this.map.delete(key);
  }
  async list<T>(opts?: { prefix?: string }): Promise<Map<string, T>> {
    const prefix = opts?.prefix ?? "";
    const out = new Map<string, T>();
    for (const [k, v] of this.map) if (k.startsWith(prefix)) out.set(k, v as T);
    return out;
  }
  // An in-memory alarm so the config-change dry-run path (dryRunConfigMutation captures + restores the alarm)
  // works against this mock exactly as the real DO storage does, now an approver-minting role-set runs through it.
  private alarm: number | null = null;
  async getAlarm(): Promise<number | null> {
    return this.alarm;
  }
  async setAlarm(t: number): Promise<void> {
    this.alarm = t;
  }
  async deleteAlarm(): Promise<void> {
    this.alarm = null;
  }
}

// makeScheduler builds a SchedulerDO over MockStorage and a SCHEDULER namespace whose
// idFromName/get both return a stub forwarding fetch() into the DO, so handleAdmin's
// schedulerStub() resolves to this one in-memory DO. opts.failRateCheck, when set, makes the stub
// THROW for the /rate-check path only (to prove the router's fail-open in the rate-limit suite),
// leaving every other DO route working; the RBAC suite passes no opts so its behaviour is unchanged.
export function makeScheduler(opts?: { failRateCheck?: boolean }): { env: Pick<Env, "SCHEDULER">; storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (opts?.failRateCheck && url.endsWith("/rate-check")) {
        // Simulate the rate-limit backing store being unavailable: the router must fail OPEN.
        throw new Error("simulated DO /rate-check unavailable");
      }
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
// A generic placeholder team slug: the JWKS endpoint is stubbed, so this is a pure fixture and must not
// embed real infrastructure naming. ISS and subjectOf derive from it, so the whole suite stays
// internally consistent.
export const TEAM = "test-team";
export const ISS = `https://${TEAM}.cloudflareaccess.com`;
export const AUD = "rbac-test-aud";
export const KID = "rbac-kid-1";

export function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

// Signer bundles the one RSA keypair plus the future-exp window every test token shares, and the
// minting helpers built over them. installFetchStub() points global fetch at the controlled JWKS so
// authorise() -> verifyAccessJWT verifies for real; restore() puts the real fetch back.
export interface Signer {
  futureExp: number;
  privateKey: CryptoKey;
  tokenForSub(email: string, sub: string): Promise<string>;
  tokenFor(email: string): Promise<string>;
  subjectOf(email: string): string;
  restoreFetch(): void;
}

export async function makeSigner(): Promise<Signer> {
  // One RSA keypair signs every test token; its public half is the only key in the JWKS the
  // stubbed fetch serves, so authorise() -> verifyAccessJWT verifies for real.
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pubJwk.n, e: pubJwk.e }] };

  // Stub global fetch so the team certs URL returns our JWKS; anything else throws so a stray
  // network call is loud, not silent. authorise() caches the JWKS per-URL after the first hit.
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${ISS}/cdn-cgi/access/certs`) {
      return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    }
    throw new Error(`unexpected network fetch in test: ${url}`);
  }) as typeof fetch;

  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  // tokenForSub mints a verified Access JWT for an (email, sub) pair. The role table now keys on the
  // STABLE subject (iss+"|"+sub), so the test must supply a sub. tokenFor defaults the sub to a stable
  // per-email value ("sub-of-<email>") so every distinct email is a distinct subject (the normal case);
  // the V10.3.3 closure regression below calls tokenForSub directly to forge the SAME email with a
  // DIFFERENT sub (a recycled address reassigned to a new Access user).
  async function tokenForSub(email: string, sub: string): Promise<string> {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  }
  async function tokenFor(email: string): Promise<string> {
    return tokenForSub(email, `sub-of-${email}`);
  }
  // subjectOf mirrors access.ts's subject construction (iss+"|"+sub) so a test can assert whoami's
  // returned subject without reaching into the engine.
  const subjectOf = (email: string): string => `${ISS}|sub-of-${email}`;

  return {
    futureExp,
    privateKey: kp.privateKey,
    tokenForSub,
    tokenFor,
    subjectOf,
    restoreFetch: () => {
      globalThis.fetch = realFetch;
    },
  };
}

// ---- The role constants the ordered proofs (1..10b) share -------------------------------------
export const OWNER = "owner@acme.example";
export const OPERATOR = "operator@acme.example";
export const VIEWER = "viewer@acme.example";
export const APPROVER = "approver@acme.example";
export const OWNER2 = "owner2@acme.example";

// Ctx is the per-run context the ordered proof groups share: the one in-memory scheduler, an Env
// factory configured for the Access path, a `call` that drives handleAdmin as a given Access
// identity, the signer (for direct mint), and the ok() reporter. Proofs 1..10b are STATEFUL over the
// same scheduler and run in the original order, so they take this single context.
export interface Ctx {
  ok: (label: string, cond: boolean) => void;
  signer: Signer;
  sched: ReturnType<typeof makeScheduler>;
  accessEnv: () => Env;
  call: (email: string, method: "GET" | "POST", path: string, body?: unknown) => Promise<Response>;
}
