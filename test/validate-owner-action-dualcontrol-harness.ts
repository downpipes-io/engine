// Shared harness for the OWNER-ACTION DUAL CONTROL proof, split out of validate-owner-action-dualcontrol.ts
// so each proof group can live in its own sibling module under the 500-line cap. This module owns:
//  - the ok()/failures accumulator (a single shared counter across all groups so the final tally is faithful);
//  - the in-memory DO storage + scheduler factory (MockStorage / makeScheduler);
//  - the forged-but-correctly-signed RS256 Access JWT harness;
//  - buildContext(), which wires the PRODUCTION handleAdmin + the DO stub into the closures (call / doFetch /
//    setGate / listDestinations / ...) every proof group shares, and returns them as a Ctx object.
// The split is behaviour-preserving: the closures are byte-equivalent to the originals, just hung off a context.

import { handleAdmin } from "../src/admin/router.ts";
export { handleAdmin };
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import { type PendingOwnerAction, OWNER_ACTION_PREFIX } from "../src/admin/owner-action.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { CHANGE_HEADER, type ChangeRef } from "../src/admin/change-ref.ts";
import type { Env } from "../src/env.d.ts";

// ---- Shared pass/fail accumulator. All groups call the SAME ok() so the final count is faithful. -------------
let failures = 0;
export function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
export function failureCount(): number {
  return failures;
}

import { MockStorage } from "./mock-storage.ts";
export { MockStorage };

// dobj is EXPOSED alongside the stub so a proof can call a DO method that no ROUTE reaches. That is a narrow
// but real need: spendTimeGroupsFor is the spend-time authority re-resolution's group source, it is invoked
// only from inside another DO method, and "this record is read by a path that presents no session" is exactly
// the kind of claim that has to be measured rather than asserted (validate-offboard-residue E15). Everything
// else must keep going through the stub, so the production router and authorisation stay under test.
export function makeScheduler(): { env: Pick<Env, "SCHEDULER">; storage: MockStorage; stub: DurableObjectStub; dobj: SchedulerDO; guardThrows: () => number; resetGuardThrows: () => void } {
  const storage = new MockStorage();
  // Instrument blockConcurrencyWhile. It runs fn() directly (exactly the DO's own fallback when the
  // platform method is absent, so every proof behaves identically to before) but COUNTS a throw OUT of the
  // guarded fn. That throw is the load-bearing signal the offline validator otherwise hides: in the REAL
  // workerd runtime a throw inside blockConcurrencyWhile RESETS the Durable Object (wiping its in-memory state)
  // and surfaces as a 500 instead of the clean 403 an AuthError maps to. A foreseeable auth refusal must
  // therefore be caught INSIDE the guard and re-thrown OUTSIDE it, leaving guardThrows() at 0. The counter lets
  // the proof assert exactly that (0 = no DO reset), which is otherwise unobservable offline.
  let guardThrowCount = 0;
  const state = {
    storage,
    blockConcurrencyWhile: async <T>(fn: () => Promise<T>): Promise<T> => {
      try {
        return await fn();
      } catch (e) {
        guardThrowCount++; // a throw here would reset the DO in workerd; the offline run re-throws the same error
        throw e;
      }
    },
  } as unknown as DurableObjectState;
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
  return { env: { SCHEDULER: namespace }, storage, stub, dobj, guardThrows: () => guardThrowCount, resetGuardThrows: () => { guardThrowCount = 0; } };
}

// ---- Forged Access JWT (real RS256 verification, controlled JWKS), from validate-config-change-control ----
export const TEAM = "maelstrom";
export const ISS = `https://${TEAM}.cloudflareaccess.com`;
export const AUD = "owner-action-test-aud";
export const KID = "owner-action-kid-1";

function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

// The shared context every proof group receives. Each field is one of the closures (or constants) the original
// single main() defined; bundling them keeps the proof groups byte-faithful to the inline original.
export interface Ctx {
  sched: ReturnType<typeof makeScheduler>;
  webhookPosts: unknown[];
  realFetch: typeof fetch;
  OWNER: string;
  OWNER2: string;
  OPERATOR: string;
  subjectOf: (email: string) => string;
  call: (email: string, method: "GET" | "POST", path: string, body?: unknown, change?: ChangeRef | null) => Promise<Response>;
  readLog: (query?: string) => Promise<{ events: AuditEvent[]; headSeq: number; headHash: string }>;
  setGate: (asEmail: string, on: boolean) => Promise<Response>;
  ownerActionKeyCount: () => number;
  inbox: (asEmail: string) => Promise<PendingOwnerAction[]>;
  listDestinations: () => Promise<{ destinations: Array<{ id: string; label?: string }>; defaultId: string | null }>;
  listIdpConnections: (asEmail: string) => Promise<{ ok: boolean; connections?: Array<{ id: string; enabled: boolean }> }>;
  discoveryStatus: () => Promise<{ present: boolean; selected?: string[] }>;
  destConfig: (bucket: string) => Record<string, unknown>;
  oidcProposal: (id: string) => Record<string, unknown>;
  ownerCaller: (email: string) => Caller;
  doFetch: (path: string, caller: Caller | null, body?: unknown, method?: "GET" | "POST") => Promise<Response>;
  applyOwnerOp: (path: string, body?: unknown) => Promise<void>;
}

// buildContext wires the production handleAdmin + DO stub into the shared closures and seeds the JWKS/webhook
// fetch shim. It bootstraps ONLY the first owner (the single-owner proofs run before the second owner exists);
// the second owner + operator are granted later, by the group that needs them (PROOF S1b two-owner onwards).
export async function buildContext(): Promise<Ctx> {
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pubJwk.n, e: pubJwk.e }] };
  // Capture webhook deliveries so the FOLD-1 disarm-alert proof can assert a notification fired. The
  // dual-control disarm alert is delivered (router-side) by POSTing the configured webhook channel's url;
  // we record each POST body to WEBHOOK_SINK so the proof can inspect it without real network.
  const WEBHOOK_SINK = "https://hooks.example.com/alert";
  const webhookPosts: unknown[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${ISS}/cdn-cgi/access/certs`) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    if (url === WEBHOOK_SINK) {
      try {
        webhookPosts.push(init && typeof init.body === "string" ? JSON.parse(init.body) : null);
      } catch {
        webhookPosts.push(null);
      }
      return new Response("ok", { status: 200 });
    }
    throw new Error(`unexpected network fetch in test: ${url}`);
  }) as typeof fetch;

  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  async function tokenFor(email: string): Promise<string> {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  }
  const subjectOf = (email: string): string => `${ISS}|sub-of-${email}`;

  const sched = makeScheduler();
  const accessEnv = (): Env => ({ ...sched.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD }) as unknown as Env;

  // Typed as string (not a literal) so the maker != checker assertion stays a genuine runtime comparison
  // (a literal type would let TypeScript prove proposedBy !== approvedBy statically and flag TS2367).
  const OWNER: string = "owner@acme.example"; // the first Access caller -> bootstrapped Owner
  const OWNER2: string = "owner2@acme.example"; // a SECOND distinct owner, the checker
  const OPERATOR = "operator@acme.example"; // a non-owner (cannot approve / cannot toggle)

  // change (optional, the 5th arg so every existing call site is untouched) threads a change reference onto
  // the request exactly as the console does: base64url(JSON(ChangeRef)) on the X-Downpipes-Change header
  // (change-ref.ts CHANGE_HEADER), which router.ts reads ONCE onto caller.change. Omitted/undefined/null
  // means no header at all, matching every pre-existing call() site byte-for-byte.
  async function call(email: string, method: "GET" | "POST", path: string, body?: unknown, change?: ChangeRef | null): Promise<Response> {
    const assertion = await tokenFor(email);
    const init: RequestInit = {
      method,
      headers: {
        "cf-access-jwt-assertion": assertion,
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
        ...(change ? { [CHANGE_HEADER]: b64urlEncode(new TextEncoder().encode(JSON.stringify(change))) } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), accessEnv());
  }
  async function readLog(query = ""): Promise<{ events: AuditEvent[]; headSeq: number; headHash: string }> {
    const r = await call(OWNER, "GET", "/admin/audit?limit=1000" + (query ? "&" + query : ""));
    return (await r.json()) as { events: AuditEvent[]; headSeq: number; headHash: string };
  }
  // setGate arms/disarms the dual-control gate. ARM (true) and a no-op are immediate. DISARM (false) is now
  // ASYMMETRIC for an attributable owner (FOLD 1): when the gate is ON it returns a 202 owner-action and only
  // flips OFF on a DISTINCT second owner's approval. So setGate(owner, false) here performs the full disarm
  // dance — propose as asEmail, approve as a DISTINCT owner — so the helper still leaves the gate OFF for the
  // call sites that just need to reset state. (The bare-token break-glass path is exercised directly in the
  // disarm proof, not through this Access-caller helper.)
  async function setGate(asEmail: string, on: boolean): Promise<Response> {
    if (on) return call(asEmail, "POST", "/admin/config/approval-policy", { requireConfigApproval: true });
    const resp = await call(asEmail, "POST", "/admin/config/approval-policy", { requireConfigApproval: false });
    if (resp.status !== 202) return resp; // gate already OFF (no-op) -> immediate 200
    // A distinct second owner approves the dual-control-disable so the gate actually flips OFF.
    const id = ((await resp.json()) as { id?: string }).id ?? "";
    const checker = asEmail === OWNER ? OWNER2 : OWNER;
    return call(checker, "POST", `/admin/owner-actions/${id}/approve`);
  }
  function ownerActionKeyCount(): number {
    return sched.storage.keysWithPrefix(OWNER_ACTION_PREFIX).length;
  }
  async function inbox(asEmail: string): Promise<PendingOwnerAction[]> {
    return (await (await call(asEmail, "GET", "/admin/owner-actions")).json()) as PendingOwnerAction[];
  }
  async function listDestinations(): Promise<{ destinations: Array<{ id: string; label?: string }>; defaultId: string | null }> {
    return (await (await call(OWNER, "GET", "/admin/destinations")).json()) as { destinations: Array<{ id: string; label?: string }>; defaultId: string | null };
  }
  async function listIdpConnections(asEmail: string): Promise<{ ok: boolean; connections?: Array<{ id: string; enabled: boolean }> }> {
    return (await (await call(asEmail, "GET", "/admin/idp/connections")).json()) as { ok: boolean; connections?: Array<{ id: string; enabled: boolean }> };
  }
  async function discoveryStatus(): Promise<{ present: boolean; selected?: string[] }> {
    return (await (await call(OWNER, "GET", "/admin/sources/discovery-status")).json()) as { present: boolean; selected?: string[] };
  }

  // A full destination config the DO's buildDestRecord accepts (the router probes live; driving the DO
  // directly bypasses the probe, so the config must carry every field). NO secret reaches the audit/inbox.
  function destConfig(bucket: string): Record<string, unknown> {
    return { endpoint: "https://acct.r2.cloudflarestorage.com", bucket, region: "auto", accessKeyId: "AKIAEXAMPLE", secretAccessKey: "super-secret-key-value", verifiedAt: Date.now(), deleteProbe: "ok" };
  }
  // A valid OIDC connection proposal (from validate-idpconn), so an approved idp-conn-create actually stores.
  function oidcProposal(id: string): Record<string, unknown> {
    return {
      proposal: {
        id, kind: "oidc", label: `conn ${id}`, presetId: "entra", enabled: true,
        issuer: "https://login.microsoftonline.com/TENANTID/v2.0", clientId: "client-abc",
        secretRef: { mode: "do-plaintext" }, scopes: ["openid", "email", "profile"],
        idTokenSigAlgs: ["RS256"], pkce: "required", clientAuth: "client_secret_post", requireNonce: true,
      },
    };
  }

  // Caller header builders for the DIRECT-to-DO (router-bypass) drives.
  function ownerCaller(email: string): Caller {
    return { method: "access", email, subject: subjectOf(email), role: "owner", groups: [] };
  }
  // method defaults to POST because almost every DO route here is one. It is a parameter because some are
  // NOT: the control-plane export slice is a GET, and without this a proof about what the export carries had
  // to reach for an admin route that needs SIGNER_PRIVATE, testing the signer rather than the slice.
  function doFetch(path: string, caller: Caller | null, body?: unknown, method: "GET" | "POST" = "POST"): Promise<Response> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (caller !== null) headers["x-downpipe-caller"] = encodeCaller(caller);
    const init: RequestInit = method === "GET" ? { method, headers } : { method, headers, body: JSON.stringify(body ?? {}) };
    return sched.stub.fetch(`https://scheduler.internal${path}`, init);
  }
  // applyOwnerOp drives a DO-executed owner op to COMPLETION regardless of whether it is gated: if the first
  // call applies inline (200) it returns; if it is queued (202, e.g. a high-blast op auto-gated by S1b once a
  // second owner exists) a DISTINCT owner approves it so the op actually executes. Used to SEED/CLEAN UP state
  // in proofs that are not themselves about the gate, so they no longer depend on the gate being off for a
  // high-blast kind. (OWNER proposes; OWNER2 approves; for ops where OWNER2 is unavailable callers pass it.)
  async function applyOwnerOp(path: string, body?: unknown): Promise<void> {
    const r = await doFetch(path, ownerCaller(OWNER), body);
    if (r.status === 202) {
      const id = ((await r.json()) as { id?: string }).id ?? "";
      await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id });
    }
  }

  // Bootstrap OWNER ONLY for now. The SECOND owner (and the operator) are granted AFTER the single-owner
  // proofs below (PROOF 1 + PROOF S1b-1owner): the high-blast auto-apply (S1b) engages ONLY once a second
  // owner exists, so the no-deadlock single-owner path must be proven while there is exactly one owner.
  await call(OWNER, "GET", "/admin/whoami");
  // Recovery ack so break-glass-retire's in-place gate is satisfied (a way back in exists). Two owners
  // already satisfy it, but ack too so the proof does not depend on the owner count.
  // (No recovery route is needed; two owners is sufficient for the retire precondition.)

  return {
    sched, webhookPosts, realFetch, OWNER, OWNER2, OPERATOR, subjectOf,
    call, readLog, setGate, ownerActionKeyCount, inbox, listDestinations, listIdpConnections,
    discoveryStatus, destConfig, oidcProposal, ownerCaller, doFetch, applyOwnerOp,
  };
}
