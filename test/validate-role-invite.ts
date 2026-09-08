// Prove the OPTIONAL role-invite notification (src/admin/router.ts): when a role (built-in OR custom)
// is granted to a person via POST /admin/roles, the engine best-effort sends that person an invite
// email. End to end and SERVER-SIDE, with in-memory doubles only. No network, no deploy, no cost. Run:
//   node test/validate-role-invite.ts
//
// What this proves:
//  - a SUCCESSFUL grant triggers ONE best-effort send (a stubbed EMAIL binding records the message),
//    and the message carries the configured INVITE_EMAIL_FROM sender, the GRANTED person as the single
//    recipient, the granted ROLE in the body, and the CONSOLE_ORIGIN sign-in link;
//  - a CUSTOM-role grant names the custom-role NAME (not the stored viewer floor) in the invite;
//  - OFF + SILENT when unconfigured: no EMAIL binding -> no send, grant still 200; binding present but
//    no INVITE_EMAIL_FROM -> no send, grant still 200 (the invite is a SEPARATE opt-in from EMAIL_FROM);
//  - a THROWING send does not fail the grant: the grant still returns 200 and the role is persisted;
//  - NEGATIVE CONTROL: a FAILED grant (the last-Owner guard 400) sends NO invite (the send fires only
//    on the DO's 200 commit), and a grant to a NON-custom-domain recipient sends nothing.
//
// The Access path is driven with a forged-but-correctly-signed RS256 JWT verified against a controlled
// JWKS served by a stubbed global fetch, so authorise() runs its REAL verification and resolves a REAL
// verified identity (the same technique as validate-rbac.ts), exercising the production code path.

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import type { CfEmailSend, Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { env: Pick<Env, "SCHEDULER">; storage: MockStorage } {
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
  return { env: { SCHEDULER: namespace }, storage };
}

// recordingEmail is the in-memory CfEmailSend double: it records every message send() is handed so a
// test can assert the exact invite payload, and performs no network I/O. It resolves to a message id
// (the real binding's shape), proving the route does not depend on the return value.
function recordingEmail(): { binding: CfEmailSend; sent: Parameters<CfEmailSend["send"]>[0][] } {
  const sent: Parameters<CfEmailSend["send"]>[0][] = [];
  return {
    binding: {
      async send(message: Parameters<CfEmailSend["send"]>[0]): Promise<{ messageId: string }> {
        sent.push(message);
        return { messageId: "stub-msg-1" };
      },
    },
    sent,
  };
}

// throwingEmail is a CfEmailSend double whose send() rejects, to prove the invite is fail-open and a
// throwing send never fails the grant.
function throwingEmail(): CfEmailSend {
  return {
    async send(): Promise<{ messageId: string }> {
      throw new Error("simulated edge restriction");
    },
  };
}

// ---- Forged Access JWT (real RS256 verification, controlled JWKS) ------------------------------
const TEAM = "maelstrom";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "invite-test-aud";
const KID = "invite-kid-1";
const CONSOLE_ORIGIN = "https://downpipe-console.example.com";

function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

const OWNER = "owner@acme.example";
const ALICE = "alice@acme.example";

// Harness exposes makeEnv (a fresh scheduler + a POST call helper per case) and bootstrap (seed the
// FIRST Access caller as Owner), so each case runs against an isolated role table.
interface Harness {
  realFetch: typeof fetch;
  makeEnv: (over: Partial<Env>) => { env: Env; call: (email: string, path: string, body?: unknown) => Promise<Response> };
  bootstrap: (env: Env) => Promise<void>;
}

// buildMakeEnv returns the makeEnv factory: each call gets a fresh scheduler + a POST `call` helper
// signed as the given email, so the first Access caller bootstraps Owner cleanly and role tables do
// not bleed between cases.
function buildMakeEnv(tokenFor: (email: string) => Promise<string>): Harness["makeEnv"] {
  return (over: Partial<Env>) => {
    const sched = makeScheduler();
    const env = {
      ...sched.env,
      CF_ACCESS_TEAM_DOMAIN: TEAM,
      CF_ACCESS_AUD: AUD,
      CONSOLE_ORIGIN,
      ...over,
    } as unknown as Env;
    async function call(email: string, path: string, body?: unknown): Promise<Response> {
      const assertion = await tokenFor(email);
      const init: RequestInit = {
        method: "POST",
        headers: { "cf-access-jwt-assertion": assertion, "content-type": "application/json" },
        body: JSON.stringify(body),
      };
      return handleAdmin(new Request(`https://engine.example${path}`, init), env);
    }
    return { env, call };
  };
}

// setup generates the Access signing key, serves its JWKS off a stubbed fetch, and returns the Harness.
async function setup(): Promise<Harness> {
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
  async function tokenFor(email: string): Promise<string> {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  }

  const makeEnv = buildMakeEnv(tokenFor);

  // The role table bootstraps the FIRST authenticated Access caller as Owner. The POST-only `call`
  // helper above cannot GET whoami, so bootstrap the Owner with a direct GET handleAdmin call before
  // each case's first grant; the subsequent grant is then an Owner-gated write.
  async function bootstrap(env: Env): Promise<void> {
    const assertion = await tokenFor(OWNER);
    await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET", headers: { "cf-access-jwt-assertion": assertion } }), env);
  }

  return { realFetch, makeEnv, bootstrap };
}

// ---- CASE 1: a successful built-in grant triggers ONE invite send with the right payload --------
async function caseSuccessfulBuiltinGrant({ makeEnv, bootstrap }: Harness): Promise<void> {
  {
    const { binding, sent } = recordingEmail();
    const { env, call } = makeEnv({ EMAIL: binding, INVITE_EMAIL_FROM: "invites@acme.example" });
    await bootstrap(env);
    const r = await call(OWNER, "/admin/roles", { email: ALICE, role: "operator" });
    const entry = (await r.json()) as { email: string; role: string };
    ok("grant: Owner grants operator -> 200", r.status === 200);
    ok("grant: the entry persisted the role", entry.role === "operator" && entry.email === ALICE);
    ok("invite: exactly one send fired on the successful grant", sent.length === 1);
    const m = (sent[0] ?? {}) as Record<string, unknown>;
    ok("invite: sender is the configured INVITE_EMAIL_FROM", m["from"] === "invites@acme.example");
    ok("invite: recipient is the granted person (single address)", m["to"] === ALICE);
    ok("invite: subject is present and non-empty", typeof m["subject"] === "string" && (m["subject"] as string).length > 0);
    const text = typeof m["text"] === "string" ? (m["text"] as string) : "";
    ok("invite: body names the granted role", text.includes("operator"));
    ok("invite: body carries the console sign-in link", text.includes(CONSOLE_ORIGIN));
    // REDACTION: only from/to/subject/text cross the boundary (no header/raw/secret field).
    const allowed = new Set(["from", "to", "subject", "text", "html"]);
    const extra = Object.keys(m).filter((k) => !allowed.has(k));
    ok("invite: message carries no extra fields (redaction-safe surface)", extra.length === 0);
  }
}

// ---- CASE 2: a CUSTOM-role grant names the custom-role NAME in the invite ----------------------
// A custom-role grant pins the stored built-in role to the viewer floor and carries the NAME; the
// invite must name the custom role (what the person actually holds), not "viewer".
async function caseCustomRoleGrant({ makeEnv, bootstrap }: Harness): Promise<void> {
  {
    const { binding, sent } = recordingEmail();
    const { env, call } = makeEnv({ EMAIL: binding, INVITE_EMAIL_FROM: "invites@acme.example" });
    await bootstrap(env);
    // Define a minimal custom role first (access.policy held by Owner). A custom role can never hold an
    // owner-reserved capability; "audit.read" is a safe capability the Owner holds (no escalation), and
    // "audit" is the landing screen that capability backs.
    const created = await call(OWNER, "/admin/custom-roles", { name: "auditor", label: "Auditor", capabilities: ["audit.read"], landing: "audit" });
    ok("custom-role: Owner can create a custom role (200)", created.status === 200);
    const beforeCount = sent.length;
    const r = await call(OWNER, "/admin/roles", { email: ALICE, customRole: "auditor" });
    ok("custom grant: 200", r.status === 200);
    ok("custom grant: exactly one invite fired", sent.length === beforeCount + 1);
    const m = (sent[sent.length - 1] ?? {}) as Record<string, unknown>;
    const text = typeof m["text"] === "string" ? (m["text"] as string) : "";
    ok("custom grant: invite names the custom-role NAME (not the viewer floor)", text.includes("auditor") && !text.includes("viewer"));
  }
}

// ---- CASE 3: OFF + SILENT when unconfigured ----------------------------------------------------
async function caseUnconfigured({ makeEnv, bootstrap }: Harness): Promise<void> {
  // 3a) No EMAIL binding at all -> no send, grant still 200.
  {
    const { env, call } = makeEnv({ INVITE_EMAIL_FROM: "invites@acme.example" }); // INVITE_EMAIL_FROM set but NO binding
    await bootstrap(env);
    const r = await call(OWNER, "/admin/roles", { email: ALICE, role: "operator" });
    ok("unconfigured: no EMAIL binding -> grant still 200", r.status === 200);
    // Nothing to record: there is no binding to observe, so we assert the grant succeeded and did not throw.
    const entry = (await r.json()) as { role?: string };
    ok("unconfigured: the grant persisted despite no email", entry.role === "operator");
  }
  // 3b) EMAIL bound but NO INVITE_EMAIL_FROM -> no send (the invite is a SEPARATE opt-in), grant 200.
  {
    const { binding, sent } = recordingEmail();
    const { env, call } = makeEnv({ EMAIL: binding }); // binding present, INVITE_EMAIL_FROM absent
    await bootstrap(env);
    const r = await call(OWNER, "/admin/roles", { email: ALICE, role: "operator" });
    ok("opt-in: binding present but no INVITE_EMAIL_FROM -> grant still 200", r.status === 200);
    ok("opt-in: no invite sent when INVITE_EMAIL_FROM is unset (separate from EMAIL_FROM)", sent.length === 0);
  }
}

// ---- CASE 4: a THROWING send does not fail the grant -------------------------------------------
async function caseThrowingSend({ makeEnv, bootstrap }: Harness): Promise<void> {
  {
    const { env, call } = makeEnv({ EMAIL: throwingEmail(), INVITE_EMAIL_FROM: "invites@acme.example" });
    await bootstrap(env);
    let threw = false;
    let r: Response | undefined;
    try {
      r = await call(OWNER, "/admin/roles", { email: ALICE, role: "operator" });
    } catch {
      threw = true;
    }
    ok("throwing send: the grant call did not throw", threw === false);
    ok("throwing send: the grant still returns 200", r !== undefined && r.status === 200);
    const entry = r ? ((await r.json()) as { role?: string }) : {};
    ok("throwing send: the role was persisted despite the failed send", entry.role === "operator");
  }
}

// ---- CASE 5: NEGATIVE CONTROLS -----------------------------------------------------------------
async function caseNegativeControls({ makeEnv, bootstrap }: Harness): Promise<void> {
  // 5a) A FAILED grant sends NO invite: the last-Owner guard refuses self-demotion of the sole Owner
  // with a 400, so the DO never committed and the invite (which fires only on the 200) must not fire.
  {
    const { binding, sent } = recordingEmail();
    const { env, call } = makeEnv({ EMAIL: binding, INVITE_EMAIL_FROM: "invites@acme.example" });
    await bootstrap(env); // OWNER is now the sole Owner
    const r = await call(OWNER, "/admin/roles", { email: OWNER, role: "viewer" });
    ok("negative: self-demotion of the only Owner is refused 400", r.status === 400);
    ok("negative: a FAILED grant fires NO invite (send only on the DO 200 commit)", sent.length === 0);
  }
  // 5b) A grant to a NON-custom-domain recipient sends nothing (the recipient fails the address gate).
  {
    const { binding, sent } = recordingEmail();
    const { env, call } = makeEnv({ EMAIL: binding, INVITE_EMAIL_FROM: "invites@acme.example" });
    await bootstrap(env);
    // A workers.dev recipient is a valid role-table email shape but not a custom-domain address; the
    // invite address gate is a no-op for it while the grant itself still commits.
    const r = await call(OWNER, "/admin/roles", { email: "bob@team.workers.dev", role: "operator" });
    ok("negative: a grant to a non-custom-domain recipient still commits (200)", r.status === 200);
    ok("negative: no invite is sent to a non-custom-domain recipient", sent.length === 0);
  }
  // 5c) A grant with the binding present + INVITE_EMAIL_FROM that is itself a workers.dev address sends
  // nothing (the sender fails the custom-domain gate), and the grant still commits.
  {
    const { binding, sent } = recordingEmail();
    const { env, call } = makeEnv({ EMAIL: binding, INVITE_EMAIL_FROM: "invites@x.workers.dev" });
    await bootstrap(env);
    const r = await call(OWNER, "/admin/roles", { email: ALICE, role: "operator" });
    ok("negative: an invalid INVITE_EMAIL_FROM (workers.dev) sends nothing, grant still 200", r.status === 200 && sent.length === 0);
  }
}

async function main(): Promise<void> {
  const harness = await setup();
  try {
    await caseSuccessfulBuiltinGrant(harness);
    await caseCustomRoleGrant(harness);
    await caseUnconfigured(harness);
    await caseThrowingSend(harness);
    await caseNegativeControls(harness);
  } finally {
    globalThis.fetch = harness.realFetch;
  }
  console.log(failures === 0 ? "\nROLE-INVITE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
