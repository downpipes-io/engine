// Prove two engine-router hardenings, end to end and SERVER-SIDE. No network, no deploy, no cost.
// Run:
//   node test/validate-restore-recompute.ts
//
// What this proves:
//
//  Server-side blast-radius recompute. POST /admin/restore/request previously forwarded the
//  client-supplied blast-radius cues (isLatest/plannedWrites/bytes) verbatim into the DO approval
//  record, so an Operator+ raising a request by direct API could seed the approver inbox with benign
//  cues that did not match the hash-bound plan. The router now RECOMPUTES the cues server-side by
//  running the SAME dry-run plan an apply for the plan hash would run (via runRestore), and stores the
//  recomputed values, IGNORING the attacker-supplied ones. We prove:
//   - a request that LIES about the cues (isLatest:false / plannedWrites:999 / bytes:123456 for a run
//     that is in fact the latest, 3 records, a known plaintext total) stores the SERVER-RECOMPUTED
//     truth (isLatest:true / plannedWrites:3 / bytes:the real total), not the attacker's values;
//   - the restore-request AUDIT event records the recomputed isLatest, not the claim;
//   - the stored plan hash is unchanged by the recompute (the binding still binds the real plan), and
//     a genuinely-distinct approver can still approve and the apply still applies (the recompute does
//     not perturb dual control);
//   - an honest request (no cues sent, or cues that already match) stores the recomputed values too,
//     so the inbox always shows the engine's truth regardless of what the client sent.
//
//  V16.3.1 (authentication logging). The auth boundary now logs authentication OUTCOMES through the
//  structured section 11 logger, so each line is a single JSON record whose "event" field carries the
//  coarse text. We prove:
//   - an authentication FAILURE (a 401: no Access configured + no/invalid bearer) emits a structured
//     error-level "authn failure" event carrying the attempted method and a reason, and NO token;
//   - the emailless-Access 401 path also logs a failure with method=access;
//   - a successful authentication emits a structured info-level "authn success" event carrying the
//     method and the verified role, and NO token/email;
//   - the 401 plaintext / 200 JSON response shapes are unchanged.
//
// The harness reuses the validate-dualcontrol idiom: a forged-but-correctly-signed RS256 Access JWT
// with a controlled JWKS + an in-memory SchedulerDO, so handleAdmin runs its REAL authorisation, role
// resolution and DO approval/audit state; plus an in-memory R2 archive + operational read-back key +
// mock KV, so a real dry-run plan and a real apply run through the production router -> DO -> runRestore
// path. This file is deliberately self-contained (no import from validate-dualcontrol.ts).

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { restorePlanHash, type RestoreApproval } from "../src/admin/approvals.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import type { Env } from "../src/env.d.ts";
import type { RestoreResult } from "../src/admin/restore-types.ts";
import { notePlanAnchorForRequest } from "./testutil.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// ---- console capture ---------------------------------------------------------------------
// captureConsole swaps console.log/console.error for collectors so the authn-logging proofs can
// assert exactly what was emitted, then restores them. The engine routes authn outcomes through the
// section 11 structured logger, which serialises each record to a single JSON line and writes it to
// console.log (info) or console.error (error), so a captured line is JSON with the coarse text in its
// "event" field. It returns the captured lines and a restore fn.
function captureConsole(): { logs: string[]; errors: string[]; restore: () => void } {
  const logs: string[] = [];
  const errors: string[] = [];
  const realLog = console.log;
  const realError = console.error;
  console.log = (...args: unknown[]) => {
    logs.push(args.map((a) => String(a)).join(" "));
  };
  console.error = (...args: unknown[]) => {
    errors.push(args.map((a) => String(a)).join(" "));
  };
  return {
    logs,
    errors,
    restore: () => {
      console.log = realLog;
      console.error = realError;
    },
  };
}

// authnEvent matches a structured-log line whose "event" field is the coarse authn outcome for the
// given outcome word ("success" or "failure"). The structured logger emits the text verbatim inside
// the JSON record as `"event":"authn <outcome> ..."`, so anchoring on that exact field prefix proves
// the captured line is the authn event itself (not an unrelated log line that merely mentions it).
function authnEvent(line: string, outcome: "success" | "failure"): boolean {
  return line.includes(`"event":"authn ${outcome} `);
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { env: Pick<Env, "SCHEDULER">; storage: MockStorage; stub: DurableObjectStub } {
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

// ---- In-memory archive doubles -----------------------------------------------------------
class MockKV {
  store = new Map<string, Uint8Array>();
  putCount = 0;
  async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> {
    this.putCount++;
    this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
  }
  async get(k: string): Promise<ArrayBuffer | null> {
    const v = this.store.get(k);
    return v ? toAB(v) : null;
  }
}
class MockR2 {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    if (!v) return null;
    return { arrayBuffer: async () => toAB(v), etag: `"${key.length}"` };
  }
  async head(key: string): Promise<{ etag: string } | null> {
    const v = this.store.get(key);
    return v ? { etag: `"${key.length}"` } : null;
  }
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> {
    this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body));
    return { etag: `"${key.length}"` };
  }
}
function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// ---- Forged Access JWT (real RS256 verification, controlled JWKS) ------------------------
const TEAM = "maelstrom";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "recompute-test-aud";
const KID = "recompute-kid-1";
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_throwaway";
const KVSET: Record<string, string> = { "a": "alpha-value", "b": "beta-value", "user:42": "gamma-value-longer" };

function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

const OWNER = "owner@acme.example";
const OPERATOR = "operator@acme.example";
const APPROVER = "approver@acme.example";

// Ctx carries the built archive bindings, the recomputed real plan totals, the restore KV, the
// stubbed-Access call helpers and the inbox/audit readers each proof function needs.
interface Ctx {
  r2: MockR2;
  restoreKV: MockKV;
  sched: ReturnType<typeof makeScheduler>;
  accessEnv: () => Env;
  emaillessToken: () => Promise<string>;
  call: (email: string, method: "GET" | "POST", path: string, body?: unknown) => Promise<Response>;
  readLog: (query?: string) => Promise<{ events: AuditEvent[] }>;
  inboxRecord: (planHash: string) => Promise<RestoreApproval | undefined>;
  planHash: string;
  realBytes: number;
  realWrites: number;
}

// setup builds the signed archive, serves the Access JWKS off a stubbed fetch, seeds the OWNER /
// OPERATOR / APPROVER roles and returns the shared Ctx. The caller restores globalThis.fetch.
interface ArchiveFixture {
  r2: MockR2;
  signerPrivateB64: string;
  operationalPrivateB64: string;
  realBytes: number;
  realWrites: number;
}

// buildSignedArchive seals the KVSET into a signed archive served from a MockR2, and returns the
// signer/operational identities plus the real plaintext totals an apply would write.
async function buildSignedArchive(): Promise<ArchiveFixture> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const archive = await buildArchive({
    downpipeId: "dp_restore",
    downpipeName: "restore",
    cadence: "3600s",
    runId: RUN_ID,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer,
    records: Object.entries(KVSET).map(([name, v]) => ({ sourceType: "kv" as const, name, value: utf8(v), namespace: NS })),
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  const r2 = new MockR2();
  for (const [k, b] of archive) r2.store.set(k, b);
  const operationalPrivateB64 = b64urlEncode(op.identity);
  // The real plaintext total an apply (or a dry-run) for the whole run would write/plan.
  const realBytes = Object.values(KVSET).reduce((n, v) => n + utf8(v).length, 0);
  const realWrites = Object.keys(KVSET).length;
  return { r2, signerPrivateB64, operationalPrivateB64, realBytes, realWrites };
}

interface AccessFixture {
  realFetch: typeof fetch;
  tokenFor: (email: string) => Promise<string>;
  emaillessToken: () => Promise<string>;
}

// installAccessJwks generates the Access signing key, serves its JWKS off a stubbed global fetch, and
// returns token builders (tokenFor with an email, emaillessToken without one) plus the saved fetch.
async function installAccessJwks(): Promise<AccessFixture> {
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
  async function signJwt(claims: Record<string, unknown>): Promise<string> {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, ...claims });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  }
  // Authorisation keys on the stable subject (iss+"|"+sub), so a usable token carries a sub (a stable
  // per-email value). The emailless token still carries a sub but no email (the emailless-Access 401 path).
  const tokenFor = (email: string): Promise<string> => signJwt({ email, sub: `sub-of-${email}` });
  const emaillessToken = (): Promise<string> => signJwt({ sub: "no-email-here" });
  return { realFetch, tokenFor, emaillessToken };
}

async function setup(): Promise<{ ctx: Ctx; realFetch: typeof fetch }> {
  const { r2, signerPrivateB64, operationalPrivateB64, realBytes: REAL_BYTES, realWrites: REAL_WRITES } = await buildSignedArchive();
  const restoreKV = new MockKV();
  const { realFetch, tokenFor, emaillessToken } = await installAccessJwks();

  const sched = makeScheduler();
  const accessEnv = (): Env =>
    ({
      ...sched.env,
      CF_ACCESS_TEAM_DOMAIN: TEAM,
      CF_ACCESS_AUD: AUD,
      DEST_KIND: "r2",
      DEST_R2: r2 as unknown as R2Bucket,
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: operationalPrivateB64,
      [`KV_${NS}`]: restoreKV as unknown as KVNamespace,
    }) as unknown as Env;

  // A REQUEST IS PRECEDED BY ITS DRY RUN'S PLAN ANCHOR. requestRestore refuses a plan hash with no recorded
  // preview, because the engine will not mint an approval against a plan it cannot date; the console reaches
  // the request route only from a dry run, so noting the anchor here makes these cases the sequence the
  // product permits. It binds the same fields restorePlanHash binds, so the request body computes the same
  // hash the dry run would have recorded.
  async function call(email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
    const assertion = await tokenFor(email);
    const init: RequestInit = {
      method,
      headers: { "cf-access-jwt-assertion": assertion, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    if (path === "/admin/restore/request" && body !== undefined) await notePlanAnchorForRequest(sched.stub.fetch, body);
    return handleAdmin(new Request(`https://engine.example${path}`, init), accessEnv());
  }
  async function readLog(query = ""): Promise<{ events: AuditEvent[] }> {
    const r = await call(OWNER, "GET", "/admin/audit?limit=500" + (query ? "&" + query : ""));
    return (await r.json()) as { events: AuditEvent[] };
  }
  async function inboxRecord(planHash: string): Promise<RestoreApproval | undefined> {
    const inbox = (await (await call(OWNER, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
    return inbox.find((r) => r.planHash === planHash);
  }

  // Bootstrap OWNER and seed the roles.
  await call(OWNER, "GET", "/admin/whoami");
  await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
  await call(OWNER, "POST", "/admin/roles", { email: APPROVER, role: "approver" });

  const planHash = await restorePlanHash({ runId: RUN_ID });
  const ctx: Ctx = { r2, restoreKV, sched, accessEnv, emaillessToken, call, readLog, inboxRecord, planHash, realBytes: REAL_BYTES, realWrites: REAL_WRITES };
  return { ctx, realFetch };
}

// =====================================================================================
// Server-side blast-radius recompute
// =====================================================================================

// ---- PROOF 1: a LYING request stores the SERVER-RECOMPUTED cues, not the attacker's ----
async function proofLyingRequest(ctx: Ctx): Promise<void> {
  const { call, inboxRecord, readLog, restoreKV, planHash, realBytes: REAL_BYTES, realWrites: REAL_WRITES } = ctx;
  {
    // The Operator raises a request that fabricates benign-looking cues for a run that is in fact the
    // latest, has 3 records, and a known plaintext total. A pre-fix engine would store the lie.
    const reqResp = await call(OPERATOR, "POST", "/admin/restore/request", {
      runId: RUN_ID,
      reason: "cues must be recomputed",
      isLatest: false, // LIE: the run IS the latest
      plannedWrites: 999, // LIE: only 3 records would be written
      bytes: 123456, // LIE: the real total is far smaller
    });
    const rec = (await reqResp.json()) as RestoreApproval;
    ok("the request is created (200, status requested)", reqResp.status === 200 && rec.status === "requested" && rec.planHash === planHash);
    // The stored record carries the ENGINE's recomputed cues, NOT the attacker's.
    ok("stored isLatest is the recomputed truth (true), not the claimed false", rec.isLatest === true);
    ok("stored plannedWrites is the recomputed count (3), not the claimed 999", rec.plannedWrites === REAL_WRITES);
    ok("stored bytes is the recomputed real total, not the claimed 123456", rec.bytes === REAL_BYTES && rec.bytes !== 123456);

    // Read it back through the inbox too (the surface the approver actually sees).
    const seen = await inboxRecord(planHash);
    ok("the approver inbox shows the recomputed cues", seen?.isLatest === true && seen?.plannedWrites === REAL_WRITES && seen?.bytes === REAL_BYTES);

    // The restore-request AUDIT event records the recomputed isLatest, not the claim.
    const reqEvt = (await readLog("action=restore-request")).events.find((e) => (e.target as { planHash?: string }).planHash === planHash);
    const t = reqEvt?.target as { isLatest?: boolean } | undefined;
    ok("the restore-request audit event records the recomputed isLatest (true)", t?.isLatest === true);

    // The plan hash is unchanged by the recompute: the binding still binds the real plan. Prove the
    // approval is genuinely usable by a distinct approver and the apply applies (recompute did not
    // perturb dual control).
    const approve = await call(APPROVER, "POST", "/admin/restore/approve", { planHash });
    ok("a distinct approver can approve the recomputed request (200)", approve.status === 200 && ((await approve.json()) as RestoreApproval).approvedBy === APPROVER);
    restoreKV.store.clear();
    // The applier must be Approver+ (the F1 role gate) and the usable approval (maker OPERATOR !=
    // checker APPROVER) binds this exact plan hash; OWNER applies (a distinct Approver+ identity). A
    // successful apply consumes the approval, which also tidies it for PROOF 2's fresh request.
    const apply = await call(OWNER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
    const res = (await apply.json()) as RestoreResult;
    ok("the apply for the hash-bound plan applies (ok:true), so the binding still binds the real plan", apply.status === 200 && res.ok === true && res.recordsRestored === REAL_WRITES);

    // THE APPLY DOES NOT CONSUME THE APPROVAL HERE, WHEN RESTORE DUAL CONTROL IS UNARMED.
    //
    // This estate has NOT armed the restore dual-control policy, so router-restore.ts:307 skips both the
    // reserve and the single-use consume, on the premise that "there is no approval record" when the policy
    // is unarmed. That premise does not hold: with the policy unarmed, POST /admin/restore/request still
    // returns 200 and POST /admin/restore/approve still returns 200, so a record exists for the consume to
    // skip. It is then never terminated, and the NEXT request for the same plan is refused 400 "an approval
    // already exists for this plan; consume or reject it before re-requesting". Consuming is exactly what
    // cannot happen while the policy is off, so reject is the operator's only way out of a state they can
    // reach without ever arming the gate.
    //
    // This is asserted explicitly below so that a later change to consume-on-apply, or to refuse the
    // request while the policy is unarmed, is caught rather than silently altering what the two proofs
    // below are standing on.
    const orphan = ((await (await call(OWNER, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[]).find((a) => a.planHash === planHash);
    ok("with the policy UNARMED a successful apply leaves the approval un-consumed, so the record survives", orphan !== undefined && orphan.status !== "consumed");
    const blocked = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "proving the survivor blocks a re-request" });
    ok("...and that survivor BLOCKS the next request for the same plan (400)", blocked.status === 400);
    // Rejecting is the way out, and it is the fixture's precondition for PROOF 2 rather than a silent tidy.
    await call(APPROVER, "POST", "/admin/restore/reject", { planHash });
  }
}

// ---- PROOF 2: an HONEST request (no cues sent) also stores the recomputed values -------
async function proofHonestRequest(ctx: Ctx): Promise<void> {
  const { call, planHash, realBytes: REAL_BYTES, realWrites: REAL_WRITES } = ctx;
  {
    // No cues on the body at all: the engine must still populate the inbox from its own dry-run, so
    // the inbox is never the pre-fix all-zero/false fabrication.
    const reqResp = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "no cues sent" });
    const rec = (await reqResp.json()) as RestoreApproval;
    ok("a request with NO cues is created", reqResp.status === 200 && rec.status === "requested");
    ok("the engine populated isLatest from its own plan (true)", rec.isLatest === true);
    ok("the engine populated plannedWrites from its own plan (3)", rec.plannedWrites === REAL_WRITES);
    ok("the engine populated bytes from its own plan (real total)", rec.bytes === REAL_BYTES);
    // Tidy up for later proofs.
    await call(APPROVER, "POST", "/admin/restore/reject", { planHash });
  }
}

// ---- PROOF 3: a subset selector recomputes a SMALLER blast radius ----------------------
async function proofSubsetSelector(ctx: Ctx): Promise<void> {
  const { call, planHash } = ctx;
  {
    // An include selector that matches exactly one record must recompute plannedWrites:1 and the
    // single record's bytes, regardless of what the client claims, and bind a DIFFERENT plan hash.
    const subsetHash = await restorePlanHash({ runId: RUN_ID, include: ["user:"] });
    const subsetBytes = utf8(KVSET["user:42"]!).length;
    const reqResp = await call(OPERATOR, "POST", "/admin/restore/request", {
      runId: RUN_ID,
      include: ["user:"],
      reason: "subset recompute",
      isLatest: true,
      plannedWrites: 3, // LIE: only 1 record matches the selector
      bytes: 999999,
    });
    const rec = (await reqResp.json()) as RestoreApproval;
    ok("the subset request binds a distinct plan hash", reqResp.status === 200 && rec.planHash === subsetHash && subsetHash !== planHash);
    ok("the subset recompute stores plannedWrites:1 (not the claimed 3)", rec.plannedWrites === 1);
    ok("the subset recompute stores the single record's bytes (not the claimed 999999)", rec.bytes === subsetBytes);
    await call(APPROVER, "POST", "/admin/restore/reject", { planHash: subsetHash });
  }
}

// =====================================================================================
// V16.3.1: authentication logging
// =====================================================================================

// ---- PROOF 4: a SUCCESSFUL authentication logs a coarse authn-success line -------------
async function proofAuthnSuccess(ctx: Ctx): Promise<void> {
  const { call } = ctx;
  {
    const cap = captureConsole();
    let resp: Response;
    try {
      resp = await call(OWNER, "GET", "/admin/whoami");
    } finally {
      cap.restore();
    }
    ok("the authenticated request still returns 200 (shape unchanged)", resp.status === 200);
    const successLines = cap.logs.filter((l) => authnEvent(l, "success"));
    ok("an authn-success line was logged", successLines.length >= 1);
    const line = successLines[0] ?? "";
    ok("the success line records method=access", /method=access/.test(line));
    ok("the success line records the verified role (owner)", /role=owner/.test(line));
    // No token and no email leak into the success line.
    ok("the success line carries NO email", !/@/.test(line));
    ok("the success line carries NO bearer/jwt material", !/Bearer|eyJ|assertion/i.test(line));
  }
}

// ---- PROOF 5: a FAILED authentication (401) logs a coarse authn-failure line -----------
async function proofAuthnFailureNoCred(ctx: Ctx): Promise<void> {
  const { r2 } = ctx;
  {
    // No Access configured AND no bearer -> authorise() returns ok:false -> 401. The attempted method
    // is the bare-token path (no cf-access-jwt-assertion header present).
    const noCredEnv = ({ DEST_KIND: "r2", DEST_R2: r2 as unknown as R2Bucket } as unknown as Env);
    const cap = captureConsole();
    let resp: Response;
    let bodyText: string;
    try {
      resp = await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET" }), noCredEnv);
      bodyText = await resp.text();
    } finally {
      cap.restore();
    }
    ok("an unauthenticated request is 401 (shape unchanged)", resp.status === 401);
    ok("the 401 body is still the plaintext 'unauthorised'", bodyText === "unauthorised");
    const failLines = cap.errors.filter((l) => authnEvent(l, "failure"));
    ok("an authn-failure line was logged on the 401", failLines.length >= 1);
    const line = failLines[0] ?? "";
    ok("the failure line records the attempted method (token, the bare-token path)", /method=token/.test(line));
    ok("the failure line carries a short reason", /reason=/.test(line));
    ok("the failure line carries NO token value", !/Bearer|eyJ|assertion/i.test(line));
  }
}

// ---- PROOF 6: a wrong bearer logs an authn-failure with method=token --------------------
async function proofWrongBearer(ctx: Ctx): Promise<void> {
  const { r2, sched } = ctx;
  {
    // ADMIN_TOKEN configured, but a WRONG bearer presented -> 401 on the token path.
    const tokenEnv = ({ ...sched.env, ADMIN_TOKEN: "the-real-token", DEST_KIND: "r2", DEST_R2: r2 as unknown as R2Bucket } as unknown as Env);
    const cap = captureConsole();
    let resp: Response;
    try {
      resp = await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET", headers: { authorization: "Bearer the-WRONG-token" } }), tokenEnv);
    } finally {
      cap.restore();
    }
    ok("a wrong-bearer request is 401", resp.status === 401);
    const failLines = cap.errors.filter((l) => authnEvent(l, "failure"));
    ok("the wrong-bearer 401 logs an authn-failure (method=token)", failLines.some((l) => /method=token/.test(l)));
    // The wrong token must never appear in the log line.
    ok("the failure line does NOT contain the presented token", !cap.errors.join(" ").includes("the-WRONG-token"));
  }
}

// ---- PROOF 7: the emailless-Access 401 path logs a failure with method=access ----------
async function proofEmaillessAccess(ctx: Ctx): Promise<void> {
  const { emaillessToken, accessEnv } = ctx;
  {
    // A validly-signed Access assertion that carries NO email is rejected at the emailless-Access boundary (401),
    // and must log an authn-failure with method=access (not token), since an Access assertion WAS
    // presented. This is the higher-severity path the audit flags (it must not silently 401).
    const assertion = await emaillessToken();
    const cap = captureConsole();
    let resp: Response;
    try {
      resp = await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET", headers: { "cf-access-jwt-assertion": assertion } }), accessEnv());
    } finally {
      cap.restore();
    }
    ok("an emailless Access assertion is rejected 401", resp.status === 401);
    const failLines = cap.errors.filter((l) => authnEvent(l, "failure"));
    ok("the emailless-Access 401 logs an authn-failure with method=access", failLines.some((l) => /method=access/.test(l)));
    ok("the emailless-Access failure carries NO assertion material", !/eyJ|assertion=/i.test(cap.errors.join(" ")));
  }
}

async function main(): Promise<void> {
  const { ctx, realFetch } = await setup();
  try {
    await proofLyingRequest(ctx);
    await proofHonestRequest(ctx);
    await proofSubsetSelector(ctx);
    await proofAuthnSuccess(ctx);
    await proofAuthnFailureNoCred(ctx);
    await proofWrongBearer(ctx);
    await proofEmaillessAccess(ctx);
  } finally {
    globalThis.fetch = realFetch;
  }
  console.log(failures === 0 ? "\nRESTORE-RECOMPUTE + AUTHN-LOGGING VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
