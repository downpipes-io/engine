// Prove dual-control approvals for a restore APPLY, end to end and SERVER-SIDE. No network,
// no deploy, no cost. Run:
//   node test/validate-dualcontrol.ts
//
// What this proves:
//  - a restore APPLY (confirm:true) is refused server-side unless a dual-control approval bound to
//    the EXACT plan exists (403 "restore not approved"), so the role gate (F1) is not the only gate;
//  - a REQUEST needs a DISTINCT approver: a second authorised identity (Approver/Owner) approves;
//  - MAKER != CHECKER is enforced server-side: the requester cannot approve their OWN request even
//    holding Approver/Owner (400 "cannot approve your own request"), at the router AND in the DO
//    (defence in depth, calling the DO directly with the requester as the caller);
//  - CASE-VARIANCE cannot defeat maker != checker: a request raised by "Alice@Example.com" cannot
//    be approved by "alice@example.com" (the same identity in a different case), because the caller
//    email is canonicalised ONCE at the trust boundary so the maker and the would-be checker are
//    recognised as one identity (a self-approval, refused 400), not two;
//  - an APPROVED request APPLIES: the real runRestore writes the records back (bytes match), and the
//    approval is CONSUMED (single use) so a second apply is refused;
//  - BOTH identities are audited: the restore-apply success event records the maker (actor) and the
//    checker (target.approverEmail), and they are distinct;
//  - re-arm-on-change: a re-plan that changes a decision field yields a different plan hash with no
//    matching approval, so the apply is refused (the server-side teeth behind the visible UX);
//  - a stale (expired) approval does not authorise an apply;
//  - reject closes a request; the role gates (Operator+ to request, Approver+ to approve) hold; the
//    bare-token fallback cannot be a maker or a checker (dual control needs attributable identities);
//  - the audit chain still VERIFIES over all the recorded request/approve/apply events.
//
// The harness combines the two existing idioms: (1) the forged-but-correctly-signed RS256 Access
// JWT + in-memory SchedulerDO from validate-rbac.ts / validate-audit.ts, so handleAdmin runs its
// REAL authorisation, role resolution, and the DO approval/audit state; and (2) the in-memory R2
// archive + operational read-back key + mock KV from validate-restore.ts, so a confirmed apply
// drives the REAL runRestore and returns ok:true (proving "an approved request applies", not a
// shim). This exercises the production router -> DO -> runRestore path end to end.

import { ORG_POLICY_KEY } from "../src/sched/scheduler-do-records.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { RATE_LIMIT_MAX_PER_WINDOW } from "../src/sched/scheduler-do-limits.ts";
import { encodeCaller, type Caller, rolePendingKey } from "../src/admin/identity.ts";
import { rateLimitKey } from "../src/admin/router-core.ts";
import { restorePlanHash, type RestoreApproval } from "../src/admin/approvals.ts";
import { verifyChain, type AuditEvent } from "../src/admin/audit.ts";
import { GOVERNANCE_REFUSALS_KEY } from "../src/sched/sched-fault-ledger.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import type { Env } from "../src/env.d.ts";
import type { RestoreResult } from "../src/admin/restore-types.ts";
import { notePlanAnchor, notePlanAnchorForRequest } from "./testutil.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
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

// ---- In-memory archive doubles (from validate-restore.ts) --------------------------------
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
const AUD = "dualcontrol-test-aud";
const KID = "dualcontrol-kid-1";
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_throwaway";
const KVSET: Record<string, string> = { "a": "alpha-value", "b": "beta-value", "user:42": "gamma-value-longer" };

function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

async function main(): Promise<void> {
  // --- the archive + keys, so a confirmed apply REALLY applies (ok:true) ---
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  mldsaKeygen(mldsaSeed);
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
  const restoreKV = new MockKV();

  // --- the Access JWKS, served by a stubbed global fetch ---
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pubJwk.n, e: pubJwk.e }] };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${ISS}/cdn-cgi/access/certs`) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    throw new Error(`unexpected network fetch in test: ${url}`);
  }) as typeof fetch;

  // The stubbed globalThis.fetch is restored in the finally below so an uncaught throw in any proof
  // cannot leave the stub installed for code that runs after (e.g. a multi-file test runner).
  try {
  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  // The role table + the maker != checker comparison now key on the STABLE subject (iss+"|"+sub). tokenFor
  // defaults the sub to a stable per-email value so each distinct email is a distinct subject (the normal
  // case); tokenForSub forges an arbitrary (email, sub) pair for the recycled-email closure proof.
  async function tokenForSub(email: string, sub: string): Promise<string> {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  }
  async function tokenFor(email: string): Promise<string> {
    return tokenForSub(email, `sub-of-${email}`);
  }
  // tokenForGroups mints the same signed Access assertion WITH a verified groups claim, so PROOF 21 can drive a
  // caller whose authority comes ONLY from a group -> role mapping and no role-table row at all. The claim is
  // read from the RS256-verified payload exactly as production reads it (access.ts), so these are genuinely
  // verified groups, not an asserted role.
  async function tokenForGroups(email: string, groups: string[]): Promise<string> {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}`, groups });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  }
  const subjectOf = (email: string): string => `${ISS}|sub-of-${email}`;

  // The restore-approval gate is OWNER-OPT-IN and OFF by default (an unconditional gate locked one-identity
  // estates out of restore entirely). This file exercises the gate, so it arms the policy explicitly.
  const sched = makeScheduler();
  await sched.storage.put(ORG_POLICY_KEY, { requireConfigApproval: false, requireRestoreApproval: true });
  // accessEnv wires Access AND the live restore destination, so handleAdmin authorises for real and
  // a confirmed apply reaches a real runRestore that applies.
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
  // preview, because the engine will not mint an approval against a plan it cannot date, and every operator
  // path reaches the request route through a dry run. Noting it here keeps each case below a sequence the
  // product permits; the anchor is put-if-absent, so a case that has already run its own preview is
  // unaffected, and a case that has just rejected or consumed (which drops the anchor) gets a fresh one,
  // which is the re-plan the operator would have had to run.
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
  async function readLog(query = ""): Promise<{ events: AuditEvent[]; headSeq: number; headHash: string }> {
    const r = await call(OWNER, "GET", "/admin/audit?limit=500" + (query ? "&" + query : ""));
    return (await r.json()) as { events: AuditEvent[]; headSeq: number; headHash: string };
  }

  const OWNER = "owner@acme.example";
  const OPERATOR = "operator@acme.example";
  const VIEWER = "viewer@acme.example";
  // Typed as string (not the string LITERAL) so the maker != checker assertions below stay genuine runtime
  // comparisons: with literal types, `a === APPROVER && a !== b` narrows the operands to distinct literals
  // and TypeScript flags the final !== as statically-known (TS2367).
  const APPROVER: string = "approver@acme.example";
  const APPROVER2: string = "approver2@acme.example";

  // Bootstrap OWNER (first Access caller -> Owner) and seed the role table.
  await call(OWNER, "GET", "/admin/whoami");
  await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
  await call(OWNER, "POST", "/admin/roles", { email: VIEWER, role: "viewer" });
  await call(OWNER, "POST", "/admin/roles", { email: APPROVER, role: "approver" });
  await call(OWNER, "POST", "/admin/roles", { email: APPROVER2, role: "approver" });

  // The plan hash the apply binds to (computed exactly as the engine does, from the request alone).
  const baseReq = { runId: RUN_ID };
  const planHash = await restorePlanHash(baseReq);

  // ---- PROOF 1: an apply with NO approval is refused server-side (the gate is real) -------
  {
    // An Approver holds the role (F1 passes), but no dual-control approval exists, so the apply is
    // refused 403 "restore not approved" and writes NOTHING.
    const r = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
    const b = (await r.json()) as { error: string; planHash: string };
    ok("apply with no approval refused 403", r.status === 403);
    ok("refusal is the dual-control gate, naming the plan hash", b.error === "restore not approved" && b.planHash === planHash);
    ok("the refused apply wrote nothing", restoreKV.store.size === 0);
    // It is recorded as a DENIED apply (a reviewer cares about a blocked production write).
    const log = await readLog("action=restore-apply&outcome=denied");
    ok("the unapproved apply is audited as denied", log.events.some((e) => e.actorEmail === APPROVER && (e.target as { planHash?: string }).planHash === planHash));
  }

  // ---- PROOF 2: the role gate on the request route (Operator+) ----------------------------
  {
    const r = await call(VIEWER, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "viewer should not get here" });
    const b = (await r.json()) as { error: string; required: string; have: string };
    ok("viewer cannot raise a restore request (403)", r.status === 403);
    // The request gate is the restore.request capability now (contract section 8); a viewer lacks it,
    // so the same denial holds with required = the capability rather than the "operator" role string.
    ok("request 403 names restore.request as required", b.error === "forbidden" && b.required === "restore.request" && b.have === "viewer");
  }

  // ---- PROOF 3: a request needs a reason --------------------------------------------------
  {
    const r = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID });
    ok("a request with no reason is refused 400", r.status === 400);
    const r2 = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "   " });
    ok("a request with a blank reason is refused 400", r2.status === 400);
  }

  // ---- PROOF 4: maker raises a request; MAKER CANNOT APPROVE THEIR OWN (maker != checker) -
  // The APPROVER raises the request (they hold Approver, so they COULD approve in a broken design).
  {
    const reqResp = await call(APPROVER, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "quarterly DR rehearsal", isLatest: true, plannedWrites: 3, bytes: 42 });
    const rec = (await reqResp.json()) as RestoreApproval;
    ok("the request is created (status requested)", reqResp.status === 200 && rec.status === "requested" && rec.planHash === planHash);
    ok("the request records the maker (requestedBy)", rec.requestedBy === APPROVER);
    ok("the request stores the blast-radius cues (not hashed)", rec.isLatest === true && rec.plannedWrites === 3);
    ok("the request stores the free-text reason", rec.reason === "quarterly DR rehearsal");

    // The MAKER tries to approve their OWN request -> refused 400 "cannot approve your own request".
    const self = await call(APPROVER, "POST", "/admin/restore/approve", { planHash });
    const sb = (await self.json()) as { error: string };
    ok("maker cannot approve their own request (400)", self.status === 400);
    ok("the refusal reason is maker != checker", /cannot approve your own request/.test(sb.error));

    // And an apply still fails (the request is not approved), proving the self-approve did nothing.
    const apply = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
    ok("apply is still refused after a self-approve attempt", apply.status === 403);
    ok("still nothing written", restoreKV.store.size === 0);
  }

  // ---- PROOF 5: a DISTINCT approver approves; the APPLY then succeeds (bytes match) -------
  {
    const approve = await call(APPROVER2, "POST", "/admin/restore/approve", { planHash });
    const ar = (await approve.json()) as RestoreApproval;
    ok("a distinct approver approves (200, status approved)", approve.status === 200 && ar.status === "approved");
    ok("the checker is recorded (approvedBy)", ar.approvedBy === APPROVER2);
    ok("maker != checker on the record (email display)", ar.requestedBy === APPROVER && ar.approvedBy === APPROVER2 && ar.requestedBy !== ar.approvedBy);
    // The record carries BOTH SUBJECTS (the authority axis) AND both emails (display), per the contract.
    ok("the record carries both SUBJECTS, maker != checker by subject", ar.requesterSubject === subjectOf(APPROVER) && ar.approverSubject === subjectOf(APPROVER2) && ar.requesterSubject !== ar.approverSubject);

    // The maker (APPROVER) now applies. The dual-control gate passes (a usable approval bound to the
    // plan, approver != requester), so the REAL runRestore applies and writes the records back.
    const apply = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
    const res = (await apply.json()) as RestoreResult;
    ok("an approved apply is NOT gated (200)", apply.status === 200);
    ok("the approved apply actually applied (ok:true, mode applied)", res.ok === true && res.mode === "applied");
    ok("all three records were restored", res.recordsRestored === 3 && res.recordsVerified === 3);
    const expectBytes = Object.values(KVSET).reduce((n, v) => n + utf8(v).length, 0);
    ok("bytesRestored equals the sealed plaintext total", res.bytesRestored === expectBytes);
    let bytesMatch = true;
    for (const [name, v] of Object.entries(KVSET)) {
      const got = restoreKV.store.get(name);
      if (!got || new TextDecoder().decode(got) !== v) bytesMatch = false;
    }
    ok("every restored value byte-matches the original (round-trip through dual control)", bytesMatch && restoreKV.store.size === 3);
  }

  // ---- PROOF 6: BOTH identities are audited on the apply ----------------------------------
  {
    const log = await readLog("action=restore-apply&outcome=success");
    const apply = log.events.find((e) => (e.target as { planHash?: string }).planHash === planHash);
    ok("a successful restore-apply event was recorded", apply !== undefined);
    ok("the apply records the MAKER as the actor (email display)", apply?.actorEmail === APPROVER);
    ok("the apply records the MAKER SUBJECT as actorSubject (the authority axis)", apply?.actorSubject === subjectOf(APPROVER));
    const t = apply?.target as { kind: "restore"; approverEmail?: string; approverSubject?: string; reason?: string; planHash: string };
    ok("the apply records the CHECKER email (target.approverEmail)", t?.approverEmail === APPROVER2);
    ok("the apply records the CHECKER SUBJECT (target.approverSubject)", t?.approverSubject === subjectOf(APPROVER2));
    ok("maker and checker are distinct in the audited apply (email)", apply?.actorEmail !== t?.approverEmail);
    ok("maker and checker SUBJECTS are distinct in the audited apply", apply?.actorSubject !== t?.approverSubject);
    ok("the apply carries the redaction-safe plan hash", typeof t?.planHash === "string" && t.planHash.startsWith("sha384:"));
    ok("the apply carries the free-text reason (not a secret)", t?.reason === "quarterly DR rehearsal");
    // The paired request + approve events were recorded too, each attributing the right identity on BOTH
    // axes (subject = authority, email = display).
    const reqEvt = (await readLog("action=restore-request")).events.find((e) => (e.target as { planHash?: string }).planHash === planHash);
    const appEvt = (await readLog("action=restore-approve")).events.find((e) => (e.target as { planHash?: string }).planHash === planHash);
    ok("a restore-request event attributes the maker (email + subject)", reqEvt?.actorEmail === APPROVER && reqEvt?.actorSubject === subjectOf(APPROVER));
    ok("a restore-approve event attributes the checker (email + subject)", appEvt?.actorEmail === APPROVER2 && appEvt?.actorSubject === subjectOf(APPROVER2));
  }

  // ---- PROOF 7: the approval is CONSUMED (single use): a second apply is refused ----------
  {
    // The successful apply above consumed the approval. A second confirm apply for the same plan,
    // with no fresh request + approval, is refused 403 (the approval can authorise exactly one apply).
    restoreKV.store.clear();
    restoreKV.putCount = 0;
    const again = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
    const b = (await again.json()) as { error: string };
    ok("a second apply on a consumed approval is refused 403", again.status === 403);
    ok("the refusal is the dual-control gate", b.error === "restore not approved");
    ok("the second apply wrote nothing", restoreKV.store.size === 0);
    // The stored record reads consumed.
    const inbox = (await (await call(OWNER, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
    const rec = inbox.find((r) => r.planHash === planHash);
    ok("the approval record is now consumed", rec?.status === "consumed");
  }

  // ---- PROOF 8: re-arm-on-change (a changed plan voids the approval) ----------------------
  {
    // Raise + approve a request for the BASE plan (original bindings) afresh.
    await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "re-arm test" });
    await call(APPROVER, "POST", "/admin/restore/approve", { planHash });
    // Now apply with a DIFFERENT decision field (a redirect target binding): a different plan hash
    // with NO matching approval -> refused, even though an approval exists for the base plan.
    const redirected = await call(APPROVER2, "POST", "/admin/restore", { runId: RUN_ID, target: { binding: "KV_somewhere_else" }, confirm: true });
    const rb = (await redirected.json()) as { error: string; planHash: string };
    ok("an apply for a CHANGED plan is refused (re-arm-on-change)", redirected.status === 403 && rb.error === "restore not approved");
    const changedHash = await restorePlanHash({ runId: RUN_ID, target: { binding: "KV_somewhere_else" } });
    ok("the refused apply names the CHANGED plan hash (distinct from the approved one)", rb.planHash === changedHash && changedHash !== planHash);
    // The base-plan approval is untouched; applying the base plan still works (consuming it).
    restoreKV.store.clear();
    const baseApply = await call(OPERATOR, "POST", "/admin/restore", { runId: RUN_ID, confirm: false }); // dry-run any role, sanity
    ok("a dry-run is still open to any role (sanity)", baseApply.status === 200);
    const realApply = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
    ok("the base-plan approval still authorises its own apply", realApply.status === 200 && ((await realApply.json()) as RestoreResult).ok === true);
  }

  // ---- PROOF 9: a stale (expired) approval does not authorise an apply --------------------
  {
    // Raise + approve, then AGE the record past its TTL by rewriting expiresAt to the past (the DO
    // computes expiry lazily from expiresAt, so this is the clock advancing). The apply must refuse.
    await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "expiry test" });
    await call(APPROVER, "POST", "/admin/restore/approve", { planHash });
    const key = "approval:" + planHash;
    const rec = sched.storage.rawGet<RestoreApproval>(key)!;
    rec.expiresAt = new Date(Date.now() - 1000).toISOString();
    sched.storage.rawPut(key, rec);
    restoreKV.store.clear();
    const apply = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
    ok("an expired approval does not authorise an apply (403)", apply.status === 403);
    ok("the expired-approval apply wrote nothing", restoreKV.store.size === 0);
    // The inbox reports it as expired (lazy, no storage mutation needed on read).
    const inbox = (await (await call(OWNER, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
    ok("the inbox reports the lapsed record as expired", inbox.find((r) => r.planHash === planHash)?.status === "expired");
    // Approving an expired request is refused too.
    const reApprove = await call(APPROVER2, "POST", "/admin/restore/approve", { planHash });
    ok("approving an expired request is refused (400)", reApprove.status === 400);
  }

  // ---- PROOF 10: reject closes a request -------------------------------------------------
  {
    // Re-request (the prior record for this plan is expired, so a fresh request replaces it), then
    // reject it; an apply must then refuse and the record reads rejected.
    await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "reject test" });
    const reject = await call(APPROVER, "POST", "/admin/restore/reject", { planHash });
    ok("an approver can reject a request (200)", reject.status === 200 && ((await reject.json()) as RestoreApproval).status === "rejected");
    // A rejected request cannot be approved.
    const approveRejected = await call(APPROVER2, "POST", "/admin/restore/approve", { planHash });
    ok("approving a rejected request is refused (400)", approveRejected.status === 400);
    restoreKV.store.clear();
    const apply = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
    ok("an apply after a reject is refused (403)", apply.status === 403);
    ok("a viewer/operator cannot reject (403)", (await call(VIEWER, "POST", "/admin/restore/reject", { planHash })).status === 403);
  }

  // ---- PROOF 11: the role gate on approve (Approver+) -------------------------------------
  {
    // Re-request so there is an open record, then an Operator tries to approve -> 403 (not the role).
    await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "approve-gate test" });
    const r = await call(OPERATOR, "POST", "/admin/restore/approve", { planHash });
    const b = (await r.json()) as { error: string; required: string; have: string };
    ok("an operator cannot approve (403)", r.status === 403);
    // The approve gate is the restore.approve capability now (contract section 8); an operator lacks it,
    // so the same denial holds with required = the capability rather than the "approver" role string.
    ok("approve 403 names restore.approve as required", b.error === "forbidden" && b.required === "restore.approve" && b.have === "operator");
    // Clean up: reject the open request so later proofs start clean.
    await call(APPROVER, "POST", "/admin/restore/reject", { planHash });
  }

  // ---- PROOF 12: the pending inbox visibility rule ---------------------------------------
  {
    // A throwaway run so this request is independent of the base-plan record above.
    const RUN2 = "01BX5ZZKBKACTAV9WEVGEMMVRY";
    const plan2 = await restorePlanHash({ runId: RUN2 });
    await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN2, reason: "inbox visibility" });
    // The OPERATOR (the requester, not an Approver) sees THEIR OWN request.
    const opInbox = (await (await call(OPERATOR, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
    ok("the requesting Operator sees their own request", opInbox.some((r) => r.planHash === plan2 && r.requestedBy === OPERATOR));
    // The VIEWER (neither Approver nor the requester) does NOT see it.
    const viewerInbox = (await (await call(VIEWER, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
    ok("a non-approver non-requester does not see the request", !viewerInbox.some((r) => r.planHash === plan2));
    // An APPROVER sees the whole inbox including this one.
    const approverInbox = (await (await call(APPROVER, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
    ok("an Approver sees the request in the inbox", approverInbox.some((r) => r.planHash === plan2));
  }

  // ---- PROOF 13: DO-side maker != checker (defence in depth) ------------------------------
  {
    // Drive the DO DIRECTLY (bypassing the router gate) with the REQUESTER as the caller header,
    // approving their own request: the DO must refuse it itself, proving the maker != checker rule
    // lives in the DO, not only at the router. Use the base-plan request raised below first.
    const RUN3 = "01CX5ZZKBKACTAV9WEVGEMMVRZ";
    const plan3 = await restorePlanHash({ runId: RUN3 });
    const maker: Caller = { method: "access", email: "do-maker@acme.example", subject: subjectOf("do-maker@acme.example"), role: "approver", groups: [] };
    // Raise the request through the DO directly as the maker.
    // The dry run this request is raised against: requestRestore refuses an unanchored plan hash.
    await notePlanAnchor(sched.stub.fetch, plan3);
    await sched.stub.fetch("https://scheduler.internal/restore/request", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(maker) },
      body: JSON.stringify({ planHash: plan3, runId: RUN3, isLatest: false, reason: "do defence-in-depth" }),
    });
    // The maker approves their OWN request at the DO -> refused 400.
    const selfAtDO = await sched.stub.fetch("https://scheduler.internal/restore/approve", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(maker) },
      body: JSON.stringify({ planHash: plan3 }),
    });
    const sb = (await selfAtDO.json()) as { error?: string };
    ok("the DO refuses a self-approval (defence in depth)", selfAtDO.status === 400 && /cannot approve your own request/.test(sb.error ?? ""));
    // A DO approve with NO caller header is refused (fails closed: no attributable checker).
    const noCaller = await sched.stub.fetch("https://scheduler.internal/restore/approve", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ planHash: plan3 }),
    });
    ok("the DO refuses an approve with no caller header (fail closed)", noCaller.status === 403);
    // A DISTINCT approver at the DO succeeds (the rule is maker != checker, not "no one can approve").
    const checker: Caller = { method: "access", email: "do-checker@acme.example", subject: subjectOf("do-checker@acme.example"), role: "approver", groups: [] };
    const okAtDO = await sched.stub.fetch("https://scheduler.internal/restore/approve", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(checker) },
      body: JSON.stringify({ planHash: plan3 }),
    });
    ok("the DO allows a DISTINCT approver", okAtDO.status === 200 && ((await okAtDO.json()) as RestoreApproval).approvedBy === "do-checker@acme.example");
  }

  // ---- PROOF 14: the bare-token fallback cannot be a maker or a checker -------------------
  {
    // With Access NOT configured and only ADMIN_TOKEN set, the caller resolves to the all-or-nothing
    // owner break-glass with NO email. Dual control needs two ATTRIBUTABLE identities, so a request
    // (maker) and an approve (checker) from the bare token are both refused 400. (A fresh DO so the
    // token caller bootstraps cleanly; the token path needs no Access env.)
    // The restore-approval gate is OWNER-OPT-IN and OFF by default (an unconditional gate locked one-identity
    // estates out of restore entirely). This file exercises the gate, so it arms the policy explicitly.
    const tsched = makeScheduler();
    await tsched.storage.put(ORG_POLICY_KEY, { requireConfigApproval: false, requireRestoreApproval: true });
    const tokenEnv = ({ ...tsched.env, ADMIN_TOKEN: "shared-break-glass-token", DEST_KIND: "r2", DEST_R2: r2 as unknown as R2Bucket, SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: operationalPrivateB64, [`KV_${NS}`]: restoreKV as unknown as KVNamespace }) as unknown as Env;
    async function tcall(method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
      const init: RequestInit = { method, headers: { authorization: "Bearer shared-break-glass-token", ...(body !== undefined ? { "content-type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
      // The dry run this request is raised against, so the refusal below is the attributable-identity rule
      // and not the unanchored-plan refusal that would otherwise fire first.
      if (path === "/admin/restore/request" && body !== undefined) await notePlanAnchorForRequest(tsched.stub.fetch, body);
      return handleAdmin(new Request(`https://engine.example${path}`, init), tokenEnv);
    }
    const reqResp = await tcall("POST", "/admin/restore/request", { runId: RUN_ID, reason: "token cannot be a maker" });
    ok("the bare-token fallback cannot raise a request (400, needs an attributable maker)", reqResp.status === 400);
    // It is owner, so the role gate passes; the refusal is the attributable-identity rule, not 403.
    ok("the token request refusal is not a role 403", reqResp.status !== 403);
  }

  // ---- PROOF 15: case-variance cannot defeat maker != checker ----------------------------
  {
    // Maker != checker now keys on the STABLE subject (iss+"|"+sub). The same Access user always carries
    // the SAME sub regardless of how their email is rendered, so signing in as "Alice@Example.com" then
    // "alice@example.com" is ONE subject and the self-approval is refused. (This subsumes the older
    // email-canonicalisation gap: even if the email case slipped through, the subject is identical.) Model
    // it faithfully: both casings carry the SAME sub (a real IdP would), so the subjects match.
    const ALICE_MIXED = "Alice@Example.com";
    const ALICE_LOWER = "alice@example.com";
    const ALICE_SUB = "sub-alice-stable"; // ONE Access user, two email renderings
    const callSub = async (email: string, sub: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
      const init: RequestInit = {
        method,
        headers: { "cf-access-jwt-assertion": await tokenForSub(email, sub), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      // The dry run this request is raised against (see call(): requestRestore refuses an unanchored plan).
      if (path === "/admin/restore/request" && body !== undefined) await notePlanAnchorForRequest(sched.stub.fetch, body);
      return handleAdmin(new Request(`https://engine.example${path}`, init), accessEnv());
    };
    // Grant Alice the Approver role by email (a pending invite, keyed by the lowercased email), so the role
    // gate passes once she authenticates and binds; the ONLY thing that can refuse the approval is maker !=
    // checker.
    await call(OWNER, "POST", "/admin/roles", { email: ALICE_MIXED, role: "approver" });

    // Use the run that has a real in-memory archive (RUN_ID) so the genuine, distinctly-approved apply at
    // the end actually applies (ok:true). The base-plan record for RUN_ID is in a terminal state from the
    // earlier proofs, so a fresh request from Alice replaces it. planHash is the base-plan hash above.
    // Best-effort: ensure no stale approved record lingers for the base plan. The test flow below
    // surfaces any inconsistency, so the reject response is intentionally not asserted here.
    await call(APPROVER, "POST", "/admin/restore/reject", { planHash });

    // Alice raises the request signed in as the MIXED-CASE identity (binding the invite to her subject).
    const reqResp = await callSub(ALICE_MIXED, ALICE_SUB, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "case-variance maker != checker" });
    const rec = (await reqResp.json()) as RestoreApproval;
    ok("the mixed-case request is created", reqResp.status === 200 && rec.status === "requested" && rec.planHash === planHash);
    // The maker SUBJECT is the stable principal; the recorded email is the canonical (lowercased) display.
    ok("the request records the maker subject (iss|sub), stable across email case", rec.requesterSubject === `${ISS}|${ALICE_SUB}`);
    ok("the request records the maker email as the canonical (lowercased) display identity", rec.requestedBy === ALICE_LOWER);

    // Alice now tries to approve the SAME request signed in as the LOWERCASE identity but the SAME sub.
    // Same subject -> refused as a self-approval (400), not allowed as a distinct checker.
    const selfLower = await callSub(ALICE_LOWER, ALICE_SUB, "POST", "/admin/restore/approve", { planHash });
    const sb = (await selfLower.json()) as { error: string };
    ok("a different-case approval by the same subject is refused (400)", selfLower.status === 400);
    ok("the refusal is the maker != checker rule (recognised as a self-approval by subject)", /cannot approve your own request/.test(sb.error));

    // And an apply is still refused (the request was never genuinely approved), nothing written.
    restoreKV.store.clear();
    const apply = await callSub(ALICE_MIXED, ALICE_SUB, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
    ok("the apply is still refused after the case-variant self-approval attempt (403)", apply.status === 403);
    ok("the case-variance attempt wrote nothing", restoreKV.store.size === 0);

    // A genuinely DISTINCT approver still works (the rule is maker != checker, not "Alice can never be
    // approved"): APPROVER2 approves Alice's request and the apply then succeeds for real.
    const approve = await call(APPROVER2, "POST", "/admin/restore/approve", { planHash });
    ok("a genuinely distinct approver can still approve the mixed-case request", approve.status === 200 && ((await approve.json()) as RestoreApproval).approvedBy === APPROVER2);
    restoreKV.store.clear();
    const realApply = await callSub(ALICE_LOWER, ALICE_SUB, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
    ok("the distinctly-approved apply succeeds regardless of the applier's email case", realApply.status === 200 && ((await realApply.json()) as RestoreResult).ok === true);
    // Clean up Alice's grant so the role table is tidy for any later assertions.
    await call(OWNER, "POST", "/admin/roles/delete", { email: ALICE_LOWER });
  }

  // ---- PROOF 15b (V10.3.3 / V10.5.2 in dual control): a recycled email with a DIFFERENT subject
  //                inherits NEITHER the maker's identity NOR the maker's role --------------------------
  // The dual-control face of the closure. The departed maker (SUB_MAKER) held approver and raised a
  // request. A NEW Access user reuses the SAME email (a DIFFERENT sub). Two facts hold, both keyed on the
  // immutable subject: (1) the recycled caller does NOT inherit the approver role (its subject has no
  // grant -> viewer), so it is refused at the role gate; (2) the genuine maker still cannot self-approve
  // (subject self-match). Conversely the OLD email-keyed code would have let the recycled email act as the
  // approver-roled prior holder. A separately, EXPLICITLY granted distinct approver then approves for real.
  {
    const SHARED = "rotated-role@acme.example";
    const SUB_MAKER = "sub-maker-dave";
    const SUB_RECYCLED = "sub-recycled-erin";
    const callSub = async (email: string, sub: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
      const init: RequestInit = {
        method,
        headers: { "cf-access-jwt-assertion": await tokenForSub(email, sub), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      // The dry run this request is raised against (see call(): requestRestore refuses an unanchored plan).
      if (path === "/admin/restore/request" && body !== undefined) await notePlanAnchorForRequest(sched.stub.fetch, body);
      return handleAdmin(new Request(`https://engine.example${path}`, init), accessEnv());
    };
    // Grant the shared email approver; the departed maker (SUB_MAKER) authenticates + binds, then raises a
    // request. Use a throwaway run so this is independent of the base-plan record.
    const RUN16 = "01DX5ZZKBKACTAV9WEVGEMMV01";
    const plan16 = await restorePlanHash({ runId: RUN16 });
    await call(OWNER, "POST", "/admin/roles", { email: SHARED, role: "approver" });
    const mk = await callSub(SHARED, SUB_MAKER, "POST", "/admin/restore/request", { runId: RUN16, reason: "rotated-email maker" });
    const mkRec = (await mk.json()) as RestoreApproval;
    ok("the departed maker raises a request bound to THEIR subject", mk.status === 200 && mkRec.requesterSubject === `${ISS}|${SUB_MAKER}`);

    // The SAME maker (same sub) cannot approve their own request (self-approval by subject), even though
    // the email matches - the control still holds for the genuine maker.
    const selfSame = await callSub(SHARED, SUB_MAKER, "POST", "/admin/restore/approve", { planHash: plan16 });
    ok("the genuine maker still cannot self-approve (subject self-match)", selfSame.status === 400 && /cannot approve your own request/.test(((await selfSame.json()) as { error: string }).error));

    // CLOSURE: a DIFFERENT Access user reusing the SAME email (SUB_RECYCLED) does NOT inherit the approver
    // role bound to SUB_MAKER's subject, so it resolves to viewer and is refused at the F1 capability gate
    // (restore.approve required). The recycled email inherits nothing - not the identity, not the role.
    const recWho = (await (await callSub(SHARED, SUB_RECYCLED, "GET", "/admin/whoami")).json()) as { role: string; subject?: string };
    ok("CLOSURE: the recycled-email caller (different subject) does NOT inherit the approver role (viewer)", recWho.role === "viewer" && recWho.subject === `${ISS}|${SUB_RECYCLED}`);
    const recApprove = await callSub(SHARED, SUB_RECYCLED, "POST", "/admin/restore/approve", { planHash: plan16 });
    const recBody = (await recApprove.json()) as { error?: string; required?: string; have?: string };
    ok("CLOSURE: the recycled-email caller is refused at the approve role gate (inherited no role)", recApprove.status === 403 && recBody.required === "restore.approve" && recBody.have === "viewer");

    // A genuinely distinct, EXPLICITLY granted approver (its own subject) approves the maker's request for
    // real, proving the rule is maker != checker by subject, not "no one can approve".
    const realApprove = await call(APPROVER2, "POST", "/admin/restore/approve", { planHash: plan16 });
    const realRec = (await realApprove.json()) as RestoreApproval;
    ok("a genuinely distinct approver (own subject) may approve the rotated maker's request", realApprove.status === 200 && realRec.status === "approved");
    ok("the approval records distinct maker and checker SUBJECTS", realRec.requesterSubject === `${ISS}|${SUB_MAKER}` && realRec.approverSubject === subjectOf(APPROVER2) && realRec.requesterSubject !== realRec.approverSubject);
    // Clean up the shared grant.
    await call(OWNER, "POST", "/admin/roles/delete", { email: SHARED });
  }

  // ---- PROOF 16: a SAME subject with a CHANGED display email is
  //               still refused as a self-approval, by the SUBJECT axis alone ------------------------
  // canApprove's own header documents TWO independent floors: the subject check (primary; a recycled
  // email with a DIFFERENT subject is a legitimate distinct checker, PROOF 15b) and the email check
  // (belt-and-suspenders; one human can hold two distinct subjects sharing one email). Every proof
  // above that exercises the subject check also happens to hold the email fixed, and every proof that
  // varies the email also happens to hold the subject fixed -- so an adversarial attack that deleted the
  // subject check ENTIRELY from canApprove (src/admin/approvals.ts) still passed this file's other 18
  // proofs at 0 failures, because the surviving email check covered every scenario THEY tried. The one
  // scenario neither of those proofs drives is the one canApprove's own comment names as the reason the
  // subject check has to be primary: the SAME Access user's display email changes between the request and
  // the approve (an IdP profile edit), while their subject (already bound via role:sub:<subject> from the
  // request) does not. Model that here: request under (EMAIL_OLD, SUB_SHARED), then attempt to approve
  // the SAME request under (EMAIL_NEW, SUB_SHARED) -- same person, different display email. Must still be
  // refused as self-approval, and specifically by the subject axis (the email axis cannot see it, because
  // EMAIL_NEW never equals record.requestedBy).
  {
    const EMAIL_OLD = "email-changes@acme.example";
    const EMAIL_NEW = "email-changes-renamed@acme.example";
    const SUB_SHARED = "sub-email-change-stable";
    const callSub = async (email: string, sub: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
      const init: RequestInit = {
        method,
        headers: { "cf-access-jwt-assertion": await tokenForSub(email, sub), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      // The dry run this request is raised against (see call(): requestRestore refuses an unanchored plan).
      if (path === "/admin/restore/request" && body !== undefined) await notePlanAnchorForRequest(sched.stub.fetch, body);
      return handleAdmin(new Request(`https://engine.example${path}`, init), accessEnv());
    };
    const RUN17 = "01EX5ZZKBKACTAV9WEVGEMMV02";
    const plan17 = await restorePlanHash({ runId: RUN17 });
    // Grant by the OLD email, then authenticate (binding role:sub:SUB_SHARED) and raise the request.
    await call(OWNER, "POST", "/admin/roles", { email: EMAIL_OLD, role: "approver" });
    const mk = await callSub(EMAIL_OLD, SUB_SHARED, "POST", "/admin/restore/request", { runId: RUN17, reason: "email-change maker" });
    const mkRec = (await mk.json()) as RestoreApproval;
    ok("the maker raises a request under their original email", mk.status === 200 && mkRec.requesterSubject === `${ISS}|${SUB_SHARED}` && mkRec.requestedBy === EMAIL_OLD);

    // The SAME subject now authenticates with a NEW display email (already bound, so the approver role
    // follows the subject unchanged) and tries to approve their own request. The email axis alone would
    // NOT catch this (EMAIL_NEW !== requestedBy); it must be refused by the subject axis.
    const selfNewEmail = await callSub(EMAIL_NEW, SUB_SHARED, "POST", "/admin/restore/approve", { planHash: plan17 });
    const sb = (await selfNewEmail.json()) as { error: string };
    ok("a same-subject approval under a CHANGED email is still refused (400)", selfNewEmail.status === 400);
    ok("the refusal is maker != checker (subject self-match, not an email match)", /cannot approve your own request/.test(sb.error));

    // And a genuinely distinct subject (its own grant) still approves for real.
    await call(OWNER, "POST", "/admin/roles", { email: APPROVER2, role: "approver" });
    const realApprove = await call(APPROVER2, "POST", "/admin/restore/approve", { planHash: plan17 });
    const realRec = (await realApprove.json()) as RestoreApproval;
    ok("a genuinely distinct approver may still approve the email-changed maker's request", realApprove.status === 200 && realRec.status === "approved");
    ok("the approval records distinct maker and checker SUBJECTS", realRec.requesterSubject === `${ISS}|${SUB_SHARED}` && realRec.approverSubject === subjectOf(APPROVER2) && realRec.requesterSubject !== realRec.approverSubject);
    await call(OWNER, "POST", "/admin/roles/delete", { email: EMAIL_OLD });
  }

  // ---- PROOF 17: reason field length and control-character bounds (V1.3.3) ----------------
  // The reason is stored verbatim in the DO approval record, the audit log, and the approver
  // inbox. An unbounded or control-character-laden reason could bloat DO storage and corrupt
  // downstream rendering. The DO must reject over-limit reasons and bare control characters at
  // the authority boundary, returning a clear 400 in each case.
  {
    // A reason exactly at the limit (1000 chars) is accepted.
    const atLimit = "a".repeat(1000);
    const okReq = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: atLimit });
    ok("a reason of exactly 1000 characters is accepted", okReq.status === 200);
    // Clean up so later sub-tests start with no conflicting open record.
    await call(APPROVER, "POST", "/admin/restore/reject", { planHash });

    // A reason one character over the limit is rejected 400.
    const overLimit = "a".repeat(1001);
    const tooLong = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: overLimit });
    const tooLongBody = (await tooLong.json()) as { error: string };
    ok("a reason of 1001 characters is rejected 400", tooLong.status === 400);
    ok("the too-long rejection names the reason field", /reason/.test(tooLongBody.error));

    // A reason containing a bare NUL byte (control character 0x00) is rejected 400.
    const withNul = "restore request\x00injected";
    const nulReq = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: withNul });
    const nulBody = (await nulReq.json()) as { error: string };
    ok("a reason with a NUL byte is rejected 400", nulReq.status === 400);
    ok("the control-character rejection names the reason field", /reason/.test(nulBody.error));

    // A reason containing a carriage-return (0x0D, another C0 control) is rejected 400.
    const withCr = "line one\r\nline two";
    const crReq = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: withCr });
    ok("a reason containing a bare CR (0x0D) is rejected 400", crReq.status === 400);

    // A reason containing a newline (0x0A) is accepted (multi-line reasons are valid in the UI).
    const withLf = "line one\nline two";
    const lfReq = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: withLf });
    ok("a reason containing a newline (0x0A) is accepted", lfReq.status === 200);
    // Clean up.
    await call(APPROVER, "POST", "/admin/restore/reject", { planHash });

    // A normal reason still passes (regression guard for the happy path).
    const normalReq = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "quarterly DR rehearsal, peer-reviewed" });
    ok("a normal reason passes the bounds check", normalReq.status === 200);
    // Clean up so the chain-verification proof below starts tidy.
    await call(APPROVER, "POST", "/admin/restore/reject", { planHash });
  }

  // ---- PROOF 18: an UNAUTHORISED apply that is ALSO rate-limited returns 403 (+ denied audit),
  //               NOT 429 -- a security-relevant denial must not be masked by the rate limiter ----
  // The ordering bug: if rateLimited() ran BEFORE the F1 role gate on the apply path, a rate-limited
  // Operator's confirm:true apply would return 429 and the denied-apply audit would never be written,
  // so a blocked production write by an under-privileged caller would go unrecorded. The fix runs the
  // role gate (and its denied-apply audit) FIRST on the apply path, so an unauthorised apply is always
  // the 403 + audit even when the caller is over their per-window cap. This proof drives the REAL
  // handleAdmin: it SATURATES an Operator's rate bucket via the DO's own /rate-check (cost = the cap,
  // which fills a fresh window exactly, so the very next mutating request is over the cap), then makes
  // that Operator attempt an apply. With the bug it would be 429; with the fix it must be 403.
  {
    // The cap the engine pins, imported from source so it stays in lockstep automatically. A single
    // /rate-check with cost = CAP fills a FRESH key's window exactly, so the next unit request (the
    // apply below) is over the cap. Asserting the OBSERVABLE 403-not-429 behaviour with the imported
    // constant means a change to the source cap is reflected here without a manual edit.
    const CAP = RATE_LIMIT_MAX_PER_WINDOW;
    // A FRESH operator identity, used nowhere else, so its rate bucket starts empty and the cost=CAP
    // fill lands the window exactly at the cap (an identity already part-way through its window would
    // refuse the cost=CAP check without filling it). Granted Operator so the F1 apply gate refuses it.
    const RL_OPERATOR = "ratelimited-operator@acme.example";
    await call(OWNER, "POST", "/admin/roles", { email: RL_OPERATOR, role: "operator" });

    // Saturate this Operator's per-caller window by driving the DO /rate-check directly with the key the
    // router ACTUALLY derives, taken from the production deriver rather than spelled out here. One check of
    // cost = CAP opens the window AT the cap, so the apply's own rate-check (a unit request) is refused.
    //
    // The bucket key must be derived from the production function rather than hand-spelled, or the fill and
    // the probe below could both operate a bucket the router never reads, agreeing with each other while
    // reporting a saturated caller who is not saturated at all -- which would make the 403-not-429 assertion
    // below vacuous, since it only means anything while a 429 is genuinely reachable for this caller.
    const fill = await sched.stub.fetch("https://scheduler.internal/rate-check", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key: rateLimitKey({ subject: subjectOf(RL_OPERATOR) } as Caller), cost: CAP }),
    });
    const fillBody = (await fill.json()) as { allowed: boolean };
    ok("the cost=CAP fill is admitted (it exactly fills the fresh window)", fillBody.allowed === true);
    // Confirm the bucket is now genuinely over the cap: a further unit /rate-check is refused. This is
    // the precondition that makes the 403-not-429 assertion meaningful (a 429 IS reachable for this
    // caller right now, so the route returning 403 proves the role gate ran BEFORE the limiter).
    const probe = await sched.stub.fetch("https://scheduler.internal/rate-check", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key: rateLimitKey({ subject: subjectOf(RL_OPERATOR) } as Caller) }),
    });
    ok("the Operator's bucket is now over the cap (a 429 is reachable)", ((await probe.json()) as { allowed: boolean }).allowed === false);

    // Snapshot the denied restore-apply events for this Operator BEFORE the apply (expected: none yet),
    // so the assertion below proves the apply ADDED the denied-apply audit record, not that one lingered.
    const planHashRL = await restorePlanHash({ runId: RUN_ID });
    const deniedBefore = (await readLog("action=restore-apply&outcome=denied")).events.filter(
      (e) => e.actorEmail === RL_OPERATOR,
    ).length;
    ok("no denied restore-apply for this Operator exists yet", deniedBefore === 0);

    // The Operator attempts an APPLY while over their cap. The capability gate must run FIRST: the
    // response must be the F1 403 (forbidden, restore.apply required), NOT a 429 that would mask it.
    const apply = await call(RL_OPERATOR, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
    ok("a rate-limited unauthorised apply returns 403 (the capability gate ran before the limiter)", apply.status === 403);
    ok("the rate-limited unauthorised apply is NOT masked as a 429", apply.status !== 429);
    const ab = (await apply.json()) as { error?: string; required?: string; have?: string };
    ok("the 403 is the F1 capability gate (forbidden, restore.apply required, operator have)", ab.error === "forbidden" && ab.required === "restore.apply" && ab.have === "operator");

    // The blocked production write was AUDITED as a denied apply despite the saturated bucket: a denied
    // restore-apply event for this Operator + this plan hash now exists that was not there before.
    const deniedAfter = (await readLog("action=restore-apply&outcome=denied")).events.filter(
      (e) => e.actorEmail === RL_OPERATOR && (e.target as { planHash?: string }).planHash === planHashRL,
    );
    ok("the rate-limited unauthorised apply was audited as a denied apply (the denial is not lost)", deniedAfter.length === 1);

    // Clean up the grant so the role table stays tidy for the chain-verify proof below.
    await call(OWNER, "POST", "/admin/roles/delete", { email: RL_OPERATOR });
  }

  // ---- PROOF 19: the audit chain still VERIFIES over the recorded events ---------------
  {
    const verify = (await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as { intact: boolean; checkedThrough: number };
    ok("the chain verifies intact after the dual-control flow", verify.intact === true && verify.checkedThrough >= 1);
    const log = await readLog();
    const ascending = [...log.events].reverse();
    const independent = await verifyChain(ascending);
    ok("an independent re-verification agrees the chain is intact", independent.intact === true);
    // The chain holds restore-request / -approve / -reject / -apply events (the first-class set).
    const actions = new Set(log.events.map((e) => e.action));
    ok("restore-request events are in the chain", actions.has("restore-request"));
    ok("restore-approve events are in the chain", actions.has("restore-approve"));
    ok("restore-reject events are in the chain", actions.has("restore-reject"));
    ok("restore-apply events are in the chain", actions.has("restore-apply"));
  }

  // ---- PROOF 20: the EMAIL axis independently, by TWO
  //                DISTINCT subjects sharing ONE email -- the scenario the email floor exists for ---
  // PROOF 16 proved the SUBJECT axis is independently defended (deleting the subject check from
  // canApprove left 0 failures across every OTHER proof in this file; the new proof there closed it).
  // The previous pass stated plainly it had not run the mirror mutation -- delete the EMAIL check
  // while holding the SUBJECT check -- so nobody had verified the email axis is independently
  // defended, only that it exists in source. Run here first as an attack against REAL
  // src/admin/approvals.ts (not restated in this file): deleting the email-floor lines (383-387)
  // while leaving the subject check in place left this file's other 19 proofs at 0 failures, because
  // every one of them either matches subject (self-approval, caught by the surviving subject check)
  // or holds a genuinely distinct subject AND a genuinely distinct email (PROOF 15b's CLOSURE never
  // reaches canApprove with two independently-capable subjects sharing one email at all, because the
  // ordinary role-grant path binds one email's grant to the FIRST subject that authenticates with it --
  // demonstrated by PROOF 15b's own closure, where the recycled-email different-subject caller
  // inherits no role and is refused at the F1 gate before canApprove is ever called). That single-bind
  // behaviour is exactly why canApprove's own header says the reverse scenario is real: "one human can
  // legitimately hold two distinct, IdP-bound subjects that share one verified email (a passkey
  // identity plus a native-IdP identity, or two group-role-mapped SSO connections)". Reaching
  // canApprove with that shape needs the DO driven directly (as PROOF 13's defence-in-depth check
  // does), constructing two Caller objects that are BOTH independently role:approver, sharing an
  // email, with different subjects -- exactly the shape a group-role mapping or two separately
  // provisioned SSO connections would produce in production, and exactly the shape the subject check
  // alone (email check deleted) cannot see, since it compares subjects and here they differ.
  {
    const RUN20 = "01FX5ZZKBKACTAV9WEVGEMMV03";
    const plan20 = await restorePlanHash({ runId: RUN20 });
    const SHARED_EMAIL = "two-subjects-one-email@acme.example";
    const makerB: Caller = { method: "access", email: SHARED_EMAIL, subject: `${ISS}|sub-b-maker`, role: "approver", groups: [] };
    const checkerB: Caller = { method: "access", email: SHARED_EMAIL, subject: `${ISS}|sub-b-checker`, role: "approver", groups: [] };
    // The dry run this request is raised against: requestRestore refuses an unanchored plan hash.
    await notePlanAnchor(sched.stub.fetch, plan20);
    await sched.stub.fetch("https://scheduler.internal/restore/request", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(makerB) },
      body: JSON.stringify({ planHash: plan20, runId: RUN20, isLatest: false, reason: "email-axis maker" }),
    });
    // The SAME email, a DIFFERENT subject, both independently role:approver: the subject check alone
    // sees two different principals and would allow this. Only the email floor refuses it.
    const sameEmailAtDO = await sched.stub.fetch("https://scheduler.internal/restore/approve", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(checkerB) },
      body: JSON.stringify({ planHash: plan20 }),
    });
    const seb = (await sameEmailAtDO.json()) as { error?: string };
    ok("EMAIL AXIS: a distinct-subject, same-email approval is refused (400)", sameEmailAtDO.status === 400);
    ok("EMAIL AXIS: the refusal is self-approval, by the email floor (subjects genuinely differ)", /cannot approve your own request/.test(seb.error ?? "") && makerB.subject !== checkerB.subject);
    // A genuinely distinct email (and subject) still approves for real, proving the rule is
    // maker != checker, not "no request from this DO can ever be approved".
    const distinctEmail: Caller = { method: "access", email: "two-subjects-real-checker@acme.example", subject: `${ISS}|sub-b-real`, role: "approver", groups: [] };
    const realAtDO = await sched.stub.fetch("https://scheduler.internal/restore/approve", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(distinctEmail) },
      body: JSON.stringify({ planHash: plan20 }),
    });
    ok("EMAIL AXIS: a genuinely distinct email and subject still approves", realAtDO.status === 200 && ((await realAtDO.json()) as RestoreApproval).approvedBy === "two-subjects-real-checker@acme.example");
  }

  // ---- PROOF 21: the SPEND is bound to WHO is spending it -
  // THE RESIDUE. An approval record is armed, single-use authority to apply a destructive restore, keyed by
  // the PLAN and by nothing else: reserveRestore and consumeApproval took a plan hash and no caller argument
  // at all. The 24-hour TTL bounds it in TIME and says nothing about WHOM, so what survived a person's removal
  // was not their access (their sessions die) but their intended destructive act, still armed and spendable.
  //
  // WHY THESE SIX AND NOT SIX EASIER ONES. Under a build with no binding at all, "the checker was DELETED from
  // the roster" is caught by almost any check somebody might write, including a useless one that merely asks
  // whether a row still exists. The cases below are chosen because the ones that matter are the ones that
  // break: a DEMOTION (the person is still on the roster, still a member, still has a live session, and only
  // the CAPABILITY lapsed) goes green under a row-existence check; a lapsed MAKER goes green under a
  // checker-only check; a DIRECT reserve goes green under a check that lives only in the advisory read-only
  // gate; and a group-conferred approver goes RED under a subject-only re-resolution, which is a legitimate
  // approver being stranded rather than a lapsed one being caught. Every refusal assertion is paired with the
  // WRITE assertion (restoreKV stayed empty), because a status-only proof passes against a build that refuses
  // and applies anyway.
  //
  // NOBODY IS STRANDED, and 21b and 21e are that claim made executable rather than asserted in prose.
  {
    const GROUPIE = "group-approver@acme.example";
    const DR_GROUP = "dr-approvers";
    const refusalRows = (): Record<string, { count: number }> => sched.storage.rawGet<Record<string, { count: number }>>(GOVERNANCE_REFUSALS_KEY) ?? {};
    const rowCount = (key: string): number => refusalRows()[key]?.count ?? 0;
    // callGroups drives handleAdmin as a caller presenting VERIFIED Access groups.
    async function callGroups(email: string, groups: string[], method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
      const assertion = await tokenForGroups(email, groups);
      const init: RequestInit = {
        method,
        headers: { "cf-access-jwt-assertion": assertion, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      return handleAdmin(new Request(`https://engine.example${path}`, init), accessEnv());
    }
    // armFresh leaves exactly one APPROVED approval for the base plan, whoever the checker is. A refused apply
    // leaves the record standing at "approved" (nothing was reserved, so there is nothing to release), so a
    // reject comes first; requestRestore itself refuses to clobber an approved record.
    const armFresh = async (checker: () => Promise<Response>): Promise<void> => {
      await call(APPROVER, "POST", "/admin/restore/reject", { planHash, rejectReason: "other" });
      await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "spend-binding proof" });
      await checker();
    };
    const applyBase = async (): Promise<Response> => {
      restoreKV.store.clear();
      restoreKV.putCount = 0;
      return call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
    };

    // ---- 21a: the CHECKER is DEMOTED, not deleted. Still on the roster, still a member, only the
    // restore.approve capability is gone. A row-existence check stays green here; the binding must not.
    await armFresh(() => call(APPROVER2, "POST", "/admin/restore/approve", { planHash }));
    const checkerBefore = rowCount("restore-apply|checker-authority-lapsed");
    await call(OWNER, "POST", "/admin/roles", { email: APPROVER2, role: "operator" }); // operator holds restore.request, NOT restore.approve
    const demotedApply = await applyBase();
    ok("[21a] an apply approved by a since-DEMOTED checker is refused 403", demotedApply.status === 403);
    ok("[21a] THE ASSERTION THAT MATTERS: the refused apply wrote NOTHING", restoreKV.store.size === 0 && restoreKV.putCount === 0);
    ok("[21a] the refusal is classified as the CHECKER axis, not a flat not-approved", rowCount("restore-apply|checker-authority-lapsed") > checkerBefore);
    // The approval is REFUSED, not VOIDED: the record is untouched and still reads approved. That distinction
    // is the whole reason binding was chosen over expiry -- an expiry destroys the ceremony, a binding suspends
    // it, and 21b spends this very record.
    {
      const inbox = (await (await call(OWNER, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
      const rec = inbox.find((r) => r.planHash === planHash);
      ok("[21a] the approval is SUSPENDED, not voided: the record still reads approved", rec?.status === "approved");
      ok("[21a] the record carries the checker's recorded groups (the re-resolution's input, not its authority)", Array.isArray(rec?.approverGroups));
    }

    // ---- 21b: NOBODY IS STRANDED. Restore the checker's authority and the SAME approval spends, with no
    // fresh ceremony. This is the claim that binding costs a legitimate approver nothing.
    await call(OWNER, "POST", "/admin/roles", { email: APPROVER2, role: "approver" });
    const restoredApply = await applyBase();
    const restoredBody = (await restoredApply.json()) as RestoreResult;
    ok("[21b] NO STRANDING: the SAME approval applies once the checker's authority is intact (200)", restoredApply.status === 200);
    ok("[21b] and it really applied (ok:true, all three records written back)", restoredBody.ok === true && restoredBody.recordsRestored === 3 && restoreKV.store.size === 3);
    {
      let bytesMatch = true;
      for (const [name, v] of Object.entries(KVSET)) {
        const got = restoreKV.store.get(name);
        if (!got || new TextDecoder().decode(got) !== v) bytesMatch = false;
      }
      ok("[21b] every restored value byte-matches (the binding gates the spend, it does not corrupt it)", bytesMatch);
    }

    // ---- 21c: the MAKER lapses while the checker is untouched. Under a checker-only binding this whole case
    // stays green and applies for real, which is the false negative that matters: the plan was chosen by
    // somebody the account has since removed, and their intended act is what outlived them.
    await armFresh(() => call(APPROVER2, "POST", "/admin/restore/approve", { planHash }));
    const makerBefore = rowCount("restore-apply|maker-authority-lapsed");
    const checkerBeforeMaker = rowCount("restore-apply|checker-authority-lapsed");
    await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "viewer" }); // viewer does not hold restore.request
    const makerApply = await applyBase();
    ok("[21c] an apply whose MAKER has since lost restore.request is refused 403", makerApply.status === 403);
    ok("[21c] THE ASSERTION THAT MATTERS: the refused apply wrote NOTHING", restoreKV.store.size === 0 && restoreKV.putCount === 0);
    ok("[21c] the refusal names the MAKER axis", rowCount("restore-apply|maker-authority-lapsed") > makerBefore);
    ok("[21c] the two axes do not coalesce: the CHECKER row did not move", rowCount("restore-apply|checker-authority-lapsed") === checkerBeforeMaker);
    await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });

    // ---- 21d: the RESERVE is the authoritative site, not the advisory gate. The router's read-only gate runs
    // some milliseconds before the reservation; a binding that lived only there would be a TOCTOU window, and
    // any caller reaching the DO route directly would spend the authority regardless. Driven straight at the
    // DO, bypassing the gate entirely -- under a gate-only build this returns reserved:true.
    await call(OWNER, "POST", "/admin/roles", { email: APPROVER2, role: "operator" });
    const directReserve = await sched.stub.fetch("https://scheduler.internal/restore/reserve", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ planHash }),
    });
    ok("[21d] a DIRECT reserve that never touched the gate is refused (the binding is on the SPEND)", ((await directReserve.json()) as { reserved: boolean }).reserved === false);
    await call(OWNER, "POST", "/admin/roles", { email: APPROVER2, role: "approver" });

    // ---- 21e: DOES NOT STRAND A GROUP-CONFERRED APPROVER, the false-positive direction and the reason the
    // re-resolution takes groups at all. This checker has NO role-table row: their authority comes entirely
    // from an IdP group mapping, which is the ordinary shape in an SSO estate. A subject-only re-resolution
    // resolves them to the viewer floor and refuses a perfectly valid approval, so this case goes RED under
    // the obvious simpler implementation.
    await call(OWNER, "POST", "/admin/group-roles", { group: DR_GROUP, role: "approver" });
    const groupWho = (await (await callGroups(GROUPIE, [DR_GROUP], "GET", "/admin/whoami")).json()) as { role: string; roleSource: string };
    ok("[21e] the group-conferred approver holds approver by MAPPING, with no role-table grant", groupWho.role === "approver" && groupWho.roleSource === "group");
    await call(APPROVER, "POST", "/admin/restore/reject", { planHash, rejectReason: "other" });
    await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "group-conferred checker" });
    const groupApprove = await callGroups(GROUPIE, [DR_GROUP], "POST", "/admin/restore/approve", { planHash });
    ok("[21e] the group-conferred approver can approve", groupApprove.status === 200);
    const groupApply = await applyBase();
    const groupApplyBody = (await groupApply.json()) as RestoreResult;
    ok("[21e] NO STRANDING: an approval by a GROUP-CONFERRED checker still applies (200, ok:true)", groupApply.status === 200 && groupApplyBody.ok === true);
    ok("[21e] and it really wrote the records back", groupApplyBody.recordsRestored === 3 && restoreKV.store.size === 3);

    // ---- 21f: the recorded groups are an INPUT to a live re-resolution and confer nothing on their own.
    // Delete the MAPPING (estate policy, re-read live) and the same recorded groups now resolve to nothing. A
    // build that trusted the stored groups as authority -- the obvious way to implement "remember who approved
    // it" -- stays green here and applies.
    await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "mapping deleted under the approval" });
    await callGroups(GROUPIE, [DR_GROUP], "POST", "/admin/restore/approve", { planHash });
    const mappingBefore = rowCount("restore-apply|checker-authority-lapsed");
    await call(OWNER, "POST", "/admin/group-roles/delete", { group: DR_GROUP });
    const unmappedApply = await applyBase();
    ok("[21f] deleting the MAPPING under an armed approval refuses the apply 403", unmappedApply.status === 403);
    ok("[21f] THE ASSERTION THAT MATTERS: the refused apply wrote NOTHING", restoreKV.store.size === 0 && restoreKV.putCount === 0);
    ok("[21f] the stored groups did not authorise it themselves (the checker axis refused)", rowCount("restore-apply|checker-authority-lapsed") > mappingBefore);

    // ---- 21g: the READ-ONLY GATE is independently bound, the mirror of 21d. This assertion exists because
    // deleting the gate's own check while leaving the reserve's left every proof above GREEN: the reserve
    // refuses either way and writes the same governance row, so nothing router-driven could tell the two builds
    // apart. Both sites are load-bearing for different reasons -- the gate is the check that runs BEFORE the
    // change-control enforce, so without it an apply that is going to be refused anyway would first record a
    // change reference against a restore that never runs -- and each now has a proof that fails without it.
    // Driven straight at the DO, the state left standing by 21f (a checker whose mapping is gone).
    const directGate = await sched.stub.fetch("https://scheduler.internal/restore/gate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ planHash }),
    });
    const directGateBody = (await directGate.json()) as { usable: boolean; approval: RestoreApproval | null };
    ok("[21g] the read-only GATE independently reports the approval unusable", directGateBody.usable === false);
    ok("[21g] and it still returns the record, so the console can say WHICH plan is stuck rather than nothing", directGateBody.approval?.planHash === planHash);

    // ---- PROOF 22: THE SPEND MUST NOT RE-ANIMATE THE PERSON IT
    // REFUSED. Proof 21 establishes that the binding SUSPENDS rather than voids, which is the property that
    // makes it safe to choose over an expiry. This is the other half of that same property, and it is the one
    // that was wrong: a suspension must lift only when the SUBJECT it refused gets its authority back, never
    // when somebody else turns up at the same ADDRESS.
    //
    // THE DEFECT, measured on the build 21 landed with. resolveStoredIdentityAuthority hands the recorded
    // email to roleForCaller, and roleForCaller hands it to resolveBoundEntry, whose bind-on-first-auth
    // defaults to ON for every non-native subject. Step 2 of that function is a WRITE: it matches a pending
    // grant BY EMAIL, binds it to whatever subject is presented, and deletes the pending row. So an ordinary
    // invite issued at a departed maker's re-used address did two things at once - it made the departed
    // maker's armed destructive approval usable again, and it consumed the NEW person's grant into the
    // departed subject, which no route anywhere would report. Against that build 22b and 22c go red and 22a
    // and 22d stay green, so the pair below distinguishes the two builds by more than a status code.
    //
    // AN ADDRESS IS NOT AN IDENTITY. Every other authorisation decision in this engine keys on the immutable
    // subject for exactly this reason, and roleForCaller's own comment records the closure in the other
    // direction (a new subject at an old address inherits nothing). This is that closure's mirror image.
    {
      const pendingKey = rolePendingKey(OPERATOR);
      await armFresh(() => call(APPROVER2, "POST", "/admin/restore/approve", { planHash }));
      const makerAxisBefore = rowCount("restore-apply|maker-authority-lapsed");

      // ---- 22a: the maker is OFFBOARDED outright, the delete a SCIM leaver run posts.
      await call(OWNER, "POST", "/admin/roles/delete", { email: OPERATOR });
      const offboardedApply = await applyBase();
      ok("[22a] an apply whose MAKER has been offboarded is refused 403", offboardedApply.status === 403);
      ok("[22a] THE ASSERTION THAT MATTERS: the refused apply wrote NOTHING", restoreKV.store.size === 0 && restoreKV.putCount === 0);
      ok("[22a] the refusal names the MAKER axis", rowCount("restore-apply|maker-authority-lapsed") > makerAxisBefore);

      // ---- 22b: THE ADDRESS IS RE-ISSUED to the next person. In production that is a new hire on a role
      // address, or a genuinely recycled mailbox; from the engine's side the artefact is identical either way,
      // an unclaimed `role:pending:<email>` row waiting for whichever subject signs in and claims it.
      const reissueBefore = rowCount("restore-apply|maker-authority-lapsed");
      await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
      ok("[22b] the re-issued grant is a PENDING grant, claimed by no subject yet", sched.storage.rawGet(pendingKey) !== undefined);
      const reissuedApply = await applyBase();
      ok("[22b] THE CLAIM UNDER TEST: re-issuing the departed maker's ADDRESS does not resurrect their armed approval (403)", reissuedApply.status === 403);
      ok("[22b] THE ASSERTION THAT MATTERS: the refused apply wrote NOTHING", restoreKV.store.size === 0 && restoreKV.putCount === 0);
      ok("[22b] and it is still refused on the MAKER axis, not silently reclassified", rowCount("restore-apply|maker-authority-lapsed") > reissueBefore);
      // The second half of the defect, and the half no status code can see: the spend must not spend somebody
      // else's invitation. A build that binds leaves this row gone and the new person resolving to viewer with
      // nothing anywhere to say why, which is the failure mode that would never be reported as a security bug.
      ok("[22b] the NEW person's grant is untouched: the spend did not consume an invitation that is not its own", sched.storage.rawGet(pendingKey) !== undefined);

      // ---- 22c: the same, driven straight at the DO reserve, the authoritative site. The gate above is
      // advisory and a caller reaching the DO route directly never touches it, so the reserve needs its own
      // proof exactly as 21d needed one - and the reserve is also the site that would perform the write.
      const directReserve22 = await sched.stub.fetch("https://scheduler.internal/restore/reserve", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ planHash }),
      });
      ok("[22c] a DIRECT reserve is refused on the re-issued address too", ((await directReserve22.json()) as { reserved: boolean }).reserved === false);
      ok("[22c] and the reserve did not consume the pending grant either", sched.storage.rawGet(pendingKey) !== undefined);

      // ---- 22d: STILL A SUSPENSION, NOT A VOID, which is what stops 22b from being a refuse-everything rule
      // wearing a proof. The person themselves signs in, their own subject claims the grant through the
      // ordinary bind-on-first-auth every live request performs, and the SAME approval spends with no fresh
      // ceremony. This is the arm that goes red if the fix is implemented by refusing whenever the recorded
      // maker has no bound row.
      await call(OPERATOR, "GET", "/admin/whoami");
      ok("[22d] a real sign-in by the address's holder claims the pending grant, exactly as it always did", sched.storage.rawGet(pendingKey) === undefined);
      const reclaimedApply = await applyBase();
      const reclaimedBody = (await reclaimedApply.json()) as RestoreResult;
      ok("[22d] NO STRANDING: the SAME approval applies once the recorded SUBJECT holds authority again (200)", reclaimedApply.status === 200);
      ok("[22d] and it really applied, so the suspension lifted rather than the record having been voided", reclaimedBody.ok === true && reclaimedBody.recordsRestored === 3);
    }
  }

  } finally {
    globalThis.fetch = realFetch;
  }
  console.log(failures === 0 ? "\nDUAL-CONTROL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
