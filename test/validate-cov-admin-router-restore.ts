// validate-cov-admin-router-restore: focused branch-coverage proof for src/admin/router-restore.ts, the
// restore dry-run / apply spoke plus the dual-control request -> approve / reject -> apply machinery and the
// read-safe BLIND restore test + KEYLESS attestation. It drives the PRODUCTION handleAdmin (real Access
// authorisation, the real SchedulerDO over in-memory storage, and the real runRestore / runBlindRestoreTest /
// runKeylessAttest) so every assertion checks a real outcome: an HTTP status, a returned body field, or a
// stored DO effect (a consumed approval, a stamped restore-proven record, a recorded audit event). No network
// is touched except the harness JWKS stub. Run:
//   node test/validate-cov-admin-router-restore.ts
//
// What it covers in router-restore.ts:
//  - buildSourceBindingMap over a live GET /downpipes (the loop + the presence-safe skip);
//  - POST /restore: the runId 400, the dry-run path (rate-limited), the F1 apply role gate (denied + denied
//    audit), the dual-control "restore not approved" 403 (denied audit), an APPROVED apply (consume + the
//    restore-apply success audit + the restore-verified receipt anchor), and the change-number policy refusal;
//  - POST /restore/request: the runId 400, the role gate (denied + audit), a created request, and the
//    client-cues-vs-server-recomputed cross-check (both the divergent and the matching paths);
//  - POST /restore/approve + /restore/reject: the role gates (denied + audit) and the success forwards;
//  - GET /restore/approvals: the approver view and the requester-own view;
//  - POST /restore/verify + /restore/attest: the runId 400, a passing proof (both stamps), a downpipe-but-no-
//    pass proof (the recency stamp only), the break-glass posture (no stamp), and the attest config-error path.

import { ORG_POLICY_KEY } from "../src/sched/scheduler-do-records.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { restorePlanHash, type RestoreApproval } from "../src/admin/approvals.ts";
import { notePlanAnchorForRequest } from "./testutil.ts";
import { rateLimitKey } from "../src/admin/router-core.ts";
import type { Caller } from "../src/admin/identity.ts";
import { b64urlEncode, concat, hexDecode, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { openCapsule, parseWraps } from "../src/crypto/capsule.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { RATE_LIMIT_MAX_PER_WINDOW } from "../src/sched/scheduler-do-limits.ts";
import type { Env } from "../src/env.d.ts";
import type { RestoreResult, RestorePlan, BlindRestoreTest, KeylessAttestationResult } from "../src/admin/restore-types.ts";
import type { AuditEvent } from "../src/admin/audit.ts";

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

// ---- In-memory archive doubles (from validate-restore / validate-dualcontrol) -------------
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
const TEAM = "test-team";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "cov-router-restore-aud";
const KID = "cov-router-restore-kid-1";
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const RUN_NA = "01BX5ZZKBKACTAV9WEVGEMMVRY"; // a valid ULID with no archive (the no-approval probe never opens it)
const NS = "ns_throwaway";
const DP_ID = "dp_restore"; // matches the sealed archive's root downpipeId
const KVSET: Record<string, string> = { "a": "alpha-value", "b": "beta-value", "user:42": "gamma-value-longer" };

function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

async function main(): Promise<void> {
  // --- the archive + keys, so a confirmed apply / blind verify / keyless attest really run ---
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  mldsaKeygen(mldsaSeed);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const archive = await buildArchive({
    downpipeId: DP_ID,
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

  try {
    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    async function tokenFor(email: string): Promise<string> {
      const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
      const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email, sub: `sub-of-${email}` });
      const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
      return `${header}.${body}.${b64urlEncode(sig)}`;
    }
    const subjectOf = (email: string): string => `${ISS}|sub-of-${email}`;

    // The restore-approval gate is OWNER-OPT-IN and OFF by default (an unconditional gate locked one-identity
    // estates out of restore entirely). This file exercises the gate, so it arms the policy explicitly.
    const sched = makeScheduler();
    await sched.storage.put(ORG_POLICY_KEY, { requireConfigApproval: false, requireRestoreApproval: true });
    const baseAccess = { ...sched.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD };
    // The full env: Access + the in-memory R2 archive destination + signer + operational read-back key + the
    // live KV namespace the convention binding KV_<NS> resolves to.
    const fullEnv = (): Env => ({ ...baseAccess, DEST_KIND: "r2", DEST_R2: r2 as unknown as R2Bucket, SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: operationalPrivateB64, [`KV_${NS}`]: restoreKV as unknown as KVNamespace } as unknown as Env);
    // Break-glass-only posture: NO operational read-back key, so a blind verify honestly reports ok:false and
    // opens no run (no downpipeId), exercising the "no stamp" arm of /restore/verify.
    const noOpEnv = (): Env => ({ ...baseAccess, DEST_KIND: "r2", DEST_R2: r2 as unknown as R2Bucket, SIGNER_PRIVATE: signerPrivateB64, [`KV_${NS}`]: restoreKV as unknown as KVNamespace } as unknown as Env);
    // No signer: runKeylessAttest's loadSigner throws -> the wrapper's catch -> ok:false with no downpipeId,
    // exercising the "no stamp" arm of /restore/attest.
    const noSignerEnv = (): Env => ({ ...baseAccess, DEST_KIND: "r2", DEST_R2: r2 as unknown as R2Bucket, OPERATIONAL_PRIVATE: operationalPrivateB64, [`KV_${NS}`]: restoreKV as unknown as KVNamespace } as unknown as Env);

    // A REQUEST IS PRECEDED BY ITS DRY RUN'S PLAN ANCHOR. requestRestore refuses a plan hash with no
    // recorded preview, because the engine will not mint an approval against a plan it cannot date, and the
    // console reaches the request route only from a dry run. Noting it here keeps each case a sequence the
    // product permits rather than one no operator could produce.
    async function call(email: string, method: "GET" | "POST", path: string, body?: unknown, env: Env = fullEnv()): Promise<Response> {
      const assertion = await tokenFor(email);
      const init: RequestInit = {
        method,
        headers: { "cf-access-jwt-assertion": assertion, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      if (path === "/admin/restore/request" && body !== undefined) await notePlanAnchorForRequest(sched.stub.fetch, body);
      return handleAdmin(new Request(`https://engine.example${path}`, init), env);
    }
    async function readAudit(query = ""): Promise<AuditEvent[]> {
      const r = await call(OWNER, "GET", "/admin/audit?limit=1000" + (query ? "&" + query : ""));
      return ((await r.json()) as { events: AuditEvent[] }).events;
    }

    const OWNER = "owner-crr@acme.example";
    const OPERATOR = "operator-crr@acme.example";
    const VIEWER = "viewer-crr@acme.example";
    // Typed as string (not the literal) so the maker != checker comparisons stay genuine runtime checks.
    const APPROVER: string = "approver-crr@acme.example";
    const APPROVER2: string = "approver2-crr@acme.example";

    // Bootstrap OWNER (first Access caller) and seed the role table.
    const who = (await (await call(OWNER, "GET", "/admin/whoami")).json()) as { role: string };
    ok("bootstrap: the first Access caller is Owner", who.role === "owner");
    await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
    await call(OWNER, "POST", "/admin/roles", { email: VIEWER, role: "viewer" });
    await call(OWNER, "POST", "/admin/roles", { email: APPROVER, role: "approver" });
    await call(OWNER, "POST", "/admin/roles", { email: APPROVER2, role: "approver" });

    // Seed a real downpipe whose id matches the archive's root downpipeId, so (1) GET /downpipes is non-empty
    // for buildSourceBindingMap to iterate, and (2) the restore-proven / restore-test recency stamps have a
    // downpipe to write onto (the stamp effect is then directly assertable from DO storage).
    await sched.storage.put(`dp:${DP_ID}`, {
      config: { id: DP_ID, name: "Restore DP", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: `KV_${NS}`, namespaceId: NS, include: [], exclude: [] } },
      nextRunAt: 4102444800000,
      lastRunId: null,
      inFlight: false,
    });

    const planHash = await restorePlanHash({ runId: RUN_ID });

    // ===== POST /restore =====

    // (1) runId is required -> a plain 400 (the FIRST check, before any role/rate gate). An Operator with no
    // runId is still a 400, never a 403/429.
    {
      const r = await call(OPERATOR, "POST", "/admin/restore", { confirm: true });
      ok("POST /restore with no runId is a 400", r.status === 400);
      ok("the 400 names runId as required", ((await r.json()) as { error: string }).error === "runId required");
    }

    // (1a) a runId that is PRESENT but not a canonical ULID (a dot-segment traversal payload) is
    // also a 400 at the router boundary, before any destination read -- the exact exploit shape (an S3-style
    // destination would otherwise collapse `run/../../evil-bucket/root.manifest.json` outside the configured
    // bucket once new URL() normalises it, see dest/sigv4.ts). Checked before the role gate, so this is a 400
    // regardless of role, never a 403/429/500.
    {
      const r = await call(OPERATOR, "POST", "/admin/restore", { runId: "../../evil-bucket", confirm: true });
      ok("POST /restore with a dot-segment runId is a 400 (not a 403/429/500)", r.status === 400);
      ok("the 400 names runId as an invalid ULID", ((await r.json()) as { error: string }).error === "runId must be a valid ULID");
    }

    // (2) the dry-run path (confirm omitted): open to any authenticated role, rate-limited, writes nothing.
    // This also drives buildSourceBindingMap over the (non-empty) live GET /downpipes.
    {
      restoreKV.store.clear();
      const r = await call(VIEWER, "POST", "/admin/restore", { runId: RUN_ID });
      const plan = (await r.json()) as RestorePlan;
      ok("a dry-run is allowed for any role (200)", r.status === 200);
      ok("the dry-run planned every record and wrote nothing", plan.mode === "dry-run" && plan.ok === true && plan.plannedWrites === 3 && restoreKV.store.size === 0);
      ok("the dry-run resolved each record to the convention binding", plan.sample.every((s) => s.binding === `KV_${NS}`));
    }

    // (3) the F1 apply role gate: an Operator (no restore.apply) is refused 403 BEFORE the rate-limit check,
    // and the blocked production write is audited as a denied apply.
    {
      restoreKV.store.clear();
      const r = await call(OPERATOR, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
      const b = (await r.json()) as { error: string; required: string; have: string };
      ok("an Operator apply is refused at the F1 gate (403)", r.status === 403);
      ok("the 403 names restore.apply as required", b.error === "forbidden" && b.required === "restore.apply" && b.have === "operator");
      ok("the refused apply wrote nothing", restoreKV.store.size === 0);
      const denied = (await readAudit("action=restore-apply&outcome=denied")).filter((e) => e.actorEmail === OPERATOR);
      ok("the denied apply is audited (the recordAudit branch ran)", denied.length === 1 && (denied[0]!.target as { planHash?: string }).planHash === planHash);
    }

    // (4) the dual-control gate: an Approver holds restore.apply but no approval is bound to the plan, so the
    // apply is refused 403 "restore not approved" and audited as denied. RUN_NA never opens (the gate precedes
    // any archive read), proving the refusal is the approval gate, not a read failure.
    {
      const naHash = await restorePlanHash({ runId: RUN_NA });
      const r = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_NA, confirm: true });
      const b = (await r.json()) as { error: string; planHash: string };
      ok("an apply with no approval is refused 403", r.status === 403);
      ok("the refusal is the dual-control gate, naming the plan hash", b.error === "restore not approved" && b.planHash === naHash);
      const denied = (await readAudit("action=restore-apply&outcome=denied")).filter((e) => e.actorEmail === APPROVER && (e.target as { planHash?: string }).planHash === naHash);
      ok("the unapproved apply is audited as denied", denied.length === 1);
    }

    // (4a) THE PLAN ANCHOR IS RECORDED EVEN WHEN THE PLAN COULD NOT BE BUILT. requestRestore refuses a plan
    // hash with no recorded dry run, so whether the dry-run route notes the anchor on an ok:false preview
    // decides whether a run that cannot be opened is requestable at all. It does: the note sits after the
    // plan and is not conditional on it, which is what lets an operator raise a request for a run whose
    // archive is unreachable today and have the approver see the honest "could not be planned" cues. Driven
    // through the production route on RUN_NA, a valid ULID with no archive, and read out of the DO's own
    // storage rather than inferred from the request succeeding.
    {
      const naHash = await restorePlanHash({ runId: RUN_NA });
      const before = await sched.storage.get(`planseen:${naHash}`);
      const dry = await call(OPERATOR, "POST", "/admin/restore", { runId: RUN_NA });
      const dryBody = (await dry.json()) as { ok?: boolean };
      const after = await sched.storage.get(`planseen:${naHash}`);
      ok("the dry run for a run with no archive answers ok:false rather than throwing", dry.status === 200 && dryBody.ok === false);
      ok("and it STILL records the plan anchor, so an unopenable run is requestable", before === undefined && after !== undefined);
    }

    // ===== POST /restore/request =====

    // (5) runId is required -> 400 (before the role gate).
    {
      const r = await call(OPERATOR, "POST", "/admin/restore/request", { reason: "no runId" });
      ok("POST /restore/request with no runId is a 400", r.status === 400);
    }

    // (5a) same ULID-shape gate, before the role gate.
    {
      const r = await call(OPERATOR, "POST", "/admin/restore/request", { runId: "../../evil-bucket", reason: "dot-segment runId" });
      ok("POST /restore/request with a dot-segment runId is a 400", r.status === 400);
      ok("the 400 names runId as an invalid ULID", ((await r.json()) as { error: string }).error === "runId must be a valid ULID");
    }

    // (6) the request role gate: a Viewer (no restore.request) is refused 403 + audited denied. The denied
    // request carries a target binding, so the denied-audit's redirectBinding takes its non-null arm.
    {
      const r = await call(VIEWER, "POST", "/admin/restore/request", { runId: RUN_ID, target: { binding: "KV_elsewhere" }, reason: "viewer cannot request" });
      const b = (await r.json()) as { error: string; required: string; have: string };
      ok("a Viewer cannot raise a restore request (403)", r.status === 403);
      ok("the 403 names restore.request as required", b.error === "forbidden" && b.required === "restore.request" && b.have === "viewer");
      const denied = (await readAudit("action=restore-request&outcome=denied")).filter((e) => e.actorEmail === VIEWER);
      ok("the denied request is audited with the redirect binding", denied.length === 1 && (denied[0]!.target as { redirectBinding?: string }).redirectBinding === "KV_elsewhere");

      // The same gate, denied with NO target, drives the null arm of the denied-audit redirectBinding.
      const r2 = await call(VIEWER, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "viewer cannot request, no target" });
      ok("a Viewer with no target is still refused (403)", r2.status === 403);
      const denied2 = (await readAudit("action=restore-request&outcome=denied")).filter((e) => e.actorEmail === VIEWER && (e.target as { redirectBinding?: string | null }).redirectBinding === null);
      ok("the no-target denied request audits a null redirect binding", denied2.length === 1);
    }

    // (7) a created request WITH a divergent plannedWrites claim only (no bytes): the engine recomputes the
    // cues server-side (the client claim is ignored, the divergence is cross-checked + logged). The stored
    // record carries the SERVER cues. Omitting bytes drives the bytes "-" arm of the divergence log line.
    {
      const r = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "cross-check writes", plannedWrites: 999 });
      const rec = (await r.json()) as RestoreApproval;
      ok("the request is created (200, status requested)", r.status === 200 && rec.status === "requested" && rec.planHash === planHash);
      ok("the request stores the SERVER-recomputed plannedWrites, not the client's 999", rec.plannedWrites === 3);
      ok("the request records the maker (requestedBy)", rec.requestedBy === OPERATOR);
    }

    // (8) GET /restore/approvals: the approver sees the open request (approver view); the requester sees their
    // own; a third party (Viewer) does not.
    {
      const approverInbox = (await (await call(APPROVER, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
      ok("an Approver sees the open request (approver view)", approverInbox.some((x) => x.planHash === planHash));
      const opInbox = (await (await call(OPERATOR, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
      ok("the requesting Operator sees their own request", opInbox.some((x) => x.planHash === planHash && x.requestedBy === OPERATOR));
      const viewerInbox = (await (await call(VIEWER, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
      ok("a non-approver non-requester does not see the request", !viewerInbox.some((x) => x.planHash === planHash));
    }

    // ===== POST /restore/approve + /restore/reject role gates =====

    // (9) approve gate: an Operator (no restore.approve) is refused 403 + audited denied. The body carries no
    // planHash, so the denied-audit's String(planHash ?? "") takes its empty-fallback arm.
    {
      const r = await call(OPERATOR, "POST", "/admin/restore/approve", {});
      const b = (await r.json()) as { error: string; required: string };
      ok("an Operator cannot approve (403)", r.status === 403 && b.required === "restore.approve");
      const denied = (await readAudit("action=restore-approve&outcome=denied")).filter((e) => e.actorEmail === OPERATOR);
      ok("the denied approve is audited (empty plan hash fallback)", denied.length === 1 && (denied[0]!.target as { planHash?: string }).planHash === "");
    }

    // (10) reject gate: a Viewer (no restore.approve) is refused 403 + audited denied (no planHash -> the
    // empty-fallback arm, mirroring the approve path).
    {
      const r = await call(VIEWER, "POST", "/admin/restore/reject", {});
      ok("a Viewer cannot reject (403)", r.status === 403);
      const denied = (await readAudit("action=restore-reject&outcome=denied")).filter((e) => e.actorEmail === VIEWER);
      ok("the denied reject is audited (empty plan hash fallback)", denied.length === 1 && (denied[0]!.target as { planHash?: string }).planHash === "");
    }

    // (11) reject success: an Approver rejects the open request (the forward succeeds, 200 rejected). This
    // clears the open record so the next blocks can request afresh.
    {
      const r = await call(APPROVER, "POST", "/admin/restore/reject", { planHash });
      ok("an Approver can reject a request (200, rejected)", r.status === 200 && ((await r.json()) as RestoreApproval).status === "rejected");
    }

    // (11a) a request whose ONLY divergent cue is bytes (writes/isLatest absent): the cross-check evaluates
    // ALL THREE clauses (isLatest absent, writes absent, bytes mismatch) and logs, driving the writes "-" arm
    // of the log line and the bytes clause of the divergence test. Rejected after to leave the slot clean.
    {
      const r = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "cross-check bytes", bytes: 999999 });
      ok("a bytes-only divergent request is still created (200)", r.status === 200 && ((await r.json()) as RestoreApproval).status === "requested");
      await call(APPROVER, "POST", "/admin/restore/reject", { planHash });
    }

    // (11b) a request carrying EVERY optional selector (target, include, exclude, maxRecords, recordName,
    // cfConfig): the dry-run-request mirror copies each present field (its "spread the present field" arm), and
    // the forwarded redirectBinding takes its non-null arm. recordName scopes to one record so the plan still
    // resolves. The plan hash differs from the base, so this is its own (rejected-after) record.
    {
      const selectorReq = { runId: RUN_ID, reason: "all selectors", target: { binding: `KV_${NS}` }, include: ["a"], exclude: ["b"], maxRecords: 5, recordName: "a", cfConfig: { token: "edit-tok", accountId: "acct-1", zoneId: "zone" } };
      const r = await call(OPERATOR, "POST", "/admin/restore/request", selectorReq);
      ok("a request with every optional selector is created (200)", r.status === 200 && ((await r.json()) as RestoreApproval).status === "requested");
      const selectorHash = await restorePlanHash(selectorReq);
      await call(APPROVER, "POST", "/admin/restore/reject", { planHash: selectorHash });
    }

    // (11c) a request with NO reason: the router still builds + forwards the request (the reason-omit arm of
    // the forward body), and the DO refuses it 400 (a reason is mandatory). This proves the router reaches the
    // forward regardless of reason, and the DO is the authority that enforces it.
    {
      const r = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID });
      ok("a request with no reason is refused 400 by the DO", r.status === 400);
    }

    // (11d) a request whose isLatest claim diverges from the server's recomputed value: drives the isLatest
    // clause of the cross-check. The server recomputes isLatest:true for this run, so claiming false diverges.
    {
      const r = await call(OPERATOR, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "cross-check isLatest", isLatest: false });
      const rec = (await r.json()) as RestoreApproval;
      ok("an isLatest-divergent request is created and stores the SERVER isLatest:true", r.status === 200 && rec.isLatest === true);
      await call(APPROVER, "POST", "/admin/restore/reject", { planHash });
    }

    // (11e) SECURITY GUARD (Stage 2 d1Tables cue passthrough): a /restore/request carrying d1Tables for a
    // database NOT in this (KV) run must recompute the approver cues WITH d1Tables -> runRestore refuses
    // ("database not found") -> plannedWrites:0. If the router dropped d1Tables from the recomputed dry-run
    // (a forged-benign-cue regression), it would instead plan the whole KV run
    // (plannedWrites:3). Asserting 0 guards that the handler threads d1Tables into the cue recomputation.
    {
      const d1Req = { runId: RUN_ID, reason: "d1Tables cue guard", d1Tables: { database: NS, tables: ["a"] } };
      const r = await call(OPERATOR, "POST", "/admin/restore/request", d1Req);
      const rec = (await r.json()) as RestoreApproval;
      ok("d1Tables cue recomputation runs WITH d1Tables (planned:0 for an absent D1 db, not the whole KV run)", r.status === 200 && rec.plannedWrites === 0);
      await call(APPROVER, "POST", "/admin/restore/reject", { planHash: await restorePlanHash(d1Req) });
    }

    // ===== an APPROVED apply: the success path end to end =====
    // (12) APPROVER requests (no cues -> the cross-check's matching/no-divergence arm), APPROVER2 approves
    // (approve success forward), APPROVER applies: the real runRestore writes the records back, the approval is
    // consumed, and the restore-apply success + restore-verified receipt anchor are recorded.
    {
      const reqR = await call(APPROVER, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "approved-apply" });
      ok("the maker raises a fresh request (200)", reqR.status === 200);
      const apR = await call(APPROVER2, "POST", "/admin/restore/approve", { planHash });
      ok("a distinct approver approves (200, approved)", apR.status === 200 && ((await apR.json()) as RestoreApproval).status === "approved");

      restoreKV.store.clear();
      const r = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
      const res = (await r.json()) as RestoreResult;
      ok("the approved apply is not gated (200)", r.status === 200);
      ok("the approved apply actually applied (ok, mode applied, 3 records)", res.ok === true && res.mode === "applied" && res.recordsRestored === 3);
      const expectBytes = Object.values(KVSET).reduce((n, v) => n + utf8(v).length, 0);
      let bytesMatch = true;
      for (const [name, v] of Object.entries(KVSET)) {
        const got = restoreKV.store.get(name);
        if (!got || new TextDecoder().decode(got) !== v) bytesMatch = false;
      }
      ok("every restored value byte-matches the original", bytesMatch && restoreKV.store.size === 3 && res.bytesRestored === expectBytes);

      // The apply audit records both identities, and the receipt anchor recorded a restore-verified event.
      const applyEvt = (await readAudit("action=restore-apply&outcome=success")).find((e) => (e.target as { planHash?: string }).planHash === planHash);
      ok("the apply is audited as success with maker + checker", applyEvt?.actorEmail === APPROVER && (applyEvt?.target as { approverEmail?: string }).approverEmail === APPROVER2);
      const verifiedEvt = (await readAudit("action=restore-verified")).find((e) => (e.target as { runId?: string }).runId === RUN_ID);
      ok("the restore receipt was anchored as a restore-verified audit event", verifiedEvt !== undefined && (verifiedEvt.target as { receiptSha384?: string }).receiptSha384 !== undefined);

      // The approval is single-use: a second apply with no fresh approval is refused.
      restoreKV.store.clear();
      const again = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
      ok("a second apply on the consumed approval is refused 403", again.status === 403 && restoreKV.store.size === 0);
    }

    // (12a) an APPROVED apply that runRestore REFUSES (a reserved-binding target): the role + dual-control
    // gates pass (the approval is bound to the reserved-target plan hash) and runRestore runs but returns
    // ok:false, so the apply is recorded as a FAILED restore-apply, the approval is NOT consumed, and no
    // receipt is anchored. This drives the redirect-binding-present, ok:false-audit, skip-consume and
    // skip-receipt arms of the apply path. The non-null target also exercises the redirectBinding capture.
    {
      const reservedReq = { runId: RUN_ID, target: { binding: "SIGNER_PRIVATE" }, reason: "reserved target" };
      const reservedHash = await restorePlanHash(reservedReq);
      const rq = await call(APPROVER, "POST", "/admin/restore/request", reservedReq);
      ok("the reserved-target request is created (200)", rq.status === 200 && ((await rq.json()) as RestoreApproval).planHash === reservedHash);
      const ap = await call(APPROVER2, "POST", "/admin/restore/approve", { planHash: reservedHash });
      ok("the reserved-target request is approved (200)", ap.status === 200);

      restoreKV.store.clear();
      const r = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true, target: { binding: "SIGNER_PRIVATE" } });
      const res = (await r.json()) as RestoreResult;
      ok("an apply runRestore refuses returns 200 with ok:false (a reserved target)", r.status === 200 && res.ok === false && res.recordsRestored === 0 && restoreKV.store.size === 0);
      const failedEvt = (await readAudit("action=restore-apply&outcome=failed")).find((e) => (e.target as { planHash?: string }).planHash === reservedHash);
      ok("the refused apply is audited as a FAILED restore-apply with the redirect binding", failedEvt !== undefined && (failedEvt.target as { redirectBinding?: string }).redirectBinding === "SIGNER_PRIVATE");

      // The approval was NOT consumed (the apply never reached the write phase), so it is still usable.
      const inbox = (await (await call(APPROVER, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
      ok("the failed apply did NOT consume the approval (still approved)", inbox.find((x) => x.planHash === reservedHash)?.status === "approved");
      // Clean it up so it does not linger as a usable approval.
      await call(APPROVER, "POST", "/admin/restore/reject", { planHash: reservedHash });
    }

    // ===== the reservation (not merely the read-only gate) is what makes an apply exclusive =====

    // (12b) a failed apply's RELEASE preserves the pre-existing "a failed apply does not burn the approval"
    // retry UX end to end: attempt 1 fails INSIDE runRestore itself (no OPERATIONAL_PRIVATE -> the honest
    // break-glass ok:false, touching no live data) and releases the reservation back to "approved"; attempt
    // 2, the SAME planHash/approval with no fresh round of dual control, then succeeds and consumes it.
    {
      const reqR = await call(APPROVER, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "fail-then-retry" });
      ok("a fresh request for the retry exercise is created (200)", reqR.status === 200);
      const apR = await call(APPROVER2, "POST", "/admin/restore/approve", { planHash });
      ok("a distinct approver approves it (200, approved)", apR.status === 200 && ((await apR.json()) as RestoreApproval).status === "approved");

      restoreKV.store.clear();
      const failed = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true }, noOpEnv());
      const failedRes = (await failed.json()) as RestoreResult;
      ok("attempt 1 (no operational key) fails honestly, ok:false, writing nothing", failed.status === 200 && failedRes.ok === false && restoreKV.store.size === 0);

      const inboxAfterFail = (await (await call(APPROVER, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
      ok("the failed attempt RELEASED the reservation: still approved, not consumed", inboxAfterFail.find((x) => x.planHash === planHash)?.status === "approved");

      const retried = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
      const retriedRes = (await retried.json()) as RestoreResult;
      ok("attempt 2, the SAME approval with no fresh dual control, succeeds", retried.status === 200 && retriedRes.ok === true && retriedRes.recordsRestored === 3 && restoreKV.store.size === 3);

      const inboxAfterRetry = (await (await call(APPROVER, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
      ok("the successful retry CONSUMED the approval (single use)", inboxAfterRetry.find((x) => x.planHash === planHash)?.status === "consumed");
    }

    // (12c) the regression test that would have caught two CONCURRENT apply requests carrying the
    // IDENTICAL approved planHash (an ordinary double-clicked Apply, or a client retry-on-timeout). Before
    // the fix, both would observe usable:true at the read-only gate and both would reach runRestore,
    // silently double-writing over live data; the reservation now makes exactly ONE of them win (the write
    // lands, the approval consumes) while the other is refused with the same 403 an unapproved apply gets.
    {
      const reqR = await call(APPROVER, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "concurrent-race" });
      ok("a fresh request for the concurrency exercise is created (200)", reqR.status === 200);
      const apR = await call(APPROVER2, "POST", "/admin/restore/approve", { planHash });
      ok("a distinct approver approves it (200, approved)", apR.status === 200 && ((await apR.json()) as RestoreApproval).status === "approved");

      restoreKV.store.clear();
      const [respA, respB] = await Promise.all([
        call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true }),
        call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true }),
      ]);
      const [bodyA, bodyB] = await Promise.all([respA.json(), respB.json()]);
      const pairs: Array<[Response, unknown]> = [[respA, bodyA], [respB, bodyB]];
      const isWinner = (r: Response, b: unknown): boolean => r.status === 200 && (b as RestoreResult).ok === true;
      const isRefused = (r: Response, b: unknown): boolean => r.status === 403 && (b as { error?: string }).error === "restore not approved";
      const winners = pairs.filter(([r, b]) => isWinner(r, b));
      const refusals = pairs.filter(([r, b]) => isRefused(r, b));
      ok("of two concurrent applies for the SAME planHash, EXACTLY ONE writes and the other is refused (the reservation, not the read-only gate, is what excludes it)", winners.length === 1 && refusals.length === 1);
      ok("the write landed exactly once with no silent double-apply / clobber", restoreKV.store.size === 3 && Object.entries(KVSET).every(([name, v]) => new TextDecoder().decode(restoreKV.store.get(name)!) === v));

      const inbox = (await (await call(APPROVER, "GET", "/admin/restore/approvals")).json()) as RestoreApproval[];
      ok("the approval is consumed exactly once by the winner (not left dangling in applying)", inbox.find((x) => x.planHash === planHash)?.status === "consumed");
    }

    // ===== change-number policy: an authorised, approved apply with NO change reference is refused =====
    // (13) Owner turns the policy ON. A fresh approval is raised + approved, then the maker applies with no
    // change reference: the role + dual-control gates pass, then the change-control enforce chokepoint returns
    // a non-OK (400) which the route surfaces verbatim, so the apply writes nothing.
    {
      const onR = await call(OWNER, "POST", "/admin/config/change-number-policy", { requireChangeNumber: true });
      ok("Owner enables Require Change Number (200)", onR.status === 200 && ((await onR.json()) as { requireChangeNumber: boolean }).requireChangeNumber === true);

      await call(APPROVER, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "change-control" });
      await call(APPROVER2, "POST", "/admin/restore/approve", { planHash });

      restoreKV.store.clear();
      const r = await call(APPROVER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true });
      const b = (await r.json()) as { error?: string };
      ok("an approved apply with no change number is refused (400 from the enforce chokepoint)", r.status === 400);
      ok("the refusal carries the actionable change-number message", typeof b.error === "string" && /change number is required/.test(b.error));
      ok("the change-control refusal wrote nothing", restoreKV.store.size === 0);

      // Turn the policy back off so it does not affect the proof tally.
      const offR = await call(OWNER, "POST", "/admin/config/change-number-policy", { requireChangeNumber: false });
      ok("Owner disables Require Change Number (200)", offR.status === 200);
    }

    // ===== POST /restore/verify =====

    // (14) runId is required -> 400 (the Viewer passes the read-safe restore.verify gate first).
    {
      const r = await call(VIEWER, "POST", "/admin/restore/verify", {});
      ok("POST /restore/verify with no runId is a 400", r.status === 400);
    }

    // (14a) a dot-segment runId is a 400 too, before withRunDestFallback/runBlindRestoreTest ever
    // opens a destination read -- this is the exact route the finding named (Viewer, the lowest role,
    // holds restore.verify with no dual control or approval).
    {
      const r = await call(VIEWER, "POST", "/admin/restore/verify", { runId: "../../evil-bucket" });
      ok("POST /restore/verify with a dot-segment runId is a 400 (not a 200 access/missing oracle)", r.status === 400);
      ok("the 400 names runId as an invalid ULID", ((await r.json()) as { error: string }).error === "runId must be a valid ULID");
    }

    // (15) a PASSING blind restore test (any role with restore.verify): ok:true with the downpipe id, so BOTH
    // the restore-proven stamp and the restore-test recency stamp run. The stamp effects are asserted from DO
    // storage (the downpipe's restoreProven + lastRestoreTest fields).
    {
      const r = await call(VIEWER, "POST", "/admin/restore/verify", { runId: RUN_ID });
      const res = (await r.json()) as BlindRestoreTest;
      ok("a blind verify passes (200, ok, 3 records, downpipe id)", r.status === 200 && res.ok === true && res.recordsVerified === 3 && res.downpipeId === DP_ID);
      const ds = (await sched.storage.get(`dp:${DP_ID}`)) as { restoreProven?: { by?: string; method?: string; runId?: string }; lastRestoreTestOk?: boolean; lastRestoreTestAt?: number };
      ok("a pass stamped restore-proven (who + method + runId)", ds.restoreProven?.by === VIEWER && ds.restoreProven?.method === "blind-test" && ds.restoreProven?.runId === RUN_ID);
      ok("a pass stamped the restore-test recency (ok:true)", ds.lastRestoreTestOk === true && typeof ds.lastRestoreTestAt === "number");
    }

    // (16) a verify that OPENS the run (downpipe id present) but verifies nothing (an include selector matching
    // no record -> ok:false): only the recency stamp runs, NOT the proven stamp. The proven record stays on the
    // prior pass while the recency flips to false.
    {
      const r = await call(VIEWER, "POST", "/admin/restore/verify", { runId: RUN_ID, include: ["zzz-no-such-prefix"] });
      const res = (await r.json()) as BlindRestoreTest;
      ok("a no-match blind verify is ok:false but still opened the run (downpipe id)", r.status === 200 && res.ok === false && res.recordsVerified === 0 && res.downpipeId === DP_ID);
      const ds = (await sched.storage.get(`dp:${DP_ID}`)) as { restoreProven?: { method?: string }; lastRestoreTestOk?: boolean };
      ok("the recency stamp ran (lastRestoreTestOk flipped to false)", ds.lastRestoreTestOk === false);
      ok("the proven stamp did NOT run (still the prior blind-test pass)", ds.restoreProven?.method === "blind-test");
    }

    // (17) break-glass-only posture (no operational read-back key): the blind verify honestly reports ok:false
    // and opens no run, so NEITHER stamp runs (no downpipe id). The route still returns the result (200).
    {
      const r = await call(VIEWER, "POST", "/admin/restore/verify", { runId: RUN_ID }, noOpEnv());
      const res = (await r.json()) as BlindRestoreTest;
      ok("a break-glass blind verify returns ok:false with no downpipe id", r.status === 200 && res.ok === false && res.downpipeId === undefined && typeof res.reason === "string");
    }

    // ===== POST /restore/attest =====

    // (18) runId is required -> 400.
    {
      const r = await call(VIEWER, "POST", "/admin/restore/attest", {});
      ok("POST /restore/attest with no runId is a 400", r.status === 400);
    }

    // (18a) same ULID-shape gate on the attest route, the other half of the finding's cited exploit.
    {
      const r = await call(VIEWER, "POST", "/admin/restore/attest", { runId: "../../evil-bucket" });
      ok("POST /restore/attest with a dot-segment runId is a 400 (not a 200 oracle)", r.status === 400);
      ok("the 400 names runId as an invalid ULID", ((await r.json()) as { error: string }).error === "runId must be a valid ULID");
    }

    // (19) a PASSING keyless attestation: ok:true with the downpipe id, so BOTH stamps run. The proven stamp
    // overwrites the earlier blind-test method with keyless-attest, which is asserted from DO storage.
    {
      const r = await call(VIEWER, "POST", "/admin/restore/attest", { runId: RUN_ID });
      const res = (await r.json()) as KeylessAttestationResult;
      ok("a keyless attest passes (200, ok, downpipe id)", r.status === 200 && res.ok === true && res.downpipeId === DP_ID);
      const ds = (await sched.storage.get(`dp:${DP_ID}`)) as { restoreProven?: { method?: string } };
      ok("the attest pass stamped restore-proven as keyless-attest", ds.restoreProven?.method === "keyless-attest");
    }

    // (20) a config error (no signer): the attest wrapper's catch returns ok:false with no downpipe id, so
    // NEITHER stamp runs; the route still returns the result (200).
    {
      const r = await call(VIEWER, "POST", "/admin/restore/attest", { runId: RUN_ID }, noSignerEnv());
      const res = (await r.json()) as KeylessAttestationResult;
      ok("a keyless attest with no signer returns ok:false with no downpipe id", r.status === 200 && res.ok === false && res.downpipeId === undefined && typeof res.reason === "string");
    }

    // ===== rate limiting: a saturated caller is refused 429 on every rate-limited restore route =====
    // (21) A fresh Approver-roled identity has its per-caller window filled exactly to the cap via the DO's own
    // /rate-check (cost = CAP on a fresh bucket), so the very next mutating request on each route is over the
    // cap. On the apply path the limiter sits AFTER the role gate but BEFORE the dual-control check, so a role-
    // holder needs no approval to reach it; for the dry-run / request / approve / reject paths the limiter sits
    // after the role gate too. Every rate-limited restore route then returns 429 (the limiter-fired arm).
    {
      const RL = "ratelimited-crr@acme.example";
      await call(OWNER, "POST", "/admin/roles", { email: RL, role: "approver" });
      const CAP = RATE_LIMIT_MAX_PER_WINDOW;
      // The bucket key comes from the PRODUCTION deriver, never a literal, so a future move of the rate-limit
      // axis (e.g. off email onto the stable subject, so passkey/oidc/saml/recovery callers do not share the
      // bare token's bucket) cannot silently land the fill in a bucket nothing reads.
      const fill = await sched.stub.fetch("https://scheduler.internal/rate-check", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: rateLimitKey({ subject: subjectOf(RL) } as Caller), cost: CAP }) });
      ok("the cost=CAP fill exactly fills RL's fresh window", ((await fill.json()) as { allowed: boolean }).allowed === true);

      ok("a saturated authorised apply is rate-limited (429)", (await call(RL, "POST", "/admin/restore", { runId: RUN_ID, confirm: true })).status === 429);
      ok("a saturated dry-run is rate-limited (429)", (await call(RL, "POST", "/admin/restore", { runId: RUN_ID })).status === 429);
      ok("a saturated request is rate-limited (429)", (await call(RL, "POST", "/admin/restore/request", { runId: RUN_ID, reason: "rl" })).status === 429);
      ok("a saturated approve is rate-limited (429)", (await call(RL, "POST", "/admin/restore/approve", { planHash })).status === 429);
      ok("a saturated reject is rate-limited (429)", (await call(RL, "POST", "/admin/restore/reject", { planHash })).status === 429);
      ok("a saturated verify is rate-limited (429)", (await call(RL, "POST", "/admin/restore/verify", { runId: RUN_ID })).status === 429);
      ok("a saturated attest is rate-limited (429)", (await call(RL, "POST", "/admin/restore/attest", { runId: RUN_ID })).status === 429);
    }

    // ===== the in-console break-glass restore -- the browser-supplied per-run master path =====
    // A break-glass-only estate (noOpEnv, NO OPERATIONAL_PRIVATE) refuses restore by default; it RESTORES when
    // the operator's browser supplies a valid per-run master it decapsulated locally, and the master reaches
    // NO durable, hashed or audited field. Driven end to end through the
    // production handleAdmin, with fresh maker/checker identities so the ceremony's dual control is genuine.
    {
      // callMaster is `call` plus the OPTIONAL per-run master transport header. The body stays the plain
      // RestoreRequest JSON; the master rides x-downpipes-restore-master, never merged into the body.
      async function callMaster(email: string, path: string, body: unknown, masterB64: string | null, env: Env): Promise<Response> {
        const assertion = await tokenFor(email);
        const headers: Record<string, string> = { "cf-access-jwt-assertion": assertion, "content-type": "application/json" };
        if (masterB64 !== null) headers["x-downpipes-restore-master"] = masterB64;
        if (path === "/admin/restore/request") await notePlanAnchorForRequest(sched.stub.fetch, body);
        return handleAdmin(new Request(`https://engine.example${path}`, { method: "POST", headers, body: JSON.stringify(body) }), env);
      }
      const BG_MAKER: string = "bg-maker-crr@acme.example";
      const BG_CHECKER: string = "bg-checker-crr@acme.example";
      await call(OWNER, "POST", "/admin/roles", { email: BG_MAKER, role: "approver" });
      await call(OWNER, "POST", "/admin/roles", { email: BG_CHECKER, role: "approver" });
      // Clear any usable approval an earlier block left on this plan hash, so a fresh break-glass request is
      // accepted (the DO refuses a new request while a usable approval already exists). Best-effort.
      await call(BG_CHECKER, "POST", "/admin/restore/reject", { planHash }, noOpEnv());

      // (22) POST /restore/capsule serves the run's NON-SECRET master capsule at the read-safe restore.verify
      // floor (a Viewer holds it) even on a break-glass-only estate. The test then plays the browser: openCapsule
      // recovers run A's per-run master with the break-glass private, which never crosses the wire.
      const capR = await call(VIEWER, "POST", "/admin/restore/capsule", { runId: RUN_ID }, noOpEnv());
      const cap = (await capR.json()) as { ok: boolean; masterCapsule: Array<{ fingerprint: string; kemCiphertext: string; sealed: string }>; keyCommitment: string; recordCount: number };
      ok("POST /restore/capsule serves the capsule at the restore.verify floor (Viewer, break-glass-only)", capR.status === 200 && cap.ok === true && cap.masterCapsule.length >= 1 && cap.keyCommitment.length > 0 && cap.recordCount === 3);
      const master = await openCapsule(parseWraps(cap.masterCapsule), parseIdentity(breakGlass.identity), hexDecode(cap.keyCommitment));
      const masterB64 = b64urlEncode(master);
      const masterHex = hexEncode(master);
      ok("the browser recovers a 32-byte per-run master from the served capsule", master.length === 32);

      // (22a) a non-ULID runId on the capsule route is a 400, never a read oracle, like the sibling routes.
      ok("POST /restore/capsule with a dot-segment runId is a 400", (await call(VIEWER, "POST", "/admin/restore/capsule", { runId: "../../evil" }, noOpEnv())).status === 400);

      // (23) the dual-control ceremony is UNCHANGED for a break-glass restore: a fresh request carrying the
      // master (so the re-plan computes REAL cues on the keyless estate, not a benign 0) + a distinct approver.
      const reqR = await callMaster(BG_MAKER, "/admin/restore/request", { runId: RUN_ID, reason: "break-glass restore" }, masterB64, noOpEnv());
      const reqRec = (await reqR.json()) as RestoreApproval;
      ok("the break-glass request re-plans WITH the master: real cues (plannedWrites 3), bound to the plan hash", reqR.status === 200 && reqRec.plannedWrites === 3 && reqRec.planHash === planHash);
      const apR = await call(BG_CHECKER, "POST", "/admin/restore/approve", { planHash }, noOpEnv());
      ok("a distinct approver approves the plan (maker != checker, unchanged)", apR.status === 200 && ((await apR.json()) as RestoreApproval).status === "approved");

      // (24) apply with NO master on the break-glass estate refuses honestly (nothing written, no 500) and
      // RELEASES the reservation, so the retry with the master reuses the same approval (the fail-then-retry UX).
      restoreKV.store.clear();
      const noMaster = await call(BG_MAKER, "POST", "/admin/restore", { runId: RUN_ID, confirm: true }, noOpEnv());
      const noMasterRes = (await noMaster.json()) as RestoreResult;
      ok("apply with NO master on a break-glass estate refuses (ok:false, nothing written, no 500)", noMaster.status === 200 && noMasterRes.ok === false && restoreKV.store.size === 0 && /break-glass-only posture/.test(noMasterRes.reason ?? ""));

      // (25) apply WITH the master succeeds: the verified bytes are written back, the approval is consumed.
      restoreKV.store.clear();
      const withMaster = await callMaster(BG_MAKER, "/admin/restore", { runId: RUN_ID, confirm: true }, masterB64, noOpEnv());
      const withMasterRes = (await withMaster.json()) as RestoreResult;
      let bytesMatch = restoreKV.store.size === 3;
      for (const [name, v] of Object.entries(KVSET)) if (new TextDecoder().decode(restoreKV.store.get(name)!) !== v) bytesMatch = false;
      ok("apply WITH a valid master restores every record on the break-glass estate, bytes matching", withMaster.status === 200 && withMasterRes.ok === true && withMasterRes.recordsRestored === 3 && bytesMatch);

      // (26) THE CUSTODY ORACLE. After a successful master-restore, NO Durable Object stored value carries the
      // master: not the approval record, not any audit event, not a stamp. Scan EVERY stored value (list with an
      // empty prefix returns all keys) for the master's base64url AND its hex; both must be absent. The
      // restore-apply success audit for this run proves the scan is over real, populated state (not vacuous).
      const all = await sched.storage.list<unknown>({});
      let masterInStorage = false;
      for (const [, v] of all) {
        const s = JSON.stringify(v);
        if (s.includes(masterB64) || s.includes(masterHex)) masterInStorage = true;
      }
      const applyAudited = (await readAudit("action=restore-apply&outcome=success")).some((e) => (e.target as { runId?: string }).runId === RUN_ID);
      ok("the DO holds populated restore state (the apply was audited), so the custody scan is not vacuous", all.size > 0 && applyAudited);
      ok("CUSTODY: the master appears in NO Durable Object write (approval, audit, stamp), never persisted", masterInStorage === false);

      // (27) a MALFORMED master header is a plain 400 (never a 500), before the role gate. Two shapes: not
      // base64url, and a valid-base64url value of the WRONG length (96 bytes is the break-glass private's size).
      ok("a non-base64url master header is a 400", (await callMaster(BG_MAKER, "/admin/restore", { runId: RUN_ID, confirm: true }, "not valid base64!!", noOpEnv())).status === 400);
      ok("a wrong-length master header (96 bytes, the private's length) is a 400", (await callMaster(BG_MAKER, "/admin/restore", { runId: RUN_ID, confirm: true }, b64urlEncode(new Uint8Array(96).fill(1)), noOpEnv())).status === 400);
    }
  } finally {
    globalThis.fetch = realFetch;
  }

  console.log(failures === 0 ? "\nVALIDATE-COV-ADMIN-ROUTER-RESTORE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
