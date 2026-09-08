// Prove the minimal SCIM 2.0 deprovision facade (handleScim, src/admin/scim.ts) end to end:
//
//  PART A (stubbed scheduler): the facade's AUTH + DISPATCH behaviour, with a scheduler stub that records
//  every /roles/delete it receives, so we assert (a) an unset SCIM_BEARER_TOKEN -> 503 with NO offboard
//  attempted; (b) a missing/wrong bearer -> 401 with no offboard; (c) DELETE /scim/v2/Users/<urlencoded
//  email> -> 204 and the stub received { email } DECODED; (d) PATCH active:false -> the same; (e) PATCH
//  active:true -> 400 and NO offboard; (f) a non-PatchOp PATCH -> 400; (g) GET ServiceProviderConfig
//  advertises deprovision-only (patch supported, the rest not); (h) DELETE of an already-absent member is
//  an idempotent 204; (h2) the last-Owner refusal (DO 400) -> SCIM 400 + scim-last-owner-refused; (h3) an
//  unexpected non-200 status (here a 202, which the real DO should never send this caller -
//  SCIM offboarding bypasses the dual-control queue entirely) still fails CLOSED to a 400, NEVER a false
//  204; (h4) any OTHER non-last-Owner refusal lands in the residual scim-offboard-refused bucket, never the
//  last-Owner one; (i) an unknown /scim/v2 path -> 404; (j) the bearer compare is over the SHA-384 of each
//  side (a token that is a prefix of the configured one is rejected, no length oracle).
//
//  PART B (REAL SchedulerDO over in-memory storage): the facade drives the EXISTING audited offboarding.
//  We grant a member via POST /admin/roles, confirm they are listed, then SCIM-DELETE them and confirm
//  they are GONE from the roster AND the per-email session epoch was bumped (live sessions terminated) AND
//  the removal was recorded in the audit chain. Proves the facade reuses the real deleteRole path, not a
//  re-implementation.
//
//  PART C (REAL SchedulerDO, dual control ON): arms "Require Config Approval"
//  via the real /admin/config/approval-policy route, then SCIM-offboards a non-owner member and proves the
//  removal APPLIES IMMEDIATELY (204; the member is gone from the roster; NO pending role-delete change is
//  ever created) - dual control has NO effect on SCIM offboarding at all, closing both the ORIGINAL silent-
//  permanent-400 failure and a stuck, unapprovable pending change from queuing it like a human proposer, which could never be approved because no login flow can
//  ever bind the queue's synthetic proposer subject for the approve-time replay to re-resolve authority
//  from - see isScimOffboardCaller in admin/identity.ts). A companion case proves a TRUE last-Owner SCIM
//  removal, under the SAME armed gate, still refuses outright (deleteRole's own guard runs inside the same
//  direct-apply call) and still records scim-last-owner-refused specifically. Two further checks drive the
//  DO's /roles/delete route DIRECTLY (bypassing the SCIM facade) to prove the bypass is exactly as narrow
//  as intended: a GENUINE, distinct, subject-bound human Owner's role-delete STILL QUEUES (202) under the
//  same gate (dual control is NOT weakened for a real operator), and a caller carrying the SAME email +
//  subject as the SCIM identity but a DIFFERENT method is refused for lack of authority (403) rather than
//  bypassing anything - isScimOffboardCaller requires an EXACT match on all three fields.
//
// Run:
//   node test/validate-scim.ts

import { handleScim } from "../src/admin/scim.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/index.ts";
import { encodeCaller, CALLER_HEADER, SCIM_OFFBOARD_EMAIL, SCIM_OFFBOARD_SUBJECT, type Caller } from "../src/admin/identity.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const SCIM_TOKEN = "scim-test-bearer-token-value";
const PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

// ---- PART A: a recording scheduler stub --------------------------------------------------
// The stub answers exactly the two DO routes the facade touches: /rate-check (always admits, so the
// per-IP gate is a no-op in the test) and /roles/delete (records the body, returns a configurable
// { deleted } verdict or a 400 to exercise the last-Owner refusal arm).
interface RecordingStub {
  deletes: Array<{ email?: string }>;
  delResult: { status: number; body: string };
  signals: string[]; // the bounded auth-signal names the facade recorded via POST /auth-signal
  // EVERY DO path the facade touched, in order. This channel exists so a mutating call the facade makes to a
  // route the stub does not specifically model is never silently swallowed: `rec.deletes.length === 1` alone
  // would only mean "exactly one /roles/delete post", not "exactly one mutation". Recording the paths
  // and asserting the SET closes that: an unrecognised route now has to be named in a test to be tolerated.
  paths: string[];
  stub: DurableObjectStub;
}

// The DO paths this facade is EXPECTED to touch. /rate-check and /auth-signal are infrastructure the facade
// calls on almost every request; anything else is a deprovisioning act and must be accounted for by name.
const INFRA_PATHS = ["/rate-check", "/auth-signal"];
// mutations returns the DO calls that ACT, with the infrastructure and the fail-open notify route removed. An
// assertion about "no offboard was attempted" is only true if this is empty.
function mutations(rec: RecordingStub): string[] {
  return rec.paths.filter((p) => !INFRA_PATHS.includes(p) && !p.includes("/notify"));
}
function recordingScheduler(): RecordingStub {
  const rec: RecordingStub = {
    deletes: [],
    delResult: { status: 200, body: JSON.stringify({ deleted: true }) },
    signals: [],
    paths: [],
    stub: undefined as unknown as DurableObjectStub,
  };
  rec.stub = {
    fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      try {
        rec.paths.push(new URL(u).pathname);
      } catch {
        rec.paths.push(u);
      }
      if (u.endsWith("/rate-check")) {
        return new Response(JSON.stringify({ allowed: true }), { headers: { "content-type": "application/json" } });
      }
      if (u.endsWith("/roles/delete")) {
        const body = init?.body ? (JSON.parse(String(init.body)) as { email?: string }) : {};
        rec.deletes.push(body);
        return new Response(rec.delResult.body, { status: rec.delResult.status, headers: { "content-type": "application/json" } });
      }
      if (u.endsWith("/auth-signal")) {
        // capture the bounded auth-signal the facade records best-effort (scim-unconfigured / -unauthorised /
        // -last-owner-refused) so the tests can assert the deprovision-diagnosis signal without touching the DO.
        const body = init?.body ? (JSON.parse(String(init.body)) as { name?: string }) : {};
        if (typeof body.name === "string") rec.signals.push(body.name);
        return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
      }
      // The fail-open notify route (routeAuthChangeAlert) and any other call: a benign 200.
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
  return rec;
}

function stubEnv(rec: RecordingStub, extra?: Partial<Env>): Env {
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => rec.stub,
  } as unknown as DurableObjectNamespace;
  return { SCHEDULER: namespace, SCIM_BEARER_TOKEN: SCIM_TOKEN, ...extra } as unknown as Env;
}

function scimReq(method: string, path: string, opts?: { bearer?: string | null; body?: unknown }): Request {
  const headers: Record<string, string> = {};
  if (opts?.bearer !== null && opts?.bearer !== undefined) headers.authorization = `Bearer ${opts.bearer}`;
  else if (opts?.bearer === undefined) headers.authorization = `Bearer ${SCIM_TOKEN}`;
  // No CF-Connecting-IP -> the per-IP gate ADMITs (the documented local/validator path), so the stub's
  // /rate-check is not even consulted. The gate's deny arm (a present IP that the rate-check refuses,
  // yielding 429/503) is proven in validate-ratelimit.ts and validate-ratelimit-do.ts, so it is out of
  // scope here.
  if (opts?.body !== undefined) headers["content-type"] = "application/scim+json";
  return new Request(`https://engine.example${path}`, {
    method,
    headers,
    ...(opts?.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
  });
}

// (a) unset bearer secret -> 503, no offboard attempted.
async function testUnsetToken(): Promise<void> {
  const rec = recordingScheduler();
  const env = { SCHEDULER: { idFromName: () => ({}), get: () => rec.stub } } as unknown as Env; // no SCIM_BEARER_TOKEN
  const r = await handleScim(scimReq("DELETE", "/scim/v2/Users/alice%40co", { bearer: "anything" }), env);
  ok("unset SCIM_BEARER_TOKEN -> 503", r.status === 503);
  ok("503 attempted no offboard, and touched NO mutating DO route at all", rec.deletes.length === 0 && mutations(rec).length === 0);
  ok("503 recorded the scim-unconfigured auth-signal", rec.signals.includes("scim-unconfigured"));
}

// (b) missing / wrong bearer -> 401, no offboard.
async function testMissingBearer(): Promise<void> {
  const rec = recordingScheduler();
  const env = stubEnv(rec);
  const noAuth = await handleScim(scimReq("DELETE", "/scim/v2/Users/alice%40co", { bearer: null }), env);
  ok("missing bearer -> 401", noAuth.status === 401);
  const wrong = await handleScim(scimReq("DELETE", "/scim/v2/Users/alice%40co", { bearer: "wrong-token" }), env);
  ok("wrong bearer -> 401", wrong.status === 401);
  ok("401 attempted no offboard, and touched NO mutating DO route at all", rec.deletes.length === 0 && mutations(rec).length === 0);
  ok("401 recorded the scim-unauthorised auth-signal", rec.signals.includes("scim-unauthorised"));
}

// (c) DELETE -> 204 and the stub received the DECODED email.
//
// SCIM-REVOKE: the mutation list is now TWO calls, and asserting the JOINED ORDER rather than a count is the
// point. The revoke MUST precede the role delete: it runs its whole veto before any of its deletes, so going
// first means nothing irreversible happens for a request that was going to be refused. Reversed, the revoke
// would resolve its target from an absent roster entry, read it as a viewer, and never run the Owner floor at
// all. A test that only counted calls would pass on the disarmed order.
async function testDeleteDecodedEmail(): Promise<void> {
  const rec = recordingScheduler();
  const env = stubEnv(rec);
  const r = await handleScim(scimReq("DELETE", "/scim/v2/Users/alice%40co"), env);
  ok("DELETE valid bearer -> 204", r.status === 204);
  ok("DELETE forwarded the decoded email, and issued the revoke BEFORE the role delete and nothing else", rec.deletes.length === 1 && rec.deletes[0]!.email === "alice@co" && mutations(rec).join(",") === "/signin-factors/revoke,/roles/delete");
}

// (d) PATCH active:false -> 204 and the same forwarded email (both PatchOp forms).
async function testPatchInactive(): Promise<void> {
  const rec = recordingScheduler();
  const env = stubEnv(rec);
  const body = { schemas: [PATCH_OP], Operations: [{ op: "replace", path: "active", value: false }] };
  const r = await handleScim(scimReq("PATCH", "/scim/v2/Users/bob%40co", { body }), env);
  ok("PATCH active:false -> 204", r.status === 204);
  ok("PATCH forwarded the decoded email, and issued the revoke BEFORE the role delete and nothing else", rec.deletes.length === 1 && rec.deletes[0]!.email === "bob@co" && mutations(rec).join(",") === "/signin-factors/revoke,/roles/delete");

  // The value-object PatchOp form also deprovisions.
  const rec2 = recordingScheduler();
  const env2 = stubEnv(rec2);
  const body2 = { schemas: [PATCH_OP], Operations: [{ op: "replace", value: { active: false } }] };
  const r2 = await handleScim(scimReq("PATCH", "/scim/v2/Users/carol%40co", { body: body2 }), env2);
  ok("PATCH value-object active:false -> 204", r2.status === 204 && rec2.deletes[0]?.email === "carol@co" && mutations(rec2).join(",") === "/signin-factors/revoke,/roles/delete");
}

// (e) PATCH active:true -> 400, NO offboard.
async function testPatchActiveTrue(): Promise<void> {
  const rec = recordingScheduler();
  const env = stubEnv(rec);
  const body = { schemas: [PATCH_OP], Operations: [{ op: "replace", path: "active", value: true }] };
  const r = await handleScim(scimReq("PATCH", "/scim/v2/Users/dave%40co", { body }), env);
  ok("PATCH active:true -> 400", r.status === 400);
  ok("active:true attempted no offboard, and touched NO mutating DO route", rec.deletes.length === 0 && mutations(rec).length === 0);
}

// (f) a non-PatchOp PATCH -> 400.
async function testNonPatchOp(): Promise<void> {
  const rec = recordingScheduler();
  const env = stubEnv(rec);
  const r = await handleScim(scimReq("PATCH", "/scim/v2/Users/eve%40co", { body: { foo: "bar" } }), env);
  ok("non-PatchOp PATCH -> 400, with no mutating DO route touched", r.status === 400 && rec.deletes.length === 0 && mutations(rec).length === 0);
}

// (g) GET ServiceProviderConfig advertises deprovision-only.
async function testServiceProviderConfig(): Promise<void> {
  const rec = recordingScheduler();
  const env = stubEnv(rec);
  const r = await handleScim(scimReq("GET", "/scim/v2/ServiceProviderConfig"), env);
  ok("GET ServiceProviderConfig -> 200", r.status === 200);
  const spc = (await r.json()) as { patch?: { supported?: boolean }; bulk?: { supported?: boolean }; filter?: { supported?: boolean }; authenticationSchemes?: Array<{ type?: string }> };
  ok("SPC advertises patch supported", spc.patch?.supported === true);
  ok("SPC advertises bulk + filter NOT supported", spc.bulk?.supported === false && spc.filter?.supported === false);
  ok("SPC advertises a bearer auth scheme", Array.isArray(spc.authenticationSchemes) && spc.authenticationSchemes[0]?.type === "oauthbearertoken");
}

// (h) DELETE of an already-absent member is an idempotent 204 (the DO returns { deleted:false }).
async function testIdempotentAbsentDelete(): Promise<void> {
  const rec = recordingScheduler();
  rec.delResult = { status: 200, body: JSON.stringify({ deleted: false }) };
  const env = stubEnv(rec);
  const r = await handleScim(scimReq("DELETE", "/scim/v2/Users/ghost%40co"), env);
  ok("DELETE absent member -> idempotent 204, revoke then role delete", r.status === 204 && rec.deletes.length === 1 && mutations(rec).join(",") === "/signin-factors/revoke,/roles/delete");
}

// (h2) an Owner-floor refusal (DO 400) surfaces as a SCIM 400, not a false 204, and is filed on the
// STRUCTURED CODE rather than on the DO's prose.
//
// deleteRole's guard can refuse with either of TWO distinct sentences: the last-Owner sentence ("would
// remove the last Owner") or the DUAL-CONTROL FLOOR sentence when the raised two-Owner floor fires; the
// second case below covers that DUAL-CONTROL FLOOR sentence, which does not contain the first sentence's
// substring, so both must be filed in the same Owner-floor bucket. The third
// case is the negative control: a refusal that is genuinely NOT the Owner floor must still land in the
// residual bucket, so the test is not simply passing everything.
async function testLastOwnerRefusal(): Promise<void> {
  const rec = recordingScheduler();
  rec.delResult = { status: 400, body: JSON.stringify({ error: "would remove the last Owner", refusal: "owner-floor", ownerFloor: "last-owner" }) };
  const env = stubEnv(rec);
  const r = await handleScim(scimReq("DELETE", "/scim/v2/Users/owner%40co"), env);
  ok("last-Owner refusal -> SCIM 400", r.status === 400);
  ok("last-Owner refusal recorded the scim-last-owner-refused auth-signal", rec.signals.includes("scim-last-owner-refused"));

  // The DUAL-CONTROL FLOOR refusal: same guard, different sentence.
  const rec2 = recordingScheduler();
  rec2.delResult = {
    status: 400,
    body: JSON.stringify({
      error: "dual control (Require Approver) is on and needs at least two Owners so a second Owner can approve a change. Removing or demoting this Owner would leave one, and a lone Owner cannot approve their own changes. Appoint another Owner first, or turn Require Approver off.",
      refusal: "owner-floor",
      ownerFloor: "dual-control-floor",
    }),
  };
  const r2 = await handleScim(scimReq("DELETE", "/scim/v2/Users/owner%40co"), stubEnv(rec2));
  ok("the RAISED dual-control floor also refuses -> SCIM 400", r2.status === 400);
  ok("and it is filed as an Owner-floor refusal despite carrying a different sentence", rec2.signals.includes("scim-last-owner-refused"));
  ok("its sentence does not contain the last-Owner-specific substring", !rec2.delResult.body.includes("would remove the last Owner"));

  // NEGATIVE CONTROL: a 400 that is not the Owner floor must NOT be filed as one.
  const rec3 = recordingScheduler();
  rec3.delResult = { status: 400, body: JSON.stringify({ error: "email required" }) };
  await handleScim(scimReq("DELETE", "/scim/v2/Users/owner%40co"), stubEnv(rec3));
  ok("a refusal with no owner-floor code lands in the residual bucket, not the Owner-floor one", rec3.signals.includes("scim-offboard-do-error-4xx") && !rec3.signals.includes("scim-last-owner-refused"));
}

// (h3) DEFENSIVE: an unexpected status other than 200 (here a 202, which the real DO should never send this
// caller post-HI-07 - SCIM offboarding bypasses the dual-control queue entirely, see isScimOffboardCaller in
// admin/identity.ts) still fails CLOSED to a 400, NEVER treated as a success, and records the residual
// scim-offboard-refused signal, not the (different) last-Owner one. Guards against a future regression
// silently re-treating a non-200 as some kind of success.
async function testUnexpectedStatusFailsClosed(): Promise<void> {
  const rec = recordingScheduler();
  rec.delResult = { status: 202, body: JSON.stringify({ queued: true, id: "chg_01test", status: "pending", contentHash: "deadbeef" }) };
  const env = stubEnv(rec);
  const r = await handleScim(scimReq("DELETE", "/scim/v2/Users/leaver%40co"), env);
  ok("an unexpected 202 fails closed to a 400 (never a false 204)", r.status === 400);
  ok("recorded the residual scim-offboard-refused auth-signal", rec.signals.includes("scim-offboard-refused"));
  ok("did NOT record the (different) last-owner signal", !rec.signals.includes("scim-last-owner-refused"));
}

// (h4) any OTHER hard refusal (defensive: not the exact last-Owner literal) is never misattributed to the
// last-Owner bucket. An HTTP refusal is bucketed by the DO's STATUS CLASS
// (scim-offboard-do-error-4xx = a facade/DO contract drift; -5xx = a DO-side fault, so the leaver was NOT
// removed and the connector will keep retrying), rather than by re-matching the DO's prose - a brittle string
// test that would silently misfile every refusal the day that wording changed. The residual
// scim-offboard-refused bucket remains for a NON-HTTP failure (a fetch throw, so there is no status at all),
// which the 202 case above still exercises.
async function testOtherRefusalNotMisattributed(): Promise<void> {
  const rec = recordingScheduler();
  rec.delResult = { status: 400, body: JSON.stringify({ error: "some other DO-side refusal" }) };
  const env = stubEnv(rec);
  const r = await handleScim(scimReq("DELETE", "/scim/v2/Users/leaver2%40co"), env);
  ok("other refusal -> SCIM 400", r.status === 400);
  ok("other 4xx refusal recorded scim-offboard-do-error-4xx, not last-owner", rec.signals.includes("scim-offboard-do-error-4xx") && !rec.signals.includes("scim-last-owner-refused"));

  // A DO-side 5xx is its OWN class: the deprovision did not happen and the connector will keep retrying.
  const rec5 = recordingScheduler();
  rec5.delResult = { status: 503, body: "unavailable" };
  const r5 = await handleScim(scimReq("DELETE", "/scim/v2/Users/leaver3%40co"), stubEnv(rec5));
  ok("a DO 5xx refusal -> SCIM 400", r5.status === 400);
  ok("a DO 5xx refusal recorded scim-offboard-do-error-5xx", rec5.signals.includes("scim-offboard-do-error-5xx") && !rec5.signals.includes("scim-last-owner-refused"));
}

// (i) an unknown /scim/v2 path -> 404.
async function testUnknownPath(): Promise<void> {
  const rec = recordingScheduler();
  const env = stubEnv(rec);
  const r = await handleScim(scimReq("GET", "/scim/v2/Groups"), env);
  ok("unknown /scim/v2 path -> 404", r.status === 404);
}

// (j) the bearer compare is over SHA-384 of each side: a token that is a PREFIX of the configured one is
// rejected (no length oracle / no prefix accept).
async function testBearerPrefixRejected(): Promise<void> {
  const rec = recordingScheduler();
  const env = stubEnv(rec);
  const prefix = SCIM_TOKEN.slice(0, SCIM_TOKEN.length - 1);
  const r = await handleScim(scimReq("DELETE", "/scim/v2/Users/x%40co", { bearer: prefix }), env);
  ok("a prefix of the configured bearer -> 401, with no mutating DO route touched", r.status === 401 && rec.deletes.length === 0 && mutations(rec).length === 0);
}

async function partA(): Promise<void> {
  console.log("PART A: facade auth + dispatch (stubbed scheduler)");
  await testUnsetToken();
  await testMissingBearer();
  await testDeleteDecodedEmail();
  await testPatchInactive();
  await testPatchActiveTrue();
  await testNonPatchOp();
  await testServiceProviderConfig();
  await testIdempotentAbsentDelete();
  await testLastOwnerRefusal();
  await testUnexpectedStatusFailsClosed();
  await testOtherRefusalNotMisattributed();
  await testUnknownPath();
  await testBearerPrefixRejected();
}

import { MockStorage } from "./mock-storage.ts";

const ADMIN_TOKEN = "scim-e2e-admin-token";

function realEnv(storage: MockStorage): Env {
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return dobj.fetch(new Request(u, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { SCHEDULER: namespace, ADMIN_TOKEN, SCIM_BEARER_TOKEN: SCIM_TOKEN } as unknown as Env;
}

async function admin(env: Env, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
  return handleAdmin(
    new Request(`https://engine.example${path}`, {
      method,
      headers: { authorization: `Bearer ${ADMIN_TOKEN}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    }),
    env,
  );
}

async function partB(): Promise<void> {
  console.log("PART B: end-to-end offboarding through the REAL SchedulerDO");
  const storage = new MockStorage();
  const env = realEnv(storage);
  const email = "leaver@example.com";

  // Grant the member an operator role so there is something to offboard (the break-glass owner stays the
  // only owner, so the last-Owner guard never fires on this member).
  const grant = await admin(env, "POST", "/admin/roles", { email, role: "operator" });
  ok("grant member operator -> 200", grant.status === 200);

  // Confirm they are on the roster (GET /admin/roles returns a bare RoleEntry[] array).
  const before = await admin(env, "GET", "/admin/roles");
  const listBefore = (await before.json()) as Array<{ email?: string }>;
  ok("member is on the roster before SCIM offboard", listBefore.some((e) => e.email === email));

  // Snapshot the session epoch storage key before (absent = 0).
  const epochKey = `sessionEpoch:${email}`;
  const epochBefore = (storage.raw().get(epochKey) as number | undefined) ?? 0;

  // SCIM-DELETE the member (the dedicated bearer, the real facade).
  const del = await handleScim(scimReq("DELETE", `/scim/v2/Users/${encodeURIComponent(email)}`), env);
  ok("SCIM DELETE -> 204", del.status === 204);

  // They are GONE from the roster.
  const after = await admin(env, "GET", "/admin/roles");
  const listAfter = (await after.json()) as Array<{ email?: string }>;
  ok("member is REMOVED from the roster after SCIM offboard", !listAfter.some((e) => e.email === email));

  // The per-email session epoch was bumped (live sessions terminated) -> the offboarding path ran.
  const epochAfter = (storage.raw().get(epochKey) as number | undefined) ?? 0;
  ok("session epoch was bumped (live sessions terminated)", epochAfter > epochBefore);

  // The removal was recorded in the audit chain (a role-change naming the leaver).
  const audit = await admin(env, "GET", "/admin/audit");
  const auditBody = (await audit.json()) as { events?: Array<{ action?: string; target?: { email?: string } }> };
  const events = auditBody.events ?? [];
  ok("offboarding recorded in the audit chain", events.some((e) => e.action === "role-change" && e.target?.email === email));

  // Idempotent: a second SCIM DELETE of the now-absent member is still 204.
  const del2 = await handleScim(scimReq("DELETE", `/scim/v2/Users/${encodeURIComponent(email)}`), env);
  ok("second SCIM DELETE (absent) -> idempotent 204", del2.status === 204);
}

// doReq hits a DO route DIRECTLY (bypassing handleAdmin), mirroring how the support pack's own
// fetchAuthSignals reads the bounded auth-signal aggregate (GET /auth-signals) - there is no /admin route
// for it, since it is an internal DO-to-Worker read, never a caller-facing one.
async function doReq(env: Env, path: string): Promise<Response> {
  const stub = env.SCHEDULER.get(env.SCHEDULER.idFromName("x"));
  return stub.fetch(new Request(`https://scheduler.internal${path}`));
}

// doPost hits a DO route DIRECTLY with a POST + an OPTIONAL hand-built caller header, mirroring PROOF 11 of
// validate-config-change-control-lifecycle.ts ("drive the DO DIRECTLY... to prove the dual-control rules
// live in the DO"). Used below (PART C) to prove the SCIM bypass is exactly as narrow as intended: a caller
// that is not the exact SCIM_OFFBOARD_CALLER identity still goes through the ordinary gated path. Passes
// the url and init as SEPARATE arguments (matching the real DurableObjectStub#fetch(input, init) contract
// and PROOF 11's own call) rather than a single pre-built Request: the local stub in realEnv() only reads
// the url off a Request `input`, and rebuilds `new Request(u, init)` from the SECOND argument, so wrapping
// method/headers/body into one Request object here would silently discard them (init would be undefined).
async function doPost(env: Env, path: string, body: unknown, caller?: Caller): Promise<Response> {
  const stub = env.SCHEDULER.get(env.SCHEDULER.idFromName("x"));
  return stub.fetch(`https://scheduler.internal${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(caller ? { [CALLER_HEADER]: encodeCaller(caller) } : {}) },
    body: JSON.stringify(body),
  });
}

// PART C: dual control ("Require Config Approval") must have NO effect on
// automated SCIM deprovisioning at all - neither a silent-permanent-400 failure nor a
// stuck, unapprovable pending change from queuing it like a
// human proposer (see the file header + isScimOffboardCaller in admin/identity.ts). It must also NOT be
// weakened for a genuine human operator: two control-group checks drive the DO directly to prove that.
async function partC(): Promise<void> {
  console.log("PART C: SCIM offboarding through the REAL SchedulerDO with dual control ON");
  const storage = new MockStorage();
  const env = realEnv(storage);
  const leaver = "gate-on-leaver@example.com";
  const humanOwnerEmail = "human-owner@example.com";
  const humanOwnerSubject = "human-owner-sub";
  const humanTarget = "human-target@example.com";
  const humanTarget2 = "human-target-2@example.com";

  // Bootstrap a REAL, subject-BOUND human Owner (the DO's own first-caller bootstrap, GET /whoami, run
  // before any role exists) so the control-group checks below have a genuinely attributable, roles.write-
  // holding caller distinct from both the SCIM synthetic identity and the bare ADMIN_TOKEN break-glass.
  // isOnlyOwner confirms they are the sole Owner, which the true-last-Owner companion case relies on.
  const bootstrap = await doReq(env, `/whoami?email=${encodeURIComponent(humanOwnerEmail)}&subject=${encodeURIComponent(humanOwnerSubject)}&method=access`);
  ok("bootstrap mints the human Owner -> 200", bootstrap.status === 200);
  const bootstrapBody = (await bootstrap.json()) as { role?: string; isOnlyOwner?: boolean };
  ok("the bootstrapped caller is Owner (sole)", bootstrapBody.role === "owner" && bootstrapBody.isOnlyOwner === true);

  // Grant the remaining members BEFORE arming the gate: the bare ADMIN_TOKEN break-glass is ITSELF an
  // unattributable ("bare-token cannot propose") caller, so a role-set through it would be refused exactly
  // like a human's identical action once dual control is on (the same generic rule this fix does not
  // broaden, see validate-config-change-control-lifecycle.ts) - a real account grants its roster before
  // opting in to dual control, or uses an attributable session afterwards; this harness only has the
  // break-glass caller, so it grants first.
  const grant = await admin(env, "POST", "/admin/roles", { email: leaver, role: "operator" });
  ok("grant gate-on-leaver operator -> 200", grant.status === 200);
  const grantTarget = await admin(env, "POST", "/admin/roles", { email: humanTarget, role: "operator" });
  ok("grant human-target operator -> 200", grantTarget.status === 200);
  const grantTarget2 = await admin(env, "POST", "/admin/roles", { email: humanTarget2, role: "operator" });
  ok("grant human-target-2 operator -> 200", grantTarget2.status === 200);

  // NOW arm the gate via the real, owner-only Settings toggle (applies immediately).
  const arm = await admin(env, "POST", "/admin/config/approval-policy", { requireConfigApproval: true });
  ok("arm requireConfigApproval -> 200", arm.status === 200);

  // THE HI-07 PROOF: SCIM-DELETE while the gate is ON must APPLY IMMEDIATELY (204) - never queue (the
  // regression) and never silently/permanently fail (the original finding).
  const del = await handleScim(scimReq("DELETE", `/scim/v2/Users/${encodeURIComponent(leaver)}`), env);
  ok("SCIM DELETE under dual control -> 204 (applied immediately, not queued)", del.status === 204);

  // The member is GONE from the roster immediately (not left pending).
  const roster = (await (await admin(env, "GET", "/admin/roles")).json()) as Array<{ email?: string }>;
  ok("gate-on-leaver is REMOVED from the roster immediately", !roster.some((e) => e.email === leaver));

  // NO pending role-delete change was EVER created for this removal - proving this is a genuine direct
  // apply, not a queue that happens to auto-resolve (the exact shape of the regression this closes).
  const changes = (await (await admin(env, "GET", "/admin/config/changes")).json()) as Array<{ kind?: string; params?: { email?: string } }>;
  ok("no pending role-delete change was ever created for gate-on-leaver", !changes.some((c) => c.kind === "role-delete" && c.params?.email === leaver));

  // Neither auth-signal bucket fired for a clean, successful removal. recordScimSignal is fire-and-forget
  // (best-effort, never blocks the SCIM response), so flush the microtask/timer queue first (matches
  // validate-cov-sched-scheduler-do-idp.ts).
  await new Promise((resolve) => setTimeout(resolve, 0));
  const sigAfterDelete = (await (await doReq(env, "/auth-signals")).json()) as Record<string, { count: number }>;
  ok("a successful gate-on SCIM removal recorded NO last-owner signal", (sigAfterDelete["scim-last-owner-refused"]?.count ?? 0) === 0);
  ok("a successful gate-on SCIM removal recorded NO residual-refusal signal", (sigAfterDelete["scim-offboard-refused"]?.count ?? 0) === 0);

  // CONTROL GROUP 1 (dual control is NOT weakened for a real operator): a GENUINE, distinct, subject-bound
  // human Owner's role-delete of an ordinary member, driven DIRECTLY at the DO (bypassing the SCIM facade
  // entirely, exactly as the human console path does), STILL QUEUES (202) under the very same armed gate.
  const humanOwnerCaller: Caller = { method: "access", email: humanOwnerEmail, subject: humanOwnerSubject, role: "owner", groups: [] };
  const humanDelete = await doPost(env, "/roles/delete", { email: humanTarget }, humanOwnerCaller);
  ok("a genuine human Owner's role-delete STILL queues under dual control (202)", humanDelete.status === 202);
  const rosterAfterHumanQueue = (await (await admin(env, "GET", "/admin/roles")).json()) as Array<{ email?: string }>;
  ok("human-target is STILL on the roster (queued, not applied)", rosterAfterHumanQueue.some((e) => e.email === humanTarget));

  // CONTROL GROUP 2 (the predicate is EXACT, not just an email/subject match): a caller carrying the SAME
  // email + subject as the SCIM synthetic identity, but a DIFFERENT method ("access" instead of "token") -
  // and even asserting role:"owner" on the caller object itself, which every DO mutation method ignores and
  // re-resolves from its own tables regardless - is refused for lack of authority (403), NOT bypassed and
  // NOT queued: isScimOffboardCaller requires an exact match on method AND email AND subject, and no login
  // flow can ever bind a real grant to this synthetic subject, so this near-miss carries no authority at all.
  const nearMissCaller: Caller = { method: "access", email: SCIM_OFFBOARD_EMAIL, subject: SCIM_OFFBOARD_SUBJECT, role: "owner", groups: [] };
  const nearMissDelete = await doPost(env, "/roles/delete", { email: humanTarget2 }, nearMissCaller);
  ok("the SCIM email+subject under a DIFFERENT method is refused for lack of authority (403), not bypassed", nearMissDelete.status === 403);
  const rosterAfterNearMiss = (await (await admin(env, "GET", "/admin/roles")).json()) as Array<{ email?: string }>;
  ok("human-target-2 is untouched (the near-miss caller applied nothing)", rosterAfterNearMiss.some((e) => e.email === humanTarget2));

  // Companion: a TRUE last-Owner SCIM removal, under the SAME armed gate, still refuses OUTRIGHT (400) even
  // though this path now applies directly rather than queuing - deleteRole's own last-Owner guard runs
  // INSIDE the direct-apply call exactly as it always has - and still records ITS OWN specific signal,
  // proving last-Owner and "bypasses the queue" remain distinct, uncorrelated causes.
  const delOwner = await handleScim(scimReq("DELETE", `/scim/v2/Users/${encodeURIComponent(humanOwnerEmail)}`), env);
  ok("SCIM DELETE of the sole real Owner (gate ON) -> still refused outright (400), not applied", delOwner.status === 400);
  const rosterAfterOwnerAttempt = (await (await admin(env, "GET", "/admin/roles")).json()) as Array<{ email?: string }>;
  ok("the sole real Owner is STILL on the roster (refused, not removed)", rosterAfterOwnerAttempt.some((e) => e.email === humanOwnerEmail));

  await new Promise((resolve) => setTimeout(resolve, 0));
  const sigAfterOwner = (await (await doReq(env, "/auth-signals")).json()) as Record<string, { count: number }>;
  ok("last-Owner refusal recorded scim-last-owner-refused specifically", (sigAfterOwner["scim-last-owner-refused"]?.count ?? 0) > 0);
  ok("last-Owner refusal did NOT also bump the residual scim-offboard-refused bucket", (sigAfterOwner["scim-offboard-refused"]?.count ?? 0) === 0);
}

async function main(): Promise<void> {
  await partA();
  await partB();
  await partC();
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.log(`\nFAILED: ${failures} check(s) failed`);
    process.exit(1);
  }
  console.log("\nAll SCIM facade checks passed.");
}

void main();
