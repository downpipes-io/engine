// The two-Owner high-blast gate must hold against the Owner it exists to check.
//
// With two Owners, an IdP connection change is a high-blast owner action: effectiveOwnerActionGateOn queues it
// for a second Owner even while requireConfigApproval is off. This validator drives the real SchedulerDO (on
// MockStorage) through the real handleAdmin router, with real passkeys, step-up and CSRF, and asserts that
// ONE Owner acting alone cannot get an IdP connection created:
//
//   Part 1: by changing the other Owner's role first (demote to viewer, operator or access-admin, or delete
//           them), then creating the connection.
//   Part 2: by taking over the other Owner's identity (revoke their factors, demote them to receive their
//           enrolment invite, enrol a second key as them, re-promote them) and approving their own proposal
//           as that Owner. No approval record may name the other Owner as approver.
//
// Each case runs on a fresh estate. The assertions state the SAFE outcome, so the file is red while one Owner
// can defeat the gate and green once it cannot. A control case first proves the gate is armed at all.

import { APPROVAL_MIN_DWELL_MS } from "../src/admin/approvals.ts";
import { CHANGE_PREFIX } from "../src/admin/change-control.ts";
import { OWNER_ACTION_PREFIX } from "../src/admin/owner-action.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { CSRF_COOKIE_NAME } from "../src/admin/session.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { ageRecord } from "./testutil.ts";
import {
  type Authenticator,
  buildAttestation,
  challengeFor,
  challengeIdFor,
  enrolBootstrapOwner,
  extractSessionCookie,
  grantRoleViaToken,
  loginBegin,
  loginFinish,
  type MockStorage,
  makeAuthenticator,
  makeScheduler,
  ORIGIN,
  registerBegin,
  registerFinish,
  signAssertion,
} from "./validate-passkey-harness.ts";

const OWNER_A = "alice@acme.example";
const OWNER_B = "bob@acme.example";
const CSRF_VALUE = "csrf-s15-value";

// No live network: any fetch is a test fault.
globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  throw new Error(`unexpected network fetch in test: ${url}`);
}) as typeof fetch;

let failures = 0;
function check(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function note(label: string): void {
  console.log(`  ..   ${label}`);
}

type Reply = { status: number; body: Record<string, unknown> };

async function admin(env: Env, method: string, path: string, cookie: string, body?: unknown, stepUp?: string): Promise<Reply> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    cookie: `${cookie}; ${CSRF_COOKIE_NAME}=${CSRF_VALUE}`,
    "x-downpipes-csrf": CSRF_VALUE,
    origin: ORIGIN,
    "CF-Connecting-IP": "198.51.100.23",
  };
  if (stepUp !== undefined) headers["x-downpipes-stepup"] = stepUp;
  const init: RequestInit = body === undefined ? { method, headers } : { method, headers, body: JSON.stringify(body) };
  const resp = await handleAdmin(new Request(`https://engine.example/admin${path}`, init), env);
  const text = await resp.text();
  let parsed: Record<string, unknown> = {};
  try {
    const v = JSON.parse(text) as unknown;
    if (v !== null && typeof v === "object") parsed = v as Record<string, unknown>;
  } catch {
    parsed = { text };
  }
  return { status: resp.status, body: parsed };
}

async function signIn(env: Env, key: Authenticator, email: string): Promise<string> {
  const begin = await loginBegin(env, email);
  const assertion = await signAssertion(key, challengeFor(begin));
  key.signCount++;
  const finish = await loginFinish(env, challengeIdFor(begin), assertion);
  const cookie = extractSessionCookie(finish.setCookie);
  if (finish.status !== 200 || cookie === null) throw new Error(`sign-in failed for ${email}: ${finish.status}`);
  return cookie;
}

// freshStepUp performs a passkey step-up for the session and returns the step-up token for the next write.
async function freshStepUp(env: Env, key: Authenticator, cookie: string): Promise<string> {
  const begin = await admin(env, "POST", "/stepup/begin", cookie, {});
  const pk = begin.body.publicKey as { challenge?: string } | undefined;
  if (begin.status !== 200 || typeof pk?.challenge !== "string") throw new Error(`step-up begin failed: ${begin.status}`);
  const assertion = await signAssertion(key, pk.challenge);
  key.signCount++;
  const finish = await admin(env, "POST", "/stepup/finish", cookie, { challengeId: begin.body.challengeId, credential: assertion });
  if (finish.status !== 200 || typeof finish.body.stepUpToken !== "string") throw new Error(`step-up finish failed: ${finish.status}`);
  return finish.body.stepUpToken;
}

async function enrolByInvite(env: Env, key: Authenticator, email: string, inviteToken: string): Promise<number> {
  const begin = await registerBegin(env, email, { inviteToken, origin: ORIGIN });
  if (begin.status !== 200) return begin.status;
  const att = await buildAttestation(key, challengeFor(begin));
  return (await registerFinish(env, email, att, { inviteToken, origin: ORIGIN })).status;
}

function idpCreateBody(id: string): Record<string, unknown> {
  return {
    proposal: {
      id,
      kind: "oidc",
      label: `connection ${id}`,
      presetId: "entra",
      enabled: true,
      issuer: "https://login.microsoftonline.com/TENANTID/v2.0",
      clientId: "client-s15",
      secretRef: { mode: "do-plaintext" },
      scopes: ["openid", "email", "profile"],
      idTokenSigAlgs: ["RS256"],
      pkce: "required",
      clientAuth: "client_secret_post",
      requireNonce: true,
    },
  };
}

type Estate = { env: Env; storage: MockStorage; keyA: Authenticator; keyB: Authenticator; cookieA: string; cookieB: string };

// twoOwnerEstate stands up an estate with two genuine Owners, each on their own passkey, gate toggle off.
async function twoOwnerEstate(): Promise<Estate> {
  const { env, storage } = makeScheduler();
  const keyA = await makeAuthenticator("ES256");
  const keyB = await makeAuthenticator("ES256");
  if ((await enrolBootstrapOwner(env, keyA, OWNER_A)).status !== 200) throw new Error("bootstrap of Owner A failed");
  const invite = await grantRoleViaToken(env, OWNER_B, "owner");
  if ((await enrolByInvite(env, keyB, OWNER_B, invite)) !== 200) throw new Error("enrolment of Owner B failed");
  const cookieA = await signIn(env, keyA, OWNER_A);
  const cookieB = await signIn(env, keyB, OWNER_B);
  const policy = await admin(env, "GET", "/config/approval-policy", cookieA);
  if (policy.body.requireConfigApproval !== false) throw new Error("expected requireConfigApproval off by default");
  return { env, storage, keyA, keyB, cookieA, cookieB };
}

async function connectionIds(e: Estate): Promise<string[]> {
  const r = await admin(e.env, "GET", "/idp/connections", e.cookieA);
  const list = (r.body.connections ?? []) as Array<{ id?: string }>;
  return list.map((c) => String(c.id));
}

function ownerActionRecords(storage: MockStorage): Array<Record<string, unknown>> {
  return storage.rawKeys(OWNER_ACTION_PREFIX).map((k) => storage.rawGet<Record<string, unknown>>(k) ?? {});
}

// ---------------------------------------------------------------------------------------------------------
console.log("\nControl: two Owners, Owner A alone creates an IdP connection");
{
  const e = await twoOwnerEstate();
  const r = await admin(e.env, "POST", "/idp/connections", e.cookieA, idpCreateBody("control-conn"), await freshStepUp(e.env, e.keyA, e.cookieA));
  check(`the create is queued for a second Owner (202) [got ${r.status}]`, r.status === 202);
  check("the connection is not stored on Owner A alone", !(await connectionIds(e)).includes("control-conn"));
}

// ---------------------------------------------------------------------------------------------------------
// Part 1. Each move changes Owner B's role, then Owner A creates a connection alone.
type Move = { name: string; path: string; body: Record<string, unknown> };
const moves: Move[] = [
  { name: "demote B to viewer", path: "/roles", body: { email: OWNER_B, role: "viewer" } },
  { name: "demote B to operator", path: "/roles", body: { email: OWNER_B, role: "operator" } },
  { name: "demote B to access-admin", path: "/roles", body: { email: OWNER_B, role: "access-admin" } },
  { name: "delete B's role", path: "/roles/delete", body: { email: OWNER_B } },
];
for (const move of moves) {
  console.log(`\nPart 1 (${move.name}): Owner A alone, then an IdP create`);
  const e = await twoOwnerEstate();
  const connId = `p1-${move.name.replace(/[^a-z]+/g, "-")}`.slice(0, 60);
  const step = await admin(e.env, "POST", move.path, e.cookieA, move.body, await freshStepUp(e.env, e.keyA, e.cookieA));
  note(`${move.name}: ${step.status}`);
  const create = await admin(e.env, "POST", "/idp/connections", e.cookieA, idpCreateBody(connId), await freshStepUp(e.env, e.keyA, e.cookieA));
  note(`IdP create after the move: ${create.status}`);
  check(`the IdP create is queued for a second Owner, not applied inline on Owner A alone (202) [got ${create.status}]`, create.status === 202 && create.body.ownerActionQueued === true);
  check("the connection is not stored on Owner A alone", !(await connectionIds(e)).includes(connId));
}

// ---------------------------------------------------------------------------------------------------------
// Part 2. Owner A takes over Owner B's identity and approves their own proposal as B.
console.log("\nPart 2: revoke B, demote B, enrol as B, re-promote B, approve as B");
{
  const e = await twoOwnerEstate();
  const keyX = await makeAuthenticator("ES256"); // Owner A's second key, enrolled under B's email
  const connId = "p2-takeover-conn";

  const revoke = await admin(e.env, "POST", "/signin-factors/revoke", e.cookieA, { email: OWNER_B }, await freshStepUp(e.env, e.keyA, e.cookieA));
  note(`revoke B's factors: ${revoke.status}`);
  const demote = await admin(e.env, "POST", "/roles", e.cookieA, { email: OWNER_B, role: "viewer" }, await freshStepUp(e.env, e.keyA, e.cookieA));
  const invite = typeof demote.body.inviteToken === "string" ? demote.body.inviteToken : null;
  note(`demote B: ${demote.status}, invite token returned to A: ${invite !== null}`);

  let cookieAsB: string | null = null;
  if (invite !== null) {
    const enrol = await enrolByInvite(e.env, keyX, OWNER_B, invite);
    note(`A enrols a key as B: ${enrol}`);
    if (enrol === 200) cookieAsB = await signIn(e.env, keyX, OWNER_B);
  }
  const promote = await admin(e.env, "POST", "/roles", e.cookieA, { email: OWNER_B, role: "owner" }, await freshStepUp(e.env, e.keyA, e.cookieA));
  note(`re-promote B: ${promote.status}`);

  const propose = await admin(e.env, "POST", "/idp/connections", e.cookieA, idpCreateBody(connId), await freshStepUp(e.env, e.keyA, e.cookieA));
  note(`A proposes the IdP create: ${propose.status}`);
  const actionId = typeof propose.body.id === "string" ? propose.body.id : null;

  if (propose.status === 202 && actionId !== null && cookieAsB !== null) {
    ageRecord(e.storage, OWNER_ACTION_PREFIX + actionId, "proposedAt", APPROVAL_MIN_DWELL_MS + 1000);
    const approve = await admin(e.env, "POST", `/owner-actions/${actionId}/approve`, cookieAsB, {}, await freshStepUp(e.env, keyX, cookieAsB));
    note(`approve as B (A's key): ${approve.status} ${String(approve.body.status ?? "")}`);
  }

  const forged = ownerActionRecords(e.storage).filter((r) => r.proposedBy === OWNER_A && r.approvedBy === OWNER_B);
  check(`no owner-action approval proposed by A names B as approver [found ${forged.length}]`, forged.length === 0);
  check("the connection is not stored", !(await connectionIds(e)).includes(connId));
  // The same outcome without the approval: if the propose ran inline, the connection check above catches it.
}

// ---------------------------------------------------------------------------------------------------------
// The cases below pin the shape of the fix: a removal of an Owner is QUEUED for a second Owner, a second Owner
// can approve it, a lone Owner and an access-admin cannot, and the one-Owner case is unchanged.

async function listRoles(env: Env, cookie: string): Promise<Array<{ email?: string; role?: string }>> {
  const headers = { cookie: `${cookie}; ${CSRF_COOKIE_NAME}=${CSRF_VALUE}`, origin: ORIGIN, "CF-Connecting-IP": "198.51.100.23" };
  const resp = await handleAdmin(new Request("https://engine.example/admin/roles", { method: "GET", headers }), env);
  const v = (await resp.json()) as unknown;
  return Array.isArray(v) ? (v as Array<{ email?: string; role?: string }>) : [];
}

async function roleNow(env: Env, cookie: string, email: string): Promise<string | null> {
  return (await listRoles(env, cookie)).find((x) => x.email === email)?.role ?? null;
}

console.log("\nPart 3: two Owners agree to drop to one (A proposes, B approves)");
{
  const e = await twoOwnerEstate();
  const propose = await admin(e.env, "POST", "/roles", e.cookieA, { email: OWNER_B, role: "viewer" }, await freshStepUp(e.env, e.keyA, e.cookieA));
  const changeId = typeof propose.body.id === "string" ? propose.body.id : null;
  check(`the demotion is queued (202) with a change id [got ${propose.status}]`, propose.status === 202 && changeId !== null && propose.body.queued === true);
  check("the queued demotion carries no invite token", propose.body.inviteToken === undefined);
  check("B is still an Owner while the demotion waits", (await roleNow(e.env, e.cookieA, OWNER_B)) === "owner");
  if (changeId !== null) {
    ageRecord(e.storage, `${CHANGE_PREFIX}${changeId}`, "proposedAt", APPROVAL_MIN_DWELL_MS + 1000);
    const self = await admin(e.env, "POST", `/config/changes/${changeId}/approve`, e.cookieA, {}, await freshStepUp(e.env, e.keyA, e.cookieA));
    check(`A cannot approve their own proposal: refused by maker != checker [got ${self.status}]`, self.status === 400 && self.body.error === "cannot approve your own change");
    const approve = await admin(e.env, "POST", `/config/changes/${changeId}/approve`, e.cookieB, {}, await freshStepUp(e.env, e.keyB, e.cookieB));
    check(`B (the target) approves their own removal [got ${approve.status}]`, approve.status === 200);
  }
  check("B is a viewer after the approval", (await roleNow(e.env, e.cookieA, OWNER_B)) === "viewer");
  const create = await admin(e.env, "POST", "/idp/connections", e.cookieA, idpCreateBody("p3-after-agreed"), await freshStepUp(e.env, e.keyA, e.cookieA));
  check(`with one Owner left the high-blast gate stays out, as before (200) [got ${create.status}]`, create.status === 200);
}

console.log("\nPart 4: an access-admin cannot be the second approver of an Owner removal");
{
  const e = await twoOwnerEstate();
  const OTHER = "carol@acme.example";
  const keyC = await makeAuthenticator("ES256");
  const grant = await admin(e.env, "POST", "/roles", e.cookieA, { email: OTHER, role: "access-admin" }, await freshStepUp(e.env, e.keyA, e.cookieA));
  note(`A grants an access-admin alone: ${grant.status}`);
  const invite = typeof grant.body.inviteToken === "string" ? grant.body.inviteToken : null;
  let cookieC: string | null = null;
  if (invite !== null && (await enrolByInvite(e.env, keyC, OTHER, invite)) === 200) cookieC = await signIn(e.env, keyC, OTHER);
  check("the access-admin is signed in (the setup worked)", cookieC !== null);
  const propose = await admin(e.env, "POST", "/roles/delete", e.cookieA, { email: OWNER_B }, await freshStepUp(e.env, e.keyA, e.cookieA));
  const changeId = typeof propose.body.id === "string" ? propose.body.id : null;
  check(`the delete of Owner B is queued (202) [got ${propose.status}]`, propose.status === 202 && changeId !== null);
  if (changeId !== null && cookieC !== null) {
    ageRecord(e.storage, `${CHANGE_PREFIX}${changeId}`, "proposedAt", APPROVAL_MIN_DWELL_MS + 1000);
    const approve = await admin(e.env, "POST", `/config/changes/${changeId}/approve`, cookieC, {}, await freshStepUp(e.env, keyC, cookieC));
    check(`the access-admin's approval is refused by the Owner-approver rule [got ${approve.status}]`, approve.status === 400 && /only an Owner may approve a change that removes the Owner role/.test(String(approve.body.error)));
  }
  check("B is still an Owner", (await roleNow(e.env, e.cookieA, OWNER_B)) === "owner");
}

console.log("\nPart 5: a custom-role assignment to an Owner is a demotion and is queued");
{
  const e = await twoOwnerEstate();
  const cr = await admin(e.env, "POST", "/custom-roles", e.cookieA, { name: "s15-reader", label: "Reader", capabilities: ["downpipe.read"], landing: "downpipes" }, await freshStepUp(e.env, e.keyA, e.cookieA));
  note(`custom role created: ${cr.status}`);
  const assign = await admin(e.env, "POST", "/roles", e.cookieA, { email: OWNER_B, customRole: "s15-reader" }, await freshStepUp(e.env, e.keyA, e.cookieA));
  check(`the assignment is queued (202) [got ${assign.status}]`, assign.status === 202);
  check("B is still an Owner", (await roleNow(e.env, e.cookieA, OWNER_B)) === "owner");
}

console.log("\nPart 6: revoking an Owner's sign-in factors while two Owners exist");
{
  const e = await twoOwnerEstate();
  const revoke = await admin(e.env, "POST", "/signin-factors/revoke", e.cookieA, { email: OWNER_B }, await freshStepUp(e.env, e.keyA, e.cookieA));
  check(`the revoke is refused (400) [got ${revoke.status}]`, revoke.status === 400);
  const stillIn = await admin(e.env, "GET", "/whoami", e.cookieB);
  check(`B can still sign in and act [got ${stillIn.status}]`, stillIn.status === 200);
  // The remedy the refusal names: remove the Owner role through a second Owner, then revoke.
  const propose = await admin(e.env, "POST", "/roles", e.cookieA, { email: OWNER_B, role: "viewer" }, await freshStepUp(e.env, e.keyA, e.cookieA));
  const changeId = typeof propose.body.id === "string" ? propose.body.id : null;
  if (changeId !== null) {
    ageRecord(e.storage, `${CHANGE_PREFIX}${changeId}`, "proposedAt", APPROVAL_MIN_DWELL_MS + 1000);
    await admin(e.env, "POST", `/config/changes/${changeId}/approve`, e.cookieB, {}, await freshStepUp(e.env, e.keyB, e.cookieB));
  }
  const after = await admin(e.env, "POST", "/signin-factors/revoke", e.cookieA, { email: OWNER_B }, await freshStepUp(e.env, e.keyA, e.cookieA));
  check(`after the approved demotion the revoke runs (200) [got ${after.status}]`, after.status === 200);
}

console.log("\nPart 7: one Owner, unchanged");
{
  const { env } = makeScheduler();
  const keyA = await makeAuthenticator("ES256");
  if ((await enrolBootstrapOwner(env, keyA, OWNER_A)).status !== 200) throw new Error("bootstrap of Owner A failed");
  const cookieA = await signIn(env, keyA, OWNER_A);
  const selfDemote = await admin(env, "POST", "/roles", cookieA, { email: OWNER_A, role: "viewer" }, await freshStepUp(env, keyA, cookieA));
  check(`the only Owner cannot demote themselves (400, the floor) [got ${selfDemote.status}]`, selfDemote.status === 400);
  const promote = await admin(env, "POST", "/roles", cookieA, { email: OWNER_B, role: "owner" }, await freshStepUp(env, keyA, cookieA));
  check(`the only Owner appoints a second Owner inline (200) [got ${promote.status}]`, promote.status === 200);
  const viewer = await admin(env, "POST", "/roles", cookieA, { email: "dave@acme.example", role: "operator" }, await freshStepUp(env, keyA, cookieA));
  check(`a non-Owner grant stays inline (200) [got ${viewer.status}]`, viewer.status === 200);
  const regrade = await admin(env, "POST", "/roles", cookieA, { email: "dave@acme.example", role: "viewer" }, await freshStepUp(env, keyA, cookieA));
  check(`a non-Owner re-grade stays inline with two Owners (200) [got ${regrade.status}]`, regrade.status === 200);
  check("the re-graded member is a viewer", (await roleNow(env, cookieA, "dave@acme.example")) === "viewer");
}

verdictReached(failures);
console.log(failures === 0 ? "\nvalidate-owner-gate-demote-bypass: PASS" : `\nvalidate-owner-gate-demote-bypass: FAIL (${failures})`);
if (failures > 0) process.exitCode = 1;
