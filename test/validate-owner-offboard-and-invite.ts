// Two follow-ups to the two-Owner removal rule, driven through the real SchedulerDO (on MockStorage), the real
// handleAdmin router and the real SCIM facade, with real passkeys, step-up and CSRF.
//
//   Part 1: a SCIM deprovision of an Owner while another Owner exists demotes them to viewer (it does not
//           delete them), ends their live session at once, writes an audit row that names the SCIM actor,
//           and raises the scim-owner-demoted alert (warning) to an all-events webhook. With one Owner the
//           SCIM offboard of that Owner is refused, as before, and a non-Owner is still removed.
//   Part 2: the Owner who issued an Owner invite nobody has accepted may withdraw it inline, audited, while
//           two Owners are counted. Somebody else's invite, and an accepted invite, still queue for a second
//           Owner.
//
// The assertions state the intended outcome, so the file is red before the change and green after it.

import { APPROVAL_MIN_DWELL_MS } from "../src/admin/approvals.ts";
import { CHANGE_PREFIX } from "../src/admin/change-control.ts";
import { SCIM_OFFBOARD_EMAIL } from "../src/admin/identity.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { handleScim } from "../src/admin/scim.ts";
import { CSRF_COOKIE_NAME } from "../src/admin/session.ts";
import type { Env } from "../src/env.d.ts";
import { dohReply } from "./lib/doh-stub.ts";
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
const MEMBER = "carol@acme.example";
const CSRF_VALUE = "csrf-s15b-value";
const SCIM_TOKEN = "scim-s15b-bearer-token";
const HOOK_URL = "https://hooks.example.com/all-events";

// The only network this file allows: DoH answers for the send-time screen, and the one webhook, recorded.
const hookPosts: string[] = [];
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const doh = dohReply(input);
  if (doh !== null) return doh;
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  if (url === HOOK_URL) {
    hookPosts.push(typeof init?.body === "string" ? init.body : "");
    return new Response("ok", { status: 200 });
  }
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
    if (Array.isArray(v)) parsed = { list: v };
    else if (v !== null && typeof v === "object") parsed = v as Record<string, unknown>;
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

type Estate = { env: Env; storage: MockStorage; keyA: Authenticator; cookieA: string };

// oneOwnerEstate stands up Owner A alone on a passkey, with SCIM configured.
async function oneOwnerEstate(): Promise<Estate> {
  const { env, storage } = makeScheduler();
  (env as unknown as { SCIM_BEARER_TOKEN: string }).SCIM_BEARER_TOKEN = SCIM_TOKEN;
  const keyA = await makeAuthenticator("ES256");
  if ((await enrolBootstrapOwner(env, keyA, OWNER_A)).status !== 200) throw new Error("bootstrap of Owner A failed");
  return { env, storage, keyA, cookieA: await signIn(env, keyA, OWNER_A) };
}

async function roleNow(e: Estate, email: string): Promise<string | null> {
  const r = await admin(e.env, "GET", "/roles", e.cookieA);
  const list = (r.body.list ?? []) as Array<{ email?: string; role?: string }>;
  return list.find((x) => x.email === email)?.role ?? null;
}

async function auditEvents(e: Estate): Promise<Array<Record<string, unknown>>> {
  const r = await admin(e.env, "GET", "/audit?limit=200", e.cookieA);
  return (r.body.events ?? []) as Array<Record<string, unknown>>;
}

async function scimDelete(env: Env, email: string): Promise<number> {
  const tasks: Promise<unknown>[] = [];
  const req = new Request(`https://engine.example/scim/v2/Users/${encodeURIComponent(email)}`, { method: "DELETE", headers: { authorization: `Bearer ${SCIM_TOKEN}` } });
  const resp = await handleScim(req, env, (t) => tasks.push(t));
  await Promise.all(tasks);
  return resp.status;
}

// ---------------------------------------------------------------------------------------------------------
console.log("\nPart 1: SCIM offboard of an Owner while another Owner exists");
{
  const e = await oneOwnerEstate();
  const keyB = await makeAuthenticator("ES256");
  const invite = await grantRoleViaToken(e.env, OWNER_B, "owner");
  if ((await enrolByInvite(e.env, keyB, OWNER_B, invite)) !== 200) throw new Error("enrolment of Owner B failed");
  const cookieB = await signIn(e.env, keyB, OWNER_B);
  const channel = await admin(e.env, "POST", "/notify/channels", e.cookieA, { kind: "webhook", name: "All events", url: HOOK_URL }, await freshStepUp(e.env, e.keyA, e.cookieA));
  const channelId = typeof channel.body.id === "string" ? channel.body.id : "";
  const rule = await admin(e.env, "POST", "/notify/rules", e.cookieA, { scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: [channelId], enabled: true }, await freshStepUp(e.env, e.keyA, e.cookieA));
  note(`all-events webhook channel: ${channel.status}, rule: ${rule.status}`);
  check("B's session works before the offboard", (await admin(e.env, "GET", "/whoami", cookieB)).status === 200);

  hookPosts.length = 0;
  const status = await scimDelete(e.env, OWNER_B);
  check(`the SCIM deprovision answers 204 [got ${status}]`, status === 204);
  check("B is demoted to viewer, not deleted", (await roleNow(e, OWNER_B)) === "viewer");
  const whoB = await admin(e.env, "GET", "/whoami", cookieB);
  check(`B's existing session is refused after the offboard [got ${whoB.status}]`, whoB.status === 401);
  const row = (await auditEvents(e)).find((ev) => ev.action === "role-change" && (ev.target as { email?: string } | undefined)?.email === OWNER_B && (ev.target as { role?: string }).role === "viewer");
  check("an audit row records the demotion and names the SCIM actor", row !== undefined && row.actorEmail === SCIM_OFFBOARD_EMAIL);
  const alerts = hookPosts.filter((b) => b.includes("scim-owner-demoted"));
  check(`the scim-owner-demoted alert reaches the all-events webhook [posts ${hookPosts.length}]`, alerts.length === 1);
  check("the alert is at warning level", alerts.length === 1 && alerts[0]!.includes("warning"));
  check("A is still an Owner", (await roleNow(e, OWNER_A)) === "owner");
}

console.log("\nPart 1 controls: one Owner, and a non-Owner");
{
  const e = await oneOwnerEstate();
  const status = await scimDelete(e.env, OWNER_A);
  check(`the SCIM offboard of the only Owner is refused, as before (400) [got ${status}]`, status === 400);
  check("the only Owner is still an Owner", (await roleNow(e, OWNER_A)) === "owner");
  await admin(e.env, "POST", "/roles", e.cookieA, { email: MEMBER, role: "operator" }, await freshStepUp(e.env, e.keyA, e.cookieA));
  const memberStatus = await scimDelete(e.env, MEMBER);
  check(`a non-Owner is still removed by SCIM (204) [got ${memberStatus}]`, memberStatus === 204);
  check("the non-Owner's grant is gone", (await roleNow(e, MEMBER)) === null);
}

// ---------------------------------------------------------------------------------------------------------
console.log("\nPart 2a: the issuer withdraws their own Owner invite inline");
{
  const e = await oneOwnerEstate();
  const grant = await admin(e.env, "POST", "/roles", e.cookieA, { email: OWNER_B, role: "owner" }, await freshStepUp(e.env, e.keyA, e.cookieA));
  note(`A invites B as Owner: ${grant.status}`);
  check("B's invite is pending and counts as an Owner", (await roleNow(e, OWNER_B)) === "owner");
  const withdraw = await admin(e.env, "POST", "/roles/delete", e.cookieA, { email: OWNER_B }, await freshStepUp(e.env, e.keyA, e.cookieA));
  check(`A withdraws their own invite inline (200) [got ${withdraw.status}]`, withdraw.status === 200 && withdraw.body.deleted === true);
  check("the invite is gone", (await roleNow(e, OWNER_B)) === null);
  const row = (await auditEvents(e)).find((ev) => ev.action === "role-change" && (ev.target as { email?: string } | undefined)?.email === OWNER_B && (ev.target as { role?: string }).role === "viewer");
  check("the withdrawal is audited with A as the actor", row !== undefined && row.actorEmail === OWNER_A);
}

console.log("\nPart 2b: somebody else's invite still queues");
{
  const e = await oneOwnerEstate();
  await grantRoleViaToken(e.env, OWNER_B, "owner"); // issued by the break-glass token, not by A
  const withdraw = await admin(e.env, "POST", "/roles/delete", e.cookieA, { email: OWNER_B }, await freshStepUp(e.env, e.keyA, e.cookieA));
  check(`A's delete of an invite A did not issue is queued (202) [got ${withdraw.status}]`, withdraw.status === 202);
  check("the invite is still there", (await roleNow(e, OWNER_B)) === "owner");
}

console.log("\nPart 2c: an accepted invite is not an invite");
{
  const e = await oneOwnerEstate();
  const keyB = await makeAuthenticator("ES256");
  const grant = await admin(e.env, "POST", "/roles", e.cookieA, { email: OWNER_B, role: "owner" }, await freshStepUp(e.env, e.keyA, e.cookieA));
  const invite = typeof grant.body.inviteToken === "string" ? grant.body.inviteToken : "";
  check("B accepts the invite and signs in", (await enrolByInvite(e.env, keyB, OWNER_B, invite)) === 200 && (await signIn(e.env, keyB, OWNER_B)).length > 0);
  const withdraw = await admin(e.env, "POST", "/roles/delete", e.cookieA, { email: OWNER_B }, await freshStepUp(e.env, e.keyA, e.cookieA));
  const changeId = typeof withdraw.body.id === "string" ? withdraw.body.id : null;
  check(`A's delete of the accepted Owner is queued (202) [got ${withdraw.status}]`, withdraw.status === 202 && changeId !== null);
  check("B is still an Owner", (await roleNow(e, OWNER_B)) === "owner");
  if (changeId !== null) {
    ageRecord(e.storage, `${CHANGE_PREFIX}${changeId}`, "proposedAt", APPROVAL_MIN_DWELL_MS + 1000);
    const self = await admin(e.env, "POST", `/config/changes/${changeId}/approve`, e.cookieA, {}, await freshStepUp(e.env, e.keyA, e.cookieA));
    check(`A cannot approve it alone [got ${self.status}]`, self.status !== 200);
  }
}

verdictReached(failures);
console.log(failures === 0 ? "\nvalidate-owner-offboard-and-invite: PASS" : `\nvalidate-owner-offboard-and-invite: FAIL (${failures})`);
if (failures > 0) process.exitCode = 1;
