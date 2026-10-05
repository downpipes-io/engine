// validate-invite-token-member-only: a registration invite for a member who has enrolled before goes only to
// that member, and an enrolment through an invite is audited and alerted.
//
// THE GAP. A role change mints a registration invite for any address that holds no passkey, and the role
// route handed that token back to the caller. For a first-time grant that is the documented onboarding flow:
// the granting operator copies the set-up link and hands it over. For a member who enrolled before and has
// since lost every factor (or had them revoked), the same response gave the caller a link that enrols a new
// passkey for that member's address. The enrolment itself wrote no audit row of its own and raised no alert.
//
// WHAT THIS FILE CHECKS, against a real Durable Object through the production router:
//   A. a first-time grant still returns its set-up link, and the token is a live invite for that address;
//   B. redeeming that invite writes a passkey-invite-enrol audit row naming the member, and routes a
//      role-change alert; the bootstrap enrolment before it wrote no such row (negative control);
//   C. after the member's factors are revoked, a re-grade returns no token, names why, and still commits;
//   D. with an invite sender configured, the re-grade emails the link to the member only, and the response
//      still carries no token;
//   E. removing the member and granting them again is still a re-grade, not a first-time grant;
//   F. a first-time grant after all of that still returns its link (the withholding is not blanket).
//
// Run: node test/validate-invite-token-member-only.ts

import type { AuditEvent } from "../src/admin/audit.ts";
import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import { PASSKEY_INVITE_PREFIX } from "../src/sched/scheduler-do-base.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import {
  ADMIN_TOKEN,
  buildAttestation,
  challengeFor,
  enrolBootstrapOwner,
  makeAuthenticator,
  makeScheduler,
  ORIGIN,
  registerBegin,
  registerFinish,
} from "./validate-passkey-harness.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const OWNER = "owner-itm@acme.example";
const MEMBER = "member-itm@acme.example";
const NEWCOMER = "newcomer-itm@acme.example";

type Emission = { event?: string; detail?: string };
type Sent = { to?: string; text?: string };

async function main(): Promise<void> {
  const base = makeScheduler();
  const storage = base.storage;
  const inner = base.env.SCHEDULER.get(base.env.SCHEDULER.idFromName("x"));
  // Every notify resolve the router asks the DO for is recorded, so "an alert was routed" is read off the
  // emission itself rather than off a counter another alert could also have bumped.
  const resolves: Emission[] = [];
  const wrapped = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.endsWith("/notify/resolve") && typeof init?.body === "string") {
        try {
          resolves.push(((JSON.parse(init.body) as { emission?: Emission }).emission ?? {}) as Emission);
        } catch {
          // not a resolve body this file can read; nothing recorded
        }
      }
      return inner.fetch(input, init);
    },
  } as unknown as DurableObjectStub;
  const env = { ...base.env, SCHEDULER: { idFromName: () => ({}), get: () => wrapped } } as unknown as Env;
  const sent: Sent[] = [];
  const mailEnv = {
    ...env,
    EMAIL: { send: async (m: Sent): Promise<void> => { sent.push(m); } },
    INVITE_EMAIL_FROM: "invites@acme.example",
  } as unknown as Env;

  const admin = async (e: Env, method: string, path: string, body?: unknown): Promise<{ status: number; text: string; json: Record<string, unknown> }> => {
    const r = await handleAdmin(
      new Request(`https://engine.example${path}`, {
        method,
        headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_TOKEN}`, origin: ORIGIN, "CF-Connecting-IP": "203.0.113.40" },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      }),
      e,
    );
    const text = await r.text();
    let json: Record<string, unknown> = {};
    try {
      json = JSON.parse(text) as Record<string, unknown>;
    } catch {
      json = {};
    }
    return { status: r.status, text, json };
  };
  // The live registration invites in storage, as [token, bound email]. Read from the store the redeem path
  // reads, so "a token in the response" is compared against the tokens that would actually enrol a key.
  const liveInvites = (): Array<[string, string]> => {
    const out: Array<[string, string]> = [];
    for (const [k, v] of storage.raw()) {
      if (!k.startsWith(PASSKEY_INVITE_PREFIX)) continue;
      const rec = v as { email?: string; expiresAt?: number };
      if (typeof rec.expiresAt === "number" && rec.expiresAt > Date.now()) out.push([k.slice(PASSKEY_INVITE_PREFIX.length), String(rec.email)]);
    }
    return out;
  };
  const audit = async (): Promise<AuditEvent[]> => {
    const r = await admin(env, "GET", "/admin/audit?limit=1000");
    return ((r.json as { events?: AuditEvent[] }).events ?? []) as AuditEvent[];
  };
  const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 25));

  // ---- setup: an account with an Owner, so the role table is populated ------------------------------
  const ownerKey = await makeAuthenticator("ES256");
  const boot = await enrolBootstrapOwner(env, ownerKey, OWNER);
  ok("setup: the first Owner enrols over the bootstrap path", boot.json.ok === true && boot.json.bootstrapped === true);

  // ---- A. a first-time grant still returns its set-up link ------------------------------------------
  console.log("\nA. first-time grant");
  const first = await admin(env, "POST", "/admin/roles", { email: MEMBER, role: "operator" });
  const firstToken = typeof first.json.inviteToken === "string" ? first.json.inviteToken : null;
  ok("A1: a first-time grant commits (200)", first.status === 200);
  ok("A2: a first-time grant returns the set-up link token to the granting operator", firstToken !== null && firstToken.length > 0);
  ok("A3: that token is a live invite bound to the member's address", firstToken !== null && liveInvites().some(([t, e]) => t === firstToken && e === MEMBER));

  // ---- B. redeeming the invite is audited and alerted ------------------------------------------------
  console.log("\nB. enrolment through the invite");
  const before = (await audit()).filter((e) => e.action === ("passkey-invite-enrol" as AuditEvent["action"]));
  ok("B0: the bootstrap enrolment wrote no invite-enrolment row (negative control)", before.length === 0);
  const resolvesBefore = resolves.length;
  const memberKey = await makeAuthenticator("ES256");
  const b = await registerBegin(env, MEMBER, { inviteToken: firstToken ?? "" });
  const f = await registerFinish(env, MEMBER, await buildAttestation(memberKey, challengeFor(b)), { inviteToken: firstToken ?? "" });
  await settle();
  ok("B1: the member enrols through the invite", f.json.ok === true && f.json.email === MEMBER && f.json.enrolmentPath === "invite");
  const rows = (await audit()).filter((e) => e.action === ("passkey-invite-enrol" as AuditEvent["action"]));
  const row = rows[0] as (AuditEvent & { target?: { kind?: string; email?: string; role?: string } }) | undefined;
  ok("B2: the enrolment writes exactly one passkey-invite-enrol audit row", rows.length === 1);
  ok("B3: the row names the member as actor and target, with the role the enrolment resolved", row !== undefined && row.actorEmail === MEMBER && row.outcome === "success" && row.target?.kind === "role" && row.target.email === MEMBER && row.target.role === "operator");
  const enrolAlerts = resolves.slice(resolvesBefore).filter((e) => e.event === "role-change" && typeof e.detail === "string" && e.detail.includes(MEMBER) && /invite/i.test(e.detail));
  ok("B4: the enrolment routes a role-change alert naming the member and the invite", enrolAlerts.length === 1);

  // ---- C. revoke every factor, then re-grade: no token to the caller --------------------------------
  console.log("\nC. re-grade of a member whose factors were revoked (no invite sender)");
  const rv = await admin(env, "POST", "/admin/signin-factors/revoke", { email: MEMBER });
  ok("C1: the member's factors are revoked (their passkey is removed)", rv.status === 200 && ((rv.json.revoked as { passkeyCredentials?: number } | undefined)?.passkeyCredentials ?? 0) === 1);
  const regrade = await admin(env, "POST", "/admin/roles", { email: MEMBER, role: "approver" });
  ok("C2: the re-grade commits (200) and names the new role", regrade.status === 200 && regrade.json.role === "approver" && regrade.json.email === MEMBER);
  ok("C3: the re-grade response carries no inviteToken", !("inviteToken" in regrade.json));
  ok("C4: no live invite token appears anywhere in the response body", liveInvites().every(([t]) => !regrade.text.includes(t)));
  ok("C5: the response says the link was withheld", regrade.json.inviteState === "withheld");
  ok("C6: the response tells the operator how the member re-enrols", typeof regrade.json.inviteNotice === "string" && /recovery code/i.test(String(regrade.json.inviteNotice)));

  // ---- D. with an invite sender, the link goes to the member only ------------------------------------
  console.log("\nD. re-grade with an invite sender configured");
  sent.length = 0;
  const mailed = await admin(mailEnv, "POST", "/admin/roles", { email: MEMBER, role: "operator" });
  const mail = sent[0];
  const link = mail?.text?.match(/#\/register\?invite=([A-Za-z0-9_\-%]+)/);
  const mailedToken = link ? decodeURIComponent(link[1]!) : null;
  ok("D1: the re-grade commits (200)", mailed.status === 200 && mailed.json.role === "operator");
  ok("D2: the re-grade response still carries no inviteToken", !("inviteToken" in mailed.json) && liveInvites().every(([t]) => !mailed.text.includes(t)));
  ok("D3: the response says the link was emailed to the member", mailed.json.inviteState === "emailed-to-member");
  ok("D4: exactly one email went out, to the member's own address", sent.length === 1 && mail?.to === MEMBER);
  ok("D5: the emailed link carries a live invite bound to the member", mailedToken !== null && liveInvites().some(([t, e]) => t === mailedToken && e === MEMBER));

  // ---- E. remove and grant again: still a re-grade ---------------------------------------------------
  console.log("\nE. remove the member, then grant them again");
  const del = await admin(env, "POST", "/admin/roles/delete", { email: MEMBER });
  ok("E1: the member is removed", del.status === 200 && del.json.deleted === true);
  const regrant = await admin(env, "POST", "/admin/roles", { email: MEMBER, role: "viewer" });
  ok("E2: the grant after removal commits (200)", regrant.status === 200);
  ok("E3: the grant after removal carries no inviteToken (the address enrolled before)", !("inviteToken" in regrant.json) && liveInvites().every(([t]) => !regrant.text.includes(t)));

  // ---- F. the withholding is not blanket -------------------------------------------------------------
  console.log("\nF. a fresh address still gets its link");
  const fresh = await admin(env, "POST", "/admin/roles", { email: NEWCOMER, role: "viewer" });
  const freshToken = typeof fresh.json.inviteToken === "string" ? fresh.json.inviteToken : null;
  ok("F1: a first-time grant to a new address still returns its set-up link", fresh.status === 200 && freshToken !== null && fresh.json.inviteState === "minted");
  ok("F2: that token is a live invite bound to the new address", freshToken !== null && liveInvites().some(([t, e]) => t === freshToken && e === NEWCOMER));

  console.log(failures === 0 ? "\nINVITE TOKEN MEMBER-ONLY VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exit(1);
}

void main();
