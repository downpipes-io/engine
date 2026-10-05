// validate-session-rotation-on-reauth: signing in again from a browser that already holds a session ends the
// session it presented (ASVS V7.2.4: a new authentication terminates the current session rather than leaving
// two live tokens for one browser).
//
// Driven against the REAL SchedulerDO over MockStorage, the way validate-session.ts drives it, so the tokens
// are minted and verified with the DO's own signing key rather than forged. The passkey mint is proven end to
// end; the recovery and IdP mints call the same revokePresentedSession helper, whose no-op cases are proven
// here directly. Every revocation is paired with a control that stays alive, so a dead token is a decision and
// not a probe that could not verify anything.
//
// WHAT THE SESSION MODEL CAN AND CANNOT DO, stated because the docs state it too: there is no per-session id
// yet, so "end the presented session" is done by bumping the account's epoch, which ends EVERY live session
// for that account. A sign-in from a browser with NO cookie (a second device) bumps nothing, and that is the
// negative control below.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { handleAdmin } from "../src/admin/router.ts";
import type { AdminRuntime } from "../src/admin/router-helpers.ts";
import { oidcTxnSetCookie } from "../src/admin/router-idp-web.ts";
import { SESSION_COOKIE_NAME } from "../src/admin/session.ts";
import type { Env } from "../src/env.d.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

function makeDO() {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const call = async (path: string, body: unknown): Promise<{ status: number; json: Record<string, unknown> }> => {
    const r = await dobj.fetch(new Request(`https://do.internal${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }));
    let json: Record<string, unknown> = {};
    try { json = (await r.json()) as Record<string, unknown>; } catch { json = {}; }
    return { status: r.status, json };
  };
  return { call, storage };
}

const EMAIL = "alice@example.com";
const mint = async (call: ReturnType<typeof makeDO>["call"], body: Record<string, unknown>) => {
  const r = await call("/passkey/session/issue", body);
  if (r.json.ok !== true || typeof r.json.token !== "string") throw new Error(`mint failed: ${r.status} ${JSON.stringify(r.json)}`);
  return r.json.token as string;
};
const verifies = async (call: ReturnType<typeof makeDO>["call"], token: string) => {
  const r = await call("/passkey/session/verify", { token });
  return r.json.ok === true || r.json.verified === true || r.json.verdict === "verified";
};

async function main(): Promise<void> {
  console.log("\nthe presented session is ended by the sign-in that replaces it");
  {
    const { call } = makeDO();
    const a = await mint(call, { email: EMAIL });
    ok("CONTROL: token A verifies once minted", await verifies(call, a));
    const b = await mint(call, { email: EMAIL, priorToken: a });
    ok("a sign-in that presents A mints B, and B verifies", await verifies(call, b));
    ok("...and A no longer verifies (the presented session was ended)", !(await verifies(call, a)));
    ok("the two tokens differ", a !== b);
  }

  console.log("\nnegative control: a sign-in that presents NO session (a second device) ends nothing");
  {
    const { call } = makeDO();
    const a = await mint(call, { email: EMAIL });
    const c = await mint(call, { email: EMAIL });
    ok("A still verifies after a cookie-less sign-in minted C", await verifies(call, a));
    ok("C verifies too", await verifies(call, c));
  }

  console.log("\nno-op cases of the revoke: nothing that does not verify can end a session");
  for (const [label, prior] of [
    ["an absent token", undefined],
    ["an empty token", ""],
    ["a tampered token", null], // filled below
    ["a token from a different account's epoch space (already revoked)", "REVOKED"],
  ] as [string, unknown][]) {
    const { call } = makeDO();
    const a = await mint(call, { email: EMAIL });
    let p: unknown = prior;
    if (prior === null) p = `${a.split(".")[0]}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
    if (prior === "REVOKED") {
      // mint X, then revoke it by presenting it at a sign-in; presenting X AGAIN must bump nothing further
      const x = await mint(call, { email: "bob@example.com" });
      await mint(call, { email: "bob@example.com", priorToken: x });
      const bobAfter = await mint(call, { email: "bob@example.com" });
      p = x;
      await mint(call, { email: "bob@example.com", priorToken: p });
      ok(`${label}: bob's live session survives a re-presentation of the dead one`, await verifies(call, bobAfter));
      continue;
    }
    await mint(call, { email: EMAIL, priorToken: p });
    ok(`${label}: A still verifies (the revoke was a no-op)`, await verifies(call, a));
  }

  // The OIDC / OAuth2 callback edge must forward the presented session cookie as priorToken
  // whether or not the IdP sent the RFC 9207 iss parameter. GitHub and most OAuth2 providers never send iss,
  // and the edge used to forward priorToken only inside the iss branch, so the DO never ended the prior session.
  console.log("\nthe OIDC / OAuth2 callback edge forwards the presented session with and without iss");
  {
    const forwarded: Record<string, unknown>[] = [];
    const stub = {
      async fetch(input: string | Request, init?: RequestInit): Promise<Response> {
        const path = new URL(typeof input === "string" ? input : input.url).pathname;
        if (path === "/idp/oidc/callback" && typeof init?.body === "string") forwarded.push(JSON.parse(init.body) as Record<string, unknown>);
        return new Response(JSON.stringify({ allowed: true, ok: false, reason: "stub" }), { headers: { "content-type": "application/json" } });
      },
    };
    const env = { CONSOLE_ORIGIN: "https://console.example", SCHEDULER: { idFromName: () => "id", get: () => stub } } as unknown as Env;
    const runtime: AdminRuntime = { sealNow: () => {}, waitUntil: (p: Promise<unknown>) => void p.catch(() => {}) };
    const txnCookie = oidcTxnSetCookie("txn-1").split(";")[0] ?? "";
    const callback = async (query: string, withSession: boolean): Promise<Record<string, unknown> | undefined> => {
      const n0 = forwarded.length;
      const cookie = withSession ? `${txnCookie}; ${SESSION_COOKIE_NAME}=tok-A` : txnCookie;
      await handleAdmin(new Request(`https://engine.example/admin/oidc/callback/conn1?${query}`, { headers: { cookie, "CF-Connecting-IP": "203.0.113.9" } }), env, runtime);
      return forwarded.length > n0 ? forwarded[forwarded.length - 1] : undefined;
    };
    const noIss = await callback("code=c1&state=s1", true);
    ok("CONTROL: the callback without iss reached the DO", noIss !== undefined);
    ok("without iss (GitHub, generic OAuth2) the presented session is forwarded as priorToken", noIss?.priorToken === "tok-A");
    ok("without iss no iss field is forwarded", noIss !== undefined && !("iss" in noIss));
    const withIss = await callback("code=c1&state=s1&iss=https%3A%2F%2Fidp.example", true);
    ok("with iss the presented session is forwarded as priorToken", withIss?.priorToken === "tok-A" && withIss?.iss === "https://idp.example");
    const noCookie = await callback("code=c1&state=s1", false);
    ok("negative control: a browser with no session cookie forwards no priorToken", noCookie !== undefined && !("priorToken" in noCookie));
  }

  console.log(failures === 0 ? "\nSESSION ROTATION ON RE-AUTH VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
