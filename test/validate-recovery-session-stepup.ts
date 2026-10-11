// Proves a session minted by account recovery does NOT satisfy step-up on its own. Run:
//   node test/validate-recovery-session-stepup.ts
//
// A recovery code is one factor, spent to get in. Step-up exists so a session that was merely signed in
// cannot perform a sensitive action without proving a factor again. A recovered session therefore needs a
// fresh passkey assertion (performed after the recovery) before any step-up-gated action, however recent the
// recovery was. Everything the recovery journey itself needs (enrolling a replacement passkey, ending the
// caller's own sessions, confirming the staged codes) stays reachable without a step-up deadlock.
//
// What this proves, over the REAL router and the REAL scheduler DO with in-memory storage:
//  (a) a recovery session is refused a step-up-gated action with 401 {"error":"step-up required"}, the
//      DO's step-up check reads not satisfied, and a re-minted (slid) copy of the same session is refused too;
//  (b) after a fresh passkey assertion on that session, the same action passes once, and the token is single-use;
//  (c) a normal passkey session behaves as before: a fresh login passes, a stale one is refused until it asserts;
//  (d) the recovery session can still enrol a replacement passkey and confirm the staged codes, and the
//      step-up ceremony is reachable from it, so recovery cannot deadlock.
//  (e) on a fake clock, a recovery session enrols a replacement passkey 4 min 59 s after its sign-in, is
//      refused the same enrolment at 5 min 01 s, and a further recovery code gives a new session that can enrol.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, STEPUP_FRESH_MS, signSession, verifySession } from "../src/admin/session.ts";
import { passkeySubject } from "../src/admin/identity.ts";
import type { Env } from "../src/env.d.ts";
import {
  buildAttestation,
  challengeFor,
  enrolBootstrapOwner,
  extractSessionCookie,
  failureCount,
  loginBegin,
  loginFinish,
  makeAuthenticator,
  makeScheduler,
  ok,
  ORIGIN,
  post,
  registerBegin,
  registerFinish,
  signAssertion,
  type Authenticator,
} from "./validate-passkey-harness.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const OWNER = "owner-recovery-stepup@example.com";
const STEPUP_HEADER = "x-downpipes-stepup";

// assertWith signs a challenge and advances the authenticator's counter so the next assertion moves forward.
async function assertWith(auth: Authenticator, challenge: string): ReturnType<typeof signAssertion> {
  const asr = await signAssertion(auth, challenge);
  auth.signCount += 1;
  return asr;
}

type Res = { status: number; json: Record<string, unknown> };

// act drives one authenticated POST through the router with a cookie and an optional step-up token.
async function actRaw(env: Env, path: string, cookie: string, stepUpToken?: string, csrf?: string): Promise<Res> {
  const headers: Record<string, string> = { "content-type": "application/json", origin: ORIGIN, cookie: csrf !== undefined ? `${cookie}; ${CSRF_COOKIE_NAME}=${csrf}` : cookie };
  if (csrf !== undefined) headers["x-downpipes-csrf"] = csrf;
  if (stepUpToken !== undefined) headers[STEPUP_HEADER] = stepUpToken;
  const resp = await handleAdmin(new Request(`https://engine.example${path}`, { method: "POST", body: "{}", headers }), env);
  const text = await resp.text();
  let json: Record<string, unknown> = {};
  try { json = JSON.parse(text) as Record<string, unknown>; } catch { json = { raw: text }; }
  return { status: resp.status, json };
}

const act = actRaw;
const refused = (r: Res): boolean => r.status === 401 && r.json.error === "step-up required" && r.json.stepUpRequired === true;

// freshFactor runs the step-up ceremony on a session with the given authenticator and returns the one-shot token.
async function freshFactor(env: Env, cookie: string, auth: Authenticator): Promise<string | null> {
  const begin = await post(env, "/admin/stepup/begin", {}, { cookie, origin: ORIGIN });
  if (begin.json.ok !== true) return null;
  const asr = await assertWith(auth, begin.json.publicKey!.challenge as string);
  const fin = await post(env, "/admin/stepup/finish", { challengeId: begin.json.challengeId, credential: asr }, { cookie, origin: ORIGIN });
  return fin.json.ok === true && typeof fin.json.stepUpToken === "string" ? fin.json.stepUpToken : null;
}

async function stepUpSatisfied(stub: DurableObjectStub, cookie: string, purpose?: string): Promise<boolean> {
  const token = cookie.slice(`${SESSION_COOKIE_NAME}=`.length);
  const resp = await stub.fetch("https://scheduler.internal/stepup/check", { method: "POST", body: JSON.stringify({ token, ...(purpose !== undefined ? { purpose } : {}) }), headers: { "content-type": "application/json" } });
  return ((await resp.json()) as { satisfied?: boolean }).satisfied === true;
}

async function run(): Promise<void> {
  console.log("validate-recovery-session-stepup: a recovery session needs a fresh factor for step-up");
  const { env, storage, stub } = makeScheduler();
  const inspector = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const GATED = "/admin/posture/accept";

  const authA = await makeAuthenticator("ES256");
  const boot = await enrolBootstrapOwner(env, authA, OWNER);
  const codes = boot.json.recoveryCodes as string[];
  ok("setup: bootstrap enrolment issues recovery codes", boot.json.ok === true && codes.length === 10);

  // ---- (c) normal passkey session: unchanged ---------------------------------------------------------------
  const lb = await loginBegin(env, OWNER);
  const lf = await loginFinish(env, lb.json.challengeId as string, await assertWith(authA, challengeFor(lb)));
  const normal = extractSessionCookie(lf.setCookie);
  ok("(c) setup: a passkey login mints a session", lf.json.ok === true && normal !== null);
  ok("(c) a fresh passkey session passes the gated action without a prompt", !refused(await act(env, GATED, normal!)));
  ok("(c) a fresh passkey session reads step-up satisfied", await stepUpSatisfied(stub, normal!));
  const key = await inspector.sessionSigningKey();
  const staleIat = Date.now() - STEPUP_FRESH_MS - 60_000;
  const staleTok = await signSession(key, { method: "passkey", email: OWNER, subject: passkeySubject(OWNER), epoch: await inspector.getSessionEpoch(OWNER), slide: { iat: staleIat, exp: Date.now() + 3_600_000 } }, Date.now());
  const stale = `${SESSION_COOKIE_NAME}=${staleTok}`;
  ok("(c) a stale passkey session is refused the gated action", refused(await act(env, GATED, stale)));
  const staleTokenStep = await freshFactor(env, stale, authA);
  ok("(c) a stale passkey session passes after a fresh assertion", staleTokenStep !== null && !refused(await act(env, GATED, stale, staleTokenStep)));

  // ---- (a) recovery session is refused ---------------------------------------------------------------------
  const rec = await post(env, "/admin/auth/recovery", { email: OWNER, code: codes[0]! });
  const recCookie = extractSessionCookie(rec.setCookie);
  ok("(a) setup: a recovery code signs in", rec.status === 200 && rec.json.ok === true && recCookie !== null);
  ok("(a) a just-recovered session is refused a step-up-gated action (401 step-up required)", refused(await act(env, GATED, recCookie!)));
  ok("(a) the DO step-up check reads not satisfied for a just-recovered session", (await stepUpSatisfied(stub, recCookie!)) === false);

  // ---- (d) the journey still works without a step-up deadlock -------------------------------------------------
  ok("(d) the recovery session may end its own sessions (end-own-session purpose)", await stepUpSatisfied(stub, recCookie!, "end-own-session"));
  const term = await handleAdmin(new Request("https://engine.example/admin/sessions/terminate-others", { method: "POST", body: "{}", headers: { "content-type": "application/json", origin: ORIGIN, cookie: `${recCookie!}; ${CSRF_COOKIE_NAME}=csrf-r`, "x-downpipes-csrf": "csrf-r" } }), env);
  const reminted = extractSessionCookie(term.headers.get("set-cookie"));
  ok("(d) terminate-others from the recovery session succeeds and re-issues its cookie", term.status === 200 && reminted !== null);
  ok("(a) the re-issued copy of the recovery session is still refused the gated action", reminted !== null && refused(await act(env, GATED, reminted)));
  const recovered = reminted ?? recCookie!;

  // ---- (b) a fresh factor performed after the recovery admits the same session -----------------------------------
  const token = await freshFactor(env, recovered, authA);
  ok("(b) a passkey assertion completes the step-up ceremony on the recovery session", token !== null);
  ok("(b) the gated action passes with the fresh-factor token", token !== null && !refused(await act(env, GATED, recovered, token)));
  ok("(b) the token is single-use (a reuse is refused)", token !== null && refused(await act(env, GATED, recovered, token)));
  ok("(b) the session is still recovery-class afterwards (no token, still refused)", refused(await act(env, GATED, recovered)));

  ok("(a) a recovery session is refused recovery-code regeneration until a fresh factor", refused(await act(env, "/admin/auth/recovery-codes/regenerate", recovered)));
  const token2 = await freshFactor(env, recovered, authA);
  const regen = token2 === null ? null : await actRaw(env, "/admin/auth/recovery-codes/regenerate", recovered, token2);
  const newCodes = regen === null ? [] : ((regen.json.codes ?? regen.json.recoveryCodes) as string[] | undefined) ?? [];
  ok("(b) a fresh factor admits recovery-code regeneration on the recovery session", regen !== null && !refused(regen) && newCodes.length === 10);

  // ---- (d) the journey completes without a step-up deadlock -------------------------------------------------------
  const authB = await makeAuthenticator("ES256");
  const rec2 = await post(env, "/admin/auth/recovery", { email: OWNER, code: newCodes[0] ?? codes[1]! });
  const journey = extractSessionCookie(rec2.setCookie);
  ok("(d) setup: a second recovery code signs in", rec2.json.ok === true && journey !== null);
  ok("(d) the new recovery session is refused the gated action", journey !== null && refused(await act(env, GATED, journey)));
  const begin = await registerBegin(env, OWNER, { cookie: journey!, origin: ORIGIN });
  ok("(d) register/begin is open to the recovery session", begin.json.ok === true);
  const fin = await registerFinish(env, OWNER, await buildAttestation(authB, challengeFor(begin)), { cookie: journey!, origin: ORIGIN });
  ok("(d) the recovery session enrols a replacement passkey with no prior step-up", fin.json.ok === true);
  const enrolled = extractSessionCookie(fin.setCookie);
  ok("(d) the enrolment ceremony issues its own passkey session", enrolled !== null);
  const confirm = await post(env, "/admin/auth/recovery-codes/confirm", {}, { cookie: enrolled!, origin: ORIGIN });
  ok("(d) the staged recovery codes are confirmed", confirm.status === 200 && confirm.json.ok === true);
  const token3 = await freshFactor(env, enrolled!, authB);
  ok("(d) the replacement passkey completes step-up", token3 !== null && !refused(await act(env, GATED, enrolled!, token3)));
  // ---- (e) the five-minute enrolment window after recovery, on a fake clock --------------------------------------------
  const liveCodes = (fin.json.recoveryCodes as string[] | undefined) ?? [];
  const realNow = Date.now;
  let clock = realNow();
  Date.now = (): number => clock;
  try {
    const signInAt = clock;
    const win1 = extractSessionCookie((await post(env, "/admin/auth/recovery", { email: OWNER, code: liveCodes[1]! })).setCookie);
    ok("(e) setup: a recovery code signs in on the fake clock", win1 !== null);
    clock = signInAt + STEPUP_FRESH_MS - 1_000;
    const b1 = await registerBegin(env, OWNER, { cookie: win1!, origin: ORIGIN });
    const f1 = await registerFinish(env, OWNER, await buildAttestation(await makeAuthenticator("ES256"), challengeFor(b1)), { cookie: win1!, origin: ORIGIN });
    ok("(e1) a recovery session enrols a replacement passkey at 4 min 59 s after its sign-in", b1.json.ok === true && f1.json.ok === true);
    clock = signInAt + 2 * STEPUP_FRESH_MS;
    const signIn2At = clock;
    const win2 = extractSessionCookie((await post(env, "/admin/auth/recovery", { email: OWNER, code: liveCodes[2]! })).setCookie);
    ok("(e) setup: a second recovery code signs in on the fake clock", win2 !== null);
    clock = signIn2At + STEPUP_FRESH_MS - 1_000;
    const b2 = await registerBegin(env, OWNER, { cookie: win2!, origin: ORIGIN });
    ok("(e2) setup: register/begin is open to the session at 4 min 59 s", b2.json.ok === true);
    const att2 = await buildAttestation(await makeAuthenticator("ES256"), challengeFor(b2));
    clock = signIn2At + STEPUP_FRESH_MS + 1_000;
    const f2 = await registerFinish(env, OWNER, att2, { cookie: win2!, origin: ORIGIN });
    ok("(e2) the same enrolment at 5 min 01 s is refused with the step-up refusal", f2.status === 401 && f2.json.error === "step-up required" && f2.json.stepUpRequired === true);
    ok("(e2) the step-up check reads not satisfied for enrol-passkey at 5 min 01 s", (await stepUpSatisfied(stub, win2!, "enrol-passkey")) === false);
    clock = signIn2At + STEPUP_FRESH_MS + 60_000;
    const win3 = extractSessionCookie((await post(env, "/admin/auth/recovery", { email: OWNER, code: liveCodes[3]! })).setCookie);
    ok("(e3) setup: spending another recovery code gives a new recovery session", win3 !== null);
    clock += 30_000;
    const b3 = await registerBegin(env, OWNER, { cookie: win3!, origin: ORIGIN });
    const f3 = await registerFinish(env, OWNER, await buildAttestation(await makeAuthenticator("ES256"), challengeFor(b3)), { cookie: win3!, origin: ORIGIN });
    ok("(e3) the new recovery session enrols a replacement passkey inside its own window", b3.json.ok === true && f3.json.ok === true);
  } finally {
    Date.now = realNow;
  }
  // ---- the recovered marker is part of the signed body and only a passkey-class session may carry it ---------------
  const markedPasskey = await signSession(key, { method: "passkey", email: OWNER, subject: passkeySubject(OWNER), epoch: 0, recovered: true }, Date.now());
  const plainPasskey = await signSession(key, { method: "passkey", email: OWNER, subject: passkeySubject(OWNER), epoch: 0 }, Date.now());
  const markedOidc = await signSession(key, { method: "oidc", connId: "conn1", email: OWNER, subject: "oidc:conn1|sub", epoch: 0, recovered: true }, Date.now());
  ok("marker: a recovered passkey session verifies as recovered", (await verifySession(key, markedPasskey, Date.now()))?.recovered === true);
  ok("marker: an ordinary passkey session verifies as not recovered", (await verifySession(key, plainPasskey, Date.now()))?.recovered === false);
  ok("marker: an oidc session claiming the marker is refused", (await verifySession(key, markedOidc, Date.now())) === null);

  console.log(failureCount() === 0 ? "\nvalidate-recovery-session-stepup: ALL PASS" : `\nvalidate-recovery-session-stepup: ${failureCount()} FAILED`);
}

await run();
verdictReached(failureCount());
if (failureCount() > 0) process.exit(1);
