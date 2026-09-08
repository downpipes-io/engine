// validate-cov-admin-router-ops: branch-coverage proof for the operations-and-alerting route spoke
// (src/admin/router-ops.ts). It drives every case in handleOps through the REAL stack (handleAdmin ->
// authorise -> resolveCaller -> the spoke dispatch -> the scheduler DO) so each branch is reached by a
// genuine request and asserted on its real outcome (an HTTP status, a returned body field, a stored
// effect), never by calling code merely to tick coverage. Covered:
//  - the per-route capability gate, allow AND deny, for drill.run / notify.config / expiry.config /
//    access.policy / keys.ceremony (a viewer/non-owner is a real 403 with the required capability echoed);
//  - the success path of each forwarding case (drill-evidence, notify channels/rules/test, expiry
//    set/delete/cleanup-attest);
//  - POST /notify/test's own validation ladder: a missing channelId (400), an empty channelId (400, the
//    second arm of the ||), an unknown channel (404), and a real test send that delivers to a channel;
//  - POST /policy/require-access across enough env + caller + DO-state combinations to exercise the
//    accessConfigured && pair, the secondFactorPresent || chain, the enforced/safeToDisableToken &&
//    pairs, the lockoutWarning ternary, and the lockout-preflight ok / non-ok / throwing branches;
//  - the per-route rate-limit pre-check refusal (429) for every mutating case, by seeding the caller's
//    fixed-window counter to the cap directly in DO storage;
//  - the spoke's default arm (a path no case matches falls through to the hub's 404).
//
// Run: node test/validate-cov-admin-router-ops.ts

import { handleAdmin } from "../src/admin/router.ts";
import { rateLimitKey } from "../src/admin/router-core.ts";
import { buildSupportBundle } from "../src/admin/support.ts";
import { fetchSchedDiag } from "../src/admin/support-sections-diag.ts";
import { fetchNotifyHistory } from "../src/admin/support-sections-notify.ts";
import type { Env } from "../src/env.d.ts";
import { makeScheduler, makeSigner, TEAM, AUD } from "./validate-rbac-harness.ts";
import { RATE_LIMIT_PREFIX, RATE_LIMIT_MAX_PER_WINDOW, RECOVERY_PREFIX } from "../src/sched/scheduler-do-limits.ts";
import { RECOVERY_SIGNING_KEY_KEY } from "../src/sched/scheduler-do-base.ts";
import { generateRecoveryCodes } from "../src/admin/recovery.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { passkeySubject } from "../src/admin/identity.ts";
import { roleSubjectKey } from "../src/admin/identity.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
async function j<T>(resp: Response): Promise<T> {
  return (await resp.json()) as T;
}

const WEBHOOK_OK = "https://hooks.example.com/ok";
// a sink whose ANSWER this suite controls per call, so the REAL POST /notify/test can be driven at a
// 400 (an engine payload regression: OUR bug), a 404 (a wrong path on a live sink) and a 410 (the Slack app
// was DEPROVISIONED: recreate the integration). Those are three different remedies and they used to be one row.
const WEBHOOK_VAR = "https://hooks.example.com/vary";
let sinkStatus = 200;
const OWNER = "owner-cov@acme.example";
const VIEWER = "viewer-cov@acme.example";

async function main(): Promise<void> {
  const signer = await makeSigner();
  const { tokenFor } = signer;
  // The makeSigner stub is now globalThis.fetch (JWKS only). Wrap it so the one notify test-send target
  // also answers 200, and everything else still routes to the JWKS stub (which throws on a stray URL).
  const jwksFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === WEBHOOK_OK) return new Response("ok", { status: 200 });
    if (url === WEBHOOK_VAR) return new Response(sinkStatus === 200 ? "ok" : "no", { status: sinkStatus });
    return jwksFetch(input, init);
  }) as typeof fetch;

  const s = makeScheduler();
  // The Access-configured env every Access caller authenticates against, plus a bootstrap ADMIN_TOKEN.
  const baseEnv = { ...s.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN: "bg-token-cov" } as unknown as Env;

  // Low-level driver: any env + headers + path, through the production handleAdmin.
  const rawCall = (env: Env, headers: Record<string, string>, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
    const init: RequestInit = {
      method,
      headers: { ...headers, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), env);
  };
  // Access caller against the main DO + Access env.
  const call = async (email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
    return rawCall(baseEnv, { "cf-access-jwt-assertion": await tokenFor(email) }, method, path, body);
  };
  // Bare-token break-glass caller (owner) against an arbitrary env/DO.
  const tokenCall = (env: Env, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
    return rawCall(env, { authorization: "Bearer tok-cov" }, method, path, body);
  };

  // ---- bootstrap: the first Access caller becomes Owner -------------------------------------------
  const who = await j<{ role: string }>(await call(OWNER, "GET", "/admin/whoami"));
  ok("bootstrap: first Access caller is Owner", who.role === "owner");

  // ---- the un-gated GET reads (any authenticated role) -------------------------------------------
  ok("GET /drill-evidence is 200 (any role)", (await call(OWNER, "GET", "/drill-evidence")).status === 200);
  ok("GET /notify/rules is 200", (await call(OWNER, "GET", "/notify/rules")).status === 200);
  ok("GET /notify/history is 200", (await call(OWNER, "GET", "/notify/history")).status === 200);
  ok("GET /expiry is 200", (await call(OWNER, "GET", "/expiry")).status === 200);

  // ---- GET /notify/channels: gated on notify.config -------------------------------------
  // Unlike the reads above, this one hands back a live bearer credential (a channel's Slack/Teams/
  // webhook url or PagerDuty routingKey) verbatim, so it gates like
  // its POST siblings instead of allowing any authenticated role. Owner holds notify.config -> 200
  // here; the viewer-403 deny case is asserted just below, alongside every other gated route.
  ok("GET /notify/channels (owner, holds notify.config) is 200", (await call(OWNER, "GET", "/notify/channels")).status === 200);

  // ---- drill-evidence: gate allow + a real append ------------------------------------------------
  {
    const r = await call(OWNER, "POST", "/drill-evidence", { runId: "run-cov-1", kind: "in-account", note: "drill ok" });
    ok("POST /drill-evidence (owner) is 200", r.status === 200);
    const list = await j<unknown[]>(await call(OWNER, "GET", "/drill-evidence"));
    ok("the drill-evidence entry was appended (list non-empty)", Array.isArray(list) && list.length === 1);
  }

  // ---- notify channels/rules/test --------------------------------------------------------------
  let channelId = "";
  {
    const created = await call(OWNER, "POST", "/notify/channels", { kind: "webhook", name: "cov-siem", url: WEBHOOK_OK });
    ok("POST /notify/channels (owner) is 200", created.status === 200);
    const ch = await j<{ id: string }>(created);
    channelId = ch.id;
    ok("the created channel carries an id", typeof channelId === "string" && channelId.length > 0);

    // notify/test validation ladder.
    const noId = await call(OWNER, "POST", "/notify/test", { note: "no channel" });
    ok("POST /notify/test with no channelId is 400", noId.status === 400);
    ok("the 400 says channelId required", (await j<{ error: string }>(noId)).error === "channelId required");

    const emptyId = await call(OWNER, "POST", "/notify/test", { channelId: "" });
    ok("POST /notify/test with empty channelId is 400 (second || arm)", emptyId.status === 400);

    const unknown = await call(OWNER, "POST", "/notify/test", { channelId: "no-such-channel" });
    ok("POST /notify/test with an unknown channel is 404", unknown.status === 404);
    ok("the 404 says unknown channel", (await j<{ error: string }>(unknown)).error === "unknown channel");

    const sent = await call(OWNER, "POST", "/notify/test", { channelId });
    ok("POST /notify/test with a real channel is 200", sent.status === 200);
    ok("the test send delivered to the (stubbed) webhook (ok:true)", (await j<{ ok: boolean }>(sent)).ok === true);

    // The test-send outcome is recorded on the history ring, flagged test:true (previously a green
    // test left NO durable trace that the channel was ever verified). Readers without the flag see a
    // plain info-severity delivery; rules and digests never read history, so it cannot route.
    const hist = await j<Array<{ channelId?: string; test?: boolean; delivered?: boolean; event?: string; severity?: string }>>(
      await call(OWNER, "GET", "/notify/history"),
    );
    const testRow = hist.find((r) => r.channelId === channelId && r.test === true);
    ok("the test-send appended a history entry flagged test:true", testRow !== undefined);
    ok("the test entry recorded the delivery outcome", testRow?.delivered === true);
    ok("the test entry rides as an info-severity success", testRow?.event === "backup-success" && testRow?.severity === "info");

    // rules CRUD (gate allow on both write + delete).
    const rule = await call(OWNER, "POST", "/notify/rules", { scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: [channelId], enabled: true });
    ok("POST /notify/rules (owner) is 200", rule.status === 200);
    const ruleId = (await j<{ id: string }>(rule)).id;
    const ruleDel = await call(OWNER, "POST", "/notify/rules/delete", { id: ruleId });
    ok("POST /notify/rules/delete (owner) is 200", ruleDel.status === 200);

    // ===== THE 512-CHARACTER apiKey BOUND RUNS IN BOTH WRAP-KEY POSTURES, NOT ONLY THE FLOOR. =====
    //
    // (.) parseChannelSecret's API_KEY_MAX runs INSIDE the DO,
    // and the router seals a jsm/servicenow apiKey before the DO ever sees it. A sealed value takes the
    // isWrappedSecret arm and returns BEFORE the length test, so with CONFIG_WRAP_KEY set -- the ordinary
    // deployment -- a 20000-character token was accepted and stored as ciphertext, answering 200. With no
    // wrap key the identical token was a clean 400. The declared bound existed and did not run where it
    // mattered, and the two postures disagreed about what the engine accepts.
    //
    // Both postures are driven HERE, in the same run, because the whole defect is that they differed. The
    // no-wrap-key arm is the KNOWN POSITIVE: it refused before the fix and must still refuse after, so a
    // change that simply broke the route cannot masquerade as this one being fixed.
    {
      const WRAP_KEY_ENV = { CONFIG_WRAP_KEY: b64urlEncode(new Uint8Array(32).map((_, i) => i + 1)) };
      const wrapEnv = { ...baseEnv, ...WRAP_KEY_ENV } as unknown as Env;
      const overlong = "K".repeat(20000);
      const jsmBody = { kind: "jsm", name: "cov-jsm-overlong", url: "https://hooks.example.com/ok", apiKey: overlong };
      const hdr = { "cf-access-jwt-assertion": await tokenFor(OWNER) };

      const floorR = await rawCall(baseEnv, hdr, "POST", "/admin/notify/channels", jsmBody);
      ok("apiKey bound, KNOWN POSITIVE (no CONFIG_WRAP_KEY): a 20000-character jsm apiKey is 400", floorR.status === 400);
      const wrappedR = await rawCall(wrapEnv, hdr, "POST", "/admin/notify/channels", jsmBody);
      ok("apiKey bound, THE DEFECT (CONFIG_WRAP_KEY set): the same 20000-character apiKey is 400, not sealed and stored", wrappedR.status === 400);
      ok("both postures give the SAME reason, naming the 512-character bound", (await j<{ error: string }>(wrappedR)).error.includes("512") && (await j<{ error: string }>(floorR)).error.includes("512"));
      // Read AT REST: a 400 that stored the row anyway is the failure that matters, and a 200 body could not
      // show it either way. No channel named cov-jsm-overlong may exist in either posture.
      const atRest = JSON.stringify([...(await s.storage.list<unknown>({ prefix: "notify-channel:" })).values()]);
      ok("apiKey bound: NOTHING was stored for the refused channel, in either posture", !atRest.includes("cov-jsm-overlong"));
      // POSITIVE CONTROL that must DISCRIMINATE: a 512-character apiKey (exactly at the bound) still stores
      // under the wrap key, sealed. Without this, a router that refused every jsm channel would pass above.
      const okKey = "K".repeat(512);
      const atBoundR = await rawCall(wrapEnv, hdr, "POST", "/admin/notify/channels", { kind: "jsm", name: "cov-jsm-atbound", url: "https://hooks.example.com/ok", apiKey: okKey });
      ok("apiKey bound CONTROL: a 512-character apiKey (exactly at the bound) still stores 200 under the wrap key", atBoundR.status === 200);
      const sealed = [...(await s.storage.list<{ name?: string; apiKey?: unknown }>({ prefix: "notify-channel:" })).values()].find((c) => c.name === "cov-jsm-atbound");
      ok("apiKey bound CONTROL: it is stored SEALED (an envelope, never the plaintext)", sealed !== undefined && typeof sealed.apiKey === "object" && sealed.apiKey !== null && !JSON.stringify(sealed.apiKey).includes(okKey));
    }

    const chDel = await call(OWNER, "POST", "/notify/channels/delete", { id: channelId });
    ok("POST /notify/channels/delete (owner) is 200", chDel.status === 200);
    ok("the channel delete reports deleted:true", (await j<{ deleted: boolean }>(chDel)).deleted === true);
  }

  // ---- expiry set / cleanup-attest / delete (gate allow) ----------------------------------------
  {
    const set = await call(OWNER, "POST", "/expiry", { id: "cov-key", label: "S3 key", kind: "credential", expiresAt: new Date(Date.now() + 30 * 86400000).toISOString() });
    ok("POST /expiry (owner) is 200", set.status === 200);
    const attest = await call(OWNER, "POST", "/expiry/cleanup-attest", { id: "cov-key" });
    ok("POST /expiry/cleanup-attest (owner) is 200", attest.status === 200);
    const del = await call(OWNER, "POST", "/expiry/delete", { id: "cov-key" });
    ok("POST /expiry/delete (owner) is 200", del.status === 200);
    ok("the expiry delete reports deleted:true", (await j<{ deleted: boolean }>(del)).deleted === true);
  }

  // ---- POST /policy/require-access: env + caller + DO-state matrix ------------------------------
  type RA = {
    tokenFallbackDisabled: boolean;
    accessConfigured: boolean;
    enforced: boolean;
    callerMethod: string;
    secondFactor: { passkeyOwnerEnrolled: boolean; accessConfigured: boolean; recoveryReady: boolean; secondOwner: boolean };
    secondFactorPresent: boolean;
    safeToDisableToken: boolean;
    lockoutWarning: string | null;
  };
  // Combo A: Access owner, Access configured, token fallback enabled -> accessConfigured short-circuits
  // secondFactorPresent true; safe (a verified Access caller, not the bare token); no warning; not enforced.
  {
    const a = await j<RA>(await call(OWNER, "POST", "/policy/require-access", {}));
    ok("require-access A: accessConfigured true", a.accessConfigured === true);
    ok("require-access A: callerMethod access", a.callerMethod === "access");
    ok("require-access A: not enforced (fallback still enabled)", a.enforced === false);
    ok("require-access A: secondFactorPresent true", a.secondFactorPresent === true);
    ok("require-access A: safeToDisableToken true (access caller, second factor present)", a.safeToDisableToken === true);
    ok("require-access A: no lockout warning", a.lockoutWarning === null);
  }
  // Combo D: Access owner + ADMIN_TOKEN_DISABLED=true -> enforced (both && operands true).
  {
    const envD = { ...baseEnv, ADMIN_TOKEN_DISABLED: "true" } as unknown as Env;
    const d = await j<RA>(await rawCall(envD, { "cf-access-jwt-assertion": await tokenFor(OWNER) }, "POST", "/policy/require-access", {}));
    ok("require-access D: tokenFallbackDisabled true", d.tokenFallbackDisabled === true);
    ok("require-access D: enforced true (fallback off AND access configured)", d.enforced === true);
  }
  // Token-caller combos run against a SEPARATE DO so the main DO stays Access-only and un-touched.
  const sTok = makeScheduler();
  // Combo B: token caller, NO Access configured, no DO second factor -> accessConfigured false, the whole
  // || chain evaluates to false, lockoutWarning is the verbatim guidance, safeToDisableToken false.
  {
    const envB = { ...sTok.env, ADMIN_TOKEN: "tok-cov" } as unknown as Env;
    const b = await j<RA>(await tokenCall(envB, "POST", "/policy/require-access", {}));
    ok("require-access B: accessConfigured false (no team domain)", b.accessConfigured === false);
    ok("require-access B: callerMethod token", b.callerMethod === "token");
    ok("require-access B: secondFactorPresent false", b.secondFactorPresent === false);
    ok("require-access B: safeToDisableToken false", b.safeToDisableToken === false);
    ok("require-access B: a lockout warning is present", typeof b.lockoutWarning === "string" && b.lockoutWarning.length > 0);
  }
  // Combo C: token caller, team domain set but AUD absent -> the && right operand decides accessConfigured.
  {
    const envC = { ...sTok.env, CF_ACCESS_TEAM_DOMAIN: TEAM, ADMIN_TOKEN: "tok-cov" } as unknown as Env;
    const c = await j<RA>(await tokenCall(envC, "POST", "/policy/require-access", {}));
    ok("require-access C: accessConfigured false (AUD missing, && right operand)", c.accessConfigured === false);
    ok("require-access C: callerMethod token", c.callerMethod === "token");
  }
  // Combo F: token caller WITH Access configured -> accessConfigured true so secondFactorPresent true, but
  // safeToDisableToken false because the caller is itself on the bare token (the && right operand false).
  {
    const envF = { ...sTok.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN: "tok-cov" } as unknown as Env;
    const f = await j<RA>(await tokenCall(envF, "POST", "/policy/require-access", {}));
    ok("require-access F: accessConfigured true", f.accessConfigured === true);
    ok("require-access F: secondFactorPresent true", f.secondFactorPresent === true);
    ok("require-access F: safeToDisableToken false (caller is the bare token)", f.safeToDisableToken === false);
    ok("require-access F: no warning (a second factor exists)", f.lockoutWarning === null);
  }
  // Combo recoveryReady: token caller, NO Access, and a USABLE recovery set for a passkey-bound Owner -> the
  // recovery operand of the || chain flips secondFactorPresent true. BOTH DIRECTIONS: the same account with
  // no Owner holding a usable set does not flip it.
  //
  // This vector used to write a bare account-level "recovery-owner-ack" boolean into a scheduler with NO role
  // entries, NO recovery record and NO codes anywhere, and assert recoveryReady true
  // (LOCKOUT-PREFLIGHT-COUNTS-RECORDS-NOT-USABLE-FACTORS). recoveryReady checked only that the
  // latch existed, so the vector passed on an engine that had no way back in at all, and it was one of the
  // three assertions that kept an existence-only check looking green.
  {
    const sNone = makeScheduler();
    const envN = { ...sNone.env, ADMIN_TOKEN: "tok-cov" } as unknown as Env;
    const n = await j<RA>(await tokenCall(envN, "POST", "/policy/require-access", {}));
    ok("require-access recovery: an account with no Owner and no codes is NOT recoveryReady", n.secondFactor.recoveryReady === false);

    const sRec = makeScheduler();
    const email = "owner-cov@cov.example";
    await sRec.storage.put(roleSubjectKey(passkeySubject(email)), { subject: passkeySubject(email), email, role: "owner", grantedBy: "bootstrap", grantedAt: "2026-06-01T00:00:00.000Z" });
    const rawKey = new Uint8Array(32).fill(5);
    await sRec.storage.put(RECOVERY_SIGNING_KEY_KEY, { key: b64urlEncode(rawKey), createdAt: "2026-06-01T00:00:00.000Z" });
    const { record } = await generateRecoveryCodes(rawKey, email, "2026-06-20T00:00:00.000Z");
    await sRec.storage.put(`${RECOVERY_PREFIX}${email}`, record);
    const envR = { ...sRec.env, ADMIN_TOKEN: "tok-cov" } as unknown as Env;
    const r = await j<RA>(await tokenCall(envR, "POST", "/policy/require-access", {}));
    ok("require-access recovery: a usable unconsumed set for a passkey-bound Owner -> recoveryReady true", r.secondFactor.recoveryReady === true);
    ok("require-access recovery: secondFactorPresent true via recovery operand", r.secondFactorPresent === true);
    ok("require-access recovery: accessConfigured still false", r.accessConfigured === false);
  }
  // Combo secondOwner: token caller, NO Access, two bound owners seeded -> the secondOwner operand flips it.
  {
    const sSec = makeScheduler();
    const at = new Date().toISOString();
    await sSec.storage.put(roleSubjectKey("subj-cov-owner-1"), { subject: "subj-cov-owner-1", email: "o1@cov.example", role: "owner", grantedBy: "bootstrap", grantedAt: at });
    await sSec.storage.put(roleSubjectKey("subj-cov-owner-2"), { subject: "subj-cov-owner-2", email: "o2@cov.example", role: "owner", grantedBy: "bootstrap", grantedAt: at });
    const envS = { ...sSec.env, ADMIN_TOKEN: "tok-cov" } as unknown as Env;
    const r = await j<RA>(await tokenCall(envS, "POST", "/policy/require-access", {}));
    ok("require-access secondOwner: secondOwner true", r.secondFactor.secondOwner === true);
    ok("require-access secondOwner: secondFactorPresent true via secondOwner operand", r.secondFactorPresent === true);
  }
  // Combo lockout-preflight NON-OK and THROWING: a wrapped scheduler whose lockout-preflight returns 500
  // (the `if (lr.ok)` false arm) or throws (the catch arm); the route still answers 200 with all-false
  // lockout (fail safe), proving both branches without fabricating a green verdict.
  {
    const lr500 = makeLockoutScheduler("500");
    const env500 = { SCHEDULER: lr500.env.SCHEDULER, ADMIN_TOKEN: "tok-cov" } as unknown as Env;
    const r500 = await tokenCall(env500, "POST", "/policy/require-access", {});
    ok("require-access lockout 500: route still answers 200 (lr.ok false arm)", r500.status === 200);
    ok("require-access lockout 500: lockout reads all-false (not populated)", (await j<RA>(r500)).secondFactor.recoveryReady === false);

    const lrThrow = makeLockoutScheduler("throw");
    const envThrow = { SCHEDULER: lrThrow.env.SCHEDULER, ADMIN_TOKEN: "tok-cov" } as unknown as Env;
    const rThrow = await tokenCall(envThrow, "POST", "/policy/require-access", {});
    ok("require-access lockout throw: route still answers 200 (catch arm)", rThrow.status === 200);
  }

  // ---- retire-break-glass: gate allow, real DO precondition refusal -----------------------------
  // A single bootstrap Owner with no recovery codes and no second Owner cannot retire the token: the gate
  // (keys.ceremony) passes for the Owner, the request reaches the DO, and the DO refuses with the
  // way-back-in precondition. This exercises the route's denied=false + limited=false path.
  {
    const r = await call(OWNER, "POST", "/policy/retire-break-glass-token", {});
    ok("POST /policy/retire-break-glass-token (owner) reaches the DO (not a 403 gate refusal)", r.status !== 403);
    ok("the DO refuses with the way-back-in precondition (400)", r.status === 400);
    ok("the refusal names the precondition", (await j<{ error: string }>(r)).error.includes("cannot retire"));
  }

  // ---- capability gate DENY for every gated case (a viewer / non-owner is a real 403) ----------
  const denyCases: Array<{ method: "POST"; path: string; required: string }> = [
    { method: "POST", path: "/drill-evidence", required: "drill.run" },
    { method: "POST", path: "/notify/channels", required: "notify.config" },
    { method: "POST", path: "/notify/channels/delete", required: "notify.config" },
    { method: "POST", path: "/notify/rules", required: "notify.config" },
    { method: "POST", path: "/notify/rules/delete", required: "notify.config" },
    { method: "POST", path: "/notify/test", required: "notify.config" },
    { method: "POST", path: "/expiry", required: "expiry.config" },
    { method: "POST", path: "/expiry/delete", required: "expiry.config" },
    { method: "POST", path: "/expiry/cleanup-attest", required: "expiry.config" },
    { method: "POST", path: "/policy/require-access", required: "access.policy" },
    { method: "POST", path: "/policy/retire-break-glass-token", required: "keys.ceremony" },
  ];
  for (const dc of denyCases) {
    const r = await call(VIEWER, dc.method, dc.path, {});
    ok(`gate deny: viewer ${dc.method} ${dc.path} is 403`, r.status === 403);
    ok(`gate deny: ${dc.path} echoes required=${dc.required}`, (await j<{ required: string }>(r)).required === dc.required);
  }

  // ---- capability gate DENY for the live-credential GET read ----------------------------
  // Asserted separately from denyCases above: a GET request cannot carry a body, so this does not fit
  // that loop's shared `body: {}` call shape. A viewer (no notify.config) must get the same 403 +
  // echoed capability every gated POST gets, never the live channel url.
  {
    const rCh = await call(VIEWER, "GET", "/notify/channels");
    ok("gate deny: viewer GET /notify/channels is 403", rCh.status === 403);
    ok("gate deny: /notify/channels echoes required=notify.config", (await j<{ required: string }>(rCh)).required === "notify.config");
  }

  // ---- THE TEST BUTTON'S ANSWER, ON THE SURFACE THE TICKET NAMES -------------------
  //
  // "My Slack test keeps failing." deliverToChannel already returns a CLOSED DeliveryFailCode (http-bad-request
  // / http-gone / http-4xx / email-platform-rejected / email-from-invalid, a 30-member vocabulary), and the
  // route laundered it through `reason` into classifyTestFailure, whose text arm coarsened every one of them to
  // "rejected". So a DEPROVISIONED webhook, a wrong path on a live sink and an engine payload regression were
  // ONE byte-identical pack row with three opposite remedies -- and a support engineer reading it would tell the
  // customer to recreate a webhook that is perfectly healthy. A confidently WRONG answer, not a missing one.
  //
  // Everything below is driven through the PRODUCTION POST /admin/notify/test (the console's own call site,
  // client-notifications.ts) against real channels created through the real POST /admin/notify/channels, varying
  // ONLY the sink's answer, and read back through the PACK'S OWN projectors.
  {
    const varCh = await j<{ id: string }>(await call(OWNER, "POST", "/notify/channels", { kind: "webhook", name: "cov-vary", url: WEBHOOK_VAR }));
    const press = async (status: number): Promise<void> => {
      sinkStatus = status;
      await call(OWNER, "POST", "/notify/test", { channelId: varCh.id });
    };
    await press(400); // the sink refused the request SHAPE: an engine payload regression, our bug
    await press(404); // a wrong path on a live sink
    await press(410); // the sink was DEPROVISIONED (the Slack app was deleted)
    await press(401); // the credential is wrong
    await press(429); // the sink is throttling us
    await press(200); // healthy

    // Read the WEBHOOK rows before the email presses: the ring is capped at TEST_OUTCOMES_PER_SURFACE (8) per
    // surface and both channels share the notify-channel surface, so a single read at the end would roll the
    // first rows -- the three this gap exists for -- off the front.
    const diagW = (await fetchSchedDiag(s.stub)) as { testOutcomes?: Record<string, Array<Record<string, unknown>>> };
    const ringW = (diagW.testOutcomes?.["notify-channel"] ?? []).slice(-6);
    const codesW = ringW.map((r) => (r.ok === true ? "ok" : `${String(r.reasonClass)}/${String(r.deliveryCode ?? "-")}/${String(r.platformCode ?? "-")}`));
    console.log(`  ..   the pack's notify-channel test ring (webhook): ${JSON.stringify(codesW)}`);
    ok("the 400 (OUR payload bug) carries http-bad-request", codesW[0] === "rejected/http-bad-request/-");
    ok("the 404 (a wrong path on a live sink) is a DIFFERENT row", codesW[1] === "rejected/http-4xx/-");
    ok("the 410 (the Slack app was DEPROVISIONED) is a THIRD row -- these three were byte-identical", codesW[2] === "rejected/http-gone/-");
    ok("400 != 404 != 410: three remedies, three rows", new Set([codesW[0], codesW[1], codesW[2]]).size === 3);
    ok("a 401 still reads as auth (the status outranks the code)", codesW[3] === "auth/http-auth/-");
    ok("a 429 still reads as rate-limited", codesW[4] === "rate-limited/http-rate-limited/-");
    ok("a healthy press carries NO reason and no code (nothing to explain: no noise on the working path)", codesW[5] === "ok");

    // The EMAIL channel through the SAME button. Its own Test button (POST /email/test) learnt to carry the
    // platform's code in R6; this one -- the same console, the same Email Service, the same adapter -- did not,
    // so an un-onboarded sending domain, an unverified sender and an invalid EMAIL_FROM were one row here.
    const emailCh = await j<{ id: string }>(await call(OWNER, "POST", "/notify/channels", { kind: "email", name: "cov-email", toAddresses: ["ops@acme.example"] }));
    const emailEnv = (code: string | undefined, from = "alerts@acme.example"): Env =>
      ({
        ...baseEnv,
        EMAIL_FROM: from,
        EMAIL: {
          send: (): Promise<void> => {
            if (code === undefined) return Promise.resolve();
            const e = new Error("the platform refused the send") as Error & { code?: string };
            e.code = code;
            return Promise.reject(e);
          },
        },
      }) as unknown as Env;
    const emailPress = async (env: Env): Promise<void> => {
      await rawCall(env, { "cf-access-jwt-assertion": await tokenFor(OWNER) }, "POST", "/notify/test", { channelId: emailCh.id });
    };
    await emailPress(emailEnv("E_SENDER_DOMAIN_NOT_AVAILABLE")); // the sending domain is not onboarded
    await emailPress(emailEnv("E_SENDER_NOT_VERIFIED")); // the sender is not verified
    await emailPress(emailEnv(undefined, "alerts@downpipe.workers.dev")); // an INVALID EMAIL_FROM: no send is attempted
    await emailPress(emailEnv(undefined)); // healthy

    // ---- THE EMAIL ROWS, on the SAME surface, through the SAME button. ----
    const diag = (await fetchSchedDiag(s.stub)) as { testOutcomes?: Record<string, Array<Record<string, unknown>>> };
    const codes = (diag.testOutcomes?.["notify-channel"] ?? []).slice(-4).map((r) => (r.ok === true ? "ok" : `${String(r.reasonClass)}/${String(r.deliveryCode ?? "-")}/${String(r.platformCode ?? "-")}`));
    console.log(`  ..   the pack's notify-channel test ring (email): ${JSON.stringify(codes)}`);
    ok("the un-onboarded sending domain carries the platform's own code", codes[0] === "rejected/email-platform-rejected/E_SENDER_DOMAIN_NOT_AVAILABLE");
    ok("an unverified sender is a DIFFERENT row (it was the same one)", codes[1] === "rejected/email-platform-rejected/E_SENDER_NOT_VERIFIED");
    ok("an invalid EMAIL_FROM is a THIRD row (no send was even attempted)", codes[2] === "rejected/email-from-invalid/-");
    ok("the three email remedies are three rows on the notify-channel surface too", new Set([codes[0], codes[1], codes[2]]).size === 3);
    ok("a healthy email test carries no reason either", codes[3] === "ok");

    // The gap's own proposedEvidence: "carry deliveryCode on test:true notify history rows".
    const hist2 = await fetchNotifyHistory(s.stub);
    const rows = (hist2 as unknown as { entries?: Array<Record<string, unknown>> }).entries ?? [];
    const failedTests = rows.filter((r) => r.test === true && r.delivered === false);
    console.log(`  ..   the pack's newest failed test row: ${JSON.stringify(failedTests[0] ?? null)}`);
    ok("the persisted TEST row now carries a reason (it carried delivered:false and nothing else)", failedTests.length > 0 && typeof failedTests[0]?.deliveryCode === "string");
    ok("and it says it was a TEST, so a failed Test press is not read as a real alert that never arrived", failedTests[0]?.test === true);
    ok("the email test rows carry the platform code on the history ring too", rows.some((r) => r.test === true && r.platformCode === "E_SENDER_DOMAIN_NOT_AVAILABLE"));
    ok("a DELIVERED test row carries no code (a delivered send has nothing to explain)", rows.filter((r) => r.test === true && r.delivered === true).every((r) => r.deliveryCode === undefined && r.platformCode === undefined));

    // Redaction: nothing that names the sink, the recipient or the platform's sentence may ride.
    const serialised = JSON.stringify({ diag, hist2 });
    ok("no webhook url, recipient address or provider sentence rides in either section", !/hooks\.example\.com|ops@acme\.example|alerts@|workers\.dev|refused the send/i.test(serialised));
  }

  // ---- WHICH CREDENTIAL PATH THE ESTATE ACTUALLY RAN ON, AND FOR HOW LONG ----------------
  //
  // The pack must be able to answer "was this estate behind Access when the change was made, and how long did
  // it run on the shared break-glass token?" status.tokenFallbackDisabled / adminTokenConfigured
  // are PRESENCE booleans (the token CAN be used) and authPosture.adminCredentialPaths is a CAPABILITY count
  // (how many alternative paths EXIST); the console's amber "token fallback in use" chip dies with the browser
  // tab, and the audit excerpt deliberately carries no authn events. The engine classified every request's
  // credential path and threw it away.
  //
  // Driven through the PRODUCTION handleAdmin -- real Cloudflare Access JWTs and the real bare-token break-glass
  // -- and read back through the REAL buildSupportBundle (not the projector directly), so the flush the pack
  // build performs is the one being tested.
  {
    // A real break-glass session: three requests on the shared bearer (the emailless, unattributable path).
    const bg = { authorization: "Bearer bg-token-cov" };
    ok("the bare-token break-glass caller authenticates (owner-equivalent)", (await rawCall(baseEnv, bg, "GET", "/admin/whoami")).status === 200);
    await rawCall(baseEnv, bg, "GET", "/downpipes");
    await rawCall(baseEnv, bg, "GET", "/notify/rules");
    // ...on an estate that is ALSO being used through Access (every `call` above was an Access request).
    await call(OWNER, "GET", "/notify/rules");

    const bundle = await buildSupportBundle(baseEnv, s.stub);
    const posture = (bundle.authPosture ?? {}) as { methodUsage?: Record<string, Record<string, unknown>> };
    const usage = posture.methodUsage ?? {};
    console.log(`  ..   the pack's authPosture.methodUsage: ${JSON.stringify(usage)}`);
    const token = usage.token as { count?: number; days?: number[]; firstAt?: string; lastAt?: string } | undefined;
    const access = usage.access as { count?: number; days?: number[] } | undefined;
    ok("the pack records that the SHARED BREAK-GLASS TOKEN was used (it recorded nothing at all before)", (token?.count ?? 0) >= 3);
    ok("and that the estate was ALSO being driven through Cloudflare Access", (access?.count ?? 0) > 0);
    ok("the two paths are SEPARATE rows: 'behind Access' and 'on the shared token' are distinguishable", token !== undefined && access !== undefined);
    ok("the token row carries firstAt + lastAt -- the BOUND on the degraded window the ticket asks for", typeof token?.firstAt === "string" && typeof token?.lastAt === "string");
    ok("and a 14-day UTC ring, so 'is it STILL happening?' is answerable, not just 'when last'", Array.isArray(token?.days) && token.days.length === 14 && (token.days[0] ?? 0) >= 3);
    ok("today's count is the day-to-date count, not a rolling window it cannot compute", token?.days?.[0] === (usage.token as { today?: number }).today);
    ok("a method NOBODY used has no row (no phantom posture)", usage.passkey === undefined && usage.saml === undefined && usage.oidc === undefined);
    const serialised = JSON.stringify(usage);
    ok("no email, subject, session id, IP or token rides in the record", !/acme\.example|owner|bg-token|Bearer|\d+\.\d+\.\d+\.\d+/i.test(serialised));
    ok("every value is a closed method name, an integer or an engine-minted stamp", Object.keys(usage).every((m) => ["access", "passkey", "oidc", "saml", "token"].includes(m)));
  }

  // ---- rate-limit pre-check refusal (429) for every mutating case ------------------------------
  // Seed the Owner's fixed-window counter to the cap directly in DO storage so the next mutating request by
  // that caller is over the cap; the DO refuses without incrementing, so a single seed covers every route.
  {
    // THE SEEDED KEY IS DERIVED FROM THE ROUTER'S OWN FUNCTION, NOT SPELLED OUT HERE, so a future change to
    // rateLimitKey's derivation cannot silently land the seed on a key the limiter no longer reads.
    const rlKey = `${RATE_LIMIT_PREFIX}${rateLimitKey({ method: "access", email: OWNER, subject: signer.subjectOf(OWNER), role: "owner", groups: [], sourceIp: null })}`;
    await s.storage.put(rlKey, { windowStart: Date.now(), count: RATE_LIMIT_MAX_PER_WINDOW });
    const limitedRoutes = [
      "/drill-evidence", "/notify/channels", "/notify/channels/delete", "/notify/rules", "/notify/rules/delete",
      "/notify/test", "/expiry", "/expiry/delete", "/expiry/cleanup-attest",
      "/policy/retire-break-glass-token",
    ];
    for (const path of limitedRoutes) {
      const r = await call(OWNER, "POST", path, {});
      ok(`rate limit: owner POST ${path} over the cap is 429`, r.status === 429);
    }
    // Restore the Owner so any later call is unaffected (defensive; nothing follows that needs it).
    await s.storage.delete(rlKey);
  }

  // ---- the spoke default arm: a path no case matches falls through to the hub 404 ---------------
  {
    const r = await call(OWNER, "GET", "/no-such-ops-route");
    ok("a path matched by no case falls through the spoke (404)", r.status === 404);
  }

  signer.restoreFetch();
  console.log(failures === 0 ? "\nVALIDATE-COV-ADMIN-ROUTER-OPS VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

// makeLockoutScheduler wraps a real scheduler DO but makes ONLY /policy/lockout-preflight misbehave (a 500
// for the lr.ok-false arm, or a throw for the catch arm); every other DO route (the token break-glass
// retire check, etc.) still works, so the require-access request authenticates and reaches the route.
function makeLockoutScheduler(mode: "500" | "throw"): { env: Pick<Env, "SCHEDULER"> } {
  const inner = makeScheduler();
  const realStub = inner.stub;
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("/policy/lockout-preflight")) {
        if (mode === "throw") throw new Error("simulated lockout-preflight unavailable");
        return Promise.resolve(new Response("error", { status: 500 }));
      }
      return realStub.fetch(input, init);
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace } };
}

void main();
