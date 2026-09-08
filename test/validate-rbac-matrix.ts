// validate-rbac PROOFs 2..9c: role grant/revoke, the per-route role
// matrix at the router, the restore hard rule, Owner-only administration, the last-Owner guard,
// the DO's independent Owner re-check, the auth boundary, the token break-glass, ADMIN_TOKEN_DISABLED
// and the require-access posture surface. Extracted verbatim from test/validate-rbac.ts; the
// assertions, order and expected values are unchanged. These proofs are STATEFUL over the shared
// scheduler in `ctx` and run in the original order; 9b/9c stand up their own fresh schedulers exactly
// as the single-file suite did.

import { handleAdmin } from "../src/admin/router.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";
import type { Env } from "../src/env.d.ts";
import { type Ctx, OWNER, OPERATOR, VIEWER, APPROVER, OWNER2, TEAM, AUD, makeScheduler } from "./validate-rbac-harness.ts";

export async function runMatrix(ctx: Ctx): Promise<void> {
  const { ok, signer, sched, call, accessEnv } = ctx;
  const { subjectOf, tokenFor } = signer;

  // ---- PROOF 2: role grant + revoke, Owner-gated -----------------------------------------
  {
    const r = await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
    const entry = (await r.json()) as { email: string; role: string; grantedBy: string };
    ok("Owner grants operator: 200", r.status === 200);
    ok("granted entry has role operator", entry.role === "operator");
    ok("granted entry records the granting Owner", entry.grantedBy === OWNER);

    await call(OWNER, "POST", "/admin/roles", { email: VIEWER, role: "viewer" });
    await call(OWNER, "POST", "/admin/roles", { email: APPROVER, role: "approver" });

    const list = (await (await call(OWNER, "GET", "/admin/roles")).json()) as Array<{ email: string; role: string }>;
    const byEmail = new Map(list.map((e) => [e.email, e.role]));
    ok("roles list shows the operator grant", byEmail.get(OPERATOR) === "operator");
    ok("roles list shows the approver grant", byEmail.get(APPROVER) === "approver");

    // Revoke (demote to viewer) the operator, then confirm whoami reflects it.
    await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "viewer" });
    const who = (await (await call(OPERATOR, "GET", "/admin/whoami")).json()) as { role: string };
    ok("revoke: operator demoted to viewer takes effect", who.role === "viewer");
    // Re-grant operator for the matrix proofs below.
    await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
    // Explicit delete (offboarding) of a throwaway member works and is idempotent.
    await call(OWNER, "POST", "/admin/roles", { email: "temp@acme.example", role: "operator" });
    const del = (await (await call(OWNER, "POST", "/admin/roles/delete", { email: "temp@acme.example" })).json()) as { deleted: boolean };
    ok("delete removes a member", del.deleted === true);
    const delAgain = (await (await call(OWNER, "POST", "/admin/roles/delete", { email: "temp@acme.example" })).json()) as { deleted: boolean };
    ok("delete is idempotent for an absent member", delAgain.deleted === false);
  }

  // ---- PROOF 3: the per-route role matrix, enforced AT THE ROUTER ------------------------
  // Reads are open to any authenticated role.
  {
    ok("viewer may GET /downpipes", (await call(VIEWER, "GET", "/admin/downpipes")).status === 200);
    ok("viewer may GET /whoami", (await call(VIEWER, "GET", "/admin/whoami")).status === 200);
    ok("viewer may GET /roles (read is not a write)", (await call(VIEWER, "GET", "/admin/roles")).status === 200);

    // These nine reads once called NO capability gate at the router and forwarded to a
    // Durable Object arm that took no caller argument, so "reads are open to any authenticated role" was
    // the comment above this block and nothing else. They now gate: posture.read for the six the
    // posture.read-gated support pack already discloses (notify rules/history, expiry, destinations, push,
    // otlp-push), downpipe.read for the roster-hygiene report whose own comment names GET /downpipes as
    // its read class, and roles.read for the two role-table reads beside GET /roles.
    //
    // WHICH PRINCIPAL THIS RUNS AS IS THE WHOLE POINT. Every pre-existing assertion on these routes calls
    // as OWNER (validate-cov-admin-router-ops.ts asserts "GET /notify/rules is 200" as the owner), and an
    // owner holds all twenty-one capabilities, so not one of them could tell a correct gate from a wrong
    // one. VIEWER is the resting role for any authenticated caller with no grant and holds exactly the
    // seven-capability floor, so it is the least-privileged principal this engine can produce. That makes
    // these the assertions that fail if a later edit tightens one of these reads to a capability above the
    // floor, which is the live risk here: notify.config is the tempting gate for the two notify reads and
    // it would refuse a viewer, a restore-operator and an access-admin, all of whom the console renders
    // these rows to.
    ok("viewer may GET /notify/rules (gated posture.read, the viewer floor)", (await call(VIEWER, "GET", "/admin/notify/rules")).status === 200);
    ok("viewer may GET /notify/history (gated posture.read, the viewer floor)", (await call(VIEWER, "GET", "/admin/notify/history")).status === 200);
    ok("viewer may GET /expiry (gated posture.read, the viewer floor)", (await call(VIEWER, "GET", "/admin/expiry")).status === 200);
    ok("viewer may GET /destinations (gated posture.read, the viewer floor)", (await call(VIEWER, "GET", "/admin/destinations")).status === 200);
    ok("viewer may GET /push (gated posture.read, the viewer floor)", (await call(VIEWER, "GET", "/admin/push")).status === 200);
    ok("viewer may GET /otlp-push (gated posture.read, the viewer floor)", (await call(VIEWER, "GET", "/admin/otlp-push")).status === 200);
    ok("viewer may GET /downpipes/roster-hygiene (gated downpipe.read, the viewer floor)", (await call(VIEWER, "GET", "/admin/downpipes/roster-hygiene")).status === 200);
    ok("viewer may GET /group-roles (gated roles.read, the same cap as GET /roles)", (await call(VIEWER, "GET", "/admin/group-roles")).status === 200);
    ok("viewer may GET /custom-roles (gated roles.read, the same cap as GET /roles)", (await call(VIEWER, "GET", "/admin/custom-roles")).status === 200);
  }

  // A Viewer cannot mutate: create/edit, trigger, drill, delete are all Operator+. The refusal
  // is a JSON 403 (not the plaintext 401), naming the required and held roles.
  {
    const r = await call(VIEWER, "POST", "/admin/downpipes", { id: "x", name: "x", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_x", include: [], exclude: [] } });
    const b = (await r.json()) as { error: string; required: string; have: string };
    ok("viewer create downpipe refused 403", r.status === 403);
    // The gate is capability-based now (contract section 1 + 8): required is the CAPABILITY the route
    // needs (downpipe.write for the upsert), have is the caller's role. The allow/deny for the four
    // existing roles is unchanged; only the `required` string moved from a role to a capability.
    ok("403 body is the forbidden capability gate", b.error === "forbidden" && b.required === "downpipe.write" && b.have === "viewer");
    ok("viewer trigger refused 403", (await call(VIEWER, "POST", "/admin/trigger", { id: "x" })).status === 403);
    ok("viewer drill refused 403", (await call(VIEWER, "POST", "/admin/drill", { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV" })).status === 403);
    ok("viewer delete downpipe refused 403", (await call(VIEWER, "POST", "/admin/downpipes/delete", { id: "x" })).status === 403);
  }

  // An Operator may mutate (these reach the engine/DO; we assert they are NOT gated, i.e. not a
  // 403). A drill/restore against a not-fully-configured engine answers 200 ok:false in-flow,
  // and a create reaches the DO validator; none of those is the 403 we are proving absent.
  {
    const create = await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp1", name: "dp one", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_dp1", include: [], exclude: [] } });
    ok("operator create downpipe is not gated (200)", create.status === 200);
    const trig = await call(OPERATOR, "POST", "/admin/trigger", { id: "dp1" });
    ok("operator trigger is not gated (200)", trig.status === 200);
    const drill = await call(OPERATOR, "POST", "/admin/drill", { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV" });
    ok("operator drill is not gated (200, in-flow ok:false is fine)", drill.status === 200);
  }

  // ---- PROOF 4: the restore hard rule, enforced SERVER-SIDE (direct API) -------------------
  // Dry-run (no confirm) is allowed for ANY role, including viewer (it writes nothing).
  {
    const r = await call(VIEWER, "POST", "/admin/restore", { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV" });
    ok("viewer dry-run restore is allowed (not 403)", r.status === 200);
  }
  // An Operator calling the API DIRECTLY with confirm:true is REFUSED server-side: the control
  // does not live in the SPA. This is the launch-gate proof.
  {
    const r = await call(OPERATOR, "POST", "/admin/restore", { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", confirm: true });
    const b = (await r.json()) as { error: string; required: string; have: string };
    ok("operator restore APPLY refused 403 (the hard rule, server-side)", r.status === 403);
    // The apply gate is the restore.apply capability now; an operator lacks it (only restore-operator/
    // approver/owner hold it), so the same operator-denied outcome holds, with required = the capability.
    ok("restore-apply 403 names restore.apply as required", b.error === "forbidden" && b.required === "restore.apply" && b.have === "operator");
  }
  // An Approver passes the ROLE gate. Restore dual control is OWNER-OPT-IN, so with no policy set there
  // is no approval to be missing: the approver gets 200 with ok:false and "break-glass-only posture: no
  // in-account read-back key", having reached the apply path.
  //
  // THIS GRADES THE ROLE GATE ITSELF rather than the gate behind it, and it does not do that by
  // weakening to "not 403", which would pass for any refusal at all. It names the operator's refusal
  // EXACTLY (the shape asserted twelve lines above: 403, error "forbidden", required "restore.apply")
  // and requires the approver's answer to differ in that specific way, PLUS positive evidence that the
  // apply path was actually reached. Both directions of the opt-in policy are driven end to end through
  // the real DO by validate-restore-approval-optional.ts, so nothing is lost by not re-proving the
  // dual-control refusal here.
  {
    const r = await call(APPROVER, "POST", "/admin/restore", { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", confirm: true });
    const b = (await r.json()) as { error?: string; required?: string; mode?: string };
    ok("approver is NOT refused the way an operator is: no role-forbidden 403 naming restore.apply", !(r.status === 403 && b.error === "forbidden" && b.required === "restore.apply"));
    ok("...and reached the apply path, so the role gate was cleared rather than merely answered differently", b.mode === "applied");
  }

  // ---- PROOF 5: role administration is Owner-only ----------------------------------------
  {
    ok("operator cannot grant roles (403)", (await call(OPERATOR, "POST", "/admin/roles", { email: VIEWER, role: "owner" })).status === 403);
    ok("approver cannot grant roles (403)", (await call(APPROVER, "POST", "/admin/roles", { email: VIEWER, role: "owner" })).status === 403);
    ok("operator cannot delete a member (403)", (await call(OPERATOR, "POST", "/admin/roles/delete", { email: VIEWER })).status === 403);
  }

  // ---- PROOF 6: the last-Owner guard (F3) ------------------------------------------------
  // There is exactly one Owner now. Demoting them, or deleting them, must be refused 400.
  {
    const demote = await call(OWNER, "POST", "/admin/roles", { email: OWNER, role: "viewer" });
    const b1 = (await demote.json()) as { error: string };
    ok("self-demotion of the only Owner refused 400", demote.status === 400);
    ok("last-Owner demote reason is explicit", /last Owner/.test(b1.error));

    const del = await call(OWNER, "POST", "/admin/roles/delete", { email: OWNER });
    const b2 = (await del.json()) as { error: string };
    ok("deleting the only Owner refused 400", del.status === 400);
    ok("last-Owner delete reason is explicit", /last Owner/.test(b2.error));

    // Owner is still Owner (the guard wrote nothing).
    const who = (await (await call(OWNER, "GET", "/admin/whoami")).json()) as { role: string; isOnlyOwner: boolean };
    ok("the guarded Owner is unchanged", who.role === "owner" && who.isOnlyOwner === true);
  }

  // With a SECOND Owner appointed, demoting the first is now allowed (>=1 Owner remains).
  {
    const grant2 = await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
    ok("a second Owner can be appointed", grant2.status === 200);
    // Now the first Owner is no longer the only one.
    const who = (await (await call(OWNER, "GET", "/admin/whoami")).json()) as { isOnlyOwner: boolean };
    ok("with two Owners, neither is isOnlyOwner", who.isOnlyOwner === false);
    const demote = await call(OWNER2, "POST", "/admin/roles", { email: OWNER, role: "approver" });
    ok("demoting one of two Owners is allowed (200)", demote.status === 200);
    // Restore OWNER to owner for any later assertions / cleanliness.
    await call(OWNER2, "POST", "/admin/roles", { email: OWNER, role: "owner" });
  }

  // ---- PROOF 7: the DO re-checks Owner independently of the router (defence in depth) -----
  // Call the DO directly with a NON-Owner caller header; the DO must refuse the role write even
  // though the router (which would 403 first) was bypassed. This proves the authority check is
  // in the DO, not only at the router.
  {
    const operatorCaller: Caller = { method: "access", email: OPERATOR, subject: subjectOf(OPERATOR), role: "operator", groups: [] };
    const r = await sched.stub.fetch("https://scheduler.internal/roles", {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(operatorCaller) },
      body: JSON.stringify({ email: VIEWER, role: "owner" }),
    });
    const b = (await r.json()) as { error?: string };
    ok("DO refuses a role write from a non-Owner caller (defence in depth)", r.status === 403 && typeof b.error === "string" && /forbidden/.test(b.error));
  }
  // And a role write with NO caller header is refused too (fails closed).
  {
    const r = await sched.stub.fetch("https://scheduler.internal/roles", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: VIEWER, role: "owner" }),
    });
    ok("DO refuses a role write with no caller header (fail closed)", r.status === 403);
  }

  // ---- PROOF 8: the auth boundary is unchanged (no credential -> plaintext 401) ----------
  {
    // No Access header and no token configured -> 401 plaintext, NOT a 403 capability gate.
    const r = await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET" }), accessEnv());
    const text = await r.text();
    ok("no credential is 401 (not 403)", r.status === 401);
    ok("401 body is the plaintext sign-in signal", text === "unauthorised");
  }

  // ---- PROOF 9: the token fallback resolves to Owner (documented break-glass) -------------
  {
    // No Access env, only ADMIN_TOKEN: the bare-token caller is the all-or-nothing break-glass
    // and must be able to administer (resolve to owner), since it cannot be attributed.
    const tokenEnv = ({ ...sched.env, ADMIN_TOKEN: "shared-break-glass-token" }) as unknown as Env;
    const r = await handleAdmin(
      new Request("https://engine.example/admin/whoami", { method: "GET", headers: { authorization: "Bearer shared-break-glass-token" } }),
      tokenEnv,
    );
    const who = (await r.json()) as { method: string; email: string | null; role: string };
    ok("token fallback authorises (200)", r.status === 200);
    ok("token fallback is method token, no email", who.method === "token" && who.email === null);
    ok("token fallback resolves to owner (break-glass)", who.role === "owner");
  }

  // ---- PROOF 9b: ADMIN_TOKEN_DISABLED hardens away the token fallback ----------------
  {
    // Same ADMIN_TOKEN as PROOF 9 but with ADMIN_TOKEN_DISABLED set: the bare-token caller is now
    // refused (401, the sign-in signal, NOT downgraded), proving an Enterprise tenant can require
    // verified Access only. A verified Access caller still passes under the same flag (the flag
    // hardens away ONLY the fallback, never Access).
    const disabledTokenEnv = ({ ...sched.env, ADMIN_TOKEN: "shared-break-glass-token", ADMIN_TOKEN_DISABLED: "1" }) as unknown as Env;
    const rTok = await handleAdmin(
      new Request("https://engine.example/admin/whoami", { method: "GET", headers: { authorization: "Bearer shared-break-glass-token" } }),
      disabledTokenEnv,
    );
    ok("ADMIN_TOKEN_DISABLED refuses the token fallback (401)", rTok.status === 401);
    ok("the refusal is the plaintext sign-in signal, not a downgrade", (await rTok.text()) === "unauthorised");

    // A falsey flag value leaves the token path working (the default is preserved unless truly set).
    const falseyEnv = ({ ...sched.env, ADMIN_TOKEN: "shared-break-glass-token", ADMIN_TOKEN_DISABLED: "false" }) as unknown as Env;
    const rFalsey = await handleAdmin(
      new Request("https://engine.example/admin/whoami", { method: "GET", headers: { authorization: "Bearer shared-break-glass-token" } }),
      falseyEnv,
    );
    ok("a falsey ADMIN_TOKEN_DISABLED still allows the token fallback (200)", rFalsey.status === 200);

    // Access still works WITH the flag set: drive a verified Access whoami through an env that has
    // BOTH Access configured and ADMIN_TOKEN_DISABLED. The first Access caller here bootstraps Owner
    // in a fresh DO, so use a separate scheduler to keep this proof self-contained.
    const sched2 = makeScheduler();
    const accessHardenedEnv = ({ ...sched2.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN: "shared-break-glass-token", ADMIN_TOKEN_DISABLED: "1" }) as unknown as Env;
    const rAcc = await handleAdmin(
      new Request("https://engine.example/admin/whoami", { method: "GET", headers: { "cf-access-jwt-assertion": await tokenFor("hardened-owner@acme.example") } }),
      accessHardenedEnv,
    );
    ok("verified Access still authorises under ADMIN_TOKEN_DISABLED (200)", rAcc.status === 200);
    ok("the Access caller is method access (not the disabled token path)", ((await rAcc.json()) as { method: string }).method === "access");
  }

  // ---- PROOF 9c: POST /policy/require-access surfaces the Access-only posture -----
  // The route is a SURFACE/ECHO of the ADMIN_TOKEN_DISABLED posture, gated on access.policy
  // (access-admin/owner). It reads env DIRECTLY (no DO read added to auth) and answers in the router.
  {
    // Grant an access-admin (the people-and-access-policy role) to prove the capability holder, not
    // only owner, can read the posture. OWNER is restored to owner by PROOF 9b's tail.
    const ACCESS_ADMIN = "accessadmin@acme.example";
    await call(OWNER, "POST", "/admin/roles", { email: ACCESS_ADMIN, role: "access-admin" });

    // accessEnv() has Access configured (team domain + AUD) and no ADMIN_TOKEN_DISABLED, so the posture
    // is: token fallback NOT disabled, Access configured, therefore NOT enforced, caller on Access.
    const rOwner = await call(OWNER, "POST", "/admin/policy/require-access");
    const pOwner = (await rOwner.json()) as { tokenFallbackDisabled: boolean; accessConfigured: boolean; enforced: boolean; callerMethod: string };
    ok("require-access: owner is allowed (200)", rOwner.status === 200);
    ok("require-access: reports token fallback not disabled (default posture)", pOwner.tokenFallbackDisabled === false);
    ok("require-access: reports Access configured (team domain + AUD present)", pOwner.accessConfigured === true);
    ok("require-access: enforced is false when the fallback is not disabled", pOwner.enforced === false);
    ok("require-access: reports the caller's own auth method (access)", pOwner.callerMethod === "access");

    const rAdmin = await call(ACCESS_ADMIN, "POST", "/admin/policy/require-access");
    ok("require-access: access-admin (the access.policy holder) is allowed (200)", rAdmin.status === 200);

    // A viewer lacks access.policy, so the route is a JSON 403 capability gate naming the capability.
    const rViewer = await call(VIEWER, "POST", "/admin/policy/require-access");
    const bViewer = (await rViewer.json()) as { error: string; required: string; have: string };
    ok("require-access: viewer is refused 403", rViewer.status === 403);
    ok("require-access: 403 names access.policy as required", bViewer.error === "forbidden" && bViewer.required === "access.policy" && bViewer.have === "viewer");
    // An operator also lacks access.policy (data role, not a people role).
    ok("require-access: operator is refused 403 (lacks access.policy)", (await call(OPERATOR, "POST", "/admin/policy/require-access")).status === 403);

    // Posture reflects env: with ADMIN_TOKEN_DISABLED set AND Access configured, enforced is true.
    // Use a fresh scheduler so the first Access caller bootstraps Owner, with the flag set on the env.
    const sched3 = makeScheduler();
    const hardenedEnv = ({ ...sched3.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN_DISABLED: "1" }) as unknown as Env;
    const rHard = await handleAdmin(
      new Request("https://engine.example/admin/policy/require-access", { method: "POST", headers: { "cf-access-jwt-assertion": await tokenFor("hardened-owner2@acme.example") } }),
      hardenedEnv,
    );
    const pHard = (await rHard.json()) as { tokenFallbackDisabled: boolean; accessConfigured: boolean; enforced: boolean };
    ok("require-access: ADMIN_TOKEN_DISABLED surfaces tokenFallbackDisabled true", pHard.tokenFallbackDisabled === true);
    ok("require-access: enforced is true when the fallback is disabled AND Access is configured", pHard.enforced === true);

    // Posture reflects env: the flag set but NO Access configured is NOT enforced (a lock-out the auth
    // layer already fails closed on); the surface reports enforced false so the console stays honest.
    // Drive the router-internal gate directly with a token owner (no Access env) to read the posture.
    const sched4 = makeScheduler();
    const flagNoAccessEnv = ({ ...sched4.env, ADMIN_TOKEN: "bg-token", ADMIN_TOKEN_DISABLED: "false" }) as unknown as Env;
    // With the flag falsey the token owner can reach the route; assert accessConfigured false there.
    const rNoAccess = await handleAdmin(
      new Request("https://engine.example/admin/policy/require-access", { method: "POST", headers: { authorization: "Bearer bg-token" } }),
      flagNoAccessEnv,
    );
    const pNoAccess = (await rNoAccess.json()) as { accessConfigured: boolean; enforced: boolean; callerMethod: string };
    ok("require-access: accessConfigured false when Access is not wired", pNoAccess.accessConfigured === false);
    ok("require-access: enforced false when Access is not configured", pNoAccess.enforced === false);
    ok("require-access: reports the token break-glass caller method (token)", pNoAccess.callerMethod === "token");
  }
}
