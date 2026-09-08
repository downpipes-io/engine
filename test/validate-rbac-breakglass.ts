// validate-rbac PROOFs 11, 12 and 13: the single-use break-glass bootstrap latch, retiring the
// break-glass token everywhere with no redeploy, and the unchanged
// fresh-tenant default path. Extracted verbatim from test/validate-rbac.ts; the assertions, order and
// expected values are unchanged. Each proof is SELF-CONTAINED (it stands up its own fresh scheduler),
// so this group takes only the signer and the ok() reporter, not the shared ordered context.

import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import { type Signer, TEAM, AUD, makeScheduler } from "./validate-rbac-harness.ts";

export async function runBreakGlass(ok: (label: string, cond: boolean) => void, signer: Signer): Promise<void> {
  const { tokenFor } = signer;

  // ---- PROOF 11: the break-glass bootstrap is SINGLE-USE (bootstrapConsumed latch) ----------------
  // The first Owner is claimed once and once only. After the first Owner exists, the bootstrapConsumed latch
  // is set; even if the role table is later EMPTIED (a hand-cleared store), no bootstrap may mint a second
  // Owner. We prove: the latch is set after the Access bootstrap; emptying the table by API is refused (the
  // last-Owner guard); and a forcibly-emptied table does NOT re-bootstrap the next Access caller (they fall
  // to viewer) nor the bare-token passkey-bootstrap path.
  {
    const s = makeScheduler();
    const accEnv = ({ ...s.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN: "bg-token-11" }) as unknown as Env;
    const callS = async (email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
      const init: RequestInit = {
        method,
        headers: { "cf-access-jwt-assertion": await tokenFor(email), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      return handleAdmin(new Request(`https://engine.example${path}`, init), accEnv);
    };
    const FIRST = "first-owner-11@acme.example";
    // First Access caller bootstraps Owner.
    const who1 = (await (await callS(FIRST, "GET", "/admin/whoami")).json()) as { role: string };
    ok("single-use: the first Access caller bootstraps Owner", who1.role === "owner");
    // The latch is now set: GET /policy/break-glass-disposal (the status read) reports bootstrapConsumed true.
    const disposal = (await (await s.stub.fetch("https://scheduler.internal/policy/break-glass-disposal", { method: "GET" })).json()) as { bootstrapConsumed: boolean };
    ok("single-use: bootstrapConsumed is latched after the first Owner is claimed", disposal.bootstrapConsumed === true);

    // Emptying the role table BY API is refused (the last-Owner guard), so the empty-table window cannot be
    // reached through the product at all - this is the primary defence; the latch is belt-and-braces over it.
    const delLast = await callS(FIRST, "POST", "/admin/roles/delete", { email: FIRST });
    ok("single-use: the last-Owner guard refuses emptying the role table by API", delLast.status === 400);

    // FORCIBLY empty the table (simulate a hand-cleared/corrupted store), then prove no re-bootstrap.
    const roleKeys = await s.storage.list({ prefix: "role:" });
    for (const k of roleKeys.keys()) await s.storage.delete(k);
    const afterClear = await s.storage.list({ prefix: "role:" });
    ok("single-use: precondition - the role table is now empty", afterClear.size === 0);
    // The next Access caller does NOT re-bootstrap (the latch blocks it): they resolve to least-privilege
    // viewer, NOT Owner, and NO new role row is written.
    const who2 = (await (await callS("second-would-be-owner-11@acme.example", "GET", "/admin/whoami")).json()) as { role: string };
    ok("single-use: an emptied table does NOT re-bootstrap a second Owner (latch holds)", who2.role === "viewer");
    const rowsAfter = await s.storage.list({ prefix: "role:" });
    ok("single-use: the refused re-bootstrap wrote NO new Owner row", rowsAfter.size === 0);

    // The bare-token passkey-bootstrap path is also closed once consumed: register/begin on the (empty) table
    // with a valid ADMIN_TOKEN is refused (resolveRegistrationAuthorisation consults the latch). A forbidden
    // begin returns ok:false; it must NOT offer a bootstrap challenge.
    const regBody = { email: "tokenbootstrap-11@acme.example", displayName: "x" };
    const regResp = await handleAdmin(
      new Request("https://engine.example/admin/auth/register/begin", { method: "POST", headers: { authorization: "Bearer bg-token-11", "content-type": "application/json", "CF-Connecting-IP": "203.0.113.11", origin: "https://console.example" }, body: JSON.stringify(regBody) }),
      ({ ...accEnv, CONSOLE_ORIGIN: "https://console.example" }) as unknown as Env,
    );
    const regJson = (await regResp.json()) as { ok?: boolean };
    ok("single-use: a token passkey-bootstrap on an emptied+consumed table is refused (no challenge)", regJson.ok !== true);
  }

  // ---- PROOF 12: retiring the break-glass token refuses it EVERYWHERE (no redeploy) ---------------
  // Once an Owner retires the token, the bare-token fallback is refused at the gate (401, like
  // ADMIN_TOKEN_DISABLED) AND the DO whoami fails it closed to viewer. Only an Owner may retire; a retired
  // token can never un-retire itself.
  {
    const s = makeScheduler();
    const env12 = ({ ...s.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN: "bg-token-12" }) as unknown as Env;
    const callAccess = async (email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
      const init: RequestInit = {
        method,
        headers: { "cf-access-jwt-assertion": await tokenFor(email), "CF-Connecting-IP": "203.0.113.12", origin: "https://console.example", ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      return handleAdmin(new Request(`https://engine.example${path}`, init), ({ ...env12, CONSOLE_ORIGIN: "https://console.example" }) as unknown as Env);
    };
    const tokenReq = (path: string, method: "GET" | "POST" = "GET"): Promise<Response> =>
      handleAdmin(new Request(`https://engine.example${path}`, { method, headers: { authorization: "Bearer bg-token-12" } }), env12);

    const OWNER12 = "owner-12@acme.example";
    const OPER12 = "operator-12@acme.example";
    const ADMIN12 = "accessadmin-12@acme.example";
    // Bootstrap the Owner via Access, and appoint an operator + an access-admin (the non-owner roles that
    // must NOT be able to retire).
    await callAccess(OWNER12, "GET", "/admin/whoami");
    await callAccess(OWNER12, "POST", "/admin/roles", { email: OPER12, role: "operator" });
    await callAccess(OWNER12, "POST", "/admin/roles", { email: ADMIN12, role: "access-admin" });

    // BEFORE retire: the bare token still works (resolves to Owner) - the default is unchanged.
    const before = (await (await tokenReq("/admin/whoami")).json()) as { role: string; method: string };
    ok("retire: before retiring, the bare token still resolves to Owner (default unchanged)", before.role === "owner" && before.method === "token");

    // ONLY AN OWNER MAY RETIRE: an operator and an access-admin are both a JSON 403 (keys.ceremony is
    // owner-exclusive); neither can retire the token.
    const operRetire = await callAccess(OPER12, "POST", "/admin/policy/retire-break-glass-token");
    ok("retire: an operator CANNOT retire (403)", operRetire.status === 403);
    const adminRetire = await callAccess(ADMIN12, "POST", "/admin/policy/retire-break-glass-token");
    ok("retire: an access-admin CANNOT retire (403, keys.ceremony is owner-only)", adminRetire.status === 403);
    // Still live after the refused attempts.
    ok("retire: the token is still live after the refused non-owner attempts", ((await (await tokenReq("/admin/whoami")).json()) as { role: string }).role === "owner");

    // BREAK-GLASS-IN-PLACE GATE: an Owner cannot retire the token while doing so would STRAND the tenant (a
    // sole Owner, no recovery codes acknowledged). The retire is REFUSED (400 with a clear reason) until a
    // way back in exists - here, until a SECOND Owner is appointed. (An operator + an access-admin do NOT
    // count; only a second OWNER or acknowledged recovery codes.)
    const strandedRetire = await callAccess(OWNER12, "POST", "/admin/policy/retire-break-glass-token");
    ok("retire: REFUSED while it would strand the tenant (sole Owner, no recovery codes)", strandedRetire.status === 400);
    const strandedBody = (await strandedRetire.json()) as { error?: string };
    ok("retire: the refusal explains a way back in must exist first", typeof strandedBody.error === "string" && /way back in|recovery codes|second Owner/i.test(strandedBody.error));
    ok("retire: the token is still live after the stranded-retire refusal", ((await (await tokenReq("/admin/whoami")).json()) as { role: string }).role === "owner");

    // Establish a way back in: appoint a SECOND Owner. Now retiring the token cannot strand the tenant.
    const OWNER12B = "owner-12b@acme.example";
    await callAccess(OWNER12, "POST", "/admin/roles", { email: OWNER12B, role: "owner" });

    // A BARE TOKEN cannot retire itself either: the token IS owner-authority, so the router gate passes, but
    // it is the very credential being disposed of - prove it succeeds here (it is still live), THEN that once
    // retired it can never un-retire. (First, the token retiring itself is allowed because it is owner; the
    // point of the control is that AFTER retiring, the token is dead, so it cannot reverse it.)
    // The OWNER (via Access) retires the token - now ALLOWED because a second Owner is a way back in.
    const ownerRetire = await callAccess(OWNER12, "POST", "/admin/policy/retire-break-glass-token");
    const ownerRetireBody = (await ownerRetire.json()) as { breakGlassTokenRetired?: boolean };
    ok("retire: an Owner (via Access) CAN retire the token once a way back in exists (200)", ownerRetire.status === 200 && ownerRetireBody.breakGlassTokenRetired === true);

    // AFTER retire: the bare token is refused at the gate (401 plaintext, like ADMIN_TOKEN_DISABLED), NOT
    // downgraded to anything weaker.
    const afterGate = await tokenReq("/admin/whoami");
    ok("retire: AFTER retiring, the bare token is refused at the gate (401)", afterGate.status === 401);
    ok("retire: the refusal is the plaintext sign-in signal (not a downgrade)", (await afterGate.text()) === "unauthorised");

    // DEFENCE IN DEPTH at the DO: even bypassing the router, the DO whoami fails a token caller closed to
    // viewer while retired (never owner).
    const doWho = (await (await s.stub.fetch("https://scheduler.internal/whoami?method=token", { method: "GET" })).json()) as { role: string };
    ok("retire: the DO whoami fails a token caller closed to viewer while retired (defence in depth)", doWho.role === "viewer");

    // A RETIRED TOKEN CANNOT UN-RETIRE ITSELF: a bare-token POST to the retire endpoint is now refused at the
    // gate (401), so it cannot even reach the route to flip the flag back; and the flag stays retired.
    const tokenUnretire = await tokenReq("/admin/policy/retire-break-glass-token", "POST");
    ok("retire: a retired bare token cannot reach the retire endpoint (401)", tokenUnretire.status === 401);
    const stillRetired = (await (await s.stub.fetch("https://scheduler.internal/policy/break-glass-retired", { method: "GET" })).json()) as { breakGlassTokenRetired: boolean };
    ok("retire: the flag stays retired (a token cannot un-retire itself)", stillRetired.breakGlassTokenRetired === true);

    // An OWNER via Access is unaffected by the retire (it disposes of the TOKEN fallback only, never Access/
    // passkey), and can administer + un-retire if they choose.
    const ownerStillWorks = await callAccess(OWNER12, "GET", "/admin/whoami");
    ok("retire: an Owner via Access still administers after the token is retired", ownerStillWorks.status === 200 && ((await ownerStillWorks.json()) as { role: string }).role === "owner");
  }

  // ---- PROOF 13: a non-retired token on a FRESH tenant still works exactly as today --------------
  // The gate-off / default behaviour is unchanged: a fresh tenant with only ADMIN_TOKEN set (no retire, no
  // disable) authorises the bare token to Owner, byte-identically to PROOF 9. This pins that the new wiring
  // adds NO behaviour change to the default path.
  {
    const s = makeScheduler();
    const env13 = ({ ...s.env, ADMIN_TOKEN: "fresh-token-13" }) as unknown as Env;
    const r = await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET", headers: { authorization: "Bearer fresh-token-13" } }), env13);
    const who = (await r.json()) as { role: string; method: string; email: string | null };
    ok("default: a non-retired token on a fresh tenant authorises (200)", r.status === 200);
    ok("default: it is the owner break-glass, method token, no email (unchanged)", who.role === "owner" && who.method === "token" && who.email === null);
    // A wrong token is still refused.
    const bad = await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET", headers: { authorization: "Bearer wrong-token-13" } }), env13);
    ok("default: a wrong token is still refused (401)", bad.status === 401);
  }
}
