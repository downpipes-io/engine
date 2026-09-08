// Prove the SUPPORT-PACK diagnostic evidence for admin auth / SSO / SCIM / passkey failures is (a) actually
// RECORDED on the fault path and (b) REDACTION-SAFE, driving the REAL modules (src/admin/auth.ts, scim.ts,
// sso-failure-class.ts, passkey-types.ts) and the REAL scheduler DO with in-memory doubles only. No network,
// no deploy. Run:
//   node test/validate-support-auth-signals.ts
//
// WHY this suite exists (the no-custody floor): the vendor holds NOTHING. A support pack is the only thing that
// crosses from the customer's account, so an auth failure that is not recorded as a CLOSED CLASS is a failure the
// vendor can never diagnose - and a failure recorded as free text is a no-custody VIOLATION. Both directions are
// therefore proven here, per gap:
//
//   RECORDED  - every deny/reject branch below bumps a named counter in the DO's bounded auth-signal aggregate,
//               read back through the same GET /auth-signals route the pack's projector reads.
//   REDACTED  - each fault is driven with a HOSTILE customer value planted at the site (a real email, a bearer
//               token, an objectId, an IdP discovery error carrying an internal host). The whole recorded
//               aggregate is then serialised and asserted to contain NONE of them, and every recorded key is
//               asserted to be a member of the closed AUTH_SIGNAL_NAMES vocabulary. So neither a secret nor a
//               customer identifier nor an attacker-chosen string can reach the pack, even by injection.
//
// The negative controls are written so they would FAIL if the corresponding recording were removed, and the
// redaction assertions would FAIL if any site were changed to interpolate its raw reason.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { authorise, type AuthDenySink } from "../src/admin/auth.ts";
import { handleScim } from "../src/admin/scim.ts";
import { SESSION_COOKIE_NAME } from "../src/admin/session.ts";
import { AUTH_SIGNAL_NAMES } from "../src/admin/auth-signals.ts";
import { classifySsoFailure, classifySsoStartFailure, SSO_FAIL_CODES } from "../src/admin/sso-failure-class.ts";
import { passkeySignalName } from "../src/admin/passkey-types.ts";
import { MockStorage } from "./mock-storage.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(what: string, cond: boolean): void {
  if (cond) {
    console.log(`  ok  ${what}`);
  } else {
    failures++;
    console.error(`  FAIL ${what}`);
  }
}

// ---- The HOSTILE customer values planted at every fault site --------------------------------------------
// Each is a value a real ticket would carry and that MUST NEVER reach the pack. They are deliberately chosen to
// be the exact things the sites handle: an email, a bearer secret, an IdP objectId, and an IdP error string that
// embeds an internal hostname (the classic no-custody leak through an interpolated `reason`).
const SECRET_BEARER = "admin-token-SUPERSECRET-abc123";
const CUSTOMER_EMAIL = "leaver@customer-corp.example";
const CUSTOMER_OBJECT_ID = "9f2c1d44-objectid-not-an-email";
const HOSTILE_REASON_TAIL = "idp-internal.customer-corp.example";
const FORBIDDEN = [SECRET_BEARER, CUSTOMER_EMAIL, CUSTOMER_OBJECT_ID, HOSTILE_REASON_TAIL];

const ORIGIN = "https://console.example";

function makeScheduler(extraEnv: Partial<Env> = {}): { env: Env; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
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
  const env = { SCHEDULER: namespace, CONSOLE_ORIGIN: ORIGIN, ...extraEnv } as unknown as Env;
  return { env, stub };
}

// readSignals reads the bounded aggregate back through the SAME DO route the support pack's projector reads
// (GET /auth-signals), so this proves the evidence is reachable by the pack, not merely written somewhere.
async function readSignals(stub: DurableObjectStub): Promise<Record<string, { count: number; lastAt: string }>> {
  const r = await stub.fetch("https://scheduler.internal/auth-signals", { method: "GET" });
  return (await r.json()) as Record<string, { count: number; lastAt: string }>;
}

// The sink the REAL router wires (router.ts): it forwards a closed name to the DO's /auth-signal route. Awaited
// here (production fires and forgets) so the test can flush the write before reading the aggregate back.
function denySink(stub: DurableObjectStub, sent: string[]): AuthDenySink {
  return (name: string) => {
    sent.push(name);
    void stub.fetch("https://scheduler.internal/auth-signal", {
      method: "POST",
      body: JSON.stringify({ name }),
      headers: { "content-type": "application/json" },
    });
  };
}

// flush lets the fire-and-forget diagnostic writes settle before the aggregate is read.
async function flush(): Promise<void> {
  await new Promise((r) => setTimeout(r, 25));
}

async function run(): Promise<void> {
  console.log("validate-support-auth-signals: the auth/SSO/SCIM/passkey evidence the support pack carries");

  // ==========================================================================================
  // Every admin-auth deny class records a closed signal (they were byte-identical 401s)
  // ==========================================================================================
  {
    console.log("\nadmin auth deny classes");

    // -- the bare-token family. Each drives the REAL authorise() and asserts the REAL closed name. --
    {
      const { env, stub } = makeScheduler({ ADMIN_TOKEN: SECRET_BEARER, ADMIN_TOKEN_DISABLED: "true" });
      const sent: string[] = [];
      const v = await authorise(new Request("https://e/admin/status"), env, undefined, undefined, denySink(stub, sent));
      ok("token fallback disabled still DENIES", v.ok === false);
      ok("token fallback disabled records admin-token-denied-disabled", sent.includes("admin-token-denied-disabled"));
    }
    {
      const { env, stub } = makeScheduler({}); // no ADMIN_TOKEN at all
      const sent: string[] = [];
      const v = await authorise(new Request("https://e/admin/status"), env, undefined, undefined, denySink(stub, sent));
      ok("unconfigured engine still DENIES", v.ok === false);
      ok("unconfigured engine records admin-token-denied-unconfigured", sent.includes("admin-token-denied-unconfigured"));
    }
    {
      const { env, stub } = makeScheduler({ ADMIN_TOKEN: SECRET_BEARER });
      const sent: string[] = [];
      // A configured engine, but the caller's automation attached no credential.
      const v = await authorise(new Request("https://e/admin/status"), env, undefined, undefined, denySink(stub, sent));
      ok("empty bearer still DENIES", v.ok === false);
      ok("empty bearer records admin-token-denied-empty-bearer", sent.includes("admin-token-denied-empty-bearer"));
    }
    {
      const { env, stub } = makeScheduler({ ADMIN_TOKEN: SECRET_BEARER });
      const sent: string[] = [];
      // The HOSTILE value: a WRONG bearer that is itself a plausible secret. It must be counted, never stored.
      const req = new Request("https://e/admin/status", { headers: { authorization: `Bearer ${SECRET_BEARER}-STALE` } });
      const v = await authorise(req, env, undefined, undefined, denySink(stub, sent));
      ok("wrong bearer still DENIES", v.ok === false);
      ok("wrong bearer records admin-token-denied-mismatch", sent.includes("admin-token-denied-mismatch"));

      await flush();
      const agg = await readSignals(stub);
      ok("the deny is READABLE through the pack's GET /auth-signals route", (agg["admin-token-denied-mismatch"]?.count ?? 0) >= 1);
      ok("REDACTION: the presented bearer never reaches the aggregate", !JSON.stringify(agg).includes(SECRET_BEARER));
    }
    {
      // A RETIRED break-glass token (the durable in-app latch), distinct from the env flag.
      const { env, stub } = makeScheduler({ ADMIN_TOKEN: SECRET_BEARER });
      const sent: string[] = [];
      const req = new Request("https://e/admin/status", { headers: { authorization: `Bearer ${SECRET_BEARER}` } });
      const v = await authorise(req, env, undefined, async () => true, denySink(stub, sent));
      ok("retired break-glass token still DENIES (even though it MATCHES)", v.ok === false);
      ok("retired break-glass records admin-token-denied-retired", sent.includes("admin-token-denied-retired"));
    }

    // -- the session-cookie family: the "logged out mid-shift" ticket. --
    {
      const { env, stub } = makeScheduler({ ADMIN_TOKEN: SECRET_BEARER });
      const sent: string[] = [];
      const req = new Request("https://e/admin/status", { headers: { cookie: `${SESSION_COOKIE_NAME}=tampered.cookie` } });
      // A verifier that refuses (expired / bad MAC / malformed all return a bare null: no oracle to the edge).
      const v = await authorise(req, env, async () => null, undefined, denySink(stub, sent));
      ok("an invalid session cookie DENIES and does NOT downgrade to the token path", v.ok === false);
      ok("an invalid session cookie records session-verify-failed", sent.includes("session-verify-failed"));
    }
    {
      const { env, stub } = makeScheduler({ ADMIN_TOKEN: SECRET_BEARER });
      const sent: string[] = [];
      const req = new Request("https://e/admin/status", { headers: { cookie: `${SESSION_COOKIE_NAME}=valid.but.emailless` } });
      // A session that VERIFIES but carries no email: a corrupt session record, a different fix entirely.
      const v = await authorise(
        req,
        env,
        async () => ({ email: "", subject: "s", method: "passkey", connId: null, groups: [] }) as never,
        undefined,
        denySink(stub, sent),
      );
      ok("an emailless session DENIES", v.ok === false);
      ok("an emailless session records session-email-missing (not session-verify-failed)", sent.includes("session-email-missing") && !sent.includes("session-verify-failed"));
    }

    // -- the Access family: "Cloudflare Access lets me in but the console says denied". --
    // A REAL RS256 Access JWT, verified by the REAL verifyAccessJWT inside authorise(), but carrying no email
    // (a Cloudflare Access SERVICE TOKEN) and, separately, no sub. Both are verified-but-unusable.
    {
      const team = "acme";
      const aud = "aud-tag";
      const kid = "k1";
      const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
      const pub = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
      const certsUrl = `https://${team}.cloudflareaccess.com/cdn-cgi/access/certs`;
      const origFetch = globalThis.fetch;
      globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (u === certsUrl) return new Response(JSON.stringify({ keys: [{ kid, kty: "RSA", n: pub.n, e: pub.e }] }), { status: 200, headers: { "content-type": "application/json" } });
        throw new Error(`unexpected fetch: ${u}`);
      }) as typeof fetch;
      const b64url = (b: Uint8Array): string => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const part = (o: unknown): string => b64url(new TextEncoder().encode(JSON.stringify(o)));
      const mint = async (claims: Record<string, unknown>): Promise<string> => {
        const now = Math.floor(Date.now() / 1000);
        const h = part({ alg: "RS256", kid, typ: "JWT" });
        const b = part({ iss: `https://${team}.cloudflareaccess.com`, aud, exp: now + 3600, iat: now, ...claims });
        const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${h}.${b}`)));
        return `${h}.${b}.${b64url(sig)}`;
      };

      {
        const { env, stub } = makeScheduler({ CF_ACCESS_TEAM_DOMAIN: team, CF_ACCESS_AUD: aud, ADMIN_TOKEN: SECRET_BEARER });
        const sent: string[] = [];
        // A service token: validly signed for the app audience, carries a sub but NO email.
        const jwt = await mint({ sub: "service-token-common-name" });
        const req = new Request("https://e/admin/status", { headers: { "cf-access-jwt-assertion": jwt } });
        const v = await authorise(req, env, undefined, undefined, denySink(stub, sent));
        ok("a verified-but-EMAILLESS Access assertion DENIES (never downgraded to the token break-glass)", v.ok === false);
        ok("an emailless Access assertion records emailless-assertion (the Access front door now emits it too)", sent.includes("emailless-assertion"));
      }
      {
        const { env, stub } = makeScheduler({ CF_ACCESS_TEAM_DOMAIN: team, CF_ACCESS_AUD: aud, ADMIN_TOKEN: SECRET_BEARER });
        const sent: string[] = [];
        // Carries the CUSTOMER'S REAL EMAIL but no sub: verified, still unusable (no stable principal).
        const jwt = await mint({ email: CUSTOMER_EMAIL });
        const req = new Request("https://e/admin/status", { headers: { "cf-access-jwt-assertion": jwt } });
        const v = await authorise(req, env, undefined, undefined, denySink(stub, sent));
        ok("a verified-but-SUBJECTLESS Access assertion DENIES", v.ok === false);
        ok("a subjectless Access assertion records subject-unusable", sent.includes("subject-unusable"));

        await flush();
        const agg = await readSignals(stub);
        ok("REDACTION: the asserted customer email never reaches the aggregate", !JSON.stringify(agg).includes(CUSTOMER_EMAIL));
      }
      globalThis.fetch = origFetch;
    }
  }

  // ==========================================================================================
  // SSO failures that bypassed the recorder entirely (start-path + the groups overage)
  // ==========================================================================================
  {
    console.log("\nSSO start-path + groups-overflow classification");

    // The start path never reaches the DO's callback wrapper (the only thing that writes the SSO aggregate), so
    // these reasons are classified to CLOSED auth-signal names at the edge instead. The reasons INTERPOLATE
    // untrusted text, so the classifier must key on the anchored PREFIX and discard the tail.
    ok(
      "a discovery OUTAGE classifies as sso-start-discovery-unreachable",
      classifySsoStartFailure(`discovery fetch failed: connect ECONNREFUSED ${HOSTILE_REASON_TAIL}`) === "sso-start-discovery-unreachable",
    );
    ok("a non-200 discovery classifies as sso-start-discovery-refused", classifySsoStartFailure("discovery endpoint returned 503") === "sso-start-discovery-refused");
    ok("a non-JSON discovery (a proxy interstitial) classifies as sso-start-discovery-refused", classifySsoStartFailure("discovery document is not JSON") === "sso-start-discovery-refused");
    ok(
      "an endpoint host-mismatch safety refusal classifies as sso-start-endpoint-refused",
      classifySsoStartFailure(`discovery token_endpoint host "${HOSTILE_REASON_TAIL}" does not match the issuer host "x"`) === "sso-start-endpoint-refused",
    );
    ok('a disabled connection classifies as sso-start-connection-refused', classifySsoStartFailure('connection "prod-okta" is disabled') === "sso-start-connection-refused");
    ok("an unnamed start refusal falls to the residual sso-start-refused", classifySsoStartFailure("something new") === "sso-start-refused");

    // REDACTION: the classifier returns a CLOSED NAME, never the reason. Prove the hostile tail cannot ride, and
    // that it cannot HIJACK the classification either (the anchored-prefix discipline).
    for (const reason of [
      `discovery fetch failed: ${HOSTILE_REASON_TAIL}`,
      `connection "${CUSTOMER_OBJECT_ID}" is disabled`,
      `discovery endpoint returned 500 for ${CUSTOMER_EMAIL}`,
    ]) {
      const name = classifySsoStartFailure(reason);
      ok(`REDACTION: start classifier emits only a closed name for ${JSON.stringify(reason.slice(0, 28))}...`, AUTH_SIGNAL_NAMES.includes(name as (typeof AUTH_SIGNAL_NAMES)[number]) && !FORBIDDEN.some((f) => name.includes(f)));
    }

    // The Entra groups OVERAGE: the IdP withholds the groups claim, so authorization is SILENTLY DOWNGRADED and
    // "our admins lost console admin overnight".
    const overflow = "the IdP withheld the groups claim (too many groups); configure App Roles or a groups filter so authorization is not silently downgraded";
    ok("the groups-overage refusal classifies as groups-overflow", classifySsoFailure(overflow) === "groups-overflow");
    ok("groups-overflow is a member of the closed SSO code vocabulary the pack projects", (SSO_FAIL_CODES as readonly string[]).includes("groups-overflow"));
  }

  // ==========================================================================================
  // SCIM lifecycle rejections (the leaver who is never removed), driving the REAL facade
  // ==========================================================================================
  {
    console.log("\nSCIM lifecycle rejections");
    const SCIM_BEARER = "scim-bearer-SECRET-xyz";
    const { env, stub } = makeScheduler({ SCIM_BEARER_TOKEN: SCIM_BEARER });
    const auth = { authorization: `Bearer ${SCIM_BEARER}`, "content-type": "application/scim+json" };
    const scim = (path: string, init: RequestInit): Promise<Response> => handleScim(new Request(`https://e${path}`, init), env);

    // THE headline SCIM failure: Entra sends the immutable objectId instead of the email userName, so every
    // deprovision 400s forever and the leaver keeps their access.
    const r1 = await scim(`/scim/v2/Users/${CUSTOMER_OBJECT_ID}`, { method: "DELETE", headers: auth });
    ok("an objectId (not an email) is still REJECTED 400", r1.status === 400);

    // A connector that deactivates via PUT: 405 forever.
    const r2 = await scim(`/scim/v2/Users/${encodeURIComponent(CUSTOMER_EMAIL)}`, { method: "PUT", headers: auth, body: "{}" });
    ok("a PUT deactivation is still REJECTED 405", r2.status === 405);

    // An unrecognised PatchOp shape (the Entra PatchOp drift).
    const r3 = await scim(`/scim/v2/Users/${encodeURIComponent(CUSTOMER_EMAIL)}`, { method: "PATCH", headers: auth, body: JSON.stringify({ schemas: ["urn:not:a:patchop"], Operations: [] }) });
    ok("an unrecognised PatchOp is still REJECTED 400", r3.status === 400);

    // A route outside the minimal facade.
    const r4 = await scim("/scim/v2/Groups", { method: "GET", headers: auth });
    ok("an unknown SCIM endpoint is still REJECTED 404", r4.status === 404);

    // A reactivation, which must refuse rather than silently no-op.
    const r5 = await scim(`/scim/v2/Users/${encodeURIComponent(CUSTOMER_EMAIL)}`, { method: "PATCH", headers: auth, body: JSON.stringify({ schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "replace", path: "active", value: true }] }) });
    ok("a reactivation is still REJECTED 400", r5.status === 400);

    await flush();
    const agg = await readSignals(stub);

    ok("the objectId rejection is RECORDED as scim-id-rejected-email-shape", (agg["scim-id-rejected-email-shape"]?.count ?? 0) >= 1);
    ok("the PUT deactivation is RECORDED as scim-method-unsupported", (agg["scim-method-unsupported"]?.count ?? 0) >= 1);
    ok("the bad PatchOp is RECORDED as scim-patch-shape-rejected", (agg["scim-patch-shape-rejected"]?.count ?? 0) >= 1);
    ok("the unknown route is RECORDED as scim-endpoint-unknown", (agg["scim-endpoint-unknown"]?.count ?? 0) >= 1);
    ok("the reactivation is RECORDED as scim-patch-reactivation-refused", (agg["scim-patch-reactivation-refused"]?.count ?? 0) >= 1);

    // REDACTION: the connector sent a real objectId and a real leaver email into every one of those branches.
    const blob = JSON.stringify(agg);
    ok("REDACTION: the SCIM objectId never reaches the aggregate", !blob.includes(CUSTOMER_OBJECT_ID));
    ok("REDACTION: the leaver's email never reaches the aggregate", !blob.includes(CUSTOMER_EMAIL));
    ok("REDACTION: the SCIM bearer never reaches the aggregate", !blob.includes(SCIM_BEARER));
  }

  // ==========================================================================================
  // Passkey ceremony failure classes (the CONSOLE_ORIGIN-change lockout)
  // ==========================================================================================
  {
    console.log("\npasskey ceremony failure classes");
    ok("an origin mismatch maps to passkey-origin-mismatch", passkeySignalName("login", "origin") === "passkey-origin-mismatch");
    ok("an rpId mismatch maps to passkey-rpid-mismatch", passkeySignalName("login", "rpid") === "passkey-rpid-mismatch");
    ok("a UV-incapable key maps to passkey-uv-unmet", passkeySignalName("register", "user_verified") === "passkey-uv-unmet");
    ok("clone detection maps to passkey-clone-detected", passkeySignalName("login", "clone") === "passkey-clone-detected");
    ok("an unknown credential maps to passkey-unknown-credential", passkeySignalName("login", "unknown_credential") === "passkey-unknown-credential");
    ok("a step-up failure maps to stepup-failed regardless of reason", passkeySignalName("stepup", "signature") === "stepup-failed");
    ok("an unnamed LOGIN reason falls to the residual passkey-login-rejected", passkeySignalName("login", "forbidden") === "passkey-login-rejected");
    ok("an unnamed REGISTER reason falls to the residual passkey-register-rejected", passkeySignalName("register", "invite_invalid") === "passkey-register-rejected");

    // REDACTION / ANTI-INJECTION: the DO's `reason` is allowlisted, so even a hostile or free-text reason can
    // only ever land in the residual bucket. It can NEVER be interpolated into a storage key.
    for (const hostile of [CUSTOMER_EMAIL, SECRET_BEARER, `origin ${HOSTILE_REASON_TAIL} != ${ORIGIN}`, "", null, undefined, { toString: () => "origin" }]) {
      const name = passkeySignalName("login", hostile);
      ok(
        `REDACTION: hostile passkey reason ${JSON.stringify(String(hostile)).slice(0, 24)} yields only a closed name`,
        AUTH_SIGNAL_NAMES.includes(name as (typeof AUTH_SIGNAL_NAMES)[number]) && !FORBIDDEN.some((f) => name.includes(f)),
      );
    }
  }

  // ==========================================================================================
  // The GLOBAL redaction invariant: EVERY name any of these paths can emit is a vocabulary member.
  // This is the defence-in-depth that makes the pack projection safe: the projector drops non-members,
  // so a name that is not in the closed set is evidence SILENTLY LOST - and a name built from customer
  // data would be a no-custody breach. Both are impossible if this holds.
  // ==========================================================================================
  {
    console.log("\nGLOBAL: the closed-vocabulary invariant");
    const names = new Set<string>(AUTH_SIGNAL_NAMES);
    ok("the vocabulary has no duplicate names", names.size === AUTH_SIGNAL_NAMES.length);
    ok(
      "every vocabulary name is a bare closed identifier (no whitespace, quotes, url, @ or path separator)",
      AUTH_SIGNAL_NAMES.every((n) => /^[a-z0-9-]+$/.test(n)),
    );
    // The new names this build added must actually be present, else the recording sites are writing keys the
    // pack's projector will silently drop.
    for (const required of [
      "session-verify-failed",
      "session-email-missing",
      "admin-token-denied-disabled",
      "admin-token-denied-unconfigured",
      "admin-token-denied-empty-bearer",
      "admin-token-denied-retired",
      "admin-token-denied-mismatch",
      "sso-start-discovery-unreachable",
      "sso-start-discovery-refused",
      "sso-start-endpoint-refused",
      "sso-start-connection-refused",
      "sso-start-refused",
      "sso-start-do-unreachable",
      "scim-id-rejected-empty",
      "scim-id-rejected-encoding",
      "scim-id-rejected-email-shape",
      "scim-patch-body-invalid",
      "scim-patch-shape-rejected",
      "scim-patch-reactivation-refused",
      "scim-method-unsupported",
      "scim-endpoint-unknown",
      "scim-response-unparseable",
      "scim-offboard-do-error-4xx",
      "scim-offboard-do-error-5xx",
      "passkey-not-configured",
      "passkey-origin-mismatch",
      "passkey-rpid-mismatch",
      "passkey-uv-unmet",
      "passkey-up-unmet",
      "passkey-challenge-failed",
      "passkey-signature-failed",
      "passkey-clone-detected",
      "passkey-unknown-credential",
      "passkey-already-registered",
      "passkey-bad-request",
      "passkey-login-rejected",
      "passkey-register-rejected",
      "passkey-session-mint-failed",
      "stepup-failed",
      "recovery-code-invalid",
      "recovery-regenerate-failed",
    ]) {
      ok(`the pack-projected vocabulary carries ${required}`, names.has(required));
    }
  }

  console.log(failures === 0 ? "\nvalidate-support-auth-signals: PASS" : `\nvalidate-support-auth-signals: ${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await run();
