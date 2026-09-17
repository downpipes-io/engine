// validate-authn-failure-audit: the tamper-evident record of a FAILED authentication (ASVS 5.0 V16.3.1).
//
// THE DEFECT THIS EXISTS TO CATCH. Three of the engine's authentication ceremonies refused callers and left
// NOTHING on the hash chain: the SAML ACS, the OIDC / OAuth2 callback, and the step-up re-authentication. All
// three recorded only recordSsoFail / recordCeremonyFault, which write a saturating {count, lastAt} map capped
// at SSO_FAIL_COUNT_CAP -- not ordered, not on the chain, and once saturated unable to separate a sweep that
// stopped in July from one running now. Driven against the real SchedulerDO before the fix, a rejected OIDC
// callback, a rejected SAML ACS and a rejected step-up finish left the chain at exactly the length it started:
// "audit rows before=1 after=1 ... after ACS=1 ... after stepup=1".
//
// AND THE DEFECT THE FIX ITSELF COULD HAVE BEEN. AUDIT_CAP is 10,000 with oldest-first rollover, and the ACS
// and the callback both sit behind the per-IP ceremony limiter that admits 30 requests a minute. A row per
// failure therefore lets one IP evict the entire retained chain -- every role change, key ceremony and restore
// approval in it -- in about five and a half hours. Section 6 below is the assertion that keeps the coalescing
// honest, and section 7 is the one that keeps its ARITHMETIC honest: coalescing that quietly lost attempts
// would be a different lie in the same row.
//
// It drives the REAL SchedulerDO over MockStorage through the production routeIdp / routeStepUp dispatch, the
// same construction validate-cov-sched-scheduler-do-idp.ts uses. Nothing under test is mocked: the only stub
// is Date.now, and only to step past a coalescing window without sleeping for a minute.
//
// Run: node test/validate-authn-failure-audit.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { ADMIN_COUNTERS_KEY, type AdminCounters } from "../src/admin/diag-records.ts";
import { CEREMONY_FAULTS_KEY, type FaultCountAgg } from "../src/sched/sched-fault-core.ts";
import { encodeCaller, roleSubjectKey, CALLER_HEADER, type Caller } from "../src/admin/identity.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import { buildSelfSignedCertPem, IDP_ENTITY, SP_ENTITY, ACS_URL, CONN_ID as SAML_CONN, NAMEID_PERSISTENT } from "./saml-response-fixtures.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ISSUER = "https://oidc.example.com";
const IDP_SSO_URL = "https://idp.example.com/sso";
// The IPs the router forwards from the edge CF-Connecting-IP. Documentation ranges only.
const SAML_IP = "192.0.2.44";
const OIDC_IP = "198.51.100.7";
const STEPUP_IP = "203.0.113.9";
// A credential id that resolves to nothing, so the step-up refuses with unknown_credential: the shape of a
// foreign assertion, or of an attacker inside a live session probing a step-up-gated action.
const UNKNOWN_CRED_ID = "AAAAAAAAAAAAAAAAAAAAAA";

async function main(): Promise<void> {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);

  async function doReq(method: "GET" | "POST", path: string, body?: unknown, caller?: Caller): Promise<Response> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["content-type"] = "application/json";
    if (caller !== undefined) headers[CALLER_HEADER] = encodeCaller(caller);
    return dobj.fetch(new Request(`https://scheduler.internal${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }));
  }
  async function doJson(method: "GET" | "POST", path: string, body?: unknown, caller?: Caller): Promise<Record<string, unknown>> {
    return (await (await doReq(method, path, body, caller)).json()) as Record<string, unknown>;
  }
  async function chain(): Promise<AuditEvent[]> {
    return [...(await storage.list<AuditEvent>({ prefix: "audit:" })).values()].sort((a, b) => a.seq - b.seq);
  }
  /** The authn-failure rows only, in chain order. */
  async function authnRows(): Promise<AuditEvent[]> {
    return (await chain()).filter((e) => e.action === "authn-failure");
  }
  // Both aggregates are FLAT closed-name -> {count, lastAt} records. Reading them through a `counts`
  // wrapper that does not exist returns undefined for every name, which passes every assertion below for
  // the wrong reason -- it did, until `npx tsc -p tsconfig.checkjs.json` refused the index.
  async function adminCount(name: string): Promise<number> {
    return (await storage.get<AdminCounters>(ADMIN_COUNTERS_KEY))?.[name]?.count ?? 0;
  }
  async function ceremonyFaultCount(name: string): Promise<number> {
    return (await storage.get<FaultCountAgg>(CEREMONY_FAULTS_KEY))?.[name]?.count ?? 0;
  }
  const sumAttempts = (rows: AuditEvent[]): number =>
    rows.reduce((n, e) => n + (e.target.kind === "authn-attempt" ? e.target.attempts : 0), 0);

  await storage.put(roleSubjectKey("passkey|founder@acme.example"), { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "owner", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z" });
  const owner: Caller = { method: "token", email: "founder@acme.example", subject: null, role: "owner", groups: [] };
  // The step-up caller: an ALREADY-AUTHENTICATED member. Their session verified them independently of the
  // assertion that is about to fail, which is what makes this the one attributable authn failure in the engine.
  // sourceIp rides the caller header exactly as resolveCaller threads it from CF-Connecting-IP.
  const member: Caller = { method: "access", email: "member@acme.example", subject: `${ISSUER}|member`, role: "operator", groups: [], sourceIp: STEPUP_IP };

  const samlKp = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const samlSpki = new Uint8Array(await crypto.subtle.exportKey("spki", samlKp.publicKey));
  const samlCert = await buildSelfSignedCertPem(samlSpki, samlKp.privateKey, "idp.example");

  const samlProposal = { id: SAML_CONN, kind: "saml", label: "Work IdP", presetId: "generic-saml", enabled: true, idpEntityId: IDP_ENTITY, idpSsoUrl: IDP_SSO_URL, idpSigningCerts: [samlCert], spEntityId: SP_ENTITY, nameIdFormat: NAMEID_PERSISTENT, wantAssertionsSigned: true, allowIdpInitiated: false, clockSkewSec: 120, emailVerifiedPolicy: "trust-idp", emailAttr: "email", groupsAttr: "groups" };
  const oidcProposal = { id: "entra", kind: "oidc", label: "Microsoft Entra ID", presetId: "entra", enabled: true, issuer: ISSUER, clientId: "client-abc", secretRef: { mode: "do-plaintext" }, scopes: ["openid", "email", "profile"], idTokenSigAlgs: ["RS256"], pkce: "required", clientAuth: "client_secret_post", requireNonce: true, rolesClaim: "roles", authorizationEndpoint: `${ISSUER}/authorize`, tokenEndpoint: `${ISSUER}/token`, jwksUri: `${ISSUER}/jwks` };

  const samlCreate = await doJson("POST", "/idp/conn/create", { proposal: samlProposal }, owner);
  const oidcCreate = await doJson("POST", "/idp/conn/create", { proposal: oidcProposal, secret: "super-secret" }, owner);
  ok("setup: both IdP connections were created (the privileged rows this suite must not evict)", samlCreate.ok === true && oidcCreate.ok === true);

  // The seeded privileged rows: two idp-connection-change events. Section 7 asserts they are STILL on the
  // retained chain after a sustained sweep, which is the harm the coalescing exists to prevent.
  const seeded = (await chain()).filter((e) => e.action === "idp-connection-change").map((e) => e.seq);
  ok("setup: two privileged idp-connection-change rows are on the chain", seeded.length === 2);
  ok("setup: no authn-failure row exists yet", (await authnRows()).length === 0);

  // ============================================================================================
  // 1. SAML ACS. A never-minted RelayState: replay, an IdP-initiated response this SP never asked
  //    for, or a probe. Before the fix this recorded an SSO-failure COUNTER and nothing else.
  // ============================================================================================
  {
    const before = (await authnRows()).length;
    const res = await doJson("POST", "/idp/saml/acs", { connId: SAML_CONN, samlResponse: "PHNhbWxwOlJlc3BvbnNlLz4=", relayState: "never-minted-relaystate", acsUrl: ACS_URL, browserBind: "b", sourceIp: SAML_IP });
    ok("SAML: the ACS refuses a never-minted RelayState", res.ok === false);
    const rows = await authnRows();
    const row = rows[rows.length - 1];
    ok("SAML: exactly one authn-failure row was appended", rows.length === before + 1);
    ok("SAML: the row is action authn-failure / outcome failed", row?.action === "authn-failure" && row?.outcome === "failed");
    ok("SAML: the row names the saml method and the step-up-free sso-callback ceremony", row?.actorMethod === "saml" && row?.target.kind === "authn-attempt" && row.target.ceremony === "sso-callback");
    // No identity is verified on a failure, so the chain must not name one. scheduler-do-recovery.ts settled
    // this rule for the sibling break-glass path: an unauthenticated caller must never choose the name the
    // tamper-evident chain records as the actor.
    ok("SAML: the row names NO actor (nothing verified an identity)", row?.actorEmail === null && row?.actorSubject === null);
    ok("SAML: the row carries the edge-forwarded source IP", row?.sourceIp === SAML_IP);
    ok("SAML: the row stands for one attempt", row?.target.kind === "authn-attempt" && row.target.attempts === 1);
  }

  // ============================================================================================
  // 2. OIDC callback. A state the DO never minted is login CSRF, or a replayed authorisation code.
  // ============================================================================================
  {
    const before = (await authnRows()).length;
    const res = await doJson("POST", "/idp/oidc/callback", { connId: "entra", code: "the-code", state: "bogus-state", txnId: "bogus-txn", iss: ISSUER, sourceIp: OIDC_IP });
    ok("OIDC: the callback refuses an unresolvable state", res.ok === false);
    const rows = await authnRows();
    const row = rows[rows.length - 1];
    ok("OIDC: exactly one authn-failure row was appended", rows.length === before + 1);
    // The SUCCESS row this path writes (idp-sign-in) records actorMethod "oidc" for the OAuth2 kind too, with
    // connKind carrying the distinction. A failure that named its method differently from the success beside
    // it would be its own small lie, so the two agree by construction.
    ok("OIDC: the row names the oidc method", row?.actorMethod === "oidc");
    ok("OIDC: the row names NO actor and carries the source IP", row?.actorEmail === null && row?.actorSubject === null && row?.sourceIp === OIDC_IP);
  }

  // ============================================================================================
  // 3. CONNECTION IDENTITY. A RESOLVED connection is named; an unresolved one is NOT. This is the
  //    assertion a future refactor is likeliest to lose, and losing it hands an unauthenticated
  //    caller a chosen string in the tamper-evident chain.
  // ============================================================================================
  {
    const rows = await authnRows();
    const samlRow = rows.find((e) => e.actorMethod === "saml");
    const oidcRow = rows.find((e) => e.actorMethod === "oidc");
    ok("identity: the SAML row names the connection that RESOLVED", samlRow?.target.kind === "authn-attempt" && samlRow.target.connId === SAML_CONN && samlRow.target.connKind === "saml");
    ok("identity: the OIDC row names the connection that RESOLVED", oidcRow?.target.kind === "authn-attempt" && oidcRow.target.connId === "entra" && oidcRow.target.connKind === "oidc");

    const before = (await authnRows()).length;
    await doJson("POST", "/idp/saml/acs", { connId: "no-such-conn", samlResponse: "x", relayState: "never-minted-relaystate", acsUrl: ACS_URL, browserBind: "b", sourceIp: SAML_IP });
    const after = await authnRows();
    const probe = after[after.length - 1];
    ok("identity: a probe at an UNKNOWN connId still records the failure", after.length === before + 1);
    ok("identity: ...and records NEITHER connId NOR connKind (the submitted slug is attacker-chosen)", probe?.target.kind === "authn-attempt" && probe.target.connId === undefined && probe.target.connKind === undefined);
    ok("identity: ...while the ceremony alone still carries the fact", probe?.target.kind === "authn-attempt" && probe.target.ceremony === "sso-callback");
  }

  // ============================================================================================
  // 4. STEP-UP. The one authn failure in the engine with a real actor to name: the caller's session
  //    verified them independently of the assertion that just failed, and step-up gates the
  //    credential delete and the dual-control owner actions.
  // ============================================================================================
  {
    const before = (await authnRows()).length;
    const res = await doJson("POST", "/stepup/finish", { challengeId: "no-such-challenge", credential: { id: UNKNOWN_CRED_ID, response: {} }, rpId: "console.downpipes.io", origin: "https://console.downpipes.io" }, member);
    ok("step-up: the ceremony refuses an unknown credential", res.ok === false && res.reason === "unknown_credential");
    const rows = await authnRows();
    const row = rows[rows.length - 1];
    ok("step-up: exactly one authn-failure row was appended", rows.length === before + 1);
    ok("step-up: the row is ATTRIBUTED to the caller their session verified", row?.actorEmail === "member@acme.example" && row?.actorSubject === `${ISSUER}|member`);
    // actorMethod is the actor's OWN sign-in method, not the factor that failed. The factor is what ceremony
    // says: a step-up is always a passkey assertion, demanded of a caller whose session may have been minted
    // by Access, OIDC or SAML, and recording the factor here would erase which of those it was.
    ok("step-up: actorMethod names how the CALLER signed in, and ceremony names the factor that failed", row?.actorMethod === "access" && row?.target.kind === "authn-attempt" && row.target.ceremony === "step-up");
    ok("step-up: the row carries the caller-header source IP", row?.sourceIp === STEPUP_IP);
    ok("step-up: no connection is named (a step-up is not an IdP callback)", row?.target.kind === "authn-attempt" && row.target.connId === undefined && row.target.connKind === undefined);

    // A malformed body from an authenticated caller is not a failed AUTHENTICATION, and a caller with no
    // identity has no actor to attribute. Neither writes a row; both are already counted elsewhere.
    const n = (await authnRows()).length;
    await doJson("POST", "/stepup/finish", { challengeId: "", credential: { id: UNKNOWN_CRED_ID }, rpId: "console.downpipes.io", origin: "https://console.downpipes.io" }, member);
    await doJson("POST", "/stepup/finish", { challengeId: "c", credential: { id: UNKNOWN_CRED_ID }, rpId: "console.downpipes.io", origin: "https://console.downpipes.io" });
    ok("step-up: a bad_request body and an identity-less caller write NO row", (await authnRows()).length === n);
  }

  // ============================================================================================
  // 5. LEAK CONTROL. The AuditTarget union makes the assertion, the code, the state, the token and
  //    the credential id unrepresentable. Assert it anyway, so a later author who adds a free-form
  //    field to the target finds out here rather than in a customer's exported trail.
  // ============================================================================================
  {
    const rows = await authnRows();
    // A leak check over an EMPTY set passes for the wrong reason. Establish the population first, so this
    // section can never report clean because nothing was written.
    ok("leak: there are rows to check (a leak control over an empty set is not a control)", rows.length >= 4);
    const blob = JSON.stringify(rows);
    const forbidden: Array<[string, string]> = [
      ["the submitted SAMLResponse", "PHNhbWxwOlJlc3BvbnNlLz4="],
      ["the authorisation code", "the-code"],
      ["the OIDC state", "bogus-state"],
      ["the transaction id", "bogus-txn"],
      ["the presented credential id", UNKNOWN_CRED_ID],
      ["the attacker-chosen connId probe", "no-such-conn"],
    ];
    for (const [what, needle] of forbidden) ok(`leak: ${what} is absent from every authn-failure row`, !blob.includes(needle));
  }

  // ============================================================================================
  // 6 + 7. ANTI-AMPLIFICATION AND ITS ARITHMETIC. This is the pair that keeps the fix from being a
  //    regression in one direction and a fiction in the other. Coalescing that lost attempts would
  //    turn an invisible sweep into an under-reported one, so the sum of `attempts` over the rows
  //    must equal the number of failures once the window's tail has been flushed.
  // ============================================================================================
  const realNow = Date.now;
  try {
    const SWEEP = 200;
    const before = await authnRows();
    const beforeN = before.length;
    for (let i = 0; i < SWEEP; i++) {
      await doJson("POST", "/idp/saml/acs", { connId: SAML_CONN, samlResponse: "x", relayState: `sweep-${i}`, acsUrl: ACS_URL, browserBind: "b", sourceIp: SAML_IP });
    }
    const swept = (await authnRows()).length - beforeN;
    // The window writes the FIRST failure immediately and then at most one row per pending-flush ceiling
    // (25), so 200 failures cost at most 9 rows. A tenfold write reduction is the property; the exact
    // figure is asserted loosely so a later change to the ceiling is not a false red.
    ok(`anti-amplification: ${SWEEP} rejected ACS posts cost ${swept} audit rows, not ${SWEEP}`, swept >= 1 && swept <= SWEEP / 10);
    // The seeded privileged rows are the ones a sweep would evict if every failure wrote a row. They are the
    // reason this is a security property and not a storage one.
    const stillThere = (await chain()).filter((e) => e.action === "idp-connection-change").map((e) => e.seq);
    ok("history survival: the privileged idp-connection-change rows are still on the retained chain", stillThere.length === 2 && stillThere.every((s) => seeded.includes(s)));

    // Step past the coalescing window and drive ONE more failure of the same row-identity: it must carry every
    // attempt the window suppressed. Only Date.now is stubbed, and only here; the failures driven above and
    // below do not depend on the clock (they are refused before any assertion window is evaluated).
    const jump = realNow() + 61_000;
    Date.now = () => jump;
    await doJson("POST", "/idp/saml/acs", { connId: SAML_CONN, samlResponse: "x", relayState: "sweep-tail", acsUrl: ACS_URL, browserBind: "b", sourceIp: SAML_IP });
    Date.now = realNow;
    const samlRows = (await authnRows()).filter((e) => e.actorMethod === "saml" && e.target.kind === "authn-attempt" && e.target.connId === SAML_CONN);
    // 1 (section 1) + SWEEP + 1 (the tail) failures have been driven against this exact row-identity.
    ok(`attempts arithmetic: the rows account for every one of the ${SWEEP + 2} failures, none lost to coalescing`, sumAttempts(samlRows) === SWEEP + 2);
    ok("attempts arithmetic: every row stands for at least one attempt", samlRows.length >= 1 && samlRows.every((e) => e.target.kind === "authn-attempt" && e.target.attempts >= 1));
  } finally {
    Date.now = realNow;
  }

  // ============================================================================================
  // 8. NO WOLF CRY. scheduler-do-audit.ts documents at length what happened the last time a failed
  //    passkey login bumped the source-IP-gap counter: the healthy row became byte-identical to the
  //    ongoing-capture-failure row it exists to tell apart. The unattributed rows must not bump it,
  //    and the ATTRIBUTED step-up row must not either, because it carries an IP.
  // ============================================================================================
  ok("no wolf cry: the source-IP-gap counter was not bumped by any authn-failure row", (await adminCount("audit-human-event-missing-source-ip")) === 0);
  // The counter IS live on this suite's data, so the assertion above is not passing because the mechanism
  // is asleep: the ledger it reads has been written by the ceremony faults the step-up refusals recorded.
  ok("no wolf cry: ...and the ledgers it reads were genuinely written, so the zero above is measured", (await ceremonyFaultCount("stepup-unknown-credential")) >= 1);
  ok("no wolf cry: no authn-failure row was dropped by the append guard", (await ceremonyFaultCount("authn-failure-audit-append-failed")) === 0);
  ok("no wolf cry: the row-identity ceiling was never reached", (await ceremonyFaultCount("authn-failure-audit-key-cap")) === 0);

  // ============================================================================================
  // 9. THE CHAIN IS STILL A CHAIN. Every row above went through the one append path, so the
  //    hash chain must still verify: an audit improvement that broke the chain would be a worse
  //    defect than the silence it replaced.
  // ============================================================================================
  const verdict = (await doJson("GET", "/audit/verify")) as { intact?: boolean; breakAtSeq?: number | null };
  ok("chain: the hash chain still verifies end to end with the new rows on it", verdict.intact === true);

  console.log(failures === 0 ? "\nAUTHN-FAILURE-AUDIT VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
