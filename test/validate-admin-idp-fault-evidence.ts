// validate-admin-idp-fault-evidence.ts -- admin/IdP support-pack evidence:
//
//   the SSO failure SUB-CAUSE for OIDC / OAuth2. The provider's own RFC 6749 `error` code (an EXPIRED
//         Entra client secret answers `invalid_client`) is extracted from the token response; nothing else
//         from the body is carried.
//   the SSO failure SUB-CAUSE for SAML, including the two ACTIVE MISCLASSIFICATIONS: an IdP-initiated
//         POST at an SP-initiated-only connection filed under `replay`, and the IdP's own StatusCode -- the one
//         field that says the IdP DECLINED THE USER -- read and classified rather than left to fall into `other`.
//   the IdP SETUP-TIME evidence: the "test connection" probe and the pre-write validator refusals are
//         classified and recorded, so "we tried to add Okta SSO and it never saves" leaves a trace.
//   the Cloudflare API fault, as closed evidence: Cloudflare's NUMERIC codes and a body class survive so a
//         CF EDGE OUTAGE and a TOKEN SCOPE problem are distinguishable rather than both reading as
//         "Cloudflare: HTTP 502".
//   the key ceremony's own failures: an install that dies at PUT #2 leaves the engine HALF-KEYED, and a
//         secret VANISHING (the owner's #1 fear: a deploy that drops SIGNER_PRIVATE) is timestamped.
//   the media re-upload's failure classes and conflict digests: "some videos restored, some failed" names
//         which failure, and can adjudicate a conflict.
//
// REDACTION IS THE POINT OF THIS SUITE. Every case plants a CUSTOMER SENTINEL at the fault site -- in the
// provider's error_description, in the IdP's StatusMessage, in the submitted IdP URL, in the pasted key, in the
// Cloudflare error body, in the media asset id -- drives the real code path, and then SCANS the recorded record
// for it. A classifier may READ a message to SELECT a closed enum member; it may never RETURN or STORE the text.

import { classifySsoFailure, classifySsoSubCode, ssoSubSignalName, oauthErrorMark, oauthErrorMarkFromBody, SSO_SUB_CODES, OAUTH_ERROR_CODES } from "../src/admin/sso-failure-class.ts";
import { classifyIdpTestFailure, classifyIdpValidationRefusal, idpTestSignalName, idpValidationSignalName, IDP_TEST_FAIL_CLASSES, IDP_VALIDATION_CLASSES } from "../src/admin/idp-diag.ts";
import { AUTH_SIGNAL_NAMES } from "../src/admin/auth-signals.ts";
import { cfFaultInfo, cfFaultOf, CfApiFault, CF_BODY_CLASSES, CF_STATUS_CLASSES } from "../src/admin/cf-api.ts";
import { installEngineSecrets, removeOperationalSecrets, keyCeremonyFaultOf, KeyCeremonyFault, KEY_CEREMONY_STEPS, KEY_CEREMONY_CAUSES } from "../src/admin/attach.ts";
import { diffStatus, type StatusSnapshot } from "../src/admin/audit-status.ts";
import { makeMediaUploader, mediaFaultOf, MediaFault, MEDIA_FAULT_CLASSES } from "../src/admin/media-restore.ts";
import { verifySamlResponse } from "../src/admin/saml/response.ts";
import type { SamlConnection } from "../src/admin/idpconn.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// The planted needles. NONE may appear in ANY recorded name, class, count or record.
const SENTINEL = "acme-payroll-crown-jewels";
const SECRET = "dps_customer-secret-9f3a-AKIA-POISON";
const CUSTOMER_URL = `https://login.${SENTINEL}.example.com/oauth2/v2.0/token`;

function scanClean(label: string, subject: unknown): void {
  const json = JSON.stringify(subject ?? null);
  const leaked = [SENTINEL, SECRET, "AKIA-POISON", "example.com", "AADSTS"].filter((p) => json.includes(p));
  ok(`${label} (redaction: no sentinel / secret / URL / provider prose in the record)`, leaked.length === 0);
}

// Every signal this subsystem records MUST be a member of the closed AUTH_SIGNAL_NAMES set: the DO DROPS any
// name outside it (that is the redaction boundary) and the pack projection gates on the SAME array, so a name
// missing here would be silently recorded nowhere and silently projected nowhere.
const SIGNAL_SET: ReadonlySet<string> = new Set(AUTH_SIGNAL_NAMES as readonly string[]);

// ---- the OIDC / OAuth2 sub-cause ---------------------------------------------------------------------

function testOidcSubCause(): void {
  console.log("\nthe provider's OWN OAuth error code reaches the pack, and NOTHING else from the body does");

  // The reject site's body is the real thing: a Microsoft-shaped error response whose error_description carries
  // the tenant, a correlation id and our sentinel. ONLY the `error` token may survive.
  const entraBody = JSON.stringify({
    error: "invalid_client",
    error_description: `AADSTS7000222: The provided client secret keys for app ${SENTINEL} are expired. Visit https://portal.azure.com/${SENTINEL}. Trace ID: ${SECRET}`,
    error_uri: CUSTOMER_URL,
  });
  const mark = oauthErrorMarkFromBody(entraBody);
  ok("the allowlisted OAuth code survives the body as a closed mark", mark === " [oauth:invalid_client]");
  scanClean("the mark built from a hostile error body", mark);

  // The reason the engine builds, with the mark appended to the unchanged prefix.
  const reason = `token endpoint returned 401${mark}`;
  ok("the COARSE code is unchanged by the mark (the connection bucket)", classifySsoFailure(reason) === "connection");
  const sub = classifySsoSubCode(reason);
  ok("the EXPIRED-Entra-secret ticket sub-classifies as invalid-client", sub === "invalid-client");
  ok("the recorded signal name is a member of the closed auth-signal vocabulary", SIGNAL_SET.has(ssoSubSignalName(sub)));
  scanClean("the recorded signal name", ssoSubSignalName(sub));

  // A VENDOR code (not in the spec allowlist) and free prose are DROPPED, not carried.
  ok("a non-allowlisted vendor error code is DROPPED, never carried", oauthErrorMark("AADSTS7000222") === "" && oauthErrorMark(SENTINEL) === "");
  ok("a non-JSON error body (a proxy interstitial) carries no mark", oauthErrorMarkFromBody(`<html>${SENTINEL}</html>`) === "");
  ok("a non-string body carries no mark", oauthErrorMarkFromBody({ error: "invalid_client" }) === "");

  // The rest of the OIDC sub-cause split (each a DIFFERENT remediation, all one `key`/`replay` code today).
  const cases: Array<[string, string]> = [
    [`jwks endpoint carries a duplicate kid: ${SENTINEL}`, "duplicate-kid"],
    ["signing key not found for the id_token kid", "kid-not-found"],
    [`jwks fetch failed: connect ECONNREFUSED ${CUSTOMER_URL}`, "jwks-unusable"],
    [`unacceptable alg: ${SENTINEL}`, "alg-unsupported"],
    ["discovery endpoint returned 403", "discovery-refused"],
    ["discovery document is not json", "discovery-refused"],
    ["token response carried no id_token", "no-id-token"],
    [`nonce mismatch (${SENTINEL})`, "nonce-mismatch"],
    ["unknown, expired or already-used state", "state-replayed"],
    ["transaction id mismatch", "txn-mismatch"],
    ["the resolved subject is not a usable key", "subject-path-miss"],
  ];
  for (const [r, expect] of cases) {
    const got = classifySsoSubCode(r);
    ok(`"${expect}" is selected, and the reason is DISCARDED`, got === expect);
    scanClean(`the ${expect} signal name`, ssoSubSignalName(got));
  }

  // Every OAuth spec code maps to a member of the closed sub-code set (no unmapped code can be admitted).
  ok("every allowlisted OAuth code resolves to a closed sub-code", OAUTH_ERROR_CODES.every((c) => (SSO_SUB_CODES as readonly string[]).includes(classifySsoSubCode(`token endpoint returned 400 [oauth:${c}]`))));
  // A FORGED mark cannot inject a key: an unknown mark falls through to the text rules / unclassified.
  const forged = classifySsoSubCode(`token endpoint returned 400 [oauth:${SENTINEL}]`);
  ok("a FORGED oauth mark cannot inject a sub-code outside the closed set", (SSO_SUB_CODES as readonly string[]).includes(forged));
  scanClean("the forged-mark outcome", ssoSubSignalName(forged));
}

// ---- the SAML sub-cause, including two cases that would otherwise misclassify ----------------------------------

const SAML_CONN: SamlConnection = {
  kind: "saml",
  id: "acme-idp",
  label: "Acme",
  presetId: "generic-saml",
  enabled: true,
  createdAt: "2026-01-01T00:00:00.000Z",
  idpEntityId: "https://idp.example.com/entity",
  idpSsoUrl: "https://idp.example.com/sso",
  idpSigningCerts: ["-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----"],
  spEntityId: "https://console.downpipes.io/saml",
  emailAttr: "email",
  groupsAttr: "groups",
  emailVerifiedPolicy: "trust-idp",
  allowIdpInitiated: false,
} as unknown as SamlConnection;

// A REAL declined-sign-in Response: a non-Success StatusCode, and a StatusMessage carrying the sentinel exactly
// the way a real IdP embeds the user, the tenant and its own internals in that free-prose field.
function declinedResponseB64(statusUri: string): string {
  const xml =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-07-11T00:00:00Z">` +
    `<saml:Issuer>https://idp.example.com/entity</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="${statusUri}"/>` +
    `<samlp:StatusMessage>User ${SENTINEL} is not assigned to this application (trace ${SECRET})</samlp:StatusMessage>` +
    `</samlp:Status></samlp:Response>`;
  return Buffer.from(xml, "utf8").toString("base64");
}

async function testSamlSubCause(): Promise<void> {
  console.log("\nthe IdP's OWN StatusCode is read, and the two misroutes are distinguished");

  const ctx = { acsUrl: "https://console.downpipes.io/admin/saml/acs/acme-idp", expectedInResponseTo: "_req1", now: Date.parse("2026-07-11T00:00:10Z") };
  const declined = await verifySamlResponse(declinedResponseB64("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"), SAML_CONN, ctx as never);
  ok("a DECLINED sign-in is refused (the sign-in outcome is unchanged)", declined.ok === false);
  const reason = declined.ok === false ? declined.reason : "";
  ok("the refusal names the IdP's StatusCode CLASS, not a generic 'no saml:Assertion'", reason.includes("[saml-status:authnfailed]"));
  // The IdP's StatusMessage prose is the one thing that must NOT ride: it is where the user, the tenant and the
  // trace id live. The reason is engine-owned text plus a CLOSED mark, and it is discarded after classification.
  ok("the IdP's free-prose StatusMessage never reaches the reason", !reason.includes(SENTINEL) && !reason.includes(SECRET));
  const declinedSub = classifySsoSubCode(reason);
  ok("a declined user sub-classifies as idp-declined-authnfailed, not the generic `other`", declinedSub === "idp-declined-authnfailed");
  ok("the declined signal is a closed auth-signal name", SIGNAL_SET.has(ssoSubSignalName(declinedSub)));
  scanClean("the declined signal name", ssoSubSignalName(declinedSub));

  const responder = await verifySamlResponse(declinedResponseB64("urn:oasis:names:tc:SAML:2.0:status:Responder"), SAML_CONN, ctx as never);
  const responderReason = responder.ok === false ? responder.reason : "";
  ok("an IdP-SIDE failure classes as responder (wait / check the IdP, do not re-key)", classifySsoSubCode(responderReason) === "idp-declined-responder");
  // A status URI we do not name is still recorded as an IdP decline, honestly unnamed -- never as free text.
  const vendor = await verifySamlResponse(declinedResponseB64(`urn:vendor:${SENTINEL}`), SAML_CONN, ctx as never);
  const vendorReason = vendor.ok === false ? vendor.reason : "";
  ok("an UNKNOWN status URI coarsens to idp-declined-other (never the URI itself)", classifySsoSubCode(vendorReason) === "idp-declined-other");
  ok("an attacker-chosen status URI never reaches the reason", !vendorReason.includes(SENTINEL));

  // The two cases that would otherwise misclassify at the coarse level.
  const idpInit = "IdP-initiated SAML Response is not permitted for this connection";
  ok("idp-initiated classifies coarse-`replay` (the coarse code stays the same)", classifySsoFailure(idpInit) === "replay");
  ok("...while its SUB-cause says idp-initiated-disallowed (a config toggle, not an attack)", classifySsoSubCode(idpInit) === "idp-initiated-disallowed");
  const enc = "encrypted assertions not supported in this build";
  ok("an encrypting IdP sub-classifies as encrypted-assertion-unsupported, not the generic `malformed`", classifySsoSubCode(enc) === "encrypted-assertion-unsupported");

  // The seven-way bearer blend, split at the site that knows.
  const blend: Array<[string, string]> = [
    ["no bearer SubjectConfirmation satisfies Recipient/InResponseTo/NotOnOrAfter [saml-bearer:recipient]", "bearer-recipient-mismatch"],
    ["no bearer SubjectConfirmation satisfies Recipient/InResponseTo/NotOnOrAfter [saml-bearer:expired]", "bearer-expired"],
    ["no bearer SubjectConfirmation satisfies Recipient/InResponseTo/NotOnOrAfter [saml-bearer:inresponseto]", "bearer-inresponseto-mismatch"],
    ["no bearer SubjectConfirmation satisfies Recipient/InResponseTo/NotOnOrAfter [saml-bearer:absent]", "bearer-absent"],
  ];
  for (const [r, expect] of blend) {
    ok(`the bearer blend splits to ${expect}`, classifySsoSubCode(r) === expect);
    ok(`...while its COARSE code stays replay (no behaviour change)`, classifySsoFailure(r) === "replay");
  }

  // Every sub-code has a signal name in the closed vocabulary, or the DO would silently drop it.
  const missing = SSO_SUB_CODES.filter((c) => !SIGNAL_SET.has(ssoSubSignalName(c)));
  ok("EVERY sub-code has a closed auth-signal name (none is silently dropped by the DO)", missing.length === 0);
}

// ---- the IdP setup-time evidence ---------------------------------------------------------------------

function testIdpSetupEvidence(): void {
  console.log("\nthe test-connection probe and the pre-write validator refusals are recorded");

  // The probe's REAL detail strings, with the operator's own URL interpolated into them (which is exactly why
  // the detail may never be stored).
  const probes: Array<[string, string, string, string]> = [
    ["Discovery document", "fail", `Could not fetch ${CUSTOMER_URL}: fetch failed.`, "unreachable"],
    ["Discovery document", "fail", "The discovery endpoint returned HTTP 403 (expected 200). Confirm the issuer is exactly right.", "non-200"],
    ["Discovery document", "fail", "The discovery endpoint did not return JSON. Confirm the issuer points at the OIDC base, not an HTML page.", "non-json"],
    ["Discovery document", "fail", `The discovery document's issuer (https://${SENTINEL}.okta.com) does not match the configured issuer (${CUSTOMER_URL}); sign-in would reject every token.`, "issuer-mismatch"],
    ["Signing keys (JWKS)", "fail", `The JWKS URL is not safe to fetch: ${SENTINEL} resolves to a private address.`, "unsafe-url"],
    ["Signing certificate", "fail", "None of the 2 pasted certificate(s) parsed as an X.509 certificate. Confirm you pasted the full PEM.", "cert-unparseable"],
    ["Signing certificate", "fail", "1 certificate(s) parsed but none is currently within its validity window (expired or not yet valid).", "cert-out-of-window"],
    ["Signing certificate", "warn", "A valid signing certificate is in use, but the soonest expires in about 9 day(s).", "cert-expiring"],
    ["IdP metadata XML", "fail", `The pasted IdP metadata XML did not parse: unexpected token near ${SENTINEL}.`, "metadata-unusable"],
    ["Test connection", "fail", "The connection test could not be completed due to an unexpected error. Re-check the connection fields and try again.", "internal-error"],
    ["Live exchange", "warn", "OAuth2 providers carry no discovery or JWKS to probe read-only; endpoint shape is validated here.", "oauth2-untestable"],
  ];
  for (const [name, status, detail, expect] of probes) {
    const got = classifyIdpTestFailure({ ok: false, checks: [{ name, status, detail }] });
    ok(`the probe's "${expect}" fault is classified from a detail that carries a customer URL`, got?.failClass === expect);
    ok(`...and its recorded signal name is in the closed vocabulary`, got !== null && SIGNAL_SET.has(idpTestSignalName(got.failClass)));
    scanClean(`the ${expect} record`, got === null ? null : { checkId: got.checkId, failClass: got.failClass, signal: idpTestSignalName(got.failClass) });
  }
  // The ENGINE-DEFECT class exists and is distinct: our bugs must stop reading as the customer's misconfiguration.
  ok("the probe's bare catch has its OWN internal-error class (a defect, not a misconfiguration)", (IDP_TEST_FAIL_CLASSES as readonly string[]).includes("internal-error"));
  // A clean pass records nothing (the aggregate must not fill with noise from healthy connections).
  ok("a PASSING probe records nothing at all", classifyIdpTestFailure({ ok: true, checks: [{ name: "Issuer", status: "pass", detail: "ok" }] }) === null);
  // A heading the probe does not own can never enter the record.
  ok("an injected check heading is DROPPED (never a caller-chosen key)", classifyIdpTestFailure({ ok: false, checks: [{ name: SENTINEL, status: "fail", detail: SECRET }] }) === null);

  // The pre-write validator refusals (which 400 before ANY storage write, so nothing else records them).
  const refusals: Array<[string, string]> = [
    [`private_key_jwt client authentication is not yet implemented in this build`, "secret-mode-unsupported"],
    [`idpSigningCerts: a PEM certificate did not parse`, "cert-invalid"],
    [`issuer must be an https URL (got ${CUSTOMER_URL})`, "url-unsafe"],
    [`a connection with id "${SENTINEL}" already exists`, "duplicate-id"],
    [`provide the required value(s): tenantId`, "field-missing"],
  ];
  for (const [reason, expect] of refusals) {
    const cls = classifyIdpValidationRefusal(reason);
    ok(`the "${expect}" pre-write refusal is classified, and the reason is DISCARDED`, cls === expect);
    ok(`...and the recorded name is a closed auth-signal`, SIGNAL_SET.has(idpValidationSignalName(cls)));
    scanClean(`the ${expect} refusal record`, { cls, signal: idpValidationSignalName(cls) });
  }
  ok("every probe fail class has a closed auth-signal name", IDP_TEST_FAIL_CLASSES.every((c) => SIGNAL_SET.has(idpTestSignalName(c))));
  ok("every validation class has a closed auth-signal name", IDP_VALIDATION_CLASSES.every((c) => SIGNAL_SET.has(idpValidationSignalName(c))));
}

// ---- the Cloudflare API fault as closed evidence ------------------------------------------------------

function testCfFault(): void {
  console.log("\nCloudflare's NUMERIC codes + a body class survive; the body itself never does");

  // A real Cloudflare error body: the message names the account and the script (which is why it may not ride).
  const body = { success: false, errors: [{ code: 10000, message: `Authentication error: token cannot access account ${SENTINEL} (${SECRET})` }] };
  const f = cfFaultInfo(body, 403);
  ok("the numeric CF code is carried (a fixed vendor vocabulary, no customer data)", f.cfCodes.length === 1 && f.cfCodes[0] === 10000);
  ok("the status class is the closed 4xx (a TOKEN problem)", f.statusClass === "4xx" && (CF_STATUS_CLASSES as readonly string[]).includes(f.statusClass));
  ok("the body class is json-api-error", f.bodyClass === "json-api-error" && (CF_BODY_CLASSES as readonly string[]).includes(f.bodyClass));
  scanClean("the CF fault record", f);

  // A CF EDGE OUTAGE (an HTML error page, so no JSON at all) is distinguishable from a token problem: each
  // carries its own status class and body class rather than both reading as "Cloudflare: HTTP 502".
  const outage = cfFaultInfo(null, 502);
  ok("a non-JSON 5xx (an edge error page) reads as an OUTAGE, not a token problem", outage.statusClass === "5xx" && outage.bodyClass === "non-json" && outage.cfCodes.length === 0);
  ok("a 429 gets its OWN class (a throttle: slow down, do not re-scope the token)", cfFaultInfo(null, 429).statusClass === "429");

  // The tag round-trips through a throw, and an UNTAGGED throw yields null (its message is never inspected).
  const thrown = new CfApiFault(`could not set the engine secret SIGNER_PRIVATE (Cloudflare: ${SECRET})`, f);
  const read = cfFaultOf(thrown);
  ok("the tag survives the throw with its codes intact", read?.cfCodes[0] === 10000 && read.statusClass === "4xx");
  ok("an UNTAGGED throw yields NULL (its message is never read)", cfFaultOf(new Error(`Cloudflare: ${SENTINEL}`)) === null);
  // A FORGED tag cannot widen the record: the reader re-validates every field.
  const forged = cfFaultOf({ cfFault: { httpStatus: 403, statusClass: SENTINEL, cfCodes: [SENTINEL, 10001], bodyClass: SECRET } });
  ok("a FORGED tag is re-validated: no string can enter cfCodes or bodyClass", forged !== null && forged.cfCodes.length === 1 && forged.cfCodes[0] === 10001 && (CF_BODY_CLASSES as readonly string[]).includes(forged.bodyClass));
  scanClean("the forged-tag record", forged);
}

// ---- the key ceremony's own failures + the presence LOSS ----------------------------------------------

// A key install driven through installEngineSecrets against a stub Cloudflare that refuses the second PUT:
// a half-keyed engine (SIGNER_PRIVATE set, BREAK_GLASS_PUBLIC not).
const GOOD_SIGNER = "A".repeat(86); // shape-only; the loader refuses it, which is the parse case we also want
async function testKeyCeremonyFaults(): Promise<void> {
  console.log("\na half-applied key install and a secret VANISHING are recorded (both were silent)");

  // 1. The PARSE refusal (a struggling ceremony: a truncated / wrong-box paste). Nothing was set, no network call.
  let parseFault: unknown = null;
  try {
    await installEngineSecrets("acct-1", "engine", { token: "cf-token", signerPrivate: SECRET, breakGlassPublic: SECRET }, (async () => new Response("{}")) as unknown as typeof fetch);
  } catch (e) {
    parseFault = e;
  }
  const parseTag = keyCeremonyFaultOf(parseFault);
  ok("a key-paste that will not parse is TAGGED {step: signer, cause: parse}", parseTag?.step === "signer" && parseTag.cause === "parse");
  scanClean("the parse-fault record (the pasted key never rides)", parseTag);

  // 2. The HALF-APPLIED install: PUT #1 succeeds, PUT #2 is refused by Cloudflare with a real error body.
  //    (loadSigner refuses our shape-only key first, so drive the CF arm directly through the tagged throw the
  //    put wrapper builds: the SAME KeyCeremonyFault the route reads, with the SAME CfApiFault cause.)
  const cfCause = new CfApiFault(`could not set the engine secret BREAK_GLASS_PUBLIC (Cloudflare: token cannot access ${SENTINEL})`, cfFaultInfo({ errors: [{ code: 10000, message: SECRET }] }, 403));
  const halfApplied = new KeyCeremonyFault("break-glass", "cf-put", cfCause);
  const halfTag = keyCeremonyFaultOf(halfApplied);
  const halfCf = cfFaultOf((halfApplied as { cause?: unknown }).cause);
  ok("an install that dies at PUT #2 names the STEP it left half-keyed", halfTag?.step === "break-glass" && halfTag.cause === "cf-put");
  ok("...and carries the bounded Cloudflare evidence (status class + CF's own numeric code)", halfCf?.statusClass === "4xx" && halfCf.cfCodes[0] === 10000);
  ok("the step is a member of the closed step vocabulary", (KEY_CEREMONY_STEPS as readonly string[]).includes(halfTag?.step ?? ""));
  ok("the cause is a member of the closed cause vocabulary", (KEY_CEREMONY_CAUSES as readonly string[]).includes(halfTag?.cause ?? ""));
  scanClean("the audit target the route writes", { kind: "key-ceremony", step: halfTag?.step, cause: halfTag?.cause, cfStatusClass: halfCf?.statusClass, cfCodes: halfCf?.cfCodes });

  // 3. The REMOVAL half: a posture switch whose SECOND delete fails leaves the engine half-posture.
  //    removeOperationalSecrets makes THREE calls in order: the durable OPERATIONAL_RETIRED marker PUT
  //    (always first, and fatal -- it must succeed so this test can reach the deletes at all), then
  //    the OPERATIONAL_PRIVATE delete, then the OPERATIONAL_PUBLIC delete. Calls #1 and #2 succeed here so
  //    the failure lands on the step this test exercises: the PUBLIC delete.
  let removeFault: unknown = null;
  const refuseThird = (() => {
    let n = 0;
    return async (_u: string, _i: RequestInit): Promise<Response> => {
      n++;
      if (n <= 2) return new Response(JSON.stringify({ success: true }), { status: 200 });
      return new Response(JSON.stringify({ success: false, errors: [{ code: 10001, message: `denied for ${SENTINEL}` }] }), { status: 403 });
    };
  })();
  try {
    await removeOperationalSecrets("acct-1", "engine", "cf-token", refuseThird as unknown as typeof fetch);
  } catch (e) {
    removeFault = e;
  }
  const removeTag = keyCeremonyFaultOf(removeFault);
  ok("a HALF-APPLIED posture switch names the delete that failed", removeTag?.step === "operational-public" && removeTag.cause === "cf-delete");
  ok("...and carries CF's numeric code, never the refusal body", cfFaultOf((removeFault as { cause?: unknown }).cause)?.cfCodes[0] === 10001);
  scanClean("the removal-fault record", { step: removeTag?.step, cause: removeTag?.cause, cf: cfFaultOf((removeFault as { cause?: unknown }).cause) });

  // 4. The presence loss (the owner's #1 fear: a deploy that silently drops SIGNER_PRIVATE). The engine records
  //    a secret VANISHING, not only one appearing, so "when did it break" has an answer.
  const prior: StatusSnapshot = { presence: { signerConfigured: true, breakGlassConfigured: true, destConfigured: true }, engineVersion: "0.1.9" };
  const { drafts } = diffStatus(prior, { signerConfigured: false, breakGlassConfigured: true, destConfigured: true, engineVersion: "0.1.9" });
  const absent = drafts.find((d) => d.action === "engine-secret-absent");
  ok("a signer that VANISHED emits engine-secret-absent (a bare presence flip would emit nothing)", absent !== undefined);
  ok("...with outcome failed (a tracked secret disappearing is never healthy)", absent?.outcome === "failed");
  ok("...naming the presence BOOLEAN from the fixed vocabulary, never a value", absent?.target.kind === "engine-state" && (absent.target as { detail?: string }).detail === "signerConfigured");
  ok("an unchanged presence emits nothing (no noise on a healthy poll)", diffStatus(prior, { signerConfigured: true, breakGlassConfigured: true, destConfigured: true, engineVersion: "0.1.9" }).drafts.length === 0);
  scanClean("the presence-loss draft", absent);
  void GOOD_SIGNER;
}

// ---- the media re-upload's failure classes + conflict digests -----------------------------------------

async function testMediaFaults(): Promise<void> {
  console.log("\n'some videos restored, some failed' names WHICH failure, and can adjudicate a conflict");

  // 1. OVER THE CAP: a platform limit, not a fault. It must never read as a retryable upload failure.
  const uploader = makeMediaUploader("cf-token", (async () => new Response("{}")) as unknown as typeof fetch);
  let overCap: unknown = null;
  try {
    await uploader.uploadStreamVideo("acct-1", `vid-${SENTINEL}`, new Uint8Array(200_000_001));
  } catch (e) {
    overCap = e;
  }
  const overTag = mediaFaultOf(overCap);
  ok("an over-the-200MB video is tagged over-size-cap (recover it out of band; retrying cannot help)", overTag?.cls === "over-size-cap");
  scanClean("the over-size-cap record (the asset id never rides)", overTag);

  // 2. The conflict: the id is occupied by DIFFERENT live bytes -- the case that produces a dispute ("that
  //    image WAS ours"). Drive the real uploader: POST 409, then the live /blob readback returns different bytes.
  const archived = new Uint8Array([1, 2, 3, 4]);
  const live = new Uint8Array([9, 9, 9, 9]);
  const conflictFetch = (async (url: string, init?: RequestInit): Promise<Response> => {
    if ((init?.method ?? "GET") === "POST") return new Response(JSON.stringify({ success: false, errors: [{ code: 5409, message: `duplicate id ${SENTINEL}` }] }), { status: 409 });
    return new Response(live, { status: 200 }); // the live /blob: DIFFERENT bytes
  }) as unknown as typeof fetch;
  let conflict: unknown = null;
  try {
    await makeMediaUploader("cf-token", conflictFetch).uploadImage("acct-1", `img-${SENTINEL}`, archived);
  } catch (e) {
    conflict = e;
  }
  const cTag = mediaFaultOf(conflict);
  ok("an id occupied by DIFFERENT live bytes is tagged conflict-different-bytes (not a generic failure)", cTag?.cls === "conflict-different-bytes");
  ok("...carrying BOTH digests, so the dispute can be ADJUDICATED from the pack", typeof cTag?.archivedSha384 === "string" && typeof cTag.liveSha384 === "string" && cTag.archivedSha384 !== cTag.liveSha384);
  ok("the digests are bare SHA-384 hex (the receipt's existing irreversible join-key idiom)", /^[0-9a-f]{96}$/.test(cTag?.archivedSha384 ?? "") && /^[0-9a-f]{96}$/.test(cTag?.liveSha384 ?? ""));
  scanClean("the conflict record (the asset id and the CF body never ride)", cTag);

  // 3. A 409 we could NOT adjudicate is its OWN class (we must not guess an idempotent re-restore).
  const unreadable = (async (_u: string, init?: RequestInit): Promise<Response> => {
    if ((init?.method ?? "GET") === "POST") return new Response("{}", { status: 409 });
    return new Response("nope", { status: 503 });
  }) as unknown as typeof fetch;
  let unread: unknown = null;
  try {
    await makeMediaUploader("cf-token", unreadable).uploadImage("acct-1", `img-${SENTINEL}`, archived);
  } catch (e) {
    unread = e;
  }
  ok("an UNADJUDICABLE 409 is its own class (we never guess an idempotent re-restore)", mediaFaultOf(unread)?.cls === "conflict-unreadable");

  // 4. The readback split: verified:false can mean two OPPOSITE things (retry vs escalate), so each is its own signal.
  const landedButUnreadable = (async (_u: string, init?: RequestInit): Promise<Response> => {
    if ((init?.method ?? "GET") === "POST") return new Response(JSON.stringify({ success: true, result: { id: "img-1" } }), { status: 200 });
    return new Response("edge error", { status: 503 }); // the /blob readback is transiently unreadable
  }) as unknown as typeof fetch;
  const res = await makeMediaUploader("cf-token", landedButUnreadable).uploadImage("acct-1", "img-1", archived);
  ok("an upload whose readback is UNREADABLE reports readbackReadable:false (retry, not corrupt)", res.verified === false && res.readbackReadable === false && res.verifiedSha384 === null);

  const landedButWrong = (async (_u: string, init?: RequestInit): Promise<Response> => {
    if ((init?.method ?? "GET") === "POST") return new Response(JSON.stringify({ success: true, result: { id: "img-1" } }), { status: 200 });
    return new Response(live, { status: 200 }); // the /blob WAS read, and it is the WRONG bytes
  }) as unknown as typeof fetch;
  const wrong = await makeMediaUploader("cf-token", landedButWrong).uploadImage("acct-1", "img-1", archived);
  ok("an upload whose readback MISMATCHES reports readbackReadable:true (a real restore failure)", wrong.verified === false && wrong.readbackReadable === true);
  scanClean("the media upload result", wrong);

  // An UNTAGGED throw is honestly counted as upload-failed, never guessed at from its text.
  ok("an UNTAGGED media throw yields null (its message is never inspected)", mediaFaultOf(new Error(`media upload failed for ${SENTINEL} (${SECRET})`)) === null);
  // A FORGED tag cannot inject a class or a non-digest string.
  const forged = mediaFaultOf(new MediaFault("x", { cls: "conflict-different-bytes", archivedSha384: SENTINEL, liveSha384: SECRET } as never));
  ok("a FORGED tag's non-digest fields are DROPPED by the shape gate", forged?.cls === "conflict-different-bytes" && forged.archivedSha384 === undefined && forged.liveSha384 === undefined);
  ok("every fault class is a member of the closed set", MEDIA_FAULT_CLASSES.length > 0 && (MEDIA_FAULT_CLASSES as readonly string[]).includes(overTag?.cls ?? ""));
  scanClean("the forged-tag record", forged);
}

async function main(): Promise<void> {
  console.log("validate-admin-idp-fault-evidence: the admin/IdP support-pack evidence");
  testOidcSubCause();
  await testSamlSubCause();
  testIdpSetupEvidence();
  testCfFault();
  await testKeyCeremonyFaults();
  await testMediaFaults();
  console.log(failures === 0 ? "\nall admin/IdP fault-evidence checks passed" : `\n${failures} check(s) FAILED`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
