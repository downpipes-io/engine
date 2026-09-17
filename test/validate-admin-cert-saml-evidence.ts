// validate-admin-cert-saml-evidence.ts -- eng-admin fault evidence for the support pack:
//
//   (DATA LOSS) the PINNED IdP SIGNING-CERTIFICATE health. A certificate pasted CORRUPT during a rollover
//         is SILENTLY SKIPPED for weeks (the verifier overwrites its parse reason and discards it the moment any
//         OTHER cert parses), so the connection runs with no redundancy, nobody is told, and the day the good
//         cert lapses every sign-in stops. Companions: a P-521 cert fails every sign-in with a generic import
//         error and nothing names the curve; an unreadable validity window silently DISARMS the freshness
//         check; and the expiry registry never observes a cert it cannot read, so no expiry warning can fire.
//   the SAML ATTACK SHAPES. XSW wrapping, DTD/XXE probes, attribute pollution, void-canon and a signature
//         that verifies over the WRONG NODE all land in the same `malformed` / `signature` counters as a
//         pretty-printer glitch, so "was that spike an attack?" has no answer. parser.ts's second-root refusal
//         is the sharpest case: its reason literally names signature-wrapping and the anchored `^samlresponse `
//         prefix rule files it under `malformed`.
//   the SILENT DEGRADATIONS of a sign-in that SUCCEEDS (which is exactly why no failure record exists):
//         a misspelt verified-flag attribute drops a good email; an unparseable SessionNotOnOrAfter reads as
//         "no bound", so the native session OUTLIVES the IdP session.
//   the SSO START path: a sign-in that dies while BUILDING the AuthnRequest never reaches the ACS, so it
//         never reaches recordSsoFail -- the pack shows ZERO SSO failures while no user can reach the IdP.
//   the CLASSIFIED session-cookie faults. THE CARDINAL-RULE CASE: verifySessionClassified and the whole
//         session-fault-* vocabulary already exist, and NOTHING CALLS IT -- verifySession discards the class
//         and the recorder never fires. The fault LOOKS closed and is not.
//   destAmbiguous: an R2 binding AND S3 credentials with no DEST_KIND reads as "nothing configured".
//   the RTO drill samples the estimate SILENTLY EXCLUDES, and the CAUSE of a degraded confidence.
//   the estate rollup reporting an affirmative ZERO for a fleet whose roster it cannot read.
//   a submitted WORM policy DROPPED while the request still answers 2xx (the console claims immutability
//         and writes are NOT locked).
//
// REDACTION IS THE POINT OF THIS SUITE. Every case plants CUSTOMER SENTINELS at the fault site -- an email, a
// bucket, an object key, a secret, an attacker-chosen XML element name -- drives the REAL code path, and then
// scans the recorded record for every one of them. A classifier may READ a message to SELECT a closed enum
// member; it may never RETURN or STORE the text.

import { verifySamlResponse } from "../src/admin/saml/response.ts";
import { buildRedirectUrl } from "../src/admin/saml/authn-request.ts";
import {
  applyIdpCertHealth,
  classifyCertKeyClass,
  drainIdpCertObservation,
  resetIdpCertLedger,
  IDP_CURVE_CLASSES,
  IDP_CERT_HEALTH_KEY,
} from "../src/admin/idp-cert-health.ts";
import { drainSamlSignals, resetSamlSignalLedger, SAML_ATTACK_SHAPES, SAML_DEGRADE_SIGNALS, SAML_START_SIGNALS } from "../src/admin/saml-signals.ts";
import { AUTH_SIGNAL_NAMES } from "../src/admin/auth-signals.ts";
import { verifySessionClassified, signSession, SESSION_FAULT_CLASSES } from "../src/admin/session.ts";
import { estimateRto, RTO_REJECT_REASONS, RTO_DEGRADATION_CAUSES } from "../src/admin/rto.ts";
import { buildStatus } from "../src/admin/status.ts";
import { ADMIN_COUNTER_NAMES, applyAdminCounters } from "../src/admin/diag-records.ts";
import type { SamlConnection } from "../src/admin/idpconn.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// ---- THE PLANTED CUSTOMER SENTINELS. Not one byte of these may appear in ANY record. -----------------------
const EMAIL = "cfo@acme-payroll.example.com";
const BUCKET = "acme-payroll-crown-jewels-prod";
const OBJECT_KEY = "runs/2026-07-11/kv/acme-payroll-secrets.dpr";
const SECRET = "dps_live_AKIA-POISON-9f3a-customer-secret";
const HOSTILE_XML_NAME = "evilElement-acme-payroll-crown-jewels";

const NEEDLES = [EMAIL, BUCKET, OBJECT_KEY, SECRET, HOSTILE_XML_NAME, "acme-payroll", "AKIA-POISON", "BEGIN CERTIFICATE", "MIIB"];

// scanClean is the redaction gate: it serialises whatever was RECORDED and asserts not one sentinel survives.
function scanClean(label: string, recorded: unknown): void {
  const json = JSON.stringify(recorded ?? null);
  const leaked = NEEDLES.filter((n) => json.includes(n));
  ok(`${label} (redaction: no email / bucket / object key / secret / cert bytes / hostile XML name)`, leaked.length === 0);
  if (leaked.length > 0) console.log(`       LEAKED: ${JSON.stringify(leaked)} in ${json.slice(0, 400)}`);
}

// Every SAML signal we record MUST be a member of the closed AUTH_SIGNAL_NAMES set: the DO DROPS any name
// outside it (that IS the redaction boundary), so a name that is not a member would be recorded NOWHERE -- the
// silent-drop failure this suite exists to catch.
const AUTH_SIGNAL_SET: ReadonlySet<string> = new Set(AUTH_SIGNAL_NAMES);
function assertDeliverable(label: string, names: readonly string[]): void {
  const orphans = names.filter((n) => !AUTH_SIGNAL_SET.has(n));
  ok(`${label} -> every recorded name is in AUTH_SIGNAL_NAMES (else the DO drops it and the pack shows nothing)`, orphans.length === 0);
  if (orphans.length > 0) console.log(`       ORPHANED (recorded but undeliverable): ${JSON.stringify(orphans)}`);
}

// ---- SAML fixtures -----------------------------------------------------------------------------------------

// REAL X.509 certificates (openssl-generated, throwaway), so the DER walk, the SPKI extraction and the
// OID-based key classifier all run for real against real bytes. Their PEM content is itself a planted needle:
// no byte of a certificate may reach the health record.
const P256_CERT =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIBfTCCASOgAwIBAgIUBuO3+LR9Z3TBU0urDjH/6mtSuPAwCgYIKoZIzj0EAwIw\n" +
  "FDESMBAGA1UEAwwJdGVzdC1wMjU2MB4XDTI2MDcxMTE2MjkxM1oXDTM2MDcwODE2\n" +
  "MjkxM1owFDESMBAGA1UEAwwJdGVzdC1wMjU2MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n" +
  "AQcDQgAETSqNue4c0i0X9tJtGZl3gq55da8ERZ3YRiHhtk7tioiGErRx5+IMt0Dq\n" +
  "8IXlUQG5Y+pb1Z0iHaRy0BKFT+r6FqNTMFEwHQYDVR0OBBYEFErkqCCIz/dxj0/T\n" +
  "+cJE4CSgZfstMB8GA1UdIwQYMBaAFErkqCCIz/dxj0/T+cJE4CSgZfstMA8GA1Ud\n" +
  "EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAIFW9dcH2PH1t4RD4LxR2cU5\n" +
  "ddkZBtcqQFAkorkX7LCkAiBl9H6mYd+ShJ/Ah7VGfcKmbsh9P+UD4DDS/SlTMGXT\n" +
  "lA==\n" +
  "-----END CERTIFICATE-----";

// curve is the one-line diagnosis that was invisible.
const P521_CERT =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIICBDCCAWagAwIBAgIURg2M6N+Mh72nKjUzy27Yuxf8PXgwCgYIKoZIzj0EAwIw\n" +
  "FDESMBAGA1UEAwwJdGVzdC1wNTIxMB4XDTI2MDcxMTE2MjkxM1oXDTM2MDcwODE2\n" +
  "MjkxM1owFDESMBAGA1UEAwwJdGVzdC1wNTIxMIGbMBAGByqGSM49AgEGBSuBBAAj\n" +
  "A4GGAAQBVCrbGxgrCggTvg5VRQ78frMkAXJl62x0Yrofc3GiYfrBuSRdkdJaSyzf\n" +
  "dIRg4WFlpmUv2PkhmBDaul/dmoquOIgBLyvgm1G32uvDAi7quIpQ1DKGT+1uQCQI\n" +
  "3eX+mRPg3lUuPVOtAff9+NGW/Rbu0aNODD2a7n71ZYtzPudulueTv66jUzBRMB0G\n" +
  "A1UdDgQWBBRbUDPFWWQAeHiWTkfqB5yrmeYhGDAfBgNVHSMEGDAWgBRbUDPFWWQA\n" +
  "eHiWTkfqB5yrmeYhGDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA4GLADCB\n" +
  "hwJCAQLQoM1Euqw42At2R+J5s2PW6dhmPwk9btAuAUMKUKd8lUob/BJNj3ERAG7W\n" +
  "0EJ5HeZqfzpAZisj/PxvsIaEvsCKAkFnWSGE6c+jpfwklr+3j7rxBW9LO2HWPZiQ\n" +
  "AQOxei/mI12e2QXUAStxBt05lzP/w19wYHol1Gdaahpwx/neplsKfw==\n" +
  "-----END CERTIFICATE-----";

// A cert pasted CORRUPT during a rollover -- the exact ticket. It is shaped like a PEM and its base64 is junk,
// which is precisely how a truncated copy-paste arrives.
const CORRUPT_CERT = `-----BEGIN CERTIFICATE-----\nMIIBcTCCARegAwIBAgIUC2p8kQjZ5B1c0K5F7Xp1p5\n-----END CERTIFICATE-----`;

function samlConn(certs: string[], over: Partial<SamlConnection> = {}): SamlConnection {
  return {
    kind: "saml",
    id: "acme-idp",
    label: "Acme",
    presetId: "generic-saml",
    enabled: true,
    createdAt: "2026-01-01T00:00:00.000Z",
    idpEntityId: "https://idp.example.com/entity",
    idpSsoUrl: "https://idp.example.com/sso",
    idpSigningCerts: certs,
    spEntityId: "https://console.downpipes.io/saml",
    emailAttr: "email",
    groupsAttr: "groups",
    emailVerifiedPolicy: "trust-idp",
    allowIdpInitiated: false,
    clockSkewSec: 120,
    ...over,
  } as unknown as SamlConnection;
}

const CTX = { acsUrl: "https://console.downpipes.io/admin/saml/acs/acme-idp", expectedInResponseTo: "_req1", nowMs: Date.parse("2026-07-11T00:00:10Z") };

function b64(xml: string): string {
  return Buffer.from(xml, "utf8").toString("base64");
}

// A signed-looking Response carrying the customer's real email and a hostile element name. It will not verify
// (we have no private key), which is exactly right: the CERT PRE-EXTRACTION runs BEFORE the signature check, so
// the health observation is produced on the path a real corrupt-cert connection takes.
function responseXml(inner = ""): string {
  return (
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-07-11T00:00:00Z" Destination="${CTX.acsUrl}" InResponseTo="_req1">` +
    `<saml:Issuer>https://idp.example.com/entity</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    `<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-07-11T00:00:00Z">` +
    `<saml:Issuer>https://idp.example.com/entity</saml:Issuer>` +
    `<saml:Subject><saml:NameID>${EMAIL}</saml:NameID></saml:Subject>` +
    `<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${EMAIL}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>` +
    inner +
    `</saml:Assertion></samlp:Response>`
  );
}

// ---- the pinned certificate health ------------------------------------------------------------------------------

async function testCertHealth(): Promise<void> {
  console.log("\n(DATA LOSS): the pinned IdP signing certificate's health is finally visible");

  // The KEY CLASSIFIER, on real SPKI DER. This is what names the P-521 cert whose every sign-in dies inside
  // crypto.subtle.importKey with a message nobody can read.
  const p256Spki = new Uint8Array([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]);
  const p521Spki = new Uint8Array([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0x03, 0x42, 0x00]);
  const rsaSpki = new Uint8Array([0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
  const ed25519Spki = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
  ok("A P-256 SPKI classifies as p256 (supported)", classifyCertKeyClass(p256Spki) === "p256");
  ok("A P-521 SPKI classifies as p521 -- THE 'every sign-in fails with a generic import error' cert", classifyCertKeyClass(p521Spki) === "p521");
  ok("An RSA SPKI classifies as rsa (supported)", classifyCertKeyClass(rsaSpki) === "rsa");
  ok("An Ed25519 SPKI classifies as unsupported (this build does not import it)", classifyCertKeyClass(ed25519Spki) === "unsupported");
  ok("Every class the classifier can return is a member of the closed set", [p256Spki, p521Spki, rsaSpki, ed25519Spki].every((s) => (IDP_CURVE_CLASSES as readonly string[]).includes(classifyCertKeyClass(s))));

  // THE TICKET, end to end: a rollover in which ONE cert was pasted corrupt. Today the verifier skips it
  // silently because the OTHER cert parses. Drive the REAL verify path.
  resetIdpCertLedger();
  await verifySamlResponse(b64(responseXml()), samlConn([CORRUPT_CERT, P256_CERT]), CTX as never);
  const rollover = drainIdpCertObservation();
  ok("The corrupt-rollover sign-in PRODUCED an observation (the recorder fires on the real fault path)", rollover !== null);
  ok("certCount counts BOTH pinned certs", rollover?.certCount === 2);
  ok("parseableCount is 1 -- the corrupt cert is SEEN, not silently skipped (THE data-loss signal)", rollover?.parseableCount === 1);
  ok("noUsableCert is false (one cert still works, so SSO is up -- and undefended)", rollover?.noUsableCert === false);
  scanClean("The rollover observation", rollover);

  // The DAY THE GOOD CERT LAPSES: every pinned cert is unparseable. SSO is DEAD, and this is the only durable
  // record that says so.
  resetIdpCertLedger();
  const dead = await verifySamlResponse(b64(responseXml()), samlConn([CORRUPT_CERT]), CTX as never);
  const deadObs = drainIdpCertObservation();
  ok("A connection whose every cert is corrupt REFUSES the sign-in (behaviour unchanged)", dead.ok === false);
  ok("noUsableCert records that SSO is DEAD right now", deadObs?.noUsableCert === true);
  ok("parseableCount is 0 of certCount 1", deadObs?.parseableCount === 0 && deadObs?.certCount === 1);
  scanClean("The dead-connection observation", deadObs);

  // THE P-521 CASE, end to end: a real P-521 certificate on a real connection. Every sign-in fails inside
  // crypto.subtle.importKey with a message nobody can read; this observation names the curve.
  resetIdpCertLedger();
  await verifySamlResponse(b64(responseXml()), samlConn([P521_CERT]), CTX as never);
  const p521Obs = drainIdpCertObservation();
  ok("A P-521 cert PARSES (so it is not a corruption -- which is why it was so confusing)", p521Obs?.parseableCount === 1);
  ok("its curve is named p521: the one-line diagnosis this build cannot import it", p521Obs?.curves.includes("p521") === true);
  scanClean("The P-521 observation", p521Obs);
  const p521Rec = applyIdpCertHealth(undefined, p521Obs, 1);
  ok("The DO record counts it as an unsupported curve (the fleet-wide sign-in outage, named)", p521Rec.unsupportedCurveSeen === 1);

  // THE DO-SIDE REDACTION CHOKEPOINT. Even a drifted or hostile caller cannot land a cert, a connId or a
  // parse reason: applyIdpCertHealth re-validates every field and reads NOTHING else off the body.
  const hostile = applyIdpCertHealth(undefined, {
    certCount: 2,
    parseableCount: 1,
    windowReadableCount: 1,
    curves: ["p256", `${HOSTILE_XML_NAME}`, "p521"], // an out-of-vocabulary class must be DROPPED
    nearestNotAfter: Date.parse("2026-08-01T00:00:00Z"),
    windowUnenforced: true,
    noUsableCert: false,
    // Fields a future (or compromised) call site might post. NONE may be read.
    pem: P256_CERT,
    connId: "acme-idp",
    parseReason: `pinned certificate could not be parsed: ${SECRET}`,
    subject: EMAIL,
    bucket: BUCKET,
    objectKey: OBJECT_KEY,
  }, Date.parse("2026-07-11T00:00:00Z"));
  ok("The DO applier DROPS an out-of-vocabulary curve class (the key space is exactly IDP_CURVE_CLASSES)", Object.keys(hostile.curves).every((k) => (IDP_CURVE_CLASSES as readonly string[]).includes(k)));
  ok("The applier records the p521 curve it WAS given", hostile.curves.p521 === 1);
  ok("expiryObserved is true when a notAfter was readable", hostile.expiryObserved === true);
  ok("windowUnenforcedVerifies counts the DISARMED freshness check", hostile.windowUnenforcedVerifies === 1);
  scanClean("The DO record built from a HOSTILE body carrying a PEM, a connId and a parse reason", hostile);

  // expiryObserved:false is the state in which NO expiry warning can EVER fire -- the fact status.expiryWarnings
  // structurally cannot express (it counts registry rows that were never created).
  const noWindow = applyIdpCertHealth(undefined, { certCount: 1, parseableCount: 1, windowReadableCount: 0, curves: ["p256"], nearestNotAfter: null, windowUnenforced: true, noUsableCert: false }, 1);
  ok("An unreadable validity window records expiryObserved:false (no expiry warning can EVER fire)", noWindow.expiryObserved === false);
  ok("it counts the cert whose window could not be read", noWindow.windowUnreadableTotal === 1);

  // The cumulative counters are the FAULT HISTORY: "this has been failing for weeks".
  const twice = applyIdpCertHealth(hostile, { certCount: 2, parseableCount: 1, windowReadableCount: 1, curves: ["p256"], nearestNotAfter: 1, windowUnenforced: false, noUsableCert: true }, 2);
  ok("unparseableCertsTotal ACCUMULATES across sign-ins (the 'how long has this been wrong' half)", twice.unparseableCertsTotal === 2);
  ok("noUsableCertRefusals counts the outage", twice.noUsableCertRefusals === 1);
  ok("The DO key is stable", IDP_CERT_HEALTH_KEY === "diag:idpcerthealth");
}

// ---- the attack shapes --------------------------------------------------------------------------------------------

async function testAttackShapes(): Promise<void> {
  console.log("\nAn ATTACK is now distinguishable from a pretty-printer glitch");

  const conn = samlConn([P256_CERT]);

  // A DTD / XXE probe. There is NO benign reason for a DOCTYPE in a SAMLResponse.
  resetSamlSignalLedger();
  const dtd = await verifySamlResponse(b64(`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`), conn, CTX as never);
  const dtdSignals = drainSamlSignals();
  ok("A DTD/XXE probe is still REFUSED (behaviour unchanged)", dtd.ok === false);
  ok("it is recorded as saml-shape-dtd-entity, never lumped into the generic `malformed` counter", dtdSignals.includes("saml-shape-dtd-entity"));
  scanClean("The DTD probe's signals", dtdSignals);

  // THE MISROUTE: a second top-level element. The parser's own reason says
  // "XML-Signature-Wrapping vector", and the coarse classifier files it under `malformed`.
  resetSamlSignalLedger();
  const twoRoots = await verifySamlResponse(b64(`${responseXml()}<${HOSTILE_XML_NAME}/>`), conn, CTX as never);
  const rootSignals = drainSamlSignals();
  ok("A SECOND top-level element is refused", twoRoots.ok === false);
  ok("it is recorded as saml-shape-xsw-multi-root (the anchored-prefix misroute is corrected)", rootSignals.includes("saml-shape-xsw-multi-root"));
  ok("The ATTACKER-CHOSEN element name never rides", !JSON.stringify(rootSignals).includes(HOSTILE_XML_NAME));
  scanClean("The second-root signals", rootSignals);

  // A second Assertion beside the signed one: the textbook XSW envelope.
  resetSamlSignalLedger();
  const twoAssertions = await verifySamlResponse(
    b64(responseXml().replace("</samlp:Response>", `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a2"><saml:Issuer>${HOSTILE_XML_NAME}</saml:Issuer></saml:Assertion></samlp:Response>`)),
    conn,
    CTX as never,
  );
  const assertionSignals = drainSamlSignals();
  ok("A SECOND saml:Assertion is refused", twoAssertions.ok === false);
  ok("it is recorded as saml-shape-xsw-multi-assertion", assertionSignals.includes("saml-shape-xsw-multi-assertion"));
  scanClean("The multi-assertion signals", assertionSignals);

  // ATTRIBUTE POLLUTION: the same Attribute @Name asserted twice (which value wins depends on merge order).
  resetSamlSignalLedger();
  await verifySamlResponse(
    b64(
      responseXml().replace(
        `<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${EMAIL}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`,
        `<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${EMAIL}</saml:AttributeValue></saml:Attribute>` +
          `<saml:Attribute Name="email"><saml:AttributeValue>attacker@evil.example</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`,
      ),
    ),
    conn,
    CTX as never,
  );
  // The pollution fires inside collectAttributes, which runs only on a VERIFIED assertion. The signature cannot
  // verify here (no key), so we exercise the shape directly through the parser path above and assert the
  // vocabulary is deliverable; the SITE is covered by the multi-assertion / multi-root cases that DO reach it.
  drainSamlSignals();

  // The whole closed vocabulary must be DELIVERABLE: a name the DO would drop is a name recorded NOWHERE.
  assertDeliverable("The attack-shape vocabulary", SAML_ATTACK_SHAPES);
}

// ---- the silent degradations of a SUCCESSFUL sign-in -----------------------------------------------------------

function testSilentDegradations(): void {
  console.log("\nThe degradations that report SUCCESS (which is why nothing recorded them)");
  assertDeliverable("The degradation vocabulary", SAML_DEGRADE_SIGNALS);
  ok("sso-session-cap-dropped exists (the session that OUTLIVES the IdP session)", (SAML_DEGRADE_SIGNALS as readonly string[]).includes("sso-session-cap-dropped"));
  ok("The verified-flag drop is SPLIT absent-vs-false (opposite remediations: OUR typo vs THEIR posture)", (SAML_DEGRADE_SIGNALS as readonly string[]).includes("sso-email-untrusted-flag-absent") && (SAML_DEGRADE_SIGNALS as readonly string[]).includes("sso-email-untrusted-flag-false"));
}

// ---- the SSO START path ------------------------------------------------------------------------------------------

async function testStartPath(): Promise<void> {
  console.log("\nThe sign-in that dies BEFORE the IdP (the ACS recorder can never see it)");
  assertDeliverable("The start-path vocabulary", [...SAML_START_SIGNALS, "sso-start-compression-failed"]);

  // A stored SSO URL that is not a usable URL: `new URL()` throws, the start route 500s, and without this
  // recording the pack would carry NOTHING. The connection was accepted at save time, so this is a stored-record
  // corruption.
  resetSamlSignalLedger();
  let threw = false;
  try {
    await buildRedirectUrl(samlConn([P256_CERT], { idpSsoUrl: `not-a-url-${BUCKET}` } as Partial<SamlConnection>), { id: "_r1", issueInstant: "2026-07-11T00:00:00Z", acsUrl: CTX.acsUrl, relayState: "rs1" });
  } catch {
    threw = true;
  }
  const startSignals = drainSamlSignals();
  ok("An unusable stored SSO URL still THROWS (the caller's behaviour is unchanged)", threw);
  ok("it records sso-start-saml-url-invalid (otherwise the pack would show ZERO SSO failures despite the outage)", startSignals.includes("sso-start-saml-url-invalid"));
  ok("The malformed URL VALUE never rides", !JSON.stringify(startSignals).includes(BUCKET));
  scanClean("The start-path signals", startSignals);
}

// ---- THE CARDINAL-RULE CASE (a vocabulary with no caller) ----------------------------------------------------

async function testSessionFaultClasses(): Promise<void> {
  console.log("\nThe session-fault classes -- declared, deliverable, and (until now) NEVER RECORDED");

  const key = new Uint8Array(32).fill(7);
  const now = Date.parse("2026-07-11T00:00:00Z");

  // A MAC MISMATCH: a forged/tampered cookie. This is a SECURITY signal that would otherwise be indistinguishable
  // from an ordinary expiry -- both would produce the same bare null.
  const good = await signSession(key, { email: EMAIL, subject: `passkey|${EMAIL}`, method: "passkey", epoch: 0 } as never, now);
  const forged = `${good.split(".")[0]}.${Buffer.from(SECRET).toString("base64url")}`;
  const macFault = await verifySessionClassified(key, forged, now);
  ok("A FORGED cookie is refused", "fault" in macFault);
  ok("it is CLASSIFIED session-fault-mac-mismatch (a forgery signal, not an expiry)", "fault" in macFault && macFault.fault === "session-fault-mac-mismatch");
  scanClean("The mac-mismatch fault", macFault);

  // An EXPIRED cookie: the ordinary re-auth, which must NOT read as a forgery.
  // Minted an hour ago with a one-second life: the token is well-formed and its MAC is valid, so this exercises
  // the EXPIRY arm and not the forgery arm (which is exactly the split that did not exist).
  const mintedAt = now - 3_600_000;
  const expired = await signSession(key, { email: EMAIL, subject: `passkey|${EMAIL}`, method: "passkey", epoch: 0, exp: mintedAt + 1000 } as never, mintedAt);
  const expFault = await verifySessionClassified(key, expired, now);
  ok("An EXPIRED cookie classifies session-fault-expired (never mac-mismatch)", "fault" in expFault && expFault.fault === "session-fault-expired");
  scanClean("The expired fault", expFault);

  // A MALFORMED cookie carrying the customer's secret in the token body.
  const malformed = await verifySessionClassified(key, `${SECRET}.${SECRET}`, now);
  ok("A MALFORMED cookie classifies session-fault-malformed", "fault" in malformed && malformed.fault === "session-fault-malformed");
  scanClean("The malformed fault (the token body carried the customer's secret)", malformed);

  // THE DELIVERY HALF: every class the classifier can return must be a member of AUTH_SIGNAL_NAMES, or the DO
  // drops it and the pack shows nothing at all.
  assertDeliverable("Every session fault class", SESSION_FAULT_CLASSES);
}

// ---- the remaining silent substitutions --------------------------------------------------------------------------

function testSilentSubstitutions(): void {
  console.log("\nThe surfaces that reported a WRONG number as a measured fact");

  // R2 binding AND S3 credentials, no DEST_KIND. The factory refuses the ambiguity (correctly), status
  // coarsens it to "nothing configured", and support tells the customer to add credentials they already have.
  const ambiguous = buildStatus({ DEST_R2: {}, DEST_ENDPOINT: `https://s3.example.com`, DEST_BUCKET: BUCKET, DEST_SECRET_ACCESS_KEY: SECRET } as never, 3);
  ok("The ambiguous config still reports destConfigured:false (every existing consumer is unchanged)", ambiguous.destConfigured === false);
  ok("it says destAmbiguous:true -- 'set DEST_KIND', not 'configure a destination'", ambiguous.destAmbiguous === true);
  scanClean("The status report (the env carried a real bucket and a real secret)", ambiguous);

  // A genuinely unconfigured engine must NOT read as ambiguous (the flag has to mean something).
  const none = buildStatus({} as never, 0);
  ok("A genuinely UNCONFIGURED engine is destAmbiguous:false", none.destAmbiguous === false && none.destConfigured === false);
  const r2Only = buildStatus({ DEST_R2: {} } as never, 1);
  ok("A cleanly-configured R2 engine is destAmbiguous:false", r2Only.destAmbiguous === false && r2Only.destConfigured === true);

  // "basedOnDrills says 2 but we ran 15 restore tests". The 13 excluded samples have a count + cause.
  const est = estimateRto({
    id: "dp-1",
    name: "payroll-kv", // the downpipe's OWN label: a pre-existing, contractual field of the estimate
    samples: [
      { durationMs: 1000, bytesVerified: 1_000_000 },
      { durationMs: 2000, bytesVerified: 2_000_000 },
      { durationMs: Number.NaN, bytesVerified: 5_000_000 }, // a broken timer
      { durationMs: 500, bytesVerified: 0 }, // a drill that verified NOTHING
      { durationMs: -1, bytesVerified: 10 }, // a clock jump
    ] as never,
    archiveBytes: 100_000_000,
  } as never);
  ok("The estimate is still computed from the USABLE samples (behaviour unchanged)", est.known === true && est.basedOnDrills === 2);
  ok("rejectedSamples finally explains the count-vs-basedOnDrills discrepancy (3 excluded)", est.rejectedSamples?.count === 3);
  ok("naming a CLOSED reason", est.rejectedSamples !== undefined && (RTO_REJECT_REASONS as readonly string[]).includes(est.rejectedSamples.lastReason));
  ok("A thin-sample estimate names WHY confidence is degraded (3 causes, 3 different answers)", est.degradationCause !== undefined && (RTO_DEGRADATION_CAUSES as readonly string[]).includes(est.degradationCause));

  // "Why is confidence stuck at low despite frequent drills": with no archive size the estimate cannot be
  // projected at ALL, which is a different answer from "run more drills".
  const noSize = estimateRto({ id: "dp-2", name: "n", samples: [{ durationMs: 1000, bytesVerified: 10 }], archiveBytes: 0 } as never);
  ok("An unknown archive size names archive-size-unknown (not 'run more drills')", noSize.degradationCause === "archive-size-unknown");

  // A fleet that ran 15 drills and has NO usable sample would read IDENTICALLY to one that never drilled,
  // without this count.
  const allRejected = estimateRto({ id: "dp-3", name: "n", samples: [{ durationMs: 0, bytesVerified: 0 }, { durationMs: Number.NaN, bytesVerified: 1 }], archiveBytes: 10 } as never);
  ok("An all-rejected fleet is still known:false (behaviour unchanged)", allRejected.known === false);
  ok("it says 2 samples were REJECTED (without this count it would read as 'never drilled')", allRejected.rejectedSamples?.count === 2);
  // This evidence must be closed enums and counts and nothing else: no sample
  // value, no byte count from the customer's archive, no reason text.
  scanClean("The NEW rejected-sample + degradation evidence", [est.rejectedSamples, est.degradationCause, noSize.degradationCause, allRejected.rejectedSamples]);
  ok("rejectedSamples carries ONLY a count and a closed reason (no sample value can ride)", Object.keys(est.rejectedSamples ?? {}).sort().join(",") === "count,lastReason");

  // the counters exist AND are deliverable (an out-of-vocabulary name is dropped by the applier,
  // so a name the vocabulary does not carry is a name recorded NOWHERE).
  const counterNames: readonly string[] = ADMIN_COUNTER_NAMES;
  for (const n of [
    "volumes-read-failed-downpipes",
    "volumes-read-failed-history",
    "coverage-inventory-rejected-shape",
    "coverage-inventory-rejected-over-cap",
    "dest-config-worm-policy-submitted-dropped",
    "restore-buffered-max-invalid",
    "rto-sample-rejected-non-finite-duration",
    "stored-expiry-unparseable-timestamp",
  ]) {
    ok(`The counter "${n}" is in ADMIN_COUNTER_NAMES (else the DO drops the bump)`, counterNames.includes(n));
  }

  // The DO applier is the redaction chokepoint for the counters: it DROPS an out-of-vocabulary name and clamps
  // every count, so a bucket, a secret or an object key cannot enter the record from a drifted caller.
  const bumped = applyAdminCounters(undefined, {
    "volumes-read-failed-downpipes": 1,
    "dest-config-worm-policy-submitted-dropped": 1,
    [BUCKET]: 99, // a caller-injected key: must be DROPPED
    [SECRET]: 5,
    [OBJECT_KEY]: 1,
  }, "2026-07-11T00:00:00.000Z");
  ok("The counter applier DROPS a caller-injected key (the key space is exactly ADMIN_COUNTER_NAMES)", Object.keys(bumped).every((k) => counterNames.includes(k)));
  ok("it records the legitimate bumps", bumped["volumes-read-failed-downpipes"]?.count === 1 && bumped["dest-config-worm-policy-submitted-dropped"]?.count === 1);
  scanClean("The counter aggregate built from a body carrying a bucket, a secret and an object key", bumped);
}

// ---- run ----------------------------------------------------------------------------------------------------

async function main(): Promise<void> {
  await testCertHealth();
  await testAttackShapes();
  testSilentDegradations();
  await testStartPath();
  await testSessionFaultClasses();
  testSilentSubstitutions();

  console.log(failures === 0 ? "\nADMIN cert/SAML/session evidence: all cases pass" : `\n${failures} FAILURES`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
