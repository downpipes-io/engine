// Prove the heal-auth-idp slice end to end: IDP-1 (zero-downtime SAML signing-cert rollover), IDP-2 (OIDC/
// OAuth2 client-secret expiry tracking), and AUTH-1 (the "no second factor — disabling/deleting the token
// will lock you out" pre-flight guard). In-memory doubles only (a real SchedulerDO over MockStorage, driven
// through handleAdmin and via direct DO fetch); no network, no deploy. Run: node test/validate-idp-rollover-lockout.ts
//
// What this proves:
//  IDP-1 — a SAML connection's pinned idpSigningCerts can be APPENDED (the overlap step) and REPLACED (the
//          prune step) IN PLACE via POST /admin/idp/connections/cert, with NO delete+recreate; the rollover
//          does NOT bump the per-connection idpEpoch (live sessions survive = zero-downtime); the cert-expiry
//          lifecycle row is RE-OBSERVED to the new MAX notAfter; the shared validateSamlCerts rejects a
//          non-PEM, an over-8 set, and the route refuses a non-SAML connection; the route is keys.ceremony +
//          dual-control gated (idp-conn-cert is a high-blast owner action).
//  IDP-2 — creating a CONFIDENTIAL OIDC/OAuth2 connection with secretExpiresAt OBSERVES an idp-secret-<id>
//          credential-lifecycle row (same machinery as the SAML cert notAfter); a pkce-public connection (no
//          secret) observes nothing; deleting the connection drops the row; a malformed secretExpiresAt is a
//          clean validation refusal.
//  AUTH-1 — lockoutPreflight reports the DO-owned second-factor facts (owner passkey / recovery codes / second
//          owner); POST /admin/policy/require-access OR's them with CF Access into secondFactorPresent and
//          returns safeToDisableToken + a lockoutWarning, so the console can refuse to advise disabling/
//          deleting the ADMIN_TOKEN when no second factor exists.

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { roleSubjectKey } from "../src/admin/identity.ts";
import { validateSamlCerts, validateOidc, validateOauth2 } from "../src/admin/idpconn-validators.ts";
import { PASSKEY_CRED_PREFIX, RECOVERY_PREFIX, RECOVERY_SIGNING_KEY_KEY } from "../src/sched/scheduler-do-base.ts";
import { generateRecoveryCodes } from "../src/admin/recovery.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { MockStorage } from "./mock-storage.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- a minimal DER X.509 cert builder (mirrors validate-cert-notafter.ts) so a built cert carries a real,
//      parseable notAfter the engine's certNotAfter observer reads. validateSamlCerts only needs the PEM
//      armour; certNotAfter needs the validity SEQUENCE, which this produces. ----
function derLen(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  let x = n;
  while (x > 0) { bytes.unshift(x & 0xff); x = Math.floor(x / 256); }
  return [0x80 | bytes.length, ...bytes];
}
function tlv(tag: number, content: number[]): number[] {
  return [tag, ...derLen(content.length), ...content];
}
function ascii(s: string): number[] {
  return Array.from(s).map((c) => c.charCodeAt(0));
}
function toPem(b64: string): string {
  return `-----BEGIN CERTIFICATE-----\n${b64.replace(/(.{64})/g, "$1\n")}\n-----END CERTIFICATE-----\n`;
}
// buildCert: a minimal tbsCertificate whose validity carries notBefore "20200101000000Z" and the given
// notAfter UTCTime string (e.g. "300101000000Z" -> 2030). serial keeps each cert distinct so the de-dupe
// does not collapse two genuinely-different certs.
function buildCert(notAfterUtc: string, serial: number): string {
  const ser = tlv(0x02, [serial & 0xff]);
  const sigAlg = tlv(0x30, []);
  const issuer = tlv(0x30, []);
  const validity = tlv(0x30, [...tlv(0x17, ascii("200101000000Z")), ...tlv(0x17, ascii(notAfterUtc))]);
  const tbs = tlv(0x30, [...ser, ...sigAlg, ...issuer, ...validity]);
  const cert = tlv(0x30, tbs);
  return toPem(Buffer.from(cert).toString("base64"));
}

const CONSOLE_ORIGIN = "https://console.downpipes.io";
const ADMIN_TOKEN = "test-admin-token";

function makeEnv(extra: Record<string, unknown> = {}): { env: Env; storage: MockStorage; dobj: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
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
  const env = { SCHEDULER: namespace, CONSOLE_ORIGIN, ADMIN_TOKEN, ...extra } as unknown as Env;
  return { env, storage, dobj };
}
function adminUrl(path: string): string { return `${CONSOLE_ORIGIN}${path}`; }
function tokenHeaders(): Record<string, string> {
  return { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" };
}
async function seedFounderOwner(storage: MockStorage): Promise<void> {
  // Seed a BOUND owner so the first-caller bootstrap does not claim a later sign-in as owner.
  await storage.put(roleSubjectKey("passkey|founder@acme.example"), { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "owner", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z" });
}

const samlProposal = (id: string, cert: string): Record<string, unknown> => ({
  id, kind: "saml", label: "Work IdP", presetId: "generic-saml", enabled: true,
  idpEntityId: "https://idp.example/entity", idpSsoUrl: "https://idp.example/sso",
  idpSigningCerts: [cert], spEntityId: "https://sp.downpipes.io", nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  wantAssertionsSigned: true, allowIdpInitiated: false, clockSkewSec: 120, emailVerifiedPolicy: "trust-idp",
  emailAttr: "email", groupsAttr: "groups",
});
const oidcProposal = (id: string, secretExpiresAt?: string, pkcePublic = false): Record<string, unknown> => ({
  id, kind: "oidc", label: "Entra", presetId: "entra", enabled: true,
  issuer: "https://idp.example.com", clientId: "client-abc",
  secretRef: { mode: pkcePublic ? "pkce-public" : "do-plaintext" },
  scopes: ["openid", "email"], idTokenSigAlgs: ["RS256"], pkce: "required",
  clientAuth: pkcePublic ? "pkce_public" : "client_secret_post", requireNonce: true,
  authorizationEndpoint: "https://idp.example.com/authorize", tokenEndpoint: "https://idp.example.com/token", jwksUri: "https://idp.example.com/jwks",
  ...(secretExpiresAt !== undefined ? { secretExpiresAt } : {}),
});

console.log("IdP cert rollover (IDP-1) + secret-expiry tracking (IDP-2) + lockout pre-flight (AUTH-1)\n");

// ============================================================================================
// PART A — pure validators (validateSamlCerts + secretExpiresAt)
// ============================================================================================
{
  const a = buildCert("300101000000Z", 1);
  const b = buildCert("350101000000Z", 2);
  const r1 = validateSamlCerts([a, b]);
  ok("validateSamlCerts: a 2-cert overlap array is accepted (de-duped, 1..8)", r1.ok === true && r1.ok && r1.certs.length === 2);
  // A DUPLICATE IS REFUSED, NOT COLLAPSED TO ONE. A rollover APPEND runs [...pinned, paste] through this
  // function, so appending an already-pinned certificate must not collapse to the pinned array and answer
  // ok:true: that would tell the operator the rollover certificate was now trusted when nothing had changed,
  // and the cutover would then fail at the IdP's switch, the one moment nobody can sign in to fix it. Nobody
  // legitimately pins one certificate twice.
  const dup = validateSamlCerts([a, a]);
  ok("validateSamlCerts: a duplicate certificate is REFUSED, not collapsed to one", dup.ok === false);
  ok("validateSamlCerts: the refusal says the same certificate appears twice", dup.ok === false && dup.reason.includes("same signing certificate appears twice"));
  ok("validateSamlCerts: an empty array is refused", validateSamlCerts([]).ok === false);
  ok("validateSamlCerts: a non-PEM string is refused (no BEGIN CERTIFICATE)", validateSamlCerts(["not a cert"]).ok === false);
  ok("validateSamlCerts: a non-array is refused", validateSamlCerts("nope").ok === false);
  const nine = Array.from({ length: 9 }, (_, i) => buildCert("300101000000Z", i + 10));
  ok("validateSamlCerts: more than 8 certs is refused", validateSamlCerts(nine).ok === false);

  const base = { id: "x", label: "X", presetId: "entra", enabled: true };
  const goodOidc = validateOidc({ ...oidcProposal("x", "2027-01-01T00:00:00Z"), secretRef: { mode: "do-plaintext" } } as never, base);
  ok("validateOidc: a valid secretExpiresAt is accepted + carried onto the connection", goodOidc.ok === true && goodOidc.ok && (goodOidc.conn as { secretExpiresAt?: string }).secretExpiresAt === "2027-01-01T00:00:00Z");
  const badOidc = validateOidc({ ...oidcProposal("x"), secretExpiresAt: "not-a-date" } as never, base);
  ok("validateOidc: a malformed secretExpiresAt is a clean refusal", badOidc.ok === false && !badOidc.ok && badOidc.reason.includes("secretExpiresAt"));
  const oauthBase = { id: "g", label: "GitHub", presetId: "github", enabled: true };
  const oauthProp = { authorizeUrl: "https://gh.example/auth", tokenUrl: "https://gh.example/token", tokenAuthStyle: "post_json", clientId: "gh", secretRef: { mode: "do-plaintext" }, scopes: ["read:user"], apiBase: "https://api.gh.example", profileUrl: "https://api.gh.example/user", subjectPath: "id", subjectPrefix: "github", pkce: "none", secretExpiresAt: "bad" };
  ok("validateOauth2: a malformed secretExpiresAt is a clean refusal", validateOauth2(oauthProp as never, oauthBase).ok === false);
}

// ============================================================================================
// PART B — IDP-1 SAML cert rollover wiring (router + DO)
// ============================================================================================
{
  const { env, storage } = makeEnv();
  await seedFounderOwner(storage);
  const certA = buildCert("300101000000Z", 1); // notAfter 2030
  const certB = buildCert("350101000000Z", 2); // notAfter 2035

  const cr = await handleAdmin(new Request(adminUrl("/admin/idp/connections"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ proposal: samlProposal("work-idp", certA) }) }), env);
  ok("create SAML connection: 200", cr.status === 200);
  const obsA = await storage.get<{ expiresAt?: string; kind?: string; source?: string }>("expiry:idp-cert-work-idp");
  ok("create: the SAML cert expiry row is observed (kind certificate, source observed, ~2030)", obsA !== undefined && obsA.kind === "certificate" && obsA.source === "observed" && (obsA.expiresAt ?? "").startsWith("2030"));

  // The per-connection idpEpoch must NOT exist/change across a rollover (zero-downtime: live sessions survive).
  const epochBefore = await storage.get<number>("idpEpoch:work-idp");

  // APPEND certB (the overlap step).
  const ap = await handleAdmin(new Request(adminUrl("/admin/idp/connections/cert"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ connId: "work-idp", addCerts: [certB] }) }), env);
  const apBody = (await ap.json()) as { ok?: boolean };
  ok("cert append: 200 + ok", ap.status === 200 && apBody.ok === true);
  const recAfterAppend = await storage.get<{ idpSigningCerts?: string[] }>("idpconn:work-idp");
  ok("cert append: the stored array now holds BOTH certs (overlap)", (recAfterAppend?.idpSigningCerts ?? []).length === 2);
  const epochAfterAppend = await storage.get<number>("idpEpoch:work-idp");
  ok("cert append: the idpEpoch was NOT bumped (zero-downtime; live sessions survive)", epochAfterAppend === epochBefore);
  const obsAfterAppend = await storage.get<{ expiresAt?: string }>("expiry:idp-cert-work-idp");
  ok("cert append: the cert expiry row re-observed to the new MAX notAfter (~2035)", (obsAfterAppend?.expiresAt ?? "").startsWith("2035"));

  // REPLACE with certB only (the prune step).
  const rp = await handleAdmin(new Request(adminUrl("/admin/idp/connections/cert"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ connId: "work-idp", certs: [certB] }) }), env);
  ok("cert replace: 200", rp.status === 200);
  const recAfterReplace = await storage.get<{ idpSigningCerts?: string[] }>("idpconn:work-idp");
  // The store trims each PEM (boundedScreened), so compare against the trimmed cert, not the raw trailing-newline form.
  ok("cert replace: the stored array is exactly the new single cert", (recAfterReplace?.idpSigningCerts ?? []).length === 1 && (recAfterReplace?.idpSigningCerts ?? [])[0] === certB.trim());

  // Refusals: a malformed cert, neither field, and a non-SAML connection.
  const bad = await handleAdmin(new Request(adminUrl("/admin/idp/connections/cert"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ connId: "work-idp", addCerts: ["not a cert"] }) }), env);
  ok("cert rollover: a non-PEM cert is refused (ok:false)", ((await bad.json()) as { ok?: boolean }).ok === false);
  const neither = await handleAdmin(new Request(adminUrl("/admin/idp/connections/cert"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ connId: "work-idp" }) }), env);
  ok("cert rollover: providing neither addCerts nor certs is refused", ((await neither.json()) as { ok?: boolean }).ok === false);

  await handleAdmin(new Request(adminUrl("/admin/idp/connections"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ proposal: oidcProposal("oidc1"), secret: "s" }) }), env);
  const nonSaml = await handleAdmin(new Request(adminUrl("/admin/idp/connections/cert"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ connId: "oidc1", addCerts: [certA] }) }), env);
  ok("cert rollover: a non-SAML connection is refused (cert rollover is SAML-only)", ((await nonSaml.json()) as { ok?: boolean; reason?: string }).ok === false);

  // The route is behind authentication (the dual-control + keys.ceremony gates are unit-tested elsewhere).
  const unauth = await handleAdmin(new Request(adminUrl("/admin/idp/connections/cert"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ connId: "work-idp", addCerts: [certA] }) }), env);
  ok("cert rollover: an unauthenticated request is refused (401)", unauth.status === 401);
}

// ============================================================================================
// PART C — IDP-2 OIDC/OAuth2 client-secret expiry tracking
// ============================================================================================
{
  const { env, storage } = makeEnv();
  await seedFounderOwner(storage);

  // Confidential OIDC with a declared secret expiry -> an observed credential row.
  const cr = await handleAdmin(new Request(adminUrl("/admin/idp/connections"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ proposal: oidcProposal("conf", "2027-03-01T00:00:00Z"), secret: "super-secret" }) }), env);
  ok("create confidential OIDC with secretExpiresAt: 200", cr.status === 200);
  const sec = await storage.get<{ expiresAt?: string; kind?: string; source?: string; usageLink?: { kind?: string; refId?: string } }>("expiry:idp-secret-conf");
  ok("IDP-2: a confidential secret expiry row is observed (kind credential, source observed, linked to the connection)", sec !== undefined && sec.kind === "credential" && sec.source === "observed" && sec.expiresAt === "2027-03-01T00:00:00Z" && sec.usageLink?.kind === "idpConnection" && sec.usageLink?.refId === "conf");

  // A pkce-public connection (no secret) declares no expiry to track.
  await handleAdmin(new Request(adminUrl("/admin/idp/connections"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ proposal: oidcProposal("pub", "2027-03-01T00:00:00Z", true) }) }), env);
  const pubSec = await storage.get("expiry:idp-secret-pub");
  ok("IDP-2: a pkce-public connection observes NO secret expiry row (it holds no secret)", pubSec === undefined);

  // Deleting the connection drops the observed secret row.
  const del = await handleAdmin(new Request(adminUrl("/admin/idp/connections/delete"), { method: "POST", headers: tokenHeaders(), body: JSON.stringify({ connId: "conf" }) }), env);
  ok("delete connection: 200", del.status === 200);
  const after = await storage.get("expiry:idp-secret-conf");
  ok("IDP-2: deleting the connection drops the observed secret expiry row", after === undefined);
}

// ============================================================================================
// PART D — AUTH-1 lockout pre-flight (DO method + require-access route)
// ============================================================================================
// doFetch drives a DO route directly (no caller needed for the lockout-preflight read).
async function lockout(dobj: SchedulerDO): Promise<{ passkeyOwnerEnrolled: boolean; recoveryReady: boolean; recoveryReadyReason: string; secondOwner: boolean }> {
  const r = await dobj.fetch(new Request("https://do/policy/lockout-preflight", { method: "GET" }));
  return (await r.json()) as { passkeyOwnerEnrolled: boolean; recoveryReady: boolean; recoveryReadyReason: string; secondOwner: boolean };
}

// seedUsableRecoverySet banks a GENUINE recovery set for an email: a real 32-byte recovery signing key, then
// a real record minted under it by the production generateRecoveryCodes. This is what a working break-glass
// looks like in storage, and it is the whole point of these vectors: recoveryReady must reflect whether a
// banked code would ACTUALLY sign an Owner back in, not merely whether an account-level acknowledgement flag
// was ever set with no record and no codes behind it.
// keyCreatedAt defaults to well before the record so the key-continuity test reads the record as live.
async function seedUsableRecoverySet(storage: MockStorage, email: string, opts: { keyCreatedAt?: string; generatedAt?: string } = {}): Promise<string[]> {
  const rawKey = new Uint8Array(32).fill(7);
  await storage.put(RECOVERY_SIGNING_KEY_KEY, { key: b64urlEncode(rawKey), createdAt: opts.keyCreatedAt ?? "2026-06-01T00:00:00.000Z" });
  const { codes, record } = await generateRecoveryCodes(rawKey, email, opts.generatedAt ?? "2026-06-20T00:00:00.000Z");
  await storage.put(`${RECOVERY_PREFIX}${email}`, record);
  return codes;
}
{
  // (1) A fresh account with a single bare-token/founder owner and nothing else: NO second factor.
  const { storage, dobj } = makeEnv();
  await seedFounderOwner(storage);
  const lp1 = await lockout(dobj);
  ok("lockoutPreflight: fresh single-owner account has no second factor (all three false)", lp1.passkeyOwnerEnrolled === false && lp1.recoveryReady === false && lp1.secondOwner === false);

  // (2) recoveryReady is the LIVE "a banked code would sign an Owner back in" verdict, BOTH DIRECTIONS.
  // (2a) NOT READY without a record: an account-level acknowledgement with no record and no codes behind it
  // must never be counted as a second factor.
  ok("lockoutPreflight: an Owner with NO recovery record is NOT recoveryReady (reason no-recovery-record)", (await lockout(dobj)).recoveryReady === false && (await lockout(dobj)).recoveryReadyReason === "no-recovery-record");

  // (2b) READY on a genuine, unconsumed set minted under the live key for a passkey-bound Owner.
  await seedUsableRecoverySet(storage, "founder@acme.example");
  const lpReady = await lockout(dobj);
  ok("lockoutPreflight: a genuine unconsumed recovery set for a passkey-bound Owner IS recoveryReady", lpReady.recoveryReady === true && lpReady.recoveryReadyReason === "ok");

  // (2c) NOT READY once every code is spent. The old latch was documented as NOT cleared when codes run low,
  // so it survived exhaustion; the count is now re-derived on every read.
  const spent = await storage.get<{ codes: { consumed: boolean }[] }>(`${RECOVERY_PREFIX}founder@acme.example`);
  for (const slot of spent!.codes) slot.consumed = true;
  await storage.put(`${RECOVERY_PREFIX}founder@acme.example`, spent);
  const lpSpent = await lockout(dobj);
  ok("lockoutPreflight: a fully-consumed recovery set is NOT recoveryReady (reason no-unconsumed-codes)", lpSpent.recoveryReady === false && lpSpent.recoveryReadyReason === "no-unconsumed-codes");

  // (2d) NOT READY when the codes cannot verify any more: the record predates the signing key in force, which
  // is the shape of an account that ran terminate-all under the pre-split code. Record present, codes
  // unconsumed, count above zero, key materialised and long enough, and every one of those codes is dead.
  // A count-based tightening alone reports this account ready; the live estate proving the defect is exactly
  // this shape.
  const { storage: sOrphan, dobj: dOrphan } = makeEnv();
  await seedFounderOwner(sOrphan);
  await seedUsableRecoverySet(sOrphan, "founder@acme.example", { generatedAt: "2026-06-20T00:00:00.000Z" });
  await sOrphan.put(RECOVERY_SIGNING_KEY_KEY, { key: b64urlEncode(new Uint8Array(32).fill(9)), createdAt: "2026-07-01T00:00:00.000Z" });
  const lpOrphan = await lockout(dOrphan);
  ok("lockoutPreflight: unconsumed codes minted under a key that is GONE are NOT recoveryReady (reason recovery-codes-orphaned-from-key)", lpOrphan.recoveryReady === false && lpOrphan.recoveryReadyReason === "recovery-codes-orphaned-from-key");

  // (2e) NOT READY when the Owner who holds the codes is no longer an Owner. The latch was set at mint time
  // and never re-resolved, so a demotion left it true.
  const { storage: sDemote, dobj: dDemote } = makeEnv();
  await seedFounderOwner(sDemote);
  await seedUsableRecoverySet(sDemote, "founder@acme.example");
  await sDemote.put(roleSubjectKey("passkey|founder@acme.example"), { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "viewer", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z" });
  const lpDemote = await lockout(dDemote);
  ok("lockoutPreflight: a demoted Owner's recovery codes are NOT recoveryReady (reason no-passkey-bound-owner)", lpDemote.recoveryReady === false && lpDemote.recoveryReadyReason === "no-passkey-bound-owner");

  // (2f) NOT READY on a record that cannot be parsed: nothing can be counted or verified, so it is not a way
  // back in, and the read must answer NO rather than fault or default optimistically.
  const { storage: sCorrupt, dobj: dCorrupt } = makeEnv();
  await seedFounderOwner(sCorrupt);
  await seedUsableRecoverySet(sCorrupt, "founder@acme.example");
  await sCorrupt.put(`${RECOVERY_PREFIX}founder@acme.example`, { email: "founder@acme.example", codes: "not-an-array", generatedAt: "2026-06-20T00:00:00.000Z" });
  const lpCorrupt = await lockout(dCorrupt);
  ok("lockoutPreflight: an unparseable recovery record is NOT recoveryReady (reason unparseable-recovery-record)", lpCorrupt.recoveryReady === false && lpCorrupt.recoveryReadyReason === "unparseable-recovery-record");

  // (2g) An account with NO recovery configured at all reads not ready with no key materialised. This is the
  // honest answer and it is what it read before the tightening too, so the tightening cries no wolf here.
  const { storage: sCold, dobj: dCold } = makeEnv();
  await seedFounderOwner(sCold);
  ok("lockoutPreflight: a never-configured account is NOT recoveryReady (no key, no record)", (await lockout(dCold)).recoveryReady === false);

  // (2h) THE MIGRATION MUST NOT CRY WOLF. An account that predates the recovery/session key split holds a
  // record minted under the SESSION key with no recovery key materialised at all. Those codes verify (the key
  // is adopted byte-for-byte on first use), so it must read READY.
  const { storage: sMigrate, dobj: dMigrate } = makeEnv();
  await seedFounderOwner(sMigrate);
  await seedUsableRecoverySet(sMigrate, "founder@acme.example");
  const preSplit = await sMigrate.get<{ key: string }>(RECOVERY_SIGNING_KEY_KEY);
  await sMigrate.delete(RECOVERY_SIGNING_KEY_KEY);
  await sMigrate.put("passkeySessionKey", { key: preSplit!.key, createdAt: "2026-06-01T00:00:00.000Z" });
  const lpMigrate = await lockout(dMigrate);
  ok("lockoutPreflight: a pre-split record with the session key still in place IS recoveryReady (adoption preserves it)", lpMigrate.recoveryReady === true && lpMigrate.recoveryReadyReason === "ok");

  // (2i) The same account AFTER the adoption ran and the session key was deleted by terminate-all. The
  // adoption stamps the adopted key's own birth date, so continuity is still provable and the account stays
  // ready. Without that stamp a healthy account would read unsafe purely for having signed everyone out.
  const { storage: sAdopted, dobj: dAdopted } = makeEnv();
  await seedFounderOwner(sAdopted);
  await seedUsableRecoverySet(sAdopted, "founder@acme.example");
  const adoptedKey = await sAdopted.get<{ key: string }>(RECOVERY_SIGNING_KEY_KEY);
  await sAdopted.put(RECOVERY_SIGNING_KEY_KEY, { key: adoptedKey!.key, createdAt: "2026-08-04T00:00:00.000Z", adoptedFromSessionKey: true, sessionKeyCreatedAt: "2026-06-01T00:00:00.000Z" });
  const lpAdopted = await lockout(dAdopted);
  ok("lockoutPreflight: an ADOPTED key whose session key is gone stays recoveryReady (sessionKeyCreatedAt dates it)", lpAdopted.recoveryReady === true && lpAdopted.recoveryReadyReason === "ok");

  // (3) A second owner -> secondOwner.
  const { storage: s3, dobj: d3 } = makeEnv();
  await seedFounderOwner(s3);
  await s3.put(roleSubjectKey("passkey|second@acme.example"), { subject: "passkey|second@acme.example", email: "second@acme.example", role: "owner", grantedBy: "founder@acme.example", grantedAt: "2026-06-20T00:00:00.000Z" });
  ok("lockoutPreflight: a second owner flips secondOwner", (await lockout(d3)).secondOwner === true);

  // (4) An owner with an enrolled passkey -> passkeyOwnerEnrolled.
  const { storage: s4, dobj: d4 } = makeEnv();
  await seedFounderOwner(s4);
  await s4.put(`${PASSKEY_CRED_PREFIX}cred-1`, { credentialId: "cred-1", email: "founder@acme.example", cosePublicKey: "AAAA", alg: -7, signCount: 0, transports: ["internal"], aaguid: "AAAA", createdAt: "2026-06-25T00:00:00.000Z" });
  ok("lockoutPreflight: an owner passkey flips passkeyOwnerEnrolled", (await lockout(d4)).passkeyOwnerEnrolled === true);

  // (5) LAPSED-OWNER-COUNTED-AS-BOUND. The SAME account as (4) with ONE difference: the owner
  // grant carries an expiresAt already in the past, so effectiveRole resolves it to viewer. The credential
  // is still enrolled and still in storage, and it is still worthless as a way back in, because its holder
  // signs in as a viewer. This factor read the STORED role while the other two factors (secondOwner via
  // countOwners, recoveryReady via recoveryBreakGlassVerdict) both ran through effectiveRole, so the
  // pre-flight told an operator a second factor existed on an account that had none.
  const { storage: s5, dobj: d5 } = makeEnv();
  await s5.put(roleSubjectKey("passkey|founder@acme.example"), { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "owner", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z", expiresAt: "2026-07-01T00:00:00.000Z" });
  await s5.put(`${PASSKEY_CRED_PREFIX}cred-1`, { credentialId: "cred-1", email: "founder@acme.example", cosePublicKey: "AAAA", alg: -7, signCount: 0, transports: ["internal"], aaguid: "AAAA", createdAt: "2026-06-25T00:00:00.000Z" });
  const lp5 = await lockout(d5);
  ok("lockoutPreflight: a LAPSED owner's passkey does NOT count as a second factor", lp5.passkeyOwnerEnrolled === false);
  // ...and the same account with the grant still live DOES count, so the assertion above is about expiry
  // and not about the seed being broken. This is the direction a naive "just return false" would fail.
  const { storage: s5b, dobj: d5b } = makeEnv();
  await s5b.put(roleSubjectKey("passkey|founder@acme.example"), { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "owner", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z" });
  await s5b.put(`${PASSKEY_CRED_PREFIX}cred-1`, { credentialId: "cred-1", email: "founder@acme.example", cosePublicKey: "AAAA", alg: -7, signCount: 0, transports: ["internal"], aaguid: "AAAA", createdAt: "2026-06-25T00:00:00.000Z" });
  ok("lockoutPreflight: an UNEXPIRED time-boxed owner's passkey still counts", (await lockout(d5b)).passkeyOwnerEnrolled === true);
  // An UNPARSEABLE expiresAt fails OPEN in effectiveRole by convention (malformed data must never itself
  // revoke a grant), so it must not manufacture a lockout warning here either.
  const { storage: s5c, dobj: d5c } = makeEnv();
  await s5c.put(roleSubjectKey("passkey|founder@acme.example"), { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "owner", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z", expiresAt: "not-a-date" });
  await s5c.put(`${PASSKEY_CRED_PREFIX}cred-1`, { credentialId: "cred-1", email: "founder@acme.example", cosePublicKey: "AAAA", alg: -7, signCount: 0, transports: ["internal"], aaguid: "AAAA", createdAt: "2026-06-25T00:00:00.000Z" });
  ok("lockoutPreflight: an UNPARSEABLE expiresAt fails open and still counts (corrupt data never invents a lockout)", (await lockout(d5c)).passkeyOwnerEnrolled === true);
}
{
  // require-access route: with NO second factor, the verdict refuses + warns; the bare-token caller is never
  // told it is safe to disable the token (disabling it mid-session would strand even that caller).
  const { env, storage } = makeEnv();
  await seedFounderOwner(storage);
  const r = await handleAdmin(new Request(adminUrl("/admin/policy/require-access"), { method: "POST", headers: tokenHeaders() }), env);
  const b = (await r.json()) as { secondFactorPresent?: boolean; safeToDisableToken?: boolean; lockoutWarning?: string | null; secondFactor?: { accessConfigured?: boolean; recoveryReady?: boolean }; callerMethod?: string };
  ok("require-access: 200", r.status === 200);
  ok("require-access: no second factor -> secondFactorPresent false + a non-null lockoutWarning", b.secondFactorPresent === false && typeof b.lockoutWarning === "string");
  ok("require-access: safeToDisableToken false (no factor, and the caller is on the bare token)", b.safeToDisableToken === false);

  // A USABLE recovery set -> the verdict flips to present (still not safe for a token caller, but no warning).
  // BOTH DIRECTIONS, in one account: banking a genuine set flips it, and spending every code flips it back.
  await seedUsableRecoverySet(storage, "founder@acme.example");
  const r2 = await handleAdmin(new Request(adminUrl("/admin/policy/require-access"), { method: "POST", headers: tokenHeaders() }), env);
  const b2 = (await r2.json()) as { secondFactorPresent?: boolean; lockoutWarning?: string | null; secondFactor?: { recoveryReady?: boolean; recoveryReadyReason?: string } };
  ok("require-access: a USABLE recovery set -> secondFactorPresent true + warning cleared", b2.secondFactorPresent === true && b2.lockoutWarning === null && b2.secondFactor?.recoveryReady === true && b2.secondFactor?.recoveryReadyReason === "ok");

  const banked = await storage.get<{ codes: { consumed: boolean }[] }>(`${RECOVERY_PREFIX}founder@acme.example`);
  for (const slot of banked!.codes) slot.consumed = true;
  await storage.put(`${RECOVERY_PREFIX}founder@acme.example`, banked);
  const r2b = await handleAdmin(new Request(adminUrl("/admin/policy/require-access"), { method: "POST", headers: tokenHeaders() }), env);
  const b2b = (await r2b.json()) as { secondFactorPresent?: boolean; lockoutWarning?: string | null; safeToDisableToken?: boolean; secondFactor?: { recoveryReady?: boolean; recoveryReadyReason?: string } };
  ok("require-access: spending every code takes the factor away again (warning returns, disable refused)", b2b.secondFactor?.recoveryReady === false && b2b.secondFactor?.recoveryReadyReason === "no-unconsumed-codes" && b2b.secondFactorPresent === false && typeof b2b.lockoutWarning === "string" && b2b.safeToDisableToken === false);

  // CF Access configured (env) is itself a second factor (the env-side fact, OR'd in by the route).
  const { env: envA, storage: sA } = makeEnv({ CF_ACCESS_TEAM_DOMAIN: "acme.cloudflareaccess.com", CF_ACCESS_AUD: "aud-tag" });
  await seedFounderOwner(sA);
  const r3 = await handleAdmin(new Request(adminUrl("/admin/policy/require-access"), { method: "POST", headers: tokenHeaders() }), envA);
  const b3 = (await r3.json()) as { secondFactorPresent?: boolean; secondFactor?: { accessConfigured?: boolean } };
  ok("require-access: CF Access configured counts as a second factor (secondFactorPresent true)", b3.secondFactorPresent === true && b3.secondFactor?.accessConfigured === true);
}

if (failures > 0) process.exitCode = 1;
if (failures === 0) console.log("\nIDP ROLLOVER + SECRET-EXPIRY + LOCKOUT PRE-FLIGHT VECTORS PASS");
else {
  console.log(`\n${failures} FAILURE(S)`);
  process.exitCode = 1;
}
