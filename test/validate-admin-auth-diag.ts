// Pins the ADMIN-PLANE auth diagnostic evidence:
//
//   G200  Cloudflare Access JWKS fetch/import outages are ordinary {reason} refusals classified to the closed
//         cf-access-jwks-* names, so a cloudflareaccess.com blip, a bad CF_ACCESS_TEAM_DOMAIN or a malformed
//         JWKS entry is distinguishable in the pack from "nobody tried to sign in".
//   G231  The ~7 Access verify-failure causes (clock skew, an alg downgrade, a wrong typ, a bad signature, a
//         corrupt token) each classify to their own name rather than one shared counter.
//   G118  The CSRF refusal sub-classes distinguish CONSOLE_ORIGIN unset on the engine (a configuration fault)
//         from a foreign Origin genuinely presented (a security event). Same for the double-submit second factor.
//   G233  The session-cookie fault classes behind verifySession's deliberately-bare null.
//
// REDACTION (binding, no-custody): every assertion below plants a CUSTOMER SENTINEL at the fault site -- an
// attacker-chosen JWT alg/typ, a real-looking Origin, a team domain, an email, a session MAC -- and asserts the
// sentinel NEVER appears in the recorded value. The recorded value is only ever a closed enum member, so the
// strongest possible statement holds: the classifiers' entire output range IS the closed vocabulary, and that is
// asserted exhaustively (every returned name is a member of AUTH_SIGNAL_NAMES).

import { accessDenySignal, classifyJwksThrow, verifyAccessJWT, JWKS_REASON } from "../src/admin/access.ts";
import { AUTH_SIGNAL_NAME_SET, bootstrapEmailSignalName, roleInviteEmailSignalName } from "../src/admin/auth-signals.ts";
import {
  csrfDoubleSubmitFailClass,
  originFailClass,
  verifySessionClassified,
  DOUBLE_SUBMIT_FAIL_CLASSES,
  ORIGIN_FAIL_CLASSES,
  SESSION_FAULT_CLASSES,
  signSession,
  CSRF_HEADER_NAME,
} from "../src/admin/session.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// SENTINELS are values a CUSTOMER (or an attacker at the customer's front door) controls. None may ever appear
// in a recorded diagnostic value. They are deliberately shaped to look like the enum members they sit beside,
// so a classifier that echoed its input, or that let an interpolated tail steer the match, is caught.
const SENTINELS = [
  "aud mismatch", // an attacker-chosen JWT alg that IMPERSONATES another reason's text (the rule-order hijack)
  "acme-corp.cloudflareaccess.com", // the customer's team domain
  "https://console.acme-corp.example", // the customer's console origin
  "https://evil.example", // the attacker's origin
  "cfo@acme-corp.example", // a customer email
  "SECRET-SESSION-MAC", // session material
  "kid-7f3a9c", // a JWKS key id
];

// assertClean fails if ANY sentinel (or any suspicious free text) shows up in a recorded value.
function assertClean(label: string, recorded: string): void {
  const leaked = SENTINELS.filter((s) => recorded.includes(s));
  ok(`${label}: carries no customer sentinel (recorded="${recorded}")`, leaked.length === 0);
}

// assertClosed fails if a recorded name is not a member of the closed auth-signal vocabulary. This is the
// redaction proof that matters most: if the ONLY values that can ever be recorded are members of a fixed set,
// then no message, token, origin or key can be recorded, by construction.
function assertClosed(label: string, recorded: string): void {
  ok(`${label}: "${recorded}" is a member of the closed AUTH_SIGNAL_NAMES vocabulary`, AUTH_SIGNAL_NAME_SET.has(recorded));
}

console.log("G231: Access verify sub-causes (the ~7 causes that collapsed into cf-access-verify-failed)");
{
  const CASES: Array<[string, string]> = [
    ["malformed JWT", "cf-access-verify-failed-malformed-jwt"],
    ["undecodable JWT", "cf-access-verify-failed-malformed-jwt"],
    ["no kid", "cf-access-verify-failed-malformed-jwt"],
    ["unexpected alg HS256", "cf-access-verify-failed-alg"],
    ["unexpected token type JWE", "cf-access-verify-failed-typ"],
    ["expired", "cf-access-verify-failed-expired"],
    ["not yet valid", "cf-access-verify-failed-nbf"],
    ["bad signature", "cf-access-verify-failed-signature"],
    ["aud mismatch", "cf-access-aud-mismatch"],
    ["issuer https://evil.example != https://acme-corp.cloudflareaccess.com", "cf-access-issuer-mismatch"],
    ["signing key not found", "cf-access-key-unknown"],
    ['signing key has unexpected kty "EC"; expected RSA', "cf-access-key-unknown"],
    ["Access team domain is not a *.cloudflareaccess.com host", "cf-access-issuer-mismatch"],
  ];
  for (const [reason, expected] of CASES) {
    const got = accessDenySignal(reason);
    ok(`accessDenySignal("${reason}") -> ${expected}`, got === expected);
    assertClosed("accessDenySignal", got);
    assertClean("accessDenySignal", got);
  }
}

console.log("G231: an ATTACKER-CHOSEN alg/typ tail cannot hijack its own classification (the anchored-rule fix)");
{
  // The reason `unexpected alg <header.alg>` interpolates a field the ATTACKER supplies in the presented JWT,
  // so an alg value crafted to read as another reason's text (e.g. alg:"aud mismatch") must not classify as
  // that other reason.
  const hijack = accessDenySignal("unexpected alg aud mismatch");
  ok('alg:"aud mismatch" still classifies as -alg, not -aud-mismatch', hijack === "cf-access-verify-failed-alg");
  const hijack2 = accessDenySignal("unexpected token type signing key not found");
  ok('typ:"signing key not found" still classifies as -typ, not -key-unknown', hijack2 === "cf-access-verify-failed-typ");
  // An attacker-chosen alg that impersonates the JWKS family must not enter the jwks branch either.
  const hijack3 = accessDenySignal("unexpected alg jwks fetch failed");
  ok('alg:"jwks fetch failed" still classifies as -alg, not a jwks-* name', hijack3 === "cf-access-verify-failed-alg");
  for (const h of [hijack, hijack2, hijack3]) {
    assertClosed("hijack attempt", h);
    assertClean("hijack attempt", h);
  }
}

console.log("G200: the JWKS throw classifier reads a message ONLY to select a fixed literal");
{
  const CASES: Array<[unknown, string, string]> = [
    [new Error("Access certs endpoint refused (not an https *.cloudflareaccess.com host)"), JWKS_REASON.hostRefused, "cf-access-jwks-host-refused"],
    [new Error("Access certs fetch failed: 503"), JWKS_REASON.nonOk, "cf-access-jwks-non-2xx"],
    [new Error("Access JWKS missing keys array"), JWKS_REASON.noKeys, "cf-access-jwks-no-keys"],
    // A raw transport throw: the runtime authors this message, and it is exactly the kind of text that must
    // NEVER be recorded. The classifier must coarsen it to the fixed fetch-failed literal and discard the text.
    [new TypeError("Network connection lost while contacting acme-corp.cloudflareaccess.com (kid-7f3a9c)"), JWKS_REASON.fetchFailed, "cf-access-jwks-fetch-failed"],
    [{ nope: true }, JWKS_REASON.fetchFailed, "cf-access-jwks-fetch-failed"], // a non-Error throw
  ];
  for (const [thrown, expectedReason, expectedName] of CASES) {
    const reason = classifyJwksThrow(thrown);
    ok(`classifyJwksThrow -> "${expectedReason}"`, reason === expectedReason);
    assertClean("classifyJwksThrow reason", reason);
    const name = accessDenySignal(reason);
    ok(`  ... and accessDenySignal maps it to ${expectedName}`, name === expectedName);
    assertClosed("jwks signal", name);
    assertClean("jwks signal", name);
  }
  ok("classifyJwksThrow maps the import rejection literal to import-failed", accessDenySignal(JWKS_REASON.importFailed) === "cf-access-jwks-import-failed");
}

console.log("G200: a JWKS outage is now a RECORDABLE deny, not a 500 out of the auth path");
{
  const TEAM = "acme-corp.cloudflareaccess.com";
  // A structurally-valid, unexpired RS256 token: it must reach the JWKS path (so the throw below is the thing
  // under test, not an earlier structural refusal).
  const now = Math.floor(Date.now() / 1000);
  const b64u = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64url");
  const token = `${b64u({ alg: "RS256", kid: "kid-7f3a9c", typ: "JWT" })}.${b64u({ iss: `https://${TEAM}`, aud: ["app-tag"], exp: now + 600, sub: "u1", email: "cfo@acme-corp.example" })}.c2ln`;

  // The certs fetch THROWS, exactly as auth.ts's fetchCertsCached does on an outage. The thrown message carries
  // the customer's team domain and a key id: the sentinel that must not survive.
  const res = await verifyAccessJWT(token, {
    teamDomain: TEAM,
    aud: "app-tag",
    fetchCerts: () => {
      throw new TypeError(`fetch to https://${TEAM}/cdn-cgi/access/certs failed (kid-7f3a9c)`);
    },
    now,
  });
  ok("verifyAccessJWT does NOT throw on a JWKS outage", res.ok === false);
  ok("... it fails CLOSED (the token is never admitted)", res.ok === false);
  const name = accessDenySignal(res.reason ?? "");
  ok(`... and the deny classifies as cf-access-jwks-fetch-failed (got ${name})`, name === "cf-access-jwks-fetch-failed");
  assertClosed("jwks outage deny", name);
  assertClean("jwks outage deny", name);
  assertClean("jwks outage reason (internal literal)", res.reason ?? "");

  // The SSRF-pin refusal (a bad CF_ACCESS_TEAM_DOMAIN) is a CONFIGURATION fault, and must be its own name.
  const refused = await verifyAccessJWT(token, {
    teamDomain: TEAM,
    aud: "app-tag",
    fetchCerts: () => {
      throw new Error("Access certs endpoint refused (not an https *.cloudflareaccess.com host)");
    },
    now,
  });
  const refusedName = accessDenySignal(refused.reason ?? "");
  ok(`an SSRF-pin refusal is its own name (got ${refusedName})`, refusedName === "cf-access-jwks-host-refused");
  assertClosed("jwks host-refused deny", refusedName);

  // A JWKS whose selected entry is a malformed RSA key: importKey REJECTS, and that rejection also used to 500.
  const badKey = await verifyAccessJWT(token, {
    teamDomain: TEAM,
    aud: "app-tag",
    // An RSA-typed entry with NO modulus: importKey rejects it with a DataError. This is the "a JWKS entry the
    // shape guard admitted but crypto cannot use" case -- every token signed under that kid is unverifiable.
    fetchCerts: async () => ({ keys: [{ kid: "kid-7f3a9c", kty: "RSA", e: "AQAB" } as unknown as { kid: string; kty: string; n: string; e: string }] }),
    now,
  });
  const badKeyName = accessDenySignal(badKey.reason ?? "");
  ok(`a malformed JWKS key entry denies as cf-access-jwks-import-failed (got ${badKeyName})`, badKeyName === "cf-access-jwks-import-failed");
  assertClosed("jwks import-failed deny", badKeyName);
  assertClean("jwks import-failed deny", badKeyName);
}

console.log("G118: the CSRF Origin refusal names WHICH branch fired (config fault vs attack)");
{
  const mut = (origin: string | null): Request =>
    new Request("https://engine.example/admin/downpipes", { method: "POST", ...(origin === null ? {} : { headers: { origin } }) });
  const CONSOLE = "https://console.acme-corp.example";

  ok("a matching Origin PASSES (null = allowed)", originFailClass(mut(CONSOLE), CONSOLE) === null);

  // The highest-value split in the whole gap: CONSOLE_ORIGIN unset means EVERY user's every cookie-borne
  // mutation 403s, and the fix is a deploy variable -- not a hunt for an attacker.
  const unset = originFailClass(mut(CONSOLE), undefined);
  ok("an UNSET CONSOLE_ORIGIN -> csrf-origin-unset (a deploy-config fault)", unset === "csrf-origin-unset");
  const empty = originFailClass(mut(CONSOLE), "");
  ok("an EMPTY CONSOLE_ORIGIN -> csrf-origin-unset", empty === "csrf-origin-unset");
  const absent = originFailClass(mut(null), CONSOLE);
  ok("NO Origin header -> csrf-origin-header-absent", absent === "csrf-origin-header-absent");
  const foreign = originFailClass(mut("https://evil.example"), CONSOLE);
  ok("a FOREIGN Origin -> csrf-origin-mismatch (a security event)", foreign === "csrf-origin-mismatch");

  for (const rec of [unset, empty, absent, foreign]) {
    if (rec === null) continue;
    assertClosed("originFailClass", rec);
    // The sentinel: the attacker's origin and the customer's console origin BOTH sit at this fault site, and
    // NEITHER may reach the record. The record is a bare enum member.
    assertClean("originFailClass", rec);
  }
  ok("every ORIGIN_FAIL_CLASSES member is in the closed auth-signal vocabulary", ORIGIN_FAIL_CLASSES.every((c) => AUTH_SIGNAL_NAME_SET.has(c)));
}

console.log("G118: the double-submit second factor names its three branches");
{
  const term = (headers: Record<string, string>): Request => new Request("https://engine.example/admin/sessions/terminate-all", { method: "POST", headers });
  const COOKIE = "__Host-downpipes_csrf=tok-abc123";

  ok("a matching header+cookie pair PASSES", csrfDoubleSubmitFailClass(term({ [CSRF_HEADER_NAME]: "tok-abc123", cookie: COOKIE })) === null);
  const noHeader = csrfDoubleSubmitFailClass(term({ cookie: COOKIE }));
  ok("no CSRF header -> csrf-double-submit-header-missing", noHeader === "csrf-double-submit-header-missing");
  const noCookie = csrfDoubleSubmitFailClass(term({ [CSRF_HEADER_NAME]: "tok-abc123" }));
  ok("header present, cookie absent -> csrf-double-submit-cookie-missing", noCookie === "csrf-double-submit-cookie-missing");
  const mismatch = csrfDoubleSubmitFailClass(term({ [CSRF_HEADER_NAME]: "SECRET-SESSION-MAC", cookie: COOKIE }));
  ok("both present, values differ -> csrf-double-submit-mismatch", mismatch === "csrf-double-submit-mismatch");

  for (const rec of [noHeader, noCookie, mismatch]) {
    if (rec === null) continue;
    assertClosed("csrfDoubleSubmitFailClass", rec);
    assertClean("csrfDoubleSubmitFailClass", rec); // the presented token value never rides
  }
  ok("every DOUBLE_SUBMIT_FAIL_CLASSES member is in the closed auth-signal vocabulary", DOUBLE_SUBMIT_FAIL_CLASSES.every((c) => AUTH_SIGNAL_NAME_SET.has(c)));
}

console.log("G233: verifySession's bare null keeps its anti-oracle contract, but the fault CLASS is now nameable");
{
  const key = new Uint8Array(32).fill(7);
  const otherKey = new Uint8Array(32).fill(9); // a DIFFERENT signing key: a rotation, or a forgery
  const now = Date.now();
  const EMAIL = "cfo@acme-corp.example";

  const good = await signSession(key, { email: EMAIL, subject: `passkey|`, method: "passkey", epoch: 1 }, now);
  const verified = await verifySessionClassified(key, good, now);
  ok("a good session still VERIFIES (the contract is unchanged)", !("fault" in verified));

  const malformed = await verifySessionClassified(key, "not-a-session-token", now);
  ok("a malformed cookie -> session-fault-malformed", "fault" in malformed && malformed.fault === "session-fault-malformed");

  // The security-significant one: the body did not authenticate. A TAMPERED or FORGED cookie, or a session
  // minted under a signing key this engine no longer holds is a posture signal, not a config fault.
  const forged = await verifySessionClassified(otherKey, good, now);
  ok("a MAC that does not authenticate -> session-fault-mac-mismatch", "fault" in forged && forged.fault === "session-fault-mac-mismatch");

  const expiredTok = await signSession(key, { email: EMAIL, subject: `passkey|`, method: "passkey", epoch: 1 }, now - 100 * 60 * 60 * 1000);
  const expired = await verifySessionClassified(key, expiredTok, now);
  ok("a session past its absolute exp -> session-fault-expired or -idle", "fault" in expired && (expired.fault === "session-fault-expired" || expired.fault === "session-fault-idle"));

  const faults = [malformed, forged, expired].filter((r): r is { fault: (typeof SESSION_FAULT_CLASSES)[number] } => "fault" in r);
  for (const f of faults) {
    assertClosed("verifySessionClassified", f.fault);
    // The sentinel: the EMAIL and the session MAC are both present at this fault site (they are literally in
    // the token being refused). Neither may reach the record.
    assertClean("verifySessionClassified", f.fault);
    ok(`  ... the fault carries no session token (fault="${f.fault}")`, !f.fault.includes(good.slice(0, 12)));
  }
  ok("every SESSION_FAULT_CLASSES member is in the closed auth-signal vocabulary", SESSION_FAULT_CLASSES.every((c) => AUTH_SIGNAL_NAME_SET.has(c)));
}

console.log("G117: bootstrap-link and role-invite send failures are now recorded (the no-oracle 200 is unchanged)");
{
  // The bootstrap route answers a no-oracle 200 on EVERY skip reason by design, so the reason is the only
  // evidence available. These are its recorded causes.
  const BOOTSTRAP: Array<[string, string]> = [
    ["console-origin-unset", "bootstrap-email-console-origin-unset"],
    ["origin-mismatch", "bootstrap-email-origin-mismatch"],
    ["owner-email-not-configured", "bootstrap-email-owner-unconfigured"],
    ["email-not-configured", "bootstrap-email-binding-unconfigured"],
    ["from-not-configured", "bootstrap-email-from-invalid"],
    ["mint-failed", "bootstrap-email-mint-failed"],
    ["not-available", "bootstrap-email-not-available"],
    ["send-rejected", "bootstrap-email-send-rejected"],
  ];
  for (const [reason, expected] of BOOTSTRAP) {
    const got = bootstrapEmailSignalName(reason);
    ok(`bootstrapEmailSignalName("${reason}") -> ${expected}`, got === expected);
    assertClosed("bootstrapEmailSignalName", got);
    assertClean("bootstrapEmailSignalName", got);
  }

  const INVITE: Array<[string, string]> = [
    ["invite-not-configured", "role-invite-email-binding-unconfigured"],
    ["invite-from-not-configured", "role-invite-email-from-unconfigured"],
    ["invite-from-invalid", "role-invite-email-from-invalid"],
    ["invite-recipient-invalid", "role-invite-email-recipient-invalid"],
    ["invite-send-failed", "role-invite-email-send-rejected"],
  ];
  for (const [reason, expected] of INVITE) {
    const got = roleInviteEmailSignalName(reason);
    ok(`roleInviteEmailSignalName("${reason}") -> ${expected}`, got === expected);
    assertClosed("roleInviteEmailSignalName", got);
    assertClean("roleInviteEmailSignalName", got);
  }

  // TOTALITY + no-leak: the mappers are the redaction chokepoint. An UNRECOGNISED reason (an upstream wording
  // change) must coarsen to a residual member of the closed set -- it must never be echoed as text. Drive them
  // with a hostile reason that carries a recipient address and a live invite link.
  const hostile = "cfo@acme-corp.example https://console.acme-corp.example/#/register?invite=SECRET-SESSION-MAC";
  const bRes = bootstrapEmailSignalName(hostile);
  const iRes = roleInviteEmailSignalName(hostile);
  ok("an unrecognised bootstrap reason coarsens to a closed residual (never echoed)", AUTH_SIGNAL_NAME_SET.has(bRes));
  ok("an unrecognised invite reason coarsens to a closed residual (never echoed)", AUTH_SIGNAL_NAME_SET.has(iRes));
  assertClean("bootstrapEmailSignalName(hostile)", bRes);
  assertClean("roleInviteEmailSignalName(hostile)", iRes);
}

console.log(failures === 0 ? "\nadmin auth diagnostics: all checks passed" : `\nadmin auth diagnostics: ${failures} FAILED`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
