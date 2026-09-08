// Advisory authentication-context signal (ASVS V6.8.4). Unit-proves the bounded, redaction-safe extractors
// that read the IdP's acr/amr/auth_time (OIDC) and AuthnContextClassRef/AuthnInstant (SAML) as a STRICTLY
// NON-GATING signal. The key properties: a present claim is surfaced (bounded); an absent one degrades to
// undefined (not a failure, not an empty shell); and a hostile/oversized value is DROPPED, never truncated,
// so it cannot become a free-text or amplification channel into the audit surface. The non-gating property
// is structural (the module has no authority and nothing here returns a decision); the RP/role tests prove
// authorization is unaffected end to end.
//
// Run: node test/validate-auth-context.ts

import {
  boundAcr,
  boundAmr,
  boundAuthTime,
  buildAuthContext,
  extractOidcAuthContext,
  ACR_MAX_LEN,
  AMR_MAX_COUNT,
  AMR_ENTRY_MAX_LEN,
} from "../src/admin/auth-context.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function testBoundAcr(): void {
  ok("boundAcr: a normal acr string passes", boundAcr("urn:mace:incommon:iap:silver") === "urn:mace:incommon:iap:silver");
  ok("boundAcr: trims surrounding whitespace", boundAcr("  mfa  ") === "mfa");
  ok("boundAcr: empty / whitespace-only -> undefined", boundAcr("") === undefined && boundAcr("   ") === undefined);
  ok("boundAcr: a non-string -> undefined", boundAcr(42) === undefined && boundAcr(null) === undefined && boundAcr(["mfa"]) === undefined);
  // An over-cap value is DROPPED, never truncated-and-stored (a partial value must not read as the real one).
  ok(`boundAcr: at the cap (${ACR_MAX_LEN}) passes`, boundAcr("a".repeat(ACR_MAX_LEN)) === "a".repeat(ACR_MAX_LEN));
  ok("boundAcr: over the cap -> undefined (dropped, not truncated)", boundAcr("a".repeat(ACR_MAX_LEN + 1)) === undefined);
}

function testBoundAmr(): void {
  const r = boundAmr(["pwd", "otp", "mfa"]);
  ok("boundAmr: a normal amr list passes", Array.isArray(r) && r.length === 3 && r[0] === "pwd" && r[2] === "mfa");
  ok("boundAmr: a non-array -> undefined", boundAmr("pwd") === undefined && boundAmr(null) === undefined && boundAmr(7) === undefined);
  ok("boundAmr: an empty array -> undefined (never [])", boundAmr([]) === undefined);
  // Non-string / empty / over-length entries are filtered; if nothing survives -> undefined.
  ok("boundAmr: filters non-string + empty entries", JSON.stringify(boundAmr([1, "", "  ", "pwd", {}])) === JSON.stringify(["pwd"]));
  ok("boundAmr: all-unusable entries -> undefined", boundAmr([1, "", null, {}]) === undefined);
  const overEntry = boundAmr(["pwd", "x".repeat(AMR_ENTRY_MAX_LEN + 1)]);
  ok("boundAmr: an over-length entry is dropped (the rest survive)", JSON.stringify(overEntry) === JSON.stringify(["pwd"]));
  // The LIST length is capped: a huge amr cannot amplify the record.
  const many = Array.from({ length: AMR_MAX_COUNT + 25 }, (_, i) => `m${i}`);
  const capped = boundAmr(many);
  ok(`boundAmr: caps the list length at ${AMR_MAX_COUNT}`, Array.isArray(capped) && capped.length === AMR_MAX_COUNT);
}

function testBoundAuthTime(): void {
  ok("boundAuthTime: a NumericDate (seconds) passes", boundAuthTime(1_700_000_000) === 1_700_000_000);
  ok("boundAuthTime: zero passes", boundAuthTime(0) === 0);
  ok("boundAuthTime: floors a fractional value", boundAuthTime(1_700_000_000.9) === 1_700_000_000);
  ok("boundAuthTime: negative -> undefined", boundAuthTime(-1) === undefined);
  ok("boundAuthTime: NaN / Infinity -> undefined", boundAuthTime(NaN) === undefined && boundAuthTime(Infinity) === undefined);
  ok("boundAuthTime: a non-number -> undefined", boundAuthTime("1700000000") === undefined && boundAuthTime(null) === undefined);
}

function testBuildAndExtract(): void {
  // buildAuthContext returns undefined when NONE of the three is usable (so the caller omits the field).
  ok("buildAuthContext: none usable -> undefined", buildAuthContext({}) === undefined);
  ok("buildAuthContext: all-unusable inputs -> undefined", buildAuthContext({ acr: 1, amr: "x", authTime: -5 }) === undefined);
  const onlyAcr = buildAuthContext({ acr: "mfa" });
  ok("buildAuthContext: only acr -> {acr} (no amr/authTime keys)", JSON.stringify(onlyAcr) === JSON.stringify({ acr: "mfa" }));
  const onlyAmr = buildAuthContext({ amr: ["otp"] });
  ok("buildAuthContext: only amr -> {amr}", JSON.stringify(onlyAmr) === JSON.stringify({ amr: ["otp"] }));
  const onlyTime = buildAuthContext({ authTime: 1_700_000_000 });
  ok("buildAuthContext: only authTime -> {authTime}", JSON.stringify(onlyTime) === JSON.stringify({ authTime: 1_700_000_000 }));

  // extractOidcAuthContext reads acr/amr/auth_time from a verified claims object and nothing else.
  const full = extractOidcAuthContext({ sub: "u1", acr: "urn:x:mfa", amr: ["pwd", "otp"], auth_time: 1_699_999_000, iss: "https://idp" });
  ok("extractOidcAuthContext: surfaces acr/amr/auth_time from claims", full !== undefined && full.acr === "urn:x:mfa" && JSON.stringify(full.amr) === JSON.stringify(["pwd", "otp"]) && full.authTime === 1_699_999_000);
  // Absent claims degrade gracefully to undefined (the common basic-IdP case) -- never an empty shell.
  ok("extractOidcAuthContext: no acr/amr/auth_time claims -> undefined", extractOidcAuthContext({ sub: "u1", iss: "https://idp", email: "a@b" }) === undefined);
  // A partial claim set surfaces only what is present.
  const partial = extractOidcAuthContext({ sub: "u1", auth_time: 1_700_000_500 });
  ok("extractOidcAuthContext: only auth_time present -> {authTime} only", JSON.stringify(partial) === JSON.stringify({ authTime: 1_700_000_500 }));
  // A hostile oversized acr is dropped (NON-GATING + non-amplifying): the extractor returns undefined here.
  ok("extractOidcAuthContext: an oversized acr is dropped", extractOidcAuthContext({ acr: "a".repeat(ACR_MAX_LEN + 1) }) === undefined);
}

function main(): void {
  testBoundAcr();
  testBoundAmr();
  testBoundAuthTime();
  testBuildAndExtract();
  console.log(failures === 0 ? "\nAUTH-CONTEXT (V6.8.4) TESTS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
