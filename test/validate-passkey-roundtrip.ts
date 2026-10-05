// validate-passkey group: the full register -> login ROUND TRIP (ES256 and RS256), the first-user
// BOOTSTRAP to Owner, the recovery-codes-on-enrolment contract, the signCount high-water advance, and the
// single-use bootstrap latch. Split out of validate-passkey.ts (behaviour-preserving); run via the
// validate-passkey.ts orchestrator.
import { b64urlEncode } from "../src/crypto/bytes.ts";
import {
  ok,
  makeScheduler,
  makeAuthenticator,
  buildAttestation,
  signAssertion,
  registerBegin,
  registerFinish,
  loginBegin,
  loginFinish,
  bootstrapOpts,
  whoamiRole,
  challengeFor,
  challengeIdFor,
  optionsFor,
  extractSessionCookie,
  RP_ID,
} from "./validate-passkey-harness.ts";

export async function run(): Promise<void> {
  // 1. Full ES256 register -> login ROUND TRIP, and FIRST-USER BOOTSTRAP to Owner (the BOOTSTRAP path:
  // the empty role table + a valid ADMIN_TOKEN bearer).
  {
    const { env, stub, storage } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "alice@example.com";

    const begin = await registerBegin(env, email, bootstrapOpts());
    ok("register/begin returns ok + creation options", begin.status === 200 && begin.json.ok === true && typeof optionsFor(begin).challenge === "string");
    ok("register/begin advertises ES256 (-7) and RS256 (-257)", JSON.stringify(optionsFor(begin).pubKeyCredParams) === JSON.stringify([{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }]));
    ok("register/begin rp.id defaults to the console host", optionsFor(begin).rp.id === RP_ID);
    ok("register/begin requests userVerification required", optionsFor(begin).authenticatorSelection.userVerification === "required");

    const att = await buildAttestation(auth, challengeFor(begin));
    const fin = await registerFinish(env, email, att, bootstrapOpts());
    ok("register/finish verifies the attestation", fin.status === 200 && fin.json.ok === true);
    ok("first registrant is BOOTSTRAPPED to Owner", fin.json.bootstrapped === true && fin.json.role === "owner");
    ok("a credential record was stored", storage.countPrefix("passkeyCred:") === 1);
    ok("a passkey user record was stored", storage.countPrefix("passkeyUser:") === 1);
    ok("the registration challenge was consumed", storage.countPrefix("passkeyChallenge:") === 0);
    ok("register/finish mints a session cookie", extractSessionCookie(fin.setCookie) !== null);

    // RECOVERY CODES on enrolment: the finish response carries exactly 10 single-use codes, ONCE, in the
    // human xxxxx-xxxxx format. They are returned for one-time display and then never again.
    ok("enrolment returns recovery codes", Array.isArray(fin.json.recoveryCodes));
    // recoveryCodes is an optional body field; enrolment always returns it, asserted on the line above, so
    // capture it once as the string[] the subsequent assertions read (this replaces the prior inline casts;
    // the non-null assertion keeps the same read as before, no runtime change).
    const codes = fin.json.recoveryCodes!;
    ok("enrolment returns exactly 10 recovery codes", codes.length === 10);
    ok("recovery codes are the six-group human format (30 chars / 150 bits)", codes.every((c: string) => /^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){5}$/.test(c)));
    ok("the 10 recovery codes are all distinct", new Set(codes).size === 10);
    // ONLY salted hashes are stored - never a plaintext code. The per-email recovery record holds the hashes;
    // assert NONE of the issued plaintext codes appears anywhere in the persisted record.
    const recRecord = await storage.get<{ codes: { hash: string; salt: string; consumed: boolean }[] }>(`recovery:${email}`);
    ok("a per-email recovery record was persisted", recRecord !== undefined && Array.isArray(recRecord.codes) && recRecord.codes.length === 10);
    const recordJson = JSON.stringify(recRecord);
    ok("NO issued plaintext code appears in the stored record (only hashes)", codes.every((c) => !recordJson.includes(c) && !recordJson.includes(c.replaceAll("-", ""))));
    ok("every stored code is an HMAC hash, not a plaintext", recRecord!.codes.every((c) => c.hash.startsWith("hmac-sha256:") && c.consumed === false));
    // The enrolment also recorded a recovery-codes-generated audit event (who+when, never a code).
    const sawGenerated = [...(await storage.list<{ action?: string }>({ prefix: "audit:" })).values()].some((e) => e.action === "recovery-codes-generated");
    ok("enrolment records a recovery-codes-generated audit event", sawGenerated);

    const who = await whoamiRole(stub, email);
    ok("whoami confirms the bootstrapped Owner (source email)", who.role === "owner" && who.roleSource === "email" && who.isOnlyOwner === true);

    // Login round trip.
    const lbegin = await loginBegin(env, email);
    ok("login/begin returns ok + request options + a challengeId", lbegin.status === 200 && lbegin.json.ok === true && typeof lbegin.json.challengeId === "string");
    // ANTI-ENUMERATION (ASVS V6.2.1/V6.3.8): allowCredentials must stay empty even though `email` names a
    // real, enrolled account - the response must be indistinguishable from an unenrolled/unknown email
    // (asserted right below), so an unauthenticated caller can never use it as an existence oracle.
    ok("login/begin does NOT scope allowCredentials to the supplied email's credential", optionsFor(lbegin).allowCredentials.length === 0);

    const assertion = await signAssertion(auth, challengeFor(lbegin), { signCount: 5 });
    const lfin = await loginFinish(env, challengeIdFor(lbegin), assertion);
    ok("login/finish verifies the assertion and returns the verified email", lfin.status === 200 && lfin.json.ok === true && lfin.json.email === email);
    ok("the login challenge was consumed", storage.countPrefix("passkeyChallenge:") === 0);

    // A second begin for a WHOLLY UNENROLLED email must return the identical empty-allowCredentials shape
    // (checked after the consume-check above so this probe's own fresh challenge doesn't affect it) - proving
    // the response can't be used to distinguish an enrolled email from one that was never registered.
    const lbeginUnknown = await loginBegin(env, "no-such-user@example.com");
    ok("login/begin for an unenrolled email returns the SAME empty allowCredentials shape", optionsFor(lbeginUnknown).allowCredentials.length === 0);

    // The signCount high-water mark advanced to the asserted value.
    const credKey = `passkeyCred:${b64urlEncode(auth.credentialId)}`;
    const storedCred = await storage.get<{ signCount: number }>(credKey);
    ok("the stored signCount advanced to the asserted value", storedCred?.signCount === 5);

    // SINGLE-USE BOOTSTRAP (break-glass disposal): the passkey bootstrap latched bootstrapConsumed in the
    // orgpolicy record, and recorded a one-time bootstrap-consumed audit event.
    const policy = await storage.get<{ bootstrapConsumed?: boolean }>("orgpolicy");
    ok("passkey bootstrap latches bootstrapConsumed", policy?.bootstrapConsumed === true);
    const auditList = await storage.list<{ action?: string }>({ prefix: "audit:" });
    const sawConsumed = [...auditList.values()].some((e) => e.action === "bootstrap-consumed");
    ok("passkey bootstrap records the one-time bootstrap-consumed audit event", sawConsumed);

    // Even if the role table is FORCIBLY emptied (a hand-cleared store), a second token-authorised passkey
    // bootstrap is REFUSED (the latch holds): register/begin returns ok:false and no second Owner is minted.
    const roleKeys = await storage.list({ prefix: "role:" });
    for (const k of roleKeys.keys()) await storage.delete(k);
    ok("single-use: precondition - the role table is empty again", (await storage.list({ prefix: "role:" })).size === 0);
    const reBegin = await registerBegin(env, "second-owner@example.com", bootstrapOpts());
    ok("single-use: a second token passkey-bootstrap is refused after consume (no challenge)", reBegin.json.ok !== true);
    ok("single-use: the refused re-bootstrap minted no new Owner row", (await storage.list({ prefix: "role:" })).size === 0);
  }

  // 2. Full RS256 register -> login ROUND TRIP (the RSA path), via the bootstrap path.
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator("RS256");
    const email = "rsa@example.com";
    const begin = await registerBegin(env, email, bootstrapOpts());
    const att = await buildAttestation(auth, challengeFor(begin));
    const fin = await registerFinish(env, email, att, bootstrapOpts());
    ok("RS256 register/finish verifies", fin.status === 200 && fin.json.ok === true && fin.json.bootstrapped === true);
    const lbegin = await loginBegin(env, email);
    const assertion = await signAssertion(auth, challengeFor(lbegin), { signCount: 1 });
    const lfin = await loginFinish(env, challengeIdFor(lbegin), assertion);
    ok("RS256 login/finish verifies the assertion", lfin.status === 200 && lfin.json.ok === true && lfin.json.email === email);
  }
}
