// validate-passkey group: the ceremony NEGATIVE CONTROLS (wrong challenge / origin / rpIdHash, a tampered
// or wrong-key signature, a backwards/equal signCount clone, an unknown credential, a replayed challenge,
// an absent user-present flag, a malformed COSE key), plus the invited-second-registrant-is-not-Owner, the
// credential-id-uniqueness check, and the CONSOLE_ORIGIN-unset fail-closed. Each control is written so it
// would FAIL if the verifier stopped checking the corresponding fact. Split out of validate-passkey.ts
// (behaviour-preserving); run via the validate-passkey.ts orchestrator.
import { b64urlEncode } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
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
  enrolBootstrapOwner,
  grantRoleViaToken,
  whoamiRole,
  challengeFor,
  challengeIdFor,
  captureErrors,
} from "./validate-passkey-harness.ts";

export async function run(): Promise<void> {
  // 3. NEGATIVE CONTROL: WRONG challenge at login is rejected.
  {
    const { env, storage } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "neg-chal@example.com";
    await enrolBootstrapOwner(env, auth, email);
    const lbegin = await loginBegin(env, email);
    // Sign over a DIFFERENT challenge than the one the server issued.
    const wrong = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    const assertion = await signAssertion(auth, wrong, {});
    const cap = captureErrors();
    const lfin = await loginFinish(env, challengeIdFor(lbegin), assertion);
    cap.restore();
    ok("login with a WRONG challenge is rejected (reason challenge)", lfin.json.ok === false && lfin.json.reason === "challenge");
    ok("the precise reason was logged with an opaque err id", cap.errors.some((l) => /\[err:[0-9a-f]{8} /.test(l)));
    // V16.3.1: the failed login is ALSO recorded in the tamper-evident audit chain (a brute-force sweep is
    // otherwise invisible there - the ceremony only returns a 200 {ok:false}).
    const failAudit = [...(await storage.list<{ action?: string; outcome?: string }>({ prefix: "audit:" })).values()].some((e) => e.action === "authn-failure" && e.outcome === "failed");
    ok("a failed passkey login is recorded as an authn-failure audit event (V16.3.1)", failAudit);
  }

  // 4. NEGATIVE CONTROL: WRONG origin is rejected (registration and login).
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "neg-origin@example.com";
    // The bootstrap path authorises this (empty table + ADMIN_TOKEN), so the verifier IS reached and the
    // origin check is what rejects (not the authorisation gate): clientDataJSON carries an origin the
    // server did not configure. The DO still sees the SERVER origin (the router supplies it); the clientData
    // origin is the forged one, so verifyRegistration's origin compare is the failing fact under test.
    const begin = await registerBegin(env, email, bootstrapOpts());
    const att = await buildAttestation(auth, challengeFor(begin), { origin: "https://evil.example" });
    const fin = await registerFinish(env, email, att, bootstrapOpts());
    ok("register with a WRONG origin is rejected (reason origin)", fin.json.ok === false && fin.json.reason === "origin");

    // Now register cleanly (bootstrap), then attempt a login from a wrong origin.
    await enrolBootstrapOwner(env, auth, email);
    const lbegin = await loginBegin(env, email);
    const assertion = await signAssertion(auth, challengeFor(lbegin), { origin: "https://evil.example" });
    const lfin = await loginFinish(env, challengeIdFor(lbegin), assertion);
    ok("login with a WRONG origin is rejected (reason origin)", lfin.json.ok === false && lfin.json.reason === "origin");
  }

  // 5. NEGATIVE CONTROL: WRONG rpIdHash is rejected (the authenticatorData was signed for a different rp).
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "neg-rpid@example.com";
    await enrolBootstrapOwner(env, auth, email);
    const lbegin = await loginBegin(env, email);
    // Build the authData with a DIFFERENT rp.id, so its rpIdHash will not match SHA-256(server rp.id).
    const assertion = await signAssertion(auth, challengeFor(lbegin), { rpId: "different.example" });
    const lfin = await loginFinish(env, challengeIdFor(lbegin), assertion);
    ok("login with a WRONG rpIdHash is rejected (reason rpid)", lfin.json.ok === false && lfin.json.reason === "rpid");

    // And at registration (the table is now non-empty): an INVITED second email whose attestation's
    // authData rpIdHash is for a different rp.id. The invite authorises the email, so the verifier IS
    // reached and the rpid check is what rejects (not the authorisation gate).
    const auth2 = await makeAuthenticator("ES256");
    const invite = await grantRoleViaToken(env, "neg-rpid2@example.com", "viewer");
    ok("a role grant to a not-yet-enrolled email mints a registration invite", typeof invite === "string");
    const begin2 = await registerBegin(env, "neg-rpid2@example.com", { inviteToken: invite });
    const att = await buildAttestation(auth2, challengeFor(begin2), { rpId: "different.example" });
    const finRpid = await registerFinish(env, "neg-rpid2@example.com", att, { inviteToken: invite });
    ok("register with a WRONG rpIdHash is rejected (reason rpid)", finRpid.json.ok === false && finRpid.json.reason === "rpid");
  }

  // 6. NEGATIVE CONTROL: TAMPERED signature is rejected (proves the signature is actually verified).
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "neg-sig@example.com";
    await enrolBootstrapOwner(env, auth, email);
    const lbegin = await loginBegin(env, email);
    const assertion = await signAssertion(auth, challengeFor(lbegin), { tamper: true });
    const lfin = await loginFinish(env, challengeIdFor(lbegin), assertion);
    ok("login with a TAMPERED signature is rejected (reason signature)", lfin.json.ok === false && lfin.json.reason === "signature");

    // RS256 tamper too, to exercise both verify paths. The second user is enrolled via an invite (the
    // table is non-empty now), proving the RSA path under a non-bootstrap registration.
    const rauth = await makeAuthenticator("RS256");
    const remail = "neg-sig-rsa@example.com";
    const rinvite = await grantRoleViaToken(env, remail, "viewer");
    await registerFinish(env, remail, await buildAttestation(rauth, challengeFor(await registerBegin(env, remail, { inviteToken: rinvite }))), { inviteToken: rinvite });
    const rlbegin = await loginBegin(env, remail);
    const rassertion = await signAssertion(rauth, challengeFor(rlbegin), { tamper: true });
    const rlfin = await loginFinish(env, challengeIdFor(rlbegin), rassertion);
    ok("RS256 login with a TAMPERED signature is rejected", rlfin.json.ok === false && rlfin.json.reason === "signature");
  }

  // 7. NEGATIVE CONTROL: a WRONG-KEY signature (signed by a different authenticator's key) is rejected.
  // This proves the verifier checks the signature against the STORED key, not merely that some valid
  // signature is present.
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const imposter = await makeAuthenticator("ES256");
    // The imposter shares the registered credential id but holds a different private key.
    imposter.credentialId = auth.credentialId;
    const email = "neg-key@example.com";
    await enrolBootstrapOwner(env, auth, email);
    const lbegin = await loginBegin(env, email);
    const assertion = await signAssertion(imposter, challengeFor(lbegin), {});
    const lfin = await loginFinish(env, challengeIdFor(lbegin), assertion);
    ok("login signed by the WRONG key is rejected (reason signature)", lfin.json.ok === false && lfin.json.reason === "signature");
  }

  // 8. NEGATIVE CONTROL: BACKWARDS signCount (clone detection).
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "neg-clone@example.com";
    await enrolBootstrapOwner(env, auth, email);
    // First login advances the counter to 10.
    const l1 = await loginBegin(env, email);
    const a1 = await signAssertion(auth, challengeFor(l1), { signCount: 10 });
    const f1 = await loginFinish(env, challengeIdFor(l1), a1);
    ok("first login advances signCount", f1.json.ok === true);
    // Second login presents a LOWER counter (8): a possible cloned authenticator.
    const l2 = await loginBegin(env, email);
    const a2 = await signAssertion(auth, challengeFor(l2), { signCount: 8 });
    const f2 = await loginFinish(env, challengeIdFor(l2), a2);
    ok("a BACKWARDS signCount is rejected as a clone (reason clone)", f2.json.ok === false && f2.json.reason === "clone");
    // Equal counter (10 again) is also a non-advance and rejected.
    const l3 = await loginBegin(env, email);
    const a3 = await signAssertion(auth, challengeFor(l3), { signCount: 10 });
    const f3 = await loginFinish(env, challengeIdFor(l3), a3);
    ok("an EQUAL (non-advancing) signCount is rejected as a clone", f3.json.ok === false && f3.json.reason === "clone");
  }

  // 9. NEGATIVE CONTROL: UNKNOWN credential at login.
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "neg-unknown@example.com";
    await enrolBootstrapOwner(env, auth, email);
    const lbegin = await loginBegin(env, email);
    // Assert with a credential id that was never registered.
    const ghost = await makeAuthenticator("ES256");
    const assertion = await signAssertion(ghost, challengeFor(lbegin), {});
    const lfin = await loginFinish(env, challengeIdFor(lbegin), assertion);
    ok("login with an UNKNOWN credential is rejected (reason unknown_credential)", lfin.json.ok === false && lfin.json.reason === "unknown_credential");
  }

  // 10. NEGATIVE CONTROL: REPLAYED / consumed challenge.
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "neg-replay@example.com";
    await enrolBootstrapOwner(env, auth, email);
    const lbegin = await loginBegin(env, email);
    const ch = challengeFor(lbegin);
    const id = challengeIdFor(lbegin);
    const first = await loginFinish(env, id, await signAssertion(auth, ch, { signCount: 2 }));
    ok("the first login with the issued challenge succeeds", first.json.ok === true);
    // Replay the SAME challengeId with a fresh (higher signCount) assertion over the same challenge.
    const replay = await loginFinish(env, id, await signAssertion(auth, ch, { signCount: 3 }));
    ok("a REPLAYED (already-consumed) challenge is rejected (reason challenge)", replay.json.ok === false && replay.json.reason === "challenge");
  }

  // 11. NEGATIVE CONTROL: absent user-present flag.
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "neg-up@example.com";
    // Registration without the UP flag is rejected. Bootstrap-authorised so the verifier IS reached and
    // the user-present check (not the authorisation gate) is the failing fact.
    const att = await buildAttestation(auth, challengeFor(await registerBegin(env, email, bootstrapOpts())), { up: false });
    const fin = await registerFinish(env, email, att, bootstrapOpts());
    ok("register without the user-present flag is rejected (reason user_present)", fin.json.ok === false && fin.json.reason === "user_present");
    // Register cleanly (bootstrap), then a login without UP is rejected.
    await enrolBootstrapOwner(env, auth, email);
    const lbegin = await loginBegin(env, email);
    const assertion = await signAssertion(auth, challengeFor(lbegin), { up: false });
    const lfin = await loginFinish(env, challengeIdFor(lbegin), assertion);
    ok("login without the user-present flag is rejected (reason user_present)", lfin.json.ok === false && lfin.json.reason === "user_present");
  }

  // 12. NEGATIVE CONTROL: malformed COSE key at registration.
  {
    const { env, storage } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "neg-cose@example.com";
    // Bootstrap-authorised so the verifier IS reached and the COSE-parse failure (not the authorisation
    // gate) is the failing fact under test.
    const att = await buildAttestation(auth, challengeFor(await registerBegin(env, email, bootstrapOpts())), { corruptCose: true });
    const fin = await registerFinish(env, email, att, bootstrapOpts());
    ok("register with a malformed COSE key is rejected (reason bad_request)", fin.json.ok === false && fin.json.reason === "bad_request");
    ok("no credential was stored for the rejected registration", storage.countPrefix("passkeyCred:") === 0);
  }

  // 13. An INVITED second registrant does NOT become Owner (the bootstrap is first-registrant ONLY; a
  // later, Owner-authorised enrolment lands at the role the table grants the email, the viewer default).
  {
    const { env, stub } = makeScheduler();
    const first = await makeAuthenticator("ES256");
    const second = await makeAuthenticator("ES256");
    await enrolBootstrapOwner(env, first, "owner@example.com");
    const invite = await grantRoleViaToken(env, "second@example.com", "viewer");
    const fin2 = await registerFinish(env, "second@example.com", await buildAttestation(second, challengeFor(await registerBegin(env, "second@example.com", { inviteToken: invite }))), { inviteToken: invite });
    ok("the invited second registrant is NOT bootstrapped to Owner", fin2.json.ok === true && fin2.json.bootstrapped === false && fin2.json.role === "viewer");
    const who2 = await whoamiRole(stub, "second@example.com");
    ok("whoami resolves the second registrant to the viewer default", who2.role === "viewer" && who2.roleSource === "default");
  }

  // 14. A credential id may not be registered twice (already_registered). The dup attempt is INVITED for a
  // second email (the table is non-empty after the bootstrap), so it is an AUTHORISED registration that the
  // credential-id-uniqueness check rejects, not the authorisation gate.
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    await enrolBootstrapOwner(env, auth, "dup@example.com");
    // The SAME authenticator (same credential id) re-registers under a second, invited email.
    const invite = await grantRoleViaToken(env, "dup2@example.com", "viewer");
    const fin = await registerFinish(env, "dup2@example.com", await buildAttestation(auth, challengeFor(await registerBegin(env, "dup2@example.com", { inviteToken: invite }))), { inviteToken: invite });
    ok("re-registering the same credential id is rejected (already_registered)", fin.json.ok === false && fin.json.reason === "already_registered");
  }

  // 15. The passkey routes fail closed (501) when CONSOLE_ORIGIN is unset (no origin to bind/check). The
  // ADMIN_TOKEN env stays set, but passkeyOriginAndRpId returns null with no origin, so the route is 501
  // BEFORE any authorisation/ceremony work.
  {
    const { env } = makeScheduler();
    const noOrigin = { ...env, CONSOLE_ORIGIN: undefined } as unknown as Env;
    const begin = await registerBegin(noOrigin, "x@example.com", bootstrapOpts());
    ok("passkey routes return 501 when CONSOLE_ORIGIN is unset", begin.status === 501 && begin.json.ok === false && begin.json.reason === "passkey_not_configured");
  }
}
