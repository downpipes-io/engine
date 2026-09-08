// validate-passkey group: the ACCOUNT-TAKEOVER FIX (registration authorisation, the blocker) and the rest
// of the front-door controls. WebAuthn proves key possession, not email ownership, so a credential may be
// bound to an email ONLY by a proven path: bootstrap (ADMIN_TOKEN + empty table), an Owner-minted single-
// use email-bound invite, or self-add (an authenticated caller's own email); the bound email comes from
// the PROOF, never the client field. Covers the takeover refusal, the empty-table seize refusal, the
// ADMIN_TOKEN-unset closed bootstrap, invite-bound registration, consumed/expired/wrong invites, self-add,
// user-verification-required, the AT-on-an-assertion rejection, the per-IP rate limit, the logout CSRF
// check, and the email-link bootstrap. Split out of validate-passkey.ts (behaviour-preserving); run via
// the validate-passkey.ts orchestrator.
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
  optionsFor,
  extractSessionCookie,
  post,
  ORIGIN,
} from "./validate-passkey-harness.ts";

export async function run(): Promise<void> {
  // 18. THE TAKEOVER IS REJECTED: an attacker tries to register a passkey for an EXISTING Owner's email
  // with no invite and no session. It must be refused (403/forbidden), with NO credential stored and NO
  // session minted. This is the core blocker.
  {
    const { env, stub, storage } = makeScheduler();
    const owner = await makeAuthenticator("ES256");
    const ownerEmail = "owner@example.com";
    await enrolBootstrapOwner(env, owner, ownerEmail);
    const credsBefore = storage.countPrefix("passkeyCred:");

    const attacker = await makeAuthenticator("ES256");
    // No invite token, no Authorization, no session cookie: a bare unauthenticated registration attempt
    // for the Owner's email. begin must refuse (no challenge stored), and finish must refuse too.
    const begin = await registerBegin(env, ownerEmail);
    ok("takeover register/begin for an existing Owner email is refused (forbidden)", begin.status === 200 && begin.json.ok === false && begin.json.reason === "forbidden");
    ok("takeover register/begin stored NO challenge", storage.countPrefix("passkeyChallenge:") === 0);
    // Even if the attacker fabricates a challenge and a full attestation, finish must refuse.
    const fakeChallenge = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    const att = await buildAttestation(attacker, fakeChallenge);
    const fin = await registerFinish(env, ownerEmail, att);
    ok("takeover register/finish for an existing Owner email is refused (forbidden)", fin.status === 200 && fin.json.ok === false && fin.json.reason === "forbidden");
    ok("takeover stored NO new credential", storage.countPrefix("passkeyCred:") === credsBefore);
    ok("takeover minted NO session (no Set-Cookie)", extractSessionCookie(fin.setCookie) === null);
    // The attacker's credential id must NOT resolve to the Owner: a login with it is unknown_credential.
    const lbegin = await loginBegin(env, ownerEmail);
    const lfin = await loginFinish(env, challengeIdFor(lbegin), await signAssertion(attacker, challengeFor(lbegin), {}));
    ok("the attacker credential cannot log in as the Owner", lfin.json.ok === false && lfin.json.reason === "unknown_credential");
    // And the Owner is still the sole Owner (no second Owner was created).
    const who = await whoamiRole(stub, ownerEmail);
    ok("the Owner is unchanged and still the sole Owner", who.role === "owner" && who.isOnlyOwner === true);
  }

  // 19. THE EMPTY-TABLE SEIZE IS REJECTED: on a fresh, empty-table account, an attacker who is first to
  // reach register WITHOUT the ADMIN_TOKEN cannot seize Owner. With the ADMIN_TOKEN bearer (the operator),
  // it works. This proves the bootstrap path is gated on the deploy-time secret.
  {
    const { env, stub, storage } = makeScheduler();
    const attacker = await makeAuthenticator("ES256");
    const email = "first@example.com";
    // No ADMIN_TOKEN bearer: bootstrap is closed, registration refused, no Owner seized.
    const begin = await registerBegin(env, email);
    ok("empty-table register/begin WITHOUT ADMIN_TOKEN is refused (forbidden)", begin.json.ok === false && begin.json.reason === "forbidden");
    ok("no challenge stored for the unauthorised bootstrap attempt", storage.countPrefix("passkeyChallenge:") === 0);
    const fin = await registerFinish(env, email, await buildAttestation(attacker, b64urlEncode(crypto.getRandomValues(new Uint8Array(32)))));
    ok("empty-table register/finish WITHOUT ADMIN_TOKEN is refused (forbidden)", fin.json.ok === false && fin.json.reason === "forbidden");
    ok("no Owner role was written for the unauthorised attempt", storage.countPrefix("role:") === 0);
    ok("no credential stored for the unauthorised bootstrap attempt", storage.countPrefix("passkeyCred:") === 0);

    // WITH the ADMIN_TOKEN bearer the operator claims the first Owner.
    const operator = await makeAuthenticator("ES256");
    const fin2 = await enrolBootstrapOwner(env, operator, "operator@example.com");
    ok("empty-table register WITH ADMIN_TOKEN bootstraps Owner", fin2.json.ok === true && fin2.json.bootstrapped === true && fin2.json.role === "owner");
    const who = await whoamiRole(stub, "operator@example.com");
    ok("the ADMIN_TOKEN registrant is the bootstrapped Owner", who.role === "owner" && who.isOnlyOwner === true);
  }

  // 20. BOOTSTRAP IS CLOSED WHEN ADMIN_TOKEN IS UNSET: with no ADMIN_TOKEN configured at all, even an
  // empty-table first registration cannot bootstrap (the operator must set the secret to enrol the first
  // passkey). authorise() yields no token verdict, so bootstrapAuthorised is never true.
  {
    const { env } = makeScheduler();
    const noToken = { ...env, ADMIN_TOKEN: undefined } as unknown as Env;
    const auth = await makeAuthenticator("ES256");
    const begin = await registerBegin(noToken, "first@example.com", { authorization: "Bearer test-admin-token-deadbeef-deadbeef", origin: ORIGIN });
    ok("bootstrap is closed when ADMIN_TOKEN is unset (begin forbidden)", begin.json.ok === false && begin.json.reason === "forbidden");
    void auth;
  }

  // 21. INVITE-BOUND REGISTRATION: an Owner grants a role to a not-yet-enrolled email; the DO mints a
  // single-use, email-bound invite; the invited person registers WITH the token and the bound email is
  // taken FROM THE INVITE, not the client field. A registration that names a DIFFERENT client email but
  // presents the invite still binds to the invite's email.
  {
    const { env, stub } = makeScheduler();
    const owner = await makeAuthenticator("ES256");
    await enrolBootstrapOwner(env, owner, "owner@example.com");
    const invitedEmail = "invitee@example.com";
    const invite = await grantRoleViaToken(env, invitedEmail, "operator");
    ok("granting a role to a not-yet-enrolled email returns an invite token", typeof invite === "string" && invite!.length > 0);

    const invitee = await makeAuthenticator("ES256");
    const begin = await registerBegin(env, invitedEmail, { inviteToken: invite });
    ok("invite register/begin is authorised", begin.status === 200 && begin.json.ok === true);
    // The creation options bind to the INVITE'S email (the user.name the DO put in the options).
    ok("invite register/begin binds the options to the invite email", optionsFor(begin).user.name === invitedEmail);
    const fin = await registerFinish(env, invitedEmail, await buildAttestation(invitee, challengeFor(begin)), { inviteToken: invite });
    ok("invite register/finish verifies and binds the invited email", fin.json.ok === true && fin.json.email === invitedEmail);
    // The invitee can now log in as the invited email, with the role the Owner granted (operator).
    const lbegin = await loginBegin(env, invitedEmail);
    const lfin = await loginFinish(env, challengeIdFor(lbegin), await signAssertion(invitee, challengeFor(lbegin), { signCount: 1 }));
    ok("the invited person can log in", lfin.json.ok === true && lfin.json.email === invitedEmail);
    const who = await whoamiRole(stub, invitedEmail);
    ok("the invited person holds the granted role (operator)", who.role === "operator");

    // The bound email comes from the INVITE, not the client field: a fresh invite for a DIFFERENT email,
    // presented while the client names yet another email, binds to the INVITE'S email.
    const owner2Invite = await grantRoleViaToken(env, "realtarget@example.com", "viewer");
    const auth2 = await makeAuthenticator("ES256");
    const begin2 = await registerBegin(env, "attacker-claimed@example.com", { inviteToken: owner2Invite });
    ok("invite begin ignores the client email and uses the invite email", begin2.json.ok === true && optionsFor(begin2).user.name === "realtarget@example.com");
    const fin2 = await registerFinish(env, "attacker-claimed@example.com", await buildAttestation(auth2, challengeFor(begin2)), { inviteToken: owner2Invite });
    ok("invite finish binds the INVITE email, not the client-claimed email", fin2.json.ok === true && fin2.json.email === "realtarget@example.com");
  }

  // 21b. ALREADY-ENROLLED INVITE REDEMPTION: an admin invites someone who is already enrolled (stood up by
  // another route, or re-invited). The invitee completes the whole WebAuthn gesture and must be answered with
  // a distinct, recorded signal (invite-redeem-refused-already-enrolled) rather than a coarse "forbidden",
  // because the remedy differs: they do not need an invite at all, they should just sign in. Driven through
  // POST /admin/auth/register/begin + /finish, the routes the invite link actually drives.
  {
    const { env, storage } = makeScheduler();
    const owner = await makeAuthenticator("ES256");
    await enrolBootstrapOwner(env, owner, "owner@example.com");
    const dup = "already-enrolled@example.com";
    // The Owner invites them (they hold no credential yet, so an invite IS minted)...
    const invite = await grantRoleViaToken(env, dup, "operator");
    // ...and meanwhile that address is enrolled by the OTHER authorised route (the break-glass token standing
    // up a new identity), so by the time the link is clicked the address already holds a passkey.
    const first = await makeAuthenticator("ES256");
    const b0 = await registerBegin(env, dup, bootstrapOpts());
    const f0 = await registerFinish(env, dup, await buildAttestation(first, challengeFor(b0)), bootstrapOpts());
    ok("already-enrolled: the address is enrolled by the token self-add route", f0.json.ok === true);

    // Now the invite link is clicked. begin still authorises (the invite is live); FINISH refuses at the
    // write point, against the live store.
    const second = await makeAuthenticator("ES256");
    const b1 = await registerBegin(env, dup, { inviteToken: invite });
    ok("already-enrolled: invite register/begin is still authorised (behaviour unchanged)", b1.json.ok === true);
    const f1 = await registerFinish(env, dup, await buildAttestation(second, challengeFor(b1)), { inviteToken: invite });
    ok("already-enrolled: invite register/finish is still refused (behaviour unchanged)", f1.json.ok !== true);

    const sig = (await storage.get<Record<string, { count: number }>>("authsignals:agg")) ?? {};
    ok("already-enrolled: the refusal is recorded as its own class (not a coarse forbidden)", (sig["invite-redeem-refused-already-enrolled"]?.count ?? 0) >= 1);
    // NOISE GUARD: the recorder is scoped to the INVITE path. The two legitimate enrolments above (the
    // bootstrap owner, and the token self-add) also passed through the same existing-credentials guard and
    // must not have fired it, and no address may ride in the record.
    ok("already-enrolled: the recorder did not fire on the legitimate bootstrap / self-add enrolments", (sig["invite-redeem-refused-already-enrolled"]?.count ?? 0) === 1);
    ok("already-enrolled: the record carries no address", !JSON.stringify(sig).includes(dup));
  }

  // 22. A CONSUMED / EXPIRED / WRONG invite is rejected.
  {
    const { env } = makeScheduler();
    const owner = await makeAuthenticator("ES256");
    await enrolBootstrapOwner(env, owner, "owner@example.com");
    const invitedEmail = "once@example.com";
    const invite = await grantRoleViaToken(env, invitedEmail, "viewer");
    const invitee = await makeAuthenticator("ES256");
    // First use succeeds.
    const fin1 = await registerFinish(env, invitedEmail, await buildAttestation(invitee, challengeFor(await registerBegin(env, invitedEmail, { inviteToken: invite }))), { inviteToken: invite });
    ok("first use of an invite succeeds", fin1.json.ok === true);
    // Second use of the SAME (now consumed) invite is rejected.
    const invitee2 = await makeAuthenticator("ES256");
    const begin2 = await registerBegin(env, invitedEmail, { inviteToken: invite });
    ok("a CONSUMED invite is rejected at begin (forbidden)", begin2.json.ok === false && begin2.json.reason === "forbidden");
    const fin2 = await registerFinish(env, "newemail@example.com", await buildAttestation(invitee2, b64urlEncode(crypto.getRandomValues(new Uint8Array(32)))), { inviteToken: invite });
    ok("a CONSUMED invite is rejected at finish (forbidden)", fin2.json.ok === false && fin2.json.reason === "forbidden");
    // A garbage / unknown invite token is rejected.
    const finBad = await registerBegin(env, "ghost@example.com", { inviteToken: "not-a-real-invite-token" });
    ok("an unknown invite token is rejected (forbidden)", finBad.json.ok === false && finBad.json.reason === "forbidden");
  }

  // 23. SELF-ADD: an already-authenticated caller may add a SECOND credential to THEIR OWN email, but NOT
  // to anyone else's. We drive self-add via the passkey SESSION cookie the bootstrap login minted.
  {
    const { env } = makeScheduler();
    const owner = await makeAuthenticator("ES256");
    const ownerEmail = "owner@example.com";
    const finBoot = await enrolBootstrapOwner(env, owner, ownerEmail);
    const session = extractSessionCookie(finBoot.setCookie);
    ok("the bootstrap finish minted a session cookie for self-add", session !== null);

    // Self-add a SECOND credential to the OWNER'S OWN email, authenticated by the owner's session cookie.
    const second = await makeAuthenticator("ES256");
    const begin = await registerBegin(env, ownerEmail, { cookie: session!, origin: ORIGIN });
    ok("self-add register/begin for the caller's own email is authorised", begin.json.ok === true);
    const fin = await registerFinish(env, ownerEmail, await buildAttestation(second, challengeFor(begin)), { cookie: session!, origin: ORIGIN });
    ok("self-add register/finish adds a SECOND credential to the owner's own email", fin.json.ok === true && fin.json.email === ownerEmail && fin.json.bootstrapped === false);
    // The owner now has two credentials and can log in with the second.
    const lbegin = await loginBegin(env, ownerEmail);
    const lfin = await loginFinish(env, challengeIdFor(lbegin), await signAssertion(second, challengeFor(lbegin), { signCount: 1 }));
    ok("the owner can log in with the self-added second credential", lfin.json.ok === true && lfin.json.email === ownerEmail);

    // Self-add to ANOTHER email (not the session's email) is refused: the owner session cannot add a
    // credential to victim@example.com.
    const victimCred = await makeAuthenticator("ES256");
    const beginV = await registerBegin(env, "victim@example.com", { cookie: session!, origin: ORIGIN });
    ok("self-add to a DIFFERENT email than the session is refused (forbidden)", beginV.json.ok === false && beginV.json.reason === "forbidden");
    const finV = await registerFinish(env, "victim@example.com", await buildAttestation(victimCred, b64urlEncode(crypto.getRandomValues(new Uint8Array(32)))), { cookie: session!, origin: ORIGIN });
    ok("self-add finish to a DIFFERENT email is refused (forbidden)", finV.json.ok === false && finV.json.reason === "forbidden");
  }

  // 24. USER VERIFICATION REQUIRED: a registration OR an assertion whose UV flag is clear is rejected (the
  // admin front door requires user verification, not mere presence).
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "uv@example.com";
    // Registration with UV clear is rejected (bootstrap-authorised so the UV check, not the gate, fires).
    const begin = await registerBegin(env, email, bootstrapOpts());
    const fin = await registerFinish(env, email, await buildAttestation(auth, challengeFor(begin), { uv: false }), bootstrapOpts());
    ok("register with the user-verified flag clear is rejected (reason user_verified)", fin.json.ok === false && fin.json.reason === "user_verified");
    // Register cleanly (UV set), then a login with UV clear is rejected.
    await enrolBootstrapOwner(env, auth, email);
    const lbegin = await loginBegin(env, email);
    const lfin = await loginFinish(env, challengeIdFor(lbegin), await signAssertion(auth, challengeFor(lbegin), { uv: false }));
    ok("login with the user-verified flag clear is rejected (reason user_verified)", lfin.json.ok === false && lfin.json.reason === "user_verified");
  }

  // 25. AN ASSERTION CARRYING ATTESTED CREDENTIAL DATA (AT flag set) is rejected (an assertion must carry
  // no attested credential data; a set AT is a malformed/hostile structure).
  {
    const { env } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "at@example.com";
    await enrolBootstrapOwner(env, auth, email);
    const lbegin = await loginBegin(env, email);
    const lfin = await loginFinish(env, challengeIdFor(lbegin), await signAssertion(auth, challengeFor(lbegin), { forceAt: true }));
    ok("an assertion with the AT (attested-credential-data) flag set is rejected (reason bad_request)", lfin.json.ok === false && lfin.json.reason === "bad_request");
  }

  // 26. THE PER-IP RATE LIMIT triggers on the unauthenticated /admin/auth/* endpoints. We fire more
  // login/begin calls from ONE source IP than the per-IP window cap (30) and confirm a 429 with a
  // Retry-After appears; a different IP is unaffected (per-IP isolation), and the limiter FAILS OPEN when
  // the IP header is absent.
  {
    const { env } = makeScheduler();
    let saw429 = false;
    let coarseBodySeen = false;
    let retryAfterHeaderSeen = false;
    for (let i = 0; i < 40; i++) {
      const r = await post(env, "/admin/auth/login/begin", {}, { ip: "198.51.100.42" });
      if (r.status === 429) {
        saw429 = true;
        // The body is the coarse { error: "rate limited" } and the response carries a Retry-After header
        // telling the client how long to wait. post() now exposes both so we verify the full contract.
        coarseBodySeen = r.json && r.json.error === "rate limited";
        retryAfterHeaderSeen = r.retryAfter !== null;
        break;
      }
    }
    ok("the per-IP auth limiter returns 429 once the window cap is exceeded", saw429);
    ok("the 429 carries the coarse rate-limited body", coarseBodySeen);
    ok("the 429 carries a Retry-After header", retryAfterHeaderSeen);
    // A DIFFERENT IP is in its own bucket and is not limited by the first IP's flood.
    const other = await post(env, "/admin/auth/login/begin", {}, { ip: "198.51.100.99" });
    ok("a different source IP is not limited by the first IP's flood", other.status === 200 && other.json.ok === true);
    // No IP header -> fail open (admitted), so a missing edge header never locks sign-in out.
    const noIp = await post(env, "/admin/auth/login/begin", {}, { ip: null });
    ok("a request with no source IP fails open (admitted)", noIp.status === 200 && noIp.json.ok === true);
  }

  // 27. LOGOUT is subject to the strict-Origin CSRF check: a cross-origin logout is refused 403, closing
  // the cross-origin forced-logout vector. A same-origin logout still clears the cookie.
  {
    const { env } = makeScheduler();
    const crossOrigin = await post(env, "/admin/auth/logout", {}, { origin: "https://evil.example" });
    ok("a cross-origin logout is refused (403)", crossOrigin.status === 403);
    const sameOrigin = await post(env, "/admin/auth/logout", {}, { origin: ORIGIN });
    ok("a same-origin logout succeeds and clears the cookie", sameOrigin.status === 200 && sameOrigin.json.ok === true && extractSessionCookie(sameOrigin.setCookie) !== null);
    // A logout with NO Origin header is also refused (fail closed on the CSRF check).
    const noOrigin = await post(env, "/admin/auth/logout", {});
    ok("a logout with no Origin header is refused (403, fail closed)", noOrigin.status === 403);
  }

  // 28. EMAIL-LINK BOOTSTRAP (the no-token first run): on an EMPTY engine with BOOTSTRAP_OWNER_EMAIL
  // pinned and the EMAIL binding bound, POST /admin/auth/bootstrap/send emails the PINNED address a
  // /#/register?invite=<token> link whose token authorises the FIRST-OWNER registration, bound to the
  // pinned email (never the client field). The route is a strict NO ORACLE: every outcome answers the
  // same generic 200; only the captured sends differ. The slot is single-active (a re-send replaces the
  // previous link), single-use (consumed on a verified finish), and closed for good once the latch sets.
  {
    const sends: Array<{ to: string | string[]; from: string; subject: string; text?: string }> = [];
    const emailStub = { send: async (m: { to: string | string[]; from: string; subject: string; text?: string }): Promise<void> => { sends.push(m); } };
    const base = makeScheduler();
    const env = { ...base.env, BOOTSTRAP_OWNER_EMAIL: "owner@customer.example", EMAIL_FROM: "no-reply@engine.example", EMAIL: emailStub } as unknown as Env;

    // a. The send: a generic 200 and exactly one email, to the PINNED address, carrying a fragment link.
    const r1 = await post(env, "/admin/auth/bootstrap/send", {}, { origin: ORIGIN });
    ok("bootstrap/send answers the generic 200", r1.status === 200 && r1.json.ok === true);
    ok("exactly one email went to the pinned owner address", sends.length === 1 && sends[0]!.to === "owner@customer.example");
    const link1 = /#\/register\?invite=([A-Za-z0-9_~.%-]+)/.exec(sends[0]!.text ?? "");
    ok("the email carries the fragment register link", link1 !== null);
    const token1 = decodeURIComponent(link1![1]!);

    // b. The client email field cannot steer the binding: a begin naming a DIFFERENT email but presenting
    // the link token binds the creation options to the PINNED address (the account-takeover discipline).
    const auth = await makeAuthenticator("ES256");
    const begin1 = await registerBegin(env, "attacker@evil.example", { inviteToken: token1, origin: ORIGIN });
    ok("link-token register/begin is authorised on the empty table", begin1.status === 200 && begin1.json.ok === true);
    ok("the options bind the PINNED owner email, not the client field", optionsFor(begin1).user.name === "owner@customer.example");

    // c. A RE-SEND replaces the single slot: the old token dies, the new one is the live capability.
    const r2 = await post(env, "/admin/auth/bootstrap/send", {}, { origin: ORIGIN });
    ok("a re-send answers the generic 200 and mails again", r2.status === 200 && r2.json.ok === true && sends.length === 2);
    const token2 = decodeURIComponent(/#\/register\?invite=([A-Za-z0-9_~.%-]+)/.exec(sends[1]!.text ?? "")![1]!);
    const oldBegin = await registerBegin(env, "owner@customer.example", { inviteToken: token1, origin: ORIGIN });
    ok("the replaced (old) link token is refused", oldBegin.json.ok === false && oldBegin.json.reason === "forbidden");

    // d. The full ceremony over the live link: finish bootstraps the pinned email to OWNER.
    const begin2 = await registerBegin(env, "owner@customer.example", { inviteToken: token2, origin: ORIGIN });
    const fin = await registerFinish(env, "owner@customer.example", await buildAttestation(auth, challengeFor(begin2)), { inviteToken: token2, origin: ORIGIN });
    ok("link finish verifies and bootstraps the FIRST Owner", fin.json.ok === true && fin.json.bootstrapped === true && fin.json.role === "owner" && fin.json.email === "owner@customer.example");
    const who = await whoamiRole(base.stub, "owner@customer.example");
    ok("the link registrant holds the Owner role", who.role === "owner" && who.isOnlyOwner === true);

    // e. Spent: the slot was consumed and the latch is set, so the redeemed link cannot begin again.
    const replay = await registerBegin(env, "owner@customer.example", { inviteToken: token2, origin: ORIGIN });
    ok("the redeemed link token is refused (consumed + latched)", replay.json.ok === false && replay.json.reason === "forbidden");

    // f. NO ORACLE after bootstrap: the send still answers the same generic 200 and mails NOTHING.
    const r3 = await post(env, "/admin/auth/bootstrap/send", {}, { origin: ORIGIN });
    ok("a post-bootstrap send is the same generic 200", r3.status === 200 && r3.json.ok === true);
    ok("a post-bootstrap send mails nothing", sends.length === 2);
  }

  // 28b. The send stays the SAME generic 200 when unconfigured or cross-origin (and mails nothing), and
  // an EXPIRED slot does not authorise a registration.
  {
    const sends: Array<{ to: string | string[] }> = [];
    const emailStub = { send: async (m: { to: string | string[] }): Promise<void> => { sends.push(m); } };
    const a = makeScheduler();
    // No pinned owner email: generic 200, nothing mailed.
    const envNoOwner = { ...a.env, EMAIL_FROM: "no-reply@engine.example", EMAIL: emailStub } as unknown as Env;
    const r1 = await post(envNoOwner, "/admin/auth/bootstrap/send", {}, { origin: ORIGIN });
    ok("send with no pinned owner: generic 200, no email", r1.status === 200 && r1.json.ok === true && sends.length === 0);
    // No EMAIL binding: generic 200.
    const envNoBinding = { ...a.env, BOOTSTRAP_OWNER_EMAIL: "owner@customer.example", EMAIL_FROM: "no-reply@engine.example" } as unknown as Env;
    const r2 = await post(envNoBinding, "/admin/auth/bootstrap/send", {}, { origin: ORIGIN });
    ok("send with no EMAIL binding: generic 200", r2.status === 200 && r2.json.ok === true);
    // A cross-origin browser call (CSRF shaping): generic 200, nothing mailed.
    const envFull = { ...a.env, BOOTSTRAP_OWNER_EMAIL: "owner@customer.example", EMAIL_FROM: "no-reply@engine.example", EMAIL: emailStub } as unknown as Env;
    const r3 = await post(envFull, "/admin/auth/bootstrap/send", {}, { origin: "https://evil.example" });
    ok("a cross-origin send: generic 200, no email", r3.status === 200 && r3.json.ok === true && sends.length === 0);
    // An EXPIRED slot does not authorise: hand-write an expired record straight into the DO storage.
    await a.storage.put("bootstrapInvite", { token: "expired-token", email: "owner@customer.example", createdAt: 0, expiresAt: 1 });
    const beginExpired = await registerBegin(envFull, "owner@customer.example", { inviteToken: "expired-token", origin: ORIGIN });
    ok("an expired bootstrap link is refused", beginExpired.json.ok === false && beginExpired.json.reason === "forbidden");
  }
}
