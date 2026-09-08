// validate-passkey group: THE USABILITY WITNESS.
// `passkeyOwnerEnrolled` counts credential RECORDS, and a record is inert to the destruction of the
// authenticator holding the private half, so orphaned credential records can keep answering "a second
// factor is present" long after the physical authenticator is gone. The witness is the
// only fact on the record that cannot be faked by a dead key: `lastAssertedAt` is written ONLY after
// verifyAssertion has returned, i.e. only after a signature over server-chosen challenge bytes verified under
// the stored public key. This file proves the witness in BOTH directions and, critically, proves the one
// property that separates it from another signCount-shaped inference: it is stamped even when the
// authenticator's counter does not move.
//
// Run via the validate-passkey.ts orchestrator.
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { encodeCaller, passkeySubject } from "../src/admin/identity.ts";
import { handleAdmin } from "../src/admin/router.ts";
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
  challengeFor,
  challengeIdFor,
} from "./validate-passkey-harness.ts";

type StoredCred = { signCount: number; createdAt: string; lastAssertedAt?: string; lastAssertedVia?: string };
type Preflight = {
  passkeyOwnerEnrolled: boolean;
  passkeyOwnerEvidence: string;
  passkeyWitnessSince: string | null;
};

export async function run(): Promise<void> {
  // 1. THE ZERO-COUNTER CASE, which is the whole reason this is a separate fact and not a line inside the
  // existing signCount write. Both assertion sites used to persist only when
  // `result.newSignCount !== record.signCount`. Platform passkeys routinely leave the counter at zero for
  // ever (admin/passkey.ts carves the zero-to-zero case out of clone detection precisely because it is the
  // common healthy state), so a witness stamped inside that condition would have been blind to exactly the
  // authenticators signCount is blind to: a proof in name, an inference in fact. Here the stored counter is
  // 0, the asserted counter is 0, the put that the old code would have skipped is the ONLY thing that can
  // record the proof, and the stamp must appear anyway.
  {
    const { env, storage } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "zero-counter@example.com";
    const begin = await registerBegin(env, email, bootstrapOpts());
    const fin = await registerFinish(env, email, await buildAttestation(auth, challengeFor(begin)), bootstrapOpts());
    ok("witness: precondition - the zero-counter authenticator enrolled", fin.status === 200 && fin.json.ok === true);

    const credKey = `passkeyCred:${b64urlEncode(auth.credentialId)}`;
    const enrolled = await storage.get<StoredCred>(credKey);
    ok("witness: enrolment stores signCount 0", enrolled?.signCount === 0);
    // Registration IS a proof of possession, and it is deliberately NOT stamped. The failure this witness
    // exists for is a credential that was provably real when it was enrolled and is dead now, so a stamp at
    // enrolment would make every orphaned key look demonstrated - the defect again, one field along.
    ok("witness: enrolment does NOT stamp lastAssertedAt", enrolled?.lastAssertedAt === undefined);

    const lbegin = await loginBegin(env, email);
    const lfin = await loginFinish(env, challengeIdFor(lbegin), await signAssertion(auth, challengeFor(lbegin), { signCount: 0 }));
    ok("witness: a zero-to-zero assertion still VERIFIES (the clone-detection carve-out)", lfin.status === 200 && lfin.json.ok === true);

    const afterLogin = await storage.get<StoredCred>(credKey);
    ok("witness: the counter did not move, so the OLD conditional write would have written nothing", afterLogin?.signCount === 0);
    ok("witness: the stamp is written anyway (the write is unconditional on success)", typeof afterLogin?.lastAssertedAt === "string" && afterLogin.lastAssertedAt.length > 0);
    ok("witness: the stamp names the ceremony that produced the proof", afterLogin?.lastAssertedVia === "login");
  }

  // 2. THE NEGATIVE DIRECTION. A stamp that appears on a failed assertion would be worse than no stamp: it
  // would attest possession to an attacker who has none. A tampered signature is refused, and nothing is
  // recorded.
  {
    const { env, storage } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "tampered@example.com";
    const begin = await registerBegin(env, email, bootstrapOpts());
    await registerFinish(env, email, await buildAttestation(auth, challengeFor(begin)), bootstrapOpts());
    const credKey = `passkeyCred:${b64urlEncode(auth.credentialId)}`;

    const lbegin = await loginBegin(env, email);
    const bad = await loginFinish(env, challengeIdFor(lbegin), await signAssertion(auth, challengeFor(lbegin), { signCount: 3, tamper: true }));
    ok("witness: a TAMPERED assertion is refused", bad.json.ok !== true);
    const afterBad = await storage.get<StoredCred>(credKey);
    ok("witness: a refused assertion stamps NOTHING", afterBad?.lastAssertedAt === undefined);
    ok("witness: a refused assertion does not move the counter either", afterBad?.signCount === 0);
  }

  // 3. THE EPOCH, which is what makes an ABSENT stamp readable. Without it, "never demonstrated" and
  // "enrolled before anything was recorded" are the same absence, and any verdict built on that absence
  // would condemn every credential in the fleet on the day the witness shipped. lockoutPreflight therefore
  // reports a four-way enum, and `unknown` is a first-class answer rather than a boolean rounded toward
  // reassurance.
  {
    const { env, stub, storage } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "evidence@example.com";

    const preflight = async (): Promise<Preflight> => {
      const r = await stub.fetch("https://do/policy/lockout-preflight", { method: "GET" });
      return (await r.json()) as Preflight;
    };

    const before = await preflight();
    ok("evidence: with no Owner credential at all the answer is no-credential", before.passkeyOwnerEnrolled === false && before.passkeyOwnerEvidence === "no-credential");

    const begin = await registerBegin(env, email, bootstrapOpts());
    await registerFinish(env, email, await buildAttestation(auth, challengeFor(begin)), bootstrapOpts());
    const witnessSince = await storage.get<string>("passkeyWitnessSince");
    ok("evidence: enrolment opens the witness epoch", typeof witnessSince === "string" && witnessSince.length > 0);

    const enrolledOnly = await preflight();
    // The credential was enrolled AFTER the epoch opened and has never asserted, so this absence is a real
    // fact and the enum says so precisely. It is still NOT a defect: a break-glass passkey kept in reserve
    // reads exactly like this and is perfectly good, which is why nothing gates on it.
    ok("evidence: a post-witness credential with no stamp reads never-asserted", enrolledOnly.passkeyOwnerEnrolled === true && enrolledOnly.passkeyOwnerEvidence === "never-asserted");
    ok("evidence: the epoch is reported so the caller can date the record-keeping", enrolledOnly.passkeyWitnessSince === witnessSince);

    const lbegin = await loginBegin(env, email);
    const lfin = await loginFinish(env, challengeIdFor(lbegin), await signAssertion(auth, challengeFor(lbegin), { signCount: 7 }));
    ok("evidence: precondition - the Owner asserts successfully", lfin.json.ok === true);
    const demonstrated = await preflight();
    ok("evidence: a verified assertion moves the Owner to demonstrated", demonstrated.passkeyOwnerEvidence === "demonstrated");

    // Now the ambiguous population, which is every account alive on the day this ships: a credential whose
    // createdAt PREDATES the epoch. Rewind this credential's birth date behind the epoch and strip its
    // stamp, exactly as a record enrolled by the previous code would look.
    const credKey = `passkeyCred:${b64urlEncode(auth.credentialId)}`;
    const cred = await storage.get<StoredCred & Record<string, unknown>>(credKey);
    const rewound = { ...cred!, createdAt: new Date(Date.parse(witnessSince!) - 86_400_000).toISOString() };
    delete rewound.lastAssertedAt;
    delete rewound.lastAssertedVia;
    await storage.put(credKey, rewound);
    const legacy = await preflight();
    ok("evidence: a credential older than the witness reads unknown, never never-asserted", legacy.passkeyOwnerEvidence === "unknown");
    ok("evidence: unknown does NOT disturb the unchanged passkeyOwnerEnrolled count", legacy.passkeyOwnerEnrolled === true);
  }

  // 4. THE ORPHAN IS VISIBLE AT ALL. deleteRole never touches `passkeyCred:` records, so a removed member's
  // credentials outlive their role, and until now no read could see it: the per-email route falls back to the
  // CALLER's own email, so establishing that an account is clean meant already knowing which emails to ask
  // about, which is exactly what you do not know when the residue is a credential whose member is gone. This
  // drives the account-wide enumeration across the seam: one credential whose email still has a role row, one
  // whose row has been deleted.
  {
    const { env, stub, storage } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "owner@example.com";
    const begin = await registerBegin(env, email, bootstrapOpts());
    await registerFinish(env, email, await buildAttestation(auth, challengeFor(begin)), bootstrapOpts());

    const all = async (): Promise<{ credentials: { email: string; hasRoleEntry: boolean }[] }> => {
      const r = await stub.fetch("https://do/passkey/credentials/all", {
        method: "GET",
        headers: { "x-downpipe-caller": encodeCaller({ method: "token", email, subject: passkeySubject(email), role: "owner", groups: [] }) },
      });
      return (await r.json()) as { credentials: { email: string; hasRoleEntry: boolean }[] };
    };

    const before = await all();
    ok("orphans: the account-wide read sees the enrolled credential", before.credentials.length === 1 && before.credentials[0]!.email === email);
    ok("orphans: a credential whose email holds a role reads hasRoleEntry true", before.credentials[0]!.hasRoleEntry === true);

    // Delete the role row the way deleteRole does, leaving the credential behind. This is the residue
    // that can accumulate in a real fleet over time.
    for (const k of (await storage.list({ prefix: "role:" })).keys()) await storage.delete(k);
    const after = await all();
    ok("orphans: the credential SURVIVES the role deletion (the residue is real, not hypothetical)", after.credentials.length === 1);
    ok("orphans: and it is now visible as having no role entry", after.credentials[0]!.hasRoleEntry === false);
  }

  // 4a. WHAT ACTUALLY HAPPENS TO A REMOVED COLLEAGUE. Section 4 proves the credential survives the role
  // delete; this proves the survival is not inert, which is the difference between untidy state and a
  // security fact a customer has to be told.
  //
  // The tempting reading of an orphan is that a credential without a role grants nothing, so it can be left
  // alone. Drive it and that is false at BOTH ends. passkeyLoginFinish looks the credential up and verifies
  // the assertion against the stored key; it consults NO roster at all, and returns the credential's own
  // email on success. sessionCookieForFinish then mints a session on that proven email, also without a
  // roster check. And resolveRole floors a caller matched by neither an email grant nor a group at
  // `viewer` / `default` rather than refusing them, so the far end of the chain is not "no access" either.
  //
  // So removing a colleague's role row leaves them able to complete a real WebAuthn ceremony, receive a real
  // session cookie, and read the account as a viewer. That is what is asserted here, end to end, because it
  // is the claim a customer would dispute and it should be provable rather than argued.
  {
    const { env, storage } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "leaver@example.com";
    const begin = await registerBegin(env, email, bootstrapOpts());
    await registerFinish(env, email, await buildAttestation(auth, challengeFor(begin)), bootstrapOpts());

    // Remove them exactly the way deleteRole does: the role row goes, the credential is never touched.
    for (const k of (await storage.list({ prefix: "role:" })).keys()) await storage.delete(k);
    ok("leaver: precondition - the role row is gone", (await storage.list({ prefix: "role:" })).size === 0);
    ok("leaver: precondition - the credential is NOT gone (deleteRole does not touch passkeyCred:)", (await storage.list({ prefix: "passkeyCred:" })).size === 1);

    const lbegin = await loginBegin(env, email);
    const lfin = await loginFinish(env, challengeIdFor(lbegin), await signAssertion(auth, challengeFor(lbegin), { signCount: 1 }));
    ok("leaver: the removed member STILL completes the WebAuthn ceremony (login checks the credential, not the roster)", lfin.status === 200 && lfin.json.ok === true);
    ok("leaver: and is STILL issued a session cookie, so the role delete did not remove the ability to sign in", typeof lfin.setCookie === "string" && lfin.setCookie.length > 0);

    // And what they are once inside. Not refused, not nothing: a viewer, by the least-privilege floor.
    const cookie = (lfin.setCookie ?? "").split(";")[0] ?? "";
    const who = await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET", headers: { cookie } }), env);
    const whoBody = (await who.json()) as { email: string | null; role: string; roleSource: string };
    ok("leaver: the session is ACCEPTED by the admin router (200, not a 401)", who.status === 200);
    ok("leaver: and it is their own proven identity, not an anonymous one", whoBody.email === email);
    ok("leaver: the removed member reads the account as a VIEWER, sourced from the least-privilege default", whoBody.role === "viewer" && whoBody.roleSource === "default");
  }

  // 4a-bis. THE SAME CLASS, ONE STORE ALONG: RECOVERY CODES. The account-wide credential route closes the
  // passkey half of this. It does not close the class, and the class is what matters, so this pins the next
  // instance with a drive rather than leaving it as an assertion in a report.
  //
  // `recovery:<email>` is a per-email record of a member's unconsumed recovery codes. deleteRole removes the
  // subject-keyed role entry and any pending invites, and bumps the two session-revocation axes. It does not
  // touch `recovery:`. And recoveryRecover gates on no roster either: it verifies the code, mints a normal
  // session under the session key, resolves a member with no grant to viewer, and returns enrolPasskey:true.
  //
  // So a recovery code is the same residue with a worse shape than the passkey it sits beside. A passkey
  // needs the physical authenticator; a recovery code is a bearer secret that a departed person may have in
  // a password manager or on paper. And the only read is GET /recovery/remaining?email=, which is per-email
  // exactly like the credential route was, so nothing enumerates which emails still hold codes.
  {
    const { env, stub, storage } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "codeholder@example.com";
    const begin = await registerBegin(env, email, bootstrapOpts());
    await registerFinish(env, email, await buildAttestation(auth, challengeFor(begin)), bootstrapOpts());

    const remaining = async (): Promise<number> => {
      const r = await stub.fetch(`https://do/recovery/remaining?email=${encodeURIComponent(email)}`, { method: "GET" });
      return ((await r.json()) as { remaining: number }).remaining;
    };
    ok("recovery-residue: precondition - registration minted recovery codes", (await remaining()) > 0);

    // Remove them the way deleteRole does. Its body deletes the subject-keyed role entry and the pending
    // invite keys and bumps the epochs; `recovery:` appears nowhere in it.
    for (const k of (await storage.list({ prefix: "role:" })).keys()) await storage.delete(k);
    ok("recovery-residue: the RECOVERY CODES survive the role removal, unconsumed and usable", (await remaining()) > 0);
    ok("recovery-residue: the record is still on the estate under its per-email key", (await storage.list({ prefix: "recovery:" })).size === 1);

    // And nothing can find it without already knowing the email. This is the passkey defect verbatim, one
    // store along: the account-wide route enumerates credentials, so an email holding ONLY recovery codes
    // and no credential does not appear on it at all.
    for (const k of (await storage.list({ prefix: "passkeyCred:" })).keys()) await storage.delete(k);
    const allR = await stub.fetch("https://do/passkey/credentials/all", {
      method: "GET",
      headers: { "x-downpipe-caller": encodeCaller({ method: "token", email: null, subject: null, role: "owner", groups: [] }) },
    });
    const allBody = (await allR.json()) as { credentials: unknown[] };
    ok("recovery-residue: the account-wide CREDENTIAL read shows clean while a live recovery-code record remains", allR.status === 200 && allBody.credentials.length === 0 && (await remaining()) > 0);
  }

  // 4b. THE FALSE EMPTY, AND THE THREE STATES THAT MUST NOT COLLAPSE INTO TWO. Section 4 gives an operator a
  // read that CAN see the residue; this is the read that used to say there was none. The per-email route
  // resolved its target as `?email=` else the CALLER's own email, and answered a null target with an empty
  // list, so a caller with no email of its own got `200 {"credentials":[]}` on every account. That is
  // byte-identical to a clean account, and a bearer token is exactly that caller (whoami answers email:null
  // for one), so an ADMIN_TOKEN sweep read every estate as clean, including estates holding dozens.
  //
  // The property is three-way, not two-way, and asserting only "the orphan shows up" would miss it. There
  // must be a distinguishable answer for "there is something here", for "there is nothing here", and for
  // "I could not look" - and the third must not be served as the second. So all three are driven, on the
  // same DO, in the same shape a client sees.
  {
    const { env, stub, storage } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "holder@example.com";
    const begin = await registerBegin(env, email, bootstrapOpts());
    await registerFinish(env, email, await buildAttestation(auth, challengeFor(begin)), bootstrapOpts());

    const list = async (caller: string | null, query: string): Promise<{ status: number; body: { credentials?: unknown[]; error?: string } }> => {
      const r = await stub.fetch(`https://do/passkey/credentials${query}`, {
        method: "GET",
        headers: caller === null ? {} : { "x-downpipe-caller": caller },
      });
      return { status: r.status, body: (await r.json()) as { credentials?: unknown[]; error?: string } };
    };
    const withEmail = encodeCaller({ method: "token", email, subject: passkeySubject(email), role: "owner", groups: [] });
    // The bearer: authenticated, fully authorised, and carrying NO email. This is the ADMIN_TOKEN caller.
    const bearerNoEmail = encodeCaller({ method: "token", email: null, subject: null, role: "owner", groups: [] });

    // State 1: there IS something here.
    const present = await list(withEmail, "");
    ok("false-empty: a caller WITH an email reads its own credential (200, one row)", present.status === 200 && present.body.credentials?.length === 1);

    // State 3: I COULD NOT LOOK. The account is identical to the one above and demonstrably NOT clean, so if
    // this answered 200-empty it would be answering a question it never asked. It must refuse instead, and it
    // must refuse with a status no client can read as an empty list.
    const blind = await list(bearerNoEmail, "");
    ok("false-empty: an emailless bearer is REFUSED rather than told the account is clean", blind.status === 400);
    ok("false-empty: and the refusal carries no credentials array to be mistaken for an empty one", blind.body.credentials === undefined && typeof blind.body.error === "string");
    // The whole defect in one assertion: the blind answer and the clean answer must not be the same bytes.
    ok("false-empty: 'I could not look' is DISTINGUISHABLE from 'there is nothing here'", blind.status !== 200);

    // State 2: there is NOTHING here. A real, resolvable member who has enrolled nothing. This is the answer
    // the blind case used to impersonate, and it must still be available, or the fix would have destroyed the
    // ability to establish a clean account rather than restored it.
    const clean = await list(withEmail, "?email=nobody%40example.com");
    ok("false-empty: a resolvable member with no credentials still reads a genuine empty list (200, zero rows)", clean.status === 200 && clean.body.credentials?.length === 0);

    // And the account-wide read answers the emailless caller properly, which is why the refusal above can
    // point at it: it needs no email, so the bearer that cannot use the per-email route is not left blind.
    const allR = await stub.fetch("https://do/passkey/credentials/all", { method: "GET", headers: { "x-downpipe-caller": bearerNoEmail } });
    const allBody = (await allR.json()) as { credentials: { email: string }[] };
    ok("false-empty: the emailless bearer CAN enumerate account-wide, so the refusal is a redirection, not a dead end", allR.status === 200 && allBody.credentials.length === 1 && allBody.credentials[0]!.email === email);

    // Both directions on the account-wide read itself: a genuinely clean account must read clean, or "clean"
    // would be unprovable and the route would only ever be trusted when it found something.
    for (const k of (await storage.list({ prefix: "passkeyCred:" })).keys()) await storage.delete(k);
    const allClean = await stub.fetch("https://do/passkey/credentials/all", { method: "GET", headers: { "x-downpipe-caller": bearerNoEmail } });
    const allCleanBody = (await allClean.json()) as { credentials: unknown[] };
    ok("false-empty: an account with no credentials at all reads a TRUE clean from the account-wide route", allClean.status === 200 && allCleanBody.credentials.length === 0);
  }

  // 5. THE WITNESS IS REPORTED, NOT CONSUMED. This is the deliberate scope line of the row: the evidence is
  // new, no fleet has produced any of it yet, and a never-asserted break-glass passkey is a HEALTHY state, so
  // gating on it now would tell correct accounts they are unsafe on the one screen whose value is that it is
  // believed. `passkeyOwnerEnrolled` therefore still counts records, and this asserts that it does - so that
  // a future pass tightening the verdict has to come through this test and state its case, rather than the
  // coupling appearing by accident.
  {
    const { env, stub } = makeScheduler();
    const auth = await makeAuthenticator("ES256");
    const email = "notgated@example.com";
    const begin = await registerBegin(env, email, bootstrapOpts());
    await registerFinish(env, email, await buildAttestation(auth, challengeFor(begin)), bootstrapOpts());
    const r = await stub.fetch("https://do/policy/lockout-preflight", { method: "GET" });
    const pf = (await r.json()) as Preflight;
    ok("not-gated: an Owner who has never asserted STILL reads passkeyOwnerEnrolled true", pf.passkeyOwnerEnrolled === true && pf.passkeyOwnerEvidence === "never-asserted");
  }
}
