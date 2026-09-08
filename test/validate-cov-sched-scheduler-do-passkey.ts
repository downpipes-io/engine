// validate-cov-sched-scheduler-do-passkey: a focused branch-coverage validator for the WebAuthn /
// passkey REGISTRATION sub-mixin src/sched/scheduler-do-passkey.ts (PasskeyMixin). It drives the real
// registration ceremonies through the production router (handleAdmin -> handlePasskey -> the SchedulerDO)
// and, for the internal helpers that have no HTTP route (the input-bounding + coarse-error helpers), calls
// them directly on a real SchedulerDO instance and asserts their real return / thrown outcome. Every
// assertion checks a genuine behaviour: an HTTP status, a coarse {ok:false,reason} verdict, a stored
// credential's filtered transports, the bound email an invite resolves to, or the bad_request / forbidden /
// challenge rejection a malformed or unauthorised request earns.
//
// It targets the branches the broad validate-passkey suite leaves uncovered on this file: the rp.id / origin
// / display-name bounding rejections, the four decodeB64urlField faults, the token self-add path, the
// excludeCredentials-with-transports map, the write-point re-check that refuses a non-self-add binding to an
// already-enrolled email, the challenge-absent register/finish, the begin internal-error catch (coarse
// bad_request, nothing leaked), the best-effort recovery-code mint (the enrolment still succeeds with an
// empty set when the mint throws), and the transport-hint filter loop. Control-character inputs are written
// as \u escape sequences so the source stays plain ASCII.
//
// Run: node test/validate-cov-sched-scheduler-do-passkey.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { PasskeyError } from "../src/admin/passkey.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { BOOTSTRAP_INVITE_KEY, PASSKEY_CRED_PREFIX, PASSKEY_INVITE_PREFIX } from "../src/sched/scheduler-do-base.ts";
import type { Env } from "../src/env.d.ts";
import {
  makeAuthenticator,
  buildAttestation,
  registerBegin,
  registerFinish,
  enrolBootstrapOwner,
  grantRoleViaToken,
  challengeFor,
  extractSessionCookie,
  post,
  bootstrapOpts,
  ORIGIN,
  RP_ID,
  ADMIN_TOKEN,
} from "./validate-passkey-harness.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The narrow view of the PasskeyMixin helpers we call directly (no HTTP route exists for them). They are
// real public methods on the assembled SchedulerDO; we assert their real return value / thrown PasskeyError.
interface PasskeyDO {
  passkeyRpId(raw: unknown): string | null;
  passkeyOrigin(raw: unknown): string | null;
  passkeyDisplayName(raw: unknown, fallback: string): string;
  decodeB64urlField(raw: unknown, name: string, maxBytes: number): Uint8Array;
  coarsePasskeyError(stage: string, e: unknown): { ok: false; reason: string; errorId: string };
  passkeyTransports(raw: unknown): string[];
  passkeyRegisterBegin(body: Record<string, unknown>): Promise<{ ok: boolean; reason?: string; publicKey?: unknown }>;
  passkeyRegisterFinish(body: Record<string, unknown>): Promise<{ ok: boolean; reason?: string }>;
}

// makeSchedulerWith builds a SchedulerDO over a caller-supplied storage (so a fault-injecting storage double
// can drive the internal-error catch branches) and the SCHEDULER namespace handleAdmin resolves to. The env
// carries CONSOLE_ORIGIN (the WebAuthn origin/rp.id source) and ADMIN_TOKEN (the bootstrap / token self-add
// secret), exactly like the shared passkey harness, so the router drives the same production code path.
function makeSchedulerWith(storage: MockStorage): { env: Env; storage: MockStorage; stub: DurableObjectStub; dobj: PasskeyDO } {
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
  const env = { SCHEDULER: namespace, CONSOLE_ORIGIN: ORIGIN, ADMIN_TOKEN } as unknown as Env;
  return { env, storage, stub, dobj: dobj as unknown as PasskeyDO };
}

// A storage double that fails the passkeyChallenge: put (an internal fault AFTER authorisation), to drive
// the register/begin catch -> coarse bad_request branch. Every other key behaves normally.
class ThrowOnChallengePut extends MockStorage {
  override async put<T>(key: string, value: T): Promise<void> {
    if (key.startsWith("passkeyChallenge:")) throw new Error("simulated storage failure (challenge put)");
    return super.put(key, value);
  }
}

// A storage double that fails ONLY the recovery: put (the last write a finish does, inside generateRecoveryFor),
// to drive the best-effort recovery-mint catch: the credential is already stored, so the enrolment still
// succeeds with an empty recovery-codes set.
class ThrowOnRecoveryPut extends MockStorage {
  override async put<T>(key: string, value: T): Promise<void> {
    if (key.startsWith("recovery:")) throw new Error("simulated storage failure (recovery put)");
    return super.put(key, value);
  }
}

type LoosePK = {
  challenge?: string;
  user?: { name?: string; displayName?: string };
  excludeCredentials?: Array<{ id?: string; type?: string; transports?: string[] }>;
};
const pkOf = (res: { json: { publicKey?: unknown } }): LoosePK => (res.json.publicKey ?? {}) as LoosePK;
const eq = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);

// throwsPasskey runs a sync helper and reports whether it threw a PasskeyError (optionally matching a needle
// in the message), the contract decodeB64urlField promises on a bad field.
function throwsPasskey(fn: () => unknown, needle?: string): boolean {
  try {
    fn();
    return false;
  } catch (e) {
    return e instanceof PasskeyError && (needle === undefined || e.message.includes(needle));
  }
}

async function main(): Promise<void> {
  // Silence the DO's coarse error/warn logs (log("error"/"warn") -> console.error/console.warn): several
  // branches here are intentional faults that log a precise reason, which would otherwise drown the ok lines.
  const origErr = console.error;
  const origWarn = console.warn;
  console.error = (): void => {};
  console.warn = (): void => {};
  try {
    // ---- A. BOOTSTRAP happy round trip: the first-Owner enrolment (empty table + ADMIN_TOKEN). Exercises
    // begin (challenge issue, empty excludeCredentials) and finish (resolve bootstrap, decode, consume,
    // verify, dedup, store, Owner mint, recovery-code mint). ----------------------------------------------
    {
      const s = makeSchedulerWith(new MockStorage());
      const auth = await makeAuthenticator("ES256");
      const fin = await enrolBootstrapOwner(s.env, auth, "alice@example.com");
      ok("A: bootstrap finish verifies and bootstraps the first Owner", fin.status === 200 && fin.json.ok === true && fin.json.bootstrapped === true && fin.json.role === "owner");
      ok("A: bootstrap finish mints exactly 10 recovery codes", Array.isArray(fin.json.recoveryCodes) && fin.json.recoveryCodes!.length === 10);
      ok("A: bootstrap stored one credential", s.storage.countPrefix(PASSKEY_CRED_PREFIX) === 1);
      ok("A: bootstrap consumed the registration challenge", s.storage.countPrefix("passkeyChallenge:") === 0);
      ok("A: bootstrap finish minted a session cookie", extractSessionCookie(fin.setCookie) !== null);
    }

    // ---- B. INVITE happy: an Owner-minted single-use invite binds the INVITE's email and lands the granted
    // role (NOT bootstrapped; the role resolves from the subject-keyed table). ------------------------------
    {
      const s = makeSchedulerWith(new MockStorage());
      const owner = await makeAuthenticator("ES256");
      await enrolBootstrapOwner(s.env, owner, "owner@example.com");
      const invite = await grantRoleViaToken(s.env, "invitee@example.com", "operator");
      const invitee = await makeAuthenticator("ES256");
      const begin = await registerBegin(s.env, "invitee@example.com", { inviteToken: invite });
      ok("B: invite begin is authorised and binds the invite email", begin.json.ok === true && pkOf(begin).user?.name === "invitee@example.com");
      const fin = await registerFinish(s.env, "invitee@example.com", await buildAttestation(invitee, challengeFor(begin)), { inviteToken: invite });
      ok("B: invite finish binds the invited email and is NOT bootstrapped", fin.json.ok === true && fin.json.email === "invitee@example.com" && fin.json.bootstrapped === false && fin.json.role === "operator");
    }

    // ---- C. SELF-ADD: an authenticated caller adds a SECOND credential to THEIR OWN email (allowExistingCreds
    // write path + existing-user upsert skip); adding to a DIFFERENT email than the session is forbidden. ----
    {
      const s = makeSchedulerWith(new MockStorage());
      const owner = await makeAuthenticator("ES256");
      const boot = await enrolBootstrapOwner(s.env, owner, "owner@example.com");
      const session = extractSessionCookie(boot.setCookie);
      ok("C: bootstrap login minted a session for self-add", session !== null);
      const second = await makeAuthenticator("ES256");
      const begin = await registerBegin(s.env, "owner@example.com", { cookie: session!, origin: ORIGIN });
      ok("C: self-add begin for the caller's own email is authorised", begin.json.ok === true);
      const fin = await registerFinish(s.env, "owner@example.com", await buildAttestation(second, challengeFor(begin)), { cookie: session!, origin: ORIGIN });
      ok("C: self-add adds a SECOND credential to the owner's own email", fin.json.ok === true && fin.json.email === "owner@example.com" && fin.json.bootstrapped === false);
      ok("C: the owner now has two credentials", s.storage.countPrefix(PASSKEY_CRED_PREFIX) === 2);
      // Self-add to ANOTHER email than the session's verified email is refused at the authorisation gate.
      const victim = await makeAuthenticator("ES256");
      const beginV = await registerBegin(s.env, "victim@example.com", { cookie: session!, origin: ORIGIN });
      ok("C: self-add begin to a DIFFERENT email is forbidden", beginV.json.ok === false && beginV.json.reason === "forbidden");
      void victim;
    }

    // ---- D. TAKEOVER: a bare unauthenticated register for an existing email (non-empty table, no proof) is
    // refused at begin and finish, the resolve-returns-null path. -------------------------------------------
    {
      const s = makeSchedulerWith(new MockStorage());
      const owner = await makeAuthenticator("ES256");
      await enrolBootstrapOwner(s.env, owner, "owner@example.com");
      const begin = await registerBegin(s.env, "owner@example.com");
      ok("D: takeover begin (no proof) is forbidden", begin.json.ok === false && begin.json.reason === "forbidden");
      const attacker = await makeAuthenticator("ES256");
      const fin = await registerFinish(s.env, "owner@example.com", await buildAttestation(attacker, b64urlEncode(crypto.getRandomValues(new Uint8Array(32)))));
      ok("D: takeover finish (no proof) is forbidden", fin.json.ok === false && fin.json.reason === "forbidden");
    }

    // ---- E. TOKEN SELF-ADD: a bare ADMIN_TOKEN bearer on a NON-empty table may stand up a NEW (credential-
    // free) email, but NEVER bind onto an email that already has a credential. -------------------------------
    {
      const s = makeSchedulerWith(new MockStorage());
      const owner = await makeAuthenticator("ES256");
      await enrolBootstrapOwner(s.env, owner, "owner@example.com");
      const beginNew = await registerBegin(s.env, "freshuser@example.com", { authorization: `Bearer ${ADMIN_TOKEN}`, origin: ORIGIN });
      ok("E: token self-add for a NEW credential-free email is authorised", beginNew.json.ok === true);
      const beginExisting = await registerBegin(s.env, "owner@example.com", { authorization: `Bearer ${ADMIN_TOKEN}`, origin: ORIGIN });
      ok("E: token self-add onto an ALREADY-enrolled email is forbidden", beginExisting.json.ok === false && beginExisting.json.reason === "forbidden");
    }

    // ---- F. SINGLE-USE BOOTSTRAP LATCH: after the first Owner, even a forcibly-emptied role table cannot
    // re-bootstrap (the bootstrapConsumed latch closes the path). -------------------------------------------
    {
      const s = makeSchedulerWith(new MockStorage());
      const owner = await makeAuthenticator("ES256");
      await enrolBootstrapOwner(s.env, owner, "owner@example.com");
      for (const k of (await s.storage.list({ prefix: "role:" })).keys()) await s.storage.delete(k);
      ok("F: precondition - the role table is empty again", (await s.storage.list({ prefix: "role:" })).size === 0);
      const reBegin = await registerBegin(s.env, "second-owner@example.com", bootstrapOpts());
      ok("F: a second bootstrap is refused after the latch sets (forbidden)", reBegin.json.ok === false && reBegin.json.reason === "forbidden");
    }

    // ---- G. INVALID / CONSUMED INVITE on a non-empty table is forbidden (peekInvite returns null). --------
    {
      const s = makeSchedulerWith(new MockStorage());
      const owner = await makeAuthenticator("ES256");
      await enrolBootstrapOwner(s.env, owner, "owner@example.com");
      const begin = await registerBegin(s.env, "ghost@example.com", { inviteToken: "not-a-real-invite-token" });
      ok("G: an unknown invite token is forbidden", begin.json.ok === false && begin.json.reason === "forbidden");
    }

    // ---- H. EMAIL-LINK BOOTSTRAP: a valid first-Owner invite slot (peeked, then single-use consumed on
    // finish) binds the PINNED email, never the client field. Plus the empty-table refusals (bad link / no
    // proof at all). ---------------------------------------------------------------------------------------
    {
      const s = makeSchedulerWith(new MockStorage());
      await s.storage.put(BOOTSTRAP_INVITE_KEY, { token: "boot-link-tok", email: "pinned@customer.example", createdAt: Date.now(), expiresAt: Date.now() + 1_000_000 });
      const auth = await makeAuthenticator("ES256");
      const begin = await registerBegin(s.env, "attacker-claimed@evil.example", { inviteToken: "boot-link-tok", origin: ORIGIN });
      ok("H: link begin is authorised and binds the PINNED email, not the client field", begin.json.ok === true && pkOf(begin).user?.name === "pinned@customer.example");
      const fin = await registerFinish(s.env, "attacker-claimed@evil.example", await buildAttestation(auth, challengeFor(begin)), { inviteToken: "boot-link-tok", origin: ORIGIN });
      ok("H: link finish bootstraps the PINNED email to Owner", fin.json.ok === true && fin.json.bootstrapped === true && fin.json.email === "pinned@customer.example" && fin.json.role === "owner");
      ok("H: the single-use bootstrap-link slot was consumed", (await s.storage.get(BOOTSTRAP_INVITE_KEY)) === undefined);
    }
    {
      const s = makeSchedulerWith(new MockStorage());
      const badLink = await registerBegin(s.env, "x@example.com", { inviteToken: "no-such-link", origin: ORIGIN });
      ok("H: an empty-table begin with an invalid link is forbidden", badLink.json.ok === false && badLink.json.reason === "forbidden");
      const noProof = await registerBegin(s.env, "x@example.com");
      ok("H: an empty-table begin with no proof at all is forbidden", noProof.json.ok === false && noProof.json.reason === "forbidden");
    }

    // ---- I. DISPLAY NAME bounding (the friendly label): a valid name is kept; a too-long or control-char
    // name falls back to the email. Driven through the real begin route (displayName is a kept client field).
    {
      const s = makeSchedulerWith(new MockStorage());
      const good = await post(s.env, "/admin/auth/register/begin", { email: "dn@example.com", displayName: "Alice Smith" }, { authorization: `Bearer ${ADMIN_TOKEN}`, origin: ORIGIN });
      ok("I: a valid display name is carried into the creation options", good.json.ok === true && pkOf(good).user?.displayName === "Alice Smith");
      const tooLong = await post(s.env, "/admin/auth/register/begin", { email: "dn2@example.com", displayName: "x".repeat(129) }, { authorization: `Bearer ${ADMIN_TOKEN}`, origin: ORIGIN });
      ok("I: a too-long display name falls back to the email", tooLong.json.ok === true && pkOf(tooLong).user?.displayName === "dn2@example.com");
      const ctrl = await post(s.env, "/admin/auth/register/begin", { email: "ctrl-name@example.com", displayName: "badname" }, { authorization: `Bearer ${ADMIN_TOKEN}`, origin: ORIGIN });
      ok("I: a control-character display name falls back to the email", ctrl.json.ok === true && pkOf(ctrl).user?.displayName === "ctrl-name@example.com");
    }

    // ---- J. excludeCredentials WITH transports: when the bound email already has a credential that reported
    // transports, the begin creation options carry those transports (so a key is not enrolled twice). -------
    {
      const s = makeSchedulerWith(new MockStorage());
      await s.storage.put(`${PASSKEY_CRED_PREFIX}seeded-id`, {
        credentialId: "seeded-id", email: "exc@example.com", cosePublicKey: "AA", alg: -7,
        signCount: 0, transports: ["usb", "nfc"], aaguid: "AA", createdAt: "2020-01-01T00:00:00.000Z",
      });
      const begin = await registerBegin(s.env, "exc@example.com", bootstrapOpts());
      ok("J: begin is authorised with a pre-seeded credential present", begin.json.ok === true);
      const ex = pkOf(begin).excludeCredentials ?? [];
      ok("J: excludeCredentials carries the existing credential's transports", ex.length === 1 && ex[0]!.id === "seeded-id" && eq(ex[0]!.transports, ["usb", "nfc"]));
    }

    // ---- K. TRANSPORT-HINT filter loop: a successful finish stores only the KNOWN transport tokens, deduped
    // and order-preserved, dropping non-strings and unknown tokens. ----------------------------------------
    {
      const s = makeSchedulerWith(new MockStorage());
      const auth = await makeAuthenticator("ES256");
      const begin = await registerBegin(s.env, "tr@example.com", bootstrapOpts());
      const att = await buildAttestation(auth, challengeFor(begin));
      // Inject a hostile-ish transports list onto the credential response (a non-string, an unknown token, a
      // duplicate, and all six known tokens). passkeyTransports must filter + dedupe it.
      (att.response as unknown as { transports: unknown[] }).transports = ["usb", 5, "nfc", "bogus", "usb", "ble", "internal", "hybrid", "smart-card"];
      const fin = await registerFinish(s.env, "tr@example.com", att, bootstrapOpts());
      ok("K: the finish with a transports list verifies", fin.json.ok === true);
      const stored = await s.storage.get<{ transports: string[] }>(`${PASSKEY_CRED_PREFIX}${b64urlEncode(auth.credentialId)}`);
      ok("K: only known transport tokens are stored, deduped + order-preserved", stored !== undefined && eq(stored.transports, ["usb", "nfc", "ble", "internal", "hybrid", "smart-card"]));
    }

    // ---- L. WRITE-POINT RE-CHECK: a non-self-add (invite) registration that resolves to an email which
    // ALREADY has a credential is refused at the write point (after a real verification), not just at
    // authorisation time. Seed an invite for the already-enrolled Owner and complete a fresh ceremony. ------
    {
      const s = makeSchedulerWith(new MockStorage());
      const owner = await makeAuthenticator("ES256");
      await enrolBootstrapOwner(s.env, owner, "owner@example.com");
      await s.storage.put(`${PASSKEY_INVITE_PREFIX}invite-L`, { token: "invite-L", email: "owner@example.com", role: "viewer", createdAt: Date.now(), expiresAt: Date.now() + 1_000_000 });
      const second = await makeAuthenticator("ES256");
      const begin = await registerBegin(s.env, "owner@example.com", { inviteToken: "invite-L" });
      ok("L: the invite begin for the enrolled email is authorised", begin.json.ok === true);
      const fin = await registerFinish(s.env, "owner@example.com", await buildAttestation(second, challengeFor(begin)), { inviteToken: "invite-L" });
      ok("L: binding a credential to an already-enrolled email (non-self-add) is forbidden at the write point", fin.json.ok === false && fin.json.reason === "forbidden");
      ok("L: no extra credential was written for the refused binding", s.storage.countPrefix(PASSKEY_CRED_PREFIX) === 1);
    }

    // ---- M. CHALLENGE ABSENT at register/finish: an authorised finish whose bound-email challenge was never
    // issued (no matching begin) is the coarse "challenge" rejection (consumeChallenge returns null). -------
    {
      const s = makeSchedulerWith(new MockStorage());
      const auth = await makeAuthenticator("ES256");
      // A well-formed attestation over a server-shaped challenge, but begin was never called, so no challenge
      // is stored under reg:<email>; the finish resolves bootstrap, decodes the fields, then finds no challenge.
      const att = await buildAttestation(auth, b64urlEncode(crypto.getRandomValues(new Uint8Array(32))));
      const fin = await registerFinish(s.env, "nochal@example.com", att, bootstrapOpts());
      ok("M: a finish with no issued challenge is rejected (reason challenge)", fin.json.ok === false && fin.json.reason === "challenge");
    }

    // ---- N. MISSING credential.response + missing decoded field: an authorised finish with an empty
    // credential object (no response) decodes against an empty response and earns a coarse bad_request. -----
    {
      const s = makeSchedulerWith(new MockStorage());
      const fin = await registerFinish(s.env, "noresp@example.com", {}, bootstrapOpts());
      ok("N: a finish with no credential.response is a coarse bad_request", fin.json.ok === false && fin.json.reason === "bad_request");
      ok("N: nothing was stored for the malformed finish", s.storage.countPrefix(PASSKEY_CRED_PREFIX) === 0);
    }

    // ---- O. BEGIN INTERNAL-ERROR CATCH: an unexpected (non-PasskeyError) fault inside begin (here, the
    // challenge put fails) is mapped to a coarse bad_request with an opaque id, leaking nothing and storing
    // nothing. --------------------------------------------------------------------------------------------
    {
      const s = makeSchedulerWith(new ThrowOnChallengePut());
      const begin = await registerBegin(s.env, "boom@example.com", bootstrapOpts());
      ok("O: an internal fault in begin returns a coarse bad_request (200-bodied)", begin.status === 200 && begin.json.ok === false && begin.json.reason === "bad_request");
      ok("O: the failed begin stored no challenge", s.storage.countPrefix("passkeyChallenge:") === 0);
    }

    // ---- P. BEST-EFFORT RECOVERY MINT: when the recovery-code mint throws (the recovery: put fails), the
    // enrolment STILL succeeds (the credential is already stored) and returns an EMPTY recovery-codes set. ---
    {
      const s = makeSchedulerWith(new ThrowOnRecoveryPut());
      const auth = await makeAuthenticator("ES256");
      const fin = await enrolBootstrapOwner(s.env, auth, "rec@example.com");
      ok("P: the enrolment still succeeds and bootstraps Owner when the recovery mint fails", fin.json.ok === true && fin.json.bootstrapped === true);
      ok("P: the failed recovery mint yields an empty recovery-codes set", Array.isArray(fin.json.recoveryCodes) && fin.json.recoveryCodes!.length === 0);
      ok("P: the credential was still stored despite the recovery-mint failure", s.storage.countPrefix(PASSKEY_CRED_PREFIX) === 1);
    }

    // ---- R. DUPLICATE CREDENTIAL ID: a credential id is globally unique, so re-presenting one already
    // registered (here the same authenticator under a second, invited email) is rejected as already_registered
    // AFTER a real verification, never silently re-bound. ------------------------------------------------
    {
      const s = makeSchedulerWith(new MockStorage());
      const auth = await makeAuthenticator("ES256");
      await enrolBootstrapOwner(s.env, auth, "dup@example.com");
      const invite = await grantRoleViaToken(s.env, "dup2@example.com", "viewer");
      const begin = await registerBegin(s.env, "dup2@example.com", { inviteToken: invite });
      // The SAME authenticator (same credential id) completes a fresh, authorised ceremony for a new email.
      const fin = await registerFinish(s.env, "dup2@example.com", await buildAttestation(auth, challengeFor(begin)), { inviteToken: invite });
      ok("R: re-registering an existing credential id is rejected (already_registered)", fin.json.ok === false && fin.json.reason === "already_registered");
      ok("R: no second credential record was written for the duplicate", s.storage.countPrefix(PASSKEY_CRED_PREFIX) === 1);
    }

    // ---- Q. THE INTERNAL BOUNDING + COARSE-ERROR HELPERS (no HTTP route): called directly on a real
    // SchedulerDO instance; each assertion checks the real return value or the real thrown PasskeyError. ----
    const pk = makeSchedulerWith(new MockStorage()).dobj;

    // passkeyRpId: non-string -> null; empty / over-253 -> null; control char -> null; valid -> trimmed.
    ok("Q rpId: a non-string is rejected", pk.passkeyRpId(123) === null);
    ok("Q rpId: an empty string is rejected", pk.passkeyRpId("   ") === null);
    ok("Q rpId: an over-253-char host is rejected", pk.passkeyRpId("a".repeat(254)) === null);
    ok("Q rpId: a control character is rejected", pk.passkeyRpId("ho\u0000st") === null);
    ok("Q rpId: a valid host is trimmed and kept", pk.passkeyRpId("  console.example  ") === "console.example");

    // passkeyOrigin: same single-line discipline with a 2048 bound.
    ok("Q origin: a non-string is rejected", pk.passkeyOrigin(null) === null);
    ok("Q origin: an empty string is rejected", pk.passkeyOrigin("") === null);
    ok("Q origin: an over-2048-char origin is rejected", pk.passkeyOrigin("https://x." + "a".repeat(2048)) === null);
    ok("Q origin: a control character is rejected", pk.passkeyOrigin("https://x.example") === null);
    ok("Q origin: a valid origin is kept", pk.passkeyOrigin("https://console.example") === "https://console.example");

    // passkeyDisplayName: non-string / empty / too-long / control char -> fallback; valid -> the name.
    ok("Q displayName: a non-string falls back", pk.passkeyDisplayName(123, "fb@example.com") === "fb@example.com");
    ok("Q displayName: an empty string falls back", pk.passkeyDisplayName("   ", "fb@example.com") === "fb@example.com");
    ok("Q displayName: a too-long name falls back", pk.passkeyDisplayName("x".repeat(129), "fb@example.com") === "fb@example.com");
    ok("Q displayName: a control-char name falls back", pk.passkeyDisplayName("abcd", "fb@example.com") === "fb@example.com");
    ok("Q displayName: a valid name is trimmed and kept", pk.passkeyDisplayName("  Bob Jones  ", "fb@example.com") === "Bob Jones");

    // decodeB64urlField: the four fault modes throw Passkey(bad_request); a valid field decodes to its bytes.
    ok("Q decode: a non-string field throws", throwsPasskey(() => pk.decodeB64urlField(123, "f", 100), "missing"));
    ok("Q decode: an empty field throws", throwsPasskey(() => pk.decodeB64urlField("", "f", 100), "missing"));
    ok("Q decode: an over-bound STRING throws before decode", throwsPasskey(() => pk.decodeB64urlField("A".repeat(200), "f", 100), "exceeds the size bound"));
    ok("Q decode: an invalid base64url field throws", throwsPasskey(() => pk.decodeB64urlField("!!!!", "f", 100), "not valid base64url"));
    ok("Q decode: a decoded length over the byte bound throws", throwsPasskey(() => pk.decodeB64urlField("AAAAAAAA", "f", 4), "out of range"));
    const decoded = pk.decodeB64urlField("QUJD", "f", 100); // "ABC"
    ok("Q decode: a valid field decodes to its bytes", decoded.length === 3 && decoded[0] === 0x41 && decoded[2] === 0x43);

    // coarsePasskeyError: a PasskeyError surfaces its coarse reason; any other error surfaces bad_request.
    const cpReason = pk.coarsePasskeyError("stage", new PasskeyError("challenge", "precise detail"));
    ok("Q coarse: a PasskeyError surfaces its coarse reason + an opaque id", cpReason.ok === false && cpReason.reason === "challenge" && typeof cpReason.errorId === "string" && cpReason.errorId.length > 0);
    const cpInternal = pk.coarsePasskeyError("stage", new Error("boom"));
    ok("Q coarse: an unexpected error surfaces a stable bad_request", cpInternal.ok === false && cpInternal.reason === "bad_request");

    // passkeyTransports: a non-array yields []; an array is filtered, deduped, and order-preserved.
    ok("Q transports: a non-array yields an empty list", eq(pk.passkeyTransports("usb"), []));
    ok("Q transports: an array is filtered + deduped", eq(pk.passkeyTransports(["usb", 5, "usb", "bogus", "nfc"]), ["usb", "nfc"]));

    // passkeyRegisterBegin / passkeyRegisterFinish early field guards (rp.id / origin are server-supplied, so
    // the router can never feed them empty; the DO still fails closed on a bad one). Driven directly.
    ok("Q begin: a missing email is a bad_request", (await pk.passkeyRegisterBegin({ rpId: RP_ID })).reason === "bad_request");
    ok("Q begin: an unusable rp.id is a bad_request", (await pk.passkeyRegisterBegin({ email: "a@b.com", rpId: "" })).reason === "bad_request");
    ok("Q finish: a missing email is a bad_request", (await pk.passkeyRegisterFinish({ rpId: RP_ID, origin: ORIGIN, credential: {} })).reason === "bad_request");
    ok("Q finish: an unusable origin is a bad_request", (await pk.passkeyRegisterFinish({ email: "a@b.com", rpId: RP_ID, origin: "", credential: {} })).reason === "bad_request");
    ok("Q finish: a non-object credential is a bad_request", (await pk.passkeyRegisterFinish({ email: "a@b.com", rpId: RP_ID, origin: ORIGIN, credential: "nope" })).reason === "bad_request");
  } finally {
    console.error = origErr;
    console.warn = origWarn;
  }

  console.log(failures === 0 ? "\nVALIDATE-COV-SCHED-SCHEDULER-DO-PASSKEY VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
