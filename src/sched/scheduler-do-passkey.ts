// The WebAuthn / passkey subsystem (the engine's own identity provider). PasskeyMixin holds the
// REGISTRATION ceremony and the shared input-bounding + coarse-error helpers; the first-Owner
// bootstrap-invite slot, the single-use teammate invites, and the LOGIN assertion ceremony live in the
// sibling ./scheduler-do-passkey-invites.ts (PasskeyInvitesMixin). Both layer over a base whose `this` is
// SchedulerDOSurface, so the ceremonies issue + single-use consume challenges, resolve the registration
// authority and bootstrap the first Owner through `this` (the login ceremony reaches the bounding
// helpers here through `this`). The account-takeover fix (the BOUND email is derived from the proof,
// never the client field) holds across both files.

import { webauthnFaultOf } from "../admin/diag-records.ts";
import { passkeySubject, type Role, type RoleEntry, roleSubjectKey } from "../admin/identity.ts";
import { CHALLENGE_TTL_MS, excludeCredentialsFor, type PasskeyCred, PasskeyError, type PasskeyUser, PUBKEY_CRED_PARAMS, errId as passkeyErrId, randomChallengeB64, userHandleFor, type VerifiedRegistration, verifyRegistration } from "../admin/passkey.ts";
import { rosterRefusesEnrolment } from "../admin/signin-factors.ts";
import { b64urlDecode, b64urlEncode } from "../crypto/bytes.ts";
import { log } from "../log.ts";
import { recordCeremonyError, recordCeremonyFault } from "./sched-fault-ledger.ts";
import { PASSKEY_ATT_OBJ_MAX, PASSKEY_CLIENT_DATA_MAX, PASSKEY_USER_PREFIX, type REG_PATHS, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { nowMillisISO } from "./scheduler-helpers.ts";

export function PasskeyMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {

  // passkeyRpId bounds the rp.id the router passes in (the engine host). It must be a non-empty, single-
  // line host-shaped string; this is an authority-boundary sanity check, not a full hostname validator
  // (the router derives it from the request URL). Returns null for anything unusable.
  passkeyRpId(raw: unknown): string | null {
    if (typeof raw !== "string") return null;
    const v = raw.trim();
    if (v.length < 1 || v.length > 253) return null;
    for (let i = 0; i < v.length; i++) {
      const c = v.charCodeAt(i);
      if (c < 0x20 || c === 0x7f) return null;
    }
    return v;
  }

  // passkeyOrigin bounds the origin the router passes in (CONSOLE_ORIGIN). Same single-line discipline as
  // passkeyRpId; the exact-match check against clientDataJSON.origin happens in the verifier.
  passkeyOrigin(raw: unknown): string | null {
    if (typeof raw !== "string") return null;
    const v = raw.trim();
    if (v.length < 1 || v.length > 2048) return null;
    for (let i = 0; i < v.length; i++) {
      const c = v.charCodeAt(i);
      if (c < 0x20 || c === 0x7f) return null;
    }
    return v;
  }

  // passkeyDisplayName bounds the operator-chosen display name. A friendly label only (never a key); 1
  // to 128 chars, no control characters. Defaults to the email when omitted.
  passkeyDisplayName(raw: unknown, fallback: string): string {
    if (typeof raw !== "string") return fallback;
    const v = raw.trim();
    if (v.length < 1 || v.length > 128) return fallback;
    for (let i = 0; i < v.length; i++) {
      const c = v.charCodeAt(i);
      if (c < 0x20 || c === 0x7f) return fallback;
    }
    return v;
  }

  // decodeB64urlField strictly decodes a base64url client field (the credential's id/clientDataJSON/
  // attestationObject/authenticatorData/signature), bounding its decoded size so a hostile oversized
  // field cannot drive a large allocation/parse on the single-threaded DO. A non-string, an invalid
  // base64url, or an over-cap size throws PasskeyError "bad_request" (the caller maps it to a 400).
  decodeB64urlField(raw: unknown, name: string, maxBytes: number): Uint8Array {
    if (typeof raw !== "string" || raw.length === 0) {
      throw new PasskeyError("bad_request", `passkey: ${name} is missing`);
    }
    // A base64url string is ~4/3 the byte length; bound the STRING first so a giant input is rejected
    // before decode allocates. The decode itself re-validates the alphabet strictly (crypto/bytes.ts).
    if (raw.length > Math.ceil((maxBytes * 4) / 3) + 4) {
      throw new PasskeyError("bad_request", `passkey: ${name} exceeds the size bound`);
    }
    let out: Uint8Array;
    try {
      out = b64urlDecode(raw);
    } catch (e) {
      throw new PasskeyError("bad_request", `passkey: ${name} is not valid base64url (${(e as Error).message})`);
    }
    if (out.length === 0 || out.length > maxBytes) {
      throw new PasskeyError("bad_request", `passkey: ${name} decoded length ${out.length} out of range`);
    }
    return out;
  }


  // coarsePasskeyError maps a thrown error to the wire result the begin/finish routes return: a coarse
  // client reason plus an opaque error id, with the PRECISE reason logged to console.error (never
  // returned). A PasskeyError carries the coarse `reason`; any other (unexpected) error is logged as an
  // "internal" category and surfaced as bad_request so the client still gets a stable, non-leaky 400.
  // The opaque id lets an operator correlate the client-visible failure with the logged precise reason.
  //
  // G158: this is the SINGLE chokepoint every ceremony failure passes through (register/begin, register/finish,
  // login/begin, login/finish, stepup/finish), so it is where the STRUCTURAL class the CBOR/COSE/DER/authData
  // parsers tagged onto the error is recorded. Fire-and-forget (the established `void this.recordAuthSignal`
  // idiom in this DO): the client result below is returned unchanged, and an untagged error records nothing.
  // The PHASE is derived from the stage: only a registration is an "enrol"; a login and a step-up both
  // re-decode the STORED key, so both are "login" -- which is precisely what separates a device the runtime
  // will not accept from a persisted credential record that has become unreadable.
  coarsePasskeyError(stage: string, e: unknown): { ok: false; reason: string; errorId: string } {
    const id = passkeyErrId(e);
    const fault = webauthnFaultOf(e);
    if (fault !== null) void this.recordWebauthnFault(stage.startsWith("register") ? "enrol" : "login", fault.webauthnFaultClass, fault.coseAlg);
    if (e instanceof PasskeyError) {
      log("error", `passkey ${stage} [err:${id} ${e.reason}] ${e.message}`);
      return { ok: false, reason: e.reason, errorId: id };
    }
    log("error", `passkey ${stage} [err:${id} internal] ${(e as Error).message}`);
    return { ok: false, reason: "bad_request", errorId: id };
  }

  // RegAuth is the outcome of resolveRegistrationAuthorisation: the PROVEN registration path and the
  // BOUND email the credential will be tied to (derived from the proof, NEVER the client email field for
  // the invite path). path "bootstrap" is the first-Owner enrolment (empty role table, valid ADMIN_TOKEN);
  // "invite" is an Owner-authorised single-use invite (email from the invite record); "self-add" is an
  // already-authenticated caller adding a credential to their own email. allowExistingCreds is true ONLY
  // for the self-add of an email that is already enrolled (the owner of that email adding a SECOND key);
  // every other path refuses an email that already has credentials.

  // resolveRegistrationAuthorisation is the SINGLE authority decision for a passkey registration: it
  // proves the registrant is authorised to bind a credential to an email by one of three paths and returns
  // the BOUND email (plus, for the invite path, the token to consume on success), or null (forbidden) for
  // everything else. This is the account-takeover fix: WebAuthn proves key possession, not email
  // ownership, so the email is NEVER taken from the client field except where a proof authorises THAT exact
  // email. It PEEKS the invite (it does not consume it): finish consumes the invite only AFTER a fully
  // successful registration (so a fumbled gesture does not burn the invite), and begin peeks it too. The
  // proven auth facts (authMethod/authEmail/bootstrapAuthorised) are forwarded by the router FROM THE
  // ROUTER ONLY (built from the verified verdict, never an inbound client field), the same trust model as
  // the caller header.
  //
  //   1. BOOTSTRAP (role table EMPTY only): requires bootstrapAuthorised (a valid ADMIN_TOKEN bearer). The
  //      bound email is the client email (the operator names the first Owner). The empty-table check and
  //      the later write are in the same single-threaded DO call, so the first-Owner claim is race-free. If
  //      ADMIN_TOKEN is unset/invalid the verdict is not method:"token", bootstrapAuthorised is false, and
  //      the bootstrap path is CLOSED (the operator must set ADMIN_TOKEN to enrol the first passkey).
  //   2. INVITE: a valid (peeked/consumed) single-use, email-bound invite token; the bound email is the
  //      invite's email (NOT the client field). Refused if that email already has credentials.
  //   3. SELF-ADD: an authenticated caller. For Access/passkey the proven email MUST equal the client
  //      registration email (you may add a key to your OWN email, including a second key). For the bare
  //      token (no email, the all-or-nothing owner break-glass) the bound email is the client email but
  //      ONLY when that email has NO existing credentials (it may stand up a NEW identity but never bind a
  //      credential onto someone else's already-enrolled email, which would be impersonation).
  //
  // In ALL non-bootstrap cases the target email must match the proven email (or, for the token, be an
  // unenrolled email), and binding to an email that already has credentials is refused unless it is the
  // self-add of that email's own owner. A bootstrap on a NON-empty table is refused (bootstrap is
  // first-Owner only). Everything else returns null.
  async resolveRegistrationAuthorisation(
    clientEmail: string,
    body: { inviteToken?: unknown; authMethod?: unknown; authEmail?: unknown; bootstrapAuthorised?: unknown },
    now: number,
  ): Promise<{ path: (typeof REG_PATHS)[number]; boundEmail: string; allowExistingCreds: boolean; inviteToken?: string; bootstrapInviteToken?: string } | null> {
    const authMethod = typeof body.authMethod === "string" ? body.authMethod : null;
    const authEmail = this.normaliseEmail(body.authEmail);
    const bootstrapAuthorised = body.bootstrapAuthorised === true;
    const inviteTokenRaw = typeof body.inviteToken === "string" ? body.inviteToken : null;

    // The role table is EMPTY only when there is no grant of any kind (no bound subject entry, no pending
    // invite, no legacy row): a pending invite means an Owner already exists in spirit (they invited), so
    // bootstrap must not re-fire. roleTableIsEmpty checks all three shapes.
    const tableEmpty = await this.roleTableIsEmpty();

    // 1. BOOTSTRAP: empty role table + a valid ADMIN_TOKEN bearer. The bound email is the client email
    // (the operator chooses the first Owner). On a NON-empty table the bootstrap path is unavailable and
    // we fall through (an invite or self-add must authorise instead).
    if (tableEmpty) {
      // BELT-AND-BRACES over the empty-table check (mirrors the whoami Access bootstrap): once the first
      // Owner has EVER been claimed (bootstrapConsumed latched), the bootstrap path is CLOSED even on an
      // empty table, so a cleared/hand-edited store cannot re-open a first-Owner passkey enrolment. Refuse
      // outright (do not fall through to invite/self-add: with the latch set the operator must restore an
      // Owner via the documented break-glass recovery, not a fresh bootstrap).
      if (await this.getBootstrapConsumed()) {
        // G061: the same DEADLOCK whoami detects, seen from the enrolment door: the role table is EMPTY and the
        // one-shot latch is SPENT, so no first-Owner passkey can ever be enrolled again and no existing Owner
        // can grant a role (there is none). The operator sees a bare "forbidden" on every attempt. Count only.
        void this.recordAuthSignalThrottled("rbac-empty-table-with-latch");
        return null;
      }
      if (bootstrapAuthorised && authMethod === "token") {
        // The first registrant: there are no credentials yet, so allowExistingCreds is moot (false).
        return { path: "bootstrap", boundEmail: clientEmail, allowExistingCreds: false };
      }
      // 1b. EMAIL-LINK BOOTSTRAP: a valid first-Owner invite (the link the engine emailed to the
      // deploy-time-pinned BOOTSTRAP_OWNER_EMAIL). The bound email comes FROM the invite record, never
      // the client field, so redeeming the link can only ever enrol the pinned address. PEEK here (do
      // not consume): finish consumes only after a verified ceremony, so a fumbled attempt does not burn
      // the one-shot link. This sits INSIDE the empty-table branch on purpose: once any Owner exists the
      // slot can no longer authorise (and mint refuses to create one).
      if (inviteTokenRaw !== null) {
        const pinnedEmail = await this.peekBootstrapInvite(inviteTokenRaw, now);
        if (pinnedEmail !== null) {
          return { path: "bootstrap", boundEmail: pinnedEmail, allowExistingCreds: false, bootstrapInviteToken: inviteTokenRaw };
        }
      }
      // Empty table but no ADMIN_TOKEN proof and no valid bootstrap link: the bootstrap path is closed.
      // Do NOT fall through to invite (no teammate invite can exist before the first Owner) or self-add
      // (no one is enrolled yet); refuse.
      return null;
    }

    // 2. INVITE: a valid single-use, email-bound invite. PEEK it here (do not consume): the bound email is
    // the invite's email, never the client field. finish consumes the invite only after a successful
    // registration, so a failed/fumbled finish does not burn the invite.
    if (inviteTokenRaw !== null) {
      const invitedEmail = await this.peekInvite(inviteTokenRaw, now);
      // G014: an invite token that is unknown, expired or already consumed. The caller only ever sees the
      // coarse forbidden, so "the link you sent me does not work" had no engine-side evidence at all.
      if (invitedEmail === null) {
        await recordCeremonyFault(this.state.storage, "passkey-invite-invalid");
        return null;
      }
      // ROSTER-BOUND ENROLMENT, the second arm. Identical rule to the self-add arm below, for an
      // identical reason, and it has to be here rather than there because this arm RETURNS: presenting any
      // valid inviteToken reaches this line and leaves the function without the self-add gate ever being
      // evaluated, so before this the invite was an unconditional way past it.
      //
      // WHAT WAS OPEN. An invite is minted at the commit point of setRole (the only producer) and lives
      // under `passkeyInvite:<token>` for seven days. deleteRole removes the bound `role:<subject>` row and
      // every `role:pending:<email>` row, and its own comment says it does so "so an offboarded person
      // cannot rebind a lingering pending invite on a later login" -- but the registration invite is keyed
      // by TOKEN, not by email, so an email-keyed delete cannot reach it even in principle. The SCIM leaver
      // path posts only /roles/delete. So for up to seven days after an address was removed from the
      // roster, its outstanding invite still resolved here, and redeeming it minted a standing passkey AND
      // a fresh set of never-expiring recovery codes, unauthenticated, with no roster check anywhere on the
      // path. That is the same defect the self-add arm was closed for, reached by a shorter route.
      //
      // NO METHOD SCOPING IS NEEDED HERE, and the difference from the self-add arm is worth stating rather
      // than leaving as an inconsistency. That arm is scoped to `authMethod === "passkey"` because a member
      // can hold authority from an IdP GROUP CLAIM with no role row at all, so the roster set is only a
      // lower bound for an "access" session. An invite has exactly one producer, setRole, which persists a
      // role row or a pending grant in the same commit. So on this arm the invite's own existence is
      // evidence that the roster once accounted for the address, and a populated roster that no longer
      // does is a removal, not a group-claim blind spot.
      //
      // FAIL OPEN, inherited whole from classifyRosterMembership: a roster read that throws and a roster
      // that reads empty are both "unreadable" and both admit. Only a populated roster that does not carry
      // this address refuses. An expired time-boxed grant also refuses, which is the same answer the
      // self-add arm gives and the one the grant itself asked for.
      //
      // IT DESTROYS NOTHING. This refuses the minting of a new way in; the invite is not consumed here (the
      // peek above does not burn it) and no existing credential is touched, so a wrong answer costs an
      // off-roster person one enrolment attempt, never their access.
      if (rosterRefusesEnrolment(await this.rosterMembership(invitedEmail))) {
        await recordCeremonyFault(this.state.storage, "passkey-invite-off-roster");
        await this.recordAuthSignalThrottled("roster-enrolment-refused");
        return null;
      }
      // An invite is for enrolling a not-yet-enrolled email; refuse binding to an email that already has
      // credentials (a second key for an enrolled person is the self-add path, not an invite).
      return { path: "invite", boundEmail: invitedEmail, allowExistingCreds: false, inviteToken: inviteTokenRaw };
    }

    // 3. SELF-ADD: an authenticated caller adding a credential to their own email.
    if (authMethod === "access" || authMethod === "passkey") {
      // The proven email must equal the email being registered; you cannot add a credential to anyone
      // else's email. allowExistingCreds is true: this is exactly "the owner of that email adding their
      // own second credential", the one case where binding to an already-enrolled email is permitted.
      if (authEmail !== null && authEmail === clientEmail) {
        // ROSTER-BOUND ENROLMENT. This arm is the ONE that converts a one-time bearer secret into standing
        // access, and it is where the recovery-code residue has to be stopped, not at the response field the
        // console reads. A recovery-code sign-in mints a session with method "passkey" and the consumed
        // email's subject, so it arrives HERE indistinguishable from an ordinary passkey session, and a
        // self-add off the back of it leaves a permanent credential behind after the single-use code is
        // spent. Gating the JSON `enrolPasskey` hint alone would have been decorative: the console would stop
        // offering the button while the route kept answering it.
        //
        // SCOPED TO THE PASSKEY METHOD, and that scope is load-bearing rather than caution. resolveRole
        // returns max(role row, group-mapped role, viewer), so a legitimate member can hold authority from an
        // IdP GROUP CLAIM with no role row at all, and the roster set cannot see them. Such a member reaches
        // this route as method "access", carrying the claims that grant them the role; refusing them here
        // would break a working estate. A passkey session carries no group claims and was therefore never
        // resolved by one, so for it the roster set is not a lower bound but the whole answer.
        //
        // FAIL OPEN. rosterMembership returns "unreadable" for a storage fault AND for a roster that reads
        // empty, and rosterRefusesEnrolment admits both. The refusal needs a populated roster that does not
        // carry this address. Bootstrap never reaches here (the empty-table branch returned above), and an
        // invited member is on the roster as a pending grant before their first enrolment.
        //
        // EXISTING CREDENTIALS ARE NOT TOUCHED. This refuses the minting of a NEW way in; it destroys
        // nothing, so a wrong answer here costs an off-roster person one enrolment attempt, never their
        // access.
        if (authMethod === "passkey" && rosterRefusesEnrolment(await this.rosterMembership(authEmail))) {
          await recordCeremonyFault(this.state.storage, "passkey-selfadd-off-roster");
          await this.recordAuthSignalThrottled("roster-enrolment-refused");
          return null;
        }
        return { path: "self-add", boundEmail: authEmail, allowExistingCreds: true };
      }
      return null;
    }
    if (authMethod === "token") {
      // The bare-token break-glass has no email identity. It already holds full owner authority, so it may
      // stand up a NEW identity (a fresh email with no credential), but it must NEVER bind a credential
      // onto an email that already has one (that would be impersonating an existing, attributable account).
      // ACCEPTED RISK: the clientEmail here is fully attacker-controlled within this path; there is no proof
      // the token holder owns it. This is bounded by the fact that reaching here requires a valid ADMIN_TOKEN,
      // which is an owner-level secret. A compromised ADMIN_TOKEN already grants full owner authority, so the
      // ability to bind a NEW (credential-free) email adds no privilege beyond what the token already confers.
      const existing = await this.listPasskeyCredsForEmail(clientEmail);
      if (existing.length === 0) {
        return { path: "self-add", boundEmail: clientEmail, allowExistingCreds: false };
      }
      return null;
    }

    // No proven path authorised this registration.
    return null;
  }

  // passkeyRegisterBegin issues a registration challenge bound to the AUTHORISED email and returns the
  // creation options the browser passes to navigator.credentials.create. It first proves the registrant is
  // authorised (resolveRegistrationAuthorisation: bootstrap / invite / self-add) and derives the BOUND
  // email from that proof, NOT the client field, then issues a challenge scoped to `reg:<boundEmail>` so
  // the matching finish (which re-derives the same bound email) consumes the right challenge. An
  // unauthorised registration is refused with a coarse forbidden reason BEFORE any challenge is stored or
  // any user-handle/exclude list is computed, so it leaks nothing and stores nothing. userVerification is
  // required, pubKeyCredParams is ES256 then RS256, and excludeCredentials lists the bound email's existing
  // credential ids so a key is not enrolled twice. It does NOT create the user record yet (finish does,
  // once a credential verifies), so a begin that is never completed leaves no half-account.
  async passkeyRegisterBegin(
    body: { email?: unknown; displayName?: unknown; rpId?: unknown; inviteToken?: unknown; authMethod?: unknown; authEmail?: unknown; bootstrapAuthorised?: unknown },
  ): Promise<
    | { ok: true; publicKey: unknown; challengeScope: string }
    | { ok: false; reason: string; errorId?: string }
  > {
    const clientEmail = this.normaliseEmail(body.email);
    const rpId = this.passkeyRpId(body.rpId);
    if (!clientEmail) return { ok: false, reason: "bad_request" };
    // G014: an rp.id the ROUTER could not supply is a deploy-config fault (an unset/unparseable CONSOLE_ORIGIN
    // after a host change), not a user fault, but the client is told `bad_request` and blames its own browser.
    // Count the server-side cause; the response is unchanged.
    if (!rpId) {
      await recordCeremonyFault(this.state.storage, "passkey-rpid-absent");
      return { ok: false, reason: "bad_request" };
    }
    try {
      const now = Date.now();
      // Prove authorisation and resolve the BOUND email (peek the invite; the finish consumes it). A
      // coarse "forbidden" is returned for any unauthorised registration, with NOTHING stored or leaked.
      const auth = await this.resolveRegistrationAuthorisation(clientEmail, body, now);
      // G014: the "the invite link fails for my colleague" ticket. The coarse forbidden is deliberately
      // uninformative to the CALLER (anti-enumeration); the pack-side count is not.
      if (auth === null) {
        await recordCeremonyFault(this.state.storage, "passkey-register-forbidden");
        return { ok: false, reason: "forbidden" };
      }
      const email = auth.boundEmail;
      const challenge = randomChallengeB64();
      const scope = `reg:${email}`;
      await this.putPasskeyChallenge(scope, challenge, now);
      const userHandle = await userHandleFor(email);
      const existing = await this.listPasskeyCredsForEmail(email);
      const displayName = this.passkeyDisplayName(body.displayName, email);
      const publicKey = {
        rp: { id: rpId, name: "Downpipes" },
        user: { id: userHandle, name: email, displayName },
        challenge,
        pubKeyCredParams: PUBKEY_CRED_PARAMS,
        // userVerification "required" (not "preferred"): this is the admin front door, so the browser
        // MUST collect a PIN/biometric, and verifyRegistration enforces the resulting UV flag. A bare
        // user-presence touch is not enough to enrol a credential that signs in to a privileged console.
        authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
        timeout: CHALLENGE_TTL_MS,
        attestation: "none",
        // BOUNDED BY THE BROWSER'S OWN CEILING: past 64 entries the browser refuses the whole ceremony
        // with a RangeError before any authenticator is consulted. An unbounded list would be a
        // permanent-lockout path rather than a blemish: enrolment is also what mints a fresh
        // recovery-code set, so an account over the ceiling would spend a break-glass code on every
        // sign-in and replace none of them.
        excludeCredentials: excludeCredentialsFor(existing).map((c) => ({ type: "public-key", id: c.credentialId, ...(c.transports.length > 0 ? { transports: c.transports } : {}) })),
      };
      return { ok: true, publicKey, challengeScope: scope };
    } catch (e) {
      const res = this.coarsePasskeyError("register/begin", e);
      await recordCeremonyError(this.state.storage, "register/begin", e instanceof PasskeyError ? e.reason : null, res.errorId);
      return res;
    }
  }

  // passkeyRegisterFinish verifies the attestation and binds a credential to a PROVEN, AUTHORISED email,
  // then BOOTSTRAPS the first registrant to Owner (bootstrap path only). The account-takeover fix lives
  // here: it does NOT bind to the client-supplied email; it first resolves the authorised path
  // (resolveRegistrationAuthorisation: bootstrap / invite / self-add) and derives the BOUND email from the
  // proof (the client email for bootstrap/self-add where it must match the proven email; the INVITE'S email
  // for the invite path), refusing any unauthorised registration with a coarse "forbidden" BEFORE any
  // challenge consume, verification or write. It then loads + single-use CONSUMES the bound-email challenge,
  // runs the REAL verifyRegistration (clientData type/origin, challenge, attestationObject fmt none,
  // rpIdHash, UP flag, UV flag, COSE key parse), refuses a credential id already registered, refuses
  // binding to an email that already has credentials UNLESS this is the self-add of that email's own owner
  // (allowExistingCreds), persists the PasskeyCred + PasskeyUser, consumes the invite (invite path) on
  // success, and ONLY on the bootstrap path writes the Owner `role:` entry. The verified identity is the
  // BOUND email; the response carries it plus whether the caller was bootstrapped.
  async passkeyRegisterFinish(
    body: { email?: unknown; credential?: unknown; rpId?: unknown; origin?: unknown; displayName?: unknown; inviteToken?: unknown; authMethod?: unknown; authEmail?: unknown; bootstrapAuthorised?: unknown; sourceIp?: unknown },
  ): Promise<
    | { ok: true; email: string; bootstrapped: boolean; role: Role; recoveryCodes: string[]; recoveryCodesPending: boolean }
    | { ok: false; reason: string; errorId?: string }
  > {
    // The coarse source IP for the bootstrap-consumed + recovery-codes-generated audit events on this
    // enrolment path, forwarded by the router from the edge CF-Connecting-IP (server-read, never a client
    // field: handlePasskey strips any inbound sourceIp and sets it from the verified edge header). Null when absent.
    const sourceIp = typeof body.sourceIp === "string" && body.sourceIp.length > 0 ? body.sourceIp : null;
    const clientEmail = this.normaliseEmail(body.email);
    const rpId = this.passkeyRpId(body.rpId);
    const origin = this.passkeyOrigin(body.origin);
    if (!clientEmail) return { ok: false, reason: "bad_request" };
    // G014: as in begin - an absent rp.id/origin is the SERVER's deploy config, reported to the user as their
    // own bad request. Counted here, unchanged on the wire.
    if (!rpId || !origin) {
      await recordCeremonyFault(this.state.storage, "passkey-rpid-absent");
      return { ok: false, reason: "bad_request" };
    }
    if (typeof body.credential !== "object" || body.credential === null) return { ok: false, reason: "bad_request" };
    try {
      const now = Date.now();
      // PROVE AUTHORISATION FIRST and derive the BOUND email. A coarse "forbidden" is returned for any
      // unauthorised registration BEFORE the challenge is consumed or the attestation is verified, so an
      // attacker registering for someone else's email (no invite, no matching session) gets a 403 with NO
      // credential stored and NO session minted (sessionCookieForFinish mints only on ok:true).
      const auth = await this.resolveRegistrationAuthorisation(clientEmail, body, now);
      if (auth === null) {
        await recordCeremonyFault(this.state.storage, "passkey-register-forbidden");
        return { ok: false, reason: "forbidden" };
      }
      const email = auth.boundEmail;

      const cred = body.credential as Record<string, unknown>;
      const resp = (typeof cred.response === "object" && cred.response !== null ? cred.response : {}) as Record<string, unknown>;
      const clientDataJSON = this.decodeB64urlField(resp.clientDataJSON, "clientDataJSON", PASSKEY_CLIENT_DATA_MAX);
      const attestationObject = this.decodeB64urlField(resp.attestationObject, "attestationObject", PASSKEY_ATT_OBJ_MAX);
      // Consume the BOUND-email challenge (single-use); a missing/expired one is a coarse "challenge"
      // rejection. The challenge was issued by begin under `reg:<boundEmail>`, so a finish whose proof
      // resolves to a different bound email than the begin did finds no challenge and is rejected.
      const expectedChallenge = await this.consumeChallenge(`reg:${email}`, now);
      if (expectedChallenge === null) return { ok: false, reason: "challenge" };
      const verified: VerifiedRegistration = await verifyRegistration({
        clientDataJSON,
        attestationObject,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRpId: rpId,
      });
      const credIdB64 = b64urlEncode(verified.credentialId);
      // Reject a credential id already registered (to anyone): a credential id is globally unique, so a
      // collision is either a replay or a hostile reuse, never a legitimate fresh enrolment.
      const dup = await this.getPasskeyCred(credIdB64);
      if (dup !== undefined) return { ok: false, reason: "already_registered" };
      // HARD RULE: refuse binding a credential to an email that ALREADY has credentials, UNLESS this is the
      // self-add of that email's own owner (allowExistingCreds). This is re-checked HERE, at the write
      // point, against the live store (not just at authorisation time), so a race that enrolled a first key
      // between begin and finish cannot slip a second binding past the rule on a non-self-add path.
      if (!auth.allowExistingCreds) {
        const existingForEmail = await this.listPasskeyCredsForEmail(email);
        if (existingForEmail.length > 0) {
          // G005: an INVITE redeemed for an address that is ALREADY enrolled. The invitee completes the whole
          // WebAuthn gesture and is answered with the coarse "forbidden": from their side the link is simply
          // broken, and the admin who sent it can see nothing. The remedy is different from every other invite
          // refusal (they do not need an invite at all -- they already have a passkey and should just sign in,
          // or add a SECOND key from their own account), so it is its own class. Count only: never the address.
          if (auth.path === "invite") await this.recordAuthSignal("invite-redeem-refused-already-enrolled");
          return { ok: false, reason: "forbidden" };
        }
      }
      // Advisory transport hints the client reported (bounded list of short tokens); used only to
      // populate the next allow/exclude list. Never trusted as authority.
      const transports = this.passkeyTransports(resp.transports);
      // Open the witness epoch BEFORE this credential's createdAt is TAKEN, so createdAt is at or after it.
      // That ordering is what makes "created after the witness opened, still carries no assertion stamp" mean
      // "never demonstrated" rather than "possibly older than the record-keeping". Registration itself is a
      // proof of possession, but deliberately does NOT set lastAssertedAt: the whole failure mode this witness
      // exists for is a credential that was provably real at enrolment and is dead now, so stamping at
      // enrolment would make every orphaned key look demonstrated.
      await this.ensurePasskeyWitnessSince();
      const record: PasskeyCred = {
        credentialId: credIdB64,
        email,
        cosePublicKey: b64urlEncode(verified.cosePublicKey),
        alg: verified.alg,
        signCount: verified.signCount,
        transports,
        aaguid: b64urlEncode(verified.aaguid),
        createdAt: nowMillisISO(),
      };
      await this.putPasskeyCred(record);
      // The registration succeeded: consume the invite (invite path) so the link works exactly once. Done
      // AFTER the credential is stored, so a failed/fumbled finish never burns a legitimate invite; the
      // delete is single-use (a concurrent replay finds it gone). Best-effort: a missing token here only
      // means it was already consumed.
      if (auth.path === "invite" && auth.inviteToken !== undefined) {
        await this.consumeInvite(auth.inviteToken, now);
      }
      // Same single-use discipline for the EMAIL-LINK bootstrap: consume the first-Owner invite slot only
      // after the credential is stored. Best-effort (the bootstrapConsumed latch below closes the path
      // regardless); a missing slot here only means a concurrent finish already consumed it.
      if (auth.path === "bootstrap" && auth.bootstrapInviteToken !== undefined) {
        await this.consumeBootstrapInvite(auth.bootstrapInviteToken, now);
      }
      // Upsert the user record (create on first credential; leave an existing one as-is).
      const userKey = `${PASSKEY_USER_PREFIX}${email}`;
      const existingUser = await this.state.storage.get<PasskeyUser>(userKey);
      if (existingUser === undefined) {
        const user: PasskeyUser = { email, displayName: this.passkeyDisplayName(body.displayName, email), createdAt: nowMillisISO() };
        await this.state.storage.put(userKey, user);
      }
      // FIRST-USER BOOTSTRAP: ONLY on the bootstrap path (resolveRegistrationAuthorisation already proved
      // the role table was empty AND a valid ADMIN_TOKEN was presented). The empty-table check + the Owner
      // write are in this same single-threaded DO call, so the first-Owner claim is race-free. The Owner
      // entry is keyed on the passkey caller's STABLE subject (passkeySubject(email)), matching the
      // subject-keyed table the rest of the engine authorises on. On every OTHER path no Owner is written
      // here: an invite/self-add registrant RESOLVES (and binds-on-first-auth) their role from the
      // subject-keyed table given their passkey subject + email (a pending email invite binds to their
      // subject, else the viewer default), so passkey registration never silently elevates a non-bootstrap
      // user. roleTableIsEmpty is re-checked here too, so a concurrent first registration cannot mint two
      // Owners.
      const subject = passkeySubject(email);
      let bootstrapped = false;
      let role: Role = "viewer";
      // BELT-AND-BRACES over the empty-table check, re-checked HERE at the write point against the live
      // latch (resolveRegistrationAuthorisation already refused a consumed bootstrap, so this is defence in
      // depth): once the first Owner has EVER been claimed, this registration mints NO Owner even if the
      // table is momentarily empty. The credential is still stored (the user can sign in); they simply
      // resolve to the least-privilege viewer until an Owner grants them a role.
      const alreadyConsumed = await this.getBootstrapConsumed();
      if (auth.path === "bootstrap" && (await this.roleTableIsEmpty()) && !alreadyConsumed) {
        const entry: RoleEntry = { subject, email, role: "owner", grantedBy: "bootstrap", grantedAt: nowMillisISO() };
        await this.state.storage.put(roleSubjectKey(subject), entry);
        // Latch the one-way bootstrap-consumed flag (and audit the one-time event) the MOMENT this first
        // Owner row is created, so no later bootstrap (Access or passkey) can mint a second Owner. The actor
        // is the bootstrapping email; the method is passkey (this is the WebAuthn enrolment path). The
        // ADMIN_TOKEN bearer authorised the bootstrap, but the resulting attributable Owner is this email.
        await this.markBootstrapConsumed(email, "passkey", sourceIp);
        bootstrapped = true;
        role = "owner";
      } else {
        // G005: the SILENT DEMOTION. A caller who came in on the BOOTSTRAP path and reaches this branch was
        // authorised for the first-Owner enrolment at BEGIN and is being refused the Owner mint at FINISH,
        // because the latch was consumed (or a row landed) in the window between the two. Their credential IS
        // stored and they CAN sign in -- as a viewer. That is exactly the "I ran the bootstrap and I am only a
        // viewer" ticket, and it recorded nothing at all. The demotion is correct (never mint a second Owner);
        // recording it is what makes it explicable. Never the address, the subject or the credential.
        if (auth.path === "bootstrap") await this.recordAuthSignal("bootstrap-claim-demoted");
        // Resolve + bind the invitee's grant by their passkey subject (an Owner's prior email invite binds
        // here, so the just-registered invitee immediately resolves the granted role on this same call).
        const mine = await this.resolveBoundEntry(subject, email);
        role = this.effectiveRole(mine, now);
      }
      // RECOVERY CODES: a completed enrolment mints a fresh single-use set for THIS email and returns the
      // plaintext ONCE for display (the router passes it straight back to the client; it is never stored or
      // returned again). A bootstrap or invite enrolment has NO prior record to protect, so it mints straight
      // to live exactly as before (generateRecoveryFor: persists only the salted hashes, records the Owner
      // break-glass-in-place acknowledgement when the email is an Owner, and audits the generation).
      //
      // STAGED-RECOVERY-CODES-CONFIRM-GATE: an enrolment that runs while a LIVE record ALREADY
      // exists is a self-add -- which includes the forced re-enrolment a recovery-code sign-in requires. That
      // caller's old codes still worked a moment ago; minting straight to live would kill them the instant
      // this call returns, before the console's save-confirm panel has even rendered, so a closed tab or a
      // crashed browser between here and the operator ticking "I have saved my recovery codes" would leave
      // them with the ONE code they just spent to get in and nothing else. Stage it instead: the fresh
      // plaintext is returned for display exactly as before, but the live record is untouched until the
      // console calls POST /admin/auth/recovery-codes/confirm (recoveryCodesPending tells it to). An
      // abandoned staged offer costs nothing -- the old set just keeps working.
      const hadLiveRecord = (await this.getRecoveryRecord(email)) !== null;
      let recoveryCodes: string[] = [];
      let recoveryCodesPending = false;
      try {
        if (hadLiveRecord) {
          recoveryCodes = await this.generateRecoveryStaged(email, "passkey", sourceIp);
          recoveryCodesPending = true;
        } else {
          recoveryCodes = await this.generateRecoveryFor(email, "passkey", sourceIp);
        }
      } catch (e) {
        log("error", `recovery-code generation skipped on enrolment (non-critical, enrolment succeeded): ${(e as Error).message}`);
        // G039: the "I never got recovery codes at enrolment" ticket. The user is now enrolled with an EMPTY
        // set (their only break-glass path if the passkey is lost) and NOTHING said so - the exception went to
        // Workers Logs, which remote support structurally cannot read. Count the class; never the message.
        await recordCeremonyFault(this.state.storage, "recovery-codes-generation-failed");
      }
      return { ok: true, email, bootstrapped, role, recoveryCodes, recoveryCodesPending };
    } catch (e) {
      const res = this.coarsePasskeyError("register/finish", e);
      await recordCeremonyError(this.state.storage, "register/finish", e instanceof PasskeyError ? e.reason : null, res.errorId);
      return res;
    }
  }

  // passkeyTransports bounds the advisory transport hint list the client reports at registration: keep
  // only the known WebAuthn transport tokens, deduped, capped to a handful. An unknown token is dropped
  // (forward-compatible, never stored as authority). A non-array yields [].
  passkeyTransports(raw: unknown): string[] {
    if (!Array.isArray(raw)) return [];
    const known = new Set(["usb", "nfc", "ble", "internal", "hybrid", "smart-card"]);
    const seen = new Set<string>();
    const out: string[] = [];
    for (const t of raw) {
      if (typeof t !== "string" || !known.has(t) || seen.has(t)) continue;
      seen.add(t);
      out.push(t);
      if (out.length >= 8) break;
    }
    return out;
  }

  };
}
