// engine-sys-struct-06 / engine-sys-arch-01 (god-module split): the invite + login half of the WebAuthn /
// passkey subsystem (the first-Owner bootstrap-invite slot, the single-use teammate invites, and the login
// assertion ceremony) split out of scheduler-do-passkey.ts so neither file exceeds the module-size
// guardrail. This is the sibling sub-mixin of PasskeyMixin (the registration ceremony + the shared input-
// bounding/coarse-error helpers stay there); both layer over a base whose `this` is SchedulerDOSurface, so
// the login ceremony still single-use consumes its challenge through this.consumeChallenge and bounds its
// fields through this.decodeB64urlField / this.passkeyRpId (which live on the registration sub-mixin) with
// the SAME dispatch and `this` binding the single class had. Dispatch is byte-identical; no storage key,
// route, status code, response body or auth gate changed. A leaf the assembly depends on, never the reverse.

import { BOOTSTRAP_INVITE_TTL_MS, type BootstrapInvite, CHALLENGE_TTL_MS, loginChallengeId, PasskeyError, type PasskeyInvite, randomChallengeB64, randomInviteToken, StoredKeyCorruptError, verifyAssertion } from "../admin/passkey.ts";
import { b64urlDecode, b64urlEncode, constantTimeEqual } from "../crypto/bytes.ts";
import { recordCeremonyError, recordCeremonyFault } from "./sched-fault-ledger.ts";
import { BOOTSTRAP_INVITE_KEY, PASSKEY_AUTH_DATA_MAX, PASSKEY_CLIENT_DATA_MAX, PASSKEY_CRED_ID_MAX, PASSKEY_INVITE_PREFIX, PASSKEY_SIG_MAX, type SchedulerDOCtor } from "./scheduler-do-base.ts";

export function PasskeyInvitesMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
  // ---- FIRST-OWNER bootstrap invite (the email-link bootstrap) -----------------------------------
  // One fixed slot (BOOTSTRAP_INVITE_KEY): minting overwrites, so at most ONE link is ever live and a
  // re-send invalidates the previous link. Mint/peek/consume all run inside this single-threaded DO, so
  // the empty-table + latch checks and the single-use delete are race-free, exactly like the token
  // bootstrap and the teammate invite.

  // mintBootstrapInvite mints (or REPLACES) the single first-Owner invite for the deploy-time-pinned
  // owner email. It refuses (null) unless the role table is EMPTY and the bootstrap latch is unset: once
  // any Owner exists (or ever existed), no first-Owner link can be minted again. The email was validated
  // by the router from env (never a client field) and is re-normalised here at the authority boundary.
  async mintBootstrapInvite(rawEmail: unknown, now: number): Promise<string | null> {
    // G005: three DISTINCT refusals collapse into one silent null, and the route's no-oracle 200 means the
    // operator is told nothing either. "I press 'email the owner a link' and nothing ever arrives" is the most
    // common bootstrap ticket in the book, and the pack carried NOTHING -- not even that the button was pressed.
    // The client response and the no-oracle property are UNCHANGED: these are counters, recorded engine-side.
    // Never the address, the token, or the link.
    const email = this.normaliseEmail(rawEmail);
    if (email === null) {
      await this.recordAuthSignal("invite-mint-refused-bad-email");
      return null;
    }
    if (!(await this.roleTableIsEmpty())) {
      await this.recordAuthSignal("invite-mint-refused-role-exists");
      return null;
    }
    if (await this.getBootstrapConsumed()) {
      // The one-shot latch is spent: no first-Owner link can EVER be minted again. The button is permanently
      // inert and says so to no one.
      await this.recordAuthSignal("invite-mint-refused-latch-consumed");
      return null;
    }
    const token = randomInviteToken();
    const rec: BootstrapInvite = { token, email, createdAt: now, expiresAt: now + BOOTSTRAP_INVITE_TTL_MS };
    await this.state.storage.put(BOOTSTRAP_INVITE_KEY, rec);
    return token;
  }

  // bootstrapInviteMatches loads the single slot and validates a presented token against it: present,
  // unexpired, and token-equal (constant-time over the encoded bytes, so a comparison cannot leak a
  // prefix). Returns the BOUND email or null. Shared by peek (authorisation) and consume (single-use).
  async bootstrapInviteMatches(token: string, now: number): Promise<string | null> {
    if (typeof token !== "string" || token.length === 0 || token.length > 512) return null;
    const rec = await this.state.storage.get<BootstrapInvite>(BOOTSTRAP_INVITE_KEY);
    if (rec === undefined || typeof rec.token !== "string") return null;
    if (typeof rec.expiresAt !== "number" || rec.expiresAt <= now) return null;
    // engine-src-043-01: compare the presented and stored tokens with the shared constant-time helper
    // (it drives the platform crypto.subtle.timingSafeEqual primitive, which requires equal-length
    // buffers and throws on a mismatch). constantTimeEqual checks length equality first and returns
    // false on a divergent length before the primitive is called, so the length is never a timing leak.
    const enc = new TextEncoder();
    if (!constantTimeEqual(enc.encode(token), enc.encode(rec.token))) {
      // G005: the ONE invite refusal where a record was FOUND, is live, and the presented secret is simply not
      // it. The bootstrap slot is a single fixed key that minting OVERWRITES, so re-sending the first-Owner
      // link silently invalidates every earlier one: the owner clicks the link in the older email and is told
      // it is invalid, while a perfectly valid invite sits in the slot. That is a different remedy (open the
      // newest email) from an absent or expired invite, and it was recorded nowhere. Never the token.
      await this.recordAuthSignal("invite-redeem-refused-token-mismatch");
      return null;
    }
    return this.normaliseEmail(rec.email);
  }

  // peekBootstrapInvite validates WITHOUT consuming (register/begin), so a fumbled ceremony leaves the
  // one-shot link intact for the real attempt, mirroring peekInvite.
  async peekBootstrapInvite(token: string, now: number): Promise<string | null> {
    return this.bootstrapInviteMatches(token, now);
  }

  // consumeBootstrapInvite validates and single-use DELETES the slot (register/finish, after a verified
  // ceremony). The delete happens before the email is returned, so the link authorises at most one
  // registration even under a replay; the bootstrapConsumed latch then closes the path independently.
  async consumeBootstrapInvite(token: string, now: number): Promise<string | null> {
    const email = await this.bootstrapInviteMatches(token, now);
    if (email === null) return null;
    await this.state.storage.delete(BOOTSTRAP_INVITE_KEY);
    return email;
  }

  // peekInvite loads a registration invite by token WITHOUT consuming it, returning the bound email when
  // the token exists and is unexpired, else null. register/begin uses it to learn the bound email to put in
  // the creation options (and to reject an unknown/expired token early); the actual single-use CONSUME
  // happens only on a successful register/finish (consumeInvite), so a begin that is never completed leaves
  // the one-shot invite intact for the real attempt.
  async peekInvite(token: string, now: number): Promise<string | null> {
    // G005: the register/BEGIN arm of the same three refusals ("the invite link does not work" is reported far
    // more often at begin than at finish, because that is where the user gives up). Same closed names, same
    // coarse client response.
    if (typeof token !== "string" || token.length === 0 || token.length > 512) {
      await this.recordAuthSignal("invite-redeem-refused-malformed");
      return null;
    }
    const rec = await this.state.storage.get<PasskeyInvite>(`${PASSKEY_INVITE_PREFIX}${token}`);
    if (rec === undefined) {
      await this.recordAuthSignal("invite-redeem-refused-absent");
      return null;
    }
    if (typeof rec.expiresAt !== "number" || rec.expiresAt <= now) {
      await this.recordAuthSignal("invite-redeem-refused-expired");
      return null;
    }
    const email = this.normaliseEmail(rec.email);
    return email;
  }

  // consumeInvite loads, single-use DELETES, and validates a registration invite by token, returning the
  // bound email or null. The delete happens BEFORE the email is returned, so an invite authorises at most
  // one registration even under a concurrent replay (the DO serialises its own storage). An absent, expired,
  // or malformed record returns null (the caller maps that to the coarse forbidden rejection).
  async consumeInvite(token: string, now: number): Promise<string | null> {
    // G005: every arm below returned the SAME null, which the caller maps to one coarse "forbidden" -- so a
    // malformed link, a link that was never minted, a link already used, and a link that EXPIRED were one
    // undiagnosable rejection. The expired case is the cruel one: the record is deleted-then-refused, so
    // afterwards NOTHING proves the invite ever existed and the customer is told their link is simply invalid.
    // Recorded BEFORE the delete. Counters only: never the token, never the bound address.
    if (typeof token !== "string" || token.length === 0 || token.length > 512) {
      await this.recordAuthSignal("invite-redeem-refused-malformed");
      return null;
    }
    const key = `${PASSKEY_INVITE_PREFIX}${token}`;
    const rec = await this.state.storage.get<PasskeyInvite>(key);
    if (rec === undefined) {
      await this.recordAuthSignal("invite-redeem-refused-absent");
      return null;
    }
    const expired = typeof rec.expiresAt !== "number" || rec.expiresAt <= now;
    if (expired) await this.recordAuthSignal("invite-redeem-refused-expired"); // BEFORE the burn
    await this.state.storage.delete(key); // single-use: delete first
    if (expired) return null;
    return this.normaliseEmail(rec.email);
  }

  // passkeyLoginBegin issues a login challenge and returns the request options for navigator.credentials
  // .get. The challenge is single-use, short-lived and scoped by a FRESH opaque id (passkeyChallenge:
  // login:<id>), because the asserting credential (and thus the email) is unknown until the finish; the
  // begin response echoes that challengeId, which the finish presents back. allowCredentials is always
  // left empty so the browser offers any resident passkey for this rp.id (usernameless flow, since
  // registration already sets residentKey:"preferred") - it is never scoped to a client-supplied email,
  // which would let an unauthenticated caller use its presence/absence as an account-enumeration oracle.
  // The challenge existing under a known id is what binds the later assertion to a server-issued challenge
  // regardless of which credential answers.
  async passkeyLoginBegin(
    body: { email?: unknown; rpId?: unknown },
  ): Promise<
    | { ok: true; publicKey: unknown; challengeId: string }
    | { ok: false; reason: string; errorId?: string }
  > {
    const rpId = this.passkeyRpId(body.rpId);
    // G014: an absent rp.id is the SERVER's deploy config (an unset/unparseable CONSOLE_ORIGIN after a host
    // change), reported to every user as their own bad request. This is the fleet-wide-lockout tell.
    if (!rpId) {
      await recordCeremonyFault(this.state.storage, "passkey-rpid-absent");
      return { ok: false, reason: "bad_request" };
    }
    try {
      const now = Date.now();
      // Bound the stored login-challenge set BEFORE minting a new one: sweep expired login challenges and,
      // if still over the cap, evict the oldest. A login/begin mints a challenge before any credential is
      // known, so an unauthenticated flood would otherwise grow DO storage unbounded (a matching finish,
      // which an attacker never sends, is the only other consumer). This keeps the family bounded.
      await this.sweepAndBoundLoginChallenges(now);
      const challenge = randomChallengeB64();
      const id = loginChallengeId();
      const scope = `login:${id}`;
      await this.putPasskeyChallenge(scope, challenge, now);
      // ANTI-ENUMERATION (ASVS V6.2.1/V6.3.8): allowCredentials is never derived from body.email. Doing so
      // would let an unauthenticated caller learn whether an arbitrary email has an enrolled passkey from
      // the response shape alone (non-empty vs empty) - the same class of leak resolveRegistrationAuthorisation
      // is deliberately careful to avoid on the register side. Always run the usernameless/discoverable-
      // credential flow instead; registration already sets residentKey:"preferred" for exactly this.
      const allowCredentials: Array<{ type: "public-key"; id: string; transports?: string[] }> = [];
      const publicKey = {
        challenge,
        rpId,
        // userVerification "required" (not "preferred"): the admin front door requires a PIN/biometric
        // on every sign-in, and verifyAssertion enforces the resulting UV flag.
        userVerification: "required",
        timeout: CHALLENGE_TTL_MS,
        allowCredentials,
      };
      return { ok: true, publicKey, challengeId: id };
    } catch (e) {
      const res = this.coarsePasskeyError("login/begin", e);
      await recordCeremonyError(this.state.storage, "login/begin", e instanceof PasskeyError ? e.reason : null, res.errorId);
      return res;
    }
  }

  // passkeyLoginFinish verifies the assertion and yields the verified identity (the credential's bound
  // email). It looks up the credential by the asserted id (an UNKNOWN id is the coarse
  // "unknown_credential" rejection, BEFORE any challenge consume so a probe for a valid id is not aided),
  // single-use CONSUMES the login challenge by the presented challengeId, runs the REAL verifyAssertion
  // (clientData type/origin, challenge, rpIdHash, UP flag, SIGNATURE over authenticatorData ||
  // SHA-256(clientDataJSON), CLONE DETECTION on signCount), and on success persists the advanced
  // signCount. The verified email is the credential's stored email; the response returns it for the
  // router to resolve the role from the same `role:` table the Access path uses.
  async passkeyLoginFinish(
    body: { challengeId?: unknown; credential?: unknown; rpId?: unknown; origin?: unknown },
  ): Promise<
    | { ok: true; email: string }
    | { ok: false; reason: string; errorId?: string }
  > {
    const rpId = this.passkeyRpId(body.rpId);
    const origin = this.passkeyOrigin(body.origin);
    if (!rpId || !origin) {
      await recordCeremonyFault(this.state.storage, "passkey-rpid-absent");
      return { ok: false, reason: "bad_request" };
    }
    if (typeof body.challengeId !== "string" || body.challengeId.length === 0 || body.challengeId.length > 128) {
      return { ok: false, reason: "bad_request" };
    }
    if (typeof body.credential !== "object" || body.credential === null) return { ok: false, reason: "bad_request" };
    try {
      const cred = body.credential as Record<string, unknown>;
      // The credential id the browser returns (rawId, base64url). Decode + bound it, then re-encode to the
      // canonical base64url storage key form so the lookup matches regardless of the client's spelling.
      const rawIdBytes = this.decodeB64urlField(cred.id, "credential id", PASSKEY_CRED_ID_MAX);
      const credIdB64 = b64urlEncode(rawIdBytes);
      // Look the credential up FIRST. An unknown id is rejected before the challenge is consumed, so a
      // probe with a random id neither consumes the challenge nor reveals timing about a valid id beyond
      // the membership fact (which an attacker cannot act on without the private key).
      const record = await this.getPasskeyCred(credIdB64);
      if (record === undefined) return { ok: false, reason: "unknown_credential" };
      const resp = (typeof cred.response === "object" && cred.response !== null ? cred.response : {}) as Record<string, unknown>;
      const clientDataJSON = this.decodeB64urlField(resp.clientDataJSON, "clientDataJSON", PASSKEY_CLIENT_DATA_MAX);
      const authenticatorData = this.decodeB64urlField(resp.authenticatorData, "authenticatorData", PASSKEY_AUTH_DATA_MAX);
      const signature = this.decodeB64urlField(resp.signature, "signature", PASSKEY_SIG_MAX);
      // Consume the login challenge by the presented id (single-use). A missing/expired one is "challenge".
      const now = Date.now();
      const expectedChallenge = await this.consumeChallenge(`login:${body.challengeId}`, now);
      if (expectedChallenge === null) return { ok: false, reason: "challenge" };
      // Decode the stored COSE key bytes; verifyAssertion re-parses + validates them through parseCoseKey
      // (a stored key is never trusted as pre-parsed). A stored record that somehow held an unparseable
      // key is a "bad_request" via the verifier, never a crash.
      let storedCose: Uint8Array;
      try {
        storedCose = b64urlDecode(record.cosePublicKey);
      } catch (e) {
        // G013: the ENGINE's own stored credential is corrupt, yet the wire reason is `bad_request` - so the
        // user is told they sent a bad request and blames their browser, and the edge's auth-signal records
        // passkey-bad-request. Count the real cause before re-throwing; the wire behaviour is unchanged.
        await recordCeremonyFault(this.state.storage, "passkey-stored-key-corrupt");
        throw new StoredKeyCorruptError(`passkey: stored COSE key is not valid base64url (${(e as Error).message})`);
      }
      const result = await verifyAssertion({
        clientDataJSON,
        authenticatorData,
        signature,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRpId: rpId,
        storedCosePublicKey: storedCose,
        storedSignCount: typeof record.signCount === "number" ? record.signCount : 0,
      });
      // Persist the advanced signCount (the clone-detection high-water mark) AND stamp the usability witness,
      // in one unconditional put, only AFTER a positive verification. Gating the witness write on
      // `result.newSignCount !== record.signCount` would be right for the counter but wrong for the witness,
      // because a platform passkey that never advances its counter would then produce a verified assertion
      // that left NO trace, which would let `passkeyOwnerEnrolled` count a dead credential as a live factor.
      // Writing on every success also keeps the fact honest in the other direction: a failed assertion still
      // writes nothing.
      await this.recordPasskeyAssertion(record, result.newSignCount, "login");
      return { ok: true, email: record.email };
    } catch (e) {
      const res = this.coarsePasskeyError("login/finish", e);
      // G013: the recentErrors ring classes an errorId from the COARSE wire reason, so the id a locked-out user
      // quotes for a corrupt STORED key read as `bad-request-shape` -- the class that says "the client sent
      // rubbish" about a fault that is entirely the engine's. The wire reason is unchanged; the CLASS is now the
      // truth, and the two are different facts on purpose.
      await recordCeremonyError(this.state.storage, "login/finish", e instanceof PasskeyError ? e.reason : null, res.errorId, e instanceof StoredKeyCorruptError ? "stored-key-corrupt" : undefined);
      return res;
    }
  }
  };
}
