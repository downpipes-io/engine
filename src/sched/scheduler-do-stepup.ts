// The STEP-UP RE-AUTH subsystem (ASVS V7.5.1 / V7.5.3). StepUpMixin layers over a
// base whose `this` is SchedulerDOSurface, so the ceremony verifies assertions through `this`
// (this.listPasskeyCredsForEmail / this.getPasskeyCred / this.consumeChallenge / this.sessionSigningKey)
// and stores under the stepup: challenge scope and STEPUP_TOKEN_PREFIX token keyspace. The single-use
// challenge, the UV-required assertion, the subject-bound one-shot token and the fresh-session-or-token
// check apply consistently across the composed class. The mixin is a leaf the
// final SchedulerDO assembly depends on, never the reverse (madge 0 cycles).

import type { AuthMethod } from "../admin/identity.ts";
import { allowCredentialsFor, CHALLENGE_TTL_MS, loginChallengeId, type PasskeyChallenge, PasskeyError, randomChallengeB64, StoredKeyCorruptError, verifyAssertion } from "../admin/passkey.ts";
import { STEPUP_FRESH_MS, STEPUP_TOKEN_TTL_MS, verifySessionClassified } from "../admin/session.ts";
import { b64urlDecode, b64urlEncode } from "../crypto/bytes.ts";
import { recordCeremonyError, recordCeremonyFault } from "./sched-fault-ledger.ts";
import {
  PASSKEY_AUTH_DATA_MAX,
  PASSKEY_CHALLENGE_PREFIX,
  PASSKEY_CLIENT_DATA_MAX,
  PASSKEY_CRED_ID_MAX,
  PASSKEY_LOGIN_CHALLENGE_CAP,
  PASSKEY_SIG_MAX,
  type SchedulerDOCtor,
  STEPUP_TOKEN_PREFIX,
} from "./scheduler-do-base.ts";

export function StepUpMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ===================== STEP-UP RE-AUTH (ASVS V7.5.1 / V7.5.3) ==========================================
    // A sensitive action (recovery-code regen, self-add passkey, keys.ceremony, posture.riskaccept,
    // restore-approve) requires a FRESH re-authentication so a STALE ambient session cannot perform it. The
    // proof is EITHER (a) a recently-authenticated PASSKEY session - iat within STEPUP_FRESH_MS, which covers a
    // just-logged-in passkey session AND a recovery-code sign-in (the break-glass alternate factor) - OR (b) a
    // single-use, challenge-bound, UV-required passkey assertion that mints a one-shot step-up token. An OIDC
    // or SAML session is treated as single-factor and needs (b); see stepUpCheck (ASVS V6.8.4).
    // The router's requireStepUp orchestrates the check; the bare-token + Access methods are exempt (there).


    // sweepStepUpChallenges bounds the stepup: challenge family exactly as login challenges are bounded
    // (sweep expired, then evict oldest over the cap), run before minting a new step-up challenge.
    async sweepStepUpChallenges(now: number): Promise<void> {
      const prefix = `${PASSKEY_CHALLENGE_PREFIX}stepup:`;
      const map = await this.state.storage.list<PasskeyChallenge>({ prefix });
      const live: Array<{ key: string; createdAt: number }> = [];
      for (const [key, rec] of map) {
        const expired = !rec || typeof rec.expiresAt !== "number" || rec.expiresAt <= now;
        if (expired) {
          await this.state.storage.delete(key);
          continue;
        }
        live.push({ key, createdAt: typeof rec.createdAt === "number" ? rec.createdAt : 0 });
      }
      if (live.length <= PASSKEY_LOGIN_CHALLENGE_CAP) return;
      live.sort((a, b) => a.createdAt - b.createdAt);
      for (let i = 0; i < live.length - PASSKEY_LOGIN_CHALLENGE_CAP; i++) await this.state.storage.delete(live[i]!.key);
      // A LIVE (unexpired) step-up challenge evicted by the cap makes the caller's later finish fail
      // with the generic "challenge" reason, indistinguishable from a TTL expiry - the flood tell would be invisible.
      await recordCeremonyFault(this.state.storage, "passkey-challenge-evicted");
    }

    // stepUpBegin issues a WebAuthn assertion challenge for the AUTHENTICATED caller's OWN registered passkeys
    // (scoped under stepup:<id> so it never collides with login:, and so sweepAndBoundLoginChallenges never
    // evicts it). A caller with no email or no passkey gets ok:false - the router exempts the bare-token method,
    // so this is reached only for a cookie caller; a cookie caller with no passkey re-authenticates instead.
    async stepUpBegin(body: { rpId?: unknown }, caller: { email: string | null; subject: string | null } | null): Promise<{ ok: true; publicKey: unknown; challengeId: string } | { ok: false; reason: string }> {
      const email = caller?.email ? this.normaliseEmail(caller.email) : null;
      // A step-up demanded of a caller with NO enrolled passkey (an Access/IdP-only member reaching a
      // step-up-gated action) can NEVER be satisfied - the console simply keeps refusing the action - so this
      // is counted; the response is unchanged.
      if (!email) {
        await recordCeremonyFault(this.state.storage, "stepup-no-passkey");
        return { ok: false, reason: "no_passkey" };
      }
      const rpId = this.passkeyRpId(body.rpId);
      if (!rpId) {
        await recordCeremonyFault(this.state.storage, "passkey-rpid-absent");
        return { ok: false, reason: "bad_request" };
      }
      const now = Date.now();
      await this.sweepStepUpChallenges(now);
      const creds = await this.listPasskeyCredsForEmail(email);
      if (creds.length === 0) {
        await recordCeremonyFault(this.state.storage, "stepup-no-passkey");
        return { ok: false, reason: "no_passkey" };
      }
      const challenge = randomChallengeB64();
      const id = loginChallengeId();
      await this.putPasskeyChallenge(`stepup:${id}`, challenge, now);
      // BOUNDED at the MEASURED browser ceiling (see ALLOW_CREDENTIALS_MAX). Emitting every credential here
      // meant an account past 64 could not step up at all, and step-up gates the credential DELETE that is
      // the only way back under the ceiling. Ranked by most-recently-proven, so the window holds the
      // authenticators the caller is likeliest to be holding.
      const allowCredentials = allowCredentialsFor(creds).map((c) => ({ type: "public-key" as const, id: c.credentialId, ...(c.transports.length > 0 ? { transports: c.transports } : {}) }));
      return { ok: true, publicKey: { challenge, rpId, userVerification: "required", timeout: CHALLENGE_TTL_MS, allowCredentials }, challengeId: id };
    }

    // stepUpFinish verifies a fresh assertion (UV-required, single-use challenge) by ONE OF THE CALLER'S OWN
    // credentials, then mints a single-use step-up token bound to the caller's SUBJECT (consumed by stepUpCheck
    // at the gated action). The asserting credential MUST belong to the caller's own email (an unknown id or
    // another principal's credential is refused), so a step-up cannot be satisfied by a foreign assertion.
    // stepUpFinish WRAPS the ceremony so every refused step-up records one authn-failure row (V16.3.1). The
    // impl keeps its side effects and its externally-visible behaviour byte-for-byte: the wire reasons, the
    // opaque errorId, the ceremony-fault counters and the response shape are untouched, and the recorder runs
    // AFTER the impl has returned, so no branch of the impl gains a step another lacks.
    //
    // THIS IS THE ONLY AUTHN FAILURE IN THE ENGINE WITH A REAL ACTOR TO NAME, and that is the whole reason it
    // is worth a row. Every other one -- passkey login, SAML ACS, OIDC callback -- is an unauthenticated
    // ceremony where nothing has verified who the caller is, so the actor fields are null by rule. Here the
    // caller's SESSION verified them independently of the assertion that just failed. And step-up gates the
    // credential delete and the dual-control owner actions, so a run of failures here is not a stranger
    // guessing at the front door, it is hands on a keyboard inside a live session.
    //
    // WHAT IS DELIBERATELY NOT AUDITED. no_identity has, by definition, no actor to attribute, and a row that
    // named nobody would say less than the ceremony-fault counters already do. bad_request is a malformed body
    // or an unusable rp.id / origin (a server-side deploy-config fault, counted as passkey-rpid-absent), which
    // is not a failed authentication. Every OTHER reason is audited, including any a later author adds, so the
    // default for an unclassified new failure is recorded rather than silent.
    async stepUpFinish(body: { challengeId?: unknown; credential?: unknown; rpId?: unknown; origin?: unknown }, caller: { email: string | null; subject: string | null; method?: AuthMethod; sourceIp?: string | null } | null): Promise<{ ok: true; stepUpToken: string } | { ok: false; reason: string; errorId?: string }> {
      const r = await this.stepUpFinishImpl(body, caller);
      if (!r.ok && r.reason !== "no_identity" && r.reason !== "bad_request") {
        await this.appendAuthnFailureAudit({
          ceremony: "step-up",
          // The actor's OWN sign-in method, not the factor that failed. The factor is what ceremony says: a
          // step-up is always a passkey assertion, demanded of a caller whose session may have been minted by
          // Access, OIDC or SAML. Recording the ceremony's factor here would erase which of those it was.
          actorMethod: caller?.method ?? "passkey",
          actorSubject: caller?.subject ?? null,
          actorEmail: caller?.email !== null && caller?.email !== undefined ? this.normaliseEmail(caller.email) : null,
          sourceIp: caller?.sourceIp ?? null,
        });
      }
      return r;
    }
    async stepUpFinishImpl(body: { challengeId?: unknown; credential?: unknown; rpId?: unknown; origin?: unknown }, caller: { email: string | null; subject: string | null } | null): Promise<{ ok: true; stepUpToken: string } | { ok: false; reason: string; errorId?: string }> {
      const email = caller?.email ? this.normaliseEmail(caller.email) : null;
      const subject = caller && typeof caller.subject === "string" && caller.subject.length > 0 ? caller.subject : null;
      if (!email || !subject) return { ok: false, reason: "no_identity" };
      const rpId = this.passkeyRpId(body.rpId);
      const origin = this.passkeyOrigin(body.origin);
      if (!rpId || !origin) return { ok: false, reason: "bad_request" };
      if (typeof body.challengeId !== "string" || body.challengeId.length === 0 || body.challengeId.length > 128) return { ok: false, reason: "bad_request" };
      if (typeof body.credential !== "object" || body.credential === null) return { ok: false, reason: "bad_request" };
      try {
        const cred = body.credential as Record<string, unknown>;
        const rawIdBytes = this.decodeB64urlField(cred.id, "credential id", PASSKEY_CRED_ID_MAX);
        const credIdB64 = b64urlEncode(rawIdBytes);
        const record = await this.getPasskeyCred(credIdB64);
        if (record === undefined || record.email !== email) {
          await recordCeremonyFault(this.state.storage, "stepup-unknown-credential");
          return { ok: false, reason: "unknown_credential" };
        }
        const resp = (typeof cred.response === "object" && cred.response !== null ? cred.response : {}) as Record<string, unknown>;
        const clientDataJSON = this.decodeB64urlField(resp.clientDataJSON, "clientDataJSON", PASSKEY_CLIENT_DATA_MAX);
        const authenticatorData = this.decodeB64urlField(resp.authenticatorData, "authenticatorData", PASSKEY_AUTH_DATA_MAX);
        const signature = this.decodeB64urlField(resp.signature, "signature", PASSKEY_SIG_MAX);
        const now = Date.now();
        const expectedChallenge = await this.consumeChallenge(`stepup:${body.challengeId}`, now);
        if (expectedChallenge === null) return { ok: false, reason: "challenge" };
        let storedCose: Uint8Array;
        try {
          storedCose = b64urlDecode(record.cosePublicKey);
        } catch (e) {
          // The engine's OWN stored credential is corrupt; the caller is told `bad_request`. Count the
          // real cause (the wire reason is deliberately unchanged).
          await recordCeremonyFault(this.state.storage, "passkey-stored-key-corrupt");
          throw new StoredKeyCorruptError(`stepup: stored COSE key is not valid base64url (${(e as Error).message})`);
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
        // Advanced signCount + the usability witness, one unconditional put on the success side only. A
        // step-up assertion is a proof of possession of exactly the same strength as a login assertion, and it
        // is the one an Owner who signs in through Access will produce, so omitting it here would leave the
        // witness blind to the very population it most needs to cover. See recordPasskeyAssertion for why the
        // old counter-conditional write is not kept.
        await this.recordPasskeyAssertion(record, result.newSignCount, "stepup");
        const stepUpToken = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
        await this.state.storage.put(`${STEPUP_TOKEN_PREFIX}${subject}:${stepUpToken}`, { expiresAt: now + STEPUP_TOKEN_TTL_MS } satisfies { expiresAt: number });
        return { ok: true, stepUpToken };
      } catch (e) {
        const res = this.coarsePasskeyError("stepup/finish", e);
        await recordCeremonyError(this.state.storage, "stepup/finish", e instanceof PasskeyError ? e.reason : null, res.errorId, e instanceof StoredKeyCorruptError ? "stored-key-corrupt" : undefined);
        return res;
      }
    }

    // stepUpCheck (router-internal): is a step-up satisfied for the cookie session presenting `token`? The DO
    // holds the signing key, so it re-verifies the session to read iat, method and subject. Satisfied when
    // (a) the session is a PASSKEY session authenticated within STEPUP_FRESH_MS (a UV WebAuthn login, or the
    // recovery-code sign-in, which mints method "passkey"), OR (b) a valid single-use step-up token bound to
    // that subject is presented (and CONSUMED here). An OIDC or SAML session never satisfies on recency alone
    // (ASVS V6.8.4): the engine cannot verify what factor the IdP used, and the session iat is the engine's
    // own callback instant, not the IdP's auth_time, so a silently reused IdP SSO session would otherwise
    // read as a fresh strong factor. Such a session is treated as single-factor, the minimum strength, and
    // must present a passkey assertion. The ONE exception is purpose "enrol-passkey": an SSO member with no
    // passkey yet has nothing to assert with, so a fresh IdP sign-in is accepted to enrol the first one.
    // Fail-closed otherwise.
    async stepUpCheck(body: { token?: unknown; stepUpToken?: unknown; purpose?: unknown }): Promise<{ satisfied: boolean }> {
      if (typeof body.token !== "string" || body.token.length === 0) return { satisfied: false };
      const key = await this.sessionSigningKey();
      const now = Date.now();
      // The step-up check re-verifies the SAME cookie, so it hits the SAME fault classes, and without recording
      // them "every sensitive action keeps demanding a passkey and never accepts it" is a step-up loop whose
      // cause (an idle-expired cookie, a MAC mismatch, a pre-upgrade token shape) would go unrecorded.
      // The fail-closed { satisfied: false } and the client-facing 401 are unaffected.
      const classified = await verifySessionClassified(key, body.token, now);
      if ("fault" in classified) {
        await this.recordAuthSignalThrottled(classified.fault);
        return { satisfied: false };
      }
      const res = classified;
      // Two purposes let a FRESH oidc/saml session pass on recency: enrolling a first passkey (the member has
      // nothing to assert with yet), and ending the member's OWN sessions (V7.5.2 asks for "at least one
      // factor" again, and a sign-in at the identity provider within STEPUP_FRESH_MS is that factor; the
      // action reaches no session but the caller's own).
      if (now - res.iat < STEPUP_FRESH_MS && (res.method === "passkey" || body.purpose === "enrol-passkey" || body.purpose === "end-own-session")) return { satisfied: true };
      if (typeof body.stepUpToken === "string" && body.stepUpToken.length > 0 && body.stepUpToken.length <= 64) {
        const tkKey = `${STEPUP_TOKEN_PREFIX}${res.subject}:${body.stepUpToken}`;
        const rec = await this.state.storage.get<{ expiresAt: number }>(tkKey);
        if (rec !== undefined) {
          await this.state.storage.delete(tkKey); // single-use: consume on check
          if (typeof rec.expiresAt === "number" && rec.expiresAt > now) return { satisfied: true };
        }
      }
      return { satisfied: false };
    }
  };
}
