// The recovery-codes subsystem: the ongoing admin sign-in break-glass (generate/regenerate/verify
// single-use recovery codes with a per-IP and per-email rate limiter). RecoveryMixin layers these over
// a base whose `this` is SchedulerDOSurface, so recover mints a session via `this.sessionSigningKey`
// and consults the role table through `this`.

import { type AuthMethod, passkeySubject, type Role } from "../admin/identity.ts";
import { CHALLENGE_TTL_MS, INVITE_TTL_MS, type PasskeyAssertionCeremony, type PasskeyChallenge, type PasskeyCred, type PasskeyInvite, randomInviteToken } from "../admin/passkey.ts";
import { fakeRecoveryRecord, generateRecoveryCodes, isRecoveryRecordShaped, isRecoverySigningKeyUsable, normaliseCode, RECOVERY_SIGNING_KEY_MIN_BYTES, type RecoveryBreakGlassReason, type RecoveryRecord, recoveryKeyProof, remainingCount, verifyCode } from "../admin/recovery.ts";
import { RECOVERY_CODES_LOW_THRESHOLD } from "../admin/recovery-constants.ts";
import { signSession } from "../admin/session.ts";
import { rosterRefusesEnrolment } from "../admin/signin-factors.ts";
import { b64urlDecode, b64urlEncode } from "../crypto/bytes.ts";
import { log } from "../log.ts";
import { recordAdminRefusal, recordAuthzRefusal, recordCeremonyFault } from "./sched-fault-ledger.ts";
import { PASSKEY_CHALLENGE_PREFIX, PASSKEY_CRED_PREFIX, PASSKEY_INVITE_PREFIX, PASSKEY_LOGIN_CHALLENGE_CAP, PASSKEY_SESSION_KEY_KEY, PASSKEY_WITNESS_SINCE_KEY, type RateWindow, RECOVERY_PREFIX, RECOVERY_RATE_MAX_PER_EMAIL, RECOVERY_RATE_MAX_PER_IP, RECOVERY_RATE_PREFIX, RECOVERY_RATE_WINDOW_MS, RECOVERY_SIGNING_KEY_KEY, RECOVERY_STAGED_PREFIX, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { nowMillisISO } from "./scheduler-helpers.ts";

export function RecoveryMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- Recovery codes (the ongoing admin-sign-in break-glass) ---------------------------
    // recovery.ts is the pure crypto core (generate/hash/verify/count); this DO owns the per-email record,
    // the hard rate limit, the session mint and the audit/alert side. The plaintext codes are returned to the
    // caller ONLY at generation and never stored, logged or returned again.

    // recoveryKey is the per-email storage key for a recovery record. The email MUST already be canonical
    // (the callers normalise it through normaliseEmail before building the key), so the key and the role-table
    // key are the one string.
    recoveryKey(canonicalEmail: string): string {
      return `${RECOVERY_PREFIX}${canonicalEmail}`;
    }

    // recoverySigningKey loads the HMAC key the recovery codes are hashed and verified under, materialising it
    // on first use. It is the recovery half of a key that used to be shared with sessions, and the split is the
    // whole fix for TERMINATE-ALL-DESTROYS-RECOVERY-CODES: terminateAllSessions DELETES the session
    // key to invalidate every outstanding token, and while the recovery hashes were computed under that same
    // key, the delete silently killed every banked recovery code in the account. The two secrets have opposite
    // lifetimes, so they are now two records.
    //
    // THE MIGRATION IS THE ADOPTION BELOW, and it re-hashes nothing. An account that predates this key has
    // recovery records whose HMACs were computed under the CURRENT session key bytes, so this copies those
    // exact bytes into the recovery record. Every stored hash keeps verifying unchanged: no record is
    // rewritten, no code is re-minted, and there is no window in which a banked code is dead. From that point
    // the two keys are independent and only an explicit regenerate replaces a code.
    //
    // WHY THE SESSION KEY IS READ FROM STORAGE AND NEVER THROUGH sessionSigningKey(): that accessor GENERATES
    // and persists a fresh key when the record is absent or corrupt (the G168 silent-regeneration arm). Calling
    // it here would let the adoption freeze a brand-new key that no stored hash was ever computed under, which
    // is the exact harm this fix exists to prevent, and it would do it durably. A direct read cannot.
    //
    // ORDERING (load-bearing, see terminateAllSessions): the adoption must run BEFORE any delete of the session
    // key. terminateAllSessions therefore calls this first and deletes second. If it is interrupted between the
    // two, the account keeps a working session key AND a materialised recovery key, so the worst outcome of an
    // interruption is that the sign-out did not happen, never that a factor was lost.
    //
    // A cold account with NO session key falls through to a fresh CSPRNG key. That is the honest answer in both
    // cases it can arise: a brand-new DO (which has no recovery record to invalidate), and an account that
    // already ran terminate-all under the old code (whose codes are already dead, and for which no key
    // anywhere can revive them). Both are recorded as closed auth signals so the pack can tell them apart.
    async recoverySigningKey(): Promise<Uint8Array> {
      const fromRecord = (rec: { key?: unknown } | undefined): Uint8Array | null => {
        if (rec !== undefined && typeof rec.key === "string" && rec.key.length > 0) {
          try {
            const bytes = b64urlDecode(rec.key);
            if (bytes.length >= RECOVERY_SIGNING_KEY_MIN_BYTES) return bytes;
          } catch {
            // fall through: an undecodable stored value is treated as absent
          }
        }
        return null;
      };
      // Fast path: the key is already materialised. A present, valid record is NEVER rewritten (rewriting it
      // would be the defect again, in slow motion), so the common case is one cheap read with no gate.
      const existing = fromRecord(await this.state.storage.get<{ key: string; createdAt: string }>(RECOVERY_SIGNING_KEY_KEY));
      if (existing !== null) return existing;
      // Not materialised yet: adopt-or-generate atomically, so two concurrent callers on a cold record cannot
      // each write a different key and leave hashes minted under the loser. Re-read inside the gate.
      return this.blockConcurrencyWhile(async () => {
        const reread = fromRecord(await this.state.storage.get<{ key: string; createdAt: string }>(RECOVERY_SIGNING_KEY_KEY));
        if (reread !== null) return reread;
        const sessionRec = await this.state.storage.get<{ key: string; createdAt?: string }>(PASSKEY_SESSION_KEY_KEY);
        const adopted = fromRecord(sessionRec);
        if (adopted !== null) {
          // sessionKeyCreatedAt is the ADOPTED key's OWN birth date, carried forward so the key-continuity
          // test survives the session key being deleted afterwards. The session key we are reading has
          // existed unbroken from that instant until now (a rotation in between would have stamped a later
          // createdAt on the record we just read), so EVERY recovery record generated at or after it was
          // minted under exactly these bytes. Without this the only way to date the adopted bytes is the
          // session key record itself, which terminateAllSessions deletes one line later, and a healthy
          // account would then read as "cannot prove a way back in" purely for having signed everyone out.
          await this.state.storage.put(RECOVERY_SIGNING_KEY_KEY, {
            key: b64urlEncode(adopted),
            createdAt: nowMillisISO(),
            adoptedFromSessionKey: true,
            ...(typeof sessionRec?.createdAt === "string" && sessionRec.createdAt.length > 0 ? { sessionKeyCreatedAt: sessionRec.createdAt } : {}),
          });
          await this.recordAuthSignal("recovery-signing-key-adopted");
          return adopted;
        }
        const fresh = crypto.getRandomValues(new Uint8Array(RECOVERY_SIGNING_KEY_MIN_BYTES));
        await this.state.storage.put(RECOVERY_SIGNING_KEY_KEY, { key: b64urlEncode(fresh), createdAt: nowMillisISO() });
        await this.recordAuthSignal("recovery-signing-key-generated");
        return fresh;
      });
    }

    // recoverySigningKeyHealth reports the PRESENCE, AGE and adequacy of the recovery HMAC key WITHOUT the key,
    // the recovery-side twin of sessionSigningKeyHealth. Since the split, the session key's health no longer
    // answers "can a banked recovery code still verify?", so the pack would otherwise have lost the P3
    // recovery-key-too-short signal it used to read off the session key. `materialised` false is not a fault: it
    // means no recovery operation has run on this DO yet, so the key is still to be adopted from the session
    // key on first use. Redaction-safe: booleans and an int age, NEVER the key bytes.
    async recoverySigningKeyHealth(): Promise<{ materialised: boolean; ageMs?: number; adequateLength?: boolean; adoptedFromSessionKey?: boolean }> {
      const rec = await this.state.storage.get<{ key?: string; createdAt?: string; adoptedFromSessionKey?: boolean }>(RECOVERY_SIGNING_KEY_KEY);
      const materialised = rec !== undefined && typeof rec.key === "string" && rec.key.length > 0;
      if (!materialised) return { materialised: false };
      let adequateLength = false;
      try {
        adequateLength = b64urlDecode((rec!.key as string).trim()).length >= RECOVERY_SIGNING_KEY_MIN_BYTES;
      } catch {
        adequateLength = false; // an unparseable stored key cannot hash a code
      }
      const adopted = rec?.adoptedFromSessionKey === true;
      const createdMs = typeof rec?.createdAt === "string" ? Date.parse(rec.createdAt) : NaN;
      if (!Number.isFinite(createdMs)) return { materialised: true, adequateLength, adoptedFromSessionKey: adopted };
      return { materialised: true, ageMs: Math.max(0, Date.now() - createdMs), adequateLength, adoptedFromSessionKey: adopted };
    }

    async getRecoveryRecord(canonicalEmail: string): Promise<RecoveryRecord | null> {
      return (await this.state.storage.get<RecoveryRecord>(this.recoveryKey(canonicalEmail))) ?? null;
    }

    // dummyRecoveryRecord builds a throwaway full-size recovery record (standard code count, fresh random
    // salts + hash-shaped random bytes) used ONLY so recoveryRecover does the SAME verify work for an unknown
    // email as for a known one (anti-enumeration: equal timing whether or not the email has a real record).
    // It delegates to fakeRecoveryRecord (recovery.ts), which draws its salts/hashes with NO HMAC sign and NO
    // key import (ML-32: the prior version minted the dummy via generateRecoveryCodes, which ran a full extra
    // 10-op HMAC pass of its own before verifyCode even started, so an unknown email cost ~2x a known one's
    // HMAC work - a timing oracle on enrolment). Needing no key, it takes none. It is never persisted and can
    // never match a real presented code (its "hashes" are uniform random, not real HMAC output), and the
    // caller forces the match off when the real record was null. The email field is a fixed placeholder; it is
    // never read for the dummy.
    async dummyRecoveryRecord(): Promise<RecoveryRecord> {
      return fakeRecoveryRecord();
    }

    // generateRecoveryFor mints a fresh set for a canonical email, REPLACES any prior record (so all prior
    // codes are invalidated at once), persists only the salted hashes, and returns the PLAINTEXT codes ONCE.
    // The signing key is the in-DO RECOVERY key (never leaves the DO). It also records the break-glass-in-place
    // acknowledgement when the email is an OWNER (the dispose-gate precondition), and audits the generation as
    // a redaction-safe access-policy event (who + when, never a code). It is the single internal mint path
    // shared by the enrolment hook and the regenerate route, so the two cannot diverge. sourceIp is the coarse
    // provenance for the audit event, threaded from the request the router forwarded (null when unavailable,
    // e.g. the first-enrolment hook); it is non-authoritative and never a secret.
    //
    // G177: onStored is the INVALIDATION BOUNDARY, published to the caller. The put below REPLACES the email's
    // record, so the prior codes verify before it and are dead after it. Everything that follows the put can
    // throw (a role read, the ack write, the audit append), and when it does the caller 500s and the fresh
    // plaintext is never returned -- the operator then holds NEITHER set. Only this function knows which side of
    // the put the throw happened on, so it says so rather than making the caller guess.
    async generateRecoveryFor(canonicalEmail: string, actorMethod: AuthMethod, sourceIp: string | null = null, onStored?: () => void): Promise<string[]> {
      // The RECOVERY key, not the session key (TERMINATE-ALL-DESTROYS-RECOVERY-CODES). Minting under
      // the session key is what made terminate-all a code-destroying operation; a set minted here now survives it.
      const key = await this.recoverySigningKey();
      // G083: a session signing key too short to import breaks EVERY recovery operation (generateRecoveryCodes
      // throws below and the caller 500s), so the last way back into a locked-out account is dead engine-side
      // with nothing recorded. OBSERVE it, then let the throw happen exactly as before: the behaviour is
      // unchanged, only the evidence is new. Counts only; the key is never read, logged or returned.
      if (!isRecoverySigningKeyUsable(key)) await this.recordAuthSignal("recovery-signing-key-invalid");
      const { codes, record } = await generateRecoveryCodes(key, canonicalEmail, nowMillisISO());
      await this.state.storage.put(this.recoveryKey(canonicalEmail), record);
      // The old set is now dead. Past this line a failure costs the operator BOTH sets (G177).
      onStored?.();
      // NO LATCH IS WRITTEN HERE: recoveryBreakGlassVerdict re-derives everything from LIVE state on every
      // read, including the passkey-bound-Owner test, so there is nothing for a latch to remember and no
      // way for one to go stale.
      await this.appendAudit({
        actorEmail: canonicalEmail,
        actorMethod,
        sourceIp,
        action: "recovery-codes-generated",
        outcome: "success",
        // Field-less access-policy target (redaction-safe): the trail records that a recovery set was
        // generated, for whom and when; NEVER a code or a hash.
        target: { kind: "access-policy" },
      });
      return codes;
    }

    // stagedRecoveryKey is the per-email storage key for a MINTED-BUT-NOT-YET-LIVE recovery set (see
    // RECOVERY_STAGED_PREFIX). Same canonical-email discipline as recoveryKey.
    stagedRecoveryKey(canonicalEmail: string): string {
      return `${RECOVERY_STAGED_PREFIX}${canonicalEmail}`;
    }

    // generateRecoveryStaged mints a fresh set for canonicalEmail WITHOUT touching the live record
    // (STAGED-RECOVERY-CODES-CONFIRM-GATE): the live set (if any) keeps verifying unchanged. It
    // exists for the one case generateRecoveryFor's immediate mint is wrong for -- an enrolment that runs
    // while a LIVE record already exists (self-add, including the forced re-enrolment a recovery-code
    // sign-in requires), where the operator has not yet had a chance to see or save the fresh plaintext and
    // an immediate mint would kill their only working set out from under them. The plaintext returned here
    // is exactly what confirmRecoveryStaged will make live; nothing is invalidated until that call. Audits
    // recovery-codes-staged (not recovery-codes-generated: the old set has not died). A second staged mint
    // for the same email before the first is confirmed simply overwrites the earlier staged set -- there is
    // only ever one pending offer, matching the one panel the console shows.
    async generateRecoveryStaged(canonicalEmail: string, actorMethod: AuthMethod, sourceIp: string | null = null): Promise<string[]> {
      const key = await this.recoverySigningKey();
      if (!isRecoverySigningKeyUsable(key)) await this.recordAuthSignal("recovery-signing-key-invalid");
      const { codes, record } = await generateRecoveryCodes(key, canonicalEmail, nowMillisISO());
      await this.state.storage.put(this.stagedRecoveryKey(canonicalEmail), record);
      await this.appendAudit({
        actorEmail: canonicalEmail,
        actorMethod,
        sourceIp,
        action: "recovery-codes-staged",
        outcome: "success",
        target: { kind: "access-policy" },
      });
      return codes;
    }

    // confirmRecoveryStaged promotes a staged set to LIVE: the actual invalidation of whatever set was live
    // before it, run only once the operator has told the console (by ticking "I have saved my recovery
    // codes" on the save-confirm panel) that the fresh plaintext they were just shown is safely saved. This
    // is the real recovery-codes-generated boundary for a re-enrolment; generateRecoveryStaged only offered
    // it. Idempotent and side-effect-free when nothing is staged: no staged mint ever ran for this email
    // (a bootstrap/invite enrolment, which has no prior set to protect and mints straight to live), it was
    // already confirmed, or a later staged mint has already superseded it. Never a fault: a confirm the
    // engine cannot honour must not read as "your enrolment failed" when the credential and the live
    // recovery set are both already fine.
    async confirmRecoveryStaged(canonicalEmail: string, actorMethod: AuthMethod, sourceIp: string | null = null): Promise<{ ok: true; promoted: boolean }> {
      const staged = await this.state.storage.get<RecoveryRecord>(this.stagedRecoveryKey(canonicalEmail));
      if (staged === undefined) return { ok: true, promoted: false };
      await this.state.storage.delete(this.stagedRecoveryKey(canonicalEmail));
      // The old set is now dead (whatever was live before this line). Mirrors generateRecoveryFor's own
      // ordering: the put is the invalidation boundary, and the audit follows it.
      await this.state.storage.put(this.recoveryKey(canonicalEmail), staged);
      await this.appendAudit({
        actorEmail: canonicalEmail,
        actorMethod,
        sourceIp,
        action: "recovery-codes-generated",
        outcome: "success",
        target: { kind: "access-policy" },
      });
      return { ok: true, promoted: true };
    }

    // recoveryRegenerate serves the self-service "regenerate my codes" route. The router has already proven
    // the caller's identity and scoped {email} to the caller's OWN verified email, so this method trusts the
    // email as the target (it still normalises it). It mints a fresh set, invalidating all prior codes, and
    // returns the plaintext ONCE. A non-usable email is refused (ok:false), never a 500.
    async recoveryRegenerate(body: { email?: unknown; ip?: unknown; method?: unknown }): Promise<{ ok: true; codes: string[] } | { ok: false; reason?: "off-roster" }> {
      const email = this.normaliseEmail(body.email);
      // G039: "regenerate silently fails" / "the console always nags me to regenerate". An email that does not
      // normalise refuses here with a bare ok:false the console shows as a generic failure, and the operator is
      // nagged to regenerate forever. Counted; the response is unchanged.
      if (!email) {
        await recordCeremonyFault(this.state.storage, "recovery-regenerate-refused");
        return { ok: false };
      }
      // The coarse source IP for the audit event, forwarded by the router from the edge CF-Connecting-IP
      // (the recovery-recover body-forward pattern). Null when absent; non-authoritative provenance, never a secret.
      const ip = typeof body.ip === "string" && body.ip.length > 0 ? body.ip : null;
      // The router forwards the verified caller method so the regenerate audit attributes the event to the
      // method the caller actually used (an OIDC/SAML/Access caller is no longer mis-recorded as passkey). It
      // falls back to "passkey" (the common console path) only when the method is absent or unrecognised.
      const allowed: readonly AuthMethod[] = ["access", "passkey", "oidc", "saml", "token"];
      const method = (typeof body.method === "string" && (allowed as readonly string[]).includes(body.method) ? body.method : "passkey") as AuthMethod;
      // ROSTER-BOUND REGENERATION, the THIRD conversion of a spent one-time secret into standing access and
      // the shortest of the three. The self-add and invite arms of resolveRegistrationAuthorisation close the
      // passkey; this closes the OTHER standing credential a recovery sign-in can mint, which is a fresh set
      // of the same never-expiring codes.
      //
      // WHY THE ROUTE'S OWN GATE IS NOT ENOUGH. handleRegenerate asks for an authenticated caller carrying a
      // verified email, a same-origin request and a step-up, and the session a spent code mints satisfies
      // every one of them: it is method "passkey" with the consumed email's subject, so it is
      // indistinguishable from an authenticator's session at exactly the point that matters, and that route's
      // own note records that a recovery sign-in is recent enough to clear the step-up. So a removed person
      // refused a passkey by the self-add arm banked an unbounded supply of codes on the very next request.
      //
      // SCOPED TO THE PASSKEY METHOD, for the identical reason the self-add arm is, and the scope is
      // load-bearing rather than caution. resolveRole is max(role row, group-mapped role, viewer), so a
      // legitimate member can hold authority from an IdP GROUP CLAIM with no role row at all, and the roster
      // set cannot see them; such a member arrives here as "access", "oidc" or "saml" carrying the claims that
      // grant them the role, and refusing them would break a working estate. A passkey session carries no
      // group claims and was therefore never resolved by one, so for it the roster set is the whole answer.
      //
      // FAIL OPEN, inherited whole from classifyRosterMembership: a roster read that throws and a roster that
      // reads empty are both "unreadable" and both admit, exactly as they do on the enrolment arms. Only a
      // populated roster that does not carry this address refuses.
      //
      // IT DESTROYS NOTHING, and the split is the same one the whole design rests on. The caller's EXISTING
      // set is untouched and their sign-in is unaffected: a removed person can still spend the codes they hold
      // and reach somebody, which is what a break-glass is for. What is closed is the minting of a fresh
      // supply, so a wrong answer here costs an off-roster person one regenerate, never their way back in.
      if (method === "passkey" && rosterRefusesEnrolment(await this.rosterMembership(email))) {
        await recordCeremonyFault(this.state.storage, "recovery-regenerate-off-roster");
        await this.recordAuthSignalThrottled("roster-enrolment-refused");
        return { ok: false, reason: "off-roster" };
      }
      // G177: the worst case, which recorded nothing. "I regenerated my recovery codes, it errored,
      // and now neither old nor new codes work." Everything from here on either happens BEFORE the new record is
      // stored (the old codes survive, and the operator should keep using them) or AFTER it (the old codes are
      // gone and the new plaintext never left the engine, because the caller got a 500 instead of the codes).
      // Both ended as one opaque 500 wearing one row, and those are opposite remedies: "use the set you already
      // have" against "you have no set at all; recover through another Owner, the break-glass token or a passkey".
      //
      // The throw is RE-THROWN unchanged, so the DO's outer catch answers the same 500 it always did and the
      // router's own recovery-regenerate-failed signal fires exactly as before. Behaviour is untouched; only the
      // evidence is new. Counts only, no code, hash, salt, email or message.
      let stored = false;
      let codes: string[];
      try {
        codes = await this.generateRecoveryFor(email, method, ip, () => {
          stored = true;
        });
        // Regenerating recovery codes rotates a sign-in factor (often done after a suspected compromise), so
        // it terminates sessions issued before the rotation (V7.4.3): bump the email's session epoch. A
        // FIRST enrolment (the generateRecoveryFor enrolment hook path) does not bump - only this explicit
        // regenerate does, so initial setup never signs the operator out. It is INSIDE the guarded region: it
        // runs after the store, so a throw here costs the operator the old set with no new one to show for it.
        await this.bumpSessionEpoch(email);
      } catch (e) {
        try {
          await this.recordAuthSignal(stored ? "recovery-regenerate-old-codes-lost" : "recovery-regenerate-mint-failed");
        } catch {
          // The recorder is best-effort and must never REPLACE the fault it is recording: a storage layer sick
          // enough to fail the regenerate can fail its own signal write, and the caller must still see the
          // original 500 rather than a fault raised by the evidence.
        }
        throw e;
      }
      return { ok: true, codes };
    }

    // recoveryRecover is the actual recovery: verify a presented code for an email, mark it consumed, and mint
    // a NORMAL signed session for that email's resolved role. It is the highest-value route in the engine, so:
    //  - HARD rate-limited per IP AND per email, FAIL CLOSED (a limiter hiccup denies, never admits), so an
    //    oracle/brute-force gains nothing by knocking the limiter over. Both buckets must pass.
    //  - GENERIC on failure: a wrong code, an unknown email, an exhausted set, and a rate-limit denial all
    //    return the SAME { ok:false } shape (the router maps it to one generic 401), so there is no oracle on
    //    which part failed and no "email not found" distinction.
    //  - SINGLE USE: a successful verify marks exactly the matched code consumed, so the same code fails next
    //    time.
    //  - AUDITED on success AND failure, and it returns alert SIGNALS (used / abuse) the router routes through
    //    the notify channels so misuse is loud.
    // It returns, on success, the canonical email + a freshly-signed session token (the router sets the
    // __Host- cookie) + the resolved role + a flag telling the console to prompt a fresh-passkey enrolment.
    async recoveryRecover(
      body: { email?: unknown; code?: unknown; ip?: unknown },
    ): Promise<
      | { ok: true; email: string; token: string; role: Role; remaining: number; enrolPasskey: boolean }
      | { ok: false; alert: "recovery-code-used" | "recovery-code-abuse" | null }
    > {
      const email = this.normaliseEmail(body.email);
      const ip = typeof body.ip === "string" && body.ip.length > 0 ? body.ip : null;
      // RATE LIMIT FIRST (fail closed), BEFORE any record read or compare, so a flood never even reaches the
      // crypto. Both the per-email and the per-IP bucket are checked; either over-cap (or a limiter error)
      // denies. We audit the throttled attempt and signal abuse so repeated failures are loud. A malformed
      // email still consumes a per-IP token (so spraying random emails from one host is still throttled).
      const emailKey = email ? `email:${email}` : "email:_invalid";
      const ipKey = ip ? `ip:${ip}` : null;
      const rateOk = await this.recoveryRateAllow(emailKey, ipKey);
      if (!rateOk) {
        // NO ACTOR ON A THROTTLED ATTEMPT (V16.3.1). This is the ONE audit row on this route that is written
        // before a single byte has been compared against anything: the limiter denies ahead of the record read,
        // so `email` here is nothing but a string an UNAUTHENTICATED caller put in a request body. See the note
        // over the failure branch below for the whole argument; it applies to this branch a fortiori.
        await this.appendAudit({
          actorEmail: null,
          actorMethod: "recovery",
          sourceIp: ip,
          action: "recovery-code-used",
          outcome: "denied",
          target: { kind: "access-policy" },
        });
        // Repeated/over-cap attempts are the abuse signal (the router fires recovery-code-abuse).
        // P2: record the bounded auth-signal so a "recovery-code (break-glass) sign-in is being refused" is
        // diagnosable from the pack (the hard per-IP/per-email fail-closed limiter is denying / a limiter outage
        // is failing closed) - recovery-ratelimited. Best-effort; never blocks the deny.
        await this.recordAuthSignal("recovery-ratelimited");
        return { ok: false, alert: "recovery-code-abuse" };
      }
      // A structurally-absent email or code fails generically (still rate-limited above). We do NOT distinguish
      // "no such email" from "wrong code": both walk to the same generic failure + a failure audit.
      const codeNorm = normaliseCode(body.code);
      // TWO KEYS, DELIBERATELY (TERMINATE-ALL-DESTROYS-RECOVERY-CODES). `key` verifies the presented
      // CODE and must survive a global sign-out; the session token minted on success below is signed under the
      // SESSION key, which must not. Reading both here (unconditionally, before the record read) keeps the
      // anti-enumeration timing uniform: a known and an unknown email do the identical storage work.
      const key = await this.recoverySigningKey();
      const record = email ? await this.getRecoveryRecord(email) : null;
      // ANTI-ENUMERATION (timing): an UNKNOWN email (no record) must run the SAME verify work as a known one,
      // or the response time would reveal whether an email has recovery codes. So when there is no record we
      // verify against a SYNTHETIC dummy record of the standard size (it can never match - its salts and
      // "hashes" are plain random bytes, no HMAC computed at construction time, and the match is forced off
      // because the real record is null below), so the absent-email and wrong-code paths do the SAME
      // ~RECOVERY_CODE_COUNT HMAC ops inside verifyCode below, not double it. verifyCode itself walks the
      // WHOLE unconsumed set in constant time, so a wrong code and a near-miss within a real record also do
      // not diverge. codeNorm length is validated inside verifyCode.
      const recordForVerify = record ?? (await this.dummyRecoveryRecord());
      // G083: the same signing-key observation as the mint path. verifyCode throws under an unusable key, so
      // "every recovery code fails" would be a bare 500 with no recorded cause.
      if (!isRecoverySigningKeyUsable(key)) await this.recordAuthSignal("recovery-signing-key-invalid");
      const result = await verifyCode(key, recordForVerify, codeNorm);
      // G083: a REAL record (never the synthetic anti-enumeration dummy, whose slots are random bytes) whose
      // persisted salt/hash will not decode. Those slots can never match, so the operator is rejected forever
      // with the same generic 401 a mistyped code gets. Recorded as a count-only closed signal; the response
      // below is untouched, so the no-oracle property is preserved.
      if (record !== null && result.corruptSlots > 0) await this.recordAuthSignal("recovery-record-corrupt");
      if (!result.matched || record === null || email === null) {
        // G039: a REJECTED code (as opposed to a THROTTLED attempt) - recorded into the EXISTING closed
        // auth-signal vocabulary (recovery-code-invalid), not a parallel one. The generic client response and
        // the no-oracle property are unchanged.
        await this.recordAuthSignal("recovery-code-invalid");
        // FAILURE: audit it (a failed recovery attempt is a security event a reviewer cares about), and signal
        // abuse so repeated failures page someone (the router decides whether to fire based on the signal).
        //
        // THE ROW NAMES NO ACTOR, AND THE RULE IS THIS CODEBASE'S OWN, NOT A NEW ONE. `audit-types.ts` states
        // it on the `authn-failure` member: "No identity is verified on a failure, so the actor fields are null
        // (V16.3.1)", and `scheduler-do-routing-identity.ts` writes exactly that for a failed passkey login.
        // This route is the OTHER failed-authentication writer in the engine and it used to disagree with its
        // sibling: POST /admin/auth/recovery is UNAUTHENTICATED, so `email` on this branch is a string the
        // caller typed and nothing has verified that they are that person, or that the address belongs to this
        // account at all. An unauthenticated caller from the public internet was therefore choosing the name
        // the tamper-evident chain recorded as the ACTOR of a break-glass attempt, and the console renders that
        // name beside an action whose own label reads "Recovery code used".
        //
        // THE SIBLING IN THIS VERY FEATURE HAD ALREADY DECIDED IT. `routeRecoveryAlert` carries the email on a
        // successful use and stays generic on a failure, because "a failed attempt's 'email' is an unverified
        // guess we must not echo as if it were a real account". The notify channel refused to echo it while the
        // audit chain recorded it as fact.
        //
        // NOTHING DIAGNOSABLE IS LOST. The row keeps the source IP and the recovery method, which is the
        // forensics that WAS established; `recovery-code-invalid` (and `recovery-ratelimited` above) already
        // count the class into the bounded auth-signal vocabulary the pack reads; and the SUCCESS row below is
        // untouched, because there the code match is what verifies the identity. The generic 401, the
        // no-oracle property and the uniform timing are all unchanged: this writes a different value into a
        // record the caller can never read.
        await this.appendAudit({
          actorEmail: null,
          actorMethod: "recovery",
          sourceIp: ip,
          action: "recovery-code-used",
          outcome: "failed",
          target: { kind: "access-policy" },
        });
        return { ok: false, alert: "recovery-code-abuse" };
      }
      // SUCCESS: mark exactly the matched code consumed (single use) and persist the record before minting the
      // session, so a crash after the mint can never leave the code reusable.
      record.codes[result.index]!.consumed = true;
      await this.state.storage.put(this.recoveryKey(email), record);
      // Resolve the role the SAME way every other path does: by the STABLE subject the recovered session will
      // authorise on. A recovered session is a passkey-class session, so its subject is passkeySubject(email);
      // resolveBoundEntry returns the bound entry (or binds a pending/legacy email grant on this first auth,
      // exactly as the next authenticated request would), with lazy expiry applied. A recovered user with no
      // grant of any kind resolves to viewer (never an elevation).
      const mine = await this.resolveBoundEntry(passkeySubject(email), email);
      const role = this.effectiveRole(mine, Date.now());
      // Mint a NORMAL session token under the SESSION signing key (the same in-DO key + signSession the passkey
      // login uses, deliberately NOT the recovery key that verified the code above), so a recovered
      // session is indistinguishable from a passkey session downstream and carries its own TTL. It is a
      // passkey-class session: method "passkey", subject passkeySubject(email). It carries the email's CURRENT
      // session epoch, so a recovery sign-in yields a valid (non-revoked) session.
      const token = await signSession(await this.sessionSigningKey(), { method: "passkey", email, subject: passkeySubject(email), epoch: await this.getSessionEpoch(email) }, Date.now());
      const remaining = remainingCount(record);
      // AUDIT the successful recovery and signal recovery-code-used so a successful break-glass sign-in is
      // loud (the router fires the alert).
      await this.appendAudit({
        actorEmail: email,
        actorMethod: "recovery",
        sourceIp: ip,
        action: "recovery-code-used",
        outcome: "success",
        target: { kind: "access-policy" },
      });
      // ROSTER-BOUND ENROLMENT PROMPT. The flag is the console's instruction to walk the user straight into
      // enrolling a fresh passkey, which is how a single-use code becomes a standing credential. It is now
      // the roster's answer rather than a constant.
      //
      // IT IS A HINT, AND THE AUTHORITY IS ELSEWHERE, DELIBERATELY. The enrolment itself is refused by the
      // self-add arm of resolveRegistrationAuthorisation, which re-reads the roster at the moment of the
      // registration. Deciding it only here would have bound the answer to a read taken at CONSUMPTION time,
      // and the two are separate requests: a role deleted in between would leave a stale "yes" the console
      // would act on. Deciding it only there would leave the console offering a button the route refuses,
      // which is a worse ticket than not offering it. Both, and the enforcing one is the later read.
      //
      // The whole recovery SIGN-IN is deliberately NOT gated on this. An off-roster consumption still mints
      // its session, because that session resolves through the same resolveBoundEntry every other path uses
      // and lands on viewer, conferring nothing the roster does not already grant, while refusing it outright
      // would invent a lockout: the person whose role row was deleted in error is exactly who a break-glass
      // is for, and they would have no way to reach anybody. What is closed is the conversion of a spent
      // secret into a permanent one.
      const enrolPasskey = !rosterRefusesEnrolment(await this.rosterMembership(email));
      return { ok: true, email, token, role, remaining, enrolPasskey };
    }

    // recoveryRemaining reports the UNCONSUMED count for ONE email (the router passes the caller's OWN verified
    // email, so a caller can never read another user's count). An absent/garbled email or no record yields 0.
    async recoveryRemaining(rawEmail: string | null): Promise<{ remaining: number; low: boolean }> {
      const email = this.normaliseEmail(rawEmail);
      if (!email) return { remaining: 0, low: true };
      const record = await this.getRecoveryRecord(email);
      const remaining = remainingCount(record);
      // low binds to RECOVERY_CODES_LOW_THRESHOLD; a record that exists but is exhausted, or no record at all,
      // both read low so the console prompts a regenerate.
      return { remaining, low: remaining <= RECOVERY_CODES_LOW_THRESHOLD };
    }

    // recoveryRateAllow checks the two hard recovery buckets (per email, per IP) and returns whether the
    // attempt is admitted. It FAILS CLOSED: if rateCheck throws (the limiter's own store is unavailable), the
    // attempt is DENIED, the opposite of the fail-open sign-in limiter, because a guessing attack must never
    // benefit from an unavailable limiter on this high-value route. Both buckets must pass; a null IP key
    // (no source IP, e.g. a local request) skips the IP bucket but still enforces the per-email one.
    async recoveryRateAllow(emailKey: string, ipKey: string | null): Promise<boolean> {
      try {
        const emailVerdict = await this.recoveryRateCheck(emailKey, RECOVERY_RATE_MAX_PER_EMAIL);
        // G039: "every recovery code we try is rejected". The three ways this route denies - the per-EMAIL
        // bucket (this one account is being sprayed), the per-IP bucket (a whole office behind one NAT locking
        // itself out) and the limiter's own store failing CLOSED (nothing is wrong with the codes at all) -
        // were byte-identical in the pack: one recovery-ratelimited count. They are named here. The caller's
        // verdict, the audit row and the generic client response are all unchanged (no oracle is created): the
        // bucket class is recorded pack-side only, and never the email, IP, prefix or code.
        if (!emailVerdict.allowed) {
          await recordCeremonyFault(this.state.storage, "recovery-denied-email-bucket");
          return false;
        }
        if (ipKey !== null) {
          const ipVerdict = await this.recoveryRateCheck(ipKey, RECOVERY_RATE_MAX_PER_IP);
          if (!ipVerdict.allowed) {
            await recordCeremonyFault(this.state.storage, "recovery-denied-ip-bucket");
            return false;
          }
        }
        return true;
      } catch (e) {
        log("error", `recovery rate-check unavailable, failing closed (attempt denied): ${(e as Error).message}`);
        await recordCeremonyFault(this.state.storage, "recovery-limiter-unavailable");
        return false;
      }
    }

    // recoveryRateCheck is a fixed-window counter in a SEPARATE `recovery-rate:` namespace (so it never
    // collides with the per-caller or per-IP sign-in buckets), with the recovery window + the supplied cap. It
    // is the same cheap read-modify-write as rateCheck; kept distinct so the recovery caps and window cannot
    // drift into the general limiter. It THROWS on a storage fault (so recoveryRateAllow can fail closed),
    // unlike rateCheck which never throws.
    async recoveryRateCheck(key: string, max: number): Promise<{ allowed: boolean }> {
      const now = Date.now();
      const storageKey = `${RECOVERY_RATE_PREFIX}${key}`;
      const cur = (await this.state.storage.get<RateWindow>(storageKey)) ?? null;
      if (cur === null || now - cur.windowStart >= RECOVERY_RATE_WINDOW_MS) {
        await this.state.storage.put(storageKey, { windowStart: now, count: 1 } satisfies RateWindow);
        return { allowed: true };
      }
      if (cur.count + 1 > max) return { allowed: false };
      cur.count += 1;
      await this.state.storage.put(storageKey, cur);
      return { allowed: true };
    }

    // recoveryBreakGlassVerdict answers the ONLY question the lockout pre-flight and the break-glass-token
    // dispose gate actually need: is there, RIGHT NOW, a banked recovery code that would sign someone back in
    // AS AN OWNER. It replaces getRecoveryOwnerAck, a write-once-true latch
    // (LOCKOUT-PREFLIGHT-COUNTS-RECORDS-NOT-USABLE-FACTORS) that was set at mint time and never
    // re-evaluated, so it stayed true after every code was consumed, after that Owner was demoted, after the
    // record was deleted, and after the key the codes were hashed under was gone. That latch fed
    // buildDisposeBootstrapToken, which tells the operator "it is now safe to dispose of it" about the
    // ADMIN_TOKEN, and it gated setBreakGlassTokenRetired, so a factor that did not work could authorise
    // destroying the only credential that did.
    //
    // Every condition is re-derived from live state on every call, and NO CODE IS CONSUMED:
    //  1. OWNER NOW. Only a PASSKEY-BOUND Owner row counts, re-resolved from the role table through
    //     effectiveRole (so a lapsed temporary elevation is not an Owner). This mirrors recoveryRecover, which
    //     resolves the recovered session's authority via resolveBoundEntry(passkeySubject(email)): an
    //     Access-bound Owner's codes recover to viewer, which is not a way back in.
    //  2. RECORD PRESENT AND PARSEABLE for that Owner's email (isRecoveryRecordShaped).
    //  3. AT LEAST ONE UNCONSUMED CODE (remainingCount > 0).
    //  4. KEY CONTINUITY: the record was minted under the key the engine would verify it with. Preferred
    //     evidence is the record's own keyProof witness, recomputed under the current key. Records minted
    //     before that field existed fall back to the key timeline (recoveryKeyMintedUnderLiveKey below).
    //
    // The reason is a CLOSED enum of coarse, redaction-safe verdict names (never an email, a count, a code, a
    // hash or a key). It exists so a "not ready" verdict is actionable: a pre-flight that cries wolf with no
    // remedy is its own harm, and "you have no unconsumed codes" and "your codes predate a key rotation" have
    // opposite remedies (regenerate, versus regenerate AND understand that a sign-out destroyed them).
    async recoveryBreakGlassVerdict(): Promise<{ ready: boolean; reason: RecoveryBreakGlassReason }> {
      const now = Date.now();
      const entries = await this.listRoleEntries();
      const ownerEmails: string[] = [];
      for (const e of entries) {
        const email = typeof e.email === "string" ? e.email.trim().toLowerCase() : "";
        if (email.length === 0) continue;
        if (e.subject !== passkeySubject(email)) continue;
        if (this.effectiveRole(e, now) !== "owner") continue;
        if (!ownerEmails.includes(email)) ownerEmails.push(email);
      }
      if (ownerEmails.length === 0) return { ready: false, reason: "no-passkey-bound-owner" };
      // Read both key records ONCE for the whole scan; neither value is returned, logged or compared against
      // anything a caller supplied.
      const keyRec = await this.state.storage.get<{ key?: string; createdAt?: string; adoptedFromSessionKey?: boolean; sessionKeyCreatedAt?: string }>(RECOVERY_SIGNING_KEY_KEY);
      const sessionRec = await this.state.storage.get<{ key?: string; createdAt?: string }>(PASSKEY_SESSION_KEY_KEY);
      // The most informative failure across the Owners is reported, so an account with one Owner holding an
      // exhausted set and another holding none says "no unconsumed codes" rather than "no record". Order is
      // least-informative first; a later Owner can only raise it.
      const RANK: RecoveryBreakGlassReason[] = ["no-recovery-record", "unparseable-recovery-record", "no-unconsumed-codes", "recovery-codes-orphaned-from-key"];
      let worst: RecoveryBreakGlassReason = "no-recovery-record";
      for (const email of ownerEmails) {
        const raw = await this.state.storage.get<unknown>(this.recoveryKey(email));
        if (raw === undefined || raw === null) continue; // stays at no-recovery-record
        if (!isRecoveryRecordShaped(raw)) {
          if (RANK.indexOf("unparseable-recovery-record") > RANK.indexOf(worst)) worst = "unparseable-recovery-record";
          continue;
        }
        if (remainingCount(raw) <= 0) {
          if (RANK.indexOf("no-unconsumed-codes") > RANK.indexOf(worst)) worst = "no-unconsumed-codes";
          continue;
        }
        if (!(await this.recoveryRecordKeyLive(raw, keyRec, sessionRec))) {
          if (RANK.indexOf("recovery-codes-orphaned-from-key") > RANK.indexOf(worst)) worst = "recovery-codes-orphaned-from-key";
          continue;
        }
        return { ready: true, reason: "ok" };
      }
      return { ready: false, reason: worst };
    }

    // recoveryRecordKeyLive is condition 4: would a code from this record still verify under the key the
    // engine would verify it with? Two independent routes, tried in order of strength.
    //
    // PROOF (records minted with a keyProof witness): recompute the witness under the key recoverySigningKey
    // would hand verifyCode and compare. Equal witnesses mean identical key bytes, so a banked code verifies;
    // different witnesses mean it cannot. This is a demonstration, not an inference, and it is what the
    // account-level latch should always have been.
    //
    // TIMELINE (records that predate the witness): a record was minted under whatever key was live at its
    // generatedAt, so it survives exactly when that key is still the one in force.
    //  - A recovery key GENERATED fresh (not adopted) is in force from its createdAt: the record survives iff
    //    it was generated at or after that. An older record was minted under something that is gone, which is
    //    the shape of an account that ran terminate-all under the pre-split code: its session key was deleted
    //    and a fresh recovery key materialised over the top, so the codes read present, unconsumed and
    //    countable while being permanently dead.
    //  - A recovery key ADOPTED from the session key carries the adopted bytes' OWN birth date
    //    (sessionKeyCreatedAt): the record survives iff it was generated at or after that. This is the
    //    migration path and it must NOT read as orphaned, because adoption copies the exact bytes forward and
    //    every stored hash keeps verifying.
    //  - An adoption written before that stamp existed is dated only by the session key record itself: the
    //    record survives iff that record is STILL present, STILL byte-identical to the adopted key (so it was
    //    never rotated since) and no younger than the recovery record.
    //  - No recovery key materialised at all means the key will be adopted from the session key on first use,
    //    so the live key is the session key: the record survives iff that key is present and no younger than
    //    it. Absent, there is nothing to adopt and a fresh key would be generated, under which nothing verifies.
    // Anything not covered reads NOT live. An unprovable way back in is not a way back in, and the cost of the
    // two mistakes is not symmetric: a false "ready" told an operator to destroy their last credential.
    async recoveryRecordKeyLive(
      record: RecoveryRecord,
      keyRec: { key?: string; createdAt?: string; adoptedFromSessionKey?: boolean; sessionKeyCreatedAt?: string } | undefined,
      sessionRec: { key?: string; createdAt?: string } | undefined,
    ): Promise<boolean> {
      const generatedMs = Date.parse(record.generatedAt);
      if (!Number.isFinite(generatedMs)) return false; // an undateable record cannot be placed on the timeline
      if (typeof record.keyProof === "string" && record.keyProof.length > 0) {
        try {
          const live = await this.recoverySigningKey();
          if (!isRecoverySigningKeyUsable(live)) return false;
          return (await recoveryKeyProof(live)) === record.keyProof;
        } catch {
          return false; // a key too short to import cannot verify anything
        }
      }
      const notOlderThan = (stamp: unknown): boolean => {
        if (typeof stamp !== "string" || stamp.length === 0) return false;
        const ms = Date.parse(stamp);
        return Number.isFinite(ms) && generatedMs >= ms;
      };
      const keyMaterialised = keyRec !== undefined && typeof keyRec.key === "string" && keyRec.key.length > 0;
      if (!keyMaterialised) {
        const sessionPresent = sessionRec !== undefined && typeof sessionRec.key === "string" && sessionRec.key.length > 0;
        return sessionPresent && notOlderThan(sessionRec?.createdAt);
      }
      if (keyRec?.adoptedFromSessionKey !== true) return notOlderThan(keyRec?.createdAt);
      if (typeof keyRec.sessionKeyCreatedAt === "string") return notOlderThan(keyRec.sessionKeyCreatedAt);
      const stillTheSameSessionKey = typeof sessionRec?.key === "string" && sessionRec.key === keyRec.key;
      return stillTheSameSessionKey && notOlderThan(sessionRec?.createdAt);
    }

    // getPasskeyCred / putPasskeyCred read and write one credential record by its base64url id.
    async getPasskeyCred(credIdB64: string): Promise<PasskeyCred | undefined> {
      return this.state.storage.get<PasskeyCred>(`${PASSKEY_CRED_PREFIX}${credIdB64}`);
    }
    async putPasskeyCred(cred: PasskeyCred): Promise<void> {
      await this.state.storage.put(`${PASSKEY_CRED_PREFIX}${cred.credentialId}`, cred);
    }

    // recordPasskeyAssertion stamps THE USABILITY WITNESS
    // (PASSKEY-OWNER-ENROLLED-COUNTS-CREDENTIALS). Call it, and only call it, on the success side
    // of a verifyAssertion: at that point a signature over server-chosen challenge bytes has verified under
    // this credential's stored public key, so the private half provably existed a moment ago. The stamp is a
    // record of that proof. Every other field on a PasskeyCred is inert to the destruction of the
    // authenticator, which is exactly how seven dead credentials kept answering `passkeyOwnerEnrolled: true`.
    //
    // THE WRITE IS UNCONDITIONAL, and that is the whole point. Both call sites previously wrote only when
    // `result.newSignCount !== record.signCount`, and platform passkeys routinely never advance the counter
    // (see the clone-detection carve-out in admin/passkey.ts, which exists because zero-to-zero is the common
    // healthy case). A witness stamped inside that condition would be blind to precisely the authenticators
    // signCount is already blind to, i.e. it would be a second inference wearing a proof's clothes. So this
    // absorbs the signCount persistence too: one put, both facts, on every verified assertion.
    async recordPasskeyAssertion(cred: PasskeyCred, newSignCount: number, via: PasskeyAssertionCeremony): Promise<void> {
      await this.ensurePasskeyWitnessSince();
      await this.putPasskeyCred({ ...cred, signCount: newSignCount, lastAssertedAt: nowMillisISO(), lastAssertedVia: via });
    }

    // ensurePasskeyWitnessSince records, ONCE per DO, the first moment this account ran witness-carrying
    // passkey code. Without it the absence of `lastAssertedAt` is two different facts wearing one spelling:
    // "this credential has never been demonstrated" and "this credential is older than the witness, so
    // nothing is known either way". That ambiguity is what would make a future gate cry wolf on every
    // pre-existing credential in the fleet, so the disambiguator is written now, alongside the stamp, rather
    // than being reconstructed later from deploy dates the DO cannot see.
    //
    // It is set by whichever witness-carrying path runs first (a registration or a verified assertion), so it
    // is always at or before the createdAt of any credential enrolled after this code landed. A credential
    // with `createdAt > witnessSince` and no `lastAssertedAt` has genuinely never been asserted; an older one
    // is simply unknown. An account that neither registers nor asserts never sets it, and that is correct:
    // nothing is known there, and the record says so rather than guessing.
    async ensurePasskeyWitnessSince(): Promise<void> {
      const existing = await this.state.storage.get<string>(PASSKEY_WITNESS_SINCE_KEY);
      if (typeof existing === "string" && existing.length > 0) return;
      await this.state.storage.put(PASSKEY_WITNESS_SINCE_KEY, nowMillisISO());
    }

    async getPasskeyWitnessSince(): Promise<string | null> {
      const v = await this.state.storage.get<string>(PASSKEY_WITNESS_SINCE_KEY);
      return typeof v === "string" && v.length > 0 ? v : null;
    }

    // listPasskeyCredsForEmail returns every credential registered to an email. It loads ALL credential
    // records for the DO and filters in memory, so each call is O(total credentials), not O(creds for
    // this email). This rests on a bounded precondition: a single-tenant DO holds a team of well under a
    // hundred members each enrolling a handful of keys, so the full list stays small. An account with
    // many hundreds of members would make these scans costly; if that scale arrives, re-key the records
    // by an email-hash prefix (`${PASSKEY_CRED_PREFIX}${emailHash}:${credId}`) so this becomes a
    // per-email prefix scan. It feeds excludeCredentials at registration (so a key cannot be enrolled
    // twice) and allowCredentials at login (so the browser offers the right keys).
    async listPasskeyCredsForEmail(email: string): Promise<PasskeyCred[]> {
      const map = await this.state.storage.list<PasskeyCred>({ prefix: PASSKEY_CRED_PREFIX });
      const out: PasskeyCred[] = [];
      for (const c of map.values()) if (c.email === email) out.push(c);
      return out;
    }

    // listPasskeyCredentials returns a member's enrolled credentials in a REDACTED view (id +
    // advisory metadata; never a secret - the COSE public key is omitted as unnecessary). A caller
    // may list their OWN credentials; listing ANOTHER member's requires roles.write (the
    // people-management capability), re-resolved from the DO's own tables. The credentialId is a
    // base64url public identifier, redaction-safe.
    async listPasskeyCredentials(
      emailParam: string | null,
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ credentials: { credentialId: string; createdAt: string; aaguid: string; transports: string[]; alg: number; lastAssertedAt: string | null; lastAssertedVia: PasskeyAssertionCeremony | null }[]; witnessSince: string | null }> {
      const callerEmail = caller ? this.normaliseEmail(caller.email) : null;
      const target = this.normaliseEmail(emailParam ?? undefined) ?? callerEmail;
      // THE FALSE EMPTY. A caller that names no `?email=` and carries no email of its own has identified no
      // target, and this line used to answer that with an empty list. `200 {"credentials":[]}` is BYTE-
      // IDENTICAL to "this account holds none", so the one read an operator would use to establish that an
      // account carries no leftover credentials returned the reassuring answer in exactly the case where it
      // had not looked at anything at all. A bearer token is that caller: GET /whoami answers `email:null`
      // for one, so every ADMIN_TOKEN sweep across every estate read a clean bill of health, including on
      // estates holding many credentials.
      //
      // Refusing is the fix, and the STATUS is the load-bearing part. A 200 carrying a new "I could not
      // resolve a target" flag would leave every client that does not yet read that flag still seeing an
      // empty array, which is the precise failure being repaired; a client cannot mistake a 400 for a clean
      // account. The plain Error is the DO's established validation-refusal mechanism (scheduler-do.ts
      // fetch() maps it to 400 with this message). No console path regresses: the console only calls this
      // without an email from a cookie session, which always has one.
      if (!target) throw new Error("passkey credential listing needs an email: this caller has none of its own, so name one with ?email=, or read the whole account with GET /admin/passkey/credentials/all");
      if (target !== callerEmail) await this.requireCapabilityResolved(caller, "roles.write");
      const creds = await this.listPasskeyCredsForEmail(target);
      // lastAssertedAt/lastAssertedVia ride along in the redacted view, and witnessSince rides with them
      // because neither is readable alone: a null stamp on a credential older than witnessSince says nothing,
      // and a null stamp on a newer one says the key has never been demonstrated. Both are timestamps and an
      // enum, so the view stays redaction-safe. This is the operator-facing surface of the witness, and today
      // it is its ONLY consumer: no verdict reads it.
      return {
        credentials: creds.map((c) => ({
          credentialId: c.credentialId,
          createdAt: c.createdAt,
          aaguid: c.aaguid,
          transports: c.transports,
          alg: c.alg,
          lastAssertedAt: typeof c.lastAssertedAt === "string" ? c.lastAssertedAt : null,
          lastAssertedVia: c.lastAssertedVia === "login" || c.lastAssertedVia === "stepup" ? c.lastAssertedVia : null,
        })),
        witnessSince: await this.getPasskeyWitnessSince(),
      };
    }

    // listAllPasskeyCredentialsForAccount answers the question no read in this engine could answer:
    // WHICH CREDENTIALS EXIST AT ALL. Every other surface is keyed by email (listPasskeyCredentials falls back
    // to the CALLER's own email when none is given), so establishing that an account is clean required already
    // knowing which emails to ask about, which is precisely what you do not know when the residue you are
    // looking for is a credential whose member is gone.
    //
    // WHY THIS IS THE FIX AND REVOKING ON deleteRole IS NOT. deleteRole does not touch `passkeyCred:` records,
    // so a removed member's credentials outlive their role.
    // The tempting fix is to have deleteRole revoke them. That would be WRONG here, and not as a matter of
    // taste: groupRoleFor (scheduler-do-rbac.ts) confers a role from IdP GROUP CLAIMS with no `role:` row
    // involved at all, so an email with no entry in the role table can still be a fully legitimate operator.
    // Destroying their credential when their row is deleted would lock out a real user whose authority never
    // depended on that row. The inverse of "harmless because authorisation fails elsewhere" applies: it would
    // be HARMFUL because authorisation SUCCEEDS elsewhere.
    //
    // So this reports rather than deletes, and it reports the fact honestly. `hasRoleEntry` is exactly what it
    // says: whether the credential's email has a row in the role table or an unexpired pending invite. It is
    // deliberately NOT called `orphaned`, because a group-mapped operator reads false here and is not an
    // orphan. A human or a teardown script decides what to do; nothing is destroyed on an inference.
    //
    // Authority: roles.write, the people-management capability that reading ANOTHER member's credentials
    // already requires. An account-wide read is strictly broader than a per-email one, so it cannot be
    // cheaper. Redaction-safe throughout: ids, timestamps, advisory metadata and the witness, never a key.
    async listAllPasskeyCredentialsForAccount(
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ credentials: { credentialId: string; email: string; createdAt: string; aaguid: string; transports: string[]; alg: number; lastAssertedAt: string | null; lastAssertedVia: PasskeyAssertionCeremony | null; hasRoleEntry: boolean }[]; witnessSince: string | null }> {
      await this.requireCapabilityResolved(caller, "roles.write");
      const now = Date.now();
      const [entries, pending] = await Promise.all([this.listRoleEntries(), this.listPendingEntries()]);
      const known = new Set<string>();
      for (const e of entries) if (e.email) known.add(e.email.trim().toLowerCase());
      for (const p of pending) {
        if (!p.email) continue;
        // An EXPIRED pending invite is not a way in, so it does not make a credential look accounted for.
        // This tested `effectiveRole(p, now) === null` and effectiveRole never returns null (it is declared
        // returning Role, a closed union of six strings), so the skip was dead and an expired invitation DID
        // make a leftover credential read as accounted for. Gate on the expiry itself; `!== "viewer"` would
        // instead drop legitimate unexpired viewers out of the accounted-for set. Same fix as the sibling in
        // listSignInFactors, which carried the identical dead comparison.
        if (this.isExpired(p, now)) continue;
        known.add(p.email.trim().toLowerCase());
      }
      const map = await this.state.storage.list<PasskeyCred>({ prefix: PASSKEY_CRED_PREFIX });
      const credentials = [...map.values()].map((c) => ({
        credentialId: c.credentialId,
        email: c.email,
        createdAt: c.createdAt,
        aaguid: c.aaguid,
        transports: c.transports,
        alg: c.alg,
        lastAssertedAt: typeof c.lastAssertedAt === "string" ? c.lastAssertedAt : null,
        lastAssertedVia: c.lastAssertedVia === "login" || c.lastAssertedVia === "stepup" ? c.lastAssertedVia : null,
        hasRoleEntry: known.has((c.email ?? "").trim().toLowerCase()),
      }));
      credentials.sort((a, b) => (a.email === b.email ? a.createdAt.localeCompare(b.createdAt) : a.email.localeCompare(b.email)));
      return { credentials, witnessSince: await this.getPasskeyWitnessSince() };
    }

    // revokePasskeyCredential deletes one WebAuthn credential (the theft/loss revocation, ASVS V6.5.6).
    // Authority: a caller may revoke their OWN credential (the credential's email is the caller's);
    // revoking ANOTHER member's requires roles.write, and revoking a credential belonging to an Owner
    // requires the caller to BE an Owner (requireNotOwnerEscalation, so an access-admin cannot lock an
    // Owner out of the passkey path). AVAILABILITY GUARD: the last credential of the SOLE Owner is
    // refused (an Owner must keep at least one in-app factor, or recover via Access/recovery codes -
    // never zero passkeys while the sole Owner). Revoking an absent credential is an idempotent no-op.
    // Audited on success; bumps the member's session epoch so sessions predating the revocation stop
    // verifying (V7.4.3).
    async revokePasskeyCredential(
      req: { credentialId?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ deleted: boolean }> {
      const credId = typeof req.credentialId === "string" ? req.credentialId : "";
      if (!credId) throw new Error("credentialId required");
      const cred = await this.getPasskeyCred(credId);
      if (cred === undefined) return { deleted: false }; // idempotent
      const callerEmail = caller ? this.normaliseEmail(caller.email) : null;
      const selfRevoke = callerEmail !== null && cred.email === callerEmail;
      const now = Date.now();
      const entries = await this.listRoleEntries();
      const pending = await this.listPendingEntries();
      const targetEntry = entries.find((e) => e.email === cred.email) ?? pending.find((p) => p.email === cred.email);
      const targetIsOwner = this.effectiveRole(targetEntry, now) === "owner";
      if (!selfRevoke) {
        const resolved = await this.requireCapabilityResolved(caller, "roles.write");
        this.requireNotOwnerEscalation(resolved.role, false, targetIsOwner);
      }
      if (targetIsOwner && this.countOwners(entries, pending, now) === 1) {
        const remaining = (await this.listPasskeyCredsForEmail(cred.email)).length;
        if (remaining <= 1) {
          // G175: THE LOCK-OUT GUARD, RECORDED. It throws a plain Error and answers 400, so it never reached the
          // AuthError funnel and there was no `last-passkey-guard` member for it to reach. A lost-device revoke
          // refused by THIS guard and one refused by a malformed credential id were both {passkey-revoke,
          // refused-validation} on the console side and NOTHING on the engine side: one row, no counterpart, and
          // the operator locked out of their own console with no evidence of why the revoke would not take.
          await recordAuthzRefusal(this.state.storage, "last-passkey-guard");
          // G146: the LOCKOUT-PREVENTION check is a policy guardrail, so it counts on the route x reason ledger
          // too ({rbac-guardrail, guardrail}, the reason's own definition: "last owner, reserved capability, a
          // lockout-prevention check"). The rate is the diagnosis: an operator hammering Revoke on a key they no
          // longer hold, refused every time, is a lockout in progress.
          await recordAdminRefusal(this.state.storage, "rbac-guardrail", "guardrail");
          throw new Error("cannot revoke the last passkey of the sole Owner; enrol another key or appoint a second Owner first");
        }
      }
      const deleted = await this.state.storage.delete(`${PASSKEY_CRED_PREFIX}${credId}`);
      if (deleted) {
        // Revoking an authentication factor terminates sessions that predate it (V7.4.3): the bumped
        // epoch is folded into the session MAC, so an older cookie fails verify on its next request.
        await this.bumpSessionEpoch(cred.email);
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "passkey-credential-revoke",
          outcome: "success",
          target: { kind: "access-policy" },
        });
      }
      return { deleted };
    }

    // putPasskeyChallenge stores a single-use challenge under its scope with a short TTL. consumeChallenge
    // loads it, deletes it (single-use, even under a concurrent replay since the DO is single-threaded),
    // and returns the stored value ONLY when it is present and unexpired; an absent or expired challenge
    // returns null (the caller maps that to the coarse "challenge" rejection). The delete happens BEFORE
    // the value is returned to the verifier, so a challenge can authorise at most one finish.
    async putPasskeyChallenge(scope: string, challengeB64: string, now: number): Promise<void> {
      const rec: PasskeyChallenge = { challenge: challengeB64, scope, createdAt: now, expiresAt: now + CHALLENGE_TTL_MS };
      await this.state.storage.put(`${PASSKEY_CHALLENGE_PREFIX}${scope}`, rec);
    }
    async consumeChallenge(scope: string, now: number): Promise<string | null> {
      const key = `${PASSKEY_CHALLENGE_PREFIX}${scope}`;
      const rec = await this.state.storage.get<PasskeyChallenge>(key);
      if (rec === undefined) return null;
      // Single-use: delete first so a concurrent or replayed finish cannot reuse it.
      await this.state.storage.delete(key);
      if (typeof rec.expiresAt !== "number" || rec.expiresAt <= now) return null; // expired
      if (typeof rec.challenge !== "string" || rec.challenge.length === 0) return null;
      return rec.challenge;
    }

    // sweepAndBoundLoginChallenges keeps the stored login-challenge set bounded so an unauthenticated
    // login/begin flood cannot grow DO storage without limit (each login challenge is consumed only by a
    // matching finish an attacker never sends). It runs at the start of every login/begin: it lists the
    // `login:` challenges, deletes any that have EXPIRED, and if the survivors still exceed
    // PASSKEY_LOGIN_CHALLENGE_CAP it evicts the OLDEST ones (by createdAt) down to the cap. It touches only
    // the login-challenge family (registration challenges are one-per-email and the per-IP limiter bounds the
    // begin rate). It is best-effort housekeeping, not a security control on its own; it never throws so a
    // sweep hiccup cannot fail a begin.
    async sweepAndBoundLoginChallenges(now: number): Promise<void> {
      const loginPrefix = `${PASSKEY_CHALLENGE_PREFIX}login:`;
      const map = await this.state.storage.list<PasskeyChallenge>({ prefix: loginPrefix });
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
      // Still over the cap after expiry: evict the oldest survivors. Sort oldest-first and delete the
      // overflow so the newest (most likely to still be completed) are kept.
      live.sort((a, b) => a.createdAt - b.createdAt);
      const overflow = live.length - PASSKEY_LOGIN_CHALLENGE_CAP;
      for (let i = 0; i < overflow; i++) await this.state.storage.delete(live[i]!.key);
      // G014: LIVE (unexpired) login challenges were evicted by the cap - the "users randomly cannot complete
      // passkey sign-in during busy periods" ticket, which is a begin FLOOD, not a TTL problem. The victim's
      // finish fails with the same generic "challenge" reason an expiry gives, so the flood was invisible.
      // Best-effort and never throwing (this sweep must never fail a begin).
      await recordCeremonyFault(this.state.storage, "passkey-challenge-evicted");
    }

    // mintRegistrationInvite stores a single-use, email-BOUND, TTL'd registration invite and returns its
    // token. It is called from setRole at the COMMIT point when an Owner/access-admin grants a role to an
    // email that has NO passkey credential yet (so the granted person can enrol their first key), and the
    // token is embedded by the router in the role-invite email's registration link. The bound email is the
    // canonical email the grant just persisted (never a client claim). Returns null when the email already
    // has a credential (no invite is needed, the person can self-add) so setRole only mints when enrolment is
    // actually pending.
    async mintRegistrationInvite(email: string, now: number): Promise<string | null> {
      const existing = await this.listPasskeyCredsForEmail(email);
      if (existing.length > 0) return null; // already enrolled: no invite needed (self-add covers a 2nd key)
      const token = randomInviteToken();
      const rec: PasskeyInvite = { email, createdAt: now, expiresAt: now + INVITE_TTL_MS };
      await this.state.storage.put(`${PASSKEY_INVITE_PREFIX}${token}`, rec);
      return token;
    }
  };
}
