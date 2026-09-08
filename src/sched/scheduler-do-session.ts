// The session lifecycle subsystem: the WebAuthn-minted session signing key, issue/verify with
// idle-slide, the per-subject session epoch and the terminate-all / terminate-own-other /
// terminate-user / logout revocation axes. SessionMixin layers these over a base whose `this` is
// SchedulerDOSurface, so verify consults the IdP epoch and the per-subject epoch through `this`.

import { type AuthMethod, passkeySubject } from "../admin/identity.ts";
import { getIdpConnectionRaw } from "../admin/oidc-store.ts";
import { SESSION_KEY_BYTES, signSession, slideDue, verifySession, verifySessionClassified } from "../admin/session.ts";
import { coarseSignInPrefix, evaluateSignInContext, type SeenContext } from "../admin/sign-in-context.ts";
import { b64urlDecode, b64urlEncode } from "../crypto/bytes.ts";
import { AuthError, OIDC_GROUPS_PREFIX, PASSKEY_SESSION_KEY_KEY, type SchedulerDOCtor, SESSION_EPOCH_PREFIX } from "./scheduler-do-base.ts";

// SIGNIN_CONTEXT_PREFIX keys the per-operator coarse seen-context baseline (R6, ASVS V6.3.5):
// signinctx:<stable subject> -> SeenContext[] (a bounded, TTL-pruned list of /24 / /48 prefixes;
// never a raw IP). One small record per operator; removed operators simply expire via the TTL.
const SIGNIN_CONTEXT_PREFIX = "signinctx:";

import { nowMillisISO } from "./scheduler-helpers.ts";

export function SessionMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- WebAuthn / passkey: the engine's own identity provider ---------------------------------
    // The DO is the storage authority for the passkey records and the SINGLE place the challenge is
    // issued and single-use consumed, so the verification and the consume share one read-modify-write and
    // a replayed challenge cannot pass. The verifier itself (passkey.ts) is pure; this layer owns storage,
    // the bootstrap, and the clone-detection persistence. rp.id and origin are passed in by the router
    // (the DO holds no env). A verification fault is logged with an opaque error id and surfaced coarsely.

    // SessionKeyRecord is the persisted session-signing key (see PASSKEY_SESSION_KEY_KEY). It carries ONLY
    // the base64url key bytes and when it was created; it is the one DO record that DOES hold a secret (the
    // MAC key), so it is never surfaced by any read route (no GET path returns it) and is read only by the
    // in-DO sign/verify below.
    // (Defined inline where used, rather than as a separate interface, to keep the secret's shape adjacent
    // to its single reader/writer; the value is structured-cloned through DO storage like the rest.)

    // sessionSigningKey loads the persisted session-signing key, GENERATING and persisting it on first use.
    // It is the single accessor both passkeySessionIssue and passkeySessionVerify go through, so the key is
    // created lazily exactly once and both the mint and the verify use the identical bytes. The raw bytes
    // are decoded from the stored base64url; a stored record that somehow held an invalid/short value is
    // treated as absent and a fresh key is generated (fail-safe: a corrupt key would only invalidate old
    // sessions, never weaken a new one).
    //
    // RACE (SESSION KEY): a DO request handler is not atomic across its `await` points, so two requests that
    // both hit a cold DO (no key persisted yet) could each read undefined, each generate a fresh key, and
    // each write, leaving the SECOND write's key in storage while a token was minted under the FIRST: the
    // first session would then fail to verify. The read-generate-write is therefore wrapped in
    // blockConcurrencyWhile, which serialises it against every other handler on this DO, so the
    // check-then-write is atomic: the first caller generates and persists, and every concurrent caller that
    // was waiting then reads the now-persisted key. blockConcurrencyWhile is available in the Workers
    // runtime; the validator's storage double provides a pass-through so the same path runs under test.
    async sessionSigningKey(): Promise<Uint8Array> {
      const fromRecord = (rec: { key?: string } | undefined): Uint8Array | null => {
        if (rec !== undefined && typeof rec.key === "string" && rec.key.length > 0) {
          try {
            const bytes = b64urlDecode(rec.key);
            if (bytes.length >= SESSION_KEY_BYTES) return bytes;
          } catch {
            // fall through to regenerate on a corrupt stored value
          }
        }
        return null;
      };
      // Fast path: a key already exists. This read needs no serialisation (a present, valid key is never
      // rewritten), so the common case stays a single cheap read with no concurrency gate.
      const existing = fromRecord(await this.state.storage.get<{ key: string; createdAt: string }>(PASSKEY_SESSION_KEY_KEY));
      if (existing !== null) return existing;
      // No usable key yet: generate-and-persist atomically so two concurrent cold-start callers cannot
      // each write a different key. Re-read inside the critical section in case another caller won the race
      // while this one was waiting on the gate.
      return this.blockConcurrencyWhile(async () => {
        const reread = fromRecord(await this.state.storage.get<{ key: string; createdAt: string }>(PASSKEY_SESSION_KEY_KEY));
        if (reread !== null) return reread;
        // G168 (THE HEADLINE): a MISSING or CORRUPT session signing key is regenerated here, silently, and
        // every live session in the account instantly stops verifying -- a MASS LOGOUT with no terminate-all
        // anywhere in the audit chain. The only tell was a suspiciously young key age in authPosture, which is
        // an inference, not a fact. Cold start writes this too (harmless, and honest: it IS the moment the key
        // came into existence). Count only: no key, no length, no material.
        const fresh = crypto.getRandomValues(new Uint8Array(SESSION_KEY_BYTES));
        await this.state.storage.put(PASSKEY_SESSION_KEY_KEY, { key: b64urlEncode(fresh), createdAt: nowMillisISO() });
        await this.recordAuthSignal("session-signing-key-regenerated");
        return fresh;
      });
    }

    // sessionSigningKeyHealth reports the PRESENCE and AGE of the session HMAC signing key WITHOUT the key (P4).
    // A "everyone was logged out at once" incident is a session-signing-key rotation: terminate-all rotates it,
    // and a lost/regenerated key invalidates every live session (their MACs no longer verify). So a YOUNG key age
    // paired with a session-verify-failure spike is the tell (session-signing-key-lost). Redaction-safe: a boolean
    // + an int age in ms, NEVER the key bytes. ageMs is omitted when the key is absent or the createdAt is
    // unparseable / from a legacy record written before createdAt was stamped.
    async sessionSigningKeyHealth(): Promise<{ present: boolean; ageMs?: number; adequateLength?: boolean }> {
      const rec = await this.state.storage.get<{ key?: string; createdAt?: string }>(PASSKEY_SESSION_KEY_KEY);
      const present = rec !== undefined && typeof rec.key === "string" && rec.key.length > 0;
      if (!present) return { present: false };
      // P3 (recovery-key-too-short): the session signing key WAS ALSO the recovery-code HMAC key (the two are
      // separate records since TERMINATE-ALL-DESTROYS-RECOVERY-CODES; recoverySigningKeyHealth reports
      // the recovery half, and on an account that predates the split this key is still the one the recovery key
      // is adopted FROM, so its adequacy still governs the adopted key). The HMAC requires
      // >= SESSION_KEY_BYTES (32) bytes or hmacKey throws and recovery-code sign-in is broken. Report whether the
      // STORED key decodes to an adequate length (a durable health flag, NEVER the key bytes), so a present-but-
      // short key - a misconfiguration that would otherwise only surface when a locked-out Owner tries a recovery
      // code - is visible in the pack. A decode failure reads as inadequate.
      let adequateLength = false;
      try {
        adequateLength = b64urlDecode((rec!.key as string).trim()).length >= SESSION_KEY_BYTES;
      } catch {
        adequateLength = false; // an unparseable stored key is not a usable signing key
      }
      const createdMs = typeof rec?.createdAt === "string" ? Date.parse(rec.createdAt) : NaN;
      if (!Number.isFinite(createdMs)) return { present: true, adequateLength };
      return { present: true, ageMs: Math.max(0, Date.now() - createdMs), adequateLength };
    }

    // blockConcurrencyWhile runs `fn` with this DO's input gate closed (no other request handler runs until
    // it resolves), so a read-modify-write inside it is atomic against concurrent requests. It delegates to
    // the platform DurableObjectState.blockConcurrencyWhile when present; under the offline validator (whose
    // storage double has no such method) it falls back to running `fn` directly, which is safe there because
    // the validator drives the DO serially (one awaited fetch at a time).
    blockConcurrencyWhile<T>(fn: () => Promise<T>): Promise<T> {
      const gate = (this.state as { blockConcurrencyWhile?: (cb: () => Promise<T>) => Promise<T> }).blockConcurrencyWhile;
      return typeof gate === "function" ? gate.call(this.state, fn) : fn();
    }

    // terminateAllSessions is the OWNER-ONLY "terminate ALL sessions, every member" lever (ASVS V7.4.5,
    // the all-users case): it deletes the session signing key, so EVERY outstanding session token fails its
    // next MAC verify and a fresh key is generated on the next issue. It is the in-account equivalent of a
    // global sign-out (a break-glass after a suspected key/session compromise). Gated on roles.write
    // re-resolved AND callerRole === owner (only an Owner may sign the whole account out). Audited.
    async terminateAllSessions(
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ ok: boolean }> {
      const resolved = await this.requireCapabilityResolved(caller, "roles.write");
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may terminate all sessions");
      // ORDER IS LOAD-BEARING (TERMINATE-ALL-DESTROYS-RECOVERY-CODES). The recovery-code HMAC key used
      // to BE this key, so the delete below silently destroyed every banked recovery code in the account: the
      // break-glass an Owner reaches for after a suspected compromise took away the break-glass they would need
      // if the compromise were real. The keys are separate records now, but on an account that predates the
      // split the recovery record is materialised LAZILY by adoption FROM this key, so it must be materialised
      // BEFORE the key it copies is deleted. Do it in this order and an interruption between the two lines can
      // only mean the sign-out did not happen; do it the other way and it means a factor was lost, which is the
      // strictly worse failure and the one this fix exists to remove.
      await this.recoverySigningKey();
      await this.state.storage.delete(PASSKEY_SESSION_KEY_KEY);
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null, actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access", sourceIp: caller?.sourceIp ?? null,
        action: "session-terminate", outcome: "success", target: { kind: "access-policy" },
      });
      return { ok: true };
    }

    // recordSignInContext is the R6 unusual-location check (ASVS V6.3.5), run at every sign-in SUCCESS
    // (OIDC/SAML in the DO's own success blocks; passkey via POST /signin-context after the router minted
    // the session). It is a no-op returning false unless the owner opted in (notifyNewSignInContext) AND a
    // coarse prefix is computable from the source IP. The RAW IP is used only in-memory to derive the
    // IPv4 /24 or IPv6 /48 prefix and is NEVER stored (sacred: no-custody, no movement log); the bounded
    // per-operator seen-set (evaluateSignInContext prunes to the TTL and caps to the newest ten) is keyed
    // by the operator's STABLE subject under signinctx:. Returns whether this context is materially NEW
    // (the caller surfaces that to the router, which fires the redaction-safe sign-in-new-context notify);
    // the FIRST context ever seen is the baseline, never an alert, but a baseline every row of which has aged
    // past the TTL is NOT a first-ever baseline and does alert (see evaluateSignInContext). Fail-safe: any
    // storage surprise reads as not-new, so the check can never block or delay a sign-in.
    async recordSignInContext(subject: string, sourceIp: string | null | undefined): Promise<boolean> {
      if (typeof subject !== "string" || subject.length === 0) return false;
      if (!(await this.getNotifyNewSignInContext())) return false; // the policy is OFF: not a skip, a choice
      const prefix = coarseSignInPrefix(sourceIp);
      if (prefix === null) {
        // G168: the owner OPTED IN to new-sign-in-location alerts and the context cannot be read (no usable
        // source IP -- a proxy that strips it, a runtime that does not supply it), so the check silently
        // ABSTAINS on every sign-in and the alert they switched on never fires. Never the IP, only the skip.
        await this.recordAuthSignalThrottled("signin-context-skipped");
        return false;
      }
      const key = `${SIGNIN_CONTEXT_PREFIX}${subject}`;
      const seen = (await this.state.storage.get<SeenContext[]>(key)) ?? [];
      const verdict = evaluateSignInContext(Array.isArray(seen) ? seen : [], prefix, Date.now());
      await this.state.storage.put(key, verdict.updated);
      if (verdict.baselineLapsed) {
        // The operator HAD a baseline and every row of it aged past the TTL, so this sign-in was judged
        // against nothing. It alerts (verdict.isNew is true unless the prefix is somehow already live, which
        // it cannot be when the live set is empty), and the lapse is ALSO counted, because the two facts have
        // different remedies: the alert asks "was this you?", the count answers "why did that fire on my own
        // office network?" -- it fired because we had not seen you for ninety days. Never the prefix, the IP
        // or the subject: the closed name and an int, exactly as the sibling skip signal above.
        await this.recordAuthSignalThrottled("signin-context-baseline-lapsed");
      }
      return verdict.isNew;
    }

    // passkeySessionIssue mints a signed session token for an ALREADY-VERIFIED email. The router calls this
    // ONLY after passkeyLoginFinish returned ok (so the email here is one a WebAuthn assertion just proved);
    // this method does not itself re-verify the login (it cannot - the proof was the assertion), it only
    // binds the proven email into a signed, short-TTL token. It normalises the email through the SAME
    // normaliseEmail discipline the role table uses, so the token's email and the role-table key are the one
    // canonical string. A non-usable email is refused (ok:false) rather than minting a session for a
    // malformed identity. The signing uses the in-DO key (sessionSigningKey); only the token string crosses
    // back to the router (the key never does).
    async passkeySessionIssue(body: { email?: unknown }): Promise<{ ok: true; token: string } | { ok: false }> {
      const email = this.normaliseEmail(body.email);
      if (!email) return { ok: false };
      const key = await this.sessionSigningKey();
      // V3 mint: a passkey session carries its method and its STABLE subject (passkeySubject(email)) in the
      // signed body, so the subject is never re-derived from the email downstream (the cross-method anti-forge
      // property a native oidc/saml session relies on); connId is absent (a passkey session has no connection).
      const token = await signSession(key, { method: "passkey", email, subject: passkeySubject(email), epoch: await this.getSessionEpoch(email) }, Date.now());
      return { ok: true, token };
    }

    async getSessionEpoch(canonicalEmail: string): Promise<number> {
      const n = await this.state.storage.get<number>(`${SESSION_EPOCH_PREFIX}${canonicalEmail}`);
      if (n === undefined) return 0; // never bumped: the honest zero, not a corruption
      if (typeof n === "number" && Number.isInteger(n) && n >= 0) return n;
      // G168 (A REVOCATION BYPASS): a PRESENT epoch record that reads back malformed is coerced to 0, and 0
      // means "revoke nothing" -- so every session the operator believed they had terminated verifies again.
      // Coercing is right (a corrupt byte must not crash the auth path); doing it silently is not. The corrupt
      // VALUE is never carried (it is arbitrary bytes); only the fact that it happened.
      await this.recordAuthSignalThrottled("session-epoch-record-corrupt");
      return 0;
    }
    // bumpSessionEpoch increments an email's session epoch, invalidating every session issued before the
    // bump. Called on a factor change (passkey revoke, recovery regenerate) and by the explicit
    // terminate-sessions routes. Returns the new epoch. Idempotent only in the sense that each call is a
    // distinct revocation point; callers that must keep the current session alive re-issue a fresh token
    // carrying the new epoch in the same response.
    async bumpSessionEpoch(canonicalEmail: string): Promise<number> {
      const next = (await this.getSessionEpoch(canonicalEmail)) + 1;
      await this.state.storage.put(`${SESSION_EPOCH_PREFIX}${canonicalEmail}`, next);
      return next;
    }

    // passkeySessionVerify re-checks a presented session token against the in-DO signing key and returns the
    // verified email or null. It is the per-request session check the router's authorise() path drives (via a
    // DO fetch) so the constant-time MAC + the exp check happen over the key that never leaves the DO. A
    // non-string/empty token, a bad MAC, an expired token, or any malformed body all resolve to a REJECTED
    // verdict (fail closed), which the router treats as "no valid passkey session" and does NOT downgrade to
    // the token path (the same fail-closed discipline as a rejected Access JWT).
    //
    // G201 (THE CONTRACT TOKEN). Every answer this function gives carries an explicit closed `verdict`:
    // "verified" or "rejected". The client-facing behaviour is UNCHANGED (email:null is still the whole of the
    // rejection, so the anti-oracle property holds), but the router can now tell an answer this function GAVE
    // from an answer it never gave. scheduler.fetch() does not throw on an HTTP error status, so an up-but-
    // broken DO (a storage fault, a TypeError, route drift) replies through the outer catch's JSON 500 envelope,
    // which carries NO verdict. Without this token the router had to infer "did the DO answer?" from the shape
    // of the payload, and it inferred it wrongly: it read the ordinary rejection as a broken DO, and the broken
    // DO as an ordinary rejection. The verdict makes the two states nameable rather than guessable.
    async passkeySessionVerify(body: { token?: unknown }): Promise<{ verdict: "verified"; email: string; subject: string; method: AuthMethod; connId: string | null; groups: string[]; slidToken?: string } | { verdict: "rejected"; email: null }> {
      if (typeof body.token !== "string" || body.token.length === 0) return { verdict: "rejected", email: null };
      const now = Date.now();
      const key = await this.sessionSigningKey();
      // G233: the CLASSIFIED verify. verifySession returns a bare null BY DESIGN -- an anti-oracle property for
      // the caller, which we KEEP (the { email: null } we return below is byte-identical, and the client-facing
      // 401 is unchanged). But that null was also all the PACK ever saw, so a logout STORM, an idle window tuned
      // too tight, an EXPECTED one-time re-auth after a token-shape upgrade, and a MAC MISMATCH (a forgery
      // attempt: a SECURITY signal, not a config fault) were one undifferentiated silence. verifySessionClassified
      // returns the closed class instead of discarding it -- and until this wiring it had NO CALLER AT ALL: the
      // vocabulary existed, the recorder existed, and nothing on the fault path ever produced a single record.
      const classified = await verifySessionClassified(key, body.token, now);
      if ("fault" in classified) {
        // The closed class (never a token, a MAC, an email or a claim). Throttled: this is the per-request
        // session check, so a mass logout lands every user's every request here.
        await this.recordAuthSignalThrottled(classified.fault);
        // G168: the coarse verify-failure counter is KEPT alongside the class. On its own it is noise; PAIRED
        // with session-signing-key-regenerated it is the definitive "your signing key was lost and every session
        // died at once" diagnosis, and existing consumers key on it.
        await this.recordAuthSignalThrottled("session-verify-failed");
        return { verdict: "rejected", email: null };
      }
      const res: typeof classified | null = classified;
      // Session-revocation gate (email axis): a token whose epoch is below the email's current stored epoch was
      // issued before a termination/factor-change and is no longer valid (fail closed, like an expired token).
      // A native oidc/saml v3 session ALSO carries the email epoch, so termination-by-email revokes it too; the
      // per-connection idpEpoch axis (kill all of one connection's sessions) is wired in Phase 2.
      if (res.epoch < (await this.getSessionEpoch(res.email))) {
        // P3 (session-idle-upgrade-reauth): this session predates a session-epoch bump (terminate-all, a
        // factor change, or an explicit terminate-sessions), so it is forced to re-authenticate. Record the
        // bounded signal so a "everyone got logged out / kept being asked to sign in again" ticket is
        // diagnosable as a version-invalidation event. Fires ONLY on an actual revocation, not per verify.
        await this.recordAuthSignal("session-revoked-email-epoch");
        return { verdict: "rejected", email: null };
      }
      // Per-SUBJECT axis (deprovision a principal) and per-CONNECTION axis (disable/delete/rotate a connection):
      // both are "not-before" instants compared against the token's signed iat. A session minted before either
      // stamp is dead. The email axis above is the monotonic-counter axis (terminate-others keeps the current
      // session alive by re-minting it with the bumped counter); these two have no such carve-out. A passkey
      // session carries connId null, so only the email + subject axes apply to it.
      if (res.iat < (await this.getSessionEpochSub(res.subject))) {
        // G168: the SUBJECT axis (a deprovisioned principal). One of the two revocation axes that had no
        // counter, unlike the email/idp ones, so a deprovision-driven sign-out showed ZERO session-revoked
        // counts and read as an unexplained lockout.
        await this.recordAuthSignal("session-revoked-subject-epoch");
        return { verdict: "rejected", email: null };
      }
      if (res.connId !== null && res.iat < (await this.getIdpEpoch(res.connId))) {
        // P3 (idp-epoch-resolver-failclosed): this oidc/saml session predates its connection's idpEpoch, so the
        // connection was disabled / deleted / had its secret rotated after the session was minted and every
        // session on that connection is now refused (fail closed). Record the bounded signal so a "the whole team
        // on one IdP was signed out" ticket is diagnosable. Fires ONLY on this connection-revocation branch.
        await this.recordAuthSignal("session-revoked-idp-epoch");
        return { verdict: "rejected", email: null };
      }
      // Authoritative connection-liveness at VERIFY time: an oidc/saml session is valid only while its connection
      // still EXISTS and is ENABLED. This closes the mint-after-bump TOCTOU the idpEpoch not-before instant cannot
      // (a connection deleted/disabled DURING an in-flight login mints a session with iat AFTER the bump, so the
      // instant check passes; re-reading the record denies it on the very next request). A pure DO storage read
      // (no IdP network), fail-closed; connId is null for a passkey session, so the passkey/token no-lockout path
      // never loads a connection and is untouched.
      if (res.connId !== null) {
        const liveConn = await getIdpConnectionRaw(this.idpKv, res.connId);
        if (liveConn === undefined || !liveConn.enabled) {
          // G168: the CONNECTION-LIVENESS axis, the other uninstrumented one. This is the branch that fires
          // when a connection is deleted or disabled mid-session -- "the whole team on one IdP got signed out"
          // -- and it is DISTINCT from the idpEpoch not-before check above (this one closes the TOCTOU).
          await this.recordAuthSignal("session-conn-liveness-refused");
          return { verdict: "rejected", email: null };
        }
      }
      // For an oidc/saml session the GROUPS live in a server-side snapshot (oidcgroups:<subject>), re-read here
      // each request so a group change (or a deprovision) takes effect WITHOUT waiting out the 12h cookie - the
      // cookie never carries groups. A passkey session has none. The router forwards these into the caller header
      // so the existing subject-keyed role resolution (group->role) applies to a native-IdP caller unchanged.
      let groups: string[] = [];
      if (res.method === "oidc" || res.method === "saml") {
        const snapshot = await this.state.storage.get<string[]>(`${OIDC_GROUPS_PREFIX}${res.subject}`);
        // G168: an SSO session whose group snapshot is MISSING silently loses every group-derived role for
        // that request -- the user is signed in and quietly demoted to their built-in floor, mid-session, with
        // no error. Count only: never a group name or a subject.
        if (snapshot === undefined) await this.recordAuthSignalThrottled("group-snapshot-missing");
        groups = this.boundGroupList(snapshot ?? []);
      }
      // SLIDE (ASVS V7.3.1): keep an ACTIVE session alive by refreshing lastSeen when it is older than
      // SESSION_SLIDE_MS. The re-mint preserves the original iat + absolute exp (slide:{iat,exp}) and the
      // session's CURRENT epoch (res.epoch, which just passed the email-axis gate), so sliding never extends the
      // 12h cap and a concurrent epoch bump still kills the slid token on its next verify. A pure re-sign (no
      // storage write); the router sets the returned token as a fresh cookie. A legacy V2 token is upgraded to
      // V3 by the same re-sign (its absolute exp is preserved), so it too gains the idle bound from then on.
      let slidToken: string | undefined;
      if (slideDue(res.lastSeen, now)) {
        slidToken = await signSession(
          key,
          { method: res.method, email: res.email, subject: res.subject, ...(res.connId !== null ? { connId: res.connId } : {}), epoch: res.epoch, slide: { iat: res.iat, exp: res.exp } },
          now,
        );
      }
      // Return the SIGNED subject + method (+ connId) VERBATIM, never re-derived: a native oidc/saml session
      // keeps its immutable IdP principal; a passkey (v2 or v3) session resolved to passkeySubject(email)/"passkey".
      return { verdict: "verified", email: res.email, subject: res.subject, method: res.method, connId: res.connId, groups, ...(slidToken !== undefined ? { slidToken } : {}) };
    }

    // terminateOwnOtherSessions bumps the caller's OWN session epoch (invalidating every other session for
    // their email) and returns a freshly-minted token carrying the new epoch, so the CURRENT session stays
    // alive while all others die (V7.5.2 "view and terminate other active sessions"). The caller's email is
    // the verified one the router forwards (a session/Access/passkey caller); a bare-token caller has no
    // first-party session to manage and is refused upstream.
    //
    // NOT AN AUTHENTICATION EVENT (ASVS V7.3 / V7.5.1): this is self-service housekeeping on an ALREADY-
    // established session, so the re-mint below MUST be a SLIDE (preserve the caller's presented iat/exp),
    // exactly like the idle-slide re-mint above, never an implicit fresh login. The router forwards the
    // caller's own raw cookie (the SAME one authorise() already verified for this very request) as
    // body.token; re-verifying it here with the PURE primitive (not the layered passkeySessionVerify, whose
    // epoch check would reject this very token the instant bumpSessionEpoch below moves the goalposts)
    // recovers that iat/exp BEFORE anything is mutated, so a verify failure - which should only happen in a
    // vanishing race - leaves every session untouched instead of bumping the epoch and then having no valid
    // replacement to hand back. Without this, a stale-but-valid (past STEPUP_FRESH_MS) session could call
    // this one benign endpoint to silently reset iat to now, defeating step-up for 5 minutes with zero
    // WebAuthn proof, and repeat it every ~11.9h to defeat the absolute 12h cap entirely.
    async terminateOwnOtherSessions(
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; connId?: string | null; sourceIp?: string | null } | null,
      body: { token?: unknown },
    ): Promise<{ ok: true; token: string } | { ok: false }> {
      const email = caller ? this.normaliseEmail(caller.email) : null;
      if (!email) return { ok: false };
      const now = Date.now();
      const key = await this.sessionSigningKey();
      const verified = typeof body.token === "string" ? await verifySession(key, body.token, now) : null;
      if (verified === null) return { ok: false };
      const epoch = await this.bumpSessionEpoch(email);
      // Re-mint the caller's CURRENT session carrying the new epoch (so this session survives while the others
      // die). A native oidc/saml caller MUST keep its OWN method + signed subject + connId: collapsing it to a
      // passkey subject would LAUNDER the (possibly UNVERIFIED) IdP email into the auto-binding passkey|<email>
      // subject - defeating the email_verified open-bind gate (an unbound owner invite for that email would then
      // bind to the passkey subject) - AND drop connId so the per-connection idpEpoch revocation axis would no
      // longer apply. The subject is taken VERBATIM from the verified caller header, never re-derived; an
      // oidc/saml header missing its subject or connId is malformed and refused (refusing, not re-deriving, is
      // the point). A passkey caller keeps the stable passkeySubject(email) exactly as before.
      const method: AuthMethod = caller ? caller.method : "passkey";
      let mintMethod: AuthMethod = "passkey";
      let subject = passkeySubject(email);
      let connId: string | undefined;
      if (method === "oidc" || method === "saml") {
        const callerSubject = caller && typeof caller.subject === "string" ? caller.subject : null;
        const callerConnId = caller && typeof caller.connId === "string" ? caller.connId : null;
        if (callerSubject === null || callerConnId === null) return { ok: false };
        mintMethod = method;
        subject = callerSubject;
        connId = callerConnId;
      }
      const token = await signSession(key, { method: mintMethod, email, subject, ...(connId !== undefined ? { connId } : {}), epoch, slide: { iat: verified.iat, exp: verified.exp } }, now);
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null, actorEmail: email, actorMethod: caller ? caller.method : "passkey",
        sourceIp: caller?.sourceIp ?? null, action: "session-terminate", outcome: "success", target: { kind: "access-policy" },
      });
      return { ok: true, token };
    }

    // terminateUserSessions is the ADMIN "terminate this user's sessions" (V7.4.5): bump a target email's
    // epoch so all their sessions die on the next request. Gated on roles.write (re-resolved), and an
    // Owner's sessions may be terminated only BY an Owner (requireNotOwnerEscalation). Audited.
    async terminateUserSessions(
      req: { email?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ ok: boolean }> {
      const target = this.normaliseEmail(req.email);
      if (!target) throw new Error("email must be a valid lowercased address");
      const resolved = await this.requireCapabilityResolved(caller, "roles.write");
      const now = Date.now();
      const entries = await this.listRoleEntries();
      const pending = await this.listPendingEntries();
      const targetEntry = entries.find((e) => e.email === target) ?? pending.find((p) => p.email === target);
      this.requireNotOwnerEscalation(resolved.role, false, this.effectiveRole(targetEntry, now) === "owner");
      await this.bumpSessionEpoch(target);
      // Also bump the per-SUBJECT revocation axis for the target's BOUND subject (once they have authenticated):
      // an oidc/saml session keys revocation on the subject (its signed iat vs sessionEpochSub), so this kills
      // those sessions too, not only the email-keyed ones. A still-pending (unbound) invitee has no subject yet.
      const boundSubject = entries.find((e) => e.email === target)?.subject;
      if (boundSubject) await this.bumpSessionEpochSub(boundSubject, now);
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null, actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access", sourceIp: caller?.sourceIp ?? null,
        action: "session-terminate", outcome: "success", target: { kind: "role", email: target, role: this.effectiveRole(targetEntry, now) },
      });
      return { ok: true };
    }

    // passkeySessionLogout terminates the caller's OWN sessions on an explicit logout (ASVS V7.4.1: a session is
    // terminated on logout, not merely cookie-cleared client-side). The stateless token model holds no per-session
    // row, so the server-side kill is coarse: verify the presented token to resolve the identity, then bump the
    // per-email epoch (kills every email-keyed session - passkey and oidc/saml both carry it) and the per-subject
    // not-before instant. The just-logged-out token, and any exfiltrated copy, then fail closed on the next
    // request. Oracle-free and BEST-EFFORT: an absent/expired/already-revoked token resolves to email:null and
    // bumps nothing, still returning ok (the router clears the cookie and returns 200 regardless).
    async passkeySessionLogout(body: { token?: unknown; sourceIp?: unknown }): Promise<{ ok: boolean }> {
      const verified = await this.passkeySessionVerify({ token: body.token });
      // G168: a logout that matched NOTHING still answers ok (deliberately: an oracle-free 200), so the user is
      // told they signed out and nothing was revoked. Benign when the token was already dead; NOT benign when
      // it is a symptom (a token the DO cannot verify, e.g. after the signing key was regenerated, cannot be
      // revoked either -- so a stolen copy stays live). Count the no-op.
      if (verified.email === null) await this.recordAuthSignal("session-logout-noop");
      if (verified.email !== null) {
        const now = Date.now();
        await this.bumpSessionEpoch(verified.email);
        await this.bumpSessionEpochSub(verified.subject, now);
        await this.appendAudit({
          actorSubject: verified.subject,
          actorEmail: verified.email,
          actorMethod: verified.method,
          sourceIp: typeof body.sourceIp === "string" ? body.sourceIp : null,
          action: "session-terminate",
          outcome: "success",
          target: { kind: "access-policy" },
        });
      }
      return { ok: true };
    }
  };
}
