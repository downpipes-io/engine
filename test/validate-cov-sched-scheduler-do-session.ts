// validate-cov-sched-scheduler-do-session: branch-coverage proof for the session-lifecycle mixin
// (src/sched/scheduler-do-session.ts) - the WebAuthn-minted session signing key (lazy generate +
// persist, corrupt/short/absent fall-safe regeneration, the blockConcurrencyWhile gate both with and
// without a platform gate), the per-email/per-subject/per-connection revocation axes, the idle slide,
// the connection-liveness verify gate, and the four termination levers (all / own-other / by-user /
// logout). It drives the REAL SchedulerDO over an in-memory storage double, calling the production
// session methods directly and minting tokens with the DO's OWN signing key via the real signSession,
// so every path under test is the production one. Every assertion checks a real outcome: a returned
// {ok}/email/token, a stored epoch row, a deleted key, a revoked-session null, or a slid token.
//
// Role resolution is the genuine DO logic: a method:"token" caller is the owner break-glass (resolves to
// owner with no table lookup), and a seeded role:sub:<subject> access-admin entry resolves to a caller
// that HOLDS roles.write but is NOT an Owner (the only way to reach the owner-only refusal in
// terminateAllSessions). No network and no clock-or-random dependent assertions, so the run is deterministic.
//
// Run: node test/validate-cov-sched-scheduler-do-session.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { signSession, verifySession, SESSION_KEY_BYTES, SESSION_SLIDE_MS, SESSION_IDLE_MS, SESSION_TTL_MS } from "../src/admin/session.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { passkeySubject, roleSubjectKey } from "../src/admin/identity.ts";
import {
  PASSKEY_SESSION_KEY_KEY,
  SESSION_EPOCH_PREFIX,
  SESSION_EPOCH_SUB_PREFIX,
  OIDC_GROUPS_PREFIX,
} from "../src/sched/scheduler-do-base.ts";
import { CONN_PREFIX } from "../src/admin/oidc-store-kv.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

// A loose caller shape (the DO recomputes the role itself; method:"token" is the owner break-glass).
type TestCaller = {
  method: string;
  email: string | null;
  subject: string | null;
  groups: string[];
  connId?: string | null;
  sourceIp?: string | null;
} | null;

// The session methods under test, typed loosely (the runner strips types; the real instance carries them).
interface SessionDO {
  sessionSigningKey(): Promise<Uint8Array>;
  terminateAllSessions(caller: TestCaller): Promise<{ ok: boolean }>;
  passkeySessionIssue(body: { email?: unknown }): Promise<{ ok: boolean; token?: string }>;
  getSessionEpoch(email: string): Promise<number>;
  bumpSessionEpoch(email: string): Promise<number>;
  passkeySessionVerify(body: { token?: unknown }): Promise<{ email: string | null; subject?: string; method?: string; connId?: string | null; groups?: string[]; slidToken?: string }>;
  terminateOwnOtherSessions(caller: TestCaller, body: { token?: unknown }): Promise<{ ok: boolean; token?: string }>;
  terminateUserSessions(req: { email?: string }, caller: TestCaller): Promise<{ ok: boolean }>;
  passkeySessionLogout(body: { token?: unknown; sourceIp?: unknown }): Promise<{ ok: boolean }>;
  bumpSessionEpochSub(subject: string, nowMs: number): Promise<void>;
  bumpIdpEpoch(connId: string, nowMs: number): Promise<void>;
  readAuthSignals(): Promise<Record<string, { count: number; lastAt: string }>>;
  sessionSigningKeyHealth(): Promise<{ present: boolean; ageMs?: number; adequateLength?: boolean }>;
}

function makeDO(): { dobj: SessionDO; storage: MockStorage } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState) as unknown as SessionDO;
  return { dobj, storage };
}

const connKey = (id: string): string => `${CONN_PREFIX}${id}`;

async function main(): Promise<void> {
  // ============================================================================================
  // 1. sessionSigningKey: lazy generate + persist, the fast path, and the fail-safe regeneration of an
  //    absent / non-string / empty / SHORT / CORRUPT stored key (fromRecord every arm).
  // ============================================================================================
  {
    const { dobj, storage } = makeDO();
    // Cold start: the first call GENERATES + persists exactly one valid key (the reread===null arm inside
    // the gate, and the fn() fallback arm of blockConcurrencyWhile since this state has no platform gate).
    const k1 = await dobj.sessionSigningKey();
    ok("sessionSigningKey: cold start generates a valid 32-byte key", k1.length === SESSION_KEY_BYTES);
    ok("sessionSigningKey: exactly one key record persisted", (await storage.list({ prefix: PASSKEY_SESSION_KEY_KEY })).size === 1);
    // Fast path: a present, valid key is read back unchanged (existing !== null), never regenerated.
    const k1again = await dobj.sessionSigningKey();
    ok("sessionSigningKey: the fast path returns the SAME persisted key", b64urlEncode(k1again) === b64urlEncode(k1));

    // A stored record whose key is NOT a string -> treated as absent -> a fresh key is generated.
    await storage.put(PASSKEY_SESSION_KEY_KEY, { key: 123, createdAt: "x" });
    ok("sessionSigningKey: a non-string stored key regenerates", (await dobj.sessionSigningKey()).length === SESSION_KEY_BYTES);
    // A stored EMPTY-string key -> length 0 -> treated as absent.
    await storage.put(PASSKEY_SESSION_KEY_KEY, { key: "", createdAt: "x" });
    ok("sessionSigningKey: an empty stored key regenerates", (await dobj.sessionSigningKey()).length === SESSION_KEY_BYTES);
    // A stored SHORT key (valid base64url, but fewer than SESSION_KEY_BYTES) -> bytes.length < cap -> absent.
    await storage.put(PASSKEY_SESSION_KEY_KEY, { key: b64urlEncode(new Uint8Array(4)), createdAt: "x" });
    ok("sessionSigningKey: a too-short stored key regenerates", (await dobj.sessionSigningKey()).length === SESSION_KEY_BYTES);
    // A stored CORRUPT key (invalid base64url) -> b64urlDecode throws -> the catch falls through to regenerate.
    await storage.put(PASSKEY_SESSION_KEY_KEY, { key: "!!!!", createdAt: "x" });
    const kCorrupt = await dobj.sessionSigningKey();
    ok("sessionSigningKey: a corrupt stored key regenerates (decode-throw catch)", kCorrupt.length === SESSION_KEY_BYTES);
    // After regeneration the record now holds a valid key, so the next read is the fast path again.
    ok("sessionSigningKey: the regenerated key persists (next read is the fast path)", b64urlEncode(await dobj.sessionSigningKey()) === b64urlEncode(kCorrupt));

    // sessionSigningKeyHealth (recovery-key-too-short) reports whether the STORED session key (which is ALSO
    // the recovery-code HMAC key, requiring >= 32 bytes) is long enough, as a durable health flag and NEVER the
    // key bytes. A present valid key is adequate; a present-but-short or unparseable one is not.
    const healthOk = await dobj.sessionSigningKeyHealth();
    ok("sessionSigningKeyHealth: a valid key is present + adequateLength true (never the key bytes)", healthOk.present === true && healthOk.adequateLength === true && !("key" in healthOk));
    await storage.put(PASSKEY_SESSION_KEY_KEY, { key: b64urlEncode(new Uint8Array(8)), createdAt: "2026-06-13T00:00:00.000Z" });
    const healthShort = await dobj.sessionSigningKeyHealth();
    ok("sessionSigningKeyHealth: a present-but-short stored key reports adequateLength false (recovery-key-too-short)", healthShort.present === true && healthShort.adequateLength === false);
    await storage.put(PASSKEY_SESSION_KEY_KEY, { key: "!!!!", createdAt: "2026-06-13T00:00:00.000Z" });
    const healthCorrupt = await dobj.sessionSigningKeyHealth();
    ok("sessionSigningKeyHealth: an unparseable stored key reports adequateLength false (decode-throw arm)", healthCorrupt.present === true && healthCorrupt.adequateLength === false);
    await storage.put(PASSKEY_SESSION_KEY_KEY, { key: b64urlEncode(crypto.getRandomValues(new Uint8Array(SESSION_KEY_BYTES))), createdAt: "not-a-date" });
    const healthNoAge = await dobj.sessionSigningKeyHealth();
    ok("sessionSigningKeyHealth: an unparseable createdAt omits ageMs but still reports adequateLength (no-age arm)", healthNoAge.present === true && healthNoAge.ageMs === undefined && healthNoAge.adequateLength === true);
  }

  // ============================================================================================
  // 1b. blockConcurrencyWhile: the PLATFORM-GATE arm (state carries blockConcurrencyWhile) AND the
  //     reread!==null arm (the gate seeds a valid key before the critical section re-reads it).
  // ============================================================================================
  {
    const storage = new MockStorage();
    const validKey = b64urlEncode(crypto.getRandomValues(new Uint8Array(SESSION_KEY_BYTES)));
    let gateUsed = false;
    // A state double whose blockConcurrencyWhile is a real function: it seeds a valid key record THEN runs
    // the critical section, so the re-read inside the section finds a key (reread !== null) and returns it
    // verbatim rather than generating a second one - exactly the concurrent-cold-start winner semantics.
    const state = {
      storage,
      blockConcurrencyWhile: async <T>(cb: () => Promise<T>): Promise<T> => {
        gateUsed = true;
        await storage.put(PASSKEY_SESSION_KEY_KEY, { key: validKey, createdAt: "seed" });
        return cb();
      },
    };
    const gated = new SchedulerDO(state as unknown as DurableObjectState) as unknown as SessionDO;
    const k = await gated.sessionSigningKey();
    ok("blockConcurrencyWhile: the platform gate arm is used (gate.call path)", gateUsed);
    ok("blockConcurrencyWhile: the gated re-read returns the seeded key (reread !== null arm)", b64urlEncode(k) === validKey);
  }

  // ============================================================================================
  // 2. getSessionEpoch / passkeySessionIssue: the epoch default + every malformed-stored-value arm, and
  //    the issue happy path + the invalid-email refusal.
  // ============================================================================================
  {
    const { dobj, storage } = makeDO();
    ok("getSessionEpoch: an absent epoch defaults to 0", (await dobj.getSessionEpoch("none@x.example")) === 0);
    const next = await dobj.bumpSessionEpoch("e@x.example");
    ok("bumpSessionEpoch: returns the incremented epoch", next === 1);
    ok("getSessionEpoch: returns the stored integer after a bump", (await dobj.getSessionEpoch("e@x.example")) === 1);
    await storage.put(`${SESSION_EPOCH_PREFIX}str@x.example`, "not-a-number");
    ok("getSessionEpoch: a non-number stored value reads as 0", (await dobj.getSessionEpoch("str@x.example")) === 0);
    await storage.put(`${SESSION_EPOCH_PREFIX}neg@x.example`, -5);
    ok("getSessionEpoch: a negative stored value reads as 0", (await dobj.getSessionEpoch("neg@x.example")) === 0);
    await storage.put(`${SESSION_EPOCH_PREFIX}flt@x.example`, 1.5);
    ok("getSessionEpoch: a non-integer stored value reads as 0", (await dobj.getSessionEpoch("flt@x.example")) === 0);

    const iss = await dobj.passkeySessionIssue({ email: "issue@x.example" });
    ok("passkeySessionIssue: a valid email mints a token", iss.ok === true && typeof iss.token === "string" && (iss.token ?? "").length > 0);
    ok("passkeySessionIssue: an invalid email is refused (ok:false)", (await dobj.passkeySessionIssue({ email: "not a valid email!!" })).ok === false);
    ok("passkeySessionIssue: an absent email is refused (ok:false)", (await dobj.passkeySessionIssue({})).ok === false);
  }

  // ============================================================================================
  // 3. passkeySessionVerify: the malformed-token guards, the bad-MAC null, the three revocation axes
  //    (email / subject / connection), the connection-liveness gate (undefined + disabled + enabled),
  //    the oidc/saml group snapshot (both arms + the ?? [] default) and the idle slide (both connId arms).
  // ============================================================================================
  {
    const { dobj, storage } = makeDO();
    const key = await dobj.sessionSigningKey();
    const now = Date.now();
    const old = now - 30 * 60 * 1000; // > SESSION_SLIDE_MS (15m), < SESSION_IDLE_MS (2h): active but due a slide
    ok("verify fixture: the slide probe point is past the slide cadence and within the idle bound", old < now - SESSION_SLIDE_MS && now - old < SESSION_IDLE_MS);

    // Malformed-token guards + bad MAC.
    ok("verify: a non-string token -> email null", (await dobj.passkeySessionVerify({})).email === null);
    ok("verify: an empty-string token -> email null", (await dobj.passkeySessionVerify({ token: "" })).email === null);
    ok("verify: a token with a bad MAC -> email null (res null)", (await dobj.passkeySessionVerify({ token: "aaaa.bbbb" })).email === null);

    // A passing, FRESH passkey session: resolves, no groups, no slide.
    const pkFresh = await signSession(key, { method: "passkey", email: "pk@x.example", subject: passkeySubject("pk@x.example"), epoch: 0 }, now);
    const pkRes = await dobj.passkeySessionVerify({ token: pkFresh });
    ok("verify: a fresh passkey session resolves with no groups and no slide", pkRes.email === "pk@x.example" && pkRes.method === "passkey" && pkRes.connId === null && (pkRes.groups ?? []).length === 0 && pkRes.slidToken === undefined);

    // A passkey session due a slide (lastSeen old): a slidToken is re-minted (connId === null arm).
    const pkOld = await signSession(key, { method: "passkey", email: "pks@x.example", subject: passkeySubject("pks@x.example"), epoch: 0 }, old);
    const pkSlid = await dobj.passkeySessionVerify({ token: pkOld });
    ok("verify: an active-but-stale passkey session slides (slidToken minted, connId-null arm)", pkSlid.email === "pks@x.example" && typeof pkSlid.slidToken === "string");

    // EMAIL-epoch axis: a token issued before an email-epoch bump is revoked.
    const emTok = await signSession(key, { method: "passkey", email: "em@x.example", subject: passkeySubject("em@x.example"), epoch: 0 }, now);
    await dobj.bumpSessionEpoch("em@x.example");
    ok("verify: an email-epoch bump revokes the pre-bump session", (await dobj.passkeySessionVerify({ token: emTok })).email === null);

    // SUBJECT-epoch axis: a deprovision stamp (a not-before instant) revokes a session whose iat predates it.
    const subTok = await signSession(key, { method: "passkey", email: "sub@x.example", subject: passkeySubject("sub@x.example"), epoch: 0 }, now);
    await dobj.bumpSessionEpochSub(passkeySubject("sub@x.example"), now + 60_000);
    ok("verify: a subject-epoch bump revokes the session (per-principal axis)", (await dobj.passkeySessionVerify({ token: subTok })).email === null);

    // CONNECTION-epoch axis: an oidc session minted before the connection's idpEpoch stamp is revoked
    // (this trips BEFORE the liveness read, so no connection record is needed).
    const oidcRev = await signSession(key, { method: "oidc", email: "oir@x.example", subject: "oidc:entrarev|iss|s", connId: "entrarev", epoch: 0 }, now);
    await dobj.bumpIdpEpoch("entrarev", now + 60_000);
    ok("verify: an idp-epoch bump revokes the oidc session (per-connection axis)", (await dobj.passkeySessionVerify({ token: oidcRev })).email === null);

    // The two forced-re-auth revocation branches record their bounded auth-signals (email/version-epoch and
    // idp-epoch), so a "everyone / a whole IdP got signed out" incident is diagnosable from the support pack. The
    // subject-epoch axis (deprovision) is deliberately NOT signalled here (it is the per-principal path).
    const revSignals = await dobj.readAuthSignals();
    ok("verify: the email-epoch revocation recorded session-revoked-email-epoch (forced re-auth signal)", (revSignals["session-revoked-email-epoch"]?.count ?? 0) > 0);
    ok("verify: the idp-epoch revocation recorded session-revoked-idp-epoch (per-connection forced re-auth)", (revSignals["session-revoked-idp-epoch"]?.count ?? 0) > 0);
    // The entry carries the TEMPORAL SHAPE (a 14-slot day ring of COUNTS, a firstAt, a capSaturated latch),
    // because a burst and a trickle would otherwise be the same row. The assertion this test exists to
    // make is the REDACTION one -- no token, e-mail or subject may ever appear -- so it pins the closed FIELD
    // SET and each field's type: a new key must be a number, a boolean, an ISO stamp or a ring of ints.
    const ALLOWED_SIGNAL_KEYS = new Set(["count", "lastAt", "firstAt", "capSaturated", "dayEpoch", "days"]);
    ok("verify: every recorded revocation signal is a closed name -> counts/timestamps only (no token/email/subject)",
      Object.entries(revSignals).every(([, v]) => {
        const e = v as unknown as Record<string, unknown>;
        if (!Object.keys(e).every((k) => ALLOWED_SIGNAL_KEYS.has(k))) return false;
        if (typeof e.count !== "number" || typeof e.lastAt !== "string") return false;
        if (e.firstAt !== undefined && typeof e.firstAt !== "string") return false;
        if (e.capSaturated !== undefined && typeof e.capSaturated !== "boolean") return false;
        if (e.dayEpoch !== undefined && typeof e.dayEpoch !== "number") return false;
        if (e.days !== undefined && !(Array.isArray(e.days) && e.days.every((n) => typeof n === "number"))) return false;
        return true;
      }));

    // CONNECTION-LIVENESS gate: an oidc session whose connection no longer EXISTS (liveConn undefined).
    const oidcGhost = await signSession(key, { method: "oidc", email: "onc@x.example", subject: "oidc:ghost|iss|s", connId: "ghost", epoch: 0 }, now);
    ok("verify: an oidc session for a deleted connection -> null (liveConn undefined arm)", (await dobj.passkeySessionVerify({ token: oidcGhost })).email === null);
    // ... and one whose connection exists but is DISABLED (!liveConn.enabled).
    await storage.put(connKey("disd"), { id: "disd", kind: "oidc", enabled: false });
    const oidcDis = await signSession(key, { method: "oidc", email: "od@x.example", subject: "oidc:disd|iss|s", connId: "disd", epoch: 0 }, now);
    ok("verify: an oidc session for a disabled connection -> null (!liveConn.enabled arm)", (await dobj.passkeySessionVerify({ token: oidcDis })).email === null);

    // A PASSING oidc session: connection enabled, groups snapshot present (the oidc arm + the left side of ?? []).
    await storage.put(connKey("entra"), { id: "entra", kind: "oidc", enabled: true });
    await storage.put(`${OIDC_GROUPS_PREFIX}oidc:entra|iss|sub1`, ["admins", "eng"]);
    const oidcOk = await signSession(key, { method: "oidc", email: "oi@x.example", subject: "oidc:entra|iss|sub1", connId: "entra", epoch: 0 }, now);
    const oidcRes = await dobj.passkeySessionVerify({ token: oidcOk });
    ok("verify: a passing oidc session resolves with its group snapshot (oidc arm)", oidcRes.email === "oi@x.example" && oidcRes.method === "oidc" && oidcRes.connId === "entra" && (oidcRes.groups ?? []).includes("admins"));
    // A passing oidc session with NO stored groups: the ?? [] default arm.
    const oidcNoGrp = await signSession(key, { method: "oidc", email: "ong@x.example", subject: "oidc:entra|iss|nogrp", connId: "entra", epoch: 0 }, now);
    const ongRes = await dobj.passkeySessionVerify({ token: oidcNoGrp });
    ok("verify: a passing oidc session with no group snapshot -> empty groups (?? [] arm)", ongRes.email === "ong@x.example" && (ongRes.groups ?? []).length === 0);

    // A PASSING saml session: the saml operand of the groups ternary, plus the connId-present slide arm.
    await storage.put(connKey("work"), { id: "work", kind: "saml", enabled: true });
    await storage.put(`${OIDC_GROUPS_PREFIX}saml:work|idp|nameid`, ["staff"]);
    const samlOk = await signSession(key, { method: "saml", email: "sm@x.example", subject: "saml:work|idp|nameid", connId: "work", epoch: 0 }, now);
    const samlRes = await dobj.passkeySessionVerify({ token: samlOk });
    ok("verify: a passing saml session resolves with its group snapshot (saml arm)", samlRes.email === "sm@x.example" && samlRes.method === "saml" && (samlRes.groups ?? []).includes("staff"));
    const samlOld = await signSession(key, { method: "saml", email: "sms@x.example", subject: "saml:work|idp|nameid2", connId: "work", epoch: 0 }, old);
    const samlSlid = await dobj.passkeySessionVerify({ token: samlOld });
    ok("verify: an active-but-stale saml session slides (slidToken minted, connId-present arm)", samlSlid.email === "sms@x.example" && typeof samlSlid.slidToken === "string" && samlSlid.connId === "work");
  }

  // ============================================================================================
  // 4. terminateAllSessions: the OWNER-ONLY global sign-out (key deleted), the audit attribution arms
  //    (email present + email null, sourceIp present + absent), and the holds-roles.write-but-not-Owner
  //    refusal (an access-admin), the only caller that reaches the owner-only throw.
  // ============================================================================================
  {
    const { dobj, storage } = makeDO();
    await dobj.sessionSigningKey(); // there is a key to delete
    const r1 = await dobj.terminateAllSessions({ method: "token", email: "o1@x.example", subject: "tok|o1", groups: [], sourceIp: "203.0.113.5" });
    ok("terminateAllSessions (owner): ok and the session signing key is deleted", r1.ok === true && (await storage.get(PASSKEY_SESSION_KEY_KEY)) === undefined);
    // A second owner caller with NO email and NO sourceIp: the null audit-attribution arms.
    const r2 = await dobj.terminateAllSessions({ method: "token", email: null, subject: null, groups: [] });
    ok("terminateAllSessions (owner, no email/sourceIp): ok (null audit arms)", r2.ok === true);
    // An access-admin holds roles.write (passes the capability gate) but is NOT an Owner -> the owner-only refusal.
    await storage.put(roleSubjectKey("access|aa"), { subject: "access|aa", email: "aa@x.example", role: "access-admin", grantedBy: "system", grantedAt: "2026-01-01T00:00:00.000Z" });
    let refused = false;
    try {
      await dobj.terminateAllSessions({ method: "access", email: "aa@x.example", subject: "access|aa", groups: [] });
    } catch {
      refused = true;
    }
    ok("terminateAllSessions (access-admin): refused (only an Owner may sign the whole account out)", refused);
  }

  // ============================================================================================
  // 5. terminateOwnOtherSessions: the null caller, the invalid-email caller, a MISSING/garbage forwarded
  //    token (both refused ok:false with NO epoch bump - ASVS V7.5.1/V7.3: this is housekeeping, never an
  //    implicit fresh login), the passkey success (current session survives AS A SLIDE preserving the
  //    presented token's original iat/exp), the oidc success (method + connId preserved), and the oidc/saml
  //    malformed-caller refusals (missing connId / missing subject).
  // ============================================================================================
  {
    const { dobj, storage } = makeDO();
    ok("terminateOwnOther: a null caller is refused (ok:false)", (await dobj.terminateOwnOtherSessions(null, {})).ok === false);
    ok("terminateOwnOther: an invalid-email caller is refused (ok:false)", (await dobj.terminateOwnOtherSessions({ method: "passkey", email: "bad email!!", subject: "x", groups: [] }, {})).ok === false);

    // A valid caller but no forwarded token (or a garbage one) is refused WITHOUT bumping the epoch: the fix
    // must fail closed rather than silently minting a fresh-login token with no proof of the caller's actual
    // session (the exact bug being closed) - and must not destroy every other session on the way to failing.
    const noTokCaller = { method: "passkey" as const, email: "notoken@x.example", subject: passkeySubject("notoken@x.example"), groups: [] };
    ok("terminateOwnOther: a missing token is refused (ok:false)", (await dobj.terminateOwnOtherSessions(noTokCaller, {})).ok === false);
    ok("terminateOwnOther: a missing token does NOT bump the epoch (no state change on refusal)", (await dobj.getSessionEpoch("notoken@x.example")) === 0);
    ok("terminateOwnOther: a garbage token is refused (ok:false)", (await dobj.terminateOwnOtherSessions(noTokCaller, { token: "not-a-real-token" })).ok === false);
    ok("terminateOwnOther: a garbage token does NOT bump the epoch either", (await dobj.getSessionEpoch("notoken@x.example")) === 0);

    // Passkey success: mint the caller's OWN presented session first (mirroring the router forwarding the
    // caller's raw cookie), 10h old - well past a step-up freshness window but a live (non-idle) session, so
    // mint AS A SLIDE (lastSeen=now, iat/exp preserved from the original 10h-old login), exactly like a real
    // session that has been idle-slid since. The email epoch is bumped and the CURRENT session is re-minted
    // AS A SLIDE too (preserving the presented iat/exp).
    const key = await dobj.sessionSigningKey();
    const passkeyMintNow = Date.now();
    const mintedAt = passkeyMintNow - 10 * 60 * 60 * 1000;
    const presentedPasskey = await signSession(key, { method: "passkey", email: "u1@x.example", subject: passkeySubject("u1@x.example"), epoch: await dobj.getSessionEpoch("u1@x.example"), slide: { iat: mintedAt, exp: mintedAt + SESSION_TTL_MS } }, passkeyMintNow);
    const op = await dobj.terminateOwnOtherSessions({ method: "passkey", email: "u1@x.example", subject: passkeySubject("u1@x.example"), groups: [], sourceIp: "198.51.100.7" }, { token: presentedPasskey });
    ok("terminateOwnOther (passkey): ok + a re-minted token + the email epoch bumped", op.ok === true && typeof op.token === "string" && (await dobj.getSessionEpoch("u1@x.example")) === 1);
    const vp = await dobj.passkeySessionVerify({ token: op.token ?? "" });
    ok("terminateOwnOther (passkey): the surviving token still verifies as passkey", vp.email === "u1@x.example" && vp.method === "passkey" && vp.connId === null);
    const vpFull = await verifySession(key, op.token ?? "", Date.now());
    ok("terminateOwnOther (passkey): the re-mint preserves the ORIGINAL iat (a SLIDE, not a fresh login - the ASVS V7.5.1 fix)", vpFull !== null && vpFull.iat === mintedAt);

    // OIDC success: the re-mint MUST keep the caller's own method + verified subject + connId, AND preserve
    // the presented token's original iat (the same slide discipline, never laundered into a fresh mint).
    const oidcMintNow = Date.now();
    const oidcMintedAt = oidcMintNow - 3 * 60 * 60 * 1000;
    const presentedOidc = await signSession(key, { method: "oidc", email: "o1@x.example", subject: "oidc:entra|iss|s", connId: "entra", epoch: await dobj.getSessionEpoch("o1@x.example"), slide: { iat: oidcMintedAt, exp: oidcMintedAt + SESSION_TTL_MS } }, oidcMintNow);
    const oo = await dobj.terminateOwnOtherSessions({ method: "oidc", email: "o1@x.example", subject: "oidc:entra|iss|s", connId: "entra", groups: [] }, { token: presentedOidc });
    ok("terminateOwnOther (oidc): ok + a re-minted token", oo.ok === true && typeof oo.token === "string");
    await storage.put(connKey("entra"), { id: "entra", kind: "oidc", enabled: true });
    const vo = await dobj.passkeySessionVerify({ token: oo.token ?? "" });
    ok("terminateOwnOther (oidc): the re-minted token keeps method oidc + connId (no passkey laundering)", vo.email === "o1@x.example" && vo.method === "oidc" && vo.connId === "entra");
    const voFull = await verifySession(key, oo.token ?? "", Date.now());
    ok("terminateOwnOther (oidc): the re-mint preserves the ORIGINAL iat (a SLIDE, not a fresh login)", voFull !== null && voFull.iat === oidcMintedAt);

    // An oidc caller MISSING its connId, and a saml caller MISSING its subject, are both refused (refusing,
    // not re-deriving, is the point) - these reach the oidc/saml branch and the callerSubject/connId-null
    // arms. A valid presented token is supplied so the refusal is proven to come from THIS check, not the
    // token gate above.
    const presentedOidc2 = await signSession(key, { method: "oidc", email: "o2@x.example", subject: "oidc:entra|iss|s", connId: "entra", epoch: await dobj.getSessionEpoch("o2@x.example") }, Date.now());
    ok("terminateOwnOther (oidc, no connId): refused (ok:false)", (await dobj.terminateOwnOtherSessions({ method: "oidc", email: "o2@x.example", subject: "oidc:entra|iss|s", groups: [] }, { token: presentedOidc2 })).ok === false);
    const presentedSaml2 = await signSession(key, { method: "saml", email: "s2@x.example", subject: passkeySubject("s2@x.example"), connId: "work", epoch: await dobj.getSessionEpoch("s2@x.example") }, Date.now());
    ok("terminateOwnOther (saml, no subject): refused (ok:false)", (await dobj.terminateOwnOtherSessions({ method: "saml", email: "s2@x.example", subject: null, connId: "work", groups: [] }, { token: presentedSaml2 })).ok === false);
  }

  // ============================================================================================
  // 6. terminateUserSessions: the invalid-email throw, a BOUND non-owner target (per-subject axis bumped),
  //    a PENDING-only target (no subject axis), an OWNER target by an Owner (the effectiveRole owner arm),
  //    and an ABSENT target with a null-email caller (the targetEntry-undefined + null audit arms).
  // ============================================================================================
  {
    const { dobj, storage } = makeDO();
    const ownerTok: TestCaller = { method: "token", email: "admin@x.example", subject: "tok|admin", groups: [], sourceIp: "203.0.113.9" };

    let threw = false;
    try {
      await dobj.terminateUserSessions({ email: "not valid!!" }, ownerTok);
    } catch {
      threw = true;
    }
    ok("terminateUserSessions: an invalid target email throws", threw);

    // A BOUND operator: matched in the role entries (left arm of ??), boundSubject present -> per-subject bump.
    await storage.put(roleSubjectKey("sub|op1"), { subject: "sub|op1", email: "op1@x.example", role: "operator", grantedBy: "admin@x.example", grantedAt: "2026-01-01T00:00:00.000Z" });
    const ru1 = await dobj.terminateUserSessions({ email: "op1@x.example" }, ownerTok);
    ok("terminateUserSessions (bound operator): ok + email epoch bumped + per-subject epoch bumped", ru1.ok === true && (await dobj.getSessionEpoch("op1@x.example")) === 1 && (await storage.get(`${SESSION_EPOCH_SUB_PREFIX}sub|op1`)) !== undefined);

    // A PENDING invite (no bound subject yet): matched only via the pending list (right arm of ??), and NO
    // per-subject epoch is written (boundSubject undefined).
    await storage.put("role:pending:pend1@x.example", { role: "viewer", grantedBy: "admin@x.example", grantedAt: "2026-01-01T00:00:00.000Z" });
    const subEpochBefore = (await storage.list({ prefix: SESSION_EPOCH_SUB_PREFIX })).size;
    const ru2 = await dobj.terminateUserSessions({ email: "pend1@x.example" }, ownerTok);
    const subEpochAfter = (await storage.list({ prefix: SESSION_EPOCH_SUB_PREFIX })).size;
    ok("terminateUserSessions (pending invite): ok + email epoch bumped, NO per-subject epoch written", ru2.ok === true && (await dobj.getSessionEpoch("pend1@x.example")) === 1 && subEpochAfter === subEpochBefore);

    // An OWNER target terminated BY an Owner: the effectiveRole === owner arm, allowed (no escalation).
    await storage.put(roleSubjectKey("sub|own2"), { subject: "sub|own2", email: "own2@x.example", role: "owner", grantedBy: "system", grantedAt: "2026-01-01T00:00:00.000Z" });
    const ru3 = await dobj.terminateUserSessions({ email: "own2@x.example" }, ownerTok);
    ok("terminateUserSessions (owner target by Owner): ok (effectiveRole-owner arm, no escalation)", ru3.ok === true && (await dobj.getSessionEpoch("own2@x.example")) === 1);

    // An ABSENT target (valid email, no entry), driven by a null-email owner-token caller: targetEntry is
    // undefined on both arms (effectiveRole defaults to viewer) and the null audit-attribution arms run.
    const ru4 = await dobj.terminateUserSessions({ email: "ghost@x.example" }, { method: "token", email: null, subject: null, groups: [] });
    ok("terminateUserSessions (absent target, null-email caller): ok + email epoch bumped", ru4.ok === true && (await dobj.getSessionEpoch("ghost@x.example")) === 1);
  }

  // ============================================================================================
  // 7. passkeySessionLogout: a valid token (best-effort revoke + audit) with a string sourceIp and with
  //    none (the sourceIp null arm), and an invalid token (email-null skip, nothing bumped).
  // ============================================================================================
  {
    const { dobj, storage } = makeDO();
    const key = await dobj.sessionSigningKey();
    const now = Date.now();

    const loTok = await signSession(key, { method: "passkey", email: "lo@x.example", subject: passkeySubject("lo@x.example"), epoch: 0 }, now);
    const lr1 = await dobj.passkeySessionLogout({ token: loTok, sourceIp: "203.0.113.20" });
    ok("logout (valid token + sourceIp): ok + email epoch bumped + per-subject epoch bumped", lr1.ok === true && (await dobj.getSessionEpoch("lo@x.example")) === 1 && (await storage.get(`${SESSION_EPOCH_SUB_PREFIX}${passkeySubject("lo@x.example")}`)) !== undefined);
    ok("logout: the just-logged-out token is now revoked on the next request", (await dobj.passkeySessionVerify({ token: loTok })).email === null);

    // A different valid token with NO sourceIp: the typeof-string-false (null) audit arm.
    const loTok2 = await signSession(key, { method: "passkey", email: "lo2@x.example", subject: passkeySubject("lo2@x.example"), epoch: 0 }, now);
    const lr2 = await dobj.passkeySessionLogout({ token: loTok2 });
    ok("logout (valid token, no sourceIp): ok (null sourceIp audit arm)", lr2.ok === true && (await dobj.getSessionEpoch("lo2@x.example")) === 1);

    // An invalid token resolves to email null: nothing is bumped, still ok (best-effort, oracle-free).
    const lr3 = await dobj.passkeySessionLogout({ token: "garbage.token", sourceIp: "203.0.113.30" });
    ok("logout (invalid token): ok and nothing bumped (email-null skip)", lr3.ok === true && (await dobj.getSessionEpoch("nobody@x.example")) === 0);
  }

  console.log(failures === 0 ? "\nVALIDATE-COV-SCHED-SCHEDULER-DO-SESSION VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
