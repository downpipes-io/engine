// The passkey SESSION layer: the signed browser session a successful passkey login (or registration +
// login) issues, and the strict-Origin CSRF guard a cookie-authenticated mutating request needs. The
// passkey core (passkey.ts) PROVES who the caller is (the credential's bound email); this turns that one
// proof into a short-lived, signed session so the subsequent /admin calls do not re-run the WebAuthn
// ceremony on every request. It is the THIRD authentication method the engine accepts, alongside a
// verified Cloudflare Access JWT and the ADMIN_TOKEN break-glass.
//
// SECURITY DISCIPLINE (a later adversarial review will hunt for flaws):
//  - The session token is a SERVER-SIGNED MAC, never a bearer secret the client could forge: it is
//    `<body_b64url>.<mac_b64url>` where mac = HMAC-SHA-256(SESSION_SIGNING_KEY, body_b64url). The key is
//    generated ONCE by the engine and persisted in the scheduler DO (passkeySessionKey); it is never
//    hardcoded and never leaves the DO, so verification (the constant-time MAC + the exp check) happens
//    INSIDE the DO. This module is the pure, key-as-argument core that the DO drives, exactly as
//    passkey.ts is the pure verifier the DO drives.
//  - The MAC is compared in CONSTANT TIME (constantTimeEqual over the raw MAC bytes), so neither the
//    contents nor a prefix of the expected MAC leaks through timing.
//  - The body is verified BEFORE it is read: a token whose MAC does not match is rejected without trusting
//    a single field of the body, so a forged/tampered body can never set the email or extend the expiry.
//  - The session has an ABSOLUTE lifetime cap (SESSION_TTL_MS) and an IDLE timeout (SESSION_IDLE_MS).
//    verifySession rejects an expired or idle token, so a leaked cookie is useless past the cap. Active
//    sessions are slid (lastSeen refreshed via SESSION_SLIDE_MS) without extending the absolute cap.
//  - The cookie is HttpOnly (no script access), Secure (HTTPS only), SameSite=Strict (not sent on any
//    cross-site navigation, the first line of CSRF defence) and Path=/ (required by the "__Host-" prefix;
//    the engine reads it only under /admin but the browser rule forces a broader path scope). logout
//    clears it with the SAME attributes and Max-Age=0.
//  - CSRF (defence in depth on top of SameSite=Strict): originAllowed enforces a STRICT match of the
//    request Origin against CONSOLE_ORIGIN on a state-changing (mutating) request authenticated via the
//    cookie, so even a browser that did not honour SameSite (or a future relaxation) cannot drive a
//    cross-origin write with the ambient cookie. A bare-token or Access caller is not cookie-borne and is
//    not subject to this check (it carries no ambient credential a foreign page could ride).
//
// Node 25 strip-types compatible and Workers-runtime compatible: Web Crypto only, no Node built-ins, no
// enums, explicit field declarations. The pure sign/verify is exercised directly by the validator with a
// real key, so the path under test is the production one.

import { ab, b64urlDecode, b64urlEncode, constantTimeEqual } from "../crypto/bytes.ts";
import type { AuthMethod } from "./identity.ts";
import { isConnId, passkeySubject } from "./identity.ts";

// SESSION_COOKIE_NAME is the cookie the engine sets after a passkey login and reads on each subsequent
// /admin request. The "__Host-" prefix is a deliberate browser-enforced hardening: a browser only accepts
// a "__Host-"-prefixed cookie when it is Secure, has Path=/ and NO Domain attribute, which pins the cookie
// to THIS exact host over HTTPS and forbids a sibling/parent domain from setting or overriding it (a
// subdomain cookie-injection / fixation defence). NOTE the "__Host-" rule requires Path=/, so the cookie
// is sent on every path of this host; the engine still only READS it under /admin (handleAdmin), and the
// strict-Origin CSRF guard plus SameSite=Strict are what bound its use, not the path scope.
export const SESSION_COOKIE_NAME = "__Host-downpipes_session";

// SESSION_TTL_MS is the absolute lifetime of an issued session (12 hours). It is long enough for a normal
// working day at the console without re-authenticating, and short enough that a leaked cookie is useless
// by the next day. It is an ABSOLUTE expiry (set once at mint, never slid forward), so a stolen session
// dies at a deterministic time regardless of activity.
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

// SESSION_IDLE_MS is the inactivity (idle) bound (ASVS V7.3.1): a session with no activity for this long is
// rejected at verify, INDEPENDENT of the 12h absolute cap. "Activity" is recorded as lastSeen inside the
// signed V3 body, refreshed by the slide (below). Two hours balances a normal working session against a
// walked-away console; the absolute SESSION_TTL_MS still caps the maximum lifetime regardless of activity.
export const SESSION_IDLE_MS = 2 * 60 * 60 * 1000;

// CLOCK_SKEW_MS is the small tolerance verifySession allows on iat so a token minted moments ago is not
// rejected if the verifying clock is marginally behind. 60 seconds is generous for a single-account DO
// (the same clock mints and verifies), so this only ever matters across a clock adjustment.
const CLOCK_SKEW_MS = 60 * 1000;

// SESSION_SLIDE_MS is how stale lastSeen may get before an authenticated request re-mints the token to
// refresh it (the "slide"). It MUST be well under SESSION_IDLE_MS so an active session's lastSeen is renewed
// before it could go idle. The re-mint preserves the ORIGINAL iat and absolute exp (it only moves lastSeen
// forward), so sliding can NEVER extend a session past its 12h absolute cap (the idle-slide TOCTOU guard).
// It is a pure re-sign (no storage write), so the cadence only bounds re-sign frequency, not DO writes.
export const SESSION_SLIDE_MS = 15 * 60 * 1000;

// STEPUP_FRESH_MS (ASVS V7.5.1 / V7.5.3): a session authenticated within this window satisfies a step-up
// (re-authentication) requirement for a sensitive action WITHOUT a separate fresh-factor proof - it just
// authenticated. This is the "recent strong factor" alternate that covers a just-logged-in passkey/OIDC/SAML
// session AND a recovery-code sign-in (the break-glass operator's recent factor, so they are never locked out
// of a sensitive action). An OLDER session must present a single-use step-up token (a fresh passkey
// assertion), or re-authenticate. Short (5 min) so the post-login exemption is narrow. iat is the ORIGINAL
// login instant (the idle-slide preserves it), so this measures time since the last strong authentication.
export const STEPUP_FRESH_MS = 5 * 60 * 1000;

// STEPUP_TOKEN_TTL_MS bounds how long a minted single-use step-up token (from a fresh passkey assertion) is
// valid before the gated action must present it. Short: the assertion was just made and the console presents
// the token on the immediate retry. The token is also single-use (consumed at the check), per the folded
// "single-use server-side, not merely short-lived" requirement.
export const STEPUP_TOKEN_TTL_MS = 2 * 60 * 1000;

// SESSION_KEY_BYTES is the length of the HMAC-SHA-256 signing key the DO generates once and persists. 32
// bytes (256 bits) matches the HMAC-SHA-256 block-independent key size and the engine's other 32-byte
// random secrets (the secret-store standard); it is a CSPRNG value (crypto.getRandomValues), never a
// hardcoded or derived constant.
export const SESSION_KEY_BYTES = 32;

// SESSION_VERSION tags the token body so a format change is unambiguous and an old-format token is rejected
// rather than misread. It is inside the SIGNED body, so it cannot be altered without invalidating the MAC.
//  - V2 (legacy): {v,email,epoch,iat,exp}. The original passkey-only shape. It is still ACCEPTED on read so
//    a passkey session minted before the V3 upgrade keeps working until it expires (no forced re-auth), and
//    it is ALWAYS interpreted as method:"passkey" with the subject re-derived as passkeySubject(email). A V2
//    token can NEVER claim to be oidc/saml (it carries no method/subject), which preserves the anti-forge
//    property: a native-IdP session is ALWAYS V3 and asserts its own SIGNED subject.
//  - V3: adds the auth METHOD, the stable SUBJECT and an optional connId to the SIGNED body, so a native
//    oidc/saml session asserts its immutable subject (never re-derived from the IdP-asserted email) and the
//    per-subject and per-connection session-epoch axes have a key. ALL new sessions (passkey included) mint at V3.
const SESSION_VERSION_V2 = 2;
const SESSION_VERSION_V3 = 3;
const _SESSION_VERSION = SESSION_VERSION_V3; // the version we MINT; verifySession accepts V2 and V3

// SessionPayloadV3 is the signed body we MINT. It carries NO secret and NO key material. The role is ALWAYS
// re-resolved from the DO role table on each request (never carried in the token), so a session can never
// pin or smuggle an elevated role; method/subject/connId are IDENTITY, not authority.
export interface SessionPayloadV3 {
  v: 3;
  method: AuthMethod; // how the session was established: passkey | oidc | saml (never access/token; those are not cookie-borne)
  email: string; // the verified, canonical email (display/audit; the pending-invite bind keys on it on first auth)
  subject: string; // the STABLE principal the role table keys on (passkeySubject/oidcSubject/samlSubject)
  connId?: string; // the IdP-connection id for oidc/saml (the idpEpoch axis + the honest provider); absent for passkey
  epoch: number; // the per-email session epoch AT ISSUE (the DO also checks the per-subject and per-connection axes)
  iat: number; // issued-at, epoch ms
  exp: number; // absolute expiry, epoch ms (min(iat + SESSION_TTL_MS, any IdP session upper bound))
  lastSeen: number; // last-activity instant, epoch ms (the idle-timeout reference; refreshed by the slide, never past exp)
}

// VerifiedSession is what verifySession returns on success: the resolved identity the caller (the DO, then
// auth.ts) builds the verdict from. subject is ALWAYS populated - the SIGNED subject for a V3 token, or
// passkeySubject(email) for a legacy V2 token (which is always passkey). method/connId reflect the signed V3
// values, or "passkey"/null for V2. The DO then checks the email/subject/connId session-epoch axes.
export interface VerifiedSession {
  email: string;
  subject: string;
  method: AuthMethod;
  connId: string | null;
  epoch: number;
  // iat (issued-at, epoch ms) is surfaced so the DO can apply the per-SUBJECT and per-CONNECTION revocation
  // axes as "not-before" instants: a deprovision-subject or disable/delete/rotate-connection event stamps the
  // current time, and any session whose iat predates that instant is rejected. The per-EMAIL axis stays a
  // monotonic counter (the `epoch` field) because terminate-others re-mints the surviving session with the
  // bumped counter; the subject/connection axes have no such "keep this one" carve-out, so a time instant is
  // the simpler, correct model. iat is already MAC-verified (it is inside the signed body).
  iat: number;
  // exp + lastSeen are surfaced so the DO can SLIDE the session (re-mint a fresh token that moves lastSeen to
  // now while PRESERVING iat and exp) when lastSeen is older than SESSION_SLIDE_MS. exp is the absolute cap the
  // slide must preserve; lastSeen is the idle reference. For a legacy V2 token lastSeen is reported as iat (V2
  // carries no lastSeen and is never slid), so the idle/slide logic has a uniform field to read.
  exp: number;
  lastSeen: number;
}

// SESSION_EMAIL_MAX bounds the email length inside a token body so a malformed or oversized value cannot
// be smuggled through verifySession even on a (hypothetically) valid MAC. It matches the DO's
// normaliseEmail ceiling (320), the RFC-5321 practical maximum; verifySession rejects anything longer.
const SESSION_EMAIL_MAX = 320;
// SESSION_SUBJECT_MAX / SESSION_CONN_ID_MAX bound the V3 subject and connId fields for the same reason: a
// subject is the issuer/entityId plus an opaque sub/NameID (comfortably under 1 KiB) and a connId is the
// short pattern-bounded connection id. verifySession rejects a token whose field exceeds these.
export const SESSION_SUBJECT_MAX = 1024;
const SESSION_CONN_ID_MAX = 64;

// importHmacKey imports the raw 32-byte signing key as a Web Crypto HMAC-SHA-256 CryptoKey for sign/verify.
// The key is non-extractable (it never needs to leave Web Crypto once imported) and is scoped to exactly
// the sign and verify usages. Importing per-call is acceptable: the session sign/verify is not a hot inner
// loop (one per login, one per request) and keeping the key as raw bytes in the DO record (not a cached
// CryptoKey) avoids holding key state across the DO's request lifecycle.
async function importHmacKey(rawKey: Uint8Array): Promise<CryptoKey> {
  if (rawKey.length < SESSION_KEY_BYTES) {
    // A short key is a misconfiguration (the DO always generates SESSION_KEY_BYTES); reject loudly rather
    // than silently signing with a weak key.
    throw new Error(`session signing key too short: ${rawKey.length} < ${SESSION_KEY_BYTES}`);
  }
  return crypto.subtle.importKey("raw", ab(rawKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

// hmac computes HMAC-SHA-256(key, message) as raw bytes. It is the one MAC primitive sign/verify share, so
// the produced and the recomputed MAC cannot diverge in construction.
async function hmac(rawKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const key = await importHmacKey(rawKey);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, ab(message)));
}

// SessionMintInput is what the DO passes signSession after a successful login (the passkey ceremony, the
// OIDC callback, the SAML ACS). The caller computes the stable subject ITSELF (passkeySubject / oidcSubject
// / samlSubject) and passes it in, so session.ts never re-derives a subject from an email at mint. exp is an
// OPTIONAL absolute upper bound (epoch ms) the IdP imposed (a SAML SessionNotOnOrAfter, an OIDC session
// bound); the minted exp is min(now + SESSION_TTL_MS, exp) so the engine session never outlives the IdP one.
export interface SessionMintInput {
  method: AuthMethod;
  email: string; // canonical (trimmed, lowercased)
  subject: string; // the stable principal the caller computed
  connId?: string; // present for oidc/saml
  epoch: number;
  exp?: number; // optional IdP session upper bound (epoch ms)
  // slide: when present this is a SLIDE re-mint of an existing session (not a fresh login). signSession uses
  // the supplied iat and exp VERBATIM - preserving the original issue time and absolute cap - and only moves
  // lastSeen to now. A fresh login omits slide (iat = now, exp = min(now + TTL, the optional IdP bound)). On a
  // slide the IdP exp bound is already baked into the preserved exp, so `exp` above is ignored.
  slide?: { iat: number; exp: number };
}

// signSession mints a signed V3 session token: it builds the SessionPayloadV3, encodes it as
// base64url(JSON), and appends a "." and the base64url HMAC of that body. The body and the MAC are BOTH
// base64url with no "." inside (base64url has no "."), so the single "." is an unambiguous separator. email
// and subject MUST already be the canonical / stable forms the role table uses; the caller (the DO, after a
// successful login) passes them. Returns the compact token string.
export async function signSession(rawKey: Uint8Array, input: SessionMintInput, now: number): Promise<string> {
  // A SLIDE re-mint preserves the original iat + absolute exp (it only refreshes lastSeen); a fresh login
  // stamps iat = now and caps exp at min(now + TTL, the optional IdP bound). lastSeen is ALWAYS now (the
  // activity instant), so even a slide that preserves iat/exp records the current request as activity.
  const iat = input.slide !== undefined ? input.slide.iat : now;
  const exp =
    input.slide !== undefined
      ? input.slide.exp
      : input.exp !== undefined
        ? Math.min(now + SESSION_TTL_MS, input.exp)
        : now + SESSION_TTL_MS;
  const payload: SessionPayloadV3 = {
    v: SESSION_VERSION_V3,
    method: input.method,
    email: input.email,
    subject: input.subject,
    ...(input.connId !== undefined ? { connId: input.connId } : {}),
    epoch: input.epoch,
    iat,
    exp,
    lastSeen: now,
  };
  const body = b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const mac = await hmac(rawKey, new TextEncoder().encode(body));
  return `${body}.${b64urlEncode(mac)}`;
}

// verifySession verifies a session token against the signing key and returns the resolved VerifiedSession,
// or null on ANY fault (a malformed shape, a bad MAC, an expired or not-yet-valid token, an unknown
// version, a missing/oversized/inconsistent field). The order is deliberate and fail-closed:
//   1. Split on the single "." into body and mac; a token without exactly one "." is malformed -> null.
//   2. Recompute HMAC over the body bytes and compare to the presented MAC in CONSTANT TIME. If it does
//      not match, return null WITHOUT parsing the body (a tampered/forged body is never trusted).
//   3. Only AFTER the MAC verifies, decode + parse the body and validate the common fields (email, epoch,
//      iat, exp + the expiry/skew checks), then branch on the version: V2 is the legacy passkey shape
//      (subject re-derived as passkeySubject(email), method "passkey", connId null); V3 carries the SIGNED
//      method + subject (+ optional connId), taken VERBATIM and NEVER re-derived (the anti-forge property).
// It NEVER throws (a decode error is caught and mapped to null), so the caller treats null as "no valid
// session" and falls through to the next auth method, exactly like a rejected Access JWT.
export async function verifySession(rawKey: Uint8Array, token: string, now: number): Promise<VerifiedSession | null> {
  const r = await verifySessionClassified(rawKey, token, now);
  return "fault" in r ? null : r;
}

// SESSION_FAULT_CLASSES are the closed causes a presented session cookie can be REFUSED for. They are
// the members of AUTH_SIGNAL_NAMES the recorder emits, named here so the classifier and the validator pin the
// same set.
//
// WHY this exists at all, given verifySession returns a bare null BY DESIGN: the bare null is an ANTI-ORACLE
// property for the CALLER (a client is never told which check it failed) and it is KEPT -- verifySession's
// contract, its return type and the generic 401 the caller sees are all unchanged. The closed class lets an
// idle-timeout window tuned too tight, an EXPECTED one-time re-auth after a token-shape upgrade, a
// signing-key rotation, and a MAC MISMATCH (a forgery attempt -- a security signal, not a config fault) be
// told apart. The class is recorded ENGINE-SIDE ONLY and never returned to the caller.
export const SESSION_FAULT_CLASSES = [
  "session-fault-malformed", // not a well-formed <body>.<mac>, or the body would not decode/parse
  "session-fault-mac-mismatch", // the body did not authenticate under the signing key (tampered, forged, or a rotated key)
  "session-fault-expired", // past the absolute exp
  "session-fault-idle", // idle past SESSION_IDLE_MS (ASVS V7.3.1)
  "session-fault-upgrade-reauth", // a valid but PRE-UPGRADE token shape (unknown version, or a v3 field the older mint never wrote): a one-time forced re-auth across a deploy
  "session-fault-shape-invalid", // authenticated but internally inconsistent claims (a corrupt session record)
] as const;
export type SessionFaultClass = (typeof SESSION_FAULT_CLASSES)[number];

// verifySessionClassified is verifySession's body, returning the VERIFIED session or the CLOSED fault class
// that refused it. The class is a closed enum member and nothing else: no token, no MAC, no email, no claim
// value and no message can ride out of here. verifySession wraps it back to null for every existing caller.
//
// @param rawKey - the session signing key.
// @param token - the presented cookie value (untrusted).
// @param now - the clock (injected).
// @returns the verified session, or { fault } naming the closed class that refused it.
export async function verifySessionClassified(rawKey: Uint8Array, token: string, now: number): Promise<VerifiedSession | { fault: SessionFaultClass }> {
  try {
    if (typeof token !== "string" || token.length === 0) return { fault: "session-fault-malformed" };
    // Exactly one separator: split into body and mac. indexOf / lastIndexOf would both find the only "."
    // (base64url contains none), but require there be exactly one so a crafted multi-dot token is rejected.
    const dot = token.indexOf(".");
    if (dot <= 0 || dot !== token.lastIndexOf(".") || dot === token.length - 1) return { fault: "session-fault-malformed" };
    const body = token.slice(0, dot);
    const macB64 = token.slice(dot + 1);
    let presentedMac: Uint8Array;
    try {
      presentedMac = b64urlDecode(macB64);
    } catch {
      return { fault: "session-fault-malformed" }; // a non-base64url MAC segment is malformed
    }
    // Recompute the MAC over the body and compare in constant time. A length mismatch is caught by
    // constantTimeEqual (it returns false on differing lengths). This is the trust gate: nothing below
    // runs unless the MAC matches, so the body is never parsed for a forged token.
    const expectedMac = await hmac(rawKey, new TextEncoder().encode(body));
    if (!constantTimeEqual(presentedMac, expectedMac)) return { fault: "session-fault-mac-mismatch" };
    // MAC verified: now it is safe to decode and validate the body.
    let bodyBytes: Uint8Array;
    try {
      bodyBytes = b64urlDecode(body);
    } catch {
      return { fault: "session-fault-malformed" };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes));
    } catch {
      return { fault: "session-fault-malformed" };
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return { fault: "session-fault-malformed" };
    const p = parsed as Record<string, unknown>;

    // Common fields (both versions): email, epoch, iat, exp + the absolute-expiry and clock-skew checks.
    const email = p.email;
    const epoch = p.epoch;
    const iat = p.iat;
    const exp = p.exp;
    // These bodies are MAC-AUTHENTICATED, so a missing/malformed common field cannot be an attacker: it is a
    // token this engine's OWN mint produced under an older shape (a v1 token has no epoch), i.e. the one-time
    // forced re-auth across an upgrade. Naming that as its own class is the whole point: support can say "that
    // logout wave was the expected re-auth after your update", which is otherwise unprovable remotely.
    if (typeof email !== "string" || email.length === 0 || email.length > SESSION_EMAIL_MAX) return { fault: "session-fault-upgrade-reauth" };
    // epoch must be a finite non-negative integer; the DO compares it against the current stored epoch
    // (the session-revocation gate). A missing/malformed epoch (e.g. a v1 token) is rejected.
    if (typeof epoch !== "number" || !Number.isInteger(epoch) || epoch < 0) return { fault: "session-fault-upgrade-reauth" };
    if (typeof iat !== "number" || !Number.isFinite(iat)) return { fault: "session-fault-upgrade-reauth" };
    if (typeof exp !== "number" || !Number.isFinite(exp)) return { fault: "session-fault-upgrade-reauth" };
    // Absolute expiry: reject a token at or past its exp. A small negative clock-skew tolerance on iat
    // (CLOCK_SKEW_MS) avoids rejecting a freshly-minted token if the verifying clock is a hair behind the
    // minting clock; the same instance mints and verifies here, so this is a backstop, not a real window.
    if (now >= exp) return { fault: "session-fault-expired" };
    if (now < iat - CLOCK_SKEW_MS) return { fault: "session-fault-shape-invalid" };

    const v = p.v;
    const common = { email, epoch, iat, exp };
    if (v === SESSION_VERSION_V2) return verifyV2Body(common);
    if (v === SESSION_VERSION_V3) return verifyV3Body(p, common, now);
    return { fault: "session-fault-upgrade-reauth" }; // an old/unknown version is rejected, not coerced
  } catch {
    // Defence in depth: any unexpected error (e.g. a Web Crypto import failure on a malformed key) is a
    // fail-closed refusal, never a thrown 500 out of the auth path.
    return { fault: "session-fault-shape-invalid" };
  }
}

// SessionCommonFields are the version-independent fields verifySession has already validated (email/epoch/iat/
// exp + the absolute-expiry and clock-skew checks) before it dispatches to the per-version verifier.
interface SessionCommonFields {
  email: string;
  epoch: number;
  iat: number;
  exp: number;
}

// verifyV2Body resolves a legacy V2 token (no method/subject in the body). It is ALWAYS passkey, and the
// subject is re-derived from the email HERE (the only place in THIS FILE a subject is re-derived, and only for
// V2, which can never be oidc/saml; scheduler-do-session.ts and scheduler-do-recovery.ts each derive one for
// their own purposes). This keeps existing passkey cookies working until they expire (no forced re-auth).
// V2 carries no lastSeen: report lastSeen = iat so the caller has a uniform field, and apply NO idle check
// HERE, because there is no honest value to check against.
// THIS VERIFIER NOT CHECKING IDLE IS NOT THE SAME AS A V2 TOKEN NEVER BEING SLID, and reading the second off
// the first is the mistake this note exists to stop. The DO slides on slideDue(res.lastSeen, now) with NO
// version test (scheduler-do-session.ts), so lastSeen = iat is exactly what makes an OLD V2 token slide on its
// next use, and the re-mint is V3. That is the intended direction and the DO says so at the slide site: the
// upgrade is how a legacy cookie GAINS the idle bound it never had. What bounds a V2 token until then is its
// absolute exp alone.
function verifyV2Body(c: SessionCommonFields): VerifiedSession {
  return { email: c.email, subject: passkeySubject(c.email), method: "passkey", connId: null, epoch: c.epoch, iat: c.iat, exp: c.exp, lastSeen: c.iat };
}

// verifyV3Body resolves a V3 token, which carries the SIGNED method + subject (+ optional connId). The subject
// is taken VERBATIM from the signed body and NEVER re-derived, so an oidc/saml session keeps its own immutable
// principal (the central anti-forge fix: an IdP-asserted email can never collapse a native session onto a
// passkey principal). access/token are not cookie-borne and are rejected as a session method.
// G233: every refusal below returns its CLOSED class instead of a bare null. The body here is MAC-AUTHENTICATED
// (nothing reaches verifyV3Body until the MAC verifies), so a wrong-shaped claim can only be a token this
// engine's OWN mint produced -- i.e. a corrupt session record (shape-invalid), or an older mint's shape (an
// upgrade re-auth) -- never an attacker's choice. The classes say which.
function verifyV3Body(p: Record<string, unknown>, c: SessionCommonFields, now: number): VerifiedSession | { fault: SessionFaultClass } {
  const method = p.method;
  const subject = p.subject;
  const connIdRaw = p.connId;
  if (method !== "passkey" && method !== "oidc" && method !== "saml") return { fault: "session-fault-shape-invalid" };
  if (typeof subject !== "string" || subject.length === 0 || subject.length > SESSION_SUBJECT_MAX) return { fault: "session-fault-shape-invalid" };
  let connId: string | null = null;
  if (connIdRaw !== undefined) {
    // Enforce the connId PATTERN here (isConnId), not merely the length: a VERIFIED v3 token's connId can
    // never contain the ":"/"|" subject separators, so the subject-collision invariant (oidc:<connId>|...
    // / saml:<connId>|... can never collide) is guaranteed BY THE VERIFIER, independent of the Phase-2
    // mint path. The length cap is kept as belt-and-braces (isConnId already bounds to 1..64).
    if (typeof connIdRaw !== "string" || connIdRaw.length > SESSION_CONN_ID_MAX || !isConnId(connIdRaw)) return { fault: "session-fault-shape-invalid" };
    connId = connIdRaw;
  }
  // An oidc/saml session MUST carry a connId (the connection it was minted through, the idpEpoch axis);
  // a passkey V3 session MUST NOT (it has no connection). Either inconsistency is a malformed token.
  if ((method === "oidc" || method === "saml") && connId === null) return { fault: "session-fault-shape-invalid" };
  if (method === "passkey" && connId !== null) return { fault: "session-fault-shape-invalid" };
  // lastSeen (ASVS V7.3.1 idle timeout): a V3 token MUST carry a finite lastSeen. A missing/non-finite
  // value fails CLOSED - it can only be a pre-idle-upgrade token (the body is MAC-signed and cannot be
  // forged), so this is a one-time re-auth on the upgrade deploy, like a key rotation. Reject a session
  // idle beyond SESSION_IDLE_MS, independent of the absolute exp; the slide keeps an ACTIVE session's
  // lastSeen fresh, so only a genuinely inactive session is rejected here.
  const lastSeen = p.lastSeen;
  // A missing lastSeen is precisely the PRE-IDLE-UPGRADE token: its own class, distinguishable from a
  // genuine idle-timeout refusal.
  if (typeof lastSeen !== "number" || !Number.isFinite(lastSeen)) return { fault: "session-fault-upgrade-reauth" };
  if (now - lastSeen >= SESSION_IDLE_MS) return { fault: "session-fault-idle" };
  return { email: c.email, subject, method, connId, epoch: c.epoch, iat: c.iat, exp: c.exp, lastSeen };
}

// slideDue reports whether an authenticated request should re-mint the session to refresh lastSeen: true when
// lastSeen is older than SESSION_SLIDE_MS. The DO calls this AFTER a token verifies and passes the epoch axes,
// to decide whether to issue a slid cookie (re-minting with slide:{iat,exp} so the absolute cap is preserved).
// A caller that does not slide simply ignores it. V2 reports lastSeen = iat, and the DO tests THIS function
// with no version discrimination, so an old V2 token IS slid on its next use and is re-minted as V3. That is
// deliberate (scheduler-do-session.ts says so at the slide site): the re-mint preserves the original iat and
// absolute exp, and is how a legacy cookie gains the idle bound it never carried. Until it is used, a V2
// token is bounded by its absolute exp alone.
export function slideDue(lastSeen: number, now: number): boolean {
  return now - lastSeen >= SESSION_SLIDE_MS;
}

// sessionSetCookie builds the Set-Cookie header VALUE for a freshly-minted session token. The attributes
// are the full hardened set: HttpOnly (no script access, so an XSS cannot read the session), Secure (only
// sent over HTTPS), SameSite=Strict (never sent on a cross-site request, the primary CSRF defence),
// Path=/ (required by the "__Host-" prefix; the engine still only reads it under /admin), and Max-Age =
// the TTL in whole seconds (so the browser drops it when the session would have expired anyway). There is
// deliberately NO Domain attribute (also required by "__Host-"): the cookie is pinned to this exact host
// and cannot be claimed by a sibling/parent domain.
export function sessionSetCookie(token: string): string {
  const maxAgeSeconds = Math.floor(SESSION_TTL_MS / 1000);
  return `${SESSION_COOKIE_NAME}=${token}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Strict`;
}

// sessionClearCookie builds the Set-Cookie header VALUE that clears the session (logout). It sets the
// cookie to an empty value with Max-Age=0 and the SAME attributes (Path=/, HttpOnly, Secure,
// SameSite=Strict) so the browser overwrites and immediately expires the existing "__Host-" cookie (a
// clear must match the original attributes to reliably remove the cookie). After this the next /admin
// request carries no session and (absent Access or the token) is unauthorised.
export function sessionClearCookie(): string {
  return `${SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

// readSessionCookie extracts the session token from a request's Cookie header, or null when absent. It
// parses the standard "name=value; name2=value2" cookie list, trims each pair, and returns the value of
// the session cookie. It does NOT decode or trust the value (verifySession does the MAC + exp check); it
// only locates the cookie. A malformed Cookie header yields null (no session), never a throw. The first
// matching cookie wins (a duplicate cookie name is a malformed client; taking the first is deterministic).
export function readSessionCookie(req: Request): string | null {
  const header = req.headers.get("cookie");
  if (header === null || header.length === 0) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    if (name !== SESSION_COOKIE_NAME) continue;
    const value = part.slice(eq + 1).trim();
    return value.length > 0 ? value : null;
  }
  return null;
}

// originAllowed is the strict-Origin CSRF check for a state-changing request authenticated via the session
// cookie. It returns true ONLY when the request carries an Origin header that EXACTLY equals the configured
// CONSOLE_ORIGIN. A missing Origin header, an empty/unset CONSOLE_ORIGIN, or any mismatch returns false
// (fail closed): the console (a browser fetch) always sends Origin on a cross-origin or same-origin
// state-changing request, so a legitimate console write always carries it, while a cross-site forgery
// either omits it or carries a foreign origin and is refused.
//
// This is enforced ONLY for the cookie (passkey-session) method on MUTATING requests: an Access JWT and
// the bare token are presented in explicit headers a foreign page cannot set on a credentialed
// cross-origin request, so they are not ambient-credential CSRF vectors and are not subject to this check
// (the router applies it conditionally). It is DEFENCE IN DEPTH on top of SameSite=Strict on the cookie:
// even a browser that ignored SameSite, or a future relaxation of it, could not drive a cross-origin
// write because the Origin would not match.
export function originAllowed(req: Request, consoleOrigin: string | undefined): boolean {
  return originFailClass(req, consoleOrigin) === null;
}

// ORIGIN_FAIL_CLASSES are the closed causes a strict-Origin CSRF check can REFUSE for. They are members
// of AUTH_SIGNAL_NAMES; named here so the classifier and the validator pin the same set.
//
// The split matters because "every console save started 403ing" has two OPPOSITE diagnoses behind it. Either
// CONSOLE_ORIGIN is UNSET on the engine -- a deploy dropped the var, so originAllowed fails CLOSED and EVERY
// cookie-borne mutation 403s for EVERY user (a configuration fault: set the var) -- or a FOREIGN Origin is
// genuinely being presented (a cross-site attempt: a security event). A shared counter cannot tell those
// apart. The raw Origin value NEVER rides; only which of the three branches fired.
export const ORIGIN_FAIL_CLASSES = [
  "csrf-origin-unset", // CONSOLE_ORIGIN is missing/empty on the engine: EVERY cookie-borne mutation 403s (a deploy-config fault, not an attack)
  "csrf-origin-header-absent", // the request carried no Origin header at all (a non-browser client, or a stripping proxy)
  "csrf-origin-mismatch", // an Origin was presented and did NOT equal CONSOLE_ORIGIN (a genuine cross-site attempt, or a console moved to a new hostname the engine was never told about)
] as const;
export type OriginFailClass = (typeof ORIGIN_FAIL_CLASSES)[number];

// originFailClass is the classifier BEHIND originAllowed: it returns null when the check PASSES, or the closed
// class that refused it. The refusal decision is byte-identical to the old boolean (fail-closed on all three
// branches) and the caller's 403 is unchanged; this only names the branch for the recorder.
//
// It returns an ENUM MEMBER and never the Origin header or the configured CONSOLE_ORIGIN, so a hostile Origin
// (attacker-chosen text) can never reach a record.
//
// @param req - the mutating request.
// @param consoleOrigin - the configured CONSOLE_ORIGIN (may be unset).
// @returns null when allowed, else the closed refusal class.
export function originFailClass(req: Request, consoleOrigin: string | undefined): OriginFailClass | null {
  if (typeof consoleOrigin !== "string" || consoleOrigin.length === 0) return "csrf-origin-unset";
  const origin = req.headers.get("origin");
  if (origin === null || origin.length === 0) return "csrf-origin-header-absent";
  return origin === consoleOrigin ? null : "csrf-origin-mismatch";
}

// ---- Double-submit CSRF token for the session-termination routes (ML-02) --------------------------
// This is a DEFENCE-IN-DEPTH layer ON TOP of originAllowed (the strict-Origin guard, §2.3a), NEVER a
// replacement for it. The Origin check is the primary CSRF control; this second, independent factor is a
// classic double-submit token the console echoes on the session-termination routes so that even a browser
// that ignored SameSite AND somehow presented a matching Origin still could not drive a cross-origin
// terminate without ALSO reading a cookie it cannot read from a foreign origin.

// CSRF_COOKIE_NAME is the READABLE (non-HttpOnly) double-submit token cookie. It carries the "__Host-"
// prefix (Secure + Path=/ + no Domain, browser-pinned to this exact host) exactly like the session cookie,
// but is DELIBERATELY not HttpOnly so the SPA can read it and echo it in CSRF_HEADER_NAME. It is not a
// secret the way the session MAC is: a cross-site page can neither read it (foreign-origin cookie access is
// forbidden) nor cause it to be sent (SameSite=Strict), so it cannot be echoed into the matching header.
export const CSRF_COOKIE_NAME = "__Host-downpipes_csrf";

// CSRF_HEADER_NAME is the request header the console echoes the double-submit token in on a mutating
// session-termination request. A custom request header cannot be set by a cross-site form/navigation and,
// on a cross-origin fetch, is subject to CORS (which the engine does not grant), so its mere presence-with-
// the-right-value is the second factor.
export const CSRF_HEADER_NAME = "x-downpipes-csrf";

// mintCsrfToken generates a fresh high-entropy double-submit token (32 random bytes, url-safe base64). It
// is unpredictable so it cannot be guessed, and independent of the session token so a session slide (which
// re-mints the session cookie) does not rotate it.
export function mintCsrfToken(): string {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  return b64urlEncode(raw);
}

// csrfSetCookie builds the Set-Cookie header VALUE for the double-submit token. Same hardened attributes as
// the session cookie (Secure, SameSite=Strict, Path=/, "__Host-"-compatible, Max-Age = the session TTL) but
// WITHOUT HttpOnly, because the SPA must read it to echo it. There is no Domain (required by "__Host-").
export function csrfSetCookie(token: string): string {
  const maxAgeSeconds = Math.floor(SESSION_TTL_MS / 1000);
  return `${CSRF_COOKIE_NAME}=${token}; Path=/; Max-Age=${maxAgeSeconds}; Secure; SameSite=Strict`;
}

// readCsrfCookie extracts the double-submit token from a request's Cookie header, or null when absent. It
// mirrors readSessionCookie exactly (parse the "name=value; ..." list, first match wins, malformed -> null).
export function readCsrfCookie(req: Request): string | null {
  const header = req.headers.get("cookie");
  if (header === null || header.length === 0) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    if (name !== CSRF_COOKIE_NAME) continue;
    const value = part.slice(eq + 1).trim();
    return value.length > 0 ? value : null;
  }
  return null;
}

// The double-submit CSRF check is exposed as csrfDoubleSubmitFailClass below, not as a boolean:
// router-account-session.ts imports the CLASSIFIER directly, because the route needs the closed fail class
// (header missing, cookie missing, mismatch) for its auth signal, not just true/false.

// DOUBLE_SUBMIT_FAIL_CLASSES are the closed causes the double-submit second factor can REFUSE for: a
// console that never received the token pair, a cookie the browser did not return (blocked / expired /
// partitioned), and a genuine value mismatch. Members of AUTH_SIGNAL_NAMES.
export const DOUBLE_SUBMIT_FAIL_CLASSES = [
  "csrf-double-submit-header-missing", // no CSRF header (a client that never read whoami, or one that does not implement the second factor)
  "csrf-double-submit-cookie-missing", // the header was present but the paired cookie was absent (a browser that blocked/partitioned it)
  "csrf-double-submit-mismatch", // both present, not byte-equal: a stale pair, or a genuine cross-site attempt
] as const;
export type DoubleSubmitFailClass = (typeof DOUBLE_SUBMIT_FAIL_CLASSES)[number];

// csrfDoubleSubmitFailClass is the classifier BEHIND csrfDoubleSubmitOk: null when the check PASSES, else the
// closed class that refused it. The refusal decision and the caller's 403 are unchanged; the comparison stays
// CONSTANT TIME (the mismatch arm is still reached only through constantTimeEqual, so naming the branch leaks no
// timing signal a caller did not already have). It returns an ENUM MEMBER and never the header or cookie value.
//
// @param req - the session-termination request.
// @returns null when the second factor passes, else the closed refusal class.
export function csrfDoubleSubmitFailClass(req: Request): DoubleSubmitFailClass | null {
  const header = req.headers.get(CSRF_HEADER_NAME);
  if (header === null || header.length === 0) return "csrf-double-submit-header-missing";
  const cookie = readCsrfCookie(req);
  if (cookie === null || cookie.length === 0) return "csrf-double-submit-cookie-missing";
  const enc = new TextEncoder();
  return constantTimeEqual(enc.encode(header), enc.encode(cookie)) ? null : "csrf-double-submit-mismatch";
}
