// Support-pack section gatherers: the auth / IdP domain (the classified SSO failure
// aggregate and its per-protocol split, the auth/RBAC defensive-branch counters, and the
// session-key / IdP-secret / admin-credential-path posture probes). Moved verbatim out of
// support.ts, which assembles the bundle from these gatherers; each keeps its original
// redaction contract (see the per-function comments). Behaviour is unchanged.

import { ADMIN_AUTH_METHODS } from "./auth-method-usage.ts";
import { ageAuthSignalRing, type AuthSignalEntry, AUTH_SIGNAL_NAMES, MS_PER_DAY } from "./auth-signals.ts";
import { IDP_CURVE_CLASSES } from "./idp-cert-health.ts";
import { doURL } from "../do-url.ts";
import { SSO_FAIL_CODES } from "./sso-failure-class.ts";
import { clampInt, clampTs, UNKNOWN_CODE } from "./support-shared.ts";

// CONN_ORDINAL_SHAPE gates the OPAQUE per-connection ordinal (G140). The connection axis is deliberately NOT
// keyed by connId: a connId is the operator's own slug, the pack carries connIds NOWHERE (ssoFailuresByKind is
// keyed by protocol for exactly this reason), and hashing a short guessable slug is not a redaction. The DO
// mints a stable ordinal at first sight and the connId never leaves it. A SHAPE gate, not a clamp: a secret, an
// e-mail or an issuer URL is not shaped like `conn-7` and is dropped outright, so even a future writer that
// passed one could not push it into the pack.
const CONN_ORDINAL_SHAPE = /^conn-\d{1,3}$/;
const SSO_CONN_ORDINAL_CAP = 24;
const IDP_CURVE_CLASS_SET: ReadonlySet<string> = new Set(IDP_CURVE_CLASSES);

// fetchSsoFailures pulls the bounded SSO sign-in FAILURE aggregate (D2) into the pack: a per-code count + last-seen
// time for interactive external-IdP (OIDC/OAuth2/SAML) sign-in failures. This is the pack's answer to "WHY can't my
// users sign in via SSO", the failure REASON is a CLOSED classifier code (sso-failure-class.ts), NEVER the raw
// reason (which could interpolate an issuer, connId or error message). Redaction-safe by construction: only codes
// from the fixed vocabulary are forwarded (anything else is dropped, defence-in-depth), counts are clamped ints,
// timestamps are clamped. A fetch/parse fault PROPAGATES to section() (recorded "error", not "empty"); only a genuine empty reads "empty". The whole map is bounded to <=10 codes.
const SSO_FAIL_CODE_SET: ReadonlySet<string> = new Set(SSO_FAIL_CODES);
export async function fetchSsoFailures(scheduler: DurableObjectStub): Promise<Record<string, { count: number; lastAt: string }>> {
  {
    const r = await scheduler.fetch(doURL("/sso-failures"), { method: "GET" });
    const j = (await r.json()) as Record<string, unknown>;
    const out: Record<string, { count: number; lastAt: string }> = {};
    for (const [code, v] of Object.entries(j)) {
      // G317: an out-of-vocabulary code no longer DISAPPEARS. A classifier that grew a new code after the pack
      // builder was last updated would otherwise take its whole failure count with it, so a fleet whose SSO is
      // failing 100% on a NEW code reads byte-identically to one where nobody has tried to sign in. Its count is
      // FOLDED into the UNKNOWN_CODE bucket instead; the code string itself is discarded, never carried.
      const key = SSO_FAIL_CODE_SET.has(code) ? code : UNKNOWN_CODE;
      const rec = (typeof v === "object" && v !== null ? v : {}) as { count?: unknown; lastAt?: unknown };
      const count = typeof rec.count === "number" && Number.isFinite(rec.count) ? Math.max(0, Math.min(1_000_000, Math.floor(rec.count))) : 0;
      const lastAt = typeof rec.lastAt === "string" ? rec.lastAt.slice(0, 40) : "";
      if (count === 0) continue;
      const prior = out[key];
      out[key] = prior === undefined ? { count, lastAt } : { count: Math.min(1_000_000, prior.count + count), lastAt: prior.lastAt > lastAt ? prior.lastAt : lastAt };
    }
    return out;
  }
}

// fetchSsoFailuresByKind (P1) projects the per-connection-KIND breakdown of the SSO failure aggregate: which
// PROTOCOL (oidc/oauth2/saml) is failing, and on which classifier code. Redaction-safe by construction, projected
// through the SAME closed vocabularies as fetchSsoFailures: only a member connKind (outer) and a member SSO code
// (inner) survive (defence-in-depth on the redaction), counts are clamped, timestamps clamped, zero-counts and
// empty kinds dropped. A fetch/parse fault PROPAGATES to section() (recorded "error", not "empty"). Answers the audit's #1 idp gap (coarse SSO reasons, no
// per-connection split): "your SAML sign-ins fail on signature while your OIDC fails on issuer".
const SSO_KIND_SET: ReadonlySet<string> = new Set(["oidc", "oauth2", "saml"]);
export async function fetchSsoFailuresByKind(scheduler: DurableObjectStub): Promise<Record<string, Record<string, { count: number; lastAt: string }>>> {
  {
    const r = await scheduler.fetch(doURL("/sso-failures-by-kind"), { method: "GET" });
    const j = (await r.json()) as Record<string, unknown>;
    const out: Record<string, Record<string, { count: number; lastAt: string }>> = {};
    for (const [kind, sub] of Object.entries(j)) {
      if (!SSO_KIND_SET.has(kind)) continue; // only the closed connKind enum reaches the pack
      const subMap = (typeof sub === "object" && sub !== null ? sub : {}) as Record<string, unknown>;
      const projected: Record<string, { count: number; lastAt: string }> = {};
      for (const [code, v] of Object.entries(subMap)) {
        if (!SSO_FAIL_CODE_SET.has(code)) continue; // only the closed classifier code
        const rec = (typeof v === "object" && v !== null ? v : {}) as { count?: unknown; lastAt?: unknown };
        const count = typeof rec.count === "number" && Number.isFinite(rec.count) ? Math.max(0, Math.min(1_000_000, Math.floor(rec.count))) : 0;
        const lastAt = typeof rec.lastAt === "string" ? rec.lastAt.slice(0, 40) : "";
        if (count > 0) projected[code] = { count, lastAt };
      }
      if (Object.keys(projected).length > 0) out[kind] = projected;
    }
    return out;
  }
}

// fetchAuthSignals (P2) projects the bounded auth/RBAC defensive-branch signal aggregate: a closed event name
// (auth-signals.ts) -> capped count + last-seen time. This is the pack's answer to the auth-availability cluster
// the audit calls the largest dark gap: fail-closed rate-limits (lockout / shared-NAT), SCIM 401/503/last-owner
// refusals (deprovision broken), dropped group claims / zero-match group->role (silent role loss), verified-but-
// emailless / unusable-subject / email_verified-bind-blocked refusals, CSRF-origin blocks. NEVER an ip/email/
// connId/subject/secret - only the closed event NAME + an int + a timestamp. Only vocabulary members survive
// (defence-in-depth), counts clamped, zero-counts dropped. A fetch/parse fault PROPAGATES to section() (recorded "error", not "empty"). Bounded to the name set.
const AUTH_SIGNAL_SET: ReadonlySet<string> = new Set(AUTH_SIGNAL_NAMES);
export async function fetchAuthSignals(scheduler: DurableObjectStub, nowMs: number = Date.now()): Promise<Record<string, Record<string, unknown>>> {
  {
    const r = await scheduler.fetch(doURL("/auth-signals"), { method: "GET" });
    const j = (await r.json()) as Record<string, unknown>;
    const out: Record<string, Record<string, unknown>> = {};
    for (const [name, v] of Object.entries(j)) {
      if (!AUTH_SIGNAL_SET.has(name)) continue; // only the closed vocabulary reaches the pack
      const rec = (typeof v === "object" && v !== null ? v : {}) as { count?: unknown; lastAt?: unknown; firstAt?: unknown; capSaturated?: unknown; days?: unknown; dayEpoch?: unknown };
      const count = typeof rec.count === "number" && Number.isFinite(rec.count) ? Math.max(0, Math.min(1_000_000, Math.floor(rec.count))) : 0;
      const lastAt = typeof rec.lastAt === "string" ? rec.lastAt.slice(0, 40) : "";
      if (count === 0) continue;
      // G270: the TEMPORAL SHAPE, still counts only. days[0] is TODAY, days[13] thirteen days back, so a
      // 10,000-in-one-day BURST ([10000,0,0,...]) and a month-long TRICKLE ([1,1,1,...]) read as two
      // different rows rather than two identical ones with a different lastAt. last24h/last7d are derived here
      // so a reader does not have to sum a ring by hand. capSaturated says the all-time count has stopped
      // moving at its cap, so every number below it is a LOWER BOUND.
      //
      // THE RING IS AGED HERE, TO THE CLOCK THE PACK IS BUILT WITH. The recorder ages it only when the
      // signal fires AGAIN, so a ring that has stopped moving is frozen at the instant of its last bump.
      // Ageing on read makes "is it STILL happening?" answerable, which is the only reason the ring
      // exists: a dead burst reads days=[0,...], last24h=0, last7d=0, with count and lastAt preserving the
      // history.
      const days = ageAuthSignalRing(rec as AuthSignalEntry, nowMs);
      const entry: Record<string, unknown> = { count, lastAt };
      if (typeof rec.firstAt === "string" && rec.firstAt !== "") entry.firstAt = rec.firstAt.slice(0, 40);
      if (rec.capSaturated === true) entry.capSaturated = true;
      if (Array.isArray(rec.days) && rec.days.length > 0) {
        entry.days = days;
        // G270 (R4): days[] is a UTC CALENDAR-DAY ring, so days[0] spans [00:00 UTC, buildTime) -- a window
        // whose true length is uniform on (0, 24h] with a MEAN OF TWELVE HOURS, so it is projected under
        // names that say exactly that rather than under a name that asserts a rolling 24-hour window the
        // ring cannot compute.
        //
        //
        // All clamped ints off the engine's own build clock. No new leak surface, and no member of any closed
        // vocabulary changes.
        //
        // THE HOT-PATH NAMES ARE A LOWER BOUND, BY AT MOST 25 (G270 R6). The session-verify / RBAC family is
        // recorded through recordAuthSignalThrottled, which defers a write and holds the deferred EVENTS in the
        // isolate. The pack read flushes that tail, but a Durable Object evicted between the burst and the pack
        // build (idleness, or any engine deploy) loses whatever is still deferred. AUTH_SIGNAL_PENDING_FLUSH
        // bounds that at 25 events per name, so these counts can under-report by up to 25 and never more: a
        // fleet lockout of 600 still reads as at least 575, and cannot masquerade as a stale browser tab.
        entry.today = days[0] ?? 0;
        entry.last7dToDate = days.slice(0, 7).reduce((a, b) => a + b, 0);
        entry.hoursIntoDay = Math.max(0, Math.min(23, Math.floor((nowMs % MS_PER_DAY) / 3_600_000)));
        entry.last24hLower = days[0] ?? 0;
        entry.last24hUpper = (days[0] ?? 0) + (days[1] ?? 0);
        // dayEpoch ANCHORS the ring: the day index days[0] refers to, as the pack was built. Without it a
        // reader holding only the pack cannot tell WHICH day the head slot is, so they cannot re-age the ring
        // by hand or check this projector's arithmetic. It is an integer day number from the engine's
        // clock (floor(ms / 86_400_000)): a count of days, carrying no identity.
        entry.dayEpoch = Math.floor(nowMs / MS_PER_DAY);
      }
      out[name] = entry;
    }
    return out;
  }
}

// fetchAuthPosture (P4) projects the auth posture probes: the session signing-key presence + age (never the key)
// and the count of confidential do-plaintext IdP connections missing their stored secret. Redaction-safe: a
// boolean + clamped int age + a clamped int count. A fetch/parse fault PROPAGATES to section() (recorded "error", not "empty"); only a genuine empty reads "empty".
export async function fetchAuthPosture(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/auth-posture"), { method: "GET" });
    const j = (await r.json()) as { sessionSigningKey?: { present?: unknown; ageMs?: unknown; adequateLength?: unknown }; doPlaintextSecretsMissing?: unknown; doPlaintextSecretsMissingConns?: unknown; adminCredentialPaths?: { passkeyCredentials?: unknown; enabledIdpConnections?: unknown }; methodUsage?: unknown };
    const out: Record<string, unknown> = {};
    const nowMs = Date.now();
    if (j.sessionSigningKey && typeof j.sessionSigningKey === "object") {
      const sk: Record<string, unknown> = { present: j.sessionSigningKey.present === true };
      if (typeof j.sessionSigningKey.ageMs === "number" && Number.isFinite(j.sessionSigningKey.ageMs)) sk.ageMs = Math.max(0, Math.floor(j.sessionSigningKey.ageMs));
      // adequateLength (recovery-key-too-short): the session key is also the recovery-code HMAC key; a false here
      // means recovery-code sign-in is broken. Projected only when the probe reported it (a boolean, never the key).
      if (typeof j.sessionSigningKey.adequateLength === "boolean") sk.adequateLength = j.sessionSigningKey.adequateLength;
      out.sessionSigningKey = sk;
    }
    if (typeof j.doPlaintextSecretsMissing === "number" && Number.isFinite(j.doPlaintextSecretsMissing)) out.doPlaintextSecretsMissing = Math.max(0, Math.floor(j.doPlaintextSecretsMissing));
    // doPlaintextSecretsMissingConns (G140): WHICH confidential connections are secretless, by OPAQUE ORDINAL.
    // The count alone said "2 of your 5 connections cannot complete a token exchange" without saying which two,
    // so the operator had to guess. The ordinal (conn-1, conn-2, ...) is minted DO-side at first sight and the
    // connId -- the operator's own slug -- goes in and never comes out; the map is never projected. Shape-gated
    // here so nothing but an ordinal can ride, even from a drifted writer.
    if (Array.isArray(j.doPlaintextSecretsMissingConns)) {
      const conns = j.doPlaintextSecretsMissingConns.filter((c): c is string => typeof c === "string" && CONN_ORDINAL_SHAPE.test(c)).slice(0, SSO_CONN_ORDINAL_CAP);
      if (conns.length > 0) out.doPlaintextSecretsMissingConns = conns;
    }
    // adminCredentialPaths (token-fallback-disabled-lockout): the count of ALTERNATIVE admin sign-in paths that
    // still work - registered passkeys + enabled IdP connections. Cross-checked against status.tokenFallbackDisabled
    // (+ Access presence): fallback OFF and BOTH counts zero and no Access = a locked-out account. Clamped ints only.
    if (j.adminCredentialPaths && typeof j.adminCredentialPaths === "object") {
      const p = j.adminCredentialPaths;
      const acp: Record<string, unknown> = {};
      if (typeof p.passkeyCredentials === "number" && Number.isFinite(p.passkeyCredentials)) acp.passkeyCredentials = Math.max(0, Math.floor(p.passkeyCredentials));
      if (typeof p.enabledIdpConnections === "number" && Number.isFinite(p.enabledIdpConnections)) acp.enabledIdpConnections = Math.max(0, Math.floor(p.enabledIdpConnections));
      if (Object.keys(acp).length > 0) out.adminCredentialPaths = acp;
    }
    // methodUsage (G253): WHICH credential path the estate actually RAN on, and WHEN. Everything above is
    // point-in-time: adminCredentialPaths says how many alternative sign-in paths EXIST, status.tokenFallbackDisabled
    // and status.adminTokenConfigured say the break-glass token CAN be used. None of them says it WAS used, on which
    // day, or for how long -- so "was this estate behind Access when the change was made, and how long did it run on
    // the shared break-glass token?" had no answer in the pack at all. The engine classifies every admin request's
    // credential path already; this is that classification, counted.
    //
    // Per closed method: the all-time count, firstAt ("since when"), lastAt ("is it still happening"), and the SAME
    // 14-slot UTC day ring the auth signals carry, AGED HERE to the clock the pack is built with -- so a token
    // fallback that ran for three days last week and stopped reads days=[0,0,...] with a stale lastAt, and one that
    // is running right now reads today>0. That pair is exactly the degraded-window bound the ticket asks for, and a
    // support engineer reads the START off firstAt / the first non-zero day and the END off lastAt.
    //
    // Redaction: closed method-name keys (a non-member is dropped), clamped integer counts, engine-minted ISO
    // stamps. Never a session id, an email, a subject or an IP.
    const usageRaw = (typeof j.methodUsage === "object" && j.methodUsage !== null ? j.methodUsage : {}) as Record<string, unknown>;
    const methodUsage: Record<string, Record<string, unknown>> = {};
    for (const method of ADMIN_AUTH_METHODS) {
      const rec = usageRaw[method];
      if (typeof rec !== "object" || rec === null) continue;
      const e = rec as AuthSignalEntry;
      const count = clampInt(e.count, 1_000_000) ?? 0;
      if (count === 0) continue;
      const entry: Record<string, unknown> = { count };
      const lastAt = clampTs(e.lastAt);
      if (lastAt !== undefined) entry.lastAt = lastAt;
      const firstAt = clampTs(e.firstAt);
      if (firstAt !== undefined) entry.firstAt = firstAt;
      if (e.capSaturated === true) entry.capSaturated = true;
      if (Array.isArray(e.days) && e.days.length > 0) {
        const days = ageAuthSignalRing(e, nowMs);
        entry.days = days;
        // The same honest window names the auth-signal ring carries (G270 R4): `today` is the count so far in the
        // CURRENT UTC calendar day (not a rolling 24 hours), and dayEpoch anchors days[0] so a reader holding only
        // the pack can tell which day the head slot is.
        entry.today = days[0] ?? 0;
        entry.last7dToDate = days.slice(0, 7).reduce((a, b) => a + b, 0);
        entry.dayEpoch = Math.floor(nowMs / MS_PER_DAY);
      }
      methodUsage[method] = entry;
    }
    if (Object.keys(methodUsage).length > 0) out.methodUsage = methodUsage;
    return out;
  }
}

// ---- G140: ssoFailuresByConn ------------------------------------------------------------------------------
// The per-CONNECTION split of the classified SSO failure aggregate. ssoFailures says "12 signature failures"
// and ssoFailuresByKind says "they are all SAML"; on a tenant with four SAML connections neither says WHICH
// connection is broken, so the operator re-checks all four. This does, by OPAQUE ORDINAL.
//
// Redaction: the ordinal is minted DO-side (ssoConnOrdinal is the chokepoint -- the connId goes in and only
// `conn-N` comes out, and the connId->ordinal map is never projected). Here it is SHAPE-gated again, the inner
// code is re-gated against the closed classifier vocabulary, counts are clamped and zero-counts dropped. A
// fetch/parse fault PROPAGATES to section() (recorded "error", never a clean "empty").
export async function fetchSsoFailuresByConn(scheduler: DurableObjectStub): Promise<Record<string, Record<string, { count: number; lastAt: string }>>> {
  const r = await scheduler.fetch(doURL("/sso-failures-by-conn"), { method: "GET" });
  const j = (await r.json()) as Record<string, unknown>;
  const out: Record<string, Record<string, { count: number; lastAt: string }>> = {};
  for (const [conn, sub] of Object.entries(typeof j === "object" && j !== null ? j : {}).slice(0, SSO_CONN_ORDINAL_CAP)) {
    if (!CONN_ORDINAL_SHAPE.test(conn)) continue; // ONLY an opaque ordinal may become a key here
    const subMap = (typeof sub === "object" && sub !== null ? sub : {}) as Record<string, unknown>;
    const projected: Record<string, { count: number; lastAt: string }> = {};
    for (const [code, v] of Object.entries(subMap)) {
      if (!SSO_FAIL_CODE_SET.has(code)) continue; // closed classifier codes only
      const rec = (typeof v === "object" && v !== null ? v : {}) as { count?: unknown; lastAt?: unknown };
      const count = clampInt(rec.count, 1_000_000) ?? 0;
      if (count === 0) continue;
      projected[code] = { count, lastAt: clampTs(rec.lastAt) ?? "" };
    }
    if (Object.keys(projected).length > 0) out[conn] = projected;
  }
  return out;
}

// ---- G053: idpCertHealth ----------------------------------------------------------------------------------
// The SAML signing certificates the engine is actually holding, and it is a DATA-LOSS-class gap in disguise:
// every one of these states ends in "nobody can sign in", and none of them left a trace.
//
// The cert pre-extraction loop OVERWROTE its parse reason on every bad PEM and DISCARDED it entirely the moment
// any other cert parsed, so a half-corrupt rollover paste (the operator pastes two certs, one mangled) verified
// on the good one and said nothing -- until the good one expired. parseableCount < certCount IS that signal.
// expiryObserved:false is the state in which NO expiry warning can EVER fire (the engine cannot read the
// validity window, so it cannot warn). windowUnenforcedVerifies counts sign-ins whose freshness check ran
// DISARMED. curves.p521 is the "every sign-in dies in a generic import error" diagnosis -- an unsupported curve
// the platform will never load, which reads as a mysterious crypto fault. noUsableCertRefusals counts the outage.
//
// Redaction: counts, a closed curve-class map, two booleans and one timestamp. The certificate bytes, the
// subject/issuer DNs, the connId and the parse-error text NEVER ride -- the classifier reads the SPKI's PUBLIC
// algorithm OID only to SELECT a curve class and returns the enum. Deliberately an AGGREGATE, not keyed by
// connId, for the same reason ssoFailuresByKind is keyed by protocol: a connId is the operator's own slug.
export async function fetchIdpCertHealth(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/idp-cert-health"), { method: "GET" });
  const j = (await r.json()) as { health?: unknown };
  const h = (typeof j.health === "object" && j.health !== null ? j.health : null) as Record<string, unknown> | null;
  if (h === null) return {}; // no SAML ACS has ever been exercised: honest absence
  const curves: Record<string, number> = {};
  if (typeof h.curves === "object" && h.curves !== null) {
    for (const [cls, n] of Object.entries(h.curves as Record<string, unknown>)) {
      if (!IDP_CURVE_CLASS_SET.has(cls)) continue; // closed curve vocabulary only
      const v = clampInt(n, 1_000_000) ?? 0;
      if (v > 0) curves[cls] = v;
    }
  }
  return {
    certCount: clampInt(h.certCount, 1_000) ?? 0,
    parseableCount: clampInt(h.parseableCount, 1_000) ?? 0,
    windowReadableCount: clampInt(h.windowReadableCount, 1_000) ?? 0,
    ...(Object.keys(curves).length > 0 ? { curves } : {}),
    // nearestNotAfter is an ABSOLUTE EXPIRY on a PUBLIC certificate -- not a customer value, and the fact that
    // makes "our SSO will die on Tuesday" predictable rather than a Tuesday outage.
    ...(typeof h.nearestNotAfter === "number" && Number.isFinite(h.nearestNotAfter) ? { nearestNotAfter: Math.max(0, Math.floor(h.nearestNotAfter)) } : {}),
    expiryObserved: h.expiryObserved === true,
    unparseableCertsTotal: clampInt(h.unparseableCertsTotal, 1_000_000) ?? 0,
    windowUnreadableTotal: clampInt(h.windowUnreadableTotal, 1_000_000) ?? 0,
    windowUnenforcedVerifies: clampInt(h.windowUnenforcedVerifies, 1_000_000) ?? 0,
    noUsableCertRefusals: clampInt(h.noUsableCertRefusals, 1_000_000) ?? 0,
    unsupportedCurveSeen: clampInt(h.unsupportedCurveSeen, 1_000_000) ?? 0,
    observations: clampInt(h.observations, 1_000_000) ?? 0,
    ...(typeof h.lastAt === "number" && Number.isFinite(h.lastAt) ? { lastAt: Math.max(0, Math.floor(h.lastAt)) } : {}),
  };
}

// LOCKOUT_PASSKEY_EVIDENCE / LOCKOUT_RECOVERY_REASON are the two closed unions the lockout pre-flight answers
// with (passkey.ts PasskeyOwnerEvidence, recovery.ts RecoveryBreakGlassReason). They are lifted from the
// modules that DECIDE, so the pack's gate and the decision cannot drift apart, and a member this build does
// not know is dropped to UNKNOWN_CODE rather than passed through.
const LOCKOUT_PASSKEY_EVIDENCE: ReadonlySet<string> = new Set(["no-credential", "demonstrated", "never-asserted", "unknown"]);
const LOCKOUT_RECOVERY_REASON: ReadonlySet<string> = new Set([
  "ok", "no-passkey-bound-owner", "no-recovery-record", "unparseable-recovery-record", "no-unconsumed-codes", "recovery-codes-orphaned-from-key",
]);

/**
 * fetchLockoutPosture pulls the DO's OWN lockout pre-flight into the pack: `GET /policy/lockout-preflight`
 * is the surface built to answer "can this account still get back in", including `rosterUnreadable` (a
 * count of stored role records that cannot be parsed, which is how an account can lose its only Owner in
 * silence) and `passkeyOwnerEvidence` (whether the first credential an account enrols has ever been
 * demonstrated).
 *
 * IT IS A PROJECTION, NOT A NEW COMPUTATION. Every field below is already computed by `lockoutPreflight()` and
 * already travels to a browser over the admin API; nothing new is derived here and no new DO write happens.
 *
 * REDACTION. Two closed enums gated by SET MEMBERSHIP (an unrecognised member becomes UNKNOWN_CODE rather than
 * riding as free text), three booleans, one clamped count and one clamped timestamp. No email, no subject, no
 * credential id, no role name, no key material: the roster's CONTENTS are not touched and cannot be, because
 * the DO answers a COUNT of unreadable rows rather than the rows.
 *
 * Best-effort through section() at the call site, so an unreadable route reads "error" rather than a clean
 * "empty" that would assert a healthy roster nothing ever read.
 */
export async function fetchLockoutPosture(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/policy/lockout-preflight"), { method: "GET" });
  const j = (await r.json()) as {
    passkeyOwnerEnrolled?: unknown; passkeyOwnerEvidence?: unknown; passkeyWitnessSince?: unknown;
    recoveryReady?: unknown; recoveryReadyReason?: unknown; secondOwner?: unknown; rosterUnreadable?: unknown;
  };
  // AN ENGINE THAT CANNOT ANSWER MUST NOT BE READ AS AN ACCOUNT WITH NO OWNER. Every field below defaults
  // false or zero, so an older engine whose router has no such route -- and whose DO stub therefore answers an
  // empty object -- would produce a block asserting no Owner is enrolled, no second Owner exists and the roster
  // is perfectly readable: a confident, false and maximally alarming claim built from an answer that was never
  // given. So the presence of the two REQUIRED booleans is the gate, and their absence is honest absence.
  if (typeof j.passkeyOwnerEnrolled !== "boolean" || typeof j.recoveryReady !== "boolean") return {};
  const evidence = typeof j.passkeyOwnerEvidence === "string" && LOCKOUT_PASSKEY_EVIDENCE.has(j.passkeyOwnerEvidence) ? j.passkeyOwnerEvidence : UNKNOWN_CODE;
  const reason = typeof j.recoveryReadyReason === "string" && LOCKOUT_RECOVERY_REASON.has(j.recoveryReadyReason) ? j.recoveryReadyReason : UNKNOWN_CODE;
  const rosterUnreadable = clampInt(j.rosterUnreadable, 1_000_000) ?? 0;
  return {
    passkeyOwnerEnrolled: j.passkeyOwnerEnrolled === true,
    passkeyOwnerEvidence: evidence,
    ...(clampTs(j.passkeyWitnessSince) !== undefined ? { passkeyWitnessSince: clampTs(j.passkeyWitnessSince) } : {}),
    recoveryReady: j.recoveryReady === true,
    recoveryReadyReason: reason,
    secondOwner: j.secondOwner === true,
    // rosterUnreadable rides ALWAYS, including at zero, and that is deliberate. Every other count in this pack
    // is omitted when empty because absence reads as "nothing to report"; here absence would be
    // indistinguishable from an OLDER ENGINE that cannot answer the question at all, and this is the one field
    // whose whole purpose is to stop a corrupt roster reading as an intact one.
    rosterUnreadable,
  };
}
