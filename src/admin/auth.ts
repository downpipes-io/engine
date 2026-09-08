import { constantTimeEqual } from "../crypto/bytes.ts";
import type { Env } from "../env.d.ts";
import { accessDenySignal, verifyAccessJWT } from "./access.ts";
import type { AuthMethod, AuthVerdict } from "./identity.ts";
import { readSessionCookie } from "./session.ts";

// Admin authentication. There are THREE accepted methods, in a strict precedence:
//   1. a VERIFIED Cloudflare Access JWT (the higher-assurance posture, when Access is configured);
//   2. a valid passkey SESSION cookie (the engine's OWN WebAuthn front door, free and self-hosted);
//   3. the ADMIN_TOKEN bearer (the lower-assurance break-glass).
// A present-but-INVALID higher method is rejected outright and NEVER falls through to a weaker one: a bad
// Access assertion does not try the passkey cookie or the token, and a present-but-invalid passkey session
// does not downgrade to the token path. This fail-closed-per-method rule is the core anti-downgrade
// property. Absent any usable credential the gate fails closed. There is never an inbound path from the
// vendor; this only gates the in-account console.
//
// HARDENING: an Enterprise tenant can set ADMIN_TOKEN_DISABLED to remove the shared-token fallback
// entirely, so ONLY a verified Access JWT or a valid passkey session is accepted (with passkeys configured,
// the account is fully self-hosted auth: no Cloudflare Access, no shared token). See envFlagEnabled and the
// token branch below; the default (flag absent/falsey) is unchanged.
//
// BREAK-GLASS DISPOSAL (retire): the ADMIN_TOKEN is meant for a ONE-TIME bootstrap of the first Owner. Once
// the Owner's passkey works, the Owner can RETIRE the token in-app (POST /admin/policy/retire-break-glass-
// token), which the engine cannot delete itself (it holds no standing Cloudflare token, by design). A
// retired token is refused EXACTLY as ADMIN_TOKEN_DISABLED refuses it, so the effective "token fallback OFF"
// predicate is: envFlagEnabled(ADMIN_TOKEN_DISABLED) OR breakGlassTokenRetired. The retired flag lives in the
// scheduler DO (so it can change with no redeploy), so authorise() consults it through an OPTIONAL injected
// resolver (breakGlassRetired) the router wires to a DO round-trip, mirroring how the passkey-session
// verifier is injected. When the resolver is omitted (a caller that does not wire it) the predicate collapses
// to the env flag alone (the prior behaviour, unchanged). The resolver FAILS CLOSED on its own error (it
// returns true = retired/deny), since the DO is the authority for everything the token could do anyway and a
// leaked token must never get a fail-open bypass by knocking the DO over; see breakGlassRetiredViaDO.
//
// SESSION VERIFICATION (passkey): the session token is an HMAC signed with a key that lives ONLY in the
// scheduler DO, so the constant-time MAC + the exp check run inside the DO. authorise() therefore does not
// hold the key; the router passes in a verifyPasskeySession resolver that performs the DO round-trip, and
// authorise() consumes its { email } | null verdict. Keeping the resolver injected (rather than importing
// the DO here) keeps auth.ts the pure precedence logic, mirrors how the rest of the module stays free of
// transport, and lets the validator drive authorise() with a stub resolver against the real precedence.

// envFlagEnabled reads a string env var as a boolean flag: trimmed, case-insensitive, true for
// "1"/"true"/"yes"/"on" and false otherwise (including unset/empty). This is the engine's one place
// to interpret a boolean-shaped env var, so ADMIN_TOKEN_DISABLED and any future flag agree on what
// "set" means and a stray "false"/"0" never reads as enabled.
export function envFlagEnabled(raw: string | undefined): boolean {
  if (raw === undefined) return false;
  const v = raw.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

// Reviewed deviation from GUARDRAILS §15 (no global mutable state across requests): this module-level cache
// holds the Cloudflare Access JWKS for the same-isolate lifetime. It is safe because the cached value carries
// no secret (RSA public keys only), is only ever written after the URL is SSRF-pinned to *.cloudflareaccess.com,
// is read-only after each write, and is bounded by a one-hour TTL. The alternative (a per-request fetch) would
// add an HTTPS round-trip to every gated request for no security gain.
let certsCache: { url: string; jwks: { keys: { kid: string; kty: string; n: string; e: string }[] }; at: number } | null = null;

async function fetchCertsCached(url: string): Promise<{ keys: { kid: string; kty: string; n: string; e: string }[] }> {
  if (certsCache && certsCache.url === url && Date.now() - certsCache.at < 3_600_000) return certsCache.jwks;
  // SSRF defence in depth (V13.2.5 / V15.3.2): the JWKS this returns GATES Access auth, so pin the fetch to
  // the Access surface. verifyAccessJWT already rejects a non-*.cloudflareaccess.com team domain before this
  // URL is built; re-assert it AT the fetch boundary (https + a *.cloudflareaccess.com host) and refuse to
  // follow a redirect, so neither a tampered team-domain env nor a 3xx can steer the key fetch off-surface.
  // This MUST permit *.cloudflareaccess.com - the OIDC guard (assertSafeFetchEndpoint) denies that suffix,
  // so it cannot reuse that screen.
  try {
    const u = new URL(url);
    if (u.protocol !== "https:" || !u.hostname.toLowerCase().endsWith(".cloudflareaccess.com")) throw new Error("off-surface");
  } catch {
    throw new Error("Access certs endpoint refused (not an https *.cloudflareaccess.com host)");
  }
  const r = await fetch(url, { redirect: "manual" });
  if (!r.ok) throw new Error(`Access certs fetch failed: ${r.status}`);
  const jwks = (await r.json()) as { keys: { kid: string; kty: string; n: string; e: string }[] };
  // Validate the shape at the boundary so a malformed or changed JWKS response fails deterministically
  // here rather than silently producing an object that downstream verification assumes is well-formed.
  if (!Array.isArray(jwks?.keys)) throw new Error("Access JWKS missing keys array");
  certsCache = { url, jwks, at: Date.now() };
  return jwks;
}

// PasskeySessionVerifier is the injected resolver authorise() uses to validate a presented session cookie
// (any cookie-borne method: passkey, oidc or saml - the v3 token carries which). It returns the verified
// identity (email + the SIGNED stable subject + the method + the optional connId) or null; null is "no valid
// session" and (when a cookie WAS present) causes authorise to FAIL CLOSED rather than fall through to the
// token path. The router supplies one that performs the DO round-trip (the signing key lives only in the
// DO); the validator supplies a stub so the precedence logic is testable without standing up the whole DO.
export type PasskeySessionVerifier = (token: string) => Promise<{ email: string; subject: string; method: AuthMethod; connId: string | null; groups: string[] } | null>;

// BreakGlassRetiredResolver is the injected resolver authorise() consults to learn whether the OWNER has
// RETIRED the break-glass ADMIN_TOKEN in-app (the durable breakGlassTokenRetired flag in the scheduler DO).
// It returns true when the token fallback must be refused (treated identically to ADMIN_TOKEN_DISABLED). The
// router supplies one that performs the DO round-trip and FAILS CLOSED (returns true) on its own error; the
// validator supplies a stub. It is OPTIONAL: when omitted, the token-fallback predicate is the env flag
// alone (the prior behaviour). It is consulted ONLY on the bare-token path (after Access and the passkey
// session), and ONLY when a token is actually configured and presented, so it adds no DO read to the Access
// or passkey paths and none to a no-credential request.
export type BreakGlassRetiredResolver = () => Promise<boolean>;

// AuthDenySink is the OPTIONAL best-effort observer authorise() calls whenever it DENIES a request: a PRESENT
// Cloudflare Access assertion that fails verification (aud/issuer/key/signature) or is verified-but-unusable
// (no email / no subject), a PRESENT session cookie that does not verify, and every bare-token deny class
// (fallback disabled, no token configured, empty bearer, retired, mismatch). It receives a CLOSED signal name
// from the auth-signals vocabulary and NEVER a reason, token, email, subject or IP; the router forwards it to a
// bounded DO counter for the support pack, which drops any out-of-vocabulary name (defence in depth). It is
// fire-and-forget: authorise ignores its result and the auth DECISION is unchanged (a denied request is still
// denied, never downgraded). When omitted (the default, and every non-router caller) no signal is emitted and
// behaviour is byte-identical to before. The client-facing 401 stays generic: these classes are pack-only, so
// the anti-oracle property of the response is preserved.
export type AuthDenySink = (signal: string) => void;

// ClaimDropSink is the OPTIONAL best-effort observer authorise() calls when a VERIFIED Access assertion
// carried a claim the engine BOUNDED AWAY: an over-long or control-char group name, a group list past the cap,
// an unusable idp hint. It fires on the ADMITTED path (the sign-in succeeds), which is the whole point -- the
// user is signed in, is missing the role their group should have conferred, and nothing anywhere says the group
// was ever there. It receives a CLOSED admin-counter name (never the claim value, which is customer IdP data
// and, on this boundary, attacker-influenceable) and is fire-and-forget: the verdict is unchanged.
export type ClaimDropSink = (counterName: string) => void;

// TokenRateLimiter is the OPTIONAL resolver authorise() consults to learn whether the BARE-TOKEN
// break-glass compare is currently throttled for this caller (ASVS V6.3.1). Unlike Access (an IdP-backed
// assertion) or the passkey session (a WebAuthn ceremony with its own per-IP authRateLimited guard), the
// ADMIN_TOKEN compare has no ceremony of its own to rate-limit, so every guess reaches tokenEqual for
// free. It returns true when the compare must be refused (over a per-IP cap, or the check itself is
// unavailable - see adminTokenRateLimitedViaDO, which fails closed like the resolver above). The router
// supplies one that performs a DO /rate-check round trip; the validator supplies a stub. It is OPTIONAL:
// when omitted, behaviour is byte-identical to before (no throttle). It is consulted ONLY on the
// bare-token path, AFTER breakGlassRetired, and ONLY once a token is configured and presented, so it adds
// no DO read to the Access/passkey/no-credential paths.
export type TokenRateLimiter = (req: Request) => Promise<boolean>;

// authorise is the identity-bearing gate. It returns a verdict carrying HOW the request authenticated
// (access | passkey | token), the verified email (null only on the bare-token fallback), and, for Access,
// the verified JWT exp, so the router can resolve the caller's role and surface session context and
// enforce roles per route. PRECEDENCE: a configured-and-asserted Access JWT is checked first; then a
// present passkey session cookie; then ADMIN_TOKEN. A present-but-invalid Access assertion OR a
// present-but-invalid passkey session still returns { ok: false } and is NEVER downgraded to a weaker
// method, preserving the original boolean-gate semantics exactly; only the SHAPE of the result changed
// (boolean -> verdict) and the passkey method was added between Access and the token.
//
// verifyPasskeySession is OPTIONAL: when it is omitted (a caller that does not wire the passkey layer), the
// passkey branch is simply skipped and the precedence collapses to the prior access-then-token behaviour,
// so existing call sites that pass no verifier are unaffected.
//
// breakGlassRetired is OPTIONAL: when omitted, the token-fallback predicate is the env flag alone (the prior
// behaviour). When wired, it is consulted ONLY on the bare-token path and ONLY once a token is configured and
// a bearer is presented (so it adds no DO read to the Access/passkey/no-credential paths), and a true verdict
// refuses the token exactly as ADMIN_TOKEN_DISABLED does.
//
// tokenRateLimited is OPTIONAL: when omitted, the bare-token path has no throttle (the prior behaviour,
// byte-identical). When wired, it is consulted ONLY on the bare-token path, immediately AFTER
// breakGlassRetired (so a disabled/retired token never even reaches the DO rate-check), and a true
// verdict refuses the compare BEFORE tokenEqual ever runs, exactly mirroring how breakGlassRetired gates
// the same branch.
export async function authorise(
  req: Request,
  env: Env,
  verifyPasskeySession?: PasskeySessionVerifier,
  breakGlassRetired?: BreakGlassRetiredResolver,
  onAuthDeny?: AuthDenySink,
  tokenRateLimited?: TokenRateLimiter,
  onClaimDrop?: ClaimDropSink,
): Promise<AuthVerdict> {
  const assertion = req.headers.get("cf-access-jwt-assertion");
  if (assertion && env.CF_ACCESS_TEAM_DOMAIN && env.CF_ACCESS_AUD) {
    const res = await verifyAccessJWT(assertion, {
      teamDomain: env.CF_ACCESS_TEAM_DOMAIN,
      aud: env.CF_ACCESS_AUD,
      fetchCerts: fetchCertsCached,
      now: Math.floor(Date.now() / 1000),
    });
    if (!res.ok) {
      // Classify WHY the signed Access assertion was refused to a closed signal (aud / issuer /
      // key / verify) so the pack can diagnose a CF_ACCESS_AUD or team-domain misconfiguration or a stale-JWKS
      // key rotation, apart from a generic denial. Best-effort + injected; it NEVER alters the fail-closed deny.
      if (onAuthDeny && typeof res.reason === "string") onAuthDeny(accessDenySignal(res.reason));
      return { ok: false }; // denied, not downgraded to the passkey or token path
    }
    // SECURITY: an authenticated Access caller MUST carry a verified email. An emailless but
    // validly-signed Access assertion (a Cloudflare Access service token is signed for the application
    // audience but carries common_name/sub, not email; an IdP may also be misconfigured to omit email)
    // must NOT be folded into the bare-token Owner break-glass downstream. Fail closed here at the trust
    // boundary; the break-glass is reachable only through the ADMIN_TOKEN path below.
    // This is the "Cloudflare Access lets me in but the console says denied" case. A service
    // token (signed for the application audience but carrying common_name, not email) or an IdP misconfigured to
    // omit the email claim lands HERE, verified but unusable, and until now recorded nothing at all. Reuse the
    // SAME closed name the native-IdP path already emits so the pack has one emailless-principal counter across
    // both front doors. Best-effort; it never alters the fail-closed deny below.
    if (!res.email) {
      if (onAuthDeny) onAuthDeny("emailless-assertion");
      return { ok: false };
    }
    // SECURITY (ASVS V10.3.3 / V10.5.2): an authenticated Access caller MUST also carry a stable
    // subject (iss+"|"+sub). A validly-signed assertion with no `sub` (a service token, or a
    // misconfigured IdP) is rejected here the SAME way an emailless one is, never downgraded to the
    // bare-token owner break-glass: authorisation keys on the immutable subject, so a caller with no
    // subject has no stable identity to authorise and must fail closed. The email alone is NOT enough
    // (it is mutable and a recycled address could inherit a prior member's role - the finding this
    // closes), so both must be present for the access method.
    // OBSERVE (G001): as above, but the subject-only failure mode (a validly-signed assertion with no `sub`).
    // Same closed name the native-IdP path uses, so one counter covers both front doors.
    if (!res.subject) {
      if (onAuthDeny) onAuthDeny("subject-unusable");
      return { ok: false };
    }
    // OBSERVE (G271): the assertion VERIFIED and is about to be admitted, and the bounder threw away one or
    // more of the claims it carried. This is the "the user is in the right AD group but gets viewer" ticket:
    // the group WAS asserted, the engine dropped it (over-long / control-char / past the 200-group cap), and
    // present-but-dropped read exactly like the IdP sending nothing. Emitted on the SUCCESS path, best-effort,
    // and the verdict is unchanged. Closed counter names only, never the dropped value.
    if (onClaimDrop && Array.isArray(res.claimDrops)) for (const name of res.claimDrops) onClaimDrop(name);
    // Thread the OPTIONAL, signature-verified identity-provider groups and idp hint through to the
    // verdict so the router can resolve the role from them. exactOptionalPropertyTypes: include each
    // key only when the verified token actually carried it, so a token with no groups yields a verdict
    // with no groups key (group-mapping stays additive; the per-email path is unchanged). The passkey and
    // token paths below carry neither (the passkey session carries an email but no IdP groups; the
    // bare-token break-glass has no IdP identity). subject is the stable principal the role table now
    // keys on; email is retained for display/audit only.
    return {
      ok: true,
      method: "access",
      email: res.email,
      subject: res.subject,
      ...(typeof res.exp === "number" ? { exp: res.exp } : {}),
      ...(res.groups !== undefined ? { groups: res.groups } : {}),
      ...(res.identityProvider !== undefined ? { identityProvider: res.identityProvider } : {}),
    };
  }
  // PASSKEY SESSION (method 2), checked BEFORE the token and BEFORE the ADMIN_TOKEN_DISABLED early-return,
  // so a fully self-hosted account (passkeys + ADMIN_TOKEN_DISABLED, no Cloudflare Access) still
  // authenticates. The cookie is read here; a present cookie is verified by the injected resolver (the DO
  // holds the signing key). CRITICAL ANTI-DOWNGRADE RULE: if a session cookie is PRESENT but does not
  // verify (bad MAC, expired, tampered, malformed), we FAIL CLOSED with { ok:false } and do NOT fall
  // through to the token path, exactly like a present-but-invalid Access assertion. Only the ABSENCE of a
  // cookie lets control proceed to the token fallback (a caller using the bare token sends no session
  // cookie). The verifier must be wired (the router always wires it); if it is absent the passkey method is
  // skipped entirely (no cookie is treated as a passkey credential without a verifier to check it).
  if (verifyPasskeySession) {
    const sessionToken = readSessionCookie(req);
    if (sessionToken !== null) {
      const res = await verifyPasskeySession(sessionToken);
      // A present cookie commits to its cookie-borne method (passkey | oidc | saml): valid -> that method's
      // verdict; invalid -> deny. It is NEVER downgraded to the token path (that would let a foreign page
      // strip a valid cookie down to a token attempt, or let an attacker present a junk cookie alongside a
      // token; both must fail closed).
      // OBSERVE (G001): "users keep getting logged out mid-shift". The single `res === null || !res.email` test is
      // SPLIT into its two real causes so each can be counted (the deny is byte-identical either way, and the
      // response stays a generic 401 - the verifier deliberately tells the edge nothing finer, which is the
      // anti-oracle property we preserve). A cookie that does not verify at all is the expiry/bad-MAC/tamper class;
      // a cookie that verifies but carries no email is a corrupt session record, a different fix entirely.
      if (res === null) {
        if (onAuthDeny) onAuthDeny("session-verify-failed");
        return { ok: false };
      }
      if (!res.email) {
        if (onAuthDeny) onAuthDeny("session-email-missing");
        return { ok: false };
      }
      // The DO returned the session's verified email and its SIGNED stable subject + method (+ optional
      // connId), taken VERBATIM from the v3 token (or passkeySubject(email)/"passkey" for a legacy v2 token).
      // We use them AS-IS and NEVER re-derive the subject from the email: a native oidc/saml session keeps its
      // immutable IdP principal and can never collapse onto a passkey principal (the cross-method anti-forge
      // property). The role is re-resolved from the subject-keyed role table on every request; the session
      // never carries a role or a JWT exp (the cookie Max-Age bounds it). IdP GROUPS are not in the cookie
      // either: the DO re-reads the current oidcgroups:<subject> snapshot on this verify and returns it (or []
      // for a passkey session), and we thread it into the verdict EXACTLY like the Access groups, so a native
      // oidc/saml caller's group->role mapping resolves from the LIVE snapshot (no 12h staleness), additive.
      return {
        ok: true,
        method: res.method,
        email: res.email,
        subject: res.subject,
        ...(res.connId !== null ? { connId: res.connId } : {}),
        ...(res.groups.length > 0 ? { groups: res.groups } : {}),
      };
    }
  }
  // P9 hardening: when the operator has disabled the token fallback, only verified Access or a valid
  // passkey session is accepted. Reaching here means neither Access (the branch above returns for a present
  // assertion) nor a passkey cookie (the branch above returns for a present cookie) supplied a credential,
  // so with the fallback disabled there is no usable credential and we fail closed BEFORE looking at
  // ADMIN_TOKEN. The default (flag absent/falsey) leaves the token path exactly as it was.
  // OBSERVE (G001): each bare-token deny below records its OWN closed class. Until now all four were one generic
  // 401, so "our automation suddenly gets denied" could not be told apart from "this engine was never given a
  // token" or "the operator turned the fallback off". Only the BRANCH is named - never the presented bearer.
  if (envFlagEnabled(env.ADMIN_TOKEN_DISABLED)) {
    if (onAuthDeny) onAuthDeny("admin-token-denied-disabled");
    return { ok: false };
  }
  const token = env.ADMIN_TOKEN;
  if (!token) {
    if (onAuthDeny) onAuthDeny("admin-token-denied-unconfigured");
    return { ok: false }; // no configured credential: deny
  }
  const header = req.headers.get("authorization") ?? "";
  const presented = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (presented.length === 0) {
    if (onAuthDeny) onAuthDeny("admin-token-denied-empty-bearer");
    return { ok: false };
  }
  // BREAK-GLASS RETIRE (in-app disposal): once the Owner has retired the token, the engine refuses the
  // bearer fallback exactly as ADMIN_TOKEN_DISABLED does. Consulted HERE (after confirming a token is
  // configured AND a bearer was presented) so the Access/passkey/no-credential paths never trigger the DO
  // read; a retired token fails closed BEFORE the constant-time compare and is NEVER downgraded to a weaker
  // method (there is none below). The resolver fails closed (true) on its own error, so a leaked token
  // cannot get a fail-open bypass by making the DO unavailable. With no resolver wired the predicate is the
  // env flag alone above (unchanged). Folding it in here keeps the env-only fast paths free of any DO read.
  if (breakGlassRetired && (await breakGlassRetired())) {
    // OBSERVE (G001): a token refused because the Owner RETIRED it in-app. Distinct from the env flag above and
    // from break-glass-check-unavailable (a DO outage failing closed), which the router records separately.
    if (onAuthDeny) onAuthDeny("admin-token-denied-retired");
    return { ok: false };
  }
  // ANTI-BRUTE-FORCE THROTTLE (ASVS V6.3.1): consulted HERE, immediately before the compare, so a
  // throttled guess never reaches tokenEqual at all. See TokenRateLimiter above for why this branch
  // (unlike Access/passkey) needed its own limiter, and adminTokenRateLimitedViaDO for the fail-closed
  // per-IP implementation the router wires in.
  // Marked THROTTLED rather than a bare deny. It is not a claim about the credential: this fires before
  // tokenEqual, so a correct and an incorrect token are refused identically, and saying "too many attempts"
  // tells an attacker nothing they did not already know from having made them. What it does fix is a
  // caller-side misreading with real consequences: a 401 here is indistinguishable from a session loss, and
  // the console's isUnauthorised() signs the operator out on one, so a rate-limited approvals lookup logged
  // an operator out in the middle of a restore.
  if (tokenRateLimited && (await tokenRateLimited(req))) return { ok: false, throttled: true };
  if (!(await tokenEqual(presented, token))) {
    // OBSERVE (G001): a bearer WAS presented and compared, and did not match: a stale/rotated/wrong token in
    // somebody's automation, or a guessing campaign (which the per-IP limiter above already throttles). The
    // presented value never leaves this frame - only the fact that a compare failed is counted.
    if (onAuthDeny) onAuthDeny("admin-token-denied-mismatch");
    return { ok: false };
  }
  // The bare-token fallback is not attributable to an email; the caller is resolved to the
  // owner role downstream (the documented break-glass), but it carries no identity here.
  return { ok: true, method: "token", email: null };
}

// tokenEqual compares two bearer tokens in constant time over their SHA-256 digests, so
// neither the contents nor the length leaks through timing. The comparison runs through
// constantTimeEqual, which drives the platform crypto.subtle.timingSafeEqual primitive in
// the Workers runtime rather than a hand-written loop.
export async function tokenEqual(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const ha = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(a)));
  const hb = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(b)));
  return constantTimeEqual(ha, hb);
}
