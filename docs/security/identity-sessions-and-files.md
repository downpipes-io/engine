# Identity, sessions and file handling

**Standard:** OWASP ASVS 5.0 - V10.3.3, V10.5.2 (identity), V6.x (first-party MFA), V7.x (session lifecycle), V5.1.1 (file handling).
**Scope:** Downpipes engine (TypeScript, Cloudflare Workers) and the offline `downpipe` CLI reader (Go).
**Date:**

This document is grounded in named source files. Where a control is delegated to an external
system (Cloudflare Access, the IdP the operator federates into Access) or is not enforced in
code, that is stated explicitly.

---

## 1. Identity model (ASVS V10.3.3, V10.5.2)

### 1.1 Authentication methods

The engine resolves admin requests at a strict authentication precedence in `authorise`
(`engine/src/admin/auth.ts`): a verified Cloudflare Access JWT, then a valid first-party SESSION
cookie, then the `ADMIN_TOKEN` bearer break-glass. The first-party session cookie is established by
ONE OF the engine's own sign-in front doors, which run BEFORE the authorise gate (in the router's
`/admin/auth/*`, `/admin/oidc/*` and `/admin/saml/*` dispatch): a WebAuthn PASSKEY ceremony, OR a
native external identity provider - OIDC (acting as a relying party), OAuth2, or a from-scratch
SAML SP supporting ~10 IdPs. All of them mint the SAME signed V3 session cookie (carrying the
authentication `method` - passkey/oidc/saml - and the stable `subject`), so from the precedence
point of view they are ONE tier: "a valid first-party session". A present-but-invalid higher
method is rejected outright and is NEVER downgraded to a weaker one: a bad Access assertion does
not try the session cookie or the token, and a present-but-invalid session does not fall through
to the token. This fail-closed-per-method rule is the core anti-downgrade property.

The native session's lifecycle (idle timeout, the slide, the concurrent-session policy, IdP-bound
expiry, step-up re-auth) is documented in the ASVS V7 mapping table and §2 below; it is the primary
federated ecosystem now (Cloudflare Access is one option among several, not the only federation).

**Cloudflare Access (when configured).** Access interposes a reverse proxy in front of the
engine's `/admin` routes and, after an operator-configured authentication flow, injects a
signed RS256 JWT into the `cf-access-jwt-assertion` request header. Trusting the mere
presence of the header would be an authentication bypass. The engine therefore verifies the
Access JWT on every request: RS256 signature against the Access account's public keys
(fetched from `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` and cached for one
hour), issuer match, audience match against the configured AUD tag, and expiry check. The
verification is in `engine/src/admin/access.ts:133-240` (`verifyAccessJWT`). Only after that
full verification do the token's email claim AND its stable subject become a trusted
identity; an Access verdict requires BOTH a verified email and a verified subject, and a
present-but-invalid assertion returns `{ ok: false }` and is never downgraded
(`engine/src/admin/auth.ts:110`, `:116`, `:124`).

As a defence against a misconfigured `CF_ACCESS_TEAM_DOMAIN` being used to redirect the JWKS
fetch to an attacker-controlled host, `assertCloudflareAccessHost` enforces that the resolved
team domain is a single-label `*.cloudflareaccess.com` subdomain before any fetch is made
(`engine/src/admin/access.ts:116-126`).

**First-party passkeys (the engine's own identity provider).** The engine is its own
identity provider: it implements WebAuthn registration and login directly (`passkey.ts` is
the pure verifier core, the scheduler DO is the storage authority, the router exposes the
`/admin/auth/*` ceremonies). A successful passkey login yields a signed session cookie that
authenticates subsequent requests (section 2). This is the free, self-hosted multi-user
front door for accounts that do not run Cloudflare Access (which is not free over 50 users).
User verification is MANDATORY: a registration whose user-verified (UV) flag is clear is
rejected (`engine/src/admin/passkey.ts:253`), and so is a login assertion whose UV flag is
clear (`engine/src/admin/passkey.ts:328`), so a bare presence touch alone is never accepted
for this privileged sign-in. A passkey caller carries the credential's bound, verified
email and resolves its role from the SAME subject-keyed role table the Access path uses.

**`ADMIN_TOKEN` bearer (bootstrap-only break-glass).** The shared `ADMIN_TOKEN` secret is a
lower-assurance break-glass that carries no email and resolves to the `owner` role
unconditionally with no session expiry. It is intended as a ONE-TIME bootstrap of the first
Owner, not a standing credential. An operator may disable it entirely by setting
`ADMIN_TOKEN_DISABLED=true`, after which only a verified Access JWT or a valid passkey
session is accepted (`engine/src/admin/auth.ts:176`); the token can also be retired in-app
once a passkey Owner exists (section 1.6).

### 1.2 Authority keyed on the immutable subject

Authorisation keys on the caller's STABLE, immutable subject, not the mutable email. The
subject is the load-bearing identity attribute: it is the storage key for the RBAC role
table in the scheduler Durable Object (`role:sub:<subject>`, section 1.4) and the axis of
the maker-not-checker comparison in the dual-control approval flow (section 1.4). The email
is retained for DISPLAY and AUDIT only: the console shows it, the audit records it, and it
is the key of a pending invite and the rate limiter, but it never decides a role lookup.

The subject is shaped at the trust boundary, distinctly per method:

- For an Access caller it is `iss + "|" + sub`, both read only from the RS256-verified
  payload: `sub` is Cloudflare Access's immutable opaque user id, and the team issuer is
  folded in so two tenants' subs can never collide
  (`engine/src/admin/access.ts:219-230`). A validly-signed assertion with no usable `sub`
  yields no subject and is rejected exactly as an emailless one is
  (`engine/src/admin/auth.ts:124`).
- For a passkey caller it is `passkey|<canonical-email>`, derived from the credential's
  bound email by `passkeySubject` (`engine/src/admin/identity.ts:526-528`). Because the
  engine issues its own passkey credentials bound at registration, the email is an
  immutable principal for that credential, not a recyclable external identifier. The
  `passkey|` namespace is disjoint from the Access `iss|sub` namespace, so the two can
  never collide.

The email is still canonicalised exactly once, at the trust boundary in `resolveCaller`,
via `canonicalEmail` (trim and `toLowerCase`) (`engine/src/admin/router-session.ts:43`;
`engine/src/admin/identity-roles.ts:104-118`), so a single canonical display form is seen by the
audit, the pending invite, and the rate limiter. The DO's own `normaliseEmail` applies the
same lowercase-and-trim normalisation at its authority boundary
(`engine/src/sched/scheduler-do-rbac.ts:47`), independently of the router, as defence in
depth.

**The recycled-email closure (ASVS V10.5.2).** Email is a mutable, reassignable attribute:
an IdP may reassign a departed user's email address to a new user, or allow a user to change
their own address. Because authority keys on the subject and not the email, a recycled or
reassigned email can NEVER inherit a departed member's role. A caller whose email equals a
departed member's but whose subject differs has no bound role entry (the departed member's
grant bound to the departed subject, or was deleted) and matches no pending invite of the
departed member, so it resolves to the least-privilege `viewer`
(`engine/src/sched/scheduler-do-rbac-authority.ts:54-96`, `roleForCaller`). The OIDC-preferred stable identifier is the
key in fact, not in aspiration.

A user who changes their own IdP email address keeps their role: the subject is unchanged,
and the bound entry's email is a display field that the next sign-in re-records. This is a
strict improvement over the prior email-keyed model, in which an email change silently
dropped the role grant.

### 1.3 Compensating controls

This section documents a fix that closes a specific privilege-escalation path: an emailless but
validly-signed Access assertion (issued by a Cloudflare Access service token, or by a
misconfigured IdP that omits the email claim) must never fold into the bearer-token break-glass
and must never reach the Owner role.

The control is applied at independent layers, and now bars an emailless OR subjectless
authenticated caller from the break-glass:

- `authorise` in `engine/src/admin/auth.ts:116`: after a positive RS256 verification, if the
  email claim is absent the verdict is `{ ok: false }` and never proceeds; a subjectless
  Access assertion is rejected the same way (`engine/src/admin/auth.ts:124`).
- `handleAdmin` in `engine/src/admin/router.ts:150-156`: after a positive `authorise`
  verdict, if the canonical email is null on an `access`- or `passkey`-method verdict, the
  request is refused with HTTP 401 and a log line tagged `authn failure method=<method>
  reason=session verified but carried no usable email`.
- `resolveCaller` in `engine/src/admin/router-session.ts:33-49`: the bearer-token Owner
  break-glass (`method === "token"`) is the only path that resolves without an email or
  subject. An `access`- or `passkey`-method verdict missing either is explicitly not allowed
  to take the token break-glass branch and instead resolves to the least-privilege `viewer`
  role.
- The scheduler DO's `roleForCaller` keys on the stable subject and fails closed to `viewer`
  for a subjectless non-token caller, with a matching `SECURITY` comment
  (`engine/src/sched/scheduler-do-rbac-authority.ts:54-96`, `roleForCaller`).

The only emailless/subjectless authenticated path that exists by design is the bearer-token
break-glass (`method: "token"`). It resolves unconditionally to `owner`, carries no session
expiry, and is excluded from the group-mapping path (it has no IdP identity, so no groups are
applicable).

### 1.4 RBAC role table and dual-control identity binding

The role table is keyed by the caller's stable subject under the `role:sub:` prefix in the
scheduler DO's durable storage (`ROLE_SUBJECT_PREFIX`, `engine/src/admin/identity.ts:258-261`).
A bound `RoleEntry` records the subject (the authority key) plus the email (display/audit
only) (`engine/src/admin/identity.ts:285-297`, `RoleEntry`). Because an Owner/access-admin invites by
email (they do not know the subject yet), a grant first lands as a pending invite keyed by
email (`role:pending:<email>`, `engine/src/admin/identity.ts:264-269`, `ROLE_PENDING_PREFIX`); on the invitee's first
verified request the DO BINDS it to their subject, writing `role:sub:<subject>` and deleting
the pending row (`resolveBoundEntry`, `engine/src/sched/scheduler-do-rbac.ts:205-265`). A legacy
`role:<email>` entry from before the re-keying is read as a pending invite, so existing grants
bind on next login and are never silently dropped
(`engine/src/sched/scheduler-do-rbac.ts:205-265`, `resolveBoundEntry`).

The roles are defined in `engine/src/admin/identity.ts:29` (the six-role union), with rank
ordering in `ROLE_RANK` at `:39-46`; per-route authority is decided by the `ROLE_CAPABILITIES`
capability map (`engine/src/admin/identity.ts:93-141`), not by rank. The last-Owner guard
prevents the only effective Owner from being demoted or removed, enforced inside a single
storage read-modify-write in the DO so there is no race (`setRole` at
`engine/src/sched/scheduler-do-rbac-mutations.ts:41`, `deleteRole` at `:205`,
`requireNotOwnerEscalation` at `:1995`). The Owner count operates over both bound and pending
entries, so the guard cannot be defeated by removing the only bound Owner while a pending
Owner exists, or vice versa (`countOwners`, `engine/src/sched/scheduler-do-rbac.ts:308-313`).

The optional identity-provider group-to-role mapping is additive and capped below `owner`: a
group can never confer `owner`. The cap is enforced both at write time (`setGroupRole` rejects
`owner`) and at resolution (`capGroupRole` clamps any stored `owner` value back to `approver`)
(`engine/src/sched/scheduler-do-rbac-mutations.ts:41-198`, `setRole`). The last-Owner count operates only over
explicit `role:sub:`/pending entries; a group mapping can never count toward it
(`engine/src/sched/scheduler-do-rbac.ts:308-313`, `countOwners`).

The dual-control maker-not-checker comparison now keys on the STABLE subject, not the email:
it compares the requester's subject (`requesterSubject`, the maker) against the approver's
subject (`approverSubject`, the checker), refusing a self-approval where the two are equal
(`canApprove`, `engine/src/admin/approvals.ts:148`, `:165`), enforced server-side in the DO
inside one read-modify-write (`approveRestore`, `engine/src/sched/scheduler-do-restore-approval.ts:163-218`).
A bare-token caller has no stable subject and so can be neither a distinct maker nor checker;
a request or approval from it is refused (`engine/src/sched/scheduler-do-restore-approval.ts:163-218`). The
display emails (`requestedBy`/`approvedBy`) are recorded alongside for the trail but are not
the comparison axis, so two capitalisation or reassignment variants of an address can never be
mistaken for one identity.

### 1.5 Operator recommendation

The role grant is decoupled from IdP email reassignment by construction (section 1.2), so the
prior recommendation to police email reuse is no longer load-bearing. Two residual operator
practices remain useful: subscribe the Owners to IdP account-lifecycle events (user deletion)
so a departed member's role entry is removed promptly even though a recycled email could never
inherit it; and, where an account runs the engine's own passkeys rather than Cloudflare
Access, revoke a departed member's enrolled credentials (section 1.6) so the credential cannot
be reused.

### 1.6 `ADMIN_TOKEN` is bootstrap-only

The shared `ADMIN_TOKEN` bearer is a ONE-TIME bootstrap credential, not a standing one. Two
controls bound its lifetime:

- **One-way bootstrap latch.** The moment the first Owner row is created (the whoami
  empty-table grant, or the first passkey enrolment) the DO latches `bootstrapConsumed` true;
  once true, no bootstrap path may ever mint a second Owner
  (`getBootstrapConsumed`/`markBootstrapConsumed`,
  `engine/src/sched/scheduler-do-org-policy.ts:175-205`). The transition is audited once as a
  `bootstrap-consumed` event.
- **In-app retire/dispose gate.** An Owner can retire the token in-app via
  `POST /admin/policy/retire-break-glass-token` (`engine/src/admin/router-ops.ts:338`), after
  which `authorise` refuses the bearer exactly as `ADMIN_TOKEN_DISABLED` does
  (`engine/src/admin/auth.ts:189`). The retire is OWNER-ONLY, re-resolved from the DO's own
  tables, and is REFUSED unless a way back in already exists: recovery codes acknowledged for
  an Owner, OR a second Owner (`setBreakGlassTokenRetired`,
  `engine/src/sched/scheduler-do-org-policy.ts:256-298`). Because a retired bare token never resolves
  to Owner, it can never un-retire itself; only a passkey/Access Owner can flip it. The
  precondition that an Owner have a passkey-bound recovery path means the gate effectively
  requires a passkey-bound Owner before the bootstrap credential can be disposed of.

---

## 2. Authentication factors and session lifecycle (ASVS V6.x, V7.x)

### 2.1 The first-party signed passkey session

The engine now issues its OWN session for passkey sign-in: a signed cookie verified
server-side against a key that lives only in the scheduler DO. It is self-contained (there is
no per-session storage row) but it IS revocable (section 2.4). For Cloudflare Access callers
the engine still holds no session of its own (Access owns that session, section 2.2), and the
bare-token break-glass is sessionless.

The session token is `<body_b64url>.<mac_b64url>`, where `mac = HMAC-SHA-256(key, body)`. The
signing key is a 32-byte CSPRNG value generated ONCE by the DO and persisted under a single DO
key (`sessionSigningKey`, `engine/src/sched/scheduler-do-session.ts:58-90`); it never leaves the
DO, so both the sign and the constant-time verify run inside the DO (`session.ts` is the pure,
key-as-argument core the DO drives, `engine/src/admin/session.ts:111-185`). Key properties:

- **Server-verified MAC, not a bearer secret.** Verification recomputes the MAC over the body
  and compares in CONSTANT time; the body is never parsed unless the MAC matches, so a
  tampered or forged body can never set the email or extend the expiry
  (`engine/src/admin/session.ts:128-185`). The per-request check runs over the in-DO key via a
  DO fetch (`passkeySessionVerify`, `engine/src/sched/scheduler-do-session.ts:231-332`).
- **Email and per-email epoch only; role is never carried.** The signed body holds the
  verified email, a per-email session `epoch`, the issued-at and absolute-expiry timestamps,
  and a format version (`SessionPayload`, `engine/src/admin/session.ts:69-77`). The role is
  ALWAYS re-resolved from the DO role table on each request (keyed on the subject), never
  pinned in the token, so a session can never smuggle an elevated role.
- **Absolute 12-hour TTL.** The session is bounded by an absolute `exp` set once at mint
  (`SESSION_TTL_MS = 12h`, `engine/src/admin/session.ts:50`); there is no sliding renewal, so
  a leaked cookie is useless past the TTL deterministically. `verifySession` rejects an expired
  token (`engine/src/admin/session.ts:177`).
- **`__Host-` cookie hardening.** The cookie name is `__Host-downpipes_session`
  (`engine/src/admin/session.ts:44`), and it is set HttpOnly, Secure, SameSite=Strict, Path=/
  with no Domain attribute (`sessionSetCookie`, `engine/src/admin/session.ts:199-202`). The
  `__Host-` prefix is browser-enforced: a browser accepts it only when it is Secure, has
  Path=/ and no Domain, which pins the cookie to this exact host over HTTPS and forbids a
  sibling/parent domain from setting or overriding it (a subdomain cookie-injection/fixation
  defence).

### 2.2 Cloudflare Access sessions (when configured)

For an Access caller, session lifetime, inactivity timeout, concurrent-session limits, and
Access-side termination remain delegated to Cloudflare Access; the operator configures the
Access session duration in the Cloudflare Access dashboard. Access is responsible for issuing
the Access JWT with an `exp` claim, rotating or revoking the session when the operator changes
the Access policy, enforcing the configured session/inactivity duration, and limiting
concurrent sessions (if the Access application is configured to do so). None of these
Access-side controls exist in the engine code; the engine cannot influence them. The engine's
own per-request expiry check (section 2.3) still applies to the Access JWT.

### 2.3 Per-request expiry enforcement

For an Access caller the engine independently enforces expiry: on every request
`verifyAccessJWT` checks `typeof payload.exp !== "number" || payload.exp <= opts.now` and
returns `{ ok: false, reason: "expired" }` when the token is expired or lacks a numeric expiry
(`engine/src/admin/access.ts:165`). The `now` value is `Math.floor(Date.now() / 1000)` at the
time the request is processed, so a token whose session has expired at the Access layer is
rejected here even if Access did not intercept the request. An `nbf` (not-before) claim, if
present and in the future, is also rejected (`engine/src/admin/access.ts:166`).

For a passkey caller the equivalent control is the absolute `exp` check in `verifySession`
(`engine/src/admin/session.ts:177`), evaluated over the in-DO key on every request.

The verified Access `exp` is carried through to `GET /admin/whoami` via the `AuthVerdict` type
(`engine/src/admin/identity.ts:442-444`) and surfaced to the console as `sessionExpiresAt`
(`engine/src/admin/router.ts:270`), so the console can display the honest Access session expiry
without re-parsing the token.

### 2.3a CSRF defence for the cookie-borne session

A passkey session is carried in an AMBIENT cookie that a foreign page could ride on a
state-changing request, so every MUTATING (non-GET, non-OPTIONS) request authenticated via the
passkey session MUST also carry an `Origin` that EXACTLY matches `CONSOLE_ORIGIN`. This
strict-Origin check is enforced before any route body read or DO forward
(`engine/src/admin/router.ts:180-185`; `originAllowed`,
`engine/src/admin/session.ts:245-250`). It fails closed on a missing `Origin` or an unset
`CONSOLE_ORIGIN`. It is defence in depth ON TOP of the cookie's `SameSite=Strict`: even a
browser that ignored SameSite, or a future relaxation, could not drive a cross-origin write.
The Access and bare-token methods present an explicit header that a cross-site page cannot set
on a credentialed cross-origin request, so they are not ambient-credential CSRF vectors and
are exempt from this check.

### 2.4 Session termination (the passkey session is revocable)

The passkey session is self-contained yet revocable, via a per-email session epoch plus
signing-key rotation. A monotonic per-email `epoch` counter is stored in the DO
(`SESSION_EPOCH_PREFIX`, `engine/src/sched/scheduler-do-base.ts:2459`); the token carries the
epoch at issue, and `passkeySessionVerify` rejects a token whose epoch is below the email's
current stored value (`engine/src/sched/scheduler-do-session.ts:258-263`). Bumping the epoch
therefore invalidates every session minted before the bump, with no session store to walk.
Single-use logout clears the cookie with the same attributes and `Max-Age=0`
(`sessionClearCookie`, `engine/src/admin/session.ts:209-211`; route `POST /admin/auth/logout`,
`engine/src/admin/router-auth-flow.ts:165`).

The termination capabilities are:

- **Terminate other sessions (self).** `POST /admin/sessions/terminate-others`
  (`engine/src/admin/router.ts:481`) bumps the caller's own epoch and returns a freshly-minted
  token carrying the new epoch, so the current session stays alive while all others die
  (`terminateOwnOtherSessions`, `engine/src/sched/scheduler-do-session.ts:351-388`).
- **Terminate a member's sessions (admin).** `POST /admin/sessions/terminate-user`
  (`engine/src/admin/router.ts:495`) bumps a target email's epoch. Gated on `roles.write`
  re-resolved, and an Owner's sessions may be terminated only BY an Owner
  (`terminateUserSessions`, `engine/src/sched/scheduler-do-session.ts:393-417`).
- **Terminate ALL sessions (owner).** `POST /admin/sessions/terminate-all`
  (`engine/src/admin/router.ts:503`) DELETES the session signing key, so every outstanding
  token fails its next MAC verify and a fresh key is generated on the next issue. Gated on
  `roles.write` re-resolved AND `role === "owner"` (`terminateAllSessions`,
  `engine/src/sched/scheduler-do-session.ts:133-145` (`terminateAllSessions`).
- **Revoke a credential.** `POST /admin/passkey/credentials/delete`
  (`engine/src/admin/router.ts:472`) removes a WebAuthn credential (the theft/loss path) and
  bumps the bound email's session epoch so any session that credential authenticated also
  dies. Self-service, or by an access-admin/owner; an Owner's credential requires an Owner
  caller, and the last credential of the sole Owner is refused so an Owner is never locked out
  of the in-app factor (`revokePasskeyCredential`,
  `engine/src/sched/scheduler-do-recovery.ts:393-445` (`revokePasskeyCredential`).

The epoch is also bumped on a factor change (a passkey revoke, a recovery-code regeneration),
so changing an authentication factor invalidates outstanding sessions for that email.

### 2.5 ASVS V6/V7 control mapping

| ASVS control | Status | Notes |
|--------------|--------|-------|
| V6.3.3 - Multi-factor / phishing-resistant authentication | Engine-enforced (passkeys) | First-party WebAuthn passkeys with MANDATORY user verification (`engine/src/admin/passkey.ts:253`, `:328`). |
| V6.5.x - Recovery / lookup-secret factor | Engine-enforced (recovery codes) | Single-use, salted-hash recovery codes; plaintext returned once, only the salted HMAC stored (`engine/src/admin/recovery.ts:57-61`, `:75`). See logging-inventory for the audited lifecycle. |
| V7.1.1 - Session tokens not in URL parameters | Met | The passkey session is a `__Host-` cookie; no token appears in a URL. The Access path uses a request header. |
| V7.2.1 / V7.8.1 - Session invalidation on logout | Engine-enforced (passkey); Access-managed (Access) | `POST /admin/auth/logout` clears the cookie (`engine/src/admin/router-auth-flow.ts:165`); termination routes (section 2.4) revoke server-side via the epoch/key. Access sign-out remains Access's. |
| V7.2.2 - Session creation after re-authentication | Engine-enforced (passkey) | A fresh signed token is minted only after a WebAuthn login (`passkeySessionIssue`, `engine/src/sched/scheduler-do-session.ts:183-192`); the role is re-resolved, never carried. Access creates its own session. |
| V7.3.1 - Session inactivity timeout | Engine-enforced (native session) | An idle (inactivity) bound now applies: a session is rejected after `SESSION_IDLE_MS` of no activity (`engine/src/admin/session.ts`), independent of the 12h absolute cap. Activity is recorded as `lastSeen` in the signed V3 body and refreshed by a slide re-mint that preserves the original `iat`/`exp` (so it never extends the absolute cap). Access's own inactivity window stays operator-configured. |
| V7.3.2 - Absolute session duration limit | Engine-enforced (native session) | Absolute 12-hour TTL set once at mint (`SESSION_TTL_MS`, `engine/src/admin/session.ts`). The idle-slide re-mint refreshes `lastSeen` only; it preserves the original `iat`/`exp`, so the absolute cap is never slid forward. Access duration is operator-configured. |
| V7.4.1 / V7.1.2 - Concurrent session policy | Engine policy (native session) | The native session is stateless (no per-session store), so the engine does NOT cap the NUMBER of concurrent sessions; instead EVERY session for an identity is revocable at once via the per-email epoch / per-subject not-before instant / signing-key rotation (section 2.4). A removed member's or a logged-out identity's sessions all die on their next request (the epoch is bumped on offboarding AND logout). Access concurrency, where used, stays operator-configured. |
| V7.4.3 / V7.4.5 - Terminate a user's sessions (admin) | Engine-enforced | `terminate-user` (admin, owner-guarded) and `terminate-all` (owner) bump the epoch / rotate the key (`engine/src/sched/scheduler-do-session.ts:393-417`, `:133-145`). |
| V7.5.2 - View and terminate other active sessions (self) | Engine-enforced | `terminate-others` bumps the caller's epoch and re-issues their current session (`engine/src/sched/scheduler-do-session.ts:351-388`). |
| V7.5.1 - Session token properties (length, entropy, unpredictability) | Engine-enforced (passkey) | The session is a server-signed HMAC over a 32-byte CSPRNG key (`engine/src/admin/session.ts:111-116`, `engine/src/sched/scheduler-do-session.ts:58-90`), not a guessable bearer. The Access JWT is RS256, verified not generated. |
| V7.6.1 - Expiry check on every request | Engine-enforced | `verifyAccessJWT` checks `exp <= now` for Access (`engine/src/admin/access.ts:165`); `verifySession` checks the absolute `exp` for the passkey session (`engine/src/admin/session.ts:177`). |

**Authentication strength (ASVS V6.8.4):** the native OIDC/OAuth2/SAML RP does NOT read or require an
IdP-reported authentication-strength claim (`acr`/`amr`/`auth_time`, or a SAML `AuthnContextClassRef`). It
verifies the standard token integrity (signature, `iss`/`aud`/`azp`, `exp`/`nbf`, `nonce`, `sub`, `at_hash`)
and assumes the IdP enforces the operator's required strength. An operator who needs a specific factor (e.g.
MFA) for sign-in must configure that policy AT THE IdP. The engine-side defence that does NOT depend on a
(spoofable or absent) IdP strength claim is the step-up re-authentication control (ASVS V7.5.1): owner-reserved
sensitive actions (`keys.ceremony`, `posture.riskaccept`, restore-approve) require a fresh strong factor
regardless of how the session was originally established. Reading `acr`/`auth_time` as an OPTIONAL,
strictly non-gating signal is a documented future enhancement.

**Operator configuration (Access only):** where Cloudflare Access is used, the operator should
still set an explicit Access session duration and inactivity window, enable concurrent-session
enforcement if policy requires it, and configure the Access revocation behaviour. The engine
cannot verify these Access-side settings; failure to set them leaves the corresponding
Access-managed controls unmet for Access callers. An account running the engine's own passkeys
needs none of this (the controls above are engine-enforced).

### 2.6 Contextual attributes and adaptive controls (ASVS V8.1.3, V8.2.4)

ASVS V8.1.3 asks the application to DOCUMENT the environmental and contextual attributes it uses to
make security decisions; V8.2.4 asks that adaptive controls based on those attributes be applied
both when a session is created and DURING an existing session, as defined in that documentation.
This section is that documentation.

A note on custody first, because it is the usual point of confusion: the engine runs in the
CUSTOMER's own Cloudflare account. Any contextual attribute it observes (a source IP, a connection
identity) is seen and, where retained, stored inside the customer's own account. None of it reaches
the vendor. No-custody is a statement about what the VENDOR holds, so using contextual attributes
for the customer's own operators does not bear on it.

The contextual attributes the engine uses for authentication and authorization decisions are:

- **Temporal context (inactivity and absolute age).** Every request re-evaluates the session's idle
  instant (`lastSeen`) against `SESSION_IDLE_MS`, and its absolute age against `SESSION_TTL_MS`
  (`engine/src/admin/session.ts`). Inactivity is a contextual signal applied continuously during a
  session, not only at sign-in.
- **Connection identity.** The signed V3 session body binds an optional `connId` at mint
  (`engine/src/admin/session.ts:101-121`), tying the session to the connection context in which it
  was established.
- **Request origin.** Every mutating passkey-session request must present an `Origin` that exactly
  matches `CONSOLE_ORIGIN`, enforced before any body read (section 2.3a). Origin is a contextual
  attribute evaluated on each state-changing request.
- **Subject continuity.** The caller's role is RE-RESOLVED from the immutable subject on every
  request (never carried in the token), and the session is checked against three revocation axes
  (per-email epoch, per-subject not-before, signing-key generation; section 2.4). A change in the
  subject's authority or standing takes effect on the next request.
- **Action sensitivity.** Owner-reserved sensitive actions (`keys.ceremony`, `posture.riskaccept`,
  restore-approve) require a fresh strong factor via step-up re-authentication (ASVS V7.5.1),
  regardless of how the session was established. The control adapts to the RISK of the operation.
- **Source network address.** The source IP is recorded on every authentication event
  (`idp-sign-in`, `authn-failure`, the sign-in events) in the tamper-evident audit chain, so it is
  available as a contextual attribute for review within the customer's account.

Adaptive controls applied AT SESSION START: WebAuthn user verification is mandatory
(`engine/src/admin/passkey.ts`), the connection identity is bound into the signed body, and the
strict-Origin check gates the establishing request.

Adaptive controls applied DURING AN EXISTING SESSION: the inactivity timeout, the per-request role
re-resolution and the revocation-axis checks, the strict-Origin check on every mutating request, and
step-up re-authentication whenever the requested action is sensitive.

Honest scope. The engine does NOT implement geolocation- or IP-reputation-based adaptive BLOCKING,
nor device-posture assessment. Those need either a per-operator behavioural baseline (noisy under
mobile and NAT address churn) or an endpoint agent, and the platform does not build them by default.
The source IP is captured and available should an operator wish to add such a control in their own
account. Network location is never a SOLE authorization factor (ASVS V8.4.2): authority always rests
on the re-resolved role and the cryptographic session, never on where the request came from.

---

## 3. File handling (ASVS V5.1.1)

### 3.1 Product architecture: no user file upload surface

The downpipes product is a content-addressed backup system. Neither the engine Worker nor the
Go CLI has an upload surface where an operator or end-user submits an arbitrary file for
storage or processing. The file-handling controls documented here are therefore on the
archive-write and restore-read paths, not on a classic file-upload pipeline.

The engine writes sealed archive objects (segments, manifests, a RUNLOG) to a destination
bucket (R2 or S3-compatible). The Go CLI reads those objects from the archive and restores
their decrypted contents to file-system or environment-variable targets. Neither path accepts
a file from an unauthenticated or externally-controlled source; all data flows from
operator-configured, in-account bindings (KV, R2, D1, Secrets Store).

### 3.2 Engine side: R2 archive object writes (engine/src/dest/r2.ts)

The engine writes content-addressed archive objects through the `R2Destination` class
(`engine/src/dest/r2.ts`). Object keys are content-addressed identifiers (segment IDs, run
IDs, manifest paths) derived from cryptographic material; they are not constructed from
operator-supplied or user-supplied strings.

A single-segment size ceiling is enforced at two independent layers:

- The source side caps a value at `MAX_STREAM_SEGMENT_BYTES` (1 GiB, SPEC 14.5) before
  streaming it to the destination.
- The `putStream` method in `R2Destination` asserts the same ceiling as defence in depth and
  throws if a size argument exceeds it (`engine/src/dest/r2.ts:74-98`, the assertion at
  `:75-76`).

Content-addressed deduplication (checking object existence before re-uploading a segment
that already landed in the same run; addressing is per-run, so it never spans runs) is
performed via `R2Destination.exists`, which calls `R2Bucket.head` to avoid fetching the
body (`engine/src/dest/r2.ts:101-103`).

### 3.3 Engine side: restore sink writes (engine/src/dest/restore-sink.ts)

The restore path (`runRestore` in `engine/src/admin/restore.ts`) writes verified archive
content back into live in-account resources. Restore sinks are constructed only after the
following checks:

- The target binding is checked against `RESERVED_BINDINGS` before any sink is constructed.
  A reserved binding (any of the engine's own configuration bindings) poisons the whole
  restore and refuses it before any write is attempted. This is the confused-deputy guard,
  enforced in `guardTarget` (`engine/src/admin/restore.ts:85-86`, called at
  `engine/src/admin/restore.ts:100`, `engine/src/admin/restore.ts:110`, `engine/src/admin/restore.ts:122`,
  `engine/src/admin/restore.ts:133`, and again at `:209`).
- For a confirmed (non-dry-run) apply, every in-scope record is verified by re-running its
  plaintext SHA-384 hash check (`run.restoreRecord`) before a single byte is written back.
  An integrity failure on any record aborts the entire apply; no bytes are written until all
  records have passed (`engine/src/admin/restore-apply.ts:36-42`, `applyDataRecords`, the two-phase verify-then-write
  described in its own comment).

The `KVRestoreSink`, `R2RestoreSink` and `D1RestoreSink` implementations in
`engine/src/dest/restore-sink.ts` write only the logically-bounded content of a verified
archive record: a KV value (platform-capped at 25 MiB), an R2 object written via a binding
with no multipart path, or a parameterised D1 INSERT replay (column values are bound
parameters, never interpolated into SQL, `engine/src/dest/restore-sink.ts:243-262`).

Secrets records are handled separately: the Cloudflare Secrets Store binding exposes no
runtime write path, so secrets records are routed to the `outOfBand` list and never pass
through the write loop. A `SecretsRestoreSink` whose target has no wired `put` callback throws
rather than silently skipping (`engine/src/dest/restore-sink.ts:162-164`).

### 3.4 Go CLI side: path-traversal protections in the file target (downpipe/internal/restore/target.go)

The `downpipe` CLI restores archive records to local files via `DirTarget` (the file
restore-sink code now lives in `downpipe/internal/restore/target.go`, formerly an
`internal/sink` package). A record key in the archive can be an arbitrary string (for
example `a/b/key`, or a key containing `..` elements). Mapping such a key straight to a path
component would be a path-traversal vulnerability.

The containment lives in `DirTarget.Key`, which the restore planner calls to map a record
name to a contained relative path before it is ever written
(`downpipe/internal/restore/target_dir.go:40-46`). `Key` delegates to `safeKey`, which splits the
name on the OS path separator (after `filepath.FromSlash`), drops every empty, `.` and `..`
element, re-joins the remainder, and collapses an empty result to `_`
(`downpipe/internal/restore/target_dir.go:180-193`). A name of `../../etc/evil` is therefore
mapped to `etc/evil`, contained inside the base directory. `DirTarget.Write` then joins the
base directory with the already-contained key (`filepath.Join(d.baseDir,
filepath.FromSlash(key))`, `downpipe/internal/restore/target_dir.go:88`); the traversal
sanitisation is the `Key`/`safeKey` step, not the join itself.

Write mode is `O_WRONLY | O_CREATE | O_EXCL` with permissions `0o600`
(`downpipe/internal/restore/target_dir.go:92`). The `O_EXCL` flag means a write fails loudly if
the target path already exists; two distinct record names that map to the same path cannot
silently clobber each other, and a re-run into a populated output directory is refused at
plan time via `DirTarget.Existing` (`downpipe/internal/restore/target_dir.go:52-82`).

The `EnvTarget` (a separate file from `DirTarget`) writes dotenv `KEY='value'` lines. The key is validated against a
strict `[A-Za-z_][A-Za-z0-9_]*` pattern (`validEnvName`,
`downpipe/internal/restore/target_env.go:104-118`) before any write. A crafted record name
containing a newline, an `=` sign, or a space fails this check, so it cannot inject extra
lines into the dotenv output (`downpipe/internal/restore/target_env.go:78-88`). Values are
single-quoted with embedded single quotes escaped via `'\''`
(`downpipe/internal/restore/target_env.go:88`). A value containing a NUL byte is rejected as
unsuitable for a dotenv target (`downpipe/internal/restore/target_env.go:86`).

(Note: `target.go` in the sibling `downpipe` repository now holds only the `Target`/`StreamTarget`
interfaces; the concrete `DirTarget` and `EnvTarget` implementations cited above live in
`target_dir.go` and `target_env.go` respectively. Re-verified against that repo directly;
re-check these line numbers if either file changes again, since this engine repo cannot
enforce them.)

### 3.5 Honest statement of scope

The file-handling controls documented above cover:

- The engine's content-addressed archive write path (segment size ceiling, reserved-binding
  guard, integrity-before-write ordering on restore).
- The Go CLI's archive restore path (path-traversal containment in `safeKey`, exclusive-create
  semantics in `DirTarget`, env-name validation and value quoting in `EnvTarget`).

There is no general file upload pipeline, no MIME-type validation surface, no file-type
detection, and no antivirus scanning, because none of those are applicable to this
architecture. The ASVS V5.1.1 file handling controls that relate to upload (client-side
versus server-side validation of file content, MIME sniffing, dangerous file-extension
blocking) are therefore not applicable here and are not claimed to be implemented.

---

## 4. ASVS mapping summary

| ASVS control | Section above | Status |
|--------------|---------------|--------|
| V6.3.3 - Multi-factor / phishing-resistant authentication | 1.1, 2.5 | MET: first-party WebAuthn passkeys, user verification mandatory (`passkey.ts:253`, `:328`). |
| V6.5.x - Recovery / lookup-secret factor | 2.5 | MET: single-use, salted-hash recovery codes (`recovery.ts:57-61`). |
| V10.3.3 - Identity-provider group/role binding | 1.4 | MET: additive group-to-role mapping, capped below owner, enforced in the scheduler DO (`engine/src/sched/scheduler-do-rbac-mutations.ts:41-198`, `setRole`). |
| V10.5.2 - Stable, unique identity key (iss+sub) | 1.2, 1.4 | MET: authority keys on the immutable subject (`role:sub:<subject>`, `identity.ts:258-261`); email is display/audit only and a recycled email cannot inherit a role (`engine/src/sched/scheduler-do-rbac-authority.ts:54-96`, `roleForCaller`). |
| V7.2.2 / V7.3.2 / V7.5.1 / V7.6.1 - Session lifecycle | 2.1, 2.3, 2.5 | MET (passkey session): server-verified `__Host-` cookie, absolute 12h TTL, expiry checked each request (`session.ts:50`, `:177`). Access session controls remain Access-managed. |
| V7.4.3 / V7.4.5 - Terminate a user's sessions (admin) | 2.4 | MET: `terminate-user` / `terminate-all` bump the epoch / rotate the key (`engine/src/sched/scheduler-do-session.ts:393-417`, `:133-145`). |
| V7.5.2 - View and terminate other active sessions (self) | 2.4 | MET: `terminate-others` bumps the caller's epoch and re-issues their session (`engine/src/sched/scheduler-do-session.ts:351-388`). |
| V8.1.3 - Documented contextual attributes for security decisions | 2.6 | MET: the environmental and contextual attributes used (inactivity, connection identity, request origin, subject continuity, action sensitivity, source IP) are defined in section 2.6. |
| V8.2.4 - Adaptive controls at session start and during the session | 2.6 | MET: adaptive controls are applied at both points as documented in section 2.6 (user verification, connection and origin binding at start; inactivity timeout, per-request role re-resolution, revocation-axis and origin checks, and risk-based step-up during the session). Contextual binding runs in the customer's own account, so it carries no vendor-custody implication. |
| V5.1.1 - Path traversal prevention in file handling | 3.4 | Implemented in the Go CLI `safeKey`/`Key` + `O_EXCL` write. Engine restore uses binding-level containment, not a file path. |
