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

The native session's lifecycle is documented in §2: the lifetime bounds and their NIST SP 800-63B
alignment in §2.1a, termination in §2.4, the ASVS V7 mapping table in §2.5, and the federated
coordination (IdP-bound expiry, the absence of single logout, re-authentication conditions) in §2.7.
The native front doors are the primary federated ecosystem; Cloudflare Access is one option among
several, not the only federation.

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
  bound email by `passkeySubject` (`engine/src/admin/identity.ts:529-531`). Because the
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

### 1.3 Compensating controls (ENG-B1)

The fix recorded as ENG-B1 closes a specific privilege-escalation path: an emailless but
validly-signed Access assertion (issued by a Cloudflare Access service token, or by a
misconfigured IdP that omits the email claim) must never fold into the bearer-token break-glass
and must never reach the Owner role.

The control is applied at independent layers, and now bars an emailless OR subjectless
authenticated caller from the break-glass:

- `authorise` in `engine/src/admin/auth.ts:116`: after a positive RS256 verification, if the
  email claim is absent the verdict is `{ ok: false }` and never proceeds; a subjectless
  Access assertion is rejected the same way (`engine/src/admin/auth.ts:124`).
- `handleAdmin` in `engine/src/admin/router.ts:149-155`: after a positive `authorise`
  verdict, if the canonical email is null on an `access`- or `passkey`-method verdict, the
  request is refused with HTTP 401 and a log line tagged `authn failure method=<method>
  reason=session verified but carried no usable email (ENG-B1)`.
- `resolveCaller` in `engine/src/admin/router-session.ts:33-49`: the bearer-token Owner
  break-glass (`method === "token"`) is the only path that resolves without an email or
  subject. An `access`- or `passkey`-method verdict missing either is explicitly not allowed
  to take the token break-glass branch and instead resolves to the least-privilege `viewer`
  role.
- The scheduler DO's `roleForCaller` keys on the stable subject and fails closed to `viewer`
  for a subjectless non-token caller, with a matching `SECURITY (ENG-B1)` comment
  (`engine/src/sched/scheduler-do-rbac-authority.ts:54-96`, `roleForCaller`).

The only emailless/subjectless authenticated path that exists by design is the bearer-token
break-glass (`method: "token"`). It resolves unconditionally to `owner`, carries no session
expiry, and is excluded from the group-mapping path (it has no IdP identity, so no groups are
applicable).

### 1.4 RBAC role table and dual-control identity binding

The role table is keyed by the caller's stable subject under the `role:sub:` prefix in the
scheduler DO's durable storage (`ROLE_SUBJECT_PREFIX`, `engine/src/admin/identity.ts:261-264`).
A bound `RoleEntry` records the subject (the authority key) plus the email (display/audit
only) (`engine/src/admin/identity.ts:288-300`, `RoleEntry`). Because an Owner/access-admin invites by
email (they do not know the subject yet), a grant first lands as a pending invite keyed by
email (`role:pending:<email>`, `engine/src/admin/identity.ts:267-272`, `ROLE_PENDING_PREFIX`); on the invitee's first
verified request the DO BINDS it to their subject, writing `role:sub:<subject>` and deleting
the pending row (`resolveBoundEntry`, `engine/src/sched/scheduler-do-rbac.ts:205-265`). A legacy
`role:<email>` entry from before the re-keying is read as a pending invite, so existing grants
bind on next login and are never silently dropped
(`engine/src/sched/scheduler-do-rbac.ts:205-265`, `resolveBoundEntry`).

The roles are defined in `engine/src/admin/identity.ts:29` (the six-role union), with rank
ordering in `ROLE_RANK` at `:39-46`; per-route authority is decided by the `ROLE_CAPABILITIES`
capability map (`engine/src/admin/identity.ts:96-144`), not by rank. The last-Owner guard
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
key (`sessionSigningKey`, `engine/src/sched/scheduler-do-session.ts:162-194`); it never leaves the
DO, so both the sign and the constant-time verify run inside the DO (`session.ts` is the pure,
key-as-argument core the DO drives, `engine/src/admin/session.ts:119-196`). Key properties:

- **Server-verified MAC, not a bearer secret.** Verification recomputes the MAC over the body
  and compares in CONSTANT time; the body is never parsed unless the MAC matches, so a
  tampered or forged body can never set the email or extend the expiry
  (`engine/src/admin/session.ts:137-196`). The per-request check runs over the in-DO key via a
  DO fetch (`passkeySessionVerify`, `engine/src/sched/scheduler-do-session.ts:345-458`).
- **Email and per-email epoch only; role is never carried.** The signed body holds the
  verified email, a per-email session `epoch`, the issued-at and absolute-expiry timestamps,
  and a format version (`SessionPayload`, `engine/src/admin/session.ts:69-77`). The role is
  ALWAYS re-resolved from the DO role table on each request (keyed on the subject), never
  pinned in the token, so a session can never smuggle an elevated role.
- **Absolute 12-hour TTL.** The session is bounded by an absolute `exp` set once at mint
  (`SESSION_TTL_MS`, `engine/src/admin/session.ts:53`). The absolute expiry is never slid; only
  `lastSeen` is refreshed (the slide re-mint at `engine/src/sched/scheduler-do-session.ts:492-497`
  passes the original `iat` and `exp` back into `signSession`), so a leaked cookie is useless past
  the TTL deterministically. `verifySessionClassified` rejects a token at or past its `exp`
  (`engine/src/admin/session.ts:358`) and a token idle past `SESSION_IDLE_MS` (`:425`). The full
  set of time bounds and their rationale is §2.1a.
- **`__Host-` cookie hardening.** The cookie name is `__Host-downpipes_session`
  (`engine/src/admin/session.ts:44`), and it is set HttpOnly, Secure, SameSite=Strict, Path=/
  with no Domain attribute (`sessionSetCookie`, `engine/src/admin/session.ts:202-205`). The
  `__Host-` prefix is browser-enforced: a browser accepts it only when it is Secure, has
  Path=/ and no Domain, which pins the cookie to this exact host over HTTPS and forbids a
  sibling/parent domain from setting or overriding it (a subdomain cookie-injection/fixation
  defence).

### 2.1a Session lifetime policy and NIST SP 800-63B alignment (ASVS V7.1.1)

The native session carries five time bounds. Each is a named constant in
`engine/src/admin/session.ts`, and each is enforced at the line the table names.

| Bound | Constant | Value | Enforced at |
|-------|----------|-------|-------------|
| Absolute lifetime | `SESSION_TTL_MS` (`engine/src/admin/session.ts:53`) | 12 hours | `exp` is set once at mint (`signSession`, `engine/src/admin/session.ts:229`; the `exp` computation at `:234-239`); `verifySessionClassified` rejects a token at or past `exp` (`engine/src/admin/session.ts:357`). |
| Inactivity timeout | `SESSION_IDLE_MS` (`engine/src/admin/session.ts:59`) | 2 hours | `verifyV3Body` rejects a token whose `lastSeen` is that old (`engine/src/admin/session.ts:437`). Evaluated on every request, independent of the absolute cap. |
| Slide cadence | `SESSION_SLIDE_MS` (`engine/src/admin/session.ts:71`) | 15 minutes | `slideDue` (`engine/src/admin/session.ts:457`); the DO re-mints with the original `iat` and `exp` preserved, moving only `lastSeen` (`engine/src/sched/scheduler-do-session.ts:488-492`). The slide never extends the absolute lifetime. |
| Step-up freshness | `STEPUP_FRESH_MS` (`engine/src/admin/session.ts:84`) | 5 minutes | `stepUpCheck` admits a passkey session whose `iat` is younger than this without a fresh assertion (`engine/src/sched/scheduler-do-stepup.ts:223`). An `oidc` or `saml` session never qualifies. |
| Step-up token | `STEPUP_TOKEN_TTL_MS` (`engine/src/admin/session.ts:90`) | 2 minutes | A minted step-up token is single use and consumed at the check. |

**Comparison with NIST SP 800-63B, revision 4.** Revision 4 states its
reauthentication figures per assurance level: §2.2.3 for AAL2 and §2.3.3 for AAL3. The engine's
bounds compare as follows.

| Level and clause | Revision 4 figure | Engine bound | Result |
|------------------|-------------------|--------------|--------|
| AAL2 overall (2.2.3) | SHOULD be no more than 24 hours | 12 hours | Within the figure |
| AAL2 inactivity (2.2.3) | SHOULD be no more than 1 hour | 2 hours | Deviation |
| AAL3 overall (2.3.3) | SHALL be no more than 12 hours | 12 hours | Within the figure |
| AAL3 inactivity (2.3.3) | SHOULD be no more than 15 minutes | 2 hours | Deviation |

The absolute lifetime meets both levels. The inactivity timeout deviates from both: the 2-hour bound
exceeds the AAL2 figure of 1 hour and the AAL3 figure of 15 minutes. Both inactivity figures are
SHOULD clauses in revision 4, so a documented deviation is the form the standard contemplates.

**Justification for the inactivity deviation.** The console is an administrative backup surface. An
operator watches long-running restores, drills and verification runs from it, and a run of that kind
commonly exceeds one hour with no console interaction. A 1-hour or 15-minute idle bound would force a
repeated WebAuthn ceremony in the middle of an operation whose outcome the operator is waiting on,
and an operator who is re-prompted mid-restore is more likely to keep a second tab active to avoid
the prompt, which defeats the bound's purpose. Two hours is the shortest bound that covers a single
long run without that effect.

**Compensating controls, each stricter than the session model revision 4 assumes.** The idle bound
does not stand alone. The following controls apply to every native session regardless of its age:

- Every owner-reserved sensitive action (`STEPUP_SUBS`, `engine/src/admin/router-core.ts:408`) is
  refused unless the session is a passkey session authenticated within 5 minutes, or the request
  carries a fresh single-use passkey assertion (`engine/src/sched/scheduler-do-stepup.ts:223`). The
  IdP-established sessions never get the recency shortcut. So the actions that matter most are
  re-authenticated on a 5-minute figure, well inside the AAL3 inactivity figure.
- The role is re-resolved from the DO role table on every request and is never carried in the token
  (§2.1), so a demotion or removal takes effect on the next request rather than at session end.
- Epoch revocation kills every session for an identity on its next request: on logout
  (`passkeySessionLogout`, `engine/src/sched/scheduler-do-session.ts:596`), on offboarding
  (`deleteRole`, `engine/src/sched/scheduler-do-rbac-mutations.ts:227`, the epoch bumps at `:272`
  and `:343-344`), and on a factor change (§2.4). The three termination actions in §2.4 end
  sessions on demand.
- The cookie is `__Host-`, `HttpOnly`, `Secure`, `SameSite=Strict` (`sessionSetCookie`,
  `engine/src/admin/session.ts:468-470`), and every mutating cookie-borne request passes the
  strict-Origin CSRF gate (§2.3a), so a session that is idle in an open tab cannot be driven from
  another origin while it waits.

**Assessment.** The combination of a 12-hour absolute lifetime, a 2-hour inactivity timeout, a
5-minute re-authentication figure on sensitive actions, per-request role re-resolution and epoch
revocation is judged appropriate for this surface. The 2-hour idle bound is a deliberate,
documented deviation from the revision 4 SHOULD figures, and the compensating controls bound the
exposure of an idle session to read-only use of a role that is re-checked on every request.

**The Cloudflare Access path.** For an Access caller the engine holds no session of its own (§2.2).
The session lifetime and the inactivity window are set by the operator in the Access application,
and the engine enforces the assertion's `exp` and `nbf` on every request
(`engine/src/admin/access.ts:288-289`). An operator who needs a given assurance level for Access
callers configures the Access session duration and inactivity window to that level's revision 4
figures; the engine cannot read or override those settings.

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
(`engine/src/admin/access.ts:288`). The `now` value is `Math.floor(Date.now() / 1000)` at the
time the request is processed, so a token whose session has expired at the Access layer is
rejected here even if Access did not intercept the request. An `nbf` (not-before) claim, if
present and in the future, is also rejected (`engine/src/admin/access.ts:289`).

For a passkey caller the equivalent control is the absolute `exp` check in `verifySessionClassified`
(`engine/src/admin/session.ts:358`), evaluated over the in-DO key on every request.

The verified Access `exp` is carried through to `GET /admin/whoami` via the `AuthVerdict` type
(`engine/src/admin/identity.ts:445-447`) and surfaced to the console as `sessionExpiresAt`
(`engine/src/admin/router.ts:269`), so the console can display the honest Access session expiry
without re-parsing the token.

### 2.3a CSRF defence for the cookie-borne session

A passkey session is carried in an AMBIENT cookie that a foreign page could ride on a
state-changing request, so every MUTATING (non-GET, non-OPTIONS) request authenticated via the
passkey session MUST also carry an `Origin` that EXACTLY matches `CONSOLE_ORIGIN`. This
strict-Origin check is enforced before any route body read or DO forward
(`engine/src/admin/router.ts:179-184`; `originAllowed`,
`engine/src/admin/session.ts:268-273`). It fails closed on a missing `Origin` or an unset
`CONSOLE_ORIGIN`. It is defence in depth ON TOP of the cookie's `SameSite=Strict`: even a
browser that ignored SameSite, or a future relaxation, could not drive a cross-origin write.
The Access and bare-token methods present an explicit header that a cross-site page cannot set
on a credentialed cross-origin request, so they are not ambient-credential CSRF vectors and
are exempt from this check.

### 2.4 Session termination (the passkey session is revocable)

The passkey session is self-contained yet revocable, via a per-email session epoch plus
signing-key rotation. A monotonic per-email `epoch` counter is stored in the DO
(`SESSION_EPOCH_PREFIX`, `engine/src/sched/scheduler-do-base.ts:2467`); the token carries the
epoch at issue, and `passkeySessionVerify` rejects a token whose epoch is below the email's
current stored value (`engine/src/sched/scheduler-do-session.ts:372-377`). Bumping the epoch
therefore invalidates every session minted before the bump, with no session store to walk.
Single-use logout clears the cookie with the same attributes and `Max-Age=0`
(`sessionClearCookie`, `engine/src/admin/session.ts:231-233`; route `POST /admin/auth/logout`,
`engine/src/admin/router-auth-flow.ts:165`).

The termination capabilities are:

- **View own sessions.** `GET /admin/sessions` (the caller's live sessions, per-session ids, coarse provenance)
- **Terminate one session (self).** `POST /admin/sessions/terminate { sid }` (step-up gated)
- **Terminate other sessions (self).** `POST /admin/sessions/terminate-others` (step-up gated)
  (`engine/src/admin/router.ts:502`) bumps the caller's own epoch and returns a freshly-minted
  token carrying the new epoch, so the current session stays alive while all others die
  (`terminateOwnOtherSessions`, `engine/src/sched/scheduler-do-session.ts:477-514`).
- **Terminate a member's sessions (admin).** `POST /admin/sessions/terminate-user`
  (`engine/src/admin/router.ts:516`) bumps a target email's epoch. Gated on `roles.write`
  re-resolved, and an Owner's sessions may be terminated only BY an Owner
  (`terminateUserSessions`, `engine/src/sched/scheduler-do-session.ts:519-543`).
- **Terminate ALL sessions (owner).** `POST /admin/sessions/terminate-all`
  (`engine/src/admin/router.ts:524`) DELETES the session signing key, so every outstanding
  token fails its next MAC verify and a fresh key is generated on the next issue. Gated on
  `roles.write` re-resolved AND `role === "owner"` (`terminateAllSessions`,
  `engine/src/sched/scheduler-do-session.ts:237-249` (`terminateAllSessions`).
- **Revoke a credential.** `POST /admin/passkey/credentials/delete`
  (`engine/src/admin/router.ts:493`) removes a WebAuthn credential (the theft/loss path) and
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
| V7.1.1 - Session lifetime documented, with 800-63B justification | Documented (§2.1a) | Inactivity timeout 2 hours (`SESSION_IDLE_MS`, `engine/src/admin/session.ts:59`, enforced at `:438`) and absolute lifetime 12 hours (`SESSION_TTL_MS`, `engine/src/admin/session.ts:53`, enforced at `:358`) are stated with their rationale, the compensating controls they combine with, and the justification for the inactivity deviation from NIST SP 800-63B revision 4 (§2.2.3, §2.3.3), all in §2.1a. Customer statement: docs.downpipes.io/identity-access/session-management. |
| V7.1.2 - Concurrent session policy documented | Documented (policy: unbounded, revocable en masse) | Allowed: unlimited. Maximum-reached behaviour: none, a further sign-in is always admitted and never evicts an existing session; the operator reduces the count with terminate-others / terminate-user / terminate-all (§2.4). The V7.4.1 row below carries the mechanism. Customer statement: docs.downpipes.io/identity-access/session-management, "Concurrent sessions". |
| V7.1.3 - Federated session systems and their coordination documented | Documented (§2.7) | The four systems that mint or manage a session (native OIDC/OAuth2 RP, native SAML SP, Cloudflare Access at the engine, Cloudflare Access at the control-plane admin portal) are tabled in §2.7 with lifetime coordination, termination coordination and the conditions that force re-authentication. Two facts an operator needs are stated there: SAML `SessionNotOnOrAfter` caps the native session and OIDC carries no IdP bound; there is no single logout in either direction. |
| V7.2.1 / V7.8.1 - Session invalidation on logout | Engine-enforced (passkey); Access-managed (Access) | `POST /admin/auth/logout` clears the cookie (`engine/src/admin/router-auth-flow.ts:165`); termination routes (section 2.4) revoke server-side via the epoch/key. Access sign-out remains Access's. |
| V7.2.2 - Session creation after re-authentication | Engine-enforced (passkey) | A fresh signed token is minted only after a WebAuthn login (`passkeySessionIssue`, `engine/src/sched/scheduler-do-session.ts:287-296`); the role is re-resolved, never carried. Access creates its own session. |
| V7.3.1 - Session inactivity timeout | Engine-enforced (native session) | A session is rejected after `SESSION_IDLE_MS` (2 hours, `engine/src/admin/session.ts:59`) of no activity (`engine/src/admin/session.ts:438`), independent of the 12h absolute cap. Activity is recorded as `lastSeen` in the signed V3 body and refreshed by a slide re-mint that preserves the original `iat`/`exp` (so it never extends the absolute cap). Access's own inactivity window stays operator-configured. |
| V7.3.2 - Absolute session duration limit | Engine-enforced (native session) | Absolute 12-hour TTL set once at mint (`SESSION_TTL_MS`, `engine/src/admin/session.ts:53`; rejected at `:358`). The idle-slide re-mint refreshes `lastSeen` only; it preserves the original `iat`/`exp`, so the absolute cap is never slid forward. Access duration is operator-configured. |
| V7.4.1 / V7.1.2 - Concurrent session mechanism | Documented (policy: unbounded, revocable en masse) | The native session is stateless (no per-session store), so the engine does NOT cap the NUMBER of concurrent sessions. Allowed: unlimited. Maximum-reached behaviour: none, a further sign-in is always admitted and never evicts an existing session; the operator reduces the count with terminate-others / terminate-user / terminate-all. EVERY session for an identity is revocable at once via the per-email epoch (`engine/src/sched/scheduler-do-session.ts:422`), the per-subject not-before instant (`:419`) and signing-key rotation (section 2.4). A removed member's or a logged-out identity's sessions all die on their next request (the epoch is bumped on offboarding AND logout). Two sessions for one Owner coexisting, and terminate-others keeping the caller's own, is proved at `engine/test/validate-session.ts:783`. Access concurrency, where used, stays operator-configured. |
| V7.4.3 / V7.4.5 - Terminate a user's sessions (admin) | Engine-enforced | `terminate-user` (admin, owner-guarded) and `terminate-all` (owner) bump the epoch / rotate the key (`engine/src/sched/scheduler-do-session.ts:519-543`, `:237-249`). |
| V7.5.2 - View and terminate any or all active sessions (self), having authenticated again | Engine-enforced | Every mint carries a per-session id and writes a `sessionRef` row; `GET /admin/sessions` lists the caller's live sessions with the presenting one flagged (`engine/src/admin/router-account-session.ts`, `listOwnSessions` in `engine/src/sched/scheduler-do-session.ts`); `POST /admin/sessions/terminate { sid }` ends one session by writing `sessionRevoked:<sid>`, consulted at every verify (`terminateOneSession`, `passkeySessionVerify`); `terminate-others` bumps the caller's epoch and re-issues their current session (`terminateOwnOtherSessions`). Both terminations are in `STEPUP_SUBS` (`engine/src/admin/router-core.ts`), so a stale session completes a passkey assertion first. |
| V7.5.1 - Session token properties (length, entropy, unpredictability) | Engine-enforced (passkey) | The session is a server-signed HMAC over a 32-byte CSPRNG key (`engine/src/admin/session.ts:119-124`, `engine/src/sched/scheduler-do-session.ts:162-194`), not a guessable bearer. The Access JWT is RS256, verified not generated. |
| V7.6.1 - RP/IdP session lifetime and termination behave as documented | Engine-enforced and documented (§2.7) | SAML: the native `exp` is `min(now + SESSION_TTL_MS, SessionNotOnOrAfter)` (`engine/src/admin/saml/assertion.ts:277-278` reads the bound, `engine/src/sched/scheduler-do-idp.ts:554-555` passes it, `engine/src/admin/session.ts:238` takes the minimum); a present-but-unreadable bound is read as no bound and recorded as `sso-session-cap-dropped` (`engine/src/admin/saml/assertion.ts:283`). OIDC/OAuth2: no IdP bound is passed (`engine/src/sched/scheduler-do-idp.ts:997`), so the 12-hour cap, the 2-hour idle bound and the revocation axes are the only re-authentication triggers. Access: `verifyAccessJWT` checks `exp` and `nbf` on every request (`engine/src/admin/access.ts:288-289`); the passkey session's absolute `exp` is checked at `engine/src/admin/session.ts:358`. Tests: `engine/test/validate-saml-assertion.ts:268`, `engine/test/validate-cov-sched-scheduler-do-idp.ts:278`. Customer statement: docs.downpipes.io/identity-access/session-management. |

**Authentication strength (ASVS V6.8.4):** the native OIDC/OAuth2/SAML RP reads the IdP's strength claims
(`acr`, `amr`, `auth_time`; SAML `AuthnContextClassRef` and `AuthnInstant`) as a bounded advisory that is
recorded on the `idp-sign-in` audit event and never authorises anything (`engine/src/admin/auth-context.ts`,
`engine/src/admin/oidc.ts:552`, `engine/src/admin/saml/assertion.ts:310`,
`engine/src/sched/scheduler-do-idp.ts:1006`). Because the engine cannot verify which factor the IdP used,
and because the session's `iat` is the engine's own callback instant rather than the IdP's `auth_time`, every
IdP-established session is treated as single-factor, the minimum strength: a step-up-gated action
(`STEPUP_SUBS` in `engine/src/admin/router-core.ts`, passkey self-add, recovery-code regeneration, the
dual-control approvals) is refused for an `oidc` or `saml` session however recently it signed in, and is
admitted only on a fresh UV passkey assertion through the step-up ceremony
(`engine/src/sched/scheduler-do-stepup.ts`, `stepUpCheck`). The recency shortcut applies to `passkey`
sessions only (a UV WebAuthn login, or the recovery-code sign-in, which mints method `passkey`). The one
exception is enrolling a first passkey: an SSO member has nothing to assert with, so `register/finish` passes
the `enrol-passkey` purpose and a fresh IdP sign-in is accepted for that route alone. An operator who needs a
specific factor at the IdP (for example MFA for every sign-in) configures that policy at the IdP; the engine
does not depend on it. `engine/test/validate-session.ts` (section 4d) and `engine/test/validate-idp-wiring.ts`
(section 4b, an `id_token` carrying `acr: urn:mfa` that is still step-up-blocked) carry the vectors.

**Operator configuration (Access only):** where Cloudflare Access is used, the operator should
still set an explicit Access session duration and inactivity window, enable concurrent-session
enforcement if policy requires it, and configure the Access revocation behaviour. The engine
cannot verify these Access-side settings; failure to set them leaves the corresponding
Access-managed controls unmet for Access callers. An account running the engine's own passkeys
needs none of this (the controls above are engine-enforced).

### 2.6 Contextual attributes and adaptive controls (ASVS V8.1.3, V8.1.4, V8.2.4)

ASVS V8.1.3 asks the application to document the environmental and contextual attributes it uses to
make security decisions. V8.1.4 asks that documentation to define how those factors are used: the
attributes evaluated, the thresholds, and the actions taken. V8.2.4 asks that adaptive controls based
on those attributes apply both when a session is created and during an existing session. This section
is that documentation. The gate `engine/test/validate-contextual-authz-docs-parity.ts` resolves every
citation below against the tree on each run and renders each threshold from the exported constant.

A note on custody first, because it is the usual point of confusion: the engine runs in the
CUSTOMER's own Cloudflare account. Any contextual attribute it observes (a source IP, a connection
identity) is seen and, where retained, stored inside the customer's own account. None of it reaches
the vendor. No-custody is a statement about what the VENDOR holds, so using contextual attributes
for the customer's own operators does not bear on it.

The contextual attributes the engine evaluates for authentication and authorization decisions are:

- **Temporal context (inactivity and absolute age).** Every request re-evaluates the session's idle
  instant (`lastSeen`) against `SESSION_IDLE_MS` (2 h, `engine/src/admin/session.ts:59`; the check is
  `engine/src/admin/session.ts:437`) and its absolute expiry against `SESSION_TTL_MS` (12 h,
  `engine/src/admin/session.ts:53`; a token at or past its expiry is rejected as `session-fault-expired`,
  `engine/src/admin/session.ts:357`). Inactivity is a contextual signal applied continuously during a
  session, not only at sign-in.
- **Connection identity.** The signed V3 session body carries the authentication method, the stable
  subject and, for an IdP session, the `connId` of the connection that established it
  (`engine/src/admin/session.ts:128`; bound at mint, `engine/src/admin/session.ts:245`). The DO checks
  the session against the per-connection epoch axis on every request (section 2.4).
- **Request origin.** Every mutating cookie-session request must present an `Origin` header that
  exactly matches `CONSOLE_ORIGIN`, enforced before any body read (`originFailClass`,
  `engine/src/admin/router.ts:462-465`; `originAllowed`, `engine/src/admin/session.ts:515`). Section 2.3a
  describes the check.
- **Subject continuity.** The caller's role is RE-RESOLVED from the immutable subject on every
  request (never carried in the token), and the session is checked against three revocation axes
  (per-email epoch, per-subject not-before, signing-key generation; section 2.4). A change in the
  subject's authority or standing takes effect on the next request.
- **Action sensitivity.** A POST whose route is in `STEPUP_SUBS` (`engine/src/admin/router-core.ts:408`)
  passes `requireStepUp` (`engine/src/admin/router-core.ts:549`) before it is dispatched
  (`engine/src/admin/router.ts:573-577`). Three further legs call `requireStepUp` directly because a
  static route string cannot match them: the config-change approve leg (`engine/src/admin/router.ts:618`),
  the owner-action approve leg (`engine/src/admin/router.ts:665`) and the restore apply leg
  (`engine/src/admin/router-restore.ts:263`). The control adapts to the risk of the operation.
- **Source network address.** The router reads the edge-injected `CF-Connecting-IP` header and the
  engine uses it in five ways, each a row of the decision table below: the per-IP throttle on the
  unauthenticated sign-in ceremonies (the `ip:` namespace; `authRateLimited`,
  `engine/src/admin/router-core.ts:612`); the per-IP and per-email throttle on the recovery-code sign-in
  (the `recovery-rate:` namespace; `recoveryRateAllow`, `engine/src/sched/scheduler-do-recovery.ts:514`);
  the per-IP throttle on the bare `ADMIN_TOKEN` compare (the `admin-token-ip:` namespace;
  `adminTokenRateLimitedViaDO`, `engine/src/admin/router-session.ts:335`); the opt-in
  sign-in-new-context notification, which compares a coarse prefix of the address against the
  operator's seen-set when the `notifyNewSignInContext` policy is on (`getNotifyNewSignInContext`,
  `engine/src/sched/scheduler-do-org-policy.ts:123`); and audit provenance, where `sourceIp` is recorded
  on every authentication event as non-authority metadata (`engine/src/admin/identity.ts:115`). The
  source IP is never an authentication or authorisation input and never a sole authorization factor
  (ASVS V8.4.2): no gate reads it to decide a role or a capability. The authenticated per-caller
  throttle is keyed in the `sub:` namespace on the verified subject, not on the address.
- **Attributes not evaluated.** Time of day, geographic location, IP reputation, and device identity or
  posture are not evaluated anywhere in the engine. No control reads them, so no threshold exists for
  them.

#### Contextual decision table

One row per factor. The threshold column renders the exported constant, and the parity gate re-renders
each value from the code on every run. The action set is allow, deny, step-up challenge and notify.
There is no silent risk score: every decision is one of those four, and each is observable to the
caller or, for notify, to the operator.

| Attribute | Where evaluated | Threshold | Action |
|-----------|-----------------|-----------|--------|
| Session absolute age | `verifySessionClassified`, `engine/src/admin/session.ts:357`, on every cookie-session request | the token's expiry is the mint instant plus `SESSION_TTL_MS` (12 h, `engine/src/admin/session.ts:53`); the idle slide never moves it | deny: `session-fault-expired`, answered 401 `unauthorised` (`engine/src/admin/router.ts:378`); the operator signs in again |
| Session inactivity | `verifySessionClassified`, `engine/src/admin/session.ts:437`, on every cookie-session request | `lastSeen` older than `SESSION_IDLE_MS` (2 h, `engine/src/admin/session.ts:59`) | deny: `session-fault-idle`, answered 401 `unauthorised` (`engine/src/admin/router.ts:378`); the operator signs in again |
| Action sensitivity | `requireStepUp` (`engine/src/admin/router-core.ts:549`), gated once before the main switch (`engine/src/admin/router.ts:573-577`) and directly on the three dynamic legs named above | the route is in `STEPUP_SUBS` (43 routes, `engine/src/admin/router-core.ts:408`) and the caller holds no passkey proof fresher than `STEPUP_FRESH_MS` (5 min, `engine/src/admin/session.ts:84`) and presents no single-use step-up token, which lives `STEPUP_TOKEN_TTL_MS` (2 min, `engine/src/admin/session.ts:90`); an Access caller is judged on the assertion's issued-at against the same 5 min; an OIDC or SAML session must assert a passkey (section 2.5) | challenge: 401 with `stepUpRequired` true in the body (`engine/src/admin/router-core.ts:590`; with `reauth: "access"` for an Access caller, `engine/src/admin/router-core.ts:555`); the bare token is exempt; fails closed when the DO check is unavailable (`stepup-check-unavailable`, `engine/src/admin/router-core.ts:588`) |
| Source IP on the sign-in ceremonies (`/admin/auth/*`, `/admin/oidc/*`, `/admin/saml/*`, all unauthenticated) | `authRateLimited` (`engine/src/admin/router-core.ts:624`), keyed `ip:<CF-Connecting-IP>` with the cap `AUTH_RATE_LIMIT_MAX_PER_WINDOW` (`engine/src/admin/router-core.ts:624`), counted by the DO `rateCheck` (`engine/src/sched/scheduler-do.ts:801`) | more than `AUTH_RATE_LIMIT_MAX_PER_WINDOW` requests in one `RATE_LIMIT_WINDOW_MS` window: 30 per 60 s (`engine/src/sched/scheduler-do-limits.ts:664`; window `engine/src/sched/scheduler-do-limits.ts:643`) | deny: 429 with `Retry-After` (`rateLimitedResponse`, `engine/src/admin/router-core.ts:274`); fails closed: only `allowed === true` admits (`engine/src/admin/router-core.ts:632`) and a limiter outage also answers 429 (`engine/src/admin/router-core.ts:661`) |
| Source IP and target email on the recovery-code sign-in (`POST /admin/auth/recovery`) | `recoveryRecover` derives `emailKey` and `ipKey` (`engine/src/sched/scheduler-do-recovery.ts:361-362`); `recoveryRateAllow` checks both (`engine/src/sched/scheduler-do-recovery.ts:514`) under the `RECOVERY_RATE_PREFIX` storage prefix `recovery-rate:` (`engine/src/sched/scheduler-do-limits.ts:731`) | `RECOVERY_RATE_MAX_PER_IP`: 5 per 60 s per IP, and `RECOVERY_RATE_MAX_PER_EMAIL`: 5 per 60 s per email (`engine/src/sched/scheduler-do-limits.ts:733-734`); both buckets must admit | deny: one generic 401 `unauthorised` with no `Retry-After` (`engine/src/admin/router-auth-flow.ts:78`), so no oracle separates a throttle from a wrong code; fails closed on a limiter fault (`recovery-limiter-unavailable`, `engine/src/sched/scheduler-do-recovery.ts:548-551`); the ceremony also passes the per-IP sign-in throttle above first |
| Source IP on the break-glass bearer (`ADMIN_TOKEN` compare) | `adminTokenRateLimitedViaDO` (`engine/src/admin/router-session.ts:335`), keyed `admin-token-ip:<CF-Connecting-IP>` with the cap `ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW` (`engine/src/admin/router-session.ts:341`), consulted inside `authorise` before the token compare | more than `ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW` attempts in one window: 10 per 60 s (`engine/src/sched/scheduler-do-limits.ts:673`) | deny: 429 with `Retry-After` set to the full window (`adminTokenThrottledResponse`, `engine/src/admin/router-core.ts:298`; answered at `engine/src/admin/router.ts:356`); fails closed on a limiter fault (`admin-token-ratelimited-unavailable`, `engine/src/admin/router-session.ts:367-375`) |
| Verified caller identity on a mutating route | `rateLimited` (`engine/src/admin/router-core.ts:303`) after the route reads its body; keyed in the `sub:` namespace by `rateLimitKey`, with the bare token sharing one `token` bucket (`engine/src/admin/router-core.ts:218-219`) | more than `RATE_LIMIT_MAX_PER_WINDOW` mutating requests in one window: 120 per 60 s (`engine/src/sched/scheduler-do-limits.ts:656`) | deny: 429 with `Retry-After` (`rateLimitedResponse`, `engine/src/admin/router-core.ts:274`); fail open: a malformed verdict or an unavailable limiter admits the request and records `limiter-verdict-malformed` (`engine/src/admin/router-core.ts:322`, `engine/src/admin/router-core.ts:341`) |
| Request Origin on a mutating cookie-session request | `originFailClass` against `CONSOLE_ORIGIN` before any body read (`engine/src/admin/router.ts:462-465`) | the `Origin` header is absent, or differs from `CONSOLE_ORIGIN`, or `CONSOLE_ORIGIN` is unset | deny: 403 `csrf origin check failed` (`engine/src/admin/router.ts:480`); Access and bearer callers are exempt because they present an explicit header a cross-site page cannot set |
| Absent `CF-Connecting-IP` on the sign-in ceremonies and the bearer compare | `authRateLimited` (`engine/src/admin/router-core.ts:612-620`) and `adminTokenRateLimitedViaDO` (`engine/src/admin/router-session.ts:337-338`) | the header is missing or empty | allow, with no throttle bucket. On the custom-domain-only deployment the Cloudflare edge always injects `CF-Connecting-IP` (overwriting any client value), and the engine rejects `workers.dev`, so a real edge request can never lack it. Its absence means a non-edge or local context (a validator), not a stripped header. Failing closed here would buy zero production security while bucketing every header-less local caller into one shared key. This is the V2.4.1 / V8.1.4 accept decision |
| Source IP prefix on a proven sign-in (R6, opt-in) | `recordSignInContext` (`engine/src/sched/scheduler-do-session.ts:270`), reached through `POST /signin-context` (`engine/src/sched/scheduler-do-routing-identity.ts:41`) from `fireSignInContextCheck` after a passkey login (`engine/src/admin/router-auth-flow.ts:682`), and inside the DO success block for an OIDC or SAML login; only when `getNotifyNewSignInContext` is true (`engine/src/sched/scheduler-do-org-policy.ts:123`) | `coarseSignInPrefix` reduces the address to an IPv4 /24 or IPv6 /48 prefix (`engine/src/admin/sign-in-context.ts:41`); the prefix is absent from the operator's seen-set, which `evaluateSignInContext` (`engine/src/admin/sign-in-context.ts:105`) prunes to `SEEN_CONTEXT_TTL_MS` (90 days, `engine/src/admin/sign-in-context.ts:28`) and caps at `SEEN_CONTEXT_CAP` (10 prefixes, `engine/src/admin/sign-in-context.ts:20`) | notify only: the `sign-in-new-context` alert, which carries no address; the sign-in is never delayed or refused; the raw IP is used in memory to derive the prefix and is never stored |

The step-up gated routes in `STEPUP_SUBS` are: `/restore/approve`, `/keys/install`, `/keys/rotate`,
`/keys/add-operational`, `/keys/break-glass-only`, `/posture/accept`, `/posture/unaccept`,
`/destination`, `/destinations`, `/destinations/remove`, `/destinations/default`, `/push`,
`/push/delete`, `/push/test`, `/otlp-push`, `/otlp-push/delete`, `/idp/connections`,
`/idp/connections/delete`, `/idp/connections/enabled`, `/idp/connections/cert`, `/roles`,
`/roles/delete`, `/group-roles`, `/group-roles/delete`, `/custom-roles`, `/custom-roles/delete`,
`/policy/retire-break-glass-token`, `/passkey/credentials/delete`, `/signin-factors/revoke`,
`/notify/rules`, `/notify/rules/delete`, `/config/signin-context-policy`, `/notify/channels`,
`/notify/channels/delete`, `/attest/session/create`, `/retention-prune/apply`,
`/retention-prune/approve`, `/support/credentials`, `/sessions/terminate-user`,
`/sessions/terminate-all`, `/sessions/terminate-others`, `/sessions/terminate` and `/custody/send-share`. The parity gate lists the set from the code and
fails when this paragraph and the set differ in either direction.

Adaptive controls applied AT SESSION START: WebAuthn user verification is mandatory (a registration
or an assertion whose UV flag is clear is rejected as `user_verified`, `engine/src/admin/passkey.ts:273`
and `engine/src/admin/passkey.ts:348`), the connection identity is bound into the signed body, the
strict-Origin check gates the establishing request, the per-IP throttle bounds the ceremony, and the
opt-in sign-in-new-context check compares the coarse network prefix against the operator's baseline.

Adaptive controls applied DURING AN EXISTING SESSION: the inactivity timeout, the absolute expiry,
the per-request role re-resolution and the revocation-axis checks, the strict-Origin check on every
mutating request, the per-caller throttle on every mutating request, and step-up re-authentication
whenever the requested action is sensitive.

Scope. The engine evaluates no geolocation, IP-reputation, time-of-day or device-posture attribute,
and it never blocks an authenticated request on its source address. The source IP serves the
throttles and the notification tabled above and audit provenance. A blocking control on location or
reputation would need a per-operator behavioural baseline or an endpoint agent, and the platform does
not build either. Network location is never a SOLE authorization factor (ASVS V8.4.2): authority
always rests on the re-resolved role and the cryptographic session, never on where the request came
from.

### 2.7 Federated session coordination (ASVS V7.1.3)

Four systems create or manage a session for this product. Each row states who mints the session,
how its lifetime is coordinated with the identity provider, how it is terminated, and what forces
re-authentication. The constants are the ones in §2.1a.

| System | Who mints the session | Lifetime coordination | Termination coordination | Re-authentication conditions |
|--------|-----------------------|-----------------------|--------------------------|------------------------------|
| Native SAML SP (`/admin/saml/*`) | The engine, after the assertion consumer verifies the signed assertion (`nativeSessionIssue`, `engine/src/sched/scheduler-do-idp.ts:443`). | `exp = min(now + SESSION_TTL_MS, AuthnStatement/@SessionNotOnOrAfter)`. The bound is read off the signature-verified assertion (`engine/src/admin/saml/assertion.ts:277-278`), threaded through the ACS (`engine/src/sched/scheduler-do-idp-saml.ts:236`), passed to the mint (`engine/src/sched/scheduler-do-idp.ts:554-555`) and applied in `signSession` (`engine/src/admin/session.ts:229`, the minimum at `:230`). A bound that is present but does not parse is read as no bound and counted as `sso-session-cap-dropped` (`engine/src/admin/saml/assertion.ts:283`, `engine/src/admin/saml-signals.ts:64`). An absent bound leaves the 12-hour cap. | Per-email epoch, per-subject not-before, per-connection `idpEpoch` and verify-time connection liveness (`engine/src/sched/scheduler-do-session.ts:422`, `:419`, `:426`, `:442`). Disabling or deleting the connection stamps its `idpEpoch` (`idpConnSetEnabled`, `engine/src/sched/scheduler-do-idp.ts:752`, stamping at `:763`; `idpConnDelete`, `engine/src/sched/scheduler-do-idp.ts:722`, stamping at `:733`). No single logout in either direction. | The 12-hour cap, the SAML bound, the 2-hour idle bound, any revocation axis, `session-fault-upgrade-reauth` after a token-shape change, and step-up for the `STEPUP_SUBS` set on every request (an IdP session never gets the 5-minute recency shortcut). |
| Native OIDC/OAuth2 RP (`/admin/oidc/*`) | The engine, after the callback verifies the token exchange (`nativeSessionIssue`, `engine/src/sched/scheduler-do-idp.ts:443`). | Not capped at the IdP session or the `id_token` expiry. The OIDC callback passes no bound (`engine/src/sched/scheduler-do-idp.ts:1012`), so the native session runs to the 12-hour cap or the 2-hour idle bound whatever the IdP's own session does. The engine consumes no OIDC session-management or back-channel logout message. | The same four axes as SAML. No single logout in either direction. | The 12-hour cap, the 2-hour idle bound, any revocation axis, `session-fault-upgrade-reauth`, and step-up for the `STEPUP_SUBS` set on every request. |
| Cloudflare Access in front of the engine | Cloudflare Access; the engine holds no session of its own for an Access caller (§2.2). | Access owns lifetime and inactivity, both operator-configured. The engine enforces the assertion's `exp` and `nbf` on every request (`engine/src/admin/access.ts:288-289`). | Access-side sign-out at `/cdn-cgi/access/logout`; the engine's termination actions do not reach an Access session, and an Access sign-out does not touch a native session. | Whatever the Access application requires; the engine's step-up gate exempts Access and bare-token callers. |
| Cloudflare Access in front of the control-plane admin portal | Cloudflare Access, with the portal Worker layering its own checks on top (`control-plane/SECURITY.md:150-160`). | Access session duration 24 hours; a 30-minute idle timeout in the Worker (`PORTAL_IDLE_MS`, `control-plane/DEPLOY-RUNBOOK.md:169-175`). | An idle request is refused and redirected through `/cdn-cgi/access/logout` (`control-plane/DEPLOY-RUNBOOK.md:172`); a revoke marker covers same-day offboarding (`control-plane/SECURITY.md:150-160`). | The Access duration, the idle timeout, and a 5-minute assertion-freshness requirement before the highest-impact actions (`control-plane/SECURITY.md:150-160`). |

**No single logout.** Neither native front door implements single logout. An IdP-side sign-out
does not end an engine session: the session lives until the 12-hour cap, the SAML bound, the 2-hour
idle bound, or a revocation axis catches it, and a deprovision at the IdP takes effect on the next
request only through the per-request group snapshot re-read (§2.5 V6.8.4 note) or a termination
action. An engine logout does not end the IdP session. Offboarding a member who signs in through an
IdP is therefore two acts: deprovision at the IdP, and terminate at the engine (§2.4). The
customer-facing statement of the same rule is docs.downpipes.io/identity-access/session-management.

**Re-authentication conditions, in one place.** A native session must be re-established when any
of the following holds: the absolute lifetime is reached (`SESSION_TTL_MS`, 12 hours); the SAML
`SessionNotOnOrAfter` bound is reached; the session has been idle for `SESSION_IDLE_MS` (2 hours);
any revocation axis rejects it (email epoch, subject not-before, connection `idpEpoch`, connection
liveness, signing-key rotation); or the token predates a token-shape change
(`session-fault-upgrade-reauth`, `engine/src/admin/session.ts:290`). Independently of the session's
age, a sensitive action in `STEPUP_SUBS` requires a passkey session younger than `STEPUP_FRESH_MS`
(5 minutes) or a fresh single-use passkey assertion; Access and bare-token callers are exempt from
the step-up gate.

---

## 3. File handling (ASVS V5.1.1)

The file-handling policy is `engine/docs/security/file-handling.md`. It enumerates every feature that
accepts a file (the console's identity.key, share and encrypted-key pickers, the pasted estate export, the
CLI's key and custody inputs, and the archive-read paths on the engine and the CLI), and states for each
the permitted type, extension and accept filter, the maximum size including the unpacked size, how a
download is made safe to open, and what the surface does with a malformed, oversized or malicious file.
`engine/test/validate-file-handling-doc.ts` keeps that document and the trees it cites in agreement.

---

## 3a. Factor-loss re-proofing (ASVS V6.4.4)

ASVS V6.4.4 asks that when a multi-factor authentication factor is lost, identity proofing is
performed at the same level as at enrolment. The engine's own passkey front door meets this
through the recovery code, not through either credential this codebase also calls
"break-glass" (see the closing note below).

**The recovery code is minted at enrolment, not issued as a lesser fallback.** A completed
passkey registration mints a fresh recovery-code set for that email in the SAME call that
resolves the role, before the response is returned (`passkeyRegisterFinish`,
`engine/src/sched/scheduler-do-passkey.ts:400`, the recovery-code mint at `:564-588`). Each code carries 150 bits of CSPRNG
entropy (six hyphen-joined groups of five characters over a 32-symbol alphabet:
`RECOVERY_CODE_GROUPS` and `RECOVERY_CODE_GROUP_LEN`, `engine/src/admin/recovery.ts:46-47`;
the alphabet, `engine/src/admin/recovery.ts:52`), which clears the ASVS V6.5.2 / V11.5.1
112-bit lookup-secret floor (`engine/src/admin/recovery.ts:41-42`). Only a per-code salted
HMAC-SHA-256 of a code is ever stored; the plaintext is returned once, at generation, and
never stored, logged or shown again (`RecoveryCodeHash`, `engine/src/admin/recovery.ts:67-71`;
`hashOf`, `engine/src/admin/recovery.ts:201-209`). A code is single use: `verifyCode` marks
exactly the matched code consumed and a consumed slot can never match again
(`engine/src/admin/recovery.ts:308-352`, the consumed check at `:347`), walking the whole
unconsumed set in constant time so neither a match position nor a wrong-code timing signature
leaks (`constantTimeEqual`, `engine/src/admin/recovery.ts:343`).

Presenting a code to `POST /admin/auth/recovery` is fail-closed rate-limited per IP and per
email before any record is read (`recoveryRateAllow`,
`engine/src/sched/scheduler-do-recovery.ts:371`), and an unknown email is verified against a
synthetic dummy record so a known and an unknown email cost the same work
(`dummyRecoveryRecord`, `engine/src/sched/scheduler-do-recovery.ts:409`). A wrong code, an
unknown email, an exhausted set and a throttle denial all answer the same generic failure
(`engine/src/sched/scheduler-do-recovery.ts:419`, `:456`); a rejected attempt is audited with
no actor named, because no identity is verified on a failure
(`engine/src/sched/scheduler-do-recovery.ts:448-455`), and a successful recovery is audited
under the recovered email (`engine/src/sched/scheduler-do-recovery.ts:480-487`).

**A recovered session carries exactly the identity's existing authority, never a fresh
grant.** A successful `recoveryRecover` resolves the role through the same `resolveBoundEntry`
path every other sign-in uses, keyed on `passkeySubject(email)`, and mints a passkey-class
session at that role (`engine/src/sched/scheduler-do-recovery.ts:467-476`). An email that is no
longer on the roster but still holds an unconsumed code signs in to `viewer`, exactly as any
other unbound identity would (`engine/src/sched/scheduler-do-recovery.ts:499-505`); recovery
grants no authority the roster does not already confer.

**Re-enrolling a passkey after recovery passes the same live roster gate a fresh enrolment
does.** The recovered session is deliberately indistinguishable from an ordinary passkey
session, so a fresh credential is bound to it through the same door every self-add passes
through: `resolveRegistrationAuthorisation` requires the session's proven email to equal the
email being registered and, for the passkey method, re-reads the roster at the moment of the
ceremony, refusing when a populated roster no longer accounts for the address
(`engine/src/sched/scheduler-do-passkey.ts:259-296`, the roster check at `:288-292`). This is
the same roster re-check the invite arm applies to a brand-new enrolment
(`engine/src/sched/scheduler-do-passkey.ts:249-253`), so a role removed between the recovery
sign-in and the re-enrolment attempt closes the door exactly as it would for a first-time
invite. Regenerating the code set at this point is staged, not immediate: the fresh plaintext
is shown before the just-spent set is invalidated, and the live set is replaced only once the
operator confirms the new codes are saved (`generateRecoveryStaged`,
`engine/src/sched/scheduler-do-recovery.ts:213`; `confirmRecoveryStaged`,
`engine/src/sched/scheduler-do-recovery.ts:238`; invoked from the enrolment hook,
`engine/src/sched/scheduler-do-passkey.ts:579-588`), so a crashed browser mid-ceremony cannot
strand the operator with zero factors.

**What this is not.** Two other credentials in this codebase are also named "break-glass", and
neither is part of this re-proofing path. The `ADMIN_TOKEN` bearer is a one-time,
all-or-nothing bootstrap credential for standing up the first Owner (section 1.6); it carries
no email and cannot be presented as a specific enrolled identity, so it has no re-proofing role
for an existing member. The offline "break-glass key" (`BREAK_GLASS_PUBLIC`,
`engine/src/admin/status.ts:405`) is a capsule-recipient public key for decrypting backup DATA
offline (`loadRecipients`, `engine/src/keys-env.ts:65-66`; `engine/src/crypto/capsule.ts:78-80`);
it authenticates nobody and is never read on any admin sign-in or enrolment path. The recovery
code documented above is the whole of the engine's factor-loss re-proofing.

**Assessment.** MET. The recovery code is a 150-bit secret issued at the same ceremony as the
passkey it backs up, consumed once under the same rate-limit and no-oracle discipline the rest
of the sign-in surface uses, and it can re-enrol a replacement passkey only through the
identical live roster check a fresh invite passes through. Factor loss lowers no bar an
attacker must clear and grants no authority the roster does not already confer.

---

## 4. ASVS mapping summary

| ASVS control | Section above | Status |
|--------------|---------------|--------|
| V6.3.3 - Multi-factor / phishing-resistant authentication | 1.1, 2.5 | MET: first-party WebAuthn passkeys, user verification mandatory (`passkey.ts:253`, `:328`). |
| V6.5.x - Recovery / lookup-secret factor | 2.5 | MET: single-use, salted-hash recovery codes (`recovery.ts:57-61`). |
| V6.4.4 - Re-proofing at factor loss | 3a | MET: recovery-code sign-in re-proofs through the same live roster gate a fresh enrolment uses and grants only the identity's existing role; passkey re-enrolment after recovery is refused unless the roster still accounts for the email (`scheduler-do-passkey.ts:288-292`). |
| V10.3.3 - Identity-provider group/role binding | 1.4 | MET: additive group-to-role mapping, capped below owner, enforced in the scheduler DO (`engine/src/sched/scheduler-do-rbac-mutations.ts:41-198`, `setRole`). |
| V10.5.2 - Stable, unique identity key (iss+sub) | 1.2, 1.4 | MET: authority keys on the immutable subject (`role:sub:<subject>`, `identity.ts:258-261`); email is display/audit only and a recycled email cannot inherit a role (`engine/src/sched/scheduler-do-rbac-authority.ts:54-96`, `roleForCaller`). |
| V7.1.1 - Session lifetime documented, with 800-63B justification | 2.1a | MET: 12-hour absolute lifetime and 2-hour inactivity timeout stated with rationale and compensating controls; the inactivity deviation from NIST SP 800-63B revision 4 (§2.2.3, §2.3.3) is justified in §2.1a. |
| V7.1.2 - Concurrent session policy documented | 2.5 | MET: unlimited concurrent sessions, no maximum-reached behaviour, count reduced only by a termination action. |
| V7.1.3 - Federated session systems and coordination documented | 2.7 | MET: the four session-minting systems, their lifetime and termination coordination, and the re-authentication conditions are tabled in §2.7. |
| V7.2.2 / V7.3.2 / V7.5.1 - Session lifecycle | 2.1, 2.3, 2.5 | MET (passkey session): server-verified `__Host-` cookie, absolute 12h TTL, expiry checked each request (`session.ts:53`, `:334`). Access session controls remain Access-managed. |
| V7.6.1 - RP/IdP session lifetime and termination behave as documented | 2.5, 2.7 | PARTIAL: SAML sessions are capped at `SessionNotOnOrAfter` (`saml/assertion.ts:277-278`, `session.ts:238`), meeting the requirement for the SAML half. OIDC sessions carry no IdP bound (`scheduler-do-idp.ts:1012` passes none; the comment at `scheduler-do-idp.ts:460-463` records id_token-exp capping as a recorded, unbuilt follow-up), so an OIDC-federated session runs to the flat 12-hour cap regardless of a shorter upstream bound, with no re-authentication forced when that bound is reached. Both facts are stated on the customer session-management page. Accepted with reason pending the fix: thread the id_token `exp` into `nativeSessionIssue` the way the SAML ACS already does. |
| V7.4.3 / V7.4.5 - Terminate a user's sessions (admin) | 2.4 | MET: `terminate-user` / `terminate-all` bump the epoch / rotate the key (`engine/src/sched/scheduler-do-session.ts:519-543`, `:237-249`). |
| V7.5.2 - View and terminate any or all active sessions (self), having authenticated again | 2.4 | MET: `GET /admin/sessions` lists the caller's live sessions by per-session id; `POST /admin/sessions/terminate` ends one and `terminate-others` ends the rest, both step-up gated (`engine/src/admin/router-account-session.ts`, `engine/src/sched/scheduler-do-session.ts`, `STEPUP_SUBS` in `engine/src/admin/router-core.ts`). |
| V8.1.3 - Documented contextual attributes for security decisions | 2.6 | MET: the attributes evaluated (session age and inactivity, connection identity, request origin, subject continuity, action sensitivity, source IP) and the attributes not evaluated (time of day, location, IP reputation, device) are defined in section 2.6, with a `file:line` for each use. |
| V8.1.4 - Attributes, thresholds and actions for contextual decisions | 2.6 | MET: the contextual decision table in section 2.6 states, per factor, where it is evaluated, the threshold rendered from the exported constant, and the action taken (allow, deny, step-up challenge, notify). `engine/test/validate-contextual-authz-docs-parity.ts` holds the table to the code. |
| V8.2.4 - Adaptive controls at session start and during the session | 2.6 | MET: adaptive controls are applied at both points as documented in section 2.6 (user verification, connection and origin binding at start; inactivity timeout, per-request role re-resolution, revocation-axis and origin checks, and risk-based step-up during the session). Contextual binding runs in the customer's own account, so it carries no vendor-custody implication. |
| V5.1.1 - Documented file types, extensions, maximum and unpacked sizes, and safe download and processing for each file-accepting feature | 3 | MET: `engine/docs/security/file-handling.md` sections 2 to 5, kept in agreement with the cited trees by `engine/test/validate-file-handling-doc.ts`. |
