# Identity, sessions and file handling

**Standard:** OWASP ASVS 5.0 - V10.3.3, V10.5.2 (identity), V6.x (first-party MFA), V7.x (session lifecycle), V5.1.1 (file handling).
**Scope:** Downpipes engine (TypeScript, Cloudflare Workers) and the offline `downpipe` CLI reader (Go).


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
native external identity provider - OIDC or OAuth2 (acting as a relying party, with ten connection
presets in `oidc-presets.ts`), or a from-scratch SAML SP. All of them mint the SAME signed V3 session cookie (carrying the
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
hour), issuer match, audience match against the configured AUD tag, and expiry check. The verification is in `engine/src/admin/access.ts:393-415` (`verifyAccessJWT`), with the claim checks at `:260-300`. Only after that
full verification do the token's email claim AND its stable subject become a trusted
identity; an Access verdict requires BOTH a verified email and a verified subject, and a
present-but-invalid assertion returns `{ ok: false }` and is never downgraded
(`engine/src/admin/auth.ts:177`, `:189`, `:202`).

As a defence against a misconfigured `CF_ACCESS_TEAM_DOMAIN` being used to redirect the JWKS
fetch to an attacker-controlled host, `assertCloudflareAccessHost` enforces that the resolved
team domain is a single-label `*.cloudflareaccess.com` subdomain before any fetch is made
(`engine/src/admin/access.ts:217-230`).

**First-party passkeys (the engine's own identity provider).** The engine is its own
identity provider: it implements WebAuthn registration and login directly (`passkey.ts` is
the pure verifier core, the scheduler DO is the storage authority, the router exposes the
`/admin/auth/*` ceremonies). A successful passkey login yields a signed session cookie that
authenticates subsequent requests (section 2). This is the free, self-hosted multi-user
front door for accounts that do not run Cloudflare Access (which is not free over 50 users).
User verification is MANDATORY: a registration whose user-verified (UV) flag is clear is
rejected (`engine/src/admin/passkey.ts:278`), and so is a login assertion whose UV flag is
clear (`engine/src/admin/passkey.ts:353`), so a bare presence touch alone is never accepted
for this privileged sign-in. A passkey caller carries the credential's bound, verified
email and resolves its role from the SAME subject-keyed role table the Access path uses.

**`ADMIN_TOKEN` bearer (break-glass).** The shared `ADMIN_TOKEN` secret is a
lower-assurance break-glass that carries no email and resolves to the `owner` role
unconditionally. The bare bearer has no expiry. The console exchanges it once at
`POST /admin/session/bootstrap` for a signed session of method `token`, which carries the §2.1a
bounds. It claims the first Owner. It has no expiry or use count, so it stays valid until an Owner retires
it or the secret is deleted or rotated. It skips step-up. An operator may disable it entirely by setting
`ADMIN_TOKEN_DISABLED=true`, after which only a verified Access JWT or a valid passkey, OIDC or SAML session is accepted
(`engine/src/admin/auth.ts:314`, and `:261` for an exchanged token session); the token can also be retired in-app
once a way back in exists: working Owner recovery codes or a second Owner (section 1.6).

### 1.2 Authority keyed on the immutable subject

Authorisation keys on the caller's STABLE, immutable subject, not the mutable email. The
subject is the load-bearing identity attribute: it is the storage key for the RBAC role
table in the scheduler Durable Object (`role:sub:<subject>`, section 1.4) and the axis of
the maker-not-checker comparison in the dual-control approval flow (section 1.4). The email
is retained for DISPLAY and AUDIT only: the console shows it, the audit records it, and it
is the key of a pending invite and of the per-email-and-source recovery-code throttle, but it never
decides a role lookup.

The subject is shaped at the trust boundary, distinctly per method:

- For an Access caller it is `iss + "|" + sub`, both read only from the RS256-verified
  payload: `sub` is Cloudflare Access's immutable opaque user id, and the team issuer is
  folded in so two tenants' subs can never collide
  (`boundSubject`, `engine/src/admin/access.ts:350-358`). A validly-signed assertion with no
  usable `sub` yields no subject and is rejected exactly as an emailless one is
  (`engine/src/admin/auth.ts:202`).
- For a passkey caller it is `passkey|<canonical-email>`, derived from the credential's
  bound email by `passkeySubject` (`engine/src/admin/identity.ts:234-236`). Because the
  engine issues its own passkey credentials bound at registration, the email is an
  immutable principal for that credential, not a recyclable external identifier. The
  `passkey|` namespace is disjoint from the Access `iss|sub` namespace, so the two can
  never collide.

The email is still canonicalised exactly once, at the trust boundary in `resolveCaller`,
via `canonicalEmail` (trim and `toLowerCase`) (`engine/src/admin/router-session.ts:55`;
`engine/src/admin/identity-roles.ts:114-118`), so a single canonical display form is seen by the
audit and the pending invite. The DO's own `normaliseEmail` applies the
same lowercase-and-trim normalisation at its authority boundary
(`engine/src/sched/scheduler-do-rbac.ts:69`), independently of the router, as defence in
depth.

**The recycled-email closure (ASVS V10.5.2).** Email is a mutable, reassignable attribute:
an IdP may reassign a departed user's email address to a new user, or allow a user to change
their own address. Because authority keys on the subject and not the email, a recycled or
reassigned email can NEVER inherit a departed member's role. A caller whose email equals a
departed member's but whose subject differs has no bound role entry (the departed member's
grant bound to the departed subject, or was deleted) and matches no pending invite of the
departed member, so it resolves to the least-privilege `viewer`
(`engine/src/sched/scheduler-do-rbac-authority.ts:83-141`, `roleForCaller`). The OIDC-preferred stable identifier is the
key in fact, not in aspiration.

A user who changes their own email address at Cloudflare Access or at a native OIDC IdP keeps
their role: the subject is unchanged. The bound entry keeps the email recorded when the grant bound, as a display field. A
passkey subject contains the email, so a passkey identity under a new address is a new subject.

### 1.3 Compensating controls (ENG-B1)

The ENG-B1 control closes a specific privilege-escalation path: an emailless but
validly-signed Access assertion (issued by a Cloudflare Access service token, or by a
misconfigured IdP that omits the email claim) must never fold into the bearer-token break-glass
and must never reach the Owner role.

The control is applied at independent layers, and bars an emailless OR subjectless
authenticated caller from the break-glass:

- `authorise` in `engine/src/admin/auth.ts:189`: after a positive RS256 verification, if the
  email claim is absent the verdict is `{ ok: false }` and never proceeds; a subjectless
  Access assertion is rejected the same way (`engine/src/admin/auth.ts:202`).
- `handleAdmin` in `engine/src/admin/router.ts:393-397`: after a positive `authorise`
  verdict, if the canonical email is null on any verdict other than the `token` method, the
  request is refused with HTTP 401 and a log line tagged `authn failure method=<method>
  reason=session verified but carried no usable email`.
- `resolveCaller` in `engine/src/admin/router-session.ts:44-95`: the bearer-token Owner
  break-glass (`method === "token"`, `:59`) is the only path that resolves without an email or
  subject. Any other method's verdict missing either is explicitly not allowed to take the
  token break-glass branch and instead resolves to the least-privilege `viewer` role (`:74`).
- The scheduler DO's `roleForCaller` keys on the stable subject and fails closed to `viewer`
  for a subjectless non-token caller, with a matching `SECURITY:` comment
  (`engine/src/sched/scheduler-do-rbac-authority.ts:83-141`, `roleForCaller`).

The only emailless authenticated path that exists by design is the `ADMIN_TOKEN` break-glass
(`method: "token"`), presented as the bare bearer or as the session it is exchanged for. It
resolves unconditionally to `owner` and is excluded from the group-mapping path (it has no IdP
identity, so no groups are applicable). The bare bearer carries no session expiry; the exchanged
session carries the §2.1a bounds.

### 1.4 RBAC role table and dual-control identity binding

The role table is keyed by the caller's stable subject under the `role:sub:` prefix in the
scheduler DO's durable storage (`ROLE_SUBJECT_PREFIX`, `engine/src/admin/identity.ts:272`).
A bound `RoleEntry` records the subject (the authority key) plus the email (display/audit
only) (`engine/src/admin/identity.ts:303-317`, `RoleEntry`). Because an Owner/access-admin invites by
email (they do not know the subject yet), a grant first lands as a pending invite keyed by
email (`role:pending:<email>`, `engine/src/admin/identity.ts:280`, `ROLE_PENDING_PREFIX`); on the invitee's first
verified request the DO BINDS it to their subject, writing `role:sub:<subject>` and deleting
the pending row (`resolveBoundEntry`, `engine/src/sched/scheduler-do-rbac.ts:269-328`). A
`role:<email>` entry is also read as a pending invite, so such a grant binds on next login and is
never silently dropped (`engine/src/sched/scheduler-do-rbac.ts:269-328`, `resolveBoundEntry`).
A weakly verified email (a SAML `trust-idp` connection, or an OAuth2 connection that names an email
field and no email-verified field) binds only a grant without `roles.write`,
`access.policy`, `restore.approve`, `keys.ceremony` or `posture.riskaccept`
(`engine/src/admin/identity-rbac.ts:161-176`, `WEAK_EMAIL_BIND_BARRED` and `weakEmailMayBind`). A
barred invite stays pending, and a missing custom role record bars the bind
(`engine/src/sched/scheduler-do-rbac.ts:30-38`, `weakBindAllowed`).

The roles are defined in `engine/src/admin/identity-roles.ts:55` (the six-role union), with rank
ordering in `ROLE_RANK` at `:65-72`; per-route authority is decided by the `ROLE_CAPABILITIES`
capability map (`engine/src/admin/identity-rbac.ts:47-95`), not by rank. The last-Owner guard
prevents the only effective Owner from being demoted or removed, enforced inside a single
storage read-modify-write in the DO so there is no race (`setRole` at
`engine/src/sched/scheduler-do-rbac-mutations.ts:42`, `deleteRole` at `:229`, each calling
`checkOwnerRemoval` at `:89` and `:294`). While Require Approver is on, the floor is two Owners.
While two or more Owners exist, a change that takes the owner role away from a current Owner (a
demotion to any other role, a custom-role assignment or a delete) is queued for a second Owner's
approval, whatever the Require Approver setting (`autoGateOwnerRemoval`,
`engine/src/sched/scheduler-do-change-control.ts:298`, applied at `:439`). Only an Owner may approve
it (`:570`). A revoke of every sign-in factor of an Owner is refused while two or more Owners exist
(`engine/src/sched/scheduler-do-signin-factors.ts:404`). So one Owner cannot bring the Owner count
down to one and then act alone. The bare-token break-glass is exempt from both rules.
A separate guard, `requireNotOwnerEscalation`
(`engine/src/sched/scheduler-do-rbac-authority.ts:496`), lets only an Owner grant or remove the
owner role. The Owner count operates over both bound and pending
entries, so the guard cannot be defeated by removing the only bound Owner while a pending
Owner exists, or vice versa (`countOwners`, `engine/src/sched/scheduler-do-rbac.ts:371-376`).

The optional identity-provider group-to-role mapping is additive and capped below `owner`: a
group can never confer `owner`. The cap is enforced both at write time (`setGroupRole` rejects
`owner`, `engine/src/sched/scheduler-do-rbac-mutations.ts:442`) and at resolution (`capGroupRole`
clamps any stored `owner` value back to `approver`, `engine/src/sched/scheduler-do-rbac.ts:389-399`).
The last-Owner count operates only over explicit `role:sub:`/pending entries; a group mapping can
never count toward it (`engine/src/sched/scheduler-do-rbac.ts:371-376`, `countOwners`).

The dual-control maker-not-checker comparison keys on the STABLE subject as its primary axis:
it compares the requester's subject (`requesterSubject`, the maker) against the approver's
subject (`approverSubject`, the checker), refusing a self-approval where the two are equal
(`canApprove`, `engine/src/admin/approvals.ts:590`, the subject check at `:591`), enforced
server-side in the DO inside one read-modify-write (`approveRestore`,
`engine/src/sched/scheduler-do-restore-approval.ts:356`). A bare-token caller has no stable
subject and so can be neither a distinct maker nor checker; a request or approval from it is
refused (`engine/src/sched/scheduler-do-restore-approval.ts:304`, `:340`). The display emails
(`requestedBy`/`approvedBy`) are recorded alongside for the trail, and `canApprove` also refuses
an approval whose email equals the requester's (`engine/src/admin/approvals.ts:596`). One person
can hold two subjects that share one verified email, so the email check is a second floor.

### 1.5 Operator recommendation

The role grant is decoupled from IdP email reassignment by construction (section 1.2), so an
operator does not need to police email reuse. Two operator practices remain useful: subscribe the Owners to IdP account-lifecycle events (user deletion)
so a departed member's role entry is removed promptly even though a recycled email could never
inherit it; and, where an account runs the engine's own passkeys rather than Cloudflare
Access, revoke a departed member's enrolled credentials (section 1.6) so the credential cannot
be reused.

### 1.6 `ADMIN_TOKEN` claims the first Owner and stays valid until retired

The shared `ADMIN_TOKEN` bearer has no expiry and no use count. It skips step-up
(`engine/src/admin/router-core.ts:614`). It can disarm dual control at once, with no second Owner. It cannot approve a
dual-control action (`engine/src/admin/owner-action.ts:135-139`, `:457`). Two controls bound it:

- **One-way bootstrap latch.** The latch ends only the first-Owner claim. The bearer stays valid after it. The moment the first Owner row is created (the whoami
  empty-table grant to an Access or passkey caller, or the first passkey enrolment; a native OIDC,
  OAuth2 or SAML caller never takes it) the DO latches `bootstrapConsumed` true;
  once true, no bootstrap path may ever mint a second Owner
  (`getBootstrapConsumed`/`markBootstrapConsumed`,
  `engine/src/sched/scheduler-do-org-policy.ts:296-326`). The transition is audited once as a
  `bootstrap-consumed` event.
- **In-app retire/dispose gate.** An Owner can retire the token in-app via
  `POST /admin/policy/retire-break-glass-token` (`engine/src/admin/router-ops.ts:521`, gated
  on `keys.ceremony`), after which `authorise` refuses the bearer exactly as
  `ADMIN_TOKEN_DISABLED` does (`engine/src/admin/auth.ts:336`), and an exchanged token session
  too (`engine/src/admin/auth.ts:265`). The retire is OWNER-ONLY, re-resolved from the DO's own
  tables, and is REFUSED unless a way back in already exists: working recovery codes for an
  Owner, OR a second Owner (`setBreakGlassTokenRetired`,
  `engine/src/sched/scheduler-do-org-policy.ts:440-495`). It is also refused while dual control
  is armed and an Owner grant carries an expiry (`wouldStrandDualControl`). Because a retired bare token never resolves
  to Owner, it can never un-retire itself, and the admin API has no un-retire route. Without a
  second Owner, the gate requires working recovery codes held by a passkey-bound Owner, because an
  Access-bound Owner's codes recover to viewer (`recoveryBreakGlassVerdict`,
  `engine/src/sched/scheduler-do-recovery.ts:603`).

---

## 2. Authentication factors and session lifecycle (ASVS V6.x, V7.x)

### 2.1 The first-party signed passkey session

The engine issues its OWN session for passkey, OIDC and SAML sign-in, and for the exchanged
bootstrap token: a signed cookie verified server-side against a key that lives only in the
scheduler DO. The token carries its own identity and expiry, and every mint also writes a
per-session `sessionRef` row so the operator can list and end sessions singly. It IS revocable
(section 2.4). For Cloudflare Access callers the engine holds no session of its own (Access owns
that session, section 2.2), and the bare `ADMIN_TOKEN` bearer carries no session until
`POST /admin/session/bootstrap` exchanges it for one.

The session token is `<body_b64url>.<mac_b64url>`, where `mac = HMAC-SHA-256(key, body)`. The
signing key is a 32-byte CSPRNG value generated ONCE by the DO and persisted under a single DO
key (`sessionSigningKey`, `engine/src/sched/scheduler-do-session.ts:188-220`); it never leaves the
DO, so both the sign and the constant-time verify run inside the DO (`session.ts` is the pure,
key-as-argument core the DO drives: `signSession`, `engine/src/admin/session.ts:245`, and
`verifySessionClassified`, `engine/src/admin/session.ts:319`). Key properties:

- **Server-verified MAC, not a bearer secret.** Verification recomputes the MAC over the body
  and compares in CONSTANT time; the body is never parsed unless the MAC matches, so a
  tampered or forged body can never set the email or extend the expiry
  (`engine/src/admin/session.ts:319-387`, the constant-time compare at `:338`). The per-request
  check runs over the in-DO key via a DO fetch (`passkeySessionVerify`,
  `engine/src/sched/scheduler-do-session.ts:388-501`).
- **Identity and epoch only; role is never carried.** The signed body holds a format version,
  the authentication method, the email (an OIDC IdP may not have verified it), the stable subject, the IdP connection id for
  an OIDC or SAML session, a per-email session `epoch`, a per-session id, and the issued-at,
  absolute-expiry and last-activity timestamps (`SessionPayloadV3`,
  `engine/src/admin/session.ts:135-147`). The role is
  ALWAYS re-resolved from the DO role table on each request (keyed on the subject), never
  pinned in the token, so a session can never smuggle an elevated role.
- **Absolute 12-hour TTL.** The session is bounded by an absolute `exp` set once at mint
  (`SESSION_TTL_MS`, `engine/src/admin/session.ts:53`). The absolute expiry is never slid; only
  `lastSeen` is refreshed (the slide re-mint at `engine/src/sched/scheduler-do-session.ts:491-496`
  passes the original `iat` and `exp` back into `signSession`), so a leaked cookie is useless past
  the TTL deterministically. `verifySessionClassified` rejects a token at or past its `exp`
  (`engine/src/admin/session.ts:374`) and a token idle past `SESSION_IDLE_MS` (`:464`). The full
  set of time bounds and their rationale is §2.1a.
- **`__Host-` cookie hardening.** The cookie name is `__Host-downpipes_session`
  (`engine/src/admin/session.ts:47`), and it is set HttpOnly, Secure, SameSite=Strict, Path=/
  with no Domain attribute (`sessionSetCookie`, `engine/src/admin/session.ts:495-497`). The
  `__Host-` prefix is browser-enforced: a browser accepts it only when it is Secure, has
  Path=/ and no Domain, which pins the cookie to this exact host over HTTPS and forbids a
  sibling/parent domain from setting or overriding it (a subdomain cookie-injection/fixation
  defence).

### 2.1a Session lifetime policy and NIST SP 800-63B alignment (ASVS V7.1.1)

The native session carries five time bounds. Each is a named constant in
`engine/src/admin/session.ts`, and each is enforced at the line the table names.

| Bound | Constant | Value | Enforced at |
|-------|----------|-------|-------------|
| Absolute lifetime | `SESSION_TTL_MS` (`engine/src/admin/session.ts:53`) | 12 hours | `exp` is set once at mint (`signSession`, `engine/src/admin/session.ts:245`; the `exp` computation at `:250-255`); `verifySessionClassified` rejects a token at or past `exp` (`engine/src/admin/session.ts:374`). |
| Inactivity timeout | `SESSION_IDLE_MS` (`engine/src/admin/session.ts:59`) | 2 hours | `verifyV3Body` rejects a token whose `lastSeen` is that old (`engine/src/admin/session.ts:464`). Evaluated on every request, independent of the absolute cap. |
| Slide cadence | `SESSION_SLIDE_MS` (`engine/src/admin/session.ts:71`) | 15 minutes | `slideDue` (`engine/src/admin/session.ts:484`); the DO re-mints with the original `iat` and `exp` preserved, moving only `lastSeen` (`engine/src/sched/scheduler-do-session.ts:541-545`). The slide never extends the absolute lifetime. |
| Step-up freshness | `STEPUP_FRESH_MS` (`engine/src/admin/session.ts:84`) | 5 minutes | `stepUpCheck` admits a passkey session whose `iat` is younger than this without a fresh assertion (`engine/src/sched/scheduler-do-stepup.ts:221`). An `oidc` or `saml` session qualifies only on passkey self-add and on ending the member's own sessions. |
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

- Every step-up gated action (`STEPUP_SUBS`, `engine/src/admin/router-core.ts:454`) is
  refused unless the session is a passkey session authenticated within 5 minutes, or the request
  carries a single-use step-up token from a fresh passkey assertion
  (`engine/src/sched/scheduler-do-stepup.ts:221-227`). The IdP-established sessions get the
  recency shortcut only when they end their own sessions. A session exchanged from `ADMIN_TOKEN`
  is exempt, as the bare bearer is. So the actions that matter most are
  re-authenticated on a 5-minute figure, well inside the AAL3 inactivity figure.
- The role is re-resolved from the DO role table on every request and is never carried in the token
  (§2.1), so a demotion or removal takes effect on the next request rather than at session end.
- Epoch revocation kills every session for an identity on its next request: on logout
  (`passkeySessionLogout`, `engine/src/sched/scheduler-do-session.ts:660`), on offboarding
  (`deleteRole`, `engine/src/sched/scheduler-do-rbac-mutations.ts:230`, the epoch bumps at `:281`
  and `:381-382`), and on a factor change (§2.4). The three termination actions in §2.4 end
  sessions on demand.
- The cookie is `__Host-`, `HttpOnly`, `Secure`, `SameSite=Strict` (`sessionSetCookie`,
  `engine/src/admin/session.ts:495-497`), and every mutating cookie-borne request passes the
  strict-Origin CSRF gate (§2.3a), so a session that is idle in an open tab cannot be driven from
  another origin while it waits.

**Assessment.** The combination of a 12-hour absolute lifetime, a 2-hour inactivity timeout, a
5-minute re-authentication figure on sensitive actions, per-request role re-resolution and epoch
revocation is judged appropriate for this surface. The 2-hour idle bound is a deliberate,
documented deviation from the revision 4 SHOULD figures. The compensating controls bound the
exposure of an idle session: a step-up gated action needs a fresh factor, and every other request
runs under a role that is re-checked on every request.

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
(`engine/src/admin/session.ts:374`), evaluated over the in-DO key on every request.

The verified Access `exp` is carried through to `GET /admin/whoami` via the `AuthVerdict` type
(`engine/src/admin/identity.ts:59-66`) and surfaced to the console as `sessionExpiresAt`
(`engine/src/admin/router-identity.ts:800`), so the console can display the honest Access session expiry
without re-parsing the token.

### 2.3a CSRF defence for the cookie-borne session

A session is carried in an AMBIENT cookie that a foreign page could ride on a
state-changing request, so every MUTATING (non-GET, non-OPTIONS) request authenticated by a
session cookie (passkey, OIDC, SAML or an exchanged token session) MUST also carry an `Origin`
that EXACTLY matches `CONSOLE_ORIGIN`. This strict-Origin check is enforced before any route body
read or DO forward (`engine/src/admin/router.ts:467-490`; `originFailClass`,
`engine/src/admin/session.ts:570-575`). It fails closed on a missing `Origin` or an unset
`CONSOLE_ORIGIN`. It is defence in depth ON TOP of the cookie's `SameSite=Strict`: even a
browser that ignored SameSite, or a future relaxation, could not drive a cross-origin write.
A mutating Cloudflare Access request that carries an `Origin` header (any value, including `null`) must match
it too, else 403. An Access request with no `Origin` header (a script) and the bare `ADMIN_TOKEN` bearer skip
the check; the cookie-borne methods are named at `engine/src/admin/identity-roles.ts:42-44`. The passkey
registration routes (`register/begin` and `register/finish`) run before that gate and apply the same rule to a
cookie-borne caller (whose request needs an `Origin` equal to `CONSOLE_ORIGIN`, so a request with none is refused)
and to an Access caller (`originFailClass` at `engine/src/admin/router-auth-flow.ts:392`).

### 2.4 Session termination (the passkey session is revocable)

The passkey session is self-contained yet revocable, via a per-email session epoch plus
signing-key rotation. A monotonic per-email `epoch` counter is stored in the DO
(`SESSION_EPOCH_PREFIX`, `engine/src/sched/scheduler-do-keys.ts:190`); the token carries the
epoch at issue, and `passkeySessionVerify` rejects a token whose epoch is below the email's
current stored value (`engine/src/sched/scheduler-do-session.ts:421-427`). Bumping the epoch
therefore invalidates every session minted before the bump, with no session store to walk.
Logout bumps the email's epoch and clears the cookie with the same attributes and `Max-Age=0`
(`sessionClearCookie`, `engine/src/admin/session.ts:505-507`; route `POST /admin/auth/logout`,
`handleLogout`, `engine/src/admin/router-auth-flow.ts:281`; `passkeySessionLogout`,
`engine/src/sched/scheduler-do-session.ts:646-675`). When the revocation is not confirmed (the DO
refuses, cannot be reached, or does not answer within 2.5 s), the cookie is still cleared
and the answer is 503 `{ok:false}` instead of 200 `{ok:true}` (`engine/src/admin/router-auth-flow.ts:347-349`), so the console warns
that a copy of the session may still work until it expires.
A native (OIDC, OAuth2 or SAML) session is the exception: its email is what the IdP asserted and may
be unverified, so its logout moves only its own subject's not-before instant, never the email
epoch. Another identity that asserts the same email is not signed out. The same rule holds for the
prior-cookie revoke at sign-in (`revokePresentedSession`).

The termination capabilities are:

- **View own sessions.** `GET /admin/sessions` (the caller's live sessions, per-session ids, coarse provenance). An OIDC, OAuth2 or SAML caller lists and ends only the sessions of its own signed-in subject. A passkey, recovery-code or Access caller lists and ends every session recorded under its email, including a native session of another subject that asserts the same email (`engine/test/validate-session-subject-keyed.ts`)
- **Terminate one session (self).** `POST /admin/sessions/terminate { sid }` (step-up gated)
- **Terminate other sessions (self).** `POST /admin/sessions/terminate-others` (step-up gated)
    (`engine/src/admin/router-account-session.ts:179`) bumps the caller's own epoch and returns a
  freshly-minted token carrying the new epoch, so the current session stays alive while all
  others die. A native caller instead revokes its own subject's other sessions one by one by id
  and moves no epoch (`terminateOwnOtherSessions`, `engine/src/sched/scheduler-do-session.ts:556-608`).
- **Terminate a member's sessions (admin).** `POST /admin/sessions/terminate-user`
    (`engine/src/admin/router-account-session.ts:221`) bumps a target email's epoch and the bound
  subject's not-before instant. Gated on `roles.write` re-resolved, and an Owner's sessions may
  be terminated only BY an Owner (`terminateUserSessions`,
  `engine/src/sched/scheduler-do-session.ts:572-596`).
- **Terminate ALL sessions (owner).** `POST /admin/sessions/terminate-all`
    (`engine/src/admin/router-account-session.ts:282`) DELETES the session signing key, so every
  outstanding token fails its next MAC verify and a fresh key is generated on the next issue.
  Gated on `roles.write` re-resolved AND `role === "owner"` (`terminateAllSessions`,
  `engine/src/sched/scheduler-do-session.ts:266-286`).
- **Revoke a credential.** `POST /admin/passkey/credentials/delete`
    (`engine/src/admin/router-account-session.ts:94`) removes a WebAuthn credential (the
  theft/loss path) and bumps the bound email's session epoch so any session that credential
  authenticated also dies. Self-service, or by a `roles.write` holder; an Owner's credential
  requires an Owner caller, and the last credential of the sole Owner is refused so an Owner is
  never locked out of the in-app factor (`revokePasskeyCredential`,
  `engine/src/sched/scheduler-do-recovery.ts:877-929`).

The epoch is also bumped on a factor change (a passkey revoke, a recovery-code regeneration),
so changing an authentication factor invalidates outstanding sessions for that email.

### 2.5 ASVS V6/V7 control mapping

| ASVS control | Status | Notes |
|--------------|--------|-------|
| V6.3.3 - Multi-factor / phishing-resistant authentication | Engine-enforced (passkeys) | First-party WebAuthn passkeys with MANDATORY user verification (`engine/src/admin/passkey.ts:278`, `:353`). |
| V6.5.x - Recovery / lookup-secret factor | Engine-enforced (recovery codes) | Single-use, salted-hash recovery codes; plaintext returned once, only the salted HMAC stored (`engine/src/admin/recovery.ts:60`, `:66-70`). See logging-inventory for the audited lifecycle. |
| V7.1.1 - Session lifetime documented, with 800-63B justification | Documented (§2.1a) | Inactivity timeout 2 hours (`SESSION_IDLE_MS`, `engine/src/admin/session.ts:59`, enforced at `:464`) and absolute lifetime 12 hours (`SESSION_TTL_MS`, `engine/src/admin/session.ts:53`, enforced at `:374`) are stated with their rationale, the compensating controls they combine with, and the justification for the inactivity deviation from NIST SP 800-63B revision 4 (§2.2.3, §2.3.3), all in §2.1a. Customer statement: docs.downpipes.io/identity-access/session-management. |
| V7.1.2 - Concurrent session policy documented | Documented (policy: unbounded, revocable en masse) | Allowed: unlimited. Maximum-reached behaviour: none, a further sign-in is always admitted. A sign-in from another browser evicts nothing; a sign-in from a browser that presents a live session cookie ends every session of the account (revokePresentedSession, V7.2.4); the operator reduces the count with terminate-others / terminate-user / terminate-all (§2.4). The V7.4.1 row below carries the mechanism. Customer statement: docs.downpipes.io/identity-access/session-management, "Concurrent sessions". |
| V7.1.3 - Federated session systems and their coordination documented | Documented (§2.7) | The four systems that mint or manage a session (native OIDC/OAuth2 RP, native SAML SP, Cloudflare Access at the engine, Cloudflare Access at the control-plane admin portal) are tabled in §2.7 with lifetime coordination, termination coordination and the conditions that force re-authentication. Two facts an operator needs are stated there: SAML `SessionNotOnOrAfter` caps the native session and OIDC carries no IdP bound; there is no single logout in either direction. |
| V7.2.1 / V7.8.1 - Session invalidation on logout | Engine-enforced (passkey); Access-managed (Access) | `POST /admin/auth/logout` bumps the epoch and clears the cookie (`engine/src/admin/router-auth-flow.ts:281`); termination routes (section 2.4) revoke server-side via the epoch/key. Access sign-out remains Access's. |
| V7.2.2 - Session creation after re-authentication | Engine-enforced (passkey) | A fresh signed token is minted only after a completed sign-in: a WebAuthn login (`passkeySessionIssue`, `engine/src/sched/scheduler-do-session.ts:334-358`), a recovery code, a verified OIDC or SAML response, or the bootstrap-token exchange. A live session the browser presents is ended first (`revokePresentedSession`, `:336`); the role is re-resolved, never carried. Access creates its own session. |
| V7.3.1 - Session inactivity timeout | Engine-enforced (native session) | A session is rejected after `SESSION_IDLE_MS` (2 hours, `engine/src/admin/session.ts:59`) of no activity (`engine/src/admin/session.ts:464`), independent of the 12h absolute cap. Activity is recorded as `lastSeen` in the signed V3 body and refreshed by a slide re-mint that preserves the original `iat`/`exp` (so it never extends the absolute cap). Access's own inactivity window stays operator-configured. |
| V7.3.2 - Absolute session duration limit | Engine-enforced (native session) | Absolute 12-hour TTL set once at mint (`SESSION_TTL_MS`, `engine/src/admin/session.ts:53`; rejected at `:357`). The idle-slide re-mint refreshes `lastSeen` only; it preserves the original `iat`/`exp`, so the absolute cap is never slid forward. Access duration is operator-configured. |
| V7.4.1 / V7.1.2 - Concurrent session mechanism | Documented (policy: unbounded, revocable en masse) | The engine does NOT cap the NUMBER of concurrent sessions. Allowed: unlimited. Maximum-reached behaviour: none, a further sign-in is always admitted. A sign-in from another browser evicts nothing; a sign-in from a browser that presents a live session cookie ends every session of the account (revokePresentedSession, V7.2.4); the operator reduces the count with terminate-others / terminate-user / terminate-all. EVERY session for an identity is revocable at once via the per-email epoch (`engine/src/sched/scheduler-do-session.ts:451`), the per-subject not-before instant (`:431`) and signing-key rotation (section 2.4). A removed member's or a logged-out identity's sessions all die on their next request (the epoch is bumped on offboarding AND logout). Two sessions for one Owner coexisting, and terminate-others keeping the caller's own, is proved at `engine/test/validate-session.ts:764`. Access concurrency, where used, stays operator-configured. |
| V7.4.3 / V7.4.5 - Terminate a user's sessions (admin) | Engine-enforced | `terminate-user` (admin, owner-guarded) and `terminate-all` (owner) bump the epoch / rotate the key (`engine/src/sched/scheduler-do-session.ts:613-637`, `:266-286`). |
| V7.5.2 - View and terminate any or all active sessions (self), having authenticated again | Engine-enforced | Every mint carries a per-session id and writes a `sessionRef` row; `GET /admin/sessions` lists the caller's live sessions with the presenting one flagged (`engine/src/admin/router-account-session.ts`, `listOwnSessions` in `engine/src/sched/scheduler-do-session.ts`); `POST /admin/sessions/terminate { sid }` ends one session by writing `sessionRevoked:<sid>`, consulted at every verify (`terminateOneSession`, `passkeySessionVerify`); `terminate-others` bumps the caller's epoch and re-issues their current session (`terminateOwnOtherSessions`). For a native (OIDC, OAuth2, SAML) caller the list, the single terminate and terminate-others are scoped to its signed-in subject, and its logout moves only its subject's not-before instant, so an identity asserting another member's email cannot see or end that member's sessions. A passkey, recovery-code or Access caller lists and ends every session recorded under its email, including a native session of another subject that asserts the same email (`engine/test/validate-session-subject-keyed.ts`). Both terminations are in `STEPUP_SUBS` (`engine/src/admin/router-core.ts`), so a stale session completes a passkey assertion first. |
| V7.5.1 - Session token properties (length, entropy, unpredictability) | Engine-enforced (passkey) | The session is a server-signed HMAC over a 32-byte CSPRNG key (`SESSION_KEY_BYTES`, `engine/src/admin/session.ts:96`; `engine/src/sched/scheduler-do-session.ts:188-220`), not a guessable bearer. The Access JWT is RS256, verified not generated. |
| V7.6.1 - RP/IdP session lifetime and termination behave as documented | Engine-enforced and documented (§2.7) | SAML: the native `exp` is `min(now + SESSION_TTL_MS, SessionNotOnOrAfter)` (`engine/src/admin/saml/assertion.ts:277-278` reads the bound, `engine/src/sched/scheduler-do-idp.ts:553-554` hands it on, `engine/src/admin/session.ts:254` takes the minimum); a present-but-unreadable bound is read as no bound and recorded as `sso-session-cap-dropped` (`engine/src/admin/saml/assertion.ts:283`). OIDC/OAuth2: no IdP bound is passed (`engine/src/sched/scheduler-do-idp.ts:1012`), so the 12-hour cap, the 2-hour idle bound and the revocation axes are the only re-authentication triggers. Access: `verifyAccessJWT` checks `exp` and `nbf` on every request (`engine/src/admin/access.ts:288-289`); the passkey session's absolute `exp` is checked at `engine/src/admin/session.ts:374`. Tests: `engine/test/validate-saml-assertion.ts:268`, `engine/test/validate-cov-sched-scheduler-do-idp.ts:293`. Customer statement: docs.downpipes.io/identity-access/session-management. |

**Authentication strength (ASVS V6.8.4):** the native OIDC/OAuth2/SAML RP reads the IdP's strength claims
(`acr`, `amr`, `auth_time`; SAML `AuthnContextClassRef` and `AuthnInstant`) as a bounded advisory that is
recorded on the `idp-sign-in` audit event and never authorises anything (`engine/src/admin/auth-context.ts`,
`engine/src/admin/oidc.ts:584`, `engine/src/admin/saml/assertion.ts:310`,
`engine/src/sched/scheduler-do-idp.ts:1021-1025`). Because the engine cannot verify which factor the IdP used,
and because the session's `iat` is the engine's own callback instant rather than the IdP's `auth_time`, every
IdP-established session is treated as single-factor, the minimum strength: a step-up-gated action
(`STEPUP_SUBS` in `engine/src/admin/router-core.ts`, recovery-code regeneration, the dual-control
approvals) is refused for an `oidc` or `saml` session however recently it signed in, and is
admitted only on a fresh UV passkey assertion through the step-up ceremony
(`engine/src/sched/scheduler-do-stepup.ts`, `stepUpCheck`). The recency shortcut applies to `passkey`
sessions (a UV WebAuthn login; a session a recovery code minted is held to the `oidc` rule). Two
exceptions accept a fresh IdP or recovery sign-in. Passkey self-add passes the `enrol-passkey` purpose, because an
SSO or recovered member may have no passkey to assert with. `/sessions/terminate` and `/sessions/terminate-others` pass
the `end-own-session` purpose, because they end only the caller's own sessions. An operator who needs a
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
is that documentation. Every citation below points at the tree, and each threshold is the value of the exported constant.

A note on custody first, because it is the usual point of confusion: the engine runs in the
CUSTOMER's own Cloudflare account. Any contextual attribute it observes (a source IP, a connection
identity) is seen and, where retained, stored inside the customer's own account. None of it reaches
the vendor. No-custody is a statement about what the VENDOR holds, so using contextual attributes
for the customer's own operators does not bear on it.

The contextual attributes the engine evaluates for authentication and authorization decisions are:

- **Temporal context (inactivity and absolute age).** Every request re-evaluates the session's idle
  instant (`lastSeen`) against `SESSION_IDLE_MS` (2 h, `engine/src/admin/session.ts:59`; the check is
  `engine/src/admin/session.ts:464`) and its absolute expiry against `SESSION_TTL_MS` (12 h,
  `engine/src/admin/session.ts:53`; a token at or past its expiry is rejected as `session-fault-expired`,
  `engine/src/admin/session.ts:374`). Inactivity is a contextual signal applied continuously during a
  session, not only at sign-in.
- **Connection identity.** The signed V3 session body carries the authentication method, the stable
  subject and, for an IdP session, the `connId` of the connection that established it
  (`engine/src/admin/session.ts:140`; bound at mint, `engine/src/admin/session.ts:261`). The DO checks
  the session against the per-connection epoch axis on every request (section 2.4).
- **Request origin.** Every mutating cookie-session request, and every mutating Access request that
  carries an `Origin`, must match `CONSOLE_ORIGIN` exactly, enforced before any body read (`originFailClass`,
  `engine/src/admin/router.ts:470`; `originAllowed`, `engine/src/admin/session.ts:541`). Section 2.3a
  describes the check.
- **Subject continuity.** The caller's role is RE-RESOLVED from the immutable subject on every
  request (never carried in the token), and the session is checked against three revocation axes
  (per-email epoch, per-subject not-before, signing-key generation; section 2.4). A change in the
  subject's authority or standing takes effect on the next request.
- **Action sensitivity.** A POST whose route is in `STEPUP_SUBS` (`engine/src/admin/router-core.ts:454`)
  passes `requireStepUp` (`engine/src/admin/router-core.ts:612`) before it is dispatched
  (`engine/src/admin/router.ts:577-583`). Three further legs call `requireStepUp` directly because a
  static route string cannot match them: the config-change approve leg (`engine/src/admin/router.ts:626`),
  the owner-action approve leg (`engine/src/admin/router.ts:673`) and the restore apply leg
  (`engine/src/admin/router-restore.ts:275`). Two sign-in-flow routes also call `requireStepUp`
  inline: recovery-code regeneration (`engine/src/admin/router-auth-flow.ts:158`) and passkey
  self-add (`engine/src/admin/router-auth-flow.ts:443`). The control adapts to the risk of the
  operation.
- **Source network address.** The router reads the edge-injected `CF-Connecting-IP` header and the
  engine uses it in five ways, each a row of the decision table below: the per-IP throttle on the
  unauthenticated sign-in ceremonies (the `ip:` namespace; `authRateLimited`,
  `engine/src/admin/router-core.ts:675`); the per-IP and per-email-and-source throttle on the recovery-code sign-in
  (the `recovery-rate:` namespace; `recoveryRateAllow`, `engine/src/sched/scheduler-do-recovery.ts:523`);
  the per-IP throttle on the bare `ADMIN_TOKEN` compare (the `admin-token-ip:` namespace;
  `adminTokenRateLimitedViaDO`, `engine/src/admin/router-session.ts:338`); the opt-in
  sign-in-new-context notification, which compares a coarse prefix of the address against the
  operator's seen-set when the `notifyNewSignInContext` policy is on (`getNotifyNewSignInContext`,
  `engine/src/sched/scheduler-do-org-policy.ts:123`); and audit provenance, where `sourceIp` is recorded
  on every authentication event as non-authority metadata (`engine/src/admin/identity.ts:116`). The
  source IP is never an authentication or authorisation input and never a sole authorization factor
  (ASVS V8.4.2): no gate reads it to decide a role or a capability. The authenticated per-caller
  throttle is keyed in the `sub:` namespace on the verified subject, not on the address.
- **Attributes not evaluated.** Time of day, geographic location, IP reputation, and device identity or
  posture are not evaluated anywhere in the engine. No control reads them, so no threshold exists for
  them.

#### Contextual decision table

One row per factor. The threshold column shows the value of the exported constant. The action set is allow, deny, step-up challenge and notify.
There is no silent risk score: every decision is one of those four, and each is observable to the
caller or, for notify, to the operator.

| Attribute | Where evaluated | Threshold | Action |
|-----------|-----------------|-----------|--------|
| Session absolute age | `verifySessionClassified`, `engine/src/admin/session.ts:374`, on every cookie-session request | the token's expiry is the mint instant plus `SESSION_TTL_MS` (12 h, `engine/src/admin/session.ts:53`); the idle slide never moves it | deny: `session-fault-expired`, answered 401 `unauthorised` (`engine/src/admin/router.ts:386`); the operator signs in again |
| Session inactivity | `verifySessionClassified`, `engine/src/admin/session.ts:464`, on every cookie-session request | `lastSeen` older than `SESSION_IDLE_MS` (2 h, `engine/src/admin/session.ts:59`) | deny: `session-fault-idle`, answered 401 `unauthorised` (`engine/src/admin/router.ts:386`); the operator signs in again |
| Action sensitivity | `requireStepUp` (`engine/src/admin/router-core.ts:612`), gated once before the main switch (`engine/src/admin/router.ts:581-583`) and directly on the three dynamic legs named above | the route is in `STEPUP_SUBS` (49 routes, `engine/src/admin/router-core.ts:454`) and the caller holds no passkey proof fresher than `STEPUP_FRESH_MS` (5 min, `engine/src/admin/session.ts:84`) and presents no single-use step-up token, which lives `STEPUP_TOKEN_TTL_MS` (2 min, `engine/src/admin/session.ts:90`); an Access caller is judged on the assertion's issued-at against the same 5 min; an OIDC or SAML session must assert a passkey, except when it ends its own sessions (section 2.5) | challenge: 401 with `stepUpRequired` true in the body (`engine/src/admin/router-core.ts:653`; with `reauth: "access"` for an Access caller, `engine/src/admin/router-core.ts:618`); the `ADMIN_TOKEN` method is exempt, as the bare bearer and as its exchanged session; fails closed when the DO check is unavailable (`stepup-check-unavailable`, `engine/src/admin/router-core.ts:651`) |
| Source IP on the sign-in ceremonies (`/admin/auth/*`, `/admin/oidc/*`, `/admin/saml/*`, all unauthenticated) | `authRateLimited` (`engine/src/admin/router-core.ts:675`), keyed `ip:<source group>` with the cap `AUTH_RATE_LIMIT_MAX_PER_WINDOW` (`engine/src/admin/router-core.ts:687`), counted by the DO `rateCheck` (`engine/src/sched/scheduler-do.ts:813`) | more than `AUTH_RATE_LIMIT_MAX_PER_WINDOW` requests in one `RATE_LIMIT_WINDOW_MS` window: 30 per 60 s (`engine/src/sched/scheduler-do-limits.ts:673`; window `engine/src/sched/scheduler-do-limits.ts:652`) | deny: 429 with `Retry-After` (`rateLimitedResponse`, `engine/src/admin/router-core.ts:320`); fails closed: only `allowed === true` admits (`engine/src/admin/router-core.ts:695`) and a limiter outage also answers 429 (`engine/src/admin/router-core.ts:695`) |
| Source IP and target email on the recovery-code sign-in (`POST /admin/auth/recovery`) | `recoveryRecover` derives `emailKey` and `ipKey` (`engine/src/sched/scheduler-do-recovery.ts:368-369`); `emailKey` is `email:<email>:<source group>` (group `none` with no address) and `ipKey` is `ip:<source group>`, as above, with every request that has no address sharing the one `ip:none` bucket; the email is trimmed and lower-cased, so one address in any case or spacing shares one row, and an address longer than `RECOVERY_EMAIL_MAX_LENGTH` (254 characters, `engine/src/sched/scheduler-do-limits.ts:996`) takes the one shared `email:_invalid:<source group>` row and still consumes the per-IP token; a new email row is written only after its source group passes the per-IP bucket (`recoveryRateRowLive`, `engine/src/sched/scheduler-do-recovery.ts:555`), so one source group adds at most `RECOVERY_RATE_MAX_PER_IP` email rows per window; `recoveryRateAllow` checks both (`engine/src/sched/scheduler-do-recovery.ts:523`) under the `RECOVERY_RATE_PREFIX` storage prefix `recovery-rate:` (`engine/src/sched/scheduler-do-limits.ts:745`) | `RECOVERY_RATE_MAX_PER_IP`: 5 per 60 s per IP, and `RECOVERY_RATE_MAX_PER_EMAIL`: 5 per 60 s per email and source group (`engine/src/sched/scheduler-do-limits.ts:747-748`); both buckets must admit | deny: one generic 401 `unauthorised` with no `Retry-After` (`engine/src/admin/router-auth-flow.ts:82`), so no oracle separates a throttle from a wrong code; fails closed on a limiter fault (`recovery-limiter-unavailable`, `engine/src/sched/scheduler-do-recovery.ts:547-550`); the ceremony also passes the per-IP sign-in throttle above first |
| Source IP on the break-glass bearer (`ADMIN_TOKEN` compare) | `adminTokenRateLimitedViaDO` (`engine/src/admin/router-session.ts:338`), keyed `admin-token-ip:<source group>` with the cap `ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW` (`engine/src/admin/router-session.ts:344`), consulted inside `authorise` before the token compare | more than `ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW` attempts in one window: 10 per 60 s (`engine/src/sched/scheduler-do-limits.ts:682`) | deny: 429 with `Retry-After` set to the full window (`adminTokenThrottledResponse`, `engine/src/admin/router-core.ts:344`; answered at `engine/src/admin/router.ts:364`); fails closed on a limiter fault (`admin-token-ratelimited-unavailable`, `engine/src/admin/router-session.ts:370-378`) |
| Verified caller identity on a mutating route | `rateLimited` (`engine/src/admin/router-core.ts:349`) after the route reads its body; keyed in the `sub:` namespace by `rateLimitKey`, with the bare token sharing one `token` bucket (`engine/src/admin/router-core.ts:264-265`) | more than `RATE_LIMIT_MAX_PER_WINDOW` mutating requests in one window: 120 per 60 s (`engine/src/sched/scheduler-do-limits.ts:659`) | deny: 429 with `Retry-After` (`rateLimitedResponse`, `engine/src/admin/router-core.ts:320`); fail open: a malformed verdict or an unavailable limiter admits the request and records `limiter-verdict-malformed` (`engine/src/admin/router-core.ts:368`, `engine/src/admin/router-core.ts:387`) |
| Request Origin on a mutating cookie-session request, or on a mutating Access request that carries an `Origin` header | `originFailClass` against `CONSOLE_ORIGIN` before any body read (`engine/src/admin/router.ts:470`) | for a cookie session: the `Origin` header is absent, or differs from `CONSOLE_ORIGIN`, or `CONSOLE_ORIGIN` is unset; for Access: an `Origin` header is present and differs from `CONSOLE_ORIGIN`, or `CONSOLE_ORIGIN` is unset | deny: 403 `csrf origin check failed` (`engine/src/admin/router.ts:488`); the engine does not run this check for the bare bearer or for an Access request with no `Origin` header |
| Absent `CF-Connecting-IP` on the sign-in ceremonies and the bearer compare | `authRateLimited` (`engine/src/admin/router-core.ts:675-683`) and `adminTokenRateLimitedViaDO` (`engine/src/admin/router-session.ts:340-341`) | the header is missing or empty | allow, with no throttle bucket. The Cloudflare edge sets `CF-Connecting-IP` on every request it proxies (overwriting any client value), on a custom domain and a `workers.dev` hostname alike, so a real edge request carries it. Its absence means a non-edge or local context (a validator), not a stripped header. Failing closed here would buy zero production security while bucketing every header-less local caller into one shared key. This is the V2.4.1 / V8.1.4 accept decision |
| Source IP prefix on a proven sign-in (R6, opt-in) | `recordSignInContext` (`engine/src/sched/scheduler-do-session.ts:299`), reached through `POST /signin-context` (`engine/src/sched/scheduler-do-routing-identity.ts:41`) from `fireSignInContextCheck` after a passkey login (`engine/src/admin/router-auth-flow.ts:737`), and inside the DO success block for an OIDC or SAML login; only when `getNotifyNewSignInContext` is true (`engine/src/sched/scheduler-do-org-policy.ts:123`) | `coarseSignInPrefix` reduces the address to an IPv4 /24 or IPv6 /48 prefix (`engine/src/admin/sign-in-context.ts:41`); the prefix is absent from the operator's seen-set, which `evaluateSignInContext` (`engine/src/admin/sign-in-context.ts:148`) prunes to `SEEN_CONTEXT_TTL_MS` (90 days, `engine/src/admin/sign-in-context.ts:28`) and caps at `SEEN_CONTEXT_CAP` (10 prefixes, `engine/src/admin/sign-in-context.ts:20`) | notify only: the `sign-in-new-context` alert, which carries no address; the sign-in is never delayed or refused; the raw IP is used in memory to derive the prefix and is never stored. Deleting a member's role deletes their seen-set. It also deletes every IdP group record that names their address. The scheduler alarm deletes a group record not refreshed for 90 days. |

The step-up gated routes in `STEPUP_SUBS` are: `/restore/approve`, `/keys/install`, `/keys/rotate`,
`/keys/add-operational`, `/keys/add-config-recovery`, `/keys/break-glass-only`, `/posture/accept`, `/posture/unaccept`,
`/destination`, `/destinations`, `/destinations/remove`, `/destinations/default`, `/push`,
`/push/delete`, `/push/test`, `/otlp-push`, `/otlp-push/delete`, `/idp/connections`,
`/idp/connections/delete`, `/idp/connections/enabled`, `/idp/connections/cert`, `/roles`,
`/roles/delete`, `/group-roles`, `/group-roles/delete`, `/custom-roles`, `/custom-roles/delete`,
`/policy/retire-break-glass-token`, `/passkey/credentials/delete`, `/signin-factors/revoke`,
`/runlog/resign`, `/runlog/floor/reset`, `/runlog/relink`, `/notify/rules`, `/notify/rules/delete`, `/config/signin-context-policy`, `/notify/channels`,
`/notify/channels/delete`, `/config/restore-approval-policy`, `/config/update-approval-policy`,
`/attest/session/create`, `/retention-prune/apply`,
`/retention-prune/approve`, `/support/credentials`, `/sessions/terminate-user`,
`/sessions/terminate-all`, `/sessions/terminate-others`, `/sessions/terminate` and `/custody/send-share`. This paragraph lists the whole set.

Adaptive controls applied AT SESSION START: WebAuthn user verification is mandatory (a registration
or an assertion whose UV flag is clear is rejected as `user_verified`, `engine/src/admin/passkey.ts:278`
and `engine/src/admin/passkey.ts:353`), the connection identity is bound into the signed body, the
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
| Native SAML SP (`/admin/saml/*`) | The engine, after the assertion consumer verifies the signed assertion (`nativeSessionIssue`, `engine/src/sched/scheduler-do-idp.ts:444`). | `exp = min(now + SESSION_TTL_MS, AuthnStatement/@SessionNotOnOrAfter)`. The bound is read off the signature-verified assertion (`engine/src/admin/saml/assertion.ts:277-278`), threaded through the ACS (`engine/src/sched/scheduler-do-idp-saml.ts:239`), passed to the mint (`engine/src/sched/scheduler-do-idp.ts:553-554`) and applied in `signSession` (`engine/src/admin/session.ts:245`, the minimum at `:254`). A bound that is present but does not parse is read as no bound and counted as `sso-session-cap-dropped` (`engine/src/admin/saml/assertion.ts:283`, `engine/src/admin/saml-signals.ts:64`). An absent bound leaves the 12-hour cap. | Per-email epoch, per-subject not-before, per-connection `idpEpoch` and verify-time connection liveness (`engine/src/sched/scheduler-do-session.ts:451`, `:462`, `:469`, `:490`). Disabling or deleting the connection stamps its `idpEpoch` (`idpConnSetEnabled`, `engine/src/sched/scheduler-do-idp.ts:760`, stamping at `:771`; `idpConnDelete`, `engine/src/sched/scheduler-do-idp.ts:730`, stamping at `:741`). No single logout in either direction. | The 12-hour cap, the SAML bound, the 2-hour idle bound, any revocation axis, `session-fault-upgrade-reauth` after a token-shape change, and step-up for the `STEPUP_SUBS` set on every request (an IdP session gets the 5-minute recency shortcut only when it ends its own sessions). |
| Native OIDC/OAuth2 RP (`/admin/oidc/*`) | The engine, after the callback verifies the token exchange (`nativeSessionIssue`, `engine/src/sched/scheduler-do-idp.ts:444`). | Not capped at the IdP session or the `id_token` expiry. The OIDC callback passes no bound (`engine/src/sched/scheduler-do-idp.ts:1012`), so the native session runs to the 12-hour cap or the 2-hour idle bound whatever the IdP's own session does. The engine consumes no OIDC session-management or back-channel logout message. | The same four axes as SAML. No single logout in either direction. | The 12-hour cap, the 2-hour idle bound, any revocation axis, `session-fault-upgrade-reauth`, and step-up for the `STEPUP_SUBS` set on every request. |
| Cloudflare Access in front of the engine | Cloudflare Access; the engine holds no session of its own for an Access caller (§2.2). | Access owns lifetime and inactivity, both operator-configured. The engine enforces the assertion's `exp` and `nbf` on every request (`engine/src/admin/access.ts:288-289`). | Access-side sign-out at `/cdn-cgi/access/logout`; the engine's termination actions do not reach an Access session, and an Access sign-out does not touch a native session. | Whatever the Access application requires, and for the `STEPUP_SUBS` set an assertion issued within `STEPUP_FRESH_MS`; the engine's step-up gate exempts only the `ADMIN_TOKEN` method, bare or exchanged for a session. |
| Cloudflare Access in front of the control-plane admin portal | Cloudflare Access, with the portal Worker layering its own checks on top. | Access session duration 24 hours; a 30-minute idle timeout in the Worker (`PORTAL_IDLE_MS`). | An idle request is refused and redirected through `/cdn-cgi/access/logout`; a revoke marker covers same-day offboarding. | The Access duration, the idle timeout, and a 5-minute assertion-freshness requirement before the highest-impact actions. |

**No single logout.** Neither native front door implements single logout. An IdP-side sign-out
does not end an engine session: the session lives until the 12-hour cap, the SAML bound, the 2-hour
idle bound, or a revocation axis catches it. The group snapshot the DO re-reads on every request
is written only at sign-in, so a deprovision at the IdP reaches the engine only through SCIM
deprovisioning or a termination action. An engine logout does not end the IdP session. Offboarding a member who signs in through an
IdP without SCIM is therefore two acts: deprovision at the IdP, and terminate at the engine (§2.4). The
customer-facing statement of the same rule is docs.downpipes.io/identity-access/session-management.

**Re-authentication conditions, in one place.** A native session must be re-established when any
of the following holds: the absolute lifetime is reached (`SESSION_TTL_MS`, 12 hours); the SAML
`SessionNotOnOrAfter` bound is reached; the session has been idle for `SESSION_IDLE_MS` (2 hours);
any revocation axis rejects it (email epoch, subject not-before, connection `idpEpoch`, connection
liveness, signing-key rotation); the subject no longer holds a grant (no role row bound to it and no
snapshotted group mapped on its connection, checked on every request, so deleting or changing a group
mapping ends the sessions it admitted; signal `session-grant-lapsed`); or the token predates a token-shape change
(`session-fault-upgrade-reauth`, `engine/src/admin/session.ts:306`). Independently of the session's
age, a sensitive action in `STEPUP_SUBS` requires a passkey session younger than `STEPUP_FRESH_MS`
(5 minutes) or a fresh single-use passkey assertion. An OIDC or SAML session of that age also
qualifies when it ends its own sessions. An Access caller needs an assertion issued within the same
5 minutes. Only an `ADMIN_TOKEN` caller, bare or through its exchanged session, is exempt from the
step-up gate.

---

## 3. File handling (ASVS V5.1.1)

The file-handling policy is `engine/docs/security/file-handling.md`. It enumerates every feature that
accepts a file (the console's identity.key, share and encrypted-key pickers, the pasted estate export, the
CLI's key and custody inputs, and the archive-read paths on the engine and the CLI), and states for each
the permitted type, extension and accept filter, the maximum size including the unpacked size, how a
download is made safe to open, and what the surface does with a malformed, oversized or malicious file.
The file-handling document cites the code that enforces each control, and a check keeps the two in agreement.

---

## 3a. Factor-loss re-proofing (ASVS V6.4.4)

ASVS V6.4.4 asks that when a multi-factor authentication factor is lost, identity proofing is
performed at the same level as at enrolment. The engine's own passkey front door meets this
through the recovery code, not through either credential this codebase also calls
"break-glass" (see the closing note below).

**The recovery code is minted at enrolment, not issued as a lesser fallback.** A completed
passkey registration mints a fresh recovery-code set for that email in the SAME call that
resolves the role, before the response is returned (`passkeyRegisterFinish`,
`engine/src/sched/scheduler-do-passkey.ts:400`, the recovery-code mint at `:578-597`). A mint
failure does not fail the enrolment; it is recorded as `recovery-codes-generation-failed`. Each
code carries 150 bits of CSPRNG
entropy (six hyphen-joined groups of five characters over a 32-symbol alphabet:
`RECOVERY_CODE_GROUPS` and `RECOVERY_CODE_GROUP_LEN`, `engine/src/admin/recovery.ts:45-46`;
the alphabet, `engine/src/admin/recovery.ts:51`), which clears the ASVS V6.5.2 / V11.5.1
112-bit lookup-secret floor (`engine/src/admin/recovery.ts:39-40`). Only a per-code salted
HMAC-SHA-256 of a code is ever stored; the plaintext is returned once, at generation, and
never stored, logged or shown again (`RecoveryCodeHash`, `engine/src/admin/recovery.ts:66-70`;
`hashOf`, `engine/src/admin/recovery.ts:199-207`). A code is single use: `verifyCode` returns
exactly one matching unconsumed slot, a consumed slot can never match again
(`engine/src/admin/recovery.ts:306-350`, the consumed check at `:345`), and the DO marks that
slot consumed before it mints the session (`engine/src/sched/scheduler-do-recovery.ts:442-443`).
`verifyCode` walks the whole set in constant time so neither a match position nor a wrong-code
timing signature leaks (`constantTimeEqual`, `engine/src/admin/recovery.ts:341`).

Presenting a code to `POST /admin/auth/recovery` is fail-closed rate-limited per IP and per
email and source before any record is read (`recoveryRateAllow`,
`engine/src/sched/scheduler-do-recovery.ts:370`), and an unknown email is verified against a
synthetic dummy record so a known and an unknown email cost the same work
(`dummyRecoveryRecord`, `engine/src/sched/scheduler-do-recovery.ts:402`). A wrong code, an
unknown email, an exhausted set and a throttle denial all answer the same generic failure
(`engine/src/sched/scheduler-do-recovery.ts:383`, `:436`); a rejected attempt is audited with
no actor named, because no identity is verified on a failure
(`engine/src/sched/scheduler-do-recovery.ts:437`, folded to one row per source and outcome per
minute), and a successful recovery is audited under the recovered email (`engine/src/sched/scheduler-do-recovery.ts:462-469`).

**A recovered session carries exactly the identity's existing authority, never a fresh
grant.** A successful `recoveryRecover` resolves the role through the same `resolveBoundEntry`
path every other sign-in uses, keyed on `passkeySubject(email)`, and mints a passkey-class
session at that role (`engine/src/sched/scheduler-do-recovery.ts:449-458`). An email that is no
longer on the roster but still holds an unconsumed code signs in to `viewer`, exactly as any
other unbound identity would (`engine/src/sched/scheduler-do-recovery.ts:449-450`); recovery
grants no authority the roster does not already confer.

**Re-enrolling a passkey after recovery passes the same live roster gate a fresh enrolment
does.** The recovered session is deliberately indistinguishable from an ordinary passkey
session, so a fresh credential is bound to it through the same door every self-add passes
through: `resolveRegistrationAuthorisation` requires the session's proven email to equal the
email being registered and, for the passkey method, re-reads the roster at the moment of the
ceremony, refusing when a populated roster no longer accounts for the address
(`engine/src/sched/scheduler-do-passkey.ts:260-296`, the roster check at `:288-292`). This is
the same roster re-check the invite arm applies to a brand-new enrolment
(`engine/src/sched/scheduler-do-passkey.ts:249-253`), so a role removed between the recovery
sign-in and the re-enrolment attempt closes the door exactly as it would for a first-time
invite. Regenerating the code set at this point is staged, not immediate: the fresh plaintext
is shown before the just-spent set is invalidated, and the live set is replaced only once the
operator confirms the new codes are saved (`generateRecoveryStaged`,
`engine/src/sched/scheduler-do-recovery.ts:210`; `confirmRecoveryStaged`,
`engine/src/sched/scheduler-do-recovery.ts:235`; invoked from the enrolment hook,
`engine/src/sched/scheduler-do-passkey.ts:594-600`), so a crashed browser mid-ceremony cannot
strand the operator with zero factors.

**A new invite for a member who enrolled before goes to that member only.** When a member has
lost every factor, an operator can change their role again, which mints a fresh registration
invite. For an address that has signed in before or ever held a passkey, the engine marks the
invite for the member (`setRole`, `engine/src/sched/scheduler-do-rbac-mutations.ts:219`), and
the role route sends it to the member's own email and removes the token from its response
(`withholdMemberInvite`, `engine/src/admin/router-sources.ts:413`). With no invite sender
configured, the response says the link was withheld, and the member re-enrols with a recovery
code. Only a first-time grant returns the link to the granting operator. Every enrolment through
an invite writes a `passkey-invite-enrol` audit row
(`engine/src/sched/scheduler-do-passkey.ts:571`) and raises the role-change alert
(`engine/src/admin/router-auth-flow.ts:642`). So an operator cannot use a re-invite to enrol a
key in an existing member's name without the member's email.

**What this is not.** Two other credentials in this codebase are also named "break-glass", and
neither is part of this re-proofing path. The `ADMIN_TOKEN` bearer is an
all-or-nothing credential that claims the first Owner and stays valid until retired (section 1.6); it carries
no email and cannot be presented as a specific enrolled identity, so it has no re-proofing role
for an existing member. The offline "break-glass key" (`BREAK_GLASS_PUBLIC`,
`engine/src/admin/status.ts:456`) is a capsule-recipient public key for decrypting backup DATA
offline (`loadRecipients`, `engine/src/keys-env.ts:65-66`; `sealToRecipients`,
`engine/src/crypto/capsule.ts:118`);
it authenticates nobody and is never read on any admin sign-in or enrolment path. The recovery
code documented above is the whole of the engine's factor-loss re-proofing.

**How it works.** The recovery code is a 150-bit secret issued at the same ceremony as the
passkey it backs up, consumed once under the same rate-limit and no-oracle discipline the rest
of the sign-in surface uses, and it can re-enrol a replacement passkey only through the
identical live roster check a fresh invite passes through. Factor loss lowers no bar an
attacker must clear and grants no authority the roster does not already confer.

---

## 4. ASVS mapping summary

| ASVS control | Section above | How it is addressed |
|--------------|---------------|--------|
| V6.3.3 - Multi-factor / phishing-resistant authentication | 1.1, 2.5 | first-party WebAuthn passkeys, user verification mandatory (`passkey.ts:278`, `:353`). |
| V6.5.x - Recovery / lookup-secret factor | 2.5 | single-use, salted-hash recovery codes (`recovery.ts:60`, `:66-70`). |
| V6.4.4 - Re-proofing at factor loss | 3a | recovery-code sign-in re-proofs through the same live roster gate a fresh enrolment uses and grants only the identity's existing role; passkey re-enrolment after recovery is refused unless the roster still accounts for the email (`scheduler-do-passkey.ts:288-292`). |
| V10.3.3 - Identity-provider group/role binding | 1.4 | additive group-to-role mapping, capped below owner, enforced in the scheduler DO (`setGroupRole`, `engine/src/sched/scheduler-do-rbac-mutations.ts:414`, the owner refusal at `:406`; `capGroupRole`, `engine/src/sched/scheduler-do-rbac.ts:389-399`). |
| V10.5.2 - Stable, unique identity key (iss+sub) | 1.2, 1.4 | authority keys on the immutable subject (`role:sub:<subject>`, `identity.ts:272`); email is display/audit only and a recycled email cannot inherit a role (`engine/src/sched/scheduler-do-rbac-authority.ts:83-141`, `roleForCaller`). |
| V7.1.1 - Session lifetime documented, with 800-63B justification | 2.1a | 12-hour absolute lifetime and 2-hour inactivity timeout stated with rationale and compensating controls; the inactivity deviation from NIST SP 800-63B revision 4 (§2.2.3, §2.3.3) is justified in §2.1a. |
| V7.1.2 - Concurrent session policy documented | 2.5 | unlimited concurrent sessions, no maximum-reached behaviour, count reduced only by a termination action. |
| V7.1.3 - Federated session systems and coordination documented | 2.7 | the four session-minting systems, their lifetime and termination coordination, and the re-authentication conditions are tabled in §2.7. |
| V7.2.2 / V7.3.2 / V7.5.1 - Session lifecycle | 2.1, 2.3, 2.5 | Passkey session: server-verified `__Host-` cookie, absolute 12h TTL, expiry checked each request (`session.ts:53`, `:357`). Access session controls remain Access-managed. |
| V7.6.1 - RP/IdP session lifetime and termination behave as documented | 2.5, 2.7 | SAML sessions are capped at `SessionNotOnOrAfter` (`saml/assertion.ts:277-278`, `session.ts:254`). OIDC sessions carry no IdP bound (`scheduler-do-idp.ts:1012` passes none; the comment at `scheduler-do-idp.ts:455-458` records id_token-exp capping as a recorded, unbuilt follow-up), so an OIDC-federated session runs to the flat 12-hour cap regardless of a shorter upstream bound, with no re-authentication forced when that bound is reached. Both facts are stated on the customer session-management page. Accepted with reason pending the fix: thread the id_token `exp` into `nativeSessionIssue` the way the SAML ACS already does. |
| V7.4.3 / V7.4.5 - Terminate a user's sessions (admin) | 2.4 | `terminate-user` / `terminate-all` bump the epoch / rotate the key (`engine/src/sched/scheduler-do-session.ts:613-637`, `:266-286`). |
| V7.5.2 - View and terminate any or all active sessions (self), having authenticated again | 2.4 | `GET /admin/sessions` lists the caller's live sessions by per-session id; `POST /admin/sessions/terminate` ends one and `terminate-others` ends the rest, both step-up gated (`engine/src/admin/router-account-session.ts`, `engine/src/sched/scheduler-do-session.ts`, `STEPUP_SUBS` in `engine/src/admin/router-core.ts`). |
| V8.1.3 - Documented contextual attributes for security decisions | 2.6 | the attributes evaluated (session age and inactivity, connection identity, request origin, subject continuity, action sensitivity, source IP) and the attributes not evaluated (time of day, location, IP reputation, device) are defined in section 2.6, with a `file:line` for each use. |
| V8.1.4 - Attributes, thresholds and actions for contextual decisions | 2.6 | the contextual decision table in section 2.6 states, per factor, where it is evaluated, the threshold rendered from the exported constant, and the action taken (allow, deny, step-up challenge, notify). `engine/test/validate-contextual-authz-docs-parity.ts` holds the table to the code. |
| V8.2.4 - Adaptive controls at session start and during the session | 2.6 | adaptive controls are applied at both points as documented in section 2.6 (user verification, connection and origin binding at start; inactivity timeout, per-request role re-resolution, revocation-axis and origin checks, and risk-based step-up during the session). Contextual binding runs in the customer's own account, so it carries no vendor-custody implication. |
| V5.1.1 - Documented file types, extensions, maximum and unpacked sizes, and safe download and processing for each file-accepting feature | 3 | `engine/docs/security/file-handling.md` sections 2 to 5, kept in agreement with the cited trees by an automated check. |
