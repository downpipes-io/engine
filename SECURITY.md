# Security Policy -- downpipes-io/engine

The engine is a TypeScript Cloudflare Worker (plus Durable Objects, including the scheduler) that
runs entirely inside the **customer's own Cloudflare account**. It is the cryptographic
backup and restore pipeline: it seals every record with a PQ-hybrid envelope before
writing any data to a destination. It holds public key material, the signing key and,
only in the two-recipient posture the operator chooses, the operational
private key. It never holds the break-glass private key.

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security findings.**

Our Vulnerability Disclosure Policy, https://maelstrom.au/trust/security/disclosure, is the
one policy for reports on this repository. Where this file and that policy differ, the
policy applies.

Report via email to:

    security@maelstrom.au

Include:

- a description of the vulnerability and the affected component;
- reproduction steps, a proof-of-concept, or a test vector if you have one;
- the potential impact as you understand it;
- your preferred contact for follow-up.

We will acknowledge your report within **2 business days** and keep you informed
throughout remediation. We will coordinate public disclosure with you and credit you
by name (or anonymously, if you prefer) once the fix is shipped.

We do not operate a bug-bounty programme at this time.

For an encrypted report, use our OpenPGP key: https://maelstrom.au/.well-known/security.asc
(fingerprint 3AFA 3933 B25B 53B9 DBFA 1464 B047 75F6 8767 EF48).

### Coordinated disclosure window

We follow a **90-day coordinated-disclosure** model. We ask that you give us up to 90
days from the date you report a finding before any public disclosure, so we can
confirm, remediate and ship a fix. If a fix is ready sooner we will disclose sooner,
and we will agree any extension with you in writing if a finding is unusually hard to
remediate. We will never ask you to delay disclosure indefinitely.

### Safe harbour

We will not pursue or support legal action against anyone who, in good faith and in
line with this policy, discovers and reports a vulnerability. Good-faith research means
you avoid privacy violations, data destruction and any interruption or degradation of
service; you only ever interact with accounts you own or have explicit permission to
test; you do not access, modify or retain customer data beyond the minimum needed to
demonstrate the finding; and you give us a reasonable time to remediate before public
disclosure. Activity conducted consistently with this policy is considered authorised,
and we will work with you to understand and resolve the issue quickly. This safe
harbour does not extend to violations of applicable law or to testing against
infrastructure you do not control. The engine runs in the customer's own Cloudflare
account, so test only against your own deployment.

---

## Risk-based remediation SLA

These timeframes run from the date a finding is confirmed (that is, triaged and
reproduced, not merely reported).

| Severity  | Definition (examples)                                         | Target remediation  |
|-----------|---------------------------------------------------------------|---------------------|
| Critical  | RCE, authentication bypass, plaintext key exfiltration        | 2 business days     |
| High      | Privilege escalation, authentication downgrade, data exposure | 7 calendar days     |
| Medium    | Defence-in-depth bypass, rate-limit absence, SSRF vector      | 30 calendar days    |
| Low       | Missing header, documentation gap, informational finding      | 90 calendar days    |

**Exception path.** Where the fix requires a coordinated release (for example a breaking
crypto-format change that must be mirrored in the Go reader), the target may be
extended by up to 30 days with a written internal risk-acceptance record. No extension
applies to Critical or High findings.

**Severity assignment** follows the CVSS 4.0 base score, adjusted for the in-account
no-custody architecture (a finding that requires a prior account compromise is
down-scoped accordingly).

---

## Supported versions and branches

| Branch / tag | Status           | Notes                                    |
|-------------|------------------|------------------------------------------|
| `main`      | Supported        | All security fixes land here first       |
| Tagged releases | Supported for 90 days after tag | Fixes backported on request for Critical/High |
| Older releases | Not supported  | Upgrade to the latest tag                |

Deployments are manual (`npm run deploy`). There is no automatic rollout; operators
are responsible for pulling and deploying fixes within the SLA window above. Use
`npm run deploy` for the engine, not a bare `wrangler deploy`: it preserves every
console-attached source binding (via `scripts/sync-bindings.mjs`, fail-closed),
whereas a bare `wrangler deploy` would silently drop them.

---

## Dependency vulnerability handling

### Detection

Two automated mechanisms detect advisories. The first runs on every push and pull request
against `main` (`.github/workflows/ci.yml`). The second runs weekly.

1. **`npm audit --omit=dev --audit-level=high`** (the `security` job) -- scans
   production dependencies and fails the build on any High or Critical advisory.
   The same job then runs `scripts/dependency-advisory-gate.mjs` over every
   lockfile, dev dependencies included. It fails on any advisory, at any severity,
   that `.github/dependency-advisories.json` does not acknowledge. That file can
   acknowledge a dev-only advisory with a reason. It cannot acknowledge a
   production advisory.

2. **Dependabot** (`.github/dependabot.yml`) -- opens weekly pull requests for both
   `npm` packages and GitHub Actions pins, keeping the supply chain current.

The `step-security/harden-runner` action is pinned to a full commit SHA in every
job that runs it, and every `actions/checkout` step runs with `persist-credentials: false`, so
compromised upstream action tags cannot inject credentials.

### Response

- A `npm audit` finding at **High or Critical** fails the `security` job, which is
  in the `CI Success` needs list, so `CI Success` goes red with it, and that blocks
  the merge. `main` in this repository is protected by an active repository ruleset
  with no bypass actors. It requires a pull request (no approving review is
  required) and a passing `CI Success` status check on a branch that is up to date
  with `main`. It also blocks force pushes to `main` and deletion of `main`. The
  finding must be resolved (an upgrade, a patch or an npm `overrides` entry) before
  the pull request can merge. A production advisory has no acknowledgement path.
- **Medium and below** advisories also fail the `security` job, through the advisory
  gate, until they are fixed or, for a dev-only dependency, acknowledged with a reason
  in `.github/dependency-advisories.json`. They are remediated within the SLA above.
- Dependabot PRs for security advisories are reviewed and merged within the
  applicable SLA window. Non-security version bumps are reviewed weekly.

### Crypto dependencies

The engine's cryptographic dependencies (`@noble/curves 2.4.0`,
`@noble/hashes 2.4.0` and `@noble/post-quantum 0.7.1`, exact-pinned in
`package.json`) are the most security-sensitive. They implement X25519 + ML-KEM-1024
key encapsulation, ML-DSA-87 signatures, Ed25519 public-key derivation, and the
incremental SHA-384 and HMAC-SHA-384 that the streaming AES-256-GCM seal uses (CNSA-2.0
PQ-hybrid; AES-256-GCM and the Ed25519 signature itself are Web Crypto). Advisories
against these libraries are treated as **at least High** regardless of the CVSS base score, because a break in any of them directly
affects the confidentiality and integrity of every backup archive.

---

## Security architecture summary

This section records the controls that are actually implemented, so that a
security review can quickly locate the relevant source.

**Authentication.** Every `/admin/*` request outside `/admin/health` and the sign-in
ceremonies (`/admin/auth/*`, `/admin/oidc/*`, `/admin/saml/*`) is authenticated by one of three
methods in strict anti-downgrade precedence (`src/admin/auth.ts`): a Cloudflare
Access RS256 JWT (verified server-side in `src/admin/access.ts`); a first-party
WebAuthn PASSKEY session (the engine is its own IdP - `src/admin/passkey.ts`
verifies, `src/admin/session.ts` mints the signed session cookie); or the
bootstrap-only `ADMIN_TOKEN` bearer (a one-way `bootstrapConsumed` latch;
retired in-app or disabled via `ADMIN_TOKEN_DISABLED`). No first-party
PASSWORDS (those stay at the customer's IdP via Access), but downpipes DOES
implement first-party MFA-grade auth: WebAuthn passkeys with mandatory user
verification (phishing-resistant), single-use salted-hash RECOVERY CODES as the
ongoing break-glass, and a signed server-verified session. Sessions are revocable: a
per-email EPOCH backs self terminate-others and admin per-user termination, and an
owner-only global key rotation ends every session (`src/sched/scheduler-do-session.ts`). The role lookup keys
on the immutable Access `(iss, sub)`, passkey or IdP subject. Sessions, the session epoch and
pending invites key on the email.

**Authorisation.** Capability-based RBAC over six built-in roles (`viewer`, `operator`,
`approver`, `restore-operator`, `access-admin`, `owner`) plus composable custom roles is enforced at the router (`src/admin/router.ts`) and independently
re-checked inside the Durable Object (`src/sched/scheduler-do.ts`). Restore
approval is an owner opt-in (`requireRestoreApproval`, off by default). When it is
on, restore approvals require dual-control (maker cannot equal checker), are bound
to a recomputed plan hash, are single-use, and carry a lazy expiry. The approval
record carries the plan the hash binds (write target, scope, `onExisting`), so the
approver reads what they authorise, and the restore audit events name the same
write target. Turning it off
needs a second Owner's approval (only the break-glass token turns it off at once),
and every disarm raises a `dual-control-disabled` alert. A change to the policy, on or
off, needs a fresh re-authentication (step-up). A retention-prune apply always
needs a second approver. A downpipe edit that lets the scheduled prune delete more (arming
`retention.enforce`, or widening an armed policy) queues for a different holder of
`restore.approve` whenever one exists. The break-glass token, or an editor whom nobody else
could approve, applies it at once and raises a `retention-armed-alone` alert.

**Cryptography.** PQ-hybrid: X25519 + ML-KEM-1024 KEM; Ed25519 + ML-DSA-87
signatures; AES-256-GCM STREAM; HKDF-SHA-384 / HMAC-SHA-384. No downgrade path --
both halves of each hybrid are mandatory. The break-glass private key is never
present in the running Worker.

**Audit.** SHA-384 hash-chained, append-only audit log (`src/admin/audit.ts`).
Redaction is by construction (closed event-type union). Export carries the chain
head for SIEM import.

**Transport.** HSTS (`max-age=63072000; includeSubDomains`), `X-Content-Type-Options:
nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`,
`Cache-Control: no-store` on all `/admin` responses (`src/index.ts`).

---

## Outbound network calls

The engine runs in the customer's account and reaches the network in two ways.

**Fixed vendor hosts, enumerated in one module.** `src/lib/outbound.ts` is the only place a vendor host is
written: `api.cloudflare.com` (the Cloudflare API and GraphQL, for source discovery, attach, deploy, media
restore, the workers and configuration sources and the cost estimate), `cloudflare-dns.com` (the
DNS-over-HTTPS lookup the egress screen makes before a sink delivery), `update.downpipes.io` (the signed
update channel; `UPDATE_CHANNEL_URL` and every artefact URL the channel names must resolve to this host or
the update is refused with the `url-config` fault) and `login.microsoftonline.com` (Entra, when an Azure
destination authenticates that way), plus the suffixes `*.cloudflareaccess.com` (the Access team's JWKS),
`*.cloudflarestream.com` (Stream source bytes) and `*.amazonaws.com` (`sts.<region>` for an STS-brokered S3
destination). `test/validate-outbound-policy.ts` refuses a vendor host literal anywhere else in `src/`.

**Operator-configured hosts, screened at their boundary.** Archive destinations (an S3-compatible or Azure
endpoint), notification channels and SIEM or OTLP sinks, and an identity provider are hosts the operator
typed. Each is screened when stored and again at send time: https only (TLS for a syslog sink), and no
loopback, private, link-local or IPv4-mapped address. A notification, SIEM or OTLP sink and an OIDC issuer
also refuse userinfo. A sink's name is resolved and every answer classified before the request is issued (`src/notify/types.ts`,
`src/admin/oidc-issuer-safety.ts`, `src/dest/`). A private sink is a named non-delivery unless the
operator opts in per channel.

**No call follows a redirect.** Every outbound `fetch` carries `redirect: "manual"`, so a 3xx is a failed
call rather than a request replayed to another host with the bearer attached. The one bounded exception is
the source byte fetch's single hop for Cloudflare Stream (`src/sources/byte-fetch.ts`), gated on the
source's own allow-list predicate with the bearer stripped across origins. The same validator refuses a new
outbound call site that does not state its redirect policy.

## Known open findings

downpipes makes no claim against the OWASP ASVS 5.0 standard for the platform. An
assessment of the identity and SSO component records no high or critical findings. It records three gaps, and none of them is an
authentication bypass. This is their status in the code:

- **G1 (low), fixed: per-caller rate limit on the IdP connection-management routes.** All
  four (`POST /idp/connections`, `/delete`, `/enabled` and `/cert`) call `rateLimited` after
  their `keys.ceremony` gate (`src/admin/router-identity.ts:867`,
  `895`, `909`, `931`).
- **G2 (low), fixed: SAML assertion id replay.** The ACS refuses an assertion id it has
  seen before `notOnOrAfter`
  (`src/sched/scheduler-do-idp-saml.ts:224-227`), and the alarm sweep prunes the expired
  ids (`src/sched/scheduler-do-scheduling.ts:774-775`).
- **G3 (informational), open.** Session mint applies no length bound of its own
  (`signSession`, `src/admin/session.ts:245`). The assessment asks for no fix: the inputs
  are server-derived, and the read path bounds every field (`SESSION_EMAIL_MAX`,
  `SESSION_SUBJECT_MAX` and `SESSION_CONN_ID_MAX`, `src/admin/session.ts:181-186`).

These are the controls the assessment covers:

- Authority keys on the immutable Access `(iss, sub)` / passkey subject
  (`src/admin/access.ts`, `src/admin/identity.ts`, `src/sched/scheduler-do-rbac.ts`);
  a recycled email cannot inherit a departed member's role.
- A per-email session epoch backs the self terminate-others and admin terminate-user
  routes and a passkey-credential revoke route (`src/admin/router-account-session.ts:94`,
  `179`, `221`; `bumpSessionEpoch`, `src/sched/scheduler-do-session.ts:396`). Owner
  terminate-all rotates the session signing key instead (`src/admin/router-account-session.ts:282`,
  `terminateAllSessions`, `src/sched/scheduler-do-session.ts:265`). They cover V7.4.3.
  For V7.5.2: an OIDC, OAuth2 or SAML caller lists and ends only the sessions of its own
  signed-in subject. A passkey, recovery-code or Access caller lists and ends every session
  recorded under its email, including a native session of another subject that asserts the same
  email (`test/validate-session-subject-keyed.ts`).

The assessment also covers these controls:

- `requireHttpsEndpoint` in `src/dest/s3-addressing.ts:28-45` rejects any non-https
  `DEST_ENDPOINT` at construction time. `http://localhost`, `http://127.0.0.1` and
  `http://[::1]` pass only when the caller sets `allowInternalEndpoint`, and no
  production caller sets it. The `UPDATE_CHANNEL_URL` check in
  `src/admin/updates.ts:693-695` refuses a non-https channel. `isPermittedEndpoint` in
  `downpipe/internal/source/s3.go:104-117` applies the https rule for the Go CLI; it
  accepts plain http only to those three loopback hosts, for local test servers.
- Every outbound fetch in `src/dest/s3.ts` uses `redirect:"manual"`
  and treats any 3xx as a hard error (`src/dest/s3.ts:458-466`, `530-535`, `769-776`); the
  update-channel fetch uses `redirect:"manual"` and treats any non-2xx as a failure
  (`src/admin/updates.ts:978-979`); the Go CLI's two `http.Client`s refuse all redirects
  via `CheckRedirect` returning `http.ErrUseLastResponse`
  (`downpipe/internal/source/s3.go:154-156`, `164`, `168`).
- Per-caller fixed-window rate limiting (120 requests per 60 s) runs before the handler on
  every mutating admin route behind the authorisation gate (`rateLimited`,
  `src/admin/router-core.ts:303`), keyed on the verified caller's stable subject rather than
  source IP (`rateLimitKey`, `src/admin/router-core.ts:218-220`). `test/validate-ratelimit.ts`
  drives the 429 and reads every mutating case in the `src/admin/router*.ts` spokes for the
  call. Two POST routes do not take this check: `/admin/session/bootstrap` accepts only
  the bare `ADMIN_TOKEN`, which has its own throttle (below), and `/admin/policy/require-access`
  is a read. The demo reset and the harness test-fault routes exist only when `DEMO_MODE` or
  `HARNESS_TEST_FAULTS` is set.
- Credential-guessing throttles: the unauthenticated sign-in ceremonies under
  `/admin/auth/*`, `/admin/oidc/*`, `/admin/saml/*` and `/scim/v2` admit at most 30 requests
  per 60 seconds per source address and deny the request on any limiter fault
  (`authRateLimited`, `src/admin/router-core.ts:629`); a recovery-code sign-in admits at
  most 5 attempts per 60 seconds per email and, separately, per source address, denying on
  either bucket or a limiter fault (`recoveryRateAllow`,
  `src/sched/scheduler-do-recovery.ts:516`); and the bare `ADMIN_TOKEN` bearer compare is
  preceded by its own cap of 10 requests per 60 seconds per source address, checked before
  the constant-time compare and denying on any limiter fault (`src/admin/auth.ts:340`,
  `adminTokenRateLimitedViaDO`, `src/admin/router-session.ts:337`).

If you believe you have found an exploitable path that builds on any control above,
please report it privately rather than assuming it is already known.
