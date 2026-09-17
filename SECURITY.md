# Security Policy -- downpipes-io/engine

The engine is a TypeScript Cloudflare Worker (plus a Durable Object scheduler) that
runs entirely inside the **customer's own Cloudflare account**. It is the cryptographic
backup and restore pipeline: it seals every record with a PQ-hybrid envelope before
writing any data to a destination, and it holds only public key material and the
signing key -- never the break-glass private key.

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security findings.**

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

Two automated mechanisms run on every push and pull request against `main`
(`.github/workflows/ci.yml`):

1. **`npm audit --omit=dev --audit-level=high`** (the `security` job) -- scans
   production dependencies and fails the build on any High or Critical advisory.
   Dev-only dependencies are excluded because they never ship in the Worker bundle.
   Nothing else here reads them either, so an advisory reachable only through
   `devDependencies` is ungated: it will not fail a run at any severity, and it is
   not enumerated anywhere. That is the deliberate scope, not an oversight, and it
   is narrower than the build toolchain a reader might assume it covers.

2. **Dependabot** (`.github/dependabot.yml`) -- opens weekly pull requests for both
   `npm` packages and GitHub Actions pins, keeping the supply chain current.

The `step-security/harden-runner` action is pinned to a full commit SHA in every
workflow job, and `actions/checkout` is run with `persist-credentials: false`, so
compromised upstream action tags cannot inject credentials.

### Response

- A `npm audit` finding at **High or Critical** fails the `security` job, which is
  in the `CI Success` needs list, so `CI Success` goes red with it. It does not
  mechanically block a merge: `main` in this repository carries no branch
  protection and no repository ruleset, so no status check is required and nothing
  stops a merge or a direct push over a red run. The finding must still be resolved
  (upgrade, patch, or justified override with a risk-acceptance comment) before any
  code lands; that is a rule people follow, not one the platform enforces.
- **Medium and below** advisories from `npm audit` do not block CI but are reviewed
  in the weekly Dependabot sweep and remediated within the SLA above.
- Dependabot PRs for security advisories are reviewed and merged within the
  applicable SLA window. Non-security version bumps are reviewed weekly.

### Crypto dependencies

The engine's cryptographic dependencies (`@noble/curves 2.4.0`,
`@noble/post-quantum 0.6.1`, sourced from `package.json`) are the most
security-sensitive. These implement X25519 + ML-KEM-1024 key encapsulation,
Ed25519 + ML-DSA-87 signatures, and AES-256-GCM streaming (CNSA-2.0 PQ-hybrid).
Advisories against these libraries are treated as **at least High** regardless of
the CVSS base score, because a break in either library directly affects the
confidentiality and integrity of every backup archive.

---

## Security architecture summary

This section records the controls that are actually implemented, so that a
security review can quickly locate the relevant source.

**Authentication.** Every `/admin/*` request is authenticated by one of three
methods in strict anti-downgrade precedence (`src/admin/auth.ts`): a Cloudflare
Access RS256 JWT (verified server-side in `src/admin/access.ts`); a first-party
WebAuthn PASSKEY session (the engine is its own IdP - `src/admin/passkey.ts`
verifies, `src/admin/session.ts` mints the signed session cookie); or the
bootstrap-only `ADMIN_TOKEN` bearer (a one-way `bootstrapConsumed` latch;
retired in-app or disabled via `ADMIN_TOKEN_DISABLED`). No first-party
PASSWORDS (those stay at the customer's IdP via Access), but downpipes DOES
implement first-party MFA-grade auth: WebAuthn passkeys with mandatory user
verification (phishing-resistant), single-use salted-hash RECOVERY CODES as the
ongoing break-glass, and a signed server-verified session with a per-email
EPOCH so sessions are revocable (self terminate-others, admin per-user, and an
owner-only global key rotation - `src/sched/scheduler-do.ts`). Identity keys on
the immutable Access `(iss, sub)` / passkey subject, never the mutable email.

**Authorisation.** Capability-based RBAC over six built-in roles (`viewer`, `operator`,
`approver`, `restore-operator`, `access-admin`, `owner`) plus composable custom roles is enforced at the router (`src/admin/router.ts`) and independently
re-checked inside the Durable Object (`src/sched/scheduler-do.ts`). Restore
approvals require dual-control (maker cannot equal checker), are bound to a
recomputed plan hash, are single-use, and carry a lazy expiry.

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
typed. Each is screened when stored and again at send time: https only, no userinfo, no loopback,
private, link-local or IPv4-mapped address, and the name is resolved and every answer classified before
the request is issued (`src/notify/types.ts`, `src/admin/oidc-issuer-safety.ts`, `src/dest/`). A private
sink is a named non-delivery unless the operator opts in per channel.

**No call follows a redirect.** Every outbound `fetch` carries `redirect: "manual"`, so a 3xx is a failed
call rather than a request replayed to another host with the bearer attached. The one bounded exception is
the source byte fetch's single hop for Cloudflare Stream (`src/sources/byte-fetch.ts`), gated on the
source's own allow-list predicate with the bearer stripped across origins. The same validator refuses a new
outbound call site that does not state its redirect policy.

## Known open findings

An OWASP ASVS 5.0 assessment covers the identity/SSO component (the core security
control) at Level 2/3, recorded in the in-repo
[`docs/asvs-5.0-assessment.md`](docs/asvs-5.0-assessment.md); the full-platform
assessment is part of the security pack available on request. It records no high or
critical findings and no unresolved Level 1 or Level 2 items. These are the controls
the assessment covers:

- Authority keys on the immutable Access `(iss, sub)` / passkey
  subject (`src/admin/access.ts`, `src/admin/identity.ts`, `src/sched/scheduler-do.ts`);
  a recycled email cannot inherit a departed member's role.
- A per-email session epoch backs termination routes (self terminate-others, admin
  terminate-user, owner terminate-all) and a passkey-credential revoke route
  (`src/sched/scheduler-do.ts`, `src/admin/session.ts`), covering V7.5.2 and
  V7.4.3/V7.4.5.

The assessment also covers these controls:

- `requireHttpsEndpoint` in `src/dest/s3-addressing.ts:32-49` rejects any
  non-https `DEST_ENDPOINT` at construction time (the only exception is
  `http://localhost` and `http://127.0.0.1` for local test loopbacks); the
  `UPDATE_CHANNEL_URL` check in `src/admin/updates.ts:701-702` applies the same guard; and
  `isPermittedEndpoint` in `downpipe/internal/source/s3.go:92-105` enforces the same rule
  for the Go CLI.
- Every outbound fetch in `src/dest/s3.ts` uses `redirect:"manual"`
  and treats any 3xx as a hard error (`src/dest/s3.ts:373-380`, `418-424`, `626-632`); the update-channel fetch does the same (`src/admin/updates.ts:987-990`); the Go
  CLI `http.Client` refuses all redirects via `CheckRedirect` returning
  `http.ErrUseLastResponse` (`downpipe/internal/source/s3.go:142-144`).
- Per-caller fixed-window rate limiting (120 requests per 60 s) is
  enforced on every mutating admin route (`rateLimited`, `src/admin/router-core.ts:282`),
  keyed on the verified caller's stable subject rather than source IP
  (`rateLimitKey`, `src/admin/router-core.ts:192-198`).
- Credential-guessing throttles: the unauthenticated sign-in ceremonies under
  `/admin/auth/*`, `/admin/oidc/*`, `/admin/saml/*` and `/scim/v2` admit at most 30 requests
  per 60 seconds per source address and deny the request on any limiter fault
  (`authRateLimited`, `src/admin/router-core.ts:595`); a recovery-code sign-in admits at
  most 5 attempts per 60 seconds per email and, separately, per source address, denying on
  either bucket or a limiter fault (`recoveryRateAllow`,
  `src/sched/scheduler-do-recovery.ts:527`); and the bare `ADMIN_TOKEN` bearer compare is
  preceded by its own cap of 10 requests per 60 seconds per source address, checked before
  the constant-time compare and denying on any limiter fault (`src/admin/auth.ts:340`,
  `adminTokenRateLimitedViaDO`, `src/admin/router-session.ts:336`).

If you believe you have found an exploitable path that builds on any control above,
please report it privately rather than assuming it is already known.
