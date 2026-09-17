# Field-level access matrix

**Standard:** OWASP ASVS 5.0 - V8.1.2 ("Authorization documentation defines field-level access
restrictions (read and write) based on consumer permissions and resource attributes")
**Scope:** the engine's admin API (src/admin)
**Date:**

This document is the field-level authorization record V8.1.2 asks for: for every sensitive field
or field group the admin API exposes, who may read it and who may write it, expressed as the
engine's own capability model rather than as prose that can drift from the code. It supersedes no
prior document; no field-level matrix existed before this one.

**This document is held to the code.** `test/validate-field-access-matrix.ts` (run in
`npm run validate`, `validate:chain`) recomputes every read/write column below from
`ROLE_CAPABILITIES` (`src/admin/identity-rbac.ts`) via `can()`, checks the two owner-reserved rows
against `OWNER_RESERVED_CAPABILITIES`, checks the step-up overlay against `STEPUP_SUBS`
(`src/admin/router-core.ts`) by set equality, checks the machine-bearer surfaces against
`IngestScope` (`src/admin/support-ingest.ts`) and the SCIM synthetic-caller predicate
(`src/admin/identity.ts`), and confirms every `file:line` citation below still contains the text
it is cited for. A capability added to or removed from a role, a route regated to a different
capability, a route added to or removed from `STEPUP_SUBS`, or a citation that drifts to the wrong
line all fail that gate before they fail anyone reading this page.

---

## 1. Consumer permission model (caller classes)

Every request to the admin API resolves to exactly one `Caller` (`src/admin/identity.ts`), which
carries a `role` and, for a composable custom role, a resolved `capabilities` set
(`identity-rbac.ts`). Section 2 below is keyed on **capability**, not role, because a composable
custom role holds an arbitrary subset of capabilities rather than one of the six names below; the
six built-in roles are the fixed points the capability grants are pinned against.

| Caller class | How it authenticates | Authority |
|---|---|---|
| **viewer** | Access JWT / passkey / OIDC / SAML session resolved to this role in the role table | Reads plus the two read-safe restore-proof capabilities (`restore.dryrun`, `restore.verify`). The least-privilege resting role; a new member defaults here. |
| **operator** | as above | Viewer's reads plus data operations (create/edit/delete a downpipe, trigger a run, run a drill), the operational config (notify/expiry/scheduled-test), and raising a restore request. No apply/approve, no people, no keys. |
| **restore-operator** | as above | A narrow role, NOT on the cumulative ladder: viewer's reads, drill, and the full restore lifecycle (request/apply/approve). Cannot create/edit/delete a downpipe, configure notify/expiry, or manage people or keys. |
| **approver** | as above | Operator's powers plus restore apply/approve. |
| **access-admin** | as above | A narrow role: viewer's reads plus `roles.write` and `access.policy` (people and account governance only). No data write, no restore apply, no keys. |
| **owner** | as above, or the `ADMIN_TOKEN` bearer (see below) | Every capability, including the two owner-reserved ones no other role or custom role may ever hold: `keys.ceremony` and `posture.riskaccept`. |
| **custom role** | Access JWT / passkey / OIDC / SAML, resolved via an account-defined named bundle | An arbitrary subset of the creator's own capabilities (`validateCustomRole`, `identity-rbac.ts`), minus the two owner-reserved capabilities, which a custom role can never hold regardless of who composes it. |
| **`ADMIN_TOKEN` break-glass** | A pre-shared bearer token, compared constant-time | Resolves **unconditionally** to owner (`src/sched/scheduler-do-rbac-authority.ts:110`). Not attributable to an email (`actorEmail: null`); can be permanently disabled (`ADMIN_TOKEN_DISABLED`) or retired in-app once an Owner passkey exists. |

### Machine-bearer surfaces

Three non-interactive surfaces sit **outside** the Capability model entirely: they are governed by
their own dedicated bearer secrets and their own narrow, hard-coded scope, never by `gate()` /
`Capability`. They are listed here because V8.1.2 asks for every consumer class, not only the ones
the capability table already names.

| Surface | Bearer | What it may READ | What it may WRITE |
|---|---|---|---|
| **SCIM deprovision** (`/scim/v2/Users/{id}`) | `SCIM_BEARER_TOKEN`, a dedicated secret separate from `ADMIN_TOKEN` (`src/admin/scim.ts:14`); unset means the whole surface is 503 | Nothing. This is a write-only facade; it has no GET/list route on a user record. | Exactly one field: the named member's row in the role table, and only by removing it (the same offboarding `POST /roles/delete` drives). It acts through a stable synthetic caller (`SCIM_OFFBOARD_EMAIL`/`SCIM_OFFBOARD_SUBJECT`, `src/admin/identity.ts`), recognised only by that exact `{method:"token", email, subject}` triple, never a real owner grant a token holder could otherwise reach. |
| **Metrics scrape** (`/metrics`) | A platform-issued ingest credential, scope `"metrics"` (`src/admin/support-ingest.ts`); dedicated, READ-ONLY (`src/admin/metrics.ts:6`) | Only the Prometheus series already derivable from `GET /downpipes`, `/history` and `/replication`: per-downpipe freshness, run counters, duration, size and destination-health gauges. Never a config field, a secret, an endpoint, or a record value. | Nothing. |
| **Support pull** (`/support/diagnostics`, `/support/audit-feed`) | A platform-issued ingest credential, scope `"diagnostics"` or `"audit-feed"` | `diagnostics`: the redaction-safe support bundle (version, presence-only status, preflight, run-history rows, notify outcomes, licence tier - never a key, secret, endpoint or customer data value). `audit-feed`: the hash-chained audit event stream, same fields `GET /admin/audit` returns. | Nothing (both scopes are pull-only). |

Minting or revoking any of the three ingest credentials is itself **owner-role-exclusive by a bare
`caller.role !== "owner"` check, deliberately NOT a `gate(caller, cap)` call**
(`src/admin/router-status.ts:370`), so this authority can never be composed into a custom role by
accident, and it additionally requires a second owner's dual-control approval before the secret is
minted (`ownerActionGate`, same file). SCIM's own offboard action, by contrast, needs no such
grant: it merely replays the existing `roles.write`-gated offboarding path under a synthetic caller
that is `owner`-authoritative by construction, never by capability.

---

## 2. Field-level matrix (capability = the field-level access restriction)

Every capability in the closed `Capability` union (`identity-rbac.ts`) governs exactly one field or
field group below; the partition is exhaustive (`test/validate-field-access-matrix.ts` asserts all
21 capabilities are covered by exactly one row). "Read holders" / "write holders" are the caller
classes from section 1 that the capability is granted to; a custom role reaches a row only if its
composed capability set includes that row's capability.

| Field / resource group | Read cap | Write cap | Read holders | Write holders | Step-up on write | Evidence |
|---|---|---|---|---|---|---|
| Downpipe configuration | `downpipe.read` | `downpipe.write` | all six roles | operator, approver, owner | no | `router.ts:591`; `router-pipelines.ts:41` |
| Downpipe deletion | - | `downpipe.delete` | - | operator, approver, owner | no | `router-pipelines.ts:89` |
| Manual run trigger | - | `run.trigger` | - | operator, approver, owner | no | `router-pipelines.ts:136` |
| Restore drill (recovery test) | - | `drill.run` | - | operator, restore-operator, approver, owner | yes, `/attest/session/create` (starting an attended session) | `router-ops.ts:70` |
| Restore dry-run preview | `restore.dryrun` | - | all six roles | - | n/a | `router-restore.ts:575` |
| Restorability proof (blind restore test / keyless attest) | `restore.verify` | - | all six roles | - | n/a | `router-restore.ts:621,867` |
| Restore request | - | `restore.request` | - | operator, restore-operator, approver, owner | no | `router-restore.ts:701` |
| Restore apply (overwrites live data) | - | `restore.apply` | - | restore-operator, approver, owner | yes, on `confirm:true` (direct `requireStepUp()` call, not a `STEPUP_SUBS` string; see router-core.ts's "second exception" comment) | `router-restore.ts:240` |
| Restore approve (dual-control) | - | `restore.approve` | - | restore-operator, approver, owner | yes, on the approve leg (a direct call, not a `STEPUP_SUBS` string) | `router-restore.ts:794` |
| Member / role table (read) | `roles.read` | - | all six roles | - | n/a | `router-rbac.ts:171` |
| Member / role table (grant/revoke) | - | `roles.write` | - | access-admin, owner | yes: `/roles`, `/roles/delete`, `/group-roles`, `/group-roles/delete`, `/custom-roles`, `/custom-roles/delete` | `router-rbac.ts:43` |
| Account governance policy (break-glass retirement, session termination, custody-share email, control-plane export/import) | - | `access.policy` | - | access-admin, owner | yes: `/policy/retire-break-glass-token`, `/passkey/credentials/delete`, `/signin-factors/revoke`, `/sessions/terminate`, `/sessions/terminate-others`, `/sessions/terminate-user`, `/sessions/terminate-all`, `/custody/send-share`, `/support/credentials` (bare owner-role check, see section 1) | `router-rbac.ts:177`; `router-identity.ts:390` |
| Audit log | `audit.read` | none (append-only; DO-internal `appendAudit` only, no external caller can write an entry) | all six roles | - | n/a | `router-rbac.ts:291`; `docs/security/data-classification.md` s2.11 |
| Trust roots and egress targets (key ceremony, destinations, IdP connections, SIEM/OTLP push targets) | - | `keys.ceremony` (**owner-reserved**; never composable into a custom role) | - | owner only | yes: `/keys/*`, `/destination*`, `/push*`, `/otlp-push*`, `/idp/connections*` | `router-keys.ts:300`; `router-destinations.ts:328`; `router-identity.ts:834`; `router-push.ts:232` |
| Notification rules and channels | - | `notify.config` | - | operator, approver, owner | yes: `/notify/rules`, `/notify/rules/delete`, `/notify/channels`, `/notify/channels/delete`, `/config/signin-context-policy` | `router-ops.ts:93` |
| Expiry / licence-lapse policy | - | `expiry.config` | - | operator, approver, owner | no | `router-ops.ts:297` |
| Scheduled restore-test policy | - | `scheduledtest.config` | - | operator, approver, owner | no | `router-pipelines.ts:39` (DO re-check; every built-in role that holds `downpipe.write` also holds this, so the only caller who can hold one without the other is a composable custom role) |
| Reports (SLA / compliance projections) | `reports.read` | - | all six roles | - | n/a | `router.ts:582` |
| Security posture (checks and scores) | `posture.read` | - | all six roles | - | n/a | `router-status.ts:244` |
| Security posture (risk-accept a failing check) | - | `posture.riskaccept` (**owner-reserved**) | - | owner only | yes: `/posture/accept`, `/posture/unaccept` | `router-config-version.ts:36` |

### Step-up overlay

The 43 mutating routes in `STEPUP_SUBS` (`src/admin/router-core.ts`) are a second, orthogonal
access restriction layered on top of the table above: even a caller who holds the write capability
for a row must additionally present a fresh passkey assertion (the `x-downpipes-stepup` header)
within the last `STEPUP_FRESH_MS` when a stale ambient session cookie could otherwise reach a
high-blast-radius mutation. It never widens who may write a field; it narrows *when* a cookie-borne
session may. The "Step-up on write" column above names, per row, which of its routes are members.

---

## 3. Reading this against the data classification inventory

`docs/security/data-classification.md` documents *what* each data asset is and how it is protected
(encryption, retention, logging) - the ASVS V14.1.1/V14.1.2 lens. This document documents *who* may
read and write it - the ASVS V8.1.2 lens. The two are complementary: for example, the audit log
chain (data-classification.md s2.11) states "Read: any authenticated role. Write: exclusively the
scheduler DO's internal `appendAudit` path"; this document's audit-log row above pins that same
fact to the live `audit.read` capability grant and the `ROLE_CAPABILITIES` table it is read from.
