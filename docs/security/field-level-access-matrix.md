# Field-level access matrix

**Standard:** OWASP ASVS 5.0 - V8.1.2 ("Authorization documentation defines field-level access
restrictions (read and write) based on consumer permissions and resource attributes")
**Scope:** the engine's admin API (src/admin)


This document is the field-level authorization record V8.1.2 asks for: for every sensitive field
or field group the admin API exposes, who may read it and who may write it, expressed as the
engine's own capability model rather than as prose that can drift from the code.

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
| **viewer** | Access JWT / passkey / OIDC / SAML session resolved to this role in the role table | Reads plus the two read-safe restore-proof capabilities (`restore.dryrun`, `restore.verify`). The least-privilege resting role; an Access or passkey identity with no role grant resolves here. A native OIDC, OAuth2 or SAML sign-in with no grant, invite or mapped group is refused and gets no session. |
| **operator** | as above | Viewer's reads plus data operations (create/edit/delete a downpipe, trigger a run, run a drill), the operational config (notify/expiry/scheduled-test), and raising a restore request. No apply/approve, no people, no keys. |
| **restore-operator** | as above | A narrow role, NOT on the cumulative ladder: viewer's reads, drill, and the full restore lifecycle (request/apply/approve). Cannot create/edit/delete a downpipe, configure notify/expiry, or manage people or keys. |
| **approver** | as above | Operator's powers plus restore apply/approve. |
| **access-admin** | as above | A narrow role: viewer's reads plus `roles.write` and `access.policy` (people and account governance only). No data write, no restore apply, no keys. |
| **owner** | as above, or the `ADMIN_TOKEN` bearer (see below) | Every capability, including the two owner-reserved ones no other role or custom role may ever hold: `keys.ceremony` and `posture.riskaccept`. |
| **custom role** | Access JWT / passkey / OIDC / SAML, resolved via an account-defined named bundle | An arbitrary subset of the creator's own capabilities (`validateCustomRole`, `identity-rbac.ts`), minus the two owner-reserved capabilities, which a custom role can never hold regardless of who composes it. |
| **`ADMIN_TOKEN` break-glass** | A pre-shared bearer token, compared constant-time | Resolves **unconditionally** to owner (`src/sched/scheduler-do-rbac-authority.ts:110`). Not attributable to an email (`actorEmail: null`); can be disabled (`ADMIN_TOKEN_DISABLED`) or retired in-app once a way back in exists (working Owner recovery codes or a second Owner). |

### Machine-bearer surfaces

Three non-interactive surfaces sit **outside** the Capability model entirely: they are governed by
their own dedicated bearer secrets and their own narrow, hard-coded scope, never by `gate()` /
`Capability`. They are listed here because V8.1.2 asks for every consumer class, not only the ones
the capability table already names.

| Surface | Bearer | What it may READ | What it may WRITE |
|---|---|---|---|
| **SCIM deprovision** (`/scim/v2/Users/{id}`) | `SCIM_BEARER_TOKEN`, a dedicated secret separate from `ADMIN_TOKEN` (`src/admin/scim.ts:14`); unset means the whole surface is 503 | Nothing. This is a write-only facade: `GET /scim/v2/Users` answers an empty list, and no route returns a user record. | Only the named member, and only by removal: it first revokes their sign-in factors (the revoke `POST /signin-factors/revoke` drives), then removes their row in the role table (the offboarding `POST /roles/delete` drives). An Owner, while another Owner exists, is demoted to viewer instead, with every session ended and the `scim-owner-demoted` alert raised (`deleteRole`, `src/sched/scheduler-do-rbac-mutations.ts:319`). It acts through a stable synthetic caller (`SCIM_OFFBOARD_EMAIL`/`SCIM_OFFBOARD_SUBJECT`, `src/admin/identity.ts`), recognised only by that exact `{method:"token", email, subject}` triple, never a real owner grant a token holder could otherwise reach. |
| **Metrics scrape** (`/metrics`) | A platform-issued ingest credential, scope `"metrics"` (`src/admin/support-ingest.ts`); dedicated, READ-ONLY (`src/admin/metrics.ts:6`) | Only the Prometheus series already derivable from `GET /downpipes`, `/history` and `/replication`: per-downpipe freshness, run counters, duration, size and destination-health gauges. Never a config field, a secret, an endpoint, or a record value. | Nothing. |
| **Support pull** (`/support/diagnostics`, `/support/audit-feed`) | A platform-issued ingest credential, scope `"diagnostics"` or `"audit-feed"` | `diagnostics`: the redaction-safe support bundle (version, presence-only status, preflight, run-history rows, notify outcomes, licence tier - never a key, secret, endpoint or customer data value). `audit-feed`: the hash-chained audit event stream, same fields `GET /admin/audit` returns. | Nothing (both scopes are pull-only). |

Minting or revoking any of the three ingest credentials is itself **owner-role-exclusive by a bare
`caller.role !== "owner"` check, deliberately NOT a `gate(caller, cap)` call**
(`src/admin/router-status.ts:383`), so this authority can never be composed into a custom role by
accident. When dual control is armed, a mint also needs a second owner's approval before the secret
is minted (`ownerActionGate`, same file). SCIM's own offboard action, by contrast, needs no such
grant: it replays the existing `roles.write`-gated revoke and offboarding paths under a synthetic
caller that is `owner`-authoritative by construction, never by capability.

---

## 2. Field-level matrix (capability = the field-level access restriction)

Every capability in the closed `Capability` union (`identity-rbac.ts`) governs exactly one field or
field group below; the partition is exhaustive (`test/validate-field-access-matrix.ts` asserts all
21 capabilities are covered by exactly one row). "Read holders" / "write holders" are the caller
classes from section 1 that the capability is granted to; a custom role reaches a row only if its
composed capability set includes that row's capability.

| Field / resource group | Read cap | Write cap | Read holders | Write holders | Step-up on write | Evidence |
|---|---|---|---|---|---|---|
| Downpipe configuration | `downpipe.read` | `downpipe.write` | all six roles | operator, approver, owner | no | `router.ts:591`; `router-pipelines.ts:44` |
| Downpipe deletion | - | `downpipe.delete` | - | operator, approver, owner | no | `router-pipelines.ts:98` |
| Manual run trigger | - | `run.trigger` | - | operator, approver, owner | no | `router-pipelines.ts:144` |
| Restore drill (recovery test) | - | `drill.run` | - | operator, restore-operator, approver, owner | yes, `/attest/session/create` (starting an attended session) | `router-ops.ts:132` |
| Restore dry-run preview | `restore.dryrun` | - | all six roles | - | n/a | `router-restore.ts:592` |
| Restorability proof (blind restore test / keyless attest) | `restore.verify` | - | all six roles | - | n/a | `router-restore.ts:638,913` |
| Restore request | - | `restore.request` | - | operator, restore-operator, approver, owner | no | `router-restore.ts:718` |
| Restore apply (overwrites live data; also the retention-prune apply, and a downpipe edit that lets the scheduled prune delete more: arming `retention.enforce`, or lowering or removing a bound or unpinning a replica while it is on) | - | `restore.apply` | - | restore-operator, approver, owner | yes: `/retention-prune/apply`, and `/restore` on `confirm:true` (a direct `requireStepUp()` call, not a `STEPUP_SUBS` string; see router-core.ts's "second exception" comment); none on the downpipe edit, which instead queues for a different `restore.approve` holder whenever one exists (break-glass and a lone approver apply at once and alert) | `router-restore.ts:252`; `scheduler-do.ts:424` (DO re-check in `addDownpipe`); `scheduler-do-change-control.ts:488` (the queue) |
| Restore approve (dual-control; also the retention-prune approve) | - | `restore.approve` | - | restore-operator, approver, owner | yes: `/restore/approve`, `/retention-prune/approve` | `router-restore.ts:818` |
| Member / role table (read) | `roles.read` | - | all six roles | - | n/a | `router-rbac.ts:178` |
| Member / role table (grant/revoke, another member's sign-in factors and sessions) | - | `roles.write` | - | access-admin, owner | yes: `/roles`, `/roles/delete`, `/signin-factors/revoke`, `/passkey/credentials/delete` (another member's credential; a caller revokes their own without it), `/sessions/terminate-user`, `/sessions/terminate-all` (the DO also requires the owner role) | `router-rbac.ts:44` |
| Account governance policy (IdP group-to-role mappings, custom roles, control-plane export/import) | - | `access.policy` | - | access-admin, owner | yes: `/group-roles`, `/group-roles/delete`, `/custom-roles`, `/custom-roles/delete` | `router-rbac.ts:184`; `router-identity.ts:391` |
| Audit log | `audit.read` | none (append-only; entries come from the DO's `appendAudit`; the only route whose sole effect is an entry is `POST /audit/intent`, which takes one of two closed intent actions: `key-ceremony-intent` needs `keys.ceremony` (Owner only), and `access-policy-change-intent` needs `roles.write` (Owner and Access admin); no route edits or deletes an entry) | all six roles | - | n/a | `router-rbac.ts:298`; `docs/security/data-classification.md` s2.11 |
| Trust roots and egress targets (key ceremony, the attended RUNLOG re-sign, floor reset and chain relink, destinations, IdP connections, SIEM/OTLP push targets, break-glass retirement, custody-share email, the sign-in-context notify policy, the restore and update approval policies) | - | `keys.ceremony` (**owner-reserved**; never composable into a custom role) | - | owner only | yes: `/keys/*`, `/runlog/resign` (the attended RUNLOG re-sign), `/runlog/floor/reset` (the attended floor reset), `/runlog/relink` (the attended chain relink), `/destination*`, `/push*`, `/otlp-push*`, `/idp/connections*`, `/policy/retire-break-glass-token`, `/custody/send-share`, `/config/signin-context-policy` | `router-keys.ts:420`; `router-destinations.ts:328`; `router-identity.ts:843`; `router-push.ts:232` |
| Notification rules and channels | - | `notify.config` | - | operator, approver, owner | yes: `/notify/rules`, `/notify/rules/delete`, `/notify/channels`, `/notify/channels/delete` | `router-ops.ts:155` |
| Expiry / licence-lapse policy | - | `expiry.config` | - | operator, approver, owner | no | `router-ops.ts:381` |
| Scheduled restore-test policy | - | `scheduledtest.config` | - | operator, approver, owner | no | `router-pipelines.ts:41` (DO re-check; every built-in role that holds `downpipe.write` also holds this, so the only caller who can hold one without the other is a composable custom role) |
| Reports (SLA / compliance projections) | `reports.read` | - | all six roles | - | n/a | `router.ts:582` |
| Security posture (checks and scores) | `posture.read` | - | all six roles | - | n/a | `router-status.ts:256` |
| Security posture (risk-accept a failing check) | - | `posture.riskaccept` (**owner-reserved**) | - | owner only | yes: `/posture/accept`, `/posture/unaccept` | `router-config-version.ts:57` |

### Step-up overlay

The 49 mutating routes in `STEPUP_SUBS` (`src/admin/router-core.ts`) are a second, orthogonal
access restriction layered on top of the table above. Even a caller who holds the write capability
for a row must also show a recent factor: a passkey session signed in within `STEPUP_FRESH_MS`, a
single-use step-up token in the `x-downpipes-stepup` header from a fresh passkey assertion, or, for
a Cloudflare Access caller, an assertion issued within `STEPUP_FRESH_MS`. The `ADMIN_TOKEN` method is
exempt, as the bare bearer and as the session exchanged for it. It never widens who may write a field; it narrows *when* a session may. The "Step-up on
write" column above names, per row, which of its routes are members. Three members sit outside the
capability rows: `/sessions/terminate` and `/sessions/terminate-others` act only on the caller's own
sessions and need no capability, and `/support/credentials` is the bare owner-role check in section 1.

---

## 3. Reading this against the data classification inventory

`docs/security/data-classification.md` documents *what* each data asset is and how it is protected
(encryption, retention, logging) - the ASVS V14.1.1/V14.1.2 lens. This document documents *who* may
read and write it - the ASVS V8.1.2 lens. The two are complementary: for example, the audit log
chain (data-classification.md s2.11) states "Read: any authenticated role. Write: exclusively the
scheduler DO's internal `appendAudit` path"; this document's audit-log row above pins that same
fact to the live `audit.read` capability grant and the `ROLE_CAPABILITIES` table it is read from.
