# Logging inventory

**Standard:** OWASP ASVS 5.0, V16.1.1 / V16.2.3
**Scope:** Downpipes engine, console, and offline downpipe CLI. The vendor control plane is a
separate component with its own inventory.


This document is the cross-layer logging inventory ASVS V16.1.1 asks for. For each layer it
states what is logged, the record format, where the records are stored, how they are used, who
can read them, and how long they are kept. It is also the log inventory V16.2.3 refers to: the
engine and the console store or broadcast log records only to the files and services named
here. Every optional sink is listed with the condition under which it is on.

The audit action table, the Layer 2 call-site figures, the set of direct `console.*` emitters
and the Layer 4 sink kinds below match the source tree. A citation is written as `identifier`
(`path:line`): the cited line holds the identifier. Console, CLI and control-plane citations
refer to those components' own source.

---

## Clock source for every timestamp in this document

Every `ts`, `at`, `createdAt`, `grantedAt`, `approvedAt` and other timestamp field named in this
document comes from the Cloudflare Workers runtime clock: `new Date()` or `Date.now()` called
inside the engine Worker or a Durable Object, never a clock the engine keeps itself. The two
producers every other timestamp in this document traces back to:

- Layer 2's `ts` field: `new Date().toISOString()` (`src/log.ts:45`).
- Every Durable Object timestamp (the Layer 1 audit log's `ts`, and the `at`/`createdAt`/
  `approvedAt`/... fields on restore, retention, IdP, recovery, RBAC, config-change and
  push-destination state): `nowMillisISO` (`src/sched/scheduler-helpers.ts:79`), which wraps
  `new Date().toISOString()` (`src/sched/scheduler-helpers.ts:80`). `canonMillisISO`
  (`src/sched/scheduler-helpers.ts:96`) re-parses a caller-supplied timestamp with `Date.parse`
  and falls back to `nowMillisISO()` on anything unparseable, so a value cannot enter storage
  from a clock this document does not name.

The engine runs no NTP client and keeps no clock of its own: it is a Cloudflare Worker and a
Durable Object, both stateless compute invoked per request with no local clock hardware to
discipline. Time-keeping is Cloudflare's platform responsibility, not the engine's. Cloudflare
synchronises the clock of every Workers runtime instance against its own NTP infrastructure; the
engine's reliance on that synchronisation, rather than running its own, is recorded here as the
current-state posture, not measured independently by this repository.

---

## Layer 1: Tamper-evident hash-chained audit log

### What it is

The primary security log. A SHA-384 hash-chained, append-only sequence of structured audit
events held in the scheduler Durable Object. Each action in the table below produces an entry.
Many routes also record a refused attempt as a `denied` entry. The chain is tamper-evident: an edit, insertion, deletion or reordering of a
retained entry is detected by `verifyChain` (`src/admin/audit.ts:205`). It is not tamper-proof:
a holder of raw Durable Object storage could rewrite the whole chain.

**Source:** `src/admin/audit.ts` (chain mechanics, verify, export), `src/admin/audit-types.ts`
(the closed vocabularies), `src/sched/scheduler-do-audit.ts` (the append path).

### Events recorded

The closed action set is `AUDIT_ACTIONS` (`src/admin/audit-types.ts:38`), 106 members, ending
at `] as const` (`src/admin/audit-types.ts:450`). `AuditAction` (`src/admin/audit-types.ts:452`)
is derived from it, so no action outside this table can be written. This table lists every member
of the constant.

| Action | What it records |
|--------|-----------------|
| `restore-apply` | A restore apply (confirmed write-back), success or denied. |
| `restore-verified` | A restore receipt anchored to the chain: receipt hash, run id and record counts for an applied restore. |
| `restore-request` | A restore request raised for dual-control approval. The `restore` target of this and the approve, reject and apply events names the write target: `redirectBinding`, and when set `namespaceId`, `bucketName`, `cfAccountId`, `cfZoneId`, `cfSurfaces`, `mediaAccountId`, `d1Database`, `d1Tables`, `d1CreateOnly` and `onExisting`. Never a token. |
| `restore-approve` | A restore request approved by a second identity (the maker is not the checker). |
| `restore-reject` | A restore request rejected. |
| `retention-prune-request` | A retention prune apply requested for dual control, bound to a plan hash. |
| `retention-prune-approve` | A retention prune request approved by a second identity. |
| `retention-prune-reject` | A retention prune request rejected. |
| `retention-armed-alone` | A downpipe edit that lets the scheduled retention prune delete more applied with no second approver: the break-glass token, or nobody else holds `restore.approve`. |
| `downpipe-create` | A downpipe configuration created or updated. |
| `downpipe-delete` | A downpipe configuration deleted. |
| `downpipe-roster-reconcile` | The roster-hygiene heal repaired structural ghost rows. |
| `run-trigger` | A manual run-now; the run id is the target. |
| `run-failed` | Engine-observed: a backup run entered the failed state, once per transition. |
| `role-change` | A role grant added, changed or removed. |
| `group-role-change` | An identity-provider group-to-role mapping upserted or removed. |
| `custom-role-change` | A custom role created, updated or deleted. |
| `idp-connection-change` | A native external IdP connection created, updated, enabled, disabled or deleted. |
| `idp-sign-in` | A principal completed a native external IdP sign-in. |
| `authn-failure` | A failed authentication attempt; the actor fields are null because no identity was verified. |
| `denied-overflow` | Refused requests that the denied fold's hourly ceiling left without a row of their own, from any actor; the engine is the actor and the count is in `deniedAttempts` (see "Folded rows"). |
| `key-ceremony-intent` | The operator recorded intent to run a key ceremony. |
| `keys-installed` | The in-product key install wrote the engine's worker secrets through a one-shot token. |
| `break-glass-rotated` | A new break-glass public key applied. |
| `runlog-handover` | A signer re-key verified each destination RUNLOG under the old signer and signed it under the new one, stopped on a RUNLOG that did not verify, or discarded the held old public key. |
| `runlog-resigned` | An Owner, after step-up, signed under the current signer the exact bytes of a destination RUNLOG that did not verify (or finished a pending re-key hand-over under the held old public key). |
| `runlog-resumed` | An Owner, after step-up, called the attended re-sign on a destination RUNLOG whose `.sig` was absent. The engine's pending signature verified the bytes, so the engine published that signature again. Nothing is signed; the row names the destination, the digest prefix and the highest index. |
| `runlog-floor-reset` | An Owner, after step-up, moved a destination's anti-rollback floor down to the highest index of the RUNLOG it holds now (0 when absent), after the writers refused it on the floor alone. |
| `runlog-relinked` | An Owner, after step-up, relinked one downpipe's anomalous chain in a destination RUNLOG that verifies, once, and recorded the anomaly acknowledged. |
| `operational-added` | The operational key pair installed. |
| `config-recovery-added` | The configuration recovery key, the configuration wrap key, or both, installed on an engine that lacked them. |
| `config-secrets-rewrapped` | After a key install set or kept the configuration wrap key, the engine sealed the credentials it still held as plaintext; counts and credential class names only. |
| `operational-removed` | Both operational worker secrets removed (break-glass-only posture). |
| `key-install-failed` | A key install died at a named step with a closed cause. |
| `key-removal-failed` | A key removal died at a named step with a closed cause. |
| `posture-acknowledged` | The customer acknowledged a versioned key-posture statement; version and text hash only. |
| `custody-share-emailed` | One Shamir share emailed to a custodian; counts only. |
| `access-policy-change-intent` | The operator recorded intent to change the access policy. |
| `posture-override-set` | An owner set a per-check posture override. |
| `posture-override-withdrawn` | An owner withdrew a per-check posture override. |
| `notify-channel-change` | A notification channel was created, edited or deleted, or a caller without `notify.config` was refused. The target carries the change kind and the channel id, never the URL. A change that config approval queues writes `config-change-propose` and `config-change-approve` instead. From engine 0.3.7. |
| `notify-rule-change` | A notification rule was created, edited or deleted, or a caller without `notify.config` was refused. The target carries the change kind and the rule id. The default rule that the first channel creates writes no row of its own; that channel's `notify-channel-change` row records it. From engine 0.3.7. |
| `config-change-propose` | A config change queued for dual-control approval (the maker). |
| `config-change-approve` | A queued config change approved (the checker). |
| `config-change-reject` | A queued config change rejected. |
| `config-change-supersede` | An approve found the base config had moved. |
| `config-policy-change` | The owner-only toggle of the config-approval gate. |
| `owner-action-propose` | A gated owner operation proposed (the maker). |
| `owner-action-approve` | A gated owner operation approved (the checker). |
| `owner-action-execute` | An approved owner operation ran. |
| `owner-action-reject` | A gated owner operation rejected or vetoed. |
| `change-recorded` | A change reference recorded for a CAB-worthy change (opt-in Require Change Number). |
| `bootstrap-consumed` | The one-time first-Owner bootstrap consumed (latched). |
| `break-glass-token-retired` | An Owner retired the ADMIN_TOKEN bearer in-app. |
| `discovery-token-set` | The read-only account-discovery token set. |
| `discovery-token-cleared` | The account-discovery token cleared. |
| `discovery-accounts-set` | The set of browsed accounts changed. |
| `discovery-sources-set` | The set of token-authenticated source types changed. |
| `engine-account-verified` | The engine proved its own Cloudflare account id for the first time. |
| `dest-config-set` | The archive destination set or replaced. |
| `dest-config-cleared` | The archive destination cleared. |
| `licence-activated` | A signed licence token pinned. |
| `licence-cleared` | The licence token removed. |
| `update-promoted` | A vendor-signed engine version made live, pending the canary. |
| `update-applied` | The canary proved the new version healthy and it was kept. |
| `update-rolled-back` | The new version reverted after the canary. |
| `update-refused` | An update aborted before going live. |
| `canary-config` | The integrity canary toggled, repointed or rescheduled. |
| `sources-attached` | Source bindings added to the engine through a one-shot deploy token. From engine 0.3.7 the target names the bindings. The console builds a binding name from the resource name, so it can hold a bucket, namespace, database or secret name in sanitised form. |
| `sources-detached` | Source bindings removed. From engine 0.3.7 the target names the bindings. |
| `expiry-cleanup-attested` | The operator attested that a spent ephemeral credential was deleted. |
| `recovery-codes-generated` | A fresh recovery-code set made live for an email, invalidating any prior set. |
| `recovery-codes-staged` | A fresh recovery-code set minted and held pending confirmation. |
| `recovery-code-used` | A recovery-code sign-in attempt: success, failed or denied; never the code. From engine 0.3.7 a failed or denied row carries the `authn-attempt` target with ceremony `recovery` and the number of attempts it stands for (see "Folded rows"). |
| `support-credential-grant` | An owner minted a scoped, expiring pull credential (diagnostics, audit-feed or metrics). |
| `support-credential-revoke` | An owner cleared a pull credential. |
| `support-diagnostics-pulled` | The vendor pulled the sealed diagnostics bundle with a diagnostics credential; one row per served pull. |
| `support-bundle-generated` | An operator downloaded or generated the support bundle through the admin API; one row per bundle served, with the route and whether the bundle was sealed to the vendor key. From engine 0.3.7. |
| `passkey-credential-revoke` | A WebAuthn credential removed. |
| `passkey-invite-enrol` | A passkey enrolled through a registration invite; the actor is the enrolling member. |
| `signin-factor-revoke` | Every sign-in factor of one member removed in one act. |
| `session-terminate` | Sessions terminated: a member's own other sessions, one member's sessions, or all sessions. |
| `retention-prune` | An applied retention prune deleted superseded runs; the cron (engine actor) or the admin route (human actor). |
| `control-plane-exported` | A signed control-plane export written to the destination bucket. |
| `control-plane-empty` | The health pass found an empty control plane while the bucket holds runs. |
| `control-plane-reconciled` | A break-glass operator rebuilt the Durable Object from a verified export, or an Owner imported an estate definition; the first event of the new chain. `actorMethod` records how the caller authenticated. |
| `control-plane-recovery-acknowledged` | An owner cleared the recovery-required latch without a reconcile. |
| `control-plane-resumed` | The cron auto-heal re-applied the no-authority resume slice. |
| `engine-secret-present` | Engine-observed: a status presence boolean turned true. |
| `engine-secret-absent` | Engine-observed: a status presence boolean turned false; outcome failed. |
| `engine-version-change` | Engine-observed: the engine version changed between two status observations. |
| `push-destination-set` | The audit-log push destination set or replaced (Layer 4). |
| `push-destination-cleared` | The audit-log push destination removed. |
| `push-delivery-failure` | Engine-observed: a failed audit-log push delivery attempt. |
| `otlp-push-destination-set` | The OTLP metrics push destination set or replaced. |
| `otlp-push-destination-cleared` | The OTLP metrics push destination removed. |
| `otlp-push-delivery-failure` | Engine-observed: a failed OTLP push delivery attempt. |
| `attest-session-started` | An attended verification session created. |
| `attest-session-proven` | The operator proved possession of the break-glass private, or a denied attempt. |
| `attest-run-verified` | A batch of runs sampled and verified; counts only. |
| `attest-session-aborted` | The operator ended an attended verification session. |
| `test-fault-armed` | A harness test fault loaded; only on an estate running with HARNESS_TEST_FAULTS. |
| `test-fault-disarmed` | A harness test fault cleared before it fired. |
| `test-fault-fired` | A harness test fault changed engine behaviour (engine actor). |
| `test-fault-control-plane-cleared` | The harness-only release of the recovery-required latch a test fault set. |
| `secret-rotation-confirmed` | An owner attested that a bearer or destination credential's rotation cadence baseline moved to now (`POST /admin/secrets/rotated`). |

Every entry carries an `AuditOutcome` (`src/admin/audit-types.ts:457`): `success`, `denied`
or `failed`. A refused attempt is recorded as a first-class entry with outcome `denied`.

### What is not recorded

The target is the closed `AuditTarget` union (`src/admin/audit-types.ts:468`), 28 target kinds.
A target can hold labels the operator chose, such as a downpipe name. Apart from these labels,
the only operator text on a target is the `reason` on a restore or retention-prune request, and
the change number and reason on `change-recorded`. A caller can only append an
`AuditDraft` (`src/admin/audit-types.ts:870`), which has no hash and no sequence. No target
field holds key material, a secret value, a record value, a destination credential, an
endpoint, a destination bucket name, a private recipient fingerprint, the licence token or the
update-channel signer. A source binding name on `source-bindings` is an allowed label. The
console builds it from the source's own name, so it can hold a source bucket, namespace,
database or secret name in sanitised form.

### Entry format

One JSON object per entry, the `AuditEvent` interface (`src/admin/audit-types.ts:835`):

```
seq           monotonic integer
ts            RFC-3339 UTC milliseconds
actorSubject  stable principal (for example iss|sub for Access, the passkey subject for a passkey); null for the token bearer and engine-observed events; optional on the wire
actorEmail    verified email; null for the token bearer and engine-observed events
actorMethod   "access" | "passkey" | "oidc" | "saml" | "token" | "recovery" | "engine"
sourceIp      CF-Connecting-IP value, or null
action        AuditAction (the table above)
outcome       "success" | "denied" | "failed"
target        AuditTarget (closed union)
advisory      optional, idp-sign-in only: the IdP's advisory acr/amr/auth_time
prevHash      "sha384:<96 hex>", the prior entry's hash or the genesis sentinel
hash          "sha384:<96 hex>", SHA-384 over canonical JSON of every other field
```

`buildEvent` (`src/admin/audit.ts:154`) computes the hash over canonical JSON, the same
discipline the archive format uses.

### Storage

The scheduler Durable Object. Every entry sits under the key prefix `AUDIT_PREFIX`
(`src/admin/audit.ts:80`), `audit:`, with a zero-padded sequence from `auditKey`
(`src/admin/audit.ts:109`) so a prefix list returns ascending order. The single write path is
`appendAudit` (`src/sched/scheduler-do-audit.ts:91`), which stores the entry with
`auditKey(seq)` (`src/sched/scheduler-do-audit.ts:101`). The router only posts drafts through
`doURL("/audit")` (`src/admin/router-audit.ts:134`); no external caller can write an entry.

### Retention

`AUDIT_CAP` (`src/admin/audit.ts:95`) is 10,000 entries. Past the cap the Durable Object rolls
over the oldest entries through `rollOverAudit` (`src/sched/scheduler-do-audit.ts:163`); the
sequence stays monotonic and the rolled-over count is surfaced. `AUDIT_NEAR_CAP_FRACTION`
(`src/admin/audit.ts:99`) is 0.9: at 9,000 retained entries `GET /admin/status` reports
`auditNearCap` so the console can prompt an export. After a rollover `verifyChain` takes its
baseline from the first retained entry through `expectGenesis` (`src/admin/audit.ts:207`).

No minimum retention period is enforced and there is no TTL. The operator path to keep the full
history is an export before the rollover, or one of the delivery paths below, each of which
carries every committed entry as it is written.

### Folded rows

Three writers record refused attempts that a caller can repeat at will. One row per attempt would let
that caller push every older entry past the cap, so each writer folds its attempts into rows that
carry a count.

- **Failed sign-ins** (`authn-failure`): `appendAuthnFailureAudit`
  (`src/sched/scheduler-do-audit.ts:333`) writes one row per minute per row identity (ceremony,
  connection and actor), with the count in `attempts`. It also writes a row once 25 attempts are
  pending, if the budget allows. The row identity holds no source address.
- **Failed and throttled recovery-code sign-ins** (`recovery-code-used`, outcome `failed` or
  `denied`): `appendRecoveryFailureAudit` (`src/sched/scheduler-do-recovery.ts:493`) writes one row
  per minute per source and outcome. An IPv6 source counts by its /64
  (`recoveryFoldSource` (`src/sched/audit-fold.ts:423`)). The row carries the `authn-attempt` target
  with ceremony `recovery` and the count in `attempts`. A throttled attempt writes no row of its own.
- **Router refusals** (outcome `denied`): `appendAuditFromRouter`
  (`src/sched/scheduler-do-audit.ts:281`) writes one row per actor per minute, whatever the route or
  target. The count rides inside the target as `deniedAttempts`: the refused requests by that actor
  since their previous denied row, this one included. The row's action and target describe the
  attempt that wrote it. Past the hourly ceiling, the count goes on a `denied-overflow` row (below).

Every folded row counts itself, so the first attempt in a quiet minute writes a row with a count of
1. Later attempts in the same minute add to a pending count. The source's next row carries it, or,
if the source stops, the next call to a writer writes it once a further minute has passed.

Each writer has a budget across all its sources: `RECOVERY_FOLD_ROWS_PER_WINDOW`
(`src/sched/audit-fold.ts:65`), `AUTHN_FOLD_ROWS_PER_WINDOW` (`src/sched/audit-fold.ts:66`) and
`DENIED_FOLD_ROWS_PER_WINDOW` (`src/sched/audit-fold.ts:67`) allow 2 rows a minute each, in a window
of `AUDIT_FOLD_WINDOW_MS` (`src/sched/audit-fold.ts:43`). Two hourly ceilings sit above the budgets.
`SIGN_IN_FOLD_ROWS_PER_HOUR` (`src/sched/audit-fold.ts:72`) allows the recovery and failed sign-in
writers 20 rows an hour together. `DENIED_FOLD_ROWS_PER_HOUR` (`src/sched/audit-fold.ts:73`) allows
the router refusals 9 rows an hour of their own. A sign-in flood cannot spend the refusals' rows, and
a flood of refusals cannot spend the sign-in rows.

Over the budget or the ceiling, a recovery attempt goes to an overflow count with a null `sourceIp`.
While the ceiling is open, that count is written as at most one row per outcome per minute. Once the
ceiling is reached, it is written as at most one row per outcome per hour. The recovery sources are
addresses a caller chooses, so their counts cannot wait on their own keys.

A router refusal over the budget stays pending on its actor while its ceiling is open, so the count
stays with the right actor. Once the denied ceiling is reached, refusals go to one overflow count,
written as at most one `denied-overflow` row per hour. That row has the engine as its actor, no
source IP, outcome `denied`, the `denied-overflow` target and the count in `deniedAttempts`. A
failed sign-in over the budget or the ceiling stays pending on its own row identity until a row is
allowed. Those identities come from the tenant's own connections and roster.

The figures come from the limits a caller meets. Before the fold, one IP wrote 30 recovery rows a
minute (the per-IP sign-in limit), a Viewer wrote one row per refused request, and 334 IPs wrote
386 failed passkey sign-in rows a minute. With the fold, a flood on all three writers at once, from
any number of IPs or accounts, writes at most 32 rows an hour: 20 sign-in rows, 9 refusal rows and
three hourly overflow rows (one per recovery outcome, one `denied-overflow`). At that rate 10,000
rows take 13 days, and `auditNearCap` shows at 9,000. Two rows a minute per writer still gives a real person
who mistypes a recovery code and then meets the per-email limit a row for each outcome.

The folds are kept in Durable Object storage under `AUDIT_FOLD_STORAGE_PREFIX`
(`src/sched/audit-fold.ts:81`). Each writer saves the folds before it appends the rows they hand out,
so a restart loses no pending count. A pending count is written at the writer's next refused
attempt, the next router audit write of any kind, or the next alarm (`flushAuditFolds`
(`src/sched/audit-fold.ts:413`)). Once those counts are written, the rows sum to every attempt made,
with two exceptions. An attempt that finds 256 identities already waiting is counted as the fault
`authn-failure-audit-key-cap` or `denied-audit-key-cap` instead. A restart between the save and the
append drops the rows in hand. Neither counts an attempt twice. The durable counters still count
every attempt: the `recovery-code-invalid`, `recovery-ratelimited`
and sign-in auth signals, and the admin refusal counters.

### How it is used and who can read it

| Route | Purpose | Gate |
|-------|---------|------|
| `GET /admin/audit` | Newest-first paged and filtered read with the chain head | `gate(caller, "audit.read")` (`src/admin/router-rbac.ts:310`) |
| `GET /admin/audit/verify` | Recompute the chain; a break is a 200 result naming the first bad sequence | `gate(caller, "audit.read")` (`src/admin/router-rbac.ts:317`) |
| `GET /admin/audit/export` | The whole or filtered log as a download, JSON or `format=csv`, with the head hash | `gate(caller, "audit.read")` (`src/admin/router-rbac.ts:325`) |

Every built-in role from the viewer floor up holds `"audit.read"`
(`src/admin/identity-rbac.ts:52`). The export format is chosen in the Durable Object
(`"csv"` (`src/sched/scheduler-do-audit.ts:555`)); `toCSV` (`src/admin/audit.ts:526`) renders
the target as a short description, never as a raw object, and `csvCell`
(`src/admin/audit.ts:517`) neutralises a leading formula trigger in every column. The head
(`headOf` (`src/admin/audit.ts:310`)) rides with both formats so an external verifier detects
truncation after export.

### Delivery paths

The same committed events reach these services, each carrying `seq`, `prevHash` and `hash` so
a collector can alert on a gap or a hash discontinuity.

| Path | Mechanism | Who turns it on | Retention |
|------|-----------|-----------------|-----------|
| Logpush mirror line | `mirrorAuditEvent` (`src/admin/audit-mirror.ts:26`) writes one JSON line per committed event with `"downpipe-audit"` (`src/admin/audit-mirror.ts:30`) as `source` and `v: 1`; called from the append path and counted on failure by `recordAuditMirrorFailure` (`src/sched/scheduler-do-audit.ts:151`). The line lands in Layer 2's Workers Logs stream. | Always emitted. It leaves the account only if the operator creates a Logpush job on the `workers_trace_events` dataset. | Workers Logs retention, then the Logpush sink's own. |
| Pull feed | `GET /support/audit-feed` is routed at `"/support/audit-feed"` (`src/index.ts:435`) to `handleSupportPull` (`src/admin/support-ingest.ts:297`), scope `"audit-feed"` (`src/admin/support-ingest.ts:299`); ascending, cursored by `afterSeq`. | An Owner mints a client/secret credential for the `audit-feed` scope (audited as `support-credential-grant`). The secret is stored as its SHA-384, verified constant-time, capped at 365 days, one active per scope, and the most recent 50 pulls are recorded on the grant. | The collector's own. |
| Push destination | Layer 4 below. | An Owner configures it. | The sink's own. |

---

## Layer 2: The structured operational stream

### What it is

`log` (`src/log.ts:41`) emits one single-line JSON record per call. This stream carries every
operational event: authentication outcomes, run and seal faults, cron pass outcomes, delivery
faults, the last-resort request handlers, and the Layer 1 mirror line.

Fields: `ts` (ISO 8601 UTC), `level` (`debug` | `info` | `warn` | `error`), `service` (the
constant `SERVICE` (`src/log.ts:28`), `downpipe-engine`), `env` (stamped by `configureLog`
(`src/log.ts:33`) from the Worker's `ENVIRONMENT` binding, else `unknown`), `event` (the
message string the call site passed), and the optional request-context fields of `LogFields`
(`src/log.ts:20`): `method`, `path`, `status`, `duration_ms`, `error_code`. There is no other
field. The level selects the sink so Workers Logs keeps it: `console.error` (`src/log.ts:62`),
`console.warn` (`src/log.ts:63`), `console.log` (`src/log.ts:64`).

### Direct emitters

Direct `console.*` emitters: `src/log.ts:62-64`, `src/admin/audit-mirror.ts:30`. No other file
under `src/` calls `console.log`, `console.error`, `console.warn`, `console.info` or
`console.debug`.

### Call sites

Measured: 281 `log(` call sites across 60 files (`src/admin/config-rewrap.ts`, `src/admin/drill.ts`, `src/admin/key-vintages.ts`, `src/admin/restore-apply.ts`, `src/admin/restore-plan-types.ts`, `src/admin/restore-plan.ts`, `src/admin/restore-receipt.ts`, `src/admin/restore-sinks.ts`, `src/admin/restore-verify.ts`, `src/admin/restore.ts`, `src/admin/router-audit.ts`, `src/admin/router-auth-flow.ts`, `src/admin/router-core.ts`, `src/admin/router-custody.ts`, `src/admin/router-identity.ts`, `src/admin/router-idp-web.ts`, `src/admin/router-keys.ts`, `src/admin/router-notify.ts`, `src/admin/router-posture.ts`, `src/admin/router-restore.ts`, `src/admin/router-runlog.ts`, `src/admin/router-session.ts`, `src/admin/router-sources.ts`, `src/admin/router-updates-shared.ts`, `src/admin/scim.ts`, `src/admin/update-support.ts`, `src/admin/updates.ts`, `src/attest/verify.ts`, `src/cron/alert-passes.ts`, `src/cron/beacon-emit.ts`, `src/cron/control-plane-pass.ts`, `src/cron/discovery-pass.ts`, `src/cron/drive.ts`, `src/cron/history-retention-pass.ts`, `src/cron/notify-passes.ts`, `src/cron/otlp-push-pass.ts`, `src/cron/posture-pass.ts`, `src/cron/reconcile-pass.ts`, `src/cron/restore-test-pass.ts`, `src/cron/retention-pass.ts`, `src/cron/runlog-index-advance.ts`, `src/cron/seal-loop-pass.ts`, `src/cron/siem-push-pass.ts`, `src/email.ts`, `src/format/keyless.ts`, `src/index.ts`, `src/notify-routing.ts`, `src/sched/scheduler-do-config-version.ts`, `src/sched/scheduler-do-expiry.ts`, `src/sched/scheduler-do-idp.ts`, `src/sched/scheduler-do-passkey.ts`, `src/sched/scheduler-do-recovery.ts`, `src/sched/scheduler-do-scheduling.ts`, `src/sched/scheduler-do.ts`, `src/seal/replicate-runlog.ts`, `src/seal/replicate.ts`, `src/seal/runseal-do.ts`, `src/seal/runstate.ts`, `src/seal/verify-at-seal.ts`, `src/sources/cloudflare-config.ts`), reproducible with:
`grep -rn 'log("error"\|log("warn"\|log("info"\|log("debug"' src --include='*.ts' | grep -v '\.test\.ts' | grep -v '^src/log.ts' | wc -l`.
The figure is a snapshot of the tree on the date shown.

### What the lines carry

The logger adds no field of its own beyond those listed. The `event` string is chosen at the
call site, and the redaction discipline lives there.

- Authentication lines. `logAuthFailure` (`src/admin/router-core.ts:173`) writes
  `authn failure method=<method> reason=<fixed string>` at level `error`;
  `logAuthSuccess` (`src/admin/router-core.ts:187`) writes
  `authn success method=<method> role=<role>` at level `info`; `logAuthCeremonySuccess`
  (`src/admin/router-core.ts:196`) writes the passkey ceremony that minted a session;
  `logSurfaceAuth` (`src/admin/router-core.ts:204`) writes the outcome for the SCIM, `/metrics`
  and `/support/*` bearer surfaces. The prefix is `AUTH_LOG_PREFIX`
  (`src/admin/router-core.ts:154`). No email, no token and no assertion bytes appear on these
  lines.
- Authorization lines (V16.3.2). `logCapabilityDenied` (`src/admin/router-core.ts:232`) writes
  `authz denied capability=<capability> have=<role>` at level `error`, called from inside `gate`
  (`src/admin/router-core.ts:244`), the one per-route capability check every admin route shares.
  It fires once per capability-gate 403 and never on a grant, and it logs the required capability
  and the caller's role only: no email, no subject and no source IP.
- Last-resort handlers. The admin dispatcher's catch writes `admin-dispatch` (`src/index.ts:411`),
  the non-admin surfaces write `fetch-dispatch` (`src/index.ts:444`), and SCIM writes
  `scim-dispatch` (`src/index.ts:228`). Each line carries `[err:<FNV-1a id> <category>]` and the
  correlation id, never the exception message and never a stack.
- Restore and drill faults carry the run id, the record name where one record failed, an opaque
  error id and a coarse category. `test/validate-errlog.ts` drives the real restore and drill
  code and fails if a raw exception message reappears on those lines.
- Cron pass lines name the pass and, when an engine-internal call raised the fault (a Durable
  Object round trip, the wrap-key check, a delivery tail), the message of the exception that
  call raised; for example `siem push pass: configuration unreadable`
  (`src/cron/siem-push-pass.ts:440`). The delivery senders return closed codes such as
  `PUSH_PASS_FAIL_CODES` (`src/cron/siem-push-pass.ts:100`), never a response body, an
  endpoint or an auth header value.
- Key install and source attach lines carry secret and binding names; never a value.

No line carries key material, a secret value, a destination credential, the ADMIN_TOKEN value,
an Access JWT, a passkey session token, a recovery code or a record value. `LogFields` has no
field that could hold one.

### Storage

Cloudflare Workers Logs. `[observability]` (`wrangler.toml:177`) with `enabled = true`
(`wrangler.toml:178`) persists every invocation's log lines in the Cloudflare dashboard. Two
further readers: `wrangler tail <worker>` for a live stream, and an operator-configured Logpush
job on the `workers_trace_events` dataset to the operator's own store or SIEM.

### Retention

Workers Logs retention is set by the Cloudflare account's Workers Logs configuration, not by
this repository; this document states no figure for it. A Logpush job makes retention the
sink's own. Nothing in the engine deletes or rewrites a log line.

### Access control

Cloudflare account IAM. Reading the dashboard, running `wrangler tail`, or reading the Logpush
destination is governed by the operator's Cloudflare account roles and API token scopes. No
application-layer gate applies, and no line is integrity-protected after collection.

### How it is used

Incident response and forensics through the dashboard or a tail; authentication review through
the `authn` lines; SIEM detection through the Logpush job, which also carries the Layer 1 mirror
line.

---

## Layer 3: Cloudflare Workers platform request logs

### What it is

The invocation log Cloudflare's edge produces for every request to the engine Worker and the
console Worker, enabled by the same `[observability]` stanza as Layer 2: method, path, status,
duration, colo and the Ray ID. Application code does not produce it.

### What is not included

Request or response bodies, the `Authorization` or `cf-access-jwt-assertion` header values, and
any application field (no resolved role, no verified email).

### Storage, retention and access control

The Cloudflare dashboard, under the account's Workers Logs retention, optionally shipped by the
same Logpush job as Layer 2. Access is Cloudflare account IAM.

---

## Layer 4: Audit-log push destination (opt-in)

### What it is

The engine's own outbound delivery of the Layer 1 events to an operator-configured service.
`runSiemPushPass` (`src/cron/drive.ts:284`) runs on every cron tick. The pass
(`runSiemPushPass` (`src/cron/siem-push-pass.ts:423`)) reads the events after the last-pushed
cursor through `/audit/export` with `SIEM_PUSH_BATCH_CAP` (`src/cron/siem-push-pass.ts:466`),
500 events per tick (`SIEM_PUSH_BATCH_CAP` (`src/cron/siem-push-shape.ts:36`)), shapes them
in one of `PUSH_FORMATS` (`src/sched/scheduler-do-limits.ts:276`) (`raw-json`, `ndjson`,
`json-array`, `splunk-hec`, `datadog`, `cef`, `leef`, `gelf`), and dispatches on the sink kind
in `deliverResolvedPush` (`src/cron/siem-push-pass.ts:324`).

### Sink kinds

`PUSH_SINKS` (`src/sched/scheduler-do-limits.ts:289`) is the closed selector. Each kind, where
it writes, and the screen that refuses a private or metadata address:

| Sink | Where the records go | Dispatch | Sender | Egress screen |
|------|----------------------|----------|--------|---------------|
| `http` | An HTTPS POST to the configured endpoint (a Splunk HEC intake, a Datadog intake, an HTTP collector); GELF sends one event per POST | `deliverSiemPush` (`src/cron/siem-push-pass.ts:348`), or with the token spliced into the URL (`deliverSiemPush` (`src/cron/siem-push-pass.ts:345`)) | `deliverSiemPush` (`src/notify/siem-push-sender.ts:158`) | `screenSinkHost` (`src/notify/siem-push-sender.ts:169`) and `screenResolvedIfHostname` (`src/notify/siem-push-sender.ts:174`) |
| `s3` | One object per batch in the configured bucket, PutObject only, key `<prefix>/<timestamp>-<afterSeq>-<nextAfterSeq>.<ext>` | `"s3"` (`src/cron/siem-push-pass.ts:325`) to `putSiemBatchToS3` (`src/cron/siem-push-pass.ts:263`), which calls `dest.put` (`src/cron/siem-push-pass.ts:276`) | `S3Destination` (`src/dest/s3.ts:50`) | `isInternalSinkHost` (`src/dest/s3.ts:270`) on the endpoint, then `screenResolvedIfHostname` (`src/dest/s3.ts:351`) on what its name resolves to |
| `syslog-tls` | RFC 5424 records, octet-framed, over one implicit-TLS socket per batch, in `SYSLOG_TLS_FORMATS` (`src/sched/scheduler-do-limits.ts:305`) (`cef`, `leef`) | `"syslog-tls"` (`src/cron/siem-push-pass.ts:329`) to `deliverSiemSyslog` (`src/cron/siem-push-pass.ts:331`) | `deliverSiemSyslog` (`src/notify/siem-syslog-sender.ts:226`) | `canonicaliseBareHost` (`src/notify/siem-syslog-sender.ts:241`) with `isInternalSinkHost`, then `screenResolvedSinkHost` (`src/notify/siem-syslog-sender.ts:252`) |

Redirects are never followed on any sink, and no response body is read into the trail. The
egress containment is described in `dangerous-functionality.md` section 3 and proven by
`test/validate-egress-host-screen.ts` and `test/validate-ssrf-resolve-screen.ts`.

### Off unless an Owner configures it

`fetchPushConfig` (`src/cron/siem-push-pass.ts:207`) answers `return null`
(`src/cron/siem-push-pass.ts:211`) when no destination record exists, and the pass returns
before any read when the record is not `enabled` (`src/cron/siem-push-pass.ts:448`). Setting,
deleting and test-sending the destination are gated on `gate(caller, "keys.ceremony")`
(`src/admin/router-push.ts:232`), (`src/admin/router-push.ts:297`) and
(`src/admin/router-push.ts:309`). `OWNER_RESERVED_CAPABILITIES`
(`src/admin/identity-rbac.ts:149`) keeps `keys.ceremony` out of every custom role, so only an
Owner can point the audit log at an external service. Each set and clear is audited as
`push-destination-set` or `push-destination-cleared`.

### Delivery guarantee and the trail

At-least-once to acceptance. The cursor advances only when the sink accepted the batch:
`entry.ok` (`src/sched/scheduler-do-siem-push.ts:487`) guards the write of
`SIEM_PUSH_CURSOR_KEY` (`src/sched/scheduler-do-siem-push.ts:490`); any other outcome holds
the cursor so the same events are re-sent next tick. Every event carries a stable `seq` and
`hash`, so a re-delivered batch is safe to dedupe. The Durable Object keeps the most recent
`SIEM_PUSH_TRAIL_CAP` (`src/sched/scheduler-do-limits.ts:455`), 50, delivery outcomes as
closed codes; a failed attempt is also audited as `push-delivery-failure`.

### Retention and access at the sink

Retention is the sink's. Access to the sink is the operator's. When `CONFIG_WRAP_KEY` is set, the
engine seals the auth header value or S3 secret under it. The engine never logs either value.

**Operator guide:** `docs/src/content/docs/day-2/audit-log-push.mdx` in the docs repository,
published at https://docs.downpipes.io/day-2/audit-log-push/.

---

## Outbound telemetry that is not a log sink

These paths leave the account when an operator turns them on. None carries a log record, so a
reviewer should not read them as undocumented log sinks.

| Path | What it carries | On when | Where it lands | Proof |
|------|-----------------|---------|----------------|-------|
| OTLP metrics push | The canonical backup-health snapshot, `OtlpDownpipeMetrics` (`src/sched/scheduler-do-limits.ts:549`): downpipe id and name, enabled flag, last success time, a 0/1 success flag, recent attempt, success and failure counts, duration, size, per-destination health. No audit event, no log line. | An Owner configures a collector (`gate(caller, "keys.ceremony")` (`src/admin/router-otlp-push.ts:101`)) and the record is `enabled` (`src/cron/otlp-push-pass.ts:184`). | The configured OTLP/HTTP collector, POSTed by `deliverOtlpPush` (`src/notify/otlp-push-sender.ts:122`) after `screenSinkHost` (`src/notify/otlp-push-sender.ts:126`); outcomes kept in the Durable Object up to `OTLP_PUSH_TRAIL_CAP` (`src/sched/scheduler-do-limits.ts:532`). Called from `runOtlpPushPass` (`src/cron/drive.ts:299`). | `test/validate-otlp-push.ts` |
| Vendor beacon | The `"downpipe-beacon-v1"` (`src/cron/beacon-emit.ts:54`) aggregate: the account tag, which is the Cloudflare account id (`CF_ACCOUNT_ID`, `src/cron/beacon-emit.ts:43`), the engine version, the Cloudflare Worker version id, the downpipe count, a healthy/stalled split, one account-wide max RUNLOG index, and the emit time. Nothing per downpipe, no name, no value. | `beaconConfigured` (`src/cron/beacon-config.ts:33`): `BEACON_URL`, `BEACON_INGEST_KEY` and `CF_ACCOUNT_ID` all set. Absent any one, `runBeaconEmitPass` (`src/cron/beacon-emit.ts:26`) returns before building a payload. | `POST` to `new URL("/beacon", base)` (`src/cron/beacon-emit.ts:69`) under `BEACON_URL`, refused unless HTTPS and not `isInternalSinkHost` (`src/cron/beacon-emit.ts:70`), and refused when `screenResolvedIfHostname` (`src/cron/beacon-emit.ts:77`) finds an internal address in what the name resolves to, with `redirect: "manual"` (`src/cron/beacon-emit.ts:85`). The vendor control plane's beacon endpoint stores the aggregate in Workers KV and rejects any per-downpipe field. Called from `runBeaconEmitPass` (`src/cron/drive.ts:256`). | `test/validate-beacon-emit.ts` |
| Notifications | Alert emissions built from the run-history ring: downpipe ids and names, statuses, freshness, enumerated error classes. | An operator configures a channel and a rule. | The operator's own endpoint through `deliverToChannel` (`src/notify-routing.ts:666`) and the adapters under `src/notify/channels/` (email, JSM, PagerDuty, ServiceNow, Slack, Teams, webhook). | `test/validate-notify.ts` |
| Support bundle | The signed, redaction-safe diagnostics bundle: version and provenance, presence-only status, the preflight report, coarse run rows, delivery outcomes, the licence tier. | The operator downloads it (`"GET /support/bundle"` (`src/admin/router-status.ts:302`)) or generates it from the console (`"POST /support/bundle"` (`src/admin/router-status.ts:326`)), both gated on `posture.read`; or vendor support pulls it with an Owner-minted `diagnostics` credential. | The ticket the operator attaches it to, or the vendor's pull. The console's client diagnostics ring is folded in request-scoped by `projectClientDiagnostics` (`src/admin/client-diag-receive.ts:463`) and never written to the Durable Object. | `test/validate-client-diag.ts` |

---

## The console Worker

### Worker-side structured stream

The console has its own emitter, `log` (`console/src/log.ts:55`), with the same field set as
Layer 2 and `SERVICE` (`console/src/log.ts:42`) set to `console`. Errors go to
`console.error` (`console/src/log.ts:76`) and everything else to `console.log`
(`console/src/log.ts:78`). The Worker has one call site: the unhandled-request catch writes
`"request.unhandled"` (`console/src/worker.ts:494`) with the method, the path, status 500 and
`error_code` `unhandled`, never the exception message. The lines land in Workers Logs through
`[observability]` (`console/wrangler.toml:23`) with `enabled = true`
(`console/wrangler.toml:24`); retention and access are as Layer 2.

### Browser-side console lines

The SPA writes to the viewer's own browser console at these sites. Those lines exist only in
that browser's developer tools; nothing reads or ships them.

| Site | Line |
|------|------|
| `console.error` (`console/src/screens/passkey/ceremony.ts:334`) | passkey ceremony refused by the browser |
| `console.error` (`console/src/screens/passkey/ceremony.ts:340`) | passkey ceremony refused |
| `console.error` (`console/src/screens/passkey/ceremony.ts:343`) | passkey transport error |
| `console.error` (`console/src/screens/passkey/ceremony.ts:384`) | recovery sign-in refused |
| `console.error` (`console/src/screens/passkey/ceremony.ts:389`) | recovery transport error |
| `console.error` (`console/src/screens/passkey/flows.ts:299`) | step-up ceremony refused by the browser |
| `console.error` (`console/src/components/data-table-bulkbar.ts:58`) | bulk action failed |
| `console.info` (`console/src/screens/map/controller.ts:447`) | the map's view diagnostics text |

### Client diagnostics ring

`console/src/lib/client-diag/ring.ts` accumulates coarse, closed-class error records in memory
for the session. Every string on a record is a member of a frozen vocabulary; there is no
free-text field. The ring leaves the browser only when the operator presses Generate on the
support screen, which posts it to `POST /support/bundle`, where the engine re-validates it and
folds it into that one bundle. The engine never stores it. The browser keeps one closed build-check
class in `sessionStorage` across the reload that ends a console update, and deletes it on read.

### Sinks that discard or are tour-only

- CSP violation reports go to the same-origin `"/csp-report"` (`console/src/worker.ts:368`)
  route, which answers 204 and stores nothing.
- The public product tour and training deploys bind `TOUR_ANALYTICS` (`console/src/worker.ts:52`), a
  Workers Analytics Engine dataset, only in `wrangler.public-demo.toml`
  (`TOUR_ANALYTICS` (`console/wrangler.public-demo.toml:59`)) and `wrangler.training.toml`
  (`TOUR_ANALYTICS` (`console/wrangler.training.toml:39`)). The `"/tour/event"`
  (`console/src/worker.ts:378`) route records closed-name funnel events through
  `writeDataPoint` (`console/src/worker.ts:401`). The genuine console has no such binding and
  the route answers 204 without writing. This is funnel telemetry, not a log.

---

## The offline downpipe CLI

The `downpipe` CLI is the offline reader, a Go program in the `downpipe` repository. It writes
progress and refusals to the terminal's standard error stream, for example `os.Stderr`
(`downpipe/cmd/downpipe/main.go:129`). It creates no log file, keeps no history and contacts no
vendor service. It is not a log producer in the sense of this inventory.

---

## Summary table

| Layer | Format | Storage | Retention | Access control | Integrity | Leaves the account |
|-------|--------|---------|-----------|----------------|-----------|--------------------|
| Audit log (Layer 1) | JSON, hash-chained | Scheduler Durable Object, `audit:` prefix | 10,000 entries, oldest rolled over and counted; no TTL | `audit.read`, held by every built-in role; Durable Object-only writes | SHA-384 chain; head hash rides every export | Through the mirror line (with a Logpush job), the pull feed (with a credential) and the push destination (Layer 4) |
| Operational stream (Layer 2) | Single-line JSON from `src/log.ts`, 281 call sites / 60 files | Cloudflare Workers Logs | Account Workers Logs retention; the Logpush sink's beyond that | Cloudflare account IAM | None after collection | Only with a Logpush job |
| Platform request logs (Layer 3) | Cloudflare invocation log | Cloudflare Workers Logs | Account Workers Logs retention | Cloudflare account IAM | None | Only with a Logpush job |
| Push destination (Layer 4) | The Layer 1 events in one of eight formats | The operator's `http`, `s3` or `syslog-tls` sink | The sink's | Owner-only to configure; the sink's to read | `seq` and `hash` on every event | Yes, when an Owner configures it |
| Console Worker stream | Single-line JSON from `console/src/log.ts` | Cloudflare Workers Logs | Account Workers Logs retention | Cloudflare account IAM | None after collection | Only with a Logpush job |

---

## ASVS V16 residuals

| ASVS ref | Status |
|----------|--------|
| V16.1.1 | This document is the inventory for the engine, the console and the CLI; the control plane keeps its own. |
| V16.2.2 | Every timestamp in this document comes from the Cloudflare Workers runtime clock (`new Date()` / `Date.now()`, see "Clock source" above); the engine runs no NTP client of its own and relies on Cloudflare keeping that clock synchronised. |
| V16.2.3 | Layers 1 to 4 and the console section name every file and service the engine and console store or broadcast log records to; the gate keeps the sink kinds, the emitter set and the citations in agreement with the tree. |
| V16.3.1 | Every authentication attempt is logged with its method: the `authn` lines in Layer 2, and the `authn-failure`, `idp-sign-in` and `recovery-code-used` rows on the chain. A failed or throttled attempt is logged as a count on a folded row (see "Folded rows"), not as a row of its own. |
| V16.3.2 | Authorization failures are logged: every capability-gate 403 logs an `authz denied` line in Layer 2 (`logCapabilityDenied`, called from inside `gate`, the one per-route capability check every admin route shares, so its ~150 call sites are covered without each having to remember to log). It carries the required capability and the caller's role only. Many audited routes also append a `denied` Layer 1 entry on a gate refusal (for example `downpipe-create`), folded to one row per actor per minute with a `deniedAttempts` count (see "Folded rows"). A refusal from the SEPARATE dual-control gates (a restore or retention-prune apply refused "not approved") is a first-class Layer 1 audit entry already (`restore-apply`, `retention-prune-*`, outcome `denied`), so it is not duplicated here. The generic `authz denied` line stays at Layer 2 rather than the tamper-evident chain, for the same reason the self-assessment already accepts for an unauthenticated 401: a per-denial row into the chain would amplify against the customer's own audit storage (the 10,000-entry cap, the mirror line, the pull feed and any configured push destination) for evidence that restates the same fact each denial. |
| V16.3.4 | Unexpected errors and security-control failures are logged: the admin dispatch runs inside a top-level `try/catch` in `src/index.ts` that emits an error line with the correlation id before the generic 500, and every fail-closed refusal in the auth, step-up and rate-limit paths emits its own error line or closed signal (Layer 2). |
| V16.4.2 | Layer 1 is tamper-evident, not tamper-proof; Layer 2 has no integrity protection after collection. Immutable retention needs an export or a delivery path into a store the operator makes immutable. |
| V16.4.3 | Layers 1 and 2 reach a logically separate system through the Logpush job, the pull feed or the push destination; the operator configures the receiving side. |
