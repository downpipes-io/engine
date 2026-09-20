# Logging inventory

**Standard:** OWASP ASVS 5.0, V16.1.1 / V16.2.3
**Scope:** Downpipes engine, console, and offline downpipe CLI. The vendor control plane is a
separate component with its own inventory at `control-plane/docs/security/logging-inventory.md`.
**Date:** 2026-09-13

This document is the cross-layer logging inventory ASVS V16.1.1 asks for. For each layer it
states what is logged, the record format, where the records are stored, how they are used, who
can read them, and how long they are kept. It is also the log inventory V16.2.3 refers to: the
engine and the console store or broadcast log records only to the files and services named
here. Every optional sink is listed with the condition under which it is on.

`test/validate-logging-inventory.ts` grades this document against the tree on every
`validate:chain` run. It fails when the audit action table, the Layer 2 call-site figures, the
set of direct `console.*` emitters, the Layer 4 sink kinds, or any `file:line` citation below
disagrees with the tree. A citation is written as `identifier` (`path:line`); the gate opens
the cited line and requires the identifier on it. Console, CLI and control-plane citations are
graded when that checkout sits beside the engine, and the gate says so when it cannot look.

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
  (`src/sched/scheduler-helpers.ts:97`) re-parses a caller-supplied timestamp with `Date.parse`
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
events held in the scheduler Durable Object. Every privileged action and every refused attempt
produces an entry. The chain is tamper-evident: an edit, insertion, deletion or reordering of a
retained entry is detected by `verifyChain` (`src/admin/audit.ts:203`). It is not tamper-proof:
a holder of raw Durable Object storage could rewrite the whole chain.

**Source:** `src/admin/audit.ts` (chain mechanics, verify, export), `src/admin/audit-types.ts`
(the closed vocabularies), `src/sched/scheduler-do-audit.ts` (the append path).

### Events recorded

The closed action set is `AUDIT_ACTIONS` (`src/admin/audit-types.ts:38`), 92 members, ending
at `] as const` (`src/admin/audit-types.ts:394`). `AuditAction` (`src/admin/audit-types.ts:396`)
is derived from it, so no action outside this table can be written. The gate compares the table
to the constant in both directions.

| Action | What it records |
|--------|-----------------|
| `restore-apply` | A restore apply (confirmed write-back), success or denied. |
| `restore-verified` | A restore receipt anchored to the chain: receipt hash, run id and record counts for an applied restore. |
| `restore-request` | A restore request raised for dual-control approval. |
| `restore-approve` | A restore request approved by a second identity (the maker is not the checker). |
| `restore-reject` | A restore request rejected. |
| `retention-prune-request` | A retention prune apply requested for dual control, bound to a plan hash. |
| `retention-prune-approve` | A retention prune request approved by a second identity. |
| `retention-prune-reject` | A retention prune request rejected. |
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
| `key-ceremony-intent` | The operator recorded intent to run a key ceremony. |
| `keys-installed` | The in-product key install wrote the engine's worker secrets through a one-shot token. |
| `break-glass-rotated` | A new break-glass public key applied. |
| `operational-added` | The operational key pair installed. |
| `operational-removed` | Both operational worker secrets removed (break-glass-only posture). |
| `key-install-failed` | A key install died at a named step with a closed cause. |
| `key-removal-failed` | A key removal died at a named step with a closed cause. |
| `posture-acknowledged` | The customer acknowledged a versioned key-posture statement; version and text hash only. |
| `custody-share-emailed` | One Shamir share emailed to a custodian; counts only. |
| `access-policy-change-intent` | The operator recorded intent to change the access policy. |
| `posture-override-set` | An owner set a per-check posture override. |
| `posture-override-withdrawn` | An owner withdrew a per-check posture override. |
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
| `sources-attached` | Source bindings added to the engine through a one-shot deploy token. |
| `sources-detached` | Source bindings removed. |
| `expiry-cleanup-attested` | The operator attested that a spent ephemeral credential was deleted. |
| `recovery-codes-generated` | A fresh recovery-code set made live for an email, invalidating any prior set. |
| `recovery-codes-staged` | A fresh recovery-code set minted and held pending confirmation. |
| `recovery-code-used` | A recovery-code sign-in attempt: success, failed or denied; never the code. |
| `support-credential-grant` | An owner minted a scoped, expiring pull credential (diagnostics or audit-feed). |
| `support-credential-revoke` | An owner cleared a pull credential. |
| `passkey-credential-revoke` | A WebAuthn credential removed. |
| `signin-factor-revoke` | Every sign-in factor of one member removed in one act. |
| `session-terminate` | Sessions terminated: a member's own other sessions, one member's sessions, or all sessions. |
| `retention-prune` | An applied retention prune deleted superseded runs; the cron (engine actor) or the admin route (human actor). |
| `control-plane-exported` | A signed control-plane export written to the destination bucket. |
| `control-plane-empty` | The health pass found an empty control plane while the bucket holds runs. |
| `control-plane-reconciled` | A break-glass operator rebuilt the Durable Object from a verified export; the first event of the new chain. |
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

Every entry carries an `AuditOutcome` (`src/admin/audit-types.ts:401`): `success`, `denied`
or `failed`. A refused attempt is recorded as a first-class entry with outcome `denied`.

### What is not recorded

The target is the closed `AuditTarget` union (`src/admin/audit-types.ts:406`), 25 target kinds
and no free-form field. A caller can only append an `AuditDraft`
(`src/admin/audit-types.ts:743`), which has no hash, no sequence and no free-form target. The
chain therefore never contains key material, a secret value, a record value, a destination
credential, an endpoint, a bucket name, a private recipient fingerprint, the licence token or
the update-channel signer.

### Entry format

One JSON object per entry, the `AuditEvent` interface (`src/admin/audit-types.ts:693`):

```
seq           monotonic integer
ts            RFC-3339 UTC milliseconds
actorSubject  stable principal (iss|sub for Access, passkey subject for passkey); null for the token bearer and engine-observed events; optional on the wire
actorEmail    verified email; null for the token bearer and engine-observed events
actorMethod   "access" | "passkey" | "token" | "engine"
sourceIp      CF-Connecting-IP value, or null
action        AuditAction (the table above)
outcome       "success" | "denied" | "failed"
target        AuditTarget (closed union)
advisory      optional, idp-sign-in only: the IdP's advisory acr/amr/auth_time
prevHash      "sha384:<96 hex>", the prior entry's hash or the genesis sentinel
hash          "sha384:<96 hex>", SHA-384 over canonical JSON of every other field
```

`buildEvent` (`src/admin/audit.ts:152`) computes the hash over canonical JSON, the same
discipline the archive format uses.

### Storage

The scheduler Durable Object. Every entry sits under the key prefix `AUDIT_PREFIX`
(`src/admin/audit.ts:78`), `audit:`, with a zero-padded sequence from `auditKey`
(`src/admin/audit.ts:107`) so a prefix list returns ascending order. The single write path is
`appendAudit` (`src/sched/scheduler-do-audit.ts:108`), which stores the entry with
`auditKey(seq)` (`src/sched/scheduler-do-audit.ts:118`). The router only posts drafts through
`doURL("/audit")` (`src/admin/router-audit.ts:52`); no external caller can write an entry.

### Retention

`AUDIT_CAP` (`src/admin/audit.ts:93`) is 10,000 entries. Past the cap the Durable Object rolls
over the oldest entries through `rollOverAudit` (`src/sched/scheduler-do-audit.ts:178`); the
sequence stays monotonic and the rolled-over count is surfaced. `AUDIT_NEAR_CAP_FRACTION`
(`src/admin/audit.ts:97`) is 0.9: at 9,000 retained entries `GET /admin/status` reports
`auditNearCap` so the console can prompt an export. After a rollover `verifyChain` takes its
baseline from the first retained entry through `expectGenesis` (`src/admin/audit.ts:205`).

No minimum retention period is enforced and there is no TTL. The operator path to keep the full
history is an export before the rollover, or one of the delivery paths below, each of which
carries every committed entry as it is written.

### How it is used and who can read it

| Route | Purpose | Gate |
|-------|---------|------|
| `GET /admin/audit` | Newest-first paged and filtered read with the chain head | `gate(caller, "audit.read")` (`src/admin/router-rbac.ts:291`) |
| `GET /admin/audit/verify` | Recompute the chain; a break is a 200 result naming the first bad sequence | `gate(caller, "audit.read")` (`src/admin/router-rbac.ts:298`) |
| `GET /admin/audit/export` | The whole or filtered log as a download, JSON or `format=csv`, with the head hash | `gate(caller, "audit.read")` (`src/admin/router-rbac.ts:306`) |

Every built-in role from the viewer floor up holds `"audit.read"`
(`src/admin/identity-rbac.ts:52`). The export format is chosen in the Durable Object
(`"csv"` (`src/sched/scheduler-do-audit.ts:560`)); `toCSV` (`src/admin/audit.ts:492`) renders
the target as a short description, never as a raw object, and `csvCell`
(`src/admin/audit.ts:486`) neutralises a leading formula trigger in every column. The head
(`headOf` (`src/admin/audit.ts:308`)) rides with both formats so an external verifier detects
truncation after export.

### Delivery paths

The same committed events reach these services, each carrying `seq`, `prevHash` and `hash` so
a collector can alert on a gap or a hash discontinuity.

| Path | Mechanism | Who turns it on | Retention |
|------|-----------|-----------------|-----------|
| Logpush mirror line | `mirrorAuditEvent` (`src/admin/audit-mirror.ts:26`) writes one JSON line per committed event with `"downpipe-audit"` (`src/admin/audit-mirror.ts:30`) as `source` and `v: 1`; called from the append path and counted on failure by `recordAuditMirrorFailure` (`src/sched/scheduler-do-audit.ts:166`). The line lands in Layer 2's Workers Logs stream. | Always emitted. It leaves the account only if the operator creates a Logpush job on the `workers_trace_events` dataset. | Workers Logs retention, then the Logpush sink's own. |
| Pull feed | `GET /support/audit-feed` is routed at `"/support/audit-feed"` (`src/index.ts:412`) to `handleSupportPull` (`src/admin/support-ingest.ts:264`), scope `"audit-feed"` (`src/admin/support-ingest.ts:266`); ascending, cursored by `afterSeq`. | An Owner mints a client/secret credential for the `audit-feed` scope (audited as `support-credential-grant`). The secret is stored as its SHA-384, verified constant-time, capped at 365 days, one active per scope, and every pull is recorded on the grant. | The collector's own. |
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
`console.debug`. The gate measures that set, excluding comment lines, and fails on any addition
this document does not name.

### Call sites

Measured 2026-09-13: 257 `log(` call sites across 55 files (`src/admin/attach.ts`, `src/admin/drill.ts`, `src/admin/key-vintages.ts`, `src/admin/restore-apply.ts`, `src/admin/restore-plan-types.ts`, `src/admin/restore-plan.ts`, `src/admin/restore-receipt.ts`, `src/admin/restore-verify.ts`, `src/admin/restore.ts`, `src/admin/router-audit.ts`, `src/admin/router-auth-flow.ts`, `src/admin/router-core.ts`, `src/admin/router-custody.ts`, `src/admin/router-identity.ts`, `src/admin/router-idp-web.ts`, `src/admin/router-keys.ts`, `src/admin/router-notify.ts`, `src/admin/router-posture.ts`, `src/admin/router-restore.ts`, `src/admin/router-session.ts`, `src/admin/router-sources.ts`, `src/admin/router-updates-shared.ts`, `src/admin/scim.ts`, `src/admin/updates.ts`, `src/attest/verify.ts`, `src/cron/alert-passes.ts`, `src/cron/beacon-emit.ts`, `src/cron/control-plane-pass.ts`, `src/cron/discovery-pass.ts`, `src/cron/drive.ts`, `src/cron/history-retention-pass.ts`, `src/cron/notify-passes.ts`, `src/cron/otlp-push-pass.ts`, `src/cron/posture-pass.ts`, `src/cron/reconcile-pass.ts`, `src/cron/restore-test-pass.ts`, `src/cron/retention-pass.ts`, `src/cron/seal-loop-pass.ts`, `src/cron/siem-push-pass.ts`, `src/email.ts`, `src/format/keyless.ts`, `src/index.ts`, `src/notify-routing.ts`, `src/sched/scheduler-do-config-version.ts`, `src/sched/scheduler-do-expiry.ts`, `src/sched/scheduler-do-idp.ts`, `src/sched/scheduler-do-passkey.ts`, `src/sched/scheduler-do-recovery.ts`, `src/sched/scheduler-do-scheduling.ts`, `src/sched/scheduler-do.ts`, `src/seal/replicate.ts`, `src/seal/runseal-do.ts`, `src/seal/runstate.ts`, `src/seal/verify-at-seal.ts`, `src/sources/cloudflare-config.ts`), reproducible with:
`grep -rn 'log("error"\|log("warn"\|log("info"\|log("debug"' src --include='*.ts' | grep -v '\.test\.ts' | grep -v '^src/log.ts' | wc -l`.
The figure is a snapshot that moves as logging is added; the gate reproduces the grep and fails
when this paragraph, the file list or the summary table disagrees with the tree.

### What the lines carry

The logger adds no field of its own beyond those listed. The `event` string is chosen at the
call site, and the redaction discipline lives there.

- Authentication lines. `logAuthFailure` (`src/admin/router-core.ts:127`) writes
  `authn failure method=<access|passkey|token> reason=<fixed string>` at level `error`;
  `logAuthSuccess` (`src/admin/router-core.ts:141`) writes
  `authn success method=<method> role=<role>` at level `info`; `logAuthCeremonySuccess`
  (`src/admin/router-core.ts:152`) writes the passkey ceremony that minted a session;
  `logSurfaceAuth` (`src/admin/router-core.ts:158`) writes the outcome for the SCIM, `/metrics`
  and `/support/*` bearer surfaces. The prefix is `AUTH_LOG_PREFIX`
  (`src/admin/router-core.ts:110`). No email, no token and no assertion bytes appear on these
  lines.
- Authorization lines (V16.3.2). `logCapabilityDenied` (`src/admin/router-core.ts:186`) writes
  `authz denied capability=<capability> have=<role>` at level `error`, called from inside `gate`
  (`src/admin/router-core.ts:202`), the one per-route capability check every admin route shares.
  It fires once per capability-gate 403 and never on a grant, and it logs the required capability
  and the caller's role only: no email, no subject and no source IP.
- Last-resort handlers. The admin dispatcher's catch writes `admin-dispatch` (`src/index.ts:388`),
  the non-admin surfaces write `fetch-dispatch` (`src/index.ts:421`), and SCIM writes
  `scim-dispatch` (`src/index.ts:226`). Each line carries `[err:<FNV-1a id> <category>]` and the
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

Cloudflare Workers Logs. `[observability]` (`wrangler.toml:181`) with `enabled = true`
(`wrangler.toml:182`) persists every invocation's log lines in the Cloudflare dashboard. Two
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
in one of `PUSH_FORMATS` (`src/sched/scheduler-do-limits.ts:267`) (`raw-json`, `ndjson`,
`json-array`, `splunk-hec`, `datadog`, `cef`, `leef`, `gelf`), and dispatches on the sink kind
in `deliverResolvedPush` (`src/cron/siem-push-pass.ts:324`).

### Sink kinds

`PUSH_SINKS` (`src/sched/scheduler-do-limits.ts:280`) is the closed selector. Each kind, where
it writes, and the screen that refuses a private or metadata address:

| Sink | Where the records go | Dispatch | Sender | Egress screen |
|------|----------------------|----------|--------|---------------|
| `http` | An HTTPS POST to the configured endpoint (a Splunk HEC intake, a Datadog intake, an HTTP collector); GELF sends one event per POST | `deliverSiemPush` (`src/cron/siem-push-pass.ts:348`), or with the token spliced into the URL (`deliverSiemPush` (`src/cron/siem-push-pass.ts:345`)) | `deliverSiemPush` (`src/notify/siem-push-sender.ts:158`) | `screenSinkHost` (`src/notify/siem-push-sender.ts:169`) and `screenResolvedIfHostname` (`src/notify/siem-push-sender.ts:174`) |
| `s3` | One object per batch in the configured bucket, PutObject only, key `<prefix>/<timestamp>-<afterSeq>-<nextAfterSeq>.<ext>` | `"s3"` (`src/cron/siem-push-pass.ts:325`) to `putSiemBatchToS3` (`src/cron/siem-push-pass.ts:263`), which calls `dest.put` (`src/cron/siem-push-pass.ts:276`) | `S3Destination` (`src/dest/s3.ts:50`) | `isInternalSinkHost` (`src/dest/s3.ts:221`) on the endpoint |
| `syslog-tls` | RFC 5424 records, octet-framed, over one implicit-TLS socket per batch, in `SYSLOG_TLS_FORMATS` (`src/sched/scheduler-do-limits.ts:296`) (`cef`, `leef`) | `"syslog-tls"` (`src/cron/siem-push-pass.ts:329`) to `deliverSiemSyslog` (`src/cron/siem-push-pass.ts:331`) | `deliverSiemSyslog` (`src/notify/siem-syslog-sender.ts:223`) | `canonicaliseBareHost` (`src/notify/siem-syslog-sender.ts:238`) with `isInternalSinkHost` |

Redirects are never followed on any sink, and no response body is read into the trail. The
egress containment is described in `dangerous-functionality.md` section 3 and proven by
`test/validate-egress-host-screen.ts` and `test/validate-ssrf-resolve-screen.ts`.

### Off unless an Owner configures it

`fetchPushConfig` (`src/cron/siem-push-pass.ts:207`) answers `return null`
(`src/cron/siem-push-pass.ts:211`) when no destination record exists, and the pass returns
before any read when the record is not `enabled` (`src/cron/siem-push-pass.ts:448`). Setting,
deleting and test-sending the destination are gated on `gate(caller, "keys.ceremony")`
(`src/admin/router-push.ts:232`), (`src/admin/router-push.ts:303`) and
(`src/admin/router-push.ts:315`). `OWNER_RESERVED_CAPABILITIES`
(`src/admin/identity-rbac.ts:149`) keeps `keys.ceremony` out of every custom role, so only an
Owner can point the audit log at an external service. Each set and clear is audited as
`push-destination-set` or `push-destination-cleared`.

### Delivery guarantee and the trail

At-least-once to acceptance. The cursor advances only when the sink accepted the batch:
`entry.ok` (`src/sched/scheduler-do-siem-push.ts:487`) guards the write of
`SIEM_PUSH_CURSOR_KEY` (`src/sched/scheduler-do-siem-push.ts:490`); any other outcome holds
the cursor so the same events are re-sent next tick. Every event carries a stable `seq` and
`hash`, so a re-delivered batch is safe to dedupe. The Durable Object keeps the most recent
`SIEM_PUSH_TRAIL_CAP` (`src/sched/scheduler-do-limits.ts:446`), 50, delivery outcomes as
closed codes; a failed attempt is also audited as `push-delivery-failure`.

### Retention and access at the sink

Retention is the sink's. Access to the sink is the operator's. The auth header value or S3
secret is sealed under the engine's config wrap key and is never logged.

**Operator guide:** `docs/src/content/docs/day-2/audit-log-push.mdx` in the docs repository,
published at https://docs.downpipes.io/day-2/audit-log-push/.

---

## Outbound telemetry that is not a log sink

These paths leave the account when an operator turns them on. None carries a log record, so a
reviewer should not read them as undocumented log sinks.

| Path | What it carries | On when | Where it lands | Proof |
|------|-----------------|---------|----------------|-------|
| OTLP metrics push | The canonical backup-health snapshot, `OtlpDownpipeMetrics` (`src/sched/scheduler-do-limits.ts:540`): downpipe id and name, enabled flag, last success time, a 0/1 success flag, recent attempt, success and failure counts, duration, size, per-destination health. No audit event, no log line. | An Owner configures a collector (`gate(caller, "keys.ceremony")` (`src/admin/router-otlp-push.ts:101`)) and the record is `enabled` (`src/cron/otlp-push-pass.ts:184`). | The configured OTLP/HTTP collector, POSTed by `deliverOtlpPush` (`src/notify/otlp-push-sender.ts:87`) after `screenSinkHost` (`src/notify/otlp-push-sender.ts:91`); outcomes kept in the Durable Object up to `OTLP_PUSH_TRAIL_CAP` (`src/sched/scheduler-do-limits.ts:523`). Called from `runOtlpPushPass` (`src/cron/drive.ts:299`). | `test/validate-otlp-push.ts` |
| Vendor beacon | The `"downpipe-beacon-v1"` (`src/cron/beacon-emit.ts:54`) aggregate: an opaque account tag, the engine version, the Cloudflare deploy id, the downpipe count, a healthy/stalled split, one account-wide max RUNLOG index, and the emit time. Nothing per downpipe, no name, no value. | `beaconConfigured` (`src/cron/beacon-config.ts:33`): `BEACON_URL`, `BEACON_INGEST_KEY` and `CF_ACCOUNT_ID` all set. Absent any one, `runBeaconEmitPass` (`src/cron/beacon-emit.ts:26`) returns before building a payload. | `POST` to `new URL("/beacon", base)` (`src/cron/beacon-emit.ts:69`) under `BEACON_URL`, refused unless HTTPS and not `isInternalSinkHost` (`src/cron/beacon-emit.ts:70`), with `redirect: "manual"` (`src/cron/beacon-emit.ts:78`). The vendor control plane's `handleBeacon` (`control-plane/src/beacon/receive.ts:186`) stores the aggregate in KV (`BEACONS.put` (`control-plane/src/beacon/receive.ts:263`)) and rejects any per-downpipe field. Called from `runBeaconEmitPass` (`src/cron/drive.ts:256`). | `test/validate-beacon-emit.ts` |
| Notifications | Alert emissions built from the run-history ring: downpipe ids and names, statuses, freshness, enumerated error classes. | An operator configures a channel and a rule. | The operator's own endpoint through `deliverToChannel` (`src/notify-routing.ts:657`) and the adapters under `src/notify/channels/` (email, JSM, PagerDuty, ServiceNow, Slack, Teams, webhook). | `test/validate-notify.ts` |
| Support bundle | The signed, redaction-safe diagnostics bundle: version and provenance, presence-only status, the preflight report, coarse run rows, delivery outcomes, the licence tier. | The operator downloads it (`"GET /support/bundle"` (`src/admin/router-status.ts:286`)) or generates it from the console (`"POST /support/bundle"` (`src/admin/router-status.ts:310`)), both gated on `posture.read`; or vendor support pulls it with an Owner-minted `diagnostics` credential. | The ticket the operator attaches it to, or the vendor's pull. The console's client diagnostics ring is folded in request-scoped by `projectClientDiagnostics` (`src/admin/client-diag-receive.ts:463`) and never written to the Durable Object. | `test/validate-client-diag.ts` |

---

## The console Worker

### Worker-side structured stream

The console has its own emitter, `log` (`console/src/log.ts:55`), with the same field set as
Layer 2 and `SERVICE` (`console/src/log.ts:42`) set to `console`. Errors go to
`console.error` (`console/src/log.ts:76`) and everything else to `console.log`
(`console/src/log.ts:78`). The Worker has one call site: the unhandled-request catch writes
`"request.unhandled"` (`console/src/worker.ts:494`) with the method, the path, status 500 and
`error_code` `unhandled`, never the exception message. The lines land in Workers Logs through
`[observability]` (`console/wrangler.toml:21`) with `enabled = true`
(`console/wrangler.toml:22`); retention and access are as Layer 2.

### Browser-side console lines

The SPA writes to the viewer's own browser console at these sites. Those lines exist only in
that browser's developer tools; nothing reads or ships them.

| Site | Line |
|------|------|
| `console.error` (`console/src/screens/passkey/ceremony.ts:327`) | passkey ceremony refused by the browser |
| `console.error` (`console/src/screens/passkey/ceremony.ts:333`) | passkey ceremony refused |
| `console.error` (`console/src/screens/passkey/ceremony.ts:336`) | passkey transport error |
| `console.error` (`console/src/screens/passkey/ceremony.ts:377`) | recovery sign-in refused |
| `console.error` (`console/src/screens/passkey/ceremony.ts:382`) | recovery transport error |
| `console.error` (`console/src/screens/passkey/flows.ts:284`) | step-up ceremony refused by the browser |
| `console.error` (`console/src/components/data-table-bulkbar.ts:58`) | bulk action failed |
| `console.info` (`console/src/screens/map/controller.ts:447`) | the map's view diagnostics text |

### Client diagnostics ring

`console/src/lib/client-diag/ring.ts` accumulates coarse, closed-class error records in memory
for the session. Every string on a record is a member of a frozen vocabulary; there is no
free-text field. The ring leaves the browser only when the operator presses Generate on the
support screen, which posts it to `POST /support/bundle`, where the engine re-validates it and
folds it into that one bundle. It is never persisted, in the browser or in the engine.

### Sinks that discard or are tour-only

- CSP violation reports go to the same-origin `"/csp-report"` (`console/src/worker.ts:368`)
  route, which answers 204 and stores nothing.
- The public product tour deploy binds `TOUR_ANALYTICS` (`console/src/worker.ts:52`), a Workers
  Analytics Engine dataset, only in `wrangler.public-demo.toml`
  (`TOUR_ANALYTICS` (`console/wrangler.public-demo.toml:59`)). The `"/tour/event"`
  (`console/src/worker.ts:383`) route records closed-name funnel events through
  `writeDataPoint` (`console/src/worker.ts:401`). The genuine console has no such binding and
  the route answers 204 without writing. This is funnel telemetry, not a log.

---

## The offline downpipe CLI

The `downpipe` CLI is the offline reader, a Go program in the `downpipe` repository. It writes
progress and refusals to the terminal's standard error stream, for example `os.Stderr`
(`downpipe/cmd/downpipe/main.go:127`). It creates no log file, keeps no history and contacts no
vendor service. It is not a log producer in the sense of this inventory.

---

## Summary table

| Layer | Format | Storage | Retention | Access control | Integrity | Leaves the account |
|-------|--------|---------|-----------|----------------|-----------|--------------------|
| Audit log (Layer 1) | JSON, hash-chained | Scheduler Durable Object, `audit:` prefix | 10,000 entries, oldest rolled over and counted; no TTL | `audit.read`, held by every built-in role; Durable Object-only writes | SHA-384 chain; head hash rides every export | Through the mirror line (with a Logpush job), the pull feed (with a credential) and the push destination (Layer 4) |
| Operational stream (Layer 2) | Single-line JSON from `src/log.ts`, 257 call sites / 55 files | Cloudflare Workers Logs | Account Workers Logs retention; the Logpush sink's beyond that | Cloudflare account IAM | None after collection | Only with a Logpush job |
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
| V16.3.1 | Every authentication attempt is logged with its method: the `authn` lines in Layer 2, and the `authn-failure`, `idp-sign-in` and `recovery-code-used` rows on the chain. |
| V16.3.2 | Authorization failures are logged: every capability-gate 403 logs an `authz denied` line in Layer 2 (`logCapabilityDenied`, called from inside `gate`, the one per-route capability check every admin route shares, so its ~150 call sites are covered without each having to remember to log). It carries the required capability and the caller's role only. A refusal from the SEPARATE dual-control gates (a restore or retention-prune apply refused "not approved") is a first-class Layer 1 audit entry already (`restore-apply`, `retention-prune-*`, outcome `denied`), so it is not duplicated here. Counter-only, at Layer 2 rather than the tamper-evident chain, for the same reason the self-assessment already accepts for an unauthenticated 401: a per-denial row into the chain would amplify against the customer's own audit storage (the 10,000-entry cap, the mirror line, the pull feed and any configured push destination) for evidence that restates the same fact each denial. |
| V16.3.4 | Unexpected errors and security-control failures are logged: the admin dispatch runs inside a top-level `try/catch` in `engine/src/index.ts` that emits an error line with the correlation id before the generic 500, and every fail-closed refusal in the auth, step-up and rate-limit paths emits its own error line or closed signal (Layer 2). |
| V16.4.2 | Layer 1 is tamper-evident, not tamper-proof; Layer 2 has no integrity protection after collection. Immutable retention needs an export or a delivery path into a store the operator makes immutable. |
| V16.4.3 | Layers 1 and 2 reach a logically separate system through the Logpush job, the pull feed or the push destination; the operator configures the receiving side. |
