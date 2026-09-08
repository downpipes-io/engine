# Logging inventory

**Standard:** OWASP ASVS 5.0 - V16.1.1
**Scope:** Downpipes engine, console, and offline downpipe CLI
**Date:**

This document is the cross-layer logging inventory required by ASVS V16.1.1 (consolidated,
cross-layer logging inventory for all security-relevant events). It was identified as missing
in the ASVS assessment (PARTIAL P-36). Every claim below is grounded in named source files.

The downpipes engine produces logs across three distinct layers that operate independently.
They are documented here in order of most-structured to least-structured.

---

## Layer 1: Tamper-evident hash-chained audit log

### What it is

The primary security log for the downpipes platform. A SHA-384 hash-chained, append-only
sequence of structured audit events stored in the scheduler Durable Object. Every privileged
action and every denied attempt produces an entry. The chain is tamper-evident: any edit,
insertion, deletion, or reordering of a past entry is detectable via `verifyChain`.

**Source:** `engine/src/admin/audit.ts` (entire module, approximately 610 lines)

### Events recorded

The closed `AuditAction` union (`audit.ts:36-92`) defines the complete set of recordable
actions. No free-form event type can be added without extending this union.

| Action | Description |
|--------|-------------|
| `restore-apply` | A restore was applied (confirmed write-back), success or denied. |
| `restore-request` | A restore request was raised (operator seeking approver dual-control). |
| `restore-approve` | A restore request was approved by a different actor (maker != checker). |
| `restore-reject` | A restore request was rejected by an approver or owner. |
| `downpipe-create` | A downpipe configuration was created or updated. |
| `downpipe-delete` | A downpipe configuration was deleted. |
| `role-change` | A role grant was added, changed, or removed. |
| `group-role-change` | An identity-provider group-to-role mapping was upserted or removed (Owner only). |
| `custom-role-change` | A composable custom role was created/updated or deleted. |
| `key-ceremony-intent` | The operator recorded intent to perform a key ceremony. |
| `access-policy-change-intent` | The operator recorded intent to change the access policy. |
| `config-change-propose` / `-approve` / `-reject` / `-supersede` | The opt-in dual-control config-approval gate lifecycle (maker on propose, checker on approve). |
| `config-policy-change` | The owner-only toggle of the config-approval gate. |
| `bootstrap-consumed` | The one-time first-Owner bootstrap was consumed (latched). |
| `break-glass-token-retired` | An Owner retired the ADMIN_TOKEN bearer in-app. |
| `recovery-codes-generated` | A fresh single-use recovery-code set was minted for an email (enrolment or regenerate), invalidating any prior set. |
| `recovery-code-used` | A recovery-code sign-in attempt (success / failed / denied); never the code or its hash. |
| `support-credential-grant` | An owner minted a scoped, expiring support/audit-feed pull credential (replaces any prior credential for the scope). |
| `support-credential-revoke` | An owner cleared a support/audit-feed pull credential. |
| `passkey-credential-revoke` | A WebAuthn credential was removed (theft/loss revocation, ASVS V6.5.6); self-service or by an access-admin/owner. |
| `session-terminate` | A member's sessions were terminated (self "terminate others", admin per-user, or owner all). |
| `retention-prune` | A retention-driven prune of aged records (being added in parallel; the action is part of the catalogue). |
| `engine-secret-present` | Engine-observed: a previously-absent secret/recipient/destination became present (false-to-true status transition). |
| `engine-version-change` | Engine-observed: the engine version changed between two status observations. |

Both successful and denied attempts are recorded as first-class events (`AuditOutcome`:
`success`, `denied`, or `failed`). Denied attempts are enumerated explicitly in `AuditOutcome`
because a review cares about refused actions as much as completed ones (`audit.ts:97`).

### What is NOT recorded

The `AuditTarget` union (`audit.ts:108-144`) is closed; there is no free-form `details` field.
The audit chain never contains:

- Key material of any kind (no private key, no master, no session token)
- Record values (no KV values, no R2 bodies, no D1 rows, no secret values)
- Destination credentials, endpoint URLs, or bucket names
- Private recipient fingerprints
- Licence token or update-channel signer

The comment at `audit.ts:13-19` documents this as "redaction by construction": the safe path
is the only path the types allow.

### Entry format

Each entry is a JSON object stored in DO storage under the key `audit:<seq-zero-padded-20>`.
The fields of `AuditEvent` (`audit.ts:152-173`):

```
seq           - monotonic integer (storage key order is ascending seq)
ts            - RFC-3339 UTC milliseconds
actorSubject  - stable principal (iss|sub for Access, passkey|email for passkey); null for ADMIN_TOKEN or engine-observed events; optional on the wire for backward compatibility
actorEmail    - verified email, lowercased-trimmed (display/audit); null for ADMIN_TOKEN or engine-observed events
actorMethod   - "access" | "passkey" | "token" | "engine"
sourceIp      - CF-Connecting-IP header value; null if absent
action        - AuditAction (closed union above)
outcome       - "success" | "denied" | "failed"
target        - AuditTarget (closed union; redaction-safe fields only)
prevHash      - "sha384:<96 hex chars>" - prior entry's hash, or the genesis sentinel
hash          - "sha384:<96 hex chars>" - SHA-384 over canonical JSON of all fields except hash
```

The hash covers every field in the entry except `hash` itself, using canonical JSON (sorted
keys, no non-integer numbers), identical to the fingerprint and archive hashing discipline
used throughout the codebase (`audit.ts:272-295`, `buildEvent` function).

### Storage location

The scheduler Durable Object. All audit entries share the storage key prefix `audit:` and
are listed with `list({ prefix: "audit:" })` to obtain them in ascending seq order
(lexicographic order over the zero-padded seq is identical to numeric order,
`audit.ts:194-197`).

The chain head (highest seq + hash) is the integrity anchor for exports.

### Retention and rollover

Retention cap: `AUDIT_CAP = 10000` entries (`audit.ts:218`). When the cap is reached, the
oldest entries are rolled over. The rollover is documented and counted, not silent:

- The retained chain stays internally verifiable from the first retained entry.
- The earliest retained seq and the rolled-over count are surfaced to a reviewer.
- `verifyChain` accepts `expectGenesis: false` to treat the first retained entry as the
  baseline after a documented rollover (`audit.ts:339-350`).
- `AUDIT_NEAR_CAP_FRACTION = 0.9`: when the retained count reaches 90% of 10,000, `GET
  /admin/status` sets `auditNearCap: true` so the console can prompt an export
  (`audit.ts:222`).

**Minimum retention period:** Not enforced. There is no TTL, no mandatory minimum retention,
and no automatic export schedule in the codebase. This is an acknowledged open item
(ASVS P-31, P-37).

**WORM / immutability:** The chain is tamper-evident, not tamper-proof. An actor with raw DO
storage write access can rewrite the whole chain undetectably (only post-export truncation
and partial in-place edits are caught by `verifyChain`). True WORM immutability is not
provided by the current implementation. See ASVS P-37.

### SIEM export

`GET /admin/audit/export` returns a self-describing export envelope (`AuditExport`,
`audit.ts:450-456`) carrying the events plus the chain `headSeq` and `headHash`. An external
verifier can confirm completeness: re-running `verifyChain` over the export and comparing the
head hash detects truncation-after-export.

Export formats: JSON (default) or CSV. CSV (`toCSV`, `src/admin/audit.ts:471-500`) renders the target
as a short, redaction-safe human description (`describeTarget`), never as a raw target object,
so no value can leak through the CSV column. The CSV carries a clearly-labelled trailing line
with `headSeq` and `headHash`.

**Shipping:** Two delivery paths now exist alongside the operator-driven export: every
committed audit event is mirrored as a structured log line (src/admin/audit-mirror.ts) that
the operator's Logpush job ships to their SIEM, and `GET /support/audit-feed` serves a
seq-cursored credentialed pull for collectors (docs/SCALE-AND-ENTERPRISE.md section 3).
P-08/P-36 are closed by these paths; configuring Logpush remains the operator's step.

### Access control

- **Read** (`GET /admin/audit`): any authenticated role (viewer, operator, approver, owner).
- **Write**: exclusively the scheduler DO's internal append path. No external caller can
  inject an audit entry; the router builds only `AuditDraft` objects and passes them to the
  DO, which constructs the full entry with the hash chain.
- **Verify** (`GET /admin/audit/verify`): any authenticated role.
- **Export** (`GET /admin/audit/export`): any authenticated role.

---

## Layer 2: Engine operational console.error / console.log stream

### What it is

Unstructured (plain text) log lines emitted by the engine Worker to the Cloudflare Workers
runtime via `console.error` and `console.log`. These are the operational event stream: run
failures, authentication events, restore/drill errors, scheduler unavailability, and the
last-resort top-level error handler.

This layer is distinct from the audit log: it is not hash-chained, not structured, not
access-gated at the application layer, and is operator-consumed through Cloudflare's platform
tooling (Wrangler tail, Logpush).

**Sources:** `engine/src/admin/router.ts`, `engine/src/index.ts`,
`engine/src/admin/drill.ts`, `engine/src/admin/restore.ts`, `engine/src/seal/runstate.ts`

### Sites and messages

Every `console.error` and `console.log` site in the engine source is listed below.

#### Authentication events (`engine/src/admin/router.ts`)

| Site | Level | Message format | What is included | What is excluded |
|------|-------|----------------|------------------|-----------------|
| `src/admin/router-core.ts:113` | `console.error` | `authn failure method=<access\|passkey\|token> reason=<fixed string>` | Attempted method (derived from request shape, not header value); fixed reason string | Token value, assertion bytes, email |
| `src/admin/router-core.ts:125` | `console.log` | `authn success method=<access\|passkey\|token> role=<role>` | Auth method; resolved role | Email (deliberately omitted to avoid PII in the stream) |

The `AUTH_LOG_PREFIX` constant is `"authn"` (`src/admin/router-core.ts:93`), so the lines read `authn
failure ...` / `authn success ...`. The failure line routes to `console.error`
(`logAuthFailure`, `src/admin/router-core.ts:106-114`); the success line to `console.log` (`logAuthSuccess`,
`src/admin/router-core.ts:117-126`). The two are distinguished by level so a log-shipping filter can route
authentication failures to a higher-priority channel.

#### Restore-request client-cue mismatch (`engine/src/admin/router-restore.ts:672`)

| Site | Level | Message format |
|------|-------|----------------|
| `src/admin/router-restore.ts:672` | `console.error` | `restore-request <runId> client cues ignored (server-recomputed wins): claimed isLatest=.../writes=.../bytes=... server isLatest=.../writes=.../bytes=...` |

Logged when the console's advisory cue values do not match the server-recomputed values.
Contains the run id and integer counts (no values, no keys).

#### Drill failures (`engine/src/admin/drill.ts:76`)

| Site | Level | Message format |
|------|-------|----------------|
| `drill.ts:76` | `console.error` | `drill <runId> [err:<errId> <coarse-reason>]` |

Contains the run id, an opaque FNV-1a error id (`errId`), and a coarse hyphenated reason only.
The raw exception message is NOT logged; the opaque id correlates the line to an incident
without disclosing the underlying detail (the engine's `errId` discipline, mirrored from
restore.ts).

#### Restore failures (`engine/src/admin/restore.ts`)

| Site | Level | Message format |
|------|-------|----------------|
| `restore.ts:211` | `console.error` | `restore <runId> refused: <RESERVED_REASON>` (reserved-binding refusal; fixed reason) |
| `restore.ts:226` | `console.error` | `restore <runId> refused: <coarse reason>` (other refusal; coarse reason only) |
| `src/admin/restore-apply.ts:59` | `console.error` | `restore <runId> record <rec.name> [err:<errId> integrity-check-failed]` |
| `src/admin/restore-apply.ts:143` | `console.error` | `restore <runId> record <rec.name> [err:<errId> integrity-check-failed-write-phase]` |
| `src/admin/restore-apply.ts:173` | `console.error` | `restore <runId> record <rec.name> [err:<errId> write-fault]` |
| `src/admin/restore.ts:236` | `console.error` | `restore <runId> [err:<errId> <coarse-reason>]` |
| `src/admin/restore-verify.ts:116` | `console.error` | `restore-verify <runId> record <rec.name> [err:<errId> record-verify-failed]` |
| `src/admin/restore-verify.ts:144` | `console.error` | `restore-verify <runId> [err:<errId> <coarse-reason>]` |
| `src/admin/restore-verify.ts:211` | `console.error` | `restore-attest <runId> [err:<errId> <coarse-reason>]` |

These lines contain the run id, the record name (the KV key / R2 key / secret name) where a
specific record failed, and an opaque FNV-1a error id (`errId`) with a coarse reason. Record
names are already in the downpipe selector config (not a new disclosure). The raw exception
message is NOT logged at the per-record integrity/write sites; the opaque id correlates a line
to an incident without disclosing the crypto/write detail, and no record value can appear.

#### Scheduler cron driver (`engine/src/index.ts`)

| Site | Level | Message format |
|------|-------|----------------|
| `index.ts:135` | `console.error` | `admin request failed: <error.message>` |
| `index.ts:171` | `console.error` | `scheduler reconciliation unavailable, skipping this tick: <error.message>` |
| `index.ts:206` | `console.error` | `run <downpipeId> completion (lock clear) failed: <error.message>` |
| `index.ts:208` | `console.error` | `run <downpipeId> failed: <error.message>` |
| `index.ts:263` | `console.error` | `alerts-delivered feedback failed (non-critical): <error.message>` |
| `index.ts:267` | `console.error` | `alert reconciliation skipped this tick: <error.message>` |
| `runstate.ts:380`, `runstate.ts:443` | `console.error` | `run <downpipeId> (<runId>) failed: <redactedRunError>` |

`index.ts:135` is the top-level last-resort handler (`engine/src/index.ts:121-140`): a
`try/catch` around the entire `handleAdmin` dispatch. It logs the error message only; no
stack trace reaches the client (the response is a generic `{"error":"internal error"}`).

The per-run failure handler now lives in `engine/src/seal/runstate.ts` (`sealRun` was
extracted to the sliced-run path). At `runstate.ts:380` and `:443` it logs the downpipe id,
the run id, and a `redactedRunError` form (the coarse vocabulary plus a SHA-derived `[cause
<hex>]` tag, `slice.ts:300-305`), NOT the raw exception message. The history-row error is the
enumerated `coarseRunError` vocabulary (`slice.ts:284`); neither the row nor the console line
carries the raw message or any record value.

### What is NOT in the console stream

By design, no console line contains:

- Key material (no signer seed, no master key, no capsule bytes)
- Secret values (no KV values, no Secrets Store values)
- Destination credentials or endpoint URLs
- The ADMIN_TOKEN value, any Access JWT assertion bytes, any passkey session token, or any recovery code
- A full stack trace (the top-level handler logs `error.message` only, `index.ts:135`)

### Format

Unstructured plain text. No JSON schema, no structured fields beyond inline key=value pairs
in some lines. Not hash-chained. Not integrity-verifiable post-collection.

### Storage location

Cloudflare Workers runtime standard streams. Accessible via:

- `wrangler tail <worker-name>` - live tail during development or incident response.
- Cloudflare Logpush - operator-configured, streams `console.error` / `console.log` to a
  destination (R2, S3, Splunk, Datadog, etc.).

### Retention

Platform-managed. Cloudflare retains Workers logs for a short window (currently 7 days for
non-Logpush logs, subject to plan limits; verify with Cloudflare documentation). Without
Logpush configured, logs beyond that window are lost.

**Logpush is not configured by default and is not wired as part of the downpipes deployment.**
This is an acknowledged open item (ASVS P-08, P-36). Operators who need durable operational
log retention must configure Logpush themselves.

### Access control

Platform-level. Access to the Cloudflare dashboard, `wrangler tail`, or the Logpush
destination is controlled by the operator's Cloudflare account IAM, not by the application.
No application-layer gate governs who can read the console stream.

---

## Layer 3: Cloudflare Workers platform request logs

### What it is

Cloudflare's platform-level request/response log for the engine and console Workers. These
are generated automatically by the Cloudflare edge for every inbound HTTP request and are
not produced by application code.

### What is included (platform-generated)

Each request log record includes (standard Cloudflare Workers Logpush fields):

- Client IP address
- Request method, URL (path + query string), and HTTP version
- Response status code
- Bytes sent / received
- Ray ID (Cloudflare request identifier)
- Timestamp (UTC)
- Worker invocation duration
- Cloudflare datacenter identifier

### What is NOT included

- Request or response body (Workers Logpush does not include body content)
- Authentication headers (the `Authorization` or `cf-access-jwt-assertion` header value)
- Application-level session or user identity (the platform log has no access to the
  resolved role or the verified email)

### Storage location

Platform-only. Available via:

- Cloudflare dashboard > Workers > Logs (short-lived, not shipped to an external store).
- Cloudflare Logpush - operator-configured pipeline to R2, S3, Splunk, Datadog, or other
  supported sinks.

### Retention

Platform-managed. Short-lived in the dashboard. Persistent only if Logpush is configured.

**Logpush is not configured by default.**

### Access control

Cloudflare account IAM. The operator's account role controls access to the dashboard logs
and the Logpush destination. No application-layer gate applies.

---

## Summary table

| Layer | Format | Storage | Retention | Access control | Integrity | Automatic shipping |
|-------|--------|---------|-----------|----------------|-----------|-------------------|
| Audit log (Layer 1) | JSON, hash-chained, structured | Scheduler Durable Object (`audit:` prefix) | Up to 10,000 entries; oldest rolled over; no minimum TTL enforced | Application auth gate (any authenticated role reads; DO-only writes) | SHA-384 chain; tamper-evident; export head hash for SIEM verification | No - previously operator-driven pull export only; superseded: every committed audit event is now ALSO mirrored as a structured Logpush line (src/admin/audit-mirror.ts) and served via the credentialed GET /support/audit-feed pull |
| Operational console stream (Layer 2) | Plain text, unstructured | Cloudflare Workers runtime (ephemeral) | Short platform window (7 days typical) unless Logpush is configured | Cloudflare account IAM | None (not hash-chained; not integrity-verifiable post-collection) | Only if Logpush is configured by operator |
| Platform request logs (Layer 3) | Platform-structured (Cloudflare Logpush schema) | Cloudflare edge (ephemeral) | Short platform window unless Logpush is configured | Cloudflare account IAM | None | Only if Logpush is configured by operator |

---

## Open items

The following requirements from ASVS V16 are not yet met and are recorded here alongside the
inventory so the gap is visible.

| ASVS ref | Finding | Gap |
|----------|---------|-----|
| V16.1.1 (P-36) | Cross-layer logging inventory | This document closes the inventory gap for Layer 1. Layers 2 and 3 were previously undocumented. |
| V16.3.1 (P-06) | Log authentication successes and failures | Partially closed: Layer 2 now records both success and failure lines (`src/admin/router-core.ts:113`, `src/admin/router-core.ts:125`) for the auth boundary. The closed `AuditTarget` union does not include an authn action as a first-class audit event; the console stream line is the only record. |
| V16.3.4 (P-07) | Log unexpected errors and security-control failures | Closed: the top-level `try/catch` in `index.ts:121-140` catches unexpected throws from the entire `handleAdmin` dispatch and emits `console.error` before returning a generic 500. |
| V16.4.2 (P-37) | Protect logs from unauthorised modification | Layer 1: tamper-evident (hash chain detects partial edits); not tamper-proof against full-chain rebuild. Layer 2: no integrity; ephemeral without Logpush. True WORM requires operator export to an immutable store. |
| V16.4.3 (P-08) | Ship logs to a logically separate system | Implemented: the audit mirror emits every committed event as a structured Logpush line and /support/audit-feed serves a credentialed seq-cursored pull; the operator configures the Logpush job or the collector (SCALE-AND-ENTERPRISE.md section 3). |
