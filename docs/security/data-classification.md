# Data classification inventory

**Standard:** OWASP ASVS 5.0 - V14.1.1 / V14.1.2 / V14.2.4
**Scope:** Downpipes engine, console, and offline downpipe CLI. The vendor control plane has its own
inventory at `control-plane/docs/security/data-classification.md`, on the same four-level scheme.
**Date:**

This document is the sensitivity inventory the engine is assessed against. Section 1 defines the
four protection levels, the regulations they answer to, and the rule for encoded data. Section 1.3
is the requirement set each level carries. Section 2 lists every class of sensitive data the engine
creates, stores or processes and places it at one level. Section 3 summarises. Every protection
claimed below is grounded in a named source file and, where a line is pinned, the identifier in
brackets is on that line. The gate `engine/test/validate-data-classification-doc.ts` checks that
every pinned citation resolves, that every secret-bearing binding in `engine/src/env.d.ts` has a
row, and that the summary table agrees with the asset rows.

Citation form: the repository-relative path with a line or line range in backticks, followed by the
identifier in backticks inside brackets. The identifier is the code on that line, never a comment
that mentions it.

---

## 1. Protection levels

| Level | Name | Meaning |
|-------|------|---------|
| L0 | Public | Deliberately disclosed; no confidentiality requirement. |
| L1 | Internal | Non-secret operational data; integrity matters; access-controlled but not encrypted at rest above the platform floor. |
| L2 | Sensitive | Confidentiality required; encrypted in transit and, where the level's requirement set says so, at rest; access-controlled; audit-logged on access or mutation. |
| L3 | Critical | Highest sensitivity; encrypted with the CNSA-2.0 hybrid suite or held as a Secrets Store value; never logged as plaintext; production access requires dual control or is structurally impossible at the engine level. |

### 1.1 Regulatory inputs

The protection levels take these regulations as inputs. The public compliance pages on the website
(`website/src/pages/compliance/privacy-act.astro`, `website/src/pages/compliance/eu-data-protection.astro`)
make the same claims; this inventory is the internal record those pages rest on.

**Privacy Act 1988 (Cth).** APP 11.1 requires reasonable steps to protect personal information from
misuse, interference, loss, unauthorised access, modification and disclosure. APP 11.2 requires
destruction or de-identification when the information is no longer needed. The Notifiable Data
Breaches scheme (Part IIIC) requires assessment of a suspected eligible breach and notification of
likely serious harm. These apply to every Australian customer, and to the vendor as the operator of
its own control plane.

**GDPR.** Article 5(1)(f) (integrity and confidentiality) and Article 32 (security of processing,
including the ability to restore availability and access to personal data, and regular testing of
the measures) apply to EU customers.

How the levels answer them:

- **L1 operator email and source IP in the audit chain are personal data of the customer's own
  operators.** The engine records the verified caller email as `actorEmail` and the caller's address
  as `sourceIp` on every audit event (`engine/src/admin/audit-types.ts:719` (`actorEmail`),
  `engine/src/admin/audit-types.ts:721` (`sourceIp`)). The customer is the controller of that
  record; the engine runs in the customer's own Cloudflare account and the vendor never reads it.
  The lawful basis is the accountability record for privileged administrative access. The data is
  minimised by construction: section 1.3's privacy column lists each technique.
- **L3 source data may contain personal data for which the customer is the controller.** KV values,
  R2 objects, D1 rows and Secrets Store values are the customer's own data stores. The engine never
  has plaintext custody outside the isolate memory of one run: the value is sealed before any byte
  reaches a destination, and the run master that can open it is destroyed at the end of the run
  (section 2.5). The vendor holds no key that opens an archive (section 4). APP 11.2 and the
  OAIC's "all copies, including back-ups" guidance are met by the opt-in retention prune (section
  1.3, retention column): the customer sets `keepRuns` and `keepDays` and arms `retention.enforce`,
  and the cron then deletes superseded runs on the customer's own schedule.
- **Breach assessment (NDB scheme, GDPR Art 33 and 34).** The hash-chained audit log (section
  2.11) and the run-history ring (section 2.14) are the records a customer's assessment reads. The
  chain is exportable with its head hash so an assessment can prove what it read.

### 1.2 Encoded is not protected

Tiering is by content, never by encoding. A base64url string, a JSON body inside a signed token, or
a cleartext manifest field is classified as the data it decodes to. The engine's encoded-only
artefacts and their level:

| Artefact | What decodes out of it | Level | Where |
|---|---|---|---|
| Cloudflare Access JWT plaintext claims | The verified caller's email, subject, issuer, audience and group claims. The signature proves origin; it hides nothing. | **L1** (same as the extracted email, section 2.10) | `engine/src/admin/auth.ts:166` (`verifyAccessJWT`) |
| Passkey, OIDC and SAML session cookie payload | The session's email, stable subject, method, connection id, epoch, issue and expiry times, last-seen time. The body is base64url JSON with an HMAC-SHA-256 tag: signed, not encrypted. | **L2** (a bearer credential for an authenticated session) | `engine/src/admin/session.ts:229` (`signSession`) |
| `LICENCE_TOKEN` base64url body | The customer's licence claims: tier, expiry, features, bound account tags. The body is canonical JSON, hybrid-signed for integrity, readable by anyone who holds the token. | **L1** content; the token itself is section 2.21 | `engine/src/admin/licence.ts:198` (`JSON.parse`), `engine/src/admin/licence.ts:217` (`canonicalJSON`) |
| Archive manifest cleartext root metadata | Run ids, timing, sizes, record counts, recipient fingerprints, algorithm suite, signer public keys. Signed, not sealed. | **L2** (section 2.9) | `engine/src/format/writer-root.ts:114` (`buildSignedRoot`) |
| Base64url key material in Worker secrets | `SIGNER_PRIVATE`, `OPERATIONAL_PRIVATE`, `CONFIG_RECIPIENT_PRIVATE`, `CONFIG_WRAP_KEY` are base64url text. Decoding yields the raw key. | **L3** regardless of encoding | `engine/src/keys-env.ts:20` (`loadSigner`), `engine/src/keys-env.ts:73` (`loadIdentity`), `engine/src/admin/config-secret.ts:108` (`loadConfigWrapKey`) |
| Base64url session signing key in Durable Object storage | The raw 32-byte HMAC key that signs every session cookie. | **L3** (section 2.16) | `engine/src/admin/session.ts:96` (`SESSION_KEY_BYTES`), `engine/src/sched/scheduler-do-session.ts:187` (`b64urlEncode`) |
| Base64url public keys in Worker secrets and the archive manifest | `BREAK_GLASS_PUBLIC`, `OPERATIONAL_PUBLIC`, `CONFIG_RECIPIENT_PUBLIC`, `UPDATE_SIGNER_PUBLIC`, `LICENCE_SIGNER_PUBLIC`, `VENDOR_SUPPORT_PUBLIC`. Decoding yields a public key. | **L0** (section 2.29) | `engine/src/keys-env.ts:44` (`loadRecipientPublic`) |

### 1.3 Protection requirements per level

This table is the requirement set. Each asset in section 2 states its level and must satisfy every
cell in that level's row. Every cell that claims a control cites the code that implements it, which
is how V14.2.4 ("implemented as defined in the documentation") is checked: the documentation and
the implementation are the same citation. "None required" means the level carries no requirement in
that column.

Log layers are the three defined in `engine/docs/security/logging-inventory.md`: Layer 1 is the
hash-chained audit log in the scheduler Durable Object; Layer 2 is the engine's `console.log` and
`console.error` stream in Workers Logs; Layer 3 is the Cloudflare platform request log.

| Level | Encryption in transit | Encryption at rest (application layer) | Database-level encryption | Integrity verification | Retention | Logging | Access control around this level in logs | Privacy and privacy-enhancing techniques | Other confidentiality |
|---|---|---|---|---|---|---|---|---|---|
| **L0** | HTTPS on every engine surface. The admin origin sends HSTS (`engine/src/index.ts:115` (`strict-transport-security`)). Plain HTTP to a destination is refused at construction (`engine/src/dest/s3-addressing.ts:28` (`requireHttpsEndpoint`)). | None required. | The Cloudflare platform floor: Durable Object storage, KV, D1 and R2 are encrypted at rest by Cloudflare. The level requires nothing above it. | Public keys are committed into the signed archive root through the recipient-set hash and the signer public key (`engine/src/format/writer-root.ts:114` (`buildSignedRoot`)), so a swapped public key is detectable. | Persists until the matching private half rotates. No engine-side deletion. | The value may appear in logs and in `GET /admin/status`. | None required. Layer 1 is readable by every role holding `audit.read`, which every built-in role holds (`engine/src/admin/identity-rbac.ts:34` (`audit.read`)). | None required. | None required. |
| **L1** | HTTPS only. Admin responses carry HSTS (`engine/src/index.ts:115` (`strict-transport-security`)). The engine never retransmits an operator email in an outbound call. | None required. Stored as plaintext fields inside Durable Object records (role table, audit chain, run-history ring, notify channel). | The Cloudflare platform floor. The level requires no application-layer sealing above it. | Origin-verified: an email enters the role table or the audit chain only from an RS256-verified Access assertion (`engine/src/admin/auth.ts:166` (`verifyAccessJWT`)) or an HMAC-verified session (`engine/src/admin/session.ts:229` (`signSession`)). Every audit entry is hashed with SHA-384 over canonical JSON including its predecessor's hash (`engine/src/admin/audit.ts:116` (`auditHash`)); `verifyChain` detects any edit, insertion, deletion or reordering (`engine/src/admin/audit.ts:203` (`verifyChain`)). | Bounded by the store that holds it, enforced by the engine: the audit chain rolls over above `AUDIT_CAP` = 10,000 entries (`engine/src/admin/audit.ts:93` (`AUDIT_CAP`)); the run-history ring holds `RING_CAP` = 50 (`engine/src/sched/scheduler-do-limits.ts:740` (`RING_CAP`)); the drill-evidence log holds `DRILL_EVIDENCE_CAP` = 500 (`engine/src/sched/scheduler-do-records.ts:320` (`DRILL_EVIDENCE_CAP`)). Export before rollover is the operator's step. No minimum retention period is enforced. | The value may appear in Layer 1 (`actorEmail`, `sourceIp`, downpipe and run ids). Layer 2 carries the auth method and the resolved role and never the email (`engine/src/admin/router-core.ts:141` (`logAuthSuccess`)); a failure line carries the attempted method and a fixed reason (`engine/src/admin/router-core.ts:127` (`logAuthFailure`)). Every committed Layer 1 event is mirrored to Layer 2 as one structured line (`engine/src/admin/audit-mirror.ts:26` (`mirrorAuditEvent`)). | Layer 1 read is behind the admin auth gate (`engine/src/admin/auth.ts:155` (`authorise`)) and the `audit.read` capability (`engine/src/admin/identity-rbac.ts:34` (`audit.read`)) on `GET /audit`, `GET /audit/verify` and `GET /audit/export` (`engine/src/admin/router-rbac.ts:287` (`GET /audit`), `engine/src/admin/router-rbac.ts:295` (`GET /audit/verify`), `engine/src/admin/router-rbac.ts:302` (`GET /audit/export`)). Layers 2 and 3 are readable only through the customer's own Cloudflare account IAM; no application-layer gate exists there. Layer 2 omits the email by design (the success line above), so the account-IAM readers of Layer 2 see roles and methods, not people. The audit mirror line is the exception: it carries the same `actorEmail` as Layer 1 into Layer 2 so a SIEM can attribute an event. | Data minimisation: the audit target is a closed union with no free-form field (`engine/src/admin/audit-types.ts:412` (`AuditTarget`)), so a value cannot enter the chain even by a caller's mistake. Email canonicalisation to a lower-cased, trimmed form before storage (`engine/src/admin/identity-roles.ts:114` (`canonicalEmail`)). The token-fallback caller records `actorEmail: null` (`engine/src/admin/auth.ts:350` (`"token"`)). Layer 2 omits the email (`engine/src/admin/router-core.ts:141` (`logAuthSuccess`)). No device or location custody: the engine stores the caller's address as sent by Cloudflare and nothing else about the client. Personal-data basis: `actorEmail` and `sourceIp` are the customer's own operators' data, held for the accountability record (section 1.1). The config-history snapshot stores a webhook's host and a presence flag, never the path or query (`engine/src/admin/config-snapshot.ts:107` (`urlHost`)). | Every `/admin` response carries `cache-control: no-store` and `pragma: no-cache` (`engine/src/index.ts:120` (`cache-control`)), applied on the success path (`engine/src/index.ts:379` (`SECURITY_HEADERS`)) and on the 500 catch path (`engine/src/index.ts:396` (`SECURITY_HEADERS`)). |
| **L2** | HTTPS only, as L1. Archive bytes reach a destination over the R2 binding (no credential on the wire) or SigV4 over HTTPS (`engine/src/dest/sigv4.ts:49` (`signV4`)). | Required where the value would otherwise be readable by a store operator: every record value in an archive is AES-256-GCM sealed in the STREAM construction (`engine/src/crypto/stream.ts:67` (`sealStream`)) before it is written, so the destination holds ciphertext. Durable Object records at this level (audit chain, passkey credential records, approval records, invite records) are stored as plaintext fields; none of them is a secret value. | The Cloudflare platform floor. The archive requires sealing above it (the column to the left); the Durable Object records do not. | Archive: per-segment GCM tag, SHA-384 Merkle root, key commitment (`engine/src/crypto/derive.ts:174` (`keyCommitment`)), recipient-set hash and hybrid Ed25519+ML-DSA-87 signature over the root (`engine/src/format/writer-root.ts:114` (`buildSignedRoot`)). Audit chain: as L1. Session cookie: HMAC-SHA-256 over the body (`engine/src/admin/session.ts:229` (`signSession`)). Passkey credential: the stored COSE public key verifies each assertion. | Archive: the opt-in prune. The cron calls `runRetentionPrunes` every tick (`engine/src/cron/drive.ts:195` (`runRetentionPrunes`)). The planner always plans; the apply runs only when that downpipe's own `retention.enforce` is the literal `true` (`engine/src/cron/retention-pass.ts:477` (`retention.enforce`), `engine/src/cron/retention-pass.ts:503` (`applyPrune`), `engine/src/seal/prune.ts:497` (`applyPrune`)). The operator-driven prune route applies the same gate (`engine/src/admin/router-retention-prune.ts:492` (`wantsRealApply`)). Bound: the union of `keepRuns` and `keepDays`. Customer-managed: the bucket's own lifecycle rules and Object-Lock window. Audit chain: `AUDIT_CAP` as L1. Approvals: 24 hours (`engine/src/admin/approvals.ts:142` (`APPROVAL_TTL_MS`)). Invites: 7 days, single use (`engine/src/admin/passkey.ts:149` (`INVITE_TTL_MS`)). | The value never appears in any layer. Names may: downpipe ids and names, run ids, record counts, plan hashes, credential ids. Values are structurally excluded from Layer 1 by the closed target union (`engine/src/admin/audit-types.ts:412` (`AuditTarget`)) and from Layer 2 by the coarse error vocabulary (`engine/src/seal/slice.ts:611` (`coarseRunError`)). | As L1: Layer 1 behind `authorise` and `audit.read`; Layers 2 and 3 behind account IAM; Layer 2 omits the email. | Data minimisation as L1. Redaction by construction through `AuditTarget`. The support bundle and the evidence pack carry presence flags and counts, never a key, a secret value or a record value (section 2.28). The audit export and the audit mirror carry the chain fields so a reader can prove completeness without the engine's help. | `cache-control: no-store` on every `/admin` response, as L1. Destination endpoint, bucket name and credentials are never logged and never returned by `GET /admin/status`, which reports a `destKind` enum only (`engine/src/admin/status.ts:45` (`destKind`)). |
| **L3** | Never transmitted in plaintext. Source values leave the isolate only as ciphertext. Key material in Worker secrets is never transmitted. Bearer secrets travel only as an `Authorization` header over HTTPS. Backup of secrets, and of every other source, is refused unless the break-glass recipient is present (`engine/src/seal/runstate.ts:394` (`BREAK_GLASS_PUBLIC`)). | Required. Source values: AES-256-GCM STREAM per record (`engine/src/crypto/stream.ts:67` (`sealStream`)) under a file key derived from the per-run master by HKDF-SHA-384 (`engine/src/crypto/derive.ts:82` (`deriveNonSecretFileKey`), `engine/src/crypto/derive.ts:111` (`deriveSecretsFileKey`)); the master is wrapped to each recipient by the hybrid X25519+ML-KEM-1024 capsule (`engine/src/crypto/capsule.ts:118` (`sealToRecipients`)). Credentials the console stores in the Durable Object: AES-256-GCM envelope under `CONFIG_WRAP_KEY` (`engine/src/admin/config-secret.ts:138` (`wrapConfigSecret`)). Worker secrets: Cloudflare Secrets Store custody. | The Cloudflare platform floor is not sufficient for this level. Every L3 value in a Durable Object must be sealed above it, or must not be there at all. Sealed: console-set destination secret, notify, push, OTLP and discovery credentials, when `CONFIG_WRAP_KEY` is set (`engine/src/env.d.ts:335` (`CONFIG_WRAP_KEY`), `engine/src/admin/config-secret.ts:184` (`resolveConfigSecret`), `engine/src/dest/factory.ts:204` (`fetchDestConfig`)); absent the key, the same values sit at the platform floor and the posture check recommends setting it. Held at the platform floor by design, and named as such in their rows: the session signing key (section 2.16), the recovery-code signing key (section 2.17) and the IdP client secret (section 2.18), because the Durable Object has no env and cannot reach a wrap key. Never in a store: the per-run master (section 2.5) and the break-glass private key (section 2.6). | Source values: GCM tag, Merkle root, key commitment, hybrid signature, as L2. Key material: the recipient-set hash commits every recipient public key into the signed root; the signer public key is in the manifest. Bearer secrets: compared in constant time over a digest (`engine/src/admin/auth.ts:357` (`tokenEqual`), `engine/src/admin/scim.ts:78` (`scimBearerOk`)). | Source values: the opt-in prune as L2, which deletes ciphertext the customer's policy no longer wants. Per-run master: zeroised at the end of the run (`engine/src/seal/runstate.ts:325` (`master.fill`)). Worker secrets: persist until the operator rotates them on the cadence in `engine/docs/security/cryptography-and-keys.md`. Durable Object secrets: the session signing key persists until terminate-all deletes it; the IdP client secret persists until its connection is deleted. | Never logged as a value, in any layer. Presence only: `GET /admin/status` reports `signerConfigured`, `breakGlassConfigured` and `operationalConfigured` booleans (`engine/src/admin/status.ts:399` (`signerConfigured`), `engine/src/admin/status.ts:406` (`breakGlassConfigured`), `engine/src/admin/status.ts:436` (`OPERATIONAL_PRIVATE`)). A secret's name (the binding name) may appear in downpipe config and audit targets; `SecretsSource.estimate` never reads a value (`engine/src/sources/secrets.ts:69-71` (`estimate`)). | As L1 for Layer 1 (`authorise` and `audit.read`). Because no L3 value is ever written to any layer, the log access control at this level is the control over names: binding names and downpipe ids are L1 data and inherit L1's gate. | Redaction by construction (`AuditTarget`). The secrets segment carries a per-record random salt in addition to the master-derived key so an archive reader cannot correlate two secrets with equal values. The offline reader, the drill and the restore need a recipient private key to recover any value. | No custody: the vendor never holds a key that opens an archive (section 4). The break-glass private key has no code path into the engine (`engine/src/keys-env.ts:65` (`loadRecipients`) accepts only the public half; `engine/src/keys-env.ts:73` (`loadIdentity`) loads only the operational half). A source can never name an engine binding (`engine/src/sched/config-validate.ts:15` (`RESERVED_BINDINGS`), `engine/src/admin/attach-plan.ts:61` (`RESERVED_BINDINGS`), `engine/src/admin/restore-sinks.ts:287` (`RESERVED_BINDINGS`)). Restore apply and enforced prune from browser-recovered masters require step-up and a maker-not-checker approval. `cache-control: no-store` as L1. |

---

## 2. Asset inventory

Each row states the asset's level. Section 1.3 is the requirement set the row must satisfy.

### 2.1 Customer KV values

| Attribute | Detail |
|-----------|--------|
| Description | Plaintext key-value pairs read from a bound `KVNamespace` by `KVSource` during a backup run. |
| Source file | `engine/src/sources/kv.ts:62` (`KVSource`) |
| Protection level | **L3** |
| Confidentiality | The value is sealed with AES-256-GCM in the STREAM construction (`engine/src/crypto/stream.ts:67` (`sealStream`)); the per-record file key is derived from the run master by HKDF-SHA-384 (`engine/src/crypto/derive.ts:82` (`deriveNonSecretFileKey`)). The run master exists only in isolate memory as a 32-byte `crypto.getRandomValues` value for one run (`engine/src/seal/runstate.ts:217` (`getRandomValues`), `engine/src/seal/pipeline.ts:185` (`master`)). It is wrapped to each recipient through the hybrid X25519+ML-KEM-1024 capsule (`engine/src/crypto/capsule.ts:118` (`sealToRecipients`)) before any archive byte is written. |
| Integrity | Each sealed segment carries a GCM authentication tag; the manifest over all segments is Merkle-hashed (SHA-384) and hybrid-signed (Ed25519+ML-DSA-87) at the root (`engine/src/format/writer-root.ts:114` (`buildSignedRoot`)). |
| Transit | Only ciphertext reaches the destination. The S3 path uses SigV4 over HTTPS (`engine/src/dest/sigv4.ts:49` (`signV4`)); the R2 path uses the in-account binding with no credential on the wire (`engine/src/dest/r2.ts:29` (`R2Destination`)). |
| Logging | KV key names may appear in the `include` and `exclude` selector fields of a downpipe config in the scheduler Durable Object; they are presence, not value. Values are never logged: the audit target union is closed (`engine/src/admin/audit-types.ts:412` (`AuditTarget`)) and the run error vocabulary is coarse (`engine/src/seal/slice.ts:611` (`coarseRunError`)). |
| Access control | The engine Worker must be bound to each KV namespace. `RESERVED_BINDINGS` prevents an engine binding from being used as a source (`engine/src/sched/config-validate.ts:15` (`RESERVED_BINDINGS`), `engine/src/admin/attach-plan.ts:61` (`RESERVED_BINDINGS`)). The admin API is gated by the three-method precedence in section 2.10 (`engine/src/admin/auth.ts:155` (`authorise`)). |
| Retention | **Enforced when the downpipe opts in.** The prune planner deletes run-tree objects and orphaned segments beyond the union of the `keepRuns` and `keepDays` bounds (`engine/src/seal/prune.ts:497` (`applyPrune`)). It runs on the cron (`engine/src/cron/drive.ts:195` (`runRetentionPrunes`)) and is plan-only, with no deletion, unless that downpipe's own `retention.enforce` is `true` (`engine/src/cron/retention-pass.ts:477` (`retention.enforce`), `engine/src/admin/router-retention-prune.ts:492` (`wantsRealApply`)). Arming enforcement is a `downpipe.write` action; an apply from browser-recovered per-run masters additionally requires step-up and a dual-control approval for that exact plan. No TTL deletes anything a policy did not ask for. This is deliberate, not an oversight: an unconditional default TTL would delete a customer's own backup archive the first time they never got around to setting a policy, which for a backup product is a worse outcome than the opt-in control it replaces. Every retention and immutability window this engine offers is opt-in for the same reason (the destination-side WORM policy is opt-in too, `engine/src/admin/posture-checks-immutability.ts:86` (`WORM`)); the one unconditional, non-opt-in purge the engine does run (the run-history ring, section 2.14) is safe to force precisely because it deletes the engine's own operational metadata, never a customer's data. |

---

### 2.2 Customer R2 object values

| Attribute | Detail |
|-----------|--------|
| Description | Binary object bodies read from a bound `R2Bucket` by `R2Source` during a backup run. |
| Source file | `engine/src/sources/r2.ts:87` (`R2Source`) |
| Protection level | **L3** |
| Confidentiality | Large R2 objects are streamed into the STREAM seal without full in-memory buffering (`engine/src/crypto/streamseal.ts:65` (`addressStream`)). The sealing model is otherwise identical to KV values above. |
| Integrity | As for KV values. R2 objects also carry a content-addressed segment identifier (`seg/<sha384hex>`) so a deduplication read can confirm identity before writing. |
| Transit | Ciphertext only; R2 binding or SigV4 over HTTPS, as above. |
| Logging | Object key names may be in selector config; values are never logged. |
| Access control | Explicit R2 binding per downpipe; `RESERVED_BINDINGS` guard. |
| Retention | Enforced when the downpipe opts in. Same policy as KV above: the prune planner bounds the archive by `keepRuns` and `keepDays` and deletes only when that downpipe's `retention.enforce` is `true`. See section 2.1 for why there is no engine-forced default. |

---

### 2.3 Customer Secrets Store values

| Attribute | Detail |
|-----------|--------|
| Description | Secret values fetched through named Secrets Store bindings by `SecretsSource` during a backup run. This is the highest-sensitivity source type. |
| Source file | `engine/src/sources/secrets.ts:30` (`SecretsSource`) |
| Protection level | **L3** |
| Confidentiality | Secrets are sealed by the same STREAM mechanism as KV values. The secrets segment is distinguished by its own address class (`engine/src/format/version.ts:66` (`ADDR_SECRETS`)) and its file key mixes a per-record random 16-byte salt in addition to the master-derived key (`engine/src/crypto/derive.ts:111` (`deriveSecretsFileKey`)). The plaintext lives only in isolate memory for the duration of the yield; it is never logged and never written to any object or Durable Object state. A run is refused without the break-glass recipient (`engine/src/seal/runstate.ts:394` (`BREAK_GLASS_PUBLIC`)). |
| Integrity | Per-record GCM tag; Merkle-hashed and hybrid-signed manifest. |
| Transit | Ciphertext only. |
| Logging | Binding names are in downpipe config; values are never logged. `estimate` never reads a secret value (`engine/src/sources/secrets.ts:69-71` (`estimate`)). |
| Access control | Each secret requires an explicit binding declared in `wrangler.toml`; there is no read-all binding. |
| Retention | Enforced when the downpipe opts in. Same policy as KV above. See section 2.1 for why there is no engine-forced default. |

---

### 2.4 Customer D1 values

| Attribute | Detail |
|-----------|--------|
| Description | Row data read from a bound `D1Database` by `D1Source` during a backup run. |
| Source file | `engine/src/sources/d1.ts:61` (`D1Source`), `engine/src/sources/d1-format.ts` |
| Protection level | **L3** |
| Confidentiality | Same STREAM sealing as KV. |
| Integrity | Per-record GCM tag; Merkle root; hybrid signature. |
| Transit | Ciphertext only. |
| Logging | Table and column names are in selector config; row values are never logged. |
| Access control | Explicit D1 binding per downpipe; `RESERVED_BINDINGS` guard. |
| Retention | Enforced when the downpipe opts in. Same policy as KV above. See section 2.1 for why there is no engine-forced default. |

---

### 2.5 Per-run master key

| Attribute | Detail |
|-----------|--------|
| Description | The 32-byte uniformly random run master from which all per-record file keys are derived. It is the symmetric root of confidentiality for one complete backup run. |
| Source file | `engine/src/seal/runstate.ts:217` (`getRandomValues`), `engine/src/format/writer.ts:65` (`master`) |
| Protection level | **L3** |
| Confidentiality | Exists only in Worker isolate memory during the run. It is never written to any persistent store, any Durable Object, or any log, except that a sliced run persists the master wrapped under the signer key in its checkpoint (`engine/src/seal/runstate.ts:162` (`SIGNER_PRIVATE`)), and `SLICED_RUNS_DISABLED` removes even that. It is wrapped to each recipient through the hybrid capsule and only the wrapped form is written to the archive. |
| Integrity | The key commitment over the master (`engine/src/crypto/derive.ts:174` (`keyCommitment`)) is signed into the archive root. The capsule DEM binds the key commitment as AEAD additional data, so a swapped capsule fails GCM authentication on open (`engine/src/crypto/capsule.ts:62` (`openCapsule`)). |
| Transit | Never transmitted in plaintext; only the wrapped capsule bytes travel to the destination. |
| Logging | Never logged. |
| Access control | In-memory only; the Worker isolate boundary is the access control. |
| Retention | Zeroised on every exit from the run (`engine/src/seal/runstate.ts:325` (`master.fill`)). No persistent plaintext copy. |

---

### 2.6 Break-glass private key

| Attribute | Detail |
|-----------|--------|
| Description | The 96-byte offline identity (x25519 scalar, 32 bytes, followed by the ML-KEM-1024 seed, 64 bytes) that can decapsulate the run master from the break-glass capsule wrap. This is the universal recovery key. |
| Source file | `engine/src/crypto/keys.ts:76-78` (`parseIdentity`) (the parse format, used by the reader); `engine/src/keys-env.ts:65` (`loadRecipients`) (only the public half is loaded in-engine) |
| Protection level | **L3** |
| Confidentiality | **The private key is never loaded into the running engine.** `loadRecipients` accepts only the public half (`BREAK_GLASS_PUBLIC`, a 1600-byte x25519+ML-KEM-1024 encapsulation key, `engine/src/keys-env.ts:44` (`loadRecipientPublic`)). The private key is generated offline by the console during the key ceremony, offered for download as a single browser-local file, and is never POSTed to the engine or stored in any server-side component. There is no code path in the engine that reads a break-glass private key. |
| Integrity | The recipient-set hash commits the public key into the signed root, so a tampered public key is detectable by the reader. |
| Transit | Never transmitted to or from the engine. The public key is stored as the Worker secret `BREAK_GLASS_PUBLIC` (`engine/src/env.d.ts:409` (`BREAK_GLASS_PUBLIC`)). |
| Logging | The private key is never logged. The public key is presence-only in `GET /admin/status` (`engine/src/admin/status.ts:406` (`breakGlassConfigured`)). The fingerprint (`dpr1:`) is in the archive manifest and is public. |
| Access control | Offline. Customer responsibility. The console generates it in-browser and instructs immediate offline storage. |
| Retention | Outside engine scope. Customer responsibility for the offline copy. |

---

### 2.7 Operational private key

| Attribute | Detail |
|-----------|--------|
| Description | The 96-byte in-account recipient private key used by the engine for the read-back drill and restore path. Unlike the break-glass key, this private key is held in-account (optionally) and loaded by the engine for drill and restore operations. |
| Source file | `engine/src/keys-env.ts:73` (`loadIdentity`), `engine/src/env.d.ts:418` (`OPERATIONAL_PRIVATE`) |
| Protection level | **L3** |
| Confidentiality | Loaded from the Worker secret binding `OPERATIONAL_PRIVATE` through `loadIdentity`. It lives in isolate memory only for the duration of a drill or restore invocation. It is never written to Durable Object storage, any log, or any archive. Its presence means a full account compromise can decrypt past archives through the operational path; operators who need higher assurance omit this key (the break-glass-only posture). |
| Integrity | The operational public key is committed into the signed archive root through the recipient-set hash, as for the break-glass key. |
| Transit | Never transmitted outside the isolate. |
| Logging | Never logged. Presence reported as `operationalConfigured.private` in `GET /admin/status` (`engine/src/admin/status.ts:436` (`OPERATIONAL_PRIVATE`)). |
| Access control | Worker secret binding; visible only to the engine Worker by Cloudflare's binding model. |
| Retention | Persists as a Worker secret until the operator rotates or deletes it. |

---

### 2.8 Signer private key

| Attribute | Detail |
|-----------|--------|
| Description | The 64-byte composite signing seed (Ed25519 seed, 32 bytes, followed by the ML-DSA-87 seed, 32 bytes) from which the engine derives the signing keys used to sign archive roots and the RUNLOG. |
| Source file | `engine/src/keys-env.ts:20` (`loadSigner`), `engine/src/env.d.ts:408` (`SIGNER_PRIVATE`) |
| Protection level | **L3** |
| Confidentiality | Loaded from the Worker secret binding `SIGNER_PRIVATE` on each run (`engine/src/seal/runstate.ts:162` (`SIGNER_PRIVATE`)) and each drill (`engine/src/admin/drill.ts:271` (`loadSigner`)). The expanded Ed25519 `CryptoKey` and the ML-DSA-87 secret are held in isolate memory only. The stored ML-DSA-87 seed is 32 bytes; the expanded form is derived at load time and never persisted. |
| Integrity | The signer public keys are placed in the archive manifest. A reader pinning the operator's signer public key can verify all runs. An adversary who seizes this key can forge future runs but cannot defeat the pinned-key guard for runs already verified. |
| Transit | Never transmitted outside the isolate. |
| Logging | Never logged. Presence reported as `signerConfigured` in `GET /admin/status` (`engine/src/admin/status.ts:399` (`signerConfigured`)). |
| Access control | Worker secret binding; visible only to the engine Worker. |
| Retention | Persists as a Worker secret until the operator rotates it. No automatic rotation exists. |

---

### 2.9 Destination archive bytes

| Attribute | Detail |
|-----------|--------|
| Description | The ciphertext objects, Merkle structures, manifest, capsule, and RUNLOG written to the destination bucket (R2 or S3-compatible). |
| Source file | `engine/src/dest/r2.ts:29` (`R2Destination`), `engine/src/dest/s3.ts:50` (`S3Destination`), `engine/src/seal/pipeline.ts` |
| Protection level | **L2** (confidentiality is held by the in-archive encryption and integrity by the archive format; the bucket operator cannot read values without a recipient private key) |
| Confidentiality | Every record value is AES-256-GCM sealed; the destination sees only ciphertext. The cleartext root metadata (run ids, timing, sizes, recipient fingerprints, algorithm suite) is in the manifest and is not value-bearing (section 1.2). |
| Integrity | Merkle root, key commitment, recipient-set hash, and hybrid Ed25519+ML-DSA-87 signature over the root. The capsule DEM binds the key commitment as AEAD additional data. Segment objects are content-addressed by SHA-384 and immutable once written. |
| Transit | HTTPS (R2 binding, or SigV4 over HTTPS for S3). |
| Logging | Run ids and record counts are logged in the run-history ring (L1 data). Destination endpoint, bucket and credentials are never logged; `GET /admin/status` reports a `destKind` enum only (`engine/src/admin/status.ts:45` (`destKind`)). |
| Access control | Destination bucket ACLs are customer-managed. The engine holds write credentials (the R2 binding, or the S3 access key and secret). The offline reader requires a recipient private key to recover any value. |
| Retention | **Opt-in prune, plan-only otherwise.** Superseded run trees and orphaned segments beyond the `keepRuns` and `keepDays` union are deleted on the cron when that downpipe's `retention.enforce` is `true` (`engine/src/cron/retention-pass.ts:477` (`retention.enforce`), `engine/src/seal/prune.ts:497` (`applyPrune`)); the operator-driven route applies the same gate (`engine/src/admin/router-retention-prune.ts:492` (`wantsRealApply`)). Without the opt-in the pass reports a plan and deletes nothing. The bucket's own lifecycle rules and any Object-Lock window are customer-managed and sit outside the engine. The run-tree objects and orphaned segments a `retention.enforce` policy targets ARE these archive bytes, not a separate copy: this row and section 2.1 describe the one prune, from two sides. See section 2.1 for why there is no engine-forced default. |

---

### 2.10 Verified caller email (session identity)

| Attribute | Detail |
|-----------|--------|
| Description | The verified caller email used as the identity for RBAC and the audit log `actorEmail` field. It is the `email` claim of a verified Cloudflare Access JWT, or the signed subject of a passkey, OIDC or SAML session. The `ADMIN_TOKEN` bearer path carries no email and records `actorEmail: null`. |
| Source file | `engine/src/admin/auth.ts:272` (`email`) (the session verdict), `engine/src/admin/identity-roles.ts:114` (`canonicalEmail`), `engine/src/admin/audit-types.ts:719` (`actorEmail`) |
| Protection level | **L1** |
| Confidentiality | The email is the customer's own operator identity within their own account. It is recorded in the audit chain and returned from `GET /admin/whoami`. It is not encrypted at rest in the scheduler Durable Object (it is a field of role-table and audit-chain entries). It is personal data of the customer's operator under the Privacy Act 1988 and the GDPR (section 1.1); the customer is the controller and the record is access-controlled. |
| Integrity | Derived from an RS256-verified, audience-and-issuer-checked Cloudflare Access JWT (`engine/src/admin/auth.ts:166` (`verifyAccessJWT`)) or from an HMAC-verified session body. Normalised to a lower-cased, trimmed form before storage (`canonicalEmail`). |
| Transit | Extracted from the signed JWT or session cookie; never retransmitted by the engine in any outbound call. `GET /admin/whoami` returns it only to the authenticated caller. |
| Logging | Recorded as `actorEmail` in every audit event (Layer 1) and in the audit mirror line (Layer 2). The Layer 2 authentication lines omit it (`engine/src/admin/router-core.ts:141` (`logAuthSuccess`)). |
| Access control | Admin API auth gate, three accepted methods in strict precedence (`engine/src/admin/auth.ts:155` (`authorise`)): a verified Cloudflare Access JWT, then a valid passkey, OIDC or SAML session cookie (the engine's own front door), then the `ADMIN_TOKEN` bearer as the lower-assurance break-glass. A present-but-invalid higher method is refused and never falls through to a weaker one (`engine/src/admin/auth.ts:177` (`ok: false`)), which is the anti-downgrade property. The token-fallback caller has `actorEmail: null` (`engine/src/admin/auth.ts:350` (`"token"`)). The token fallback can be removed by `ADMIN_TOKEN_DISABLED` (`engine/src/admin/auth.ts:302` (`ADMIN_TOKEN_DISABLED`)) or by retiring it in-app once an Owner passkey works. |
| Retention | Retained in the audit chain for the lifetime of the chain, subject to the `AUDIT_CAP` rollover (10,000 entries, `engine/src/admin/audit.ts:93` (`AUDIT_CAP`)). No separate email-specific TTL. |

---

### 2.11 Audit log chain

| Attribute | Detail |
|-----------|--------|
| Description | The tamper-evident, SHA-384 hash-chained, append-only log of privileged actions stored in the scheduler Durable Object. Each entry records: seq, RFC 3339 timestamp, actorEmail (or null), actorMethod, sourceIp, action, outcome, a closed AuditTarget, prevHash, and hash. |
| Source file | `engine/src/admin/audit.ts` (the module), `engine/src/admin/audit-types.ts:708` (`AuditEvent`) |
| Protection level | **L2** |
| Confidentiality | The log contains operator email addresses, source IP addresses, downpipe ids and names, run ids, roles and plan hashes. It does not contain, by construction, any key material, secret value, destination credential, endpoint or bucket name: the `AuditTarget` union is closed (`engine/src/admin/audit-types.ts:412` (`AuditTarget`)) and has no free-form field that can receive a value. |
| Integrity | Each entry is SHA-384-hashed over canonical JSON including the prior entry's hash (`engine/src/admin/audit.ts:116` (`auditHash`)). `verifyChain` detects any edit, insertion, deletion or reordering (`engine/src/admin/audit.ts:203` (`verifyChain`)). The export carries the head hash. The chain is tamper-evident, not tamper-proof: an actor with raw Durable Object storage write access could rebuild the whole chain. |
| Transit | Served from `GET /admin/audit` (JSON) and `GET /admin/audit/export` (JSON or CSV) over HTTPS, auth-gated. Two delivery paths carry the chain off-account: every committed event is mirrored as one structured Workers Logs line (`engine/src/admin/audit-mirror.ts:26` (`mirrorAuditEvent`), called at `engine/src/sched/scheduler-do-audit.ts:166` (`mirrorAuditEvent`)) which the customer's own Logpush job ships to their SIEM, and `GET /support/audit-feed` serves a seq-cursored credentialed pull (`engine/docs/security/logging-inventory.md`, "SIEM export"). Configuring Logpush is the customer's step; the vendor operates no sink. |
| Logging | The audit log is the log layer; it does not itself produce further logs for its own operations beyond the mirror line above. |
| Access control | Read: any authenticated role holding `audit.read`, which every built-in role holds (`engine/src/admin/identity-rbac.ts:34` (`audit.read`)). Write: exclusively the scheduler Durable Object's internal append path; no external caller can inject an entry. Verify: `GET /admin/audit/verify` (`engine/src/admin/router-rbac.ts:295` (`GET /audit/verify`)). |
| Retention | Capped at `AUDIT_CAP` = 10,000 entries (`engine/src/admin/audit.ts:93` (`AUDIT_CAP`)); the oldest entries roll over and the rollover count and earliest retained seq are surfaced. The engine enforces no minimum retention period and no mandatory WORM export; export before rollover, and the Logpush mirror, are the customer's steps. |

---

### 2.12 Admin bearer token (ADMIN_TOKEN)

| Attribute | Detail |
|-----------|--------|
| Description | The pre-shared bearer secret used as the lower-assurance fallback authentication path when neither Cloudflare Access nor a session credential is presented. Resolves to the owner role. |
| Source file | `engine/src/env.d.ts:204` (`ADMIN_TOKEN`), `engine/src/admin/auth.ts:341` (`tokenEqual`) |
| Protection level | **L3** |
| Confidentiality | Held as a Worker secret. Compared in constant time over SHA-256 digests (`engine/src/admin/auth.ts:357` (`tokenEqual`)). Never logged: the deny sink records a signal name only (`engine/src/admin/router.ts:315` (`onAuthDeny`)). |
| Integrity | Static secret; no expiry mechanism in the engine. Rotation is a new Worker secret value, set without a redeploy. |
| Transit | Received as a `Bearer` header over HTTPS only (custom-domain-only, HSTS-enforced deployment). |
| Logging | Authentication failures are logged as a coarse method-and-reason line with no token value (`engine/src/admin/router-core.ts:127` (`logAuthFailure`)). Successes produce audit events attributed to `actorEmail: null`. |
| Access control | Available to any caller who knows the value. Every mutating admin route is rate-limited per caller (`engine/src/admin/router.ts:621` (`rateLimited`)). `ADMIN_TOKEN_DISABLED` removes this path entirely (`engine/src/env.d.ts:212` (`ADMIN_TOKEN_DISABLED`)). |
| Retention | Persists as a Worker secret until rotated. |

---

### 2.13 S3 destination credentials

| Attribute | Detail |
|-----------|--------|
| Description | The `DEST_ACCESS_KEY_ID` and `DEST_SECRET_ACCESS_KEY` used to authenticate writes to an S3-compatible destination bucket through SigV4, and the console-set equivalents stored in the scheduler Durable Object (section 2.18). |
| Source file | `engine/src/env.d.ts:321-322` (`DEST_ACCESS_KEY_ID`, `DEST_SECRET_ACCESS_KEY`), `engine/src/dest/s3.ts:126` (`accessKeyID`) |
| Protection level | **L3** |
| Confidentiality | Held as a Worker secret, or as a `CONFIG_WRAP_KEY` envelope in the Durable Object when set from the console. Used only for SigV4 request signing; never embedded in URLs or logs. |
| Integrity | Static long-lived key pair (SigV4 makes each signed request short-lived, but the underlying credential is static). No automatic rotation exists. |
| Transit | Never transmitted; used locally to compute a SigV4 `Authorization` header (`engine/src/dest/sigv4.ts:49` (`signV4`)). The header travels over HTTPS only: `requireHttpsEndpoint` rejects any non-https `DEST_ENDPOINT` at construction, before any credential or byte is signed or sent (`engine/src/dest/s3.ts:134` (`requireHttpsEndpoint`), `engine/src/dest/s3-addressing.ts:28` (`requireHttpsEndpoint`)). |
| Logging | Never logged. `GET /admin/status` reports a `destKind` enum only. |
| Access control | Worker secret binding. The R2 binding path (`DEST_R2`) avoids credentials on the wire entirely and is the documented default. |
| Retention | Persists as a Worker secret until rotated. |

---

### 2.14 Run-history ring and drill evidence (scheduler Durable Object)

| Attribute | Detail |
|-----------|--------|
| Description | Per-downpipe ring of the last N run outcomes in the scheduler Durable Object: run ids, start time, status, record counts, byte counts, coarse error strings. Also the drill-evidence log of restore-test outcomes. |
| Source file | `engine/src/sched/scheduler-do-limits.ts:740` (`RING_CAP`), `engine/src/sched/scheduler-do-records.ts:320` (`DRILL_EVIDENCE_CAP`) |
| Protection level | **L1** |
| Confidentiality | Contains only redaction-safe operational metadata (ids, times, enums, counts). No key material, no record values, no selector details. Coarse error strings use an enumerated vocabulary (`engine/src/seal/slice.ts:611` (`coarseRunError`)). |
| Integrity | Held in Durable Object storage; single-writer by design. |
| Transit | Served from `GET /admin/history` over HTTPS, auth-gated. |
| Logging | Surfaced in the run-history UI. Run ids and timestamps appear in audit events for restore-request operations. |
| Access control | Any authenticated role through `GET /admin/history`. |
| Retention | Two independent bounds. COUNT: `RING_CAP` = 50 run entries per downpipe (`engine/src/sched/scheduler-do-limits.ts:740` (`RING_CAP`)); the drill-evidence log rolls over above `DRILL_EVIDENCE_CAP` = 500; older entries are evicted automatically. AGE (ASVS V14.1.2, added after this document's first CLOSED claim below was found stale): an entry older than `RUN_HISTORY_MAX_AGE_DAYS` (400 days, `engine/src/sched/history-retention.ts:26-27` (`RUN_HISTORY_MAX_AGE_DAYS`)) is purged regardless of how many entries the ring holds, so a low-traffic downpipe no longer keeps a run's metadata for the life of the account. Enforced by a cron-driven pass (`engine/src/cron/history-retention-pass.ts`) that calls the scheduler DO's own purge route (`POST /history-retention-pass`, `engine/src/sched/scheduler-do-routing.ts:303` (`history-retention-pass`)); an in-flight run, or an entry whose timestamp will not parse, is never purged (fail-safe towards retaining data). Proven by `engine/test/validate-run-history-retention.ts`. |

---

### 2.15 Webhook URL and notification channel configuration

| Attribute | Detail |
|-----------|--------|
| Description | The customer-configured HTTPS endpoint the engine POSTs alert payloads to. It is a notify channel's `url`, stored in the scheduler Durable Object under `notify-channel:<id>`. |
| Source file | `engine/src/notify/types.ts:394` (`NotifyChannel`), `engine/src/sched/scheduler-do-notify.ts:187` (`NOTIFY_CHANNEL_PREFIX`) |
| Protection level | **L1** (the URL); a JSM or ServiceNow API key on the same channel is L3 and is section 2.18 |
| Confidentiality | The URL is the customer's own operational endpoint. It may embed a path-based authentication token on the customer's side; the engine treats it opaquely. It is returned verbatim from `GET /admin/notify/channels` to the authenticated console, which is why that read gates on `notify.config` rather than any authenticated role. |
| Integrity | Validated at write time as HTTPS-only with no userinfo component and no `workers.dev` host (`engine/src/notify/types.ts:1016` (`isAllowedWebhookUrl`)). |
| Transit | Transmitted over HTTPS (engine to the customer's own endpoint). |
| Logging | Not logged. The config-history snapshot records the destination host and a presence flag only (`engine/src/admin/config-snapshot.ts:107` (`urlHost`)), never the path, query or full URL. |
| Access control | Read, write and delete: `notify.config`. |
| Retention | Persists in Durable Object storage until the channel is deleted. |

---

### 2.16 Session signing key (Durable Object)

| Attribute | Detail |
|-----------|--------|
| Description | The 32-byte HMAC-SHA-256 key the scheduler Durable Object generates once and uses to sign and verify every passkey, OIDC and SAML session cookie and every step-up token. |
| Source file | `engine/src/admin/session.ts:96` (`SESSION_KEY_BYTES`), `engine/src/sched/scheduler-do-session.ts:186-187` (`getRandomValues`, `PASSKEY_SESSION_KEY_KEY`), `engine/src/sched/scheduler-do-keys.ts:51` (`PASSKEY_SESSION_KEY_KEY`) |
| Protection level | **L3** |
| Confidentiality | A CSPRNG value generated inside the Durable Object and persisted under the single key `passkeySessionKey` as base64url text (section 1.2). It sits at the Cloudflare platform floor: the Durable Object has no env and cannot reach `CONFIG_WRAP_KEY`, so the record cannot be sealed above the floor, and this row names that. The key never leaves the Durable Object; signing and the constant-time verify both run inside it. |
| Integrity | A stored value shorter than 32 bytes or not decodable is refused and regenerated, which signs every session out; the regeneration is counted as an auth signal. |
| Transit | Never transmitted. Only the HMAC tag it produces travels, inside the session cookie. |
| Logging | Never logged. `authPosture` reports presence and age of the key, never the value. |
| Access control | Durable Object storage; reachable only through the Durable Object's own methods. |
| Retention | Persists until `POST /admin/sessions/terminate-all` deletes it (owner-only), after which a fresh key is generated on the next issue. Rotated on incident, not on a calendar (`engine/docs/security/cryptography-and-keys.md`). |

---

### 2.17 Recovery-code signing key and recovery codes (Durable Object)

| Attribute | Detail |
|-----------|--------|
| Description | The HMAC-SHA-256 key under which an operator's banked recovery codes are hashed and verified, and the hashed codes themselves. |
| Source file | `engine/src/sched/scheduler-do-keys.ts:63` (`RECOVERY_SIGNING_KEY_KEY`), `engine/src/sched/scheduler-do-recovery.ts:74` (`RECOVERY_SIGNING_KEY_KEY`) |
| Protection level | **L3** |
| Confidentiality | The key is generated inside the Durable Object and persisted under `recoverySigningKey` at the platform floor, for the same reason as section 2.16. Recovery codes are stored only as keyed hashes; the plaintext code is shown once to the operator and never stored. |
| Integrity | A code verifies only under the stored key; a rate limit per email and per IP bounds guessing. |
| Transit | The plaintext code travels once, in the response that mints it, over HTTPS. |
| Logging | Never logged. Sign-in with a recovery code is an audited event that names the method, never the code. |
| Access control | Durable Object storage. Recovery sign-in is its own audited ceremony. |
| Retention | The key is separate from the session signing key so that terminate-all does not destroy banked codes. Codes persist until used or regenerated. |

---

### 2.18 CONFIG_WRAP_KEY and the sealed credential envelopes

| Attribute | Detail |
|-----------|--------|
| Description | `CONFIG_WRAP_KEY` is an optional base64url AES-256 key in the account Secrets Store. When set, every credential the console stores in the scheduler Durable Object is sealed as a `WrappedSecret` envelope: the console-set destination's secret access key, JSM and ServiceNow API keys on notify channels, the SIEM push and OTLP push authorisation headers, the push S3 secret, and the console-set discovery token. |
| Source file | `engine/src/env.d.ts:335` (`CONFIG_WRAP_KEY`), `engine/src/admin/config-secret.ts:22` (`WrappedSecret`), `engine/src/admin/config-secret.ts:138` (`wrapConfigSecret`), `engine/src/admin/config-secret.ts:146` (`unwrapConfigSecret`); writers: `engine/src/admin/router-destinations.ts:215` (`maybeWrapConfigSecret`), `engine/src/admin/router-ops.ts:28` (`wrapNotifyChannelSecret`), `engine/src/admin/router-push.ts:265` (`maybeWrapConfigSecret`), `engine/src/admin/router-otlp-push.ts:120` (`maybeWrapConfigSecret`), `engine/src/admin/router-discovery.ts:395` (`maybeWrapConfigSecret`); reader: `engine/src/dest/factory.ts:204` (`fetchDestConfig`) |
| Protection level | **L3** (the key and every plaintext it protects) |
| Confidentiality | The key never enters the Durable Object, which has no env; wrapping and unwrapping happen in the engine Worker context. Each envelope is AES-256-GCM with a per-envelope nonce and a domain-separating AAD per secret class (`engine/src/admin/config-secret.ts:39` (`PUSH_SECRET_AAD`), `engine/src/admin/config-secret.ts:55` (`JSM_SECRET_AAD`), `engine/src/admin/config-secret.ts:62` (`SERVICENOW_SECRET_AAD`), `engine/src/admin/config-secret.ts:81` (`DISCOVERY_SECRET_AAD`)), so an envelope only opens in the slot it was sealed for. Absent the key, the same values sit as plaintext fields at the platform floor and the posture check recommends setting it. |
| Integrity | GCM authentication tag; a rotated or wrong key fails closed with a named cause (`engine/src/admin/config-secret.ts:184` (`resolveConfigSecret`)). |
| Transit | The key is never transmitted. Envelopes travel only between the engine Worker and its own Durable Object. |
| Logging | Never logged. A present-but-malformed key fails loud with a class, never the value. |
| Access control | Secrets Store binding for the key; owner-gated console routes for every writer. |
| Retention | The key persists until rotated; there is no re-wrap, so every sealed credential must be re-entered after a rotation. Envelopes persist until the destination, channel or token is deleted. |

---

### 2.19 IdP connection client secrets (Durable Object)

| Attribute | Detail |
|-----------|--------|
| Description | The OAuth client secret of a native OIDC connection, stored write-only under `idpsecret:<id>` beside its connection record. A public client using PKCE stores none. |
| Source file | `engine/src/admin/oidc-store.ts:160-161` (`putIdpSecret`, `storage.put`), `engine/src/admin/oidc-store.ts:168` (`getIdpSecret`), `engine/src/admin/oidc-store.ts:120` (`storage.delete`) |
| Protection level | **L3** |
| Confidentiality | Stored as plaintext in the Durable Object at the platform floor: the Durable Object has no env and cannot reach `CONFIG_WRAP_KEY`, and this row names that. The value is write-only from the admin surface; `getIdpSecret` is internal to the token exchange and no route returns it. The connection record itself holds only a `secretRef` descriptor. |
| Integrity | Not applicable: a bearer credential the engine presents to the IdP. |
| Transit | Sent to the IdP token endpoint over HTTPS only, at code exchange time. |
| Logging | Never logged. The support pack reports presence and lifecycle of the credential, never the value. |
| Access control | Owner-gated connection routes. |
| Retention | Persists until the connection is deleted, which removes both the record and the secret entry. |

---

### 2.20 SCIM bearer token

| Attribute | Detail |
|-----------|--------|
| Description | The dedicated bearer that authenticates the SCIM 2.0 deprovision surface (`/scim/v2/Users`). Separate from `ADMIN_TOKEN` so an identity provider's connector holds a leaver-offboarding credential only. |
| Source file | `engine/src/env.d.ts:222` (`SCIM_BEARER_TOKEN`), `engine/src/admin/scim.ts:78` (`scimBearerOk`), `engine/src/admin/scim.ts:346` (`SCIM_BEARER_TOKEN`) |
| Protection level | **L3** |
| Confidentiality | Worker secret. Compared in constant time over the SHA-384 of each side. When unset, every `/scim/v2` request answers 503 and the surface is off. |
| Integrity | Static secret; no expiry in the engine. |
| Transit | `Authorization: Bearer` over HTTPS only. |
| Logging | Never logged; refusals are counted by class. |
| Access control | Grants deprovision only: role removal and session termination through the existing audited offboarding path, never provisioning or any other write. Listed in `RESERVED_BINDINGS` so no source can read it into an archive. |
| Retention | Persists as a Worker secret until rotated (12-month cadence, `engine/docs/security/cryptography-and-keys.md`). |

---

### 2.21 Licence token

| Attribute | Detail |
|-----------|--------|
| Description | The vendor-signed assurance licence, `<body_b64url>.<sig_b64url>`, read from the `LICENCE_TOKEN` binding or from the Durable Object copy the console activation route stores. |
| Source file | `engine/src/env.d.ts:464` (`LICENCE_TOKEN`), `engine/src/admin/licence.ts:270` (`verifyLicenceToken`), `engine/src/sched/scheduler-do-records.ts:724` (`LICENCE_KEY`) |
| Protection level | **L1** (the decoded body is customer licence claims; a leaked token gates nothing on backups or recovery) |
| Confidentiality | The body is base64url canonical JSON and is readable by anyone who holds the token (section 1.2). It discloses tier, expiry, features and bound account tags. Fail-open by design: absence or invalidity degrades to the community tier. |
| Integrity | Hybrid Ed25519+ML-DSA-87 signature verified against the pinned vendor public key; both halves must verify, and the body must re-canonicalise to the signed bytes (`engine/src/admin/licence.ts:217` (`canonicalJSON`)). |
| Transit | Set as a Worker secret at deploy time or POSTed once to the activation route over HTTPS. |
| Logging | Never logged. Status reports tier and expiry, never the token. |
| Access control | Worker secret or owner-gated activation route. |
| Retention | Persists until replaced by a new token. |

---

### 2.22 Beacon ingest key

| Attribute | Detail |
|-----------|--------|
| Description | The per-account bearer the opt-in vendor beacon presents when POSTing a content-free aggregate to the control plane. Off unless both `BEACON_URL` and `BEACON_INGEST_KEY` are set. |
| Source file | `engine/src/env.d.ts:189` (`BEACON_INGEST_KEY`), `engine/src/cron/beacon-emit.ts:42` (`BEACON_INGEST_KEY`) |
| Protection level | **L3** |
| Confidentiality | Worker secret. Its leak lets a third party forge this one account's beacon, which is advisory data; the vendor's master key that derives it is classified in the control plane's own inventory. |
| Integrity | Not applicable: a bearer. |
| Transit | `Authorization: Bearer` over HTTPS, to `BEACON_URL` only. Never on a backup or restore path. |
| Logging | Never logged. The beacon attempt ring records outcomes only. |
| Access control | Worker secret; listed in `RESERVED_BINDINGS`. |
| Retention | Persists until rotated; rotating the vendor master invalidates it and requires re-issue. |

---

### 2.23 Discovery API token

| Attribute | Detail |
|-----------|--------|
| Description | A read-only Cloudflare API token the customer creates in their own account for account-wide source discovery. Either the `DISCOVERY_API_TOKEN` binding (IaC fallback) or the console-set token stored in the scheduler Durable Object; the stored token wins when both exist. |
| Source file | `engine/src/env.d.ts:515` (`DISCOVERY_API_TOKEN`), `engine/src/admin/router-discovery.ts:395` (`maybeWrapConfigSecret`), `engine/src/sched/scheduler-do-account-config.ts:169` (`DISCOVERY_KEY`) |
| Protection level | **L3** |
| Confidentiality | The binding is a Worker secret. The console-set token is sealed under `CONFIG_WRAP_KEY` with `DISCOVERY_SECRET_AAD` before it reaches the Durable Object (section 2.18), so a storage read yields ciphertext; absent the wrap key it sits at the platform floor. The vendor never sees it. |
| Integrity | Verified live against the Cloudflare API before storage. |
| Transit | Sent only to the Cloudflare API over HTTPS. Never returned by any route. |
| Logging | Never logged. Set and clear are audited as `discovery-token-set` and `discovery-token-cleared` with an `access-policy` target. |
| Access control | Owner-gated set and clear; the binding is in `RESERVED_BINDINGS` so no source can read it into an archive. |
| Retention | The binding persists until rotated (90-day cadence). The stored token persists until cleared. |

---

### 2.24 Passkey credential records (Durable Object)

| Attribute | Detail |
|-----------|--------|
| Description | One record per registered WebAuthn credential: credential id, bound email, COSE public key, algorithm, sign count, transports, AAGUID and creation time, stored under `passkeyCred:<id>`. |
| Source file | `engine/src/sched/scheduler-do-keys.ts:16` (`PASSKEY_CRED_PREFIX`), `engine/src/sched/scheduler-do-passkey.ts:491-499` (`credentialId`, `cosePublicKey`), `engine/src/sched/scheduler-do-passkey.ts:500` (`putPasskeyCred`) |
| Protection level | **L2** |
| Confidentiality | The record holds a public key and an email; no private key material exists server-side. Plaintext fields at the platform floor. |
| Integrity | Each assertion is verified against the stored COSE public key; the sign count is checked and updated. |
| Transit | Created and asserted through the WebAuthn ceremony over HTTPS between the console origin and the engine. |
| Logging | Never logged as a record. The support pack reports registered-credential counts only. Registration and revocation are audited by credential id. |
| Access control | Registration requires a valid invite, the bootstrap slot or an existing session; revocation is `roles.write`. |
| Retention | Persists until the credential is revoked or the member is offboarded. |

---

### 2.25 Dual-control approval records (Durable Object)

| Attribute | Detail |
|-----------|--------|
| Description | One record per restore-apply or prune approval, keyed `approval:<planHash>`: the plan hash, blast-radius cues, the requester's subject and email, the approver's subject and email, groups, reason text, status and timestamps. |
| Source file | `engine/src/admin/approvals.ts:73` (`RestoreApproval`), `engine/src/admin/approvals.ts:131` (`APPROVAL_PREFIX`), `engine/src/sched/scheduler-do-restore-approval.ts:300` (`storage.put`) |
| Protection level | **L2** |
| Confidentiality | Holds operator emails and subjects (L1 personal data, section 1.1) and a free-text reason the requester wrote. No plaintext record value and no key material: the plan hash is a SHA-384 over the plan, recomputable from the live RUNLOG. |
| Integrity | Maker and checker must differ on subject and on email, enforced inside the Durable Object; a changed plan yields a different hash with no matching approval. |
| Transit | HTTPS, auth-gated routes. |
| Logging | Audited on request, approve, reject and consume with both identities on the event. |
| Access control | Approve requires the approver rank and a fresh step-up; the requester cannot approve their own plan. |
| Retention | 24 hours from the plan anchor (`engine/src/admin/approvals.ts:142` (`APPROVAL_TTL_MS`)); a consumed approval is single use. |

---

### 2.26 Invite tokens (Durable Object)

| Attribute | Detail |
|-----------|--------|
| Description | Single-use, email-bound registration invites under `passkeyInvite:<token>`, and the one deploy-time first-Owner bootstrap invite. |
| Source file | `engine/src/sched/scheduler-do-keys.ts:30` (`PASSKEY_INVITE_PREFIX`), `engine/src/sched/scheduler-do-recovery.ts:977-978` (`INVITE_TTL_MS`, `PASSKEY_INVITE_PREFIX`), `engine/src/sched/scheduler-do-passkey-invites.ts:144` (`storage.delete`) |
| Protection level | **L2** (a bearer for one registration) |
| Confidentiality | The token is random and travels once, in the invite email or the register link. The record holds the bound email and expiry only. |
| Integrity | The registration must present the token and its finish binds the credential to the invited email. |
| Transit | HTTPS; the email path where the `EMAIL` binding is configured. |
| Logging | Never logged. Refusals are counted by class (malformed, absent, expired), never the token or the address. |
| Access control | Minting is `roles.write`; redemption is the public register ceremony, bounded by the token. |
| Retention | 7 days (`engine/src/admin/passkey.ts:149` (`INVITE_TTL_MS`)); the bootstrap invite 24 hours (`engine/src/admin/passkey.ts:170` (`BOOTSTRAP_INVITE_TTL_MS`)). Deleted before the bound email is returned, so an invite authorises at most one registration. |

---

### 2.27 Browser-recovered per-run masters (attended verification and break-glass restore)

| Attribute | Detail |
|-----------|--------|
| Description | A 32-byte per-run master the operator's browser recovered by opening that run's capsule with the break-glass private key, handed to the engine for one verification, restore or enforced prune. |
| Source file | `engine/src/admin/router-attest.ts:294` (`verifyRunWithMaster`), `engine/src/admin/restore-open.ts:72` (`openRunFromMaster`) |
| Protection level | **L3** |
| Confidentiality | In-memory only, for the one request that carries it. The break-glass private key never leaves the browser; the engine receives the single-archive master and nothing that opens another run. Never written to any store. |
| Integrity | Refused unless the master satisfies the run's signed key commitment. |
| Transit | POSTed once over HTTPS by the authenticated, step-up-verified console session. |
| Logging | Never logged. The attended session and its outcome are audited by run id. |
| Access control | Owner-bound attended session; restore apply and enforced prune additionally require a maker-not-checker approval. |
| Retention | Discarded at the end of the request. |

---

### 2.28 Support bundle and evidence pack contents

| Attribute | Detail |
|-----------|--------|
| Description | The redaction-safe diagnostics bundle (`GET /support/bundle`) and the framework evidence pack the console renders and signs. |
| Source file | `engine/src/admin/router-status.ts:286` (`GET /support/bundle`), `engine/src/admin/support.ts:944` (`sealedSupportBundle`), `engine/src/admin/reports.ts:243` (`buildEvidencePackReport`), `engine/src/env.d.ts:197` (`VENDOR_SUPPORT_PUBLIC`) |
| Protection level | **L2** |
| Confidentiality | Presence flags, counts, versions, posture verdicts, downpipe names and coarse error classes. Never a key, a secret value, a record value, a destination endpoint or a bucket name. When `VENDOR_SUPPORT_PUBLIC` is set the bundle is sealed to the vendor support key with the archive's own hybrid capsule construction, so it stays confidential through a ticket system. |
| Integrity | Signed by the engine's run signer so the vendor can verify provenance. |
| Transit | HTTPS, auth-gated. The credentialed pull path serves the same bundle to a collector. |
| Logging | Not logged. Bundle generation is audited. |
| Access control | `posture.read` and the support routes' own gates. |
| Retention | Not stored by the engine; generated on request. Customer-held once downloaded. |

---

### 2.29 Public key material

| Attribute | Detail |
|-----------|--------|
| Description | Public halves, pinned verification keys and public build descriptors: `BREAK_GLASS_PUBLIC`, `OPERATIONAL_PUBLIC`, `CONFIG_RECIPIENT_PUBLIC`, `UPDATE_SIGNER_PUBLIC`, `LICENCE_SIGNER_PUBLIC`, `VENDOR_SUPPORT_PUBLIC`, and the release provenance descriptors `RELEASE_SIGNER_PIN` and `ARTEFACT_SHA384`. Setting any of them grants no access to anything in the account. |
| Source file | `engine/src/env.d.ts:409-410` (`BREAK_GLASS_PUBLIC`, `OPERATIONAL_PUBLIC`), `engine/src/env.d.ts:433` (`CONFIG_RECIPIENT_PUBLIC`), `engine/src/env.d.ts:439` (`UPDATE_SIGNER_PUBLIC`), `engine/src/env.d.ts:465` (`LICENCE_SIGNER_PUBLIC`), `engine/src/env.d.ts:197` (`VENDOR_SUPPORT_PUBLIC`), `engine/src/env.d.ts:258-259` (`ARTEFACT_SHA384`, `RELEASE_SIGNER_PIN`) |
| Protection level | **L0** |
| Confidentiality | None required. The recipient publics are in every archive manifest by fingerprint; the signer pins are meant to be compared. |
| Integrity | Integrity is what these keys verify. Recipient publics are committed into the signed root; a signer pin is the operator's own trust anchor. |
| Transit | Presence-only in `GET /admin/status`; fingerprints in the manifest. |
| Logging | May appear freely. |
| Access control | None needed. |
| Retention | Persists until the corresponding private half rotates. |

---

### 2.30 Config recipient key pair

| Attribute | Detail |
|-----------|--------|
| Description | A recipient key pair whose only job is opening this engine's own sealed configuration export (the control-plane recovery artefact): the roster, topology, destination endpoint and access key id, and the RBAC email addresses. `CONFIG_RECIPIENT_PRIVATE` is the private half; `CONFIG_RECIPIENT_PUBLIC` is section 2.29. |
| Source file | `engine/src/env.d.ts:434` (`CONFIG_RECIPIENT_PRIVATE`), `engine/src/cron/control-plane-pass.ts:204` (`CONFIG_RECIPIENT_PUBLIC`), `engine/src/cron/control-plane-pass.ts:609` (`CONFIG_RECIPIENT_PRIVATE`) |
| Protection level | **L3** |
| Confidentiality | Worker secret. It opens the configuration export and nothing else: a strictly smaller disclosure class than an archive-decryption key, and named as its own class here rather than an absent one. Break-glass stays a recipient of the export in every posture. |
| Integrity | The export is signed by the engine signer; the recipient set is in the sealed envelope. |
| Transit | Never transmitted. |
| Logging | Never logged. Presence reported as a key slot in `GET /admin/status`. |
| Access control | Worker secret binding. |
| Retention | Persists until rotated (12 months, and at any recipient ceremony). An export sealed to the old pair stays openable only with the break-glass key. |

---

## 3. Summary table

The first column carries the section 2 row number. The "Retention enforced" column must agree with
that row's Retention cell; the gate checks it.

| Asset | Level | Encrypted at rest | Encrypted in transit | Integrity verified | Audit-logged | Retention enforced |
|-------|-------|-------------------|----------------------|--------------------|--------------|-------------------|
| 2.1 Customer KV values | L3 | Yes (AES-256-GCM STREAM) | Yes (ciphertext only) | Yes (GCM tag, Merkle root, signature) | No (names only in config) | Opt-in, enforced when configured (no forced default; see 2.1) |
| 2.2 Customer R2 values | L3 | Yes (AES-256-GCM STREAM) | Yes (ciphertext only) | Yes (GCM tag, Merkle root, signature) | No (names only in config) | Opt-in, enforced when configured (no forced default; see 2.1) |
| 2.3 Customer Secrets values | L3 | Yes (AES-256-GCM STREAM with per-record salt) | Yes (ciphertext only) | Yes (GCM tag, Merkle root, signature) | No (binding names in config only) | Opt-in, enforced when configured (no forced default; see 2.1) |
| 2.4 Customer D1 values | L3 | Yes (AES-256-GCM STREAM) | Yes (ciphertext only) | Yes (GCM tag, Merkle root, signature) | No (table names in config only) | Opt-in, enforced when configured (no forced default; see 2.1) |
| 2.5 Per-run master key | L3 | Not applicable (in-memory only; wrapped in the capsule) | Not applicable (never transmitted) | Yes (key commitment and capsule AAD) | Never | Zeroised at the end of the run |
| 2.6 Break-glass private key | L3 | Not applicable (never in the engine) | Not applicable (never transmitted) | Yes (public key in the signed root) | Never | Customer offline |
| 2.7 Operational private key | L3 | Yes (Worker secret) | Not applicable (never transmitted) | Yes (public key in the signed root) | Never (presence only) | Persists until rotated |
| 2.8 Signer private key | L3 | Yes (Worker secret) | Not applicable (never transmitted) | Yes (public key in the manifest) | Never (presence only) | Persists until rotated |
| 2.9 Destination archive bytes | L2 | Yes (end-to-end CNSA-2.0) | Yes (HTTPS or R2 binding) | Yes (Merkle root, signature, GCM tag) | Run ids and counts only | Opt-in, enforced when configured (no forced default; see 2.9) |
| 2.10 Verified caller email | L1 | No (Durable Object plaintext) | Yes (HTTPS, signed JWT or cookie) | Yes (RS256 JWT or HMAC session) | Yes (`actorEmail` in the chain) | Subject to `AUDIT_CAP` rollover |
| 2.11 Audit log chain | L2 | No (Durable Object) | Yes (HTTPS) | Yes (SHA-384 chain) | Self-describing | Capped at 10,000; rollover surfaced; no minimum period |
| 2.12 ADMIN_TOKEN | L3 | Yes (Worker secret) | Yes (HTTPS bearer) | Not applicable (static) | Failures logged coarsely; successes as null-actor | Persists until rotated |
| 2.13 S3 destination credentials | L3 | Yes (Worker secret, or `CONFIG_WRAP_KEY` envelope) | Yes (SigV4 header over HTTPS) | Not applicable (static) | Never | Persists until rotated |
| 2.14 Run-history ring and drill evidence | L1 | No (Durable Object) | Yes (HTTPS) | Durable Object single-writer | Partial (run ids in restore audit events) | Yes: 50-entry rolling ring AND a 400-day age purge (cron-driven); drill evidence caps at 500 |
| 2.15 Webhook URL | L1 | No (Durable Object) | Yes (HTTPS) | Validated at write | Host and presence only | Persists until deleted |
| 2.16 Session signing key | L3 | No (Durable Object platform floor, named) | Not applicable (never transmitted) | Length-checked on read | Never (presence and age only) | Persists until terminate-all |
| 2.17 Recovery-code signing key and codes | L3 | No (Durable Object platform floor, named); codes as keyed hashes | Code travels once | Keyed hash | Never | Persists until used or regenerated |
| 2.18 CONFIG_WRAP_KEY and envelopes | L3 | Key: Secrets Store; envelopes: AES-256-GCM | Not applicable | GCM tag | Never | Persists until rotated or deleted |
| 2.19 IdP connection client secrets | L3 | No (Durable Object platform floor, named) | Yes (HTTPS to the IdP) | Not applicable | Never | Persists until the connection is deleted |
| 2.20 SCIM bearer token | L3 | Yes (Worker secret) | Yes (HTTPS bearer) | Not applicable | Never | Persists until rotated |
| 2.21 Licence token | L1 | Worker secret or Durable Object | Yes (HTTPS) | Yes (hybrid signature) | Never | Persists until replaced |
| 2.22 Beacon ingest key | L3 | Yes (Worker secret) | Yes (HTTPS bearer) | Not applicable | Never | Persists until rotated |
| 2.23 Discovery API token | L3 | Worker secret, or `CONFIG_WRAP_KEY` envelope | Yes (HTTPS to Cloudflare) | Verified live | Set and clear audited | Persists until rotated or cleared |
| 2.24 Passkey credential records | L2 | No (Durable Object; public key and email) | Yes (HTTPS) | Assertion verified against the stored key | Registration and revocation audited | Persists until revoked |
| 2.25 Dual-control approval records | L2 | No (Durable Object) | Yes (HTTPS) | Plan hash binding | Audited on every transition | 24 hours, single use |
| 2.26 Invite tokens | L2 | No (Durable Object) | Yes (HTTPS or email) | Email-bound | Refusals counted | 7 days, single use |
| 2.27 Browser-recovered per-run masters | L3 | Not applicable (in-memory only) | Yes (HTTPS, once) | Key commitment | Never | Discarded at the end of the request |
| 2.28 Support bundle and evidence pack | L2 | Sealed to `VENDOR_SUPPORT_PUBLIC` when set | Yes (HTTPS) | Signed by the run signer | Generation audited | Not stored |
| 2.29 Public key material | L0 | Not required | Not required | Committed into the signed root | Freely | Persists until the private half rotates |
| 2.30 Config recipient key pair | L3 | Yes (Worker secret) | Not applicable | Export signed | Never (presence only) | Persists until rotated |

---

## 4. No-custody model summary

The central confidentiality property of downpipes is that the vendor and the engine never hold a
key that can decrypt customer data. The tables above reflect this in three facts:

1. The break-glass private key (section 2.6) has no code path into the engine. Only its public half
   is present at runtime.
2. The per-run master key (section 2.5) exists in isolate memory for one run, is never persisted in
   plaintext, and is zeroised at the end of the run. The only persistent form is the hybrid-wrapped
   capsule, which requires a recipient private key the engine does not hold (break-glass) or holds
   only optionally in-account (operational).
3. A full account compromise (adversary 2, `THREAT-MODEL.md`) yields at most the operational key,
   never the break-glass key. The break-glass-only posture (omitting `OPERATIONAL_PRIVATE`) removes
   even that path, at the cost of in-account read-back.

---

## 5. Standards coverage

Every requirement below is MET. Each row also carries the finding id the original ASVS
assessment recorded it under and, where the closure involved separating two conflated
controls or correcting stale wording, the reasoning, so a reader auditing the assessment's
own history can see what changed and why.

| ASVS ref | Where this document answers it |
|----------|--------------------------------|
| V14.1.1 (P-30) | Sections 1, 1.1 and 1.2 define the levels, the regulatory inputs and the content-not-encoding rule. Section 2 classifies every class of sensitive data the engine creates, stores or processes, and section 3 summarises. The gate keeps section 2 in step with the secret-bearing bindings in `engine/src/env.d.ts` and the Durable Object secret keys. This document is what closes the classification gap; the ASVS assessment recorded it as PARTIAL pending this inventory. |
| V14.1.2 (P-31) | Section 1.3 is the documented set of protection requirements per level: encryption in transit, encryption at rest, database-level encryption, integrity verification, retention, logging, access control around the level in logs, privacy techniques, and other confidentiality. CLOSED, correctly scoped: this row was conflating two different controls, and separating them is what closes it honestly. (1) An unconditional, non-opt-in, age-based retention floor for stored records the engine itself owns: the run-history ring (section 2.14) purges entries past `RUN_HISTORY_MAX_AGE_DAYS` (400 days) on every cron pass, with no customer configuration required (`engine/src/sched/history-retention.ts`, proven red-before-green by `engine/test/validate-run-history-retention.ts`). (2) Retention for the customer's own source data - KV, R2, Secrets and D1 values (sections 2.1-2.4) and the destination archive bytes that hold them (section 2.9) - which stays OPT-IN by design, not by omission. The prune planner (`engine/src/seal/prune.ts`) enforces a downpipe's own `keepRuns`/`keepDays` policy the moment `retention.enforce` is `true` (`engine/src/admin/router-retention-prune.ts:492` (`wantsRealApply`)), identically for every source type, because all four are sealed into the one archive per run and pruned by the same downpipe-scoped mechanism regardless of which source produced the bytes. A tier-mandated default TTL for this class was considered and rejected: it would auto-delete a customer's only backup copy the first time they never configured a policy, which is a data-loss regression a backup product cannot accept, and it would be inconsistent with the same opt-in posture the engine already applies to destination-side WORM immutability (`engine/src/admin/posture-checks-immutability.ts`). Section 3's summary table states this precisely (`Opt-in, enforced when configured`) for every affected row instead of a bare "No". Two engine-operational stores still have no age-based purge and remain open, but are OUT OF SCOPE for this row because they are not source-data asset classes: the audit chain (section 2.11, count-capped at 10,000 only) and the config-version history (`CONFIG_HISTORY_CAP`, count-capped only). The admin bearer token, S3 destination credentials and the signer/operational private keys (sections 2.12, 2.13, 2.7, 2.8) are tracked under secret rotation cadence (ASVS V13.3.4), a separate control on its own branch, not this one. |
| V14.2.4 (P-32) | Every cell in section 1.3 that claims a control cites the code that implements it, and every section 2 row cites the code for its level's controls. The gate resolves each citation and its identifier against the tree, so the documentation and the implementation cannot drift apart silently. CLOSED: the controls are implemented, including hybrid-PQ encryption before egress, the SHA-384 hash-chained tamper-evident audit, retention auto-deletion via `seal/prune.ts` (above), `Cache-Control: no-store` on all admin responses (`SECURITY_HEADERS`), and redaction-by-construction; the assessment's earlier "not implemented" wording was stale. |
