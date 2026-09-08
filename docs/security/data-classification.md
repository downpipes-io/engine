# Data classification inventory

**Standard:** OWASP ASVS 5.0 - V14.1.1 / V14.1.2
**Scope:** Downpipes engine, console, and offline downpipe CLI
**Date:**

This document is the per-data-type sensitivity inventory required by ASVS V14.1.1 (classify
all sensitive data into protection levels) and V14.1.2 (document protection requirements per
tier). It supersedes the informal asset list in `THREAT-MODEL.md` with a structured,
auditable record. Every protection claimed below is grounded in named source files; where a
requirement is not yet enforced in code, that is stated explicitly.

---

## 1. Protection levels

| Level | Name | Meaning |
|-------|------|---------|
| L0 | Public | Deliberately disclosed; no confidentiality requirement. |
| L1 | Internal | Non-secret operational data; integrity matters; access-controlled but not encrypted at rest in the primary store. |
| L2 | Sensitive | Confidentiality required; encrypted in transit and, where applicable, at rest; access-controlled; audit-logged on access or mutation. |
| L3 | Critical | Highest sensitivity; encrypted with the CNSA-2.0 hybrid suite; break-glass or Secrets-Store custody; never logged as plaintext; production access requires dual-control or is structurally impossible at the engine level. |

---

## 2. Asset inventory

### 2.1 Customer KV values

| Attribute | Detail |
|-----------|--------|
| Description | Plaintext key-value pairs read from a bound `KVNamespace` by `KVSource` during a backup run. |
| Source file | `engine/src/sources/kv.ts` |
| Protection level | **L3** |
| Confidentiality | The value is sealed with AES-256-GCM in the STREAM construction (`engine/src/crypto/stream.ts`), then the per-record file key is derived from the run master via HKDF-SHA-384 (`engine/src/crypto/derive.ts`). The run master itself exists only as in-memory `RunClock.master` (`engine/src/seal/pipeline.ts:226`) - a 32-byte `crypto.getRandomValues` value - for the duration of a single run invocation. The master is wrapped to each recipient via the hybrid X25519+ML-KEM-1024 KEM-DEM capsule (`engine/src/crypto/capsule.ts:56-69`) before any archive byte is written to the destination. |
| Integrity | Each sealed segment carries a GCM authentication tag; the manifest over all segments is Merkle-hashed (SHA-384) and hybrid-signed (Ed25519+ML-DSA-87) at root (`engine/src/format/writer.ts`). |
| Transit | Only ciphertext reaches the destination. The S3 destination path uses SigV4 over HTTPS; the R2 destination uses the in-account binding with no credential on the wire (`engine/src/dest/r2.ts`, `engine/src/dest/s3.ts`). |
| Logging | KV key names MAY appear in the `include`/`exclude` selector fields of a downpipe config stored in the scheduler DO; they are redaction-safe (presence, not value). Values are never logged - `SecretsSource.estimate()` explicitly documents "never read a secret value to estimate" (`engine/src/sources/secrets.ts:39`), and the same discipline applies to KV via the closed `AuditTarget` union (`engine/src/admin/audit.ts:65-84`). |
| Access control | The engine Worker must be explicitly bound to each KV namespace; `RESERVED_BINDINGS` prevents the engine's own namespaces from being used as a source (`engine/src/index.ts:274`). The admin API is gated by Cloudflare Access JWT or `ADMIN_TOKEN`. |
| Retention | **Not yet enforced.** The destination archive is never automatically deleted or aged out. There is no TTL or purge schedule in the codebase. This is an acknowledged open item (ASVS P-31, P-32). |

---

### 2.2 Customer R2 object values

| Attribute | Detail |
|-----------|--------|
| Description | Binary object bodies read from a bound `R2Bucket` by `R2Source` during a backup run. |
| Source file | `engine/src/sources/r2.ts` |
| Protection level | **L3** |
| Confidentiality | Large R2 objects are streamed directly into the STREAM seal without full in-memory buffering (`engine/src/crypto/streamseal.ts`). The sealing model is otherwise identical to KV values above. |
| Integrity | As for KV values. R2 objects also carry a content-addressed segment identifier (`seg/<sha384hex>`) so a content-deduplication read can confirm identity before writing. |
| Transit | Ciphertext only; R2 binding (in-account, no credential) or S3-over-HTTPS as above. |
| Logging | Object key names may be in selector config; values are never logged. |
| Access control | Explicit R2 binding per downpipe; RESERVED_BINDINGS guard. |
| Retention | Not yet enforced. Same caveat as KV. |

---

### 2.3 Customer Secrets Store values

| Attribute | Detail |
|-----------|--------|
| Description | Secret values fetched through named Secrets Store bindings by `SecretsSource` during a backup run. This is the highest-sensitivity source type. |
| Source file | `engine/src/sources/secrets.ts` |
| Protection level | **L3** |
| Confidentiality | Secrets are sealed by the same STREAM mechanism as KV values. The secrets segment is explicitly distinguished (`ADDR_SECRETS` address class, `engine/src/crypto/segment.ts`), receiving a per-record random 16-byte salt in addition to the master-derived file key, providing an extra isolation layer within the archive. The plaintext "lives only in isolate memory for the duration of the yield; it is never logged, never written to any object or DO state" (source comment, `engine/src/sources/secrets.ts:18-19`). Backing up secrets without the break-glass recipient in the recipient set is refused upstream (`engine/src/seal/pipeline.ts`, `engine/src/index.ts:207`). |
| Integrity | Per-record GCM tag; Merkle-hashed and hybrid-signed manifest. |
| Transit | Ciphertext only. |
| Logging | Secret names (binding names) are in downpipe config; values are never logged. The `estimate()` method documents "never read a secret value to estimate" explicitly. |
| Access control | Each secret requires an explicit binding declared in `wrangler.toml`; there is no read-all binding. |
| Retention | Not yet enforced. |

---

### 2.4 Customer D1 values

| Attribute | Detail |
|-----------|--------|
| Description | Row data read from a bound `D1Database` by `D1Source` during a backup run. |
| Source file | `engine/src/sources/d1.ts`, `engine/src/sources/d1-format.ts` |
| Protection level | **L3** |
| Confidentiality | Same STREAM sealing as KV. |
| Integrity | Per-record GCM tag; Merkle root; hybrid signature. |
| Transit | Ciphertext only. |
| Logging | Table/column names are in selector config; row values are never logged. |
| Access control | Explicit D1 binding per downpipe; RESERVED_BINDINGS guard. |
| Retention | Not yet enforced. |

---

### 2.5 Per-run master key

| Attribute | Detail |
|-----------|--------|
| Description | The 32-byte uniformly-random run master from which all per-record file keys are derived. It is the symmetric root of confidentiality for one complete backup run. |
| Source file | `engine/src/seal/pipeline.ts:226` (`clock.master = crypto.getRandomValues(new Uint8Array(32))`), `engine/src/format/writer.ts:49-55` (WriteParams.master) |
| Protection level | **L3** |
| Confidentiality | Exists only in Worker isolate memory during the run. It is never written to any persistent store, any DO, or any log. It is wrapped to each recipient via the hybrid KEM-DEM capsule and the wrapped form (only) is written to the archive. Once the isolate is evicted the plaintext master is irrecoverable except through the capsule. |
| Integrity | The key commitment (`engine/src/crypto/derive.ts`) over the master is signed into the archive root. The capsule DEM binds the key commitment as AEAD AAD so a swapped capsule fails GCM authentication (`engine/src/crypto/capsule.ts:38-48`). |
| Transit | Never transmitted in plaintext; only the wrapped capsule bytes travel to the destination. |
| Logging | Never logged. |
| Access control | In-memory only; Worker isolate boundary is the access control. |
| Retention | Automatically destroyed at isolate eviction. No persistent copy. |

---

### 2.6 Break-glass private key

| Attribute | Detail |
|-----------|--------|
| Description | The 96-byte offline identity (x25519 scalar (32 bytes) concatenated with ML-KEM-1024 seed (64 bytes)) that can decapsulate the run master from the break-glass capsule wrap. This is the universal recovery key. |
| Source file | `engine/src/crypto/keys.ts:22-24` (parse format); `engine/src/keys-env.ts:53-57` (only the PUBLIC half is loaded in-engine) |
| Protection level | **L3** |
| Confidentiality | **The private key is never loaded into the running engine.** `loadRecipients` accepts only the public half (`BREAK_GLASS_PUBLIC`, a 1600-byte x25519+ML-KEM-1024 encapsulation key). The corresponding private key is generated offline by the console during the key ceremony, offered for download as a single browser-local file, and is never POSTed to the engine or stored in any server-side component. There is no code path in the engine that reads or processes a break-glass private key. |
| Integrity | The recipient-set hash commits the public key into the signed root, so a tampered public key is detectable by the reader. |
| Transit | Never transmitted to or from the engine. The public key is stored in the Secrets Store as `BREAK_GLASS_PUBLIC`. |
| Logging | The private key is never logged. The public key is presence-only in `GET /admin/status` (`breakGlassConfigured: boolean`, `engine/src/admin/status.ts:32`). The fingerprint (dpr1:) is in the archive manifest but is already public. |
| Access control | Offline. Customer responsibility. The console generates it in-browser and instructs immediate offline storage. |
| Retention | Outside engine scope. Customer responsibility for the offline copy. |

---

### 2.7 Operational private key

| Attribute | Detail |
|-----------|--------|
| Description | The 96-byte in-account recipient private key used by the engine for the read-back restore drill path. Unlike the break-glass key, this private key IS held in-account (optionally) and loaded by the engine for drill and restore operations. |
| Source file | `engine/src/keys-env.ts:71-75` (`loadIdentity`, reads `OPERATIONAL_PRIVATE`), `engine/src/env.d.ts:397` |
| Protection level | **L3** |
| Confidentiality | Loaded from the Cloudflare Secrets Store binding `OPERATIONAL_PRIVATE` via `loadIdentity`. It lives in Worker isolate memory only for the duration of a drill or restore invocation. It is never written to DO storage, any log, or any archive. The threat model explicitly notes that its presence means a full account compromise can decrypt past archives through the operational path; operators who need higher assurance omit this key (break-glass-only posture). |
| Integrity | The operational public key is committed into the signed archive root via the recipient-set hash, like the break-glass key. |
| Transit | Never transmitted outside the isolate. |
| Logging | Never logged. Presence reported as `operationalConfigured.private: boolean` in `/admin/status` only. |
| Access control | Secrets Store binding; visible only to the engine Worker by Cloudflare's binding model. |
| Retention | Persists in the Secrets Store until manually deleted. |

---

### 2.8 Signer private key

| Attribute | Detail |
|-----------|--------|
| Description | The 64-byte composite signing seed (Ed25519 seed (32 bytes) concatenated with ML-DSA-87 seed (32 bytes)) from which the engine derives the signing keys used to sign archive roots and the RUNLOG. |
| Source file | `engine/src/keys-env.ts:20-41` (`loadSigner`, reads `SIGNER_PRIVATE`), `engine/src/env.d.ts:387` |
| Protection level | **L3** |
| Confidentiality | Loaded from the Cloudflare Secrets Store binding `SIGNER_PRIVATE` on every run invocation (`engine/src/index.ts:206`). The expanded Ed25519 `CryptoKey` and ML-DSA-87 secret are held in isolate memory only. The ML-DSA-87 seed stored is 32 bytes (not the expanded 4896-byte secret); the expanded form is derived deterministically at load time and never persisted separately. |
| Integrity | The signer public keys are placed in the archive manifest. A reader pinning the operator's signer public key can verify all runs. An adversary who seizes this key can forge future runs but cannot retroactively defeat the pinned-key guard for already-verified runs. |
| Transit | Never transmitted outside the isolate. |
| Logging | Never logged. Presence reported as `signerConfigured: boolean` in `/admin/status` only. |
| Access control | Secrets Store binding; visible only to the engine Worker. |
| Retention | Persists in the Secrets Store until manually rotated. No automatic rotation is implemented. |

---

### 2.9 Destination archive bytes

| Attribute | Detail |
|-----------|--------|
| Description | The ciphertext objects, Merkle structures, manifest, capsule, and RUNLOG written to the destination bucket (R2 or S3-compatible). |
| Source file | `engine/src/dest/r2.ts`, `engine/src/dest/s3.ts`, `engine/src/seal/pipeline.ts` |
| Protection level | **L2** (confidentiality held by the in-archive encryption; integrity held by the archive format; the destination bucket itself is not an L3 store because the bucket operator cannot read values without the private key) |
| Confidentiality | Every record value is AES-256-GCM sealed; the destination sees only ciphertext. The cleartext root metadata (run ids, timing, sizes, recipient fingerprints, algorithm suite) is in the manifest but not value-bearing. |
| Integrity | Merkle root, key commitment, recipient-set hash, and hybrid Ed25519+ML-DSA-87 signature over the root. The capsule DEM binds the key commitment as AEAD AAD. Segment objects are content-addressed by SHA-384 and immutable once written. |
| Transit | HTTPS (R2 binding or SigV4 over HTTPS for S3). |
| Logging | Run ids and record counts are logged in the run-history ring (L1 data). Destination endpoint/bucket/credentials are never logged; `GET /admin/status` reports `destKind` enum only, never the endpoint or bucket name. |
| Access control | Destination bucket ACLs are customer-managed. The engine holds write credentials (R2 binding or S3 access-key/secret in the Secrets Store). The offline reader requires a recipient private key to recover any value. |
| Retention | Customer-managed. Not automatically deleted by the engine. |

---

### 2.10 Verified Access email (session identity)

| Attribute | Detail |
|-----------|--------|
| Description | The `email` claim extracted from a successfully verified Cloudflare Access JWT, used as the caller identity for RBAC and the audit log `actorEmail` field. |
| Source file | `engine/src/admin/auth.ts:63` (verdict.email), `engine/src/admin/identity.ts:45-48` (canonicalEmail), `engine/src/admin/audit.ts:96` (AuditEvent.actorEmail) |
| Protection level | **L1** |
| Confidentiality | The email is the customer's own operator identity within their own account. It is recorded in the audit chain (`actorEmail`) and returned from `GET /admin/whoami`. It is not encrypted at rest in the scheduler DO (it is stored as part of role-table and audit-chain entries). It is not considered a secret by the ASVS context for a single-account, operator-attributable governance product, but it is access-controlled. |
| Integrity | Derived from an RS256-verified, audience-and-issuer-checked Cloudflare Access JWT. Normalised to lowercase-trimmed form before storage (`canonicalEmail`). |
| Transit | Extracted from the signed JWT; never retransmitted by the engine in any outbound call. The `GET /admin/whoami` response returns it only to the authenticated caller. |
| Logging | Recorded as `actorEmail` in every audit event. The `GET /admin/audit` endpoint is access-controlled (any authenticated role). |
| Access control | Admin API auth gate (Cloudflare Access JWT or ADMIN_TOKEN). The token-fallback caller has `actorEmail: null` (no email). |
| Retention | Retained in the audit chain for the lifetime of the chain, subject to the AUDIT_CAP rollover (10,000 entries, `engine/src/admin/audit.ts:145`). No separate email-specific TTL. |

---

### 2.11 Audit log chain

| Attribute | Detail |
|-----------|--------|
| Description | The tamper-evident, SHA-384 hash-chained, append-only log of privileged actions stored in the scheduler Durable Object. Each entry records: seq, RFC-3339 timestamp, actorEmail (or null), actorMethod, sourceIp, action, outcome, a closed AuditTarget, prevHash, and hash. |
| Source file | `engine/src/admin/audit.ts` (entire module) |
| Protection level | **L2** |
| Confidentiality | The log contains operator email addresses, downpipe ids/names, run ids, roles, plan hashes, and IP addresses. It does not contain - by construction - any key material, secret values, destination credentials, endpoints, or bucket names. The `AuditTarget` union (`audit.ts:65-84`) is closed; there is no free-form field that can receive a sensitive value. |
| Integrity | Each entry is SHA-384-hashed over canonical JSON including the prior entry's hash. `verifyChain` detects any edit, insertion, deletion, or reordering. The export carries the head hash. The chain is tamper-evident, not tamper-proof: an actor with raw DO storage write access could rebuild the whole chain. |
| Transit | Served from `GET /admin/audit` (JSON) and `GET /admin/audit/export` (JSON or CSV) over HTTPS, auth-gated. No automatic off-account shipping is implemented. |
| Logging | The audit log IS the log layer; it does not itself produce further logs for its own operations. |
| Access control | Read: any authenticated role. Write: exclusively the scheduler DO's internal `appendAudit` path; no external caller can inject an entry. Verify: `GET /admin/audit/verify` (any role). |
| Retention | Capped at AUDIT_CAP = 10,000 entries; oldest entries are rolled over (documented, not silently dropped). The rollover count and earliest retained seq are surfaced. No minimum retention period or mandatory WORM export is yet enforced - this is an acknowledged gap (ASVS P-31, P-37). |

---

### 2.12 Admin bearer token (ADMIN_TOKEN)

| Attribute | Detail |
|-----------|--------|
| Description | The pre-shared bearer secret used as the lower-assurance fallback authentication path when Cloudflare Access is not configured. Resolves to the owner role unconditionally. |
| Source file | `engine/src/env.d.ts:15`, `engine/src/admin/auth.ts:78-86` |
| Protection level | **L3** |
| Confidentiality | Held in the Cloudflare Secrets Store. Compared with a constant-time SHA-256 digest comparison (`tokenEqual`, `engine/src/admin/auth.ts:337-345`). Never logged (the auth failure log line records the signal name and reason, never the presented token, `onAuthDeny`, `engine/src/admin/router.ts:263-271`). |
| Integrity | Static secret; no expiry mechanism in the engine. Rotation requires deploying a new Secrets Store binding. |
| Transit | Received as a `Bearer` header over HTTPS only (the custom-domain-only, HSTS-enforced Workers deployment). |
| Logging | Authentication failures are logged as a coarse method+reason line (no token value). Successes result in audit events attributed to `actorEmail: null` (unattributable). |
| Access control | Available to any caller who knows the value. Per-caller rate limiting is implemented on every mutating admin route (120 requests per 60 seconds, keyed by the verified caller; src/admin/router.ts rateLimited) - GAP-03 is resolved. `ADMIN_TOKEN_DISABLED` can remove this path entirely for hardened deployments (`env.d.ts:17-23`). |
| Retention | Persists in the Secrets Store until rotated. |

---

### 2.13 S3 destination credentials

| Attribute | Detail |
|-----------|--------|
| Description | The `DEST_ACCESS_KEY_ID` and `DEST_SECRET_ACCESS_KEY` used to authenticate writes to an S3-compatible destination bucket via SigV4 (`engine/src/dest/sigv4.ts`). |
| Source file | `engine/src/env.d.ts:48-49`, `engine/src/dest/s3.ts:16-19` |
| Protection level | **L3** |
| Confidentiality | Held in the Cloudflare Secrets Store. Used only for SigV4 request signing; never embedded in URLs or logs. |
| Integrity | Static long-lived key/secret pair (SigV4 itself makes each signed request short-lived, but the underlying credential is static). No automatic rotation is implemented. |
| Transit | Never transmitted; used only locally to compute a SigV4 `Authorization` header. The header is transmitted over HTTPS only; `requireHttpsEndpoint` (`engine/src/dest/s3.ts:12-25`) rejects any non-https `DEST_ENDPOINT` at construction time, before any credential or byte is signed or sent. |
| Logging | Never logged. `GET /admin/status` reports `destKind` enum only. |
| Access control | Secrets Store binding. The R2 binding path (`DEST_R2`) avoids credentials on the wire entirely and is the documented default. |
| Retention | Persists in Secrets Store. |

---

### 2.14 Run-history ring (scheduler DO)

| Attribute | Detail |
|-----------|--------|
| Description | Per-downpipe circular ring of the last N run outcomes held in the scheduler Durable Object: run ids, start time, status (in-flight / ok / failed), record counts, byte counts, coarse error strings. Maximum ring size (`RING_CAP`) is 50 entries. |
| Source file | `engine/src/sched/scheduler-do.ts` |
| Protection level | **L1** |
| Confidentiality | Contains only redaction-safe operational metadata (ids, times, enums, counts). No key material, no record values, no selector details. Coarse error strings use an enumerated vocabulary (`engine/src/index.ts:179-185`, `coarseRunError`). |
| Integrity | Held in DO storage; single-writer by design. |
| Transit | Served from `GET /admin/history` over HTTPS, auth-gated. |
| Logging | Surfaced in the run-history UI. Run ids and timestamps appear in audit events for restore-request operations. |
| Access control | Any authenticated role via `GET /admin/history`. |
| Retention | Rolling 50-entry ring; older entries are evicted automatically. |

---

### 2.15 Webhook URL

| Attribute | Detail |
|-----------|--------|
| Description | The customer-configured HTTPS endpoint the engine POSTs alert payloads to. It is a notify channel's `url`, stored in the scheduler DO under `notify-channel:<id>`. |
| Source file | `engine/src/notify-routing.ts` (`NotifyChannel`), `engine/src/sched/scheduler-do-notify.ts` |
| Protection level | **L1** |
| Confidentiality | The URL is the customer's own operational endpoint. It may embed a path-based authentication token on the customer's side (the engine treats it opaquely). It is returned verbatim from `GET /admin/notify/channels` to the authenticated console, which is why that read gates on `notify.config` rather than any authenticated role. It is validated as HTTPS-only with no userinfo component and no workers.dev host before storage. |
| Integrity | Validated at write time by `isAllowedWebhookUrl` (`src/notify/types.ts`). |
| Transit | Transmitted over HTTPS (engine to the customer's own endpoint). |
| Logging | Not logged. The config-history snapshot records the destination HOST and a presence boolean only (`urlHost` / `urlConfigured`), never the path, query or full url. |
| Access control | Read, write and delete: `notify.config`. |
| Retention | Persists in DO storage until the channel is deleted. |

---

## 3. Summary table

| Asset | Level | Encrypted at rest | Encrypted in transit | Integrity verified | Audit-logged | Retention enforced |
|-------|-------|-------------------|----------------------|--------------------|--------------|-------------------|
| Customer KV values | L3 | Yes (AES-256-GCM STREAM) | Yes (ciphertext only) | Yes (GCM tag + Merkle + signature) | No (names only in config) | No |
| Customer R2 values | L3 | Yes (AES-256-GCM STREAM) | Yes (ciphertext only) | Yes (GCM tag + Merkle + signature) | No (names only in config) | No |
| Customer Secrets values | L3 | Yes (AES-256-GCM STREAM + per-record salt) | Yes (ciphertext only) | Yes (GCM tag + Merkle + signature) | No (binding names in config only) | No |
| Customer D1 values | L3 | Yes (AES-256-GCM STREAM) | Yes (ciphertext only) | Yes (GCM tag + Merkle + signature) | No (table names in config only) | No |
| Per-run master key | L3 | N/A (in-memory only; wrapped in capsule) | N/A (never transmitted) | Yes (key commitment + capsule AAD) | Never | Auto-destroyed at isolate eviction |
| Break-glass private key | L3 | N/A (never in engine) | N/A (never transmitted) | Yes (public key in signed root) | Never | Customer offline |
| Operational private key | L3 | Yes (Secrets Store) | N/A (never transmitted) | Yes (public key in signed root) | Never (presence only) | Persists in Secrets Store |
| Signer private key | L3 | Yes (Secrets Store) | N/A (never transmitted) | Yes (public in manifest) | Never (presence only) | Persists in Secrets Store |
| Destination archive bytes | L2 | Yes (end-to-end CNSA-2.0) | Yes (HTTPS / R2 binding) | Yes (Merkle + signature + GCM tag) | Run ids / counts only | No |
| Verified Access email | L1 | No (DO storage, plaintext) | Yes (HTTPS + JWT) | Yes (RS256 JWT) | Yes (actorEmail in chain) | Subject to AUDIT_CAP rollover |
| Audit log chain | L2 | No (DO storage) | Yes (HTTPS) | Yes (SHA-384 chain) | Self-describing | Capped at 10,000; rollover documented but WORM export not enforced |
| ADMIN_TOKEN | L3 | Yes (Secrets Store) | Yes (HTTPS Bearer) | N/A (static; no integrity mechanism) | Failures logged (coarse); successes in audit as null-actor | Persists until rotated |
| S3 destination credentials | L3 | Yes (Secrets Store) | Yes (SigV4 header over HTTPS) | N/A (static) | Never | Persists until rotated |
| Run-history ring | L1 | No (DO storage) | Yes (HTTPS) | DO single-writer | Partial (run ids in restore audit events) | 50-entry rolling ring |
| Webhook URL | L1 | No (DO storage) | Yes (HTTPS) | Validated at write | Not specifically | Persists until deleted |

---

## 4. No-custody model summary

The central confidentiality property of downpipes is that the vendor and the engine never
hold a key that can decrypt customer data. The table above reflects this in three concrete
facts:

1. The break-glass private key (section 2.6) has no code path into the engine. Only its
   public half is present at runtime.
2. The per-run master key (section 2.5) exists in isolate memory for one run invocation,
   is never persisted to any store, and is destroyed at isolate eviction. The only persistent
   form is the hybrid-wrapped capsule, which requires a recipient private key the engine
   does not hold (for break-glass) or holds only optionally in-account (for operational).
3. Even a full account compromise (adversary 2, `THREAT-MODEL.md`) yields only the
   operational key, not the break-glass key. Break-glass-only posture (omitting
   `OPERATIONAL_PRIVATE`) removes even that path, at the cost of in-account read-back.

---

## 5. Open items

The following requirements from ASVS V14 are not yet met in code. They are stated here
honestly so the gap is visible alongside the protections that are implemented.

| ASVS ref | Gap |
|----------|-----|
| V14.1.1 (P-30) | This document closes the classification gap; the ASVS assessment recorded it as PARTIAL pending this inventory. |
| V14.1.2 (P-31) | CLOSED. Destination-archive retention IS enforced when a downpipe sets `retention.enforce === true`: the prune planner (`engine/src/seal/prune.ts`) deletes run-tree objects + orphaned segments beyond the `keepRuns` / `keepDays` union bound, driven by the cron (`engine/src/index.ts`). It is dry-run plan-only (no deletion) when `retention.enforce !== true`. (Earlier revisions of this doc stated "not yet enforced" - that was stale.) |
| V14.2.4 (P-32) | CLOSED. The controls are implemented: hybrid-PQ encryption before egress, the SHA-384 hash-chained tamper-evident audit, retention auto-deletion via `seal/prune.ts` (above), `Cache-Control: no-store` on all admin responses (`SECURITY_HEADERS`), and redaction-by-construction. The earlier "not implemented" wording was stale. |
