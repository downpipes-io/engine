# Cryptographic inventory and key-management policy

**Standard:** OWASP ASVS 5.0 - V11 (Cryptography); satisfies the V11 NEEDS_MANUAL items "documented cryptographic inventory" and "documented key-management policy".
**Scope:** Downpipes engine (TypeScript, Cloudflare Workers), in-account console (key ceremony), and the offline `downpipe` CLI reader (Go).
**Date:**

This document is the cryptographic inventory and key-management policy required by ASVS V11.
Every primitive, key and control below is grounded in named source files. Where something is
policy rather than a control enforced in code (for example a rotation cadence that is not yet
automated), that is stated explicitly and not dressed up as an implemented control.

The single load-bearing design property that the whole suite serves is the no-custody
recovery guarantee: the running engine seals to public recipient keys and signs with its own
signer, and the break-glass private identity that can actually decrypt an archive is never
present in the engine. That property is what lets a customer recover without Cloudflare and
without the vendor, and it is the reason the key inventory below distinguishes so carefully
between what is held in the account and what is customer-held offline.

The TypeScript engine and the Go reader implement the **same** byte-exact suite. The TS port
states this repeatedly in-line ("ported byte-for-byte from internal/crypto/...", "must
reproduce the Go reference byte for byte") and the frozen on-disk constants live in one place
on each side: `engine/src/format/version.ts` on the TS side, ported verbatim from the Go
`internal/spec/spec.go`. Both are exercised against shared cross-implementation known-answer
vectors (the `crypto-kat` and `kem-combiner-kat` referenced in
`engine/src/crypto/derive.ts` and `engine/src/crypto/combiner.ts`).

---

## 1. Cryptographic inventory

The suite is aligned to CNSA 2.0: a hybrid (classical + post-quantum) KEM for
confidentiality, a hybrid signature for integrity, AES-256-GCM for bulk encryption, and a
SHA-384 hash/KDF/MAC family throughout. The Go package doc states this alignment directly
(`downpipe/internal/crypto/doc.go:1-12`), as does the Go hash-layer comment
(`downpipe/internal/crypto/derive.go:15-19`).

**Discovery.** A committed manifest at `engine/docs/security/crypto-call-sites.json` lists
every cryptographic call site below by file, kind and algorithm. `engine/test/validate-crypto-
discovery.ts` walks `engine/src`, `engine/scripts` and `engine/tools`, finds every
`crypto.subtle` call, every random-source call, every `@noble/*`, `node:crypto` or bare
`crypto` import, and every algorithm literal, and fails the engine's validate chain when a call
site is missing from the manifest, when a manifest row names a call site the tree no longer
has, when the walk finds nothing, or when an algorithm outside the approved list appears.
`console/scripts/crypto-discovery-gate.mjs` runs the same census over `console/src` and
`console/scripts`, against its own manifest at `console/docs/security/crypto-call-sites.json`.
`downpipe/internal/crypto/importallowlist_test.go`'s `TestCryptoDiscovery` runs the package-
level equivalent over the Go module, comparing every package that imports `crypto/*`,
`golang.org/x/crypto/*` or `filippo.io/*` against a committed allowlist.

### 1.1 Hybrid KEM - X25519 + ML-KEM-1024

| Attribute | Detail |
|-----------|--------|
| Purpose | Confidentiality. Wraps the per-run 32-byte master to each recipient (KEM-DEM). |
| Classical half | X25519 (RFC 7748). TS: `@noble/curves` (`engine/src/crypto/x25519.ts:1`). Go: `crypto/ecdh` X25519 (`downpipe/internal/crypto/pq.go:4`). |
| Post-quantum half | ML-KEM-1024 (FIPS 203). TS: `@noble/post-quantum/ml-kem.js` (`engine/src/crypto/pq.ts:8`). Go: `crypto/mlkem` (`downpipe/internal/crypto/pq.go:6`). |
| Hybrid ciphertext | `ct_M (1568) || ct_X (32) = 1600 bytes`, where `ct_X` is the X25519 ephemeral public share (`engine/src/crypto/kem.ts:6-8,34`; Go `pq.go:71-91`). |
| Combiner | 32-byte shared secret derived by HKDF-SHA-384 with `ikm = ssM || ssX`, empty salt, and `info = label || 0x00 || ctX || pkX`. The binding set mirrors X-Wing, generalised to ML-KEM-1024 over HKDF-SHA-384 (X-Wing itself is fixed to ML-KEM-768). TS: `engine/src/crypto/combiner.ts:10-13`. Go: `pq.go:118-138`. |
| Contributory abort | The X25519 exchange rejects an all-zero shared secret (SPEC 4.1), because some implementations return all-zero rather than erroring (`engine/src/crypto/x25519.ts:18-24`; Go enforces via `ECDH` erroring, `pq.go:81-83`). |
| Hybrid property | The derived secret is secure if **either** X25519 or ML-KEM-1024 holds; a break of one half alone does not expose plaintext. |
| Direction in engine | **Posture-dependent, and the default posture decapsulates.** The engine always encapsulates (`encapsulateHybrid` in `engine/src/crypto/kem.ts`). It also decapsulates with a LONG-LIVED key (`decapsulateHybrid`, same file) whenever `OPERATIONAL_PRIVATE` is present, which is the default: the restore drill, the hourly canary, verify-at-seal, in-console restore, the retention prune and the control-plane auto-heal all do. Break-glass-only is the posture that removes that exposure, and it removes it by removing the key rather than by mitigating it. This row matters beyond bookkeeping because the retracted "encapsulates only" claim was the stated justification for accepting a post-quantum library that is not constant-time-guaranteed, and decapsulation with a long-lived key is the shape a timing side channel targets. The header of `engine/src/crypto/pq.ts` carries the full caveat and its two real bounds. |

### 1.2 Hybrid signature - Ed25519 + ML-DSA-87 (both halves mandatory, no downgrade)

| Attribute | Detail |
|-----------|--------|
| Purpose | Integrity and authenticity of the signed manifest root and the account-wide RUNLOG. |
| Classical half | Ed25519. TS verify/sign via Web Crypto `crypto.subtle` (`engine/src/crypto/sign.ts:26-27,35`); TS public-key derivation via `@noble/curves` ed25519 (`engine/src/keys-env.ts:1,38`). Go: `crypto/ed25519` (`downpipe/internal/crypto/pq.go:5`). |
| Post-quantum half | ML-DSA-87 (FIPS 204). TS: `@noble/post-quantum/ml-dsa.js` (`engine/src/crypto/pq.ts:9`). Go: `filippo.io/mldsa` `MLDSA87()` (`downpipe/internal/crypto/pq.go:14`). |
| Detached signature | `edSig(64) || mldsaSig(4627) = 4691 bytes`. The fixed 64-byte Ed25519 length lets a verifier split the two halves (`engine/src/crypto/sign.ts:6-8`; Go `pq.go:168-178`). |
| Both halves required | Verification returns false / errors unless **both** halves verify. A forgery must break a classical AND a post-quantum scheme, and neither half can be stripped to downgrade the archive. TS: `hybridVerify` returns false on a short signature and on either half failing (`engine/src/crypto/sign.ts:22-30`). Go: `Verify` errors if either half is missing or fails (`pq.go:181-194`). |
| Direction in engine | The engine **signs**; verify exists for the in-account drill reader and the validator (`engine/src/crypto/pq.ts:47-52`). |

### 1.3 AEAD - AES-256-GCM in the downpipe STREAM construction

| Attribute | Detail |
|-----------|--------|
| Purpose | Bulk encryption of every sealed unit: data segments, secrets segments, and the master capsule DEM. |
| Primitive | AES-256-GCM, 256-bit key, 12-byte nonce, 128-bit (16-byte) tag. TS via Web Crypto (`engine/src/crypto/primitives.ts:33-46`, `tagLength: 128`). Go via `crypto/aes` + `crypto/cipher` GCM (`downpipe/internal/crypto/stream.go:3-11,83-97`). |
| STREAM framing | A 16-byte payload nonce, then AES-256-GCM chunks of 64 KiB (`CHUNK_SIZE = 65536`) plaintext. The final chunk may be shorter (`engine/src/crypto/stream.ts:1-9`; Go `stream.go:18-46`). |
| Chunk nonce | 12 bytes: an 11-byte big-endian counter (the counter occupies the low 8 bytes; the top 3 are reserved zero) followed by a 1-byte last-chunk flag. A reordered, truncated or spliced stream therefore fails authentication, and a dropped final chunk is caught because the preceding chunk does not carry the last-chunk flag. TS: `chunkNonce` (`engine/src/crypto/stream.ts:13-18`). Go: `chunkNonce` (`stream.go:235-245`). |
| Per-unit key freshness | The AES-256 key is not the file key directly: it is `HKDF-SHA-384(fileKey, salt = payloadNonce, info = "downpipe/0.1.0 payload")`, so every sealed unit gets a fresh AES-256 key bound to its random payload nonce (`engine/src/crypto/derive.ts:187`; Go `stream.go:87`). |
| AAD | Empty for data and shard units. For the master capsule, the signed run key commitment is bound as AAD, so a swapped or replayed capsule fails authentication even on the unverified path (and even though AES-GCM is not key-committing) (`engine/src/crypto/capsule.ts:10-13,60-69`; Go `capsule.go:99-112`). |
| Streaming form | A byte-identical streaming seal holds roughly one chunk in memory so a multi-GiB object stays within the Worker memory limit. It uses incremental SHA-384/HMAC from `@noble/hashes` for two-pass content addressing because Web Crypto has no streaming MAC; these byte-match Web Crypto and the Go reference (`engine/src/crypto/streamseal.ts:1-13`). |

### 1.4 Hash / KDF / MAC family - SHA-384 throughout

| Use | Construction | Source |
|-----|--------------|--------|
| Content / segment / shard / Merkle / recipient hashes | SHA-384 | `engine/src/crypto/primitives.ts:12-14`; Go `derive.go:15-19` |
| Key derivation (whole key tree, payload keys, combiner) | HKDF-SHA-384 | `engine/src/crypto/primitives.ts:17-21`; `engine/src/crypto/derive.ts`; Go `derive.go:24-30` |
| Keyed segment address, keyed name MAC, run key commitment, capsule integrity | HMAC-SHA-384 (48-byte output) | `engine/src/crypto/primitives.ts:25-28`; `engine/src/crypto/derive.ts:25-30,82-91`; Go `derive.go:49-64,127-156` |
| Recipient fingerprint | `dpr1:` + hex SHA-384 of `x25519(32) || ML-KEM-1024 ek(1568)` (the 1600-byte recipient encoding) | `engine/src/crypto/capsule.ts:21-25`; Go `capsule.go:15-22,32-40` |
| Signer fingerprint | `edmldsa1:` + hex SHA-384 of `ed25519(32) || ML-DSA-87 public(2592)` | console `console/src/keygen.ts:58`; Go `downpipe/internal/crypto/capsule.go:24-30` |

Derived symmetric keys are 32 bytes (the AES-256 key size); hash and MAC-as-hash outputs are
48 bytes (SHA-384). Constant-time comparison is used for security-relevant equality checks
(`engine/src/crypto/bytes.ts:99-105`; Go `capsule.go:61-66`, which the reader uses in place of
variable-time `bytes.Equal`).

### 1.5 Randomness

All key, master, nonce and salt randomness comes from the platform CSPRNG. TS: Web Crypto
`crypto.getRandomValues` (per-run master and the 16-byte nonce/salt are generated at
`engine/src/index.ts:223-225`; the in-browser ceremony uses the same source via
`console/src/keygen.ts:35,47,51`). Go: `crypto/rand` (`downpipe/internal/crypto/pq.go:7,44,156`).

### 1.6 Content hash - BLAKE3 (Cloudflare Workers asset-manifest upload)

| Attribute | Detail |
|-----------|--------|
| Purpose | Per-file content hash for the Workers Static Assets upload manifest the console deploy driver builds, matching wrangler's own uploader so the driver speaks the same protocol as Cloudflare's reference client. |
| Primitive | BLAKE3, over the UTF-8 bytes of (standard base64 of the file's raw bytes) concatenated with the file extension without its leading dot, truncated to the first 32 hex characters. TS: `@noble/hashes/blake3.js` (`engine/src/admin/cf-assets-deploy.ts:41,131`). |
| Scope | This digest addresses Workers asset-manifest entries only. It never touches archive content, a key or a signature; the archive and signature primitives stay SHA-384/Ed25519/ML-DSA-87 as in sections 1.2 and 1.4. |
| Cross-check | `engine/test/validate-assets-deploy.ts` checks the recipe against pinned vectors computed from wrangler 4.103.0's own `blake3-wasm` dependency, so a drift in either implementation fails the gate. |

---

## 2. Key inventory

Every key type, with its size, byte format, location, generation and custody. The three keys
that the running engine reads from the account are Worker secrets on the engine, declared as typed
bindings in `engine/src/env.d.ts` and installed with one PUT per secret by the console ceremony or the
terminal deploy; none is a Cloudflare Secrets Store binding. The break-glass private identity is
**not** among them.

### 2.1 Signer private key (held in the account)

| Attribute | Detail |
|-----------|--------|
| Composition | Ed25519 seed(32) `||` ML-DSA-87 seed(32) = **64 bytes**, base64url-encoded. |
| Why the seed form | The 32-byte ML-DSA-87 **seed** is stored, not the expanded ~4896-byte secret, so the value stays around 86 base64 characters and fits the Cloudflare 5.1 kB text-binding limit. The expanded ML-DSA secret is derived deterministically from the seed at load time (`engine/src/keys-env.ts:20-41`, especially the comment at `:22-25`; matching `console/src/keygen.ts:89-97` (`makeSigner`)). |
| Binding | `SIGNER_PRIVATE` (Worker secret) (`engine/src/env.d.ts:387`). |
| Generation | In the operator's browser during the key ceremony, from `crypto.getRandomValues` via `randomBytes` (`console/src/bytes.ts:137-139`; called for this seed at `console/src/keygen.ts:94`). |
| Load behaviour | `loadSigner` parses the 64 bytes, imports the Ed25519 seed as a non-extractable Web Crypto signing key (via a PKCS8 wrapper), and derives the ML-DSA secret and both public halves (`engine/src/keys-env.ts:20-41`). The Ed25519 private becomes a `CryptoKey` marked non-extractable (`importKey(..., false, ["sign"])`). |
| Custody | **In the account.** This is the one secret the engine necessarily holds, because it must sign every run. The recovery sheet states this explicitly to the operator (`console/src/recovery-sheet.ts`; `console/src/keygen.ts:9-13`). |
| Go equivalent format | `MarshalSigner` = ed25519 seed(32) `||` ML-DSA-87 private (`downpipe/internal/crypto/keys.go:77-99`). The offline tool never holds the signer private; it holds only the signer public (verifier). |

### 2.2 Break-glass recipient - public (in account) and private (customer-held, never in the engine)

| Attribute | Detail |
|-----------|--------|
| Public composition | x25519 pub(32) `||` ML-KEM-1024 ek(1568) = **1600 bytes**, base64url. |
| Private composition | x25519 scalar(32) `||` ML-KEM-1024 seed(64) = **96 bytes**, base64url. |
| Public binding | `BREAK_GLASS_PUBLIC` (Worker secret) (`engine/src/env.d.ts:55`). Always present in the recipient set, listed first (`engine/src/keys-env.ts:51-57`). |
| Private location | **Customer-held, offline. Never present in the running engine.** Generated in the operator's browser and downloaded as `identity.key`; it is never sent to the engine or the vendor (`console/src/keygen.ts:8-13,33-44`; recovery sheet wording at `console/src/recovery-sheet.ts:34-36,120`). The drill explicitly notes the break-glass private "is never here" (`engine/src/admin/drill.ts:8-11`). |
| Generation | In-browser, `crypto.getRandomValues`: an X25519 keypair plus a fresh 64-byte ML-KEM seed (`console/src/keygen.ts:33-44`). |
| Custody role | This is the only identity that can decrypt an archive in the worst case. The engine wraps the master to its **public** half and can never unwrap, which is what keeps a destination-bucket-alone compromise from yielding plaintext (`engine/src/crypto/capsule.ts:56-69`; Go `capsule.go:78-115`). |
| Go equivalent format | Private `MarshalKEMPrivate` = x25519(32) `||` ML-KEM seed(64) = 96 bytes (`downpipe/internal/crypto/keys.go:17-40`); public `MarshalKEMPublic` = 1600 bytes (`keys.go:42-51`). The offline tool parses the 96-byte identity to recover (`engine/src/crypto/keys.ts:21-25`). |

### 2.3 Operational recipient - public (in account) and an optional in-account private read-back key

| Attribute | Detail |
|-----------|--------|
| Composition | Same formats as the break-glass recipient: public 1600 bytes, private 96 bytes. |
| Public binding | `OPERATIONAL_PUBLIC` (optional) (`engine/src/env.d.ts:56`). Added to the recipient set after break-glass when present (`engine/src/keys-env.ts:53-56`). |
| Private binding | `OPERATIONAL_PRIVATE` (optional) (`engine/src/env.d.ts:57`). |
| Purpose of the private | The **in-account read-back key** used only by the restore drill, to prove a run is recoverable without leaving the account (`engine/src/admin/drill.ts:1-11,26-51`). It is loaded via `loadIdentity` (`engine/src/keys-env.ts:59-63`). |
| Custody | The operational private is a deliberate, optional convenience that lives in the account so the drill can run unattended. In the break-glass-only posture it is absent, and the drill honestly reports that recovery must be exercised offline with the break-glass key (`engine/src/admin/drill.ts:26-29`). The break-glass private is **never** loaded in-account (`engine/src/keys-env.ts:59-61`). |
| Generation | In-browser during the ceremony, only when the operator opts into an operational recipient (`console/src/keygen.ts:64-70`). |

### 2.4 Per-run master key (ephemeral, in-memory only)

| Attribute | Detail |
|-----------|--------|
| Composition | 32 bytes (256-bit), the root of the per-run key tree. |
| Generation | Fresh `crypto.getRandomValues(new Uint8Array(32))` per run, allocated into `RunClock.master` at run start (`engine/src/index.ts:225`; type at `engine/src/seal/pipeline.ts:31-39`). |
| Custody | **In-memory only, for the duration of one run invocation.** It is never written to any object, DO state, or log. It is wrapped to each recipient (KEM-DEM) and that capsule, not the master, is persisted (`engine/src/crypto/capsule.ts:56-69`). |
| Derived material | The whole key tree hangs off the master via HKDF-SHA-384: the per-downpipe content-addressing key, per-segment file keys, the per-run manifest subkey, the name-MAC key, manifest-wrap keys, and the run key commitment (`engine/src/crypto/derive.ts:18-97`; Go `derive.go:42-156`). |
| Recovery | The master is recoverable only by a recipient that holds a matching private identity opening the capsule, with the signed run key commitment as AAD (`engine/src/crypto/capsule.ts:38-49`). |

### 2.5 Derived keys (not stored; reproducible from the master)

These never have independent custody; they are HKDF-SHA-384 derivations of the master (or, for
the payload key, of a file key), and exist only transiently in isolate memory while a segment
is sealed or opened.

| Key | Derivation | Source |
|-----|------------|--------|
| Content-addressing key (CAK), 32 B | `HKDF(master, salt=downpipeID, info="downpipe/0.1.0 content-address")` | `derive.ts:29` |
| Non-secret file key, 32 B | content-only `HKDF(master, info="downpipe/0.1.0 seg-key" + 0x00 + context)` (enables dedup within a run; the per-run master means it never spans runs) | `derive.ts:83` |
| Secrets file key, 32 B | `HKDF(master, salt=runId, info="downpipe/0.1.0 seg-key" + 0x00 + context incl. record + salt)` (never dedup) | `derive.ts:113` |
| Manifest subkey (MK), 32 B | `HKDF(master, salt=runId, info="downpipe/0.1.0 manifest-key")` | `derive.ts:125` |
| Name-MAC key, 32 B | `HKDF(MK, salt=runId, info="downpipe/0.1.0 name-mac")` | `derive.ts:136` |
| Manifest-wrap key, 32 B (per shard) | `HKDF(MK, salt=runId, info="downpipe/0.1.0 manifest-wrap" + 0x00 + shardID)` | `derive.ts:149` |
| Payload (AES) key, 32 B (per sealed unit) | `HKDF(fileKey, salt=payloadNonce, info="downpipe/0.1.0 payload")` | `derive.ts:187` |
| Capsule DEM key, 32 B (per recipient wrap) | `HKDF(kemSharedSecret, info="downpipe/0.1.0 capsule-dem")` | `capsule.ts:67,122` |

### 2.6 Out-of-band verify-only public keys (non-secret, pinned by the operator)

These are pinned **public** keys the engine verifies signatures against; they carry no private
material and are listed here for completeness of the inventory.

| Key | Binding | Format | Source |
|-----|---------|--------|--------|
| Update channel signer | `UPDATE_SIGNER_PUBLIC` | ed25519(32) `||` ML-DSA-87 public(2592) | `engine/src/env.d.ts:60-62` |
| Licence signer | `LICENCE_SIGNER_PUBLIC` | same 2624-byte layout | `engine/src/env.d.ts:64-70` |

(The destination credentials `DEST_ACCESS_KEY_ID` / `DEST_SECRET_ACCESS_KEY` at
`engine/src/env.d.ts:50-51` are Secrets-Store-bound secrets but are SigV4 access credentials,
not cryptographic keys of this suite; they are out of scope here and covered by the data
classification inventory.)

---

## 3. Key-management policy

### 3.1 Generation

All long-lived key material is generated **in the operator's browser** during the key ceremony
(`console/src/keygen.ts`), using the Web Crypto CSPRNG, in the exact byte formats the engine
and the Go offline tool consume. The ceremony produces:

- a break-glass recipient (always),
- an optional operational recipient,
- the signer

(`console/src/keygen.ts:62-70`). The Go reference can generate the same identities and signer
from `crypto/rand` for offline use (`downpipe/internal/crypto/pq.go:42-54,154-166`), and the
labelled key-file formats are interoperable between the console download and the Go CLI
(`console/src/keygen.ts:72-85`; Go parsers `downpipe/internal/crypto/keys.go`). The per-run
master is generated server-side per run (section 2.4); it is not part of the ceremony.

### 3.2 Storage and custody

| Material | Where it lives | How |
|----------|----------------|-----|
| Signer private | Worker secret on the engine | `SIGNER_PRIVATE` binding (`env.d.ts:54`) |
| Break-glass public, operational public | Worker secrets on the engine | `BREAK_GLASS_PUBLIC`, `OPERATIONAL_PUBLIC` bindings |
| Operational private (optional read-back) | Worker secret on the engine | `OPERATIONAL_PRIVATE` binding |
| Break-glass private | **Customer custody, offline** | downloaded `identity.key`; never transmitted |
| Per-run master | In-memory only | never persisted |

These are Worker secrets: values held by Cloudflare for this Worker alone, readable by the running engine through its typed `Env` bindings and by nothing else, and not listable or readable back through the Worker's own API. The Cloudflare Secrets Store is a different product, the account-scoped store the engine backs up as a source; the engine's own keys do not live there today. The engine is explicitly bound to each source secret it backs up and never reads the whole store (`engine/src/sources/secrets.ts:6-13,29-35`), and a backed-up secret value lives only in isolate memory for the duration of the yield (`engine/src/sources/secrets.ts:16-20`).

### 3.3 The no-custody guarantee

This is the central policy property and it is structural, not procedural:

1. The engine holds only **public** recipient keys plus the **signer private**.
2. Sealing wraps the master to the recipients' **public** halves (`sealToRecipients`,
   `engine/src/crypto/capsule.ts:56-69`; Go `SealToRecipients`, `capsule.go:78-115`). The
   engine can wrap but, lacking any recipient private, can never unwrap.
3. The break-glass **private** identity (the one that can decrypt in the worst case) is
   generated in-browser, downloaded by the customer, and is never sent to the engine or the
   vendor (`console/src/keygen.ts:8-13`; `engine/src/admin/drill.ts:8-11`).

Therefore a compromise of the destination bucket alone, or of the running engine alone, does
not yield archive plaintext: the bucket holds only ciphertext and capsules, and the engine
cannot open its own capsules. Recovery requires the customer-held break-glass key and the
offline `downpipe` CLI, with neither Cloudflare nor the vendor in the loop
(`console/src/recovery-sheet.ts:34-41,120,123`; Go `doc.go:1-12`).

### 3.4 Rotation

Rotation is supported by the format and is partly automated and partly operator-run. Be
precise about which is which:

**What the format enables (mechanism present in code):**

- **Recipient rotation.** The recipient set is a list, addressed per-wrap by recipient
  fingerprint, and the exact set is bound into the signed root via the recipient-set hash
  (`engine/src/crypto/capsule.ts:71-77`; Go `capsule.go:42-59`). To rotate a recipient, run a
  fresh key ceremony for the new identity and update `BREAK_GLASS_PUBLIC` /
  `OPERATIONAL_PUBLIC`. Each run wraps to whatever recipients are configured at run time
  (`engine/src/index.ts:207`, `engine/src/keys-env.ts:51-57`), so new runs immediately use the
  new set while existing archives remain openable by the identity that sealed them. There is no
  re-wrap of historical archives in code.
- **Signer rotation.** The verifier is the operator-pinned signer public derived from the
  loaded signer (`engine/src/keys-env.ts:65-69`). Replacing `SIGNER_PRIVATE` rotates the
  signer; runs sealed after the swap are signed by, and verify against, the new signer. The
  engine's in-account verifier is always the CURRENT signer, so a historical run sealed by a
  prior signer no longer verifies in-account after a rotation: verify or restore it with the
  OFFLINE tool, passing that era's signer public as `--signer` (the offline reader takes the
  verifier explicitly, so any era's archive is recoverable with its signer public). To make
  this legible rather than look like tampering, an in-account signature failure whose archive
  `signingKeyFingerprint` hint does not match the current pinned signer is reported as a likely
  signer rotation with both fingerprints, not a generic tamper failure
  (`engine/src/format/reader.ts`).
- **Format / suite versioning** underpins any primitive change: see section 4.

**What is operator-run, not automated:**

- The **key ceremony** itself is a deliberate, operator-driven action in the console; the
  engine does not self-rotate or self-mint key material.
- Distributing a rotated `identity.key` to its offline holders is an operator process; the
  recovery sheet even suggests splitting the break-glass identity across several offline
  holders (`console/src/recovery-sheet.ts:36,120`).

#### The rotation schedule

Every secret below is critical to the security of a deployment. The cadence is the maximum age
before a planned rotation is due; the triggers are events that require one immediately
regardless of age. The engine deploys into the customer's own Cloudflare account, so with one
exception these are rotations the operator performs and the schedule is the commitment they
are operating to, not a timer the engine runs.

| Secret | What it protects | Planned cadence | Rotate immediately on |
|---|---|---|---|
| `SIGNER_PRIVATE` | archive authenticity: it signs every run | 12 months | suspected account compromise; offboarding of anyone who held account access; an advisory against Ed25519 or ML-DSA-87 |
| Break-glass private (`identity.key`, customer-held offline) | the only key that opens an archive under the strict posture | 24 months | any change to the holder set; suspected disclosure of a recovery sheet; a lost or unreturned holder copy |
| `BREAK_GLASS_PUBLIC`, `OPERATIONAL_PUBLIC` | recipient addressing | with the private half they derive from | whenever their private half rotates |
| `OPERATIONAL_PRIVATE` (optional in-account read-back) | in-account restore without the break-glass key | 12 months, or remove the binding when in-account restore is not in use | completion of any drill where the value could have been observed; any move to the strict posture |
| `ADMIN_TOKEN` (bearer fallback) | the whole admin surface | 90 days | operator offboarding; suspected disclosure; whenever Access becomes available, prefer setting `ADMIN_TOKEN_DISABLED` and retiring the token entirely |
| `SCIM_BEARER_TOKEN` | the SCIM deprovision surface | 12 months | an IdP change; offboarding of anyone who configured the IdP connector |
| `DISCOVERY_API_TOKEN` (opt-in IaC fallback) | account-wide read-only source discovery | 90 days | any change to its scope; prefer removing the binding once discovery is configured |
| `DEST_SECRET_ACCESS_KEY` and per-destination credentials | write access to the archive destination | 90 days, or the destination provider's own policy where it is shorter | offboarding; a destination provider's own rotation event |
| Per-run master key and every key derived from it | a single run's contents | rotated by construction, once per run, never persisted | not applicable |
| `CONFIG_WRAP_KEY` | every console-set destination and notification credential at rest in the scheduler Durable Object | 12 months | suspected exposure of the engine's secrets; offboarding of anyone who could read them. Rotation has a cost the engine does not hide: there is no re-wrap, so every sealed credential must be re-entered afterwards, and a credential sealed under the old key reads as `credential-undecryptable` until it is |
| `CONFIG_RECIPIENT_PRIVATE` and `CONFIG_RECIPIENT_PUBLIC` | the sealed configuration export the control-plane auto-heal reads (the roster, topology, destination endpoint and access key id, RBAC email addresses); never a customer archive | 12 months, and at any recipient ceremony | suspected account compromise. An export sealed to the old pair stays openable only with the break-glass key |
| Session signing key (generated inside the Durable Object, `src/admin/session.ts`) | every admin session cookie | engine-managed: regenerating it signs every operator out at once, so it is rotated on incident rather than on a calendar | suspected theft of the DO's storage; any suspicion that a session token has been minted outside the engine |

`LICENCE_TOKEN` is deliberately absent: it is a signed, verify-only assurance token rather than
a secret, and it is reissued at renewal rather than rotated.

**Two consequences of rotating that an operator has to plan for, because the engine does not
paper over them.**

Rotating a recipient does **not** re-key archives already sealed. There is no re-wrap of
historical archives in code, by design, since re-wrapping would require the engine to hold the
opening key. So a retired break-glass `identity.key` must be retained, offline and under the
same custody, for as long as any archive sealed under it is still within its retention period.
Destroying a retired break-glass key destroys access to everything it sealed.

Rotating the signer means a historical run no longer verifies in-account, because the
in-account verifier is always the current signer. Those archives verify with the offline tool
when passed that era's signer public, so each retired signer public must be retained alongside
the archives it signed. The engine reports this case as a likely signer rotation with both
fingerprints rather than as a tamper failure, so it reads as what it is.

**How the schedule above is enforced:** every secret in the table is a tracked row in the
credential lifecycle registry (`src/admin/secret-rotation.ts`,
`src/sched/scheduler-do-expiry.ts`). Each row carries an expiry equal to its cadence. The same
30/14/7/1 notification ladder and credential-expiry posture check that watch every other
tracked credential watch these too.

`SIGNER_PRIVATE`, `BREAK_GLASS_PUBLIC` and `OPERATIONAL_PUBLIC` are engine-observed. On each
reconcile tick the engine reads the installed key's public fingerprint. A changed fingerprint
resets the tracked baseline; no operator action is needed or accepted for these three.

`ADMIN_TOKEN`, `SCIM_BEARER_TOKEN`, `DISCOVERY_API_TOKEN` and `DEST_SECRET_ACCESS_KEY` carry no
fingerprint the engine can read: the no-custody rule bars retaining even a hash of a bearer
secret. An owner confirms a rotation of one of these through `POST /admin/secrets/rotated`,
which moves its tracked baseline to the call's own timestamp.

A lapsed cadence raises the credential-expiry posture check and the notification ladder. It
does not refuse a run: the enforcement here is observability, matching the fail-open discipline
the rest of this document states.

#### ASVS V13.2.1 - the engine's outbound service credentials

ASVS V13.2.1 asks that a backend service account authenticate with an individual, purpose-scoped
credential and a short-term or certificate-based one, not a shared static secret. The engine
makes five kinds of outbound call on the operator's behalf. Each is assessed here on its own
terms, because the honest answer differs by call: two carry no credential at all, two already
present a short-term credential on the wire, and one is a genuine residual.

| Outbound call | Individually scoped | What is actually presented on the wire | Posture |
|---|---|---|---|
| Cloudflare API (account and source discovery) | Yes: a read-only token scoped to exactly the discovery products, separate from `ADMIN_TOKEN` and `SCIM_BEARER_TOKEN` (`DISCOVERY_API_TOKEN`, `src/env.d.ts:515`, or the console-set equivalent) | The token itself | **Met.** A token with no expiry, or one further out than 90 days, is refused before the scheduler stores it (`discoveryTokenExpiryVerdict`, `src/admin/cf-api.ts:263`; enforced at `src/admin/router-discovery.ts:384` and, for the deploy-time fallback, `src/admin/preflight-probes.ts:672`), and the accepted expiry is registered in the credential lifecycle registry so the 30/14/7/1-day ladder and the credential-expiry posture check watch it. |
| DNS over HTTPS (notification sink-host resolution) | n/a | Nothing: a fixed public resolver, unauthenticated (`DOH_ENDPOINT`, `src/lib/outbound.ts:20`, used at `src/notify/types.ts:762`) | **Not applicable.** No credential exists to be static or short-term. |
| Update channel (signed release consult) | n/a | Nothing: a plain GET to a pinned host (`UPDATE_CHANNEL_HOST`, `src/lib/outbound.ts:21`); integrity comes from verifying the release against the pinned `UPDATE_SIGNER_PUBLIC` key (`src/env.d.ts:439`), not from a bearer credential | **Not applicable.** A public verification key is not a secret and there is nothing to rotate. |
| Destination write, AWS STS AssumeRole configured | Yes: the assumed role, scoped by its own trust policy and an optional external id (`AssumeRoleParams`, `src/dest/sts.ts:28-33`) | AWS-minted temporary credentials, valid 900 seconds to 12 hours and held in memory only for the run that minted them (`assumeRole`, `src/dest/sts.ts:123-188`); a failed AssumeRole throws rather than falling back to the long-lived principal (`resolveRuntimeDest`, `src/dest/factory.ts:76-101`) | **Met.** Short-term by construction, fail-closed. |
| Destination write, Azure Blob with a Microsoft Entra service principal | Yes: one application registration per destination (`AzureEntraCreds`, `src/dest/azure-entra.ts:47-51`) | A cached OAuth2 bearer token, refreshed on a 5-minute margin well inside its own lifetime; no request is ever signed with the static client secret (`AzureEntraTokenSource.bearer`, `src/dest/azure-entra.ts:221-234`) | **Met for the wire credential.** The client secret that mints the token is the residual below. |
| Destination write, static access key (the default S3-compatible path, and the long-lived value behind an STS principal or an Entra client secret) | Yes: per-destination, write-scoped (`DEST_ACCESS_KEY_ID` / `DEST_SECRET_ACCESS_KEY`, `src/env.d.ts:321-322`, or the console-stored equivalent) | The static secret itself, SigV4-signed (or Shared-Key-signed) on every request | **Accepted residual**, reasoned below. |

**The residual, stated plainly.** The default destination-write credential, and the long-lived
value behind an STS principal or an Entra client secret, is a static secret with no expiry: the
engine does not track its age. This is not a gap the engine can close on its own, because the
destination is a system the customer owns and configures, and the engine writes under whatever
credential type that system offers. STS and Entra are used wherever the destination supports
them, and both already convert the credential presented on the wire to a short-lived one. A
destination that offers neither (most S3-compatible object stores, and any appliance with no STS
implementation) leaves a static key as the only mechanism the provider makes available; an R2
destination under `DEST_KIND=r2` is a different case entirely; it carries no credential on the
wire at all, because the write goes over the in-account R2 binding. The compensating control on
the genuine residual is the rotation cadence already in the table above (90 days, or the
provider's own policy where it is shorter); as the paragraph before this one discloses, that
cadence is operator-run and not code-enforced the way the discovery token's term limit is.
`test/validate-v13-2-1-outbound-credentials.ts` gates this section to the bindings and constants
it cites, so a renamed binding or a changed constant fails the chain here rather than leaving
this table to go stale silently, the way section 3.4's own header note warns a rotation cadence
can.

### 3.5 Destruction and clearing

- **Per-run master and derived keys** are ephemeral isolate-memory values bound to a single
  run invocation; they are never persisted and are reclaimed when the invocation ends
  (section 2.4, 2.5). The garbage-collected runtime gives no explicit zeroisation primitive
  for these JS buffers, so "destruction" here means non-persistence and isolate teardown, not
  an explicit wipe. This is stated honestly rather than claimed as a memory-scrubbing control.
- **In-browser ceremony material** is explicitly cleared. The console holds key-ceremony
  material in memory only while the operator is in a ceremony route and clears it on navigation
  away and on sign-out, via `clearSensitiveState()` (a no-op when there is no ceremony state)
  (`console/src/app.ts:21,175-198`). This is documented in-code as no-custody hygiene.
- **The break-glass private** is the customer's to destroy or retain; the engine never holds it
  and so has nothing to destroy. Its loss is irrecoverable by design, which the recovery sheet
  states plainly (`console/src/recovery-sheet.ts:35-36,120`).

---

## 4. Cryptographic agility

### 4.1 Versioning anchors

The on-disk format is versioned and the constants are frozen per format identity:

- `VERSION = "downpipe/0.1.0"` and a 1-byte `CONTAINER_VERSION = 0x01` carried in the 4-byte
  container magic frame (`DPS1` for a segment, `DPE1`), which is framing only and never folded
  into the AEAD (`engine/src/format/version.ts:7,71-75`).
- Every HKDF/MAC `info` string and address domain separator is namespaced with the
  `downpipe/0.1.0` format version (`engine/src/format/version.ts:50-66`). A change to any label
  or size is, by construction, a new suite: the constants file is the single source of these
  values and is described as "never edited without a vector regeneration"
  (`engine/src/format/version.ts:1-4`).

The format is semver'd below 1.0. While the major is 0 a byte-level rule change bumps the
MINOR, so the compatibility unit is `major.minor` and the forward-compatible component is the
PATCH: a reader implements exactly its own `major.minor` at any patch and refuses every other
version (`engine/src/format/structural-gates.ts` `checkFormatVersion`; Go
`internal/format/verify.go`).

Because the version and all domain-separation labels are part of the signed/derived material,
a future `downpipe/0.2.0` (or `DPS2`/container version `0x02`) is a clean break: old archives
remain bound to their own labels and verify under the suite that wrote them, and a reader
selects behaviour by the version it reads.

> **These labels are key-derivation inputs, not descriptions.** A re-implementation that uses
> any other spelling derives every key to different bytes and opens nothing, and the failure
> presents as an authentication error over intact data rather than as a version complaint. This
> document previously quoted all six of the labels above as `downpipe/1.0 <purpose>`, which no
> implementation has ever used: both the engine (`engine/src/format/version.ts:50-66`) and the
> Go reference (`downpipe/internal/spec/spec.go:46-70`) have read `downpipe/0.1.0 <purpose>`
> since the semver cutover of. The `downpipe/1.0` spelling is the PRE-cutover
> identity, and it is still live in one place: the engine artefact the update channel currently
> recommends. Anyone working from a released artefact rather than from this document should read
> the version out of the archive's own manifest and use that exact string.

### 4.2 How a primitive or key could be rotated

- **A symmetric or hash change** (for example a different AEAD or a move off SHA-384) would be a
  new format version with new `info` labels in `version.ts` and a regenerated set of
  cross-implementation vectors; both the TS engine and the Go reader would carry the new suite
  side by side and dispatch on the container version.
- **A KEM or signature primitive change** would similarly bump the suite. The hybrid structure
  is itself the agility hedge for the asymmetric layer: each half is independently swappable,
  and the combiner/signature wire formats are explicit byte layouts in `kem.ts` / `sign.ts`
  (and their Go twins), so a half can be replaced without disturbing the other.
- **Key rotation** is the recipient-set / signer mechanism of section 3.4; it needs no format
  change because the recipient set and the pinned signer are already first-class, per-run,
  fingerprint-addressed values.

### 4.3 The both-halves-required hybrid stance

The suite is deliberately hybrid on both the confidentiality and integrity axes, and the
"both halves required" property is the explicit defence against a future break of **either**
the classical or the post-quantum half:

- **Confidentiality.** The KEM combiner binds `ssM` (ML-KEM-1024) and `ssX` (X25519) together,
  so the shared secret is secure if **either** holds (`engine/src/crypto/combiner.ts:5-13`; Go
  `pq.go:122-138`). A break of X25519 alone, or of ML-KEM-1024 alone, does not expose the
  master.
- **Integrity.** Verification requires **both** Ed25519 and ML-DSA-87 to pass; neither half can
  be stripped to downgrade an archive, so a forgery must defeat a classical AND a post-quantum
  signature scheme (`engine/src/crypto/sign.ts:6-8,22-30`; Go `pq.go:140-142,181-194`). There
  is deliberately no downgrade path: a signature missing or failing either half is rejected.

This is why the inventory in section 1 treats the post-quantum and classical primitives as a
matched pair rather than as alternatives, and why a single-primitive cryptanalytic advance does
not, on its own, break either the confidentiality or the integrity of an existing archive.

---

## 5. Component pinning (for the cryptographic inventory)

The cryptographic dependency surface and its pinning are maintained in `sbom.md` (ASVS V15);
summarised here so the cryptographic inventory is self-contained.

| Implementation | Library | Version pin | Primitives |
|----------------|---------|-------------|------------|
| TS engine / console | `@noble/curves` | `2.4.0` (exact-pinned; see `sbom.md`) | Ed25519, X25519 |
| TS engine / console | `@noble/post-quantum` | `0.6.1` (exact-pinned; see `sbom.md`) | ML-KEM-1024, ML-DSA-87 |
| TS engine / console | Web Crypto (`crypto.subtle`) | runtime (Workers / Node) | SHA-384, HKDF-SHA-384, HMAC-SHA-384, AES-256-GCM, Ed25519 |
| TS streaming addressing | `@noble/hashes` | per lockfile | incremental SHA-384 / HMAC-SHA-384 |
| Go reader | `golang.org/x/crypto` | `v0.52.0` (hash-pinned in `go.sum`) | `mlkem`, `ecdh`, `ed25519`, `sha512`, `hkdf` |
| Go reader | `filippo.io/mldsa` | `v0.0.0-20260215214346-43d0283efc3e` (hash-pinned) | ML-DSA-87 |
| Go reader | Go stdlib (`crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha512`) | `go 1.26` toolchain | AES-256-GCM, SHA-384, CSPRNG |

A known caveat recorded in `engine/src/crypto/pq.ts:1-6`: the `@noble/post-quantum` library is
not constant-time-guaranteed; a Rust/WASM escalation is the documented fallback should a
constant-time PQ implementation be required. This is noted as an honest limitation, not a
present mitigation.

---

## 6. ASVS V11 mapping

| ASVS V11 expectation | Where satisfied |
|----------------------|-----------------|
| Documented cryptographic inventory of primitives and their uses | Section 1 |
| Automated discovery of every cryptographic call site (V11.1.3) | Section 1's Discovery paragraph; `engine/test/validate-crypto-discovery.ts`, `console/scripts/crypto-discovery-gate.mjs`, `downpipe/internal/crypto/importallowlist_test.go` |
| Approved, strong primitives (AEAD with integrity; no weak hashes/ciphers) | Section 1.3 (AES-256-GCM, 128-bit tag), 1.4 (SHA-384 family); no ECB, no unauthenticated modes, no MD5/SHA-1 |
| Authenticated encryption with per-message uniqueness | Section 1.3 (STREAM chunk nonce + per-unit payload key; capsule AAD) |
| Post-quantum readiness | Sections 1.1, 1.2, 4.3 (hybrid X25519+ML-KEM-1024 and Ed25519+ML-DSA-87, both halves required) |
| Documented key-management policy: generation, storage, rotation, destruction | Section 3, with the per-secret rotation schedule in 3.4 |
| Key custody / separation | Section 2 and 3.3 (Secrets-Store-bound vs customer-held; engine cannot unwrap) |
| Cryptographic agility | Section 4 |
| CSPRNG for all key/nonce/salt material | Section 1.5 |
| Honest disclosure of gaps | Section 3.4 (the documented cadences are not enforced in code), 3.5 (no explicit memory zeroisation in the GC runtime), section 5 (PQ lib not constant-time-guaranteed) |
