<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/downpipes-mark-light.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/downpipes-mark-dark.svg">
    <img alt="downpipes" src="./assets/downpipes-mark-dark.svg" width="96">
  </picture>
</p>

<h1 align="center">downpipes-io/engine</h1>

<p align="center">Back up your Cloudflare data and configuration to storage you control. Runs in your account. Keys only you hold.</p>

<p align="center">
  <a href="https://github.com/downpipes-io/engine/actions/workflows/ci.yml"><img src="https://github.com/downpipes-io/engine/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/downpipes-io/engine"><img src="https://api.securityscorecards.dev/projects/github.com/downpipes-io/engine/badge" alt="OpenSSF Scorecard"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/licence-Elastic--2.0-blue" alt="Licence Elastic 2.0"></a>
  <img src="https://img.shields.io/badge/TypeScript-strict-blue?logo=typescript&logoColor=white" alt="TypeScript strict">
  <img src="https://img.shields.io/badge/runtime-Cloudflare%20Workers-f38020?logo=cloudflare&logoColor=white" alt="Cloudflare Workers">
</p>

downpipes is a source-available backup platform for Cloudflare. This repository is the engine: the Cloudflare Worker that captures your account's data and configuration on a schedule, seals it into signed, post-quantum-hybrid-encrypted archives, and writes them to a destination bucket you own. It is the writer half of the platform; the MIT-licensed [`downpipe`](https://github.com/downpipes-io/downpipe) reader recovers those archives offline, with no engine and no vendor.

No custody, structurally: the engine runs entirely in your own Cloudflare account, never sends data or a Cloudflare token to the vendor, and holds only public recipient keys plus the run signer. Every archive's content key is also wrapped to a mandatory break-glass key whose private half stays offline with you, so a full compromise of the live account still cannot read past archives, and neither can we.

## What it backs up

The engine covers the Cloudflare data and configuration layer, not the compute layer. That is nine source types plus 214 configuration surfaces:

| Source | Captured | Restore path |
|--------|----------|--------------|
| Workers KV | Keys and values, selector-scoped | In-account restore |
| R2 | Objects, streamed at any size | In-account restore |
| D1 | Whole database as resumable row-page records (schema and rows) | Restore into a fresh database |
| Secrets Store | Secret values, sealed | In-account restore |
| Cloudflare configuration | 214 zone and account surfaces (DNS, WAF and rulesets, Access and Zero Trust, load balancers, Email Routing, Logpush, Turnstile, Queues, Hyperdrive, Pages projects, Vectorize index config, account members and roles, more) | 7 surfaces write back in-console; all 214 get a diff preview for deliberate re-apply (121 idempotent, 49 ordered, 44 reprovision) |
| Workers | Script code, settings, bindings inventory, versions inventory | Backup-with-reprovision: prove everything, redeploy deliberately |
| Stream | Inventory by default, video bytes by opt-in | Confirmation-gated additive re-upload |
| Images | Inventory by default, image bytes by opt-in | Confirmation-gated additive re-upload, original ids kept |
| Artifact Registry | Namespace, repositories, contents | Backup-with-reprovision |

The four account-wide sources read with a read-only discovery token rather than a binding, so your Worker code, and the downpipes Workers themselves, are recoverable.

**Not covered, honestly:** Durable Object embedded storage and Vectorize stored vectors. Neither has an account-level read API a discovery token can reach: DO storage is readable only from inside the object's own isolate (an in-tenant export shim is the documented path), and Vectorize reads are id-driven with no list-all surface, so only the index configuration is captured. These are platform limits, stated rather than hidden.

**Limits, stated:** D1 capture streams as a resumable sequence of bounded row-page records (peak memory is one page, nominal cap 256 GiB); a crawl can span invocations, so it is not a single point-in-time transaction under concurrent writes, and restores create tables into a fresh, empty database. Media re-upload in-account is bounded at 25 MiB per image and a 200 MB (decimal) direct upload per video, the Cloudflare ceiling; larger files surface for manual re-upload rather than silent skips. Workers script bytes buffer with a 128 MiB ceiling; the Artifact Registry walk captures 5,000 objects per repository and records an honest truncation marker past that. Secret binding values on Workers are never readable by the platform; they come back as a name-and-type reprovision checklist.

## Quick start

The engine deploys into your own account with Wrangler, once, by the operator; every day-2 action after that happens in the [console](https://github.com/downpipes-io/console).

```bash
git clone https://github.com/downpipes-io/engine
cd engine && npm install
# configure wrangler.toml (account, custom domain route, destination binding)
npx wrangler deploy
```

Then pair the console, run the key ceremony (the break-glass private key is generated in your browser and never leaves it), and add sources. The full guided path, including exact `wrangler.toml` wiring and token scopes, is the docs quickstart: [docs.downpipes.io/start-here/quickstart](https://docs.downpipes.io/start-here/quickstart).

This repository ships two Wrangler configs: `wrangler.toml` is the one you edit and deploy from for your engine, and `wrangler.dev.toml` is a template for a second, non-production instance you can stand up alongside it (for trying an upgrade or a config change before it touches your real backups).

`GET /admin/status` reports `ready: true` once a signer, a break-glass recipient key and a destination are configured. Destinations: native R2 (in-account binding, no credentials on the wire), any S3-compatible endpoint, Google Cloud Storage through its S3-interoperable endpoint, or Azure Blob Storage through its own client. An ambiguous destination configuration is refused and reported honestly rather than guessed at.

## Architecture

One Worker, one scheduler Durable Object, a straight-line run pipeline:

```
src/sources     KV / R2 / Secrets / D1 / cf-config / Workers / Stream / Images / Artifacts
                adapters -> one ordered record stream per run
src/seal        segmentation, packing, content addressing; verify-at-seal
src/crypto      the CNSA 2.0 suite: SHA-384 / HKDF / HMAC / AES-256-GCM (Web Crypto),
                hybrid KEM combiner, ML-KEM / ML-DSA via pinned @noble/post-quantum
src/format      version constants, container framing, canonical JSON, the archive reader
src/dest        destination writers (native R2, SigV4 S3 incl. Google Cloud Storage, and
                Azure Blob with its own signer), RUNLOG, recovery bundle
src/sched       the scheduler Durable Object: per-downpipe alarms with jitter,
                coalescing and a run lock; a */15 cron is the coarse safety net
src/admin       the admin API the console calls; Cloudflare Access auth, RBAC,
                dual-control restore, hash-chained audit log
src/canary      hourly known-answer restore flights per destination
src/notify      alert events, webhooks, digests, SIEM push (CEF / LEEF / JSON)
src/cron        reconciliation and background passes
src/cost        run cost accounting and projections
test            the Go conformance vectors + the cross-implementation validators
```

Every run is signed (hybrid Ed25519 + ML-DSA-87) and sealed to recipients (hybrid X25519 + ML-KEM-1024). Archives are verified at seal time, and restores dry-run and verify before a byte is written back. The audit log is a hash chain: tamper-evident, meaning tampering is detectable, not impossible, and the verify-chain action demonstrates the detection.

## Admin API

The `/admin` surface is the only API, it lives in your account, and the console is just a client of it. Authentication is Cloudflare Access (JWT verified server-side against your AUD) with roles resolved per verified email (viewer, operator, restore-operator, approver, access-admin, owner), or an `ADMIN_TOKEN` bearer fallback you can disable once Access is in place. Owner is always an explicit per-email grant, never group-conferred; a restore request must be approved by a second authenticated person before it executes.

The complete route catalogue, with capabilities per route, is documented at [docs.downpipes.io/reference/api/overview](https://docs.downpipes.io/reference/api/overview), with a machine-readable spec at [/api/openapi/engine.json](https://docs.downpipes.io/api/openapi/engine.json) and role setup in [docs/ACCESS.md](docs/ACCESS.md).

## Security model

- **Post-quantum hybrid, precisely stated.** Sealing uses X25519 + ML-KEM-1024; signing uses Ed25519 + ML-DSA-87 (the CNSA 2.0 suite). This is a post-quantum hybrid, not a quantum-proof guarantee. The pinned `@noble/post-quantum` is not constant-time-certified and a Rust/WASM escalation path is documented. The break-glass private key never enters the account at all: verify-at-seal, canary flights and in-account restores exercise the hybrid verify and decapsulate paths with the run and operational keys, never the break-glass half.
- **Break-glass recovery is vendor-free.** Offline recovery from the break-glass private key alone is always available: the `downpipe` reader verifies and decrypts archives with no engine, no console and no vendor.
- **Fail-open licensing.** An unreachable or expired licence never blocks backups or restores. The data path is never gated.
- **Tamper-evident audit.** Hash-chained log with a retention cap; `auditNearCap` warns before roll-off so the operator can export. Counts never cross the status wire, only booleans.
- **Release provenance.** `GET /admin/status` surfaces `artefactSha384` and `releaseSignerPin` when set at deploy time, and they are honestly absent otherwise; they are operator cross-checks against the published release, not self-attestation.

## Conformance and validation

```bash
npm install
npm run validate        # the full chain: 220 validators as of July 2026
npm run validate:crypto # byte-match against the Go reference vectors alone
npm run typecheck
```

The validators cover crypto conformance (byte-identical against the Go reader's known-answer vectors, so the TypeScript writer and the Go reader provably agree on the archive format), the format reader, SigV4, Access JWT verification, STREAM sealing, restore and D1 restore, RBAC and group-role mapping, dual-control, the scheduler, every source adapter, canary flights, licensing, updates and webhook notification. Requires Node 22+.

## Integrations

`integrations/microsoft-sentinel/` ships a standalone ARM template that deploys a Microsoft Sentinel connector for the audit feed (`GET /support/audit-feed`) directly into your own Azure workspace, no Content Hub listing required. Running it creates a Data Collection Endpoint, a custom `DownpipesAudit_CL` Log Analytics table, a Data Collection Rule, and a Sentinel `RestApiPoller` data connector that pages forward on the feed's own `afterSeq`/`nextAfterSeq` cursor. Two example parameters files are included: `parameters.example.json` carries the bearer token as a plain inline value, and `parameters.keyvault.example.json` pulls it live from an Azure Key Vault secret at deployment time so the token never sits in the parameters file at all. Deploy from that directory with:

```bash
az deployment group create \
  --resource-group <rg> \
  --template-file mainTemplate.json \
  --parameters @parameters.example.json
```

Full prerequisites, the Key Vault variant, and the Cloudflare Access exemption needed for a pull connector are in [integrations/microsoft-sentinel/README.md](integrations/microsoft-sentinel/README.md).

## The downpipes family

| Repository | What it is | Licence |
|------------|-----------|---------|
| `engine` (this repo) | The in-account backup Worker: capture, seal, schedule, restore | Elastic 2.0 |
| [`console`](https://github.com/downpipes-io/console) | The in-account management console; every action in the browser | Elastic 2.0 |
| [`downpipe`](https://github.com/downpipes-io/downpipe) | The offline Go reader: verify and recover archives with no vendor | MIT |

Docs live at [docs.downpipes.io](https://docs.downpipes.io), and you can mount them in your AI tooling: [use the docs in your agent](https://docs.downpipes.io/reference/connect-docs-to-ai). The product site is [downpipes.io](https://downpipes.io).

## Verify a release

Every tagged release is reproducible and signed. See [VERIFY.md](VERIFY.md) for the exact
commands to rebuild the artefact from source, compare it against the signed update channel, and
check the cosign and SLSA attestations.

## Support and security

General support: support@downpipes.io. Report a vulnerability by email rather than a public
issue; see [SECURITY.md](SECURITY.md) for the address and what to include.

## Licence

Elastic License 2.0 (ELv2). See [LICENSE](LICENSE).

Free to use, modify and self-host in your own account. You may not provide the software to third parties as a hosted or managed service.
