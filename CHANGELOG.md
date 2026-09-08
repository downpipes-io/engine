# Changelog

All notable changes to the downpipe engine are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
on the `0.x.y` pre-release series. While the engine is pre-1.0, minor releases may
carry behaviour changes; operator-action upgrade steps live in
[UPGRADING.md](UPGRADING.md).

The on-disk archive format carries its own frozen version (`downpipe/0.1.0`) that is
independent of the engine version. A change to a byte-level rule of the archive
format is a new format MINOR version (an incompatible format identity while the
format major stays 0), specified normatively in the sibling
`downpipe` repository at `docs/format/SPEC.md`, not an entry here. This changelog
tracks the engine Worker, its scheduler Durable Object and the admin API.

## [Unreleased]

## [0.3.3] - 2026-09-07

### Added

- The engine records its Cloudflare account id at the end of a self-update as well,
  so the first update from an older engine completes licence binding.

## [0.3.2] - 2026-09-07

### Added

- The engine records its own Cloudflare account id after its first verified source
  attach or update, so a self-serve licence binds to it without any configuration.

## [0.3.1] - 2026-09-07

### Changed

- A self-serve licence now binds to the Cloudflare accounts that activate it, up to
  the band's estate count, so activation no longer warns about a different account.
- The engine status reports its Cloudflare account id, which the console sends when
  it activates a licence.

## [0.3.0] - 2026-09-06

### Added

- Azure Blob Storage joins Cloudflare R2, Amazon S3 and Google Cloud Storage as a
  backup destination, including immutable (WORM) retention, sign-in as a Microsoft
  Entra service principal or with a SAS credential, and the Azure Government and
  Azure China cloud endpoints.
- Restore approval can now be turned on for a single-operator account. Previously an
  account with only one Owner could plan a restore but never apply it once approval
  was required; an Owner can now enable approval and the account stays usable solo.

### Fixed

- The SLA compliance report no longer understates a new downpipe's compliance by
  counting scheduled runs from before the downpipe existed. Each row states the exact
  time window it was measured over.
- A restore into a Cloudflare D1 database that is refused because the target already
  holds data now writes nothing at all for that database. Previously, index and
  trigger records for that database could still be created against the live table
  after the refusal.
- Adding a second, console-managed destination alongside the default Cloudflare R2
  storage created at deploy time no longer reassigns that default's existing backup
  history to the new destination. The deploy-time storage becomes a permanent, named
  destination and both are kept.
- Account status and setup pages no longer describe an account's storage as
  S3-compatible when its only destination is the default Cloudflare R2 storage
  created at deploy time.
- A scheduled backup of a very small source, such as two secrets, no longer fails
  when it happens to run alongside several other scheduled backups at the same time.

### Security

- Enrolling a new passkey after signing in with a recovery code no longer immediately
  invalidates the account's other recovery codes. The new codes are held pending
  until confirmed in the console, and the old codes keep working until then.

## [0.1.9] - 2026-07-03

### Changed

- No engine behaviour changes (version pairing with console 0.1.9, which auto-reloads
  the page after a console update instead of asking the operator to reload).

## [0.1.7] - 2026-07-03

### Changed

- The update settle is now OPTIMISTIC: a verified atomic promote is kept unless there is
  positive evidence of a bad build (a dead canary -- a completed flight with a strayed
  byte). A canary or self-check that cannot COMPLETE in the moments after the deploy
  swap (the Durable Object reset window) no longer rolls back a healthy update; it keeps,
  confirmation pending, and the hourly canary confirms it from clear of the window.

### Added

- The full settle decision trace (the self-check result, every canary retry verdict, and
  the reason) is now logged live, persisted into the update record and the audit event,
  and captured in the support pack -- so a rollback or a kept-pending update is diagnosable
  after the fact from the record alone, not only from a live tail.

### Fixed

- confirmationPending is now persisted (it was response-only), so a status re-read shows
  the true pending state and the hourly canary can clear it.

## [0.1.6] - 2026-07-03

### Changed

- No engine behaviour changes. A pathway-drill release paired with console 0.1.6 to
  exercise the 0.1.5 single-flow update experience end to end.

## [0.1.5] - 2026-07-03

### Changed

- Update judgment and reporting overhaul (design UPDATE-UX-015): a canary flight that
  cannot complete in the moments after a deploy swap is retried and then handed to a
  CRITICAL-only self-check (the durable-object round-trip), never read as a regression;
  only a dead canary rolls back immediately. A self-check keep is confirmed in the
  background by the hourly canary. A live apply with no destination configured refuses
  before any deploy. An engine rollback that would drop below what the live console
  requires becomes a paired rollback. Every settled outcome is persisted before any
  rollback deploy and reported honestly.

## [0.1.4] - 2026-07-03

### Changed

- No engine behaviour changes. This release pairs the engine with console 0.1.4 so the
  multi-component update pathway (engine settle, then the console component with its
  ownership proof and post-apply check) can be exercised end to end.

## [0.1.3] - 2026-07-03

### Added

- Multi-component updates: the signed channel now carries a per-component map, and a
  release can ship the console (a static-assets component) alongside the engine. The
  engine applies itself first and must settle before the console component applies;
  failures report the honest partial state and the console rolls back independently.
  Old engines keep reading the engine-only artefact list unchanged.
- A deploy-target ownership proof for console updates: the target script's live
  bindings must include the service binding pointing at this engine, or every
  mutating call refuses -- a script name alone is never trusted. CONSOLE_WORKER_NAME
  names the console script (default "downpipe-console").

### Fixed

- Settle judgment after the first live apply: a canary flight that cannot complete in
  the moments after the code swap (the isolate reset window) is retried on a short
  bounded schedule and then handed to the self-check -- it is no longer read as a
  regression. Only a dead canary (a strayed byte) rolls back immediately. The settled
  outcome is persisted before any rollback deploy and the update status reports it,
  so the console always shows the recorded truth.

## [0.1.2] - 2026-07-03

### Fixed

- A token-less update preview (dry run) was refused with "could not read the engine's
  current deployed version": the rollback-target read ran before the dry-run boundary,
  and a preview carries no deploy token by design. A dry run now reports the unread
  target honestly and completes the plan; a live apply still refuses, before any
  change, when it cannot read the rollback target with the operator's token.

## [0.1.1] - 2026-07-02

### Added

- A max-lines size guardrail in the lint gate: src files over 800 lines fail unless
  pinned with an explicit ceiling and rationale, so the decomposed modules cannot
  silently regrow.

- Four account-API source adapters that read with the engine's read-only discovery
  token rather than a binding: Workers script code, settings (bindings, compatibility
  date and flags, observability and limits) and a versions inventory, with secret
  binding values reduced to a name-and-type reprovision checklist; the Stream video
  inventory with opt-in MP4 bytes and WebVTT captions; the Images inventory and variant
  definitions with opt-in image bytes; and the Artifact Registry namespace and
  repository inventory with an opt-in full-history object walk bounded to 5000 objects
  per repository.
- Opt-in, confirmation-gated in-account media re-upload for Stream and Images: an
  additive restore of captured bytes that keeps an image's original id and remaps a
  restored video to a new uid reported as an id-map, bounded to 25 MiB for an image and
  a 200 MiB direct upload for a video. Workers and Artifact Registry remain
  backup-with-reprovision: the operator redeploys or re-pushes deliberately rather than
  the engine blind-writing a live service.

### Changed

- The support-bundle builder, cron drive passes, demo engine and diagnosis modules
  were decomposed into single-concern modules (support-sections-*, *-pass.ts,
  demo-seed/world/routes, signals-<domain>). Byte-level moves; no behaviour change.
- Cloudflare configuration coverage grew from 51 surfaces to 214 zone and account
  surfaces. In-account automated restore now covers the 7 in-band write surfaces; the
  remaining 207 are backup plus a diff-preview (121 idempotent, 49 ordered, 44
  reprovision by restore tier), re-applied out of band by an operator. This supersedes
  the surface and restore counts recorded against 0.1.0 below.

## [0.1.0] - 2026-06-21

### Added

- The in-account Cloudflare Worker that seals Workers KV, R2, Secrets Store and D1
  to the `downpipe/0.1.0` archive format on a schedule, into the customer's own
  destination bucket, with no custody by the vendor.
- The scheduler Durable Object: per-downpipe alarms with jitter, coalescing and a
  run lock, behind a `*/15` reconciliation cron safety net.
- CNSA 2.0 hybrid post-quantum sealing: X25519 + ML-KEM-1024 key encapsulation,
  Ed25519 + ML-DSA-87 signatures, AES-256-GCM STREAM, HKDF-SHA-384 throughout,
  with both halves of each hybrid mandatory and no downgrade path.
- The admin API the console calls, authenticated in strict anti-downgrade
  precedence by a Cloudflare Access RS256 JWT, a first-party WebAuthn passkey
  session, or the bootstrap-only `ADMIN_TOKEN` bearer.
- Capability-based RBAC over six built-in roles plus composable custom roles,
  enforced at the router and re-checked inside the Durable Object; dual-control
  restore bound to a recomputed plan hash, single-use and lazily expiring.
- Destination writers for native R2 (in-account binding) and S3-compatible
  endpoints, with 3-2-1 destination failover and per-destination replication
  state.
- A SHA-384 hash-chained, append-only audit log with a retention cap and SIEM
  export carrying the chain head.
- Cloudflare configuration backup across 214 zone and account surfaces, with
  automated in-account restore for the 7 in-band write surfaces and a diff-preview
  for the remaining surfaces, re-applied out of band by an operator.
- A controlled, reversible engine self-update channel: signed release manifest,
  one-click rollback, opt-in ramp, and dual-control for migration or breaking
  changes.
- A native identity-provider bridge: OIDC, OAuth2 and a native SAML service
  provider across the supported providers.

[Unreleased]: https://github.com/downpipes-io/engine/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/downpipes-io/engine/releases/tag/v0.3.2
[0.3.1]: https://github.com/downpipes-io/engine/releases/tag/v0.3.1
[0.3.0]: https://github.com/downpipes-io/engine/releases/tag/v0.3.0
[0.1.0]: https://github.com/downpipes-io/engine/releases/tag/v0.1.0
