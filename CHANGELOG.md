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
format major stays 0), specified normatively in the format specification of the
`downpipe` reader repository, not an entry here. This changelog
tracks the engine Worker, its scheduler Durable Object and the admin API.

## [0.3.8] - 2026-10-11

### Added

- The audit action `runlog-resumed` records an Owner's attended `POST /runlog/resign` that publishes an absent `RUNLOG.sig` again from the engine's pending signature. The row names the destination, the digest prefix and the highest index, and the support pack lists it.
- The support pack records a `sig-restored` RUNLOG anomaly when a deleted `RUNLOG.sig` is published again from the engine's pending signature.
- The support pack shows each RUNLOG hand-over and relink. A refused relink writes an audit row that names its refusal.
- A re-key that the RUNLOG pre-check refuses for a chain anomaly records a RUNLOG anomaly row in the support pack that names the anomaly.
- A support pack replication row that is reachable but holds no run carries `copy: "none-yet"`: the destination has no restorable copy yet.
- A failed run names its destination (`destinationId` and `destinationIdBasis`), and each destination fault names its destination. A refused destination save, and a refused clear or remove, records the refusal class and the blockers behind it in the support pack.
- The support pack reports each destination's write facts (key class, `checksumRequired` and the region hint), the update channel state, and why an update channel fetch failed.
- After an account recovery, the support pack states the Owner actions still pending.
- The support pack's site-fault legend states the evidence each fault undermines.
- The Security Centre grades a console served on a `workers.dev` hostname with a low-severity
  "Console on your own domain" check (`console-on-workers-dev`), read from the hostname of `CONSOLE_ORIGIN`.
  It is not raised when `CONSOLE_ORIGIN` is unset, unparseable or not https.
- The support pack keys section reports `operationalRetired.state` (`stale-key-held`, `applied` or `not-set`). For `stale-key-held`, an operational key is still bound after a strict re-key, and `action` names the `POST /admin/keys/break-glass-only` route that deletes it.
- The signed update channel carries the release date of every release. A release is supported until
  90 days after the next release ships. `GET /admin/updates` reports `supportedUntil` and
  `supportStatus` (`supported`, `ending` or `end-of-life`) for the running version. The latest release
  has no `supportedUntil`. See `docs/SUPPORTED-VERSIONS.md`.
- The Cloudflare configuration backup captures per-bucket R2 settings. For each bucket, the `r2-bucket-config`
  surface records CORS rules, lifecycle rules, bucket lock, custom domains, public r2.dev access (`publicAccess`),
  Sippy and event notifications. The engine does not write bucket settings back: the restore plan marks them
  captured, not restorable, and gives the manual step.

### Changed

- When a RUNLOG append refuses an index its destination already holds, the scheduler holds new runs, reads every configured destination's RUNLOG and moves the run counter past the highest index any of them holds. The support pack records a `counter-advanced-after-recovery` row with where the counter moved from and to, and the destination that held the highest index. The recovery seed also takes the highest verified index across the configured destinations.
- A RUNLOG append refuses an index that another run in that destination's RUNLOG already holds, and the support pack records a `duplicate-index` anomaly. After a control-plane recovery the run counter can restart below the indices a second destination holds; such a run fails and does not write a duplicate index.
- A RUNLOG append refuses an anti-rollback floor that reads back but is not a whole number above zero, with the integrity reason `floor-invalid`.
- When two first backups race on one empty destination, the run that loses the create backs off and re-reads, and records no anomaly. If the signature has not landed when its attempts run out, an inline run parks and resumes.
- The "Sources fan out to two destinations" posture check counts, for each downpipe, the destinations
  that hold its latest successful run. A destination still catching up, or one whose copies keep
  failing, counts once replication reports the run there.
- The config history is signed under its own key, so a global sign-out leaves every stored history entry verifiable.
- A deleted D1 source reads as deleted, not unavailable. An R2 bucket-lock refusal reads as `ObjectLocked`.
- The SCIM service provider configuration states that a member who signs in through Cloudflare Access is removed from the Access policy in Access; a SCIM deprovision ends their sessions in the engine.

### Fixed

- Deleting a member's role, including a SCIM deprovision, deletes their sign-in network prefixes and their IdP group record with it.
- An IdP group record names the address it was written for. Offboarding a member by address deletes it, including for a member who holds access only through an IdP group. A group record not refreshed for 90 days is deleted.
- Replication copies the recovery bundle to every destination that holds runs. A destination reached only through replication verifies and restores with `--signer-fingerprint` like any other.
- A seal verify that reads a RUNLOG while another run writes it records no integrity fault when the next read verifies.
- Safe-apply reads the uploaded engine module back from Cloudflare and compares it with the signed digest before it promotes the version.
- `GET /admin/status.artefactSha384` is the SHA-384 of the main module bytes the engine uploaded.
- During a new destination's first sync, the other downpipes keep replicating their runs.
- A RUNLOG writer waits for a held lock long enough to take its turn.

### Security

- A session that starts with a recovery code does not satisfy step-up; step-up needs a passkey, either an existing passkey or one enrolled after recovery.
- The sign-in, break-glass bearer and recovery-code limiters key an IPv6 client by its /64 and an IPv4 client by its address.
- Every engine response carries the same hardening headers on every path and status, including `cache-control: no-store`.
- Admin write routes check the caller's access before they read the request body. A body that is not a JSON object gets 400, and a denied request always writes its audit row.
- `/admin/health`, `/ready` and `/` answer 405 with `Allow: GET, HEAD` for any method other than GET, HEAD and OPTIONS.
- Importing an estate needs both `keys.ceremony` and `access.policy`.
- The engine chooses the store behind a destination endpoint from its host alone: a query, a fragment or userinfo cannot select a different store.
- The parsers that read untrusted input refuse malformed input with their own errors: a count written with a fraction, an exponent, a sign or a leading zero, or a count key that differs only in case; a JSON null line in a RUNLOG or a shard; a root or update signature file that is not base64url; a config snapshot that is not JSON; a sealed control-plane export with a malformed capsule member; a control-plane import body with no canonical form; and a SCIM PATCH body of JSON null (400). An ID token key set without a `keys` array fails closed, and the export secret check is bounded by nesting depth.
- Dependency install scripts are off, and the install guide uses `npm ci`.

## [0.3.7] - 2026-10-05

### Added

- Owner-only RUNLOG routes, each needing `keys.ceremony`, and step-up for each POST: `GET /admin/runlog/signature` and `POST /admin/runlog/resign`,
  `GET /admin/runlog/floor` and `POST /admin/runlog/floor/reset`, and `GET /admin/runlog/chain` and `POST /admin/runlog/relink`.
- The notify events `runlog-resigned`, `runlog-floor-reset` and `runlog-relinked` (warning) report each attended RUNLOG action.
- The support pack says how each destination id resolves and what each destination
  fault points at. `destResolution` gains `resolution` (every stored destination id and every id a
  downpipe names, each with the resolver branch, `ok` and the closed refusal reason), `defaultResolution`,
  `collection` (per stored destination: `source`, `kind`, `isDefault`, which fields are set as booleans,
  `deleteProbe` with `deleteProbeBasis`, and a stored `deleteStatusClass` when the probe was not `ok`),
  `danglingRefs` (each downpipe and destination id pair the resolver refuses, with the reason) and
  `ioTimeouts` (request timeouts per destination id). The deploy-time destination's `deleteProbe` of
  `other` reads `deleteProbeBasis: "seeded-unprobed"`, because the engine stamps it when it seeds the row
  and never probes it. Each destination change in `configEvents` carries the destination ids and the
  default before and after the change. A failed replication row carries `reasonSite`. A new
  `sealFaultSpans` section keeps, per fault kind and reason (and per target destination for a replica
  fault), the count and the first and last time it was seen, which the 64-row `sealFaults` ring loses.
  A `replica-target-fault` row lists up to 16 of the runs it cannot fill, each with its origin
  destination, the cause and whether the origin still holds it. Every row in `runs` carries the
  destination the run sealed to, or a `destinationBasis` that says why none is named (`env-default`,
  `unrecorded` for a run sealed before 0.3.7, `not-sealed`, `unknown`). A default-routed run records the
  id of the stored default it sealed to. No field carries an endpoint, a bucket name or a credential.
- A destination saved from the console now stores the verification probe's read of the bucket's
  default retention rule, and the destination status (`GET /admin/destinations`,
  `GET /admin/destination`) carries it as `defaultRetention`. The field is present only when the
  bucket enforces Object-Lock and the engine can read the rule: `true` when the bucket has a default
  retention rule, `false` when Object-Lock is on and no rule applies. An Azure Blob container never
  carries the field, because its default retention policies are on the Azure management plane, and a
  storage-account key or a SAS cannot read them. Before, the verify response and the support pack
  carried it, but the stored record did not, so the console could not tell a lock that retains
  archives from a lock that retains nothing. The signed control-plane export now carries the field,
  and an estate reconciled from the export keeps it. A destination saved before this version has no
  `defaultRetention` until you save it again.
- A `source-bindings` audit target. The `sources-attached` and `sources-detached` rows now name the
  bindings the in-product attach added or removed, as the attach design always described. Before this,
  both rows carried the field-less `access-policy` target, so the trail said that the protected set
  changed but not which source. The console builds each binding name from the resource name, so a row can
  show a bucket, namespace, database or secret name in sanitised form. A row never carries an id, a value
  or the token. A SIEM parser that validates target kinds must accept `source-bindings`.

- An audit action, `support-bundle-generated`, with a new `support-bundle` target kind. A support bundle
  downloaded (`GET /admin/support/bundle`) or generated from the console (`POST /admin/support/bundle`)
  now writes a row that names the route and whether the engine sealed the bundle to the vendor support key.
  The vendor's credentialed pull writes a new audit action, `support-diagnostics-pulled`. A SIEM parser
  that validates target kinds must accept `support-bundle`.

- Two audit actions, `notify-channel-change` and `notify-rule-change`. A notification channel or rule
  that is created, edited or deleted now writes a row to the audit chain, and a caller without
  `notify.config` writes a `denied` row. The target is the existing `configchange` kind: the closed change
  kind and the channel or rule id, never the URL, routing key or API key. Before this, an applied change
  wrote no row while config approval was off, so a repointed channel or a deleted rule left no trace. A
  change that config approval queues still writes `config-change-propose`, and its approval writes
  `config-change-approve` with the same change kind. Neither writes a notify row. The first channel on an
  engine with no rules also creates a default rule, and only that channel's `notify-channel-change` row
  records it. The support pack's config-events excerpt includes both actions. A SIEM rule keyed on the
  action list sees two new values.

- `POST /admin/policy/require-access` reports `adminTokenPresent`, `breakGlassTokenRetired` and
  `tokenPathClosed`. The engine refuses the shared token when `ADMIN_TOKEN_DISABLED` is set, when the
  `ADMIN_TOKEN` secret is not set, or when an Owner retired the token. `tokenFallbackDisabled` reports only
  the first. `tokenPathClosed` is true when any of the three applies. `breakGlassTokenRetired` is null when
  the engine cannot read its retire record, and null does not make `tokenPathClosed` true. While the engine
  cannot read that record, it refuses the shared token.
- The generic webhook body (`downpipe-event-v1`) now carries `dedupKey`, a stable key of the form
  `downpipe:<id>:<event>` (or `account:<event>` for an account-level event), and `recovered: true` on the
  message that closes a `backup-failure`, `backup-stale`, `replication-degraded` or `run-at-risk-eviction`
  alert. The key is the same key the PagerDuty, Jira Service Management and ServiceNow channels use, so a
  webhook-based incident tool can close the incident the trigger opened. `canary-recovered` is a separate
  event and does not carry `recovered`. The `kind` stays `downpipe-event-v1`. A receiver that ignores
  unknown keys keeps working. A receiver that rejects unknown keys rejects every body from this version,
  critical alerts included, so change it before you upgrade (see UPGRADING.md).

- `POST /admin/keys/add-config-recovery` installs the configuration recovery key, the configuration wrap
  key, or both, on an engine that holds a signer but lacks them. It never replaces a key the engine
  already holds, and it never touches the signer, the break-glass public or the operational pair.
  When it installs the wrap key, it also seals the credentials stored before that key (the next entry).
  `GET /admin/status` reports `configKeysConfigured` (presence only) so the console can offer it.
  `configKeysConfigured.recipient` is true only when both halves of the configuration recovery key are
  bound, and `configKeysConfigured.recipientHalves` (`{ public, private }`, presence only) names a partial
  pair. A lone `CONFIG_RECIPIENT_PRIVATE`, which a key install leaves when its second write fails, is
  completed with the public derived from it (the x25519 public from the scalar, the ML-KEM-1024
  encapsulation key from the seed) by a re-key or by this route. The request's new pair is validated but not
  written, and the answer says `configRecipient: "repaired"`. A lone public is never overwritten, because
  exports are sealed to it: this route refuses it and names the recovery step (delete
  `CONFIG_RECIPIENT_PUBLIC` in the Cloudflare dashboard, then add the keys again; exports sealed to it still
  open with break-glass), and a re-key keeps it and answers `configRecipient: "kept-partial"`.
- A console key install now seals the credentials the engine already holds as plaintext.
  `POST /admin/keys/install`, and `POST /admin/keys/add-config-recovery` when it installs
  `CONFIG_WRAP_KEY`, seal the discovery token, destination credentials, SIEM and OTLP push secrets, Jira
  Service Management and ServiceNow channel keys and IdP client secrets under that key in the same step.
  The response carries `rewrap` with the counts (`wrapped`, `alreadyWrapped`, `leftPlaintext`) and the
  classes left plaintext. When the engine held any such credential, one `config-secrets-rewrapped` audit
  row records the counts and classes, never a value. The pass never fails the install. A credential it
  cannot seal stays plaintext, keeps working and is sealed on its next save. A key set with
  `wrangler secret put` does not run the pass. A SIEM rule keyed on the action list sees one new value.
- Each Cloudflare configuration run now carries one coverage record, `_cf-config-coverage`, after the
  identity record. It names each registry surface the run has no record for, with the reason: `not-used`,
  `plan-gated`, `no-zone` or `not-selected`. In Auto mode the reasons come from the daily discovery. Before
  this, a surface left out because the account does not use it or its plan does not include it left no
  trace, so the archive could not tell "not on your plan" from "not captured". The record carries no
  marker, so it does not count toward `recordsIncomplete`, and a restore preview lists it as informational.
- The restore dry run now says which planned Workers KV keys and R2 objects already exist in the target
  (`RestorePlan.overwriteCheck` and `sample[].targetExists`). It asks with a KV read whose value stream
  it cancels without reading, or an R2 head, so it never reads or returns a live value. It costs one read
  per KV or R2 record, inside the 200-record in-account limit.
- `RestoreRequest.onExisting: "skip"` keeps a live KV key or R2 object of the same name. The apply checks
  each name just before its write, reports a kept name in `skipped`, and writes nothing when the check
  fails. The default, `"overwrite"`, replaces the live value as before. `"skip"` is bound into the plan
  hash; any other value is refused before a write. A `"skip"` request has an in-account limit of 160
  records, because the check is one more call per record.
- Every dry-run plan carries `onExisting`, the choice it planned with. An engine without it ignores
  `"skip"` and replaces live keys, so a client checks for it before it sends a `"skip"` apply.
- The support pack's restore fault ring records a failed `"skip"` check as `exists-check-failed`, and
  does not record a kept live key as a fault.
- A Secrets Store backup now records where each secret was. Each record carries the secret's scopes and
  comment, and every Worker that binds it with the binding name that Worker uses. The engine reads them with
  the read-only discovery token and never reads a value through it. Without a token, or with a token that
  cannot read the Secrets Store or a Worker's settings, the run still seals every value and records the
  Worker wiring as `unknown`. It never records a partial list. The Workers read stops when the run's slice
  budget cannot cover it, so it never fails a run, and the wiring is then `unknown`. The engine reads only
  accounts in the Owner's discovery scope. `captured` needs the secret's name in the store and the engine's
  own binding in the list. The archive keys are `scopes`, `comment`, `workers` and `wiring` (SPEC 12.3); the
  single `scope` and `worker` keys, which no run ever wrote, are gone. A secrets source's optional
  `accountId` must now be a hex account id in the discovery scope.
- Every run's recovery bundle (`_RECOVERY/downpipe/0.1.0/`) now carries `signer.pub`, the public key of
  the signer that sealed the run, in the recovery-kit file form. It is listed in the signed `SHA384SUMS`
  (downpipe SPEC.md 9.1). With the downpipe reader's `--signer-fingerprint`, the signer fingerprint on
  the printed recovery sheet pins this copy, so a recoverer who holds the sheet but not the kit file can
  still verify and restore. The copy is public and is not a trust anchor: the reader uses it only when
  its fingerprint equals the one on the sheet. Every run overwrites it, so it is always the current
  signer's key, and a run sealed before a signer rotation still needs that signer's `signer.pub`.
- The `role-change` event for a time-boxed member grant, and the `custom-role-change` event for a
  time-boxed custom-role assignment, now carry `target.expiresAt`: the moment the grant self-revokes, in
  canonical ISO form. A standing grant's event carries none. Before, the audit log recorded the grant but
  not until when the elevation ran.
- The Generic OAuth2 preset has six optional values: scopes, an email URL, an email field, an
  email-verified field, a groups URL and a group name field. Each sets its connection field only when
  filled. Before, a connection made from this preset read no email, and the engine refuses a sign-in with
  no email, so the preset could not complete a sign-in.

- The support pack's console diagnostics admit a new renderer cause, `edge-budget`. A console from 0.2.7
  records it when the Map shows more flows than it animates and draws one still frame. Before this change,
  the console recorded that state as `none`, which means the live view was running. An older engine drops
  an `edge-budget` row.
- The support pack's console diagnostics accept `cost-offline-recoveries`, the Costs screen's "Offline
  recoveries per month" field, as a form field. A console from 0.2.7 records a refused value there. An
  older engine drops that row.
- The support pack dates three records it already counted. `adminRouteErrors.lastAt` and
  `recovery.recoveryRefusals.lastAt` carry the time of the last admin-route fault and the last refused
  manual recovery, as epoch milliseconds. `schedDiag.posture.overrides[].at` carries the time an Owner
  accepted the override, as an ISO timestamp. The engine recorded all three, but the pack read the
  first two as text and the third under the wrong name, so no pack carried them. Each field is a
  positive integer or an ISO timestamp, and the pack drops any other stored value.
- The support pack's `canary` section carries `ailingDetail`, one row for each destination whose
  canary is ailing now. A row has the flight time (`at`), the classified cause (`ailingCause`: `auth`,
  `worm-refused`, `throttled`, `timeout`, `network`, `tls`, `other`, `probe-mismatch` or `unreachable`)
  and the flight aspects that failed or were skipped (`failedAspects`). A stored cause outside that list
  reads `causeAbsent: true`. Before, the pack said only that the canary was ailing, so a rejected key
  pair, a WORM refusal and a store that throttled requests read the same. A row does not name the
  destination.
- An update settle records the canary baseline it compared against. The settled update record
  (`GET /admin/update/status`, `last`) and the support pack's `updates.last` carry `canaryBaseline`
  (`alive`, `dead`, `ailing`, `pending` or `disabled`), and `canaryBaselineReadFailed: true` when the
  engine could not read the canary and used `pending`. A `pending` baseline cannot show a regression,
  so the flag tells a disarmed regression check from a canary that had not flown. The apply, settle
  and ramp settle responses carry the flag too. The `update-applied` and `update-rolled-back` audit
  details now read `(canary <verdict>, baseline <baseline>, ...)`, with `unread` after the baseline
  when the read failed. The decision to keep or roll back is unchanged.

- The audit action `config-recovery-added` records each successful `POST /admin/keys/add-config-recovery`, with a
  `key-ceremony` target, and a `denied` row for a caller without the capability.
- The audit action `passkey-invite-enrol` records a passkey enrolled through a registration invite. Its
  target is the `role` kind and names the member and the role the enrolment resolved to.
- The notify event `scim-owner-demoted` (warning) reports an Owner that a SCIM deprovision demoted to
  Viewer.
- The audit action and notify event `retention-armed-alone` (warning) record a downpipe edit that lets the
  scheduled retention prune delete more with no second approver.
- The audit action `denied-overflow`, with a target kind of the same name. Past the hourly ceiling of 9
  refused-request rows, the engine writes at most one row an hour, which carries `deniedAttempts`.
- The audit actions `runlog-handover`, `runlog-resigned`, `runlog-floor-reset` and `runlog-relinked` use a
  new `runlog-signature` target kind. A SIEM parser that validates target kinds must accept it.
- A medium posture check, `release-signer-pin`. It fails when a declared `RELEASE_SIGNER_PIN` is not the
  fingerprint of `UPDATE_SIGNER_PUBLIC`. With no pin declared, the check is not raised.
- The support pack has a `siteFaults` section. Each fault site that recorded a fault has its legend line,
  its fault class, a count, and the first and last time it was seen.
- A `replica-target-fault` row in `sealFaults`, and a failed destination row in the support pack's
  replication section, carry `nextStep`: the next step for its reason.
- The support pack counts `session-grant-lapsed` when a native session is refused because its subject no
  longer holds a role or a mapped group.

### Changed

- Every RUNLOG writer (the seal append, the retention prune and replication) verifies the stored RUNLOG before it changes or re-signs it.
  The engine never re-signs a RUNLOG that does not verify on its own. Runs to that destination fail at the RUNLOG write until an Owner acts.
- Each RUNLOG write puts its signature at `_RECOVERY/RUNLOG.sig.pending` first, and an interrupted write resumes from it only when it verifies.
- A signer re-key hands each destination's RUNLOG over to the new signer. New runs wait up to 15 minutes. The old public key stays until every destination is handed over.
- A seal or relink refused for a duplicate RUNLOG index says to attach the downpipe to a fresh destination.
- Turning off restore approval (`POST /admin/config/restore-approval-policy`) or update
  approval for every release (`POST /admin/config/update-approval-policy`) now needs a
  second Owner, as turning off the config gate does. With two or more Owners, an Owner's
  disarm returns 202 with a pending owner action (`restore-approval-disable` or
  `update-approval-disable`), and the policy stays on until a different Owner approves it.
  Arming still takes effect at once, after step-up. The break-glass admin token still disarms at once. Every
  disarm raises a `dual-control-disabled` alert whose detail names the policy.

- `npm run deploy` needs Node.js 22.18 or later (on the 23 line, 23.6 or later), and `engines.node`
  is `>=22.18.0 <23 || >=23.6.0`. The deploy runs `.ts` files directly, which an earlier Node refuses. `scripts/node-floor.sh` checks the version before
  anything else runs and stops with a message that names 22.18 and the version it found.
- The ISO/IEC 27001 evidence pack carries A.5.33 (Protection of records), bound to `seal-verification`,
  `encryption-pq-hybrid`, `break-glass-present` and `destination-configured`.
- The ISO/IEC 27001 A.8.24 row says that destination credentials are envelope-encrypted at rest when
  `CONFIG_WRAP_KEY` is set, and that the deploy sets that key as a Worker secret on your engine.
- The Essential Eight ML3 own-backup row and the ISM-1812/1813 row say that a grant is keyed to the stable
  subject of the sign-in or to a mapped IdP group, and that a passkey sign-in's subject comes from the
  email the passkey is bound to.
- The approval summary for a queued support credential mint now names the term the mint grants, for
  example `Mint a diagnostics support credential that expires after 3 days (opens a read-only pull
  surface)`. The approval binds to the scope and the term, so the second owner now sees the term they
  approve. It is the term the approved mint grants: the requested term, or the scope default, clamped to
  the scope cap.
- The control-plane export in the destination bucket is now sealed whenever the engine holds a break-glass
  public key or a config-recipient public key. Before, it was sealed only when break-glass was installed and
  `CONTROL_PLANE_EXPORT_SEALING_DISABLED` was not set, so an engine with only a config recipient wrote the
  operator roster and the destination topology in cleartext. The export is cleartext only when the engine
  holds neither key. The export state records the form (`sealed`), and the `environment-self-backup`
  posture check says when the export is cleartext.
- The export pass now finishes an incomplete export on later scheduled ticks. A destination whose write
  failed, or that the tick's budget cut off, gets the export on the next tick, and only that destination
  is written. A budget-cut destination now reads as failed in the posture check until then.
- The bundled `RECOVER.md` teaches the fingerprint-pinned restore first and keeps the `--signer
  signer.pub` restore. It says the directory holds only the current signer's copy, and how to check the
  copy by hand with a reader that has no `--signer-fingerprint`. The bundled `FORMAT.md` names the signer
  fingerprint as a recovery input.
- The bundled `RECOVER.md` tells a recoverer what `--allow-unverified` does when a signature check
  fails. The flag skips only the signature checks and the RUNLOG freshness check. The restore writes the
  records and then exits with code 2, and this is not a verified restore. A receipt records the mode
  only when `--receipt` is given.
- The SEC 17a-4(f)(2)(iv) capability text in the evidence pack names `signer.pub` as the reader's signer
  input, and the sheet's signer fingerprint as a stand-in while the signer that sealed the run is current.
- The offline-key posture statement is now `key-posture-ack/v3`. v2 said the engine proves its test data
  recoverable every hour, but the canary runs on its own schedule (300 to 86,400 seconds, 3,600 by
  default) and an operator can turn it off. v2 also named only the offline reader for pruning, but the
  console's break-glass prune also prunes, with the key in the browser. The engine refuses a `v2`
  acknowledgement, so update the console to 0.2.7 at the same time. The operational statement stays `v1`.
- `POST /admin/restore/verify` checks the request before the role gate, as `POST /admin/restore` and
  `POST /admin/restore/request` do. A missing or malformed `runId`, or an empty prefix in `include` or
  `exclude`, is a 400 whatever the caller holds. Before, a caller without `restore.verify` got the 403
  first, and the engine recorded a `forbidden` restore-proof refusal for a request that could not have run.
  A well-formed request from that caller still gets the 403 and the refusal record.
  `test/validate-selector-empty-prefix.ts` holds it.
- An OIDC or OAuth2 connection created from a preset (`POST /admin/idp/connections` with a `presetId`) is
  now switched off unless the create sends `enabled: true`. A create with no `enabled` stores
  `enabled: false`, so a console that never sends the field also creates connections off. A value that is
  not a boolean is refused with "enabled must be a boolean when supplied". A switched-off connection
  cannot start a sign-in until an Owner switches it on. A connection that already exists keeps its state.
  A create with a full `proposal` still needs `enabled` in the proposal, as before.
  `test/validate-cov-sched-scheduler-do-idp.ts` holds it.
- Creating a SAML connection with `emailVerifiedPolicy: "require-flag"` and no `emailVerifiedAttr` is
  refused. The reason names `emailVerifiedAttr`. Such a connection admitted nobody: with no flag attribute
  every assertion carried no email, and the engine refuses an emailless sign-in. A connection stored
  before this change is not re-checked.

- Failed and recovery sign-ins share an hourly ceiling of 20 folded audit rows, and refused requests have
  their own ceiling of 9. Pending fold counts survive an engine restart.

### Removed

- `CONTROL_PLANE_EXPORT_SEALING_DISABLED`. The engine ignores it. It existed so that a break-glass-only
  engine could auto-heal from a cleartext export, and the config-recipient key now does that for a sealed
  export. See UPGRADING.md before you upgrade an engine that sets it.

### Fixed

- After a control-plane recovery, a failed read of the bucket's RUNLOG no longer lets the first run re-use
  a run index the RUNLOG already holds. The recovery path used to drop any read, signature or parse failure,
  so the next run took index 1, the RUNLOG gained a duplicate index, and every later restore, drill or
  attestation from that destination refused with "runlog index 1 appears twice". The outcome is now
  recorded with the recovery latch as `runlogSeed` (a seed, or `noSeed` with the reason `absent`,
  `unreadable`, `sig-absent`, `sig-invalid`, `unparsable` or `no-signer`) and appears in recovery status and
  in the support pack's recovery section. On `unreadable` and `no-signer` the engine holds new runs until a
  later read succeeds, and the health pass reads again on every tick. `test/validate-recovery-counter-seed.ts`
  holds it.
- The expiry reconcile no longer treats a missing, unparseable or non-object request body as an empty one,
  which deleted every secret-rotation marker and restarted every rotation clock. It answers 400
  `expiry-reconcile-body-invalid` and changes nothing. `test/validate-secret-rotation-cadence.ts` holds it.
- The preflight source-liveness item no longer reports `probeErrorClass: "not-found"` for every probe
  fault. It now reads "not-found" only when a probe answer proves a resource gone (the same rule as the run
  row: R2 10006, KV 10041, D1 7404 or 10181). A timeout, a network fault, a 5xx, a 429 or an answer that
  proves nothing carries its own class (`timeout`, `transport`, `unavailable`, `rate-limited`, or `other`).
  Each entry of `missingResources` now carries its own `probeErrorClass`, and the item reads "not-found" when
  any resource is proven gone, the shared class when all agree, and "other" when they differ. The probe's
  own error rides only as the non-enumerable `Error.cause`. `test/validate-source-liveness.ts` holds it.
- Replication to a second destination now reaches every downpipe at every cron tick. The pass walked the
  downpipes in one fixed order and copied a downpipe's whole backlog before it went to the next, so the first
  downpipe used the pass window at every tick and the others were deferred. On a fresh five-downpipe estate
  the second destination gained no run in 23 minutes, and only a force removal ended the wait that the
  removal refusal asks for. Now the downpipes take turns: each copies at most one run to each destination in
  a round, and the downpipe that starts, and the destination it serves first, move on by one at each tick.
  A copy is not started once the window is spent, and a run-tree is not copied before its segments, so a
  pass with little window left no longer copies the same run-tree again at every tick. One pass reads each
  destination's configuration and RUNLOG once for all downpipes. Runs are still copied oldest first within
  each downpipe, and what a destination is counted as holding is unchanged. The removal refusal now says
  "oldest first within each downpipe".

- An account with exactly 100 R2 buckets can now finish setup. Source discovery asked the R2 bucket list
  for `per_page=100&page=N`. R2 pages by cursor only: it ignores `page`, and it sends `result_info.cursor`
  only while more buckets remain. With exactly 100 buckets the first page was full and had no cursor, so
  discovery asked for page 2, got the same 100 buckets, and did this until the 500 cap. Each bucket was
  listed five times, and the listing counted as truncated. Protect then ticked all five copies of a pick,
  and Apply sent its binding five times. Discovery now reads R2 by cursor only and lists each bucket name
  once. With more than 100 buckets the first page carries a cursor, so those accounts were not affected.
  The same page-then-repeat loop was in the Cloudflare API paginator that the Workers source, the
  secrets wiring and the cf-config surfaces use. The Workers scripts list ignores `page` and `per_page`,
  so an account with 1,000 or more Workers read the same list until the 1,000-page cap and failed with a
  truncation. Both paginators now stop when an endpoint returns the same page again.
  `test/validate-discovery.ts` and `test/validate-workers-source.ts` model the live list behaviour.
- The attach planner no longer says that a binding "already exists on the engine" when the same new
  binding is in one change more than once. It now says "binding NAME is in this change more than once". Such
  a change is also refused when it removes that name, where it was accepted before with two bindings of one
  name.
- A deleted source resource now fails the run as "source resource missing", not as "run failed". The first
  slice of a sliced run, the default path, ran without the liveness probe that the buffered path and the seal
  Durable Object run. A deleted R2 bucket then failed in the crawl's first list with a raw platform error,
  and the run row, the log line and the support pack named no cause. The first slice now probes the source
  before it crawls, so the run row, the log line and the pack's `sourceFaults` (stage `probe`) name the
  cause. The same applies to a deleted KV namespace or D1 database. The log line keeps the class and the
  digest only; the resource name and the platform text are not logged. `test/validate-source-faults.ts`
  scenario I runs this through `sealRunSliced`.
- A liveness probe that fails without proof of absence no longer reads "source resource missing". The probe
  called a resource deleted on any answer that held "not found", "404", "deleted" and similar text, and every
  other probe fault still carried the "source resource missing" message. So a timeout, a 5xx, a 429 or a
  network fault on the probe read "source resource missing" on the buffered path and in the seal Durable
  Object. Now only the vendor's own absence answer counts: R2 error 10006 ("The specified bucket does not
  exist"), KV error 10041 ("No KV namespace found with ID"), D1 error 7404 or 10181. Any other probe fault
  reads "source read error". The run fails on the inline first slice and on the buffered path, as a crawl
  read fault does there, and the next due run tries again. In the seal Durable Object the first slice
  counts it as a strike and retries it, and a later slice ignores it, as before. The old matcher also
  missed the real KV answer: it holds neither "not found" nor a code that the matcher knew.
  `test/validate-source-liveness.ts` and `test/validate-source-faults.ts` scenario J hold the split.
- The cf-config surface `r2-bucket-config` is now labelled "R2 bucket list (names and creation dates, not
  bucket settings)". It was labelled "R2 bucket settings (lifecycle / lock / CORS)", but it captures one row
  that holds the R2 bucket list, and it reads no per-bucket setting. `test/validate-cf-config-expand.ts`
  records the capture for the live list shape and holds the label to it.
- A destination added to a downpipe now receives the downpipe's older runs, and the old destination can then
  be removed without force. The replication pass ran on the cron tick's shared budget, whose 20-second wall
  clock starts before the seal loop. The six passes before it make their own scheduler round trips, and on a
  live account they used the whole allowance, so the pass started with none left. It either stopped at once
  or copied one segment and one run-tree with no RUNLOG entry, and it did the same at every tick. In a
  customer-path check, one run of six reached the new destination in 48 minutes and none was proven there,
  so removing the old destination was refused until force dropped the six runs. The pass now has its own wall
  window (`SliceBudget.passWindow`) and shares the tick's subrequest tally. With the tick's allowance spent
  before the pass and 150 ms for each destination request, six runs of two downpipes are on the new
  destination after 2 ticks.
- The two destination-removal refusals no longer send the operator in a circle. The in-use refusal said
  "Reassign them first" while runs were only on this destination. Taking the destination off left each
  downpipe with one destination, replication then stopped, and the orphan guard asked for a second
  destination. The in-use refusal now says to keep the destination on the downpipes and counts the runs not
  yet copied. The orphan refusal names the step that makes replication run (this destination and one other on
  each downpipe), says when waiting does not help, and says what force costs. Both count runs one at a time,
  so the count falls as replication copies. Replication copies at each 15-minute tick, and no run is held on a
  destination until the segment data its runs share is there, so the count can stay the same for several
  ticks: both refusals say that the wait can take hours. Runs older than the history ring (the newest 50
  runs of each downpipe) are never copied, and nothing counted them. The refusals, and the response of a
  removal that goes through, now state how many there are.
- A seal completion no longer raises a destination's proven copy past a run the destination does not hold.
  After a part-way backfill, a run sealed to the new destination moved its `holdsIndex` over the older runs
  still only on the old destination. The removal guard then allowed removing the old destination without
  force, which dropped those runs.
- `npm run deploy` deploys a release-tag checkout. Its preflight ran the developer chain, `npm run validate`,
  which refuses with exit 2 (CANNOT CHECK) when a sibling checkout is behind its own origin/main. The deploy page
  tells you to check out the release tag in both engine and console, and a tag is behind main as soon as anything
  lands after it, so the deploy stopped before it started. On the public trees it also failed at
  `test/validate-logging-inventory.ts`, which checks a document against a console file the public console does
  not ship. The developer chain took 17 to 23 minutes, and the script said it took 13. The preflight now checks that `node_modules` matches `package-lock.json`, typechecks,
  builds the bundle with a `wrangler` dry run, and runs `npm run validate:customer`: the 93 members of the
  developer chain that guard your data and keys. Measured in a fresh clone of the public tree, the preflight took 299 seconds at load average 15 to 30 and 738 seconds at 95 to 110; the developer chain ran for 2,899 seconds there before it refused. `npm run validate` is unchanged.

- The recovery sheet for a break-glass-only install said the posture was "chosen with --break-glass-only"
  when it was chosen at the prompt, or taken by default with no terminal. The sheet and the deploy output also
  said in-console restores are off. An in-console restore or retention prune works when you supply
  `identity.key` in the browser. What is off is scheduled restore tests and drills, and scheduled retention
  pruning. The sheet now says how the posture was chosen, and both say what is off and what still works.

- `npm run deploy` reported a deploy when `wrangler` had uploaded nothing. After a console source attach, key
  install or update apply, `wrangler deploy` asks "You are about to upload a Worker that was last updated via
  the script API ... Would you like to continue?". Answered no, it uploads nothing and exits 0, and the script
  went on to report success and generate keys. The script now compares the worker's deployed version before
  and after the upload on every exit code. When the version did not move, it stops with "NOTHING WAS
  DEPLOYED", says to answer yes to the script API question (the binding reconcile has already carried the
  sources the console attached into the upload, so continuing keeps them), and says re-running is safe.

- Two members of the deploy preflight could fail on a busy machine with no defect in the code.
  `test/validate-azure-blob.ts` required two unpaced writes to finish inside 25 ms of wall clock, and
  `test/validate-verify-at-seal.ts` waited one event-loop turn for a record written in the background. The first
  now counts the waits the pacer asks for, and the second waits for the record itself, with a bound.

- A downpipe that names the deploy-time destination (`deploy`) keeps its backups when the stored `deploy`
  row is gone. The singular clear (`POST /admin/destination` with `{"config": null}`) removes that row when
  `deploy` is the default, a downpipe can name `deploy` after that, and an estate can hold the state from an
  engine whose singular clear did not check the downpipes that name the default. Such a downpipe was
  refused as `not-configured` on the seal, replication and scheduled-drill paths while `DEST_R2` or the
  `DEST_*` variables were set, and the support pack counted it in `danglingDestinationRefs`. `deploy` now
  resolves to the deploy-time destination with or without its stored row, and is refused only as
  `deploy-binding-missing`, when the deployment has no `DEST_R2` binding and no `DEST_*` variables. The
  support pack's dangling count follows the same rule.
- `POST /admin/destination` with a destination config is refused while the default is the deploy-time
  destination (`deploy`). The set stored the new bucket under the reserved id `deploy`, so a default-routed
  downpipe sealed to the new bucket and recorded `deploy`, every read by that id (restore, drill,
  replication, prune) went to the `DEST_R2` bucket, and a downpipe that names `deploy` kept sealing to the
  `DEST_R2` bucket. The refusal is a 400 that names the two steps to take instead: add the bucket as a
  destination, then make it the default. It also holds while no destination is stored and the env
  destination is the default. The singular clear (`{"config": null}`) now runs the in-use check of a
  destination removal on the default: while a downpipe names the default, it is refused with the same text.
  `POST /admin/drill-all` reads only a JSON object: `{}` drills every downpipe and `{"downpipeIds": [...]}`
  drills those downpipes. A missing, unparseable or non-object body is refused with a 400
  `fleet-drill-body-invalid`, and an empty or non-list `downpipeIds` with a 400
  `fleet-drill-selection-invalid`. Before, the route read a body it could not parse as `{}` and drilled
  every downpipe. A refused request starts nothing and is counted in the support pack's config-rejection
  ledger (surface `fleet-drill`).
- A D1 backup no longer fails when a BLOB column holds a byte from 0x80 to 0x9F. The BLOB encoder built
  the string for `btoa` with `TextDecoder("latin1")`. Under the WHATWG Encoding standard that label means
  windows-1252, which maps 27 of those bytes to code points above U+00FF, so `btoa` threw and the whole D1
  backup failed on every retry. A random 32-byte value holds such a byte about 97% of the time, so a table
  of hashes, binary UUIDs or ciphertext could not be backed up at all. The encoder now builds the string
  one code unit per byte. HTTP Basic credentials (the ServiceNow channel, and OAuth 2.0 and OIDC
  `client_secret_basic`) no longer use `btoa` over the joined text, which threw on a password or client
  secret holding a character above U+00FF. They are now the base64 of the UTF-8 bytes, which is unchanged
  for ASCII text.
- The Security Centre no longer reports "No archive destination is configured" as a critical failure on an
  estate whose destination was set in the console. The posture slice (`statusSliceForPosture`) and the
  immutability report called `buildStatus(env, 0)`, which sees only a deploy-time destination in env, while
  `/admin/status` also passed the console-set destination. Every estate set up through the Focus Flow sets
  its destination in the console, so each one scored a false critical beside "You are protected", and the
  signed immutability report said no destination was configured. Both now read the default destination from
  the stored collection, as `/admin/status` does.
- A D1 capture defect is now recorded by its type, so a BLOB the engine cannot encode is named. The D1
  defect classifier matched the error message against patterns, and the `btoa` exception says "Invalid
  character", which matched none of them. So the BLOB failure left the run row, the logs and the
  support pack saying only "run failed". Every D1 refusal is now a `D1DefectError` that carries its closed
  class, and the classifier reads that class, never the message. A BLOB encoding refusal has its own
  class, `blob-encode`, which the support pack's `sourceFaults.d1Defects` carries with the table handle,
  and its run row reads "source read error".
- A strict break-glass-only re-key now leaves the engine holding no key that can decrypt a run. A re-key
  from the Keys screen that omits the operational pair (`POST /admin/keys/install` with no operational
  keys) did not delete an existing `OPERATIONAL_PUBLIC` or `OPERATIONAL_PRIVATE`, and it set no
  `OPERATIONAL_RETIRED` marker. Every seal read `OPERATIONAL_PUBLIC`, so runs sealed after the strict re-key
  still carried the old operational recipient, and the engine still held the private key that opens them.
  The strict install now runs the same removal as the break-glass-only switch
  (`POST /admin/keys/break-glass-only`): it sets the marker, then deletes `OPERATIONAL_PRIVATE`, then
  `OPERATIONAL_PUBLIC`. A delete of a secret that is not set is a success. A removal leaves an
  `operational-removed` audit row, and a failed one a `key-removal-failed` row that names the step.
  The engine also honours the marker over a pair that is still set. While `OPERATIONAL_RETIRED` is set,
  every seal (the sliced and buffered runs, and the canary) wraps to the break-glass recipient alone, and
  verify-at-seal, the canary read-back, drills, scheduled restore tests, in-console restores and retention
  pruning do not use `OPERATIONAL_PRIVATE`. The recipients preflight and the recipient pin in the sealed
  configuration export follow the same set. `GET /admin/status` reports `operationalRetired`, the support
  pack's `keys.operationalRetired` reports `markerSet` and `staleKeyHeld`, and a new high-severity posture
  check, `operational-retired-key-held`, fails while an operational secret is still set beside the marker.
  Adding an operational key (`POST /admin/keys/add-operational`, an install with the pair, or
  `npm run deploy -- --enable-operational`) now deletes the marker before it sets the pair, and a marker that
  cannot be deleted fails the add with nothing set.
  **If you re-keyed with break-glass-only on an engine that held an operational key**, the old private key is
  still in your Cloudflare account. That re-key set no marker, so after the upgrade the engine still reads
  the pair as your operational key and seals runs to it, and `operational-retired-key-held` does not fail.
  Run the switch to break-glass only once (Keys screen, Posture tab, or `POST /admin/keys/break-glass-only`)
  to set the marker and delete the pair. Runs sealed while it was in use also carry your break-glass
  recipient, so `identity.key` still opens them.

- `GET /admin/status.artefactSha384` on an engine installed with `npm run deploy` is the SHA-384 of the
  main module Cloudflare serves. `scripts/deploy.sh` hashed a `wrangler deploy --dry-run` bundle that held
  the placeholder, wrote the digest into `src/format/build-stamp.ts`, and then ran `wrangler deploy`, which
  bundled the source again with the digest in place of the placeholder. The uploaded file was 81 bytes longer
  than the hashed one, so the reported hash could not match the served bytes. `npm run deploy` now builds the
  bundle once (`scripts/build-deploy-bundle.mjs`), hashes that file, uploads the same file with
  `wrangler deploy --no-bundle`, and records the hash as the plain-text binding `DEPLOYED_ARTEFACT_SHA384`.
  The update-channel apply sets that binding to the hash of the bytes it uploads, so a carried-forward value
  never names earlier bytes. Status adds `artefactSha384Source` (`operator`, `deployed` or `build-stamp`),
  and `docs/OPERATIONS.md` says what each source is.
- The dry-run preview of a two-component update no longer reports the console as refused when the console's
  engine floor is the engine version the same apply installs. The preview judged the console against the
  running engine, while the live apply promotes the engine first and applies the console at settle, when the
  running engine is the new one. The preview now judges the console against the engine the apply installs,
  and its console row reads "the console component applies after the engine reaches" that version. A floor
  above that version is still refused, and the reason names the engine the update installs. A live apply is
  unchanged.
- `tools/publish-channel.mjs` refuses to sign a channel whose console component has no risk class. It read
  the console's class only from `--console-risk-class`, and an absent value reached the engine as nothing,
  which `normaliseRiskClass` reads as `migration`, so a routine console release asked for a second Owner's
  approval on every apply. The tool now also reads `console.riskClass` from `--meta-file`, as it does the
  engine's `riskClass`, and when neither gives a class it stops before signing and names both ways to set
  one.

- A destination with a fractional cost rate no longer stops the control-plane recovery
  export. What broke: the console saves a destination's cost rates on the destination, and R2's Class A
  rate is 4.5 per million. The export copies the rates into a signed object, and a signed object holds
  integers only, so `canonicalJSON` refused the whole export with "non-integer number 4.5 is not allowed
  in a signed object". The export pass threw on every 15-minute tick and never wrote a recovery artefact
  (an estate with integer rates or no rates was not affected). The console's export download failed
  the same way. The fix: a rate that is a safe integer is exported as a JSON number, as before, and any
  other rate as its shortest round-trip decimal string (`"4.5"`), which the import reads back as exactly
  the saved value. Each value has one form, so every export an earlier engine wrote (integer rates only)
  has the same bytes and imports unchanged, and the export layout stays `v: 1`. A rate string in any other
  form is refused as a pricing drop. The archive format and the reader are unchanged: the reader's
  `unseal-export` writes the export body out as bytes and does not parse it. Three more inputs could put an
  integer past 2^53 - 1 into the same export and are now refused or dropped at write time: a downpipe's
  `cadenceSeconds` and `restoreTestCadenceSeconds`, an STS `durationSeconds` and a WORM `retentionDays`.
  The failure is now loud: a pass that throws records a closed class, `unsignable` (a value the signed export
  cannot carry) or `pass-fault` (any other throw), as the export-health `skipped` reason (the support
  pack's recovery section) and as `cpExport.passFaultByClass` in the pack's cron health, and the
  environment-self-backup posture check fails and names it.
- The deploy-time destination (`deploy`, the destination the console lists as
  "Deploy-time destination" once a second destination is added) is a destination like any other on every
  path that reads a downpipe's `destinationIds`. A downpipe with `["deploy", "<console destination>"]`
  seals to `deploy` first and fails over to the next destination only when `deploy` refuses a write. The
  replication pass copies to `deploy`, reports it `ok` with a real `holdsIndex`, and copies the runs
  sealed there to the other destinations. The scheduled drill, both retention prunes and the orphan
  reconcile serve a downpipe whose first destination is `deploy`. A restore of a run whose copy is on
  `deploy` is not reported as sitting on a removed destination. After the upgrade, the replication pass
  catches each destination up on the runs it is missing, back to the oldest run the run history holds
  (50 per downpipe). When a downpipe names `deploy` and the deployment has no `DEST_R2` binding and no
  `DEST_*` variables, each path refuses with the reason `deploy-binding-missing` (in the replication row,
  the seal-fault ring, the pre-run seal error class and the retention and reconcile skip codes), not
  `not-configured`, which keeps its meaning: the id names no destination. A canary, a destination verify
  (`POST /admin/destination/verify?id=`) and the control-plane export aimed at an id that names no
  destination now answer that refusal, and do not use the deploy-time destination in its place.
  `resolveDestination` is now the one resolver for a destination id.
- A drill of a run that holds no records records no row in the support pack's
  `restoreFaults` ring. The drill opens and verifies that run and reports it as a deferral
  (`nothingToVerify`), and the scheduled restore test records it as deferred (`no-records`), so the
  ring holds only drills that failed. A drill that cannot open a run (a missing root manifest, a bad
  signature, a missing object) still records its row. The pack's `downpipes[]` row now carries
  `lastRestoreTestDeferred` (`no-run`, `posture` or `no-records`) beside `lastRestoreTestOk`, so a
  deferral does not read as a failed restore test. On 0.3.5, a `restoreFaults` row of
  `{op: "drill", phase: "open", cls: "other"}` for a downpipe whose last run has `recordCount: 0` is
  this deferral, not a fault.
- A D1 table declared `WITHOUT ROWID` now pages by its `PRIMARY KEY`, with the same page size bound as a
  rowid table, and a run can resume in the middle of it. Before, such a table was read in one page, and a
  table larger than the page bound failed the run. The engine takes the table kind from the table's
  `CREATE TABLE` text. A key cursor over 4 KiB is not written to a checkpoint, so a run cannot stop after
  that page. A table whose key cannot be read is still read in one page.
- A D1 table resumed in a later slice now continues its page numbering. Before, the resumed slice sealed
  row pages under names an earlier slice had already used, and the offline reader reported a name
  collision.
- The `dest-cred-encryption` posture check and the `CONFIG_WRAP_KEY` unwrap error say that the wrap key is
  a Worker secret on your engine. They said it was held in your Secrets Store.

- The streamed segment seal now applies backpressure. It seals the next 64 KiB chunk only when the
  destination write reads the previous one, so the seal stream's queue holds one sealed part. Before,
  the seal ran ahead of the write, and a slow destination let sealed chunks queue in memory, up to the
  whole segment. The destination's own write buffer is unchanged: the S3-compatible destination
  buffers up to 32 MiB, and the Azure Blob destination buffers one 8 MiB block. A cancelled write now
  also stops the seal and closes the source. The sealed bytes are unchanged.

- An Azure Blob container with version-level immutability no longer reads as a lock with no default
  retention rule. The engine cannot read an Azure default retention policy with a key or a SAS, but
  the verify probe took the unread rule as no rule. The verify response, the support pack, the
  immutability posture check and the immutability report then said that nothing retained the
  archives, also for a container whose default policy does retain them. They now say that the rule
  was not read.

- The Azure Blob destination now refuses a streamed segment over the 1 GiB single-segment ceiling
  before it sends a request, as the S3 and R2 destinations do. Before, it staged and committed the
  segment. The refusal is recorded as `segment-over-limit` in the destination fault snapshot on the
  run row, which the Azure Blob destination now reports.

- An Azure Blob endpoint in `DEST_ENDPOINT` now builds the Azure Blob client, as a console-set Azure
  destination does. Before, the `DEST_*` vars always built the S3 client, so an Azure Blob endpoint
  failed with 403 on the first request, while the status surface reported the destination as Azure.
  `DEST_ACCESS_KEY_ID` is the storage account (empty means the account in the host),
  `DEST_SECRET_ACCESS_KEY` is an account key or a shared access signature, and `DEST_REGION` is not
  necessary. An Azure Data Lake Storage Gen2 `dfs` endpoint in `DEST_ENDPOINT` is now refused when the
  engine builds the destination, with the new build cause `endpoint-unusable` and the same remedy the
  console gives.
- An Access admin can now record the offboarding attestation. `POST /admin/audit/intent` gates each
  marker on its own capability: `access-policy-change-intent` needs `roles.write`, which the Owner and the
  Access admin hold, and `key-ceremony-intent` still needs `keys.ceremony` (Owner only). Before this, both
  markers needed `keys.ceremony`. The console offers the "I have removed this person" box to every
  `roles.write` holder, so an Access admin who ticked it was refused and the attestation was not recorded.
  A body that is not a JSON object now gets a 400. Before this, it got a 500.
- The canary now flies at the interval you set. The next flight counted from the end of the previous
  flight, and the canary flies only from the 15-minute cron tick, so the flight waited one more tick: the
  default 60-minute interval flew every 75 minutes. The next flight now counts whole ticks from the tick
  that flew the previous one, however late in that tick the flight started, so a 60-minute canary flies on
  the same quarter hour every hour. A save of the canary settings (the cadence, the destinations or an
  enable) also counts from that tick, not from the save: a save just after a tick made the next flight wait
  one more tick. If the new mark has already passed, the next tick flies. An interval that is not a
  multiple of 15 minutes flies on the tick nearest the end of the interval, so an interval shorter than 15
  minutes flies on every tick. `test/validate-cov-sched-scheduler-do-canary.ts` holds it.

- A canary flight is now dead, not ailing, when the RUNLOG signature on its own new cell does not verify.
  The reader files a bad RUNLOG signature as a check that could not run, because for a restore a replica
  signs its own RUNLOG. The canary reads a RUNLOG it signed seconds before, so a bad signature there means
  the bytes changed at the destination. An absent or unreadable RUNLOG stays ailing.

- An edit of an auto-observed credential registry item no longer turns it into a manual item.
  `POST /admin/expiry` for an id the engine observed now changes only the purpose and the note. The engine
  keeps the source, the label, the kind, the expiry, the lifecycle class and the observation fields
  (`observedAt`, `tokenRef`, `usageLink`, `permissionSummary`, `usedAt` and `cleanupState`). Before, one
  save from the console form wrote source `manual` and dropped those fields, so a spent attach token that
  was pending cleanup stopped being pending. A request that asks to change the kind, the expiry (a
  different day, or `noExpiry` on a dated item) or the lifecycle class of an observed item is refused with
  400, because each observation writes those fields again. The same values sent back unchanged are
  accepted.
- `POST /admin/licence` no longer tells you to paste the licence token from your activation email when a
  paste does not have the shape of a token. No downpipes email carries a token. The activation and renewal
  emails carry a claim code. The 400 now says what a token looks like, and tells you to enter the claim code
  in the Claim code field. The scheduler's own shape check before it stores a token gives the same reason.

- The refusal when you turn on "Require a second approver for restores" with only one Owner no longer
  tells you to appoint a second Owner or Approver. The check counts Owners only, so an Approver did not
  lift the refusal. The sentence now says that the check counts Owners only and tells you to appoint a
  second Owner.
- `GET /admin/audit/verify` no longer reports `headAnchorUnreadable` for an audit log with no entries.
  A log with no entries stores an empty chain-head record, and the second verify read that record as
  damaged. The flag is still set when the chain-head record is damaged, and when the empty record is
  present over retained entries.
- A digest rule no longer batches a `restore-applied` notification for a restore that fell short. The
  engine raises that notification to warning severity, but digest eligibility read only the event, so a
  daily or weekly digest rule held it until the next flush. A success-class event is now digested only when
  its severity is info, and a warning is sent at once on every rule that selects it.

- A backup that recovers while the Worker cron is down now gets its auto-resolve. The cron dead-man sweep
  found the recovery and cleared the alert cooldown, but it cannot deliver, so it discarded the resolve and a
  PagerDuty, Jira Service Management or ServiceNow incident stayed open. The sweep now writes the same
  pending-recovery marker a failed delivery writes, and re-arms it on each sweep, so the cron sends the
  resolve when it resumes.

- A request body of JSON `null` to `POST /admin/idp/connections`, `/delete`, `/enabled`, `/cert`,
  `/admin/idp/test` or `/admin/idp/test-saved` now gets a 400. Before, the route read a field of the null
  body and the request failed with a 500.
- The Workers source now refuses a script body over the 128 MiB size limit before it holds the whole body.
  A `Content-Length` over the limit is refused with no body read. A body with no length is refused as soon
  as the bytes pass the limit, so the engine holds at most the limit and the chunk it is reading. Before
  this, the engine read the whole body and then checked its size. The script is still marked unavailable with the same
  size-limit reason. A body with a `Content-Length` within the limit is read into one buffer of that size.
- The release channel carries `rekorLogIndex` again for a release signed with cosign v3. The publish tool now
  also reads the index from the Sigstore bundle form that cosign v3 writes
  (`verificationMaterial.tlogEntries[0].logIndex`). Before this, a v3-signed release gave a channel with no
  index, and the console did not show its Transparency log (Rekor) row.
- The licence account check (`accountClaimMatchesEngine`) now works on an engine without `CF_ACCOUNT_ID`.
  When that variable is not set, the engine uses the Cloudflare account it verified and recorded on its
  first successful attach or update-apply, which is the same account `GET /admin/status` reports as
  `cfAccountId`. No deploy path sets `CF_ACCOUNT_ID`, so before this the check did not run on a standard
  deployment and a licence bound to a different account was not flagged. It applies to the stored console
  token, the deploy token and the verify in `POST /admin/licence`. The check still does not block anything.
- The preflight email-sending remediation now points to **Send a test email** in Settings, Email delivery.
  It named "Settings, Support", which the console does not have.
- The recovery sheet that `npm run deploy` prints now lists the configuration recovery key pair under
  "Went to your engine". The deploy always installed it, in both postures, but the sheet did not name it.
- A scheduled run that falls due just before a maintenance blackout window no longer starts inside it.
  Dispatch rides the fifteen-minute tick, so a run due at 01:55 before a 02:00 window used to start on the
  02:00 tick. The scheduler now checks the windows again when it dispatches, and moves a run that would
  start inside a window to the end of that window. This also holds a run whose window was added after its
  next run time was set. The scheduler moves a run in this way at most once for each due time, and only when
  the end of the windows is a time outside all of them. If no tick falls outside the windows, the run starts
  on the first tick at or after its new time, even inside a window. A window set that no deferral can leave, for
  example a full-day window, starts the run on time as before.
- A validly signed `_RECOVERY/RUNLOG` with a line that does not parse now gives an unchecked freshness
  result, as the offline reader does. A verified open then refuses with the `freshness-unverifiable`
  category, so a restore can try a replica whose RUNLOG verifies. Before this, the parse error escaped as an
  untyped error, and the restore classified it by its message, which did not give the replica fallback.
  A `_RECOVERY/RUNLOG.sig` whose text does not decode now gets the same result as a signature that does not
  verify, for the same reason. Before this, the decode error also escaped as an untyped error.
- An AWS S3 destination whose bucket has an Object Lock default retention rule can now be added and
  written to. AWS refuses every write into such a bucket that carries neither `Content-MD5` nor an
  `x-amz-checksum-*` header, and the engine sent `x-amz-checksum-sha256` only for a destination with its
  own immutability policy. So the save-time probe failed with `PUT _RECOVERY/.write-probe: status 400
  (InvalidRequest: object lock write requires a checksum)`, and run writes from a destination without a
  policy were refused the same way. When AWS answers a write that sent no checksum with that refusal, the
  engine now sends the write again once with `x-amz-checksum-sha256`, signed, and every later write from
  the same destination instance carries it from the start. A multipart upload is then created with
  `x-amz-checksum-algorithm: SHA256`, each part carries its own checksum, and the completion names them;
  when AWS refuses the first part of an upload created without one, that upload is aborted and a
  checksummed one takes its place. When the save-time probe learns the fact, the destination record keeps
  it as `checksumRequired`, so each new destination instance (per slice, probe, canary cycle and SIEM push)
  sends the checksum from its first write. Each refused write that teaches it is counted as
  `dest-io-checksum-retry` in the support pack. Other stores receive the header only when the destination
  has its own immutability policy or the store sends AWS's refusal, because the engine does not rely on
  how a store treats a header it did not ask for.

- The console key install (`POST /admin/keys/install`) now installs `CONFIG_RECIPIENT_PUBLIC`,
  `CONFIG_RECIPIENT_PRIVATE` and `CONFIG_WRAP_KEY`, as the terminal deploy does. A console-keyed engine
  had none of them, so its sealed configuration export was sealed to the break-glass key only, auto-heal
  refused, and console-stored credentials were not wrapped at rest. The engine checks that the recovery
  private matches its public before it writes anything, and keeps a configuration key it already holds.

- A strict break-glass-only choice made in the console's key ceremony now survives the next
  `npm run deploy`. The ceremony records it with the `OPERATIONAL_RETIRED` marker, and a deploy that finds
  keys but no operational key now asks (or, with no terminal, keeps break-glass-only) instead of installing a
  key that can read your archives.
- The signed evidence pack no longer names R2 bucket locks as meeting Essential Eight ML3 admin
  immutability, SEC 17a-4(f)(2)(i)(B) or ISM-1708. The engine can neither set nor read an R2 bucket lock.
  Those three rows now name compliance mode as the setting that binds a backup administrator.
- The immutability posture check and the signed immutability report no longer say a compromised
  credential cannot delete an archive when the lock is in governance mode. In governance mode they name
  the bypass permission that can lift the lock, and the check recommends compliance mode.
- The signed evidence pack no longer states conditional controls as standing facts. Dual control is
  described as it works: always on for a prune applied from the console, optional and off by default for a
  restore and for arming the scheduled prune. Off-account copies and immutability depend on the destination
  and lock you choose. Rollback to an older signed run log is caught by the minimum-index pin from your
  recovery sheet. An identity with no grant resolves to Viewer. There are six roles, not four. SEC 17a-4 says
  that downpipes does not provide the audit-trail alternative. The CPS 230 rows cite the paragraph numbers
  of the version in force from 1 July 2026 (37(b), 33(c), 42-43 and 53(b)).
- The signed evidence pack no longer prints a pass from a check that cannot fail for the control. Storage
  limitation, deletion and CP-9(7) rows were evidenced by credential-expiry, audit-export-available or
  two-owners; they now carry no check. AU-9 is evidenced by off-account-audit-mirror.
- The seal-verification posture check now fails when `VERIFY_AT_SEAL` switches verify-at-seal off. It
  passed before, because a downpipe keeps its last clean verdict after the switch. The signed evidence
  packs bind this check to integrity verification on every run.
- The signed immutability report no longer states that every run is verified at seal and that the hourly
  canary proves the write path when either is switched off. It now reads both states, says when one is off
  or could not be read, and calls the canary hourly only at the hourly cadence.
- The signed evidence pack no longer prints the immutability check as a pass on a control row when no
  retention lock is in force. The posture check still passes when WORM is not configured, because WORM is
  opt-in, and the posture score is unchanged. In the pack that check now reads "not met", with the reason.
- The signed evidence pack no longer shows SEC 17a-4(f)(2)(i)(B), ISM-1708 or Essential Eight ML3 admin
  immutability as met under a governance-mode lock. Those rows need compliance mode, because a principal
  holding the bypass permission can lift a governance lock.
- The evidence pack now reads the lock on every destination an enabled downpipe writes to, not only the
  default destination. A downpipe that seals or replicates to an unlocked destination stops the pack
  showing retention as met.
- The signed evidence pack no longer counts the post-quantum hybrid encryption and audit-log export checks
  as passing evidence. Both pass in every deployment and cannot fail, so the pack now labels them "stated,
  cannot fail" and tallies them apart from the checks the platform observed.
- The immutability posture check now names the correct store's remedy on Azure, Google Cloud and R2 in a
  live posture read. The Durable Object dropped the destination's provider, so the check used the S3 wording.
- A retention prune that stops partway now finishes on a later pass. The leftovers of runs it already
  marked superseded are planned again, and a run's segments are deleted before the run tree that names them,
  so a later pass can still find them.
- On a versioned bucket, which every S3 Object Lock bucket is, a prune delete adds a delete marker and the
  bytes stay. The prune now counts those objects as hidden rather than reclaimed, and says the bytes stay until
  the bucket's noncurrent-version lifecycle rule or its lock releases them.
- A refused prune delete is called an Object Lock refusal only when the object's own lock headers say so. The
  prune continues past a refused object instead of stopping, a partial apply records what it actually did, and
  a scheduled pass that left planned work undone counts as failed rather than healthy.
- A scheduled retention prune that changed the archive now writes a retention-prune audit event, including one
  that stopped partway. A pass that changed nothing writes none, so a remainder held by a lock does not write a
  new event every tick. The attended prune now counts an audit write it lost.
- The Stream backup no longer writes to your Stream account. The MP4 capture created a download for each
  video, which the read-only discovery token cannot do, so every MP4 was recorded as unavailable. It now
  reads the download that already exists. A video with no download is recorded with an unavailable marker
  (reason `not-enabled`) that says to enable downloads for the video in Stream. A download that failed in
  Stream (reason `download-error`), or that is ready but has no url (reason `download-no-url`), is also
  recorded as unavailable, not pending, with a note to re-create the download in Stream.
- The export-recorded route stored no recipient-pin hash, so from engine 0.3.0 the change gate re-exported
  on every scheduled tick. Each tick wrote a new generation at the same configuration version, and the
  auto-heal then refused the bucket as `ambiguous`. The route now stores the hash, the health route
  stores the recipient-set drift, and an unchanged tick keeps the last write outcome.
- The export pass now removes the earlier generations at the configuration version it just wrote. It
  removes only a generation whose signature verifies under this engine's signer and whose account id is
  this engine's. A sibling from another signer or account, or one with no signature, stays, and the
  auto-heal keeps refusing that version. The backlog an earlier engine left clears over several ticks
  after the upgrade. A bucket lock that refuses the delete leaves it, and the auto-heal then refuses that
  version until a configuration change writes a higher one.
- A non-owner request to delete, enable, disable or roll over the certificates of an IdP connection now
  records an `idp-connection-change` event with outcome `denied`, as a refused create or test already did.
  Before, these three routes returned the 403 and wrote nothing to the audit log. The event carries the
  submitted connection id when it is a well-formed id, else `unknown`, and the op the request asked for.
  The gate refuses before the body is read, so the caller gets the 403 whatever the body holds, and the
  engine reads at most 64 KiB of a refused body. The event's `connKind` is not read from the stored
  connection: it is `saml` for a certificate rollover and `oidc` for the other two routes.
- `POST /admin/idp/test` now builds a preset form's proposal (`presetId` and `vars`) from its preset before
  it probes, as the create route does. Before, the pre-save Test connection on every OIDC and OAuth2 preset
  form reported the issuer or the OAuth2 endpoints as not set, because the console sends the preset values
  and not the built issuer. An unknown preset or an unfilled required value is one failed `Preset values`
  check, and the support pack records its class (`kind-unknown` or `not-set`). `POST /admin/idp/test-saved`
  is unchanged.
- The OAuth2 Test connection now also checks the email URL and each groups URL. A connection with no email
  URL fails the test, because the engine refuses a sign-in with no email and an OAuth2 connection reads the
  email only from that URL. Before, such a connection passed the test and every sign-in was refused.
- The `idp-connection-change` event for a SAML connection create now carries
  `target.emailVerifiedPolicy` (`require-flag` or `trust-idp`). The console's trust-idp warning says the
  choice is recorded in the audit log, and before this the event recorded only that the connection was
  created.
- A restore over a Secrets Store source no longer records a restore fault for each secret. A secret is
  restored out of band by design, and its skip reason starts with "Secrets Store value", which the fault
  filter did not match because it looked for a lowercase "secrets". Every dry run and apply over such a run
  put an `other` row in the support pack's `restoreFaults`. The filter now matches the out-of-band reason
  exactly, and a real fault in the same restore is still recorded.
  `test/validate-secrets-restore.ts` holds it.
- Replication now copies a run from any destination of its downpipe that holds it when the run's origin
  cannot supply it: the origin is removed, its RUNLOG will not read, or the run is not in it. Before, such a
  run was stranded on every destination that lacked it, and the destination's proven copy window stopped
  below it, so the downpipe's newer runs stayed in the destination removal count until the stranded run
  left the newest 50 runs of the downpipe. A destination added after the origin was removed received none
  of the origin's runs. The source must list the run as active in its own RUNLOG, and the copy is checked
  at the target as a copy from the origin is. A run that no destination holds is stranded, and recorded
  with the origin's fault, as before. `test/validate-repl-backfill-dest-removal.ts` holds it.

- Restores, drills and keyless attestations refuse a signed root whose `envelope` names another algorithm
  suite, chunk size or codec, as the Go reader does.
- A fanned-out seal no longer fails as "fan-out worker stalled (no progress)" when a duplicate range report
  arrives while another range reports.
- A config change that config approval queues no longer sends a `success` audit line to Workers Logs for
  its dry run, which never commits.
- The `authn-failure` audit row of a failed passkey sign-in records the `CF-Connecting-IP` address as
  `sourceIp`, as the SSO callback rows do.
- Destination removal refuses to drop the last proven copy of a run whose origin was removed. The singular
  clear (`{"config": null}`) runs the same check.
- The destination removal refusals count a run as copied when a destination holds that run above its
  contiguous window, not only inside the window.
- The `control-plane-reconciled` row that an Owner's estate import writes records the Owner's sign-in
  method in `actorMethod`, not `token`.
- `POST /admin/downpipes/cf-config/mode` writes a `downpipe-create` audit row, and config history records
  `cfConfigMode`, so an approver's diff shows a capture-mode change.
- A replication fault reads `runlog-corrupt` when the target RUNLOG fails its integrity check, and
  `copy-failed` when one object copy fails, not `unreachable`.

### Security

- A native sign-in (OIDC, OAuth2 or SAML) needs a grant: a role row, a pending invite for its verified email, or a mapped group.
- A native sign-in never claims the first Owner on an empty role table.
- A native sign-in session reaches only its own subject's sessions, and it ends when the grant that admitted it is removed.
- An email the identity provider does not mark as verified binds only a Viewer or operator invite.
- The engine refuses an email that contains ":" wherever it normalises one.
- A replayed IdP-initiated SAML assertion is refused for as long as the engine would accept it.
- A group-to-role mapping scoped to one identity provider is kept apart from a global mapping for the same group.
- While two or more Owners exist, removing an Owner's role needs a second Owner, and revoking all of an Owner's sign-in factors is refused.
- A SCIM deprovision of an Owner, while another Owner exists, demotes them to Viewer and ends their sessions.
- Dual control re-checks that the approver is still an Owner when an approved Owner action runs.
- Turning restore approval or update approval for every release on or off needs step-up. Turning it off needs a second Owner when one exists.
- An edit that lets the scheduled retention prune delete more needs `restore.apply`, and a second holder of `restore.approve` when one exists.
- A restore approval shows the write target and `onExisting` that the plan hash covers.
- `POST /admin/roles` sends the registration link for a member who enrolled before to that member's address, not in the response.
- A session exchanged from the break-glass `ADMIN_TOKEN` ends when that secret is deleted or rotated.
- Failed sign-ins and refused requests fold into counted audit rows with an hourly ceiling, so they cannot push real rows off the 10,000-row cap.
- The S3-compatible destination endpoint, `BEACON_URL` and the OIDC discovery, JWKS and token calls pass the send-time DNS resolve screen.
- The syslog-over-TLS SIEM sink resolves its host name before it connects, and refuses a private, loopback or link-local address.
- The five control-plane import and restore routes apply the per-caller rate limit.
- Each vendor pull of the diagnostics bundle writes an audit row.
- In-console restore, the drills, and the verify and attest proofs refuse a destination whose RUNLOG was put back to an older signed copy.
- A Cloudflare config restore into a different zone needs the target zone id echoed, even when it is limited to some surfaces.
- The credential registry refuses a control character in an item's label.
- The support pack names a record by its index and keyed name MAC, never by its name or a plain hash of its name.
- `GET /admin/status` and the support pack report the update-signer fingerprint, and check a declared `RELEASE_SIGNER_PIN` against it.

- Each OIDC and OAuth2 call on the sign-in path (discovery, JWKS, token, profile, email and groups) stops after 10 seconds.
- The recovery sign-in and the passkey sign-in and enrolment routes refuse a body over 64 KiB with 413 `body_too_large`.
- The SAML ACS POST reads no more than 512 KiB of a body, and a larger body fails the sign-in.
- A Google connection with `hdDomain` refuses a sign-in whose `hd` claim is absent or different, even when the verified email is in that domain.
- Preflight destination evidence in the support bundle no longer carries a console-set endpoint or bucket, or the host name of any endpoint.
- An OIDC or OAuth2 sign-in ends the session the browser presented, also when the provider sends no `iss` callback parameter.
- A restore target that is not an object, or whose `binding`, `namespaceId` or `bucketName` is present but not a non-empty string, is refused with 400.
- The OTLP push stops reading a collector's response after 16 KiB, and refuses a larger declared `Content-Length` before it reads.

### Dependencies

- `typescript` is 7.0.2 and supplies every `tsc` run. The `typescript-7` alias package is gone. The
  compiler-API gates import `@typescript/typescript6` 6.0.2, because the 7.x line ships no JavaScript
  compiler API. `npm run lint:circular` loads `scripts/madge-ts6-resolve.mjs`, which gives madge's
  TypeScript parser the 6.x API; the module graph madge reads for `src` is byte-identical to the one the
  6.x compiler gave it.
- @cloudflare/workers-types 5.20260928.1 (from 5.20260914.1) and @types/node 26.6.3 (from 26.6.1).
- wrangler 4.140.0 (from 4.134.0), with Miniflare 5.20260923.0-alpha and workerd 1.20260923.1.
- @vitest/coverage-istanbul 4.1.11 (from 4.1.9).
- @stryker-mutator/core 10.0.0 (from 9.6.1).
- fast-check 4.10.2 (from 4.10.1) and knip 6.38.0 (from 6.36.0).
- The release workflow pins cosign 3.1.3 (`cosign-release`), so the cosign-installer default cannot
  change the signing tool between releases.

## [0.3.5] - 2026-09-21

This release includes the 0.3.4 changes.

### Changed

- The first public CI run is green on a standalone clone: the cross-repository checks that need a
  sibling repository now check out the public downpipe at its release tag or state that they skipped.
- Dead compatibility re-exports removed from the admin, scheduler, destination and seal modules;
  every consumer already imported the real definition.

### Dependencies

- Runtime harness on Miniflare 5 (wrangler 4.134, @cloudflare/vitest-pool-workers 0.22),
  with the workers-shaped options the new Miniflare requires.
- TypeScript 7.0.2 compiles the engine (as the `typescript-7` package); TypeScript 6 stays
  installed under its own name for the tools that still need the JavaScript compiler API.
- @types/node 26.6.1, c8 12, fast-check 4.10.1.
- @noble/hashes 2.4.0 and @noble/post-quantum 0.7.1.
- @cloudflare/workers-types 5.20260914.
- Biome 2.5.14, with the diagnostics the new release adds cleared at their sites.
- knip 6.36.
- GitHub Actions pins: step-security/harden-runner 2.21.1, actions/checkout 7.0.1,
  actions/setup-node 7.0.0, actions/upload-artifact 7.0.1, actions/download-artifact 8.0.1,
  ossf/scorecard-action 2.4.4, github/codeql-action 4.38.0.

## [0.3.4] - 2026-09-17

### Changed

- The syslog-over-TLS audit-export sink now refuses a private, loopback or link-local
  host, at the point the destination is saved and again before it opens a socket. The
  engine runs at the Cloudflare edge and has no route into a private network, so a
  SIEM on a private address was never reachable through this sink; the attempt is now
  a named non-delivery in the push trail rather than an unscreened connection.
- A backup destination endpoint that resolves to a private, loopback or link-local
  address is refused wherever it was stored, and every request the destination client
  makes is screened against the host it is about to reach.
- A `DEST_ENDPOINT` of `http://localhost`, `http://127.0.0.1` or `http://[::1]` is no
  longer accepted. It was the local test-emulator allowance and it applied to deployed
  configurations too, where it would have sent the destination credential in cleartext.

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

- No engine behaviour changes. This release pairs the engine with console 0.1.6.

## [0.1.5] - 2026-07-03

### Changed

- Update judgement and reporting: a canary flight that
  cannot complete in the moments after a deploy swap is retried and then handed to a
  CRITICAL-only self-check (the durable-object round-trip), never read as a regression;
  only a dead canary rolls back immediately. A self-check keep is confirmed in the
  background by the hourly canary. A live apply with no destination configured refuses
  before any deploy. An engine rollback that would drop below what the live console
  requires becomes a paired rollback. Every settled outcome is persisted before any
  rollback deploy and reported as it happened.

## [0.1.4] - 2026-07-03

### Changed

- No engine behaviour changes. This release pairs the engine with console 0.1.4.

## [0.1.3] - 2026-07-03

### Added

- Multi-component updates: the signed channel now carries a per-component map, and a
  release can ship the console (a static-assets component) alongside the engine. The
  engine applies itself first and must settle before the console component applies;
  failures report the actual partial state and the console rolls back independently.
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
  target and completes the plan; a live apply still refuses, before any
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
  reprovision by restore tier), re-applied out of band by an operator.

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

[0.3.8]: https://github.com/downpipes-io/engine/releases/tag/v0.3.8
[0.3.7]: https://github.com/downpipes-io/engine/releases/tag/v0.3.7
[0.3.5]: https://github.com/downpipes-io/engine/releases/tag/v0.3.5
[0.3.4]: https://github.com/downpipes-io/engine/releases/tag/v0.3.4
[0.3.3]: https://github.com/downpipes-io/engine/releases/tag/v0.3.3
[0.3.2]: https://github.com/downpipes-io/engine/releases/tag/v0.3.2
[0.3.1]: https://github.com/downpipes-io/engine/releases/tag/v0.3.1
[0.3.0]: https://github.com/downpipes-io/engine/releases/tag/v0.3.0
[0.1.0]: https://github.com/downpipes-io/engine/releases/tag/v0.1.0
