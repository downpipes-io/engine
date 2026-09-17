# Input Validation and Operating Limits

This document defines the input-validation rules and the operating limits the downpipes engine
enforces. Each rule states the accepting pattern, the bounds and the exact refusal message, with a
citation into the engine source. A rule without a citation is not listed.

Every console-entered field has its own row in the field catalogue
(accepted values, client and server validators, cross-field impacts, documentation link).
This document covers the inputs that reach the engine
without a console field: Access JWT claims, group lists, API bodies for roles, approvals and drill
evidence, webhook URLs, and the rate-limit envelope. The two documents together are the
validation reference for the platform. The vendor-side limits (the control plane's per-IP and
per-operator ceilings) are in `control-plane/SECURITY.md`, section "Rate limiting and
anti-automation".

## How to read a citation

A citation has the form `` `symbol` at `path:line` `` or `` `symbol` at `path:first-last` ``. The
path is relative to the engine repository root. The symbol is the identifier, literal or message
that the cited line carries. A value citation has the form `` `NAME` = `value` at `path:line` ``,
and the value is the literal as it appears in the source. The gate
`test/validate-limits-doc-citations.ts` opens every cited line and refuses the document when the
symbol or the value is not on it, and refuses it again when a limit constant in `src/` is not named
here. The document is therefore the pin, and the gate is what keeps it true.

The scheduler Durable Object (`SchedulerDO`) is the authority for most rules. Every write goes
through it, and it validates inputs independently of any router gate.

---

## Summary of limits

Scope says who a limit binds: one signed-in identity (per subject), one source address (per IP),
one email address (per email), one ingest client id (per ingest client id), one downpipe, one
destination (per destination), one webhook delivery (per delivery), one fleet-drill campaign
(per campaign), one request with no narrower key (per request), or the whole account
(account-global). A scope written as "account-global, per request" or "account-global, per
campaign" binds the whole account, and is checked one request or one campaign at a time.

| Limit | Value | Scope | Where enforced |
|-------|-------|-------|----------------|
| Mutating admin requests per window | 120 per 60 s | per subject (one shared `token` bucket for the bare-token break-glass) | `RATE_LIMIT_MAX_PER_WINDOW` at `src/sched/scheduler-do-limits.ts:650` |
| Unauthenticated `/admin/auth/*` ceremony requests | 30 per 60 s | per IP | `AUTH_RATE_LIMIT_MAX_PER_WINDOW` at `src/sched/scheduler-do-limits.ts:664` |
| Bare `ADMIN_TOKEN` compares | 10 per 60 s | per IP | `ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW` at `src/sched/scheduler-do-limits.ts:673` |
| Recovery-code attempts | 5 per 60 s | per IP | `RECOVERY_RATE_MAX_PER_IP` at `src/sched/scheduler-do-limits.ts:733` |
| Recovery-code attempts | 5 per 60 s | per email | `RECOVERY_RATE_MAX_PER_EMAIL` at `src/sched/scheduler-do-limits.ts:734` |
| Audit-feed pulls | 120 per 60 s | per ingest client id | `INGEST_PULL_RATE_LIMIT_MAX_PER_WINDOW` at `src/admin/support-ingest.ts:226` |
| Downpipes per bulk create | 100 (10 while config approval is on) | account-global, per request | `BULK_DOWNPIPES_MAX` at `src/sched/config-validate.ts:97` |
| Run cadence floor | 60 s | per downpipe | `cadenceSeconds` at `src/sched/config-validate.ts:162` |
| Destinations per downpipe | 20 | per downpipe | `MAX_DESTINATIONS_PER_DOWNPIPE` at `src/sched/config-validate.ts:87` |
| Secrets per secrets source | 5000 | per downpipe | `MAX_SECRETS_PER_SOURCE` at `src/sched/config-validate.ts:81` |
| Blackout windows per schedule | 32 | per downpipe | `SCHEDULE_MAX_BLACKOUT_WINDOWS` at `src/sched/schedule-window.ts:21` |
| Retention keepRuns | 1 to 10000 | per downpipe | `RETENTION_MAX_KEEP_RUNS` at `src/sched/config-validate.ts:111` |
| Retention keepDays | 1 to 36500 | per downpipe | `RETENTION_MAX_KEEP_DAYS` at `src/sched/config-validate.ts:112` |
| Groups carried from one token | 200 | per subject | `GROUPS_MAX` at `src/admin/groups-bounds.ts:9` |
| Group name length | 256 | per subject | `GROUP_NAME_MAX` at `src/admin/groups-bounds.ts:14` |
| Restore reason length | 1000 | per request | `REASON_MAX_LEN` at `src/sched/scheduler-do-records.ts:368` |
| Drill-evidence note length | 1000 | per request | `NOTE_MAX_LEN` at `src/sched/scheduler-do-records.ts:369` |
| Restore approval lifetime | 24 h | per request | `APPROVAL_TTL_MS` at `src/admin/approvals.ts:142` |
| Prune approval lifetime | 24 h | per request | `PRUNE_APPROVAL_TTL_MS` at `src/admin/prune-approvals.ts:84` |
| Dry-run preview rows | 50 | per request | `SAMPLE_CAP` at `src/admin/restore-sinks.ts:139` |
| In-account restore records | 200 | per request | `MAX_IN_ACCOUNT_RESTORE_RECORDS` at `src/admin/restore-sinks.ts:149` |
| Run-history ring | 50 runs | per downpipe | `RING_CAP` at `src/sched/scheduler-do-limits.ts:740` |
| Audit chain entries retained | 10000 | account-global | `AUDIT_CAP` at `src/admin/audit.ts:93` |
| Audit page size | 500 | per request | `AUDIT_PAGE_MAX` at `src/admin/audit.ts:269` |
| Drill-evidence rows retained | 500 | account-global | `DRILL_EVIDENCE_CAP` at `src/sched/scheduler-do-records.ts:320` |
| Config-history versions retained | 2000 | account-global | `CONFIG_HISTORY_CAP` at `src/admin/config-history.ts:70` |
| Downpipes per fleet drill | 5000 | account-global, per campaign | `FLEET_DRILL_MAX` at `src/sched/scheduler-do-limits.ts:751` |
| Change number length | 64 | per request | `CHANGE_NUMBER_MAX` at `src/admin/change-ref.ts:37` |
| Change reason length | 500 | per request | `CHANGE_REASON_MAX` at `src/admin/change-ref.ts:38` |
| STS session duration | 900 to 43200 s | per destination | `STS_DURATION_MAX` at `src/dest/factory-validators.ts:134` |
| In-flight run lease | 30 min | per downpipe | `INFLIGHT_LEASE_MS` at `src/sched/scheduler-do-records.ts:169` |
| RUNLOG lock lease | 30 s | account-global | `RUNLOG_LEASE_MS` at `src/sched/scheduler-do-records.ts:539` |
| Webhook POST timeout | 5 s | per delivery | `WEBHOOK_TIMEOUT_MS` at `src/notify/types.ts:881` |
| Same-state re-alert interval | 1 h | per downpipe | `ALERT_COOLDOWN_MS` at `src/notify.ts:40` |

---

## 1. Downpipe Configuration (`validateConfig`)

`validateConfig` at `src/sched/config-validate.ts:455-461` runs six section validators in order:
identity, destinations, restore-test cadence, retention, schedule, source. The first failing
section throws, and the DO maps the throw to a 400 with the message as the body. The order is
fixed, so a config with two faults reports the identity fault first.

### 1.1 Downpipe `id`

- Pattern: `DOWNPIPE_ID_PATTERN` at `src/sched/config-validate.ts:145`, built from
  `DOWNPIPE_ID_MAX_LEN` = `128` at `src/sched/config-validate.ts:143`. The pattern is
  `^[A-Za-z0-9._-]{1,128}$`.
- Type must be `string`. Any other type, or a non-matching string, throws
  `downpipe id must be 1 to 128 chars of [A-Za-z0-9._-]` (`DOWNPIPE_ID_PATTERN` at
  `src/sched/config-validate.ts:150`).
- An id made only of dots is a path-reserved token and throws
  `downpipe id must not be entirely dots` at `src/sched/config-validate.ts:156`.

### 1.2 Downpipe `name`

- Type must be `string`, length 1 to `DOWNPIPE_NAME_MAX_LEN` = `256` at
  `src/sched/config-validate.ts:144`.
- Violation throws `downpipe name must be 1 to 256 characters` (`DOWNPIPE_NAME_MAX_LEN` at
  `src/sched/config-validate.ts:159`).

### 1.3 `cadenceSeconds`

- Must be an integer of at least 60 (`cadenceSeconds` at `src/sched/config-validate.ts:162`).
- Violation throws `cadenceSeconds must be an integer of at least 60` at
  `src/sched/config-validate.ts:162`.

### 1.4 `enabled`

- Must be a boolean (`enabled` at `src/sched/config-validate.ts:165`).
- Violation throws `enabled must be a boolean` at `src/sched/config-validate.ts:165`.

### 1.5 `destinationId` and `destinationIds`

`validateDestinations` at `src/sched/config-validate.ts:171-194`:

- `destinationId` is optional. When present it must match `^[A-Za-z0-9._-]{1,128}$`; otherwise
  `destinationId must be 1 to 128 chars of [A-Za-z0-9._-]` (`destinationId` at
  `src/sched/config-validate.ts:177`).
- `destinationIds` is optional. When present it must be a non-empty array
  (`destinationIds must be a non-empty array when present` at `src/sched/config-validate.ts:183`),
  of at most `MAX_DESTINATIONS_PER_DOWNPIPE` = `20` at `src/sched/config-validate.ts:87` entries
  (`destinationIds must not exceed 20 entries`, `MAX_DESTINATIONS_PER_DOWNPIPE` at
  `src/sched/config-validate.ts:186`), each matching the same id pattern
  (`each destinationId must be 1 to 128 chars of [A-Za-z0-9._-]` at
  `src/sched/config-validate.ts:190`).
- An oversized list is refused whole, never truncated.
- Whether an id names a live destination is checked in `addDownpipe`, not here.

### 1.6 `restoreTestCadenceSeconds`

`validateRestoreTestCadence` at `src/sched/config-validate.ts:198-211`:

- Optional. `0` means off.
- Must be a non-negative integer, else
  `restoreTestCadenceSeconds must be a non-negative integer (0 = off)` at
  `src/sched/config-validate.ts:205`.
- A non-zero value must be at least `RESTORE_TEST_MIN_CADENCE_SECONDS` = `60` at
  `src/sched/config-validate.ts:103`, else
  `restoreTestCadenceSeconds must be 0 (off) or at least 60` (`RESTORE_TEST_MIN_CADENCE_SECONDS` at
  `src/sched/config-validate.ts:208`).

### 1.7 `retention`

`validateRetention` at `src/sched/config-validate.ts:215-244`:

- Optional. Absent means keep everything.
- Must be a plain object, else `retention must be an object { keepRuns?, keepDays?, enforce? }` at
  `src/sched/config-validate.ts:225`.
- At least one of `keepRuns` or `keepDays` must be present, else
  `retention requires at least one of keepRuns or keepDays` at `src/sched/config-validate.ts:228`.
- `keepRuns` must be an integer from 1 to `RETENTION_MAX_KEEP_RUNS` = `10000` at
  `src/sched/config-validate.ts:111`, else `retention.keepRuns must be an integer from 1 to 10000`
  (`RETENTION_MAX_KEEP_RUNS` at `src/sched/config-validate.ts:232`).
- `keepDays` must be an integer from 1 to `RETENTION_MAX_KEEP_DAYS` = `36500` at
  `src/sched/config-validate.ts:112`, else `retention.keepDays must be an integer from 1 to 36500`
  (`RETENTION_MAX_KEEP_DAYS` at `src/sched/config-validate.ts:237`).
- `enforce`, when present, must be a boolean, else `retention.enforce must be a boolean` at
  `src/sched/config-validate.ts:241`. Its default is dry-run, decided at the apply site.

### 1.8 `schedule`

`validateSchedule` at `src/sched/config-validate.ts:248-314`:

- Optional. Absent means the `cadenceSeconds` interval.
- Must be a plain object, else `schedule must be an object { cron?, timeZone?, blackoutWindows? }`
  at `src/sched/config-validate.ts:259`.
- `timeZone`, when present, must be a non-empty string
  (`schedule.timeZone must be a non-empty IANA time zone string` at
  `src/sched/config-validate.ts:263`) and a known IANA zone (`isValidTimeZone` at
  `src/sched/config-validate.ts:265`; refusal `is not a known IANA time zone` at
  `src/sched/config-validate.ts:266`).
- `cron`, when present, must be a string (`schedule.cron must be a string` at
  `src/sched/config-validate.ts:270`) that parses (`validateCron` at
  `src/sched/config-validate.ts:274`); a parse failure throws `schedule.cron is invalid:` followed
  by the parser's own reason (`schedule.cron is invalid` at `src/sched/config-validate.ts:276`).
- `blackoutWindows`, when present, must be an array (`schedule.blackoutWindows must be an array` at
  `src/sched/config-validate.ts:281`) of at most `SCHEDULE_MAX_BLACKOUT_WINDOWS` = `32` at
  `src/sched/schedule-window.ts:21` windows (`SCHEDULE_MAX_BLACKOUT_WINDOWS` at
  `src/sched/config-validate.ts:284`).
- Each window is an object `{ days?, startMinute, endMinute }` (`each blackout window must be an object`
  at `src/sched/config-validate.ts:288`). `startMinute` and `endMinute` are integers from 0 to
  `MINUTES_PER_DAY` = `1440` at `src/sched/schedule-window.ts:16` (`startMinute` at
  `src/sched/config-validate.ts:291`, `endMinute` at `src/sched/config-validate.ts:294`).
- A window whose start equals its end covers no time and is refused
  (`startMinute and endMinute must differ` at `src/sched/config-validate.ts:301`).
- `days`, when present, must be an array (`blackout window days must be an array of weekday numbers`
  at `src/sched/config-validate.ts:304`) of integers 0 to 6
  (`blackout window days must be integers 0-6 (0 = Sunday)` at `src/sched/config-validate.ts:307`).

### 1.9 `source.type`

- Must be one of `SELECTABLE_SOURCE_TYPES` at `src/sched/config-validate.ts:131`:
  `kv`, `r2`, `secrets`, `d1`, `cf-config`, `workers`, `stream`, `images`.
- `artifacts` is absent from the list on purpose (Artifact Registry is a closed beta). Its
  validator branch stays in the code and is unreachable through a stored config.
- The refusal message is built from the same list, so it can never name a set the check does not
  enforce: `source.type must be kv/r2/secrets/d1/cf-config/workers/stream/images`
  (`SELECTABLE_SOURCE_TYPES` at `src/sched/config-validate.ts:353`).

### 1.10 Source binding (`source.binding` for `kv`, `r2`, `d1`)

- `bindingOK` at `src/sched/config-validate.ts:359`: a string matching `^[A-Za-z0-9_]{1,64}$`
  that is not in `RESERVED_BINDINGS` (section 1.13).
- Violation throws `source.binding must be 1 to 64 chars of [A-Za-z0-9_]` at
  `src/sched/config-validate.ts:417`.

### 1.11 Secrets source (`source.secrets`)

For `type === "secrets"` (`validateSource` at `src/sched/config-validate.ts:348`):

- `secrets` must be a non-empty array, else `a secrets source needs a non-empty secrets list` at
  `src/sched/config-validate.ts:366`.
- At most `MAX_SECRETS_PER_SOURCE` = `5000` at `src/sched/config-validate.ts:81` entries, else
  `a secrets source must not exceed 5000 secrets` (`MAX_SECRETS_PER_SOURCE` at
  `src/sched/config-validate.ts:371`). An oversized list is refused, not truncated.
- Each entry needs a `name` of 1 to 256 characters and a `binding` that passes `bindingOK`, else
  `each secret needs a 1 to 256 char name and a 1 to 64 char [A-Za-z0-9_] binding` at
  `src/sched/config-validate.ts:375`.
- `storeId`, when present, must match `resId` (`^[A-Za-z0-9_-]{1,128}$`, `resId` at
  `src/sched/config-validate.ts:363`), else
  `each secret's storeId must be a Secrets Store store id` at `src/sched/config-validate.ts:378`.

### 1.12 Token-read sources (`cf-config`, `workers`, `stream`, `images`)

These sources read the Cloudflare REST API with the engine's read-only discovery token and carry
no binding. `cfId` at `src/sched/config-validate.ts:383` accepts `^[a-f0-9]{1,64}$`, case
insensitive.

- `cf-config`: `accountId` is required
  (`a cf-config source needs an accountId (a zoneId alone cannot be crawled)` at
  `src/sched/config-validate.ts:385`) and must be hex
  (`cf-config accountId must be a Cloudflare account id (hex)` at
  `src/sched/config-validate.ts:388`); `zoneId`, when present, must be hex
  (`cf-config zoneId must be a Cloudflare zone id (hex)` at `src/sched/config-validate.ts:387`).
- `workers`: `a workers source needs an accountId` at `src/sched/config-validate.ts:394`;
  `workers accountId must be a Cloudflare account id (hex)` at `src/sched/config-validate.ts:395`.
- `stream`: `a stream source needs an accountId` at `src/sched/config-validate.ts:401`;
  `stream accountId must be a Cloudflare account id (hex)` at `src/sched/config-validate.ts:402`.
- `images`: `an images source needs an accountId` at `src/sched/config-validate.ts:408`;
  `images accountId must be a Cloudflare account id (hex)` at `src/sched/config-validate.ts:409`.
- The account named by a token-read source must be one the Owner's discovery config covers
  (`accountInDiscoveryScope` at `src/sched/config-validate.ts:338-343`), which is the cross-account
  confused-deputy guard applied at the write site.

### 1.13 Reserved bindings

`RESERVED_BINDINGS` at `src/sched/config-validate.ts:15-70` is the set of engine-own env bindings a
source must never name, so a crafted downpipe cannot seal the engine's own keys or credentials into
a backup. The set holds the scheduler and rate-limit Durable Object bindings, the Access, admin
token, SCIM and beacon secrets, the destination credentials and their wrap key, every signer and
recipient key slot, the update and licence channel values, the run-seal and scale knobs, the email
and bootstrap addresses, and the discovery token and account id.

The restore path applies the same guard: `guardTarget` at `src/admin/restore-sinks.ts:286-289`
throws `RESERVED_REASON` = `"target binding is reserved"` at `src/admin/restore-sinks.ts:276` for
any resolved write binding in the set, and the whole restore is refused before any write.

### 1.14 Per-type resource ids

`resId` at `src/sched/config-validate.ts:363` (`^[A-Za-z0-9_-]{1,128}$`) bounds the optional
native ids recorded for re-attach, checked only when present:

- `source.databaseId must be a Cloudflare database id` at `src/sched/config-validate.ts:420`.
- `source.namespaceId must be a Cloudflare KV namespace id` at `src/sched/config-validate.ts:423`.
- `source.bucketName must be a Cloudflare R2 bucket name` at `src/sched/config-validate.ts:424`.

### 1.15 `source.includeContent`

- When present it must be a boolean (`source.includeContent must be a boolean` at
  `src/sched/config-validate.ts:429`).
- It is accepted only on `stream`, `images` and `artifacts`; on any other type it throws
  `source.includeContent is only valid for stream/images/artifacts` at
  `src/sched/config-validate.ts:431`.

### 1.16 `source.include` and `source.exclude`

- Both must be arrays, else `source.include and source.exclude must be arrays` at
  `src/sched/config-validate.ts:435`.
- Every entry must be a string, and no entry may be the empty prefix. `selectorPrefixFault` at
  `src/sources/selector.ts:37` returns the reason, and the config validator throws it with a
  `source.` prefix (`selectorPrefixFault` at `src/sched/config-validate.ts:443`). An empty
  `exclude` prefix would match every record name and put the whole source out of scope
  (`exclude contains an empty prefix` at `src/sources/selector.ts:46`); an empty `include` prefix
  says nothing (`include contains an empty prefix` at `src/sources/selector.ts:47`); a non-string
  entry `must contain only strings` at `src/sources/selector.ts:43`.

### 1.17 `source.cfConfigMode`

- Optional. When present it must be the literal `auto` or `manual`, else
  `source.cfConfigMode must be "auto" or "manual"` at `src/sched/config-validate.ts:448`.

### 1.18 Bulk create

`bulkUpsertDownpipes` at `src/sched/scheduler-do.ts:897` runs the full single-upsert path for each
item of `POST /admin/downpipes/bulk`.

- The body's `downpipes` must be a non-empty array, else `downpipes must be a non-empty array` at
  `src/sched/scheduler-do.ts:899`.
- The batch is capped at `BULK_DOWNPIPES_MAX` = `100` at `src/sched/config-validate.ts:96`, and at
  `BULK_DOWNPIPES_MAX_GATED` = `10` at `src/sched/config-validate.ts:97` while config approval is
  on (`BULK_DOWNPIPES_MAX_GATED` at `src/sched/scheduler-do.ts:901`).
- An oversized batch is refused whole with a 400 whose body carries the cap as `maxBatch`
  (`at most ${cap} downpipes per bulk request` at `src/sched/scheduler-do.ts:904`). Nothing is
  partially processed or truncated.

---

## 2. RBAC Role Enumeration

`Role` at `src/admin/identity-roles.ts:55` is the closed union of six built-in roles:
`viewer`, `operator`, `restore-operator`, `approver`, `access-admin`, `owner`.

`isRole` at `src/admin/identity-roles.ts:76-85` is the runtime guard the DO applies before any
role is stored. The four cumulative roles rank `viewer` 0, `operator` 1, `approver` 3, `owner` 5;
the two narrow roles sit at `restore-operator` 2 and `access-admin` 4 (`ROLE_RANK` at
`src/admin/identity-roles.ts:65-72`). Rank orders resolution only. Authority is decided by the
capability map, because the two narrow roles are a subset of owner, not a prefix of it.

### 2.1 Role writes

`setRole` at `src/sched/scheduler-do-rbac-mutations.ts:41` (`POST /admin/roles`):

- `email` must pass `normaliseEmail` (section 3), else
  `email must be a valid lowercased address` at `src/sched/scheduler-do-rbac-mutations.ts:47`.
- The write names either a built-in `role` or a `customRole`, never both. A `customRole` must name
  a stored custom role, else `unknown custom role` at `src/sched/scheduler-do-rbac-mutations.ts:54`.
  Otherwise `role` must satisfy `isRole`, else
  `role must be viewer/operator/approver/owner (or customRole must name an existing custom role)`
  at `src/sched/scheduler-do-rbac-mutations.ts:56`.
- `expiresAt`, when present, must be a string that `Date.parse` accepts, else
  `expiresAt must be an RFC-3339 timestamp` at `src/sched/scheduler-do-rbac-mutations.ts:60`.
  The check does not require a future time. A grant whose expiry has passed reads as `viewer`
  through lazy expiry (`effectiveRole` at `src/sched/scheduler-do-rbac.ts:312`).

`setGroupRole` (`POST /admin/group-roles`) applies the same role rule
(`role must be viewer/operator/approver/owner` at `src/sched/scheduler-do-rbac-mutations.ts:395`).

### 2.2 Group-to-role cap

A group may confer any role except `owner`. Mapping a group to `owner` is refused at write time
with `a group cannot be mapped to owner; owner must be an explicit per-email grant`
(`AuthError` at `src/sched/scheduler-do-rbac-mutations.ts:401`).

Resolution re-applies the cap: `capGroupRole` at `src/sched/scheduler-do-rbac.ts:366-376` clamps
a stored `owner` mapping to `approver` and records the clamp as a tamper signal
(`rbac-owner-clamp-fired` at `src/sched/scheduler-do-rbac.ts:372`).

### 2.3 Last-Owner guard

A role write or role delete that would leave the estate without an Owner is refused.
`checkOwnerRemoval` at `src/sched/scheduler-do-rbac-mutations.ts:89` guards the demotion path and
`checkOwnerRemoval` at `src/sched/scheduler-do-rbac-mutations.ts:294` guards the delete path. The
refusal sentence is `LAST_OWNER_REFUSAL` = `"would remove the last Owner"` at
`src/admin/owner-floor.ts:47`. With dual control on, the floor is two Owners and the sentence is
`DUAL_CONTROL_FLOOR_REFUSAL` at `src/admin/owner-floor.ts:48`. Owners are counted over explicit
per-email grants only; group mappings never count.

### 2.4 Custom role names

- `CUSTOM_ROLE_NAME_PATTERN` at `src/admin/identity-rbac.ts:202` is
  `^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`: 1 to 64 characters of lowercase letters, digits and
  hyphen, with no leading or trailing hyphen. The name is trimmed and lowercased before the check
  (`validateCustomRoleName` at `src/admin/identity-rbac.ts:251`).
- Violation returns
  `name must be 1 to 64 chars of lowercase letters, digits and hyphen (not leading/trailing hyphen)`
  at `src/admin/identity-rbac.ts:255`.
- A name equal to a built-in role is refused: `name must not collide with a built-in role` at
  `src/admin/identity-rbac.ts:258`.
- `label` must be 1 to 128 characters after trimming, else `label must be 1 to 128 characters` at
  `src/admin/identity-rbac.ts:261`.
- `validateCustomRole` at `src/admin/identity-rbac.ts:335` also refuses an unknown capability, an
  owner-reserved capability, and any capability the creator does not hold. It never throws; the
  DO maps a refusal to a 400.

---

## 3. Email Validation (`normaliseEmail`)

`normaliseEmail` at `src/sched/scheduler-do-rbac.ts:54-73` is applied to every email supplied to a
role operation and to the recovery-code routes:

- Input must be a string.
- Trimmed and lowercased before every check.
- Length after trimming: 3 to 320 characters (`e.length < 3 || e.length > 320` at
  `src/sched/scheduler-do-rbac.ts:60`).
- No whitespace (`/\s/` at `src/sched/scheduler-do-rbac.ts:61`).
- Must match `^[^@]+@[^@]+$`, one `@` with a non-empty local part and domain
  (`/^[^@]+@[^@]+$/` at `src/sched/scheduler-do-rbac.ts:62`).
- No ASCII control character 0x00 to 0x1F or 0x7F (`c < 0x20 || c === 0x7f` at
  `src/sched/scheduler-do-rbac.ts:69`).
- Returns `null` for any failure; the caller maps `null` to a 400.

This is an authority-boundary sanity check, not RFC 5322 validation; the identity provider has
already issued the identity. `canonicalEmail` at `src/admin/identity-roles.ts:114-118` is a
different function: it trims and lowercases the verified caller's display email once at the trust
boundary, for display, audit and the rate-limit key. It is not the validator.

---

## 4. JWT Field Checks (`verifyAccessJWT`)

`verifyAccessJWT` at `src/admin/access.ts:393` accepts a Cloudflare Access JWT only when every
check below passes. The pre-crypto checks live in `verifyStructureAndClaims` at
`src/admin/access.ts:260`.

| Check | Rule | Citation |
|-------|------|----------|
| Structure | Exactly three dot-separated parts, else `malformed JWT` | `parts.length !== 3` at `src/admin/access.ts:265` |
| Decode | Header and payload decode as JSON, else `undecodable JWT` | `undecodable JWT` at `src/admin/access.ts:274` |
| `alg` | Must be `RS256` | `header.alg !== "RS256"` at `src/admin/access.ts:276` |
| `kid` | Must be present | `no kid` at `src/admin/access.ts:277` |
| `typ` | If present, must be `JWT`; absent is accepted | `header.typ !== "JWT"` at `src/admin/access.ts:282` |
| `iss` | Must equal `https://<team>.cloudflareaccess.com` | `payload.iss !== issuer` at `src/admin/access.ts:285` |
| `aud` | Must include the configured AUD tag, else `aud mismatch` | `aud mismatch` at `src/admin/access.ts:287` |
| `exp` | Must be a number strictly greater than now, else `expired` | `payload.exp <= opts.now` at `src/admin/access.ts:288` |
| `nbf` | If present, must be at or before now, else `not yet valid` | `payload.nbf > opts.now` at `src/admin/access.ts:289` |
| Team host | Must be a single-label `*.cloudflareaccess.com` host | `assertCloudflareAccessHost` at `src/admin/access.ts:217-229` |
| Signature | RS256 (`RSASSA-PKCS1-v1_5`) must verify under a JWKS key matching `kid`; a throw or a false verdict is `bad signature` | `RSASSA-PKCS1-v1_5` at `src/admin/access.ts:407` |

The JWKS URL is derived from the verified issuer only after `assertCloudflareAccessHost` at
`src/admin/access.ts:295` confirms the host (the V1.3.6 SSRF guard).

### 4.1 Groups claim bounds

Groups are read from the signed payload only after the signature verifies. `boundGroups` at
`src/admin/access.ts:83-115` bounds the list:

- A non-array claim yields `undefined` (no groups).
- Non-string entries are dropped. Each entry is trimmed; empty entries are dropped.
- An entry longer than `GROUP_NAME_MAX` = `256` at `src/admin/groups-bounds.ts:14` is dropped
  (`GROUP_NAME_MAX` at `src/admin/access.ts:91`).
- An entry carrying an ASCII control character (0x00 to 0x1F or 0x7F) is dropped
  (`c < 0x20 || c === 0x7f` at `src/admin/access.ts:98`).
- Duplicates are dropped, first occurrence kept (`seen.has(g)` at `src/admin/access.ts:107`).
- At most `GROUPS_MAX` = `200` at `src/admin/groups-bounds.ts:9` groups are carried
  (`GROUPS_MAX` at `src/admin/access.ts:108`).
- Every drop is tallied by kind (over-length, control character, list capped) and never by name.

The DO re-applies the same bounds to every group list it ingests (`boundGroupList`, section 5).

### 4.2 Subject and identity-provider hint

- The stable subject is `iss|sub`. `boundSubject` at `src/admin/access.ts:349-357` requires a
  trimmed `sub` of 1 to `GROUP_NAME_MAX` characters with no control character; otherwise the token
  carries no subject and the router refuses it. A subject is never fabricated from the email.
- The `idp` claim, when present, is kept only as a trimmed non-empty string of at most
  `GROUP_NAME_MAX` characters (`idpTrimmed.length <= GROUP_NAME_MAX` at
  `src/admin/access.ts:372`); otherwise it is absent.

---

## 5. Group Name Validation (`normaliseGroup`)

`normaliseGroup` at `src/sched/scheduler-do-rbac.ts:384-395` is applied to every group name at a
DO write boundary (`setGroupRole`, `deleteGroupRole`, every ingested group list):

- Input must be a string.
- Trimmed but not lowercased. Group names match case-sensitively.
- Length after trimming: 1 to `GROUP_NAME_MAX` (`GROUP_NAME_MAX` at
  `src/sched/scheduler-do-rbac.ts:387`).
- No ASCII control character 0x00 to 0x1F or 0x7F (`c < 0x20 || c === 0x7f` at
  `src/sched/scheduler-do-rbac.ts:393`).
- Returns `null` for any failure; the caller maps `null` to a 400.

### 5.1 `boundGroupList`

`boundGroupList` at `src/sched/scheduler-do-rbac.ts:407` is the DO's own bounding of a group list,
applied whatever the list's origin. It keeps string entries that pass `normaliseGroup`, dedupes
them (first occurrence wins), scans at most `GROUPS_MAX * 4` entries (`SCAN_MAX` at
`src/sched/scheduler-do-rbac.ts:423`) and caps the result at `GROUPS_MAX`
(`out.length >= GROUPS_MAX` at `src/sched/scheduler-do-rbac.ts:442`). A list longer than the cap is
truncated, and the truncation is counted as `rbac-group-list-truncated` at
`src/sched/scheduler-do-rbac.ts:412`.

### 5.2 The constants

The bounds are declared once for the IdP paths (`GROUPS_MAX` = `200` at
`src/admin/groups-bounds.ts:9`, `GROUP_NAME_MAX` = `256` at `src/admin/groups-bounds.ts:14`) and
duplicated by value in the DO (`GROUP_NAME_MAX` = `256` at `src/sched/scheduler-do-records.ts:359`,
`GROUPS_MAX` = `200` at `src/sched/scheduler-do-records.ts:360`), so the DO bounds its own inputs
with no cross-module dependency.

---

## 6. Free-Text Fields (`validateFreeText`)

`validateFreeText` at `src/sched/scheduler-helpers.ts:18-26` checks a client-supplied free-text
field against a per-field maximum:

- Over the maximum returns `<field> must not exceed <max> characters`
  (`must not exceed` at `src/sched/scheduler-helpers.ts:19`).
- Horizontal tab (0x09) and newline (0x0A) are allowed. Every other C0 control character and DEL
  (0x7F) returns `<field> must not contain control characters`
  (`must not contain control characters` at `src/sched/scheduler-helpers.ts:23`).
- Returns `null` on success. The caller throws the string to produce a 400.

### 6.1 `REASON_MAX_LEN` (restore-request reason)

`REASON_MAX_LEN` = `1000` at `src/sched/scheduler-do-records.ts:368`. The `reason` of
`POST /admin/restore/request`:

- Must be a non-empty string after trimming, else `reason required` at
  `src/sched/scheduler-do-restore-approval.ts:210`.
- Passes `validateFreeText` with `REASON_MAX_LEN` (`REASON_MAX_LEN` at
  `src/sched/scheduler-do-restore-approval.ts:211`).

The same bound applies to a prune-approval reason (`REASON_MAX_LEN` at
`src/sched/scheduler-do-prune-approval.ts:73`) and a posture override reason (`REASON_MAX_LEN` at
`src/sched/scheduler-do-observability.ts:1156`).

### 6.2 `NOTE_MAX_LEN` (drill-evidence note)

`NOTE_MAX_LEN` = `1000` at `src/sched/scheduler-do-records.ts:369`. The `note` of
`POST /admin/drill-evidence` is optional. When present it must be a string
(`note must be a string` at `src/sched/scheduler-do-restore-approval.ts:646`) and pass
`validateFreeText` with `NOTE_MAX_LEN` (`NOTE_MAX_LEN` at
`src/sched/scheduler-do-restore-approval.ts:649`).

---

## 7. Approval TTL (`APPROVAL_TTL_MS`)

`APPROVAL_TTL_MS` = `24 * 60 * 60 * 1000` at `src/admin/approvals.ts:142`.

A restore-approval record expires 24 hours after it is created. Expiry is applied lazily:
`effectiveStatus` at `src/admin/approvals.ts:362-365` reports `expired` for a record whose
`expiresAt` has passed, without mutating storage. An expired record cannot be approved
(`the request has expired; raise a new one` at `src/admin/approvals.ts:503`) and cannot authorise
an apply (`isUsableApproval` at `src/admin/approvals.ts:382-388` requires the effective status
`approved`).

A record reserved by an in-flight apply is held for `RESTORE_APPLY_LEASE_MS` = `30 * 60 * 1000`
at `src/admin/approvals.ts:175`; past the lease the reservation reads as `approved` again
(`RESTORE_APPLY_LEASE_MS` at `src/admin/approvals.ts:368`).

`PRUNE_APPROVAL_TTL_MS` = `24 * 60 * 60 * 1000` at `src/admin/prune-approvals.ts:84` and
`PRUNE_APPLY_LEASE_MS` = `30 * 60 * 1000` at `src/admin/prune-approvals.ts:85` give a retention
prune approval the same two windows (`PRUNE_APPROVAL_TTL_MS` at
`src/sched/scheduler-do-prune-approval.ts:98`).

---

## 8. Restore `maxRecords`, `SAMPLE_CAP` and the in-account ceiling

- `maxRecords` is an optional caller-supplied cap. It is honoured when it is a number of at least 1
  (`body.maxRecords >= 1` at `src/admin/restore.ts:216`).
- When it is absent or invalid, a dry-run returns at most `SAMPLE_CAP` = `50` at
  `src/admin/restore-sinks.ts:139` preview rows in `sample`, while still verifying every in-scope
  record. `SAMPLE_CAP` is a DO-side constant and cannot be set by a caller.
- An in-account restore covers at most `MAX_IN_ACCOUNT_RESTORE_RECORDS` = `200` at
  `src/admin/restore-sinks.ts:149` records. A larger window is refused before any write with
  `inAccountTooLargeReason` at `src/admin/restore-sinks.ts:157-159`, which steers the operator to
  the offline reader or to a bounded `maxRecords`.
- A reserved target binding refuses the whole restore (`guardTarget`, section 1.13).

---

## 9. Ring and Audit Caps

### 9.1 `RING_CAP`

`RING_CAP` = `50` at `src/sched/scheduler-do-limits.ts:740`. The per-downpipe run-history ring holds
the 50 most recent runs. When a run is appended, the ring is shifted from the front until it is
within the cap (`hist.length > RING_CAP` at `src/sched/scheduler-do-scheduling.ts:306`). The durable
record is the signed RUNLOG in the archive.

### 9.2 `AUDIT_CAP`

`AUDIT_CAP` = `10000` at `src/admin/audit.ts:93`. The tamper-evident audit chain retained in the DO
holds at most 10,000 entries. Past the cap the oldest entries are rolled over, not silently
dropped: the DO records the earliest retained sequence number and the cumulative rolled-over count
under `AUDIT_ROLLOVER_KEY` at `src/sched/scheduler-do-limits.ts:897`
(`rolledOverCount` at `src/sched/scheduler-do-audit.ts:209`). `GET /admin/audit/verify` surfaces
the count, and `GET /admin/audit/export` carries the chain head hash so an export is verifiable
without the live DO.

`AUDIT_NEAR_CAP_FRACTION` = `0.9` at `src/admin/audit.ts:97`: `auditNearCap` reads true from 9,000
entries, so the operator has time to export before the rollover begins.

---

## 10. Webhook URL Rules (`isAllowedWebhookUrl`)

`isAllowedWebhookUrl` at `src/notify/types.ts:1016` validates a customer-supplied webhook URL
before it is stored. Every rejection carries a closed code from `WEBHOOK_REJECT_CODES` at
`src/notify/types.ts:127` (`non-https`, `userinfo`, `workers-dev`, `internal-no-optin`, `too-long`,
`unparseable`) beside the operator-facing sentence.

| Rule | Refusal | Code | Citation |
|------|---------|------|----------|
| Required | `url is required` | `unparseable` | `url is required` at `src/notify/types.ts:1020` |
| Maximum length 2048 | `url is too long` | `too-long` | `trimmed.length > 2048` at `src/notify/types.ts:1022` |
| Absolute URL | `url must be a valid absolute URL` | `unparseable` | `url must be a valid absolute URL` at `src/notify/types.ts:1027` |
| Scheme `https:` | `url must be https` | `non-https` | `u.protocol !== "https:"` at `src/notify/types.ts:1029` |
| No userinfo | `url must not carry userinfo (username or password); use a path token on your endpoint instead` | `userinfo` | `u.username !== ""` at `src/notify/types.ts:1033` |
| Not workers.dev | `workers.dev endpoints are not allowed; use a custom domain` | `workers-dev` | `endsWith(".workers.dev")` at `src/notify/types.ts:1038` |
| Not an internal address | `url points at a private/loopback/link-local address (incl. cloud metadata); these are refused by default.` | `internal-no-optin` | `internal-no-optin` at `src/notify/types.ts:1050` |

### 10.1 Default deny on internal sinks

`isInternalSinkHost` at `src/notify/types.ts:641` classifies `localhost` and `*.localhost`, IPv6
loopback, unspecified, link-local (`fe80::/10`) and unique-local (`fc00::/7`) addresses, IPv4-mapped
IPv6 in both spellings, and every IPv4 literal in `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10` and `0.0.0.0/8` as internal
(`isInternalIpv4` at `src/notify/types.ts:676`).

A URL whose host is internal is refused unless the channel carries the per-channel override
`allowInternalSink: true` (`opts?.allowInternalSink !== true` at `src/notify/types.ts:1045`). The
override is the on-premises SIEM case, and it is a stored, auditable channel field.

### 10.2 Send-time screens

`deliverPayload` at `src/notify/types.ts:911` re-screens the host at send time, so a channel that
reached storage by any path is still refused when it points inside:

- The literal screen `screenSinkHost` at `src/notify/types.ts:271` classifies the URL without any
  network call: `url-invalid`, `internal-literal`, `public-literal` or `hostname`. An
  `internal-literal` target is a non-delivery with code `internal-sink-blocked` at
  `src/notify/types.ts:937`.
- A `hostname` verdict is the one case the literal screen cannot see through. For it,
  `screenResolvedSinkHost` at `src/notify/types.ts:746` resolves the name over DNS-over-HTTPS at
  `DOH_ENDPOINT` at `src/lib/outbound.ts:20` with a `SINK_RESOLVE_TIMEOUT_MS` = `2000` at
  `src/notify/types.ts:720` budget, asks for A and AAAA, and classifies every address. Any
  internal address is a non-delivery with code `internal-sink-resolved` at
  `src/notify/types.ts:944`.
- No answer (a resolver timeout, a transport failure, or an empty answer set) is the verdict
  `resolve-unavailable` at `src/notify/types.ts:781`, and the delivery proceeds. The screen fails
  open on no answer and fails closed on a bad answer, and the abstention is recorded on the
  delivery result rather than read as a pass.
- Every channel that opted into an internal sink skips both screens, and a fixed provider endpoint
  the adapter chose (PagerDuty) skips them too.

Residual exposure: the Workers runtime resolves the name again inside `fetch`, so a record flipped
between the screen's lookup and the runtime's lookup, against the resolver cache, still reaches an
internal address. That race is the remaining gap. The gate `test/validate-ssrf-resolve-screen.ts`
in `validate:chain` proves the screen refuses a resolved-internal name and abstains on no answer.
References ASVS V13.2.5 and V15.3.2.

The webhook URL is never written to the tamper-evident audit chain. A channel change reaches the
chain as a config-change event carrying the closed `changeKind` enum only.

Outbound POST timeout: `WEBHOOK_TIMEOUT_MS` = `5000` at `src/notify/types.ts:881`. The POST runs
with `redirect: "manual"` and never follows a redirect.

---

## 11. Dual-Control Cross-Field Rules

### 11.1 `planHash` must match the recomputed hash

`restorePlanHash` at `src/admin/approvals.ts:301` computes the binding hash from the restore
request's decision-relevant fields (run id, target binding and names, selectors, `maxRecords`)
as `sha384:` plus the hex SHA-384 of the canonical JSON (`sha384:` at
`src/admin/approvals.ts:333`). The apply route re-derives the hash from the incoming request and
looks the approval up by it, so a request whose fields differ from the approved plan finds no
record and is refused.

The `planHash` in a request body must be a string starting with `sha384:`, else
`planHash must be a sha384 plan-binding hash` at `src/sched/scheduler-do-restore-approval.ts:208`.
The prune-approval route applies the same rule (`planHash must be a sha384 plan-binding hash` at
`src/sched/scheduler-do-prune-approval.ts:70`).

### 11.2 The bare-token caller cannot be a maker or a checker

The `ADMIN_TOKEN` break-glass has no stable subject, so it can neither raise a restore request
nor approve one:

- Maker: `dual control requires an attributable identity; the bare-token fallback cannot raise a request`
  at `src/sched/scheduler-do-restore-approval.ts:271`.
- Checker: `dual control requires an attributable identity; the bare-token fallback cannot approve`
  at `src/sched/scheduler-do-restore-approval.ts:340`.

### 11.3 `expiresAt` on a role grant

`expiresAt must be an RFC-3339 timestamp` at `src/sched/scheduler-do-rbac-mutations.ts:60`
(section 2.1). A time-boxed Owner grant is refused while dual control is on and the break-glass
token is retired, because the grant could lapse with no identity left to act
(`grant-expiring-owner` at `src/sched/scheduler-do-rbac-mutations.ts:113`).

### 11.4 Maker and checker must differ

`canApprove` at `src/admin/approvals.ts:493-503` refuses a self-approval on the subject axis
(`cannot approve your own request` at `src/admin/approvals.ts:500`) and again on the display-email
axis (`approverEmail === record.requestedBy` at `src/admin/approvals.ts:499`).
`isUsableApproval` at `src/admin/approvals.ts:382-388` re-checks at apply time
(`record.approverSubject === record.requesterSubject` at `src/admin/approvals.ts:386`). Both run
inside the DO's storage read-modify-write, so the decision is atomic with the write.

---

## 12. Drill Evidence Validation

`recordDrillEvidence` at `src/sched/scheduler-do-restore-approval.ts:621` (`POST /admin/drill-evidence`):

- Capability `drill.run` is required (`drill.run` at
  `src/sched/scheduler-do-restore-approval.ts:625`).
- `runId` must be a non-empty string after trimming, else `runId required` at
  `src/sched/scheduler-do-restore-approval.ts:638`.
- `kind` must be `in-account` or `offline-rehearsal`, else
  `kind must be in-account or offline-rehearsal` at
  `src/sched/scheduler-do-restore-approval.ts:642`.
- `note` follows section 6.2.
- A refused entry is counted (`evidence-refused` at
  `src/sched/scheduler-do-restore-approval.ts:633`) so a failing writer is visible in the support
  pack.

The evidence log holds at most `DRILL_EVIDENCE_CAP` = `500` at
`src/sched/scheduler-do-records.ts:320` rows. Past the cap the oldest rows are deleted in the same
storage turn as the append (`window.size > DRILL_EVIDENCE_CAP` at
`src/sched/scheduler-do-restore-approval.ts:680`).

---

## 13. In-flight Lease

`INFLIGHT_LEASE_MS` = `30 * 60 * 1000` at `src/sched/scheduler-do-records.ts:169`.

A triggered run must post `/complete` within 30 minutes. `leased` at
`src/sched/scheduler-do-scheduling.ts:246-248` treats a downpipe as in flight only while
`now - inFlightSince <= INFLIGHT_LEASE_MS`. A run past the lease is treated as crashed: the next
`trigger` resolves its history row to `abandoned` with the error `abandoned (run lease expired)`
at `src/sched/scheduler-do-scheduling.ts:297` and allocates a fresh run. This bounds the wedge
time after an evicted or redeployed Worker isolate.

---

## 14. RUNLOG Lock Lease

`RUNLOG_LEASE_MS` = `30_000` at `src/sched/scheduler-do-records.ts:539`.

The RUNLOG write lock is held for at most 30 seconds. `acquireRunlogLock` at
`src/sched/scheduler-do.ts:762-770` admits a new holder when the stored lease has expired and
stamps the new lease as `now + RUNLOG_LEASE_MS` (`RUNLOG_LEASE_MS` at
`src/sched/scheduler-do.ts:768`). A crashed holder wedges the RUNLOG for at most one lease.

---

## 15. Audit Page Bounds

`AUDIT_PAGE_DEFAULT` = `100` at `src/admin/audit.ts:268` and `AUDIT_PAGE_MAX` = `500` at
`src/admin/audit.ts:269`.

`pageEvents` at `src/admin/audit.ts:274-275` clamps the `limit` parameter of `GET /admin/audit`
to `[1, AUDIT_PAGE_MAX]` and defaults it to `AUDIT_PAGE_DEFAULT`. The compliance export
(`GET /admin/audit/export`) is a distinct path with no page cap, so an export is complete up to
`AUDIT_CAP`.

---

## 16. Alert Cooldown

`ALERT_COOLDOWN_MS` = `60 * 60 * 1000` at `src/notify.ts:40` and `STALE_CADENCE_MULTIPLE` = `3`
at `src/notify.ts:48`.

A downpipe in the same alertable state (failed or stale) is re-alerted at most once an hour
(`ALERT_COOLDOWN_MS` at `src/sched/scheduler-do-sre-alerting.ts:717`). A downpipe is stale when
its last successful run started more than `3 * cadenceSeconds` seconds ago.

A state-transition alert whose delivery fails is retried: `markAlertsDelivered` at
`src/sched/scheduler-do-sre-alerting.ts:371-380` deletes the cooldown record of each failed
transition, so the next reconciliation tick re-qualifies the downpipe.

---

## 17. Rate Limits

The admin API implements anti-automation rate limiting aligned with OWASP ASVS V2.4.1. The engine
holds six fixed-window limiters. Each is a counter in the scheduler Durable Object under its own
key namespace, so the buckets never collide. `rateCheck` at `src/sched/scheduler-do.ts:796` is the
counter for five of them; the recovery-code limiter has its own `recoveryRateCheck` at
`src/sched/scheduler-do-recovery.ts:547` in the same shape. The consolidated contextual model (each
attribute with its threshold and its action) is `docs/security/identity-sessions-and-files.md`
section 2.6; this section is the limiter reference, and its fail posture per surface (section 17.7)
is the limiter-specific complement to that model.

### 17.1 The window and the counter

`RATE_LIMIT_WINDOW_MS` = `60_000` at `src/sched/scheduler-do-limits.ts:643`. A fixed window costs
one storage read and one write per check on the single-threaded DO; a burst can straddle two
windows, which is acceptable for an anti-automation limiter.

`rateCheck` reads the stored window for the key (`RATE_LIMIT_PREFIX` = `"ratelimit:"` at
`src/sched/scheduler-do-limits.ts:634`). With no live window it opens one at `now` and admits.
Inside a live window it refuses when `count + cost` would exceed the bucket's `max`
(`cur.count + cost > max` at `src/sched/scheduler-do.ts:814`), reporting `retryAfterMs` as the
time left in the window (`retryAfterMs` at `src/sched/scheduler-do.ts:813`). A refused request
does not increment the counter. A request without an explicit `max` uses
`RATE_LIMIT_MAX_PER_WINDOW` (`RATE_LIMIT_MAX_PER_WINDOW` at `src/sched/scheduler-do.ts:803`).

### 17.2 Per-subject limit on mutating admin routes

`RATE_LIMIT_MAX_PER_WINDOW` = `120` at `src/sched/scheduler-do-limits.ts:650`.

The mutating admin routes call `rateLimited` at `src/admin/router-core.ts:303` after the caller
is resolved and before the handler runs; GET routes are exempt. `test/validate-ratelimit.ts` in
`validate:chain` proves a burst past the cap answers 429 and a limiter fault admits. The bucket key is `rateLimitKey` at `src/admin/router-core.ts:218-219`: `sub:<subject>`
for every attributable caller (Access, passkey, OIDC, SAML and recovery sessions all carry a
subject), and the single shared `token` bucket for the bare-token break-glass, which has no
subject. This bucket's key excludes the source IP entirely, so a shared NAT or corporate egress
cannot exhaust one budget for every operator behind it.

Fail-open: a thrown `/rate-check` round trip, or a verdict with no boolean `allowed`, admits the
request (`typeof verdict.allowed !== "boolean"` at `src/admin/router-core.ts:321`; `catch (e)` at
`src/admin/router-core.ts:333`). Each admit-on-fault is recorded as
`limiter-verdict-malformed` at `src/admin/router-core.ts:322`. An unavailable limiter never
blocks a verified operator's recovery action.

### 17.3 Per-IP limits on the unauthenticated surfaces

Two limiters key on `CF-Connecting-IP`, because there is no verified identity yet:

- `AUTH_RATE_LIMIT_MAX_PER_WINDOW` = `30` at `src/sched/scheduler-do-limits.ts:664` bounds the
  `/admin/auth/*` ceremony routes (register and login, begin and finish). `authRateLimited` at
  `src/admin/router-core.ts:612` keys the bucket `ip:<address>` (`ip:${ip}` at
  `src/admin/router-core.ts:624`) and is called from every auth-flow route
  (`authRateLimited` at `src/admin/router-auth-flow.ts:49`).
- `ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW` = `10` at `src/sched/scheduler-do-limits.ts:673` bounds
  the bare `ADMIN_TOKEN` compare. `adminTokenRateLimitedViaDO` at `src/admin/router-session.ts:335`
  keys the bucket `admin-token-ip:<address>` (`admin-token-ip:${ip}` at
  `src/admin/router-session.ts:341`).

Both fail closed: a refusal, a malformed verdict, or a thrown round trip returns 429
(`verdict.allowed === true` at `src/admin/router-core.ts:632` is the only admit; `catch (e)` at
`src/admin/router-core.ts:650` answers `RATE_LIMIT_UNAVAILABLE_ERROR` with
`AUTH_RATE_LIMIT_FALLBACK_RETRY_AFTER_S` = `60` at `src/admin/router-core.ts:610`). A request with
no `CF-Connecting-IP` header is admitted: the Cloudflare edge always injects the header on the
custom-domain-only deployment, so its absence means a local context, not a stripped header
(`ip === null` at `src/admin/router-core.ts:620`). This is a deliberate, edge-guaranteed accept
rather than a gap: the V2.4.1 / V8.1.4 accept decision for this case.

Together the two authenticated-mutating and three credential-guessing limiters gate: every
mutating admin route (section 17.2); the WebAuthn passkey ceremonies, first-owner bootstrap,
recovery-code sign-in, native OIDC start and callback, and native SAML start and ACS (this
section); the SCIM bearer check (`authRateLimited` at `src/admin/scim.ts:360`); and the recovery-code and
`ADMIN_TOKEN` bearer surfaces (this section and section 17.4). `GET` reads are exempt from
every limiter except the `ADMIN_TOKEN` bearer check, which runs inside the auth gate itself and
so applies to a `GET` request presenting the bearer just as it does to a `POST`. ASVS mapping:
V2.4.1 (anti-automation on application functions) covers the per-subject and per-IP-ceremony
limiters (sections 17.2 and this section); V6.3.1 (controls against credential stuffing and
password brute force) covers this section and the recovery-code and audit-feed limiters
(sections 17.4 and 17.5).

### 17.4 Per-IP and per-email limits on recovery codes

`RECOVERY_RATE_WINDOW_MS` = `60_000` at `src/sched/scheduler-do-limits.ts:732`,
`RECOVERY_RATE_MAX_PER_IP` = `5` at `src/sched/scheduler-do-limits.ts:734` and
`RECOVERY_RATE_MAX_PER_EMAIL` = `5` at `src/sched/scheduler-do-limits.ts:734`.

A recovery-code sign-in must pass both buckets (`recoveryRateAllow` at
`src/sched/scheduler-do-recovery.ts:514`): the email bucket `email:<canonical email>` (a malformed
email spends the shared `email:_invalid` bucket) and the IP bucket `ip:<address>`
(`recoveryRateAllow` at `src/sched/scheduler-do-recovery.ts:363`). The buckets live in the
`recovery-rate:` namespace (`RECOVERY_RATE_PREFIX` at `src/sched/scheduler-do-limits.ts:731`). The
limiter fails closed: a storage fault denies the attempt (`recovery-limiter-unavailable` at
`src/sched/scheduler-do-recovery.ts:537`). A denied attempt does not increment the counter, so a
caller cannot extend their own lockout past one window.

### 17.5 Per-client limit on the audit-feed pull

`INGEST_PULL_RATE_LIMIT_MAX_PER_WINDOW` = `120` at `src/admin/support-ingest.ts:226` bounds the
SIEM audit-feed pull per ingest client id. `ingestPullRateLimited` at
`src/admin/support-ingest.ts:241` keys the bucket `ingest:<clientId>` (`ingest:${clientId}` at
`src/admin/support-ingest.ts:245`) and fails open, matching the per-subject limiter, so an engine
fault cannot become a collector outage.

### 17.6 The 429 response

`rateLimitedResponse` at `src/admin/router-core.ts:274` is the single producer of a 429. The body
is RFC 9457 problem+json with `error` set to `RATE_LIMITED_ERROR` = `"rate limited"` at
`src/admin/router-core.ts:257` (or `RATE_LIMIT_UNAVAILABLE_ERROR` = `"rate limit unavailable"` at
`src/admin/router-core.ts:258` on a fail-closed outage). The headers carry `retry-after` in whole
seconds, rounded up and floored at 1 (`Math.ceil(retryAfterMs / 1000)` at
`src/admin/router-core.ts:329`), plus the advisory IETF `ratelimit` and `ratelimit-policy` headers
(`rateLimitHeaders` at `src/admin/router-core.ts:245`). `ratelimit-policy` advertises the ceiling
of the bucket that refused and the window in seconds (`RATE_LIMIT_WINDOW_SECONDS` at
`src/admin/router-core.ts:237`), so a caller can read the limit off the wire.

Two surfaces answer differently rather than through this builder. The break-glass 429
(`adminTokenThrottledResponse` at `src/admin/router-core.ts:298`) advertises the full window rather
than the time remaining. The recovery-code sign-in answers a generic 401 `unauthorised` with no
`Retry-After` at all (`unauthorised` at `src/admin/router-auth-flow.ts:78`), because a back-off
signal on the per-email bucket would tell an unauthenticated caller that recovery is being
attempted on that address. `retryAfterMs` in the DO verdict is the time remaining in the current
window (`retryAfterMs` at `src/sched/scheduler-do.ts:813`); a refused request does not increment
the counter, so only admitted requests count toward the window cap (`retryAfterMs` at
`src/sched/scheduler-do.ts:814-821`).

### 17.7 Fail posture per surface

| Surface | Limiter | When the DO is unavailable or answers without a boolean verdict | Where |
|---------|---------|------------------------------------------------------------------|-------|
| Authenticated mutating routes | `rateLimited` | fail open: the request is admitted and `limiter-verdict-malformed` is recorded | `limiter-verdict-malformed` at `src/admin/router-core.ts:322`, `limiter-verdict-malformed` at `src/admin/router-core.ts:341` |
| Unauthenticated sign-in ceremonies | `authRateLimited` | fail closed: 429, recording `auth-limiter-verdict-malformed` on an answered-but-broken limiter and `auth-limiter-unavailable` on a thrown round trip | `auth-limiter-verdict-malformed` at `src/admin/router-core.ts:645`, `auth-limiter-unavailable` at `src/admin/router-core.ts:660` |
| Bare-token compare | `adminTokenRateLimitedViaDO` | fail closed: blocked, recording `admin-token-ratelimited-unavailable` | `admin-token-ratelimited-unavailable` at `src/admin/router-session.ts:373` |
| Recovery-code sign-in | `recoveryRateAllow` | fail closed: denied, recording `recovery-limiter-unavailable` | `recovery-limiter-unavailable` at `src/sched/scheduler-do-recovery.ts:537` |
| Audit-feed pull | `ingestPullRateLimited` | fail open, matching the per-subject limiter | `ingestPullRateLimited` at `src/admin/support-ingest.ts:241` |

The per-caller and audit-feed limiters fail open because each guards a verified operator's own
path (a recovery action, a SIEM collector's own pull): a limiter that failed closed when its store
hiccupped would block a legitimate use rather than an attacker. The three unauthenticated limiters
fail closed because a guessing attack must never benefit from knocking the limiter over, and the
ceremony behind each depends on the same DO, so failing closed costs no extra availability. The one
admit-on-absence case, a request with no `CF-Connecting-IP` header, is tabled with its rationale in
identity-sessions-and-files.md section 2.6.

---

## 18. Config History Cap

`CONFIG_HISTORY_CAP` = `2000` at `src/admin/config-history.ts:70`. The DO retains at most 2000
config versions. Past the cap the oldest versions roll off while the sequence stays monotonic
(`countAfter > CONFIG_HISTORY_CAP` at `src/sched/scheduler-do-config-version.ts:131`), and the
retained chain stays verifiable from its first retained version.

---

## 19. Change Reference Bounds

`CHANGE_NUMBER_MAX` = `64` at `src/admin/change-ref.ts:37` and `CHANGE_REASON_MAX` = `500` at
`src/admin/change-ref.ts:38` bound the change reference the console attaches in the
`x-downpipes-change` header (`CHANGE_HEADER` at `src/admin/change-ref.ts:33`).

- A change number longer than 64 characters, measured after control characters are stripped and
  the text trimmed (`changeNumberExceedsMax` at `src/admin/change-ref.ts:66-68`), is refused with
  `CHANGE_NUMBER_TOO_LONG` at `src/admin/change-ref.ts:44` (`CHANGE_NUMBER_TOO_LONG` at
  `src/admin/router.ts:552`), so the operator sees which field to shorten.
- The reason is cleaned and cut to 500 characters (`normaliseChangeText` at
  `src/admin/change-ref.ts:89-92`), never refused.

---

## 20. STS Session Duration

`STS_DURATION_MIN` = `900` at `src/dest/factory-validators.ts:128` and `STS_DURATION_MAX` = `43200`
at `src/dest/factory-validators.ts:134` are AWS's own bounds on an AssumeRole session. A submitted
duration must be an integer in that range, else
`the STS session duration must be a whole number of seconds from 900 to 43200`
(`the STS session duration must be a whole number of seconds from` at
`src/dest/factory-validators.ts:158`). The run path clamps the stored value into the same range
(`STS_DURATION_MAX` at `src/dest/sts.ts:72`).

---

## 21. Fleet Drill Cap

`FLEET_DRILL_MAX` = `5000` at `src/sched/scheduler-do-limits.ts:751`. One fleet-drill campaign may
enqueue at most 5000 downpipes; a larger selection is refused with
`fleet drill exceeds the 5000-downpipe cap; narrow it with a downpipeIds subset`
(`FLEET_DRILL_MAX` at `src/sched/scheduler-do-observability.ts:618`).

---

## 22. IdP Connection Field Bounds

`validateIdpConnection` at `src/admin/idpconn.ts:54` bounds every field of a native OIDC, OAuth2
or SAML connection at the write boundary.

- `id` must satisfy `CONN_ID_PATTERN` at `src/admin/identity.ts:241`
  (`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`), else
  `id must be 1 to 64 chars of lowercase letters, digits and hyphen (no leading/trailing hyphen)`
  at `src/admin/idpconn.ts:57`. A duplicate id is refused (`already exists` at
  `src/admin/idpconn.ts:58`).
- `label`: 1 to `LABEL_MAX` = `128` at `src/admin/idpconn-validators.ts:35` characters
  (`label must be 1 to` at `src/admin/idpconn.ts:61`).
- `presetId`: at most `PRESET_ID_MAX` = `64` at `src/admin/idpconn-validators.ts:41` characters.
- `clientId`: at most `CLIENT_ID_MAX` = `512` at `src/admin/idpconn-validators.ts:36` characters.
- `scopes`: at most `SCOPES_MAX` = `32` at `src/admin/idpconn-validators.ts:38` entries, each at
  most `SCOPE_MAX` = `64` at `src/admin/idpconn-validators.ts:37` characters.
- Claim names and paths (`groupsClaim`, `rolesClaim`, `claimNamespace`, `hdDomain`, `emailPath`,
  `subjectPath`, `emailAttr` and their siblings): at most `CLAIM_NAME_MAX` = `128` at
  `src/admin/idpconn-validators.ts:39` characters.
- Entity ids and the NameID format: at most `REF_MAX` = `256` at
  `src/admin/idpconn-validators.ts:40` characters.
- `acceptedTenantIds`: at most `TENANT_IDS_MAX` = `32` at `src/admin/idpconn-validators.ts:42`
  entries; `acceptIssuerVariants`: at most `ISSUER_VARIANTS_MAX` = `4` at
  `src/admin/idpconn-validators.ts:43`; `extraAuthParams`: at most `EXTRA_PARAMS_MAX` = `8` at
  `src/admin/idpconn-validators.ts:44` entries (`extraAuthParams may have at most` at
  `src/admin/idpconn-validators.ts:203`).
- `clockSkewSec` (SAML): a number from 0 to `CLOCK_SKEW_MAX` = `600` at
  `src/admin/idpconn-validators.ts:397`, else `clockSkewSec must be a number from 0 to 600`
  (`clockSkewSec must be a number from 0 to` at `src/admin/idpconn-validators.ts:480`).
- `idpSigningCerts` (SAML): at most `SAML_CERTS_MAX` = `8` at
  `src/admin/idpconn-validators.ts:402` PEM certificates, each at most `CERT_PEM_MAX` = `8192` at
  `src/admin/idpconn-validators.ts:403` characters; an over-capacity append is refused with
  `the pinned set holds at most 8 signing certificates`
  (`the pinned set holds at most` at `src/admin/idpconn-validators.ts:433`).
- The transient NameID format is refused at config time (`NAMEID_TRANSIENT` at
  `src/admin/idpconn-validators.ts:396`), because a per-session pseudonym cannot key a stable
  principal.

---

## 23. Regex Construction from Non-Literal Data

Policy: any `new RegExp` interpolating a value that is not fixed at compile time must escape
it first, as `azureHostPattern` does (`new RegExp` at `src/dest/provider.ts:107`), which
escapes every dot in each configured cloud suffix before joining them into the pattern
(`replace` at `src/dest/provider.ts:106`) so a suffix cannot smuggle a regex metacharacter.
Enforced by `test/validate-regex-construction.ts` in `validate:chain`: it scans `src/` for
every `new RegExp(...)` call built from a template literal with an interpolated segment and
fails on one that is neither escaped nor provably fixed at compile time (a literal union, an
integer constant, or a parameter closed over at a call site that only ever passes a fixed
literal). See section 24 for the companion V1.3.12 sweep (every regex, literal or
constructed, checked for catastrophic backtracking rather than injection), which reviews
the same three constructed-pattern call sites from the ReDoS angle.

---

## 24. Regex Safety (ReDoS) Sweep: ASVS V1.3.12 sign-off

Source: `test/validate-regex-safety.ts`, wired into `validate:chain`
(`package.json`, `validate:chain` member list).

Every regex under `src/` is checked for catastrophic backtracking (ReDoS) on every run
of `npm run validate`: every `/literal/` and every `new RegExp(...)` / `RegExp(...)`
construction whose pattern (and flags, if given) is a static string. Coverage at the
time this section was last measured: 440 files under `src/`, 487 distinct patterns
(regex literals plus static-string constructor calls), plus 3 `RegExp(...)` constructor
call sites whose pattern is built from a runtime string rather than a literal (see
24.4). "Every regex literal" in the sweep's original scope did not reach that last
group; 24.4 is the fix and its disclosure. See section 23 for the companion V1.2.9
control (escape-or-prove-fixed on the same constructor calls); this section is the
ReDoS-safety sweep over ALL regex, literal or constructed.

### 24.1 Method

1. **Enumeration.** Every `RegularExpressionLiteral` node under `src/` is collected via
   the TypeScript compiler API (syntactic parse only), deduplicated by exact literal
   text, and each unique pattern's citing file:line(s) are recorded.
2. **`RegExp(...)` constructor calls, read the same way when the argument is a static
   string.** Every `new RegExp(...)` / `RegExp(...)` call site under `src/` is also
   collected. When its pattern argument (and flags argument, if given) is a plain string
   literal or a template literal with no `${...}` substitution, its resolved text is
   known without running anything, and it is folded into the same pattern set as a
   `/literal/`, checked by steps 3-4 below identically. When the pattern argument is
   anything else, its concrete text cannot be read syntactically; see 24.4 for how those
   are handled.
3. **Static classification.** A pattern with no unbounded repetition (no bare `*` or
   `+`, no open-ended `{n,}`, outside any character class) is recorded safe without
   further work: a backtracking search bounded by construction cannot blow up without
   bound. 393 of 487 patterns are safe on this ground alone.
4. **Dynamic check, for the remaining 94 patterns.** Each is executed against a
   generated input built from characters read out of the pattern's own character
   classes, at doubling lengths (8, 16, 32, and so on up to 8192), with two terminator
   variants: a clean match, and one astral-plane codepoint no class in this repo
   admits, chosen to force a failed match at an anchor, which is where classic
   catastrophic patterns such as `(a|aa)+$` do their damage. Each attempt runs in a
   freshly spawned Node child process with a 3-second hard OS-level timeout
   (`SIGKILL`); a child killed before completing its doubling schedule is the finding,
   because a linear-time pattern finishes the whole schedule in microseconds per step
   regardless of length. A subprocess-plus-timeout is used rather than an in-process
   timer because a single `RegExp.prototype.test()` call cannot be interrupted
   mid-flight in JavaScript's single-threaded model; only an OS-level kill bounds a
   call this file cannot otherwise interrupt.
5. **Why dynamic rather than a static nested-quantifier rule.** A naive rule (flag any
   quantified group that itself contains a quantified sub-pattern) was tried first and
   rejected against this repo's own corpus: `/^[a-z]{2}(-[a-z]+)+-\d{1,2}$/`
   (`VALID_STS_REGION` at `src/dest/sts.ts:56`, an AWS region code) nests `[a-z]+` inside
   a repeated group and is completely safe, because the outer group's leading `-` can
   never be produced by the inner `[a-z]+`, so every repetition is forced apart and there
   is only ever one way to parse a given string. That rule would have flagged this
   pattern and its non-capturing siblings (`AWS_REGION_SHAPE` at
   `src/admin/run-fault-records.ts:98`, `AWS_REGION_RE` at `src/dest/fault-log.ts:205`),
   none of which is unsafe. Executing each pattern
   against a real generated input answers the only question that matters, whether the
   engine's cost stays flat as the input grows, without needing to reconstruct
   NFA-ambiguity theory to get the right answer for this shape.

### 24.2 Result at the time this section was last measured

All 487 distinct patterns pass: 393 safe by bound alone, 94 probed dynamically, 0
unsafe. Full sweep wall time: approximately 26 seconds. Of the 3 `RegExp(...)`
constructor call sites whose pattern is a non-literal string, all 3 are on the reviewed
allowlist (24.4); 0 are unreviewed, and 0 constructor calls in `src/` build their
pattern from a static string literal today.

Three of the patterns documented elsewhere in this file are asserted present in the
scan by exact text, so a future edit cannot silently drop one from the tree without the
validator itself failing:

- `/^[A-Za-z0-9._-]{1,128}$/`, downpipe id (section 1.1)
- `/^[A-Za-z0-9_]{1,64}$/`, source/secret binding (section 1.6)
- `/^[^@]+@[^@]+$/`, `normaliseEmail` (section 3)

### 24.3 Red-before-green

The control was gated red before landing: a fixture pattern `/^(a+)+$/` (the textbook
nested-quantifier ReDoS shape) was planted under `src/`, the validator failed naming
the fixture's file:line and reporting that the probe was killed by the 3-second
timeout rather than completing, the fixture was removed, and the validator passed
again. No production pattern was ever red; the fixture was never committed.

The constructor-call extension (24.4) was gated red the same way, against two
fixtures planted under `src/` and never committed:

- `new RegExp("^(" + x + "+)+$")`, a **dynamic, un-allowlisted** pattern (`x` an
  ordinary local variable, not a literal) -- failed naming the fixture's file:line
  and reporting that its file was not on `DYNAMIC_REGEX_ALLOWLIST`.
- `new RegExp("^(a+)+$")`, a **static string literal** argument carrying the same
  nested-quantifier shape -- failed naming the fixture's file:line and reporting that
  its dynamic probe was killed by the 3-second timeout rather than completing.

Both fixtures were removed and the validator passed again before this control landed.

### 24.4 `RegExp(...)` constructed from a non-literal string: scope and the allowlist rule

**The gap this closes.** A `/literal/` is not the only way JavaScript builds a RegExp:
`new RegExp(someString)` compiles a pattern from a runtime string, and a sweep that
only enumerates `RegularExpressionLiteral` AST nodes never sees it. A pattern built as
`new RegExp("^(" + x + "+)+$")` is the textbook catastrophic shape from 24.1's step 5,
constructed instead of written, and it passed the original version of this sweep
undetected. This section is the fix and its precise scope, replacing the "every regex
literal" framing above wherever it implied broader coverage than the sweep delivered:
the sweep now also reaches every `new RegExp(...)` / `RegExp(...)` call under `src/`,
by two different means depending on what the call site's own text can prove.

**What is statically analysed, the same way as a `/literal/`.** A constructor call
whose pattern argument (and flags argument, if any) is a plain string literal or a
template literal with no `${...}` substitution has a resolved value the TypeScript
parser already knows, with no execution needed. That value is checked exactly like a
`/literal/`: the same unbounded-repetition test, the same child-process dynamic probe
when it applies. There are 0 such call sites in `src/` today; if one is added, it is
covered automatically, with no allowlist entry needed.

**What requires the reviewed allowlist, and why it cannot be checked automatically.** A
constructor call whose pattern argument is a template literal WITH a substitution,
a string concatenation, a bare identifier, or a function call has no text the sweep can
read without running the program that builds it -- the runtime value is exactly the
thing under test, and there is no static shortcut that both stays sound and stays
syntactic (step 5's rejected nested-quantifier rule, applied here, would need to
reason about the CALLER's possible values, which is the call-graph analysis 24.5
already declines to build). Each such call site fails the sweep, naming its file:line
and its own source text, UNLESS the file it lives in is named in
`DYNAMIC_REGEX_ALLOWLIST` (`test/validate-regex-safety.ts`) -- a plain list of file
paths, each with an inline comment recording the by-hand review of why that file's
constructed pattern cannot backtrack catastrophically regardless of the runtime value
substituted into it. The allowlist is file-scoped, not call-site-scoped: a passing
review excuses every non-literal constructor call already in that file from the
automatic check, which is why entries are kept few and each one is reasoned in place
rather than added on request.

There are 3 files on the allowlist today, all reviewed when this section was added,
none added since:

- **`new RegExp` at `src/admin/router-sources.ts:509`, inside `matchActionPath`.** `matchActionPath(method, sub, prefix)` builds
  `` new RegExp(`^/${prefix}/([^/]+)/(approve|reject)$`) ``. `prefix` is a function
  parameter, so its value cannot be read from this call site alone -- but the file's
  only two callers (lines 548 and 556) each pass a hardcoded string
  (`"config/changes"`, `"owner-actions"`), and the pattern's only unbounded piece,
  `[^/]+`, is a single un-nested repetition regardless of what text `prefix` supplies.
  A future caller passing a request-derived prefix would need this entry re-reviewed.
- **`DOWNPIPE_ID_PATTERN` at `src/sched/config-validate.ts:145`.** `DOWNPIPE_ID_PATTERN` builds
  `` new RegExp(`^[A-Za-z0-9._-]{1,${DOWNPIPE_ID_MAX_LEN}}$`) ``, interpolating a
  same-file exported numeric constant (`DOWNPIPE_ID_MAX_LEN = 128`, line 145) into a
  BOUNDED quantifier's upper bound. The pattern this builds is
  `/^[A-Za-z0-9._-]{1,128}$/`, byte-identical to the literal already asserted present
  in 24.2's list (section 1.1), and a bounded quantifier cannot backtrack
  catastrophically for any value of that constant.
- **`new RegExp` at `src/dest/provider.ts:107`, inside `azureHostPattern`.** `azureHostPattern(family)` builds
  `` new RegExp(`\\.${family}\\.(?:${clouds})$`, "i") ``, interpolating `family`
  (typed `"blob" | "dfs"`, called with only those two literals at lines 110-111) and
  `clouds` (every element of the same-file literal array `AZURE_STORAGE_SUFFIXES`,
  joined with `|` after each element's own dots are escaped). Neither substituted
  piece, nor the literal text around them, carries an unbounded quantifier, so there
  is nothing to nest.

### 24.5 Residual

This sweep checks every regex literal syntactically present under `src/`, and every
`RegExp(...)` constructor call whose pattern is a static string; it does not trace
which HTTP field, JWT claim, or destination response actually reaches each one (a full
call-graph/data-flow analysis this repo does not have). Checking the whole tree rather
than a hand-picked subset is the deliberate, conservative choice this residual implies:
it costs one dynamic probe pass (about 26 seconds) rather than a reachability analysis
that could itself be wrong in the lenient direction.

For a `RegExp(...)` built from a non-literal string, the residual is different in kind:
24.4's allowlist is a recorded human review of the file, not a probe of the constructed
pattern's actual runtime text, because that text does not exist until the program runs.
A change to `DOWNPIPE_ID_MAX_LEN`, `AZURE_STORAGE_SUFFIXES`, or `matchActionPath`'s
callers that introduced an unbounded quantifier into the substituted value would not be
caught by this sweep; it would need the same by-hand review 24.4 already asks for, and
this sweep enforces only that a NEW dynamic call site outside these three files gets
that review before it can pass.
