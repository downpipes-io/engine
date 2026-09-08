# Input Validation and Operating Limits

This document enumerates every input-validation rule and operating limit enforced by the
downpipes engine. All statements are grounded in the source; file:line citations are given for
each rule. Aspirational or untested controls are not listed here.

The scheduler Durable Object (`SchedulerDO`) is the single authority for most rules: all
writes go through it, and it validates inputs independently of any upstream router gate.

---

## 1. Downpipe Configuration (`validateConfig`)

Source: `src/sched/scheduler-do.ts`, function `validateConfig` (lines 1658-1695).

Called unconditionally from `addDownpipe` (line 429) before any storage write.

### 1.1 Downpipe `id`

```
/^[A-Za-z0-9._-]{1,128}$/
```

- Character set: ASCII alphanumerics, `.`, `_`, `-` only.
- Minimum length: 1 character.
- Maximum length: 128 characters.
- Type must be `string`; any other type or a non-matching string throws
  `"downpipe id must be 1 to 128 chars of [A-Za-z0-9._-]"`.

Source: line 1659.

### 1.2 Downpipe `name`

- Type must be `string`.
- Minimum length: 1 character.
- Maximum length: 256 characters.
- Throws `"downpipe name must be 1 to 256 characters"` on violation.

Source: line 1662-1664.

### 1.3 `cadenceSeconds` (minimum cadence)

- Must be a safe integer (`Number.isInteger`).
- Minimum value: 60 (seconds).
- Throws `"cadenceSeconds must be an integer of at least 60"` on violation.

Source: line 1665-1667.

### 1.4 `enabled`

- Must be a boolean.
- Throws `"enabled must be a boolean"` on violation.

Source: line 1668-1670.

### 1.5 `source.type`

- Must be one of `"kv"`, `"r2"`, `"secrets"`, `"d1"`.
- Throws `"source.type must be kv/r2/secrets/d1"` on violation.

Source: line 1672-1674.

### 1.6 Source binding (`source.binding` for `kv`, `r2`, `d1`)

```
/^[A-Za-z0-9_]{1,64}$/
```

- Character set: ASCII alphanumerics and `_` only.
- Minimum length: 1 character.
- Maximum length: 64 characters.
- Must NOT be in `RESERVED_BINDINGS` (see section 1.8).
- Throws `"source.binding must be 1 to 64 chars of [A-Za-z0-9_]"` on violation.

Source: line 1679, 1689-1691.

### 1.7 Secrets source (`source.secrets`)

For `type === "secrets"`:

- `secrets` must be a non-empty array; throws
  `"a secrets source needs a non-empty secrets list"` otherwise (line 1681-1683).
- Each entry's `name` must be a string of 1 to 256 characters.
- Each entry's `binding` must satisfy the same regex as `source.binding` (1 to 64 chars of
  `[A-Za-z0-9_]`, not in `RESERVED_BINDINGS`).
- Throws `"each secret needs a 1 to 256 char name and a 1 to 64 char [A-Za-z0-9_] binding"`
  on violation (line 1685-1687).

Source: lines 1680-1688.

### 1.8 Reserved bindings

`RESERVED_BINDINGS` is the set of engine-own env bindings that a source (or restore target)
must never name, to prevent a confused-deputy read of the engine's own credentials or keys.
Defined at lines 1633-1654:

```
SCHEDULER, CF_ACCESS_TEAM_DOMAIN, CF_ACCESS_AUD, ADMIN_TOKEN, CONSOLE_ORIGIN,
DEST_ENDPOINT, DEST_BUCKET, DEST_REGION, DEST_ACCESS_KEY_ID, DEST_SECRET_ACCESS_KEY,
DEST_R2, DEST_KIND, SIGNER_PRIVATE, BREAK_GLASS_PUBLIC, OPERATIONAL_PUBLIC,
OPERATIONAL_PRIVATE, UPDATE_CHANNEL_URL, UPDATE_SIGNER_PUBLIC, LICENCE_TOKEN,
LICENCE_SIGNER_PUBLIC
```

The same guard is applied on the restore path (a target binding must not be in
`RESERVED_BINDINGS`); a match poisons the whole restore before any write
(`src/admin/restore.ts`, `guardTarget`, lines 65-68; enforced at line 176-181).

### 1.9 `source.include` and `source.exclude`

- Both must be arrays.
- Throws `"source.include and source.exclude must be arrays"` on violation.
- No per-element validation at the config layer; selector semantics are applied at run time.

Source: line 1692-1694.

---

## 2. RBAC Role Enumeration

Source: `src/admin/identity.ts`, function `isRole` (lines 31-33).

The role field on any write (POST /roles, POST /group-roles) must be exactly one of:

```
"viewer" | "operator" | "approver" | "owner"
```

`isRole` is the runtime guard called at the DO authority boundary before any role is stored
(scheduler-do.ts lines 748, 866). Any other string throws
`"role must be viewer/operator/approver/owner"` (line 748) or
`"role must be viewer/operator/approver/owner"` (line 866).

Role rank (higher number = more privilege):

| Role     | Rank |
|----------|------|
| viewer   | 0    |
| operator | 1    |
| approver | 2    |
| owner    | 3    |

Source: `src/admin/identity.ts` lines 22-27.

### 2.1 Group-to-role cap

A group may be mapped to `viewer`, `operator`, or `approver` only. Mapping a group to
`"owner"` is rejected at write time:

```
"a group cannot be mapped to owner; owner must be an explicit per-email grant"
```

Source: `src/sched/scheduler-do.ts` lines 869-870.

Resolution also re-applies the cap at read time: `capGroupRole` (lines 535-537) clamps a
group-conferred role to `"approver"` even if a stored entry somehow held `"owner"`.

### 2.2 Last-Owner guard

A role write (setRole or deleteRole) that would leave zero effective owners is refused with
`"would remove the last Owner"`. Counted over explicit `role:` entries only; group mappings
never contribute to the owner count.

Source: lines 764-765, 807-808.

---

## 3. Email Validation (`normaliseEmail`)

Source: `src/sched/scheduler-do.ts`, `normaliseEmail` (lines 482-492).

Applied to every email supplied to role operations:

- Input must be a string.
- Trimmed and lowercased before all checks.
- Minimum length (after trim + lowercase): 3 characters.
- Maximum length: 320 characters (RFC 5321 maximum address length).
- Must contain no whitespace.
- Must match `^[^@]+@[^@]+$` (exactly one `@`, non-empty local and domain parts).
- Returns `null` (mapped to 400 by the caller) for any failure.

Note: this is an authority-boundary sanity check, not full RFC 5322 validation; the identity
provider has already issued the identity.

---

## 4. JWT Field Checks (`verifyAccessJWT`)

Source: `src/admin/access.ts`, `verifyAccessJWT` (lines 124-201).

The following checks must all pass before a Cloudflare Access JWT is accepted:

| Check | Rule | Line |
|-------|------|------|
| Structure | Exactly 3 dot-separated parts | 125-126 |
| `alg` | Must be `"RS256"` | 140 |
| `kid` | Must be present (non-empty) | 141 |
| `typ` | If present, must be `"JWT"` (absent is accepted) | 146-148 |
| `iss` | Must equal `https://<team>.cloudflareaccess.com` | 151 |
| `aud` | Must include the configured AUD tag | 152-153 |
| `exp` | Must be a number and strictly greater than `now` | 154 |
| `nbf` | If present, must be at or before `now` | 155 |
| Team domain | Resolved host must be exactly `<single-label>.cloudflareaccess.com` | 107-119, 162-166 |
| Signature | RS256 signature must verify under a key from the JWKS endpoint | 170-180 |

The JWKS endpoint is derived from the verified issuer only after `assertCloudflareAccessHost`
confirms the host is a single-label `*.cloudflareaccess.com` subdomain (SSRF guard, V1.3.6).

### 4.1 Groups claim bounds (from signed payload)

Groups are read from the signed JWT payload only after signature verification. Bounding is
applied by `boundGroups` (lines 62-84):

- Non-array claim: treated as absent (`undefined`).
- Non-string entries: dropped.
- Each entry is trimmed; empty entries after trimming are dropped.
- Maximum length per group name: **256** characters (`GROUP_NAME_MAX`, line 51).
- Any entry containing an ASCII control character (0x00-0x1F or 0x7F) is dropped.
- Duplicates are dropped (first occurrence wins).
- Maximum groups per token: **200** (`GROUPS_MAX`, line 46).

The same bounds are independently re-applied by the DO's own `boundGroupList` (scheduler-do.ts
lines 568-579) and by `boundCallerGroups` in identity.ts (lines 170-192).

### 4.2 Identity provider hint bound

The `idp` claim, if present, must be a non-empty string after trimming and must not exceed
256 characters (`GROUP_NAME_MAX`). Otherwise it is treated as absent. Source: lines 192-193.

---

## 5. Group Name Validation (`normaliseGroup`)

Source: `src/sched/scheduler-do.ts`, `normaliseGroup` (lines 545-557).

Applied to group names at every DO write boundary (setGroupRole, deleteGroupRole, and every
ingested groups list):

- Input must be a string.
- Trimmed but NOT lowercased (group names are matched case-sensitively).
- Minimum length (after trim): 1 character.
- Maximum length: **256** characters (`GROUP_NAME_MAX`, line 183).
- Any ASCII control character (0x00-0x1F or 0x7F) causes rejection (returns `null`).
- Returns `null` (mapped to 400 by the caller) for any failure.

### 5.1 `GROUPS_MAX` and `GROUP_NAME_MAX` constants

```
GROUP_NAME_MAX = 256   // src/sched/scheduler-do.ts line 183
GROUPS_MAX     = 200   // src/sched/scheduler-do.ts line 184
```

These constants are deliberately duplicated in `access.ts` (lines 46, 51) and `identity.ts`
(lines 161, 162) so each module bounds its own inputs independently without cross-module
dependency.

---

## 6. Free-Text Fields (`validateFreeText`)

Source: `src/sched/scheduler-do.ts`, `validateFreeText` (lines 201-209).

Applied to restore-request `reason` and drill-evidence `note`.

- Maximum length: defined per field (see below).
- ASCII control characters 0x00-0x1F are rejected, except:
  - Horizontal tab (0x09): allowed.
  - Newline (0x0A): allowed.
- DEL (0x7F) is rejected.
- Returns an error string on failure (caller throws it to produce a 400).

### 6.1 `REASON_MAX_LEN` (restore request reason)

```
REASON_MAX_LEN = 1000   // src/sched/scheduler-do.ts line 192
```

The `reason` field of a restore-request (POST /restore/request) must be:

- A non-empty string after trimming (throws `"reason required"` if blank, line 1140).
- At most 1000 characters (throws `"reason must not exceed 1000 characters"`, line 202).
- No disallowed control characters (line 203-207).

### 6.2 `NOTE_MAX_LEN` (drill-evidence note)

```
NOTE_MAX_LEN = 1000   // src/sched/scheduler-do.ts line 193
```

The `note` field of a drill-evidence record (POST /drill-evidence) is optional. When present:

- Must be a string (throws `"note must be a string"` otherwise, line 1307).
- At most 1000 characters.
- No disallowed control characters.

Source: lines 1308-1311.

---

## 7. Approval TTL (`APPROVAL_TTL_MS`)

Source: `src/admin/approvals.ts` line 80.

```
APPROVAL_TTL_MS = 24 * 60 * 60 * 1000   // 24 hours
```

A restore-approval record (both `requested` and `approved` states) expires 24 hours after it
is created. Expiry is applied lazily: `effectiveStatus` (line 124-129) reports `"expired"` for
any record whose `expiresAt` is in the past without mutating storage, so a stale approval
cannot authorise an apply without a sweep. An expired record reads as `"expired"` and cannot
be re-approved (line 157); the requester must raise a new request.

The `expiresAt` timestamp is set at request time and is NOT folded into the plan-binding hash
(it is a stored fact, not a decision field), so a re-request for the same plan simply
overwrites the old record with a fresh TTL.

---

## 8. Restore `maxRecords` and `SAMPLE_CAP`

Source: `src/admin/restore.ts` lines 48-49, 159, 200, 218.

```
SAMPLE_CAP = 50   // src/admin/restore.ts line 48
```

- `maxRecords` is an optional caller-supplied cap on how many records a dry-run or apply
  processes. When provided it must be a positive integer (`>= 1`); the check is
  `body.maxRecords && body.maxRecords >= 1` (lines 159, 200, 218).
- When `maxRecords` is absent or invalid, a dry-run returns at most `SAMPLE_CAP` (50) preview
  rows in the `sample` array, but still verifies all in-scope records (line 205).
- For an applied restore without `maxRecords`, all in-scope records in the plan are written
  (no default cap on writes).

`SAMPLE_CAP` is a DO-side constant, not a client-supplied value, so it cannot be overridden by
a caller (line 159).

---

## 9. Ring and Audit Caps

### 9.1 `RING_CAP`

```
RING_CAP = 50   // src/sched/scheduler-do.ts line 246
```

The per-downpipe run-history ring held in the DO is bounded to the 50 most recent runs.
When a new run is appended (trigger, line 1544), the ring is shifted from the front if its
length exceeds `RING_CAP` (line 1545). Older entries are dropped; the durable record is the
signed RUNLOG in the archive.

### 9.2 `AUDIT_CAP`

```
AUDIT_CAP = 10000   // src/admin/audit.ts line 145
```

The tamper-evident audit chain retained in the DO is capped at 10,000 entries. Once the cap
is reached the oldest entries are rolled over (not silently dropped): the DO records the
earliest retained sequence number and the cumulative rolled-over count under `AUDIT_ROLLOVER_KEY`
(scheduler-do.ts lines 976-991). The `GET /admin/audit/verify` response surfaces this count.
The export path (GET /admin/audit/export) carries the chain head hash so an exported document
is verifiable independently of the live DO.

Near-cap warning threshold:

```
AUDIT_NEAR_CAP_FRACTION = 0.9   // src/admin/audit.ts line 149
```

`auditNearCap` is reported true when the retained entry count reaches 9,000 (90 % of cap),
giving the operator time to export before the rollover begins.

---

## 10. Webhook URL Rules (`isAllowedWebhookUrl`)

Source: `src/notify.ts`, `isAllowedWebhookUrl` (lines 212-235).

A customer-supplied webhook URL must pass all of the following checks before it is stored:

| Rule | Detail | Line |
|------|--------|------|
| Required | Must be a non-empty string | 213 |
| Maximum length | At most 2048 characters | 215 |
| Valid URL | Must parse as an absolute URL | 217-220 |
| Scheme | Must be `https:` | 222 |
| No userinfo | `username` and `password` must both be empty | 226-229 |
| Not workers.dev | `hostname` must not be `workers.dev` or end with `.workers.dev` | 231-233 |

Private/loopback addresses (localhost, RFC 1918 ranges) are not blocked by policy; an Owner
who configures such an address is making an explicit decision to route alerts to an internal
relay (noted in comments at lines 207-211).

The webhook URL is never written to the tamper-evident audit chain. A notify-channel change
reaches the chain as a config-change event carrying the closed `changeKind` enum only; the
channel's params (and with them the url) are unrepresentable on that target by design.

Outbound POST timeout:

```
WEBHOOK_TIMEOUT_MS = 5000   // src/notify.ts line 241
```

### 10.1 Accepted deviation: DNS-rebinding SSRF on outbound egress

The engine makes outbound fetches to customer-supplied hostnames on several surfaces:
webhook, Slack and Teams alert sinks; the OIDC discovery, JWKS and token endpoints; and the
SAML/IdP test probe. The host screens (`isIpLiteral`, `isInternalSinkHost` in `src/notify/types.ts`)
are literal-spelling only: they reject IP-literal hosts and known-internal names outright but do
not resolve the hostname and pin the connection to the resolved IP. A name under attacker control
that resolves (or, via a short-TTL rebind between the screen and the fetch, is made to resolve) to
`169.254.169.254` or an RFC 1918 service passes every screen and is then fetched. On a host that
exposes a metadata service this is a credential-theft SSRF; against an internal service it is a
confused-deputy.

Residual risk is bounded but real: all IP-literal hosts are rejected, so an attacker must control
DNS for a name an Owner can be induced to configure (an OIDC issuer/JWKS URL or a webhook URL) or
win a rebind race; `redirect: error` / `redirect: manual` bounds the redirect vector but not the
initial host resolution. The Cloudflare Workers `fetch` runtime does not expose a resolve-then-pin
or connect-time IP hook, so the full mitigation is not implementable on the platform today.

Status: ACCEPTED, tracked. Follow-up when the platform allows resolve-then-pin (resolve the host to
an IP, classify it with `isInternalIpv4`/`isInternalIpv6`, then fetch by the pinned IP carrying the
original Host header and SNI), or move to a connect-time IP check. References ASVS V13.2.5 /
V15.3.2.

---

## 11. Dual-Control Cross-Field Rules

### 11.1 planHash must match the recomputed hash

Source: `src/admin/approvals.ts`, `restorePlanHash` (lines 102-117).

The `planHash` supplied to POST /restore/approve, POST /restore/reject, POST /restore/gate,
and POST /restore/consume is a key into the DO's approval store. The plan-binding hash is
computed from the restore request's decision-relevant fields only (runId, target binding and
namespace/bucket names, include/exclude selectors, maxRecords) using SHA-384 over canonical
JSON. It is not re-derived from the stored record; the apply route re-derives it from the
incoming apply request and looks up the stored record by that hash, so a request whose fields
differ from the approved plan finds no matching record and the apply is refused.

The `planHash` in the POST body must be a string starting with `"sha384:"`:

```
if (typeof req.planHash !== "string" || !req.planHash.startsWith("sha384:"))
  throw new Error("planHash must be a sha384 plan-binding hash");
```

Source: scheduler-do.ts line 1138.

### 11.2 Token-fallback caller cannot be a dual-control maker

Source: scheduler-do.ts lines 1154-1155.

The bare-token (ADMIN_TOKEN) break-glass path has no attributable email, so it cannot raise a
restore request (be the maker) or approve one (be the checker). Both operations require an
attributable Access identity. Attempts throw:

- Maker: `"dual control requires an attributable identity; the bare-token fallback cannot raise a request"` (line 1155).
- Checker: `"dual control requires an attributable identity; the bare-token fallback cannot approve"` (line 1202).

### 11.3 `expiresAt` must post-date `grantedAt` (role expiry)

Source: scheduler-do.ts lines 749-752.

When `expiresAt` is supplied on a POST /roles write, it must be a valid RFC-3339 timestamp
(parseable by `Date.parse` to a finite number). The check does not enforce that it is in the
future at write time (a write of an already-past expiry is accepted and the role immediately
reads as viewer via lazy expiry); however, it must be a parseable timestamp:

```typescript
if (typeof req.expiresAt !== "string" || !Number.isFinite(Date.parse(req.expiresAt)))
  throw new Error("expiresAt must be an RFC-3339 timestamp");
```

Lazy expiry is applied by `effectiveRole` (lines 505-512): a role entry past its `expiresAt`
resolves to `"viewer"` without a storage mutation, so a time-boxed elevation self-revokes.

### 11.4 `approvedBy` must differ from `requestedBy` (maker != checker)

Source: `src/admin/approvals.ts`, `canApprove` (lines 152-161); `isUsableApproval` (lines
137-143).

A self-approval (caller email equal to `requestedBy`) is refused at approve time
(line 153-155) and also re-checked at apply time as defence in depth (isUsableApproval
line 141). The rule is enforced inside the DO's storage read-modify-write so the decision is
atomic with the write.

---

## 12. Drill Evidence Validation

Source: scheduler-do.ts, `recordDrillEvidence` (lines 1300-1322).

- `runId` must be a non-empty string after trimming (line 1305).
- `kind` must be exactly `"in-account"` or `"offline-rehearsal"` (line 1306).
- `note`, when present, must be a string (line 1307) and pass `validateFreeText` with
  `NOTE_MAX_LEN` (1000 characters, line 1309).
- Role minimum: `"operator"` (enforced by `requireRole`, line 1304).

---

## 13. In-flight Lease

```
INFLIGHT_LEASE_MS = 30 * 60 * 1000   // 30 minutes, scheduler-do.ts line 105
```

A triggered run must complete (call POST /complete) within 30 minutes. A run that holds the
in-flight flag for longer than this is treated as crashed and reclaimed by the next trigger
(its history row is resolved to `"abandoned"`, line 1537-1541). This bounds the wedge time in
the event of an evicted or redeployed Worker isolate.

---

## 14. RUNLOG Lock Lease

```
RUNLOG_LEASE_MS = 30_000   // 30 seconds, scheduler-do.ts line 241
```

The account-wide RUNLOG write lock (`runlogLock`) is held for at most 30 seconds. A lock
older than this is treated as expired and a new caller may take over (acquireRunlogLock,
lines 458-465). This bounds the RUNLOG serialisation wedge in the event of a crashed holder.

---

## 15. Audit Page Bounds

Source: `src/admin/audit.ts` lines 317-321.

```
AUDIT_PAGE_DEFAULT = 100
AUDIT_PAGE_MAX     = 500
```

A single GET /admin/audit response returns at most 500 entries regardless of the `limit`
parameter (enforced by `pageEvents` line 335). The default page size is 100. The `limit`
parameter is clamped to `[1, AUDIT_PAGE_MAX]`.

---

## 16. Alert Cooldown

```
ALERT_COOLDOWN_MS = 60 * 60 * 1000   // 1 hour, src/notify.ts line 45
STALE_CADENCE_MULTIPLE = 3            // src/notify.ts line 53
```

A downpipe in the same alertable state (failed or stale) is re-alerted at most once per hour.
A downpipe is considered stale when the last successful run started more than
`3 * cadenceSeconds` seconds ago.

State-transition alerts (a new failure or a stale-to-failed flip) are retried if delivery
fails: the DO clears the cooldown record on a failed delivery so the next reconciliation
re-qualifies the downpipe (scheduler-do.ts `markAlertsDelivered`, lines 1485-1495).

---

## 17. Rate Limits

Source: `src/sched/scheduler-do.ts` lines 265-288 (constants), lines 528-564 (`rateCheck`);
`src/admin/router.ts` lines 112-120 (router wiring), lines 707-758 (`rateLimited`).

The admin API implements per-caller anti-automation rate limiting aligned with OWASP ASVS
V2.4.1. The mechanism is a fixed-window counter maintained in the scheduler Durable Object,
checked before every mutating route.

### 17.1 Constants

```
RATE_LIMIT_MAX_PER_WINDOW = 120   // src/sched/scheduler-do.ts line 288
RATE_LIMIT_WINDOW_MS      = 60_000  // 60 seconds, line 281
```

Up to 120 mutating requests per 60-second window are admitted per caller. A fixed window was
chosen over a sliding window or token bucket deliberately: it requires one storage read and
one storage write per check on the single-threaded DO, is trivial to reason about, and the
coarse boundary behaviour (a burst can straddle two windows) is acceptable for an
authenticated admin API whose goal is anti-automation, not precise shaping (scheduler-do.ts
lines 277-280).

### 17.2 Keying strategy

The rate-limit bucket is keyed on the **verified caller identity**, never the source IP
(router.ts lines 707-715, `rateLimitKey`):

- An Cloudflare Access caller is keyed by their verified, canonicalised email:
  `email:<email>` (one bucket per identity).
- The bare-token break-glass has no attributable email; it uses a single shared `"token"`
  bucket. This caps an automated misuse of the shared token without leaking any per-IP
  signal.

A per-IP limiter is explicitly avoided because it fails closed across a shared NAT or
corporate egress gateway, harming legitimate customers (router.ts lines 709-713).

Bucket state is stored under `ratelimit:<key>` in the DO, alongside `dp:/hist:/role:/audit:`
(scheduler-do.ts lines 274, 547).

### 17.3 Gated routes (mutating POST routes only)

Only **mutating (POST) admin routes** are gated. All GET reads are exempt (router.ts
lines 122-188 show the read block, which contains no `rateLimited()` call). The gated writes
are:

`POST /admin/downpipes`, `POST /admin/downpipes/delete`, `POST /admin/trigger`,
`POST /admin/drill`, `POST /admin/restore` (both dry-run and apply),
`POST /admin/restore/request`, `POST /admin/restore/approve`, `POST /admin/restore/reject`,
`POST /admin/roles`, `POST /admin/roles/delete`,
`POST /admin/group-roles`, `POST /admin/group-roles/delete`,
`POST /admin/audit/intent`,
`POST /admin/drill-evidence`,
`POST /admin/notify/channels`, `POST /admin/notify/channels/delete`.

The check is placed **after** the caller is resolved and **after** the route has consumed the
request body, so a malformed body still produces a plain 400 rather than a 429 (router.ts
lines 112-120).

### 17.4 Response when the limit is exceeded

When a caller is over the cap, the router returns:

```
HTTP 429
Retry-After: <whole seconds until the window resets>
Content-Type: application/json

{ "error": "rate limited" }
```

`Retry-After` is in whole seconds, rounded up to the nearest second and floored at 1, so a
client never retries into a still-saturated window (router.ts lines 746-750).

`retryAfterMs` in the DO response is computed as `RATE_LIMIT_WINDOW_MS - (now - windowStart)`,
the time remaining in the current window (scheduler-do.ts lines 555-556).

A refused request does NOT increment the counter; only admitted requests count toward the
window cap (scheduler-do.ts lines 556-560).

### 17.5 Fail-open policy

If the `/rate-check` call to the scheduler DO itself throws (the DO is temporarily
unavailable), the router **admits the request** and logs a coarse `console.error`. An
unavailable limiter never blocks a verified operator's recovery action (router.ts lines
722-730, 752-758). The limiter narrows abuse on the happy path; it must not become a new
point of denial for legitimate administrators.
