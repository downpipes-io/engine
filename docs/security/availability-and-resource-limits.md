# Availability and Resource Limits

This document describes the architecture-level availability strategy for the downpipe engine,
identifies the time-consuming and resource-bounded operations, and maps each implemented
control to the risk it addresses. All statements are grounded in the source; file:line
citations are given for each control. Aspirational or unimplemented mitigations are not
listed here.

The document closes ASVS V15.1.3 (identify and document the resource-consuming or
time-consuming operations) and V15.2.2 (document the strategies that prevent consumer
timeout and resource exhaustion).

---

## 1. Resource-bounded and time-consuming operations

### 1.1 Per-run AEAD seal over KV/R2 sweeps

The central work of a run is a full crawl of the configured source (KV namespace, R2 bucket,
D1 database, or Secrets Store) followed by per-record AEAD sealing and a write to the
archive destination.

**Why it is resource-bounded:** The crawl and seal are proportional to the number and size of
source records. A large KV namespace or a bucket with many large R2 objects can drive
significant CPU and memory use inside a single Worker invocation. Non-secret values above the
buffered-seal threshold are handled via a streaming two-pass path (address then seal to a
`ReadableStream`, never held whole in memory), but the cryptographic work still scales with
plaintext volume.

**Why it is time-consuming:** Cloudflare Workers cron invocations are bounded by the
platform wall-clock limit. A run that cannot complete within a single invocation's allowed
time budget terminates without calling `/complete`, which triggers the in-flight lease
reclaim path (see section 3.2).

Source: `src/seal/pipeline.ts` `runBackup` (lines 62-124); `src/crypto/streamseal.ts`
`sealSegmentToStream` (lines 115-129, streaming seal to avoid buffering a multi-GiB object;
the chunk pump holds one `CHUNK_SIZE` slice at a time, lines 81-84).

### 1.2 The RUNLOG single-writer bottleneck

The account-wide `_RECOVERY/RUNLOG` is a single append-only file that all runs share. It is
written with an optimistic conditional put (`If-Match: <etag>` to extend, `If-None-Match: *`
to create); concurrent runs that lose the race re-read and retry.

**Why it is resource-bounded:** Each retry requires a `dest.get(RUNLOG_KEY)` round trip, a
re-sign of the whole log, and a new conditional put. If many concurrent runs contend
simultaneously, retries mount. The retry loop is bounded to `RUNLOG_MAX_ATTEMPTS = 6`
attempts before throwing (pipeline.ts line 15, lines 155-177).

**Why it is time-consuming:** The RUNLOG write is the last step of every run. Contention
extends a run's wall-clock duration and, if all attempts are exhausted, fails the run with
`"RUNLOG write contended N times for run <id>"` (pipeline.ts line 177).

---

## 2. Implemented availability controls

### 2.1 Run coalescing (skip, never queue twice)

**Control:** A downpipe whose previous run is still in flight is skipped when the next cron
tick fires. The scheduler DO returns `{ skipped: "a previous run is still in flight (coalesced)" }`
from `trigger()` and the cron driver returns early without allocating a new run or any extra
work.

**What it prevents:** Without coalescing, a slow or large run that outlasts its cadence
interval would accumulate a backlog of queued runs that all start simultaneously when the
slow run finishes, multiplying memory use, RUNLOG write contention, and destination write
volume.

Source: `src/sched/scheduler-do.ts` `trigger()` line 4768:

```typescript
if (this.leased(ds, now)) return { skipped: "a previous run is still in flight (coalesced)" };
```

`leased()` at lines 4758-4759 returns `true` when `inFlight && inFlightSince !== undefined && now - inFlightSince <= INFLIGHT_LEASE_MS`.

The cron driver in `src/index.ts` checks for `"skipped" in trig` and returns immediately
without sealing (`src/cron/seal-dispatch.ts:65`).

### 2.2 In-flight lease (reclaim a crashed run)

**Control:** The in-flight flag is bounded by a lease timer. A run that holds the in-flight
flag for longer than `INFLIGHT_LEASE_MS` without posting `/complete` is treated as crashed
and is re-eligible for dispatch on the next cron tick.

```
INFLIGHT_LEASE_MS = 30 * 60 * 1000   // 30 minutes
// src/sched/scheduler-do.ts line 373
```

When a leased run is reclaimed, `trigger()` resolves the orphaned in-flight history row to
`"abandoned"` and allocates a fresh run (scheduler-do.ts lines 4773-4788). The RUNLOG append
is idempotent on `(runId, index)`, so a re-triggered run cannot duplicate a RUNLOG entry.

**What it prevents:** Without the lease, a Worker isolate that is evicted, hits the platform
wall-clock limit, or is redeployed mid-seal would leave the downpipe wedged in the in-flight
state permanently. With the lease, the downpipe self-heals within roughly two cron-tick
intervals (at most `2 * INFLIGHT_LEASE_MS / cron_interval` minutes in the worst case).

Source: scheduler-do.ts line 373 (the `INFLIGHT_LEASE_MS` constant; the rationale comment is
at lines 369-373), lines 4748-4798 (`due()` and `trigger()`).

### 2.3 RUNLOG write-lock lease (reclaim a crashed lock holder)

**Control:** The account-wide RUNLOG write lock (serialised through the scheduler DO) is
held for at most `RUNLOG_LEASE_MS`. A holder that crashes without releasing the lock is
reclaimed by the next acquirer once the lease expires.

```
RUNLOG_LEASE_MS = 30_000   // 30 seconds
// src/sched/scheduler-do.ts line 601
```

`acquireRunlogLock()` (scheduler-do.ts lines 1285-1292) reads the stored lock record and
admits the new acquirer if `now > expiresAt`. The lock write sets
`expiresAt = now + RUNLOG_LEASE_MS`. A crashed holder thus wedges the RUNLOG for at most 30
seconds.

**What it prevents:** A Worker isolate that acquires the lock and is then evicted before
releasing it would otherwise serialise all subsequent RUNLOG writes behind a permanent
phantom lock holder, causing every run's final step to fail.

Source: scheduler-do.ts lines 599-601 (the `RUNLOG_LEASE_MS` constant), lines 1285-1298
(`acquireRunlogLock`, `releaseRunlogLock`); pipeline.ts lines 140-152 (`appendRunlog`, the
three-attempt best-effort lock acquire at line 145).

### 2.4 Segment size cap (prevent oversized single-put writes)

**Control:** A sealed segment streamed to the destination is rejected if its plaintext size
exceeds `MAX_STREAM_SEGMENT_BYTES`. The source caps the value before streaming and the
destination asserts the same limit as defence in depth.

```
MAX_STREAM_SEGMENT_BYTES = 1024 * 1024 * 1024   // 1 GiB
// src/dest/types.ts line 20
```

The R2 destination (`src/dest/r2.ts` `putStream`, lines 74-98; the assertion at 75-76) throws
`"segment <key> exceeds the <N>-byte single-segment limit"` when
`size > MAX_STREAM_SEGMENT_BYTES`. A SigV4 multipart upload path is now implemented for the
S3-compatible destination (src/dest/s3.ts, 32 MiB parts, lines 15-16; see
SCALE-AND-ENTERPRISE.md); the R2 binding path has no multipart, so a source that would emit a
segment above this ceiling on R2 must be chunked at the source level.

**What it prevents:** An unbounded single PUT to R2 (or S3) could exhaust the Worker memory
budget, cause a platform timeout, or hit destination API limits. The 1 GiB ceiling is the
maximum the streaming path can deliver in a single object write without multipart; any value
above it fails explicitly rather than silently timing out or corrupting the archive.

Note: the 1 GiB ceiling is an application-level constraint. The Cloudflare Workers runtime
imposes its own memory limit (128 MiB per isolate at the time of writing); a Worker sealing
a multi-GiB R2 record relies on the streaming path (`sealSegmentToStream`) to avoid holding
the full plaintext in memory. The streaming path holds roughly one `CHUNK_SIZE` (64 KiB)
chunk at a time (`src/crypto/streamseal.ts` lines 81-84; `CHUNK_SIZE = 65536`,
`src/format/version.ts:14`). The ceiling in `MAX_STREAM_SEGMENT_BYTES` is therefore a
practical upper bound on what the R2 API accepts in one PUT, not what the runtime can hold.

Source: `src/dest/types.ts` line 20; `src/dest/r2.ts` lines 74-98; `src/crypto/streamseal.ts`
lines 115-129 (with the chunk pump at 81-84).

### 2.5 Webhook timeout (bound the SRE alert POST)

**Control:** The outbound webhook POST (SRE alerting) is bounded by a 5-second
`AbortController` timeout. A slow or hanging customer endpoint is abandoned after 5 seconds;
the alert is treated as undelivered and the next eligible tick retries.

```
WEBHOOK_TIMEOUT_MS = 5000   // src/notify/types.ts
```

`deliverPayload` (`src/notify/types.ts`) sets `setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS)`,
passes the `signal` to `fetch`, and swallows any resulting `AbortError` (or any other network
throw). The function never throws; it returns `{ ok: false }` on any failure. Every url-bearing
notify channel (generic webhook, Slack, Teams, PagerDuty, JSM, ServiceNow) delivers through it, so
one bound covers the whole outbound alert surface.

**What it prevents:** An unresponsive customer endpoint would stall the reconciliation tick's
alerting block, delaying the cron's return. Because the alert pass runs under
`ctx.waitUntil(drive(env))` and after the backup loop, a stall here cannot delay a
backup run, but it could hold the cron invocation open well past its useful life and consume
CPU. The 5-second bound ensures the alerting block always terminates quickly.

**Fail-open:** An alert is observability, never a control. A timeout or delivery failure
never blocks, delays, or fails a backup.

Source: `src/notify/types.ts` (`WEBHOOK_TIMEOUT_MS`, `deliverPayload`);
`src/cron/alert-passes.ts` (`runAlertPass`, the guarded alerting block `drive()` calls).

### 2.6 Per-caller rate limit (bound mutating write volume)

**Control:** Every mutating (POST) admin route is gated by a per-caller fixed-window rate
limiter: at most 120 requests per 60-second window per verified caller identity.

```
RATE_LIMIT_MAX_PER_WINDOW = 120
RATE_LIMIT_WINDOW_MS      = 60_000  // 60 seconds
// src/sched/scheduler-do.ts lines 634, 627
```

The limiter uses one DO storage read and one write per check. An over-quota caller receives
`HTTP 429` with a `Retry-After` header; the request is not processed and the counter is not
incremented. GET reads are exempt.

**What it prevents:** A scripted caller hammering the write surface (downpipe creation,
role changes, restore requests) could saturate the DO's storage write budget or drive
unbounded audit-log growth. The limiter bounds this while sitting well above any plausible
human console rate (two writes per second sustained is far above what a person clicking
through a SPA can achieve).

**Fail-open:** If the scheduler DO is unavailable when the rate-check is attempted, the
request is admitted (not blocked). An unavailable limiter must not deny legitimate recovery
operations (src/admin/router.ts lines 1905-1911; the limiter also fails open on any verdict
that is not an explicit `allowed === false`, line 1896).

For full detail, including keying strategy and response shape, see
[input-validation-and-limits.md, section 17](./input-validation-and-limits.md#17-rate-limits).

Source: `src/sched/scheduler-do.ts` lines 604-646 (constants), 1301-1340 (`rateCheck`);
`src/admin/router.ts` lines 1883-1912 (`rateLimited`).

### 2.7 Cron-tick cadence as the dispatch bound

**Control:** The Worker `scheduled` handler fires on the Cloudflare cron trigger (configured
to `*/15 * * * *` in `wrangler.toml`, every 15 minutes). On each tick the driver asks the
scheduler DO for all enabled, non-leased, due downpipes and runs each one sequentially within
the same invocation.

**What this means for scheduling precision:** A downpipe with a cadence shorter than 15
minutes will not be dispatched more frequently than the cron interval allows. Precise
sub-cron-interval dispatch via DO alarms (the `alarm()` path in scheduler-do.ts lines
4910-4929) is implemented in the DO but the alarm currently only re-arms the next wake time;
it does not yet dispatch the seal because the engine is not wired as a service binding to
itself. This is noted in the source as a deferred refinement (scheduler-do.ts line 4925).

**What it bounds:** The cron interval is the worst-case dispatch latency for a due downpipe
when no DO alarm fires early. It is not an application-level guarantee; it is inherited from
the Cloudflare Workers cron-trigger platform behaviour.

Source: `src/index.ts` line 154 (`scheduled` handler); `src/sched/scheduler-do.ts` lines
4910-4929 (`alarm()`, `rearmAlarm()`); `wrangler.toml` (cron schedule).

---

## 3. Cloudflare Workers runtime bounds (not application-controlled)

The following limits are enforced by the Cloudflare Workers platform and are not application
constants. They are documented here for completeness because they interact with the
application-level controls above.

| Limit | Platform behaviour | Interaction with engine controls |
|-------|--------------------|----------------------------------|
| CPU time per invocation | Workers enforces a per-invocation CPU limit (free: 10 ms; paid: up to 30 s; cron: up to 15 min wall clock). A run that exceeds this is terminated without calling `/complete`. | The in-flight lease (section 2.2) reclaims the wedged downpipe on the next tick. |
| Memory per isolate | 128 MiB. | The streaming seal path (`sealSegmentToStream`) holds one 64 KiB chunk at a time for large R2 records, keeping memory use flat regardless of segment size (up to `MAX_STREAM_SEGMENT_BYTES`). |
| Durable Object storage per key | 128 KiB per value. | Run-history rings are bounded by `RING_CAP = 50` entries; audit chains by `AUDIT_CAP = 10 000`. Both prevent the DO from approaching per-key limits under normal operation. |
| R2 single-object PUT | R2 accepts up to 5 GiB in a single PUT. | The application imposes a stricter 1 GiB ceiling (`MAX_STREAM_SEGMENT_BYTES`) on the R2 binding path, which has no multipart. (The S3-compatible destination does upload via SigV4 multipart, src/dest/s3.ts.) An object above 1 GiB on R2 fails with a clear error rather than a silent platform rejection. |

---

## 4. Mapping controls to V15.2.2

The table below maps each implemented availability control to the specific risk it addresses,
closing V15.2.2.

| Control | Risk addressed | Source reference |
|---------|---------------|------------------|
| Run coalescing | Prevents queued-run pile-up when a slow run outlasts its cadence interval; bounds concurrent RUNLOG write contention and destination write volume | scheduler-do.ts line 4768 |
| In-flight lease (`INFLIGHT_LEASE_MS = 30 min`) | Reclaims a Worker invocation that is evicted or terminated mid-seal; prevents a permanently wedged downpipe | scheduler-do.ts lines 373, 4748-4798 |
| RUNLOG write-lock lease (`RUNLOG_LEASE_MS = 30 s`) | Reclaims a RUNLOG lock whose holder was evicted; prevents a permanently serialised RUNLOG | scheduler-do.ts line 601, lines 1285-1298 |
| Segment size cap (`MAX_STREAM_SEGMENT_BYTES = 1 GiB`) | Prevents an oversized single-object write from exhausting Worker memory or hitting a destination API limit | dest/types.ts line 20; dest/r2.ts lines 74-98 |
| Webhook timeout (`WEBHOOK_TIMEOUT_MS = 5 s`) | Prevents a slow customer endpoint from stalling the alerting block and consuming the cron invocation | notify.ts lines 246, 254-277 |
| Per-caller rate limit (120 req / 60 s) | Bounds scripted write volume against the admin API; limits unbounded DO storage writes and audit-log growth | scheduler-do.ts lines 627, 634; router.ts lines 1883-1912 |
| Cron-tick cadence (platform-bound) | Establishes the maximum dispatch latency and the minimum gap between successive ticks of the reconciliation loop | index.ts line 154; wrangler.toml |
