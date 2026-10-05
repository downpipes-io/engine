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

The central work of a run is a full crawl of the configured source (for example a KV namespace,
R2 bucket, D1 database or Secrets Store) followed by per-record AEAD sealing and a write to the
archive destination.

**Why it is resource-bounded:** The crawl and seal are proportional to the number and size of
source records. A large KV namespace or a bucket with many large R2 objects can drive
significant CPU and memory use inside a single Worker invocation. Non-secret values above the
buffered-seal threshold are handled via a streaming two-pass path (address then seal to a
`ReadableStream`, never held whole in memory), but the cryptographic work still scales with
plaintext volume.

**Why it is time-consuming:** Cloudflare Workers cron invocations are bounded by the
platform wall-clock limit. The cron invocation runs the first slice of a run. A run that does
not finish in that slice continues in the per-downpipe seal Durable Object, which runs further
slices on alarms, each with a fresh budget. A run whose isolate dies without calling `/complete`
is reclaimed through the in-flight lease (see section 2.2).

Source: `src/seal/runstate.ts` `sealRunSliced` (line 205); `src/seal/pipeline.ts` `runBackup`
(lines 222-348); `src/crypto/streamseal.ts` `sealSegmentToStream` (lines 165-197, streaming seal
to avoid buffering a multi-GiB object; the seal pump `sealedStreamParts` holds about one `CHUNK_SIZE`
slice at a time, lines 103-137).

### 1.2 The RUNLOG single-writer bottleneck

Each destination holds one `_RECOVERY/RUNLOG`, a single append-only file that every run sealing
to that destination shares. It is written with an optimistic conditional put (`If-Match: <etag>` to extend, `If-None-Match: *`
to create); concurrent runs that lose the race re-read and retry. Its detached signature is
`_RECOVERY/RUNLOG.sig`. Before each body write the engine also puts the new signature at
`_RECOVERY/RUNLOG.sig.pending`. If a write stops after the body and before the `.sig`, the next
RUNLOG write publishes the pending signature, but only when it verifies the stored body under the
engine's own key. Readers never use the pending object, and an archive without it reads as before.
Before any write, the engine also verifies the stored RUNLOG (signature, the chain it rewrites, the
destination's floor) and refuses one that fails, so a RUNLOG it cannot vouch for stops that
destination's seals and prunes until an Owner reviews it.

**Why it is resource-bounded:** Each retry requires a `dest.get(RUNLOG_KEY)` round trip, a
re-sign of the whole log, and a new conditional put. If many concurrent runs contend
simultaneously, retries mount. The retry loop is bounded to `RUNLOG_MAX_ATTEMPTS = 6`
attempts before throwing (pipeline.ts line 19, lines 393-452).

**Why it is time-consuming:** The RUNLOG write is the last step of every run. Contention
extends a run's wall-clock duration. If all attempts are exhausted, the append throws
`RunlogContendedError` with `"RUNLOG write contended N times for run <id>"` (pipeline.ts line
451), and a sliced run parks and resumes from its checkpoint.

---

## 2. Implemented availability controls

### 2.1 Run coalescing (skip, never queue twice)

**Control:** A downpipe whose previous run is still in flight is skipped when the next cron
tick fires. `due()` leaves out a leased downpipe, and `trigger()` also returns
`{ skipped: "a previous run is still in flight (coalesced)" }`, so the cron driver allocates no
new run.

**What it prevents:** Without coalescing, a slow or large run that outlasts its cadence
interval would accumulate a backlog of queued runs that all start simultaneously when the
slow run finishes, multiplying memory use, RUNLOG write contention, and destination write
volume.

Source: `src/sched/scheduler-do-scheduling.ts` `trigger()` line 313:

```typescript
if (this.leased(ds, now)) return { skipped: "a previous run is still in flight (coalesced)" };
```

`leased()` at lines 280-282 returns `true` when `inFlight && inFlightSince !== undefined && now - inFlightSince <= INFLIGHT_LEASE_MS`.

The cron driver checks for `"skipped" in trig` and returns immediately without sealing
(`src/cron/seal-dispatch.ts:64`).

### 2.2 In-flight lease (reclaim a crashed run)

**Control:** The in-flight flag is bounded by a lease timer. A run that holds the in-flight
flag for longer than `INFLIGHT_LEASE_MS` without posting `/complete` is treated as crashed
and is re-eligible for dispatch on the next cron tick. A sliced run renews the lease through
`heartbeat()` (scheduler-do-scheduling.ts line 354), so a long seal that is still running keeps
it.

```
INFLIGHT_LEASE_MS = 30 * 60 * 1000   // 30 minutes
// src/sched/scheduler-do-records.ts line 169
```

When a leased run is reclaimed, `trigger()` resolves the orphaned in-flight history row to
`"abandoned"` and allocates a fresh run (scheduler-do-scheduling.ts lines 314-331). The RUNLOG append
is idempotent on `(runId, index)`, so a re-triggered run cannot duplicate a RUNLOG entry.

**What it prevents:** Without the lease, a Worker isolate that is evicted, hits the platform
wall-clock limit, or is redeployed mid-seal would leave the downpipe wedged in the in-flight
state permanently. With the lease, the downpipe self-heals on the first cron tick that reaches it after
`INFLIGHT_LEASE_MS` expires. With the 15-minute cron, that is normally within 45 minutes. A
blackout window or a tick that runs out of budget can defer it further.

Source: scheduler-do-records.ts line 169 (the `INFLIGHT_LEASE_MS` constant; the rationale comment
is at lines 164-168); scheduler-do-scheduling.ts lines 171 (`due()`), 284-346 (`trigger()`) and
354-366 (`heartbeat()`).

### 2.3 RUNLOG write-lock lease (reclaim a crashed lock holder)

**Control:** The per-destination RUNLOG write lock (serialised through the scheduler DO) is
held for at most `RUNLOG_LEASE_MS`. A holder that crashes without releasing the lock is
reclaimed by the next acquirer once the lease expires.

```
RUNLOG_LEASE_MS = 30_000   // 30 seconds
// src/sched/scheduler-do-records.ts line 539
```

`acquireRunlogLock()` (scheduler-do.ts lines 765-773) reads the stored lock record for that
destination and admits the new acquirer once `expiresAt` has passed. The lock write sets
`expiresAt = now + RUNLOG_LEASE_MS`. A crashed holder thus wedges the RUNLOG for at most 30
seconds.

**What it prevents:** A Worker isolate that acquires the lock and is then evicted before
releasing it would otherwise hold that destination's lock slot permanently. Every later writer
would then wait out its acquire window and fall back to the lock-free conditional write.

Source: scheduler-do-records.ts lines 537-539 (the `RUNLOG_LEASE_MS` constant); scheduler-do.ts
lines 763-780 (`acquireRunlogLock`, `releaseRunlogLock`); pipeline.ts lines 134-155
(`patientAcquire`, `RUNLOG_LOCK_ACQUIRE_ATTEMPTS = 4` at line 39) and 375-391 (`appendRunlog`,
which proceeds lock-free when the lock stays held for the whole window).

### 2.4 Segment size cap (prevent oversized single-put writes)

**Control:** A sealed segment streamed to the destination is rejected if its plaintext size
exceeds `MAX_STREAM_SEGMENT_BYTES`. The seal path splits a larger value into chained segments,
each at or below the limit, and the destination asserts the same limit as defence in depth.

```
MAX_STREAM_SEGMENT_BYTES = 1024 * 1024 * 1024   // 1 GiB
// src/dest/types.ts line 142
```

The R2 destination (`src/dest/r2.ts` `putStream`, lines 132-148; the assertion at 133-137) throws
`"segment <key> exceeds the <N>-byte single-segment limit"` when
`size > MAX_STREAM_SEGMENT_BYTES`. The S3-compatible destination asserts the same limit
(`src/dest/s3.ts` lines 537-543). From engine 0.3.7 the Azure Blob destination asserts it too
(`src/dest/azure-blob.ts` lines 407-410), before it stages a block. The S3-compatible destination uploads a segment whose sealed size is above 32 MiB, or is not known, as a SigV4
multipart upload in 32 MiB parts (`src/dest/s3-multipart.ts` lines 15 and 24; see `docs/SCALE-AND-ENTERPRISE.md`).
The R2 binding path writes each segment in one PUT. `sealRecordToDest` (`src/seal/record.ts`
lines 88-99) sends a value above the limit to the chained multi-segment path.

**What it prevents:** An unbounded single PUT to R2 (or S3) could exhaust the Worker memory
budget, cause a platform timeout, or hit destination API limits. The 1 GiB ceiling is the
format's single-segment ceiling (SPEC 14.5: `MAX_SEGMENT_CHUNKS` of 16,384 chunks of
`CHUNK_SIZE`). A segment above it fails explicitly rather than silently timing out or corrupting
the archive.

Note: the 1 GiB ceiling is an application-level constraint. The Cloudflare Workers runtime
imposes its own memory limit (128 MiB per isolate at the time of writing); a Worker sealing
a multi-GiB R2 record relies on the streaming path (`sealSegmentToStream`) to avoid holding
the full plaintext in memory. The seal pump holds roughly one `CHUNK_SIZE` (64 KiB) chunk at a
time (`src/crypto/streamseal.ts` lines 103-137; `CHUNK_SIZE = 65536`,
`src/format/version.ts:33`). The stream that `sealSegmentToStream` returns
applies backpressure: it seals the next chunk only when the destination write reads the previous
one, and its queue holds one sealed part. When the destination write is slower than the source
read, the seal waits. The seal queue is not the only memory the
write holds. The destination's own write buffer sets the rest: the S3-compatible destination
buffers up to 32 MiB (a whole segment at or below 32 MiB, or one multipart part), and the Azure
Blob destination buffers one 8 MiB block (`AZURE_BLOCK_SIZE`, `src/dest/azure-blob.ts` line 68).
The R2 binding path passes the stream through, so it holds near one sealed chunk.

Source: `src/dest/types.ts` line 142; `src/dest/r2.ts` lines 132-148; `src/crypto/streamseal.ts`
lines 165-197 (with the chunk pump at 103-137).

### 2.5 Webhook timeout (bound the SRE alert POST)

**Control:** The outbound webhook POST (SRE alerting) is bounded by a 5-second
`AbortController` timeout. A slow or hanging customer endpoint is abandoned after 5 seconds;
the alert is treated as undelivered and the next eligible tick retries.

```
WEBHOOK_TIMEOUT_MS = 5000   // src/notify/types.ts
```

`deliverPayload` (`src/notify/types.ts`) sets `setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS)`,
passes the `signal` to `fetch`, and swallows any resulting `AbortError` (or any other network
throw). The function never throws; it returns `{ ok: false }` on any failure. The generic webhook,
Slack, Teams, PagerDuty and ServiceNow channels deliver through it. JSM's own sender uses the same
`WEBHOOK_TIMEOUT_MS`, so one bound covers every HTTP alert channel. The email channel sends
through the Email binding (`src/email.ts`), and this timeout does not apply to it.

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
// src/sched/scheduler-do-limits.ts lines 650, 643
```

The limiter uses one DO storage read and at most one write per check. An over-quota caller receives
`HTTP 429` with a `Retry-After` header; the request is not processed and the counter is not
incremented. GET reads are exempt.

**What it prevents:** A scripted caller hammering the write surface (downpipe creation,
role changes, restore requests) could saturate the DO's storage write budget or drive
unbounded audit-log growth. The limiter bounds this while sitting well above any plausible
human console rate (two writes per second sustained is far above what a person clicking
through a SPA can achieve).

**Fail-open:** If the scheduler DO is unavailable when the rate-check is attempted, the
request is admitted (not blocked). An unavailable limiter must not deny legitimate recovery
operations (src/admin/router-core.ts lines 333-342; the limiter also fails open on any verdict
that is not an explicit `allowed === false`, lines 321-325).

For full detail, including keying strategy and response shape, see
[input-validation-and-limits.md, section 17](./input-validation-and-limits.md#17-rate-limits).

Source: `src/sched/scheduler-do-limits.ts` lines 643-650 (constants); `src/sched/scheduler-do.ts`
lines 797-827 (`rateCheck`); `src/admin/router-core.ts` lines 303-344 (`rateLimited`).

### 2.7 Cron-tick cadence as the dispatch bound

**Control:** The Worker `scheduled` handler fires on the Cloudflare cron trigger (configured
to `*/15 * * * *` in `wrangler.toml`, every 15 minutes). On each tick the driver asks the
scheduler DO for all enabled, non-leased, due downpipes and runs them one after another within
the same invocation. A downpipe that the invocation's subrequest budget cannot reach stays due
for the next tick.

**What this means for scheduling precision:** A downpipe with a cadence shorter than 15
minutes will not be dispatched more frequently than the cron interval allows. The scheduler
DO's `alarm()` (scheduler-do-scheduling.ts line 761) runs storage sweeps, re-arms, and then runs
the cron dead-man check. It does not dispatch a seal, because the engine is not wired as a service
binding to itself.

**What it bounds:** The cron interval is the dispatch latency for a due downpipe that the
tick's budget reaches. It is not an application-level guarantee; it is inherited from
the Cloudflare Workers cron-trigger platform behaviour.

Source: `src/index.ts` line 453 (`scheduled` handler); `src/sched/scheduler-do-scheduling.ts`
lines 761 (`alarm()`) and 802 (`rearmAlarm()`); `wrangler.toml` line 198 (cron schedule).

---

## 3. Cloudflare Workers runtime bounds (not application-controlled)

The following limits are enforced by the Cloudflare Workers platform and are not application
constants. They are documented here for completeness because they interact with the
application-level controls above.

| Limit | Platform behaviour | Interaction with engine controls |
|-------|--------------------|----------------------------------|
| CPU time per invocation | Workers enforces a per-invocation CPU limit (free: 10 ms; paid: 30 s by default; cron: up to 15 min wall clock). The engine's `wrangler.toml` sets `cpu_ms = 300000` (5 min). An invocation that exceeds this is terminated without calling `/complete`. | A sliced run continues in the seal DO. The in-flight lease (section 2.2) reclaims a wedged downpipe. |
| Memory per isolate | 128 MiB. | The seal pump behind `sealSegmentToStream` holds about one 64 KiB chunk at a time for large records (up to `MAX_STREAM_SEGMENT_BYTES` per segment). From engine 0.3.7 the returned stream applies backpressure, so a slow destination write makes the seal wait instead of queueing sealed chunks in memory. The destination's own write buffer adds up to 32 MiB on S3 and 8 MiB on Azure Blob (section 2.4). |
| Durable Object storage per key | 128 KiB per value. | A run-history ring is one key, bounded by `RING_CAP = 50` entries. The audit chain stores one entry per key and is capped at `AUDIT_CAP = 10,000` entries, which bounds its total storage. |
| R2 single-object PUT | R2 accepts up to 5 GiB in a single PUT. | The format imposes a stricter 1 GiB segment ceiling (`MAX_STREAM_SEGMENT_BYTES`). The R2 binding path writes each segment in one PUT; the S3-compatible destination uses SigV4 multipart (src/dest/s3.ts). A larger value is split into chained segments, and a single segment above 1 GiB fails with a clear error. |

---

## 4. Mapping controls to V15.2.2

The table below maps each implemented availability control to the specific risk it addresses,
closing V15.2.2.

| Control | Risk addressed | Source reference |
|---------|---------------|------------------|
| Run coalescing | Prevents queued-run pile-up when a slow run outlasts its cadence interval; bounds concurrent RUNLOG write contention and destination write volume | scheduler-do-scheduling.ts line 313 |
| In-flight lease (`INFLIGHT_LEASE_MS = 30 min`) | Reclaims a Worker invocation that is evicted or terminated mid-seal; prevents a permanently wedged downpipe | scheduler-do-records.ts line 169; scheduler-do-scheduling.ts lines 171-365 |
| RUNLOG write-lock lease (`RUNLOG_LEASE_MS = 30 s`) | Reclaims a RUNLOG lock whose holder was evicted; prevents a permanently held lock slot | scheduler-do-records.ts line 539; scheduler-do.ts lines 765-782 |
| Segment size cap (`MAX_STREAM_SEGMENT_BYTES = 1 GiB`) | Prevents an oversized single-object write from exhausting Worker memory or hitting a destination API limit | dest/types.ts line 142; dest/r2.ts lines 132-148; dest/s3.ts lines 537-543; dest/azure-blob.ts lines 407-410 |
| Webhook timeout (`WEBHOOK_TIMEOUT_MS = 5 s`) | Prevents a slow customer endpoint from stalling the alerting block and consuming the cron invocation | notify/types.ts lines 881, 911 |
| Per-caller rate limit (120 req / 60 s) | Bounds scripted write volume against the admin API; limits unbounded DO storage writes and audit-log growth | scheduler-do-limits.ts lines 643, 650; router-core.ts lines 303-344 |
| Cron-tick cadence (platform-bound) | Establishes the maximum dispatch latency and the minimum gap between successive ticks of the reconciliation loop | index.ts line 453; wrangler.toml line 198 |
