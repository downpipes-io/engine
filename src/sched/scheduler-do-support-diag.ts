// SupportDiagMixin: the SchedulerDO's DIAGNOSTIC RECORDERS + READ PATHS for the CRON and ADMIN subsystems
// (support-pack gap audit, gaps G163, G049, G158, G100/G331). It is the sibling of
// scheduler-do-diag.ts (which owns the SCHEDULER's own storage/housekeeping/state-refusal recorders) and it
// follows that module's shape exactly: classify into a CLOSED vocabulary, clamp everything, write a bounded
// counter or stamp, and NEVER let the observation break the path it observed.
//
// What each recorder exists for:
//   recordSealError    (G163) a PRE-RUN seal dispatch throw -- the destination record a downpipe pins was
//                      deleted, the /trigger round-trip faulted, or the lock-clear itself failed. The throw
//                      lands BEFORE a run index is allocated, so the loop's /complete is a runId-"" history
//                      no-op: run history shows a GAP and the pack shows only an anonymous sealErrors integer.
//                      This ATTRIBUTES the fault to the downpipe and names its closed cause.
//   recordMetricsScrape(G049) the Prometheus /metrics scrape surface's own health: a DO hiccup that is
//                      reported to the scraper as a 401, an expired metrics credential, a SHAPE fallback that
//                      empties every series while up == 1, and a pull-trail write that keeps failing (so a
//                      live scrape reads as abandoned).
//   recordWebauthnFault(G158) the 14 structural CBOR/COSE/DER/authData defects that all coarsen to the one
//                      ceremony reason "bad_request" today, split by ceremony PHASE -- which is what tells an
//                      Ed25519-only key fleet that can never enrol from ONE user's CORRUPTED STORED key
//                      (login re-decodes the stored key through the same parser).
//   recordDroppedWrites(G100/G331) THE META-FINDING: the diagnostic recorders' own dropped writes, so the
//                      pack stops under-counting during the exact outage it is meant to explain.
//
// Every field written here is a count, a clamped integer, a closed enum, a clamped timestamp, or the
// customer's OWN opaque downpipe id (the class the pack already carries in downpipes[] and sealFaults). A raw
// error message, a stack, a key, a secret, a bearer, an endpoint or a customer value NEVER rides.

import { ADMIN_COUNTERS_KEY, ADMIN_REFUSALS_KEY, ADMIN_ROUTE_ERRORS_KEY, type AdminCounterName, type AdminCounters, type AdminRefusals, type AdminRouteErrors, applyAdminCounters, applyAdminRefusal, applyAdminRouteError, applyBindingAlarm, applyCostSizing, applyDestProbeFaultsCounted, applyDispatchFault, applyDroppedWrites, applyExportAttempt, applyIntegrityFaultsCounted, applyMetricsScrape, applyRecoveryRefusal, applyRestoreFault, applySealErrorStamp, applyUnwrapFault, applyUpdateFault, applyWebauthnFault, BINDING_ALARMS_KEY, type BindingAlarmRow, COST_SIZING_KEY, type CostSizing, DEST_PROBE_FAULTS_KEY, type DestProbeFaults, DISPATCH_FAULTS_KEY, type DispatchFaultRow, DROPPED_WRITES_KEY, type DroppedWrites, EXPORT_ATTEMPTS_KEY, type ExportAttempts, INTEGRITY_FAULTS_KEY, type IntegrityFaults, METRICS_HEALTH_KEY, type MetricsHealth, RECOVERY_REFUSALS_KEY, RESTORE_FAULT_ROWS_PER_OP, RESTORE_FAULTS_KEY, type RecoveryRefusals, type RestoreFaultRow, SEAL_ERROR_CLASSES, SEAL_ERROR_PREFIX, type SealErrorClass, type SealErrorStamp, UNWRAP_FAULTS_KEY, type UnwrapFaults, UPDATE_FAULTS_KEY, UPDATE_FAULTS_RING_CAP, type UpdateFaultRow, WEBAUTHN_FAULTS_KEY, type WebauthnFaults } from "../admin/diag-records.ts";
import { ATTACH_HEALTH_KEY, type AttachHealth, applyAttachHealth, applyDiscoveryHealth, applyDiscoveryTokenSet, DISCOVERY_HEALTH_KEY, DISCOVERY_TOKEN_SET_KEY, type DiscoveryHealth, type DiscoveryTokenSet } from "../admin/discovery-health.ts";
import { applyIdpCertHealth, IDP_CERT_HEALTH_KEY, type IdpCertHealth } from "../admin/idp-cert-health.ts";
import {
  applyDestFaults,
  applySourceFaults,
  DEST_FAULTS_KEY,
  type DestFaults,
  SOURCE_FAULTS_KEY,
  type SourceFaults,
} from "../admin/run-fault-records.ts";
import { applyCronHealth, CRON_HEALTH_KEY, type CronHealth, emptyCronHealth } from "../cron/cron-fault-ledger.ts";
import { applyDestBuildHealth, DEST_BUILD_HEALTH_KEY, type DestBuildHealth } from "../dest/build-health.ts";
import { flushDroppedWrites, type GovernanceRefusalReason, type GovernanceRefusalStage, noteDroppedDiagWrite, recordAuthzRefusal, recordCapTruncation, recordGovernanceRefusal, recordTestOutcome } from "./sched-fault-ledger.ts";

import type { SchedulerDOCtor } from "./scheduler-do-base.ts";
import { safeDownpipeId } from "./scheduler-helpers.ts";

const SEAL_ERROR_CLASS_SET: ReadonlySet<string> = new Set(SEAL_ERROR_CLASSES);

// The per-downpipe seal-error read is bounded: a fleet cannot make this read unbounded, and the pack carries
// a bounded projection. Well above any real fleet's FAULTING subset (only faulting downpipes hold a stamp).
const SEAL_ERROR_READ_MAX = 500;

// ADMIN_COUNTER_THROTTLE_MS bounds how often a HOT-READ-PATH admin counter may hit storage. It mirrors
// AUTH_SIGNAL_THROTTLE_MS exactly (scheduler-do-idp.ts) and exists for the same reason: a corrupt stored
// approval, expiry row or custom role is read back on EVERY request that touches it (the RBAC authority
// resolution runs on every authenticated request), so an unthrottled counter would turn one bad record into a
// storage write per request, for ever. One minute: long enough that the cost is one write a minute, short
// enough that is it still happening stays answerable from the count.
const ADMIN_COUNTER_THROTTLE_MS = 60_000;

export function SupportDiagMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- G163: per-downpipe pre-run seal errors ---------------------------------------------------------

    // recordSealError STAMPS one downpipe's most recent pre-run dispatch fault (closed class + a clamped time
    // + a consecutive count). Best-effort and never throwing, exactly like recordStorageFault: observing a
    // fault must never break the path that hit it (the cron loop already logged and moved on). The id is run
    // through safeDownpipeId, so a malformed id can never become a storage key.
    async recordSealError(downpipeId: unknown, cls: unknown): Promise<{ ok: true }> {
      try {
        const id = safeDownpipeId(downpipeId);
        if (id === null) return { ok: true };
        if (typeof cls !== "string" || !SEAL_ERROR_CLASS_SET.has(cls)) return { ok: true }; // out-of-vocabulary: DROP, never persist
        const key = `${SEAL_ERROR_PREFIX}${id}`;
        const prior = await this.state.storage.get<SealErrorStamp>(key);
        await this.state.storage.put(key, applySealErrorStamp(prior, cls as SealErrorClass, Date.now()));
      } catch {
        /* best-effort: a fault WHILE recording a fault must not mask the original */
      }
      return { ok: true };
    }

    // sealErrors returns the per-downpipe last-seal-error stamps for the pack (GET /seal-errors), keyed by the
    // customer's own downpipe id. Redaction-safe by construction (a closed class + a clamped time + a count).
    // Empty on a healthy fleet: only a downpipe whose dispatch THREW before its run index was allocated holds
    // a stamp. The stamp is deliberately NOT cleared by a later successful dispatch (clearing would cost one
    // extra DO round-trip per downpipe per tick on the hot seal loop): it is a LAST-seal-error, and the pack
    // reads its `at` against the downpipe's newest successful run to tell a live fault from a healed one.
    async sealErrors(): Promise<{ byDownpipe: Record<string, SealErrorStamp> }> {
      const map = await this.state.storage.list<SealErrorStamp>({ prefix: SEAL_ERROR_PREFIX, limit: SEAL_ERROR_READ_MAX });
      const byDownpipe: Record<string, SealErrorStamp> = {};
      for (const [key, stamp] of map) byDownpipe[key.slice(SEAL_ERROR_PREFIX.length)] = stamp;
      return { byDownpipe };
    }

    // ---- G049: the Prometheus /metrics scrape surface ---------------------------------------------------

    // recordMetricsScrape folds ONE scrape observation (closed outcome + the two cumulative counters) into the
    // bounded health record. Best-effort and never throwing: the scrape response is already decided and must
    // never be delayed or failed by its own observation.
    async recordMetricsScrape(body: { outcome?: unknown; shapeFallback?: unknown; pullFailed?: unknown }): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<MetricsHealth>(METRICS_HEALTH_KEY);
        const next = applyMetricsScrape(prior, typeof body.outcome === "string" ? body.outcome : "", Date.now(), {
          shapeFallback: body.shapeFallback === true,
          pullFailed: body.pullFailed === true,
        });
        await this.state.storage.put(METRICS_HEALTH_KEY, next);
      } catch {
        /* best-effort */
      }
      return { ok: true };
    }

    // metricsHealth is the pack read (GET /metrics-health). Closed outcome enums + counts + a clamped time;
    // never a bearer, a clientId or an endpoint. Null until a scrape has been attempted at all (which is
    // itself the answer to "is anything even scraping us?").
    async metricsHealth(): Promise<{ health: MetricsHealth | null }> {
      return { health: (await this.state.storage.get<MetricsHealth>(METRICS_HEALTH_KEY)) ?? null };
    }

    // ---- G158: the structural WebAuthn fault classes ----------------------------------------------------

    // recordWebauthnFault bumps ONE "<phase>:<class>" counter in the bounded aggregate (and records the
    // offered COSE alg int for cose-unsupported-alg). Best-effort and never throwing: the ceremony has already
    // been refused and its COARSE client-facing reason is unchanged, so recording the structural class here
    // never oracles anything back to the caller. An out-of-vocabulary phase/class is dropped by
    // applyWebauthnFault (defence in depth: the key space is bounded by the two closed sets).
    async recordWebauthnFault(phase: string, cls: string, coseAlg?: number): Promise<void> {
      try {
        const prior = await this.state.storage.get<WebauthnFaults>(WEBAUTHN_FAULTS_KEY);
        await this.state.storage.put(WEBAUTHN_FAULTS_KEY, applyWebauthnFault(prior, phase, cls, new Date().toISOString(), coseAlg));
        await flushDroppedWrites(this.state.storage);
      } catch {
        // G104: the `webauthn-fault` droppedWrites kind was declared for exactly this catch and never wired, so
        // a storage fault here made the counter vanish in silence -- and the window in which this recorder is
        // MOST likely to fail (a DO under stress) is the window in which a total-lockout investigation most
        // needs it. A pack that shows an EMPTY WebAuthn aggregate during a lockout, with nothing saying the
        // aggregate itself could not be written, is the worst reading available: it says the ceremonies were
        // fine. The auth path is unchanged (still best-effort, still never throwing); the loss is now counted,
        // in memory, and folded into the shared aggregate by the next write that succeeds.
        noteDroppedDiagWrite(this.state.storage, "webauthn-fault");
      }
    }

    // readWebauthnFaults is the pack read (GET /webauthn-faults). Closed "<phase>:<class>" keys, int counts,
    // timestamps and IANA COSE alg integers; never a credential id, a public key or a user.
    async readWebauthnFaults(): Promise<WebauthnFaults> {
      return (await this.state.storage.get<WebauthnFaults>(WEBAUTHN_FAULTS_KEY)) ?? {};
    }

    // ---- G100 / G331: the recorders' own dropped writes -------------------------------------------------

    // recordDroppedWrites folds a FLUSHED writer-side tally ({closed kind: int count}) into the bounded
    // aggregate. applyDroppedWrites is the redaction chokepoint (an out-of-vocabulary kind is dropped, every
    // count is clamped), so a malformed or hostile body can neither add a key nor fabricate an unbounded loss
    // claim. Best-effort and never throwing.
    async recordDroppedWrites(body: { drops?: unknown }): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<DroppedWrites>(DROPPED_WRITES_KEY);
        await this.state.storage.put(DROPPED_WRITES_KEY, applyDroppedWrites(prior, body.drops, new Date().toISOString()));
      } catch {
        /* best-effort: if THIS write is dropped too, the writer re-pends its tally and a later flush lands it */
      }
      return { ok: true };
    }

    // readDroppedWrites is the pack read (GET /dropped-writes). Closed kind keys + int counts + timestamps.
    // Empty is the healthy steady state; ANY non-zero count means the pack you are holding is INCOMPLETE by
    // that many records, and says of which kind.
    async readDroppedWrites(): Promise<DroppedWrites> {
      return (await this.state.storage.get<DroppedWrites>(DROPPED_WRITES_KEY)) ?? {};
    }

    // ---- G070: the restore / drill / verify fault ring ---------------------------------------------------

    // recordRestoreFaults folds the Worker edge's PROJECTED rows (already aggregated by phase+class and
    // capped) into the bounded ring. applyRestoreFault is the redaction chokepoint: it re-validates EVERY
    // field on the DO side (out-of-vocabulary op/phase/class dropped, record label control-stripped and
    // clamped to 128, errId accepted only as 8 lower-case hex digits), so even a compromised or drifted
    // caller cannot land a raw provider message in the record. The posted array is itself capped, so one
    // pathological restore cannot flood the ring. Best-effort and never throwing.
    async recordRestoreFaults(body: { rows?: unknown }): Promise<{ ok: true }> {
      try {
        const rows = Array.isArray(body.rows) ? body.rows.slice(0, RESTORE_FAULT_ROWS_PER_OP) : [];
        if (rows.length === 0) return { ok: true };
        let ring = (await this.state.storage.get<RestoreFaultRow[]>(RESTORE_FAULTS_KEY)) ?? [];
        const now = Date.now();
        for (const row of rows) ring = applyRestoreFault(ring, row, now);
        await this.state.storage.put(RESTORE_FAULTS_KEY, ring);
      } catch {
        /* best-effort: a fault WHILE recording a restore fault must not mask the restore's own outcome */
      }
      return { ok: true };
    }

    // readRestoreFaults is the pack read (GET /restore-faults): the bounded ring, oldest-first. Closed enums,
    // clamped record labels, the 8-hex Workers-Logs join key and int counts only. Empty is the healthy steady
    // state: a row here means a restore, drill or verify FAILED, and names the phase and the mode.
    async readRestoreFaults(): Promise<{ faults: RestoreFaultRow[] }> {
      return { faults: (await this.state.storage.get<RestoreFaultRow[]>(RESTORE_FAULTS_KEY)) ?? [] };
    }

    // ---- G080 / G081 / G082: the admin diagnostic counters -----------------------------------------------

    // recordAdminCounters folds a posted {closed name: int count} tally into the bounded aggregate.
    // applyAdminCounters is the redaction chokepoint (an out-of-vocabulary name is dropped, every count is
    // clamped), so a malformed or hostile body can neither add a key nor fabricate an unbounded claim.
    async recordAdminCounters(body: { bumps?: unknown }): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<AdminCounters>(ADMIN_COUNTERS_KEY);
        await this.state.storage.put(ADMIN_COUNTERS_KEY, applyAdminCounters(prior, body.bumps, new Date().toISOString()));
      } catch {
        /* best-effort */
      }
      return { ok: true };
    }

    // The per-isolate throttle window, shared by BOTH hot-path recorders below. Instance-scoped (never shared
    // across DO instances) and never persisted.
    adminCounterThrottle = new Map<string, number>();

    // bumpAdminCounterLocal is the IN-DO writer for the same aggregate. Several of the silent-exclusion
    // counters the vocabulary promises are raised INSIDE the DO (a corrupt run row dropped from a
    // point-in-time resolution, a stored approval whose TTL cannot be enforced, a drill sample the estimate
    // could not use), where there is no scheduler stub to POST to and a Worker-edge recorder cannot see the
    // branch at all. It folds through the SAME applyAdminCounters chokepoint the edge posts to (an
    // out-of-vocabulary name is dropped, every count is clamped), so there is one aggregate and one redaction
    // boundary, and the precedent set by bumpReplicationCopyCountInvalid / the notify digest is followed
    // rather than a second, parallel record being opened.
    //
    // Best-effort by contract: observing a fault must never break the path that observed it.
    async bumpAdminCounterLocal(name: AdminCounterName, n = 1): Promise<void> {
      try {
        const prior = await this.state.storage.get<AdminCounters>(ADMIN_COUNTERS_KEY);
        await this.state.storage.put(ADMIN_COUNTERS_KEY, applyAdminCounters(prior, { [name]: n }, new Date().toISOString()));
      } catch {
        /* best-effort: the surface it observed still answers */
      }
    }

    // bumpAdminCounterLocalThrottled is bumpAdminCounterLocal for a counter raised on a HOT READ PATH (the
    // RBAC authority resolution runs on EVERY authenticated request, so a single tampered stored custom role
    // would otherwise drive a storage write per request, forever). The same discipline, and the same reasoning,
    // as recordAuthSignalThrottled: a given name is recorded at most once per window per isolate, so the count
    // is of DISTINCT ~minute windows in which the branch fired, never of individual reads. It can only
    // UNDER-count, and the question these answer ("is this still happening, and since when?") is unchanged.
    async bumpAdminCounterLocalThrottled(name: AdminCounterName): Promise<void> {
      const now = Date.now();
      const last = this.adminCounterThrottle.get(name);
      if (last !== undefined && now - last < ADMIN_COUNTER_THROTTLE_MS) return;
      this.adminCounterThrottle.set(name, now);
      await this.bumpAdminCounterLocal(name);
    }

    // recordAdminCountersThrottled is recordAdminCounters for the counters that fire on a HOT READ PATH
    // (G312: a corrupt stored approval, expiry row or custom role is read back on EVERY request that touches
    // it, so an unthrottled recorder would turn one bad record into a storage write per request, for ever).
    // A given name is recorded at most once per ADMIN_COUNTER_THROTTLE_MS per DO isolate, so the counter counts
    // DISTINCT ~minute WINDOWS in which the anomaly was observed rather than individual reads. It can only
    // UNDER-count, never over-count; lastAt stays exact; and the question these answer ("is this record STILL
    // corrupt, and since when?") is unchanged. The same idiom as recordAuthSignalThrottled.
    async recordAdminCountersThrottled(names: readonly string[]): Promise<void> {
      const now = Date.now();
      const due: string[] = [];
      for (const n of names) {
        const last = this.adminCounterThrottle.get(n);
        if (last !== undefined && now - last < ADMIN_COUNTER_THROTTLE_MS) continue;
        this.adminCounterThrottle.set(n, now);
        due.push(n);
      }
      if (due.length === 0) return;
      await this.recordAdminCounters({ bumps: Object.fromEntries(due.map((n) => [n, 1])) });
    }

    // readAdminCounters is the pack read (GET /admin-counters). Closed name keys + int counts + timestamps.
    // Empty is healthy; ANY non-zero counter means a surface the pack carries is quietly incomplete, and
    // says which one (a reclaimed apply lease, a licence source flip, a silently excluded row).
    async readAdminCounters(): Promise<AdminCounters> {
      return (await this.state.storage.get<AdminCounters>(ADMIN_COUNTERS_KEY)) ?? {};
    }

    // ---- G015/G042/G068/G110/G144/G096/G170/G213/G327 + G135/G186: the run's SOURCE + DEST fault evidence --

    // recordRunFaults folds ONE finished crawl's drained source-fault ledger and destination fault /
    // degradation snapshots into the two bounded per-downpipe aggregates. The seal path posts this at the end
    // of every crawl that recorded anything (a clean run posts nothing at all).
    //
    // applySourceFaults / applyDestFaults are the REDACTION CHOKEPOINT: they re-validate every field DO-side
    // against the closed vocabularies the recorders own (an out-of-vocabulary reason / marker kind / stage /
    // status class / source type / S3 code / op / classifier arm is DROPPED, every count is clamped, every
    // attribution id must pass a structural shape gate), so even a drifted or hostile caller cannot land a
    // raw provider message, a bucket, an endpoint or a customer value here. Best-effort and never throwing:
    // observing a fault must never break the run that hit it.
    async recordRunFaults(body: { id?: unknown; source?: unknown; dest?: unknown }): Promise<{ ok: true }> {
      try {
        const id = safeDownpipeId(body.id);
        if (id === null) return { ok: true };
        const now = Date.now();
        if (body.source !== undefined) {
          const prior = await this.state.storage.get<SourceFaults>(SOURCE_FAULTS_KEY);
          await this.state.storage.put(SOURCE_FAULTS_KEY, applySourceFaults(prior, id, body.source, now));
        }
        const d = (typeof body.dest === "object" && body.dest !== null ? body.dest : null) as { faults?: unknown; io?: unknown } | null;
        if (d !== null) {
          const prior = await this.state.storage.get<DestFaults>(DEST_FAULTS_KEY);
          await this.state.storage.put(DEST_FAULTS_KEY, applyDestFaults(prior, id, d.faults, d.io, now));
        }
      } catch {
        /* best-effort: a fault WHILE recording a fault must not mask the run's own outcome */
      }
      return { ok: true };
    }

    // readSourceFaults is the pack read (GET /source-faults): the per-downpipe SOURCE evidence -- WHY each
    // incompleteness sentinel was sealed (a 403 scope gap, a 5xx outage, a size ceiling, a page cap, a stuck
    // render), the tolerant-parse drops that void coverage behind a green run, the run-fatal transport class
    // and crawl stage, the D1 snapshot-consistency verdict, the corrupt resume tokens, the absorbed 429s, and
    // the security refusals. Empty is the healthy steady state.
    async readSourceFaults(): Promise<SourceFaults> {
      return (await this.state.storage.get<SourceFaults>(SOURCE_FAULTS_KEY)) ?? {};
    }

    // readDestFaults is the pack read (GET /dest-faults): the per-downpipe DESTINATION evidence -- the closed
    // identity of every failing op (an expired STS session vs a bucket-policy denial vs a WORM checksum
    // complaint vs a signature mismatch, and whether the classifier DEFAULTED to permanent because it could
    // not read the message), plus the degradation counters of a destination that is quietly making a GREEN
    // run slow and expensive. Empty is the healthy steady state.
    async readDestFaults(): Promise<DestFaults> {
      return (await this.state.storage.get<DestFaults>(DEST_FAULTS_KEY)) ?? {};
    }

    // ---- G011/G012/G056/G057/G087/G088/G111: the FORMAT + CRYPTO integrity fault aggregate ---------------

    // recordIntegrityFaults folds ONE drained integrity-fault snapshot (format/integrity-fault-ledger.ts) into
    // the bounded per-downpipe record. applyIntegrityFaults is the redaction chokepoint: it re-validates every
    // enum against its closed set, clamps every count and ordinal, and shape-gates the two hex fields (a 12-hex
    // one-way digest and a fingerprint of PUBLIC key material), so a raw exception message, an object key, a
    // bucket, an endpoint or a byte of key material cannot land here even from a drifted caller. Best-effort
    // and never throwing: observing a verification failure must never mask it.
    async recordIntegrityFaults(body: { id?: unknown; snapshot?: unknown }): Promise<{ ok: true }> {
      try {
        const id = safeDownpipeId(body.id);
        if (id === null || body.snapshot === undefined) return { ok: true };
        const prior = await this.state.storage.get<IntegrityFaults>(INTEGRITY_FAULTS_KEY);
        const { record, refusedSubjects } = applyIntegrityFaultsCounted(prior, id, body.snapshot, Date.now());
        await this.state.storage.put(INTEGRITY_FAULTS_KEY, record);
        // G325: THE 101ST FAULTING DOWNPIPE WAS BEING DROPPED SILENTLY. This record is read as the answer to
        // "which downpipes failed verification", and a downpipe absent from it reads as one whose archives
        // verified -- so a systematic fault (a mis-provisioned wrap key, a format drift) that reaches the
        // whole fleet at once was reported as reaching exactly 100 downpipes. Booked AFTER the record write
        // so a failed declaration can never cost the evidence that produced it.
        //
        // AND IT NAMES THE DOWNPIPE. `id` is the very subject the map just refused, already shape-gated by
        // `safeDownpipeId` above and already the key `integrityFaults` carries for every ADMITTED downpipe,
        // so the refusal discloses nothing the admission does not. Without it the pack could say a downpipe's
        // verification evidence was dropped and not which, which is the fleet-wide fact rather than the one a
        // reader holding a downpipe row needs.
        if (refusedSubjects > 0) await recordCapTruncation(this.state.storage, "integrity-faults-downpipe", refusedSubjects, [id]);
      } catch {
        /* best-effort */
      }
      return { ok: true };
    }

    // readIntegrityFaults is the pack read (GET /integrity-faults): per downpipe, WHICH SPEC 8.3 verification
    // stage failed, WHETHER the class was typed or guessed from a keyword, WHICH shard/record/segment failed
    // and by how much (declared vs recovered), WHICH key role was mis-provisioned, WHERE a streaming open
    // aborted, and how many records were sealed as ZERO BYTES behind a green run. Empty is healthy.
    async readIntegrityFaults(): Promise<IntegrityFaults> {
      return (await this.state.storage.get<IntegrityFaults>(INTEGRITY_FAULTS_KEY)) ?? {};
    }

    // ---- G072: the last-resort dispatch fault ring -------------------------------------------------------

    // recordDispatchFault appends ONE last-resort catch (an /admin, /support, /metrics, SCIM or manual-canary
    // 500) to the bounded ring. The errId is the engine's existing irreversible FNV id, which is the ONLY join
    // key back to the Workers-Logs line the pack structurally cannot carry.
    async recordDispatchFault(body: unknown): Promise<{ ok: true }> {
      try {
        const ring = (await this.state.storage.get<DispatchFaultRow[]>(DISPATCH_FAULTS_KEY)) ?? [];
        await this.state.storage.put(DISPATCH_FAULTS_KEY, applyDispatchFault(ring, body, Date.now()));
      } catch {
        /* best-effort */
      }
      return { ok: true };
    }

    // readDispatchFaults is the pack read (GET /dispatch-faults): the bounded ring, oldest-first. A row means
    // a surface threw a 500 the customer saw and the pack previously carried NO trace of.
    async readDispatchFaults(): Promise<{ faults: DispatchFaultRow[] }> {
      return { faults: (await this.state.storage.get<DispatchFaultRow[]>(DISPATCH_FAULTS_KEY)) ?? [] };
    }

    // ---- G084/G132/G133/G205/G220/G234/G278: the CRON INVOCATION's health --------------------------------

    // CRON_INTERVAL_MS is the engine's own cron cadence (wrangler.toml `crons = ["*/15 * * * *"]`). The DO
    // derives the tick GAP from it against its OWN clock, so a wedged or hostile edge clock can neither
    // fabricate nor conceal a missed tick.
    // recordCronHealth folds ONE cron invocation's drained delta into the bounded record: which of the ~20
    // passes failed and with what closed class (a pass that crashed while the tick still reported green), the
    // HOLES in the tick ring (a DO-unreachable tick can only be reported by the NEXT healthy one, which is
    // exactly what tickRecordFailures carries), the cf-config discovery skips, the auto-heal stalls, the
    // beacon's env-presence and fail class, and the SIEM shaping/cursor fallbacks.
    //
    // applyCronHealth is the REDACTION CHOKEPOINT: an out-of-vocabulary pass name, error class, skip reason,
    // beacon class, deferral class, resume code or SIEM fallback kind is DROPPED, and every count is clamped,
    // so a drifted or hostile caller cannot land a message, a beacon URL, an ingest key, an endpoint, a bucket
    // or an audit event body here.
    async recordCronHealth(body: { delta?: unknown; cronIntervalMs?: unknown }): Promise<{ ok: true }> {
      try {
        const interval = typeof body.cronIntervalMs === "number" && Number.isFinite(body.cronIntervalMs) && body.cronIntervalMs > 0 ? body.cronIntervalMs : 900_000;
        const prior = await this.state.storage.get<CronHealth>(CRON_HEALTH_KEY);
        await this.state.storage.put(CRON_HEALTH_KEY, applyCronHealth(prior, body.delta, Date.now(), interval));
      } catch {
        /* best-effort: a fault WHILE recording a cron fault must never crash the cron */
      }
      return { ok: true };
    }

    // readCronHealth is the pack read (GET /cron-health). An engine whose cron is healthy returns the empty
    // record; ANY non-zero pass failure, tick hole, discovery skip run, auto-heal deferral, beacon fail class
    // or SIEM fallback count is a surface the pack previously could not see at all.
    async readCronHealth(): Promise<CronHealth> {
      return (await this.state.storage.get<CronHealth>(CRON_HEALTH_KEY)) ?? emptyCronHealth();
    }

    // ---- G151: the per-destination selection-probe reasons -----------------------------------------------

    // recordDestProbeFaults folds the individual probe verdicts of ONE destination-selection pass into the
    // bounded per-destination map, so "all destinations unreachable" finally names a cause for each one.
    async recordDestProbeFaults(body: { rows?: unknown; refusedUpstream?: unknown }): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<DestProbeFaults>(DEST_PROBE_FAULTS_KEY);
        const { record, refusedRows, refusedIds } = applyDestProbeFaultsCounted(prior, body.rows, Date.now());
        await this.state.storage.put(DEST_PROBE_FAULTS_KEY, record);
        // G325: THE 33RD FAILING DESTINATION WAS BEING DROPPED SILENTLY, at three cuts. `refusedUpstream` is
        // the FIRST of them, counted in the Worker's own cron accumulator before this DO is ever called, and
        // it is the only one visible from there; the other two are counted by the writer above. It is our own
        // number rather than a caller's, but it is clamped here anyway because this route is the redaction
        // and shape chokepoint for everything on this body.
        const upstream = typeof body.refusedUpstream === "number" && Number.isFinite(body.refusedUpstream) ? Math.min(1_000_000, Math.max(0, Math.floor(body.refusedUpstream))) : 0;
        const dropped = refusedRows + upstream;
        // THE NAMES RIDE, AND THE UNNAMED ONES ARE DECLARED UNNAMED. `refusedIds` covers the two cuts this DO
        // can see; the upstream cut counts refusals in the Worker's own cron accumulator whose ROWS never
        // reach here, so it can never be named, and passing fewer subjects than the dropped count is exactly
        // what makes the subjects ledger mark this surface `incomplete`. Over-declaring incompleteness is the
        // safe direction: "there may be more than you can see" is recoverable where "this is all of them" is not.
        if (dropped > 0) await recordCapTruncation(this.state.storage, "dest-probe-faults", dropped, refusedIds);
      } catch {
        /* best-effort */
      }
      return { ok: true };
    }

    // readDestProbeFaults is the pack read (GET /dest-probe-faults): destination label -> closed reason class.
    async readDestProbeFaults(): Promise<DestProbeFaults> {
      return (await this.state.storage.get<DestProbeFaults>(DEST_PROBE_FAULTS_KEY)) ?? {};
    }

    // ---- G296: the cost sizing-probe outcomes ------------------------------------------------------------

    // recordCostSizing folds ONE sizing-probe outcome into the per-source-type record. The measured-zero class
    // is the load-bearing one: it separates a Cloudflare Analytics schema drift (a 0 presented to the customer
    // as a MEASURED size) from an honestly unavailable one.
    async recordCostSizing(body: { sourceType?: unknown; class?: unknown }): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<CostSizing>(COST_SIZING_KEY);
        await this.state.storage.put(COST_SIZING_KEY, applyCostSizing(prior, body.sourceType, body.class, new Date().toISOString()));
      } catch {
        /* best-effort */
      }
      return { ok: true };
    }

    // readCostSizing is the pack read (GET /cost-sizing): closed source type -> {sized, unavailable,
    // measuredZero, lastClass, lastAt}. Never a namespace id, a bucket name, an endpoint or a token scope.
    async readCostSizing(): Promise<CostSizing> {
      return (await this.state.storage.get<CostSizing>(COST_SIZING_KEY)) ?? {};
    }

    // ---- G136 / G137: the standing destination-BUILD health ---------------------------------------------

    // recordDestBuildHealth folds ONE destination-build outcome into the standing record. applyDestBuildHealth
    // is the redaction chokepoint: an out-of-vocabulary cause / env-var name / STS failure class is DROPPED
    // (never coerced, never carried as text) and the DO status is clamped, so even a drifted or hostile caller
    // cannot land an endpoint, a bucket, a role ARN, a credential or a raw message here. Best-effort and never
    // throwing: observing a build must never break the backup that depends on it.
    async recordDestBuildHealth(body: unknown): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<DestBuildHealth>(DEST_BUILD_HEALTH_KEY);
        await this.state.storage.put(DEST_BUILD_HEALTH_KEY, applyDestBuildHealth(prior, body, Date.now()));
      } catch {
        /* best-effort */
      }
      return { ok: true };
    }

    // readDestBuildHealth is the pack read (GET /dest-build-health): the last build outcome, the moment the
    // destination STARTED failing to build (failingSinceAt -- the fact a coarse run error can never carry), the
    // closed cause, the named knob, the STS refusal class, and the per-cause counters. Null until a build has
    // been observed at all; lastOutcome "ok" is the healthy steady state.
    async readDestBuildHealth(): Promise<{ health: DestBuildHealth | null }> {
      return { health: (await this.state.storage.get<DestBuildHealth>(DEST_BUILD_HEALTH_KEY)) ?? null };
    }

    // ---- G028: the runtime wrap-key UNWRAP fault timeline -------------------------------------------------

    // recordUnwrapFault bumps ONE closed cause in the bounded {cause -> count, firstAt, lastAt} record. firstAt
    // is the fact the probe-time wrapKeyHealth verdict structurally cannot recover: WHEN destination-credential
    // reads started failing (the customer rotated CONFIG_WRAP_KEY on the Tuesday; the first run failed on the
    // Thursday). applyUnwrapFault is the redaction chokepoint. Best-effort and never throwing: the read that hit
    // the fault has already decided to fail, and observing it must never mask its own error.
    async recordUnwrapFault(body: { cause?: unknown }): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<UnwrapFaults>(UNWRAP_FAULTS_KEY);
        await this.state.storage.put(UNWRAP_FAULTS_KEY, applyUnwrapFault(prior, typeof body.cause === "string" ? body.cause : "", Date.now()));
      } catch {
        /* best-effort */
      }
      return { ok: true };
    }

    // readUnwrapFaults is the pack read (GET /unwrap-faults). Closed causes + counts + clamped timestamps.
    // Empty is the healthy steady state; ANY entry means a destination credential could not be OPENED at the
    // moment of use, and says which of the five causes -- and, in firstAt, since when.
    async readUnwrapFaults(): Promise<UnwrapFaults> {
      return (await this.state.storage.get<UnwrapFaults>(UNWRAP_FAULTS_KEY)) ?? {};
    }

    // ---- G099: the post-write BINDING-SAFETY alarms -------------------------------------------------------

    // recordBindingAlarm folds ONE post-write safety alarm into the bounded ring, so an alarm that names a
    // DROPPED binding, or proves a concurrent writer's lost update, is preserved in the pack rather than only
    // surfacing in a single operator's HTTP response while the pack keeps showing healthy-looking
    // sources-attached audit rows. applyBindingAlarm is the redaction chokepoint (closed kind;
    // binding names control-stripped, clamped and capped). Best-effort and never throwing.
    async recordBindingAlarm(body: { row?: unknown }): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<BindingAlarmRow[]>(BINDING_ALARMS_KEY);
        await this.state.storage.put(BINDING_ALARMS_KEY, applyBindingAlarm(prior, body.row, Date.now()));
      } catch {
        /* best-effort: a fault WHILE recording an alarm must not mask the alarm itself */
      }
      return { ok: true };
    }

    // readBindingAlarms is the pack read (GET /binding-alarms): the bounded ring, oldest-first. A row here is
    // the highest-impact failure mode caught in the act -- a change to the engine's bindings that did not preserve them,
    // or that raced another writer -- and it names the bindings.
    async readBindingAlarms(): Promise<{ alarms: BindingAlarmRow[] }> {
      return { alarms: (await this.state.storage.get<BindingAlarmRow[]>(BINDING_ALARMS_KEY)) ?? [] };
    }

    // ---- G050 / G054 / G101 / G159 / G162: the self-update pipeline's fault ring --------------------------

    // recordUpdateFaults folds the Worker edge's already-classified update-pipeline rows into the bounded ring:
    // WHICH step failed, in WHICH closed cause, with Cloudflare's own integer error codes, the observed digest
    // of a failed integrity check (so CDN corruption can be told from tamper), the NAMES of the source bindings
    // an update dropped, and the latch that says the auto-rollback ITSELF failed -- so a pack taken afterwards
    // proves the engine is limping on a bad version. applyUpdateFault re-validates every field DO-side.
    // Best-effort and never throwing.
    async recordUpdateFaults(body: { rows?: unknown }): Promise<{ ok: true }> {
      try {
        const rows = Array.isArray(body.rows) ? body.rows.slice(0, UPDATE_FAULTS_RING_CAP) : [];
        if (rows.length === 0) return { ok: true };
        let ring = (await this.state.storage.get<UpdateFaultRow[]>(UPDATE_FAULTS_KEY)) ?? [];
        const now = Date.now();
        for (const row of rows) ring = applyUpdateFault(ring, row, now);
        await this.state.storage.put(UPDATE_FAULTS_KEY, ring);
      } catch {
        /* best-effort */
      }
      return { ok: true };
    }

    // readUpdateFaults is the pack read (GET /update-faults): the bounded ring, oldest-first. Empty is healthy.
    async readUpdateFaults(): Promise<{ faults: UpdateFaultRow[] }> {
      return { faults: (await this.state.storage.get<UpdateFaultRow[]>(UPDATE_FAULTS_KEY)) ?? [] };
    }

    // ---- G245: the admin REFUSAL aggregate ---------------------------------------------------------------

    // recordAdminRefusal folds ONE refused admin write into the bounded {surface}:{reason} aggregate. The
    // highest-value member is gate-unavailable: a restore refused "not approved" because the approval gate
    // could not be READ is an ENGINE fault, and it was previously indistinguishable from a genuinely missing
    // approval. applyAdminRefusal is the redaction chokepoint (both axes closed; nothing else is read).
    // Best-effort and never throwing: the refusal response is already decided.
    async recordAdminRefusal(body: { surface?: unknown; reason?: unknown }): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<AdminRefusals>(ADMIN_REFUSALS_KEY);
        const next = applyAdminRefusal(prior, typeof body.surface === "string" ? body.surface : "", typeof body.reason === "string" ? body.reason : "", new Date().toISOString());
        await this.state.storage.put(ADMIN_REFUSALS_KEY, next);
      } catch {
        /* best-effort */
      }
      return { ok: true };
    }

    // readAdminRefusals is the pack read (GET /admin-refusals). Closed "<surface>:<reason>" keys + counts.
    // Empty is healthy; a row is an attempt the customer MADE and the engine refused, with the closed why.
    async readAdminRefusals(): Promise<AdminRefusals> {
      return (await this.state.storage.get<AdminRefusals>(ADMIN_REFUSALS_KEY)) ?? {};
    }

    // ---- G053: the pinned IdP signing-certificate health --------------------------------------------------

    // recordIdpCertHealth folds ONE cert-health observation (drained from the pure SAML verify path's ledger)
    // into the standing record. This is the DATA-LOSS gap of the auth plane: a certificate pasted CORRUPT during
    // a rollover is SILENTLY SKIPPED for weeks (the verifier overwrites its parse reason and discards it the
    // moment any other cert parses), so the connection runs with no redundancy, nobody is told, and the day the
    // good cert lapses every sign-in stops. applyIdpCertHealth is the redaction chokepoint: counts are clamped,
    // curve classes re-checked against the closed set, everything else coerced to a boolean -- so a PEM, an SPKI,
    // a subject DN, a connId or a parse reason cannot land here. A null observation (the verify path never
    // reached its cert pre-extraction: a malformed envelope, a replayed RelayState) is a NO-OP, so a failure
    // BEFORE the certs can never overwrite the last real observation. Best-effort and never throwing: recording
    // the health of a sign-in must never break the sign-in.
    async recordIdpCertHealth(obs: unknown): Promise<{ ok: true }> {
      try {
        if (obs === null || obs === undefined) return { ok: true };
        const prior = await this.state.storage.get<IdpCertHealth>(IDP_CERT_HEALTH_KEY);
        await this.state.storage.put(IDP_CERT_HEALTH_KEY, applyIdpCertHealth(prior, obs, Date.now()));
      } catch {
        /* best-effort: observing a cert fault must never mask the sign-in that hit it */
      }
      return { ok: true };
    }

    // readIdpCertHealth is the pack read (GET /idp-cert-health). Null until a SAML sign-in has been attempted at
    // all. A healthy connection reads certCount == parseableCount == windowReadableCount with an rsa/p256 curve
    // tally and a future nearestNotAfter. EVERY interesting state is a plain comparison against that: a
    // parseableCount BELOW certCount is the corrupt rollover paste; expiryObserved false means no expiry warning
    // can ever fire; a p521/unsupported curve is a connection that can never verify; windowUnenforcedVerifies
    // above zero means the cert-freshness check has been running DISARMED; noUsableCertRefusals above zero means
    // SSO is dead right now.
    async readIdpCertHealth(): Promise<{ health: IdpCertHealth | null }> {
      return { health: (await this.state.storage.get<IdpCertHealth>(IDP_CERT_HEALTH_KEY)) ?? null };
    }

    // ---- G008: the SOURCE-DISCOVERY outcome ---------------------------------------------------------------

    // recordDiscoveryHealth folds ONE discover request's classified outcome into the standing record. This is
    // the setup form's own health: GET /sources/discover is FAIL-OPEN PER PRODUCT, so a token missing the R2
    // scope answers 200 with an EMPTY bucket list and the operator builds their whole backup estate against a
    // form that silently omits the resources they most need to protect. applyDiscoveryHealth is the redaction
    // chokepoint: every product key is re-checked against DISCOVERY_PRODUCTS, every verdict against
    // DISCOVERY_OUTCOMES, every count clamped -- so a bucket, a namespace, an account name, a zone or a token
    // cannot land here. Best-effort and never throwing: observing the form must never break the form.
    async recordDiscoveryHealth(obs: unknown): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<DiscoveryHealth>(DISCOVERY_HEALTH_KEY);
        await this.state.storage.put(DISCOVERY_HEALTH_KEY, applyDiscoveryHealth(prior, obs, Date.now()));
      } catch {
        /* best-effort: the discover response is already decided */
      }
      return { ok: true };
    }

    // readDiscoveryHealth is the pack read (GET /discovery-health). Null until a discover has ever run. A
    // healthy account reads every attempted product "ok" or "empty" with degradedObservations 0; a denied
    // product, a truncated listing, or an engineAccountKnown of false (no source can EVER be attached) is the
    // difference between "the account is empty" and "the form could not see the account".
    async readDiscoveryHealth(): Promise<{ health: DiscoveryHealth | null; lastTokenSet: DiscoveryTokenSet | null }> {
      return {
        health: (await this.state.storage.get<DiscoveryHealth>(DISCOVERY_HEALTH_KEY)) ?? null,
        // G129: the token-SET verdict rides with the discover health because it is the same question one step
        // earlier ("could this token see the account at all?"), and a pack that carries a degraded form wants
        // both halves side by side.
        lastTokenSet: (await this.state.storage.get<DiscoveryTokenSet>(DISCOVERY_TOKEN_SET_KEY)) ?? null,
      };
    }

    // recordDiscoveryTokenSet (G129) stores the verdict of ONE pasted-token verification. It is a DIFFERENT event
    // from a discover (it happens BEFORE any listing can run, and it is the one the operator retries over and
    // over), so it gets its own key rather than folding into the discover record and pretending a refused token
    // was an observation of the form.
    //
    // Only the LAST attempt is kept, deliberately: "Verify and save always fails" is a question about the state
    // the operator is stuck in RIGHT NOW, and a history of attempts would be a per-keystroke ledger of a person
    // fixing a typo. applyDiscoveryTokenSet is the redaction chokepoint (both enums re-checked by set membership,
    // the count re-clamped, nothing else on the body read).
    async recordDiscoveryTokenSet(obs: unknown): Promise<{ ok: true }> {
      try {
        const rec = applyDiscoveryTokenSet(obs, Date.now());
        if (rec !== null) await this.state.storage.put(DISCOVERY_TOKEN_SET_KEY, rec);
      } catch {
        /* best-effort: the token-set response is already decided */
      }
      return { ok: true };
    }

    // ---- G022: the AUDIT-EXPORT attempt -------------------------------------------------------------------

    // recordExportAttempt folds ONE audit-log export attempt into the standing record. The export is how the
    // tamper-evident trail leaves the account, so an export that keeps failing means the customer cannot PROVE
    // what happened -- and the failure is, by construction, the one fact the exported log can never carry.
    // applyExportAttempt is the redaction chokepoint: three closed enums and a boolean, an out-of-vocabulary
    // value dropping the attempt whole, so the caller's filter (an actor e-mail, a downpipe name, a date range)
    // and the log's bytes cannot enter the record. Best-effort and never throwing.
    async recordExportAttempt(att: unknown): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<ExportAttempts>(EXPORT_ATTEMPTS_KEY);
        await this.state.storage.put(EXPORT_ATTEMPTS_KEY, applyExportAttempt(prior, att, Date.now()));
      } catch {
        /* best-effort: the export (or its error) has already been served */
      }
      return { ok: true };
    }

    // readExportAttempts is the pack read (GET /export-attempts). Null until an export has ever been attempted
    // (which is itself the answer to "has anyone ever taken this log out?"). failures > 0 with a recent
    // lastFailureAt is the customer who cannot get their evidence out; byChannel says whether it is the
    // operator's download or the SIEM collector; byFormat.csv alone is a whole-log SCAN size fault.
    async readExportAttempts(): Promise<{ attempts: ExportAttempts | null }> {
      return { attempts: (await this.state.storage.get<ExportAttempts>(EXPORT_ATTEMPTS_KEY)) ?? null };
    }

    // ---- G131: the ATTACH / RE-ATTACH outcome -------------------------------------------------------------

    // recordAttachHealth folds ONE attach / re-attach attempt into the standing record. reattach-missing is the
    // HEAL for a bare `wrangler deploy` resetting the worker's bindings and silently dropping every
    // console-attached source, so the pack shows whether the heal has run and succeeded rather than the
    // refusal surfacing only as an HTTP response. applyAttachHealth is the redaction chokepoint: a closed
    // op, a closed fault class and clamped counts, so the deploy token, the account id, the script name and the
    // Cloudflare message cannot land here. Best-effort and never throwing.
    async recordAttachHealth(obs: unknown): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<AttachHealth>(ATTACH_HEALTH_KEY);
        await this.state.storage.put(ATTACH_HEALTH_KEY, applyAttachHealth(prior, obs, Date.now()));
      } catch {
        /* best-effort: the attach (or its refusal) is already decided */
      }
      return { ok: true };
    }

    // readAttachHealth is the pack read (GET /attach-health). Null until an attach has ever been attempted.
    // faults.reattach with successes.reattach absent is "the heal for the wiped bindings has NEVER worked";
    // lastPlan.malformedSources > 0 is the plan silently omitting a downpipe from the heal altogether.
    async readAttachHealth(): Promise<{ health: AttachHealth | null }> {
      return { health: (await this.state.storage.get<AttachHealth>(ATTACH_HEALTH_KEY)) ?? null };
    }

    // ---- G183: the ADMIN-ROUTE outer catch ----------------------------------------------------------------

    // recordAdminRouteError folds ONE admin-route outer-catch fault into the standing record. These catches
    // return a FIXED "nothing was changed" and discard the exception -- and the sentence can be FALSE, because
    // the throw can land after the deploy went live. applyAdminRouteError is the redaction chokepoint: a closed
    // route and a closed stage, so the exception text never persists. Best-effort and never throwing.
    async recordAdminRouteError(err: unknown): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<AdminRouteErrors>(ADMIN_ROUTE_ERRORS_KEY);
        await this.state.storage.put(ADMIN_ROUTE_ERRORS_KEY, applyAdminRouteError(prior, err, Date.now()));
      } catch {
        /* best-effort: the route's 400 is already decided */
      }
      return { ok: true };
    }

    // readAdminRouteErrors is the pack read (GET /admin-route-errors). mutatingFaults > 0 is the number a
    // diagnosis reads first: a fault at deploy-driver or persist means the route's "nothing was changed" claim
    // is not safe to believe, and the engine may well be running the version the customer was told it is not.
    async readAdminRouteErrors(): Promise<{ errors: AdminRouteErrors | null }> {
      return { errors: (await this.state.storage.get<AdminRouteErrors>(ADMIN_ROUTE_ERRORS_KEY)) ?? null };
    }

    // ---- G202: the CONTROL-PLANE RECOVERY refusal ---------------------------------------------------------

    // recordRecoveryRefusal folds ONE refused recovery action into the standing record, so a refusal on this
    // path -- where the pack may be the only surviving artefact -- is preserved rather than only living in the
    // operator's browser. applyRecoveryRefusal is the redaction chokepoint: a closed surface and a closed class, so no
    // signature material, verifier bytes, export contents or free-text reason can land here.
    async recordRecoveryRefusal(refusal: unknown): Promise<{ ok: true }> {
      try {
        const prior = await this.state.storage.get<RecoveryRefusals>(RECOVERY_REFUSALS_KEY);
        await this.state.storage.put(RECOVERY_REFUSALS_KEY, applyRecoveryRefusal(prior, refusal, Date.now()));
      } catch {
        /* best-effort: the refusal is already decided */
      }
      return { ok: true };
    }

    // readRecoveryRefusals is the pack read (GET /recovery-refusals). lastClass "verify-threw" against
    // "signature" distinguishes a damaged recovery KIT from a tampered EXPORT.
    async readRecoveryRefusals(): Promise<{ refusals: RecoveryRefusals | null }> {
      return { refusals: (await this.state.storage.get<RecoveryRefusals>(RECOVERY_REFUSALS_KEY)) ?? null };
    }

    // ---- the sub-dispatch --------------------------------------------------------------------------------

    // routeSupportDiag is this subsystem's link in route()'s dispatch chain. Every POST here is an INTERNAL
    // recording route (reached only by the Worker's own scheduler.fetch, like /auth-signal and /seal-fault)
    // and every GET is the INTERNAL pack read. Returns the handler Response for a key it owns, or null ("not
    // my route") so route() tries the next link.
    async routeSupportDiag(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
        // G163: the cron seal loop posts ONE closed class per pre-run dispatch fault, attributed to the
        // downpipe whose dispatch threw; the pack reads the whole per-downpipe map back.
        case "POST /seal-error": {
          const b = (await req.json()) as { id?: unknown; class?: unknown };
          return this.json(await this.recordSealError(b.id, b.class));
        }
        case "GET /seal-errors":
          return this.json(await this.sealErrors());
        // G049: the /metrics handler posts its scrape outcome (authorised or not); the pack reads the health.
        case "POST /metrics-scrape":
          return this.json(await this.recordMetricsScrape((await req.json()) as { outcome?: unknown; shapeFallback?: unknown; pullFailed?: unknown }));
        case "GET /metrics-health":
          return this.json(await this.metricsHealth());
        // G158: the pack read of the structural WebAuthn fault aggregate (the RECORDING is DO-internal: the
        // ceremony runs inside the DO, so there is no POST route and no way for a caller to inject a class).
        case "GET /webauthn-faults":
          return this.json(await this.readWebauthnFaults());
        // G070: the Worker edge posts the PROJECTED fault rows of one finished restore / drill / verify (a
        // clean one posts nothing); the pack reads the bounded ring back.
        case "POST /diag/restore-faults":
          return this.json(await this.recordRestoreFaults((await req.json()) as { rows?: unknown }));
        case "GET /restore-faults":
          return this.json(await this.readRestoreFaults());
        // G080/G081/G082: the Worker edge bumps the silent-fallback / silent-exclusion counters.
        case "POST /diag/admin-counters":
          return this.json(await this.recordAdminCounters((await req.json()) as { bumps?: unknown }));
        // G246: the Worker edge files ONE wiring-check outcome (a Test button's result). recordTestOutcome is
        // the redaction chokepoint: an out-of-vocabulary surface / reason / status class is DROPPED, so nothing
        // but closed enums and a boolean can enter the ring, whatever a caller posts.
        case "POST /diag/test-outcome": {
          const body = (await req.json()) as { surface?: unknown; ok?: unknown; reasonClass?: unknown; statusClass?: unknown; deleteProbe?: unknown; deleteStatusClass?: unknown; objectLock?: unknown; objectLockUnknownReason?: unknown; defaultRetention?: unknown; platformCode?: unknown; deliveryCode?: unknown };
          await recordTestOutcome(this.state.storage, {
            surface: typeof body.surface === "string" ? body.surface : "",
            ok: body.ok === true,
            ...(typeof body.reasonClass === "string" ? { reasonClass: body.reasonClass } : {}),
            ...(typeof body.statusClass === "string" ? { statusClass: body.statusClass } : {}),
            // G246: forwarded as-is; recordTestOutcome is the redaction chokepoint and closed-set gates both
            // (and admits them only on dest-verify), so a drifted or hostile body cannot put a string here.
            ...(typeof body.deleteProbe === "string" ? { deleteProbe: body.deleteProbe } : {}),
            ...(typeof body.deleteStatusClass === "string" ? { deleteStatusClass: body.deleteStatusClass } : {}),
            ...(typeof body.objectLock === "string" ? { objectLock: body.objectLock } : {}),
            ...(typeof body.objectLockUnknownReason === "string" ? { objectLockUnknownReason: body.objectLockUnknownReason } : {}),
            ...(typeof body.defaultRetention === "boolean" ? { defaultRetention: body.defaultRetention } : {}),
            // R6: the email platform code, forwarded as-is. recordTestOutcome re-runs the E_UPPER_SNAKE shape
            // gate and admits it only on a FAILED email row, so a drifted or hostile body cannot put a message
            // here, nor hang a code off a push, idp or destination row.
            ...(typeof body.platformCode === "string" ? { platformCode: body.platformCode } : {}),
            // R7: the notify-channel delivery code, forwarded as-is. recordTestOutcome re-gates it against the
            // closed DELIVERY_FAIL_CODES and admits it only on a FAILED notify-channel row, so a drifted or
            // hostile body cannot put a URL here, nor hang a code off an email, push, idp or destination row.
            ...(typeof body.deliveryCode === "string" ? { deliveryCode: body.deliveryCode } : {}),
          });
          return this.json({ ok: true });
        }
        case "GET /admin-counters":
          return this.json(await this.readAdminCounters());
        // The seal path posts ONE finished crawl's drained source-fault ledger + destination fault /
        // degradation snapshots (a clean run posts nothing); the pack reads the two aggregates back.
        case "POST /diag/run-faults":
          return this.json(await this.recordRunFaults((await req.json()) as { id?: unknown; source?: unknown; dest?: unknown }));
        case "GET /source-faults":
          return this.json(await this.readSourceFaults());
        case "GET /dest-faults":
          return this.json(await this.readDestFaults());
        // G011/G012/G056/G057/G087/G088/G111: the seal / restore path posts ONE drained integrity-fault
        // snapshot from the format + crypto core (a clean verify posts nothing); the pack reads it back.
        case "POST /diag/integrity-faults":
          return this.json(await this.recordIntegrityFaults((await req.json()) as { id?: unknown; snapshot?: unknown }));
        case "GET /integrity-faults":
          return this.json(await this.readIntegrityFaults());
        // G072: the Worker's four last-resort catches post their surface + errId; the pack reads the ring.
        case "POST /diag/dispatch-fault":
          return this.json(await this.recordDispatchFault(await req.json()));
        case "GET /dispatch-faults":
          return this.json(await this.readDispatchFaults());
        // G151: the destination-selection pass posts the per-destination probe verdicts it used to discard.
        // The cron driver posts ONE health delta at the end of every invocation; the pack reads it back.
        case "POST /diag/cron-health":
          return this.json(await this.recordCronHealth((await req.json()) as { delta?: unknown; cronIntervalMs?: unknown }));
        case "GET /cron-health":
          return this.json(await this.readCronHealth());
        case "POST /diag/dest-probe-faults":
          return this.json(await this.recordDestProbeFaults((await req.json()) as { rows?: unknown }));
        case "GET /dest-probe-faults":
          return this.json(await this.readDestProbeFaults());
        // G296: the sizing probe posts its outcome class per source type; the pack reads the record.
        case "POST /diag/cost-sizing":
          return this.json(await this.recordCostSizing((await req.json()) as { sourceType?: unknown; class?: unknown }));
        case "GET /cost-sizing":
          return this.json(await this.readCostSizing());
        // G136/G137: dest/factory.ts posts every destination-BUILD outcome (a failure always; a success once per
        // isolate, which is what clears the failing streak); the pack reads the standing record back.
        case "POST /diag/dest-build":
          return this.json(await this.recordDestBuildHealth(await req.json()));
        case "GET /dest-build-health":
          return this.json(await this.readDestBuildHealth());
        // G100/G331: the Worker edge flushes its isolate-local dropped-write tally; the pack reads it back.
        case "POST /diag/dropped-writes":
          return this.json(await this.recordDroppedWrites((await req.json()) as { drops?: unknown }));
        case "GET /dropped-writes":
          return this.json(await this.readDroppedWrites());
        // G028: the read-for-use sites post ONE closed unwrap cause; the pack reads the timeline back.
        case "POST /diag/unwrap-fault":
          return this.json(await this.recordUnwrapFault((await req.json()) as { cause?: unknown }));
        case "GET /unwrap-faults":
          return this.json(await this.readUnwrapFaults());
        // G099: the attach pipeline posts a post-write binding-safety alarm; the pack reads the ring back.
        case "POST /diag/binding-alarm":
          return this.json(await this.recordBindingAlarm((await req.json()) as { row?: unknown }));
        case "GET /binding-alarms":
          return this.json(await this.readBindingAlarms());
        // G050/G054/G101/G159/G162: the update pipeline posts its classified fault rows; the pack reads them.
        case "POST /diag/update-faults":
          return this.json(await this.recordUpdateFaults((await req.json()) as { rows?: unknown }));
        case "GET /update-faults":
          return this.json(await this.readUpdateFaults());
        // G053: the pack read of the pinned IdP signing-cert health (the RECORDING is DO-internal: the SAML ACS
        // runs inside the DO, so there is no POST route and no way for a caller to inject an observation).
        case "GET /idp-cert-health":
          return this.json(await this.readIdpCertHealth());
        // G129: the token-SET route posts its CLOSED fail class, decided where the Cloudflare STATUS is known.
        // The console sees a flat 400 and cannot subdivide it; the engine made the call and can.
        case "POST /diag/discovery-token-set":
          return this.json(await this.recordDiscoveryTokenSet(await req.json()));
        // G008: the discover route posts its CLASSIFIED per-product outcome; the pack reads the record back.
        case "POST /diag/discovery-health":
          return this.json(await this.recordDiscoveryHealth(await req.json()));
        case "GET /discovery-health":
          return this.json(await this.readDiscoveryHealth());
        // G022: the two export channels (the console download, the collector feed) post ONE classified attempt
        // each; the pack reads the aggregate back.
        case "POST /diag/export-attempt":
          return this.json(await this.recordExportAttempt(await req.json()));
        case "GET /export-attempts":
          return this.json(await this.readExportAttempts());
        // G131: the attach / re-attach routes post their classified outcome + the heal plan's shape.
        case "POST /diag/attach-health":
          return this.json(await this.recordAttachHealth(await req.json()));
        case "GET /attach-health":
          return this.json(await this.readAttachHealth());
        // G183: the update / licence routes' outermost catches post the route + the last checkpoint passed.
        case "POST /diag/admin-route-error":
          return this.json(await this.recordAdminRouteError(await req.json()));
        case "GET /admin-route-errors":
          return this.json(await this.readAdminRouteErrors());
        // G182: the Worker edge posts the change-reference header faults it alone can see (a garbled header,
        // or one whose operator text normalised away). The DO-side governance surfaces record their own
        // refusals directly through recordGovernanceRefusal; this route exists only for the EDGE half.
        case "POST /diag/governance-refusal": {
          const b = (await req.json()) as { stage?: unknown; reason?: unknown };
          // recordGovernanceRefusal is itself the redaction chokepoint: it re-checks BOTH members against
          // their closed sets and records nothing at all for an out-of-vocabulary value, so a hostile or
          // drifted caller on this internal route cannot widen the key space.
          await recordGovernanceRefusal(this.state.storage, b.stage as GovernanceRefusalStage, b.reason as GovernanceRefusalReason);
          return this.json({ ok: true });
        }
        // G175: the EDGE half of the guard ledger. The two DO-side guards (last-Owner, last-passkey) call
        // recordAuthzRefusal directly at the guard; the first-party-session guard is decided in the ROUTER (it
        // never reaches the DO at all), so it posts its closed gate here. recordAuthzRefusal is itself the
        // redaction chokepoint: it re-checks the gate against AUTHZ_GATE_SET and records NOTHING for an
        // out-of-vocabulary value, so a drifted caller on this internal route cannot widen the key space.
        case "POST /diag/authz-refusal": {
          const b = (await req.json()) as { gate?: unknown };
          await recordAuthzRefusal(this.state.storage, typeof b.gate === "string" ? b.gate : "");
          return this.json({ ok: true });
        }
        // G202: the control-plane import / reconcile / download refusals post their closed surface + class.
        case "POST /diag/recovery-refusal":
          return this.json(await this.recordRecoveryRefusal(await req.json()));
        case "GET /recovery-refusals":
          return this.json(await this.readRecoveryRefusals());
        // G245: the admin routers post a refused write's closed (surface, reason); the pack reads the aggregate.
        case "POST /diag/admin-refusal":
          return this.json(await this.recordAdminRefusal((await req.json()) as { surface?: unknown; reason?: unknown }));
        case "GET /admin-refusals":
          return this.json(await this.readAdminRefusals());
        default:
          return null;
      }
    }
  };
}
