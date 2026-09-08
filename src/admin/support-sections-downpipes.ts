// Support-pack section gatherer: the PER-DOWNPIPE diagnostic projections that are derived from state the
// roster read (GET /downpipes) already returns, or joined onto a downpipe from a fleet-level signal the
// scheduler section already fetched. They live here rather than inline in support.ts because they are pure
// row-level derivations with their own closed vocabularies, and support.ts is at its module-size budget.
//
// Every field is a closed enum / boolean / clamped int, gated at the pack boundary against its own closed
// vocabulary (defence in depth: the DO clamps at the recording site, and an out-of-vocabulary value is DROPPED
// here rather than propagated). No schedule string, window minute, bucket name, secret or record content rides.

import { RESTORE_TEST_REASON_CODES } from "../restore-reasons.ts";
import { allDestinationIds, replNeverReportedSince } from "../sched/destinations.ts";
import { INFLIGHT_LEASE_MS } from "../sched/scheduler-do-records.ts";
import type { DownpipeState } from "../sched/types.ts";
import { selfIdentityClass, selfIdentityDegraded } from "../seal/adapters.ts";
import { SOURCE_FAULT_STATUS_CLASSES } from "../sources/source-fault-ledger.ts";
import { doURL } from "../do-url.ts";
import { RTO_DEGRADATION_CAUSES, RTO_REJECT_REASONS } from "./rto.ts";
import type { CapTruncationSubjectIndex } from "./support-sections-diag.ts";
import { danglingDestinationRef } from "./support-sections-config.ts";
import { STATE_REFUSED_CLASSES } from "./support-sections-runs.ts";
import { clampNonNegInt, gateClosed, UNKNOWN_CODE } from "./support-shared.ts";

// SOURCE_FAULT_STATUS_CLASS_SET gates the cf-config discovery's per-surface UNAVAILABILITY class (G006).
// It re-uses the source ledger's own closed status vocabulary, so the class the probe recorded and the class
// the pack carries cannot drift apart. An out-of-vocabulary key is DROPPED (never a bundle key), and the
// counts are clamped: a raw Cloudflare message can no more reach the pack through this map than through any
// other closed-set gate.
const SOURCE_FAULT_STATUS_CLASS_SET: ReadonlySet<string> = new Set(SOURCE_FAULT_STATUS_CLASSES);
function projectUnavailableByClass(raw: unknown): Record<string, number> | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const out: Record<string, number> = {};
  for (const [cls, n] of Object.entries(raw as Record<string, unknown>)) {
    if (!SOURCE_FAULT_STATUS_CLASS_SET.has(cls)) continue;
    const v = clampNonNegInt(n);
    if (v > 0) out[cls] = Math.min(1000, v);
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

// RESTORE_TEST_REASON_CODE_SET is the CLOSED restore-test failure-code vocabulary: the row projects a
// downpipe's lastRestoreTestReason only when it is a member, and an out-of-vocabulary value collapses to the
// drift placeholder (G317) rather than to silence -- the raw string never rides either way.
const RESTORE_TEST_REASON_CODE_SET: ReadonlySet<string> = new Set(RESTORE_TEST_REASON_CODES);

// CRON_RESOLVE_CLASSES is the closed cron-resolution class vocabulary (mirrors CronResolveClass in
// sched/types.ts). The cron expression and the timezone STRING are never carried; only the class rides.
const CRON_RESOLVE_CLASSES: ReadonlySet<string> = new Set(["ok", "cron-parse", "tz-invalid", "no-next-fire"]);

// BLACKOUT_RESOLVE_CLASSES mirrors the closed BlackoutResolveClass vocabulary (sched/types.ts, G322). The row
// projection forwards a class ONLY when it is a member, so an unexpected value is dropped, never propagated.
export const BLACKOUT_RESOLVE_CLASSES: ReadonlySet<string> = new Set(["ok", "hop-ceiling-fired-inside-window", "degenerate-window-inert", "end-walk-exhausted"]);

// SupportDownpipeState is the FULL roster row shape GET /downpipes returns (moved here from support.ts, which
// was at its module-size budget: this is the downpipe-row domain, and support.ts imports it back as the type of
// the roster it maps over). Behaviour and field semantics are unchanged.
export type SupportDownpipeState = {
  config: { id: string; name: string; enabled: boolean; cadenceSeconds: number; source: { type: string; include?: string[]; exclude?: string[]; accountId?: string; zoneId?: string; secrets?: unknown[]; cfConfigMode?: string }; schedule?: { blackoutWindows?: unknown[] } };
  lastRunId: string | null;
  inFlight: boolean;
  // G299: the monotone sealed-run counter + the per-destination anchor map the engine persists on the downpipe
  // (sched/types.ts). They are the ONLY evidence that separates a destination configured minutes ago from one
  // that has never held a copy since March, and the pack could not carry the distinction without them. Counts
  // only (the anchor's KEYS are the customer's own destination ids, which already ride on this row).
  sealedRuns?: number;
  replAnchors?: Record<string, number>;
  lastRestoreTestAt?: number;
  lastRestoreTestOk?: boolean;
  // scheduled-restore-fail-reason: the CLOSED coarse code for the last scheduled restore-test FAILURE + the
  // consecutive-failure streak (persisted on the downpipe state; absent when currently healthy). Redaction-safe.
  lastRestoreTestReason?: string;
  restoreTestConsecutiveFailures?: number;
  // lastRestoreOom (INFRA isolate-oom-restore): the restore-subsystem OOM-risk marker the scheduled restore test
  // stamps -- the largest single record the drill buffered WHOLE, the memory-safe ceiling, and whether it crossed.
  lastRestoreOom?: { at: number; maxRecordBytes: number; safeBytes: number; overSafe: boolean };
  // restoreTestStartedAt (support-pack mode restore-test-tick-killed): the drill in-flight marker; present +
  // older than the lease = a scheduled restore test whose cron tick was killed mid-drill (attempted-but-incomplete).
  restoreTestStartedAt?: number;
  integrityVerified?: { at: number; how: string };
  // lastSealVerify carries the redaction-safe verdict whole; tier0Cause (mode tier0-only-reason-unknown)
  // says WHY a verified Tier-0 verdict skipped the decrypt sample (break-glass / sample-off / too-large),
  // and attempts/recovered (mode runlog-sig-stale-window) expose a verdict that self-healed after a
  // read-after-write retry -- the always-on at-seal signal of a transient RUNLOG body-vs-sig window.
  lastSealVerify?: { status: string; tier: string; sampled: number; at: number; reason?: string; tier0Cause?: string; via?: string; attempts?: number; recovered?: boolean };
  // restorability assurance the engine already persists on the downpipe (B2): the offline-restorability
  // proof (who is projected to a boolean, the verified prover email is NEVER carried), the rotating
  // full-decrypt coverage cursor, and the RTO drill samples. The /downpipes route returns the full state;
  // these ride in but were not declared/copied before.
  restoreProven?: { at: number; by: string | null; method: string; runId: string };
  deepVerify?: { runId: string; cursor: number; records: number; updatedAt: number; lastFullPassAt?: number };
  recoverySamples?: Array<{ at: number; durationMs: number; bytesVerified: number; recordsVerified: number }>;
  // cfConfigDiscovery (WS-D #2) is the cached cf-config surface-discovery result the engine already
  // persists on the downpipe and returns unredacted from /downpipes: which product surfaces the last probe
  // found PRESENT (captured), definitively EMPTY (skipped), or UNAVAILABLE (errored, no plan/scope/transient).
  // The arrays hold FIXED surface.id strings (e.g. "dns", "zone-settings"), a closed product vocabulary, NOT
  // customer data (the zone/account id is interpolated into the request URL, never the id). Projecting it lets
  // support see a "my CF config backup is silently missing surfaces" fault. Optional: absent for a non-cf-config
  // downpipe (or one that never discovered).
  // gated (split out of unavailable) = surfaces the account's PLAN does not include (a definitive
  // entitlement gate), BENIGN, the backup is complete w.r.t. the account; the diagnosis bot ignores it
  // (like empty), so it is NOT lumped with the actionable `unavailable` faults. Optional so a discovery
  // cache persisted before this field existed still reads (projected with `?? []`).
  cfConfigDiscovery?: { at: number; present: string[]; empty: string[]; gated?: string[]; unavailable: string[]; unavailableByClass?: Record<string, number>; truncated?: string[] };
  // nextRunAt (epoch ms) + inFlightSince let the pack reason about a WEDGED/overdue downpipe (per-downpipe
  // nextRunAt vs the bundle's generatedAt = the due-index-drift signal at the downpipe level). cronResolve is
  // the closed cron-resolution class (SCHED cron-runtime-fallback-to-cadence / invalid-tz-runtime /
  // impossible-cron-runtime); the cron/timezone STRINGS never ride (no-custody), only the class + when.
  nextRunAt?: number;
  inFlightSince?: number;
  cronResolve?: { class: string; at: number };
  // blackoutResolve (G322): the closed outcome of applying this downpipe's blackout (change-freeze) windows at
  // the last reschedule. Projected by support-sections-downpipes.ts; window minutes/days never ride.
  blackoutResolve?: { class: string; at: number };
};

// SupportDownpipeRow is the STRUCTURAL slice of a roster row the projections below actually need: the source
// config (for the self-identity derivation) and the blackout stamp. Narrower than SupportDownpipeState so the
// projector states its real dependency, and so a test can drive it with a minimal fixture.
export interface SupportDownpipeRow {
  config: { id: string; source: DownpipeState["config"]["source"] };
  blackoutResolve?: { class: string; at: number };
}

// StateRefusedRow is one refusal already projected by fetchSchedulerSignals (closed class, clamped ints). We
// re-read it from the scheduler section rather than re-fetching, so the join costs no extra DO round trip.
type StateRefusedRow = { downpipeId: string; class: string; at: number; count: number; storedVersion: number; supportedVersion: number };

// stateRefusalIndex builds the downpipeId -> refusal lookup from the ALREADY-PROJECTED scheduler section.
// Returns an empty map when the section faulted or carried no refusals (so the join simply adds nothing).
export function stateRefusalIndex(schedulerSignals: Record<string, unknown>): Map<string, StateRefusedRow> {
  const out = new Map<string, StateRefusedRow>();
  const sr = schedulerSignals.stateRefusals as { downpipes?: unknown } | undefined;
  if (sr === undefined || sr === null || !Array.isArray(sr.downpipes)) return out;
  for (const row of sr.downpipes as StateRefusedRow[]) {
    if (typeof row?.downpipeId === "string" && STATE_REFUSED_CLASSES.has(row.class)) out.set(row.downpipeId, row);
  }
  return out;
}

// projectDownpipeDiagnostics returns the extra per-downpipe fields the pack now carries. Spread into the
// downpipes[] row by support.ts. Returns {} for a healthy, fully-identified, never-refused downpipe, so a clean
// fleet's rows are byte-identical to before.
export function projectDownpipeDiagnostics(d: SupportDownpipeRow, refusals: Map<string, StateRefusedRow>): Record<string, unknown> {
  const out: Record<string, unknown> = {};

  // blackoutResolve (G322): the CLOSED outcome of applying this downpipe's declared blackout (change-freeze)
  // windows at the last reschedule. "hop-ceiling-fired-inside-window" is a SILENT change-freeze VIOLATION (the
  // deferral loop gave up and the run will fire inside the customer's declared freeze); "degenerate-window-inert"
  // is a window with startMinute === endMinute, an empty half-open interval that has never once applied (the
  // operator believes they have a freeze that does not exist). Both were previously invisible. The class + the
  // evaluation time only: window minutes and days NEVER ride, consistent with the schedule-string exclusion.
  // Gated on the closed vocabulary; "ok" is carried too, so "the freeze applied cleanly" is a positive answer
  // rather than an absence a reader has to guess at.
  const br = d.blackoutResolve;
  if (br && typeof br.class === "string" && BLACKOUT_RESOLVE_CLASSES.has(br.class)) {
    out.blackoutResolve = { class: br.class, ...(typeof br.at === "number" && Number.isFinite(br.at) ? { at: Math.floor(br.at) } : {}) };
  }

  // selfIdentity (G282): whether this downpipe's stored source config still carries the NATIVE ids a roster
  // rebuild needs (a kv namespaceId / r2 bucketName / d1 databaseId, or a Secrets Store storeId on every bound
  // secret). A source missing them is one the engine cannot re-identify from its own config, so after a control-
  // plane loss the downpipe cannot be reconstructed -- a posture that is un-reconstructable and, until now,
  // discoverable only by the customer reading their own config. Derived from the SAME fields buildAdapter itself
  // falls back on, so it cannot drift from the behaviour it describes. A boolean + a closed class; no id rides.
  if (d.config?.source !== undefined) {
    const degraded = selfIdentityDegraded(d.config.source);
    if (degraded) {
      out.selfIdentityDegraded = true;
      out.selfIdentityClass = selfIdentityClass(d.config.source);
    }
  }

  // stateRefused (G095/G210): this downpipe's persisted dp: record was REFUSED at read time by the schema guard
  // -- the engine was ROLLED BACK and is reading new-shape state (schema-newer), or the version stamp is corrupt
  // (schema-version-malformed). The downpipe is skipped BEFORE a run row is ever created, so it silently stops
  // producing runs and the pack shows only growing staleness with no failed run to explain it. Joining the
  // refusal onto its row turns an INDETERMINATE "stale, no runs, no errors" into a named rollback-skew answer.
  // The two version ints are the whole diagnosis; the record's CONTENTS never ride.
  const refusal = refusals.get(d.config?.id ?? "");
  if (refusal !== undefined) {
    out.stateRefused = {
      class: refusal.class,
      at: clampNonNegInt(refusal.at),
      count: clampNonNegInt(refusal.count),
      storedVersion: clampNonNegInt(refusal.storedVersion),
      supportedVersion: clampNonNegInt(refusal.supportedVersion),
    };
  }

  return out;
}

// selfIdentityDegradedCount is the FLEET count of downpipes whose source config cannot re-identify itself
// (G282), the roster-level twin of the per-row boolean. 0 is meaningful (a fully reconstructable fleet).
export function selfIdentityDegradedCount(downpipes: readonly SupportDownpipeRow[]): number {
  return downpipes.reduce((n, d) => (d.config?.source !== undefined && selfIdentityDegraded(d.config.source) ? n + 1 : n), 0);
}

// ProjectRowOpts are the fleet-level joins the row projection needs, each ALREADY fetched by the bundle (no
// DEST_FANOUT_CAP bounds the projected fan-out lists. A downpipe fanning out to more destinations than this has
// a configuration problem the roster section already carries; the pack does not need the tail.
const DEST_FANOUT_CAP = 32;

// configuredDestinationIds reads the downpipe's INTENDED fan-out off its own config, exactly as the run path
// does. destinationIds (the list) supersedes destinationId (the legacy singular); an ABSENT pin means "the
// default destination", which is not a fan-out and yields [] -- so a default-destination downpipe never gets a
// never-reported row, because it named no destination to fail to report.
//
// THE DOUBLE-COUNT. This used to read the RAW destinationIds array (blanks dropped, nothing else), while the
// anchor map beside it is stamped from allDestinationIds -- primary + DE-DUPLICATED replicas, which is what the
// run path actually writes to. A config carrying the same destination id twice therefore produced a configured
// list of length 2 for ONE destination, so that destination appeared TWICE in neverReportedIds and
// neverReportedCount read 2 where the truth is 1. The count is the number the bot's threshold and the pack's
// severity both read, so a duplicate id in one config inflated the finding on every consumer at once. There is
// now ONE resolver on both sides of the join: allDestinationIds, the same function the run path and
// nextReplAnchors use, so the configured set and the anchor keys cannot drift again. The cap still bounds the
// tail (the roster section carries an over-wide fan-out).
function configuredDestinationIds(config: { destinationIds?: unknown; destinationId?: unknown }): string[] {
  const ids = Array.isArray(config.destinationIds) ? config.destinationIds.filter((id): id is string => typeof id === "string") : undefined;
  const single = typeof config.destinationId === "string" && config.destinationId !== "" ? config.destinationId : undefined;
  return allDestinationIds({
    ...(ids !== undefined ? { destinationIds: ids } : {}),
    ...(single !== undefined ? { destinationId: single } : {}),
  }).slice(0, DEST_FANOUT_CAP);
}

// projectReplication (G299) emits the replication block: what HAS reported, what the downpipe was CONFIGURED to
// fan out to, and the difference -- the destinations that have never reported at all. That difference is the
// escalate state ("this destination holds no copy of anything, and has not since the day it was configured"),
// and it is what the console can see and the pack could not. Absent entirely when the downpipe has neither a
// configured fan-out nor a heartbeat: an honest absence, not an empty claim.
//
// `readable` IS THE SECOND ARGUMENT AND IT IS LOAD-BEARING (G299). The never-reported claim is a fact about
// HEARTBEATS, and it can only be made by code that actually READ them. When the /replication read faulted the
// section degraded to an empty map, and the difference (configured minus reported) then named EVERY configured
// destination -- so one transient DO blip made the pack assert, of a destination that holds every run, that it
// has never held anything. That row is not merely undiscriminated: it is FALSE, and it is the row a support
// engineer would escalate on. On an unreadable read the block still carries the intended fan-out (which comes
// off the downpipe's own config and is always readable) and makes NO claim about what has reported.
    // THE AGE OF THE SILENCE IS THE WHOLE DIAGNOSIS. A destination configured five minutes ago has
    // reported no heartbeat. So has a destination that has held no copy of any backup since March. The rows
    // are byte-identical, so an alarm over row absence fires on the customer who has done nothing wrong, and
    // a bot that cries wolf devalues every true finding it reports. neverReportedSealedRunsSince is the
    // discriminator: how many backups have SUCCEEDED since this destination entered the fan-out and still
    // produced no copy of anything. It is a COUNT (sealedRuns minus the destination's anchor), never a
    // timestamp of a customer event. 0 = "no backup has succeeded since you added it": nothing is owed,
    // nothing is wrong. It is the MAXIMUM across the never-reported destinations, because the worst one is
    // the one the customer needs told about.
//
// neverReportedUnanchoredCount is the honest absence beside it: destinations whose anchor the engine does not
// hold (a record written before the anchor shipped, or imported), so their age CANNOT be established. They are
// counted and NOT guessed at, and the bot is required to stay silent on them.
function projectReplication(
  config: { destinationIds?: unknown; destinationId?: unknown },
  rows: Array<Record<string, unknown>> | undefined,
  readable: boolean,
  anchors: Record<string, number> | undefined,
  sealedRuns: number,
): { replication?: Record<string, unknown> } {
  const reported = rows ?? [];
  const configured = configuredDestinationIds(config);
  if (reported.length === 0 && configured.length === 0) return {};
  const reportedIds = new Set(reported.map((r) => (typeof r.id === "string" ? r.id : "")));
  const neverReportedIds = readable ? configured.filter((id) => !reportedIds.has(id)) : [];
  const since = replNeverReportedSince(neverReportedIds, anchors, sealedRuns);
  return {
    replication: {
      ...(reported.length > 0 ? { destinations: reported } : {}),
      ...(configured.length > 0 ? { configuredIds: configured } : {}),
      ...(readable ? {} : { heartbeatsUnreadable: true }),
      ...(neverReportedIds.length > 0 ? { neverReportedIds, neverReportedCount: neverReportedIds.length } : {}),
      ...(neverReportedIds.length > 0 && since.maxSince !== undefined ? { neverReportedSealedRunsSince: clampNonNegInt(since.maxSince) } : {}),
      ...(neverReportedIds.length > 0 && since.unanchored > 0 ? { neverReportedUnanchoredCount: clampNonNegInt(since.unanchored) } : {}),
    },
  };
}

// extra DO round trip): the per-destination replication heartbeats, the configured-destination roster (null
// when that read faulted, so the dangling check is SKIPPED rather than producing false positives), the
// per-downpipe pre-run seal-dispatch faults (G163), the downpipes whose freshness rule cannot arm (G076), and
// the state-refusal index (G095/G210).
export interface ProjectRowOpts {
  replication: Record<string, Array<Record<string, unknown>>> | null;
  destIdSet: Set<string> | null;
  sealErrors: Record<string, Record<string, unknown>>;
  freshnessIndex: Map<string, string>;
  // freshnessTruncation (G325 x G076): the downpipes the freshness-fault map REFUSED at its cap, and whether
  // any refusal could not be named. Without this the row past the cap carries NO freshness field at all and
  // the projector's convention reads an absent field as "does not apply", i.e. as a working staleness rule.
  freshnessTruncation: CapTruncationSubjectIndex;
  refusalIndex: Map<string, StateRefusedRow>;
}

// projectDownpipeRow builds ONE downpipes[] row: the config facts the operator chose, the run/restore/verify
// verdicts the engine persisted on the downpipe, and the fleet-level signals joined onto it. Moved out of
// support.ts (which is at its module-size budget) for the same reason projectDownpipeDiagnostics was: this is
// the downpipe-row domain. Behaviour is unchanged. Every field is a closed enum / boolean / clamped int /
// timestamp, or the customer's OWN labels (their downpipe id + name, their selector prefixes, their
// destination ids) -- never a record name, a record value, a secret, an endpoint, a bucket or an email.
export function projectDownpipeRow(d: SupportDownpipeState, opts: ProjectRowOpts): Record<string, unknown> {
  const { replication, destIdSet, sealErrors, freshnessIndex, freshnessTruncation, refusalIndex } = opts;
  return {
    id: d.config.id,
    name: d.config.name,
    enabled: d.config.enabled,
    cadenceSeconds: d.config.cadenceSeconds,
    sourceType: d.config.source.type,
    // The crawl SELECTOR (include/exclude prefixes) disambiguates a 0-record run (empty source vs an
    // over-narrow/typo'd selector vs all-vanished) and a discovery account/zone mismatch, both previously
    // unanswerable. Prefixes are operator-chosen labels (the bot quarantines them), never customer data.
    selector: { include: d.config.source.include ?? [], exclude: d.config.source.exclude ?? [] },
    // Config shape COUNTS (A9 G024): a silently dropped form row (a secret binding, a schedule blackout
    // window, a cf-config include entry) is otherwise indistinguishable from operator intent. Counts only,
    // never the values: secretsRowCount for a secrets source, scheduleWindowCount for blackout windows, and
    // cfConfigIncludeCount for a MANUAL cf-config selection (0 under manual = the all-surfaces sentinel).
    ...(d.config.source.type === "secrets" && Array.isArray(d.config.source.secrets) ? { secretsRowCount: d.config.source.secrets.length } : {}),
    ...(Array.isArray(d.config.schedule?.blackoutWindows) && d.config.schedule.blackoutWindows.length > 0 ? { scheduleWindowCount: d.config.schedule.blackoutWindows.length } : {}),
    ...(d.config.source.type === "cf-config" && d.config.source.cfConfigMode === "manual" ? { cfConfigIncludeCount: (d.config.source.include ?? []).length } : {}),
    ...(d.config.source.accountId ? { accountId: d.config.source.accountId } : {}),
    ...(d.config.source.zoneId ? { zoneId: d.config.source.zoneId } : {}),
    inFlight: d.inFlight,
    // cpu-kill-wedged-slice / sliced-runs-disabled-oom (OOM part): a run that is inFlight but whose in-flight
    // LEASE has EXPIRED is a WEDGED / crashed / OOM-killed / CPU-killed run -- an uncatchable isolate death
    // (OOM / CPU kill) leaves no completion, so the lease is the ONLY signal, and this is the read-side
    // stalled indicator. Surfaces the lease start + a computed `stalled` boolean using the SAME predicate the
    // scheduler's own reclaim + beacon use (INFLIGHT_LEASE_MS), only for a downpipe actually in flight.
    // Redaction-safe: a timestamp + a boolean.
    ...(d.inFlight === true && typeof d.inFlightSince === "number" ? { inFlightSince: d.inFlightSince, stalled: Date.now() - d.inFlightSince > INFLIGHT_LEASE_MS } : {}),
    lastRunId: d.lastRunId,
    // nextRunAt / inFlightSince (clamped timestamps): the scheduled next fire + the in-flight lease start,
    // so the pack can spot a downpipe whose nextRunAt is long past `generatedAt` (wedged / not being
    // dispatched) -- the per-downpipe view of the due-index / scheduler-liveness signals. Timestamps only.
    ...(typeof d.nextRunAt === "number" && Number.isFinite(d.nextRunAt) ? { nextRunAt: Math.floor(d.nextRunAt) } : {}),
    ...(typeof d.inFlightSince === "number" && Number.isFinite(d.inFlightSince) ? { inFlightSince: Math.floor(d.inFlightSince) } : {}),
    // cronResolve (SCHED cron-runtime-fallback-to-cadence / invalid-tz-runtime / impossible-cron-runtime):
    // the closed class of the last cron-schedule resolution. Forwarded ONLY when the class is a member of the
    // closed set (defence-in-depth redaction: an unexpected value is dropped, never propagated); the cron and
    // timezone STRINGS are never carried (no-custody). Absent for a cadence-only downpipe.
    // G317: an out-of-vocabulary class no longer drops the WHOLE cronResolve block (which would read as "this
    // downpipe has no cron", the healthy state). The block rides with the drift placeholder; the raw class,
    // the cron expression and the timezone string are never carried.
    ...(d.cronResolve && typeof d.cronResolve.class === "string" && d.cronResolve.class !== ""
      ? { cronResolve: { class: gateClosed(d.cronResolve.class, CRON_RESOLVE_CLASSES) ?? UNKNOWN_CODE, ...(typeof d.cronResolve.at === "number" && Number.isFinite(d.cronResolve.at) ? { at: Math.floor(d.cronResolve.at) } : {}) } }
      : {}),
    ...(d.lastRestoreTestAt !== undefined ? { lastRestoreTestAt: d.lastRestoreTestAt, lastRestoreTestOk: d.lastRestoreTestOk } : {}),
    // scheduled-restore-fail-reason: WHY the last scheduled restore test failed (a CLOSED coarse code) +
    // how many have failed IN A ROW, so a pack read days after the notify ring rolled over still carries
    // the cause. Gated on the closed vocabulary (a non-member code is dropped: defence-in-depth redaction);
    // the streak rides only when positive. Absent = currently healthy (the last test passed, or none yet).
    // G317: a reason code the pack's allowlist has not learned yet no longer VANISHES, leaving a downpipe
    // whose restore tests have failed for weeks reading as though it never reported a cause at all.
    ...(gateClosed(d.lastRestoreTestReason, RESTORE_TEST_REASON_CODE_SET) !== undefined ? { lastRestoreTestReason: gateClosed(d.lastRestoreTestReason, RESTORE_TEST_REASON_CODE_SET) } : {}),
    ...(typeof d.restoreTestConsecutiveFailures === "number" && d.restoreTestConsecutiveFailures > 0 ? { restoreTestConsecutiveFailures: d.restoreTestConsecutiveFailures } : {}),
    // lastRestoreOom (INFRA isolate-oom-restore): the restore-subsystem OOM-risk marker -- the largest single
    // record the last restore-test drill buffered WHOLE, the memory-safe ceiling, and whether it crossed
    // (overSafe = a record big enough to risk an isolate OOM on restore). Re-clamped to ints + a flag; the
    // stored overSafe is re-derived defensively so a spoofed flag can't ride. Present only when the DO stamped it.
    ...(d.lastRestoreOom && typeof d.lastRestoreOom.maxRecordBytes === "number" && typeof d.lastRestoreOom.safeBytes === "number"
      ? { lastRestoreOom: { at: clampNonNegInt(d.lastRestoreOom.at), maxRecordBytes: clampNonNegInt(d.lastRestoreOom.maxRecordBytes), safeBytes: clampNonNegInt(d.lastRestoreOom.safeBytes), overSafe: clampNonNegInt(d.lastRestoreOom.maxRecordBytes) > clampNonNegInt(d.lastRestoreOom.safeBytes) } }
      : {}),
    // restore-test-tick-killed: a drill in-flight marker still set + older than the lease is a scheduled
    // restore test whose cron tick was KILLED mid-drill (attempted but incomplete) -- surfaced as
    // restoreTestStalled + the marker time, the read-side twin of the run's `stalled` indicator. The marker
    // is cleared on any completion, so a fresh/just-started drill reads stalled:false until it ages out.
    ...(typeof d.restoreTestStartedAt === "number" ? { restoreTestStartedAt: d.restoreTestStartedAt, restoreTestStalled: Date.now() - d.restoreTestStartedAt > INFLIGHT_LEASE_MS } : {}),
    ...(d.integrityVerified ? { integrityVerified: d.integrityVerified } : {}),
    // Verify-at-seal verdict (ENG-RST-01): redaction-safe (status/tier/sampled/at + coarse reason).
    ...(d.lastSealVerify ? { lastSealVerify: d.lastSealVerify } : {}),
    // Restorability assurance (B2). restoreProven = the offline-restorability proof: WHEN it last passed,
    // the METHOD (blind-test|keyless-attest), and the run proven, but `by` (the prover's verified Access
    // EMAIL) is PROJECTED to a boolean `attributed`; the address itself is never carried (no-custody: the
    // pack holds zero emails). deepVerify = the rotating full-decrypt coverage (lastFullPassAt answers "has
    // EVERY record been verified, and how recently"). recoverySamples = RTO drill measurements, FOLDED to a
    // count + the most-recent sample (counts/ms only) so a long ring never bloats the pack.
    ...(d.restoreProven ? { restoreProven: { at: d.restoreProven.at, method: d.restoreProven.method, runId: d.restoreProven.runId, attributed: d.restoreProven.by != null } } : {}),
    ...(d.deepVerify ? { deepVerify: { runId: d.deepVerify.runId, cursor: d.deepVerify.cursor, records: d.deepVerify.records, ...(d.deepVerify.lastFullPassAt !== undefined ? { lastFullPassAt: d.deepVerify.lastFullPassAt } : {}) } } : {}),
    ...(Array.isArray(d.recoverySamples) && d.recoverySamples.length > 0
      ? { recoverySamples: { count: d.recoverySamples.length, last: ((s) => ({ at: s.at, durationMs: s.durationMs, bytesVerified: s.bytesVerified, recordsVerified: s.recordsVerified }))(d.recoverySamples[d.recoverySamples.length - 1]!) } }
      : {}),
    // cf-config surface discovery (WS-D #2): the last probe's present/empty/gated/unavailable surface-id sets,
    // so a "my CF config backup is silently missing surfaces" fault is visible (a surface drifting from present
    // -> empty/gated/unavailable means it stopped being captured). Surface ids are a FIXED product vocabulary
    // (not customer data); each list is CAPPED to 64 because a total outage could fill `unavailable` with the
    // whole surface catalogue, which would otherwise bloat the pack. `gated` is the BENIGN plan/entitlement
    // bucket (split from `unavailable`) the bot ignores; `unavailableCount` is the TRUE, UNCAPPED `unavailable`
    // length so the bot's "could not read N surfaces" prose stays accurate even when the array is capped at 64.
    // Present only when the source state has it.
    ...(d.cfConfigDiscovery
      ? {
          cfConfigDiscovery: {
            at: d.cfConfigDiscovery.at,
            present: (d.cfConfigDiscovery.present ?? []).slice(0, 64),
            empty: (d.cfConfigDiscovery.empty ?? []).slice(0, 64),
            gated: (d.cfConfigDiscovery.gated ?? []).slice(0, 64),
            unavailable: (d.cfConfigDiscovery.unavailable ?? []).slice(0, 64),
            unavailableCount: (d.cfConfigDiscovery.unavailable ?? []).length,
            // unavailableByClass (G006): the closed STATUS CLASS behind the bare `unavailable` id list. A token
            // that lost a scope (403 -- actionable, permanent, and auto-mode will skip those surfaces from
            // EVERY backup forever) and a transient Cloudflare outage (5xx -- self-healing) produced identical
            // evidence: a list of ids. Closed classes -> clamped counts only.
            ...(projectUnavailableByClass(d.cfConfigDiscovery.unavailableByClass) !== undefined ? { unavailableByClass: projectUnavailableByClass(d.cfConfigDiscovery.unavailableByClass) } : {}),
            // truncated (G006): the surfaces whose probe hit a PAGINATION truncation. A truncated read is
            // classified `present` -- correctly, partial data IS data -- which silently discarded the early
            // warning that the surface is larger than the engine walked.
            ...(Array.isArray(d.cfConfigDiscovery.truncated) && d.cfConfigDiscovery.truncated.length > 0
              ? { truncated: d.cfConfigDiscovery.truncated.filter((t) => typeof t === "string").slice(0, 64) }
              : {}),
          },
        }
      : {}),
    // Per-destination replication heartbeats (A3.2): WHICH destination(s) are failing for this downpipe.
    // A failed run records the down destination here (not on the run row), so this is the ONLY place a
    // single-destination outage is attributable. Redaction-safe (dest id = customer label; coarse reason).
    //
    // G299: THE INTENDED FAN-OUT RIDES WITH IT, and without it the row was unreadable. A destination that has
    // NEVER reported replication state has no heartbeat, so it is simply ABSENT from destinations[] -- and row
    // absence only means something against the set of destinations the downpipe was CONFIGURED to fan out to,
    // which the pack did not carry anywhere. So "P is configured to fan out to D2 and D2 has never once
    // replicated" (escalate: that copy of the backup does not exist) and "P was never configured to fan out to
    // D2 at all" (entirely legitimate; D2 belongs to some other downpipe) produced a BYTE-IDENTICAL row. The
    // console can tell them apart because the browser holds cfg.destinationIds; the ENGINE holds the same config
    // right here, at pack-build time, and simply did not project it.
    //
    // The old `if (rows.length > 0)` guard also ERASED the worst case: a downpipe on which NOT ONE destination
    // has ever reported dropped the replication key entirely, so the most severe instance of the gap was the one
    // the pack hid hardest. The key is now emitted whenever the downpipe has a configured fan-out, reported or
    // not. Destination ids are already an accepted class on this exact row (they ride in destinations[].id
    // above): they are the customer's OWN labels, not a secret, and no bucket, endpoint or credential is here.
    ...(projectReplication(
      d.config as { destinationIds?: unknown; destinationId?: unknown },
      replication === null ? undefined : replication[d.config.id],
      replication !== null,
      d.replAnchors,
      d.sealedRuns ?? 0,
    )),
    // danglingDestinationRef (A4 G044/G268): this downpipe pins a destination id absent from the roster, so
    // its runs fail loudly rather than writing anywhere. A boolean only; the roster join is engine-computed
    // (both /downpipes and /destinations are DO-resident). Skipped (never set) when the roster read faulted.
    ...(destIdSet && danglingDestinationRef(d.config as { destinationId?: unknown; destinationIds?: unknown }, destIdSet) ? { danglingDestinationRef: true } : {}),
    // lastSealError (G163): the PRE-RUN seal-dispatch fault, attributed to THIS downpipe. The throw lands
    // before a run index is allocated, so it produces no run row at all: without this the downpipe simply
    // stops producing runs and the pack shows growing staleness with nothing to explain it. A closed class +
    // a clamped time + the consecutive-fault streak (the same class streaking = a standing, not a flaky, fault).
    ...(sealErrors[d.config.id] ? { lastSealError: sealErrors[d.config.id] } : {}),
    // freshnessComputable (G076): FALSE means the shared staleness rule can never ARM for this downpipe (a
    // non-finite cadence, or a newest run whose startedAt does not parse), so the map and the overview read
    // "Fresh" indefinitely -- "the map said Fresh for weeks while my backups had stopped". The CAUSE rides in
    // schedDiag.freshnessFaults; only a downpipe that is actually uncomputable carries the field.
    //
    // freshnessComputableUnknown (G325 x G076): THE THIRD THING, and the reason this row stopped lying. The
    // fault map REFUSES a new downpipe once full rather than evicting an old one, so past the cap a downpipe
    // with an unarmable staleness rule is ABSENT from the map, and an absent row carried no field, and no
    // field reads as "the staleness rule is fine". The count in schedDiag.capTruncations said some row was
    // dropped and could not say which, so the clean assertion stayed HERE while the caveat sat in a different
    // section. Now the refusal names its subject, and this row says the one thing that is actually true of
    // it: we do not know whether this downpipe's staleness rule can arm.
    //
    // The order matters. A downpipe IN the map has a KNOWN answer, so the false wins and no unknown is
    // emitted -- a downpipe refused earlier and admitted later must not carry a caveat over a fact. When the
    // refusal record is `incomplete` no subject list can be trusted, so EVERY unmarked downpipe takes the
    // unknown: at that point the honest reading of the fleet is that any row may be the dropped one.
    ...(freshnessIndex.has(d.config.id)
      ? { freshnessComputable: false }
      : freshnessTruncation.named.has(d.config.id) || freshnessTruncation.incomplete
        ? { freshnessComputableUnknown: true }
        : {}),
    // blackoutResolve (G322) / selfIdentityDegraded + selfIdentityClass (G282) / stateRefused (G095/G210):
    // per-row derivations over state the roster read already returned (stateRefused joins the scheduler
    // section fetched above -- no extra DO round trip). Each is gated on its own closed vocabulary inside the
    // projector, and a healthy downpipe contributes nothing. See support-sections-downpipes.ts.
    ...projectDownpipeDiagnostics(d as SupportDownpipeRow, refusalIndex),
  };
}

// ---- G318: recoveryRto ------------------------------------------------------------------------------------
// The RTO estimator's own SELF-ASSESSMENT, which the pack has never carried at all: GET /rto exists on the DO
// and NO gatherer fetched it, so every field the estimator computes (including the two new ones) landed in a
// route nothing read. This is the delivery half.
//
// The two facts it adds are the ones support could not answer:
//
//   rejectedSamples -- "basedOnDrills says 2 but we ran 15 restore tests". The other 13 carried a non-finite
//   duration or zero verified bytes and were filtered out of the throughput maths with NO record. The FILTER is
//   correct (a zero-duration sample carries no throughput signal and would corrupt the estimate); its SILENCE
//   was the bug, because the pack shows recoverySamples.count and basedOnDrills side by side and the
//   discrepancy read as a bug in one of them.
//
//   degradationCause -- "why is our RTO confidence stuck at low despite frequent drills". The 3-value
//   confidence enum ERASES the cause, and the three causes want three DIFFERENT answers: archive-size-unknown
//   ("we cannot size your archive", so the estimate is a raw observation and cannot be projected to the whole
//   archive at all), single-drill ("run more than one drill"), thin-sample ("your drills cover a sliver of the
//   archive"). A fleet that ran 15 drills and has no usable sample used to read IDENTICALLY to one that never
//   drilled.
//
// Redaction: an explicit ALLOWLIST, not a spread. The estimate carries the downpipe `name` (a customer label)
// and free-text `reason`/`caveat`, and NONE of the three is projected -- degradationCause carries the cause as
// a closed enum, which is what a diagnosis actually needs. Only the downpipe id (the label class the pack
// already carries), booleans, clamped ints and two closed enums cross. A fetch/parse fault PROPAGATES to
// section() so an unreadable estimator reads "error", never a clean "empty".
const RTO_CONFIDENCE_SET: ReadonlySet<string> = new Set(["none", "low", "medium", "high"]);
const RTO_REJECT_REASON_SET: ReadonlySet<string> = new Set(RTO_REJECT_REASONS);
const RTO_DEGRADATION_CAUSE_SET: ReadonlySet<string> = new Set(RTO_DEGRADATION_CAUSES);
const RTO_DOWNPIPES_CAP = 200;
function projectRtoEstimate(raw: unknown): Record<string, unknown> | null {
  const e = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
  const confidence = typeof e.confidence === "string" && RTO_CONFIDENCE_SET.has(e.confidence) ? e.confidence : undefined;
  if (confidence === undefined) return null; // a drifted estimate is DROPPED whole, never half-carried
  const rs = (typeof e.rejectedSamples === "object" && e.rejectedSamples !== null ? e.rejectedSamples : null) as Record<string, unknown> | null;
  const rsReason = rs !== null && typeof rs.lastReason === "string" && RTO_REJECT_REASON_SET.has(rs.lastReason) ? rs.lastReason : undefined;
  const rsCount = rs !== null ? (clampNonNegInt(rs.count) ?? 0) : 0;
  return {
    ...(typeof e.id === "string" ? { id: e.id.slice(0, 128) } : {}),
    known: e.known === true,
    confidence,
    ...(typeof e.estimateSeconds === "number" && Number.isFinite(e.estimateSeconds) ? { estimateSeconds: clampNonNegInt(e.estimateSeconds) } : {}),
    ...(typeof e.basedOnDrills === "number" && Number.isFinite(e.basedOnDrills) ? { basedOnDrills: clampNonNegInt(e.basedOnDrills) } : {}),
    ...(typeof e.observedThroughputBytesPerSec === "number" && Number.isFinite(e.observedThroughputBytesPerSec)
      ? { observedThroughputBytesPerSec: clampNonNegInt(e.observedThroughputBytesPerSec) }
      : {}),
    // Carried ONLY when a sample was actually excluded AND its reason is a closed member: a count with no
    // reason would say "we threw some away" and not why, which is the silence this gap exists to end.
    ...(rsCount > 0 && rsReason !== undefined ? { rejectedSamples: { count: rsCount, lastReason: rsReason } } : {}),
    ...(typeof e.degradationCause === "string" && RTO_DEGRADATION_CAUSE_SET.has(e.degradationCause) ? { degradationCause: e.degradationCause } : {}),
  };
}
export async function fetchRtoEstimates(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/rto"), { method: "GET" });
  const j = (await r.json()) as { fleet?: unknown; downpipes?: unknown };
  const fleet = projectRtoEstimate(j.fleet);
  const downpipes = (Array.isArray(j.downpipes) ? j.downpipes : []).slice(0, RTO_DOWNPIPES_CAP).flatMap((d) => {
    const p = projectRtoEstimate(d);
    return p === null ? [] : [p];
  });
  if (fleet === null && downpipes.length === 0) return {};
  return {
    ...(fleet !== null ? { fleet } : {}),
    ...(downpipes.length > 0 ? { downpipes } : {}),
  };
}
