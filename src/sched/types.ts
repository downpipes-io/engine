// Leaf module of shared scheduler/admin types, extracted to break the import cycles
// between sched/scheduler-do.ts (the scheduler DO) and the admin route spokes
// (admin/config-history, admin/point-in-time, admin/reports) plus notify.ts, all of which
// imported these types back from scheduler-do.ts while scheduler-do.ts imported their
// runtime. Every definition here is MOVED VERBATIM from scheduler-do.ts (or, for
// SealVerification, from seal/verify-at-seal.ts); behaviour is unchanged. scheduler-do.ts
// and verify-at-seal.ts re-export the symbols so existing by-name imports keep working.
//
// This module imports ONLY terminal leaves (admin/rto.ts has no imports), so it never
// imports back into any module that imports it.

import type { RtoSample } from "../admin/rto.ts";
import type { OpCounts } from "../meter.ts";
// seal/marker.ts is a terminal leaf (it imports nothing), so naming IncompleteByMarker on RunHistoryEntry
// keeps this module's leaf-only discipline (line 9) intact and introduces no cycle.
import type { IncompleteByMarker, IncompleteIds } from "../seal/marker.ts";

// Re-exported so the scheduler DO (and other importers of this leaf) can name OpCounts on RunHistoryEntry
// without a second import path.
export type { OpCounts } from "../meter.ts";

// LastConfigChange is the record of the most recent CONFIG write to a downpipe: which revision it
// produced, when, by whom, and WHICH FIELDS it moved. It lives here rather than beside the precondition
// logic (sched/downpipe-precondition.ts) so this leaf keeps its leaf-only import discipline: the
// precondition module names DownpipeState, so a type defined THERE and named HERE would point this
// module at a non-leaf. Field names only, never values.
export interface LastConfigChange {
  rev: number;
  at: string;
  by: string | null;
  fields: string[];
}

export interface SecretBindingSpec {
  name: string; // the source-native secret name (recorded and restored)
  binding: string; // the env binding the Worker reads it through
  // storeId is the Secrets Store store id this secret lives in. RECORDED (not used at run time: the
  // engine reads the secret through `binding`, not the store) so the persisted roster can REBUILD the
  // Worker binding after a deploy/wipe dropped it. attach needs store_id + secret_name to re-create a
  // secrets_store_secret binding (attach-plan.ts bindingFromSource); without storeId a re-attach cannot
  // reconstruct this secret. Optional for back-compat: a config saved before this field is reconstructable
  // only for its kv/r2 sources, and the secret re-attach is flagged unreconstructable until re-saved.
  storeId?: string;
}

// CfConfigMode is how a cf-config downpipe chooses WHICH surfaces to capture each run (defined here in
// the leaf types module so both the source-discovery helper and the scheduler import it without a cycle):
//   - "auto" (default): capture exactly the DISCOVERED present set (CfConfigDiscovery), refreshed daily,
//     so a run makes one GET per surface-in-use instead of one per all every surface in the registry.
//   - "manual": capture the operator's explicit source.include/exclude selection; discovery is advisory.
export type CfConfigMode = "auto" | "manual";

// CfConfigDiscovery is the cached result of the last surface-discovery probe for a cf-config downpipe
// (persisted on DownpipeState; the capture path reads `present`, the console shows the counts + `at`).
export interface CfConfigDiscovery {
  at: number; // epoch ms the probe finished
  present: string[]; // surfaces that returned real data -> captured
  empty: string[]; // surfaces that returned a definitive empty (account does not use them) -> skipped
  // gated = surfaces whose read returned a DEFINITIVE account-PLAN / entitlement gate (the account's plan
  // simply does not include the product) -> skipped, BENIGN: the backup is COMPLETE w.r.t. the account, so
  // there is nothing to capture and nothing actionable (like `empty`). Split out of `unavailable` so a
  // diagnosis/escalation consumer does NOT treat a non-Enterprise account's expected gating as a fault.
  gated: string[];
  // unavailable = surfaces whose read errored with an ACTIONABLE or AMBIGUOUS fault (a token-scope/permission
  // gap, a transient 5xx, a 429-after-retry, a network fault, an unrecognised error) -> skipped, re-checked
  // next probe. This is the conservative bucket: anything not a DEFINITIVE plan gate stays here so a real
  // token-scope gap is never silently hidden.
  unavailable: string[];
  // unavailableByClass (G006) is the CLOSED status-class -> count map behind `unavailable`. The id list alone
  // says WHICH surfaces are missing from every backup; it can never say WHY, so a token that lost a scope
  // ("auto-mode silently skips 12 surfaces from every backup") and a transient Cloudflare outage look
  // identical and only one of them is actionable. Classes are the closed SOURCE_FAULT_STATUS_CLASSES; counts
  // are clamped. Never a message, a request path or a CF error-code list.
  unavailableByClass?: Record<string, number>;
  // truncated (G006) are surfaces whose probe read hit a pagination truncation. They are classified `present`
  // (correctly: partial data IS data), which silently DISCARDS the early warning that the surface is large
  // enough to be at risk of a partial capture. Surface ids are the fixed product vocabulary already carried.
  truncated?: string[];
}

export interface SourceSpec {
  type: "kv" | "r2" | "secrets" | "d1" | "cf-config" | "workers" | "stream" | "images" | "artifacts";
  binding?: string; // the env binding for kv/r2/d1 (e.g. KV_uploads, R2_media, D1_app)
  namespaceId?: string; // for kv, recorded in the record
  bucketName?: string; // for r2, recorded in the record
  // databaseId is the D1 database's native id (a UUID). RECORDED, not used at run time (the engine reads
  // the database through `binding`); its purpose is RE-ATTACH after a deploy/wipe dropped the binding: the
  // attach path needs the database id to re-create a d1 binding (attach-plan.ts bindingFromSource), and it
  // gives a re-attached resource a STABLE identity to match back to this downpipe (so a re-protect can
  // reuse this downpipe and keep its history, never orphan it). Optional for back-compat: a d1 config saved
  // before this field is identified only by its binding (matchKeysForSource) and cannot be roster-rebuilt
  // until re-saved with the id. Mirrors namespaceId (kv) / bucketName (r2).
  databaseId?: string; // for d1, the native database UUID, recorded (re-attach + match-back identity)
  zoneId?: string; // for cf-config: the Cloudflare zone to snapshot (omit for an account-only downpipe)
  accountId?: string; // for cf-config AND workers: the Cloudflare account (the engine's own); cf-config uses it for account-scoped surfaces, workers lists the account's scripts
  secrets?: SecretBindingSpec[]; // for the secrets source: each secret and its binding
  cfConfigMode?: CfConfigMode; // for cf-config: auto (capture the discovered present set) | manual (capture include/exclude). Absent = auto.
  includeContent?: boolean; // for stream/images/artifacts: also capture the resource BYTES (video/image/repo blobs), size-gated, not just the metadata inventory. Absent/false = metadata only (the safe default: bytes can multiply a run's size and cost).
  include: string[];
  exclude: string[];
}

// BlackoutWindow is one maintenance / no-run window expressed in MINUTES SINCE LOCAL MIDNIGHT in the
// schedule's timeZone (so it tracks DST the same way the cron fields do). startMinute is inclusive,
// endMinute is EXCLUSIVE, both in [0, 1440]. A window that does not wrap (startMinute <= endMinute)
// blacks out [start, end); a window that WRAPS past midnight (startMinute > endMinute, e.g.
// 22:00-06:00 = {startMinute:1320, endMinute:360}) blacks out [start, 1440) U [0, end). An optional
// `days` filter (0=Sunday..6=Saturday) restricts the window to those weekdays; ABSENT means every
// day. A computed cron fire that lands inside an active window is DEFERRED to the first instant after
// the window (see deferPastBlackouts). Windows only ever PUSH a fire LATER; they never bring one
// earlier and never cancel a run.
export interface BlackoutWindow {
  days?: number[]; // 0-6 (Sunday=0); absent = every day
  startMinute: number; // inclusive, minutes since local midnight, 0-1440
  endMinute: number; // exclusive, minutes since local midnight, 0-1440
}

// DownpipeSchedule is the OPTIONAL cron / time-of-day / timezone / blackout schedule (DownpipeConfig
// .schedule). It is purely additive: cadenceSeconds remains the default cadence, and a config with
// no schedule (every pre-existing config) is byte-unchanged and scheduled exactly as before.
//   - cron: a 5-field crontab expression (minute hour day-of-month month day-of-week; see cron.ts).
//     When present, nextRunAt is computed from the cron (next matching wall-clock minute in timeZone)
//     INSTEAD OF lastRun + cadenceSeconds. When absent, the cadenceSeconds path is used (so a schedule
//     that carries ONLY blackoutWindows still rides the cadence cadence, just with the windows applied).
//   - timeZone: the IANA zone the cron fields AND the blackout-window minutes are interpreted in
//     (e.g. "Australia/Sydney"). Optional; defaults to "UTC". Validated via an Intl.DateTimeFormat probe.
//   - blackoutWindows: maintenance windows a fire is deferred out of (applies to BOTH the cron path and
//     the cadence path, so an operator can declare "never run 01:00-03:00" regardless of cadence kind).
// validateConfig rejects a malformed cron / unknown timeZone / bad window at save time with a clear
// reason, so a schedule never throws at run time.
export interface DownpipeSchedule {
  cron?: string;
  timeZone?: string; // IANA; defaults to "UTC" when absent
  blackoutWindows?: BlackoutWindow[];
}

export interface DownpipeConfig {
  id: string;
  name: string;
  cadenceSeconds: number; // requested cadence; the EFFECTIVE floor is the engine cron tick (*/15 in wrangler.toml), so a smaller value dispatches at the next tick, not sooner (the console floors the picker at Hourly). cron parsing is a refinement
  enabled: boolean;
  source: SourceSpec;
  // destinationId selects WHICH archive destination this downpipe writes to (the multi-destination
  // collection; see DESTINATIONS_KEY). ABSENT means the DEFAULT destination, so every pre-existing
  // config (and any downpipe the operator never reassigns) keeps writing exactly where it did. The
  // run path resolves it per-downpipe; a dangling id (a destination since removed) fails the run
  // loudly rather than writing to the wrong bucket (getDestConfigById returns null for an unknown id).
  destinationId?: string;
  // destinationIds is the FAN-OUT destination list (3-2-1): index 0 is the PRIMARY the run seals to,
  // the rest are REPLICAS the finalised run is copied to. SUPERSEDES destinationId, when present it
  // wins; when absent the primary falls back to destinationId, then the default (full back-compat, so
  // a pre-fan-out config is unchanged). A run writes 3 copies (source + primary + >=1 replica) when
  // this lists >=2 ids. See seal/replicate.ts.
  destinationIds?: string[];
  // restoreTestCadenceSeconds (contract section 5) is how often the scheduler runs a scheduled
  // restore test (the in-account drill) for this downpipe. 0 or absent = off; addDownpipe DEFAULTS it
  // to RESTORE_TEST_DEFAULT_CADENCE_SECONDS (weekly) when omitted, so best practice is on by default.
  // The upsert as a whole gates on downpipe.write at the router; CHANGING this field additionally gates
  // on scheduledtest.config, re-checked in addDownpipe against the DO's own resolved authority (see the
  // cadence-gate block there). For the six built-in roles that is invisible (every downpipe.write holder
  // also holds scheduledtest.config); the gate only bites a composable CUSTOM role that bundled
  // downpipe.write WITHOUT scheduledtest.config. Optional so existing persisted configs from before this
  // version stay readable (they read as "off" only if explicitly 0; an absent value on a re-upsert
  // re-defaults to weekly, see addDownpipe).
  restoreTestCadenceSeconds?: number;
  // retention is the per-downpipe archive RETENTION policy (ASVS V14.2.7: classification-driven
  // retention with automatic deletion). ABSENT means keep everything (the current behaviour: no
  // run is ever pruned), so an existing persisted config is unchanged. When present it bounds how
  // many runs and/or how many days of runs are RETAINED; runs outside the window are SUPERSEDED
  // (the RUNLOG entry is kept marked status="superseded", never removed, since removing one is a
  // rollback the reader rejects) and their now-unreferenced segments are pruned. enforce is the
  // SAFETY GATE: absent/false computes the prune PLAN and writes/deletes NOTHING (dry-run, report
  // only); ONLY enforce===true applies it. See seal/prune.ts and the cron drive loop.
  retention?: RetentionPolicy;
  // schedule is the OPTIONAL cron / time-of-day / timezone / blackout schedule (see DownpipeSchedule).
  // ABSENT means the cadenceSeconds interval cadence, exactly as before, so a pre-existing persisted
  // config is byte-unchanged and scheduled identically. When schedule.cron is present, nextRunAt is
  // computed from the cron (in schedule.timeZone) instead of lastRun + cadenceSeconds; blackoutWindows
  // (if any) defer a computed fire out of a maintenance window on EITHER path. validateConfig bounds
  // the whole object (valid cron, known IANA tz, sane windows) at save time.
  schedule?: DownpipeSchedule;
}

// RetentionPolicy is the per-downpipe retention window (DownpipeConfig.retention). At least one
// of keepRuns / keepDays must be set when the policy is present (validateConfig enforces this);
// when both are set a run is RETAINED if it satisfies EITHER (the most-recent keepRuns OR within
// keepDays of now), so the union is kept and only a run outside BOTH is superseded. enforce gates
// deletion: it must be the literal boolean true to apply a prune; absent or false is dry-run
// (the plan is computed and reported, nothing is written or deleted). This is the non-negotiable
// dry-run-by-default contract: the prune never deletes on the default path.
export interface RetentionPolicy {
  keepRuns?: number; // retain the N most-recent runs (by RUNLOG index); a positive integer
  keepDays?: number; // retain runs whose RUNLOG time is within N days of now; a positive integer
  enforce?: boolean; // the apply gate: true = delete, absent/false = dry-run (report only)
}

interface DownpipeState {
  // schemaVersion is the on-disk version stamp of this persisted per-downpipe record (the config + run
  // state stored under dp:<id> in the SchedulerDO). It is STAMPED at the storage boundary by
  // persistDownpipeState (the single writer) and CHECKED at read time by migrateOrRejectConfig, mirroring
  // the seal CHECKPOINT's `v:1` fail-closed gate (seal/checkpoint.ts) and the on-R2 archive's unknown-major
  // rejection. The per-downpipe DO record was the one persisted surface with neither a version field nor a
  // read-time validator (validateConfig runs only on write, every read was a blind cast), so a future
  // engine that changed a load-bearing config field could read an old/new-shape record back as undefined
  // and seal the WRONG/EMPTY source set while reporting ok (a silent partial). ABSENT means a legacy record
  // written before this stamp shipped: it is treated as v1 and accepted unchanged (forward-compatible), so
  // every existing record stays readable and behaviour is byte-identical today. See CONFIG_SCHEMA_VERSION.
  schemaVersion?: number;
  // configRev is the downpipe's CONFIG revision, and it exists so an operator's save can carry a
  // precondition. It is bumped by addDownpipe and by NOTHING else: the run path rewrites dp:<id>
  // constantly (heartbeats, completions, restore-test stamps) through the same persistDownpipeState, and a
  // revision that moved on those would refuse an operator's save because a BACKUP RAN, which is not a
  // collision. A run carries the value through untouched because it reads the stored state, mutates its
  // run fields and persists the same object. ABSENT on a record written before this shipped, read as 0 by
  // currentConfigRev, so a stale-page save against such a record states a revision that cannot match and
  // is refused, which is the fail-closed direction. See sched/downpipe-precondition.ts.
  configRev?: number;
  // lastConfigChange records the most recent CONFIG write to this downpipe (its revision, when, by whom
  // and WHICH FIELDS moved), so a refused save can tell the losing operator what moved under them rather
  // than only that something did. Field NAMES only, never values. ABSENT until the record's first edit.
  lastConfigChange?: LastConfigChange;
  config: DownpipeConfig;
  // createdAt (epoch ms) is when this downpipe was FIRST created: stamped once by addDownpipe on a
  // genuine create (prior === undefined) and carried forward UNCHANGED on every later edit, the same
  // preserve-across-re-upsert shape as lastRestoreTestAt and the other prior-derived fields below. It
  // exists so the SLA compliance report can tell how long a downpipe has actually existed rather than
  // assuming it has existed for the whole report period: without it, expectedRuns is computed over the
  // report's default 90-day window regardless of when the downpipe was made, so a downpipe a few hours
  // old at hourly cadence reads as ~0.2% compliant (a handful of successful runs against ~2160 expected)
  // on day one of every install, which is the report at its LEAST true. buildSlaComplianceReport clamps
  // each row's window to max(period.fromSeconds, createdAt) using this field. ABSENT on a record written
  // before this shipped (every downpipe that existed before today): the SLA report falls back to the
  // earliest run its history ring still holds (scheduler-do-reporting.ts's slaReportData), which is a
  // later, more conservative start than the true creation time, never an earlier one.
  createdAt?: number;
  // sealedRuns (G299) is the downpipe's MONOTONE lifetime count of SUCCESSFUL runs: incremented by completeRun
  // on an ok completion and never reset, never rewound, and (unlike the hist: ring) never rolled over. It is a
  // COUNT, not a clock: paired with replAnchors it answers "how many backups have succeeded since this
  // destination was configured?", which is the ONLY thing that separates a destination configured five minutes
  // ago from one that has held no copy since March. ABSENT on a record written before this shipped (read as 0;
  // the next successful run starts the count), so every existing record stays readable.
  sealedRuns?: number;
  // replAnchors (G299) maps each CONFIGURED fan-out destination id to the value of sealedRuns when that
  // destination entered the list. Maintained by nextReplAnchors (destinations.ts), which is the single producer:
  // an existing anchor is preserved across a config edit (so a rename cannot reset a months-old fault), a new
  // destination anchors at the current count, and a removed destination drops its anchor. ABSENT for a downpipe
  // with no configured fan-out, and on a legacy record until the next successful run backfills it.
  replAnchors?: Record<string, number>;
  nextRunAt: number; // epoch ms
  lastRunId: string | null;
  inFlight: boolean;
  // inFlightSince (epoch ms) is set when a run is triggered and cleared on completion. It bounds the
  // in-flight flag as a LEASE (ENG-B2): a run whose worker invocation is evicted, hits a limit, or is
  // redeployed mid-seal never calls /complete, so without a lease inFlight would wedge forever and the
  // downpipe would silently stop backing up. A run still in flight past INFLIGHT_LEASE_MS is treated as
  // crashed and reclaimed on the next trigger. Optional so existing persisted state stays readable.
  inFlightSince?: number;
  // lastRestoreTestAt / lastRestoreTestOk (contract section 5) record the recency and outcome of the
  // most recent SCHEDULED restore test (the in-account drill the scheduler runs at
  // restoreTestCadenceSeconds), so posture and reports can read restore-test recency without scanning
  // the drill-evidence log. lastRestoreTestAt is epoch ms; lastRestoreTestOk is the pass/fail of that
  // run (a break-glass-only posture records ok:false with a note, never a false pass). Both optional so
  // a downpipe that has never had a scheduled test (or pre-dates this version) is honestly absent.
  lastRestoreTestAt?: number;
  lastRestoreTestOk?: boolean;
  // lastRestoreTestReason / restoreTestConsecutiveFailures (support-pack mode scheduled-restore-fail-reason)
  // record WHY the most recent scheduled restore test FAILED and how many have failed IN A ROW. The failure
  // reason previously lived ONLY on the bounded notify ring + the drill-evidence note (both roll over), so a
  // pack read days later saw lastRestoreTestOk:false with no cause and no persistence of a run of failures.
  // lastRestoreTestReason is a CLOSED short code (restore-reasons.ts RESTORE_TEST_REASON_CODES: integrity /
  // freshness / object-missing / dest-access / origin-removed / not-configured / recovery-check / other),
  // NEVER the raw reason; restoreTestConsecutiveFailures is a monotone count reset to 0 on a pass. A PASS
  // clears the reason (absent = currently healthy) and resets the count; a real FAILURE sets the code and
  // increments; a DEFERRAL (break-glass-only posture, or no completed run yet) leaves both untouched (it is
  // neither pass nor fail evidence). Both optional so a downpipe that has never failed (or pre-dates this
  // version) is honestly absent. Redaction-safe: a closed code + an int, never a key / value / record name.
  lastRestoreTestReason?: string;
  restoreTestConsecutiveFailures?: number;
  // lastRestoreTestDeferred records that the MOST RECENT scheduled-restore-test completion was a
  // DEFERRAL, and which kind: "no-run" (the downpipe had no completed run to read back at test time),
  // "posture" (break-glass-only posture, no operational read-back key, so the engine cannot
  // self-test), or "no-records" (a run existed and opened, but held no records, so the drill decrypted
  // nothing and established nothing). A deferral is recorded ok:false (never a false pass), and before this field the
  // console could not tell "could not test" from "tested and FAILED", so a freshly created downpipe
  // read "Last test failed" until its next cadence tick. Set by completeRestoreTest on a deferral,
  // CLEARED on a pass or a real failure (absent = the last completion was real evidence). A closed
  // three-value kind, never a message; optional so prior state stays readable.
  lastRestoreTestDeferred?: "no-run" | "posture" | "no-records";
  // lastRestoreTestKind / lastRestoreTestSampleRate record HOW the most recent recency stamp
  // (lastRestoreTestAt/Ok) was produced, so a compliance surface can never mistake a partial attended
  // sample for a full test. "scheduled" is the in-account cron drill (windowed rotating coverage); "attended"
  // is an operator-run attended verification where the operator supplied their break-glass key through the
  // browser and the engine verified a sample of records. lastRestoreTestSampleRate is the per-cent of records
  // that attended run verified (1..100; 100 = every record, the only attended pass that reads as a FULL proof
  // and stamps restoreProven). Both optional so a scheduled-only or pre-this-version downpipe is honestly
  // absent; a scheduled completion leaves them at "scheduled"/absent. Redaction-safe: a closed kind + an int.
  lastRestoreTestKind?: "scheduled" | "attended";
  lastRestoreTestSampleRate?: number;
  // restoreTestRetestAt (epoch ms) is the post-backup retest request: stamped by completeRun when a
  // SUCCESSFUL run lands while the last scheduled restore test did not PASS (never tested, deferred
  // for no-run, or genuinely failed) and a restore-test cadence is configured, so restoreTestsDue
  // treats the downpipe as due IMMEDIATELY instead of a full cadence later. The fresh run is exactly
  // the evidence the drill was missing (a no-run deferral now has a run; a failure gets a prompt
  // re-verdict against the new archive). Consumed (cleared) by completeRestoreTest on ANY completion
  // so it can never loop; optional so prior state stays readable.
  restoreTestRetestAt?: number;
  // lastRestoreOom (INFRA isolate-oom-restore) is the most recent restore-subsystem OOM-risk marker, recorded by
  // the scheduled restore test's completion (completeRestoreTest) from the drill's measurement. The drill has no
  // streaming path -- it buffers each sampled record WHOLE to hash-check it -- so a record larger than the memory-
  // safe single-record ceiling (RESTORE_OOM_SAFE_BYTES) risks an isolate OOM on restore (an uncatchable kill that
  // wedges recovery). It records the largest record the drill buffered, the ceiling, and whether it crossed --
  // the recurring, pack-visible early warning that "restore OOMs on large objects" BEFORE a slightly-larger
  // record kills the isolate. A size + a flag + a timestamp; never a key, value or plaintext. Optional so a
  // downpipe never restore-tested (or one whose test buffered nothing, or pre-dating this version) is honestly absent.
  lastRestoreOom?: RestoreOomMarker;
  // restoreTestStartedAt (support-pack mode restore-test-tick-killed) is set to epoch ms just before the cron
  // driver runs a scheduled restore-test DRILL, and CLEARED by completeRestoreTest on any completion. It is the
  // read-side lease for the drill: a marker still present + older than a drill could plausibly take means the
  // drill's cron tick was KILLED (CPU / wall-clock) mid-flight before it completed -- an "attempted but
  // incomplete" restore test the recency fields (lastRestoreTestAt stays stale) could not tell from "never
  // tested". Optional so a downpipe with no drill in flight (or pre-dating this field) is honestly absent.
  restoreTestStartedAt?: number;
  // restoreProven (restorability assurance) is the "offline restorability last proven" record: WHO
  // proved this downpipe's archives recoverable and WHEN and BY WHICH method, set ONLY when a BLIND
  // restore test or a KEYLESS attestation PASSED. It is what lets the console show "offline restorability
  // last proven on <date> by <who>" without scanning the evidence log. It is distinct from
  // lastRestoreTestAt (the SCHEDULED-test recency, which records every scheduled run pass OR fail): this
  // records only PASSES, the affirmative proof. It carries the prover's verified email (null for the
  // bare-token break-glass, which is not attributable), the epoch-ms timestamp, the method, and the runId
  // that was proven, all redaction-safe (never a key, never a value). Optional so a downpipe never proven
  // (or pre-dating this version) is honestly absent.
  restoreProven?: RestoreProven;
  // integrityVerified (protection-statement integrity recency) is the "archive integrity last verified"
  // stamp: WHEN this downpipe's archive integrity was last AFFIRMATIVELY verified, and BY WHICH path. It
  // is set ONLY on an actual verification PASS, never on a failure, so its mere presence is the
  // affirmative proof (the console reads it as a passed integrity check). Two paths set it, both of which
  // verify the archive's cryptographic integrity:
  //   - "run": a run completed SUCCESSFULLY. A successful seal builds the per-record hashes, signs the
  //     manifest, and appends + re-signs the account-wide RUNLOG chain (seal/pipeline.ts runBackup), so a
  //     clean completion IS an integrity verification of the just-written archive (the manifest + RUNLOG
  //     chain it produced verify by construction). A FAILED run never reaches the success branch, so it
  //     never stamps (honest: never a false positive).
  //   - "attest": a KEYLESS attestation or a BLIND restore test PASSED (recordRestoreProven, which the
  //     router calls ONLY on a pass). Both re-verify the signature/completeness/anti-rollback (and the
  //     blind test decrypts-and-verifies every record), so a pass is a fresh integrity verification.
  // It is distinct from restoreProven (which records the RECOVERABILITY proof: who + method + runId): this
  // records only the integrity recency (when + how), which the plain-English protection statement reads to
  // say "integrity-checked daily" instead of the honest "never integrity-checked". It carries only the
  // epoch-ms timestamp and the coarse path enum, never a key, value or plaintext. Optional so a downpipe
  // that has never completed a run or passed an attestation (or pre-dates this version) is honestly absent.
  integrityVerified?: IntegrityVerified;
  // lastSealVerify (ENG-RST-01) is this downpipe's MOST RECENT verify-at-seal verdict: the result of
  // reading the just-written archive back and verifying it after the last successful run on which
  // verify-at-seal ran. Unlike integrityVerified (set only on a PASS), this records BOTH outcomes, so a
  // SUSPECT verdict is observable: the posture seal-verification check reads it (a suspect last verdict
  // is a critical posture finding) and /admin/status surfaces it. It carries only the status enum, the
  // tier, the sample count, the epoch-ms time and a coarse reason, no key, value or plaintext. Optional
  // so a downpipe never run with the feature on (or pre-dating this version) is honestly absent.
  lastSealVerify?: SealVerification;
  // recoverySamples (RTO estimate, E4/C1) is a bounded ring (RTO_SAMPLE_CAP, newest-last) of MEASURED
  // recovery-test samples: each carries the wall-clock a drill took and the plaintext bytes/records it
  // decrypted-and-verified. They are the honest signal the RTO estimate derives from (observed drill
  // throughput scaled to the archive size); a downpipe with no drill history has no samples and reports an
  // honest "unknown" RTO rather than a guess. Recorded only on a SUCCESSFUL drill that verified >=1 record
  // (a failed/break-glass drill measured no recoverable work). Each sample is counts + a duration; no
  // secret. Optional so a downpipe never drilled (or pre-dating this version) is honestly absent.
  recoverySamples?: RtoSample[];
  // deepVerify (INT-1) is the per-downpipe windowed cursor for the scheduled restore test's rotating
  // FULL decrypt coverage. The previous scheduled drill re-decrypted the SAME strided <=8 records every
  // tick, so a flipped byte in an off-stride record was never caught by the drill (only by a full
  // restore). Instead, each scheduled tick now decrypts a WINDOW of records and advances this cursor, so
  // over ceil(records / window) ticks EVERY record of the run is decrypted-and-verified at least once. It
  // is persisted so a killed/evicted tick resumes from the same cursor (no coverage is silently lost).
  // Optional so a downpipe never deep-verified (or pre-dating this version) is honestly absent.
  deepVerify?: DeepVerifyState;
  // cfConfigDiscovery (cf-config read-cost control) is the cached result of the last surface-discovery
  // probe for an auto-mode cf-config downpipe: which surfaces are present/empty/unavailable, and when.
  // The capture path reads `present` to back up only the surfaces in use (instead of one GET per all
  // every surface in the registry every run); a stale/absent cache fail-safes to capturing ALL surfaces. Refreshed by
  // the daily discovery cron pass and by a manual "rediscover". Optional so a downpipe never discovered
  // (or pre-dating this version, or not cf-config) is honestly absent and simply captures all.
  cfConfigDiscovery?: CfConfigDiscovery;
  // cronResolve (SCHED cron-runtime-fallback-to-cadence / invalid-tz-runtime / impossible-cron-runtime) is
  // the MOST RECENT outcome of resolving this downpipe's cron schedule at reschedule time (set by
  // nextWithJitter). A downpipe with a `schedule.cron` computes its next fire from the cron + timezone; if
  // that resolution FAILS AT RUNTIME (a stored cron that no longer parses, an IANA zone the runtime does not
  // recognise, or an impossible date with no next fire) the scheduler silently FALLS BACK to the plain
  // cadence, so the operator's intended fire time is silently not honoured and no run-history row explains it.
  // This records the closed CLASS of that outcome (never the cron STRING, which is operator-influenced text --
  // no-custody) so the support pack can show "this downpipe's cron isn't resolving; it's running on cadence".
  // Absent for a cadence-only downpipe (no cron to resolve) or one that pre-dates this stamp.
  cronResolve?: CronResolve;
  // blackoutResolve (SCHED blackout-hop-ceiling / degenerate-window-inert) is the MOST RECENT outcome of
  // deferring this downpipe's computed fire time out of its declared blackout (change-freeze) windows, set by
  // nextWithJitter at every reschedule. Two silent violations live here: a deferral that exhausts the hop ceiling
  // and fires INSIDE the customer's declared freeze, and a window saved with equal start/end minutes that has
  // never once applied. Neither leaves any trace today (blackout windows are deliberately never carried in the
  // pack). This records only the closed CLASS + the evaluation time -- never the window minutes or days.
  // Absent for a downpipe with no blackout windows (nothing to resolve) or one that pre-dates this stamp.
  blackoutResolve?: BlackoutResolve;
}

// CronResolveClass is the closed outcome vocabulary for resolving a downpipe's cron schedule at run time:
//   - "ok"           : the cron + timezone resolved to a next fire (the intended schedule is honoured);
//   - "cron-parse"   : the stored cron expression no longer parses -> fell back to the plain cadence;
//   - "tz-invalid"   : the stored IANA timezone is not recognised by the runtime -> fell back to cadence;
//   - "no-next-fire" : the cron parses but has no next fire within the search bound (an impossible date,
//                       e.g. "0 0 30 2 *") -> fell back to cadence.
// The three non-ok classes are the runtime-fallback faults a validated config should never reach, but a
// record stored by an older/looser validator, or an IANA zone the deployed runtime lacks, can.
export type CronResolveClass = "ok" | "cron-parse" | "tz-invalid" | "no-next-fire";

// CronResolve is the stamped cron-resolution outcome on a DownpipeState: the closed class + when it was last
// resolved (epoch ms). A closed enum + a timestamp only -- never the cron/timezone string (no-custody).
export interface CronResolve {
  class: CronResolveClass;
  at: number;
}

// RestoreProvenMethod distinguishes the two restorability-assurance tiers that can set the "last proven"
// record: "blind-test" is the keyed BLIND restore test (every in-scope record decrypted-and-verified to a
// discard sink), "keyless-attest" is the Tier 0 keyless integrity attestation (signature + completeness +
// anti-rollback, no decryption key). Both are affirmative recoverability proofs; the method is surfaced so
// the console can show WHICH assurance backs the "last proven" claim.
export type RestoreProvenMethod = "blind-test" | "keyless-attest" | "attended-blind-test";

// RestoreProven is the per-downpipe "offline restorability last proven" record (see DownpipeState). It
// carries only redaction-safe provenance: who proved it (the verified email, null for the unattributable
// bare-token fallback), when (epoch ms), by which method, and the proven runId. No key, no value, no
// plaintext. Stored on the downpipe state under `dp:<id>`.
export interface RestoreProven {
  at: number; // epoch ms the proof passed
  by: string | null; // the prover's verified Access email; null for the bare-token fallback
  method: RestoreProvenMethod;
  runId: string; // the run that was proven recoverable
}

// IntegrityVerifiedHow names which path affirmatively verified the archive integrity: "run" is a
// successful run completion (the seal builds the per-record hashes, signs the manifest and appends +
// re-signs the RUNLOG chain, so a clean seal is an integrity verification of what it just wrote);
// "attest" is a PASSED keyless attestation or blind restore test (signature + completeness + anti-rollback,
// re-verified). Both are affirmative integrity verifications; the path is surfaced so a future console can
// show WHICH path backs the "integrity-checked" claim, though the current statement does not distinguish them.
export type IntegrityVerifiedHow = "run" | "attest";

// IntegrityVerified is the per-downpipe "archive integrity last verified" stamp (see DownpipeState). It is
// written ONLY on a verification PASS, so its presence is the affirmative proof. It carries only the epoch-ms
// timestamp and the coarse path enum: no key, no value, no plaintext, no runId (the recoverability proof's
// runId lives on restoreProven). Stored on the downpipe state under `dp:<id>`.
export interface IntegrityVerified {
  at: number; // epoch ms the integrity was last verified (a run sealed cleanly, or an attestation passed)
  how: IntegrityVerifiedHow;
}

// AttestSessionRunState is one pinned run's progress inside an attended-verification session. state moves
// pending -> verified | failed (the operator supplied a master and the engine sampled it) or skipped. The
// counts + timestamp are recorded so the console can show per-run progress; they are redaction-safe (a run
// id + ints), never a key or value. name/recordCount are the display facts pinned at session start (the
// downpipe's own name + the run's declared record count), so the status view needs no second lookup.
export interface AttestSessionRunState {
  downpipeId: string;
  runId: string;
  name?: string;
  recordCount?: number;
  state: "pending" | "verified" | "failed" | "skipped";
  recordsVerified?: number;
  recordsTotal?: number;
  at?: number; // epoch ms this run's verify result was recorded
}

// AttestSession is the durable state of an attended-verification session (stored in the scheduler DO under
// `attest-session:<id>`). Attended verification lets an offline-key-only customer prove their backups
// restorable by supplying, through their browser, only the per-run MASTER keys (never the break-glass
// private). This record carries NO key material by construction: seedB64 is a per-session SAMPLING seed (a
// reproducible random selector, never a decryption key), proofHash is sha384(expectedProof) of the live-
// possession challenge (deleted the moment the session is proven; it reveals nothing about the key or the KEM
// shared secret), and the masters the operator submits are used ONLY within the verify request and are NEVER
// stored here. createdBy is the OWNER's stable principal (subject); every non-create route enforces
// caller.subject === createdBy, so only the operator who created the session can drive it. status moves
// active -> complete (every pinned run resolved) | aborted (the operator ended it) | expired (past
// expiresAt). Every field is redaction-safe: an opaque id, a subject/email, timestamps, a sample rate, a
// seed, a hash, and the per-run progress rows.
export interface AttestSession {
  id: string;
  createdBy: string | null; // the owner's stable subject; null only for a legacy/degenerate record (create refuses a null-subject caller)
  createdByEmail: string | null;
  createdAt: number; // epoch ms
  expiresAt: number; // epoch ms; a create refuses while an active non-expired session exists (one active session)
  sampleRate: number; // 1..100; the per-cent of each run's records the verify samples (100 = every record)
  seedB64: string; // a per-session SAMPLING seed (base64url), NOT a key
  proofHash?: string; // "sha384:<hex>" of the live-possession challenge's expected proof; DELETED once proven
  proven: boolean; // the operator proved live possession of the break-glass private (the challenge round-trip)
  status: "active" | "complete" | "aborted" | "expired";
  runs: AttestSessionRunState[];
}

// SealVerificationTier is which depth of verification actually ran. "tier-0" is the keyless chain
// attestation (signature + completeness + freshness); "sampled-decrypt" additionally opened the
// run with the operational key (the full keyed structural chain: capsule unwrap, key commitment,
// per-record recordHash, Merkle root) and decrypted + hash-checked a STRIDED SAMPLE of records;
// "full" is the same keyed open but decrypts + hash-checks EVERY record (full byte coverage), used
// at seal time for a run whose plaintext is within SEAL_VERIFY_FULL_BYTES so a flipped byte in ANY
// record of a small run is caught NOW, not only if it happened to fall in the strided sample (INT-1).
export type SealVerificationTier = "tier-0" | "sampled-decrypt" | "full";

// SealVerification is the redaction-safe verdict recorded on the run row and exposed on
// /admin/status. status is the only load-bearing flag for the operator ("verified" vs "suspect").
// tier is the depth that ran; sampled is how many records were decrypt-checked (0 for tier-0);
// at is the epoch-ms the verify ran; reason is a SHORT coarse, secret-free note present ONLY on a
// suspect verdict (never a raw exception, which could carry a shard id / object key).
export interface SealVerification {
  status: "verified" | "suspect";
  tier: SealVerificationTier;
  sampled: number; // records decrypt-checked (0 for tier-0; the full record count for the "full" tier)
  at: number; // epoch ms the verification ran
  reason?: string; // coarse, secret-free, present only when status === "suspect"
  // attempts is how many whole read-back verification attempts actually ran (the bounded
  // read-after-write retry, SEAL_VERIFY_ATTEMPTS). ABSENT on a healthy first-try verified verdict
  // (so an unchanged row looks exactly like today) and on legacy rows -> treat absence as 1.
  attempts?: number;
  // recovered is true when a retry turned an attempt-1 consistency failure (a read-after-write lag
  // on the just-written object) into a clean verified verdict. It is observability only: a recovered
  // run is "verified" and does NOT raise the seal-verification posture finding or fire the critical
  // alert. Absent on a first-try verified verdict and on a suspect verdict.
  recovered?: boolean;
  // tier0Cause (support-pack mode tier0-only-reason-unknown) is WHY a "verified" verdict ran only Tier-0
  // (the keyless chain attestation) and skipped the keyed decrypt sample, a distinction the bare
  // {tier:"tier-0"} could not convey: was the downpipe break-glass-only (no in-account read-back key), did
  // the operator set SEAL_VERIFY_SAMPLE=0, or was the run over SEAL_VERIFY_MAX_BYTES? Without it a support
  // read could not tell an intentional Tier-0 posture from a misconfigured one. It is DIAGNOSTIC run-history
  // metadata set ONLY on the intentional {status:"verified", tier:"tier-0", sampled:0} return; it does NOT
  // change the archive, the root, the signature, or the verdict's status/tier/sampled. A verified verdict
  // that DID run the decrypt sample (tier "sampled-decrypt"/"full") never carries it, and a suspect verdict
  // never carries it (its `reason` is the signal). Absent on legacy rows. Redaction-safe: a closed enum word.
  //   too-many-shards  the run has more shards than the decrypt tier's subrequest budget allows. Tier-0 and
  //                    the decrypt tier each walk the shard list, so both running costs roughly twice the
  //                    shard count, and past the ceiling the decrypt pass could not have completed.
  tier0Cause?: "break-glass" | "sample-off" | "too-large" | "too-many-shards";
  // via is HOW the decrypt tier reached the run's master, and it exists because the two routes prove
  // different things while producing an identical-looking verdict.
  //
  //   "recipient"  the run was opened by DECAPSULATING its master capsule with the in-account operational
  //                private. That proves the recipient wrap written into this root actually opens, which is
  //                a property of the archive.
  //   "master"     the run was opened with the per-run master the seal path still had in scope. That proves
  //                the archive's bytes decrypt and hash-check, and proves NOTHING about whether any
  //                recipient wrap opens, because no wrap was touched.
  //
  // Without this field a break-glass-only estate's "full" verdict rendered identically to a two-recipient
  // estate's, and a reader would reasonably conclude the same thing had been checked. It had not. Neither
  // route exercises the BREAK-GLASS wrap in either posture, because the engine has never held that private
  // and cannot; only attended verification proves that one against a real archive.
  //
  // Absent on a Tier-0 verdict (no decrypt ran) and on legacy rows. Redaction-safe: a closed enum word.
  via?: "master" | "recipient";
  // G067: the evidence a SUSPECT verdict on a 50,000-record run needs and could not carry. All three are
  // redaction-safe by construction and are ADDITIVE metadata only: the status, tier and sampled fields are
  // unchanged, so no sealed byte, root, signature or verdict semantic moves.
  //   causeDigest       an 8-hex FNV correlation handle of the RAW failure text (the errId idiom the restore
  //                     fault ring already uses). It answers "are these two recurring reader faults the SAME
  //                     fault?" without the text -- which can embed a shard id or an object key -- ever riding.
  //   failingOrdinal    WHICH record the decrypt step died on, as an integer INDEX into the run's record list.
  //                     Never a key, never a name.
  //   verifiedBeforeFail how many records verified CLEAN before the fault. `sampled` is zeroed on a failure, so
  //                     today a suspect verdict cannot say whether it died on record 1 or record 49,999.
  causeDigest?: string;
  failingOrdinal?: number;
  verifiedBeforeFail?: number;
}

// DeepVerifyState (INT-1) is the persisted windowed cursor that rotates FULL decrypt coverage of a
// run across scheduled restore-test ticks. The cursor is bound to runId: when the downpipe's latest
// run changes the cursor resets to 0 so the new run is covered from the start. cursor is the next
// record index to decrypt; records is the run's record count observed at the last tick; updatedAt is
// the last tick's epoch ms; lastFullPassAt stamps when the cursor last wrapped (a full record pass
// completed), so reports can show "every record deep-verified since <date>". It carries only counts and
// the customer's own runId, never a key, value or plaintext.
export interface DeepVerifyState {
  runId: string;
  cursor: number;
  records: number;
  updatedAt: number;
  lastFullPassAt?: number;
}

// RestoreOomMarker (INFRA isolate-oom-restore) is the restore-subsystem OOM-risk marker recorded on a downpipe
// by the scheduled restore test's completion. The in-account drill has NO streaming path -- it buffers each
// sampled record WHOLE to hash-check it -- so maxRecordBytes (the largest single record it buffered) crossing
// safeBytes (the memory-safe single-record ceiling on a 128 MB isolate) is the early warning that a restore of
// this run risks an isolate OOM (an uncatchable kill that wedges recovery). at is the epoch ms the drill measured
// it. A size + the ceiling + a flag + a timestamp -- never a key, value or plaintext (redaction-safe).
export interface RestoreOomMarker {
  at: number;
  maxRecordBytes: number;
  safeBytes: number;
  overSafe: boolean;
}

// RunHistoryEntry is one row of the bounded recent-run ring the DO keeps per downpipe so the
// console can show a run list and prefill drill/restore with a real runId. It carries no
// plaintext and no key material, only the run's id, its monotonic runlogIndex (the join key
// between the in-flight append and the completion update), the start time, the resolved
// status and coarse outcome counts. error is a SHORT coarse reason on failure, never a stack.
// archiveBytesWritten/segmentsWritten/durationMs are optional throughput fields added at
// completion for the cost calculator (observed mode) and the topology throughput view; old
// ring entries from before this version lack them and that is intentional.
export interface RunHistoryEntry {
  runId: string;
  index: number;
  startedAt: string; // RFC-3339 UTC millis, matching the manifest/RUNLOG time format
  status: "in-flight" | "ok" | "failed" | "abandoned";
  // prevRunId is this downpipe's SUCCESSFUL-run predecessor at the instant this run was allocated
  // (trigger's own `ds.lastRunId`, the same pointer handed to the seal path and mirrored in the
  // destination-local RUNLOG's freshness.prevRunId, F10) -- null when this is the downpipe's first
  // run ever, never an empty string (an empty string would read as a broken chain rather than "no
  // predecessor"). Recorded since this field was added; a row sealed before that carries no
  // `prevRunId` key at all (`"prevRunId" in entry` is false), which is a THIRD, distinct state from
  // both null and a real id -- run-chain.ts's annotatePredecessorChain is the one place that turns
  // this raw pointer, plus ring membership, into an honest per-row verdict for an admin/auditor read
  // (none / retained / pruned / unknown) rather than leaving the caller to guess from a missing key.
  prevRunId?: string | null;
  recordCount?: number;
  bytes?: number;
  error?: string;
  // causeDigest is the 12-hex correlation digest = first 6 bytes of SHA-384(raw error), recorded on a FAILED
  // row; byte-identical to the Logpush `[cause <hex>]` the engine writes for the same fault, so support joins
  // a customer's log line to this row by the digest. One-way (no raw error text); absent on ok/legacy rows.
  causeDigest?: string;
  archiveBytesWritten?: number; // new stored bytes written to the archive destination this run
  segmentsWritten?: number;     // object count written (segments + manifest, not skipped objects)
  durationMs?: number;          // wall-clock duration of runBackup, ms
  // recordsSkipped is how many in-scope records the seal could not capture this run (a value that
  // vanished or changed mid-crawl, an unsealable record). It is observability: a non-zero count means the
  // archive is intentionally short of the live source, so the operator can see it on the run row rather
  // than only in counts that never surfaced. Optional; absent on legacy rows and on the buffered seal path.
  recordsSkipped?: number;
  // recordsVanished is how many in-scope objects the LIST returned but that were GONE at value-read time (a KV
  // key / R2 object DELETED between the list page and the GET -- a mid-crawl live-source race, SPEC 12.5,
  // WS-P2). It surfaces on the run row so a churning source is visible ("N objects vanished mid-crawl") rather
  // than silently skipped. DISTINCT from recordsSkipped (etag-changed large objects, which also seal nothing)
  // and recordsIncomplete (a marker that DID seal). Optional; absent on legacy rows and on a run with none.
  recordsVanished?: number;
  // recordsIncomplete is how many records this run sealed as INCOMPLETENESS SENTINELS (R1-1): a
  // marker landed in place of the real bytes (_truncated/_unavailable/_skipped/_pending/_refused),
  // so the backup completed "ok" but is intentionally short of the live source. Unlike
  // recordsSkipped (etag-mid-crawl, which seals nothing), these ARE in the archive but are not the
  // real value. A non-zero count makes the run "completed with N items not fully captured". Optional;
  // absent on legacy rows and on a run that captured everything fully.
  recordsIncomplete?: number;
  // incompleteByMarker is the PER-MARKER breakdown of recordsIncomplete (support pack / diagnostics-bot):
  // WHICH incompleteness sentinel kinds this run sealed (_truncated/_unavailable/_skipped/_pending/_refused)
  // and how many of each. Only non-zero keys are present; absent when the run sealed no markers or on a
  // legacy row. Redaction-safe: the marker KEY identity + an integer count only, never the marker payload.
  incompleteByMarker?: IncompleteByMarker;
  // incompleteIds is the PER-KIND ATTRIBUTION of incompleteByMarker (WS-P1): for each marker kind, a bounded,
  // deduplicated list of WHICH surface/object was short (support pack / diagnostics-bot). NO-CUSTODY: only
  // redaction-safe closed/product-token ids reach it -- cf-config surface ids today, the exact class the
  // cfConfigDiscovery cache already carries -- never a KV/R2 object key or operator/customer free-text. Only
  // non-empty kinds; absent on a legacy row or a run with nothing name-attributable.
  incompleteIds?: IncompleteIds;
  // opCounts is the exact per-resource Cloudflare op tally this run made (cost Phase 3): KV/R2/D1 reads,
  // R2 writes, control-plane reads, and the subrequest total. It makes the cost estimate's "cost to run"
  // exact rather than an over-estimate. Optional; absent on legacy rows.
  opCounts?: OpCounts;
  // The destination this run was actually SEALED to (the failover-chosen origin). With fan-out
  // failover the run seals to the FIRST REACHABLE destination, not always the configured primary,
  // so the origin must be recorded per run: the replicate pass mirrors FROM it and a restore reads
  // FROM it. Absent on legacy rows and on failed rows (a failed run sealed nowhere); the resolver
  // then falls back to the configured primary, exactly as a single-destination deployment always did.
  destinationId?: string;
  // Verify-at-seal verdict (ENG-RST-01): the result of reading this run's archive BACK from the
  // destination and verifying it right after the seal. Present on a successful row when verify-at-seal
  // ran (VERIFY_AT_SEAL on); "verified" with the tier + sample count means the bytes that LANDED are
  // internally consistent and signed, "suspect" means the readback verify failed (the run still
  // completed "ok", fail-open, and the archive was NOT deleted). Absent on legacy rows and when the
  // feature is off. Redaction-safe (a status enum + tier + count + a coarse reason; never a value).
  sealVerification?: SealVerification;
  // multipartAbortFailed (multipart-abort-stranded-parts): a FAILED multipart upload's best-effort abort ALSO
  // failed on this run's destination, so parts were stranded (invisible storage the bucket's lifecycle/abort
  // policy must reap). A BOOLEAN only (never a key/id/value). Present when set by completeRun; absent on
  // legacy rows and whenever nothing was stranded (the common case). Surfaced in the support pack run row.
  multipartAbortFailed?: boolean;
}

// DrillEvidenceKind distinguishes an engine-run in-account drill from an operator-entered
// offline-rehearsal record (the break-glass-only posture, where the engine cannot self-test).
export type DrillEvidenceKind = "in-account" | "offline-rehearsal";

// DrillEvidenceEntry is one row in the drill-evidence log. It carries no key material and no
// secret; note is redaction-safe free text. The log is NOT hash-chained
// (it is evidence, not a tamper-evident audit chain). Storage key: 'drill-evidence:<ulid>'.
export interface DrillEvidenceEntry {
  runId: string;
  kind: DrillEvidenceKind;
  recordedBy: string | null; // the verified Access email; null for the token fallback
  recordedAt: string;        // RFC-3339 UTC millis
  note?: string;
}

// FleetDrillCampaign is an ON-DEMAND bulk restore-test ("drill the whole fleet now") campaign (SCALE-2).
// A scheduled restore test only re-tests a downpipe when its weekly cadence falls due, so an operator who
// wants to drill 100 downpipes on demand would otherwise wait ~weeks for the cadence to sweep the fleet.
// A campaign is the worklist that lets the EXISTING per-downpipe restore-test-pass machinery fan a whole
// fleet across cron ticks under the same per-tick cap + shared subrequest budget: it does NOT bypass the
// drill (each downpipe is drilled by the same runScheduledRestoreTest / runDrill the scheduled test uses,
// so the integrity-drill semantics are identical), it only schedules WHICH downpipes get drilled and HOW
// MANY per tick, and tracks progress. It carries only the downpipe ids + counts (redaction-safe; the
// per-downpipe pass/fail evidence still lands in the drill-evidence log, the durable record). Storage keys:
// 'fleetdrill:active' (the in-progress campaign, deleted on completion) and 'fleetdrill:last' (the most
// recently FINISHED campaign, kept so the console can show the last fleet-drill result). Bounded: `pending`
// is the un-dispatched worklist (drained cap-per-tick), `inFlight` maps a dispatched id to its dispatch
// time (so a completion can be attributed to the campaign and a never-completed dispatch re-queued after a
// timeout), and only a small `failedSample` of ids is retained (the full per-downpipe outcome lives in the
// evidence log), so the record stays small even for a large fleet.
export interface FleetDrillCampaign {
  campaignId: string;        // ULID
  startedAt: number;         // epoch ms
  startedBy: string | null;  // the starter's verified Access email; null for the bare-token fallback
  total: number;             // how many downpipes the campaign drills
  pending: string[];         // downpipe ids not yet dispatched (the drain worklist)
  inFlight: Record<string, number>; // dispatched id -> dispatch epoch ms (re-queued if it never completes)
  passed: number;            // completed-and-passed count
  failed: number;            // completed-and-not-passed count (fail / deferred / deleted-mid-campaign)
  failedSample: string[];    // up to FLEET_DRILL_FAILED_SAMPLE ids that did not pass, for at-a-glance surfacing
  done: boolean;             // true once pending + inFlight are both empty
  finishedAt?: number;       // epoch ms the campaign finished (present only when done)
}

// FleetDrillProgress is the redaction-safe, at-a-glance projection of a FleetDrillCampaign for the status
// route: counts and the small failed-id sample, never the full pending worklist. `completed` = passed +
// failed; `remaining` = pending + inFlight. Used by GET /admin/drill-all so the console can render a
// progress bar without reading the whole campaign record.
export interface FleetDrillProgress {
  campaignId: string;
  startedAt: number;
  startedBy: string | null;
  total: number;
  passed: number;
  failed: number;
  completed: number;  // passed + failed
  pending: number;    // not yet dispatched
  inFlight: number;   // dispatched, awaiting completion
  remaining: number;  // pending + inFlight
  done: boolean;
  finishedAt?: number;
  failedSample: string[];
}

// TickReport is the redaction-safe per-cron-tick OUTCOME the cron driver (drive()) posts to the scheduler DO
// at the END of each invocation (INFRA cron-green-but-passes-crash / subrequest-budget-starved-tick; SCHED
// due-page-cap-truncation / coalesced-runs-invisible / budget-estimate-overdraw-kill /
// single-missed-tick-undetected). A Worker cron completing without throwing is a FALSE GREEN: the tick can
// report "ok" while the seal loop dispatched nothing, a pass crashed, or the shared budget was overdrawn and
// starved the tail. Every field is a COUNT or a flag -- never an id/name/value/Worker timestamp (the DO stamps
// the time) -- so it is redaction-safe by construction (no-custody). It lives in this shared leaf so the DO,
// the cron driver and the support pack all reference one shape without an import cycle.
export interface TickReport {
  due: number; // downpipes the DO reported due this tick
  dispatched: number; // due downpipes the seal loop actually ran
  coalesced: number; // due downpipes SKIPPED because a prior run was still in flight (coalesced trigger)
  carried: number; // due downpipes NOT started because the shared budget ran low (carried to the next tick)
  sealErrors: number; // per-downpipe dispatch failures caught in the seal loop this tick
  passErrors: number; // trailing passes that bailed or threw this tick (the false-green signal)
  budgetCap: number; // the resolved per-invocation subrequest budget for this tick
  budgetSpent: number; // subrequests the invocation spent against the shared cap
}

// TickOutcome is one stored ring entry: a clamped TickReport plus the DO-stamped time, the interval since the
// prior recorded tick (the single-missed-tick signal -- a large gap means one or more ticks were missed), the
// derived remaining budget, and the over-budget flag (the invocation overdrew its subrequest estimate).
export interface TickOutcome extends TickReport {
  at: number; // DO-stamped epoch ms (clamped)
  intervalMs: number; // ms since the prior recorded tick (0 for the first); a large gap = missed tick(s)
  budgetRemaining: number;
  overBudget: boolean; // spent > cap: the invocation overdrew its subrequest estimate
}

// StorageFaultKind is the CLOSED classification of a persist-state storage.put failure (SCHED persist-state-
// storage-fault / INFRA do-value-size-limit): "value-too-large" is the DO 128 KiB per-value limit; "put-failed"
// is any other persist/storage failure. A closed enum so the projected marker is redaction-safe by construction.
// It lives in this shared leaf (like TickReport) so the DO, the pure helpers and the pack all share one shape.
export type StorageFaultKind = "value-too-large" | "put-failed";

// StorageFaultCounter is the cumulative persisted persist-state storage-fault tally: the total, the per-class
// sub-counts, the most-recent fault time (clamped epoch ms) and its class. It PROMOTES the indirect tick
// sealErrors/passErrors (which conflate a storage fault with any other dispatch error) into a distinct fault-
// class signal. Counts + a closed enum + a timestamp -- never an id/name/value (redaction-safe by construction).
export interface StorageFaultCounter {
  total: number;
  valueTooLarge: number;
  putFailed: number;
  lastAt: number;
  lastKind: StorageFaultKind | null;
  // lastDownpipeId ATTRIBUTES the most recent fault: which downpipe's dp:<id> record was being persisted when
  // the put threw. Without it, a climbing valueTooLarge count names no downpipe, so the operator cannot tell
  // WHICH downpipe's state has outgrown the DO 128 KiB per-value cap (the one that silently stops advancing its
  // next-run time). The id is the customer's OWN downpipe label -- the same redaction class the pack already
  // carries in downpipes[] and sealFaults.downpipeId -- clamped to 128 chars at the recording site. NEVER the
  // storage error text, never the record's contents. null when no fault has been attributed yet.
  lastDownpipeId: string | null;
}

// ---- SCHED housekeeping-health counters (G040) -------------------------------------------------
// SchedHealthKind is the CLOSED classification of a scheduler housekeeping fault that today is either fully
// silent or swallowed by a best-effort catch, so it can grow for months with no pack evidence:
//   - "sweep-fault"          : the alarm()'s opportunistic housekeeping sweep (expired IdP login records, SAML
//                              assertion markers, step-up artefacts) THREW. It is best-effort by design, so a
//                              persistently failing sweep grows DO storage without bound until the value/row
//                              limits bite, with no evidence anywhere until then.
//   - "list-truncated"       : listAllByPrefix exhausted the DO_LIST_MAX_PAGES paging guard with a still-FULL
//                              page, i.e. the enumeration was TRUNCATED. For the dp: prefix that means downpipes
//                              past the cap are never enumerated, hence never scheduled: they read as
//                              nonexistent to due()/restoreTestsDue() and to the fleet reads.
//   - "parity-stamp-failed"  : the due-index parity snapshot (DUE_INDEX_HEALTH_KEY) failed to write after a
//                              rebuild, so the pack's dueIndex block serves the PRIOR snapshot as if it were
//                              fresh (a stale-but-plausible parity reading).
// A closed enum so the projected marker is redaction-safe by construction.
export type SchedHealthKind = "sweep-fault" | "list-truncated" | "parity-stamp-failed";

// SchedHealthCounter is one cumulative tally: how many times the class has fired and when it last fired
// (clamped epoch ms). Counts + a timestamp only.
export interface SchedHealthCounter {
  count: number;
  lastAt: number;
}

// SchedHealthCounters is the persisted record holding one counter per SchedHealthKind. Bounded by construction
// (three fixed classes), redaction-safe (ints only), and read back into the support pack's scheduler section.
export interface SchedHealthCounters {
  sweepFaults: SchedHealthCounter;
  listTruncations: SchedHealthCounter;
  parityStampFailures: SchedHealthCounter;
}

// ---- Per-downpipe state-refusal stamp (G095 / G210) --------------------------------------------
// StateRefusedClass is the CLOSED reason a persisted dp:<id> record was REFUSED at read time by
// migrateOrRejectConfig (the read-time schema guard on the load-bearing source-selection reads, due() and
// trigger()):
//   - "schema-newer"             : the record's schemaVersion is strictly NEWER than this engine supports, i.e.
//                                  the engine was ROLLED BACK and is now reading new-shape state. The downpipe
//                                  is skipped (no run row is ever created), so its backups stop with nothing but
//                                  growing staleness to show for it.
//   - "schema-version-malformed" : the record carries a schemaVersion that is not a number (a corrupt or
//                                  hand-edited stamp), which would otherwise DEFEAT the guard silently.
// A closed enum: the raw refusal message never rides.
export type StateRefusedClass = "schema-newer" | "schema-version-malformed";

// StateRefusal is the stamped refusal evidence for ONE downpipe, persisted under its own key (NOT on the dp:
// record itself -- writing back to a newer-schema record would CLOBBER the very state the guard is protecting).
// Two clamped integers, a closed class, a clamped timestamp and a count: no state content ever rides.
export interface StateRefusal {
  class: StateRefusedClass;
  at: number; // clamped epoch ms of the most recent refusal
  count: number; // clamped count of refusals since the stamp was last cleared (a successful trigger clears it)
  storedVersion: number; // the schemaVersion found on the record (0 when it was not a number)
  supportedVersion: number; // the CONFIG_SCHEMA_VERSION this engine supports
}

// ---- Blackout-window resolution (G322) ---------------------------------------------------------
// BlackoutResolveClass is the CLOSED outcome of deferring a computed fire time out of a downpipe's declared
// blackout (change-freeze) windows:
//   - "ok"                            : the windows applied as declared (either the fire was outside them, or it
//                                       was deferred cleanly past them).
//   - "hop-ceiling-fired-inside-window": the deferral loop exhausted SCHEDULE_BLACKOUT_DEFER_MAX_HOPS and the
//                                       fire time is STILL inside a window, so the run WILL fire inside the
//                                       customer's declared change freeze.
//   - "degenerate-window-inert"       : at least one declared window has startMinute === endMinute, an empty
//                                       half-open interval that covers NOTHING, so that window has never once
//                                       applied (the operator believes they have a freeze that does not exist).
//   - "end-walk-exhausted"            : the window-end walk did not find an uncovered minute within a day, or did
//                                       not advance, so the deferral bailed and the fire may land in the window.
// Class + timestamp only: window minutes/days NEVER ride, consistent with the schedule-string exclusion.
export type BlackoutResolveClass = "ok" | "hop-ceiling-fired-inside-window" | "degenerate-window-inert" | "end-walk-exhausted";

// BlackoutResolve is the stamped blackout-resolution outcome on a DownpipeState: the closed class + when it was
// last evaluated (epoch ms). Absent for a downpipe with no blackout windows (nothing to resolve).
export interface BlackoutResolve {
  class: BlackoutResolveClass;
  at: number;
}

export type { DownpipeState };
