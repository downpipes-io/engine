// THE CRON FAULT LEDGER -- the cron subsystem's closed-vocabulary evidence sink (support-pack gaps
// G084 / G132 / G133 / G205 / G220 / G234 / G278).
//
// THE BUG THIS CLOSES. The cron invocation is the engine's heartbeat: it dispatches every backup, probes
// every destination, refreshes cf-config discovery, pushes the SIEM feed, drives the auto-heal and emits the
// beacon. Every one of those passes is guarded so a fault degrades to "skip this pass this tick" rather than
// crashing the invocation -- which is right, and which is exactly why the faults were INVISIBLE. What the
// pack could see was one anonymous `passErrors` integer per tick (G132: WHICH of ~20 passes failed, and why,
// was Workers-Logs-only), a tick ring with unexplained HOLES (G205: a DO-unreachable tick records nothing at
// all, so "the DO is flapping" and "cron never fired" read identically), a destination probe whose catch
// dropped the S3 error before any sink (G133: an expired STS credential, a DNS fault and a deleted bucket
// all read as "all destinations unreachable"), a discovery cache that silently never refreshed (G234), an
// auto-heal latched forever with no recorded deferral (G220), a beacon failing with no class (G278), and --
// the data-loss-grade one -- SIEM shaping fallbacks that substitute a timestamp, truncate a field, cap a
// batch or RESET THE CURSOR TO ZERO with no counter anywhere (G084).
//
// THE SHAPE. One ISOLATE-LOCAL accumulator, drained and posted ONCE at the end of the cron invocation (the
// same drain-and-post protocol sources/source-fault-ledger.ts uses for a crawl). The post goes through
// admin/diag-writer.ts recordDiagWrite, so a post that is itself DROPPED (the DO is the very thing that was
// flapping) is counted in droppedWrites["cron-health"] and lands the moment the DO comes back.
//
// THE OUTAGE THAT CANNOT REPORT ITSELF (G205). When the scheduler DO is unreachable, drive() bails BEFORE it
// can record anything -- the sink for the record is the thing that is down. So the tick-record failure is
// noted in the isolate-local tally and FLUSHED ON THE NEXT HEALTHY TICK, exactly like the dropped-write
// protocol: the hole in the ring is then explained by tickRecordFailures rather than being indistinguishable
// from a cron that never fired. An isolate that dies holding a pending tally loses it; that is the
// irreducible floor, and it is strictly better than the prior zero.
//
// REDACTION (binding, NO-CUSTODY). Every field is a CLOSED ENUM, a COUNT, a CLAMPED INT or a BOOLEAN. The
// classifiers below READ an error only to SELECT an enum member and RETURN THAT ENUM: the Cloudflare/S3
// message, the beacon URL, the ingest key, the destination endpoint, the bucket, the object key, the audit
// event body and the DO's own free-text refusal reason (which can embed storage paths) never enter the
// ledger, and applyCronHealth re-gates every field DO-side so even a drifted or hostile caller cannot land
// one. The ONLY identifier carried is a destination id -- the operator's own label, already in the pack's
// destResolution section -- and it is control-stripped and clamped.

import { bumpAdminCounters } from "../admin/diag-counters.ts";
import type { AdminCounterName, DestProbeReason } from "../admin/diag-records.ts";
import { recordDiagWrite } from "../admin/diag-writer.ts";
import { doURL } from "../do-url.ts";
import { destDownReason } from "../dest/classify.ts";
import { NOTIFY_EVENT_NAMES } from "../notify/types.ts";

// ---- closed vocabularies ---------------------------------------------------------------------------------

// CRON_PASS_NAMES is the CLOSED set of passes the cron invocation drives (G132). Today a pass that bails in
// its own guard bumps ONE anonymous passErrors integer, and three passes (the fleet drill, deploy-observe
// and the health pass, which swallows its own throw) never move it at all -- so "no alerts / no restore
// tests / no exports for days" cannot be attributed to a pass, let alone a cause.
export const CRON_PASS_NAMES = [
  "seal-loop", // the backup dispatch loop itself
  "alerts", // alert reconciliation + the webhook sends
  "replication-alerts", // the replica-lag / replica-down alert pass
  "source-drift", // the detached-source (binding vanished) alert pass
  "expiry", // the licence/key expiry stream
  "restore-tests", // the scheduled restore drills
  "replication", // the 3-2-1 fan-out catch-up
  "retention", // the retention prune
  "orphan-reconcile", // the orphaned-run/segment reconciliation
  "canary", // the hourly canary flight
  "cp-export", // the signed control-plane export
  "cp-health", // the control-plane amnesia probe + recovery latch
  "auto-heal", // the control-plane auto-recovery
  "deploy-observe", // the deploy-identity keystone observation
  "discovery", // the cf-config discovery refresh
  "posture", // the security-centre posture evaluation
  "beacon", // the opt-in vendor beacon
  "digest", // the notification digest flush
  "update-alert", // the new-engine-version alert
  "siem-push", // the audit-log SIEM push
  "otlp-push", // the OTLP metrics push
] as const;
export type CronPassName = (typeof CRON_PASS_NAMES)[number];
const CRON_PASS_NAME_SET: ReadonlySet<string> = new Set(CRON_PASS_NAMES);

// CRON_PASS_ERROR_CLASSES is the CLOSED vocabulary for WHY a pass failed. It is deliberately coarse: the
// exception message stays in Workers Logs, and this is the class that routes triage (an engine-plane fault
// vs a customer-config fault vs an outbound-delivery fault).
//   do-fetch  - a scheduler-DO round trip threw or answered non-2xx (the ENGINE plane, not the customer's)
//   parse     - a DO/API response did not have the expected shape (a version skew after a partial deploy)
//   budget    - the pass yielded/skipped because the shared subrequest budget was exhausted (chronic
//               starvation is why a pass "never runs" on a crowded fleet)
//   config    - the pass could not resolve what it needed from configuration (no destination, no token)
//   delivery  - an OUTBOUND send failed (a webhook, a SIEM collector, an OTLP endpoint, the beacon)
//   other     - anything else; last, so an unrecognised fault is never mislabelled
export const CRON_PASS_ERROR_CLASSES = ["do-fetch", "parse", "budget", "config", "delivery", "other"] as const;
export type CronPassErrorClass = (typeof CRON_PASS_ERROR_CLASSES)[number];
const CRON_PASS_ERROR_CLASS_SET: ReadonlySet<string> = new Set(CRON_PASS_ERROR_CLASSES);

// DISCOVERY_SKIP_REASONS is the CLOSED vocabulary for why the cf-config discovery pass did NOT refresh a
// stale cache this tick (G234). Every one of these is currently either swallowed or an anonymous passErrors
// bump, while capture fail-safes to ALL every surface in the registry every run -- which is the "cf-config backups got slow
// and expensive" ticket, with no recorded cause.
//   no-token       - neither the stored discovery config nor DISCOVERY_API_TOKEN carried a token
//   out-of-scope   - the downpipe's account was narrowed OUT of the discovery scope after it was created
//                    (the confused-deputy re-check); the cache can now never refresh
//   budget-starved - the shared tick budget never had the probe reserve free (a crowded fleet)
//   probe-failed   - the probe itself threw (a CF-API 403/5xx)
//   none-due       - no downpipe was stale; the healthy steady state (recorded so a QUIET pass is
//                    distinguishable from a BLOCKED one -- the whole point of the gap)
export const DISCOVERY_SKIP_REASONS = ["no-token", "out-of-scope", "budget-starved", "probe-failed", "none-due"] as const;
export type DiscoverySkipReason = (typeof DISCOVERY_SKIP_REASONS)[number];
const DISCOVERY_SKIP_REASON_SET: ReadonlySet<string> = new Set(DISCOVERY_SKIP_REASONS);

// BEACON_FAIL_CLASSES is the CLOSED vocabulary for a failed beacon emission (G278). The throw path today
// persists ok:false with NO status and NO class, so a malformed BEACON_URL (a permanent operator error, one
// line to fix) and a network blip (self-healing) are indistinguishable.
//   url-invalid - new URL("/beacon", base) threw: BEACON_URL is not a valid base (never self-heals)
//   network     - the outbound POST threw (DNS, TLS, reset, timeout)
//   non-2xx     - the receiver answered, and refused (ingestion disabled, or a 422 shape rejection)
//   do-read     - the /beacon-aggregate DO read threw: an ENGINE fault, nothing to do with the vendor
//   unknown     - residual
export const BEACON_FAIL_CLASSES = ["url-invalid", "network", "non-2xx", "do-read", "unknown"] as const;
export type BeaconFailClass = (typeof BEACON_FAIL_CLASSES)[number];
const BEACON_FAIL_CLASS_SET: ReadonlySet<string> = new Set(BEACON_FAIL_CLASSES);

// AUTOHEAL_DEFERRAL_CLASSES is the CLOSED vocabulary for an auto-heal attempt that did NOT refuse (a refusal
// already has its own closed AutoHealRefusalCode and a durable marker) and did NOT progress -- it simply
// returned, leaving the recovery latched with `staged:null` or `resumeApplied:false` forever, with the reason
// swallowed or Workers-Logs-only (G220). "Backups stopped after a wipe and never resumed" is THIS shape.
//   budget-reserve   - the shared tick budget never had CONTROL_PLANE_AUTOHEAL_RESERVE free: budget-starved
//                      every tick, so the auto-heal literally never runs
//   dest-unresolvable - the destination could not be resolved/built this tick (no bucket to scan)
//   resume-refused   - the export WAS staged and verified, and the DO's resume-apply slice refused
//   probe-transport  - the amnesia-probe POST itself failed, so the probe field silently goes STALE (an
//                      empty catch today) and the pack's amnesiaProbe class is a lie by omission
export const AUTOHEAL_DEFERRAL_CLASSES = ["budget-reserve", "dest-unresolvable", "resume-refused", "probe-transport"] as const;
export type AutoHealDeferralClass = (typeof AUTOHEAL_DEFERRAL_CLASSES)[number];
const AUTOHEAL_DEFERRAL_CLASS_SET: ReadonlySet<string> = new Set(AUTOHEAL_DEFERRAL_CLASSES);

// RESUME_APPLY_REASON_CODES is the CLOSED projection of the DO's resume-apply refusal reason (G220). The DO
// returns `reason` as FREE TEXT that can embed storage paths, so it must NEVER be carried: this classifier
// reads it once, selects a member, and the text is discarded at the boundary.
export const RESUME_APPLY_REASON_CODES = ["not-staged", "verify-failed", "already-applied", "storage-failed", "shape", "unknown"] as const;
export type ResumeApplyReasonCode = (typeof RESUME_APPLY_REASON_CODES)[number];
const RESUME_APPLY_REASON_CODE_SET: ReadonlySet<string> = new Set(RESUME_APPLY_REASON_CODES);

// SIEM_SHAPING_FALLBACKS is the CLOSED vocabulary of the SIEM push's SILENT fallbacks (G084). Not one of
// these has a counter or a marker anywhere today.
//   timestamp-substituted - a malformed event ts fell back to "now": the SIEM's own event ordering is wrong
//   field-truncated       - a header/extension field hit the CEF/LEEF length cap: a truncated HASH field
//                           fails the customer's chain-verification script
//   batch-cap-truncated   - the shaper sliced the batch to SIEM_PUSH_BATCH_CAP. DATA-LOSS GRADE: if the
//                           drain limit ever exceeds the cap, the tail is dropped while the cursor advances
//                           PAST it and the trail claims full delivery. assertSiemBatchCapSound() below is
//                           the standing guard; this counter is the evidence if it ever opens.
//   cursor-reset          - the push cursor was reset to 0: the SIEM receives thousands of DUPLICATE
//                           historical events, which is the ticket that opened this gap
export const SIEM_SHAPING_FALLBACKS = ["timestamp-substituted", "field-truncated", "batch-cap-truncated", "cursor-reset"] as const;
export type SiemShapingFallback = (typeof SIEM_SHAPING_FALLBACKS)[number];
const SIEM_SHAPING_FALLBACK_SET: ReadonlySet<string> = new Set(SIEM_SHAPING_FALLBACKS);

// ---- ROUND 5 (G184 / G292 / G293 / G294 / G295 / G319 / G333) ---------------------------------------------
//
// Every one of these is the SAME shape of hole: a cron pass DECIDED something (an alert was consumed but never
// delivered; an export skipped a destination; a push tick never reached a send; a restore test never ran; the
// reconcile pass bailed) and the decision left NO durable trace, so the pack shows a healthy silence. They all
// ride the ledger that already exists, so there is ONE sink (POST /diag/cron-health), ONE read (GET
// /cron-health) and ONE redaction chokepoint (applyCronHealth) rather than seven new ones.

// NOTIFY_EVENT_NAME_SET is the closed alert vocabulary, imported from its SINGLE SOURCE OF TRUTH
// (notify/types.ts NOTIFY_EVENT_NAMES) rather than re-listed here -- a hand-copied union would drift, and a
// drifted member is silently dropped at the chokepoint, which is exactly the failure this record exists to
// catch. It keys BOTH G184's undelivered-critical latch and G294's dropped-emission map.
const NOTIFY_EVENT_NAME_SET: ReadonlySet<string> = new Set(NOTIFY_EVENT_NAMES);

// CP_EXPORT_FAIL_CLASSES is the CLOSED vocabulary for WHY one destination refused the signed control-plane
// export (G292). Today perDest carries ok:false and NOTHING else, so "one destination's recovery artefact is
// generations old" cannot separate a WORM policy refusing the overwrite (an irreducible, permanent refusal
// that needs a new key scheme) from a rotated CONFIG_WRAP_KEY (the credential cannot be opened at all) from a
// transient blip (it will heal on the next change).
export const CP_EXPORT_FAIL_CLASSES = ["transport", "auth", "worm-denied", "wrap-key", "unknown"] as const;
export type CpExportFailClass = (typeof CP_EXPORT_FAIL_CLASSES)[number];
const CP_EXPORT_FAIL_CLASS_SET: ReadonlySet<string> = new Set(CP_EXPORT_FAIL_CLASSES);

// RESTORE_TEST_SKIP_CLASSES is the CLOSED vocabulary for a scheduled restore test that did NOT RUN (G295).
// The pack shows lastRestoreTestAt going stale and restoreTestStalled going true; it has never been able to
// say WHY, and the four causes need four different answers.
//   pre-drill-fault     - the drill threw BEFORE it started (an unresolvable destination, an unusable wrap
//                         key): the whole recording machinery is downstream of the throw, so nothing was
//                         written at all -- the "never tested for months" ticket
//   budget-deferred     - the tick's shared subrequest budget was already spent by backups. Correct (backups
//                         outrank drills) and invisible: CHRONIC starvation on a crowded fleet is why a
//                         compliance report reads "restore tests overdue fleet-wide"
//   start-marker-failed - the in-flight marker write failed, so a tick-killed drill leaves no "attempted" trace
//   record-failed       - the drill RAN and its outcome write was lost: a week-long hole in the evidence with
//                         a perfectly healthy engine behind it
export const RESTORE_TEST_SKIP_CLASSES = ["pre-drill-fault", "budget-deferred", "start-marker-failed", "record-failed"] as const;
export type RestoreTestSkipClass = (typeof RESTORE_TEST_SKIP_CLASSES)[number];
const RESTORE_TEST_SKIP_CLASS_SET: ReadonlySet<string> = new Set(RESTORE_TEST_SKIP_CLASSES);

// RECONCILE_SKIP_REASONS is the CLOSED vocabulary for an orphan-reconcile pass that recorded no signal (G333).
// The reconcile signals are persisted ONLY when the inventory got far enough, so every bail leaves the LAST
// signal standing -- and a months-old signal is indistinguishable from a fresh one. The pass is also opt-in,
// so ABSENCE is ambiguous too (hence `enabled`, the flag echo).
export const RECONCILE_SKIP_REASONS = ["downpipes-unavailable", "signer-missing", "dest-not-configured", "dest-build-failed", "inventory-fault", "persist-failed"] as const;
export type ReconcileSkipReason = (typeof RECONCILE_SKIP_REASONS)[number];
const RECONCILE_SKIP_REASON_SET: ReadonlySet<string> = new Set(RECONCILE_SKIP_REASONS);

/**
 * classifyCpExportFail coarsens a per-destination control-plane export fault into a closed CpExportFailClass
 * (G292). It reads the fault ONLY to select a member and RETURNS that member: the endpoint, the bucket, the
 * object key and the store's message never leave this function.
 *
 * @param e - the thrown fault.
 * @returns the closed class.
 */
export function classifyCpExportFail(e: unknown): CpExportFailClass {
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  const s = m.toLowerCase();
  // The wrap-key arm FIRST: a rotated CONFIG_WRAP_KEY throws out of the credential read, before any store is
  // reached, and it is the one cause whose remedy (restore the prior key / re-enter the credential) has
  // nothing to do with the destination.
  if (s.includes("wrap key") || s.includes("config_wrap_key") || s.includes("unwrap") || s.includes("envelope")) return "wrap-key";
  // Then the WORM arm, BEFORE the shared classifier. This ordering deliberately differs from destDownReason's
  // (which asks auth first, correctly, for an ARCHIVE write): a control-plane export re-writes a RECOVERY
  // ARTEFACT into a WORM-locked namespace, and an Object-Lock refusal of that overwrite arrives as a 403 --
  // so the shared classifier would file the single most important cause here (a permanent, structural refusal
  // that no credential change can fix) under `auth`, and send the operator to rotate a perfectly good key.
  if (/object[- ]lock|InvalidRetentionPeriod|retention|worm/i.test(m)) return "worm-denied";
  switch (destDownReason(e)) {
    case "auth":
      return "auth";
    case "worm-refused":
      return "worm-denied";
    case "timeout":
    case "network":
    case "tls":
    case "throttled":
      return "transport";
    case "other":
      return "unknown";
  }
}

// G133's per-destination probe class REUSES the DEST_PROBE_REASONS vocabulary and the bounded
// diag:destprobefaults record that ALREADY exist in admin/diag-records.ts (built for the sibling "which
// destination refused, and why" gap). There is deliberately NO second vocabulary and NO second sink: the
// failover WRITE probe in cron/seal-dispatch.ts is simply the caller that record never had. Its catch
// dropped the S3 error before ANY sink, so "backups failing: all destinations unreachable" could not
// separate an expired STS credential (rotate it) from a deleted bucket (recreate it) from a DNS fault
// (wait). classifyDestProbeReason below is the bridge, and the probe rows ride the existing
// POST /diag/dest-probe-faults route.

// ---- bounds ----------------------------------------------------------------------------------------------

export const CRON_HEALTH_KEY = "diag:cronhealth";
// The destination-probe accumulator's bound, and it is the FIRST of the three cuts on this record's path.
//
// THE COMMENT HERE USED TO SAY "the 32 most-recently-probed destinations", AND THAT WAS FALSE. The guard
// below refuses a destination the map has never seen, so what it keeps is the FIRST n probed in the
// invocation, not the most recent; nothing here evicts anything. It also said "a fleet has a handful; 32 is
// far above any real estate", which is an assumption rather than a measurement -- nothing in the product
// bounds how many destinations an estate may hold, and the product's own per-destination cap in the export
// health record is 64. Raised to match it and the DO map (another pass), and the refusal is now COUNTED
// and posted, because a destination refused here never reaches the DO at all: it is invisible to every cut
// downstream, and a failing destination missing from this record reads as a destination that probed fine.
export const DEST_PROBE_MAX = 64;
// The destination id is the OPERATOR'S OWN label (already carried in the pack's destResolution section).
// Control-stripped and clamped at the chokepoint so it can never become a free-text seam.
const COUNT_MAX = 1_000_000_000;
const BUMP_MAX = 100_000;
// missedApprox is clamped to a week of */15 ticks: a garbled or hostile clock can never write an unbounded
// number onto the tick record.
const MISSED_TICKS_MAX = 672;

// ---- pure classifiers (each READS to SELECT an enum member, and RETURNS the enum) -------------------------

/**
 * classifyCronPassError coarsens a thrown pass fault into a closed CronPassErrorClass. It reads the message
 * ONLY to select a member and returns THAT: the message never leaves this function, and can never be stored.
 *
 * @param e - the thrown fault (untrusted; may be anything).
 * @returns the closed class.
 */
export function classifyCronPassError(e: unknown): CronPassErrorClass {
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  const s = m.toLowerCase();
  if (s.includes("subrequest") || s.includes("budget") || s.includes("too many api requests")) return "budget";
  // The DO plane: a stub fetch that threw, or a non-2xx from an internal route.
  if (s.includes("durable object") || s.includes("scheduler") || s.includes("internal error") || s.includes("cannot resolve do")) return "do-fetch";
  if (s.includes("json") || s.includes("unexpected token") || s.includes("is not a function") || s.includes("undefined is not")) return "parse";
  if (s.includes("not configured") || s.includes("no token") || s.includes("no destination") || s.includes("missing binding")) return "config";
  if (s.includes("fetch failed") || s.includes("network") || s.includes("webhook") || s.includes("dns") || s.includes("tls") || s.includes("connect")) return "delivery";
  return "other";
}

/**
 * classifyBeaconFail coarsens a beacon emission fault into a closed BeaconFailClass (G278).
 *
 * @param e - the thrown fault, or undefined when the receiver answered with a non-2xx.
 * @param status - the receiver's HTTP status, when it answered at all.
 * @returns the closed class.
 */
export function classifyBeaconFail(e: unknown, status?: number): BeaconFailClass {
  if (typeof status === "number") return "non-2xx";
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  const s = m.toLowerCase();
  if (s.includes("invalid url") || s.includes("failed to parse url") || s.includes("invalid base url")) return "url-invalid";
  if (s.includes("beacon-aggregate") || s.includes("durable object") || s.includes("scheduler")) return "do-read";
  if (s.includes("fetch failed") || s.includes("network") || s.includes("dns") || s.includes("tls") || s.includes("connect") || s.includes("timed out")) return "network";
  return "unknown";
}

/**
 * classifyResumeApplyReason projects the control-plane DO's FREE-TEXT resume-apply refusal reason onto a
 * closed code (G220). The DO's reason can embed storage paths, so this is the boundary at which the text is
 * read and DISCARDED: only the returned enum is ever recorded.
 *
 * @param reason - the DO's reason string (untrusted, may be undefined).
 * @returns the closed code.
 */
export function classifyResumeApplyReason(reason: string | undefined): ResumeApplyReasonCode {
  const s = (reason ?? "").toLowerCase();
  if (s === "") return "unknown";
  if (s.includes("not staged") || s.includes("nothing staged") || s.includes("no staged")) return "not-staged";
  if (s.includes("verify") || s.includes("signature") || s.includes("unverified")) return "verify-failed";
  if (s.includes("already applied") || s.includes("already resumed")) return "already-applied";
  if (s.includes("storage") || s.includes("put failed") || s.includes("write failed")) return "storage-failed";
  if (s.includes("shape") || s.includes("malformed") || s.includes("invalid")) return "shape";
  return "unknown";
}

/**
 * classifyDestProbeReason coarsens a failed destination WRITE probe into a closed DestProbeReason (G133) --
 * the SAME closed vocabulary the destination-selection record already speaks, so the failover probe and the
 * archive-destination probe answer "why is this store refusing us" in identical words.
 *
 * It reads the fault ONLY to SELECT a member and RETURNS that member: the S3 <Code>, the message, the
 * endpoint, the bucket and the object key never leave the driver and can never be recorded. It bridges the
 * shared dest/classify.ts destDownReason (which knows the message shapes) onto the record's vocabulary; the
 * two sets differ deliberately (destDownReason models WRITE-time behaviour: throttling and WORM refusals are
 * real, retryable outcomes there), so the mapping is total and explicit rather than a cast.
 *
 * @param e - the thrown probe fault.
 * @returns the closed reason.
 */
export function classifyDestProbeReason(e: unknown): DestProbeReason {
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  // The status is extracted with the SAME `status NNN` / `HTTP NNN` shape dest/classify.ts uses, and never
  // with a bare 3-digit match: a bucket named "acme-500-prod", an object key with a number in it or a byte
  // count would otherwise be read as an HTTP status and MIS-classify the fault -- and a wrong class is worse
  // than an honest unknown, because it sends triage to a remedy that cannot work.
  const status = /(?:status|HTTP) (\d{3})/.exec(m);
  const code = status !== null ? Number(status[1]) : 0;
  // A 404 is not a "down" store at all -- it is a bucket that has been DELETED or renamed under a live
  // downpipe, which destDownReason has no member for.
  if (code === 404 || /NoSuchBucket|no such bucket/i.test(m)) return "not-found";
  // The shared classifier decides EVERYTHING else, so the failover probe and the archive-destination probe
  // never disagree. Note the ordering that matters: a 503 SlowDown is THROTTLING, not an outage -- routing it
  // to http-5xx would tell an operator to wait out a Cloudflare incident that is not happening, when the real
  // remedy is to back off. destDownReason already draws that line, so it is asked BEFORE any 5xx test.
  switch (destDownReason(e)) {
    case "auth":
      return "auth";
    case "timeout":
      return "timeout";
    // TLS is a transport fault with no HTTP exchange, exactly like DNS/a reset: the record's `network` member.
    case "network":
    case "tls":
      return "network";
    case "throttled":
      return "throttled";
    case "worm-refused":
      return "worm-refused";
    case "other":
      // A server error the shared classifier had no narrower member for.
      return code >= 500 && code <= 599 ? "http-5xx" : "probe-other";
  }
}

// ---- the isolate-local ledger ----------------------------------------------------------------------------

/** PassHealthDelta is ONE pass's outcome this tick: it either completed, or it failed with a closed class. */
interface PassDelta {
  ok: boolean;
  cls?: CronPassErrorClass;
}

/** CronHealthDelta is the drained, redaction-safe snapshot the cron invocation posts. Every field bounded. */
export interface CronHealthDelta {
  passes?: Partial<Record<CronPassName, PassDelta>>;
  // tickRecordFailures: how many ticks could not record their outcome AT ALL (the DO was the thing that was
  // down). Carried across ticks in the isolate-local tally and reported by the next HEALTHY tick (G205).
  tickRecordFailures?: number;
  // tickGap / tickMissedApprox: derived by the DO from the previous tick's timestamp; the Worker sends the
  // interval it believes elapsed, and the DO recomputes from its OWN clock (never trusts this one).
  discoverySkips?: Partial<Record<DiscoverySkipReason, number>>;
  beacon?: { envPresent: { url: boolean; ingestKey: boolean; accountId: boolean }; failClass?: BeaconFailClass; stateWriteFailures?: number };
  autoHeal?: { attempted: boolean; deferral?: AutoHealDeferralClass; resumeApplyReason?: ResumeApplyReasonCode };
  siem?: Partial<Record<SiemShapingFallback, number>>;
  // danglingDestinationRefs: fan-out destinationIds with NO config record, silently skipped on an otherwise
  // healthy run (G133). The customer durably holds FEWER copies than they configured, with zero warning.
  danglingDestinationRefs?: number;
  // ---- round 5 ------------------------------------------------------------------------------------------
  // notify (G184 + G294): the alerts that were CONSUMED and never delivered, and the history rows that were
  // never written. undeliveredCritical is keyed by the closed event vocabulary; claimSpent counts the subset
  // whose ONE-SHOT claim (the once-per-event budget) was already spent, so the page is permanently lost.
  notify?: {
    undeliveredCritical?: Partial<Record<string, number>>;
    claimSpent?: number;
    historyAppendFailures?: number;
    digestNoTransport?: number;
    droppedEmissions?: Partial<Record<string, number>>;
  };
  // updates (G319): the update channel's own verification state, and the confirm-clear that keeps failing.
  updates?: { checked?: boolean; channelVerified?: boolean; verifyFailures?: number; confirmClearFailures?: number };
  // cpExport (G292): the control-plane export pass's TRUNCATION, its per-destination fail classes, its
  // unpurged plaintext debt, and the record writes (including its own) that were lost.
  cpExport?: {
    attempted?: boolean;
    truncated?: boolean;
    destsSkippedByBudget?: number;
    perDestFail?: Partial<Record<string, number>>;
    plaintextPurgePending?: number;
    recordWriteFailures?: number;
    passThrew?: boolean;
  };
  // push (G293): the delivery-trail writes that were themselves DROPPED. A lost trail write on a SUCCESSFUL
  // delivery strands the cursor, so the next tick re-sends the same batch: the duplicate-events ticket.
  push?: { siemTrailWriteFailures?: number; otlpTrailWriteFailures?: number };
  // restoreTest (G295): per-downpipe non-execution (closed class), the whole-pass budget deferral, and the
  // fleet-drill campaign's own batch health.
  restoreTest?: {
    skips?: Array<{ id: string; cls: RestoreTestSkipClass }>;
    passBudgetDeferred?: number;
    fleetBatchAttempted?: boolean;
    fleetBatchFailures?: number;
  };
  // reconcile (G333): the flag echo, the closed skip reason, the RUNLOG signature verdict split, and the
  // abstain reason as a one-way digest (the free text can describe topology and must never ride).
  reconcile?: {
    enabled?: boolean;
    attempted?: boolean;
    skips?: Partial<Record<string, number>>;
    runlogSigAbsent?: number;
    runlogVerifyFailed?: number;
    persistFailures?: number;
    circuitBreakerTripped?: boolean;
  };
  // alarms: the closed ADMIN counter names this tick's faults should ALSO raise. They ride the admin-counter
  // aggregate, which the pack already carries in full, so the loudest fact of each gap ("a critical page was
  // never delivered", "a restore test did not run") is visible in a pack taken TODAY even before the richer
  // cronHealth projections land. Counts only, against a closed name set.
  alarms?: Partial<Record<AdminCounterName, number>>;
}

// The accumulator. Module scope (one per isolate) and reset at the top of every cron invocation, exactly as
// the source ledger is reset before a crawl -- except tickRecordFailures, which SURVIVES the reset by design
// (it is the record of a tick that could not report at all, and its whole purpose is to be reported later).
let ledger: CronHealthDelta = {};
let pendingTickRecordFailures = 0;
// The per-invocation destination-probe rows. They ride the EXISTING diag:destprobefaults record (its own
// route), not the cron-health delta, so they are held separately and drained by recordDestProbeFaults.
let destProbeRows: Map<string, DestProbeReason> | null = null;
// The destinations DEST_PROBE_MAX refused this invocation. Held beside the rows and drained with them, so
// the refusal travels to the DO on the same post rather than dying in the isolate.
let destProbeRefused = 0;

/** resetCronFaultLedger clears the per-invocation accumulator. The pending tick-record failures SURVIVE. */
export function resetCronFaultLedger(): void {
  ledger = {};
  destProbeRows = null;
  destProbeRefused = 0;
}

/**
 * noteCronPass records ONE pass's outcome (G132). A completed pass resets its consecutive-failure run; a
 * failed pass carries a closed class.
 *
 * @param name - the closed pass name.
 * @param ok - whether the pass completed.
 * @param e - the fault, when it did not (classified here; the message is discarded).
 */
export function noteCronPass(name: CronPassName, ok: boolean, e?: unknown): void {
  ledger.passes ??= {};
  const passes = ledger.passes;
  if (ok) {
    passes[name] = { ok: true };
    return;
  }
  // A pass reports its failure TWICE: once at its own catch (which holds the exception, so it can classify
  // it) and once at the driver's tally (which sees only a false return). The classified one must WIN, so a
  // classless failure never overwrites a classed one already recorded for this pass this tick -- otherwise
  // the driver's generic "other" would erase the very attribution the gap exists to provide.
  const prev = passes[name];
  if (e === undefined && prev !== undefined && prev.ok === false) return;
  passes[name] = { ok: false, cls: classifyCronPassError(e) };
}

/**
 * noteTickRecordFailure notes that a tick could not record its outcome at all (G205): either the scheduler
 * DO was unreachable at the /tick or /due preamble (so drive() bailed before doing any work), or the
 * /tick-outcome POST itself failed. It is ISOLATE-LOCAL and survives the per-invocation reset, so the next
 * HEALTHY tick reports it -- which is what turns an unexplained HOLE in the tick ring into a recorded cause.
 */
export function noteTickRecordFailure(): void {
  pendingTickRecordFailures = Math.min(COUNT_MAX, pendingTickRecordFailures + 1);
}

/** noteDiscoverySkip records why the cf-config discovery pass did not refresh a stale cache (G234). */
export function noteDiscoverySkip(reason: DiscoverySkipReason): void {
  ledger.discoverySkips ??= {};
  const m = ledger.discoverySkips;
  m[reason] = (m[reason] ?? 0) + 1;
}

/**
 * noteBeaconEnv records WHICH of the three beacon env vars are present (G278). Presence booleans only: a
 * half-configured beacon (one var typo'd) is indistinguishable from a deliberately-off one today, which is
 * the "we opted in but the vendor assurance view never lit up" ticket. The VALUES never enter the ledger.
 *
 * @param env - the three raw values (read for emptiness only).
 */
export function noteBeaconEnv(env: { url: unknown; ingestKey: unknown; accountId: unknown }): void {
  const present = (v: unknown): boolean => typeof v === "string" && v.trim() !== "";
  ledger.beacon ??= { envPresent: { url: false, ingestKey: false, accountId: false } };
  const b = ledger.beacon;
  b.envPresent = { url: present(env.url), ingestKey: present(env.ingestKey), accountId: present(env.accountId) };
}

/** noteBeaconFail records the closed class of a failed beacon emission (G278). */
export function noteBeaconFail(cls: BeaconFailClass): void {
  ledger.beacon ??= { envPresent: { url: false, ingestKey: false, accountId: false } };
  const b = ledger.beacon;
  b.failClass = cls;
}

/** noteBeaconStateWriteFailure records that recordBeaconState swallowed its OWN failure (G278). */
export function noteBeaconStateWriteFailure(): void {
  ledger.beacon ??= { envPresent: { url: false, ingestKey: false, accountId: false } };
  const b = ledger.beacon;
  b.stateWriteFailures = (b.stateWriteFailures ?? 0) + 1;
}

/** noteAutoHealAttempt records that the auto-heal pass ran at all this tick (G220). */
export function noteAutoHealAttempt(): void {
  ledger.autoHeal = { ...(ledger.autoHeal ?? {}), attempted: true };
}

/** noteAutoHealDeferral records a STALL (not a refusal): latched, no progress, reason previously swallowed. */
export function noteAutoHealDeferral(cls: AutoHealDeferralClass): void {
  ledger.autoHeal = { ...(ledger.autoHeal ?? { attempted: true }), attempted: true, deferral: cls };
}

/** noteResumeApplyRefusal records the CLOSED projection of the DO's free-text resume-apply reason (G220). */
export function noteResumeApplyRefusal(reason: string | undefined): void {
  ledger.autoHeal = {
    ...(ledger.autoHeal ?? { attempted: true }),
    attempted: true,
    deferral: "resume-refused",
    resumeApplyReason: classifyResumeApplyReason(reason),
  };
}

/** noteSiemShapingFallback counts ONE silent SIEM shaping / cursor fallback (G084). */
export function noteSiemShapingFallback(kind: SiemShapingFallback, n = 1): void {
  if (n <= 0) return;
  ledger.siem ??= {};
  const m = ledger.siem;
  m[kind] = Math.min(COUNT_MAX, (m[kind] ?? 0) + n);
}

/**
 * noteDestProbeFault records that the failover WRITE probe found ONE destination unwritable (G133), with the
 * closed reason. The destinationId is the OPERATOR'S OWN label (already carried in the pack's destResolution
 * section); the probe fault itself is classified here and DISCARDED. A destination that probes HEALTHY
 * records nothing at all: this record exists to name a cause, and only a FAILING destination holds a row.
 *
 * @param destinationId - the operator's destination id.
 * @param e - the probe fault (classified here; never stored).
 */
export function noteDestProbeFault(destinationId: string, e: unknown): void {
  destProbeRows ??= new Map();
  const rows = destProbeRows;
  // The refusal is COUNTED rather than merely taken: this accumulator is not a ring, so a destination
  // refused here is absent from the pack rather than late in it, and the drain carries the count out.
  if (rows.size >= DEST_PROBE_MAX && !rows.has(destinationId)) {
    destProbeRefused = Math.min(COUNT_MAX, destProbeRefused + 1);
    return;
  }
  rows.set(destinationId, classifyDestProbeReason(e));
}

/**
 * noteDanglingDestinationRef counts a fan-out destinationId with NO config record (G133): the run is skipped
 * silently on an otherwise healthy tick, so the customer durably holds FEWER copies than they configured.
 */
export function noteDanglingDestinationRef(): void {
  ledger.danglingDestinationRefs = Math.min(COUNT_MAX, (ledger.danglingDestinationRefs ?? 0) + 1);
}

// ---- round 5 recorders (G184 / G292 / G293 / G294 / G295 / G319 / G333) -----------------------------------
//
// THE CARRIED HALF. The notify + alarm notes can be raised OUTSIDE a cron invocation: the MANUAL canary
// fly-now (index.ts) drives runCanaryIfDue directly, and it can spend a one-shot rollback-needed claim on an
// alert that is never delivered. The per-invocation ledger is RESET at the top of every cron tick, so a note
// left there by a non-cron path would be wiped by the next tick that runs in the same warm isolate -- silently
// losing exactly the evidence this closes. So these two SURVIVE the reset and are cleared only when the report
// actually LANDS, the same discipline pendingTickRecordFailures uses for the tick it could not record.
let carriedNotify: NonNullable<CronHealthDelta["notify"]> = {};
let carriedAlarms: Partial<Record<AdminCounterName, number>> = {};

/**
 * noteUndeliveredCriticalAlert records that a ONE-SHOT alert was CONSUMED (its claim spent, its dedupe
 * latched) and then NOT delivered to a single channel (G184). This is the "nobody was paged when backups
 * STOPPED / the destination died / a bad update needed rolling back" ticket: the claim-then-deliver pattern
 * spends the once-per-event budget BEFORE it checks routeNotification's delivered boolean (which several call
 * sites ignore outright), so the page is permanently lost -- and the only trace was an aged delivered:false
 * row inside a 20-of-1000 notify history window that a later pack no longer carries.
 *
 * @param event - the closed notify event name (out-of-vocabulary is dropped at the chokepoint).
 * @param claimSpent - whether a one-shot claim was consumed for it (so it will NEVER be re-attempted).
 */
export function noteUndeliveredCriticalAlert(event: string, claimSpent: boolean): void {
  carriedNotify.undeliveredCritical ??= {};
  const m = carriedNotify.undeliveredCritical;
  m[event] = Math.min(COUNT_MAX, (m[event] ?? 0) + 1);
  if (claimSpent) carriedNotify.claimSpent = Math.min(COUNT_MAX, (carriedNotify.claimSpent ?? 0) + 1);
  noteAdminAlarm("notify-critical-alert-undelivered");
}

/** noteNotifyHistoryAppendFailure records a notify history append that was DROPPED (G294): the alert may well
 * have been delivered, and the pack's history has no row for it, so "was our critical alert delivered?" is
 * unanswerable from the pack in exactly the case that matters. */
export function noteNotifyHistoryAppendFailure(): void {
  carriedNotify.historyAppendFailures = Math.min(COUNT_MAX, (carriedNotify.historyAppendFailures ?? 0) + 1);
  noteAdminAlarm("notify-history-append-failed");
}

/** noteDigestNoTransport records a due digest flushed to a channel that no longer exists or is disabled
 * (G294): the batch is discarded, its pending seqs are cleared, and NO history row is written at all. */
export function noteDigestNoTransport(): void {
  carriedNotify.digestNoTransport = Math.min(COUNT_MAX, (carriedNotify.digestNoTransport ?? 0) + 1);
}

/** noteDroppedEmission records a WHOLE notify emission lost because the routing pass threw (G294). Today it
 * becomes an anonymous passSkips++ whose own bump can silently fail; this names the EVENT that was lost. */
export function noteDroppedEmission(event: string): void {
  carriedNotify.droppedEmissions ??= {};
  const m = carriedNotify.droppedEmissions;
  m[event] = Math.min(COUNT_MAX, (m[event] ?? 0) + 1);
}

/** noteAdminAlarm raises ONE closed admin-counter name for this tick. The admin-counter aggregate is carried
 * in the pack IN FULL (its projection gates on the closed name set), so an alarm raised here is visible in a
 * pack taken today, whatever the richer cronHealth projection carries. */
export function noteAdminAlarm(name: AdminCounterName, n = 1): void {
  if (n <= 0) return;
  carriedAlarms[name] = Math.min(BUMP_MAX, (carriedAlarms[name] ?? 0) + n);
}

/** noteUpdateChannelCheck records the update channel's verification state this tick (G319): a channel that
 * stopped VERIFYING (a signing-key rotation, or tamper) makes the update-alert pass return silently -- no
 * alert, no evidence -- so "we were never told a critical update existed" had nothing behind it at all. */
export function noteUpdateChannelCheck(verified: boolean): void {
  ledger.updates = { ...(ledger.updates ?? {}), checked: true, channelVerified: verified };
  if (!verified) {
    const u = ledger.updates;
    u.verifyFailures = Math.min(COUNT_MAX, (u.verifyFailures ?? 0) + 1);
    noteAdminAlarm("update-channel-verify-failed");
  }
}

/** noteUpdateConfirmClearFailure records a confirm-clear attempt that failed (G319): the applied update shows
 * "verification pending" forever, with only a log line behind it. */
export function noteUpdateConfirmClearFailure(): void {
  ledger.updates = { ...(ledger.updates ?? {}), confirmClearFailures: Math.min(COUNT_MAX, (ledger.updates?.confirmClearFailures ?? 0) + 1) };
}

/** noteCpExportAttempt records that the control-plane export pass RAN at all this tick (G292). */
export function noteCpExportAttempt(): void {
  ledger.cpExport = { ...(ledger.cpExport ?? {}), attempted: true };
}

/** noteCpExportTruncated records that the export loop BROKE OUT on the shared budget (G292), leaving the
 * remaining destinations with NO perDest row -- so the record LOOKED complete while some destinations kept a
 * generations-old recovery artefact. `skipped` is how many destinations never got their turn. */
export function noteCpExportTruncated(skipped: number): void {
  ledger.cpExport = { ...(ledger.cpExport ?? {}), attempted: true, truncated: true };
  const c = ledger.cpExport;
  if (skipped > 0) c.destsSkippedByBudget = Math.min(COUNT_MAX, (c.destsSkippedByBudget ?? 0) + skipped);
}

/** noteCpExportDestFail records WHY one destination refused the recovery artefact (G292): perDest carried
 * ok:false with no cause, so a WORM refusal, a rotated wrap key and a network blip were one signal. */
export function noteCpExportDestFail(e: unknown): void {
  ledger.cpExport = { ...(ledger.cpExport ?? {}), attempted: true };
  const c = ledger.cpExport;
  c.perDestFail ??= {};
  const m = c.perDestFail;
  const cls = classifyCpExportFail(e);
  m[cls] = Math.min(COUNT_MAX, (m[cls] ?? 0) + 1);
  noteAdminAlarm("cp-export-dest-failed");
}

/** noteCpPlaintextPurgePending records plaintext control-plane exports that could NOT be purged from a
 * sealed-posture bucket (G292): the readable roster/topology stays in the destination, and the debt was
 * recorded NOWHERE. `pending` is how many generations are still readable. */
export function noteCpPlaintextPurgePending(pending: number): void {
  if (pending <= 0) return;
  ledger.cpExport = { ...(ledger.cpExport ?? {}), attempted: true };
  const c = ledger.cpExport;
  c.plaintextPurgePending = Math.min(COUNT_MAX, (c.plaintextPurgePending ?? 0) + pending);
  noteAdminAlarm("cp-export-plaintext-purge-pending");
}

/** noteCpExportRecordWriteFailure records that the export-health record write ITSELF was lost (G292): the
 * pack then reads a STALE export-health as if it were this tick's verdict. */
export function noteCpExportRecordWriteFailure(): void {
  ledger.cpExport = { ...(ledger.cpExport ?? {}), attempted: true };
  const c = ledger.cpExport;
  c.recordWriteFailures = Math.min(COUNT_MAX, (c.recordWriteFailures ?? 0) + 1);
  noteAdminAlarm("cp-export-record-write-failed");
}

/** noteCpExportPassThrew records that the export pass threw and BYPASSED recordExportHealth entirely (G292),
 * so the last-written record was a previous, healthier tick's. */
export function noteCpExportPassThrew(): void {
  ledger.cpExport = { ...(ledger.cpExport ?? {}), attempted: true, passThrew: true };
}

/** notePushTrailWriteFailure records a push delivery-trail write that was DROPPED (G293). On a SUCCESSFUL
 * delivery this strands the cursor, so the next tick re-sends the same batch: the "our SIEM is getting
 * duplicate events" ticket, previously with nothing behind it. */
export function notePushTrailWriteFailure(which: "siem" | "otlp"): void {
  ledger.push ??= {};
  const p = ledger.push;
  if (which === "siem") p.siemTrailWriteFailures = Math.min(COUNT_MAX, (p.siemTrailWriteFailures ?? 0) + 1);
  else p.otlpTrailWriteFailures = Math.min(COUNT_MAX, (p.otlpTrailWriteFailures ?? 0) + 1);
  noteAdminAlarm("push-trail-write-failed");
}

/** noteRestoreTestSkip records that ONE downpipe's scheduled restore test did NOT run, with the closed class
 * (G295). The downpipe id is the customer's OWN label (the class the pack already carries in downpipes[]);
 * the map is capped at the chokepoint. */
export function noteRestoreTestSkip(downpipeId: string, cls: RestoreTestSkipClass): void {
  ledger.restoreTest ??= {};
  const rt = ledger.restoreTest;
  rt.skips ??= [];
  const rows = rt.skips;
  if (rows.length >= RESTORE_TEST_SKIP_MAX) return;
  rows.push({ id: downpipeId, cls });
  noteAdminAlarm("restore-test-not-run");
}

/** noteRestoreTestPassDeferred records that the WHOLE restore-test pass yielded on the shared budget (G295).
 * A single deferral is routine; a run of them is why "restore tests are overdue fleet-wide". */
export function noteRestoreTestPassDeferred(): void {
  ledger.restoreTest ??= {};
  const rt = ledger.restoreTest;
  rt.passBudgetDeferred = Math.min(COUNT_MAX, (rt.passBudgetDeferred ?? 0) + 1);
}

/** noteFleetDrillBatch records the on-demand fleet-drill campaign's batch health (G295): a stuck campaign
 * used to move no counter at all. */
export function noteFleetDrillBatch(failed: boolean): void {
  ledger.restoreTest ??= {};
  const rt = ledger.restoreTest;
  rt.fleetBatchAttempted = true;
  if (failed) rt.fleetBatchFailures = Math.min(COUNT_MAX, (rt.fleetBatchFailures ?? 0) + 1);
}

/** noteReconcileEnabled echoes the ORPHAN_RECONCILE flag (G333). The pass is opt-in, so an EMPTY reconcile
 * section is ambiguous today: "the operator never turned it on" and "it is on and has been failing for weeks"
 * look identical. This is the boolean that separates them. */
export function noteReconcileEnabled(enabled: boolean): void {
  // `attempted` (which stamps lastPassAt DO-side) is set ONLY when the pass actually runs: a DISABLED pass
  // must never look like one that ran and found nothing, which is the very confusion this echo exists to end.
  ledger.reconcile = { ...(ledger.reconcile ?? {}), enabled, ...(enabled ? { attempted: true } : {}) };
}

/** noteReconcileSkip records WHY the reconcile pass (or one destination's inventory) recorded no signal
 * (G333), so a MONTHS-OLD signal is attributable rather than indistinguishable from a fresh one. */
export function noteReconcileSkip(reason: ReconcileSkipReason): void {
  ledger.reconcile = { ...(ledger.reconcile ?? {}), attempted: true };
  const r = ledger.reconcile;
  r.skips ??= {};
  const m = r.skips;
  m[reason] = Math.min(COUNT_MAX, (m[reason] ?? 0) + 1);
  if (reason === "persist-failed") r.persistFailures = Math.min(COUNT_MAX, (r.persistFailures ?? 0) + 1);
  noteAdminAlarm("reconcile-pass-skipped");
}

/** noteRunlogSigVerdict SPLITS the merged RUNLOG-signature abstain (G333): a DELETED .sig object (an operator
 * or a lifecycle rule removed it -- re-sign it) and a signature that FAILED cryptographic verification (a
 * signer rotation, or tamper -- do NOT proceed) both collapsed into one runlogSigVerified:false, and they
 * need opposite responses.
 *
 * @param sigPresent - whether the detached .sig object existed at all.
 */
export function noteRunlogSigVerdict(sigPresent: boolean): void {
  ledger.reconcile = { ...(ledger.reconcile ?? {}), attempted: true };
  const r = ledger.reconcile;
  if (sigPresent) r.runlogVerifyFailed = Math.min(COUNT_MAX, (r.runlogVerifyFailed ?? 0) + 1);
  else r.runlogSigAbsent = Math.min(COUNT_MAX, (r.runlogSigAbsent ?? 0) + 1);
}

/** noteReconcileCircuitBreaker records that the inventory's circuit breaker TRIPPED (G333). */
export function noteReconcileCircuitBreaker(): void {
  ledger.reconcile = { ...(ledger.reconcile ?? {}), attempted: true, circuitBreakerTripped: true };
}

/** drainCronFaultLedger returns the accumulated snapshot (folding in the carried tick-record failures, notify
 * notes and admin alarms) and clears the per-invocation half. The CARRIED half is cleared only by a report
 * that LANDED (recordCronHealth), so a note raised outside a cron invocation survives to the next tick. */
export function drainCronFaultLedger(): CronHealthDelta {
  const out: CronHealthDelta = {
    ...ledger,
    ...(pendingTickRecordFailures > 0 ? { tickRecordFailures: pendingTickRecordFailures } : {}),
    ...(Object.keys(carriedNotify).length > 0 ? { notify: carriedNotify } : {}),
    ...(Object.keys(carriedAlarms).length > 0 ? { alarms: carriedAlarms } : {}),
  };
  ledger = {};
  return out;
}

/** clearCarriedCronNotes clears the carried notify + alarm notes. Called ONLY after a report landed (and by
 * the validator between cases, so one case cannot leak a note into the next). */
export function clearCarriedCronNotes(): void {
  carriedNotify = {};
  carriedAlarms = {};
}

/** carriedCronNotes is test-only observability on the carried half. */
export function carriedCronNotes(): { notify: CronHealthDelta["notify"]; alarms: CronHealthDelta["alarms"] } {
  return { notify: { ...carriedNotify }, alarms: { ...carriedAlarms } };
}

/** isEmptyCronLedger reports whether a drained snapshot carries nothing worth a subrequest. */
export function isEmptyCronLedger(d: CronHealthDelta): boolean {
  return Object.keys(d).length === 0;
}

/** pendingTickRecordFailureCount is test-only observability on the carried tally. */
export function pendingTickRecordFailureCount(): number {
  return pendingTickRecordFailures;
}

/** clearPendingTickRecordFailures resets the carried tally. Test-only (and after a SUCCESSFUL report). */
export function clearPendingTickRecordFailures(): void {
  pendingTickRecordFailures = 0;
}

/**
 * assertSiemBatchCapSound is the STANDING GUARD on the latent data-loss path in G084: the SIEM shapers slice
 * every batch to SIEM_PUSH_BATCH_CAP, but the drain that FEEDS them has its own limit, and the push cursor
 * advances to the drained head. If the drain limit ever exceeds the shaping cap, the batch TAIL is dropped
 * while the cursor advances PAST it and the delivery trail claims a full, successful delivery -- silent,
 * permanent audit-log loss. The two constants must be equal, and this throws at module wiring time (and in
 * the validator) if a future edit parts them.
 *
 * @param drainLimit - the number of events the push pass drains from the audit feed.
 * @param shapeCap - SIEM_PUSH_BATCH_CAP, the number the shapers will actually emit.
 */
export function assertSiemBatchCapSound(drainLimit: number, shapeCap: number): void {
  if (drainLimit > shapeCap) {
    throw new Error(`SIEM drain limit ${drainLimit} exceeds the shaping cap ${shapeCap}: the batch tail would be dropped while the cursor advanced past it`);
  }
}

// ---- the DO-side record + its redaction chokepoint -------------------------------------------------------

/** One pass's durable health (G132). Counts + closed class + timestamps; never a message. */
export interface CronPassHealth {
  readonly consecutiveFailures: number;
  readonly failCount: number;
  readonly lastErrorAt?: string;
  readonly lastOkAt?: string;
  readonly lastErrorClass?: CronPassErrorClass;
}

/** The bounded cron-health record. Every field a closed enum, a count, a clamped int or a boolean. */
export interface CronHealth {
  readonly passes: Record<string, CronPassHealth>;
  readonly tick: {
    readonly lastAt?: string;
    readonly intervalMs?: number;
    readonly gapDetected: boolean;
    readonly missedApprox: number;
    readonly recordFailures: number;
    readonly recordFailuresLastAt?: string;
  };
  readonly discovery: { readonly skips: Record<string, number>; readonly consecutiveSkips: number; readonly lastAttemptAt?: string };
  readonly beacon: {
    readonly envPresent: { readonly url: boolean; readonly ingestKey: boolean; readonly accountId: boolean };
    readonly lastFailClass?: BeaconFailClass;
    readonly failCounts: Record<string, number>;
    readonly stateWriteFailures: number;
    readonly stateWriteFailuresLastAt?: string;
  };
  readonly autoHeal: {
    readonly lastAttemptAt?: string;
    readonly lastDeferral?: AutoHealDeferralClass;
    readonly deferrals: Record<string, number>;
    readonly resumeApplyLastReasonCode?: ResumeApplyReasonCode;
    readonly amnesiaProbeWriteFailures: number;
  };
  readonly siem: Record<string, { readonly count: number; readonly lastAt: string }>;
  readonly danglingDestinationRefs: number;
  // ---- round 5 (all bounded: closed enums, counts, booleans, clamped labels) ------------------------------
  /** G184 + G294: the alerts CONSUMED and never delivered (by closed event), the one-shot claims spent on
   * them, the history rows never written, the digests discarded to a dead channel, the emissions lost whole. */
  readonly notify: {
    readonly undeliveredCritical: Record<string, { readonly count: number; readonly lastAt: string }>;
    readonly claimSpent: number;
    readonly historyAppendFailures: number;
    readonly historyAppendFailuresLastAt?: string;
    readonly digestNoTransport: number;
    readonly droppedEmissions: Record<string, number>;
  };
  /** G319: the update channel's verification state, and the confirm-clear that keeps failing. */
  readonly updates: {
    readonly lastCheckAt?: string;
    readonly channelVerified?: boolean;
    readonly verifyFailures: number;
    readonly confirmClearFailures: number;
    readonly confirmClearFailuresLastAt?: string;
  };
  /** G292: the control-plane export's truncation, per-destination fail classes, plaintext debt and lost writes. */
  readonly cpExport: {
    readonly lastAttemptAt?: string;
    readonly truncated: boolean;
    readonly destsSkippedByBudget: number;
    readonly perDestFail: Record<string, number>;
    readonly plaintextPurgePending: number;
    readonly recordWriteFailures: number;
    readonly passThrewCount: number;
  };
  /** G293: the push delivery-trail writes that were themselves dropped (a stranded cursor => duplicates). */
  readonly push: { readonly siemTrailWriteFailures: number; readonly otlpTrailWriteFailures: number; readonly lastAt?: string };
  /** G295: per-downpipe restore-test NON-EXECUTION, the pass's budget deferrals, the fleet campaign's health. */
  readonly restoreTest: {
    readonly skips: Record<string, { readonly cls: RestoreTestSkipClass; readonly count: number; readonly lastAt: string }>;
    readonly passBudgetDeferred: number;
    readonly fleetLastBatchAt?: string;
    readonly fleetBatchFailures: number;
  };
  /** G333: the reconcile flag echo, the closed skip reasons, and the SPLIT RUNLOG-signature verdict. */
  readonly reconcile: {
    readonly enabled?: boolean;
    readonly lastPassAt?: string;
    readonly lastSkipReason?: ReconcileSkipReason;
    readonly skips: Record<string, number>;
    readonly runlogSigAbsent: number;
    readonly runlogVerifyFailed: number;
    readonly persistFailures: number;
    readonly circuitBreakerTripped: boolean;
  };
}

// The per-downpipe restore-test skip map is bounded: a 1,000-downpipe fleet cannot make this record (or the
// pack section) unbounded. Only a downpipe whose test did NOT run holds a row, so 64 is far above any real
// failing subset.
export const RESTORE_TEST_SKIP_MAX = 64;
// The downpipe id is the customer's OWN label (the class the pack already carries in downpipes[] and
// sealFaults). Control-stripped and clamped at the chokepoint so it can never become a free-text seam.
const LABEL_MAX = 128;

/**
 * safeLabel strips C0/C1 control characters from a customer-owned label and clamps it, so an id can never
 * inject a line break (or a terminal escape) into an operator's view of the record. Character-code filter
 * rather than a regex, matching the codebase's idiom (admin/diag-records.ts stripControls).
 *
 * @param s - the raw label (untrusted).
 * @returns the safe label, or null when it is not a usable string.
 */
function safeLabel(s: unknown): string | null {
  if (typeof s !== "string" || s === "") return null;
  let out = "";
  for (let i = 0; i < s.length && out.length < LABEL_MAX; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) continue;
    out += s[i];
  }
  return out === "" ? null : out;
}

/** The empty record: the healthy steady state (and the shape a first read returns). */
export function emptyCronHealth(): CronHealth {
  return {
    passes: {},
    tick: { gapDetected: false, missedApprox: 0, recordFailures: 0 },
    discovery: { skips: {}, consecutiveSkips: 0 },
    beacon: { envPresent: { url: false, ingestKey: false, accountId: false }, failCounts: {}, stateWriteFailures: 0 },
    autoHeal: { deferrals: {}, amnesiaProbeWriteFailures: 0 },
    siem: {},
    danglingDestinationRefs: 0,
    notify: { undeliveredCritical: {}, claimSpent: 0, historyAppendFailures: 0, digestNoTransport: 0, droppedEmissions: {} },
    updates: { verifyFailures: 0, confirmClearFailures: 0 },
    cpExport: { truncated: false, destsSkippedByBudget: 0, perDestFail: {}, plaintextPurgePending: 0, recordWriteFailures: 0, passThrewCount: 0 },
    push: { siemTrailWriteFailures: 0, otlpTrailWriteFailures: 0 },
    restoreTest: { skips: {}, passBudgetDeferred: 0, fleetBatchFailures: 0 },
    reconcile: { skips: {}, runlogSigAbsent: 0, runlogVerifyFailed: 0, persistFailures: 0, circuitBreakerTripped: false },
  };
}

const clamp = (v: unknown, max = COUNT_MAX): number => (typeof v === "number" && Number.isFinite(v) && v > 0 ? Math.min(max, Math.floor(v)) : 0);
const bump = (v: unknown): number => clamp(v, BUMP_MAX);
// stripControls removes C0/C1 control characters from the destination id, so an operator's own label can
// never inject a line break (or a terminal escape) into a support view of the record. Character-code
// filter rather than a control-character regex, matching the codebase's idiom (admin/diag-records.ts).

/**
 * applyCronHealth folds ONE cron invocation's drained delta into the bounded record. It is PURE and it is
 * THE REDACTION CHOKEPOINT for this aggregate: an out-of-vocabulary pass name, error class, skip reason,
 * beacon class, deferral class, resume code, SIEM fallback kind or dest-probe class is DROPPED (never
 * persisted); every count is clamped to a bounded non-negative integer; the ONLY string that survives is a
 * destination id, which is control-stripped and clamped to 128; and NOTHING else on the posted body is read.
 * So a raw error message, a stack, a token, a beacon URL, an endpoint, a bucket, an object key, an audit
 * event body or a DO free-text reason structurally cannot enter this record, even from a drifted or hostile
 * caller that posts one.
 *
 * @param prior - the stored record, if any.
 * @param delta - the posted delta (UNTRUSTED).
 * @param now - the DO clock in epoch ms (injected, so the validator is deterministic).
 * @param cronIntervalMs - the expected tick interval, used to derive the tick gap (G205).
 * @returns the new record.
 */
export function applyCronHealth(prior: CronHealth | undefined, delta: unknown, now: number, cronIntervalMs: number): CronHealth {
  const base = prior ?? emptyCronHealth();
  if (typeof delta !== "object" || delta === null || Array.isArray(delta)) return base;
  const d = delta as Record<string, unknown>;
  const nowIso = new Date(now).toISOString();

  // ---- passes (G132) --------------------------------------------------------------------------------
  const passes: Record<string, CronPassHealth> = { ...base.passes };
  const dp = typeof d.passes === "object" && d.passes !== null ? (d.passes as Record<string, unknown>) : {};
  for (const [name, raw] of Object.entries(dp)) {
    if (!CRON_PASS_NAME_SET.has(name)) continue; // out of vocabulary: DROP
    if (typeof raw !== "object" || raw === null) continue;
    const r = raw as Record<string, unknown>;
    const prev = passes[name] ?? { consecutiveFailures: 0, failCount: 0 };
    if (r.ok === true) {
      passes[name] = { ...prev, consecutiveFailures: 0, lastOkAt: nowIso };
      continue;
    }
    const cls = typeof r.cls === "string" && CRON_PASS_ERROR_CLASS_SET.has(r.cls) ? (r.cls as CronPassErrorClass) : "other";
    passes[name] = {
      consecutiveFailures: Math.min(COUNT_MAX, prev.consecutiveFailures + 1),
      failCount: Math.min(COUNT_MAX, prev.failCount + 1),
      lastErrorAt: nowIso,
      lastErrorClass: cls,
      ...(prev.lastOkAt !== undefined ? { lastOkAt: prev.lastOkAt } : {}),
    };
  }

  // ---- the tick ring's HOLES (G205) -----------------------------------------------------------------
  // The gap is derived from the DO's OWN clock against the previous recorded tick, never from a number the
  // Worker sends: a wedged or hostile edge clock cannot fabricate (or conceal) a gap.
  const priorAt = base.tick.lastAt !== undefined ? Date.parse(base.tick.lastAt) : Number.NaN;
  const intervalMs = Number.isFinite(priorAt) ? Math.max(0, now - priorAt) : undefined;
  const missed = intervalMs !== undefined && cronIntervalMs > 0 ? Math.max(0, Math.round(intervalMs / cronIntervalMs) - 1) : 0;
  const recordFails = bump(d.tickRecordFailures);
  const tick = {
    lastAt: nowIso,
    ...(intervalMs !== undefined ? { intervalMs } : {}),
    gapDetected: missed > 0,
    missedApprox: Math.min(MISSED_TICKS_MAX, missed),
    recordFailures: Math.min(COUNT_MAX, base.tick.recordFailures + recordFails),
    ...(recordFails > 0 ? { recordFailuresLastAt: nowIso } : base.tick.recordFailuresLastAt !== undefined ? { recordFailuresLastAt: base.tick.recordFailuresLastAt } : {}),
  };

  // ---- discovery skips (G234) -----------------------------------------------------------------------
  const skips: Record<string, number> = { ...base.discovery.skips };
  const ds = typeof d.discoverySkips === "object" && d.discoverySkips !== null ? (d.discoverySkips as Record<string, unknown>) : {};
  let skippedThisTick = false;
  let attemptedThisTick = false;
  for (const [reason, raw] of Object.entries(ds)) {
    if (!DISCOVERY_SKIP_REASON_SET.has(reason)) continue; // out of vocabulary: DROP
    const n = bump(raw);
    if (n === 0) continue;
    skips[reason] = Math.min(COUNT_MAX, (skips[reason] ?? 0) + n);
    attemptedThisTick = true;
    // "none-due" is the healthy quiet state, NOT a blocked refresh: it must not accumulate a consecutive run.
    if (reason !== "none-due") skippedThisTick = true;
  }
  const discovery = {
    skips,
    consecutiveSkips: skippedThisTick ? Math.min(COUNT_MAX, base.discovery.consecutiveSkips + 1) : attemptedThisTick ? 0 : base.discovery.consecutiveSkips,
    ...(attemptedThisTick ? { lastAttemptAt: nowIso } : base.discovery.lastAttemptAt !== undefined ? { lastAttemptAt: base.discovery.lastAttemptAt } : {}),
  };

  // ---- beacon (G278) --------------------------------------------------------------------------------
  let beacon = base.beacon;
  const db = typeof d.beacon === "object" && d.beacon !== null ? (d.beacon as Record<string, unknown>) : null;
  if (db !== null) {
    const ep = typeof db.envPresent === "object" && db.envPresent !== null ? (db.envPresent as Record<string, unknown>) : {};
    const failCounts: Record<string, number> = { ...base.beacon.failCounts };
    const cls = typeof db.failClass === "string" && BEACON_FAIL_CLASS_SET.has(db.failClass) ? (db.failClass as BeaconFailClass) : undefined;
    if (cls !== undefined) failCounts[cls] = Math.min(COUNT_MAX, (failCounts[cls] ?? 0) + 1);
    const swf = bump(db.stateWriteFailures);
    beacon = {
      envPresent: { url: ep.url === true, ingestKey: ep.ingestKey === true, accountId: ep.accountId === true },
      ...(cls !== undefined ? { lastFailClass: cls } : base.beacon.lastFailClass !== undefined ? { lastFailClass: base.beacon.lastFailClass } : {}),
      failCounts,
      stateWriteFailures: Math.min(COUNT_MAX, base.beacon.stateWriteFailures + swf),
      ...(swf > 0 ? { stateWriteFailuresLastAt: nowIso } : base.beacon.stateWriteFailuresLastAt !== undefined ? { stateWriteFailuresLastAt: base.beacon.stateWriteFailuresLastAt } : {}),
    };
  }

  // ---- auto-heal stalls (G220) ----------------------------------------------------------------------
  let autoHeal = base.autoHeal;
  const da = typeof d.autoHeal === "object" && d.autoHeal !== null ? (d.autoHeal as Record<string, unknown>) : null;
  if (da !== null) {
    const deferrals: Record<string, number> = { ...base.autoHeal.deferrals };
    const def = typeof da.deferral === "string" && AUTOHEAL_DEFERRAL_CLASS_SET.has(da.deferral) ? (da.deferral as AutoHealDeferralClass) : undefined;
    if (def !== undefined) deferrals[def] = Math.min(COUNT_MAX, (deferrals[def] ?? 0) + 1);
    const rc = typeof da.resumeApplyReason === "string" && RESUME_APPLY_REASON_CODE_SET.has(da.resumeApplyReason) ? (da.resumeApplyReason as ResumeApplyReasonCode) : undefined;
    autoHeal = {
      ...(da.attempted === true ? { lastAttemptAt: nowIso } : base.autoHeal.lastAttemptAt !== undefined ? { lastAttemptAt: base.autoHeal.lastAttemptAt } : {}),
      ...(def !== undefined ? { lastDeferral: def } : base.autoHeal.lastDeferral !== undefined ? { lastDeferral: base.autoHeal.lastDeferral } : {}),
      deferrals,
      ...(rc !== undefined ? { resumeApplyLastReasonCode: rc } : base.autoHeal.resumeApplyLastReasonCode !== undefined ? { resumeApplyLastReasonCode: base.autoHeal.resumeApplyLastReasonCode } : {}),
      amnesiaProbeWriteFailures: Math.min(COUNT_MAX, base.autoHeal.amnesiaProbeWriteFailures + (def === "probe-transport" ? 1 : 0)),
    };
  }

  // ---- SIEM shaping fallbacks (G084) ----------------------------------------------------------------
  const siem: Record<string, { count: number; lastAt: string }> = { ...base.siem };
  const dsi = typeof d.siem === "object" && d.siem !== null ? (d.siem as Record<string, unknown>) : {};
  for (const [kind, raw] of Object.entries(dsi)) {
    if (!SIEM_SHAPING_FALLBACK_SET.has(kind)) continue; // out of vocabulary: DROP
    const n = bump(raw);
    if (n === 0) continue;
    siem[kind] = { count: Math.min(COUNT_MAX, (siem[kind]?.count ?? 0) + n), lastAt: nowIso };
  }

  // ---- round 5 ---------------------------------------------------------------------------------------
  // Every sub-record below re-gates DO-side: an out-of-vocabulary event name, export fail class, restore-test
  // skip class or reconcile skip reason is DROPPED, every count is clamped, the ONLY string that survives is a
  // downpipe id (control-stripped and clamped), and nothing else on the posted body is read. So a raw message,
  // a channel id, a webhook url, an endpoint, a bucket, a RUNLOG path or a DO free-text reason structurally
  // cannot enter this record, even from a drifted or hostile caller that posts one.
  const baseNotify = base.notify ?? emptyCronHealth().notify;
  let notify = baseNotify;
  const dn = obj(d.notify);
  if (dn !== null) {
    const undelivered: Record<string, { count: number; lastAt: string }> = { ...baseNotify.undeliveredCritical };
    for (const [event, raw] of Object.entries(obj(dn.undeliveredCritical) ?? {})) {
      if (!NOTIFY_EVENT_NAME_SET.has(event)) continue; // out of vocabulary: DROP
      const n = bump(raw);
      if (n === 0) continue;
      undelivered[event] = { count: Math.min(COUNT_MAX, (undelivered[event]?.count ?? 0) + n), lastAt: nowIso };
    }
    const dropped: Record<string, number> = { ...baseNotify.droppedEmissions };
    for (const [event, raw] of Object.entries(obj(dn.droppedEmissions) ?? {})) {
      if (!NOTIFY_EVENT_NAME_SET.has(event)) continue; // out of vocabulary: DROP
      const n = bump(raw);
      if (n === 0) continue;
      dropped[event] = Math.min(COUNT_MAX, (dropped[event] ?? 0) + n);
    }
    const haf = bump(dn.historyAppendFailures);
    notify = {
      undeliveredCritical: undelivered,
      claimSpent: Math.min(COUNT_MAX, baseNotify.claimSpent + bump(dn.claimSpent)),
      historyAppendFailures: Math.min(COUNT_MAX, baseNotify.historyAppendFailures + haf),
      ...(haf > 0 ? { historyAppendFailuresLastAt: nowIso } : baseNotify.historyAppendFailuresLastAt !== undefined ? { historyAppendFailuresLastAt: baseNotify.historyAppendFailuresLastAt } : {}),
      digestNoTransport: Math.min(COUNT_MAX, baseNotify.digestNoTransport + bump(dn.digestNoTransport)),
      droppedEmissions: dropped,
    };
  }

  const baseUpdates = base.updates ?? emptyCronHealth().updates;
  let updates = baseUpdates;
  const du = obj(d.updates);
  if (du !== null) {
    const ccf = bump(du.confirmClearFailures);
    updates = {
      ...(du.checked === true ? { lastCheckAt: nowIso } : baseUpdates.lastCheckAt !== undefined ? { lastCheckAt: baseUpdates.lastCheckAt } : {}),
      ...(typeof du.channelVerified === "boolean" ? { channelVerified: du.channelVerified } : baseUpdates.channelVerified !== undefined ? { channelVerified: baseUpdates.channelVerified } : {}),
      verifyFailures: Math.min(COUNT_MAX, baseUpdates.verifyFailures + bump(du.verifyFailures)),
      confirmClearFailures: Math.min(COUNT_MAX, baseUpdates.confirmClearFailures + ccf),
      ...(ccf > 0 ? { confirmClearFailuresLastAt: nowIso } : baseUpdates.confirmClearFailuresLastAt !== undefined ? { confirmClearFailuresLastAt: baseUpdates.confirmClearFailuresLastAt } : {}),
    };
  }

  const baseCp = base.cpExport ?? emptyCronHealth().cpExport;
  let cpExport = baseCp;
  const dc = obj(d.cpExport);
  if (dc !== null) {
    const perDestFail: Record<string, number> = { ...baseCp.perDestFail };
    for (const [cls, raw] of Object.entries(obj(dc.perDestFail) ?? {})) {
      if (!CP_EXPORT_FAIL_CLASS_SET.has(cls)) continue; // out of vocabulary: DROP
      const n = bump(raw);
      if (n === 0) continue;
      perDestFail[cls] = Math.min(COUNT_MAX, (perDestFail[cls] ?? 0) + n);
    }
    cpExport = {
      ...(dc.attempted === true ? { lastAttemptAt: nowIso } : baseCp.lastAttemptAt !== undefined ? { lastAttemptAt: baseCp.lastAttemptAt } : {}),
      truncated: dc.truncated === true,
      destsSkippedByBudget: Math.min(COUNT_MAX, baseCp.destsSkippedByBudget + bump(dc.destsSkippedByBudget)),
      perDestFail,
      // The plaintext-purge debt is a STANDING level, not a running total: the last tick's observation is the
      // truth (a purge that succeeds next tick must take it back to zero, not leave a growing sum).
      plaintextPurgePending: Math.min(COUNT_MAX, bump(dc.plaintextPurgePending)),
      recordWriteFailures: Math.min(COUNT_MAX, baseCp.recordWriteFailures + bump(dc.recordWriteFailures)),
      passThrewCount: Math.min(COUNT_MAX, baseCp.passThrewCount + (dc.passThrew === true ? 1 : 0)),
    };
  }

  const basePush = base.push ?? emptyCronHealth().push;
  let push = basePush;
  const dpu = obj(d.push);
  if (dpu !== null) {
    const s = bump(dpu.siemTrailWriteFailures);
    const o = bump(dpu.otlpTrailWriteFailures);
    push = {
      siemTrailWriteFailures: Math.min(COUNT_MAX, basePush.siemTrailWriteFailures + s),
      otlpTrailWriteFailures: Math.min(COUNT_MAX, basePush.otlpTrailWriteFailures + o),
      ...(s + o > 0 ? { lastAt: nowIso } : basePush.lastAt !== undefined ? { lastAt: basePush.lastAt } : {}),
    };
  }

  const baseRt = base.restoreTest ?? emptyCronHealth().restoreTest;
  let restoreTest = baseRt;
  const dr = obj(d.restoreTest);
  if (dr !== null) {
    const skips: Record<string, { cls: RestoreTestSkipClass; count: number; lastAt: string }> = { ...baseRt.skips };
    for (const raw of (Array.isArray(dr.skips) ? dr.skips : []).slice(0, RESTORE_TEST_SKIP_MAX)) {
      const r = obj(raw);
      if (r === null) continue;
      const id = safeLabel(r.id);
      if (id === null) continue;
      if (typeof r.cls !== "string" || !RESTORE_TEST_SKIP_CLASS_SET.has(r.cls)) continue; // out of vocabulary: DROP
      if (skips[id] === undefined && Object.keys(skips).length >= RESTORE_TEST_SKIP_MAX) continue; // hard-bounded
      skips[id] = { cls: r.cls as RestoreTestSkipClass, count: Math.min(COUNT_MAX, (skips[id]?.count ?? 0) + 1), lastAt: nowIso };
    }
    restoreTest = {
      skips,
      passBudgetDeferred: Math.min(COUNT_MAX, baseRt.passBudgetDeferred + bump(dr.passBudgetDeferred)),
      ...(dr.fleetBatchAttempted === true ? { fleetLastBatchAt: nowIso } : baseRt.fleetLastBatchAt !== undefined ? { fleetLastBatchAt: baseRt.fleetLastBatchAt } : {}),
      fleetBatchFailures: Math.min(COUNT_MAX, baseRt.fleetBatchFailures + bump(dr.fleetBatchFailures)),
    };
  }

  const baseRec = base.reconcile ?? emptyCronHealth().reconcile;
  let reconcile = baseRec;
  const drc = obj(d.reconcile);
  if (drc !== null) {
    const skips: Record<string, number> = { ...baseRec.skips };
    let lastSkip: ReconcileSkipReason | undefined;
    for (const [reason, raw] of Object.entries(obj(drc.skips) ?? {})) {
      if (!RECONCILE_SKIP_REASON_SET.has(reason)) continue; // out of vocabulary: DROP
      const n = bump(raw);
      if (n === 0) continue;
      skips[reason] = Math.min(COUNT_MAX, (skips[reason] ?? 0) + n);
      lastSkip = reason as ReconcileSkipReason;
    }
    reconcile = {
      ...(typeof drc.enabled === "boolean" ? { enabled: drc.enabled } : baseRec.enabled !== undefined ? { enabled: baseRec.enabled } : {}),
      ...(drc.attempted === true ? { lastPassAt: nowIso } : baseRec.lastPassAt !== undefined ? { lastPassAt: baseRec.lastPassAt } : {}),
      ...(lastSkip !== undefined ? { lastSkipReason: lastSkip } : baseRec.lastSkipReason !== undefined ? { lastSkipReason: baseRec.lastSkipReason } : {}),
      skips,
      runlogSigAbsent: Math.min(COUNT_MAX, baseRec.runlogSigAbsent + bump(drc.runlogSigAbsent)),
      runlogVerifyFailed: Math.min(COUNT_MAX, baseRec.runlogVerifyFailed + bump(drc.runlogVerifyFailed)),
      persistFailures: Math.min(COUNT_MAX, baseRec.persistFailures + bump(drc.persistFailures)),
      circuitBreakerTripped: drc.circuitBreakerTripped === true,
    };
  }

  return {
    passes,
    tick,
    discovery,
    beacon,
    autoHeal,
    siem,
    danglingDestinationRefs: Math.min(COUNT_MAX, base.danglingDestinationRefs + bump(d.danglingDestinationRefs)),
    notify,
    updates,
    cpExport,
    push,
    restoreTest,
    reconcile,
  };
}

/** obj narrows an untrusted value to a plain object, or null. The single shape gate the round-5 sub-records use. */
function obj(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

// ---- the CHECKED writer ----------------------------------------------------------------------------------

/**
 * recordCronHealth drains the isolate-local ledger and posts it to the DO's bounded cron-health record, ONCE
 * per cron invocation. It routes through recordDiagWrite, so a post that is itself DROPPED (the DO is
 * exactly what was flapping) is counted in droppedWrites["cron-health"] and re-attempted on the next
 * successful diagnostic write. It NEVER throws: observing a cron fault must never crash the cron.
 *
 * A tick with nothing to say posts NOTHING (the healthy steady state costs no subrequest). Note that a
 * healthy tick DOES have something to say -- the pass "ok" stamps are what make a SILENT pass distinguishable
 * from a passing one -- so in practice this posts once per tick and stays silent only in the degenerate case.
 *
 * @param scheduler - the scheduler DO stub.
 * @param cronIntervalMs - the expected tick interval (the DO derives the tick gap from it).
 */
export async function recordCronHealth(scheduler: DurableObjectStub, cronIntervalMs: number): Promise<void> {
  const delta = drainCronFaultLedger();
  if (isEmptyCronLedger(delta)) return;
  const landed = await recordDiagWrite(scheduler, "cron-health", () =>
    scheduler.fetch(doURL("/diag/cron-health"), {
      method: "POST",
      body: JSON.stringify({ delta, cronIntervalMs }),
      headers: { "content-type": "application/json" },
    }),
  );
  // The carried tick-record-failure tally is cleared ONLY when the report actually landed. A dropped report
  // re-notes it, so the hole is still explained by a later healthy tick rather than being lost by the
  // reporter -- the same restore-on-failure discipline flushDroppedWrites uses.
  if (landed) clearPendingTickRecordFailures();
  else if (delta.tickRecordFailures !== undefined) noteTickRecordFailure();
  // The round-5 ALARMS ride the admin-counter aggregate (its own CHECKED writer, its own bounded record), so
  // the loudest fact of each gap -- a critical page that was never delivered, a restore test that did not run,
  // a push trail write that was lost -- is visible in a pack taken TODAY. A no-op on a healthy tick.
  if (delta.alarms !== undefined) await bumpAdminCounters(scheduler, delta.alarms);
  // The carried notify + alarm notes are cleared only by a report that LANDED. A dropped report leaves them
  // pending, so the next healthy tick re-reports them rather than the reporter losing them.
  if (landed) clearCarriedCronNotes();
}

/**
 * drainCronDestProbeFaults returns the invocation's failed destination-probe rows and clears them. Exported so
 * the run-now (non-cron) dispatch path, which shares cron/seal-dispatch.ts, can post the SAME rows through its
 * own writer instead of losing them.
 *
 * IT RETURNS THE REFUSAL COUNT WITH THE ROWS, deliberately as ONE value rather than two drains: a caller
 * that took the rows and forgot the count would post a record that is silently short, which is the exact
 * defect this declaration exists to close.
 *
 * @returns the [{id, reason}] rows (empty when every probe passed) and the destinations DEST_PROBE_MAX
 *          refused this invocation.
 */
export function drainCronDestProbeFaults(): { rows: Array<{ id: string; reason: DestProbeReason }>; refusedUpstream: number } {
  const rows = destProbeRows;
  const refusedUpstream = destProbeRefused;
  destProbeRows = null;
  destProbeRefused = 0;
  if (rows === null) return { rows: [], refusedUpstream };
  return { rows: [...rows.entries()].map(([id, reason]) => ({ id, reason })), refusedUpstream };
}

/**
 * recordCronDestProbeFaults posts the cron invocation's failed destination-probe rows to the EXISTING bounded
 * diag:destprobefaults record (G133). Only FAILING destinations produce a row, so a healthy fleet posts
 * nothing and costs no subrequest. CHECKED (a dropped post is counted in droppedWrites["dest-probe-faults"])
 * and never throwing.
 *
 * @param scheduler - the scheduler DO stub.
 */
export async function recordCronDestProbeFaults(scheduler: DurableObjectStub): Promise<void> {
  const { rows, refusedUpstream } = drainCronDestProbeFaults();
  // A refusal cannot happen without rows (it takes DEST_PROBE_MAX admitted destinations to reach one), so
  // the empty-rows short circuit still cannot drop a declaration.
  if (rows.length === 0) return;
  await recordDiagWrite(scheduler, "dest-probe-faults", () =>
    scheduler.fetch(doURL("/diag/dest-probe-faults"), {
      method: "POST",
      body: JSON.stringify({ rows, ...(refusedUpstream > 0 ? { refusedUpstream } : {}) }),
      headers: { "content-type": "application/json" },
    }),
  );
}
