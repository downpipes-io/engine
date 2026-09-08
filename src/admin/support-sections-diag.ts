// Support-pack section gatherers: the ENGINE SELF-DIAGNOSTIC domain -- the fault ledgers the
// second round of the gap audit added, which had recorders but no pack projection:
//
//   - the scheduler DO's fault ledger (GET /sched-diag): the opaque errorId ring a customer quotes
//     from a console toast (G013), the DO-side structural ceremony/recovery fault classes the Worker
//     edge cannot see (G014/G039), the Worker<->DO contract faults that used to be coerced in silence
//     (G221), the env-default destination's reachability heartbeat (G120) and the downpipes whose
//     staleness rule can never arm (G076);
//   - the per-downpipe PRE-RUN seal-dispatch fault class (GET /seal-errors, G163);
//   - the Prometheus /metrics scrape surface's own health (GET /metrics-health, G049);
//   - the structural WebAuthn fault classes split by ceremony phase (GET /webauthn-faults, G158);
//   - the recorders' OWN dropped writes (GET /dropped-writes, G100/G331/G104) -- the "how much of this
//     pack is missing?" aggregate, whose vocabulary is the UNION of the admin-side and sched-side kinds
//     (both writers share the one `diag:droppedwrites` record);
//   - the account-global rate-limit DO's fail-open health (RATELIMIT_DO GET /health, G104).
//
// Every projection re-gates its closed vocabulary at the PACK boundary (defence in depth: the recorder
// already sanitises, but a drifted or legacy record must never push free text into the bundle), clamps
// every count/timestamp, and carries at most the customer's own downpipe labels. A fetch/parse fault
// PROPAGATES to section() (the section reads "error", never a clean "empty").

import type { Env } from "../env.d.ts";
import { NOTIFY_EVENT_NAMES } from "../notify.ts";
import {
  // The ROUND-5 sched vocabularies. AUTHZ_GATES is re-derived from the product's own ALL_CAPABILITIES at its
  // source, so the pack's gate cannot drift from the capability model (G139/G141/G187/G249/G188/G297/G325/G334).
  ALERTING_HEALTH_EVENTS,
  APPROVAL_REFUSAL_CLASSES,
  APPROVAL_STAGES,
  AUDIT_CHAINS,
  CHAIN_BREAKS_PER_CHAIN,
  AUTHZ_GATES,
  CANARY_LOSS_KINDS,
  CANARY_UNCOVERED_CAP,
  CAP_TRUNCATION_SURFACES,
  CEREMONY_FAULT_KINDS,
  CLIENT_BULK_FAIL_CLASSES,
  CLIENT_BULK_OPS,
  CLIENT_CRASH_PHASES,
  CLIENT_DIAG_RING_CAP,
  CLIENT_FAULT_KINDS,
  CLIENT_ROUTE_FAMILIES,
  CLIENT_SETTLE_STATES,
  CLIENT_SKEW_KINDS,
  CONFIG_COERCION_SURFACES,
  CONFIG_DROP_CLASSES,
  CONFIG_REJECT_REASONS,
  CONFIG_SURFACES,
  CONTRACT_FAULT_KINDS,
  CONTRACT_ROUTE_CLASSES,
  DEST_FALLBACK_RING_CAP,
  DEST_RESOLVE_FALLBACK_CLASSES,
  DRILL_DROP_KINDS,
  ERROR_REASON_CLASSES,
  ERROR_STAGES,
  EXPIRY_FAULT_CLASSES,
  EXPIRY_ITEM_CLASSES,
  CAP_TRUNCATION_SUBJECT_IDS_CAP,
  FRESHNESS_FAULTS_CAP,
  FRESHNESS_FAULT_CAUSES,
  GOVERNANCE_OUTCOME_CLASSES,
  GOVERNANCE_REFUSAL_REASONS,
  GOVERNANCE_REFUSAL_STAGES,
  GOVERNANCE_STAGES,
  IMPORT_DROP_FIELDS,
  NOTIFY_DROP_KINDS,
  NOTIFY_DROPS_RING_CAP,
  POSTURE_INPUT_FAULTS,
  POSTURE_OVERRIDES_CAP,
  REESTABLISH_DESTS_CAP,
  REFUSAL_RING_CAP,
  REFUSAL_SURFACES,
  REPLICATION_REASONS,
  RESUME_SKIP_CLASSES,
  RESUME_SKIPS_CAP,
  ROSTER_DISCARDS_CAP,
  ADMIN_REFUSAL_REASONS as SCHED_ADMIN_REFUSAL_REASONS,
  ADMIN_REFUSAL_ROUTES as SCHED_ADMIN_REFUSAL_ROUTES,
  DROPPED_WRITE_KINDS as SCHED_DROPPED_WRITE_KINDS,
  STAGED_APPLY_REFUSAL_CLASSES,
  STORAGE_ANOMALY_KINDS,
  TEST_DELETE_PROBES,
  TEST_OBJECT_LOCKS,
  TEST_OUTCOMES_PER_SURFACE,
  TEST_REASON_CLASSES,
  TEST_STATUS_CLASSES,
  TEST_SURFACES,
  VOCAB_DROP_SURFACES,
} from "../sched/sched-fault-ledger.ts";
import { WORM_UNKNOWN_REASONS } from "../dest/types.ts";
import { DELIVERY_FAIL_CODES, sanitiseEmailPlatformCode } from "../notify/types.ts";
import { CHAIN_BREAK_CAUSES } from "./audit-types.ts";
import { CHECK_SEVERITY, POSTURE_OVERRIDE_KINDS } from "./posture.ts";
import { doURL } from "../do-url.ts";

// G313: the closed sets the chain-break latch is re-gated against at the pack boundary (defence in depth).
const AUDIT_CHAIN_SET: ReadonlySet<string> = new Set(AUDIT_CHAINS);
const CHAIN_BREAK_CAUSE_SET: ReadonlySet<string> = new Set(CHAIN_BREAK_CAUSES);

// G246: the closed sets the wiring-check ring is re-gated against at the pack boundary (defence in depth: the
// recorder already gates them DO-side, and a drifted writer must not be able to widen what the pack carries).
const TEST_SURFACE_SET: ReadonlySet<string> = new Set(TEST_SURFACES);
const TEST_REASON_CLASS_SET: ReadonlySet<string> = new Set(TEST_REASON_CLASSES);
const TEST_STATUS_CLASS_SET: ReadonlySet<string> = new Set(TEST_STATUS_CLASSES);
const TEST_DELETE_PROBE_SET: ReadonlySet<string> = new Set(TEST_DELETE_PROBES);
const TEST_OBJECT_LOCK_SET: ReadonlySet<string> = new Set(TEST_OBJECT_LOCKS);
// The store layer's OWN closed reason vocabulary (G279), reused rather than re-declared: "unknown" without it
// names no remedy, and its members ("denied" / "not-implemented") are the two intents G246 exists to separate.
const WORM_UNKNOWN_REASON_SET: ReadonlySet<string> = new Set(WORM_UNKNOWN_REASONS);

import {
  ADMIN_COUNTER_NAMES,
  DROPPED_WRITE_KINDS as ADMIN_DROPPED_WRITE_KINDS,
  METRICS_SCRAPE_OUTCOMES,
  RESTORE_BINDING_NAMES,
  RESTORE_FAULT_CLASSES,
  RESTORE_FAULT_OPS,
  RESTORE_FAULT_PHASES,
  RESTORE_FAULTS_RING_CAP,
  SEAL_ERROR_CLASSES,
  WEBAUTHN_FAULT_CLASSES,
  WEBAUTHN_PHASES,
} from "./diag-records.ts";
import { RUN_FAULT_DOWNPIPES_MAX, sanitiseDestFaults, sanitiseSourceFaults } from "./run-fault-records.ts";
import { clampInt, clampTs } from "./support-shared.ts";

const CEREMONY_FAULT_KIND_SET: ReadonlySet<string> = new Set(CEREMONY_FAULT_KINDS);
const ERROR_STAGE_SET: ReadonlySet<string> = new Set(ERROR_STAGES);
const ERROR_REASON_CLASS_SET: ReadonlySet<string> = new Set(ERROR_REASON_CLASSES);
const REPLICATION_REASON_SET: ReadonlySet<string> = new Set(REPLICATION_REASONS);
const FRESHNESS_FAULT_CAUSE_SET: ReadonlySet<string> = new Set(FRESHNESS_FAULT_CAUSES);
const SEAL_ERROR_CLASS_SET: ReadonlySet<string> = new Set(SEAL_ERROR_CLASSES);
const METRICS_SCRAPE_OUTCOME_SET: ReadonlySet<string> = new Set(METRICS_SCRAPE_OUTCOMES);
const RESTORE_FAULT_OP_SET: ReadonlySet<string> = new Set(RESTORE_FAULT_OPS);
const RESTORE_FAULT_PHASE_SET: ReadonlySet<string> = new Set(RESTORE_FAULT_PHASES);
const RESTORE_FAULT_CLASS_SET: ReadonlySet<string> = new Set(RESTORE_FAULT_CLASSES);
const ADMIN_COUNTER_NAME_SET: ReadonlySet<string> = new Set(ADMIN_COUNTER_NAMES);
const RESTORE_BINDING_NAME_SET: ReadonlySet<string> = new Set(RESTORE_BINDING_NAMES);
// The ROUND-5 closed sets. The two COMPOSITE key spaces (surface|reason, surface|dropClass) are re-derived as
// the full cross product rather than parsed out of the key: a drifted key outside the product is DROPPED, never
// split and half-carried. This is precisely the closed-vocabulary bypass a redaction proof hunts for -- a
// caller-derived string becoming a map KEY -- and re-deriving the product forecloses it.
const CONFIG_REJECT_KEY_SET: ReadonlySet<string> = new Set(CONFIG_SURFACES.flatMap((s) => CONFIG_REJECT_REASONS.map((r) => `${s}|${r}`)));
const CONFIG_COERCION_KEY_SET: ReadonlySet<string> = new Set(CONFIG_COERCION_SURFACES.flatMap((s) => CONFIG_DROP_CLASSES.map((c) => `${s}|${c}`)));
const AUTHZ_GATE_SET: ReadonlySet<string> = new Set(AUTHZ_GATES);
const ALERTING_HEALTH_EVENT_SET: ReadonlySet<string> = new Set(ALERTING_HEALTH_EVENTS);
const CAP_TRUNCATION_SURFACE_SET: ReadonlySet<string> = new Set(CAP_TRUNCATION_SURFACES);
const POSTURE_INPUT_FAULT_SET: ReadonlySet<string> = new Set(POSTURE_INPUT_FAULTS);
const POSTURE_OVERRIDE_KIND_SET: ReadonlySet<string> = new Set(POSTURE_OVERRIDE_KINDS);
// The posture CHECK ids are gated against the product's own severity table (its single source of truth), so a
// check added to the product rides without a vocabulary edit here and an invented id cannot become a pack key.
const POSTURE_CHECK_ID_SET: ReadonlySet<string> = new Set(Object.keys(CHECK_SEVERITY));
const POSTURE_SEVERITY_SET: ReadonlySet<string> = new Set(["critical", "high", "medium", "low"]);
const POSTURE_CHECKS_PROJECT_CAP = 64;
// ERR_ID_SHAPE gates the restore-fault ring's Workers-Logs join key: the engine's own 8-hex FNV exception id.
// Anything else is dropped, so no message can ever ride into the pack through the join-key field.
const ERR_ID_SHAPE = /^[0-9a-f]{8}$/;
// CONFIG_DIGEST_SHAPE gates the roster-discard ring's one-way config digest: engine-computed hex, nothing else.
const CONFIG_DIGEST_SHAPE = /^[0-9a-f]{1,32}$/;

// The round-3 scheduler-DO ledger key spaces. The two COMPOSITE aggregates are keyed "<a>|<b>", so the pack
// re-derives the whole cross product rather than parsing the key: a drifted key outside the product is
// DROPPED, never propagated.
const VOCAB_DROP_SURFACE_SET: ReadonlySet<string> = new Set(VOCAB_DROP_SURFACES);
const STORAGE_ANOMALY_KIND_SET: ReadonlySet<string> = new Set(STORAGE_ANOMALY_KINDS);
const RESUME_SKIP_CLASS_SET: ReadonlySet<string> = new Set(RESUME_SKIP_CLASSES);
const IMPORT_DROP_FIELD_SET: ReadonlySet<string> = new Set(IMPORT_DROP_FIELDS);
const STAGED_APPLY_REFUSAL_SET: ReadonlySet<string> = new Set(STAGED_APPLY_REFUSAL_CLASSES);
const EXPIRY_FAULT_KEY_SET: ReadonlySet<string> = new Set(
  EXPIRY_ITEM_CLASSES.flatMap((item) => EXPIRY_FAULT_CLASSES.map((fault) => `${item}|${fault}`)),
);
const APPROVAL_FAULT_KEY_SET: ReadonlySet<string> = new Set(
  APPROVAL_STAGES.flatMap((stage) => APPROVAL_REFUSAL_CLASSES.map((cls) => `${stage}|${cls}`)),
);

// ---- the round-4 scheduler-DO ledger key spaces ---------------------------------------------------------
// The same discipline as above: a COMPOSITE key is re-derived as the whole cross product of its two closed
// sets, never parsed, so a drifted key outside the product is DROPPED rather than propagated. A caller-derived
// string becoming a map KEY is the classic closed-vocabulary bypass, and re-deriving the product forecloses it.
const DEST_RESOLVE_FALLBACK_SET: ReadonlySet<string> = new Set(DEST_RESOLVE_FALLBACK_CLASSES);
const CANARY_LOSS_KIND_SET: ReadonlySet<string> = new Set(CANARY_LOSS_KINDS);
const DRILL_DROP_KIND_SET: ReadonlySet<string> = new Set(DRILL_DROP_KINDS);
const NOTIFY_DROP_KIND_SET: ReadonlySet<string> = new Set(NOTIFY_DROP_KINDS);
const NOTIFY_EVENT_NAME_SET: ReadonlySet<string> = new Set(NOTIFY_EVENT_NAMES);
const NOTIFY_SEVERITY_SET: ReadonlySet<string> = new Set(["info", "warning", "critical"]);
const REFUSAL_SURFACE_SET: ReadonlySet<string> = new Set(REFUSAL_SURFACES);
const GOVERNANCE_FAULT_KEY_SET: ReadonlySet<string> = new Set(
  GOVERNANCE_STAGES.flatMap((stage) => GOVERNANCE_OUTCOME_CLASSES.map((cls) => `${stage}|${cls}`)),
);
// G182: the REFUSAL key space, built as the full cross-product of the two closed vocabularies taken from the
// module that RECORDS them, so the pack's gate and the recorder cannot drift apart.
const GOVERNANCE_REFUSAL_KEY_SET: ReadonlySet<string> = new Set(
  GOVERNANCE_REFUSAL_STAGES.flatMap((stage) => GOVERNANCE_REFUSAL_REASONS.map((reason) => `${stage}|${reason}`)),
);
const SCHED_ADMIN_REFUSAL_KEY_SET: ReadonlySet<string> = new Set(
  SCHED_ADMIN_REFUSAL_ROUTES.flatMap((route) => SCHED_ADMIN_REFUSAL_REASONS.map((reason) => `${route}|${reason}`)),
);
const CLIENT_CRASH_PHASE_SET: ReadonlySet<string> = new Set(CLIENT_CRASH_PHASES);
const CLIENT_FAULT_KIND_SET: ReadonlySet<string> = new Set(CLIENT_FAULT_KINDS);
const CLIENT_BULK_OP_SET: ReadonlySet<string> = new Set(CLIENT_BULK_OPS);
const CLIENT_BULK_FAIL_SET: ReadonlySet<string> = new Set(CLIENT_BULK_FAIL_CLASSES);
const CLIENT_SETTLE_STATE_SET: ReadonlySet<string> = new Set(CLIENT_SETTLE_STATES);
const CLIENT_SKEW_KEY_SET: ReadonlySet<string> = new Set(
  CLIENT_ROUTE_FAMILIES.flatMap((family) => CLIENT_SKEW_KINDS.map((kind) => `${family}|${kind}`)),
);
// The console's own BUILD id: a product-controlled version string, the same redaction class as engine.version
// (which the pack already carries). Pattern-gated so the skew pair's other half can never become a smuggling
// channel for a message, a screen name or a path.
const CONSOLE_BUILD_ID_SHAPE = /^[0-9A-Za-z._+-]{1,64}$/;

// CONTRACT_FAULT_KEY_SET is the closed key space of the contract-fault aggregate: the DO keys it
// "<routeClass>|<faultKind>", so the pack re-derives the whole cross product rather than parsing the key
// (a drifted key that is not a member of the cross product is DROPPED, never propagated).
const CONTRACT_FAULT_KEY_SET: ReadonlySet<string> = new Set(
  CONTRACT_ROUTE_CLASSES.flatMap((route) => CONTRACT_FAULT_KINDS.map((kind) => `${route}|${kind}`)),
);

// WEBAUTHN_FAULT_KEY_SET is the closed "<phase>:<class>" key space (2 phases x 14 classes), re-derived here
// for the same reason: the phase is the diagnosis (key-import-failed on LOGIN means the STORED COSE key is
// corrupt and the user can never sign in again; on ENROL it means the runtime refused the device).
const WEBAUTHN_FAULT_KEY_SET: ReadonlySet<string> = new Set(
  WEBAUTHN_PHASES.flatMap((phase) => WEBAUTHN_FAULT_CLASSES.map((cls) => `${phase}:${cls}`)),
);

// DROPPED_WRITE_KIND_SET is the UNION of the two disjoint vocabularies that share the one
// `diag:droppedwrites` DO record: the Worker-edge kinds (admin/diag-records.ts) and the scheduler-DO kinds
// (sched/sched-fault-ledger.ts). Gating on either half alone would silently discard the other half's
// evidence at the pack boundary, which is exactly the under-count this aggregate exists to make visible.
export const PACK_DROPPED_WRITE_KINDS: readonly string[] = [...ADMIN_DROPPED_WRITE_KINDS, ...SCHED_DROPPED_WRITE_KINDS];
const DROPPED_WRITE_KIND_SET: ReadonlySet<string> = new Set(PACK_DROPPED_WRITE_KINDS);

// projectCountAgg projects a closed-vocabulary { name -> {count,lastAt} } aggregate: only a member key rides,
// counts are clamped, a zero/absent count drops the row. Shared by the ceremony-fault, contract-fault and
// dropped-write aggregates (identical shape, different vocabularies).
function projectCountAgg(raw: unknown, allowed: ReadonlySet<string>): Record<string, { count: number; lastAt?: string }> {
  const out: Record<string, { count: number; lastAt?: string }> = {};
  if (typeof raw !== "object" || raw === null) return out;
  for (const [name, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!allowed.has(name)) continue; // only the CLOSED vocabulary reaches the pack
    const rec = (typeof v === "object" && v !== null ? v : {}) as { count?: unknown; lastAt?: unknown };
    const count = clampInt(rec.count, 1_000_000_000) ?? 0;
    if (count === 0) continue;
    const lastAt = clampTs(rec.lastAt);
    out[name] = { count, ...(lastAt !== undefined ? { lastAt } : {}) };
  }
  return out;
}

// fetchSchedDiag projects the scheduler DO's whole fault ledger (GET /sched-diag) in ONE read. Redaction-safe
// by construction: closed-enum keys, integer counts, clamped ISO timestamps, the OPAQUE server-minted error id
// (guarded hex/uuid-shaped, so a customer value can never ride even if a drifted writer put one there), and
// the customer's own 128-char-clamped downpipe labels. `droppedWrites` is deliberately NOT projected here: it
// is the SAME `diag:droppedwrites` record fetchDroppedWrites reads, and one aggregate must have one home.
// A fetch/parse fault PROPAGATES to section().
const ERROR_ID_SHAPE = /^[0-9a-fA-F-]{1,64}$/;
export async function fetchSchedDiag(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/sched-diag"), { method: "GET" });
    const j = (await r.json()) as {
      ceremonyFaults?: unknown;
      recentErrors?: unknown;
      contractFaults?: unknown;
      defaultDestination?: unknown;
      freshnessFaults?: unknown;
      vocabDrops?: unknown;
      expiryObserveFaults?: unknown;
      approvalFaults?: unknown;
      storageAnomalies?: unknown;
      rosterDiscards?: unknown;
      chainBreaks?: unknown;
      testOutcomes?: unknown;
      recoveryResume?: unknown;
      destResolveFallbacks?: unknown;
      canaryLosses?: unknown;
      drillDrops?: unknown;
      notifyDrops?: unknown;
      governanceFaults?: unknown;
      governanceRefusals?: unknown;
      refusalRings?: unknown;
      adminRefusals?: unknown;
      clientDiagnostics?: unknown;
      // ---- round 5 (all served by readSchedDiag on the SAME GET /sched-diag read) ----
      configRejections?: unknown;
      authzRefusals?: unknown;
      alertingHealth?: unknown;
      configCoercions?: unknown;
      auditEgress?: unknown;
      capTruncations?: unknown;
      capTruncationSubjects?: unknown;
      posture?: unknown;
    };
    const out: Record<string, unknown> = {};
    // ceremonyFaults (G014/G039): the DO-side STRUCTURAL ceremony + recovery fault classes the Worker edge
    // cannot see (a live passkey challenge EVICTED under a begin flood, an absent rp.id, a corrupt stored COSE
    // key, WHICH recovery limiter denied, a fail-CLOSED limiter refusing a legitimate operator with good codes).
    // Deliberately DISJOINT from the edge-side AUTH_SIGNAL_NAMES the authSignals section already carries.
    const ceremonyFaults = projectCountAgg(j.ceremonyFaults, CEREMONY_FAULT_KIND_SET);
    if (Object.keys(ceremonyFaults).length > 0) out.ceremonyFaults = ceremonyFaults;
    // contractFaults (G221): every Worker<->DO contract fault that used to be coerced in silence -- an
    // out-of-vocabulary auth-signal name, a `?? []` reconcile coercion that CLEARS a real detached-source
    // marker, a run completion discarded as unowned, a console screen 404ing after a mixed deploy. A climb
    // after an engine-version-change event is the version-skew signal.
    const contractFaults = projectCountAgg(j.contractFaults, CONTRACT_FAULT_KEY_SET);
    if (Object.keys(contractFaults).length > 0) out.contractFaults = contractFaults;
    // recentErrors (G013): the OPAQUE errorId the customer quotes from a console toast, with its ceremony/route
    // STAGE, a coarse reason CLASS and a recurrence count. This is what turns "the console said err:ab12cd" into
    // a diagnosis. The id is engine-minted (crypto.randomUUID / a digest prefix); the shape guard drops anything
    // that is not hex/uuid-shaped, so a drifted writer can never push customer text through this seam.
    const recentErrors = (Array.isArray(j.recentErrors) ? j.recentErrors : []).slice(-64).flatMap((e) => {
      const r0 = (typeof e === "object" && e !== null ? e : {}) as { errorId?: unknown; stage?: unknown; reasonClass?: unknown; count?: unknown; at?: unknown };
      if (typeof r0.errorId !== "string" || !ERROR_ID_SHAPE.test(r0.errorId)) return [];
      if (typeof r0.stage !== "string" || !ERROR_STAGE_SET.has(r0.stage)) return [];
      if (typeof r0.reasonClass !== "string" || !ERROR_REASON_CLASS_SET.has(r0.reasonClass)) return [];
      return [{
        errorId: r0.errorId,
        stage: r0.stage,
        reasonClass: r0.reasonClass,
        count: clampInt(r0.count, 1_000_000) ?? 1,
        ...(clampTs(r0.at) !== undefined ? { at: clampTs(r0.at) } : {}),
      }];
    });
    if (recentErrors.length > 0) out.recentErrors = recentErrors;
    // defaultDestination (G120): the ENV-DEFAULT destination's own reachability heartbeat. The common
    // single-destination tenant named no console destination id, so recordReplicationState early-returned and NO
    // down indicator existed anywhere in the pack. `downSince` makes "down for a week" a recorded fact rather
    // than an inference, and `reason` is the same closed class the repl: heartbeats now carry.
    const dd = (typeof j.defaultDestination === "object" && j.defaultDestination !== null ? j.defaultDestination : null) as { ok?: unknown; reason?: unknown; at?: unknown; downSince?: unknown } | null;
    if (dd !== null) {
      out.defaultDestination = {
        ok: dd.ok === true,
        ...(typeof dd.reason === "string" && REPLICATION_REASON_SET.has(dd.reason) ? { reason: dd.reason } : {}),
        ...(clampTs(dd.at) !== undefined ? { at: clampTs(dd.at) } : {}),
        ...(clampTs(dd.downSince) !== undefined ? { downSince: clampTs(dd.downSince) } : {}),
      };
    }
    // freshnessFaults (G076): the downpipes whose staleness rule can NEVER arm (a non-finite cadence, an
    // unparseable run timestamp), so the map and the overview read "Fresh" for weeks while the backups have
    // stopped. Keyed by the customer's own downpipe label; the per-downpipe boolean rides on downpipes[] too.
    const freshnessFaults: Record<string, Record<string, unknown>> = {};
    if (typeof j.freshnessFaults === "object" && j.freshnessFaults !== null) {
      // Sliced at the WRITER'S OWN CAP rather than a literal 50: the two were equal, so this slice could not
      // truncate, and a future raise of FRESHNESS_FAULTS_CAP not mirrored here would have started a SECOND,
      // undeclared cut on the read path. Keyed off the constant, that can no longer happen.
      for (const [id, v] of Object.entries(j.freshnessFaults as Record<string, unknown>).slice(0, FRESHNESS_FAULTS_CAP)) {
        const f = (typeof v === "object" && v !== null ? v : {}) as { cause?: unknown; at?: unknown };
        if (typeof f.cause !== "string" || !FRESHNESS_FAULT_CAUSE_SET.has(f.cause)) continue;
        freshnessFaults[id.slice(0, 128)] = { cause: f.cause, ...(clampTs(f.at) !== undefined ? { at: clampTs(f.at) } : {}) };
      }
    }
    if (Object.keys(freshnessFaults).length > 0) out.freshnessFaults = freshnessFaults;

    // ---- the round-3 scheduler-DO ledgers ---------------------------------------------------------------
    // vocabDrops (G092): the VERSION-SKEW blind spot. Every closed-set gate in the DO used to drop an
    // out-of-vocabulary token in SILENCE, so after a partial deploy (a Worker newer than its DO, or the
    // reverse) a whole class of evidence simply stopped landing and every aggregate downstream read clean.
    // ANY non-zero count here means the pack sections it names are a LOWER BOUND. The cruellest member is
    // deferral-kind: a restore drill that COULD NOT RUN is otherwise rendered as "tested and failed".
    const vocabDrops = projectCountAgg(j.vocabDrops, VOCAB_DROP_SURFACE_SET);
    if (Object.keys(vocabDrops).length > 0) out.vocabDrops = vocabDrops;
    // expiryObserveFaults (G093): a credential-expiry observation that never armed the warning ladder. An
    // EMPTY licenceExpiryTracker / expiryWarnings is now self-explaining -- "we could not observe it" is a
    // different fact from "there is nothing to warn about", and unparseable-date used to be indistinguishable
    // from "this account has no licence expiry at all".
    const expiryObserveFaults = projectCountAgg(j.expiryObserveFaults, EXPIRY_FAULT_KEY_SET);
    if (Object.keys(expiryObserveFaults).length > 0) out.expiryObserveFaults = expiryObserveFaults;
    // approvalFaults (G094): the dual-control restore lifecycle's refusals. Two members are ESCALATIONS, not
    // diagnostics: "approve|self-approval" is a BLOCKED maker-checker violation (the thing a dual-control
    // attestation must prove never happened), and "consume|lease-reclaimed" is the accounting hole -- a
    // single-use approval whose consume MISSED after a successful apply, so single-use is NOT PROVEN for a
    // completed restore.
    const approvalFaults = projectCountAgg(j.approvalFaults, APPROVAL_FAULT_KEY_SET);
    if (Object.keys(approvalFaults).length > 0) out.approvalFaults = approvalFaults;
    // storageAnomalies (G105): every silent self-heal, coercion and safe-default read. The headline member is
    // epoch-corrupt-defaulted: a corrupt IdP epoch coerced to 0 means "revoke nothing", which is the
    // REVOCATION BYPASS behind "we disabled the connection but a session kept working".
    const storageAnomalies = projectCountAgg(j.storageAnomalies, STORAGE_ANOMALY_KIND_SET);
    if (Object.keys(storageAnomalies).length > 0) out.storageAnomalies = storageAnomalies;
    // rosterDiscards (G105): WHAT a roster repair threw away. A delete-ghost over a row that DOES carry an
    // embedded id is a DIVERGENT CLAIMANT whose config (the operator's schedule/retention edits) is discarded
    // with it. The two ids are the customer's own labels; the config itself rides only as a one-way digest.
    const rosterDiscards = (Array.isArray(j.rosterDiscards) ? j.rosterDiscards : []).slice(-ROSTER_DISCARDS_CAP).flatMap((e) => {
      const d = (typeof e === "object" && e !== null ? e : {}) as { key?: unknown; embeddedId?: unknown; configDigest?: unknown; at?: unknown };
      if (typeof d.key !== "string" || typeof d.embeddedId !== "string") return [];
      const digest = typeof d.configDigest === "string" && CONFIG_DIGEST_SHAPE.test(d.configDigest) ? d.configDigest : undefined;
      return [{
        key: d.key.slice(0, 128),
        embeddedId: d.embeddedId.slice(0, 128),
        ...(digest !== undefined ? { configDigest: digest } : {}),
        ...(clampTs(d.at) !== undefined ? { at: clampTs(d.at) } : {}),
      }];
    });
    if (rosterDiscards.length > 0) out.rosterDiscards = rosterDiscards;
    // chainBreaks (G313): the tamper verdict that a retention rollover would otherwise ERASE. The pack
    // RECOMPUTES the audit / config-history verdicts at bundle-build time, so a break whose entries have since
    // rolled off reads INTACT and the customer who saw it last Tuesday sounds unreliable. This latch is the
    // durable memory the recompute cannot have: firstDetectedAt (never overwritten), the seq it broke at, the
    // CLOSED cause class -- which finally separates a LAZY body edit that did not refresh its own unkeyed hash
    // (recompute-mismatch) from a COMPETENT one that did, and is caught by the successor's keyed parentHash
    // (content-swapped) from a body that IS keyed-vouched by its successor and whose attribution was rewritten
    // (envelope-digest-mismatch) from a digest failure with NO keyed witness at all, on the head or behind a
    // broken successor (digest-unvouched) from an inserted or deleted entry (prev-hash-mismatch) from a gap
    // (seq-gap) from a chain that no longer links to genesis (genesis-link) from a version whose BODY is gone
    // (missing-version) from an in-DO signing key that was REGENERATED OR LOST, which makes every keyed digest
    // fail and proves nothing about the bodies (signing-key-rotated -- and R5: that row is latched only when the
    // KEY-FREE pass over the whole chain came back clean; when it did not, its cause is latched BESIDE it at its
    // own seq, because an owner button that deletes the signing key must not be able to mask a tamper) -- and
    // healedAt, which says the break is no longer in the retained chain WITHOUT pretending it never happened.
    //
    // It is a LIST, not one row per chain, and that is the second half of the fix: a later, genuinely
    // different break must not fold into an earlier one and disappear. Each distinct (chain, cause, seq)
    // has its own row, so "detections: 2" always means two occurrences of the SAME tamper signature, never
    // two unrelated tamper events collapsed into one.
    //
    // Closed chain names, closed causes, integer seqs, counts, clamped timestamps. No entry content, no hash,
    // no actor, no target ever rides.
    const chainBreaks = Object.values((typeof j.chainBreaks === "object" && j.chainBreaks !== null ? j.chainBreaks : {}) as Record<string, unknown>)
      .flatMap((v) => {
        const b = (typeof v === "object" && v !== null ? v : {}) as { chain?: unknown; firstDetectedAt?: unknown; lastDetectedAt?: unknown; brokenAtSeq?: unknown; causeClass?: unknown; detections?: unknown; healedAt?: unknown };
        if (typeof b.chain !== "string" || !AUDIT_CHAIN_SET.has(b.chain)) return [];
        if (typeof b.causeClass !== "string" || !CHAIN_BREAK_CAUSE_SET.has(b.causeClass)) return [];
        return [{
          chain: b.chain,
          causeClass: b.causeClass,
          brokenAtSeq: clampInt(b.brokenAtSeq, 10_000_000) ?? 0,
          detections: clampInt(b.detections, 1_000_000) ?? 0,
          ...(clampTs(b.firstDetectedAt) !== undefined ? { firstDetectedAt: clampTs(b.firstDetectedAt) } : {}),
          ...(clampTs(b.lastDetectedAt) !== undefined ? { lastDetectedAt: clampTs(b.lastDetectedAt) } : {}),
          ...(clampTs(b.healedAt) !== undefined ? { healedAt: clampTs(b.healedAt) } : {}),
        }];
      })
      // Oldest first: the order a reader wants to read a tamper timeline in, and deterministic across builds.
      .sort((a, b) => String(a.firstDetectedAt ?? "").localeCompare(String(b.firstDetectedAt ?? "")))
      .slice(0, AUDIT_CHAINS.length * CHAIN_BREAKS_PER_CHAIN);
    if (chainBreaks.length > 0) out.chainBreaks = chainBreaks;
    // testOutcomes (G246): the Test / Verify button's ANSWER, which used to die with the browser tab. Per
    // surface, newest last, so the SEQUENCE reads: "failed, failed, ok" is a configuration the operator fixed;
    // "ok, failed, ok, failed" is a flapping endpoint; and a lone failure yesterday against a pass today is
    // exactly the customer's story, corroborated. A pass carries NO reason (there is nothing to explain); a
    // failure ALWAYS carries one. Closed surface, boolean, closed reason class, closed status class -- never
    // the webhook URL, the recipient, the SIEM endpoint, the bucket, the IdP issuer or the provider's text.
    const testOutcomes: Record<string, Array<Record<string, unknown>>> = {};
    for (const [surface, rows] of Object.entries((typeof j.testOutcomes === "object" && j.testOutcomes !== null ? j.testOutcomes : {}) as Record<string, unknown>)) {
      if (!TEST_SURFACE_SET.has(surface) || !Array.isArray(rows)) continue;
      const ring = rows.slice(-TEST_OUTCOMES_PER_SURFACE).flatMap((raw) => {
        const r = (typeof raw === "object" && raw !== null ? raw : {}) as { ok?: unknown; reasonClass?: unknown; statusClass?: unknown; at?: unknown; deleteProbe?: unknown; deleteStatusClass?: unknown; objectLock?: unknown; objectLockUnknownReason?: unknown; defaultRetention?: unknown; platformCode?: unknown; deliveryCode?: unknown };
        const ok = r.ok === true;
        const reasonClass = typeof r.reasonClass === "string" && TEST_REASON_CLASS_SET.has(r.reasonClass) ? r.reasonClass : undefined;
        const statusClass = typeof r.statusClass === "string" && TEST_STATUS_CLASS_SET.has(r.statusClass) ? r.statusClass : undefined;
        // G246: the destination-verify discriminator. Without these the pack CANNOT tell a healthy destination
        // from one that accepts every backup and can never expire one -- both were {ok:true} -- and it could not
        // tell a short IAM allow-list (objectLockUnknownReason "denied": the key may read neither the lock config
        // nor delete) from a store with no Object-Lock API at all ("not-implemented", where the refused delete is
        // the customer's own policy). Every field is re-gated against its closed set here, as every other field on
        // this row is, and the retention boolean stops "enforced" standing in for "actually retaining anything".
        const deleteProbe = typeof r.deleteProbe === "string" && TEST_DELETE_PROBE_SET.has(r.deleteProbe) ? r.deleteProbe : undefined;
        // R5: the delete verdict's own status class, re-gated and admitted ONLY beside a delete that FAILED --
        // "denied" is now the 401/403 fact alone, "transient" is the busy store or the dropped socket, and this
        // separates a throttle (429) from a store fault (5xx). Its absence beside a "transient" IS the transport.
        const deleteStatusClass =
          deleteProbe !== undefined && deleteProbe !== "ok" && typeof r.deleteStatusClass === "string" && TEST_STATUS_CLASS_SET.has(r.deleteStatusClass) ? r.deleteStatusClass : undefined;
        const objectLock = typeof r.objectLock === "string" && TEST_OBJECT_LOCK_SET.has(r.objectLock) ? r.objectLock : undefined;
        const objectLockUnknownReason = objectLock === "unknown" && typeof r.objectLockUnknownReason === "string" && WORM_UNKNOWN_REASON_SET.has(r.objectLockUnknownReason) ? r.objectLockUnknownReason : undefined;
        const defaultRetention = objectLock === "enforced" && typeof r.defaultRetention === "boolean" ? r.defaultRetention : undefined;
        // R6: WHAT THE EMAIL SERVICE ACTUALLY SAID. Re-gated through the same E_UPPER_SNAKE shape gate the
        // recorder used, and admitted only on a FAILED email row, so it can only ever ride where it describes
        // something. Without it the pack cannot tell an un-onboarded sending domain (E_SENDER_DOMAIN_NOT_AVAILABLE
        // -- onboard it in the Cloudflare dashboard) from an unverified sender (E_SENDER_NOT_VERIFIED) from a
        // platform throttle (E_RATE_LIMITED -- wait it out): all three read {"ok":false,"reasonClass":"other"}.
        const platformCode = (surface === "email" || surface === "notify-channel") && !ok ? sanitiseEmailPlatformCode(r.platformCode) : undefined;
        // R7: WHAT THE SINK ACTUALLY DID, on the surface the ticket names. Re-gated against the channel layer's
        // closed DELIVERY_FAIL_CODES and admitted only on a FAILED notify-channel row. Without it a
        // DEPROVISIONED webhook (http-gone: recreate the integration), a wrong path on a live sink (http-4xx),
        // and an engine payload regression (http-bad-request: our bug) are one {"ok":false,"reasonClass":
        // "rejected"} row -- and a support engineer reading it tells the customer to recreate a webhook that is
        // perfectly healthy. A confidently WRONG answer, which is worse than a missing one.
        const deliveryCode = surface === "notify-channel" && !ok && typeof r.deliveryCode === "string" && DELIVERY_FAIL_CODES.has(r.deliveryCode) ? r.deliveryCode : undefined;
        // A FAILURE with no admissible reason class is a drifted writer, not evidence: drop it rather than
        // carry a failure the pack cannot explain (which is the exact shape of the notify test row this gap
        // exists to fix).
        if (!ok && reasonClass === undefined) return [];
        return [{
          ok,
          ...(reasonClass !== undefined ? { reasonClass } : {}),
          ...(statusClass !== undefined ? { statusClass } : {}),
          ...(deleteProbe !== undefined ? { deleteProbe } : {}),
          ...(deleteStatusClass !== undefined ? { deleteStatusClass } : {}),
          ...(objectLock !== undefined ? { objectLock } : {}),
          ...(objectLockUnknownReason !== undefined ? { objectLockUnknownReason } : {}),
          ...(defaultRetention !== undefined ? { defaultRetention } : {}),
          ...(platformCode !== undefined ? { platformCode } : {}),
          ...(deliveryCode !== undefined ? { deliveryCode } : {}),
          ...(clampTs(r.at) !== undefined ? { at: clampTs(r.at) } : {}),
        }];
      });
      if (ring.length > 0) testOutcomes[surface] = ring;
    }
    if (Object.keys(testOutcomes).length > 0) out.testOutcomes = testOutcomes;
    // recoveryResume (G103): what the DR auto-heal SILENTLY dropped, re-pointed and stripped. defaultRepointed
    // is the "backups land in an unexpected bucket" cause; importFieldDrops.worm is the customer's WORM
    // retention posture VANISHING inside the very recovery meant to restore it.
    const rr = (typeof j.recoveryResume === "object" && j.recoveryResume !== null ? j.recoveryResume : null) as Record<string, unknown> | null;
    if (rr !== null) {
      const resumeSkips = (Array.isArray(rr.resumeSkips) ? rr.resumeSkips : []).slice(-RESUME_SKIPS_CAP).flatMap((e) => {
        const s = (typeof e === "object" && e !== null ? e : {}) as { downpipeId?: unknown; reasonClass?: unknown; at?: unknown };
        if (typeof s.downpipeId !== "string" || typeof s.reasonClass !== "string" || !RESUME_SKIP_CLASS_SET.has(s.reasonClass)) return [];
        return [{ downpipeId: s.downpipeId.slice(0, 128), reasonClass: s.reasonClass, ...(clampTs(s.at) !== undefined ? { at: clampTs(s.at) } : {}) }];
      });
      const reestablishDestIds = (Array.isArray(rr.reestablishDestIds) ? rr.reestablishDestIds : [])
        .filter((d): d is string => typeof d === "string")
        .slice(0, REESTABLISH_DESTS_CAP)
        .map((d) => d.slice(0, 128));
      const importFieldDrops = projectCountAgg(rr.importFieldDrops, IMPORT_DROP_FIELD_SET);
      const refusal = (typeof rr.stagedApplyRefusal === "object" && rr.stagedApplyRefusal !== null ? rr.stagedApplyRefusal : null) as { cls?: unknown; at?: unknown } | null;
      const refusalCls = refusal !== null && typeof refusal.cls === "string" && STAGED_APPLY_REFUSAL_SET.has(refusal.cls) ? refusal.cls : undefined;
      const block: Record<string, unknown> = {
        ...(resumeSkips.length > 0 ? { resumeSkips } : {}),
        ...(rr.defaultRepointed === true ? { defaultRepointed: true } : {}),
        ...(reestablishDestIds.length > 0 ? { reestablishDestIds } : {}),
        ...(Object.keys(importFieldDrops).length > 0 ? { importFieldDrops } : {}),
        ...(refusalCls !== undefined ? { stagedApplyRefusal: { cls: refusalCls, ...(clampTs(refusal?.at) !== undefined ? { at: clampTs(refusal?.at) } : {}) } } : {}),
        ...(clampTs(rr.at) !== undefined ? { at: clampTs(rr.at) } : {}),
      };
      // Omit the block when the auto-heal replayed everything cleanly (only a bare timestamp survived).
      if (Object.keys(block).filter((k) => k !== "at").length > 0) out.recoveryResume = block;
    }

    // ---- the round-4 scheduler-DO ledgers ---------------------------------------------------------------
    // destResolveFallbacks (G090): the resolver deviations that silently write to a destination the customer
    // did NOT choose -- a malformed destinationIds list that fell back to the legacy pin, a dangling default
    // healed to "the first entry", a canary pinned to destinations that no longer exist. `counts` is the RATE
    // (a heal that fires on every read is a different fault from one that fired once); `recent` names WHICH
    // downpipes deviated. The customer's own labels only.
    const drf = (typeof j.destResolveFallbacks === "object" && j.destResolveFallbacks !== null ? j.destResolveFallbacks : null) as { counts?: unknown; recent?: unknown } | null;
    if (drf !== null) {
      const counts = projectCountAgg(drf.counts, DEST_RESOLVE_FALLBACK_SET);
      const recent = (Array.isArray(drf.recent) ? drf.recent : []).slice(-DEST_FALLBACK_RING_CAP).flatMap((e) => {
        const f = (typeof e === "object" && e !== null ? e : {}) as { cls?: unknown; downpipeId?: unknown; at?: unknown };
        if (typeof f.cls !== "string" || !DEST_RESOLVE_FALLBACK_SET.has(f.cls)) return [];
        return [{
          cls: f.cls,
          downpipeId: typeof f.downpipeId === "string" ? f.downpipeId.slice(0, 128) : null,
          ...(clampTs(f.at) !== undefined ? { at: clampTs(f.at) } : {}),
        }];
      });
      if (Object.keys(counts).length > 0 || recent.length > 0) out.destResolveFallbacks = { ...(Object.keys(counts).length > 0 ? { counts } : {}), ...(recent.length > 0 ? { recent } : {}) };
    }
    // canaryLosses (G091): the canary's own losses. lost-flight means a flight was allocated and its
    // completion never arrived within the lease (it was abandoned and silently re-allocated); malformed-result
    // means ONE destination's bird froze on a stale verdict while the aggregate read healthy; and
    // uncoveredDestIds NAMES the destinations CANARY_MAX_DESTS truncated away -- destinations that are never
    // flown at all, so their liveness is asserted by nothing.
    const cl = (typeof j.canaryLosses === "object" && j.canaryLosses !== null ? j.canaryLosses : null) as { counts?: unknown; uncoveredDestIds?: unknown } | null;
    if (cl !== null) {
      const counts = projectCountAgg(cl.counts, CANARY_LOSS_KIND_SET);
      const uncoveredDestIds = (Array.isArray(cl.uncoveredDestIds) ? cl.uncoveredDestIds : [])
        .filter((d): d is string => typeof d === "string")
        .slice(0, CANARY_UNCOVERED_CAP)
        .map((d) => d.slice(0, 128));
      if (Object.keys(counts).length > 0 || uncoveredDestIds.length > 0) {
        out.canaryLosses = { ...(Object.keys(counts).length > 0 ? { counts } : {}), ...(uncoveredDestIds.length > 0 ? { uncoveredDestIds } : {}) };
      }
    }
    // drillDrops (G059/G097): the restore-test pipeline's silent discards. member-requeued is the "stuck at 3
    // remaining for two days" signal (a fleet-drill member re-queued forever); member-deleted-failed is a
    // DELETED downpipe reported to the customer as a drill FAILURE; proof-dropped is a PASSED restorability
    // proof thrown away; and evidence-write-failed means the drill RAN (lastRestoreTestAt proves it) and the
    // dated evidence row the customer's auditor reads does not exist.
    const drillDrops = projectCountAgg(j.drillDrops, DRILL_DROP_KIND_SET);
    if (Object.keys(drillDrops).length > 0) out.drillDrops = drillDrops;
    // notifyDrops (G060): WHICH alert died, not just how many. notifyHealth carries four integers; the
    // customer's question is never "how many alerts were dropped" but "MY backup-failure alert never arrived".
    // The ring names the dead alert with the same closed fields the delivered-history ring already carries (a
    // closed event name, a closed severity, the customer's own downpipe id) and NOTHING else.
    const nd = (typeof j.notifyDrops === "object" && j.notifyDrops !== null ? j.notifyDrops : null) as { counts?: unknown; recent?: unknown } | null;
    if (nd !== null) {
      const counts = projectCountAgg(nd.counts, NOTIFY_DROP_KIND_SET);
      const recent = (Array.isArray(nd.recent) ? nd.recent : []).slice(-NOTIFY_DROPS_RING_CAP).flatMap((e) => {
        const d = (typeof e === "object" && e !== null ? e : {}) as { at?: unknown; dropKind?: unknown; event?: unknown; severity?: unknown; downpipeId?: unknown };
        if (typeof d.dropKind !== "string" || !NOTIFY_DROP_KIND_SET.has(d.dropKind)) return [];
        return [{
          dropKind: d.dropKind,
          ...(clampTs(d.at) !== undefined ? { at: clampTs(d.at) } : {}),
          ...(typeof d.event === "string" && NOTIFY_EVENT_NAME_SET.has(d.event) ? { event: d.event } : {}),
          ...(typeof d.severity === "string" && NOTIFY_SEVERITY_SET.has(d.severity) ? { severity: d.severity } : {}),
          ...(typeof d.downpipeId === "string" ? { downpipeId: d.downpipeId.slice(0, 128) } : {}),
        }];
      });
      if (Object.keys(counts).length > 0 || recent.length > 0) out.notifyDrops = { ...(Object.keys(counts).length > 0 ? { counts } : {}), ...(recent.length > 0 ? { recent } : {}) };
    }
    // governanceFaults (G034): the dual-control / change-control plane's refusals, keyed "<stage>|<class>".
    // Two members are ESCALATIONS rather than diagnostics: integrity-failed (the STORED governance record did
    // not match its own integrity tag -- a tamper, or a storage corruption, on the approval record itself) and
    // replay-detected (a one-shot approval presented twice, which IS the replay detector for "the same
    // approval seems to have authorised two applies").
    const governanceFaults = projectCountAgg(j.governanceFaults, GOVERNANCE_FAULT_KEY_SET);
    if (Object.keys(governanceFaults).length > 0) out.governanceFaults = governanceFaults;
    // governanceRefusals (G182): the REASON, keyed "<stage>|<reason>". governanceFaults above says a guard
    // refused; this says WHICH guard and WHY, which is the whole difference between a shrug and a fix:
    //
    //   restore-apply|expired        raise a new request       restore-apply|applying-lease   an apply is IN FLIGHT
    //   restore-apply|consumed       an earlier apply ALREADY WORKED: the retry is the mistake, not the engine
    //   restore-apply|pending        it was never approved     restore-apply|no-such-request  nobody raised this plan
    //   restore-approve|self-approval  get a second person     change-apply|base-moved        the config moved under you
    //   restore-reject|applying-lease  a VETO of a live restore was refused while the apply went through: its own
    //                                  stage, so it can never coalesce with a refused APPROVAL again
    //   change-ref|change-ref-garbled  the console's header did not decode -- the operator DID enter the change
    //                                  number they are being asked for again
    //   role-escalation|escalation-refused  somebody tried to grant themselves a capability they do not hold
    //
    // Every one of these previously collapsed into the single "guard-refused" class, or into nothing at all.
    const governanceRefusals = projectCountAgg(j.governanceRefusals, GOVERNANCE_REFUSAL_KEY_SET);
    if (Object.keys(governanceRefusals).length > 0) out.governanceRefusals = governanceRefusals;
    // refusalRings (G037): the SEQUENCE, not the last-only collapse. A customer who retried a licence
    // activation five times with THREE different causes read as count=5 and one code -- and the last code is
    // the one they got right before giving up, i.e. the least informative. "expired, expired, wrong-signer" is
    // a different story from "malformed, malformed, malformed". config-snapshot's signing-key class means NO
    // config change can EVER be versioned until it is fixed.
    const refusalRings: Record<string, unknown[]> = {};
    if (typeof j.refusalRings === "object" && j.refusalRings !== null) {
      for (const [surface, v] of Object.entries(j.refusalRings as Record<string, unknown>)) {
        if (!REFUSAL_SURFACE_SET.has(surface)) continue; // closed surface vocabulary only
        const ring = (Array.isArray(v) ? v : []).slice(-REFUSAL_RING_CAP).flatMap((e) => {
          const row = (typeof e === "object" && e !== null ? e : {}) as { at?: unknown; code?: unknown };
          // The code is the surface's OWN engine-set closed member (a licence reason code, an engine action
          // kind, a snapshot failure class), control-stripped and clamped at the write site. It is re-stripped
          // and re-clamped here so a drifted writer cannot widen it, and a non-string is dropped outright.
          if (typeof row.code !== "string" || row.code === "") return [];
          return [{ code: stripControl(row.code).slice(0, 64), ...(clampTs(row.at) !== undefined ? { at: clampTs(row.at) } : {}) }];
        });
        if (ring.length > 0) refusalRings[surface] = ring;
      }
    }
    if (Object.keys(refusalRings).length > 0) out.refusalRings = refusalRings;
    // schedAdminRefusals (G126/G146): what the DO itself refused, keyed "<route>|<reason>" over two closed
    // sets. Deliberately a COUNT map rather than a ring: the customer's question ("which check keeps refusing
    // me") is a rate, and a count map cannot be grown by a retry storm. It is DISJOINT from the Worker-edge
    // adminRefusals section (a different DO key and a different composite separator), and the pack carries
    // both: the edge records what the ROUTER refused, this records what the DO refused. The headline is the
    // dest-remove guard split (in-use vs orphan-guard), which the console used to tell apart by SUBSTRING-
    // MATCHING the refusal prose.
    const schedAdminRefusals = projectCountAgg(j.adminRefusals, SCHED_ADMIN_REFUSAL_KEY_SET);
    if (Object.keys(schedAdminRefusals).length > 0) out.schedAdminRefusals = schedAdminRefusals;
    // clientDiagnostics (G172/G173/G174/G176/G178/G181 + G097's console half): the BROWSER's own evidence,
    // riding IN the point-in-time pack the customer generates and chooses to share (the owner's standing
    // ruling: no background beacon). The console keeps a bounded closed-class ring in the browser and POSTs it
    // at pack-generation time. The body is BROWSER-AUTHORED and therefore UNTRUSTED, so it is re-gated here as
    // well as at the DO's applyClientDiagnostics chokepoint: every enum closed-set validated (a drifted value
    // is DROPPED, never carried, so no browser string can become a bundle key), every count clamped, and the
    // build id must match a version-shaped pattern. consoleBuildId + engine.version is the SKEW PAIR support
    // could never assemble.
    const cd = (typeof j.clientDiagnostics === "object" && j.clientDiagnostics !== null ? j.clientDiagnostics : null) as Record<string, unknown> | null;
    if (cd !== null) {
      const crashes = projectCountAgg(cd.crashes, CLIENT_CRASH_PHASE_SET);
      const faults = projectCountAgg(cd.faults, CLIENT_FAULT_KIND_SET);
      const skew = projectCountAgg(cd.skew, CLIENT_SKEW_KEY_SET);
      const bulkOutcomes = (Array.isArray(cd.bulkOutcomes) ? cd.bulkOutcomes : []).slice(-CLIENT_DIAG_RING_CAP).flatMap((e) => {
        const b = (typeof e === "object" && e !== null ? e : {}) as Record<string, unknown>;
        if (typeof b.op !== "string" || !CLIENT_BULK_OP_SET.has(b.op)) return [];
        return [{
          op: b.op,
          ...(clampTs(b.at) !== undefined ? { at: clampTs(b.at) } : {}),
          attempted: clampInt(b.attempted, 100_000) ?? 0,
          succeeded: clampInt(b.succeeded, 100_000) ?? 0,
          failed: clampInt(b.failed, 100_000) ?? 0,
          halted: b.halted === true,
          timedOut: b.timedOut === true,
          pollFailures: clampInt(b.pollFailures, 100_000) ?? 0,
          failedByClass: projectCountAgg(b.failedByClass, CLIENT_BULK_FAIL_SET),
        }];
      });
      const settleJourneys = (Array.isArray(cd.settleJourneys) ? cd.settleJourneys : []).slice(-CLIENT_DIAG_RING_CAP).flatMap((e) => {
        const s = (typeof e === "object" && e !== null ? e : {}) as Record<string, unknown>;
        if (typeof s.terminalState !== "string" || !CLIENT_SETTLE_STATE_SET.has(s.terminalState)) return [];
        return [{
          terminalState: s.terminalState,
          ...(clampTs(s.at) !== undefined ? { at: clampTs(s.at) } : {}),
          settleAttempts: clampInt(s.settleAttempts, 100_000) ?? 0,
          statusReadFailures: clampInt(s.statusReadFailures, 100_000) ?? 0,
          pollAttempts: clampInt(s.pollAttempts, 100_000) ?? 0,
          pollCeilingHit: s.pollCeilingHit === true,
          unexpectedOutcome: s.unexpectedOutcome === true,
        }];
      });
      const buildId = typeof cd.consoleBuildId === "string" && CONSOLE_BUILD_ID_SHAPE.test(cd.consoleBuildId) ? cd.consoleBuildId : undefined;
      const block: Record<string, unknown> = {
        ...(buildId !== undefined ? { consoleBuildId: buildId } : {}),
        ...(Object.keys(crashes).length > 0 ? { crashes } : {}),
        ...(Object.keys(faults).length > 0 ? { faults } : {}),
        ...(Object.keys(skew).length > 0 ? { skew } : {}),
        ...(bulkOutcomes.length > 0 ? { bulkOutcomes } : {}),
        ...(settleJourneys.length > 0 ? { settleJourneys } : {}),
        ...(clampTs(cd.at) !== undefined ? { at: clampTs(cd.at) } : {}),
      };
      if (Object.keys(block).filter((k) => k !== "at").length > 0) out.clientDiagnostics = block;
    }

    // ---- the ROUND-5 sched evidence ---------------------------------------------------------------------
    // configRejections (G139 + G141): EVERY refused configuration save, recorded at the ONE funnel every DO
    // validator throw already passes through (SchedulerDO.fetch()'s 400 branch), so all 32 catalogue sites are
    // covered and a NEW route cannot forget to record. The surface is the DO's own STATIC route key (engine
    // vocabulary, never a path id); the classifier READS the validator message only to SELECT a closed reason
    // and RETURNS the enum, so the quoted cron string / bucket / URL / e-mail / account id is consumed and
    // discarded. `reserved-binding` is tested FIRST and is its own reason, so a SIGNER_PRIVATE confused-deputy
    // attempt can never coarsen into an ordinary typo. cp-reconcile|* and cp-import|* are the DR half: a
    // break-glass reconcile or estate-import refusal previously wrote NOTHING AT ALL.
    const configRejections = projectCountAgg(j.configRejections, CONFIG_REJECT_KEY_SET);
    if (Object.keys(configRejections).length > 0) out.configRejections = configRejections;

    // authzRefusals (G187 + G249): every capability gate, owner gate, escalation guard and break-glass guard,
    // recorded at the DO's single AuthError funnel. The PUBLIC 403 body stays the bare "forbidden" (the
    // anti-enumeration posture is unchanged); the GATE is recorded engine-side only. No caller e-mail, subject
    // or IP is a parameter of the recorder, so it structurally cannot be stored. The forensic twin lives in the
    // guard gates: grant-over-authority is a SELF-ELEVATION attempt, group-to-owner an escalation via mapping.
    const authzRefusals = projectCountAgg(j.authzRefusals, AUTHZ_GATE_SET);
    if (Object.keys(authzRefusals).length > 0) out.authzRefusals = authzRefusals;

    // alertingHealth (G188): the alerting plane's own liveness. detection-off-no-sink fires at BOTH detection
    // short-circuits -- delete your last channel and detection SILENTLY STOPS. cron-deadman-tripped is the
    // pack's first-class cron-driver-silent signal (the DO stood in for a dead cron). undeliverable-alert-batch
    // fires on url===null too, which is exactly the PagerDuty-only tenant whose alerts are generated and then
    // discarded. abandoned-recovery-resolve is recorded immediately BEFORE the owed-resolve marker is deleted --
    // the record was previously being destroyed in the same statement that abandoned the incident.
    const alertingHealth = projectCountAgg(j.alertingHealth, ALERTING_HEALTH_EVENT_SET);
    if (Object.keys(alertingHealth).length > 0) out.alertingHealth = alertingHealth;

    // configCoercions (G297): the config a save ACCEPTED and then silently DROPPED. The count is the number of
    // DROPPED ITEMS, not of saves. malformed-secret-kept-prior is the "we rotated the Datadog key but the
    // engine kept pushing with the old one" ticket: the keep-secret path RETAINED THE PRIOR SEALED SECRET.
    // Nothing about either secret (not its length, not a digest, not a fragment) is recorded -- the PRESENCE of
    // the substitution is the whole signal.
    const configCoercions = projectCountAgg(j.configCoercions, CONFIG_COERCION_KEY_SET);
    if (Object.keys(configCoercions).length > 0) out.configCoercions = configCoercions;

    // capTruncations (G325): the rows a bounded record DROPPED. This matters far beyond cosmetics: the
    // export-health record is what decides the self-backup posture check's allDestinationsWrote, so a
    // truncated-away FAILED destination read as fully covered -- a MISSING RECOVERY COPY, invisible.
    const capTruncations = projectCountAgg(j.capTruncations, CAP_TRUNCATION_SURFACE_SET);
    if (Object.keys(capTruncations).length > 0) out.capTruncations = capTruncations;

    // capTruncationSubjects (G325, second half): WHICH subjects the cap dropped, for the three surfaces whose
    // dropped row is keyed by one. A count alone leaves the harm intact on the surface a reader actually
    // reads -- the downpipe past the freshness cap is absent from `freshnessFaults`, so its downpipes[] row
    // carries no marker and asserts a working staleness rule while the caveat sits in a different section.
    // `incomplete` is the honesty bit: TRUE means a dropped subject is NOT named here, so the named list is a
    // LOWER BOUND and no un-named subject may be read as unaffected. Ids only, each already the key space the
    // capped map itself is keyed by and the pack already carries verbatim; no cause, count or free text.
    const cts = (typeof j.capTruncationSubjects === "object" && j.capTruncationSubjects !== null ? j.capTruncationSubjects : null) as Record<string, unknown> | null;
    if (cts !== null) {
      const projected: Record<string, { ids: string[]; incomplete: boolean; lastAt?: string | undefined }> = {};
      for (const [surface, raw] of Object.entries(cts)) {
        if (!CAP_TRUNCATION_SURFACE_SET.has(surface)) continue; // closed vocabulary, as everywhere here
        const e = (typeof raw === "object" && raw !== null ? raw : {}) as { ids?: unknown; incomplete?: unknown; lastAt?: unknown };
        const all = Array.isArray(e.ids) ? e.ids : [];
        const ids = all.slice(0, CAP_TRUNCATION_SUBJECT_IDS_CAP).flatMap((v) => (typeof v === "string" && v.length > 0 ? [v.slice(0, 128)] : []));
        // A read-path slice or a dropped malformed id is itself a truncation, so it FEEDS the same bit rather
        // than being silent: this projector must never be the place the naming goes quiet.
        const incomplete = e.incomplete === true || all.length > ids.length;
        if (ids.length === 0 && !incomplete) continue;
        projected[surface] = { ids, incomplete, ...(clampTs(e.lastAt) !== undefined ? { lastAt: clampTs(e.lastAt) } : {}) };
      }
      if (Object.keys(projected).length > 0) out.capTruncationSubjects = projected;
    }

    // auditEgress (G323 + G269): the audit feed's DELIVERY health. mirrorFailures counts the committed audit
    // events whose mirror leg was swallowed (the commit is never affected -- but it is no longer SILENT).
    // gapPagesServed is the collector's own blind spot: its cursor sits BELOW the oldest retained entry, so
    // those events rolled over and it will NEVER receive them. Only the engine-minted monotonic sequence
    // boundary rides; no event content. Read alongside the audit section's seq high-water mark, which IS the
    // emitted count (every committed event is mirrored exactly once inside appendAudit).
    const ae = (typeof j.auditEgress === "object" && j.auditEgress !== null ? j.auditEgress : null) as Record<string, unknown> | null;
    if (ae !== null) {
      const mf = (typeof ae.mirrorFailures === "object" && ae.mirrorFailures !== null ? ae.mirrorFailures : null) as Record<string, unknown> | null;
      const gp = (typeof ae.gapPagesServed === "object" && ae.gapPagesServed !== null ? ae.gapPagesServed : null) as Record<string, unknown> | null;
      const mfCount = mf !== null ? (clampInt(mf.count, 1_000_000_000) ?? 0) : 0;
      const gpCount = gp !== null ? (clampInt(gp.count, 1_000_000_000) ?? 0) : 0;
      const block: Record<string, unknown> = {
        ...(mfCount > 0 ? { mirrorFailures: { count: mfCount, ...(clampTs(mf?.lastAt) !== undefined ? { lastAt: clampTs(mf?.lastAt) } : {}) } } : {}),
        ...(gpCount > 0
          ? {
              gapPagesServed: {
                count: gpCount,
                ...(clampTs(gp?.lastAt) !== undefined ? { lastAt: clampTs(gp?.lastAt) } : {}),
                lastGapBeforeSeq: clampInt(gp?.lastGapBeforeSeq, Number.MAX_SAFE_INTEGER) ?? 0,
              },
            }
          : {}),
      };
      if (Object.keys(block).length > 0) out.auditEgress = block;
    }

    // posture (G334): the posture EVALUATION itself, plus the three ways its inputs arrive unusable.
    // identity-read-failed is a DROPPED IDP_KV BINDING -- a permanent one-line fix that was indistinguishable
    // from a transient blip ("admin-strong-auth has said cannot-verify for weeks"). status-slice-malformed
    // manufactures a SPURIOUS "retire the break-glass token" regression; worm-slice-malformed FLATTENS a real
    // WORM misconfiguration to not-configured.
    //
    // THIS PROJECTION IS THE REDACTION CHOKEPOINT for the overrides: an override carries a free-text
    // JUSTIFICATION and the acceptedBy EMAIL of whoever accepted the risk, and NEITHER is projected. Only the
    // closed check id, the closed override kind and the timestamp cross the boundary.
    const po = (typeof j.posture === "object" && j.posture !== null ? j.posture : null) as Record<string, unknown> | null;
    if (po !== null) {
      const checks = (Array.isArray(po.checks) ? po.checks : []).slice(0, POSTURE_CHECKS_PROJECT_CAP).flatMap((raw) => {
        const c = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
        if (typeof c.id !== "string" || !POSTURE_CHECK_ID_SET.has(c.id)) return []; // closed check ids only
        if (typeof c.severity !== "string" || !POSTURE_SEVERITY_SET.has(c.severity)) return [];
        return [{ id: c.id, passed: c.passed === true, severity: c.severity }];
      });
      const overrides = (Array.isArray(po.overrides) ? po.overrides : []).slice(0, POSTURE_OVERRIDES_CAP).flatMap((raw) => {
        const o = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
        if (typeof o.checkId !== "string" || !POSTURE_CHECK_ID_SET.has(o.checkId)) return [];
        if (typeof o.overrideKind !== "string" || !POSTURE_OVERRIDE_KIND_SET.has(o.overrideKind)) return [];
        // NOTE the explicit allowlist: justification and acceptedBy are READ by the DO and DROPPED HERE.
        return [{ checkId: o.checkId, overrideKind: o.overrideKind, ...(clampTs(o.at) !== undefined ? { at: clampTs(o.at) } : {}) }];
      });
      const inputFaults = projectCountAgg(po.inputFaults, POSTURE_INPUT_FAULT_SET);
      // The estate's STATED attended-verification interval. Re-clamped at this boundary like everything else,
      // and carried because "attended-verification-cadence: failed" is uninterpretable without it: failed
      // against what? Projected only when a rhythm is actually stated, so an estate that has stated none adds
      // no field rather than a 0 a reader might mistake for a zero-day target.
      const cadenceRaw = po.attendedCadenceDays;
      const attendedCadenceDays = typeof cadenceRaw === "number" && Number.isFinite(cadenceRaw) && cadenceRaw > 0 ? Math.floor(cadenceRaw) : 0;
      if (checks.length > 0 || overrides.length > 0 || Object.keys(inputFaults).length > 0 || clampTs(po.lastEvaluatedAt) !== undefined || attendedCadenceDays > 0) {
        out.posture = {
          ...(clampTs(po.lastEvaluatedAt) !== undefined ? { lastEvaluatedAt: clampTs(po.lastEvaluatedAt) } : {}),
          ...(checks.length > 0 ? { checks } : {}),
          ...(overrides.length > 0 ? { overrides } : {}),
          ...(Object.keys(inputFaults).length > 0 ? { inputFaults } : {}),
          ...(attendedCadenceDays > 0 ? { attendedCadenceDays } : {}),
        };
      }
    }
    return out;
  }
}

// freshnessUncomputable is the downpipes[] join for G076: the set of downpipe ids whose staleness rule cannot
// arm, taken from the schedDiag section ALREADY fetched (no extra DO round trip). Pure over its input.
export function freshnessUncomputableIndex(schedDiag: Record<string, unknown>): Map<string, string> {
  const out = new Map<string, string>();
  const ff = schedDiag.freshnessFaults;
  if (typeof ff !== "object" || ff === null) return out;
  for (const [id, v] of Object.entries(ff as Record<string, { cause?: unknown }>)) {
    if (typeof v?.cause === "string") out.set(id, v.cause);
  }
  return out;
}

// capTruncationSubjectIndex is the downpipes[] join for the OTHER half of G076: the subjects a cap REFUSED,
// taken from the schedDiag section ALREADY fetched (no extra DO round trip). Pure over its input.
//
// THIS IS THE REPAIR THAT REACHES THE ROW. `freshnessUncomputableIndex` above can only mark a downpipe that is
// IN the freshness map, and the whole defect is the downpipe that is not: past the cap it is absent, carries
// no marker, and its row reads as a downpipe with a working staleness rule while the caveat sits in the
// schedDiag section. `named` is the set this row-level marker can be attributed to exactly. `incomplete` says
// at least one refused subject could NOT be named, and a reader must then treat EVERY unmarked row as
// unverified rather than clean -- which is why the caller marks the whole population on it.
export interface CapTruncationSubjectIndex {
  named: Set<string>;
  incomplete: boolean;
}
export function capTruncationSubjectIndex(schedDiag: Record<string, unknown>, surface: string): CapTruncationSubjectIndex {
  const empty: CapTruncationSubjectIndex = { named: new Set<string>(), incomplete: false };
  const cts = schedDiag.capTruncationSubjects;
  if (typeof cts !== "object" || cts === null) return empty;
  const e = (cts as Record<string, unknown>)[surface];
  if (typeof e !== "object" || e === null) return empty;
  const entry = e as { ids?: unknown; incomplete?: unknown };
  const named = new Set<string>((Array.isArray(entry.ids) ? entry.ids : []).filter((v): v is string => typeof v === "string" && v.length > 0));
  return { named, incomplete: entry.incomplete === true };
}

// fetchDroppedWrites projects the recorders' OWN dropped writes (GET /dropped-writes, G100/G331/G104). ANY
// non-zero count means the pack you are holding is INCOMPLETE by that many records, and says of which kind --
// an explicit under-count caveat a diagnosis must read BEFORE concluding "no events happened". The Worker edge
// and the scheduler DO share this one record with disjoint, additive vocabularies, so the gate is the UNION of
// both (PACK_DROPPED_WRITE_KINDS): allowlisting either half alone would drop the other half's evidence here.
// Counts + clamped timestamps only; the dropped PAYLOAD is never retained, so it can never ride.
export async function fetchDroppedWrites(scheduler: DurableObjectStub): Promise<Record<string, { count: number; lastAt?: string }>> {
  {
    const r = await scheduler.fetch(doURL("/dropped-writes"), { method: "GET" });
    return projectCountAgg(await r.json(), DROPPED_WRITE_KIND_SET);
  }
}

// fetchSealErrors projects the per-downpipe PRE-RUN seal-dispatch fault (GET /seal-errors, G163). The throw
// lands BEFORE a run index is allocated, so the loop's /complete is a runId-"" history no-op and the pack
// showed only an anonymous scheduler.ticks.sealErrors integer: nothing said WHICH downpipe, or why. Now each
// downpipe carries a CLOSED class (destination unresolvable / config unreadable / wrap key invalid / the
// /trigger round trip / a wedged lease the lock-clear could not release) with a consecutive-fault streak.
// Never the exception message. A fetch/parse fault PROPAGATES to section().
export async function fetchSealErrors(scheduler: DurableObjectStub): Promise<Record<string, Record<string, unknown>>> {
  {
    const r = await scheduler.fetch(doURL("/seal-errors"), { method: "GET" });
    const j = (await r.json()) as { byDownpipe?: unknown };
    const out: Record<string, Record<string, unknown>> = {};
    if (typeof j.byDownpipe !== "object" || j.byDownpipe === null) return out;
    for (const [id, v] of Object.entries(j.byDownpipe as Record<string, unknown>).slice(0, 64)) {
      const s = (typeof v === "object" && v !== null ? v : {}) as { cls?: unknown; at?: unknown; consecutive?: unknown };
      if (typeof s.cls !== "string" || !SEAL_ERROR_CLASS_SET.has(s.cls)) continue; // closed vocabulary only
      out[id.slice(0, 128)] = {
        class: s.cls,
        at: clampInt(s.at, Number.MAX_SAFE_INTEGER) ?? 0,
        consecutive: clampInt(s.consecutive, 1_000_000) ?? 0,
      };
    }
    return out;
  }
}

// fetchMetricsHealth projects the Prometheus /metrics scrape surface's own health (GET /metrics-health, G049).
// The headline is auth-check-unavailable: a DO hiccup on the credential check is fail-CLOSED refused and
// misreported to the operator as "unauthorised", which is the "Prometheus started 401ing with an unexpired
// credential" ticket. shapeFallbacks counts the scrapes that rendered a VALID response with ZERO series (a
// DO 2xx with an unexpected body) while Prometheus's own `up` stayed 1. null until anything has scraped at all,
// which is itself the answer to "is anything even scraping us?". Closed outcome enums + counts + a clamped time.
export async function fetchMetricsHealth(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/metrics-health"), { method: "GET" });
    const j = (await r.json()) as { health?: unknown };
    const h = (typeof j.health === "object" && j.health !== null ? j.health : null) as { lastScrapeAt?: unknown; lastOutcome?: unknown; outcomes?: unknown; shapeFallbacks?: unknown; recordPullFailures?: unknown } | null;
    if (h === null) return {}; // nothing has ever scraped: honest absence
    const outcomes: Record<string, number> = {};
    if (typeof h.outcomes === "object" && h.outcomes !== null) {
      for (const [k, v] of Object.entries(h.outcomes as Record<string, unknown>)) {
        if (!METRICS_SCRAPE_OUTCOME_SET.has(k)) continue; // closed vocabulary only
        const c = clampInt(v, 1_000_000_000) ?? 0;
        if (c > 0) outcomes[k] = c;
      }
    }
    return {
      lastScrapeAt: clampInt(h.lastScrapeAt, Number.MAX_SAFE_INTEGER) ?? 0,
      ...(typeof h.lastOutcome === "string" && METRICS_SCRAPE_OUTCOME_SET.has(h.lastOutcome) ? { lastOutcome: h.lastOutcome } : {}),
      outcomes,
      shapeFallbacks: clampInt(h.shapeFallbacks, 1_000_000_000) ?? 0,
      recordPullFailures: clampInt(h.recordPullFailures, 1_000_000_000) ?? 0,
    };
  }
}

// fetchWebauthnFaults projects the 14 structural WebAuthn defect classes split by ceremony PHASE (GET
// /webauthn-faults, G158). All 14 used to collapse into the one coarse bad_request the ceremony returns, so
// "half my fleet cannot enrol a key" and "this user can never sign in again because their STORED COSE record
// is corrupt" were the same pack evidence: none. The key is "<phase>:<class>"; cose-unsupported-alg carries the
// offered IANA COSE alg integers, so support can say "your fleet offers -8 (EdDSA)". Never a credential id, a
// public key or a user. Recording is DO-internal (no POST route), so no caller can inject a class.
export async function fetchWebauthnFaults(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/webauthn-faults"), { method: "GET" });
    const j = (await r.json()) as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(typeof j === "object" && j !== null ? j : {})) {
      if (!WEBAUTHN_FAULT_KEY_SET.has(key)) continue; // only the closed phase:class cross product
      const e = (typeof v === "object" && v !== null ? v : {}) as { count?: unknown; lastAt?: unknown; algs?: unknown };
      const count = clampInt(e.count, 1_000_000) ?? 0;
      if (count === 0) continue;
      const algs = (Array.isArray(e.algs) ? e.algs : [])
        .filter((a): a is number => typeof a === "number" && Number.isFinite(a))
        .slice(0, 16)
        .map((a) => Math.max(-1_000_000, Math.min(1_000_000, Math.floor(a))));
      out[key] = {
        count,
        ...(clampTs(e.lastAt) !== undefined ? { lastAt: clampTs(e.lastAt) } : {}),
        ...(algs.length > 0 ? { algs } : {}),
      };
    }
    return out;
  }
}

// ---- the SOURCE + DESTINATION run-fault sections --------------------------------------------------------
// These are the projections of the two ledgers Wave-D recorded at the fault site and then never delivered:
// the source ledger (WHY an incompleteness sentinel was sealed, the tolerant-parse drops, the run-fatal
// transport class + crawl stage, the D1 snapshot verdict, the corrupt resume tokens, the absorbed 429s, the
// security refusals) and the destination fault log (the closed identity of every failing op, and the
// degradation counters of a store that is quietly making a GREEN run slow and expensive).
//
// Every field is re-gated HERE against the same closed vocabularies the DO's applier already enforced
// (defence in depth: a drifted or legacy record must never push free text into the bundle), and a
// fetch/parse fault PROPAGATES to section() so an unreadable ledger reads "error", never a clean "empty".

// fetchSourceFaults projects the per-downpipe SOURCE fault evidence (GET /source-faults). The headline: an
// "_unavailable" surface is no longer just unavailable, it is unavailable BECAUSE auth / entitlement /
// server-error / size-cap / page-cap -- four different tickets that used to produce identical packs. Keyed by
// the customer's own downpipe label; the ids are engine-chosen product tokens and one-way handles.
export async function fetchSourceFaults(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/source-faults"), { method: "GET" });
  const j = (await r.json()) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [id, v] of Object.entries(typeof j === "object" && j !== null ? j : {}).slice(0, RUN_FAULT_DOWNPIPES_MAX)) {
    // sanitiseSourceFaults is the SAME pure chokepoint the DO writes through, re-run at the pack boundary. It
    // re-gates every closed vocabulary, re-clamps every count and re-applies the structural id shape gate, so
    // a record written by a DRIFTED (or older, or tampered) engine cannot widen what reaches the bundle.
    const entry = sanitiseSourceFaults(v, clampInt((v as { at?: unknown })?.at, Number.MAX_SAFE_INTEGER) ?? 0);
    if (entry !== null) out[id.slice(0, 128)] = entry;
  }
  return out;
}

// fetchDestFaults projects the per-downpipe DESTINATION fault + degradation evidence (GET /dest-faults). The
// headline: "status 403" is now an EXPIRED STS SESSION vs a bucket-policy denial vs a signature mismatch vs a
// WORM checksum complaint -- and `arm: default-permanent` says the classifier could not read the store's
// message and DEFAULTED, so a retryable fault may have been given up on. Closed enums / clamped ints /
// booleans only; the S3 <Code> rides only from the documented allow-list, and the request id only as a
// presence boolean.
//
// strandedAborts (G343) rides through the SAME sanitiseDestFaults chokepoint, which re-gates it against the
// closed ABORT_FAILURE_CLASSES. It has to be forwarded EXPLICITLY, because this projector rebuilds the
    // and a field the rebuild forgets is a recorder writing into a void, which this projector guards
    // against.
// a multipart upload that was refused mid-flight AND whose abort was ALSO refused, so the parts are still
// accruing storage cost in the customer's bucket with nothing left to complete them: `denied` means the
// credential can write parts but not abort them (fix the bucket policy), `server-error` wants a lifecycle rule,
// and `network` will heal on its own.
export async function fetchDestFaults(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/dest-faults"), { method: "GET" });
  const j = (await r.json()) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [id, v] of Object.entries(typeof j === "object" && j !== null ? j : {}).slice(0, RUN_FAULT_DOWNPIPES_MAX)) {
    const e = (typeof v === "object" && v !== null ? v : {}) as { at?: unknown; faults?: unknown; total?: unknown; overflow?: unknown; io?: unknown; strandedAborts?: unknown };
    const entry = sanitiseDestFaults({ total: e.total, overflow: e.overflow, faults: e.faults, strandedAborts: e.strandedAborts }, e.io, clampInt(e.at, Number.MAX_SAFE_INTEGER) ?? 0);
    if (entry !== null) out[id.slice(0, 128)] = entry;
  }
  return out;
}

// stripControl removes the C0/C1 control codepoints from a customer-owned label before it is projected. It
// filters by CODEPOINT rather than by a regex character class: a control character written literally into a
// regex is both unreadable and a classic source of silent corruption (it is exactly what the linter's
// noControlCharactersInRegex rule exists to catch), and the intent -- "no control bytes reach the pack" --
// is clearer said outright.
function stripControl(v: string): string {
  let out = "";
  for (const ch of v) {
    const c = ch.codePointAt(0) ?? 0;
    if (c < 0x20 || c === 0x7f) continue;
    out += ch;
  }
  return out;
}

// fetchRestoreFaults projects the bounded restore / drill / blind-test / attest fault ring (GET
// /restore-faults, G070/G080). The `phase` field is the one a diagnosis reads FIRST: `verify` means NOTHING
// was written; `write` means other records landed and this one did not; `readback` means the bytes ARE on the
// target and could not be PROVEN (offline-recoverable, never loss). Class `too-large` is likewise
// OFFLINE-RECOVERABLE and must never be reasoned about as data loss. Closed enums, a control-stripped record
// label, the 8-hex Workers-Logs join key and int counts only.
export async function fetchRestoreFaults(scheduler: DurableObjectStub): Promise<unknown[]> {
  const r = await scheduler.fetch(doURL("/restore-faults"), { method: "GET" });
  const j = (await r.json()) as { faults?: unknown };
  const rows = Array.isArray(j.faults) ? j.faults : [];
  const out: unknown[] = [];
  for (const raw of rows.slice(-RESTORE_FAULTS_RING_CAP)) {
    const f = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
    const op = f.op;
    const phase = f.phase;
    const cls = f.cls;
    if (typeof op !== "string" || !RESTORE_FAULT_OP_SET.has(op)) continue;
    if (typeof phase !== "string" || !RESTORE_FAULT_PHASE_SET.has(phase)) continue;
    if (typeof cls !== "string" || !RESTORE_FAULT_CLASS_SET.has(cls)) continue;
    const errId = typeof f.errId === "string" && ERR_ID_SHAPE.test(f.errId) ? f.errId : undefined;
    // The record name is the customer's OWN object label -- the same redaction class the pack already carries
    // as a downpipe name. Control characters are stripped (a crafted name must not be able to corrupt the
    // rendered pack) and it is clamped to 128, the same discipline the restore-fault writer itself applies.
    const recordName = typeof f.recordName === "string" ? stripControl(f.recordName).slice(0, 128) : undefined;
    out.push({
      at: clampInt(f.at, Number.MAX_SAFE_INTEGER) ?? 0,
      op,
      phase,
      cls,
      count: clampInt(f.count, 1_000_000_000) ?? 1,
      ...(recordName !== undefined && recordName !== "" ? { recordName } : {}),
      ...(errId !== undefined ? { errId } : {}),
      // The DRILL's discriminating detail (G029). `index` is the FIRST failing record's index in the run, so
      // support can say "records 0 to 400 verify and 401 does not" (a lifecycle-expired chunk) instead of
      // "somewhere in 500"; `binding` names WHICH engine binding was absent, so a wiped SIGNER_PRIVATE stops
      // reading as a corrupt archive. The class posture-unexercisable is the honest third answer between pass
      // and fail: this engine holds no in-account read-back key, so the drill COULD NOT RUN -- which used to
      // be shape-identical to a genuine not-configured failure.
      ...(f.index !== undefined ? { index: clampInt(f.index, Number.MAX_SAFE_INTEGER) ?? 0 } : {}),
      ...(typeof f.binding === "string" && RESTORE_BINDING_NAME_SET.has(f.binding) ? { binding: f.binding } : {}),
    });
  }
  return out;
}

// fetchAdminCounters projects the admin-side silent-fallback / silent-exclusion counters (GET /admin-counters,
// G080/G081/G082 + the dest-config / dest-io counters, G185/G186). READ THIS ALONGSIDE droppedWrites: ANY
// non-zero value means a surface the pack ALREADY carries is quietly incomplete or was quietly degraded, and
// names which -- a reclaimed restore-apply lease (an apply that crashed mid-write and whose single-use
// approval may have authorised a second apply), a licence source flip, a point-in-time run silently excluded
// for a corrupt timestamp, a signed compliance report built over an unreadable read, an operator's WORM or
// assume-role destination policy silently discarded, or a store throttling the write path.
export async function fetchAdminCounters(scheduler: DurableObjectStub): Promise<Record<string, { count: number; lastAt?: string }>> {
  const r = await scheduler.fetch(doURL("/admin-counters"), { method: "GET" });
  return projectCountAgg(await r.json(), ADMIN_COUNTER_NAME_SET);
}

// fetchRateLimitHealth reads the account-global CF API rate-limit DO's own health (G104). infra
// .rateLimitDoConfigured was PRESENCE-ONLY: a limiter that has been FAILING OPEN (its take() throws, so every
// caller is granted a free pass and nothing is throttled) reads byte-identically to a healthy one -- which is
// exactly the "Cloudflare is 429-ing our crawls" ticket, where the engine's own throttle had quietly stopped
// throttling. knobInvalid flags a CF_API_RATE_PER_SEC that is SET but unparseable, silently falling back to the
// conservative default. Best-effort: {} when the binding is absent or the read faults (the presence boolean
// beside it already carries the absent case), so a limiter blip can never fail the bundle.
export async function fetchRateLimitHealth(env: Env): Promise<Record<string, unknown>> {
  const ns = env.RATELIMIT_DO;
  if (ns === undefined) return {};
  try {
    const stub = ns.get(ns.idFromName("account-cf-api"));
    const r = await stub.fetch(doURL("/health"), { method: "GET" });
    const j = (await r.json()) as { failOpenCount?: unknown; lastFailOpenAt?: unknown; knobInvalid?: unknown };
    return {
      failOpenCount: clampInt(j.failOpenCount, 1_000_000_000) ?? 0,
      lastFailOpenAt: clampInt(j.lastFailOpenAt, Number.MAX_SAFE_INTEGER) ?? 0,
      knobInvalid: j.knobInvalid === true,
    };
  } catch {
    // A read fault is NOT a healthy limiter. Flag it so a diagnoser can tell the two apart (G031).
    return { rateLimitHealthUnavailable: true };
  }
}
