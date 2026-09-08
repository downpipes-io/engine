// Support-pack section gatherers: the ROUND-4 fault ledgers -- ten DO records that the round-4 recorders
// wrote at the fault site and which, until this pass, NOTHING read. A gap is not closed until its evidence is
// in the BUNDLE, so each of these is the delivery half of a recorder that already fires on the fault path:
//
//   - unwrapFaults    (G028): WHEN the runtime CONFIG_WRAP_KEY unwrap started failing, and which of the four
//                             causes. The probe-time wrapKeyHealth verdict says WHETHER the key opens today;
//                             `firstAt` (never overwritten) is the "since when" it structurally cannot recover.
//   - bindingAlarms   (G099): the post-write binding-safety alarms (the highest-impact failure mode: a deploy that drops a
//                             source binding), with the operator's own binding labels.
//   - updateFaults    (G050/G054/G101/G159/G162): the self-update pipeline's failing STEP + closed cause, the
//                             Cloudflare integer error codes, the rollbackFailed latch, the bookkeeping rows
//                             that prove "the engine is LIVE and nothing recorded it", and droppedSources.
//   - adminRefusals   (G245): the Worker-EDGE refusal trail (surface x reason). gate-unavailable is the one to
//                             read at DR hour: a restore refused "not approved" because the approval gate could
//                             not be READ is an ENGINE fault, not a missing approval.
//   - integrityFaults (G011/G012/G056/G057/G087/G088/G089/G111): the seal/verify/restore core's fault LOCUS --
//                             the fetch fault behind an "absent" RUNLOG, the 16-way verify failStage split, the
//                             crypto-provisioning faults, the streaming chunk index, and defaultedEmptyRecords
//                             (records SEALED AS ZERO BYTES behind a green run).
//   - dispatchFaults  (G072): the Worker's four last-resort catches, including the SELF-REFERENTIAL one that
//                             covers /support/diagnostics itself.
//   - cronHealth      (G084/G132/G205/G220/G234/G278): every cron pass's outcome by closed name + error class,
//                             the tick ring's HOLES, the auto-heal STALLS, the discovery skips, the beacon's
//                             partial configuration, and the SIEM push's four silent fallbacks.
//   - destProbeFaults (G133/G151): per destination, the closed reason the write-probe refused it -- so "all
//                             destinations unreachable" finally names a cause per destination.
//   - destBuildHealth (G136/G137): failingSinceAt -- "every backup has been failing to even BUILD its
//                             destination since Tuesday, because DEST_ENDPOINT is gone".
//   - costSizing      (G296): the sizing probe's outcome by source type, including measured-zero (a 0 presented
//                             to the customer as a MEASURED answer).
//
// Every projection re-gates its closed vocabulary at the PACK boundary (defence in depth: the DO's applier
// already sanitises, but a drifted, older or tampered record must never push free text into the bundle),
// clamps every count/ordinal/timestamp, omits an empty block, and lets a fetch/parse fault PROPAGATE to
// section() so an unreadable ledger reads "error", never a clean "empty".

import {
  AUTOHEAL_DEFERRAL_CLASSES,
  BEACON_FAIL_CLASSES,
  CP_EXPORT_FAIL_CLASSES,
  CRON_PASS_ERROR_CLASSES,
  CRON_PASS_NAMES,
  DISCOVERY_SKIP_REASONS,
  RECONCILE_SKIP_REASONS,
  RESTORE_TEST_SKIP_CLASSES,
  RESUME_APPLY_REASON_CODES,
  SIEM_SHAPING_FALLBACKS,
} from "../cron/cron-fault-ledger.ts";
import { DEST_BUILD_CAUSES, DEST_BUILD_VARS, STS_FAILURE_CLASSES } from "../dest/build-health.ts";
import { CLASSIFIED_BY_KINDS, FETCH_FAULT_CLASSES, FETCH_SITES, FETCH_STATUS_CLASSES, STREAM_LEGS } from "../format/integrity-fault-ledger.ts";
import { NOTIFY_EVENT_NAMES } from "../notify/types.ts";
import {
  ADMIN_REFUSAL_REASONS,
  ADMIN_REFUSAL_SURFACES,ADMIN_ROUTE_NAMES, ADMIN_ROUTE_STAGES, 
  BINDING_ALARM_KINDS,
  BINDING_ALARMS_RING_CAP,
  COST_SIZING_CLASSES,
  COST_SIZING_SOURCE_TYPES,
  CRYPTO_FAULT_CLASS_NAMES,
  CRYPTO_KEY_ROLE_NAMES,
  DEST_PROBE_FAULTS_CAP,
  DEST_PROBE_REASONS,
  DISPATCH_FAULTS_CAP,
  DISPATCH_ROUTE_FAMILIES,
  DISPATCH_SURFACES,
  INTEGRITY_FAULT_KIND_NAMES,
  INTEGRITY_FAULTS_DOWNPIPE_CAP,
  // The ROUND-5 format-layer vocabularies, re-declared DO-side in diag-records.ts and pinned member-for-member
  // to the format sets by validate-format-root-evidence, so a drift fails loudly instead of silently emptying
  // the section (G102 / G166 / G320).
  KEYLESS_COVERAGE_NAMES,
  RUNLOG_ANOMALY_KIND_NAMES,
  STREAM_FAULT_CLASS_NAMES,
  UNWRAP_FAULT_CAUSES,
  UPDATE_CAUSE_CLASSES,
  UPDATE_COMPONENTS,
  UPDATE_FAIL_STEPS,
  UPDATE_FAULTS_RING_CAP,
  UPDATE_RECORD_PHASES,
  VERIFY_FAIL_STAGE_NAMES,
  WRITER_REFUSAL_KIND_NAMES
} from "./diag-records.ts";
import { doURL } from "../do-url.ts";
import { clampInt, clampTs } from "./support-shared.ts";

const UNWRAP_CAUSE_SET: ReadonlySet<string> = new Set(UNWRAP_FAULT_CAUSES);
const BINDING_ALARM_KIND_SET: ReadonlySet<string> = new Set(BINDING_ALARM_KINDS);
const UPDATE_COMPONENT_SET: ReadonlySet<string> = new Set(UPDATE_COMPONENTS);
const UPDATE_STEP_SET: ReadonlySet<string> = new Set(UPDATE_FAIL_STEPS);
const UPDATE_CAUSE_SET: ReadonlySet<string> = new Set(UPDATE_CAUSE_CLASSES);
const UPDATE_PHASE_SET: ReadonlySet<string> = new Set(UPDATE_RECORD_PHASES);
const DISPATCH_SURFACE_SET: ReadonlySet<string> = new Set(DISPATCH_SURFACES);
const DISPATCH_FAMILY_SET: ReadonlySet<string> = new Set(DISPATCH_ROUTE_FAMILIES);
const DEST_PROBE_REASON_SET: ReadonlySet<string> = new Set(DEST_PROBE_REASONS);
const COST_SIZING_CLASS_SET: ReadonlySet<string> = new Set(COST_SIZING_CLASSES);
const COST_SIZING_TYPE_SET: ReadonlySet<string> = new Set(COST_SIZING_SOURCE_TYPES);
const DEST_BUILD_CAUSE_SET: ReadonlySet<string> = new Set(DEST_BUILD_CAUSES);
const DEST_BUILD_VAR_SET: ReadonlySet<string> = new Set(DEST_BUILD_VARS);
const STS_CLASS_SET: ReadonlySet<string> = new Set(STS_FAILURE_CLASSES);
const CRON_PASS_NAME_SET: ReadonlySet<string> = new Set(CRON_PASS_NAMES);
const CRON_PASS_ERROR_SET: ReadonlySet<string> = new Set(CRON_PASS_ERROR_CLASSES);
const DISCOVERY_SKIP_SET: ReadonlySet<string> = new Set(DISCOVERY_SKIP_REASONS);
const BEACON_FAIL_SET: ReadonlySet<string> = new Set(BEACON_FAIL_CLASSES);
const AUTOHEAL_DEFERRAL_SET: ReadonlySet<string> = new Set(AUTOHEAL_DEFERRAL_CLASSES);
const RESUME_APPLY_REASON_SET: ReadonlySet<string> = new Set(RESUME_APPLY_REASON_CODES);
const SIEM_FALLBACK_SET: ReadonlySet<string> = new Set(SIEM_SHAPING_FALLBACKS);
const VERIFY_FAIL_STAGE_SET: ReadonlySet<string> = new Set(VERIFY_FAIL_STAGE_NAMES);
const INTEGRITY_KIND_SET: ReadonlySet<string> = new Set(INTEGRITY_FAULT_KIND_NAMES);
const CRYPTO_CLASS_SET: ReadonlySet<string> = new Set(CRYPTO_FAULT_CLASS_NAMES);
const CRYPTO_ROLE_SET: ReadonlySet<string> = new Set(CRYPTO_KEY_ROLE_NAMES);
const STREAM_LEG_SET: ReadonlySet<string> = new Set(STREAM_LEGS);
const STREAM_CLASS_SET: ReadonlySet<string> = new Set(STREAM_FAULT_CLASS_NAMES);
const CLASSIFIED_BY_SET: ReadonlySet<string> = new Set(CLASSIFIED_BY_KINDS);
// The ROUND-5 closed sets, each re-gated at the PACK boundary as well as at the DO applier (defence in depth).
const RUNLOG_ANOMALY_SET: ReadonlySet<string> = new Set(RUNLOG_ANOMALY_KIND_NAMES);
const WRITER_REFUSAL_SET: ReadonlySet<string> = new Set(WRITER_REFUSAL_KIND_NAMES);
const KEYLESS_COVERAGE_SET: ReadonlySet<string> = new Set(KEYLESS_COVERAGE_NAMES);
const NOTIFY_EVENT_SET: ReadonlySet<string> = new Set(NOTIFY_EVENT_NAMES);
const CP_EXPORT_FAIL_SET: ReadonlySet<string> = new Set(CP_EXPORT_FAIL_CLASSES);
const RESTORE_TEST_SKIP_SET: ReadonlySet<string> = new Set(RESTORE_TEST_SKIP_CLASSES);
const RECONCILE_SKIP_SET: ReadonlySet<string> = new Set(RECONCILE_SKIP_REASONS);
// The per-downpipe restore-test skip map is bounded at the pack boundary too (the DO caps it at 64; a drifted
// or hostile record must not be able to make the SECTION unbounded).
const RESTORE_TEST_SKIP_CAP = 64;

// The composite key spaces. The DO keys these aggregates "<a>|<b>" (or "<a>:<b>"), so the pack RE-DERIVES the
// whole cross product rather than parsing the key: a drifted key outside the product is DROPPED, never
// propagated. This is the closed-vocabulary bypass the audit's own redaction proof hunts for -- a
// caller-derived string becoming a map KEY -- and re-deriving the product is what forecloses it here too.
const ADMIN_REFUSAL_KEY_SET: ReadonlySet<string> = new Set(ADMIN_REFUSAL_SURFACES.flatMap((s) => ADMIN_REFUSAL_REASONS.map((r) => `${s}:${r}`)));
const INTEGRITY_FETCH_KEY_SET: ReadonlySet<string> = new Set(
  FETCH_SITES.flatMap((site) => FETCH_FAULT_CLASSES.flatMap((cls) => FETCH_STATUS_CLASSES.map((st) => `${site}|${cls}|${st}`))),
);

// The three shape gates on the ONLY non-enum, non-integer values any of these records may carry. Each is a
// PUBLIC or ENGINE-MINTED token, never a customer value: the engine's 8-hex FNV exception id (the sole join
// key to a Workers-Logs line the pack structurally cannot carry), the 12-hex one-way correlation digest, the
// 96-hex SHA-384 of a PUBLIC release artefact, the fixed `downpipe/<n>.x` format label, and a public-material
// key fingerprint. Anything else in these fields is dropped, so no message can ride through a "digest" seam.
const ERR_ID_SHAPE = /^[0-9a-f]{8}$/;
const HEX12_SHAPE = /^[0-9a-f]{12}$/;
const SHA384_SHAPE = /^[0-9a-f]{96}$/;
const FORMAT_MAJOR_SHAPE = /^downpipe\/\d{1,3}\.x$/;
const FINGERPRINT_SHAPE = /^(?:dpr1:)?[0-9a-f]{8,96}$/;
// BINDING_NAME_SHAPE gates the operator's own Workers binding labels (droppedSources / bindingNames). It is a
// SHAPE gate, not a clamp: a secret, an e-mail, an endpoint or an object key is not shaped like a binding name
// and is dropped outright, so even a future call site that passed one could not push it into the pack.
const BINDING_NAME_SHAPE = /^[A-Za-z0-9_-]{1,64}$/;
// gateCounts folds an untrusted {key -> count} map, keeping only closed-vocabulary keys and clamping counts.
// A zero drops the row (the healthy steady state is silence, not a wall of zeroes).
function gateCounts(raw: unknown, allowed: ReadonlySet<string>, cap = 1_000_000_000): Record<string, number> {
  const out: Record<string, number> = {};
  if (typeof raw !== "object" || raw === null) return out;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!allowed.has(k)) continue;
    const n = clampInt(v, cap) ?? 0;
    if (n > 0) out[k] = n;
  }
  return out;
}

// gateCountAgg folds an untrusted {key -> {count,lastAt}} aggregate the same way (the shape most ledgers use).
function gateCountAgg(raw: unknown, allowed: ReadonlySet<string>): Record<string, { count: number; lastAt?: string }> {
  const out: Record<string, { count: number; lastAt?: string }> = {};
  if (typeof raw !== "object" || raw === null) return out;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!allowed.has(k)) continue;
    const rec = (typeof v === "object" && v !== null ? v : {}) as { count?: unknown; lastAt?: unknown };
    const count = clampInt(rec.count, 1_000_000_000) ?? 0;
    if (count === 0) continue;
    const lastAt = clampTs(rec.lastAt);
    out[k] = { count, ...(lastAt !== undefined ? { lastAt } : {}) };
  }
  return out;
}

// gated returns a closed-set member or undefined. An out-of-vocabulary value is DROPPED here rather than
// collapsed to a placeholder: unlike the operator-facing code fields UNKNOWN_CODE serves, these are the
// ledgers' own structural discriminants, and carrying a drifted one would let it become a bundle key.
function gated(v: unknown, allowed: ReadonlySet<string>): string | undefined {
  return typeof v === "string" && allowed.has(v) ? v : undefined;
}

function shaped(v: unknown, re: RegExp): string | undefined {
  return typeof v === "string" && re.test(v) ? v : undefined;
}

// ---- G028: unwrapFaults ---------------------------------------------------------------------------------
// The RUNTIME wrap-key unwrap faults, recorded at the read-for-use chokepoint every run / drill / restore /
// canary / retention / replication pass funnels through. `firstAt` is NEVER overwritten by the applier, and it
// is the whole point: the probe-time wrapKeyHealth verdict (section 4.14) says WHETHER the key opens right
// now, and structurally cannot say SINCE WHEN it stopped -- which is the fact that separates "the operator
// rotated CONFIG_WRAP_KEY last Tuesday" from "one stored record is damaged".
export async function fetchUnwrapFaults(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/unwrap-faults"), { method: "GET" });
  const j = (await r.json()) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [cause, v] of Object.entries(typeof j === "object" && j !== null ? j : {})) {
    if (!UNWRAP_CAUSE_SET.has(cause)) continue; // closed vocabulary only
    const e = (typeof v === "object" && v !== null ? v : {}) as { count?: unknown; firstAt?: unknown; lastAt?: unknown };
    const count = clampInt(e.count, 1_000_000_000) ?? 0;
    if (count === 0) continue;
    out[cause] = {
      count,
      firstAt: clampInt(e.firstAt, Number.MAX_SAFE_INTEGER) ?? 0,
      lastAt: clampInt(e.lastAt, Number.MAX_SAFE_INTEGER) ?? 0,
    };
  }
  return out;
}

// ---- G099: bindingAlarms --------------------------------------------------------------------------------
// The post-write binding-safety alarms verifyAfter raises when a plan APPLIED and the read-back did not agree
// -- a binding the plan added that is absent, a removal that survived, a lost-update race. This is the owner's
// #1 fear (a deploy that silently drops a source binding) with the operator's own binding labels attached, so
// support can say WHICH binding to re-attach. The names are SHAPE-gated, the same class as sourcesDetached.
export async function fetchBindingAlarms(scheduler: DurableObjectStub): Promise<unknown[]> {
  const r = await scheduler.fetch(doURL("/binding-alarms"), { method: "GET" });
  const j = (await r.json()) as { alarms?: unknown };
  const rows = Array.isArray(j.alarms) ? j.alarms : [];
  const out: unknown[] = [];
  for (const raw of rows.slice(-BINDING_ALARMS_RING_CAP)) {
    const a = (typeof raw === "object" && raw !== null ? raw : {}) as { at?: unknown; kind?: unknown; bindingNames?: unknown };
    const kind = gated(a.kind, BINDING_ALARM_KIND_SET);
    if (kind === undefined) continue;
    const bindingNames = (Array.isArray(a.bindingNames) ? a.bindingNames : []).flatMap((n) => {
      const s = shaped(n, BINDING_NAME_SHAPE);
      return s !== undefined ? [s] : [];
    }).slice(0, 16);
    out.push({
      at: clampInt(a.at, Number.MAX_SAFE_INTEGER) ?? 0,
      kind,
      ...(bindingNames.length > 0 ? { bindingNames } : {}),
    });
  }
  return out;
}

// ---- G050 / G054 / G101 / G159 / G162: updateFaults -----------------------------------------------------
// The self-update pipeline's failing STEP and closed cause. Four things ride that the existing 4.26
// updates.last block structurally cannot carry: `rollbackFailed` (the engine is LIVE on a bad version and its
// auto-rollback ALSO failed), the `bookkeeping` rows (the deploy went live and the record of it was lost --
// which half is named by recordPhase), `droppedSources` (WHICH source bindings an update dropped: the owner's
// #1 fear, previously a bare count on an HTTP response nobody kept), and `readbackShape` (a bounded descriptor
// of an unrecognised Cloudflare read-back: a key COUNT and three booleans, never a Cloudflare key NAME).
export async function fetchUpdateFaults(scheduler: DurableObjectStub): Promise<unknown[]> {
  const r = await scheduler.fetch(doURL("/update-faults"), { method: "GET" });
  const j = (await r.json()) as { faults?: unknown };
  const rows = Array.isArray(j.faults) ? j.faults : [];
  const out: unknown[] = [];
  for (const raw of rows.slice(-UPDATE_FAULTS_RING_CAP)) {
    const f = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
    const component = gated(f.component, UPDATE_COMPONENT_SET);
    const step = gated(f.step, UPDATE_STEP_SET);
    const cause = gated(f.cause, UPDATE_CAUSE_SET);
    if (component === undefined || step === undefined || cause === undefined) continue; // closed vocabulary only
    const cfCodes = (Array.isArray(f.cfCodes) ? f.cfCodes : [])
      .filter((c): c is number => typeof c === "number" && Number.isFinite(c))
      .slice(0, 8)
      .map((c) => Math.max(0, Math.min(1_000_000, Math.floor(c))));
    const droppedSources = (Array.isArray(f.droppedSources) ? f.droppedSources : []).flatMap((n) => {
      const s = shaped(n, BINDING_NAME_SHAPE);
      return s !== undefined ? [s] : [];
    }).slice(0, 64);
    const rb = (typeof f.readbackShape === "object" && f.readbackShape !== null ? f.readbackShape : null) as Record<string, unknown> | null;
    out.push({
      at: clampInt(f.at, Number.MAX_SAFE_INTEGER) ?? 0,
      component,
      step,
      cause,
      ...(f.httpStatus !== undefined ? { httpStatus: clampInt(f.httpStatus, 599) ?? 0 } : {}),
      ...(cfCodes.length > 0 ? { cfCodes } : {}),
      ...(shaped(f.observedSha384, SHA384_SHAPE) !== undefined ? { observedSha384: f.observedSha384 } : {}),
      ...(gated(f.recordPhase, UPDATE_PHASE_SET) !== undefined ? { recordPhase: f.recordPhase } : {}),
      ...(droppedSources.length > 0 ? { droppedSources } : {}),
      ...(rb !== null
        ? {
            readbackShape: {
              topLevelKeys: clampInt(rb.topLevelKeys, 64) ?? 0,
              hasSuccess: rb.hasSuccess === true,
              hasResult: rb.hasResult === true,
              hasErrors: rb.hasErrors === true,
            },
          }
        : {}),
      ...(f.rollbackFailed === true ? { rollbackFailed: true } : {}),
    });
  }
  return out;
}

// ---- G245: adminRefusals (the Worker EDGE half) ---------------------------------------------------------
// A durable refusal trail for the admin writes that previously existed only in an HTTP response the customer
// may not have kept. The key is "<surface>:<reason>" over TWO closed sets, so the key space is bounded by
// their product. `restore-apply:gate-unavailable` is the DR-hour headline: a restore refused "not approved"
// BECAUSE the approval gate could not be READ is an ENGINE fault, and until now it was indistinguishable from
// a genuinely missing approval. Disjoint from the DO-side schedAdminRefusals (which records what the DO
// refused); the two share no key and the pack carries both.
export async function fetchAdminRefusals(scheduler: DurableObjectStub): Promise<Record<string, { count: number; lastAt?: string }>> {
  const r = await scheduler.fetch(doURL("/admin-refusals"), { method: "GET" });
  return gateCountAgg(await r.json(), ADMIN_REFUSAL_KEY_SET);
}

// ---- G011 / G012 / G056 / G057 / G087 / G088 / G089 / G111: integrityFaults ------------------------------
// The seal / verify / restore core's fault LOCUS, per downpipe. Six things a coarse "integrity check failed"
// could never say: WHY a RUNLOG read failed (cold-storage vs access-denied -- and the classifier tests
// cold-storage FIRST, because several stores answer a restore-required object with a 403); WHICH of the 16
// verify stages failed; whether the class was TYPED or merely keyword-guessed (`classifiedBy`, a
// lower-confidence caveat on the class you are reading); the crypto-provisioning fault with the PUBLIC-material
// fingerprints ("you hold X, this archive is wrapped to Y"); the streaming CHUNK INDEX (chunk 0 = the object
// was mangled from its first byte; chunk 4,000 of 4,001 = a truncated tail); and defaultedEmptyRecords -- the
// silent zero-byte seal, a record with no value and no stream that was hashed, sealed, signed and reported
// GREEN, and whose emptiness the customer discovers months later at restore.
export async function fetchIntegrityFaults(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/integrity-faults"), { method: "GET" });
  const j = (await r.json()) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [id, v] of Object.entries(typeof j === "object" && j !== null ? j : {}).slice(0, INTEGRITY_FAULTS_DOWNPIPE_CAP)) {
    const e = (typeof v === "object" && v !== null ? v : {}) as Record<string, unknown>;
    const fetchFaults = gateCounts(e.fetchFaults, INTEGRITY_FETCH_KEY_SET);
    const failStages = gateCounts(e.failStages, VERIFY_FAIL_STAGE_SET);
    const classifiedBy = gateCounts(e.classifiedBy, CLASSIFIED_BY_SET);
    const locators = (Array.isArray(e.locators) ? e.locators : []).slice(-16).flatMap((raw) => {
      const l = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
      const kind = gated(l.kind, INTEGRITY_KIND_SET);
      if (kind === undefined) return [];
      return [{
        kind,
        ...(l.shardOrdinal !== undefined ? { shardOrdinal: clampInt(l.shardOrdinal, Number.MAX_SAFE_INTEGER) ?? 0 } : {}),
        ...(l.declaredCount !== undefined ? { declaredCount: clampInt(l.declaredCount, Number.MAX_SAFE_INTEGER) ?? 0 } : {}),
        ...(l.recoveredCount !== undefined ? { recoveredCount: clampInt(l.recoveredCount, Number.MAX_SAFE_INTEGER) ?? 0 } : {}),
        ...(shaped(l.digest, HEX12_SHAPE) !== undefined ? { digest: l.digest } : {}),
      }];
    });
    const cryptoFaults = (Array.isArray(e.cryptoFaults) ? e.cryptoFaults : []).slice(-16).flatMap((raw) => {
      const c = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
      const cls = gated(c.cls, CRYPTO_CLASS_SET);
      const role = gated(c.role, CRYPTO_ROLE_SET);
      if (cls === undefined || role === undefined) return [];
      return [{
        cls,
        role,
        ...(shaped(c.heldFingerprint, FINGERPRINT_SHAPE) !== undefined ? { heldFingerprint: c.heldFingerprint } : {}),
        ...(shaped(c.wantFingerprint, FINGERPRINT_SHAPE) !== undefined ? { wantFingerprint: c.wantFingerprint } : {}),
        ...(c.lengthClass !== undefined ? { lengthClass: clampInt(c.lengthClass, 1_000_000) ?? 0 } : {}),
      }];
    });
    const streamFaults = (Array.isArray(e.streamFaults) ? e.streamFaults : []).slice(-16).flatMap((raw) => {
      const s = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
      const leg = gated(s.leg, STREAM_LEG_SET);
      const cls = gated(s.cls, STREAM_CLASS_SET);
      if (leg === undefined || cls === undefined) return [];
      return [{
        leg,
        cls,
        ...(s.segmentOrdinal !== undefined ? { segmentOrdinal: clampInt(s.segmentOrdinal, Number.MAX_SAFE_INTEGER) ?? 0 } : {}),
        ...(s.chunkIndex !== undefined ? { chunkIndex: clampInt(s.chunkIndex, Number.MAX_SAFE_INTEGER) ?? 0 } : {}),
        ...(s.receivedBytes !== undefined ? { receivedBytes: clampInt(s.receivedBytes, Number.MAX_SAFE_INTEGER) ?? 0 } : {}),
        ...(s.expectedBytes !== undefined ? { expectedBytes: clampInt(s.expectedBytes, Number.MAX_SAFE_INTEGER) ?? 0 } : {}),
      }];
    });
    const defaultedEmptyRecords = clampInt(e.defaultedEmptyRecords, 1_000_000) ?? 0;
    // runlogAnomalies (G102): the ANTI-ROLLBACK / RUNLOG chain forensics. The detector's own `reason` string
    // interpolates the customer's run and downpipe ids and is NEVER recorded; what rides is the closed kind,
    // the two DISAGREEING indices, the failing line's ordinal, the chain length, and a 12-hex digest of the
    // RUNLOG BYTES (so the customer can hash their own _RECOVERY/RUNLOG and prove it is the same document).
    // sig-invalid vs index-regression vs duplicate-index are three different tickets that were one silent read.
    const runlogAnomalies = (Array.isArray(e.runlogAnomalies) ? e.runlogAnomalies : []).slice(-8).flatMap((raw) => {
      const a = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
      const kind = gated(a.kind, RUNLOG_ANOMALY_SET);
      if (kind === undefined) return []; // a drifted/hostile kind is DROPPED, never coerced
      return [{
        kind,
        ...(a.indexA !== undefined ? { indexA: clampInt(a.indexA, Number.MAX_SAFE_INTEGER) ?? 0 } : {}),
        ...(a.indexB !== undefined ? { indexB: clampInt(a.indexB, Number.MAX_SAFE_INTEGER) ?? 0 } : {}),
        ...(a.lineOrdinal !== undefined ? { lineOrdinal: clampInt(a.lineOrdinal, Number.MAX_SAFE_INTEGER) ?? 0 } : {}),
        ...(a.entryCount !== undefined ? { entryCount: clampInt(a.entryCount, Number.MAX_SAFE_INTEGER) ?? 0 } : {}),
        ...(shaped(a.digest, HEX12_SHAPE) !== undefined ? { digest: a.digest } : {}),
      }];
    });
    // writerRefusals (G166): the writer's three LOUD refusals, which collapsed into a generic run failure.
    // source-enumerated-zero is the CUSTOMER-side fault (an emptied KV namespace, a de-scoped token) that
    // reached support as "the engine broke". The refusal message interpolates the record NAME (an object key)
    // and never rides: the closed kind IS the whole row.
    const writerRefusals = gateCounts(e.writerRefusals, WRITER_REFUSAL_SET);
    // attestCoverage (G320): what the attestation's complete:true actually CLAIMS. sampled-no-presence is the
    // OVERCLAIM -- a strided sample with no per-shard presence pass, the mode in which a durably missing shard
    // outside the sample reads as complete. "full" is never recorded, so a healthy fleet stays silent here.
    const attestCoverage = gated(e.attestCoverage, KEYLESS_COVERAGE_SET);
    const block: Record<string, unknown> = {
      ...(Object.keys(fetchFaults).length > 0 ? { fetchFaults } : {}),
      ...(Object.keys(failStages).length > 0 ? { failStages } : {}),
      ...(Object.keys(classifiedBy).length > 0 ? { classifiedBy } : {}),
      ...(locators.length > 0 ? { locators } : {}),
      ...(cryptoFaults.length > 0 ? { cryptoFaults } : {}),
      ...(streamFaults.length > 0 ? { streamFaults } : {}),
      ...(runlogAnomalies.length > 0 ? { runlogAnomalies } : {}),
      ...(Object.keys(writerRefusals).length > 0 ? { writerRefusals } : {}),
      ...(attestCoverage !== undefined ? { attestCoverage } : {}),
      ...(defaultedEmptyRecords > 0 ? { defaultedEmptyRecords } : {}),
      ...(shaped(e.formatVersionSeen, FORMAT_MAJOR_SHAPE) !== undefined ? { formatVersionSeen: e.formatVersionSeen } : {}),
      at: clampInt(e.at, Number.MAX_SAFE_INTEGER) ?? 0,
    };
    // Omit a downpipe whose record survived the gate carrying only a timestamp (a fully drifted row).
    if (Object.keys(block).filter((k) => k !== "at").length === 0) continue;
    out[id.slice(0, 128)] = block;
  }
  return out;
}

// ---- G072: dispatchFaults -------------------------------------------------------------------------------
// The Worker's four last-resort catches, which previously produced a 500 and nothing else. The non-admin
// dispatch surface is SELF-REFERENTIAL: it covers /support/diagnostics itself, so a support endpoint that
// 500s is recorded and surfaces in the NEXT successful pull. The errId is the engine's own 8-hex FNV exception
// id -- the ONLY join key to the Workers-Logs line the pack structurally cannot carry.
export async function fetchDispatchFaults(scheduler: DurableObjectStub): Promise<unknown[]> {
  const r = await scheduler.fetch(doURL("/dispatch-faults"), { method: "GET" });
  const j = (await r.json()) as { faults?: unknown };
  const rows = Array.isArray(j.faults) ? j.faults : [];
  const out: unknown[] = [];
  for (const raw of rows.slice(-DISPATCH_FAULTS_CAP)) {
    const f = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
    const surface = gated(f.surface, DISPATCH_SURFACE_SET);
    if (surface === undefined) continue;
    out.push({
      at: clampInt(f.at, Number.MAX_SAFE_INTEGER) ?? 0,
      surface,
      ...(gated(f.routeFamily, DISPATCH_FAMILY_SET) !== undefined ? { routeFamily: f.routeFamily } : {}),
      ...(shaped(f.errId, ERR_ID_SHAPE) !== undefined ? { errId: f.errId } : {}),
      ...(f.httpStatus !== undefined ? { httpStatus: clampInt(f.httpStatus, 599) ?? 0 } : {}),
    });
  }
  return out;
}

// ---- G084 / G132 / G205 / G220 / G234 / G278: cronHealth ------------------------------------------------
// The cron plane's own health, which the pack previously reduced to one anonymous scheduler.ticks.passErrors
// integer. `passes` attributes every failure to a CLOSED pass name AND a closed error class, so "no alerts /
// no restore tests / no exports for days" finally names which pass and why (consecutiveFailures > 0 is the
// chronic signal). `tick` records the ring's HOLES -- an invocation whose DO preamble failed did nothing and
// recorded nothing, and the DO derives gapDetected/missedApprox from its OWN clock, so a wedged or hostile
// edge clock can neither fabricate nor conceal a missed tick. `siem` carries the four silent SIEM-push
// fallbacks (a non-zero cursor-reset IS the duplicate-delivery ticket; a batch-cap-truncated is audit LOSS).
export async function fetchCronHealth(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/cron-health"), { method: "GET" });
  const j = (await r.json()) as Record<string, unknown>;
  const out: Record<string, unknown> = {};

  const passes: Record<string, unknown> = {};
  if (typeof j.passes === "object" && j.passes !== null) {
    for (const [name, v] of Object.entries(j.passes as Record<string, unknown>)) {
      if (!CRON_PASS_NAME_SET.has(name)) continue; // closed pass vocabulary only
      const p = (typeof v === "object" && v !== null ? v : {}) as Record<string, unknown>;
      passes[name] = {
        consecutiveFailures: clampInt(p.consecutiveFailures, 1_000_000) ?? 0,
        failCount: clampInt(p.failCount, 1_000_000_000) ?? 0,
        ...(clampTs(p.lastErrorAt) !== undefined ? { lastErrorAt: clampTs(p.lastErrorAt) } : {}),
        ...(clampTs(p.lastOkAt) !== undefined ? { lastOkAt: clampTs(p.lastOkAt) } : {}),
        ...(gated(p.lastErrorClass, CRON_PASS_ERROR_SET) !== undefined ? { lastErrorClass: p.lastErrorClass } : {}),
      };
    }
  }
  if (Object.keys(passes).length > 0) out.passes = passes;

  const t = (typeof j.tick === "object" && j.tick !== null ? j.tick : {}) as Record<string, unknown>;
  const tick: Record<string, unknown> = {
    ...(clampTs(t.lastAt) !== undefined ? { lastAt: clampTs(t.lastAt) } : {}),
    ...(t.intervalMs !== undefined ? { intervalMs: clampInt(t.intervalMs, 86_400_000) ?? 0 } : {}),
    gapDetected: t.gapDetected === true,
    missedApprox: clampInt(t.missedApprox, 672) ?? 0,
    recordFailures: clampInt(t.recordFailures, 1_000_000) ?? 0,
    ...(clampTs(t.recordFailuresLastAt) !== undefined ? { recordFailuresLastAt: clampTs(t.recordFailuresLastAt) } : {}),
  };
  if (tick.lastAt !== undefined || tick.gapDetected === true || (tick.recordFailures as number) > 0) out.tick = tick;

  const d = (typeof j.discovery === "object" && j.discovery !== null ? j.discovery : {}) as Record<string, unknown>;
  const skips = gateCounts(d.skips, DISCOVERY_SKIP_SET);
  const consecutiveSkips = clampInt(d.consecutiveSkips, 1_000_000) ?? 0;
  if (Object.keys(skips).length > 0 || consecutiveSkips > 0) {
    out.discovery = {
      skips,
      consecutiveSkips,
      ...(clampTs(d.lastAttemptAt) !== undefined ? { lastAttemptAt: clampTs(d.lastAttemptAt) } : {}),
    };
  }

  // beacon: envPresent is the PARTIAL-configuration answer. The opt-in gate is all-or-nothing, so a beacon
  // with one env var typo'd is indistinguishable from a deliberately-off one -- which is the whole of "we
  // opted in but the vendor assurance view never lit up". Presence BOOLEANS; never the values.
  const b = (typeof j.beacon === "object" && j.beacon !== null ? j.beacon : {}) as Record<string, unknown>;
  const bEnv = (typeof b.envPresent === "object" && b.envPresent !== null ? b.envPresent : {}) as Record<string, unknown>;
  const failCounts = gateCounts(b.failCounts, BEACON_FAIL_SET);
  const stateWriteFailures = clampInt(b.stateWriteFailures, 1_000_000) ?? 0;
  if (Object.keys(failCounts).length > 0 || stateWriteFailures > 0 || bEnv.url === true || bEnv.ingestKey === true || bEnv.accountId === true) {
    out.beacon = {
      envPresent: { url: bEnv.url === true, ingestKey: bEnv.ingestKey === true, accountId: bEnv.accountId === true },
      ...(gated(b.lastFailClass, BEACON_FAIL_SET) !== undefined ? { lastFailClass: b.lastFailClass } : {}),
      failCounts,
      stateWriteFailures,
      ...(clampTs(b.stateWriteFailuresLastAt) !== undefined ? { stateWriteFailuresLastAt: clampTs(b.stateWriteFailuresLastAt) } : {}),
    };
  }

  // autoHeal: a STALL is not a refusal. A refusal already carries a closed code and a durable marker; a stall
  // just returns and leaves recovery latched forever -- and on a crowded fleet the budget-reserve bail can
  // fire on EVERY tick, so the auto-heal literally never runs. amnesiaProbeWriteFailures is why the pack's
  // amnesiaProbe field can be silently STALE (a lie by omission on the disaster-recovery path).
  const a = (typeof j.autoHeal === "object" && j.autoHeal !== null ? j.autoHeal : {}) as Record<string, unknown>;
  const deferrals = gateCounts(a.deferrals, AUTOHEAL_DEFERRAL_SET);
  const amnesiaProbeWriteFailures = clampInt(a.amnesiaProbeWriteFailures, 1_000_000) ?? 0;
  if (Object.keys(deferrals).length > 0 || amnesiaProbeWriteFailures > 0 || clampTs(a.lastAttemptAt) !== undefined) {
    out.autoHeal = {
      ...(clampTs(a.lastAttemptAt) !== undefined ? { lastAttemptAt: clampTs(a.lastAttemptAt) } : {}),
      ...(gated(a.lastDeferral, AUTOHEAL_DEFERRAL_SET) !== undefined ? { lastDeferral: a.lastDeferral } : {}),
      deferrals,
      ...(gated(a.resumeApplyLastReasonCode, RESUME_APPLY_REASON_SET) !== undefined ? { resumeApplyLastReasonCode: a.resumeApplyLastReasonCode } : {}),
      amnesiaProbeWriteFailures,
    };
  }

  const siem = gateCountAgg(j.siem, SIEM_FALLBACK_SET);
  if (Object.keys(siem).length > 0) out.siem = siem;

  const dangling = clampInt(j.danglingDestinationRefs, 1_000_000) ?? 0;
  if (dangling > 0) out.danglingDestinationRefs = dangling;

  // ---- the ROUND-5 cron evidence ------------------------------------------------------------------------
  // Each block is the DELIVERY half of a recorder that already fires on the cron's real fault path. Every enum
  // is re-gated against the vocabulary its recording site used, every count clamped, every block omitted when
  // empty (the healthy steady state is silence, not a wall of zeroes).
  //
  // notify (G184 + G294): the CRITICAL alerts that were CLAIMED and never delivered. `claimSpent` is the one to
  // read: the one-shot claim (the once-per-event budget) was already spent, so the page is PERMANENTLY lost --
  // a bad update is live and the owner is never paged, and nothing anywhere said so. historyAppendFailures is
  // the opposite fault: the alert WAS delivered and only its row was lost.
  const n = (typeof j.notify === "object" && j.notify !== null ? j.notify : {}) as Record<string, unknown>;
  const undeliveredCritical = gateCountAgg(n.undeliveredCritical, NOTIFY_EVENT_SET);
  const droppedEmissions = gateCounts(n.droppedEmissions, NOTIFY_EVENT_SET);
  const claimSpent = clampInt(n.claimSpent, 1_000_000) ?? 0;
  const historyAppendFailures = clampInt(n.historyAppendFailures, 1_000_000) ?? 0;
  const digestNoTransport = clampInt(n.digestNoTransport, 1_000_000) ?? 0;
  if (Object.keys(undeliveredCritical).length > 0 || Object.keys(droppedEmissions).length > 0 || claimSpent > 0 || historyAppendFailures > 0 || digestNoTransport > 0) {
    out.notify = {
      ...(Object.keys(undeliveredCritical).length > 0 ? { undeliveredCritical } : {}),
      ...(Object.keys(droppedEmissions).length > 0 ? { droppedEmissions } : {}),
      claimSpent,
      historyAppendFailures,
      ...(clampTs(n.historyAppendFailuresLastAt) !== undefined ? { historyAppendFailuresLastAt: clampTs(n.historyAppendFailuresLastAt) } : {}),
      digestNoTransport,
    };
  }

  // updates (G319): the update channel's own VERIFICATION verdict, checked on every tick the channel is
  // configured. A channel that stopped verifying (a signing-key rotation, or tamper) made the pass return in
  // silence: no alert, no evidence. confirmClearFailures is why an applied update can read "verification
  // pending" forever. The channel document itself never rides -- a boolean, two counts and two timestamps.
  const u = (typeof j.updates === "object" && j.updates !== null ? j.updates : {}) as Record<string, unknown>;
  const verifyFailures = clampInt(u.verifyFailures, 1_000_000) ?? 0;
  const confirmClearFailures = clampInt(u.confirmClearFailures, 1_000_000) ?? 0;
  if (clampTs(u.lastCheckAt) !== undefined || verifyFailures > 0 || confirmClearFailures > 0 || typeof u.channelVerified === "boolean") {
    out.updates = {
      ...(clampTs(u.lastCheckAt) !== undefined ? { lastCheckAt: clampTs(u.lastCheckAt) } : {}),
      ...(typeof u.channelVerified === "boolean" ? { channelVerified: u.channelVerified } : {}),
      verifyFailures,
      confirmClearFailures,
      ...(clampTs(u.confirmClearFailuresLastAt) !== undefined ? { confirmClearFailuresLastAt: clampTs(u.confirmClearFailuresLastAt) } : {}),
    };
  }

  // cpExport (G292): the control-plane export pass. `truncated` + destsSkippedByBudget matter because the
  // export-health record LOOKED complete when the budget cut it short -- and that record is what decides the
  // self-backup posture check's allDestinationsWrote, so a truncated-away FAILED destination read as fully
  // covered (a MISSING RECOVERY COPY, invisible). plaintextPurgePending counts readable roster/topology
  // generations left behind in a bucket the customer believes is sealed. worm-denied is deliberately its own
  // fail class: it arrives as a 403 and the shared classifier would file it under auth and send the operator
  // to rotate a perfectly good key.
  const cp = (typeof j.cpExport === "object" && j.cpExport !== null ? j.cpExport : {}) as Record<string, unknown>;
  const perDestFail = gateCounts(cp.perDestFail, CP_EXPORT_FAIL_SET);
  const destsSkippedByBudget = clampInt(cp.destsSkippedByBudget, 1_000_000) ?? 0;
  const plaintextPurgePending = clampInt(cp.plaintextPurgePending, 1_000_000) ?? 0;
  const cpRecordWriteFailures = clampInt(cp.recordWriteFailures, 1_000_000) ?? 0;
  const passThrewCount = clampInt(cp.passThrewCount, 1_000_000) ?? 0;
  if (clampTs(cp.lastAttemptAt) !== undefined || cp.truncated === true || Object.keys(perDestFail).length > 0 || destsSkippedByBudget > 0 || plaintextPurgePending > 0 || cpRecordWriteFailures > 0 || passThrewCount > 0) {
    out.cpExport = {
      ...(clampTs(cp.lastAttemptAt) !== undefined ? { lastAttemptAt: clampTs(cp.lastAttemptAt) } : {}),
      truncated: cp.truncated === true,
      destsSkippedByBudget,
      ...(Object.keys(perDestFail).length > 0 ? { perDestFail } : {}),
      plaintextPurgePending,
      recordWriteFailures: cpRecordWriteFailures,
      passThrewCount,
    };
  }

  // push (G293): the delivery-TRAIL writes that were themselves dropped. This is the duplicate-events ticket:
  // a lost trail write on a SUCCESSFUL delivery strands the cursor, so the next tick re-sends the same batch.
  const p = (typeof j.push === "object" && j.push !== null ? j.push : {}) as Record<string, unknown>;
  const siemTrailWriteFailures = clampInt(p.siemTrailWriteFailures, 1_000_000) ?? 0;
  const otlpTrailWriteFailures = clampInt(p.otlpTrailWriteFailures, 1_000_000) ?? 0;
  if (siemTrailWriteFailures > 0 || otlpTrailWriteFailures > 0) {
    out.push = {
      siemTrailWriteFailures,
      otlpTrailWriteFailures,
      ...(clampTs(p.lastAt) !== undefined ? { lastAt: clampTs(p.lastAt) } : {}),
    };
  }

  // restoreTest (G295): the drills that did NOT RUN. The pre-drill throw landed BEFORE all the recording
  // machinery, so the "we have not been tested for months" ticket wrote nothing at all. Keyed by the
  // customer's own downpipe id (the same label class downpipes[] and sealFaults already carry), control-
  // stripped and clamped at the DO chokepoint and re-capped here so a drifted record cannot unbound the section.
  const rt = (typeof j.restoreTest === "object" && j.restoreTest !== null ? j.restoreTest : {}) as Record<string, unknown>;
  const restoreTestSkips: Record<string, unknown> = {};
  if (typeof rt.skips === "object" && rt.skips !== null) {
    for (const [id, v] of Object.entries(rt.skips as Record<string, unknown>).slice(0, RESTORE_TEST_SKIP_CAP)) {
      const s = (typeof v === "object" && v !== null ? v : {}) as Record<string, unknown>;
      const cls = gated(s.cls, RESTORE_TEST_SKIP_SET);
      if (cls === undefined) continue; // a row with a drifted class is dropped WHOLE, never half-carried
      restoreTestSkips[stripControlLabel(id)] = {
        cls,
        count: clampInt(s.count, 1_000_000) ?? 0,
        ...(clampTs(s.lastAt) !== undefined ? { lastAt: clampTs(s.lastAt) } : {}),
      };
    }
  }
  const passBudgetDeferred = clampInt(rt.passBudgetDeferred, 1_000_000) ?? 0;
  const fleetBatchFailures = clampInt(rt.fleetBatchFailures, 1_000_000) ?? 0;
  if (Object.keys(restoreTestSkips).length > 0 || passBudgetDeferred > 0 || fleetBatchFailures > 0 || clampTs(rt.fleetLastBatchAt) !== undefined) {
    out.restoreTest = {
      ...(Object.keys(restoreTestSkips).length > 0 ? { skips: restoreTestSkips } : {}),
      passBudgetDeferred,
      ...(clampTs(rt.fleetLastBatchAt) !== undefined ? { fleetLastBatchAt: clampTs(rt.fleetLastBatchAt) } : {}),
      fleetBatchFailures,
    };
  }

  // reconcile (G333): the flag ECHO first -- an empty reconcile section was ambiguous, because "never turned
  // on" and "on and bailing for weeks" were the identical read. The RUNLOG-signature verdict is SPLIT because
  // the two halves are opposite instructions: sig-absent means re-sign it; verify-failed means a signer
  // rotation or TAMPER, so do not proceed. The abstain free text can describe the customer's topology and
  // never rides -- the circuit-breaker trip is a boolean.
  const rc = (typeof j.reconcile === "object" && j.reconcile !== null ? j.reconcile : {}) as Record<string, unknown>;
  const reconcileSkips = gateCounts(rc.skips, RECONCILE_SKIP_SET);
  const runlogSigAbsent = clampInt(rc.runlogSigAbsent, 1_000_000) ?? 0;
  const runlogVerifyFailed = clampInt(rc.runlogVerifyFailed, 1_000_000) ?? 0;
  const persistFailures = clampInt(rc.persistFailures, 1_000_000) ?? 0;
  if (typeof rc.enabled === "boolean" || Object.keys(reconcileSkips).length > 0 || runlogSigAbsent > 0 || runlogVerifyFailed > 0 || persistFailures > 0 || rc.circuitBreakerTripped === true) {
    out.reconcile = {
      ...(typeof rc.enabled === "boolean" ? { enabled: rc.enabled } : {}),
      ...(clampTs(rc.lastPassAt) !== undefined ? { lastPassAt: clampTs(rc.lastPassAt) } : {}),
      ...(gated(rc.lastSkipReason, RECONCILE_SKIP_SET) !== undefined ? { lastSkipReason: rc.lastSkipReason } : {}),
      ...(Object.keys(reconcileSkips).length > 0 ? { skips: reconcileSkips } : {}),
      runlogSigAbsent,
      runlogVerifyFailed,
      persistFailures,
      circuitBreakerTripped: rc.circuitBreakerTripped === true,
    };
  }
  return out;
}

// stripControlLabel removes the C0/C1 control codepoints from a customer-owned label (a downpipe id) before it
// becomes a KEY in the pack, and clamps it. Filtered by CODEPOINT rather than a regex character class, matching
// the idiom the sibling gatherers already use: a control character written literally into a regex is both
// unreadable and a classic source of silent corruption, and "no control bytes reach the pack" is clearer said
// outright. The DO chokepoint already does this; doing it again here is the defence-in-depth the pack boundary
// owes every customer-owned label, because a drifted or tampered record must never inject a line break (or a
// terminal escape) into an operator's rendered view.
function stripControlLabel(v: string): string {
  let out = "";
  for (const ch of v) {
    const c = ch.codePointAt(0) ?? 0;
    if (c < 0x20 || c === 0x7f) continue;
    out += ch;
  }
  return out.slice(0, 128);
}

// ---- G133 / G151: destProbeFaults -----------------------------------------------------------------------
// Per destination, the CLOSED reason the failover write-probe refused it. "All destinations unreachable" now
// names a cause per destination: an expired STS credential (rotate it), a deleted bucket (recreate it) and a
// DNS fault (wait) are three different remedies that produced identical evidence. Keyed by the operator's own
// destination id; the probe's error message never leaves the classifier.
export async function fetchDestProbeFaults(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/dest-probe-faults"), { method: "GET" });
  const j = (await r.json()) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [id, v] of Object.entries(typeof j === "object" && j !== null ? j : {}).slice(0, DEST_PROBE_FAULTS_CAP)) {
    const e = (typeof v === "object" && v !== null ? v : {}) as { reason?: unknown; count?: unknown; at?: unknown };
    const reason = gated(e.reason, DEST_PROBE_REASON_SET);
    if (reason === undefined) continue; // closed vocabulary only
    out[id.slice(0, 128)] = {
      reason,
      count: clampInt(e.count, 1_000_000_000) ?? 0,
      at: clampInt(e.at, Number.MAX_SAFE_INTEGER) ?? 0,
    };
  }
  return out;
}

// ---- G136 / G137: destBuildHealth -----------------------------------------------------------------------
// The destination's own CONSTRUCTION health. `failingSinceAt` is the START of the current failing streak and
// is the one fact a coarse run error can never carry: "every backup has been failing to even BUILD its
// destination since Tuesday, because DEST_ENDPOINT is gone" (the highest-impact failure mode, fully instrumented).
// lastVarName is an ALLOW-LISTED engine knob name (never a value); lastStsFailureClass splits an AssumeRole
// refusal into a trust-policy denial vs a rotated principal vs a deleted role vs throttling.
export async function fetchDestBuildHealth(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/dest-build-health"), { method: "GET" });
  const j = (await r.json()) as { health?: unknown };
  const h = (typeof j.health === "object" && j.health !== null ? j.health : null) as Record<string, unknown> | null;
  if (h === null) return {}; // nothing has ever built a destination: honest absence
  return {
    lastAt: clampInt(h.lastAt, Number.MAX_SAFE_INTEGER) ?? 0,
    lastOutcome: h.lastOutcome === "failed" ? "failed" : "ok",
    ...(h.failingSinceAt !== undefined ? { failingSinceAt: clampInt(h.failingSinceAt, Number.MAX_SAFE_INTEGER) ?? 0 } : {}),
    ...(gated(h.lastCause, DEST_BUILD_CAUSE_SET) !== undefined ? { lastCause: h.lastCause } : {}),
    ...(gated(h.lastVarName, DEST_BUILD_VAR_SET) !== undefined ? { lastVarName: h.lastVarName } : {}),
    ...(gated(h.lastStsFailureClass, STS_CLASS_SET) !== undefined ? { lastStsFailureClass: h.lastStsFailureClass } : {}),
    ...(h.lastDoStatus !== undefined ? { lastDoStatus: clampInt(h.lastDoStatus, 599) ?? 0 } : {}),
    consecutiveFailures: clampInt(h.consecutiveFailures, 1_000_000_000) ?? 0,
    causes: gateCounts(h.causes, DEST_BUILD_CAUSE_SET),
    stsClasses: gateCounts(h.stsClasses, STS_CLASS_SET),
  };
}

// ---- G296: costSizing -----------------------------------------------------------------------------------
// The estate-sizing probe's outcome per source type. `measuredZero` is the load-bearing member: a Cloudflare
// Analytics schema drift returns a 0 that the console then presents to the customer as a MEASURED size ("this
// source is empty"), which is a different fact from an honestly unavailable one -- and the two were the same
// evidence. The source type is a closed engine token, so no customer identifier can become a key here.
export async function fetchCostSizing(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/cost-sizing"), { method: "GET" });
  const j = (await r.json()) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [type, v] of Object.entries(typeof j === "object" && j !== null ? j : {})) {
    if (!COST_SIZING_TYPE_SET.has(type)) continue; // closed source-type vocabulary only
    const e = (typeof v === "object" && v !== null ? v : {}) as Record<string, unknown>;
    const cls = gated(e.lastClass, COST_SIZING_CLASS_SET);
    if (cls === undefined) continue;
    out[type] = {
      sized: clampInt(e.sized, 1_000_000) ?? 0,
      unavailable: clampInt(e.unavailable, 1_000_000) ?? 0,
      measuredZero: clampInt(e.measuredZero, 1_000_000) ?? 0,
      lastClass: cls,
      ...(clampTs(e.lastAt) !== undefined ? { lastAt: clampTs(e.lastAt) } : {}),
    };
  }
  return out;
}

// ---- G183: adminRouteErrors ------------------------------------------------------------------------------
// The update / rollback / ramp / licence routes' outermost catches. Each returned a FIXED sentence -- "nothing
// was changed" -- and DISCARDED the exception, so "update apply always fails with a generic message" arrived
// with no server-side trace of any kind: not the locus, not the cause, not even the fact that it happened.
//
// Two things make this projection worth reading:
//
//   byRouteStage  the LOCUS, and the OWNER that goes with it. "update-apply|do-read" is the customer's own
//                 scheduler DO (the floor / status / pending reads); "update-apply|channel-fetch" is the
//                 signed channel (the vendor's, or the customer's egress); "update-apply|deploy-driver" is
//                 Cloudflare's deploy API; "licence-activate|persist" is the DO again, after a deploy landed.
//                 Different owners, previously one generic message.
//
  //                 The do-read / channel-fetch split is load-bearing: the anti-rollback floor read (a DO
  //                 read, uncaught by design so it fails the route closed) is bracketed to do-read in both
  //                 the apply and the ramp, distinct from the channel-fetch window, so a scheduler DO
  //                 outage is never misattributed to a CDN that was never involved.
//   mutatingFaults the HONESTY CHECK. A fault at deploy-driver or persist means the route's "nothing was
//                 changed" claim is NOT SAFE TO BELIEVE: the promote can land and the follow-up write can then
//                 throw (the promote redeploys the engine, which resets the very DO that write needs). A
//                 non-zero mutatingFaults beside a customer insisting nothing was deployed is the whole ticket.
//
// Redaction: two closed enums and integers. The exception text -- which interpolates version ids, Cloudflare
// messages and, on the licence path, could echo token material -- never persists and cannot be projected.
const ADMIN_ROUTE_ERROR_KEY_SET: ReadonlySet<string> = new Set(
  ADMIN_ROUTE_NAMES.flatMap((route) => ADMIN_ROUTE_STAGES.map((stage) => `${route}|${stage}`)),
);
const ADMIN_ROUTE_NAME_SET: ReadonlySet<string> = new Set(ADMIN_ROUTE_NAMES);
const ADMIN_ROUTE_STAGE_SET: ReadonlySet<string> = new Set(ADMIN_ROUTE_STAGES);

export async function fetchAdminRouteErrors(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const j = (await (await scheduler.fetch(doURL("/admin-route-errors"), { method: "GET" })).json()) as { errors?: unknown };
  const e = (typeof j.errors === "object" && j.errors !== null ? j.errors : null) as Record<string, unknown> | null;
  if (e === null) return {}; // no admin route has ever thrown: honest absence, and the good state

  const byRouteStage: Record<string, number> = {};
  for (const [k, v] of Object.entries((typeof e.byRouteStage === "object" && e.byRouteStage !== null ? e.byRouteStage : {}) as Record<string, unknown>)) {
    if (!ADMIN_ROUTE_ERROR_KEY_SET.has(k)) continue; // re-gated against the cross-product at the pack boundary too
    const n = clampInt(v, 1_000_000) ?? 0;
    if (n > 0) byRouteStage[k] = n;
  }
  const total = clampInt(e.total, 1_000_000) ?? 0;
  if (total === 0 && Object.keys(byRouteStage).length === 0) return {};
  const lastRoute = typeof e.lastRoute === "string" && ADMIN_ROUTE_NAME_SET.has(e.lastRoute) ? e.lastRoute : undefined;
  const lastStage = typeof e.lastStage === "string" && ADMIN_ROUTE_STAGE_SET.has(e.lastStage) ? e.lastStage : undefined;
  return {
    ...(Object.keys(byRouteStage).length > 0 ? { byRouteStage } : {}),
    total,
    mutatingFaults: clampInt(e.mutatingFaults, 1_000_000) ?? 0,
    ...(lastRoute !== undefined ? { lastRoute } : {}),
    ...(lastStage !== undefined ? { lastStage } : {}),
    ...(clampTs(e.lastAt) !== undefined ? { lastAt: clampTs(e.lastAt) } : {}),
  };
}
