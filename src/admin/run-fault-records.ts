// RUN-FAULT RECORDS (the SOURCE + DESTINATION evidence sink) -- gaps G015 / G042 / G068 / G110 / G144 /
// G096 / G170 / G213 / G327 (source) and G135 / G186 (destination).
//
// THE BUG THIS CLOSES. Wave-D built two per-run fault ledgers at the exact fault sites:
//   - sources/source-fault-ledger.ts : the closed REASON behind every incompleteness sentinel, the tolerant-
//     parse drops, the run-fatal transport class + stage, the D1 snapshot-consistency verdict, the resume-token
//     defects, the absorbed 429s, the security refusals;
//   - dest/fault-log.ts + dest/dest-io.ts : the closed IDENTITY of every failing destination op, and the
//     DEGRADATION counters of a destination that is quietly making a green run slow and expensive.
// Both were RECORDED and then DROPPED ON THE FLOOR. drainSourceFaultLedger() had NO CALLER anywhere in src/,
// destFaults() was read only by the SIEM push classifier, destIo() by nobody -- so none of that evidence ever
// reached a durable sink, and therefore none of it ever reached the support pack. Evidence that does not
// reach the bundle does not exist: a gap is not closed until a remote diagnosis can read it.
//
// THE SHAPE. The seal path (seal/run-fault-report.ts) DRAINS both ledgers at the end of every crawl -- the
// inline Worker slice, each RunSealDO slice, and the buffered whole-run path -- and posts the drained,
// already-coarse snapshot to the scheduler DO. This module is the DO-side REDACTION CHOKEPOINT: it re-gates
// EVERY field of that post against the closed vocabularies the recorders own, so even a drifted, malformed
// or hostile caller cannot land a message, a key, a bucket, an endpoint or a customer value in the record.
// The two aggregates are keyed by the customer's OWN downpipe id (the class the pack already carries in
// downpipes[] and sealErrors) and bounded in every dimension.
//
// NO-CUSTODY (binding). Every field below is a closed enum, a count, a clamped int, a boolean, or a bounded
// engine-chosen product token / one-way handle (the seal/marker.ts safeMarkerAttribution rule: a CLOSED
// product token rides raw and length-clamped; a CUSTOMER-owned name is reduced to a `h:<12 hex>` handle at
// the WRITE site, before it ever gets here). No raw error message, stack, status body, S3 <Code> outside the
// documented allow-list, header, request id, endpoint, bucket, object key or customer value can pass.

import type { DestClassifierArm, DestFault } from "../dest/classify.ts";
import { DEST_ANOMALIES, DEST_FAULT_SHAPES, DEST_OPS, S3_ERROR_CODES, type StrandedAborts, sanitiseStrandedAborts } from "../dest/fault-log.ts";
import { MARKER_ATTRIBUTION_MAX_PER_KIND, MARKER_KEYS } from "../seal/marker.ts";
import {
  CF_SELECTOR_MODES,
  D1_DEFECT_CLASSES,
  FAULT_ID_MAX_LEN,
  FAULT_IDS_MAX_PER_KIND,
  RESUME_TOKEN_DEFECTS,
  SNAPSHOT_CONSISTENCY_CLASSES,
  SOURCE_FAULT_REASONS,
  SOURCE_FAULT_STAGES,
  SOURCE_FAULT_STATUS_CLASSES,
  SOURCE_SECURITY_REFUSAL_KINDS,
} from "../sources/source-fault-ledger.ts";

// ---- storage keys + bounds -----------------------------------------------------------------------------

export const SOURCE_FAULTS_KEY = "diag:sourcefaults";
export const DEST_FAULTS_KEY = "diag:destfaults";
// RUN_FAULT_DOWNPIPES_MAX bounds each aggregate to the 64 most-recently-faulting downpipes. Only a downpipe
// whose crawl actually recorded a fault holds an entry (a clean run posts nothing at all), so this is far
// above any real fleet's FAULTING subset while keeping the record, and the pack section, bounded.
export const RUN_FAULT_DOWNPIPES_MAX = 64;

// SOURCE_TYPE_TOKENS is the engine's OWN closed source-adapter vocabulary (sources/types.ts SourceRecord
// .sourceType). It is a product token, never customer data, and gating on it is what stops a drifted writer
// from turning the `fatal.sourceType` / `resumeTokenSourceTypes` fields into a free-text seam.
export const SOURCE_TYPE_TOKENS = ["kv", "r2", "secrets", "d1", "cf-config", "workers", "stream", "images", "artifacts", "durable_object"] as const;

// DEST_CLASSIFIER_ARM_TOKENS / DEST_FAULT_CLASS_TOKENS mirror dest/classify.ts. They are re-declared as
// VALUES here (classify.ts exports them as TYPE unions only) so the applier can gate on them.
//
// THE PIN IS REAL NOW. The claim that used to sit here, that "the type annotations below pin the two
// together, so a member added there and forgotten here fails the typecheck", was not true: the tokens were a
// bare `as const` with no annotation at all, and nothing referred to the unions. The gate below DROPS a fault
// record whose arm or class is not in these sets (sanitiseDestFaults `continue`s the whole record), so the
// real consequence of a forgotten member was a destination fault silently absent from the support pack, which
// is the same shape of defect as a recorder writing into a void.
//
// Deriving the tokens from a TOTAL Record over each union is what makes the sentence true: a member added to
// dest/classify.ts and forgotten here is a missing property and fails the typecheck, and a token invented
// here that no longer exists there is an excess property and also fails. Object key order is insertion order
// for string keys, so the token arrays keep the declaration order.
const DEST_FAULT_CLASS_TOTAL: Record<DestFault, null> = { throttle: null, transient: null, auth: null, permanent: null, ok: null };
const DEST_CLASSIFIER_ARM_TOTAL: Record<DestClassifierArm, null> = {
  "matched-status": null,
  "typed-status": null,
  "embedded-status": null,
  "matched-retry-after": null,
  "matched-network": null,
  "default-permanent": null,
  "object-lock-refusal": null,
};
export const DEST_FAULT_CLASS_TOKENS = Object.keys(DEST_FAULT_CLASS_TOTAL) as readonly DestFault[];
export const DEST_CLASSIFIER_ARM_TOKENS = Object.keys(DEST_CLASSIFIER_ARM_TOTAL) as readonly DestClassifierArm[];

const MARKER_KEY_SET: ReadonlySet<string> = new Set(MARKER_KEYS);
const SOURCE_FAULT_REASON_SET: ReadonlySet<string> = new Set(SOURCE_FAULT_REASONS);
const SOURCE_FAULT_STAGE_SET: ReadonlySet<string> = new Set(SOURCE_FAULT_STAGES);
const SOURCE_FAULT_STATUS_SET: ReadonlySet<string> = new Set(SOURCE_FAULT_STATUS_CLASSES);
const SOURCE_TYPE_SET: ReadonlySet<string> = new Set(SOURCE_TYPE_TOKENS);
const SNAPSHOT_CONSISTENCY_SET: ReadonlySet<string> = new Set(SNAPSHOT_CONSISTENCY_CLASSES);
const RESUME_TOKEN_DEFECT_SET: ReadonlySet<string> = new Set(RESUME_TOKEN_DEFECTS);
const D1_DEFECT_SET: ReadonlySet<string> = new Set(D1_DEFECT_CLASSES);
const CF_SELECTOR_MODE_SET: ReadonlySet<string> = new Set(CF_SELECTOR_MODES);
const SECURITY_REFUSAL_SET: ReadonlySet<string> = new Set(SOURCE_SECURITY_REFUSAL_KINDS);
const DEST_OP_SET: ReadonlySet<string> = new Set(DEST_OPS);
const DEST_ANOMALY_SET: ReadonlySet<string> = new Set(DEST_ANOMALIES);
// AWS_REGION_SHAPE re-applies the region gate DO-side (defence in depth over dest/fault-log.ts's own
// regionHintFromLocation). A redirect Location embeds the customer's BUCKET and HOST; only a bare AWS region
// token may ever ride, so a URL, a host, a path or any punctuation is DROPPED here even if a future write site
// regressed and posted one.
const AWS_REGION_SHAPE = /^[a-z]{2}(?:-[a-z]+)+-\d{1,2}$/;
const S3_ERROR_CODE_SET: ReadonlySet<string> = new Set([...S3_ERROR_CODES, "other", "none"]);
const DEST_FAULT_CLASS_SET: ReadonlySet<string> = new Set(DEST_FAULT_CLASS_TOKENS);
const DEST_CLASSIFIER_ARM_SET: ReadonlySet<string> = new Set(DEST_CLASSIFIER_ARM_TOKENS);

const COUNT_MAX = 1_000_000;
const RATE_MAX = 100_000;
const RETRY_AFTER_MAX = 86_400;

// ATTRIBUTION_ID_SHAPE is the structural gate on an attribution id at the DO boundary (defence in depth over
// the ledger's own write-site discipline). An attribution id is only ever ONE of two things, both built by
// sources/source-fault-ledger.ts faultItemId:
//   - an ENGINE-CHOSEN product token, as up to four lower-case slash-separated segments ("workers/settings",
//     "cf-config/rulesets", "r2-bucket-config/lock"); or
//   - that token followed by a one-way HANDLE of a customer-owned name ("rulesets/h:ab12cd34ef56"), where the
//     name has already been reduced to 12 hex of SHA-384 at the WRITE site and can never be recovered.
//
// The gate is deliberately NARROW rather than a permissive charset. A charset gate that merely forbade
// whitespace would still admit `s3://acme-prod-invoices/payroll-Q3.xlsx` -- a bucket AND an object key, in
// the clear, which is precisely the class of value this seam exists to keep out. Requiring lower-case token
// segments (no scheme, no colon, no dot, no upper case) means a bucket, a key, a URL, an endpoint, a header
// or an error message structurally CANNOT match, so the seam stays un-smugglable even if a future writer
// regresses. The cost is that a legitimately-drifted engine token is dropped rather than carried, which is
// the correct trade: a dropped id costs a line of attribution, a leaked one costs custody.
const ATTRIBUTION_ID_SHAPE = /^[a-z0-9][a-z0-9_-]*(?:\/[a-z0-9][a-z0-9_-]*){0,3}(?:\/h:[0-9a-f]{12})?$/;

// D1_TABLE_HANDLE_SHAPE is the STRICTER gate for the D1 defect locus (G069). The generic shape above admits a
// BARE product token, and a customer's D1 table name ("customer_invoices_2026") is lower-case, alphanumeric and
// underscored -- so it looks exactly like one, and would sail straight through into the pack. A D1 table name
// is ALWAYS a customer schema label and is therefore ALWAYS reduced to a one-way handle at the write site, so
// the boundary REQUIRES the handle form. A raw name structurally cannot match.
const D1_TABLE_HANDLE_SHAPE = /^d1-table\/h:[0-9a-f]{12}$/;

// ---- record shapes -------------------------------------------------------------------------------------

/** The run-fatal source fault: the transport verdict + the crawl stage it died at (G144). */
export interface SourceFatalRow {
  sourceType: string;
  statusClass: string;
  stage: string;
  attempted?: number;
  succeeded?: number;
}

/** One downpipe's most recent drained source-fault ledger. Closed enums / counts / bounded tokens only. */
export interface SourceFaultsEntry {
  at: number;
  incompleteReasons?: Record<string, Record<string, number>>;
  incompleteIds?: Record<string, string[]>;
  shapeAnomalies?: number;
  shapeAnomalyIds?: string[];
  truncation?: { pagesRead: number; recordsAccumulated: number };
  oldestPendingAgeMs?: number;
  fatal?: SourceFatalRow;
  snapshotConsistency?: string;
  rowidProbeFallbacks?: number;
  resumeTokenDefects?: Record<string, number>;
  resumeTokenSourceTypes?: string[];
  throttle429Count?: number;
  retryExhaustedCount?: number;
  maxRetryAfterSeconds?: number;
  securityRefusals?: Record<string, number>;
  // cfSelectorMode (G006): WHICH cf-config surface selector the run actually used. Only the stale fail-safe is
  // recorded (see below): it is the cost-explosion signal ("runs suddenly take 10x longer and trip rate limits").
  cfSelectorMode?: string;
  // d1Defects / d1DefectTables (G069): the closed D1 decode-defect class -> count, plus the one-way HANDLES of
  // the tables the defect was found in, so the customer does not have to bisect their own schema.
  d1Defects?: Record<string, number>;
  d1DefectTables?: string[];
}
export type SourceFaults = Record<string, SourceFaultsEntry>;

/** One destination fault SHAPE (G135): the op, the coarse status, the allow-listed S3 code, the arm. */
export interface DestFaultRow {
  op: string;
  httpStatus: number;
  s3Code: string;
  fault: string;
  arm: string;
  requestIdPresent: boolean;
  wormChecksumComplaint: boolean;
  count: number;
}

/** One downpipe's most recent destination fault + degradation snapshot (G135 + G186 + G085/G119/G206/G207). */
export interface DestFaultsEntry {
  at: number;
  total?: number;
  overflow?: number;
  faults?: DestFaultRow[];
  /** G085/G119/G206/G207: {closed anomaly -> count}. A non-conformant store, a silently-truncated listing,
   * an engine guard refusal. Counters only. */
  anomalies?: Record<string, number>;
  /** G119: the region token of a redirect target (never the Location URL). */
  redirectRegionHint?: string;
  /** G207: the clamped size that tripped an engine ceiling. */
  overBoundBytes?: number;
  /** G085: pages the listing walk reached before the store truncated it without a cursor. */
  listPagesReached?: number;
  /** G343: the multipart aborts that THEMSELVES failed, stranding part storage the customer is billed for --
   * how many, and the closed class of the most recent (denied / server-error / network / other). The run row
   * carried only a boolean, so "fix the bucket policy" and "set a lifecycle rule" were indistinguishable. */
  strandedAborts?: StrandedAborts;
  io?: {
    throttleObservations?: number;
    retryAttemptsTotal?: number;
    timeouts?: number;
    conditionalPutConflicts?: number;
    headNon200CollapsedToAbsent?: number;
    retryAfterUnparseable?: number;
    minEffectiveRatePerSec?: number;
  };
}
export type DestFaults = Record<string, DestFaultsEntry>;

// ---- pure gates ----------------------------------------------------------------------------------------

function clampCount(v: unknown, max = COUNT_MAX): number {
  if (typeof v !== "number" || !Number.isFinite(v) || v < 0) return 0;
  return Math.min(max, Math.floor(v));
}

function gated(v: unknown, allowed: ReadonlySet<string>): string | undefined {
  return typeof v === "string" && allowed.has(v) ? v : undefined;
}

// safeAttributionId re-applies the ledger's OWN id discipline at the DO boundary: the structural shape gate
// above, then the 128-char clamp. Anything else is DROPPED (never coerced, never truncated-and-kept).
function safeAttributionId(v: unknown): string | undefined {
  if (typeof v !== "string" || v === "" || v.length > FAULT_ID_MAX_LEN) return undefined;
  return ATTRIBUTION_ID_SHAPE.test(v) ? v : undefined;
}

function safeIdList(v: unknown, cap: number): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: string[] = [];
  for (const raw of v) {
    const id = safeAttributionId(raw);
    if (id === undefined || out.includes(id)) continue;
    out.push(id);
    if (out.length >= cap) break;
  }
  return out.length > 0 ? out : undefined;
}

// countMap gates a {closed key -> count} map: only a vocabulary member rides, every count is clamped, a zero
// drops the row. The single shape every one of the ledger's tallies uses.
function countMap(v: unknown, allowed: ReadonlySet<string>): Record<string, number> | undefined {
  if (typeof v !== "object" || v === null) return undefined;
  const out: Record<string, number> = {};
  for (const [k, n] of Object.entries(v as Record<string, unknown>)) {
    if (!allowed.has(k)) continue;
    const c = clampCount(n);
    if (c > 0) out[k] = c;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

// ---- the appliers (the redaction chokepoint) ------------------------------------------------------------

/**
 * sanitiseSourceFaults re-gates ONE drained source-fault ledger into a bounded record. This is the single
 * chokepoint every source-fault byte passes through on its way to durable storage: an out-of-vocabulary
 * reason / marker kind / stage / status class / source type / defect / refusal kind is DROPPED, every count
 * is clamped, every attribution id must pass the structural shape gate, and any field the caller invented is
 * simply never read. Returns null when nothing survives (a clean crawl records nothing at all).
 *
 * @param raw - the posted, already-coarse ledger snapshot (untrusted).
 * @param now - epoch ms to stamp.
 * @returns the bounded entry, or null when the snapshot carries no evidence.
 */
export function sanitiseSourceFaults(raw: unknown, now: number): SourceFaultsEntry | null {
  const r = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
  const entry: SourceFaultsEntry = { at: clampCount(now, Number.MAX_SAFE_INTEGER) };

  // incompleteReasons: {closed marker kind -> {closed reason -> count}} (G015/G042/G068).
  const reasons: Record<string, Record<string, number>> = {};
  if (typeof r.incompleteReasons === "object" && r.incompleteReasons !== null) {
    for (const [kind, byReason] of Object.entries(r.incompleteReasons as Record<string, unknown>)) {
      if (!MARKER_KEY_SET.has(kind)) continue;
      const m = countMap(byReason, SOURCE_FAULT_REASON_SET);
      if (m !== undefined) reasons[kind] = m;
    }
  }
  if (Object.keys(reasons).length > 0) entry.incompleteReasons = reasons;

  // incompleteIds: {closed marker kind -> bounded product tokens / one-way handles}.
  const ids: Record<string, string[]> = {};
  if (typeof r.incompleteIds === "object" && r.incompleteIds !== null) {
    for (const [kind, list] of Object.entries(r.incompleteIds as Record<string, unknown>)) {
      if (!MARKER_KEY_SET.has(kind)) continue;
      const l = safeIdList(list, MARKER_ATTRIBUTION_MAX_PER_KIND);
      if (l !== undefined) ids[kind] = l;
    }
  }
  if (Object.keys(ids).length > 0) entry.incompleteIds = ids;

  // shapeAnomalies (G110): the tolerant-parse drops -- the ONLY trace that a silent Cloudflare API shape
  // drift is voiding coverage while every run still reports ok.
  const shapeAnomalies = clampCount(r.shapeAnomalies);
  if (shapeAnomalies > 0) entry.shapeAnomalies = shapeAnomalies;
  const shapeIds = safeIdList(r.shapeAnomalyIds, FAULT_IDS_MAX_PER_KIND);
  if (shapeIds !== undefined) entry.shapeAnomalyIds = shapeIds;

  // truncation (G015): the SHORTFALL MAGNITUDE. "Is our monorepo fully backed up?" is answerable only with
  // this; the object list itself stays archive-sealed.
  const t = (typeof r.truncation === "object" && r.truncation !== null ? r.truncation : null) as { pagesRead?: unknown; recordsAccumulated?: unknown } | null;
  if (t !== null) {
    const pagesRead = clampCount(t.pagesRead);
    const recordsAccumulated = clampCount(t.recordsAccumulated);
    if (pagesRead > 0 || recordsAccumulated > 0) entry.truncation = { pagesRead, recordsAccumulated };
  }

  const pending = clampCount(r.oldestPendingAgeMs, Number.MAX_SAFE_INTEGER);
  if (pending > 0) entry.oldestPendingAgeMs = pending;

  // fatal (G144): the run-fatal throw's transport verdict + crawl stage. This is the "my Images backup fails
  // after a token rotation" answer: a 401 expired token, a 403 missing scope, an entitlement gate, or a 5xx
  // outage -- and whether the token could not even LIST.
  const f = (typeof r.fatal === "object" && r.fatal !== null ? r.fatal : null) as Record<string, unknown> | null;
  if (f !== null) {
    const sourceType = gated(f.sourceType, SOURCE_TYPE_SET);
    const statusClass = gated(f.statusClass, SOURCE_FAULT_STATUS_SET);
    const stage = gated(f.stage, SOURCE_FAULT_STAGE_SET);
    // All three are required: a partial fatal row is a drifted writer, and a half-named fault is worse than
    // none (it invites a diagnosis of the wrong subsystem). Drop it whole.
    if (sourceType !== undefined && statusClass !== undefined && stage !== undefined) {
      const attempted = clampCount(f.attempted);
      const succeeded = clampCount(f.succeeded);
      entry.fatal = {
        sourceType,
        statusClass,
        stage,
        ...(attempted > 0 ? { attempted } : {}),
        ...(succeeded > 0 ? { succeeded } : {}),
      };
    }
  }

  // snapshotConsistency (G096): a DATA-INTEGRITY verdict that rides on runs which report OK. "pinned" is the
  // healthy state and is deliberately NOT recorded (it would make every clean D1 run non-empty); only a
  // DEGRADED verdict is evidence.
  const snap = gated(r.snapshotConsistency, SNAPSHOT_CONSISTENCY_SET);
  if (snap !== undefined && snap !== "pinned") entry.snapshotConsistency = snap;

  const rowid = clampCount(r.rowidProbeFallbacks);
  if (rowid > 0) entry.rowidProbeFallbacks = rowid;

  // resumeTokenDefects (G213): the closed defect class + a COUNT, which is what separates a one-off from a
  // WEDGE (every slice failing on the same corrupt token) and maps the ticket to its remedy.
  const defects = countMap(r.resumeTokenDefects, RESUME_TOKEN_DEFECT_SET);
  if (defects !== undefined) entry.resumeTokenDefects = defects;
  const defectTypes = safeIdList(r.resumeTokenSourceTypes, FAULT_IDS_MAX_PER_KIND)?.filter((t2) => SOURCE_TYPE_SET.has(t2));
  if (defectTypes !== undefined && defectTypes.length > 0) entry.resumeTokenSourceTypes = defectTypes;

  // d1Defects (G069): the closed defect class + a COUNT. The three classes route to COMPLETELY different
  // diagnoses -- multi-statement-ddl is a TAMPER signature in a signed archive, unknown-format is ENGINE
  // VERSION SKEW after a rollback, non-finite-real is a writer bug -- so an out-of-vocabulary class is DROPPED
  // rather than coerced: a wrong class here would send support to the wrong system with confidence.
  const d1 = countMap(r.d1Defects, D1_DEFECT_SET);
  if (d1 !== undefined) entry.d1Defects = d1;
  // The table LOCUS, gated on the STRICT handle shape. The generic attribution-id gate is not enough here: a
  // customer's table name is lower-case, alphanumeric and underscored, so it is structurally indistinguishable
  // from an engine product token and would pass. Requiring `d1-table/h:<12 hex>` means only a value that was
  // already one-way hashed at the write site can land, and a raw schema label CANNOT.
  const d1Tables = (Array.isArray(r.d1DefectTables) ? r.d1DefectTables : [])
    .filter((t2): t2 is string => typeof t2 === "string" && D1_TABLE_HANDLE_SHAPE.test(t2))
    .slice(0, FAULT_IDS_MAX_PER_KIND);
  if (d1Tables.length > 0) entry.d1DefectTables = [...new Set(d1Tables)];

  // cfSelectorMode (G006): like snapshotConsistency, the HEALTHY values are deliberately NOT recorded
  // (`configured` and `auto` are the modes a well-running downpipe uses, and recording them would make every
  // clean cf-config run non-empty). Only `stale-fallback-all` -- the discovery cache going stale and the run
  // silently crawling EVERY surface in the registry, every run -- is evidence.
  const mode = gated(r.cfSelectorMode, CF_SELECTOR_MODE_SET);
  if (mode === "stale-fallback-all") entry.cfSelectorMode = mode;

  // throttle pressure (G170): the absorbed 429s are the EARLY WARNING -- a chronically throttled account
  // looks healthy right up to the day the retries exhaust, because withRetry only surfaces the terminal
  // outcome. retryExhaustedCount is the day it did.
  const throttles = clampCount(r.throttle429Count);
  if (throttles > 0) entry.throttle429Count = throttles;
  const exhausted = clampCount(r.retryExhaustedCount);
  if (exhausted > 0) entry.retryExhaustedCount = exhausted;
  const retryAfter = clampCount(r.maxRetryAfterSeconds, RETRY_AFTER_MAX);
  if (retryAfter > 0) entry.maxRetryAfterSeconds = retryAfter;

  // securityRefusals (G327): the KIND is the whole record. The refused host / URL / DDL text is exactly the
  // value that must never be carried, and it is never posted.
  const refusals = countMap(r.securityRefusals, SECURITY_REFUSAL_SET);
  if (refusals !== undefined) entry.securityRefusals = refusals;

  // Nothing but the timestamp survived: a clean crawl. Record NOTHING (the omit-when-empty discipline).
  return Object.keys(entry).length > 1 ? entry : null;
}

/**
 * sanitiseDestFaults re-gates ONE destination fault + degradation snapshot. The S3 <Code> is admitted only
 * from the documented allow-list (fault-log.ts S3_ERROR_CODES, plus "other"/"none"), the op / class / arm
 * only from their closed sets, the status only as a clamped int -- so a hostile or misconfigured store
 * cannot push arbitrary text through this seam, and the request id survives only as a PRESENCE boolean.
 *
 * @param faults - the posted DestFaultSnapshot (untrusted).
 * @param io - the posted DestIoSnapshot (untrusted).
 * @param now - epoch ms to stamp.
 * @returns the bounded entry, or null when the destination behaved cleanly.
 */
export function sanitiseDestFaults(faults: unknown, io: unknown, now: number): DestFaultsEntry | null {
  const entry: DestFaultsEntry = { at: clampCount(now, Number.MAX_SAFE_INTEGER) };

  const f = (typeof faults === "object" && faults !== null ? faults : {}) as { total?: unknown; overflow?: unknown; faults?: unknown };
  // The same posted object, read for the ANOMALY half of the snapshot (G085/G119/G206/G207). Typed separately
  // so each half's gate reads on its own; both are re-validated field by field below.
  const f2 = f as { anomalies?: unknown; redirectRegionHint?: unknown; overBoundBytes?: unknown; listPagesReached?: unknown };
  const total = clampCount(f.total);
  const overflow = clampCount(f.overflow);
  const rows: DestFaultRow[] = [];
  for (const raw of (Array.isArray(f.faults) ? f.faults : []).slice(0, DEST_FAULT_SHAPES)) {
    const rr = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
    const op = gated(rr.op, DEST_OP_SET);
    const s3Code = gated(rr.s3Code, S3_ERROR_CODE_SET);
    const fault = gated(rr.fault, DEST_FAULT_CLASS_SET);
    const arm = gated(rr.arm, DEST_CLASSIFIER_ARM_SET);
    // Every closed field must be a member. A drifted row is dropped whole rather than half-carried: a fault
    // named by its op but not its cause sends support to the wrong subsystem.
    if (op === undefined || s3Code === undefined || fault === undefined || arm === undefined) continue;
    rows.push({
      op,
      httpStatus: clampCount(rr.httpStatus, 999),
      s3Code,
      fault,
      arm,
      requestIdPresent: rr.requestIdPresent === true,
      wormChecksumComplaint: rr.wormChecksumComplaint === true,
      count: Math.max(1, clampCount(rr.count)),
    });
  }
  if (total > 0) entry.total = total;
  if (overflow > 0) entry.overflow = overflow;
  if (rows.length > 0) entry.faults = rows;

  // anomalies (G085/G119/G206/G207): the destination behaviours that are NOT a failing op with a status -- a
  // listing the store truncated WITHOUT a cursor (so the walk silently believed it saw the whole keyspace and
  // the replica is non-restorable), a non-conformant store (no UploadId, no ETag, an error in a 200 body), an
  // engine guard refusal. The key space is the closed DEST_ANOMALIES set; every count is clamped.
  const anomalies = countMap(f2.anomalies, DEST_ANOMALY_SET);
  if (anomalies !== undefined) entry.anomalies = anomalies;
  // redirectRegionHint (G119): the ONE field derived from a store-controlled header. It is re-gated to the bare
  // AWS region shape here, so the Location URL (which embeds the bucket and the host) structurally cannot ride.
  if (typeof f2.redirectRegionHint === "string" && AWS_REGION_SHAPE.test(f2.redirectRegionHint)) entry.redirectRegionHint = f2.redirectRegionHint;
  const overBound = clampCount(f2.overBoundBytes, Number.MAX_SAFE_INTEGER);
  if (overBound > 0) entry.overBoundBytes = overBound;
  const listPages = clampCount(f2.listPagesReached);
  if (listPages > 0) entry.listPagesReached = listPages;
  // strandedAborts (G343): re-gated DO-side against the closed ABORT_FAILURE_CLASSES with a clamped count, so
  // a drifted or hostile driver cannot land a message, a key or an uploadId in this field.
  const stranded = sanitiseStrandedAborts((f2 as { strandedAborts?: unknown }).strandedAborts);
  if (stranded !== undefined) entry.strandedAborts = stranded;

  // io (G186): the DEGRADATION counters of a destination that is making a GREEN run slow and expensive --
  // the store's throttle pushback, the silently re-issued multipart steps, the black-holed timeouts, and the
  // dedup-defeating head-collapse (a 403/5xx HEAD read as "absent", so the segment re-uploads every night).
  const i = (typeof io === "object" && io !== null ? io : {}) as Record<string, unknown>;
  const ioOut: Record<string, number> = {};
  for (const k of ["throttleObservations", "retryAttemptsTotal", "timeouts", "conditionalPutConflicts", "headNon200CollapsedToAbsent", "retryAfterUnparseable"] as const) {
    const c = clampCount(i[k]);
    if (c > 0) ioOut[k] = c;
  }
  const minRate = clampCount(i.minEffectiveRatePerSec, RATE_MAX);
  if (minRate > 0) ioOut.minEffectiveRatePerSec = minRate;
  if (Object.keys(ioOut).length > 0) entry.io = ioOut;

  return Object.keys(entry).length > 1 ? entry : null;
}

// capAggregate keeps an aggregate to the RUN_FAULT_DOWNPIPES_MAX most-recently-stamped downpipes, so a large
// fleet (or a pathological churn of downpipe ids) can never grow the record without bound.
function capAggregate<T extends { at: number }>(agg: Record<string, T>): Record<string, T> {
  const keys = Object.keys(agg);
  if (keys.length <= RUN_FAULT_DOWNPIPES_MAX) return agg;
  const kept = keys.sort((a, b) => (agg[b]?.at ?? 0) - (agg[a]?.at ?? 0)).slice(0, RUN_FAULT_DOWNPIPES_MAX);
  const out: Record<string, T> = {};
  for (const k of kept) out[k] = agg[k] as T;
  return out;
}

/**
 * applySourceFaults folds one downpipe's sanitised source-fault entry into the bounded aggregate. LAST-WINS
 * per downpipe: this is a "what did the most recent faulting crawl see" record, not a ring -- the run-history
 * rows already carry the per-run outcome, and what a diagnosis needs here is the CURRENT cause.
 *
 * @param prior - the stored aggregate (or undefined).
 * @param downpipeId - the customer's own downpipe id (already validated by the caller).
 * @param raw - the posted ledger snapshot (untrusted; re-gated here).
 * @param now - epoch ms.
 * @returns the new aggregate.
 */
export function applySourceFaults(prior: SourceFaults | undefined, downpipeId: string, raw: unknown, now: number): SourceFaults {
  const agg: SourceFaults = { ...(prior ?? {}) };
  const entry = sanitiseSourceFaults(raw, now);
  if (entry === null) return capAggregate(agg); // a clean crawl clears nothing and adds nothing
  agg[downpipeId] = entry;
  return capAggregate(agg);
}

/**
 * applyDestFaults folds one downpipe's sanitised destination fault + degradation entry into the bounded
 * aggregate. LAST-WINS per downpipe, for the same reason as applySourceFaults.
 *
 * @param prior - the stored aggregate (or undefined).
 * @param downpipeId - the customer's own downpipe id (already validated by the caller).
 * @param faults - the posted DestFaultSnapshot (untrusted; re-gated here).
 * @param io - the posted DestIoSnapshot (untrusted; re-gated here).
 * @param now - epoch ms.
 * @returns the new aggregate.
 */
export function applyDestFaults(prior: DestFaults | undefined, downpipeId: string, faults: unknown, io: unknown, now: number): DestFaults {
  const agg: DestFaults = { ...(prior ?? {}) };
  const entry = sanitiseDestFaults(faults, io, now);
  if (entry === null) return capAggregate(agg);
  agg[downpipeId] = entry;
  return capAggregate(agg);
}
