// SEAL-FAULT SPANS: when each seal or replication fault reason was FIRST and LAST seen, beside the ring.
//
// The seal-fault ring (scheduler-do-observability.ts recordSealFault) keeps the freshest 64 observations.
// A replication pass that records the same two faults for seven downpipes every tick fills it within a day,
// so the ring shows only the tail of a fault and never its start: a support pack read carried
// 30 origin-dest-unconfigured and 29 not-configured rows, and nothing said both began when a
// destination was added. The span answers that. It is folded at post time in the DO from the SANITISED fault
// (so it can never hold a field the ring would drop), keyed by the closed kind and one closed reason, and for
// a replica fault also by the target destination id. It is bounded: a new key past SEAL_FAULT_SPAN_MAX is
// counted in `overflow` and never evicts an older span, because the first-seen time is the point.
//
// Redaction: every string on a span is a closed-vocabulary member, or the customer's own destination and
// downpipe ids (the class the pack already carries in downpipes[] and sealFaults). Counts are clamped.
// sanitiseSealFaultSpans re-gates all of it at the pack boundary.

import { CONFIG_FAULT_CODES } from "./config-fault.ts";
import {
  FANOUT_DISCARD_CLASSES,
  FANOUT_DOWNGRADE_REASONS,
  PRUNE_DEFER_CLASSES,
  REPLICA_FAULT_REASONS,
  REPLICATION_PASS_OUTCOMES,
  SEAL_FAULT_DROP_CLASSES,
  SEAL_FAULT_KINDS,
  type SealFault,
  SKIP_CAUSES,
  STRAND_CLASSES,
  WORM_REFUSAL_CLASSES,
} from "./seal-faults.ts";

export const SEAL_FAULT_SPANS_KEY = "signal:seal-fault-spans";
export const SEAL_FAULT_SPAN_MAX = 48;
const SPAN_DOWNPIPES_MAX = 16;
const ID_MAX = 128;
const INT_MAX = 1_000_000_000;

// The ONE closed reason field a span is keyed by, in precedence order, each with its own closed vocabulary.
const REASON_FIELDS = {
  replicaReason: REPLICA_FAULT_REASONS,
  passOutcome: REPLICATION_PASS_OUTCOMES,
  configCode: CONFIG_FAULT_CODES,
  strandClass: STRAND_CLASSES,
  skipCause: SKIP_CAUSES,
  wormRefusalClass: WORM_REFUSAL_CLASSES,
  deferClass: PRUNE_DEFER_CLASSES,
  discardClass: FANOUT_DISCARD_CLASSES,
  dropClass: SEAL_FAULT_DROP_CLASSES,
  downgradeReason: FANOUT_DOWNGRADE_REASONS,
} as const satisfies Record<string, readonly string[]>;
export type SpanReasonField = keyof typeof REASON_FIELDS;
const REASON_FIELD_NAMES = Object.keys(REASON_FIELDS) as SpanReasonField[];
const KIND_SET: ReadonlySet<string> = new Set(SEAL_FAULT_KINDS);

export interface SealFaultSpan {
  kind: string;
  reasonField?: SpanReasonField;
  reason?: string;
  destinationId?: string; // replica-target-fault only: WHICH target
  count: number;
  firstSeenAt: number;
  lastSeenAt: number;
  maxStrandedRuns?: number; // replica-target-fault: the most runs ever stranded on this target in one pass
  downpipeIds?: string[]; // the downpipes that posted this span, capped at SPAN_DOWNPIPES_MAX
  downpipesTruncated?: true;
}
export interface SealFaultSpans {
  spans: SealFaultSpan[];
  overflow: number; // observations whose NEW key arrived after the cap, so no span records them
}

function reasonOf(f: Record<string, unknown>): { reasonField: SpanReasonField; reason: string } | undefined {
  for (const field of REASON_FIELD_NAMES) {
    const v = f[field];
    if (typeof v === "string" && (REASON_FIELDS[field] as readonly string[]).includes(v)) return { reasonField: field, reason: v };
  }
  return undefined;
}

function spanKey(kind: string, r: { reasonField: string; reason: string } | undefined, destinationId: string | undefined): string {
  return `${kind}|${r ? `${r.reasonField}=${r.reason}` : ""}|${destinationId ?? ""}`;
}

/**
 * foldSealFaultSpan folds ONE sanitised fault into the spans. PURE: returns a new value.
 *
 * @param prev - the stored spans (or undefined before the first fault).
 * @param fault - the fault exactly as sanitiseSealFault returned it.
 * @returns the updated spans.
 */
export function foldSealFaultSpan(prev: SealFaultSpans | undefined, fault: SealFault): SealFaultSpans {
  const spans = (prev?.spans ?? []).map((s) => ({ ...s, ...(s.downpipeIds ? { downpipeIds: [...s.downpipeIds] } : {}) }));
  const overflow = prev?.overflow ?? 0;
  const f = fault as unknown as Record<string, unknown>;
  const r = reasonOf(f);
  const destinationId = fault.kind === "replica-target-fault" && typeof fault.destinationId === "string" ? fault.destinationId : undefined;
  const key = spanKey(fault.kind, r, destinationId);
  const at = fault.at;
  let span = spans.find((s) => spanKey(s.kind, s.reasonField && s.reason ? { reasonField: s.reasonField, reason: s.reason } : undefined, s.destinationId) === key);
  if (span === undefined) {
    if (spans.length >= SEAL_FAULT_SPAN_MAX) return { spans, overflow: Math.min(INT_MAX, overflow + 1) };
    span = { kind: fault.kind, ...(r ?? {}), ...(destinationId !== undefined ? { destinationId } : {}), count: 0, firstSeenAt: at, lastSeenAt: at };
    spans.push(span);
  }
  span.count = Math.min(INT_MAX, span.count + 1);
  span.firstSeenAt = Math.min(span.firstSeenAt, at);
  span.lastSeenAt = Math.max(span.lastSeenAt, at);
  if (typeof fault.strandedRuns === "number" && fault.strandedRuns > (span.maxStrandedRuns ?? 0)) span.maxStrandedRuns = fault.strandedRuns;
  if (typeof fault.downpipeId === "string") {
    const ids = span.downpipeIds ?? [];
    if (!ids.includes(fault.downpipeId)) {
      if (ids.length < SPAN_DOWNPIPES_MAX) ids.push(fault.downpipeId);
      else span.downpipesTruncated = true;
    }
    span.downpipeIds = ids;
  }
  return { spans, overflow };
}

const clampInt = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), INT_MAX) : 0);
const clampTs = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), 8_640_000_000_000_000) : 0);
const clampId = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v.slice(0, ID_MAX) : undefined);

/**
 * sanitiseSealFaultSpans re-gates stored spans at the PACK boundary: a span whose kind is outside the closed
 * vocabulary is dropped, a reason field or reason outside its closed vocabulary is dropped from the span,
 * ids are clamped, counts clamped, and the list is sorted by most recent first.
 *
 * @param raw - whatever the DO returned for the spans.
 * @returns the pack-safe spans, or undefined when there are none to carry.
 */
export function sanitiseSealFaultSpans(raw: unknown): { spans: SealFaultSpan[]; overflow?: number } | undefined {
  const r = (raw ?? {}) as { spans?: unknown; overflow?: unknown };
  const rows = Array.isArray(r.spans) ? r.spans : [];
  const spans: SealFaultSpan[] = [];
  for (const row of rows.slice(0, SEAL_FAULT_SPAN_MAX)) {
    const s = (row ?? {}) as Record<string, unknown>;
    if (typeof s.kind !== "string" || !KIND_SET.has(s.kind)) continue;
    const field = typeof s.reasonField === "string" && (REASON_FIELD_NAMES as string[]).includes(s.reasonField) ? (s.reasonField as SpanReasonField) : undefined;
    const reason = field !== undefined && typeof s.reason === "string" && (REASON_FIELDS[field] as readonly string[]).includes(s.reason) ? s.reason : undefined;
    const destinationId = clampId(s.destinationId);
    const ids = Array.isArray(s.downpipeIds) ? s.downpipeIds.map(clampId).filter((x): x is string => x !== undefined).slice(0, SPAN_DOWNPIPES_MAX) : [];
    spans.push({
      kind: s.kind,
      ...(field !== undefined && reason !== undefined ? { reasonField: field, reason } : {}),
      ...(destinationId !== undefined ? { destinationId } : {}),
      count: clampInt(s.count),
      firstSeenAt: clampTs(s.firstSeenAt),
      lastSeenAt: clampTs(s.lastSeenAt),
      ...(s.maxStrandedRuns !== undefined ? { maxStrandedRuns: clampInt(s.maxStrandedRuns) } : {}),
      ...(ids.length > 0 ? { downpipeIds: ids } : {}),
      ...(s.downpipesTruncated === true ? { downpipesTruncated: true as const } : {}),
    });
  }
  const overflow = clampInt(r.overflow);
  if (spans.length === 0 && overflow === 0) return undefined;
  spans.sort((a, b) => b.lastSeenAt - a.lastSeenAt);
  return { spans, ...(overflow > 0 ? { overflow } : {}) };
}
