// Pure, this-free helpers for the SchedulerDO: free-text validation, timestamp canonicalisation,
// byte compare, sequence padding, the monotonic ULID generator, and the authority-boundary enum
// guards for the audit query and the internal notify emit routes. All moved VERBATIM out of
// scheduler-do.ts (the SchedulerDO god-module split, guardrails B8-2): behaviour is unchanged and
// every call site is unchanged because scheduler-do.ts imports these back under the same names.
// This module depends only on the audit.ts / notify.ts type unions (leaves), never on scheduler-do.ts,
// so madge stays at 0 cycles.
import type { AuditAction, AuditFilter, AuditOutcome } from "../admin/audit.ts";
import { AUDIT_ACTIONS } from "../admin/audit-types.ts";
import type { ChannelKind, NotifyEvent, Severity } from "../notify.ts";
import type { SourceSpec } from "./types.ts";

// validateFreeText checks a client-supplied free-text field at the authority boundary, matching
// the character-range discipline of normaliseGroup (which excludes ALL control chars). Here we
// keep horizontal tab (0x09) and newline (0x0A) because a multi-line reason/note is legitimate
// in the console UI; all other C0 control characters and DEL (0x7F) are rejected. Returns an
// error message string on failure, or null on success (the caller throws on non-null so the
// existing fetch() catch maps it to a 400).
export function validateFreeText(value: string, fieldName: string, maxLen: number): string | null {
  if (value.length > maxLen) return `${fieldName} must not exceed ${maxLen} characters`;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c === 0x09 || c === 0x0a) continue; // tab and newline are allowed
    if (c < 0x20 || c === 0x7f) return `${fieldName} must not contain control characters`;
  }
  return null;
}

// parseAuditFilter turns the GET /audit query string into a typed AuditFilter. Unknown action or
// outcome values are dropped (treated as "no constraint") rather than rejected, so a typo narrows
// nothing instead of 500ing; before/limit are parsed as finite non-negative integers. It is a
// free function (like validateConfig) so the DO route stays small and the parsing is testable.
export function parseAuditFilter(params: URLSearchParams): AuditFilter {
  const f: AuditFilter = {};
  const actor = params.get("actor");
  if (actor) f.actor = actor;
  const action = params.get("action");
  if (action && isAuditAction(action)) f.action = action;
  const downpipe = params.get("downpipe");
  if (downpipe) f.downpipe = downpipe;
  const outcome = params.get("outcome");
  if (outcome && isAuditOutcome(outcome)) f.outcome = outcome;
  const from = params.get("from");
  if (from) f.from = from;
  const to = params.get("to");
  if (to) f.to = to;
  const before = params.get("before");
  if (before !== null) {
    const n = Number(before);
    if (Number.isFinite(n) && n >= 0) f.before = n;
  }
  const afterSeq = params.get("afterSeq");
  if (afterSeq !== null) {
    const n = Number(afterSeq);
    if (Number.isFinite(n) && n >= 0) f.afterSeq = Math.floor(n);
  }
  const limit = params.get("limit");
  if (limit !== null) {
    const n = Number(limit);
    if (Number.isFinite(n) && n > 0) f.limit = Math.floor(n);
  }
  return f;
}

// isAuditAction / isAuditOutcome are runtime guards for the query enums, mirroring isRole's
// authority-boundary discipline so a crafted query value cannot widen the filter to an unknown
// action. isAuditAction iterates the AUDIT_ACTIONS const array that the AuditAction union is itself
// derived from, so the guard can never drift from the union: every member is accepted, an unknown is
// rejected, and the filter narrows rather than silently widens.
export function isAuditAction(v: string): v is AuditAction {
  return (AUDIT_ACTIONS as readonly string[]).includes(v);
}

export function isAuditOutcome(v: string): v is AuditOutcome {
  return v === "success" || v === "denied" || v === "failed";
}

// nowMillisISO is the run-history/manifest timestamp form: RFC-3339 UTC truncated to
// milliseconds, the same normalisation runDownpipe applies to the manifest createdAt.
export function nowMillisISO(): string {
  return new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

// bytesEqualLocal is the config-history de-dupe's byte compare (is the current serialised snapshot
// byte-identical to the head version's?). It is the shared non-security bytesEqual under its existing
// call-site name, so scheduler-do.ts's import is unchanged; the single definition lives in util/bytes-equal.ts
// (de-duplicated with seal/pipeline.ts's identical compare).
export { bytesEqual as bytesEqualLocal } from "../util/bytes-equal.ts";

// canonMillisISO normalises an arbitrary client-supplied timestamp to the SAME RFC-3339 millis-Z form
// the producers emit (the nowMillisISO / cron-at shape: UTC, truncated to milliseconds, trailing Z).
// It parses to an instant and re-serialises, so any precision/offset the caller sent (e.g. "+10:00",
// microseconds, no millis) collapses to one canonical string. A non-string, empty, or UNPARSEABLE
// input falls back to the DO clock (nowMillisISO), so a malformed `at` can never wedge a stored
// emission with a non-comparable timestamp. Reuses nowMillisISO's normalisation regex verbatim so the
// canonical form cannot drift from the producers'.
export function canonMillisISO(raw: unknown): string {
  if (typeof raw !== "string" || raw.length === 0) return nowMillisISO();
  const t = Date.parse(raw);
  if (!Number.isFinite(t)) return nowMillisISO();
  return new Date(t).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

// padSeqLocal zero-pads a notification-history/digest sequence to a fixed width so the storage-key
// lexical order is numeric order (the same trick audit.ts's padSeq uses for the audit chain). Kept
// local so the DO has no cross-module dependency for its own notify key formatting; width 20 matches
// audit's SEQ_PAD so a far-future large account never overflows the field.
export function padSeqLocal(seq: number): string {
  return String(seq).padStart(20, "0");
}

// isNotifyEventLocal / isSeverityLocal / isChannelKindLocal are the DO's authority-boundary guards
// for the internal emit routes (parseEmission, recordNotify), mirroring isAuditAction's local-guard
// discipline so a crafted internal payload cannot widen an enum. The lists are kept in lockstep with
// the unions in notify.ts. They are local (not value imports) on purpose: the DO bounds its own
// inputs without coupling to the notify module's guards.
export function isNotifyEventLocal(v: unknown): v is NotifyEvent {
  return (
    v === "backup-success" ||
    v === "backup-failure" ||
    v === "backup-stale" ||
    v === "backup-volume-regression" ||
    v === "source-detached" ||
    v === "restore-test-pass" ||
    v === "restore-test-fail" ||
    v === "restore-applied" ||
    v === "credential-expiry" ||
    v === "posture-regression" ||
    v === "role-change" ||
    v === "auth-credential-change" ||
    v === "dest-change" ||
    v === "sign-in-new-context" ||
    // Kept in lockstep with NOTIFY_EVENT_NAMES (the NotifyEvent union) in notify.ts: EVERY notifiable event
    // is emitted through routeNotification -> POST /notify/resolve, so the DO's authority-boundary guard must
    // admit ALL of them, otherwise parseEmission returns null and the alert resolves ZERO channels (silently
    // dropped). The retention volume-regression, source-detach, and the two replication-redundancy events are
    // all routed this way; omitting them here dropped their alerts even though they were emitted, severity-
    // mapped and (mostly) nameable in a rule. validate-notify-routing.ts's structural guard iterates
    // NOTIFY_EVENT_NAMES and fails CI if any event is missing from this list, so the lockstep cannot re-drift.
    v === "recovery-code-used" ||
    v === "recovery-code-abuse" ||
    v === "canary-dead" ||
    v === "canary-recovered" ||
    v === "dual-control-disabled" ||
    v === "update-available" ||
    v === "update-rollback-needed" ||
    v === "replication-degraded" ||
    v === "run-at-risk-eviction"
  );
}
export function isSeverityLocal(v: unknown): v is Severity {
  return v === "info" || v === "warning" || v === "critical";
}
export function isChannelKindLocal(v: unknown): v is ChannelKind {
  // Kept in lockstep with the ChannelKind union in notify/types.ts: recordNotify guards a Worker-
  // reported channelKind against this list before it stores a NotifyHistoryEntry, so a kind missing
  // here has its delivery outcome SILENTLY SKIPPED (the same drop class isNotifyEventLocal guards
  // against for events, above). validate-notify-routing.ts's channel-kind wiring guard iterates a
  // canonical list mirroring NOTIFY_EVENT_NAMES's discipline and fails CI if a kind is missing here.
  return v === "email" || v === "webhook" || v === "slack" || v === "pagerduty" || v === "teams" || v === "jsm" || v === "servicenow";
}

// ---- per-tick cron OUTCOME ring (INFRA + SCHED scheduler-liveness new-logging) ------------------------
//
// A Worker cron invocation completing without throwing is a FALSE GREEN: the tick can report "ok" while the
// seal loop dispatched nothing (the DO was momentarily unavailable, or every due run was coalesced), or a
// trailing pass crashed, or the shared subrequest budget was overdrawn and starved the tail. None of that
// is durably recorded today, so "my backups silently stopped" has no evidence in the support pack. The cron
// driver reports a TickReport at the END of each invocation and the scheduler DO keeps a bounded ring of the
// derived TickOutcomes. It is the pack's answer to the single most common support ticket class.

// TickReport / TickOutcome live in the shared ./types.ts leaf (imported by the DO, the cron driver and the
// pack projection without an import cycle); this module owns the PURE clamp/append logic over them.
import type { TickOutcome, TickReport } from "./types.ts";

export type { TickOutcome, TickReport } from "./types.ts";

// TICK_COUNT_MAX clamps every count field so a malformed report can never bloat the ring; TICK_RING_CAP is
// how many most-recent ticks the ring retains (newest-last), enough to see a missed-tick / starvation pattern
// across a diagnosis window without unbounded growth.
const TICK_COUNT_MAX = 1_000_000;
export const TICK_RING_CAP = 64;

function clampTickCount(n: unknown): number {
  return typeof n === "number" && Number.isFinite(n) ? Math.max(0, Math.min(TICK_COUNT_MAX, Math.floor(n))) : 0;
}

// appendTickOutcome is the PURE ring-append: clamp every field of an (in-domain but still validated) report,
// derive the interval from the prior entry and the over-budget flag, append, and trim to `cap` (newest-last).
// Pure so it is unit-testable without a DO harness; the DO method is a thin storage read-modify-write around it.
export function appendTickOutcome(ring: TickOutcome[], report: TickReport, now: number, cap: number = TICK_RING_CAP): TickOutcome[] {
  const prev = ring.length > 0 ? ring[ring.length - 1]! : null;
  const at = Number.isFinite(now) ? Math.max(0, Math.floor(now)) : 0;
  const intervalMs = prev !== null ? Math.max(0, at - prev.at) : 0;
  const budgetCap = clampTickCount(report.budgetCap);
  const budgetSpent = clampTickCount(report.budgetSpent);
  const entry: TickOutcome = {
    at,
    intervalMs,
    due: clampTickCount(report.due),
    dispatched: clampTickCount(report.dispatched),
    coalesced: clampTickCount(report.coalesced),
    carried: clampTickCount(report.carried),
    sealErrors: clampTickCount(report.sealErrors),
    passErrors: clampTickCount(report.passErrors),
    budgetCap,
    budgetSpent,
    budgetRemaining: Math.max(0, budgetCap - budgetSpent),
    overBudget: budgetSpent > budgetCap,
  };
  const next = [...ring, entry];
  return next.length > cap ? next.slice(next.length - cap) : next;
}

// ---- persist-state storage-fault counter (SCHED persist-state-storage-fault / INFRA do-value-size-limit) ----
//
// A DO storage.put fault on the persist-STATE writer (persistDownpipeState) already fails LOUD -- it propagates,
// so the seal loop counts it as tick.sealErrors + a failed run row (a trailing pass counts it as passErrors).
// But those counters CONFLATE a storage fault with any other dispatch error, so "persist is failing" and "the
// DO value is too large" are invisible as a class. This is the DISTINCT counter: the writer classifies the
// thrown error and bumps a cumulative, persisted tally, so a diagnoser sees the persist/storage-fault subset
// (putFailed) and the DO-value-too-large subset (valueTooLarge) separately from generic dispatch errors.

// StorageFaultKind / StorageFaultCounter live in the shared ./types.ts leaf (like TickReport/TickOutcome), so
// the DO, these pure helpers and the pack projection share one shape without an import cycle; this module owns
// the pure classify/apply logic over them.
import type { SchedHealthCounter, SchedHealthCounters, SchedHealthKind, StateRefusal, StateRefusedClass, StorageFaultCounter, StorageFaultKind } from "./types.ts";

export type { SchedHealthCounters, SchedHealthKind, StateRefusal, StateRefusedClass, StorageFaultCounter, StorageFaultKind } from "./types.ts";

// EMPTY_STORAGE_FAULTS is the zero counter (never any fault yet), reused by the DO read fallback and the pack.
export const EMPTY_STORAGE_FAULTS: StorageFaultCounter = { total: 0, valueTooLarge: 0, putFailed: 0, lastAt: 0, lastKind: null, lastDownpipeId: null };

// LABEL_MAX is the clamp applied to a customer's OWN downpipe label before it is recorded on a diagnostic
// counter (the same 128-char class the pack's incomplete-marker ids and sealFaults.downpipeId already use).
// A label is the only customer-authored string any of these counters carries; nothing else does.
const LABEL_MAX = 128;

// safeDownpipeId clamps a downpipe id for a diagnostic record: a non-string (a malformed/absent id) becomes
// null rather than a coerced "undefined", and a long id is sliced to LABEL_MAX. It is the SINGLE place a
// customer-authored string enters these counters, so the redaction posture is enforced in one spot.
export function safeDownpipeId(id: unknown): string | null {
  return typeof id === "string" && id.length > 0 ? id.slice(0, LABEL_MAX) : null;
}

// clampCount is the shared non-negative-integer clamp for every counter below: a malformed persisted record
// (a negative, a NaN, a string) can never carry a bad value forward into the pack.
function clampCount(n: unknown): number {
  return typeof n === "number" && Number.isFinite(n) ? Math.max(0, Math.floor(n)) : 0;
}

// classifyStorageFault maps a thrown storage.put error to its closed StorageFaultKind. The Workers DO runtime
// rejects a value over the 128 KiB per-value limit with a size/too-large message; everything else (a transient
// storage error, an outage) is "put-failed". A best-effort message heuristic is acceptable for a DIAGNOSTIC
// classifier -- it never changes behaviour (the original error is always re-thrown), only the counter's class.
export function classifyStorageFault(err: unknown): StorageFaultKind {
  const msg = (err instanceof Error ? err.message : String(err ?? "")).toLowerCase();
  return /too large|size limit|exceed|larger than|413|value.*large/.test(msg) ? "value-too-large" : "put-failed";
}

// applyStorageFault is the PURE counter update: bump the total + the class sub-count, stamp the time + class.
// Pure so it is unit-testable without a DO harness; the DO method is a thin storage read-modify-write around it.
// It CLAMPS the prior counter defensively (a malformed persisted record can never carry a negative/NaN forward).
// It also ATTRIBUTES the fault (G040): `downpipeId` names WHICH downpipe's dp:<id> record the failing put was
// persisting, so a climbing valueTooLarge count finally names the downpipe whose state has outgrown the DO
// 128 KiB per-value cap (the one that stops advancing its next-run time). The id is clamped through
// safeDownpipeId; the raw storage error text is NEVER recorded (only its closed classification).
export function applyStorageFault(prior: StorageFaultCounter | undefined, kind: StorageFaultKind, now: number, downpipeId?: unknown): StorageFaultCounter {
  const c = prior ?? EMPTY_STORAGE_FAULTS;
  const at = Number.isFinite(now) ? Math.max(0, Math.floor(now)) : 0;
  const attributed = safeDownpipeId(downpipeId);
  return {
    total: clampCount(c.total) + 1,
    valueTooLarge: clampCount(c.valueTooLarge) + (kind === "value-too-large" ? 1 : 0),
    putFailed: clampCount(c.putFailed) + (kind === "put-failed" ? 1 : 0),
    lastAt: at,
    lastKind: kind,
    // Keep the PRIOR attribution when this fault carries none, so an unattributed fault never erases the last
    // known culprit (the value-too-large case always carries one; a bare counter write does not).
    lastDownpipeId: attributed ?? safeDownpipeId(c.lastDownpipeId),
  };
}

// ---- SCHED housekeeping-health counters (G040) -------------------------------------------------
// EMPTY_SCHED_HEALTH is the zero record: no sweep fault, no truncated enumeration, no failed parity stamp.
export const EMPTY_SCHED_HEALTH: SchedHealthCounters = {
  sweepFaults: { count: 0, lastAt: 0 },
  listTruncations: { count: 0, lastAt: 0 },
  parityStampFailures: { count: 0, lastAt: 0 },
};

// SCHED_HEALTH_FIELD maps each closed SchedHealthKind to the counter field it bumps, so the DO recorder is a
// pure switch-free lookup and an unknown kind cannot invent a field.
const SCHED_HEALTH_FIELD: Record<SchedHealthKind, keyof SchedHealthCounters> = {
  "sweep-fault": "sweepFaults",
  "list-truncated": "listTruncations",
  "parity-stamp-failed": "parityStampFailures",
};

// applySchedHealth is the PURE counter update for a scheduler housekeeping fault: bump the class count and stamp
// the time. It CLAMPS the prior record defensively so a malformed persisted value can never carry forward. Only
// integers ride: no error text, no key, no id (the three classes are fleet-level, not per-downpipe).
export function applySchedHealth(prior: SchedHealthCounters | undefined, kind: SchedHealthKind, now: number): SchedHealthCounters {
  const p = prior ?? EMPTY_SCHED_HEALTH;
  const at = Number.isFinite(now) ? Math.max(0, Math.floor(now)) : 0;
  const clampOne = (c: { count?: unknown; lastAt?: unknown } | undefined): { count: number; lastAt: number } => ({ count: clampCount(c?.count), lastAt: clampCount(c?.lastAt) });
  const next: SchedHealthCounters = {
    sweepFaults: clampOne(p.sweepFaults),
    listTruncations: clampOne(p.listTruncations),
    parityStampFailures: clampOne(p.parityStampFailures),
  };
  const field = SCHED_HEALTH_FIELD[kind];
  next[field] = { count: next[field].count + 1, lastAt: at };
  return next;
}

// schedHealthView is the PURE read-side projection of the housekeeping counters for the support pack: the three
// clamped counters plus the DERIVED parityStampStale flag. The flag is true when the last parity-stamp WRITE
// failed at or after the timestamp of the due-index snapshot the pack is serving, i.e. the snapshot is older
// than the last attempt to refresh it and must NOT be read as a fresh parity measurement (a failed stamp
// otherwise serves a stale-but-plausible due-index reading as if it were current). Ints + a boolean.
export function schedHealthView(raw: SchedHealthCounters | undefined, dueIndexAt: unknown): SchedHealthCounters & { parityStampStale: boolean } {
  const p = raw ?? EMPTY_SCHED_HEALTH;
  const one = (c: { count?: unknown; lastAt?: unknown } | undefined): SchedHealthCounter => ({ count: clampCount(c?.count), lastAt: clampCount(c?.lastAt) });
  const parityStampFailures = one(p.parityStampFailures);
  const snapshotAt = clampCount(dueIndexAt);
  return {
    sweepFaults: one(p.sweepFaults),
    listTruncations: one(p.listTruncations),
    parityStampFailures,
    parityStampStale: parityStampFailures.count > 0 && parityStampFailures.lastAt >= snapshotAt,
  };
}

// ---- Per-downpipe state-refusal stamp (G095 / G210) --------------------------------------------
// stateRefusalView is the PURE read-side projection of ONE persisted refusal stamp for the support pack. It is
// the redaction CHOKE POINT for this evidence: the id is clamped through safeDownpipeId, the class must be a
// member of the closed vocabulary (an unrecognised/corrupt class is DROPPED, never passed through as free text),
// and every number is clamped to a non-negative integer. Returns null for a row that cannot be projected safely.
export function stateRefusalView(rawId: string, raw: StateRefusal | undefined): (StateRefusal & { downpipeId: string }) | null {
  const downpipeId = safeDownpipeId(rawId);
  if (downpipeId === null || raw === null || typeof raw !== "object") return null;
  const cls = (raw as { class?: unknown }).class;
  if (cls !== "schema-newer" && cls !== "schema-version-malformed") return null;
  return {
    downpipeId,
    class: cls,
    at: clampCount((raw as { at?: unknown }).at),
    count: clampCount((raw as { count?: unknown }).count),
    storedVersion: clampCount((raw as { storedVersion?: unknown }).storedVersion),
    supportedVersion: clampCount((raw as { supportedVersion?: unknown }).supportedVersion),
  };
}

// applyStateRefusal is the PURE stamp update for a REFUSED dp:<id> read (migrateOrRejectConfig threw): it keeps
// the most recent class + time and COUNTS the consecutive refusals, so the pack can say "this downpipe has been
// refused N times since <at>: its state is stamped by a newer schema (a rollback), which is why it has produced
// no runs". The version pair rides as two clamped integers; the raw refusal message NEVER does. The consecutive
// count RESETS when the class changes (a different fault is a different story).
export function applyStateRefusal(prior: StateRefusal | undefined, cls: StateRefusedClass, storedVersion: unknown, supportedVersion: number, now: number): StateRefusal {
  const at = Number.isFinite(now) ? Math.max(0, Math.floor(now)) : 0;
  const priorCount = prior !== undefined && prior.class === cls ? clampCount(prior.count) : 0;
  return {
    class: cls,
    at,
    count: priorCount + 1,
    storedVersion: clampCount(storedVersion),
    supportedVersion: clampCount(supportedVersion),
  };
}

// newULID builds a 26-char Crockford ULID from a timestamp and random bytes.
// It is MONOTONIC within a millisecond: when timeMs equals the last-used timestamp the random
// component is incremented by 1 (in the least-significant bit) rather than regenerated, so two
// ULIDs minted in the same millisecond are guaranteed to sort in call order. This is the standard
// monotonic ULID rule (spec section 5.1). The state is module-level so it persists across the full
// lifetime of the SchedulerDO isolate; a new millisecond resets to fresh random bytes.
let _ulidLastMs = -1;
let _ulidLastRandom: bigint = 0n;

// ULID random component is 80 bits (10 bytes; bytes[6..15] in the 128-bit layout). The max value
// for those 80 bits is 2^80 - 1. If an increment would overflow we roll forward one millisecond so
// the monotonic invariant is preserved without ever wrapping the random component, matching the spec
// recommendation. In practice a DO invocation that mints 2^80 ULIDs in a single millisecond would
// already have crashed long before hitting the overflow.
const ULID_RANDOM_BITS = 80n;
const ULID_RANDOM_MAX = (1n << ULID_RANDOM_BITS) - 1n;

export function newULID(timeMs: number): string {
  const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

  let ms = timeMs;
  let rand: bigint;
  if (ms === _ulidLastMs) {
    // Same millisecond: increment the random component by 1 (monotonic ULID rule).
    const next = _ulidLastRandom + 1n;
    if (next > ULID_RANDOM_MAX) {
      // Overflow: roll the timestamp forward one millisecond so the increment never wraps.
      ms = ms + 1;
      const freshBytes = new Uint8Array(10);
      crypto.getRandomValues(freshBytes);
      rand = 0n;
      for (const b of freshBytes) rand = (rand << 8n) | BigInt(b);
    } else {
      rand = next;
    }
  } else {
    // New millisecond: generate a fresh random component.
    const freshBytes = new Uint8Array(10);
    crypto.getRandomValues(freshBytes);
    rand = 0n;
    for (const b of freshBytes) rand = (rand << 8n) | BigInt(b);
  }

  _ulidLastMs = ms;
  _ulidLastRandom = rand;

  // Assemble the 128-bit value: 48-bit timestamp (high) | 80-bit random (low).
  const bits = (BigInt(ms) << ULID_RANDOM_BITS) | rand;
  let out = "";
  let remaining = bits;
  for (let i = 0; i < 26; i++) {
    out = CROCKFORD[Number(remaining & 0x1fn)]! + out;
    remaining >>= 5n;
  }
  return out;
}
// sameSourceIdentity reports whether an edited config still reads the SAME source: the type plus the
// fields that identify WHICH resource is read (binding / namespaceId / bucketName / databaseId for the
// binding-backed stores, zoneId / accountId for the api-discovery scopes, and the secret-binding set for
// the secrets source). include/exclude, cfConfigMode and includeContent are capture FILTERS over the same
// resource, not identity, so changing them keeps the latest-run pointer. Used by addDownpipe to decide
// whether a re-upsert may carry lastRunId forward. Pure; order-insensitive over the secrets list.
export function sameSourceIdentity(a: SourceSpec, b: SourceSpec): boolean {
  if (a.type !== b.type) return false;
  if ((a.binding ?? null) !== (b.binding ?? null)) return false;
  if ((a.namespaceId ?? null) !== (b.namespaceId ?? null)) return false;
  if ((a.bucketName ?? null) !== (b.bucketName ?? null)) return false;
  if ((a.databaseId ?? null) !== (b.databaseId ?? null)) return false;
  if ((a.zoneId ?? null) !== (b.zoneId ?? null)) return false;
  if ((a.accountId ?? null) !== (b.accountId ?? null)) return false;
  const bindings = (spec: SourceSpec): string => (spec.secrets ?? []).map((sec) => sec.binding).sort().join("\u0000");
  return bindings(a) === bindings(b);
}
