// D1 RESTORE FAULT CLASSIFICATION (gap G055) -- the closed vocabulary and the typed error a D1 restore raises,
// so a partial apply can be LOCALISED without carrying a single byte of the customer's schema or data.
//
// THE PROBLEM. A D1 restore replays a schema-plus-rows document over several NON-ATOMIC db.batch() calls, so a
// fault part way through leaves a PARTIALLY-LOADED database. The receipt said only "partial restore": not which
// batch broke, not what kind of failure it was, and not how far the load had got. Support could not tell a
// bind-type problem (which fails on the FIRST batch, and is an engine/format question) from a constraint or
// size problem (which fails deep into the load, and is a data question), so every ticket started from zero.
//
// NO-CUSTODY REDACTION (binding). A SQLite / D1 error message embeds the table name, the column name and -- on a
// constraint violation -- the offending ROW VALUE. That message is the single most dangerous string in the whole
// restore path. classifyD1Error READS it ONLY to SELECT a member of D1_ERROR_CLASSES and RETURNS that member:
// the text is never returned, stored, forwarded or logged from here, and the output alphabet of this module is
// exactly D1_ERROR_CLASSES plus two clamped integers.

/**
 * D1_ERROR_CLASSES is the CLOSED vocabulary of D1 apply failures. Each names a different investigation:
 *   type-error       a bind value D1 refuses (the classic D1_TYPE_ERROR on a bigint): an ENGINE/format question,
 *                    and it fails on the first batch that carries such a value
 *   constraint       a UNIQUE / NOT NULL / FK / CHECK violation: a DATA question (and, on a fresh target, a sign
 *                    the archive itself disagrees with the schema)
 *   too-large        the batch exceeded D1's per-call statement or size limit
 *   no-such-table    a statement referenced a table that was not created (the table-SUBSET restore's dangling
 *                    index/trigger case)
 *   syntax           D1 rejected the statement text (a schema the engine reconstructed and D1 will not accept)
 *   internal         a D1_ERROR / internal failure with no readable cause: the store, not the data
 *   network          the batch never reached D1
 *   target-not-empty the fresh-target guard REFUSED before any write (nothing was applied at all)
 *   other            residual: never a message
 *
 * classifyD1Error returns the FIRST arm whose pattern matches, so an earlier arm wins on a message that
 * would satisfy several. Its test order is NOT quite the declaration order here: it tries network before
 * internal, so a D1_ERROR mentioning a connection classifies as network. target-not-empty has no message
 * pattern at all; only the fresh-target guard raises it, by construction.
 */
export const D1_ERROR_CLASSES = ["type-error", "constraint", "too-large", "no-such-table", "syntax", "internal", "network", "target-not-empty", "other"] as const;
/**
 * D1ErrorClass is one member of D1_ERROR_CLASSES: the ENTIRE output alphabet of D1 restore fault
 * classification, and the reason a SQLite message (which embeds table names, column names and, on a
 * constraint violation, the offending row value) never has to be carried to say what went wrong.
 */
export type D1ErrorClass = (typeof D1_ERROR_CLASSES)[number];
const D1_ERROR_CLASS_SET: ReadonlySet<string> = new Set(D1_ERROR_CLASSES);

/**
 * classifyD1Error coarsens a D1 / SQLite apply failure into a CLOSED D1ErrorClass. It reads the message ONLY to
 * match D1's own documented error tokens and SQLite's fixed error vocabulary, and RETURNS the enum. The message
 * -- which can embed a table name, a column name or a row value -- never leaves this function.
 *
 * @param e - the thrown value from db.batch().
 * @returns the closed class.
 */
export function classifyD1Error(e: unknown): D1ErrorClass {
  const m = e instanceof Error ? e.message : "";
  if (/D1_TYPE_ERROR|not supported|Type '/.test(m)) return "type-error";
  if (/constraint|UNIQUE|NOT NULL|FOREIGN KEY|CHECK/i.test(m)) return "constraint";
  if (/too large|too many|exceeds|limit exceeded|size limit/i.test(m)) return "too-large";
  if (/no such table/i.test(m)) return "no-such-table";
  if (/syntax error|malformed|near "/i.test(m)) return "syntax";
  if (/network|fetch failed|connection/i.test(m)) return "network";
  if (/D1_ERROR|internal/i.test(m)) return "internal";
  return "other";
}

/**
 * D1RestoreError is the TYPED form of a D1 restore fault. It extends Error and keeps the message the restore
 * orchestrator already classifies (so every downstream behaviour, including the restore-fault ring's own closed
 * class, is unchanged); `d1ErrorClass` and the two clamped magnitudes are the ADDITIVE evidence.
 *
 * The magnitudes are what LOCALISE a partial apply: failedBatchIndex/batchTotal say the load stopped at batch 3
 * of 900 (a schema/type problem) rather than 899 of 900 (a size or constraint problem), and residualTableCount
 * says how many tables are standing in the way of a refused fresh-target restore. All three are integers.
 */
export class D1RestoreError extends Error {
  readonly d1ErrorClass: D1ErrorClass;
  readonly failedBatchIndex?: number;
  readonly batchTotal?: number;
  readonly residualTableCount?: number;
  constructor(cls: D1ErrorClass, message: string, opts?: { failedBatchIndex?: number; batchTotal?: number; residualTableCount?: number }) {
    super(message);
    this.name = "D1RestoreError";
    this.d1ErrorClass = D1_ERROR_CLASS_SET.has(cls) ? cls : "other";
    if (isCount(opts?.failedBatchIndex)) this.failedBatchIndex = clamp(opts.failedBatchIndex);
    if (isCount(opts?.batchTotal)) this.batchTotal = clamp(opts.batchTotal);
    if (isCount(opts?.residualTableCount)) this.residualTableCount = clamp(opts.residualTableCount);
  }
}

const COUNT_MAX = 1_000_000;
function isCount(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0;
}
function clamp(v: number): number {
  return Math.min(COUNT_MAX, Math.floor(v));
}

/** The redaction-safe evidence one D1 restore fault yields: a closed class plus clamped integers. */
export interface D1FaultEvidence {
  readonly d1ErrorClass: D1ErrorClass;
  readonly failedBatchIndex?: number;
  readonly batchTotal?: number;
  readonly residualTableCount?: number;
}

/**
 * d1FaultEvidence reads the evidence off a CAUGHT D1 restore error, or null when the error is not one. It matches
 * on the TYPE, never on the message text -- the message is exactly the string this vocabulary exists to keep out
 * of the record. PURE.
 *
 * @param e - the caught error.
 * @returns the closed evidence, or null.
 */
export function d1FaultEvidence(e: unknown): D1FaultEvidence | null {
  if (!(e instanceof D1RestoreError)) return null;
  return {
    d1ErrorClass: e.d1ErrorClass,
    ...(e.failedBatchIndex !== undefined ? { failedBatchIndex: e.failedBatchIndex } : {}),
    ...(e.batchTotal !== undefined ? { batchTotal: e.batchTotal } : {}),
    ...(e.residualTableCount !== undefined ? { residualTableCount: e.residualTableCount } : {}),
  };
}

// ---------------------------------------------------------------------------------------------------------
// G348: THE RESTORE METADATA A SINK SILENTLY SHEDS
//
// THE PROBLEM. A restored KV key whose stored `expiration` descriptor is not a positive number is written
// WITHOUT the expiration (restore-sink.ts KVRestoreSink.put), and a restored R2 object whose stored
// `cacheExpiry` does not parse as a date is written WITHOUT it (r2PutOptions). Both are deliberate -- writing
// an Invalid Date, or a garbage TTL, would be worse -- but both are SILENT: the receipt reports the record
// restored at full fidelity, so "our restored KV keys never expire" reaches support with no evidence that the
// engine dropped the field BY DESIGN, and nobody can tell the customer to re-set the TTLs with any confidence.
//
// A KV expiration that has ALREADY LAPSED joins them for the same reason, and it is the common one: a KV
// expiration is an ABSOLUTE instant, so every backup older than a namespace's TTLs carries instants in the
// past, and the binding refuses a put whose expiration is not at least a minute ahead. Restoring the key without
// the lapsed expiration avoids that failure, and the loss is counted here.
//
// THE SHAPE. One ISOLATE-LOCAL {closed field -> count} tally, drained by the apply (admin/restore-apply.ts) at
// the end of the operation and carried on the restore receipt's audit target. The apply drains it BEFORE the
// operation too, so a warm isolate can never attribute a previous restore's shed to this one.
//
// NO-CUSTODY: the key space is exactly METADATA_SHED_FIELDS and the values are clamped counts. The
// unparseable VALUE (a customer TTL, a cache header) is read only to decide it is unusable, and is never
// carried -- this records the LOSS, not the lost content.
// ---------------------------------------------------------------------------------------------------------

/**
 * The CLOSED set of restore descriptor fields a sink can shed. Each names what the customer has to re-set
 * AND why it was dropped, which is why the two KV expiration kinds are separate members rather than one:
 * an UNUSABLE expiration is a defect signal (something wrote a value the format does not allow), while a
 * LAPSED one is the ordinary consequence of restoring a backup older than the namespace's TTLs. The remedy
 * is the same and the conversation with the customer is not.
 */
export const METADATA_SHED_FIELDS = [
  "kv-expiration", // the stored KV expiration was absent-shaped / non-positive / not a number: the key restores with NO TTL and never expires
  "kv-expiration-lapsed", // the stored KV expiration was a real instant that has ALREADY PASSED (the archive outlived the namespace's TTLs): the key restores with NO TTL and never expires
  "r2-cache-expiry", // the stored R2 httpMetadata.cacheExpiry did not parse as a date: the object restores with NO edge cache-expiry
] as const;
/**
 * MetadataShedField is one member of METADATA_SHED_FIELDS: the whole key space of the shed tally, and so
 * the whole vocabulary a restore receipt can use to say a descriptor was dropped. Each member names a
 * different thing the customer has to re-set by hand after the restore.
 */
export type MetadataShedField = (typeof METADATA_SHED_FIELDS)[number];
const METADATA_SHED_FIELD_SET: ReadonlySet<string> = new Set(METADATA_SHED_FIELDS);

const SHED_COUNT_MAX = 1_000_000;
let shedTally: Partial<Record<MetadataShedField, number>> = {};

/**
 * noteMetadataShed counts ONE restore descriptor field dropped at the sink. Called at the DROP SITE, so the
 * count can never drift from the behaviour it describes. The dropped value never enters the tally.
 *
 * @param field - the closed field kind.
 */
export function noteMetadataShed(field: MetadataShedField): void {
  shedTally[field] = Math.min(SHED_COUNT_MAX, (shedTally[field] ?? 0) + 1);
}

/**
 * drainMetadataShed returns the tally and CLEARS it, so one operation's shed is never attributed to the next
 * one this warm isolate serves.
 *
 * @returns the {closed field: count} tally (empty when the restore was full-fidelity).
 */
export function drainMetadataShed(): Partial<Record<MetadataShedField, number>> {
  const out = shedTally;
  shedTally = {};
  return out;
}

/**
 * sanitiseMetadataShed re-gates a drained tally: an out-of-vocabulary field is DROPPED and every count is
 * clamped, so the recorded map's key space is exactly METADATA_SHED_FIELDS. PURE (the redaction chokepoint
 * for this evidence on the way to the audit target).
 *
 * @param raw - the tally (untrusted).
 * @returns the gated map, or undefined when nothing was shed.
 */
export function sanitiseMetadataShed(raw: unknown): Record<string, number> | undefined {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return undefined;
  const out: Record<string, number> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!METADATA_SHED_FIELD_SET.has(k)) continue;
    if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) continue;
    out[k] = Math.min(SHED_COUNT_MAX, Math.floor(v));
  }
  return Object.keys(out).length > 0 ? out : undefined;
}
