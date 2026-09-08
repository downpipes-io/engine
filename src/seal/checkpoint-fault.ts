// CHECKPOINT-FAULT TYPES (gap G107, support-pack mode checkpoint-corruption-unattributed). The LEAF that
// lets a resume fault name ITSELF instead of collapsing to a generic "run failed" / "checkpoint unwrap
// failed" in the pack.
//
// This exists so a large backup that restarts from scratch every cycle is diagnosable: without it, nothing
// says (a) that a corrupt checkpoint was being ABANDONED, (b) WHICH field of it failed validation (a signer
// rotation, a tampered doc and a corrupted DO write are three different investigations), or (c) that N
// slices of real, durable progress were thrown away when it was.
//
// The design mirrors config-fault.ts exactly: the existing throws keep their EXACT messages (so every
// downstream text classification -- slice.ts coarseRunError, the strike ladder, the redacted log line -- is
// byte-for-byte unchanged), and the TYPE carries the closed evidence. Classifying by TYPE (never by reading
// the message) is what keeps the recorder redaction-safe by construction.
//
// NO-CUSTODY: every value here is a CLOSED enum member. The corrupt VALUE, the cursor, the key material and
// the AEAD's own error text never enter these objects and can never be recorded from them.

// CHECKPOINT_FIELDS is the CLOSED vocabulary of WHICH part of a stored checkpoint failed validation. Each
// member names a different investigation:
//   identity       runId / runlogIndex / downpipeId malformed  (the doc is not this run's)
//   wrapped-master the wrapped master is not a {iv, ct} pair    (the run can never derive its content keys)
//   progress       nextRecordIndex / nextShardIndex / sliceCount malformed (resume would mint bad ids)
//   cursor         the resume cursor (or its at-rest wrap) is malformed    (the crawl cannot resume)
//   frontier       the Merkle frontier or one of its nodes is malformed    (the root could not be recomputed)
//   counts         a required run counter is not a number       (the run would seal a miscounted archive)
//   partial-record the mid-record-resume prefix (or its wrap) is malformed (a half-record cannot be resumed)
//   open-shard     the carried open-shard line count is malformed          (the final shard would be short)
//   range-index    a fan-out worker's range tag is malformed    (it would mint a malformed composite id)
//   version        the doc is not v1                            (a format the engine cannot read)
export const CHECKPOINT_FIELDS = ["identity", "wrapped-master", "progress", "cursor", "frontier", "counts", "partial-record", "open-shard", "range-index", "version"] as const;
export type CheckpointField = (typeof CHECKPOINT_FIELDS)[number];
const CHECKPOINT_FIELD_SET: ReadonlySet<string> = new Set(CHECKPOINT_FIELDS);

/** isCheckpointField gates a value against the CLOSED field vocabulary (the recorder's chokepoint). */
export function isCheckpointField(v: unknown): v is CheckpointField {
  return typeof v === "string" && CHECKPOINT_FIELD_SET.has(v);
}

// CHECKPOINT_UNWRAP_CODES is the CLOSED sub-code of a checkpoint UNWRAP failure -- the distinction the pack
// could not make before (all three read as one "checkpoint-unwrap-failed" row):
//   master-unwrap  the AEAD over the wrapped MASTER (or the cursor/partial field) failed: a SIGNER_PRIVATE
//                  rotation stranded the in-flight run, or the doc was tampered with / corrupted at rest
//   batch-unwrap   an OPEN-SHARD batch's AEAD failed: the carried manifest lines cannot be re-read
//   wrong-length   the AEAD SUCCEEDED but the plaintext master is not 32 bytes: a corrupted write, NOT a
//                  rotation (the wrap key was right), which is a completely different remedy
export const CHECKPOINT_UNWRAP_CODES = ["master-unwrap", "batch-unwrap", "wrong-length"] as const;
export type CheckpointUnwrapCode = (typeof CHECKPOINT_UNWRAP_CODES)[number];
const CHECKPOINT_UNWRAP_CODE_SET: ReadonlySet<string> = new Set(CHECKPOINT_UNWRAP_CODES);

/** isCheckpointUnwrapCode gates a value against the CLOSED unwrap-code vocabulary. */
export function isCheckpointUnwrapCode(v: unknown): v is CheckpointUnwrapCode {
  return typeof v === "string" && CHECKPOINT_UNWRAP_CODE_SET.has(v);
}

/**
 * CheckpointInvalidError is a checkpoint VALIDATION refusal, typed with the closed field that failed. The
 * message is the EXISTING message verbatim, so coarseRunError's classification and the strike ladder behave
 * exactly as before; only the recorder reads `field`.
 */
export class CheckpointInvalidError extends Error {
  readonly field: CheckpointField;
  constructor(field: CheckpointField, message: string) {
    super(message);
    this.name = "CheckpointInvalidError";
    this.field = field;
  }
}

/**
 * CheckpointUnwrapError is a checkpoint UNWRAP failure, typed with the closed sub-code. It PRESERVES the
 * underlying message (an AEAD OperationError text or the existing wrong-length sentence), so nothing
 * downstream changes; only the recorder reads `code`. The key, the ciphertext and the plaintext never enter.
 */
export class CheckpointUnwrapError extends Error {
  readonly code: CheckpointUnwrapCode;
  constructor(code: CheckpointUnwrapCode, message: string) {
    super(message);
    this.name = "CheckpointUnwrapError";
    this.code = code;
  }
}

/** checkpointInvalidOf returns the closed FIELD of a checkpoint-validation refusal, or null for any other
 * error. Type-based (an instanceof check), never a message match, so it cannot drift or leak. */
export function checkpointInvalidOf(e: unknown): CheckpointField | null {
  return e instanceof CheckpointInvalidError ? e.field : null;
}

/** checkpointUnwrapOf returns the closed CODE of a checkpoint-unwrap failure, or null for any other error. */
export function checkpointUnwrapOf(e: unknown): CheckpointUnwrapCode | null {
  return e instanceof CheckpointUnwrapError ? e.code : null;
}

// COERCED_COUNTS are the checkpoint COUNTERS validateCheckpoint DEFAULTS rather than rejects, so that an
// engine upgrade never strands an in-flight run. The forward-compatibility is deliberate and stays -- but it
// made two very different things identical: a LEGACY doc that simply predates the counter (absent: benign),
// and a CORRUPTED doc whose counter came back as a non-number and was silently coerced (a miscounted archive
// waiting to happen). checkpointCoercions is the pure inspector that tells them apart.
const COERCED_NUMBER_COUNTS = ["recordsIncomplete", "recordsVanished"] as const;
const COERCED_OBJECT_COUNTS = ["incompleteByMarker", "incompleteIds"] as const;

/** CheckpointCoercion is one defaulted counter: `legacyAbsent` true = the field was simply missing (a doc
 * written before the counter shipped); false = the field was PRESENT but of the wrong type, i.e. a corrupted
 * write that is being silently coerced. The field NAME is one of a fixed engine list, never customer data. */
export interface CheckpointCoercion {
  readonly legacyAbsent: boolean;
}

/**
 * checkpointCoercions inspects a STORED checkpoint document (the at-rest form, whose counts ride in
 * plaintext) and reports the counters validateCheckpoint is about to DEFAULT, split by whether each was
 * absent (legacy) or present-but-malformed (corruption). PURE and READ-ONLY: it mutates nothing, it is
 * called BEFORE validateCheckpoint's in-place defaulting, and it returns counts + booleans only -- never the
 * corrupt value.
 *
 * @param stored - the raw stored checkpoint document.
 * @returns one entry per coerced counter (empty for a clean, current-format doc).
 */
export function checkpointCoercions(stored: unknown): CheckpointCoercion[] {
  const counts = (stored as { counts?: unknown } | null | undefined)?.counts;
  if (typeof counts !== "object" || counts === null) return [];
  const c = counts as Record<string, unknown>;
  const out: CheckpointCoercion[] = [];
  for (const f of COERCED_NUMBER_COUNTS) {
    if (typeof c[f] === "number") continue;
    out.push({ legacyAbsent: c[f] === undefined });
  }
  for (const f of COERCED_OBJECT_COUNTS) {
    if (typeof c[f] === "object" && c[f] !== null) continue;
    out.push({ legacyAbsent: c[f] === undefined });
  }
  return out;
}
