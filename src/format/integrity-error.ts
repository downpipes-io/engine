// Leaf module: the STRUCTURED failure category the verifying reader raises, so the restore /
// verify / drill side never has to GUESS integrity-vs-availability from a free-text error message.
//
// The DR guarantee is that INTEGRITY is NOT availability: a tamper / completeness / structural /
// signature / freshness failure must surface immediately and NEVER fall through to a 3-2-1 replica
// (a replica holds the SAME signed run, so reading it would only mask the corruption the operator
// must see). The 3-2-1 replica fallback (router-sources.ts withRunDestFallback) is reserved STRICTLY
// for AVAILABILITY faults a healthy replica could remedy: the object is missing here (404), the
// destination refused/faulted with an HTTP status (403 / 5xx / redirect / 429), or a network fault.
//
// A keyword regex over the raw reader message cannot be relied on to catch every genuine integrity/
// completeness failure the reader throws (e.g. "recovered N records, the root declares M", a codec/preamble
// structural mismatch): a message that fails to match would default to the catch-all "recovery check failed"
// reason, which IS in the replica-fallback set, so a truncated / incomplete / corrupt archive could wrongly
// fall back to a replica instead of failing loud. Raising this typed error removes the guessing: any
// RunIntegrityError is NON-fallback by construction, regardless of its message.

/**
 * The failure category. "integrity" covers tamper / completeness / structural / signature failures;
 * "freshness" is the anti-rollback verifier firing on a check that RAN; "freshness-unverifiable" is a
 * freshness check that COULD NOT RUN on this destination. All three refuse the open. restore-reasons.ts
 * maps this category straight to REASON_INTEGRITY, REASON_FRESHNESS or REASON_FRESHNESS_UNVERIFIABLE, so
 * the union is the contract between every throw site in the reader and the single classifier the restore
 * side runs.
 *
 * WHY THE THIRD MEMBER EXISTS. "integrity" and "freshness" are both non-fallback on the same stated
 * ground: a replica holds the SAME signed run, so reading it could only mask the corruption the operator
 * must see. That ground does not hold for a freshness check that could not run, because the RUNLOG is NOT
 * the same document on every destination. appendRunlog's relinkLocalPrev writes each destination its own
 * entry against its own tail and signs that destination's own document, so an absent or unverifiable
 * `_RECOVERY/RUNLOG` on the primary is a fault in THAT bucket's copy and says nothing about the replica's.
 * A check that ran and found a rollback is a FINDING about the run and stays terminal; a check that could
 * not run is an UNKNOWN about one destination, and the second and third copies exist for exactly that.
 * The split is the `checked` field the reader already computes, raised to the type the restore side reads.
 *
 * WHY THE FOURTH MEMBER EXISTS, AND WHY IT IS NOT AN INTEGRITY FAILURE. "format-unsupported" is the format
 * version gate (structural-gates.ts checkFormatVersion) refusing a label this build does not implement. The
 * bytes are intact, the signature verified, nothing was written, and the only thing wrong is that the reader
 * is a different build from the writer. Carrying that as "integrity" made the console tell the customer their
 * archive "failed its integrity verification (possible corruption or tampering)" over an archive that is
 * perfect, which sends them hunting a corruption that is not there. It is kept in this union, rather than
 * raised as an unrelated error type, because the SAFETY posture is identical: a replica holds the SAME signed
 * run carrying the SAME formatVersion label, so a replica walk could only fail again, and the union is what
 * makes every member non-fallback by construction. The category is the sole carrier of the distinction; the
 * message is never classified on.
 */
export type IntegrityCategory = "integrity" | "freshness" | "freshness-unverifiable" | "format-unsupported";

// A non-enumerable brand so an instance is recognised even across module-realm boundaries (a second
// copy of this module, or a structuredClone), where `instanceof` alone can miss. isIntegrityFailure
// checks the brand first, then instanceof, then a duck-typed category field.
const BRAND = "__downpipeRunIntegrityError" as const;

/**
 * RunIntegrityError is thrown by the verifying reader for a NON-availability verification failure: a
 * bad signature, a key-commitment mismatch, a per-record or Merkle hash mismatch, a completeness
 * shortfall (recovered count != declared count), a structural format violation, or an anti-rollback
 * freshness failure. It carries an explicit {@link IntegrityCategory} so the restore side classifies
 * by TYPE, not by string-matching the message. It NEVER carries an object key or plaintext (the
 * message stays the same coarse text the reader already used); the category is the only added signal.
 */
export class RunIntegrityError extends Error {
  readonly category: IntegrityCategory;
  readonly [BRAND] = true;
  constructor(message: string, category: IntegrityCategory = "integrity") {
    super(message);
    this.name = "RunIntegrityError";
    this.category = category;
  }
}

/**
 * integrityError builds an integrity-category RunIntegrityError (the common case: tamper /
 * completeness / structural / signature). A thin helper so the reader's many throw sites stay terse.
 * It BUILDS the error and does not throw it, so a call site reads `throw integrityError(...)`.
 * The message is the coarse operator-facing text only: it must carry no object key and no plaintext,
 * because the category, not the message, is what the restore side classifies on.
 */
export function integrityError(message: string): RunIntegrityError {
  return new RunIntegrityError(message, "integrity");
}

/**
 * freshnessError builds a freshness-category RunIntegrityError (the anti-rollback verifier firing).
 * Same shape as integrityError and the same non-fallback posture; only the category differs, which is
 * what lets the restore side report a stale or rolled-back RUNLOG separately from a damaged archive.
 * The reader raises it from one place, the freshness gate in openRunWith.
 */
export function freshnessError(message: string): RunIntegrityError {
  return new RunIntegrityError(message, "freshness");
}

/**
 * freshnessUnverifiableError builds a freshness-unverifiable RunIntegrityError: the freshness check could
 * not run against THIS destination at all (FreshnessResult.checked false -- the RUNLOG or its signature
 * could not be read, the signature did not verify, or the document does not carry this run in a form that
 * binds to the signed root). It refuses the open exactly as freshnessError does; the only difference is
 * what the restore side is then allowed to do about it, because the RUNLOG is a per-destination document
 * and a replica writes and signs its own. The reader raises it from one place, the freshness gate in
 * openRunWith, and never from a path where a verdict WAS reached.
 */
export function freshnessUnverifiableError(message: string): RunIntegrityError {
  return new RunIntegrityError(message, "freshness-unverifiable");
}

/**
 * formatUnsupportedError builds a format-unsupported RunIntegrityError: this build does not implement the
 * archive's format version. Same shape and the same non-fallback posture as integrityError, and the ONLY
 * difference is what the customer is then told, which is the whole point of the split. The reader raises it
 * from one place, checkFormatVersion in structural-gates.ts, and never from a path where any check over the
 * BYTES failed. The message is operator-facing and says in as many words that nothing is wrong with the
 * bytes; it carries no object key, no plaintext and no customer value (the only interpolation is the format
 * label from the signature-verified manifest, which is a format constant).
 */
export function formatUnsupportedError(message: string): RunIntegrityError {
  return new RunIntegrityError(message, "format-unsupported");
}

/**
 * isIntegrityFailure reports whether a caught value is a structured reader integrity/freshness
 * failure, i.e. a NON-fallback fault. It is realm-tolerant: it accepts a genuine instanceof, the
 * non-enumerable brand, or a duck-typed object carrying name "RunIntegrityError" with a category, so
 * the classifier on the restore side never silently treats a typed integrity failure as availability.
 */
export function isIntegrityFailure(e: unknown): e is RunIntegrityError {
  if (e instanceof RunIntegrityError) return true;
  if (typeof e !== "object" || e === null) return false;
  const rec = e as Record<string, unknown>;
  if (rec[BRAND] === true) return true;
  return rec.name === "RunIntegrityError" && (rec.category === "integrity" || rec.category === "freshness" || rec.category === "freshness-unverifiable" || rec.category === "format-unsupported");
}

/**
 * integrityCategoryOf returns the category of a structured integrity failure, or null when the value
 * is not one. "freshness" callers need this to split the freshness reason out from plain integrity.
 *
 * It shares isIntegrityFailure's realm tolerance, so a duck-typed or cross-realm copy is read the same
 * way as a genuine instance. A recognised failure carrying any UNKNOWN category reports "integrity", so an
 * absent, misspelled or future category degrades to the strictest answer (terminal, never a replica walk,
 * and the loudest sentence) rather than to null, which the classifier would otherwise be free to treat as
 * availability. Every non-default member is matched EXPLICITLY for that reason: only a category this build
 * knows about can reach the eligible-for-fallback answer or the softer format-mismatch wording, and
 * everything else fails closed on the terminal side.
 */
export function integrityCategoryOf(e: unknown): IntegrityCategory | null {
  if (!isIntegrityFailure(e)) return null;
  const cat = (e as { category?: unknown }).category;
  if (cat === "freshness") return "freshness";
  if (cat === "freshness-unverifiable") return "freshness-unverifiable";
  if (cat === "format-unsupported") return "format-unsupported";
  return "integrity";
}
