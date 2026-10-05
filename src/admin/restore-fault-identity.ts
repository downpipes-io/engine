// The identity a restore fault row carries for a record, in place of the record's name.
//
// A record's name, such as a KV key or an R2 object key, is customer data, so a restore fault row never
// carries one. It carries two values from the run's own signed manifest instead:
//   - index: the number in the record's recordId (r followed by 15 digits), the record's position in the run;
//   - keyNameHash: the record's keyed name MAC, HMAC-SHA-384 over the source type and the name under the run's
//     name-MAC key (SPEC 6.4, crypto/derive.ts nameMAC). The key derives from the run master, which is never
//     in the pack, so a short or guessable name cannot be recovered by hashing candidates.
// The customer's own copy of the run carries the same keyNameHash on the record's manifest line, beside the
// name, so the customer can say which record a row means while support never sees the name.
//
// The identity travels BESIDE a failure or skip entry, not in it. The entry is part of the operator's own
// restore response, so a WeakMap keyed by the entry object leaves that response unchanged, and the fault
// projection (restore-faults.ts restoreFaultRows) is its only reader.

/** The record identity a restore fault row may carry: the run index and the keyed name MAC. */
export interface RecordFaultIdentity {
  readonly index: number;
  readonly keyNameHash: string;
}

// A final archive's record id is r + the zero-padded 15-digit global index (format/writer.ts, seal/slice.ts
// recordIdFor after the fan-out renumber). Any other shape carries no index.
const RECORD_ID_SHAPE = /^r(\d{15})$/;

/** The shape of a keyed name MAC: 48 bytes as lower-case hex. The DO and the pack accept nothing else. */
export const KEY_NAME_HASH_SHAPE = /^[0-9a-f]{96}$/;

const identities = new WeakMap<object, RecordFaultIdentity>();

/**
 * withRecordIdentity attaches the record's index and keyed name MAC to a failure or skip entry and returns
 * the entry unchanged. A record whose id or MAC is out of shape attaches nothing, so its fault row carries
 * no identity rather than a wrong one.
 *
 * A failure push names its type, as in withRecordIdentity<RestoreFailure>(...). Without it T is inferred from
 * the literal, so the cls literal has no RESTORE_FAILURE_CLASSES slot and the dead-vocabulary gate cannot see
 * the producer.
 *
 * @param entry - the failure or skip entry the restore path is about to push.
 * @param rec - the manifest record the entry is about.
 * @returns the same entry.
 */
export function withRecordIdentity<T extends object>(entry: T, rec: { readonly recordId: string; readonly keyNameHash: string }): T {
  const m = RECORD_ID_SHAPE.exec(rec.recordId);
  if (m !== null && KEY_NAME_HASH_SHAPE.test(rec.keyNameHash)) identities.set(entry, { index: Number(m[1]), keyNameHash: rec.keyNameHash });
  return entry;
}

/**
 * recordIdentityOf reads the identity withRecordIdentity attached to an entry.
 *
 * @param entry - a failure or skip entry from a restore outcome.
 * @returns the identity, or undefined when the entry has none.
 */
export function recordIdentityOf(entry: object): RecordFaultIdentity | undefined {
  return identities.get(entry);
}
